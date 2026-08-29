#import <UIKit/UIKit.h>
#import <AVFoundation/AVFoundation.h>
#import <CoreImage/CoreImage.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <ImageIO/ImageIO.h>
#import <Vision/Vision.h>
#import <QuartzCore/QuartzCore.h>
#import <objc/runtime.h>

#ifdef __cplusplus
extern "C" {
#endif
void MSHookMessageEx(Class _class, SEL message, IMP hook, IMP *old);
#ifdef __cplusplus
}
#endif

typedef NS_ENUM(NSInteger, ALBeautyFilterStyle) {
    ALBeautyFilterStyleNone = 0,
    ALBeautyFilterStyleSmooth = 1,
    ALBeautyFilterStyleWarm = 2,
    ALBeautyFilterStyleCool = 3,
    ALBeautyFilterStyleGlam = 4,
    ALBeautyFilterStyleBlush = 5,
    ALBeautyFilterStyleGlasses = 6,
    ALBeautyFilterStyleCrown = 7,
    ALBeautyFilterStyleSparkle = 8
};

static NSString * const kALSelectedFilterKey = @"com.mohammed.aladbeauty.selected-filter";
static NSInteger const kALFilterButtonTagBase = 7100;
static void *kALDelegateProxyKey = &kALDelegateProxyKey;

static UIWindow *ALCurrentKeyWindow(void) {
    UIApplication *application = UIApplication.sharedApplication;
    if (@available(iOS 13.0, *)) {
        for (UIScene *scene in application.connectedScenes) {
            if (scene.activationState != UISceneActivationStateForegroundActive) {
                continue;
            }
            for (UIWindow *window in ((UIWindowScene *)scene).windows) {
                if (window.isKeyWindow) {
                    return window;
                }
            }
        }
    }
    for (UIWindow *window in application.windows) {
        if (window.isKeyWindow) {
            return window;
        }
    }
    return application.windows.firstObject;
}

@interface ALFaceSnapshot : NSObject
@property(nonatomic, assign) CGRect boundingBox;
@property(nonatomic, assign) CGFloat roll;
@end

@implementation ALFaceSnapshot
@end

static CIImage *ALFilterOutput(CIFilter *filter) {
    return [filter valueForKey:kCIOutputImageKey];
}

static CIImage *ALApplyColorControls(CIImage *image, CGFloat saturation, CGFloat brightness, CGFloat contrast) {
    CIFilter *filter = [CIFilter filterWithName:@"CIColorControls"];
    [filter setValue:image forKey:kCIInputImageKey];
    [filter setValue:@(saturation) forKey:kCIInputSaturationKey];
    [filter setValue:@(brightness) forKey:kCIInputBrightnessKey];
    [filter setValue:@(contrast) forKey:kCIInputContrastKey];
    return ALFilterOutput(filter) ?: image;
}

static CIImage *ALApplyTemperature(CIImage *image, CGFloat targetTemperature) {
    CIFilter *filter = [CIFilter filterWithName:@"CITemperatureAndTint"];
    [filter setValue:image forKey:kCIInputImageKey];
    [filter setValue:[CIVector vectorWithX:6500.0 Y:0.0] forKey:@"inputNeutral"];
    [filter setValue:[CIVector vectorWithX:targetTemperature Y:0.0] forKey:@"inputTargetNeutral"];
    return ALFilterOutput(filter) ?: image;
}

static CIImage *ALApplyVignette(CIImage *image, CGFloat intensity) {
    CIFilter *filter = [CIFilter filterWithName:@"CIVignetteEffect"];
    [filter setValue:image forKey:kCIInputImageKey];
    [filter setValue:[CIVector vectorWithX:CGRectGetMidX(image.extent) Y:CGRectGetMidY(image.extent)] forKey:kCIInputCenterKey];
    [filter setValue:@(MAX(image.extent.size.width, image.extent.size.height) * 0.78) forKey:kCIInputRadiusKey];
    [filter setValue:@(intensity) forKey:kCIInputIntensityKey];
    return ALFilterOutput(filter) ?: image;
}

static CIImage *ALApplyBloom(CIImage *image, CGFloat radius, CGFloat intensity) {
    CIFilter *filter = [CIFilter filterWithName:@"CIBloom"];
    [filter setValue:image forKey:kCIInputImageKey];
    [filter setValue:@(radius) forKey:kCIInputRadiusKey];
    [filter setValue:@(intensity) forKey:kCIInputIntensityKey];
    return [ALFilterOutput(filter) imageByCroppingToRect:image.extent] ?: image;
}

static CIImage *ALFaceMask(CIImage *image, ALFaceSnapshot *face) {
    if (!face) {
        return nil;
    }

    CGRect extent = image.extent;
    CGRect faceRect = CGRectMake(CGRectGetMinX(face.boundingBox) * extent.size.width,
                                 CGRectGetMinY(face.boundingBox) * extent.size.height,
                                 CGRectGetWidth(face.boundingBox) * extent.size.width,
                                 CGRectGetHeight(face.boundingBox) * extent.size.height);
    CGPoint center = CGPointMake(CGRectGetMidX(faceRect), CGRectGetMidY(faceRect));
    CGFloat radius = MAX(CGRectGetWidth(faceRect), CGRectGetHeight(faceRect)) * 0.62;

    CIFilter *gradient = [CIFilter filterWithName:@"CIRadialGradient"];
    [gradient setValue:[CIVector vectorWithCGPoint:center] forKey:@"inputCenter"];
    [gradient setValue:@(radius * 0.42) forKey:@"inputRadius0"];
    [gradient setValue:@(radius) forKey:@"inputRadius1"];
    [gradient setValue:[CIColor colorWithRed:1.0 green:1.0 blue:1.0 alpha:1.0] forKey:@"inputColor0"];
    [gradient setValue:[CIColor colorWithRed:0.0 green:0.0 blue:0.0 alpha:0.0] forKey:@"inputColor1"];
    return [ALFilterOutput(gradient) imageByCroppingToRect:extent];
}

static CIImage *ALApplySmooth(CIImage *image, ALFaceSnapshot *face, CGFloat strength) {
    CIImage *mask = ALFaceMask(image, face);
    if (!mask) {
        return image;
    }

    CGFloat radius = MAX(2.0, MIN(9.0, MIN(image.extent.size.width, image.extent.size.height) * 0.009 * strength));
    CIFilter *blur = [CIFilter filterWithName:@"CIGaussianBlur"];
    [blur setValue:image forKey:kCIInputImageKey];
    [blur setValue:@(radius) forKey:kCIInputRadiusKey];
    CIImage *blurred = [[ALFilterOutput(blur) imageByCroppingToRect:image.extent] imageByApplyingFilter:@"CIColorControls" withInputParameters:@{kCIInputSaturationKey:@1.02, kCIInputContrastKey:@0.99}];
    if (!blurred) {
        blurred = image;
    }

    CIFilter *blend = [CIFilter filterWithName:@"CIBlendWithMask"];
    [blend setValue:blurred forKey:kCIInputImageKey];
    [blend setValue:image forKey:kCIInputBackgroundImageKey];
    [blend setValue:mask forKey:kCIInputMaskImageKey];
    return ALFilterOutput(blend) ?: image;
}

static CIImage *ALComposite(CIImage *overlay, CIImage *background) {
    if (!overlay) {
        return background;
    }
    CIFilter *filter = [CIFilter filterWithName:@"CISourceOverCompositing"];
    [filter setValue:overlay forKey:kCIInputImageKey];
    [filter setValue:background forKey:kCIInputBackgroundImageKey];
    return [[ALFilterOutput(filter) imageByCroppingToRect:background.extent] imageByClampingToExtent] ?: background;
}

static CIImage *ALAddBlush(CIImage *image, ALFaceSnapshot *face) {
    if (!face) {
        return image;
    }

    CGRect extent = image.extent;
    CGRect faceRect = CGRectMake(CGRectGetMinX(face.boundingBox) * extent.size.width,
                                 CGRectGetMinY(face.boundingBox) * extent.size.height,
                                 CGRectGetWidth(face.boundingBox) * extent.size.width,
                                 CGRectGetHeight(face.boundingBox) * extent.size.height);
    CGFloat radius = MAX(12.0, CGRectGetWidth(faceRect) * 0.12);
    CGFloat y = CGRectGetMinY(faceRect) + CGRectGetHeight(faceRect) * 0.42;
    CGFloat leftX = CGRectGetMinX(faceRect) + CGRectGetWidth(faceRect) * 0.25;
    CGFloat rightX = CGRectGetMinX(faceRect) + CGRectGetWidth(faceRect) * 0.75;

    CIImage *result = image;
    for (NSNumber *xValue in @[@(leftX), @(rightX)]) {
        CIFilter *gradient = [CIFilter filterWithName:@"CIRadialGradient"];
        [gradient setValue:[CIVector vectorWithX:xValue.doubleValue Y:y] forKey:@"inputCenter"];
        [gradient setValue:@0.0 forKey:@"inputRadius0"];
        [gradient setValue:@(radius) forKey:@"inputRadius1"];
        [gradient setValue:[CIColor colorWithRed:1.0 green:0.16 blue:0.28 alpha:0.30] forKey:@"inputColor0"];
        [gradient setValue:[CIColor colorWithRed:1.0 green:0.16 blue:0.28 alpha:0.0] forKey:@"inputColor1"];
        result = ALComposite([ALFilterOutput(gradient) imageByCroppingToRect:extent], result);
    }
    return result;
}

static CGImageRef ALCreateGlassesSticker(void) {
    size_t width = 360;
    size_t height = 132;
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    CGContextRef context = CGBitmapContextCreate(NULL, width, height, 8, width * 4, colorSpace, kCGImageAlphaPremultipliedLast);
    CGColorSpaceRelease(colorSpace);
    if (!context) {
        return NULL;
    }

    CGContextClearRect(context, CGRectMake(0.0, 0.0, width, height));
    CGContextSetLineWidth(context, 9.0);
    CGContextSetStrokeColorWithColor(context, [UIColor colorWithRed:0.05 green:0.05 blue:0.08 alpha:0.95].CGColor);
    CGContextSetFillColorWithColor(context, [UIColor colorWithRed:0.12 green:0.18 blue:0.30 alpha:0.26].CGColor);
    CGContextAddEllipseInRect(context, CGRectMake(18.0, 22.0, 142.0, 82.0));
    CGContextDrawPath(context, kCGPathFillStroke);
    CGContextAddEllipseInRect(context, CGRectMake(200.0, 22.0, 142.0, 82.0));
    CGContextDrawPath(context, kCGPathFillStroke);
    CGContextMoveToPoint(context, 160.0, 58.0);
    CGContextAddCurveToPoint(context, 174.0, 44.0, 186.0, 44.0, 200.0, 58.0);
    CGContextStrokePath(context);
    CGContextMoveToPoint(context, 18.0, 52.0);
    CGContextAddLineToPoint(context, 0.0, 38.0);
    CGContextMoveToPoint(context, 342.0, 52.0);
    CGContextAddLineToPoint(context, 360.0, 38.0);
    CGContextStrokePath(context);
    CGImageRef image = CGBitmapContextCreateImage(context);
    CGContextRelease(context);
    return image;
}

static CGImageRef ALCreateCrownSticker(void) {
    size_t width = 360;
    size_t height = 190;
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    CGContextRef context = CGBitmapContextCreate(NULL, width, height, 8, width * 4, colorSpace, kCGImageAlphaPremultipliedLast);
    CGColorSpaceRelease(colorSpace);
    if (!context) {
        return NULL;
    }

    CGContextClearRect(context, CGRectMake(0.0, 0.0, width, height));
    CGContextSetFillColorWithColor(context, [UIColor colorWithRed:1.0 green:0.70 blue:0.08 alpha:0.94].CGColor);
    CGContextSetStrokeColorWithColor(context, [UIColor colorWithRed:0.62 green:0.26 blue:0.02 alpha:1.0].CGColor);
    CGContextSetLineWidth(context, 6.0);
    CGContextMoveToPoint(context, 28.0, 28.0);
    CGContextAddLineToPoint(context, 80.0, 142.0);
    CGContextAddLineToPoint(context, 132.0, 68.0);
    CGContextAddLineToPoint(context, 180.0, 146.0);
    CGContextAddLineToPoint(context, 228.0, 68.0);
    CGContextAddLineToPoint(context, 280.0, 142.0);
    CGContextAddLineToPoint(context, 332.0, 28.0);
    CGContextAddLineToPoint(context, 310.0, 168.0);
    CGContextAddLineToPoint(context, 50.0, 168.0);
    CGContextClosePath(context);
    CGContextDrawPath(context, kCGPathFillStroke);
    CGContextSetFillColorWithColor(context, [UIColor colorWithRed:0.25 green:0.75 blue:1.0 alpha:0.95].CGColor);
    CGContextFillEllipseInRect(context, CGRectMake(65.0, 130.0, 24.0, 24.0));
    CGContextSetFillColorWithColor(context, [UIColor colorWithRed:1.0 green:0.25 blue:0.45 alpha:0.95].CGColor);
    CGContextFillEllipseInRect(context, CGRectMake(168.0, 132.0, 24.0, 24.0));
    CGContextSetFillColorWithColor(context, [UIColor colorWithRed:0.35 green:1.0 blue:0.65 alpha:0.95].CGColor);
    CGContextFillEllipseInRect(context, CGRectMake(271.0, 130.0, 24.0, 24.0));
    CGImageRef image = CGBitmapContextCreateImage(context);
    CGContextRelease(context);
    return image;
}

static CIImage *ALGlassesSticker(void) {
    static CIImage *image;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        CGImageRef cgImage = ALCreateGlassesSticker();
        if (cgImage) {
            image = [[CIImage alloc] initWithCGImage:cgImage];
            CGImageRelease(cgImage);
        }
    });
    return image;
}

static CIImage *ALCrownSticker(void) {
    static CIImage *image;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        CGImageRef cgImage = ALCreateCrownSticker();
        if (cgImage) {
            image = [[CIImage alloc] initWithCGImage:cgImage];
            CGImageRelease(cgImage);
        }
    });
    return image;
}

static CIImage *ALPlaceSticker(CIImage *background, CIImage *sticker, ALFaceSnapshot *face, BOOL crown) {
    if (!sticker || !face) {
        return background;
    }

    CGRect extent = background.extent;
    CGFloat faceWidth = CGRectGetWidth(face.boundingBox) * extent.size.width;
    CGFloat faceHeight = CGRectGetHeight(face.boundingBox) * extent.size.height;
    CGFloat stickerWidth = faceWidth * (crown ? 1.08 : 0.92);
    CGFloat stickerHeight = stickerWidth * sticker.extent.size.height / MAX(1.0, sticker.extent.size.width);
    CGFloat centerX = CGRectGetMinX(face.boundingBox) * extent.size.width + faceWidth * 0.5;
    CGFloat centerY = CGRectGetMinY(face.boundingBox) * extent.size.height + faceHeight * (crown ? 1.12 : 0.53);

    CGAffineTransform transform = CGAffineTransformIdentity;
    transform = CGAffineTransformTranslate(transform, centerX, centerY);
    transform = CGAffineTransformRotate(transform, face.roll);
    transform = CGAffineTransformScale(transform,
                                       stickerWidth / MAX(1.0, sticker.extent.size.width),
                                       stickerHeight / MAX(1.0, sticker.extent.size.height));
    transform = CGAffineTransformTranslate(transform,
                                            -sticker.extent.size.width * 0.5,
                                            -sticker.extent.size.height * 0.5);
    CIImage *placed = [sticker imageByApplyingTransform:transform];
    return ALComposite(placed, background);
}

static BOOL ALFilterNeedsFace(ALBeautyFilterStyle style) {
    return style == ALBeautyFilterStyleSmooth ||
           style == ALBeautyFilterStyleGlam ||
           style == ALBeautyFilterStyleBlush ||
           style == ALBeautyFilterStyleGlasses ||
           style == ALBeautyFilterStyleCrown ||
           style == ALBeautyFilterStyleSparkle;
}

@interface ALBeautyFilterEngine : NSObject
@property(nonatomic, assign) ALBeautyFilterStyle style;
+ (instancetype)sharedEngine;
- (CMSampleBufferRef)processedSampleBufferFromSampleBuffer:(CMSampleBufferRef)sampleBuffer;
@end

@implementation ALBeautyFilterEngine {
    CIContext *_context;
    NSUInteger _frameIndex;
    ALFaceSnapshot *_lastFace;
    CFTimeInterval _lastFaceDetectionTime;
}

+ (instancetype)sharedEngine {
    static ALBeautyFilterEngine *engine;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        engine = [[self alloc] init];
    });
    return engine;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _context = [CIContext contextWithOptions:@{kCIContextUseSoftwareRenderer:@NO}];
        _style = (ALBeautyFilterStyle)[[NSUserDefaults standardUserDefaults] integerForKey:kALSelectedFilterKey];
    }
    return self;
}

- (ALFaceSnapshot *)faceSnapshotForPixelBuffer:(CVPixelBufferRef)pixelBuffer {
    _frameIndex += 1;
    CFTimeInterval now = CACurrentMediaTime();
    BOOL shouldDetect = (_lastFace == nil) || ((_frameIndex % 4) == 0) || (now - _lastFaceDetectionTime > 0.30);
    if (!shouldDetect) {
        return _lastFace;
    }

    VNDetectFaceRectanglesRequest *request = [[VNDetectFaceRectanglesRequest alloc] init];
    VNImageRequestHandler *handler = [[VNImageRequestHandler alloc] initWithCVPixelBuffer:pixelBuffer
                                                                                    orientation:kCGImagePropertyOrientationUp
                                                                                        options:@{}];
    NSError *error = nil;
    [handler performRequests:@[request] error:&error];
    CFTimeInterval previousDetectionTime = _lastFaceDetectionTime;
    _lastFaceDetectionTime = now;

    VNFaceObservation *largestFace = nil;
    CGFloat largestArea = 0.0;
    for (VNFaceObservation *observation in request.results) {
        CGFloat area = CGRectGetWidth(observation.boundingBox) * CGRectGetHeight(observation.boundingBox);
        if (area > largestArea) {
            largestArea = area;
            largestFace = observation;
        }
    }

    if (largestFace) {
        ALFaceSnapshot *snapshot = [[ALFaceSnapshot alloc] init];
        snapshot.boundingBox = largestFace.boundingBox;
        snapshot.roll = largestFace.roll.doubleValue;
        _lastFace = snapshot;
    } else if (now - previousDetectionTime > 0.55) {
        _lastFace = nil;
    }
    return _lastFace;
}

- (CIImage *)filteredImageFromImage:(CIImage *)image face:(ALFaceSnapshot *)face {
    ALBeautyFilterStyle style = self.style;
    switch (style) {
        case ALBeautyFilterStyleSmooth:
            return ALApplySmooth(ALApplyColorControls(image, 1.04, 0.015, 1.01), face, 1.0);
        case ALBeautyFilterStyleWarm:
            return ALApplyTemperature(ALApplyColorControls(image, 1.10, 0.018, 1.03), 7200.0);
        case ALBeautyFilterStyleCool:
            return ALApplyTemperature(ALApplyColorControls(image, 0.98, 0.008, 1.05), 4800.0);
        case ALBeautyFilterStyleGlam: {
            CIImage *result = ALApplyColorControls(image, 1.08, 0.025, 1.04);
            result = ALApplySmooth(result, face, 1.15);
            result = ALApplyBloom(result, 4.0, 0.22);
            return ALApplyVignette(result, 0.20);
        }
        case ALBeautyFilterStyleBlush:
            return ALAddBlush(ALApplySmooth(ALApplyColorControls(image, 1.06, 0.012, 1.02), face, 0.85), face);
        case ALBeautyFilterStyleGlasses:
            return ALPlaceSticker(image, ALGlassesSticker(), face, NO);
        case ALBeautyFilterStyleCrown:
            return ALPlaceSticker(image, ALCrownSticker(), face, YES);
        case ALBeautyFilterStyleSparkle: {
            CIImage *result = ALApplyColorControls(image, 1.12, 0.018, 1.03);
            result = ALApplySmooth(result, face, 0.75);
            return ALApplyBloom(result, 7.0, 0.38);
        }
        case ALBeautyFilterStyleNone:
        default:
            return image;
    }
}

- (CMSampleBufferRef)processedSampleBufferFromSampleBuffer:(CMSampleBufferRef)sampleBuffer {
    if (!sampleBuffer || self.style == ALBeautyFilterStyleNone) {
        return nil;
    }

    CVPixelBufferRef inputBuffer = CMSampleBufferGetImageBuffer(sampleBuffer);
    if (!inputBuffer) {
        return nil;
    }

    CIImage *inputImage = [CIImage imageWithCVPixelBuffer:inputBuffer options:nil];
    if (!inputImage) {
        return nil;
    }

    ALFaceSnapshot *face = ALFilterNeedsFace(self.style) ? [self faceSnapshotForPixelBuffer:inputBuffer] : nil;
    CIImage *outputImage = [self filteredImageFromImage:inputImage face:face];
    if (!outputImage) {
        return nil;
    }

    size_t width = CVPixelBufferGetWidth(inputBuffer);
    size_t height = CVPixelBufferGetHeight(inputBuffer);
    CVPixelBufferRef outputBuffer = NULL;
    NSDictionary *attributes = @{
        (id)kCVPixelBufferIOSurfacePropertiesKey : @{},
        (id)kCVPixelBufferMetalCompatibilityKey : @YES,
        (id)kCVPixelBufferCGBitmapContextCompatibilityKey : @YES
    };
    CVReturn pixelBufferStatus = CVPixelBufferCreate(kCFAllocatorDefault,
                                                      width,
                                                      height,
                                                      kCVPixelFormatType_32BGRA,
                                                      (__bridge CFDictionaryRef)attributes,
                                                      &outputBuffer);
    if (pixelBufferStatus != kCVReturnSuccess || !outputBuffer) {
        return nil;
    }

    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    [_context render:[outputImage imageByCroppingToRect:inputImage.extent]
    toCVPixelBuffer:outputBuffer
             bounds:inputImage.extent
         colorSpace:colorSpace];
    CGColorSpaceRelease(colorSpace);

    CMVideoFormatDescriptionRef formatDescription = NULL;
    OSStatus formatStatus = CMVideoFormatDescriptionCreateForImageBuffer(kCFAllocatorDefault,
                                                                          outputBuffer,
                                                                          &formatDescription);
    if (formatStatus != noErr || !formatDescription) {
        CVPixelBufferRelease(outputBuffer);
        return nil;
    }

    CMSampleTimingInfo timing = {
        .duration = CMSampleBufferGetDuration(sampleBuffer),
        .presentationTimeStamp = CMSampleBufferGetPresentationTimeStamp(sampleBuffer),
        .decodeTimeStamp = CMSampleBufferGetDecodeTimeStamp(sampleBuffer)
    };
    CMSampleBufferRef outputSampleBuffer = NULL;
    OSStatus sampleStatus = CMSampleBufferCreateReadyWithImageBuffer(kCFAllocatorDefault,
                                                                       outputBuffer,
                                                                       formatDescription,
                                                                       &timing,
                                                                       &outputSampleBuffer);

    CFDictionaryRef attachments = CMCopyDictionaryOfAttachments(kCFAllocatorDefault,
                                                                  sampleBuffer,
                                                                  kCMAttachmentMode_ShouldPropagate);
    if (attachments && outputSampleBuffer) {
        CMSetAttachments(outputSampleBuffer, attachments, kCMAttachmentMode_ShouldPropagate);
    }
    if (attachments) {
        CFRelease(attachments);
    }
    CFRelease(formatDescription);
    CVPixelBufferRelease(outputBuffer);

    if (sampleStatus != noErr) {
        if (outputSampleBuffer) {
            CFRelease(outputSampleBuffer);
        }
        return nil;
    }
    return outputSampleBuffer;
}

@end

@interface ALVideoDelegateProxy : NSObject <AVCaptureVideoDataOutputSampleBufferDelegate>
@property(nonatomic, weak) id originalDelegate;
- (instancetype)initWithDelegate:(id)delegate;
@end

@implementation ALVideoDelegateProxy

- (instancetype)initWithDelegate:(id)delegate {
    self = [super init];
    if (self) {
        _originalDelegate = delegate;
    }
    return self;
}

- (void)captureOutput:(AVCaptureOutput *)captureOutput
 didOutputSampleBuffer:(CMSampleBufferRef)sampleBuffer
        fromConnection:(AVCaptureConnection *)connection {
    CMSampleBufferRef processedSampleBuffer = [[ALBeautyFilterEngine sharedEngine] processedSampleBufferFromSampleBuffer:sampleBuffer];
    id delegate = self.originalDelegate;
    if (delegate && [delegate respondsToSelector:_cmd]) {
        [delegate captureOutput:captureOutput
         didOutputSampleBuffer:processedSampleBuffer ?: sampleBuffer
                fromConnection:connection];
    }
    if (processedSampleBuffer) {
        CFRelease(processedSampleBuffer);
    }
}

- (BOOL)respondsToSelector:(SEL)selector {
    if (selector == @selector(captureOutput:didOutputSampleBuffer:fromConnection:)) {
        return YES;
    }
    return [super respondsToSelector:selector] || [self.originalDelegate respondsToSelector:selector];
}

- (id)forwardingTargetForSelector:(SEL)selector {
    if (selector == @selector(captureOutput:didOutputSampleBuffer:fromConnection:)) {
        return nil;
    }
    return self.originalDelegate;
}

@end

@interface ALFilterController : NSObject
@property(nonatomic, strong) UIButton *toggleButton;
@property(nonatomic, strong) UIView *panel;
@property(nonatomic, strong) UIScrollView *filterScrollView;
@property(nonatomic, weak) UIWindow *attachedWindow;
@property(nonatomic, assign) NSInteger activeCaptureCount;
@property(nonatomic, assign) BOOL didLoadSavedStyle;
+ (instancetype)sharedController;
- (void)captureDidStart;
- (void)captureDidStop;
@end

@implementation ALFilterController

+ (instancetype)sharedController {
    static ALFilterController *controller;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        controller = [[self alloc] init];
    });
    return controller;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        [[NSNotificationCenter defaultCenter] addObserver:self
                                                 selector:@selector(applicationDidBecomeActive:)
                                                     name:UIApplicationDidBecomeActiveNotification
                                                   object:nil];
    }
    return self;
}

- (void)applicationDidBecomeActive:(NSNotification *)notification {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (self.activeCaptureCount > 0) {
            [self installOverlayIfNeeded];
        }
    });
}

- (void)captureDidStart {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.activeCaptureCount += 1;
        [self installOverlayIfNeeded];
    });
}

- (void)captureDidStop {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.activeCaptureCount = MAX(0, self.activeCaptureCount - 1);
        if (self.activeCaptureCount == 0) {
            self.toggleButton.hidden = YES;
            self.panel.hidden = YES;
        }
    });
}

- (void)installOverlayIfNeeded {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self installOverlayIfNeeded];
        });
        return;
    }

    UIWindow *window = ALCurrentKeyWindow();
    if (!window) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            if (self.activeCaptureCount > 0) {
                [self installOverlayIfNeeded];
            }
        });
        return;
    }

    if (!self.didLoadSavedStyle) {
        NSInteger savedStyle = [[NSUserDefaults standardUserDefaults] integerForKey:kALSelectedFilterKey];
        [ALBeautyFilterEngine sharedEngine].style = (ALBeautyFilterStyle)savedStyle;
        self.didLoadSavedStyle = YES;
    }

    if (self.attachedWindow != window) {
        [self.toggleButton removeFromSuperview];
        [self.panel removeFromSuperview];
        self.toggleButton = nil;
        self.panel = nil;
        self.filterScrollView = nil;
        self.attachedWindow = window;
    }

    if (!self.toggleButton) {
        UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
        button.translatesAutoresizingMaskIntoConstraints = NO;
        button.tag = 0xA1AD;
        button.accessibilityLabel = @"فتح الفلاتر";
        button.backgroundColor = [UIColor colorWithWhite:0.04 alpha:0.88];
        button.layer.cornerRadius = 24.0;
        button.layer.borderColor = [UIColor colorWithRed:0.96 green:0.65 blue:0.20 alpha:0.85].CGColor;
        button.layer.borderWidth = 1.0;
        [button setTitle:@"✨" forState:UIControlStateNormal];
        button.titleLabel.font = [UIFont systemFontOfSize:22.0 weight:UIFontWeightSemibold];
        [button addTarget:self action:@selector(togglePanel:) forControlEvents:UIControlEventTouchUpInside];
        [window addSubview:button];
        UILayoutGuide *safeArea = window.safeAreaLayoutGuide;
        [NSLayoutConstraint activateConstraints:@[
            [button.trailingAnchor constraintEqualToAnchor:safeArea.trailingAnchor constant:-14.0],
            [button.topAnchor constraintEqualToAnchor:safeArea.topAnchor constant:14.0],
            [button.widthAnchor constraintEqualToConstant:48.0],
            [button.heightAnchor constraintEqualToConstant:48.0]
        ]];
        self.toggleButton = button;
    }

    if (!self.panel) {
        UIView *panel = [[UIView alloc] initWithFrame:CGRectZero];
        panel.translatesAutoresizingMaskIntoConstraints = NO;
        panel.backgroundColor = [UIColor colorWithWhite:0.04 alpha:0.94];
        panel.layer.cornerRadius = 18.0;
        panel.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.14].CGColor;
        panel.layer.borderWidth = 1.0;
        panel.hidden = YES;

        UILabel *title = [[UILabel alloc] initWithFrame:CGRectZero];
        title.translatesAutoresizingMaskIntoConstraints = NO;
        title.text = @"الفلاتر";
        title.textColor = UIColor.whiteColor;
        title.font = [UIFont systemFontOfSize:15.0 weight:UIFontWeightSemibold];
        title.textAlignment = NSTextAlignmentRight;
        [panel addSubview:title];

        UIScrollView *scrollView = [[UIScrollView alloc] initWithFrame:CGRectZero];
        scrollView.translatesAutoresizingMaskIntoConstraints = NO;
        scrollView.showsHorizontalScrollIndicator = NO;
        scrollView.alwaysBounceHorizontal = YES;
        [panel addSubview:scrollView];

        NSArray<NSDictionary *> *filters = @[
            @{ @"title": @"بدون", @"style": @(ALBeautyFilterStyleNone) },
            @{ @"title": @"تنعيم", @"style": @(ALBeautyFilterStyleSmooth) },
            @{ @"title": @"دافئ", @"style": @(ALBeautyFilterStyleWarm) },
            @{ @"title": @"بارد", @"style": @(ALBeautyFilterStyleCool) },
            @{ @"title": @"جلام", @"style": @(ALBeautyFilterStyleGlam) },
            @{ @"title": @"توريد", @"style": @(ALBeautyFilterStyleBlush) },
            @{ @"title": @"نظارات", @"style": @(ALBeautyFilterStyleGlasses) },
            @{ @"title": @"تاج", @"style": @(ALBeautyFilterStyleCrown) },
            @{ @"title": @"لمعة", @"style": @(ALBeautyFilterStyleSparkle) }
        ];

        CGFloat itemWidth = 72.0;
        CGFloat gap = 8.0;
        for (NSUInteger index = 0; index < filters.count; index += 1) {
            NSDictionary *item = filters[index];
            UIButton *filterButton = [UIButton buttonWithType:UIButtonTypeSystem];
            filterButton.frame = CGRectMake(8.0 + index * (itemWidth + gap), 2.0, itemWidth, 42.0);
            filterButton.tag = kALFilterButtonTagBase + [item[@"style"] integerValue];
            filterButton.layer.cornerRadius = 12.0;
            filterButton.titleLabel.font = [UIFont systemFontOfSize:12.0 weight:UIFontWeightMedium];
            filterButton.accessibilityLabel = item[@"title"];
            [filterButton setTitle:item[@"title"] forState:UIControlStateNormal];
            [filterButton addTarget:self action:@selector(filterButtonPressed:) forControlEvents:UIControlEventTouchUpInside];
            [scrollView addSubview:filterButton];
        }
        scrollView.contentSize = CGSizeMake(16.0 + filters.count * (itemWidth + gap), 46.0);

        [window addSubview:panel];
        UILayoutGuide *safeArea = window.safeAreaLayoutGuide;
        [NSLayoutConstraint activateConstraints:@[
            [panel.leadingAnchor constraintEqualToAnchor:safeArea.leadingAnchor constant:12.0],
            [panel.trailingAnchor constraintEqualToAnchor:safeArea.trailingAnchor constant:-12.0],
            [panel.bottomAnchor constraintEqualToAnchor:safeArea.bottomAnchor constant:-10.0],
            [panel.heightAnchor constraintEqualToConstant:82.0],
            [title.topAnchor constraintEqualToAnchor:panel.topAnchor constant:7.0],
            [title.trailingAnchor constraintEqualToAnchor:panel.trailingAnchor constant:-14.0],
            [title.leadingAnchor constraintEqualToAnchor:panel.leadingAnchor constant:14.0],
            [title.heightAnchor constraintEqualToConstant:20.0],
            [scrollView.leadingAnchor constraintEqualToAnchor:panel.leadingAnchor constant:7.0],
            [scrollView.trailingAnchor constraintEqualToAnchor:panel.trailingAnchor constant:-7.0],
            [scrollView.topAnchor constraintEqualToAnchor:title.bottomAnchor constant:4.0],
            [scrollView.bottomAnchor constraintEqualToAnchor:panel.bottomAnchor constant:-6.0]
        ]];
        self.panel = panel;
        self.filterScrollView = scrollView;
        [self updateFilterButtonAppearance];
    }

    self.toggleButton.hidden = self.activeCaptureCount == 0;
}

- (void)togglePanel:(UIButton *)sender {
    self.panel.hidden = !self.panel.hidden;
    if (!self.panel.hidden) {
        [self updateFilterButtonAppearance];
    }
}

- (void)filterButtonPressed:(UIButton *)sender {
    NSInteger style = sender.tag - kALFilterButtonTagBase;
    [ALBeautyFilterEngine sharedEngine].style = (ALBeautyFilterStyle)style;
    [[NSUserDefaults standardUserDefaults] setInteger:style forKey:kALSelectedFilterKey];
    [self updateFilterButtonAppearance];
    self.panel.hidden = YES;
}

- (void)updateFilterButtonAppearance {
    ALBeautyFilterStyle selectedStyle = [ALBeautyFilterEngine sharedEngine].style;
    for (UIView *view in self.filterScrollView.subviews) {
        if (![view isKindOfClass:UIButton.class]) {
            continue;
        }
        UIButton *button = (UIButton *)view;
        BOOL selected = button.tag - kALFilterButtonTagBase == selectedStyle;
        button.backgroundColor = selected ? [UIColor colorWithRed:0.95 green:0.57 blue:0.16 alpha:0.95] : [UIColor colorWithWhite:1.0 alpha:0.10];
        [button setTitleColor:selected ? UIColor.blackColor : UIColor.whiteColor forState:UIControlStateNormal];
    }
}

@end

// MARK: - Runtime hook (Cydia Substrate)

typedef void (*ALSetSampleBufferDelegateIMP)(id, SEL, id<AVCaptureVideoDataOutputSampleBufferDelegate>, dispatch_queue_t);
static ALSetSampleBufferDelegateIMP gALOriginalSetSampleBufferDelegate = NULL;
static void *kALCaptureActiveKey = &kALCaptureActiveKey;

static void ALSetSampleBufferDelegateHook(AVCaptureVideoDataOutput *self,
                                          SEL _cmd,
                                          id<AVCaptureVideoDataOutputSampleBufferDelegate> delegate,
                                          dispatch_queue_t queue) {
    if (!gALOriginalSetSampleBufferDelegate) {
        return;
    }

    if (!delegate) {
        NSNumber *wasActive = objc_getAssociatedObject(self, kALCaptureActiveKey);
        objc_setAssociatedObject(self, kALDelegateProxyKey, nil, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        objc_setAssociatedObject(self, kALCaptureActiveKey, nil, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        if (wasActive.boolValue) {
            [[ALFilterController sharedController] captureDidStop];
        }
        gALOriginalSetSampleBufferDelegate(self, _cmd, delegate, queue);
        return;
    }

    if ([delegate isKindOfClass:ALVideoDelegateProxy.class]) {
        gALOriginalSetSampleBufferDelegate(self, _cmd, delegate, queue);
        return;
    }

    ALVideoDelegateProxy *existingProxy = objc_getAssociatedObject(self, kALDelegateProxyKey);
    if (existingProxy && existingProxy.originalDelegate == delegate) {
        gALOriginalSetSampleBufferDelegate(self, _cmd, existingProxy, queue);
        return;
    }

    ALVideoDelegateProxy *proxy = [[ALVideoDelegateProxy alloc] initWithDelegate:delegate];
    objc_setAssociatedObject(self, kALDelegateProxyKey, proxy, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    NSNumber *wasActive = objc_getAssociatedObject(self, kALCaptureActiveKey);
    if (!wasActive.boolValue) {
        objc_setAssociatedObject(self, kALCaptureActiveKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        [[ALFilterController sharedController] captureDidStart];
    }
    gALOriginalSetSampleBufferDelegate(self, _cmd, proxy, queue);
}

__attribute__((constructor)) static void ALBeautyFiltersInit(void) {
    @autoreleasepool {
        NSString *bundleIdentifier = NSBundle.mainBundle.bundleIdentifier;
        if (![bundleIdentifier isEqualToString:@"com.minichat"]) {
            return;
        }

        Class outputClass = objc_getClass("AVCaptureVideoDataOutput");
        SEL selector = @selector(setSampleBufferDelegate:queue:);
        if (outputClass && class_getInstanceMethod(outputClass, selector)) {
            MSHookMessageEx(outputClass, selector, (IMP)ALSetSampleBufferDelegateHook, (IMP *)&gALOriginalSetSampleBufferDelegate);
            NSLog(@"[MOD X Beauty] camera hook installed");
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            (void)[ALFilterController sharedController];
        });
    }
}
