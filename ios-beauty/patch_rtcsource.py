#!/usr/bin/env python3
from pathlib import Path
import sys

if len(sys.argv) != 3:
    raise SystemExit('usage: patch_rtcsource.py <input.m> <output.m>')

src = Path(sys.argv[1]).read_text(encoding='utf-8')
marker = '// MARK: - Runtime hook (Cydia Substrate)'
if marker not in src:
    raise SystemExit('runtime hook marker not found')

head = src.split(marker, 1)[0]
head = head.replace('#import <objc/runtime.h>', '#import <objc/runtime.h>\n#import <objc/message.h>')

runtime = r'''// MARK: - Runtime hook (Cydia Substrate) — safe RTCVideoSource path

// Do NOT hook RTCCameraVideoCapturer or replace AVCapture callbacks here.
// MiniChat must receive its original camera sample buffers unchanged. We only
// replace the RTCVideoFrame after WebRTC has accepted the camera frame.

typedef void (*ALRTCVideoSourceFrameIMP)(id, SEL, id, id);
static ALRTCVideoSourceFrameIMP gALOriginalRTCVideoSourceFrame = NULL;
static void *kALRTCSourceActiveKey = &kALRTCSourceActiveKey;

static CMSampleBufferRef ALCreateSampleBufferForPixelBuffer(CVPixelBufferRef pixelBuffer) {
    if (!pixelBuffer) return NULL;

    CMVideoFormatDescriptionRef format = NULL;
    OSStatus fs = CMVideoFormatDescriptionCreateForImageBuffer(kCFAllocatorDefault, pixelBuffer, &format);
    if (fs != noErr || !format) return NULL;

    CMSampleTimingInfo timing = {
        .duration = kCMTimeInvalid,
        .presentationTimeStamp = kCMTimeZero,
        .decodeTimeStamp = kCMTimeInvalid
    };

    CMSampleBufferRef sample = NULL;
    OSStatus ss = CMSampleBufferCreateReadyWithImageBuffer(kCFAllocatorDefault,
                                                            pixelBuffer,
                                                            format,
                                                            &timing,
                                                            &sample);
    CFRelease(format);
    if (ss != noErr) {
        if (sample) CFRelease(sample);
        return NULL;
    }
    return sample;
}

static id ALFilteredRTCFrame(id frame) {
    if (!frame || [ALBeautyFilterEngine sharedEngine].style == ALBeautyFilterStyleNone) {
        return nil;
    }

    SEL bufferSel = sel_registerName("buffer");
    if (![frame respondsToSelector:bufferSel]) return nil;

    id bufferObj = ((id (*)(id, SEL))objc_msgSend)(frame, bufferSel);
    if (!bufferObj) return nil;

    SEL pixelSel = sel_registerName("pixelBuffer");
    if (![bufferObj respondsToSelector:pixelSel]) return nil;

    CVPixelBufferRef inputPixelBuffer = ((CVPixelBufferRef (*)(id, SEL))objc_msgSend)(bufferObj, pixelSel);
    if (!inputPixelBuffer) return nil;

    CMSampleBufferRef inputSample = ALCreateSampleBufferForPixelBuffer(inputPixelBuffer);
    if (!inputSample) return nil;

    CMSampleBufferRef processedSample = [[ALBeautyFilterEngine sharedEngine]
        processedSampleBufferFromSampleBuffer:inputSample];
    CFRelease(inputSample);

    if (!processedSample) return nil;

    CVPixelBufferRef processedPixelBuffer = CMSampleBufferGetImageBuffer(processedSample);
    if (!processedPixelBuffer) {
        CFRelease(processedSample);
        return nil;
    }
    CVPixelBufferRetain(processedPixelBuffer);
    CFRelease(processedSample);

    Class cvBufferClass = objc_getClass("RTCCVPixelBuffer");
    Class videoFrameClass = objc_getClass("RTCVideoFrame");
    if (!cvBufferClass || !videoFrameClass) {
        CVPixelBufferRelease(processedPixelBuffer);
        return nil;
    }

    id rtcBufferAlloc = ((id (*)(id, SEL))objc_msgSend)(cvBufferClass, sel_registerName("alloc"));
    id rtcBuffer = ((id (*)(id, SEL, CVPixelBufferRef))objc_msgSend)(
        rtcBufferAlloc,
        sel_registerName("initWithPixelBuffer:"),
        processedPixelBuffer
    );
    CVPixelBufferRelease(processedPixelBuffer);
    if (!rtcBuffer) return nil;

    NSInteger rotation = 0;
    int64_t timeStampNs = 0;
    SEL rotationSel = sel_registerName("rotation");
    SEL timestampSel = sel_registerName("timeStampNs");
    if ([frame respondsToSelector:rotationSel]) {
        rotation = ((NSInteger (*)(id, SEL))objc_msgSend)(frame, rotationSel);
    }
    if ([frame respondsToSelector:timestampSel]) {
        timeStampNs = ((int64_t (*)(id, SEL))objc_msgSend)(frame, timestampSel);
    }

    id frameAlloc = ((id (*)(id, SEL))objc_msgSend)(videoFrameClass, sel_registerName("alloc"));
    id filteredFrame = ((id (*)(id, SEL, id, NSInteger, int64_t))objc_msgSend)(
        frameAlloc,
        sel_registerName("initWithBuffer:rotation:timeStampNs:"),
        rtcBuffer,
        rotation,
        timeStampNs
    );
    return filteredFrame;
}

static void ALRTCVideoSourceFrameHook(id self, SEL _cmd, id capturer, id frame) {
    if (!gALOriginalRTCVideoSourceFrame) return;

    NSNumber *active = objc_getAssociatedObject(self, kALRTCSourceActiveKey);
    if (!active.boolValue) {
        objc_setAssociatedObject(self, kALRTCSourceActiveKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        [[ALFilterController sharedController] captureDidStart];
        NSLog(@"[MOD X Beauty] RTCVideoSource stream detected");
    }

    id filteredFrame = ALFilteredRTCFrame(frame);
    gALOriginalRTCVideoSourceFrame(self, _cmd, capturer, filteredFrame ?: frame);
}

__attribute__((constructor)) static void ALBeautyFiltersInit(void) {
    @autoreleasepool {
        NSString *bundleIdentifier = NSBundle.mainBundle.bundleIdentifier;
        if (![bundleIdentifier isEqualToString:@"com.minichat"]) {
            return;
        }

        Class sourceClass = objc_getClass("RTCVideoSource");
        SEL selector = sel_registerName("capturer:didCaptureVideoFrame:");
        if (sourceClass && class_getInstanceMethod(sourceClass, selector)) {
            MSHookMessageEx(sourceClass,
                            selector,
                            (IMP)ALRTCVideoSourceFrameHook,
                            (IMP *)&gALOriginalRTCVideoSourceFrame);
            NSLog(@"[MOD X Beauty] safe RTCVideoSource hook installed");
        } else {
            NSLog(@"[MOD X Beauty] RTCVideoSource hook target not found");
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            (void)[ALFilterController sharedController];
        });
    }
}
'''

Path(sys.argv[2]).write_text(head + runtime, encoding='utf-8')
