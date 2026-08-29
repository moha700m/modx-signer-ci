#!/usr/bin/env python3
from pathlib import Path
import sys

if len(sys.argv) != 3:
    raise SystemExit('usage: patch_webrtc.py <input.m> <output.m>')

src = Path(sys.argv[1]).read_text(encoding='utf-8')
marker = '// MARK: - Runtime hook (Cydia Substrate)'
if marker not in src:
    raise SystemExit('runtime hook marker not found')

head = src.split(marker, 1)[0]

# MiniChat's bundled WebRTC owns the AVCaptureVideoDataOutput callback. Hook that
# callback directly, but NEVER replace its CMSampleBuffer. Replacing the sample
# buffer can make RTCCameraVideoCapturer reject/drop frames because timing,
# format-description identity, attachments, and capture-pipeline expectations
# no longer match. Instead, render the filtered frame into a temporary buffer,
# copy only the pixel bytes back into the original camera pixel buffer, then
# call WebRTC with the exact original CMSampleBuffer object.
runtime = r'''// MARK: - Runtime hook (Cydia Substrate) — WebRTC-safe in-place path

typedef void (*ALRTCCaptureOutputIMP)(id, SEL, AVCaptureOutput *, CMSampleBufferRef, AVCaptureConnection *);
typedef void (*ALRTCStopCaptureIMP)(id, SEL, id);

static ALRTCCaptureOutputIMP gALOriginalRTCCaptureOutput = NULL;
static ALRTCStopCaptureIMP gALOriginalRTCStopCapture = NULL;
static void *kALRTCCaptureActiveKey = &kALRTCCaptureActiveKey;

static BOOL ALCopyPixelBufferPixels(CVPixelBufferRef source, CVPixelBufferRef destination) {
    if (!source || !destination) {
        return NO;
    }
    if (CVPixelBufferGetWidth(source) != CVPixelBufferGetWidth(destination) ||
        CVPixelBufferGetHeight(source) != CVPixelBufferGetHeight(destination) ||
        CVPixelBufferGetPixelFormatType(source) != CVPixelBufferGetPixelFormatType(destination)) {
        return NO;
    }

    CVReturn sourceLock = CVPixelBufferLockBaseAddress(source, kCVPixelBufferLock_ReadOnly);
    if (sourceLock != kCVReturnSuccess) {
        return NO;
    }

    CVReturn destinationLock = CVPixelBufferLockBaseAddress(destination, 0);
    if (destinationLock != kCVReturnSuccess) {
        CVPixelBufferUnlockBaseAddress(source, kCVPixelBufferLock_ReadOnly);
        return NO;
    }

    BOOL copied = YES;
    size_t sourcePlanes = CVPixelBufferGetPlaneCount(source);
    size_t destinationPlanes = CVPixelBufferGetPlaneCount(destination);

    if (sourcePlanes > 0 || destinationPlanes > 0) {
        if (sourcePlanes == 0 || sourcePlanes != destinationPlanes) {
            copied = NO;
        } else {
            for (size_t plane = 0; plane < sourcePlanes; plane++) {
                uint8_t *src = (uint8_t *)CVPixelBufferGetBaseAddressOfPlane(source, plane);
                uint8_t *dst = (uint8_t *)CVPixelBufferGetBaseAddressOfPlane(destination, plane);
                size_t srcStride = CVPixelBufferGetBytesPerRowOfPlane(source, plane);
                size_t dstStride = CVPixelBufferGetBytesPerRowOfPlane(destination, plane);
                size_t srcHeight = CVPixelBufferGetHeightOfPlane(source, plane);
                size_t dstHeight = CVPixelBufferGetHeightOfPlane(destination, plane);

                if (!src || !dst) {
                    copied = NO;
                    break;
                }

                size_t rows = MIN(srcHeight, dstHeight);
                size_t bytesPerRow = MIN(srcStride, dstStride);
                for (size_t row = 0; row < rows; row++) {
                    memcpy(dst + row * dstStride, src + row * srcStride, bytesPerRow);
                }
            }
        }
    } else {
        uint8_t *src = (uint8_t *)CVPixelBufferGetBaseAddress(source);
        uint8_t *dst = (uint8_t *)CVPixelBufferGetBaseAddress(destination);
        size_t srcStride = CVPixelBufferGetBytesPerRow(source);
        size_t dstStride = CVPixelBufferGetBytesPerRow(destination);
        size_t rows = MIN(CVPixelBufferGetHeight(source), CVPixelBufferGetHeight(destination));

        if (!src || !dst) {
            copied = NO;
        } else {
            size_t bytesPerRow = MIN(srcStride, dstStride);
            for (size_t row = 0; row < rows; row++) {
                memcpy(dst + row * dstStride, src + row * srcStride, bytesPerRow);
            }
        }
    }

    CVPixelBufferUnlockBaseAddress(destination, 0);
    CVPixelBufferUnlockBaseAddress(source, kCVPixelBufferLock_ReadOnly);
    return copied;
}

static void ALRTCCaptureOutputHook(id self,
                                   SEL _cmd,
                                   AVCaptureOutput *captureOutput,
                                   CMSampleBufferRef sampleBuffer,
                                   AVCaptureConnection *connection) {
    if (!gALOriginalRTCCaptureOutput) {
        return;
    }

    NSNumber *active = objc_getAssociatedObject(self, kALRTCCaptureActiveKey);
    if (!active.boolValue) {
        objc_setAssociatedObject(self, kALRTCCaptureActiveKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        [[ALFilterController sharedController] captureDidStart];
        NSLog(@"[MOD X Beauty] WebRTC camera stream detected");
    }

    // Fail-open by design: WebRTC always receives its original sample buffer.
    // If filtering/copying fails for any reason, the unmodified camera frame
    // continues normally rather than making the camera disappear.
    CMSampleBufferRef processedSampleBuffer = [[ALBeautyFilterEngine sharedEngine]
        processedSampleBufferFromSampleBuffer:sampleBuffer];

    if (processedSampleBuffer) {
        CVPixelBufferRef filteredPixelBuffer = CMSampleBufferGetImageBuffer(processedSampleBuffer);
        CVPixelBufferRef cameraPixelBuffer = CMSampleBufferGetImageBuffer(sampleBuffer);
        if (!ALCopyPixelBufferPixels(filteredPixelBuffer, cameraPixelBuffer)) {
            NSLog(@"[MOD X Beauty] frame copy skipped; preserving original camera frame");
        }
        CFRelease(processedSampleBuffer);
    }

    gALOriginalRTCCaptureOutput(self, _cmd, captureOutput, sampleBuffer, connection);
}

static void ALRTCStopCaptureHook(id self, SEL _cmd, id completionHandler) {
    NSNumber *active = objc_getAssociatedObject(self, kALRTCCaptureActiveKey);
    if (active.boolValue) {
        objc_setAssociatedObject(self, kALRTCCaptureActiveKey, nil, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        [[ALFilterController sharedController] captureDidStop];
    }

    if (gALOriginalRTCStopCapture) {
        gALOriginalRTCStopCapture(self, _cmd, completionHandler);
    }
}

__attribute__((constructor)) static void ALBeautyFiltersInit(void) {
    @autoreleasepool {
        NSString *bundleIdentifier = NSBundle.mainBundle.bundleIdentifier;
        if (![bundleIdentifier isEqualToString:@"com.minichat"]) {
            return;
        }

        Class rtcCapturerClass = objc_getClass("RTCCameraVideoCapturer");
        SEL frameSelector = sel_registerName("captureOutput:didOutputSampleBuffer:fromConnection:");

        if (rtcCapturerClass && class_getInstanceMethod(rtcCapturerClass, frameSelector)) {
            MSHookMessageEx(rtcCapturerClass,
                            frameSelector,
                            (IMP)ALRTCCaptureOutputHook,
                            (IMP *)&gALOriginalRTCCaptureOutput);
            NSLog(@"[MOD X Beauty] WebRTC-safe frame hook installed");

            SEL stopSelector = sel_registerName("stopCaptureWithCompletionHandler:");
            if (class_getInstanceMethod(rtcCapturerClass, stopSelector)) {
                MSHookMessageEx(rtcCapturerClass,
                                stopSelector,
                                (IMP)ALRTCStopCaptureHook,
                                (IMP *)&gALOriginalRTCStopCapture);
            }
        } else {
            NSLog(@"[MOD X Beauty] RTCCameraVideoCapturer not found");
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            (void)[ALFilterController sharedController];
        });
    }
}
'''

# Keep the temporary filtered buffer in the exact same pixel format as the
# incoming camera buffer, so byte-for-byte copy-back is safe for BGRA or NV12.
head = head.replace(
    'kCVPixelFormatType_32BGRA,\n                                                      (__bridge CFDictionaryRef)attributes,',
    'CVPixelBufferGetPixelFormatType(inputBuffer),\n                                                      (__bridge CFDictionaryRef)attributes,'
)

Path(sys.argv[2]).write_text(head + runtime, encoding='utf-8')
