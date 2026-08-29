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

# Keep the full filter engine/UI, but route frames at WebRTC's actual
# RTCCameraVideoCapturer callback instead of proxying AVCaptureVideoDataOutput.
# This is more deterministic for MiniChat because its bundled WebRTC framework
# implements this exact delegate callback.
runtime = r'''// MARK: - Runtime hook (Cydia Substrate) — direct WebRTC path

typedef void (*ALRTCCaptureOutputIMP)(id, SEL, AVCaptureOutput *, CMSampleBufferRef, AVCaptureConnection *);
typedef void (*ALRTCStopCaptureIMP)(id, SEL, id);

static ALRTCCaptureOutputIMP gALOriginalRTCCaptureOutput = NULL;
static ALRTCStopCaptureIMP gALOriginalRTCStopCapture = NULL;
static void *kALRTCCaptureActiveKey = &kALRTCCaptureActiveKey;

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

    CMSampleBufferRef processedSampleBuffer = [[ALBeautyFilterEngine sharedEngine]
        processedSampleBufferFromSampleBuffer:sampleBuffer];

    gALOriginalRTCCaptureOutput(self,
                                _cmd,
                                captureOutput,
                                processedSampleBuffer ?: sampleBuffer,
                                connection);

    if (processedSampleBuffer) {
        CFRelease(processedSampleBuffer);
    }
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
            NSLog(@"[MOD X Beauty] direct WebRTC frame hook installed");

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

# The original implementation emitted BGRA unconditionally. WebRTC supports
# CVPixelBuffer-backed frames, but retaining the incoming pixel format when
# Core Image can render it avoids an unnecessary format transition. For NV12
# buffers, Core Image can render directly on iOS; BGRA inputs remain BGRA.
head = head.replace(
    'kCVPixelFormatType_32BGRA,\n                                                      (__bridge CFDictionaryRef)attributes,',
    'CVPixelBufferGetPixelFormatType(inputBuffer),\n                                                      (__bridge CFDictionaryRef)attributes,'
)

Path(sys.argv[2]).write_text(head + runtime, encoding='utf-8')
