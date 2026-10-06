/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSVolume.h"

void ntfs_test_fskit_lifecycle(NSData *image, BOOL modern);
BOOL ntfs_test_modern_runtime_available(void);

/* Observe the real native eligibility result without manufacturing kernel
 * publication counts. The separate model exercises both eligibility outcomes. */
@protocol NTFSTestReclaimObservation
@property NSUInteger reclaimAttempts;
@property BOOL reclaimAccepted;
@end

@interface NTFSTestLegacyVolume : NTFSLegacyVolume <NTFSTestReclaimObservation>
@property NSUInteger reclaimAttempts;
@property BOOL reclaimAccepted;
@end

#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
API_AVAILABLE(macos(27.0))
@interface NTFSTestModernVolume : NTFSModernVolume <NTFSTestReclaimObservation>
@property NSUInteger reclaimAttempts;
@property BOOL reclaimAccepted;
@end
#endif
