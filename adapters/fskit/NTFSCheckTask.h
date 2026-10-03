/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSResource.h"
#include <ntfs/validate.h>

enum {
	NTFS_CHECK_PROGRESS_UNITS = 1,
	NTFS_CHECK_CANCEL_DRAIN_SECONDS = 5,
	NTFS_CHECK_OPTION_LIMIT = 16
};

/* Admission is checked before and after reads and before allocation. The caller
 * serializes run against the volume/resource's other allocator and read users.
 * Cancellation never releases storage borrowed by an outstanding exact read. */
@interface NTFSCheckTask : NSObject
- (instancetype)initWithResource:(NTFSResource *)resource
			   quick:(BOOL)quick
		       admission:(enum ntfs_result (^)(void))admission
			  limits:(const struct ntfs_validation_limits *)limits;
- (enum ntfs_result)run;
- (void)cancel;
/* Seal after run has released all diagnostic children and physical read scopes.
 * Cancellation wins until sealing; later requests cannot change the verdict. */
- (NSError *)sealResult:(enum ntfs_result)result;
- (BOOL)validationReport:(struct ntfs_validation_report *)report;
@property(readonly) BOOL cancelled;
@property(readonly) enum ntfs_result result;
@end
