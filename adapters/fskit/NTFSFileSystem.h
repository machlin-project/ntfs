/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import <FSKit/FSKit.h>
#import "NTFSResource.h"
#include <ntfs/validate.h>

@interface NTFSFileSystem
    : FSUnaryFileSystem <FSUnaryFileSystemOperations, FSManageableResourceMaintenanceOperations>
/* Overridable ownership/policy boundaries also permit faulted component readers. */
- (NTFSResource *)newResourceWithReader:(id<NTFSBlockReader>)reader;
- (struct ntfs_validation_limits)validationLimits;
@end
