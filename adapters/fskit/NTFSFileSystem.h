/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import <FSKit/FSKit.h>
#import "NTFSResource.h"
#include <ntfs/validate.h>

@class NTFSImageTransport;

@interface NTFSFileSystem
    : FSUnaryFileSystem <FSUnaryFileSystemOperations, FSManageableResourceMaintenanceOperations>
/* Overridable ownership/policy boundaries also permit faulted component readers. */
- (NTFSResource *)newResourceWithReader:(id<NTFSBlockReader>)reader;
/* Keep the original resource and require positive native URL scope before open. */
- (NTFSImageTransport *)newImageTransportWithResource:(FSPathURLResource *)resource
						error:(NSError **)error;
- (struct ntfs_validation_limits)validationLimits;
@end
