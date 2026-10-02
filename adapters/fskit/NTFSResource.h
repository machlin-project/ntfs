/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import <FSKit/FSKit.h>
#include <ntfs/ntfs.h>

enum {
	NTFS_RESOURCE_WINDOW = 1048576,
	NTFS_CORE_MEMORY_LIMIT = 64 * 1048576,
	NTFS_RESOURCE_MIN_ALIGNMENT = 512,
	NTFS_RESOURCE_MAX_ALIGNMENT = 65536
};

@protocol NTFSBlockReader <NSObject>
@property(readonly) uint64_t blockSize;
@property(readonly) uint64_t blockCount;
@property(readonly) uint64_t physicalBlockSize;
@property(readonly, getter=isRevoked) BOOL revoked;
- (size_t)readInto:(void *)buffer
	startingAt:(off_t)offset
	    length:(size_t)length
	     error:(NSError **)error;
@end

@interface NTFSResource : NSObject
- (instancetype)initWithReader:(id<NTFSBlockReader>)reader;
- (struct ntfs_environment)environment;
- (void *)allocateSize:(size_t)size;
- (void)releaseBytes:(void *)bytes size:(size_t)size;
/* Synchronous exact read. Failed reads may alter bytes inside the requested span;
 * callers must discard them. No bytes outside that span are transferred there. */
- (enum ntfs_result)readAt:(uint64_t)offset bytes:(void *)buffer length:(size_t)length;
/* Revocation permanently fails this owner; cleanup remains valid. */
@property(readonly, getter=isAvailable) BOOL available;
@end

NSError *ntfs_error(enum ntfs_result result);
/* Modern handlers require a result on success; failed construction is EIO.
 * Preserve an existing operation error, including its domain and metadata. */
NSError *ntfs_native_result_error(id result, NSError *error);
NSUUID *ntfs_uuid(uint64_t serial);
