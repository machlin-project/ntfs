/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import <FSKit/FSKit.h>
#include <ntfs/ntfs.h>

@protocol NTFSBlockReader <NSObject>
@property(readonly) uint64_t blockSize;
@property(readonly) uint64_t blockCount;
@property(readonly) uint64_t physicalBlockSize;
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
- (enum ntfs_result)readAt:(uint64_t)offset bytes:(void *)buffer length:(size_t)length;
@end

NSError *ntfs_error(enum ntfs_result result);
NSUUID *ntfs_uuid(uint64_t serial);
FSFileName *ntfs_filename(const uint16_t *units, size_t length);
