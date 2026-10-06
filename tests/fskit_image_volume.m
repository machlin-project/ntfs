/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "fskit_image_volume.h"
#import "NTFSImageVolume.h"
#include <assert.h>
#include <errno.h>
#include <string.h>

enum {
	TEST_IMAGE_FILE_OFFSET = 123,
	TEST_IMAGE_WRITE_BARRIERS = 10,
	TEST_IMAGE_FILE_NANOSECONDS = 661343100,
	TEST_IMAGE_READ_SAMPLE = 64,
	TEST_IMAGE_SHORT_DIVISOR = 2,
	TEST_IMAGE_DRAIN_WAIT_SECONDS = 5
};

typedef NS_ENUM(NSUInteger, ImageVolumeCase) {
	ImageVolumeNormal,
	ImageVolumeAllocationFailure,
	ImageVolumeShortWrite,
	ImageVolumeReentrantUnmount,
	ImageVolumeReentrantInvalidate,
	ImageVolumeCaseCount
};

#define TEST_IMAGE_FILE_TIME UINT64_C(134357146906613431)
#define TEST_IMAGE_FILE_SECONDS INT64_C(1791241090)

/* Component peers expose the public resource properties. Installed sandbox
 * authorization remains a separate native test, as for the transport suite. */
@interface ImageVolumePathResource : FSPathURLResource
@end

@implementation ImageVolumePathResource

- (BOOL)isRevoked
{
	return NO;
}

@end

@interface NTFSImageTransport (ImageVolumeTestHooks)
- (void *)allocateSize:(size_t)size;
- (enum ntfs_result)readAt:(uint64_t)offset bytes:(void *)bytes length:(size_t)length;
- (enum ntfs_result)transferWriteAt:(uint64_t)offset
			      bytes:(const void *)bytes
			     length:(size_t)length
			  completed:(size_t *)completed;
- (enum ntfs_result)transferPersist;
@end

@interface ImageVolumeTransport : NTFSImageTransport
@property BOOL denyAllocations, shortWrite;
@property NSUInteger nativeWrites, nativeBarriers, denyAfterBarrier;
@property(copy) void (^nextRead)(void);
@property(copy) void (^nextWrite)(void);
@end

@implementation ImageVolumeTransport

- (void *)allocateSize:(size_t)size
{
	return _denyAllocations ? NULL : [super allocateSize:size];
}

- (enum ntfs_result)readAt:(uint64_t)offset bytes:(void *)bytes length:(size_t)length
{
	void (^callback)(void) = _nextRead;

	_nextRead = nil;
	if (callback != nil) {
		callback();
	}
	return [super readAt:offset bytes:bytes length:length];
}

- (enum ntfs_result)transferWriteAt:(uint64_t)offset
			      bytes:(const void *)bytes
			     length:(size_t)length
			  completed:(size_t *)completed
{
	void (^callback)(void) = _nextWrite;

	_nextWrite = nil;
	if (callback != nil) {
		callback();
	}
	_nativeWrites++;
	return [super transferWriteAt:offset
				bytes:bytes
			       length:_shortWrite ? length / TEST_IMAGE_SHORT_DIVISOR : length
			    completed:completed];
}

- (enum ntfs_result)transferPersist
{
	enum ntfs_result result;

	_nativeBarriers++;
	result = [super transferPersist];
	if (_denyAfterBarrier != 0 && _nativeBarriers == _denyAfterBarrier) {
		_denyAllocations = YES;
		_denyAfterBarrier = 0;
	}
	return result;
}

@end

static FSItem *
lookup_item(NTFSVolume *volume, FSItem *root, NSString *name)
{
	FSFileName *stored = nil;
	FSItem *item;
	NSError *error = nil;

	item = [volume lookup:[FSFileName nameWithString:name]
		  inDirectory:root
		   storedName:&stored
			error:&error];
	assert(item != nil && stored != nil && error == nil);
	return item;
}

static void
image_volume_case(
    NSString *path, NSData *source, NSData *payload, NSData *expected, ImageVolumeCase mode)
{
	__attribute__((objc_precise_lifetime)) ImageVolumeTransport *transport;
	__weak ImageVolumeTransport *callbackTransport;
	ImageVolumePathResource *peer;
	NTFSVolume *volume;
	FSItem *root, *file, *resident, *again;
	FSItemAttributes *before, *after;
	NSArray<FSFileName *> *xattrs, *freshXattrs;
	NSMutableData *read = [NSMutableData dataWithLength:payload.length];
	NSData *uncertain;
	uint8_t sample[TEST_IMAGE_READ_SAMPLE];
	size_t completed, committed;
	NSUInteger writes, barriers, index;
	dispatch_semaphore_t drained = dispatch_semaphore_create(0);
	__block BOOL unmounted = NO, mounted = NO, synced = NO;
	NSError *error = nil;
	enum ntfs_result result;

	assert([NSFileManager.defaultManager createFileAtPath:path
						     contents:source
						   attributes:@{
							   NSFilePosixPermissions : @0600
						   }]);
	peer = [[ImageVolumePathResource alloc] initWithURL:[NSURL fileURLWithPath:path]
						   writable:YES];
	transport = [[ImageVolumeTransport alloc] initWithResource:peer error:&error];
	assert(transport != nil && error == nil);
	callbackTransport = transport;
	volume = ntfs_image_volume_create(transport, &error);
	assert(volume != nil && error == nil && transport.isClaimed);
	root = [volume activateExtraction:&error];
	assert(root != nil && error == nil);
	file = lookup_item(volume, root, @"fragmented.bin");
	resident = lookup_item(volume, root, @"hello.txt");
	before = [volume attributes:file error:&error];
	assert(before != nil && error == nil);
	xattrs = [volume xattrsForItem:file error:&error];
	assert(xattrs != nil && error == nil);
	assert([volume readItem:file
			 offset:TEST_IMAGE_FILE_OFFSET
			  bytes:sample
			 length:sizeof(sample)
		      completed:&completed] == NTFS_OK &&
	    completed == sizeof(sample));
	writes = transport.nativeWrites;
	transport.nextRead = ^{
	  size_t nested = SIZE_MAX;

	  assert([volume overwriteImageItem:file
				     offset:TEST_IMAGE_FILE_OFFSET
				      bytes:payload.bytes
				     length:payload.length
				   fileTime:TEST_IMAGE_FILE_TIME
				  completed:&nested] == NTFS_BUSY &&
	      nested == 0);
	};
	assert([volume readItem:file
			 offset:TEST_IMAGE_FILE_OFFSET
			  bytes:sample
			 length:sizeof(sample)
		      completed:&completed] == NTFS_OK &&
	    completed == sizeof(sample));
	assert(transport.nextRead == nil && transport.nativeWrites == writes);
	transport.shortWrite = mode == ImageVolumeShortWrite;
	if (mode == ImageVolumeAllocationFailure) {
		transport.denyAfterBarrier = transport.nativeBarriers + TEST_IMAGE_WRITE_BARRIERS;
	}
	if (mode == ImageVolumeReentrantUnmount || mode == ImageVolumeReentrantInvalidate) {
		transport.nextWrite = ^{
		  ImageVolumeTransport *retainedTransport = callbackTransport;
		  size_t nested = SIZE_MAX;
		  uint8_t sample[TEST_IMAGE_READ_SAMPLE];

		  assert(volume.lifecycle == NTFSVolumeWriting && retainedTransport.isClaimed);
		  if (mode == ImageVolumeReentrantUnmount) {
			  [volume unmountWithReplyHandler:^{
			    unmounted = YES;
			    dispatch_semaphore_signal(drained);
			  }];
			  assert(!unmounted && volume.lifecycle == NTFSVolumeDraining);
		  } else {
			  [volume invalidate];
			  assert(volume.lifecycle == NTFSVolumeInvalidating);
		  }
		  assert(retainedTransport.isClaimed);
		  assert([volume readItem:file
				   offset:TEST_IMAGE_FILE_OFFSET
				    bytes:sample
				   length:sizeof(sample)
				completed:&nested] == NTFS_STALE &&
		      nested == 0);
		  assert([volume overwriteImageItem:file
					     offset:TEST_IMAGE_FILE_OFFSET
					      bytes:payload.bytes
					     length:payload.length
					   fileTime:TEST_IMAGE_FILE_TIME
					  completed:&nested] == NTFS_STALE &&
		      nested == 0);
		};
	}
	result = [volume overwriteImageItem:file
				     offset:TEST_IMAGE_FILE_OFFSET
				      bytes:payload.bytes
				     length:payload.length
				   fileTime:TEST_IMAGE_FILE_TIME
				  completed:&completed];
	committed = completed;
	if (mode == ImageVolumeReentrantInvalidate) {
		assert(result == NTFS_OK && committed == payload.length);
		assert(volume.lifecycle == NTFSVolumeInvalidated && !transport.isClaimed);
		assert([[NSData dataWithContentsOfFile:path] isEqualToData:expected]);
		assert([volume attributes:file error:&error] == nil && error.code == ESTALE);
		assert([volume overwriteImageItem:file
					   offset:TEST_IMAGE_FILE_OFFSET
					    bytes:payload.bytes
					   length:payload.length
					 fileTime:TEST_IMAGE_FILE_TIME
					completed:&completed] == NTFS_STALE &&
		    completed == 0);
	} else if (mode == ImageVolumeShortWrite) {
		assert(result == NTFS_IO && committed == 0 && !transport.isAvailable);
		writes = transport.nativeWrites;
		barriers = transport.nativeBarriers;
		uncertain = [NSData dataWithContentsOfFile:path];
		assert([volume attributes:file error:&error] == nil && error.code == EIO);
		assert([volume readItem:file
				 offset:TEST_IMAGE_FILE_OFFSET
				  bytes:sample
				 length:sizeof(sample)
			      completed:&completed] == NTFS_IO &&
		    completed == 0);
		assert([volume overwriteImageItem:file
					   offset:TEST_IMAGE_FILE_OFFSET
					    bytes:payload.bytes
					   length:payload.length
					 fileTime:TEST_IMAGE_FILE_TIME
					completed:&completed] == NTFS_IO &&
		    completed == 0);
		assert(transport.nativeWrites == writes && transport.nativeBarriers == barriers);
		assert([[NSData dataWithContentsOfFile:path] isEqualToData:uncertain]);
	} else {
		assert(result == NTFS_OK && committed == payload.length);
		assert([[NSData dataWithContentsOfFile:path] isEqualToData:expected]);
		if (mode == ImageVolumeAllocationFailure) {
			assert(transport.denyAllocations);
			assert(
			    [volume attributes:file error:&error] == nil && error.code == ENOMEM);
			assert([volume readItem:file
					 offset:TEST_IMAGE_FILE_OFFSET
					  bytes:sample
					 length:sizeof(sample)
				      completed:&completed] == NTFS_NO_MEMORY &&
			    completed == 0);
			[volume synchronizeWithFlags:0
					replyHandler:^(NSError *failure) {
					  assert(failure == nil);
					  synced = YES;
					}];
			assert(synced && committed == payload.length);
			transport.denyAllocations = NO;
		} else {
			/* Remount after mutation must also reopen an absent immutable view. */
			if (mode == ImageVolumeReentrantUnmount) {
				assert(dispatch_semaphore_wait(drained,
					   dispatch_time(DISPATCH_TIME_NOW,
					       TEST_IMAGE_DRAIN_WAIT_SECONDS * NSEC_PER_SEC)) == 0);
			} else {
				[volume unmountWithReplyHandler:^{
				  unmounted = YES;
				}];
			}
			assert(unmounted && volume.lifecycle == NTFSVolumeUnmounted);
			[volume mountWithOptions:nil
				    replyHandler:^(NSError *failure) {
				      assert(failure == nil);
				      mounted = YES;
				    }];
			assert(mounted && volume.lifecycle == NTFSVolumeActive);
		}
		assert([volume attributes:root error:&error] != nil && error == nil);
		if (mode == ImageVolumeAllocationFailure) {
			/* The new view exists, but this held file's node is still unbound. */
			transport.denyAllocations = YES;
			assert(
			    [volume attributes:file error:&error] == nil && error.code == ENOMEM);
			transport.denyAllocations = NO;
		}
		after = [volume attributes:file error:&error];
		assert(after != nil && error == nil && after.fileID == before.fileID);
		assert(after.modifyTime.tv_sec == TEST_IMAGE_FILE_SECONDS &&
		    after.modifyTime.tv_nsec == TEST_IMAGE_FILE_NANOSECONDS &&
		    after.changeTime.tv_sec == TEST_IMAGE_FILE_SECONDS &&
		    after.changeTime.tv_nsec == TEST_IMAGE_FILE_NANOSECONDS);
		again = lookup_item(volume, root, @"fragmented.bin");
		assert(again == file && lookup_item(volume, root, @"hello.txt") == resident);
		assert([volume attributes:resident error:&error] != nil && error == nil);
		freshXattrs = [volume xattrsForItem:file error:&error];
		assert(freshXattrs != nil && error == nil && freshXattrs.count == xattrs.count);
		/* FSFileName instances can be recreated when a catalog closes. Compare
		 * the native name bytes, without imposing NSObject pointer equality. */
		for (index = 0; index < xattrs.count; index++) {
			assert([freshXattrs[index].data isEqualToData:xattrs[index].data]);
		}
		assert([volume readItem:file
				 offset:TEST_IMAGE_FILE_OFFSET
				  bytes:read.mutableBytes
				 length:read.length
			      completed:&completed] == NTFS_OK &&
		    completed == payload.length && [read isEqualToData:payload]);
		assert([[NSData dataWithContentsOfFile:path] isEqualToData:expected]);
	}
	[volume invalidate];
	assert(volume.lifecycle == NTFSVolumeInvalidated && !transport.isClaimed);
	assert([NSFileManager.defaultManager removeItemAtPath:path error:&error]);
}

void
ntfs_test_fskit_image_volume(NSString *fixtures)
{
	NSString *directory = [NSTemporaryDirectory()
	    stringByAppendingPathComponent:[@"machlin-ntfs-image-volume-"
					       stringByAppendingString:NSUUID.UUID.UUIDString]];
	NSString *path = [directory stringByAppendingPathComponent:@"owned.img"];
	NSData *source =
	    [NSData dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:@"source.img"]];
	NSData *payload = [NSData
	    dataWithContentsOfFile:[fixtures
				       stringByAppendingPathComponent:@"execute-payload.input"]];
	NSData *expected = [NSData
	    dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:@"execute-final.img"]];
	ImageVolumeCase mode;
	NSError *error = nil;

	assert(source != nil && payload != nil && expected != nil);
	assert([NSFileManager.defaultManager createDirectoryAtPath:directory
				       withIntermediateDirectories:NO
							attributes:@{
								NSFilePosixPermissions : @0700
							}
							     error:&error]);
	for (mode = ImageVolumeNormal; mode < ImageVolumeCaseCount; mode++) {
		@autoreleasepool {
			image_volume_case(path, source, payload, expected, mode);
		}
	}
	assert([NSFileManager.defaultManager removeItemAtPath:directory error:&error]);
	printf("PASS: private FSKit image item identity, view replacement, allocation retry, "
	       "mutation drain and poison\n");
}
