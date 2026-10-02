/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "fskit_lifecycle.h"
#import "NTFSVolume.h"
#include "fixture.h"
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <time.h>

enum {
	TEST_LIFECYCLE_TIMEOUT_SECONDS = 5,
	TEST_LIFECYCLE_STATE_POLL_NANOSECONDS = NSEC_PER_MSEC,
	TEST_LIFECYCLE_UNUSED_BYTE = 0xa5,
	TEST_INTERLEAVED_FIRST_CAPACITY = 1,
	TEST_INTERLEAVED_SECOND_CAPACITY = 2
};

enum lifecycle_scenario {
	TEST_UNMOUNT_BLOCKED_READ,
	TEST_INVALIDATE_BLOCKED_READ,
	TEST_REPEAT_UNMOUNT_BLOCKED_READ,
	TEST_UNMOUNT_INVALIDATE_BLOCKED_READ,
	TEST_RECLAIM_BLOCKED_READ,
	TEST_REVOKE_BLOCKED_READ,
	TEST_FAILED_BLOCKED_READ,
	TEST_SHORT_BLOCKED_READ,
	TEST_LIFECYCLE_SCENARIOS
};

static dispatch_time_t
test_deadline(void)
{
	return dispatch_time(DISPATCH_TIME_NOW, TEST_LIFECYCLE_TIMEOUT_SECONDS * NSEC_PER_SEC);
}

static void
test_wait(dispatch_semaphore_t semaphore)
{
	assert(dispatch_semaphore_wait(semaphore, test_deadline()) == 0);
}

/* Poll a synchronized state transition, never infer admission from a delay. */
static void
test_wait_for_state(NTFSVolume *volume, NTFSVolumeLifecycle state)
{
	struct timespec start, now;
	const struct timespec interval = {0, TEST_LIFECYCLE_STATE_POLL_NANOSECONDS};

	assert(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
	while (volume.lifecycle != state) {
		assert(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
		assert(now.tv_sec - start.tv_sec < TEST_LIFECYCLE_TIMEOUT_SECONDS);
		nanosleep(&interval, NULL);
	}
}

@interface LifecycleReader : NSObject <NTFSBlockReader>
@property NSData *image;
@property(getter=isRevoked) BOOL revoked;
@property BOOL failed;
@property BOOL shortRead;
@property BOOL blockNextRead;
@property NSUInteger reads;
@property dispatch_semaphore_t entered;
@property dispatch_semaphore_t resume;
@end

@implementation LifecycleReader

- (uint64_t)blockSize
{
	return TEST_SECTOR_BYTES;
}

- (uint64_t)physicalBlockSize
{
	return TEST_PHYSICAL_BLOCK_BYTES;
}

- (uint64_t)blockCount
{
	return self.image.length / self.blockSize;
}

- (size_t)readInto:(void *)buffer
	startingAt:(off_t)offset
	    length:(size_t)length
	     error:(NSError **)error
{
	BOOL blocked;

	assert(offset >= 0 && (uint64_t)offset % TEST_PHYSICAL_BLOCK_BYTES == 0);
	assert(length % TEST_PHYSICAL_BLOCK_BYTES == 0);
	assert((uintptr_t)buffer % TEST_PHYSICAL_BLOCK_BYTES == 0);
	assert((uint64_t)offset <= self.image.length);
	assert(length <= self.image.length - (size_t)offset);
	@synchronized(self) {
		self.reads++;
		blocked = self.blockNextRead;
		self.blockNextRead = NO;
	}
	if (blocked) {
		dispatch_semaphore_signal(self.entered);
		test_wait(self.resume);
	}
	if (self.failed) {
		*error = [NSError errorWithDomain:NSPOSIXErrorDomain code:EIO userInfo:nil];
		return 0;
	}
	/* Revocation deliberately permits a late successful device return. The
	 * production owner must reject it before copying its aligned window. */
	memcpy(buffer, (const uint8_t *)self.image.bytes + (size_t)offset, length);
	return self.shortRead ? length - 1 : length;
}

@end

@interface LifecycleResource : NTFSResource
@property NSUInteger liveAllocations;
@end

@implementation LifecycleResource

- (void *)allocateSize:(size_t)size
{
	void *bytes;

	@synchronized(self) {
		bytes = [super allocateSize:size];
		if (bytes != NULL) {
			self.liveAllocations++;
		}
	}
	return bytes;
}

- (void)releaseBytes:(void *)bytes size:(size_t)size
{
	@synchronized(self) {
		if (bytes != NULL) {
			assert(self.liveAllocations != 0);
			self.liveAllocations--;
		}
		[super releaseBytes:bytes size:size];
	}
}

@end

/* The SDK creates its mutable buffers. This double exercises the Objective-C
 * buffer boundary only; it is not an installed kernel-buffer test. */
@interface LifecycleBuffer : NSObject
@property NSMutableData *data;
@property(readonly) NSUInteger length;
- (void *)mutableBytes;
@end

@implementation LifecycleBuffer

- (NSUInteger)length
{
	return self.data.length;
}

- (void *)mutableBytes
{
	return self.data.mutableBytes;
}

@end

@interface LifecycleReply : NSObject
@property NSUInteger count;
@property NSInteger errorCode;
@property size_t completed;
- (void)record:(NSError *)error completed:(size_t)completed;
@end

@implementation LifecycleReply

- (void)record:(NSError *)error completed:(size_t)completed
{
	@synchronized(self) {
		assert(self.count == 0);
		self.errorCode = error.code;
		self.completed = completed;
		self.count++;
	}
}

@end

@interface LifecyclePacker : NSObject
@property NSUInteger capacity;
@property NSMutableArray<NSString *> *names;
@property FSDirectoryCookie cookie;
@end

static void
test_read_request(
    NTFSVolume *volume, FSItem *item, LifecycleBuffer *buffer, BOOL modern, LifecycleReply *reply)
{
	if (modern) {
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
		if (@available(macOS 27.0, *)) {
			[(NTFSModernVolume *)volume
			    readFromFile:item
				  offset:0
				  length:buffer.length
			      intoBuffer:(FSMutableFileDataBuffer *)buffer
			    replyHandler:^(FSReadFileResult *result, NSError *error) {
			      assert((result != nil) == (error == nil));
			      [reply record:error completed:0];
			    }];
			return;
		}
#endif
		assert(!"modern runtime was not admitted");
	} else {
		[(NTFSLegacyVolume *)volume readFromFile:item
						  offset:0
						  length:buffer.length
					      intoBuffer:(FSMutableFileDataBuffer *)buffer
					    replyHandler:^(size_t completed, NSError *error) {
					      [reply record:error completed:completed];
					    }];
	}
}

static void
test_deactivate_request(NTFSVolume *volume, BOOL modern, LifecycleReply *reply)
{
	if (modern) {
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
		if (@available(macOS 27.0, *)) {
			[(NTFSModernVolume *)volume deactivateVolumeWithOptions:0
								   replyHandler:^(NSError *error) {
								     [reply record:error
									 completed:0];
								   }];
			return;
		}
#endif
		assert(!"modern runtime was not admitted");
	} else {
		[(NTFSLegacyVolume *)volume deactivateWithOptions:0
						     replyHandler:^(NSError *error) {
						       [reply record:error completed:0];
						     }];
	}
}

static NTFSVolume *
test_new_volume(struct ntfs_volume *core, NTFSResource *resource, BOOL modern)
{
	if (modern) {
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
		if (@available(macOS 27.0, *)) {
			return [[NTFSModernVolume alloc] initWithCore:core resource:resource];
		}
#endif
		assert(!"modern runtime was not admitted");
		return nil;
	}
	return [[NTFSLegacyVolume alloc] initWithCore:core resource:resource];
}

static void
test_pattern(NSData *data)
{
	const uint8_t *bytes = data.bytes;
	size_t i;

	for (i = 0; i < data.length; i++) {
		assert(bytes[i] == (uint8_t)(i * TEST_PATTERN_MULTIPLIER + TEST_PATTERN_ADDEND));
	}
}

static void
test_blocked_read(NSData *image, BOOL modern, enum lifecycle_scenario scenario)
{
	LifecycleReader *reader = [[LifecycleReader alloc] init];
	LifecycleResource *resource;
	LifecycleBuffer *buffer = [[LifecycleBuffer alloc] init];
	LifecycleBuffer *queuedBuffer = [[LifecycleBuffer alloc] init];
	LifecycleReply *readReply = [[LifecycleReply alloc] init];
	LifecycleReply *controlReply = [[LifecycleReply alloc] init];
	LifecycleReply *additionalControlReply = [[LifecycleReply alloc] init];
	LifecycleReply *queuedReply = [[LifecycleReply alloc] init];
	NTFSVolume *volume;
	struct ntfs_environment env;
	struct ntfs_volume *core = NULL;
	FSItem *root, *file, *resident, *compressed;
	LifecyclePacker *warmPage;
	FSFileName *stored;
	NSError *error = nil;
	dispatch_group_t workers = dispatch_group_create();
	dispatch_queue_t queue = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0);
	dispatch_semaphore_t controlEntered = dispatch_semaphore_create(0);
	NSUInteger live, reads;
	size_t completed, i;
	uint8_t *bytes;
	NSInteger expectedError;
	BOOL unmounting = scenario == TEST_UNMOUNT_BLOCKED_READ ||
	    scenario == TEST_REPEAT_UNMOUNT_BLOCKED_READ ||
	    scenario == TEST_UNMOUNT_INVALIDATE_BLOCKED_READ;
	BOOL invalidating = scenario == TEST_INVALIDATE_BLOCKED_READ ||
	    scenario == TEST_UNMOUNT_INVALIDATE_BLOCKED_READ;
	BOOL closing = unmounting || invalidating;

	reader.image = image;
	reader.entered = dispatch_semaphore_create(0);
	reader.resume = dispatch_semaphore_create(0);
	resource = [[LifecycleResource alloc] initWithReader:reader];
	env = [resource environment];
	assert(ntfs_mount(&env, NULL, &core) == NTFS_OK);
	volume = test_new_volume(core, resource, modern);
	assert(volume != nil && volume.lifecycle == NTFSVolumeLoaded);
	[volume mountWithOptions:nil
		    replyHandler:^(NSError *e) {
		      assert(e.code == ESTALE);
		    }];
	root = [volume activate:&error];
	assert(root != nil && error == nil && volume.lifecycle == NTFSVolumeActive);
	file = [volume lookup:[FSFileName nameWithString:@"fragmented.bin"]
		  inDirectory:root
		   storedName:&stored
			error:&error];
	resident = [volume lookup:[FSFileName nameWithString:@"hello.txt"]
		      inDirectory:root
		       storedName:&stored
			    error:&error];
	assert(file != nil && resident != nil && error == nil);
	buffer.data = [NSMutableData dataWithLength:TEST_READ_WINDOW_BYTES];
	queuedBuffer.data = [NSMutableData dataWithLength:TEST_READ_WINDOW_BYTES];
	assert([volume readItem:file
			 offset:0
			  bytes:buffer.mutableBytes
			 length:buffer.length
		      completed:&completed] == NTFS_OK &&
	    completed == buffer.length);
	test_pattern(buffer.data);
	/* Fill all transient cache kinds before testing the drain boundary. */
	compressed = [volume lookup:[FSFileName nameWithString:@"compressed.bin"]
			inDirectory:root
			 storedName:&stored
			      error:&error];
	assert(compressed != nil && error == nil);
	assert([volume readItem:compressed
			 offset:0
			  bytes:buffer.mutableBytes
			 length:buffer.length
		      completed:&completed] == NTFS_OK &&
	    completed == buffer.length);
	assert([volume xattrsForItem:root error:&error] != nil && error == nil);
	warmPage = [[LifecyclePacker alloc] init];
	warmPage.capacity = TEST_INTERLEAVED_FIRST_CAPACITY;
	warmPage.names = [NSMutableArray array];
	assert([volume enumerate:root
			  cookie:0
			verifier:0
		      attributes:YES
			  packer:(FSDirectoryEntryPacker *)warmPage] == nil);
	memset(buffer.mutableBytes, TEST_LIFECYCLE_UNUSED_BYTE, buffer.length);
	live = resource.liveAllocations;
	reader.blockNextRead = YES;
	dispatch_group_async(workers, queue, ^{
	  @autoreleasepool {
		  test_read_request(volume, file, buffer, modern, readReply);
	  }
	});
	test_wait(reader.entered);
	reads = reader.reads;
	assert(readReply.count == 0);
	if (unmounting) {
		dispatch_group_async(workers, queue, ^{
		  [volume unmountWithReplyHandler:^{
		    dispatch_semaphore_t inspected = dispatch_semaphore_create(0);

		    /* A reply must let a different thread inspect the drained owner. */
		    dispatch_async(queue, ^{
		      NSError *e = nil;

		      assert([volume attributes:root error:&e] == nil && e.code == ESTALE);
		      dispatch_semaphore_signal(inspected);
		    });
		    test_wait(inspected);
		    [controlReply record:nil completed:0];
		  }];
		});
		test_wait_for_state(volume, NTFSVolumeDraining);
		if (scenario == TEST_REPEAT_UNMOUNT_BLOCKED_READ) {
			dispatch_group_async(workers, queue, ^{
			  dispatch_semaphore_signal(controlEntered);
			  [volume unmountWithReplyHandler:^{
			    [additionalControlReply record:nil completed:0];
			  }];
			});
			test_wait(controlEntered);
		} else if (invalidating) {
			dispatch_group_async(workers, queue, ^{
			  test_deactivate_request(volume, modern, additionalControlReply);
			});
			test_wait_for_state(volume, NTFSVolumeInvalidating);
		}
	} else if (scenario == TEST_INVALIDATE_BLOCKED_READ) {
		dispatch_group_async(workers, queue, ^{
		  test_deactivate_request(volume, modern, controlReply);
		});
		test_wait_for_state(volume, NTFSVolumeInvalidating);
	} else if (scenario == TEST_RECLAIM_BLOCKED_READ) {
		dispatch_group_async(workers, queue, ^{
		  dispatch_semaphore_signal(controlEntered);
		  [volume reclaimItem:file
			 replyHandler:^(NSError *e) {
			   [controlReply record:e completed:0];
			 }];
		});
		test_wait(controlEntered);
	} else if (scenario == TEST_REVOKE_BLOCKED_READ) {
		reader.revoked = YES;
	} else if (scenario == TEST_FAILED_BLOCKED_READ) {
		reader.failed = YES;
	} else {
		assert(scenario == TEST_SHORT_BLOCKED_READ);
		reader.shortRead = YES;
	}
	if (closing) {
		dispatch_group_async(workers, queue, ^{
		  test_read_request(volume, resident, queuedBuffer, modern, queuedReply);
		});
	}
	/* No read callback or cleanup may run while the device owns its window. */
	assert(readReply.count == 0 && controlReply.count == 0 && queuedReply.count == 0 &&
	    additionalControlReply.count == 0);
	assert(resource.liveAllocations == live);
	dispatch_semaphore_signal(reader.resume);
	assert(dispatch_group_wait(workers, test_deadline()) == 0);
	expectedError = closing ? ESTALE : scenario == TEST_RECLAIM_BLOCKED_READ ? 0 : EIO;
	assert(readReply.count == 1 && readReply.errorCode == expectedError);
	if (!modern) {
		assert(readReply.completed == (expectedError == 0 ? buffer.length : 0));
	}
	assert(reader.reads == reads);
	if (closing) {
		assert(controlReply.count == 1 && controlReply.errorCode == 0);
		assert(queuedReply.count == 1 && queuedReply.errorCode == ESTALE);
		assert(queuedReply.completed == 0);
		assert(volume.lifecycle ==
		    (invalidating ? NTFSVolumeInvalidated : NTFSVolumeUnmounted));
		if (scenario == TEST_REPEAT_UNMOUNT_BLOCKED_READ ||
		    scenario == TEST_UNMOUNT_INVALIDATE_BLOCKED_READ) {
			assert(additionalControlReply.count == 1 &&
			    additionalControlReply.errorCode == 0);
		}
		assert([volume readItem:file
				 offset:0
				  bytes:buffer.mutableBytes
				 length:buffer.length
			      completed:&completed] == NTFS_STALE &&
		    completed == 0);
	} else if (scenario == TEST_RECLAIM_BLOCKED_READ) {
		assert(controlReply.count == 1 && controlReply.errorCode == 0);
		test_pattern(buffer.data);
		assert([volume readItem:file
				 offset:0
				  bytes:buffer.mutableBytes
				 length:buffer.length
			      completed:&completed] == NTFS_STALE &&
		    completed == 0);
	} else {
		bytes = buffer.mutableBytes;
		for (i = 0; i < buffer.length; i++) {
			assert(bytes[i] == TEST_LIFECYCLE_UNUSED_BYTE);
		}
		reader.failed = NO;
		reader.shortRead = NO;
		reader.revoked = NO;
		if (scenario == TEST_REVOKE_BLOCKED_READ) {
			assert(!resource.isAvailable);
			assert([volume readItem:resident
					 offset:0
					  bytes:buffer.mutableBytes
					 length:buffer.length
				      completed:&completed] == NTFS_IO &&
			    completed == 0 && reader.reads == reads);
		} else {
			assert([volume readItem:file
					 offset:0
					  bytes:buffer.mutableBytes
					 length:buffer.length
				      completed:&completed] == NTFS_OK &&
			    completed == buffer.length);
			test_pattern(buffer.data);
		}
	}
	if (unmounting && !invalidating) {
		assert(resource.liveAllocations < live && resource.liveAllocations != 0);
		[volume unmountWithReplyHandler:^{
		  assert(volume.lifecycle == NTFSVolumeUnmounted);
		}];
		[volume mountWithOptions:nil
			    replyHandler:^(NSError *e) {
			      assert(e == nil && volume.lifecycle == NTFSVolumeActive);
			    }];
		assert([volume lookup:[FSFileName nameWithString:@"fragmented.bin"]
			   inDirectory:root
			    storedName:&stored
				 error:&error] == file &&
		    error == nil);
		assert([volume readItem:file
				 offset:0
				  bytes:buffer.mutableBytes
				 length:buffer.length
			      completed:&completed] == NTFS_OK &&
		    completed == buffer.length);
		test_pattern(buffer.data);
	}
	reads = reader.reads;
	[volume invalidate];
	[volume invalidate];
	assert(volume.lifecycle == NTFSVolumeInvalidated);
	assert(resource.liveAllocations == 0 && reader.reads == reads);
	[volume mountWithOptions:nil
		    replyHandler:^(NSError *e) {
		      assert(e.code == ESTALE);
		    }];
	assert([volume activate:&error] == nil && error.code == ESTALE);
}

@implementation LifecyclePacker

- (BOOL)packEntryWithName:(FSFileName *)name
		 itemType:(FSItemType)type
		   itemID:(FSItemID)itemID
	       nextCookie:(FSDirectoryCookie)cookie
	       attributes:(FSItemAttributes *)attributes
{
	assert(type == FSItemTypeFile && itemID != FSItemIDInvalid);
	assert(attributes != nil && attributes.fileID == itemID);
	if (self.names.count == self.capacity) {
		return NO;
	}
	[self.names addObject:name.string];
	self.cookie = cookie;
	return YES;
}

@end

static void
test_interleaved_enumeration(NSData *image, BOOL modern)
{
	LifecycleReader *reader = [[LifecycleReader alloc] init];
	LifecycleResource *resource;
	NTFSVolume *volume;
	struct ntfs_environment env;
	struct ntfs_volume *core = NULL;
	FSItem *root;
	NSError *error = nil;
	LifecyclePacker *page;
	NSMutableArray<NSString *> *first = [NSMutableArray array];
	NSMutableArray<NSString *> *second = [NSMutableArray array];
	NSArray<NSString *> *const expected = @[
		@"compressed.bin", @"extended.bin", @"fragmented.bin", @"hello.txt", @"middle.dat",
		@"sparse.bin", @"streamed.txt", @"tail.bin", @"Ωmega.txt"
	];
	FSDirectoryCookie firstCookie = 0, secondCookie = 0;
	NSUInteger round;

	reader.image = image;
	resource = [[LifecycleResource alloc] initWithReader:reader];
	env = [resource environment];
	assert(ntfs_mount(&env, NULL, &core) == NTFS_OK);
	volume = test_new_volume(core, resource, modern);
	root = [volume activate:&error];
	assert(root != nil && error == nil);
	for (round = 0; round <= TEST_FILE_COUNT; round++) {
		page = [[LifecyclePacker alloc] init];
		page.capacity = TEST_INTERLEAVED_FIRST_CAPACITY;
		page.names = [NSMutableArray array];
		assert([volume enumerate:root
				  cookie:firstCookie
				verifier:firstCookie == 0 ? 0 : volume.directoryVerifier
			      attributes:YES
				  packer:(FSDirectoryEntryPacker *)page] == nil);
		[first addObjectsFromArray:page.names];
		if (page.names.count != 0) {
			firstCookie = page.cookie;
		}
		/* Rewinding a third empty packer must not consume either continuation. */
		page = [[LifecyclePacker alloc] init];
		page.names = [NSMutableArray array];
		assert([volume enumerate:root
				  cookie:0
				verifier:0
			      attributes:YES
				  packer:(FSDirectoryEntryPacker *)page] == nil);
		assert(page.names.count == 0 && page.cookie == 0);
		page = [[LifecyclePacker alloc] init];
		page.capacity = TEST_INTERLEAVED_SECOND_CAPACITY;
		page.names = [NSMutableArray array];
		assert([volume enumerate:root
				  cookie:secondCookie
				verifier:secondCookie == 0 ? 0 : volume.directoryVerifier
			      attributes:YES
				  packer:(FSDirectoryEntryPacker *)page] == nil);
		[second addObjectsFromArray:page.names];
		if (page.names.count != 0) {
			secondCookie = page.cookie;
		}
	}
	assert([first isEqualToArray:expected] && [second isEqualToArray:expected]);
	assert(firstCookie == TEST_FILE_COUNT && secondCookie == TEST_FILE_COUNT);
	[volume unmountWithReplyHandler:^{
	}];
	[volume reclaimItem:root
	       replyHandler:^(NSError *e) {
		 assert(e == nil);
	       }];
	[volume invalidate];
	assert(resource.liveAllocations == 0);
}

void
ntfs_test_fskit_lifecycle(NSData *image, BOOL modern)
{
	enum lifecycle_scenario scenario;

	if (modern) {
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
		if (@available(macOS 27.0, *)) {
			/* The actual result classes are required for modern reply checks. */
		} else {
			puts("SKIP: modern lifecycle requires the macOS 27 runtime");
			return;
		}
#else
		puts("SKIP: modern lifecycle requires the macOS 27 SDK and runtime");
		return;
#endif
	}
	for (scenario = 0; scenario < TEST_LIFECYCLE_SCENARIOS; scenario++) {
		test_blocked_read(image, modern, scenario);
	}
	test_interleaved_enumeration(image, modern);
	printf("PASS: %s lifecycle, eight gated-read scenarios, exactly-once replies, "
	       "admission/drain, cache release, permanent revocation and interleaved cookies\n",
	    modern ? "modern" : "legacy");
}
