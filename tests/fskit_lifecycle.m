/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "fskit_lifecycle.h"
#import "NTFSVolume.h"
#include "fixture.h"
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
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

BOOL
ntfs_test_native_reclaim_available(void)
{
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
	if (@available(macOS 27.0, *)) {
		return YES;
	}
#endif
	return NO;
}

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
@property void *caller;
@property BOOL blockedDirect;
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
		if (blocked) {
			self.blockedDirect = buffer == self.caller;
		}
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
	 * production owner must reject it before reporting a successful read. */
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
@interface LifecycleBuffer : NSObject {
	void *_alignedBytes;
}
@property NSMutableData *data;
@property(readonly) NSUInteger length;
- (instancetype)initAligned;
- (NSData *)snapshot;
- (void *)mutableBytes;
@end

@implementation LifecycleBuffer

- (instancetype)initAligned
{
	self = [super init];
	if (self != nil) {
		assert(posix_memalign(&_alignedBytes, TEST_PHYSICAL_BLOCK_BYTES,
			   TEST_PHYSICAL_BLOCK_BYTES) == 0);
	}
	return self;
}

- (void)dealloc
{
	free(_alignedBytes);
}

- (NSUInteger)length
{
	return _alignedBytes != NULL ? TEST_PHYSICAL_BLOCK_BYTES : self.data.length;
}

- (NSData *)snapshot
{
	/* NSMutableData may rehome a bytes-no-copy allocation on mutable access.
	 * The fake native buffer owns its aligned bytes; test snapshots are copies. */
	return _alignedBytes != NULL ? [NSData dataWithBytes:_alignedBytes length:self.length]
				     : self.data;
}

- (void *)mutableBytes
{
	return _alignedBytes != NULL ? _alignedBytes : self.data.mutableBytes;
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

/* A controllable native eligibility boundary, not FSKit's kernel counters. */
@interface ReclaimModelVolume : NTFSLegacyVolume
@property BOOL eligible;
@property BOOL publicationOpen;
@property NSUInteger attempts;
@property NSUInteger cleanups;
@end

@implementation ReclaimModelVolume

- (BOOL)reclaimIfEligible:(FSItem *)item cleanup:(void (^)(void))cleanup
{
	(void)item;
	assert(!self.publicationOpen);
	self.attempts++;
	if (!self.eligible) {
		return NO;
	}
	cleanup();
	self.cleanups++;
	return YES;
}

@end

static ReclaimModelVolume *
test_reclaim_volume(
    NSData *image, LifecycleResource **resourceOut, LifecycleReader **readerOut, FSItem **rootOut)
{
	LifecycleReader *reader = [[LifecycleReader alloc] init];
	LifecycleResource *resource;
	ReclaimModelVolume *volume;
	struct ntfs_environment env;
	struct ntfs_limits limits;
	struct ntfs_volume *core = NULL;
	NSError *error = nil;

	reader.image = image;
	resource = [[LifecycleResource alloc] initWithReader:reader];
	env = [resource environment];
	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	assert(ntfs_mount(&env, &limits, &core) == NTFS_OK);
	volume = [[ReclaimModelVolume alloc] initWithCore:core resource:resource];
	assert(volume != nil);
	*rootOut = [volume activate:&error];
	assert(*rootOut != nil && error == nil);
	*resourceOut = resource;
	*readerOut = reader;
	return volume;
}

static void
test_held_item(NSData *image)
{
	LifecycleResource *resource;
	LifecycleReader *reader;
	ReclaimModelVolume *volume;
	FSItem *root;
	__weak FSItem *released;
	FSFileName *stored;
	NSError *error = nil;
	NSUInteger baseline, reads;
	size_t completed;
	uint8_t byte;

	volume = test_reclaim_volume(image, &resource, &reader, &root);
	baseline = resource.liveAllocations;
	@autoreleasepool {
		FSItem *file, *again, *replacement;
		LifecycleReply *deferred = [[LifecycleReply alloc] init];
		LifecycleReply *accepted = [[LifecycleReply alloc] init];
		LifecycleReply *stale = [[LifecycleReply alloc] init];
		FSItemID identity;

		file = [volume lookup:[FSFileName nameWithString:@"hello.txt"]
			  inDirectory:root
			   storedName:&stored
				error:&error];
		assert(file != nil && error == nil);
		identity = [volume attributes:file error:&error].fileID;
		released = file;
		assert([volume readItem:file
				 offset:0
				  bytes:&byte
				 length:sizeof(byte)
			      completed:&completed] == NTFS_OK &&
		    completed == sizeof(byte) && byte == 'H');
		reads = reader.reads;
		[volume reclaimItem:file
		       replyHandler:^(NSError *e) {
			 [deferred record:e completed:0];
		       }];
		assert(deferred.count == 1 && deferred.errorCode == 0);
		assert(volume.attempts == 1 && volume.cleanups == 0 && reader.reads == reads);
		assert([volume readItem:file
				 offset:0
				  bytes:&byte
				 length:sizeof(byte)
			      completed:&completed] == NTFS_OK &&
		    byte == 'H' && reader.reads == reads);
		again = [volume lookup:[FSFileName nameWithString:@"HELLO.TXT"]
			   inDirectory:root
			    storedName:&stored
				 error:&error];
		assert(again == file && error == nil);
		volume.eligible = YES;
		reads = reader.reads;
		[volume reclaimItem:file
		       replyHandler:^(NSError *e) {
			 [accepted record:e completed:0];
		       }];
		assert(accepted.count == 1 && accepted.errorCode == 0);
		assert(volume.attempts == 2 && volume.cleanups == 1 && reader.reads == reads);
		assert([volume readItem:file
				 offset:0
				  bytes:&byte
				 length:sizeof(byte)
			      completed:&completed] == NTFS_STALE &&
		    completed == 0);
		[volume reclaimItem:file
		       replyHandler:^(NSError *e) {
			 [stale record:e completed:0];
		       }];
		assert(stale.count == 1 && stale.errorCode == ESTALE && volume.attempts == 2);
		replacement = [volume lookup:[FSFileName nameWithString:@"hello.txt"]
				 inDirectory:root
				  storedName:&stored
				       error:&error];
		assert(replacement != nil && replacement != file && error == nil);
		assert([volume attributes:replacement error:&error].fileID == identity);
	}
	assert(released == nil && resource.liveAllocations == baseline);
	reads = reader.reads;
	[volume invalidate];
	assert(resource.liveAllocations == 0 && reader.reads == reads);
}

static void
test_last_item_owner(NSData *image)
{
	LifecycleResource *resource = nil;
	LifecycleReader *reader = nil;
	__weak NTFSVolume *owner;
	__attribute__((objc_precise_lifetime)) FSItem *file = nil;
	NSUInteger reads;

	@autoreleasepool {
		ReclaimModelVolume *volume;
		FSItem *root;
		FSFileName *stored;
		NSError *error = nil;

		volume = test_reclaim_volume(image, &resource, &reader, &root);
		file = [volume lookup:[FSFileName nameWithString:@"hello.txt"]
			  inDirectory:root
			   storedName:&stored
				error:&error];
		assert(file != nil && error == nil);
		owner = volume;
	}
	assert(owner != nil && owner.lifecycle == NTFSVolumeActive);
	reads = reader.reads;
	@autoreleasepool {
		file = nil;
	}
	assert(owner == nil && resource.liveAllocations == 0 && reader.reads == reads);
}

enum publication_action {
	TEST_PUBLICATION_RECLAIM,
	TEST_PUBLICATION_UNMOUNT,
	TEST_PUBLICATION_DEACTIVATE,
	TEST_PUBLICATION_ACTIONS
};

static void
test_publication_race(NSData *image, enum publication_action action)
{
	LifecycleResource *resource;
	LifecycleReader *reader;
	ReclaimModelVolume *volume;
	FSItem *root, *file;
	FSFileName *stored;
	NSError *error = nil;
	LifecycleReply *publicationReply = [[LifecycleReply alloc] init];
	LifecycleReply *controlReply = [[LifecycleReply alloc] init];
	dispatch_group_t workers = dispatch_group_create();
	dispatch_queue_t queue = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0);
	dispatch_semaphore_t entered = dispatch_semaphore_create(0);
	dispatch_semaphore_t resume = dispatch_semaphore_create(0);
	dispatch_semaphore_t controlStarted = dispatch_semaphore_create(0);
	dispatch_semaphore_t inspected = dispatch_semaphore_create(0);
	NSUInteger live;

	volume = test_reclaim_volume(image, &resource, &reader, &root);
	file = [volume lookup:[FSFileName nameWithString:@"hello.txt"]
		  inDirectory:root
		   storedName:&stored
			error:&error];
	assert(file != nil && error == nil);
	volume.eligible = YES;
	live = resource.liveAllocations;
	dispatch_group_async(workers, queue, ^{
	  [volume
	      lookupItemNamed:[FSFileName nameWithString:@"hello.txt"]
		  inDirectory:root
		 replyHandler:^(FSItem *item, FSFileName *name, NSError *e) {
		   assert(item == file && [name.string isEqualToString:@"hello.txt"] && e == nil);
		   volume.publicationOpen = YES;
		   dispatch_semaphore_signal(entered);
		   test_wait(resume);
		   volume.publicationOpen = NO;
		   [publicationReply record:e completed:0];
		 }];
	});
	test_wait(entered);
	dispatch_group_async(workers, queue, ^{
	  dispatch_semaphore_signal(controlStarted);
	  if (action == TEST_PUBLICATION_RECLAIM) {
		  [volume reclaimItem:file
			 replyHandler:^(NSError *e) {
			   [controlReply record:e completed:0];
			 }];
	  } else if (action == TEST_PUBLICATION_UNMOUNT) {
		  [volume unmountWithReplyHandler:^{
		    [controlReply record:nil completed:0];
		  }];
	  } else {
		  assert(action == TEST_PUBLICATION_DEACTIVATE);
		  [volume deactivateWithOptions:0
				   replyHandler:^(NSError *e) {
				     [controlReply record:e completed:0];
				   }];
	  }
	});
	test_wait(controlStarted);
	if (action != TEST_PUBLICATION_RECLAIM) {
		test_wait_for_state(volume,
		    action == TEST_PUBLICATION_UNMOUNT ? NTFSVolumeDraining
						       : NTFSVolumeInvalidating);
	}
	/* An item publication does not hold the core operation monitor. */
	dispatch_group_async(workers, queue, ^{
	  NSError *e = nil;
	  FSItemAttributes *attributes = [volume attributes:file error:&e];

	  if (action == TEST_PUBLICATION_RECLAIM) {
		  assert(attributes != nil && e == nil);
	  } else {
		  assert(attributes == nil && e.code == ESTALE);
	  }
	  dispatch_semaphore_signal(inspected);
	});
	test_wait(inspected);
	assert(publicationReply.count == 0 && controlReply.count == 0);
	assert(volume.attempts == 0 && volume.cleanups == 0);
	assert(resource.liveAllocations == live);
	dispatch_semaphore_signal(resume);
	assert(dispatch_group_wait(workers, test_deadline()) == 0);
	assert(
	    publicationReply.count == 1 && controlReply.count == 1 && controlReply.errorCode == 0);
	if (action == TEST_PUBLICATION_RECLAIM) {
		assert(volume.attempts == 1 && volume.cleanups == 1);
		assert([volume attributes:file error:&error] == nil && error.code == ESTALE);
	} else {
		assert(volume.attempts == 0 && volume.cleanups == 0);
	}
	[volume invalidate];
	assert(resource.liveAllocations == 0);
}

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

static LifecycleBuffer *
test_read_buffer(BOOL aligned)
{
	LifecycleBuffer *buffer;

	if (aligned) {
		return [[LifecycleBuffer alloc] initAligned];
	}
	buffer = [[LifecycleBuffer alloc] init];
	buffer.data = [NSMutableData dataWithLength:TEST_READ_WINDOW_BYTES];
	return buffer;
}

static void
test_blocked_read(NSData *image, BOOL modern, enum lifecycle_scenario scenario, BOOL directBuffer)
{
	LifecycleReader *reader = [[LifecycleReader alloc] init];
	LifecycleResource *resource;
	LifecycleBuffer *buffer = test_read_buffer(directBuffer);
	LifecycleBuffer *queuedBuffer = test_read_buffer(directBuffer);
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
	assert([volume readItem:file
			 offset:0
			  bytes:buffer.mutableBytes
			 length:buffer.length
		      completed:&completed] == NTFS_OK &&
	    completed == buffer.length);
	test_pattern([buffer snapshot]);
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
	reader.caller = buffer.mutableBytes;
	reader.blockNextRead = YES;
	dispatch_group_async(workers, queue, ^{
	  @autoreleasepool {
		  test_read_request(volume, file, buffer, modern, readReply);
	  }
	});
	test_wait(reader.entered);
	if (reader.blockedDirect != directBuffer) {
		fprintf(stderr,
		    "lifecycle route mismatch: scenario=%u aligned=%u length=%lu "
		    "caller_alignment_remainder=%lu direct=%u\n",
		    (unsigned)scenario, (unsigned)directBuffer, (unsigned long)buffer.length,
		    (unsigned long)((uintptr_t)buffer.mutableBytes % TEST_PHYSICAL_BLOCK_BYTES),
		    (unsigned)reader.blockedDirect);
	}
	assert(reader.blockedDirect == directBuffer);
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
		test_pattern([buffer snapshot]);
		assert([volume readItem:file
				 offset:0
				  bytes:buffer.mutableBytes
				 length:buffer.length
			      completed:&completed] ==
		    (ntfs_test_native_reclaim_available() ? NTFS_STALE : NTFS_OK));
		assert(completed == (ntfs_test_native_reclaim_available() ? 0 : buffer.length));
	} else {
		if (directBuffer && scenario != TEST_FAILED_BLOCKED_READ) {
			/* Late direct device fills remain invalid: the reply above reports
			 * an error and zero completed bytes, despite modified caller bytes. */
			test_pattern([buffer snapshot]);
		} else {
			bytes = buffer.mutableBytes;
			for (i = 0; i < buffer.length; i++) {
				assert(bytes[i] == TEST_LIFECYCLE_UNUSED_BYTE);
			}
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
			test_pattern([buffer snapshot]);
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
		test_pattern([buffer snapshot]);
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
	enum publication_action action;

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
		test_blocked_read(image, modern, scenario, NO);
		test_blocked_read(image, modern, scenario, YES);
	}
	test_interleaved_enumeration(image, modern);
	if (!modern) {
		test_held_item(image);
		test_last_item_owner(image);
		for (action = 0; action < TEST_PUBLICATION_ACTIONS; action++) {
			test_publication_race(image, action);
		}
		puts("PASS: modeled conditional reclaim, weak identity/last-item ownership and "
		     "lookup publication against reclaim/unmount/deactivation");
	}
	printf("PASS: %s lifecycle, 16 gated direct/window-read scenarios, exactly-once replies, "
	       "admission/drain, cache release, permanent revocation and interleaved cookies\n",
	    modern ? "modern" : "legacy");
}
