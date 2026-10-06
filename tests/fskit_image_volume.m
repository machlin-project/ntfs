/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "fskit_image_volume.h"
#import "NTFSImageVolume.h"
#import "NTFSFileSystem.h"
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

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
	ImageVolumeReentrantDeactivate,
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

#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
/* Numeric component subjects test operation boundaries. They do not establish
 * authenticated FSContext delivery from the installed kernel. */
API_AVAILABLE(macos(27.0))
@interface ImageCallerContext : NSObject
@property NSInteger realUserID, effectiveUserID;
@end

@implementation ImageCallerContext

- (BOOL)isKindOfClass:(Class)type
{
	return type == FSContext.class || [super isKindOfClass:type];
}

@end
#endif

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
@property(copy) void (^nextPersist)(void);
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
	void (^callback)(void) = _nextPersist;
	enum ntfs_result result;

	_nextPersist = nil;
	if (callback != nil) {
		callback();
	}
	_nativeBarriers++;
	result = [super transferPersist];
	if (_denyAfterBarrier != 0 && _nativeBarriers == _denyAfterBarrier) {
		_denyAllocations = YES;
		_denyAfterBarrier = 0;
	}
	return result;
}

@end

static BOOL probeScopeAllowed;
static NSUInteger probeScopeStarts, probeScopeStops;

@interface ImageProbeTransport : ImageVolumeTransport
@end

@implementation ImageProbeTransport

- (BOOL)beginSecurityScopeForURL:(NSURL *)url
{
	assert(url.isFileURL);
	probeScopeStarts++;
	return probeScopeAllowed;
}

- (void)endSecurityScopeForURL:(NSURL *)url
{
	assert(url.isFileURL);
	probeScopeStops++;
}

@end

@interface ImageProbeFileSystem : NTFSFileSystem
@property(strong) ImageProbeTransport *lastTransport;
@property(copy) void (^transportReady)(ImageProbeTransport *);
@end

@implementation ImageProbeFileSystem

- (NTFSImageTransport *)newImageTransportWithResource:(FSPathURLResource *)resource
						error:(NSError **)error
{
	self.lastTransport = [[ImageProbeTransport alloc] initWithResource:resource
						      requireSecurityScope:YES
								     error:error];
	if (self.lastTransport != nil && self.transportReady != nil) {
		self.transportReady(self.lastTransport);
	}
	return self.lastTransport;
}

@end

@interface ImageWriteReply : NSObject
@property(strong) FSItemAttributes *attributes;
@property size_t bytes;
@end

@implementation ImageWriteReply
@end

@interface ImageControllerOptions : NSObject
@property(copy) NSArray<NSString *> *taskOptions;
@end

@implementation ImageControllerOptions
@end

static NTFSVolume *
controller_load(ImageProbeFileSystem *filesystem, FSPathURLResource *resource,
    NSArray<NSString *> *arguments, NSInteger expected)
{
	ImageControllerOptions *options = [[ImageControllerOptions alloc] init];
	__block NTFSVolume *loaded = nil;
	__block NSUInteger replies = 0;

	options.taskOptions = arguments;
	[filesystem loadResource:resource
			 options:(FSTaskOptions *)options
		    replyHandler:^(FSVolume *volume, NSError *failure) {
		      assert(expected == 0 ? failure == nil
					   : [failure.domain isEqual:NSPOSIXErrorDomain] &&
				  failure.code == expected);
		      assert((volume != nil) == (expected == 0));
		      loaded = (NTFSVolume *)volume;
		      replies++;
		    }];
	assert(replies == 1);
	return loaded;
}

static void
controller_unload(NTFSFileSystem *filesystem, FSResource *resource, NSInteger expected)
{
	ImageControllerOptions *options = [[ImageControllerOptions alloc] init];
	__block NSUInteger replies = 0;

	options.taskOptions = @[];
	[filesystem unloadResource:resource
			   options:(FSTaskOptions *)options
		      replyHandler:^(NSError *failure) {
			assert(expected == 0 ? failure == nil
					     : [failure.domain isEqual:NSPOSIXErrorDomain] &&
				    failure.code == expected);
			replies++;
		      }];
	assert(replies == 1);
}

static void
image_probe_case(NSString *path, NSData *source)
{
	ImageProbeFileSystem *filesystem = [[ImageProbeFileSystem alloc] init];
	ImageVolumePathResource *resource;
	NSString *missing = [path stringByAppendingString:@".missing"];
	NSError *error = nil;
	__block NSUInteger replies = 0;

	assert([NSFileManager.defaultManager createFileAtPath:path
						     contents:source
						   attributes:@{
							   NSFilePosixPermissions : @0600
						   }]);
	resource = [[ImageVolumePathResource alloc] initWithURL:[NSURL fileURLWithPath:missing]
						       writable:YES];
	probeScopeAllowed = NO;
	probeScopeStarts = probeScopeStops = 0;
	[filesystem probeResource:resource
		     replyHandler:^(FSProbeResult *result, NSError *failure) {
		       assert(result == nil && failure.code == EACCES);
		       replies++;
		     }];
	assert(replies == 1 && probeScopeStarts == 1 && probeScopeStops == 0 &&
	    filesystem.lastTransport == nil);
	probeScopeAllowed = YES;
	resource = [[ImageVolumePathResource alloc] initWithURL:[NSURL fileURLWithPath:path]
						       writable:YES];
	[filesystem
	    probeResource:resource
	     replyHandler:^(FSProbeResult *result, NSError *failure) {
	       assert(result != nil && failure == nil && result.result == FSMatchResultUsable &&
		   [result.name isEqualToString:@"NTFS"] && result.containerID != nil);
	       replies++;
	     }];
	assert(replies == 2 && probeScopeStarts == 2 && probeScopeStops == 0 &&
	    filesystem.lastTransport != nil && !filesystem.lastTransport.isClaimed &&
	    filesystem.lastTransport.isAvailable && filesystem.lastTransport.nativeWrites == 0 &&
	    filesystem.lastTransport.nativeBarriers == 0);
	filesystem.lastTransport = nil;
	assert(probeScopeStops == 1);
	resource = [[ImageVolumePathResource alloc] initWithURL:[NSURL fileURLWithPath:missing]
						       writable:YES];
	[filesystem probeResource:resource
		     replyHandler:^(FSProbeResult *result, NSError *failure) {
		       assert(result == nil && failure.code == ENOENT);
		       replies++;
		     }];
	assert(replies == 3 && probeScopeStarts == 3 && probeScopeStops == 2 &&
	    filesystem.lastTransport == nil);
	resource = [[ImageVolumePathResource alloc] initWithURL:[NSURL fileURLWithPath:path]
						       writable:NO];
	[filesystem probeResource:resource
		     replyHandler:^(FSProbeResult *result, NSError *failure) {
		       assert(result == nil && failure.code == EROFS);
		       replies++;
		     }];
	assert(replies == 4 && probeScopeStarts == 3 && probeScopeStops == 2 &&
	    filesystem.lastTransport == nil);
	assert([[NSData dataWithContentsOfFile:path] isEqualToData:source]);
	assert([NSFileManager.defaultManager removeItemAtPath:path error:&error]);
}

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
image_controller_case(NSString *path, NSData *source, NSData *payload, NSData *expected)
{
	ImageProbeFileSystem *filesystem = [[ImageProbeFileSystem alloc] init];
	__weak ImageProbeFileSystem *weakFilesystem = filesystem;
	ImageVolumePathResource *resource, *other, *proxy;
	NSString *missing = [path stringByAppendingString:@".missing"];
	NSArray<NSString *> *selection = @[ @"-o", @"rw,ntfs-access=image-edit" ];
	NTFSVolume *volume;
	FSItem *root, *file;
	NSError *error = nil;
	NSUInteger starts, stops;
	uid_t owner;
	size_t committed;
	BOOL modern = NO;
	__block NSUInteger recoveryCallbacks = 0;
	__block BOOL unloaded = NO;
	dispatch_semaphore_t drained = dispatch_semaphore_create(0);
	enum ntfs_result result;

	resource = [[ImageVolumePathResource alloc] initWithURL:[NSURL fileURLWithPath:missing]
						       writable:YES];
	probeScopeAllowed = YES;
	probeScopeStarts = probeScopeStops = 0;
	controller_load(filesystem, resource, @[], EACCES);
	controller_load(filesystem, resource, @[ NTFSExtractionAccessOption ], ENOTSUP);
	controller_load(filesystem, resource, @[ NTFSImageEditingAccessOption, @"-f" ], ENOTSUP);
	controller_load(filesystem, resource,
	    @[ NTFSImageEditingAccessOption, NTFSImageEditingAccessOption ], EINVAL);
	controller_load(
	    filesystem, resource, @[ NTFSImageEditingAccessOption, @"windows-root=C:" ], ENOTSUP);
	assert(probeScopeStarts == 0 && probeScopeStops == 0 && filesystem.lastTransport == nil);
	puts("PASS: image controller rejects missing, conflicting and forced policy before "
	     "scope or recovery");
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
	if (@available(macOS 27.0, *)) {
		modern = YES;
	}
#endif
	if (!modern) {
		controller_load(filesystem, resource, selection, ENOTSUP);
		assert(probeScopeStarts == 0 && filesystem.lastTransport == nil);
		puts("SKIP: modern image controller ownership and mutation drain require "
		     "macOS 27");
		return;
	}
	probeScopeAllowed = NO;
	controller_load(filesystem, resource, selection, EACCES);
	assert(probeScopeStarts == 1 && probeScopeStops == 0);
	probeScopeAllowed = YES;
	controller_load(filesystem, resource, selection, ENOENT);
	assert(probeScopeStarts == 2 && probeScopeStops == 1 && filesystem.lastTransport == nil);
	assert([NSFileManager.defaultManager createFileAtPath:path
						     contents:source
						   attributes:@{
							   NSFilePosixPermissions : @0600
						   }]);
	resource = [[ImageVolumePathResource alloc] initWithURL:[NSURL fileURLWithPath:path]
						       writable:NO];
	controller_load(filesystem, resource, selection, EROFS);
	assert(probeScopeStarts == 2 && probeScopeStops == 1);
	resource = [[ImageVolumePathResource alloc] initWithURL:[NSURL fileURLWithPath:path]
						       writable:YES];
	filesystem.transportReady = ^(ImageProbeTransport *transport) {
	  transport.denyAllocations = YES;
	};
	controller_load(filesystem, resource, selection, ENOMEM);
	assert(filesystem.lastTransport != nil && !filesystem.lastTransport.isClaimed &&
	    filesystem.lastTransport.nativeWrites == 0 &&
	    filesystem.lastTransport.nativeBarriers == 0);
	filesystem.lastTransport = nil;
	assert(probeScopeStarts == 3 && probeScopeStops == 2 &&
	    [[NSData dataWithContentsOfFile:path] isEqualToData:source]);
	filesystem.transportReady = ^(ImageProbeTransport *transport) {
	  transport.nextPersist = ^{
	    ImageProbeFileSystem *retained = weakFilesystem;

	    assert(retained != nil);
	    controller_load(retained, resource, selection, EBUSY);
	    controller_unload(retained, resource, EBUSY);
	    recoveryCallbacks++;
	  };
	};
	volume = controller_load(filesystem, resource, selection, 0);
	assert(volume != nil && volume.lifecycle == NTFSVolumeLoaded && volume.nativeImageEditing &&
	    (volume.requestedMountOptions & FSMountOptionsReadOnly) == 0 &&
	    volume.nativeAccessMode == NTFSNativeAccessImageEditing && recoveryCallbacks == 1 &&
	    filesystem.lastTransport.isClaimed && filesystem.lastTransport.nativeWrites == 0 &&
	    filesystem.lastTransport.nativeBarriers == 1);
	filesystem.transportReady = nil;
	assert([[NSData dataWithContentsOfFile:path] isEqualToData:source]);
	controller_load(filesystem, resource, selection, EBUSY);
	other = [[ImageVolumePathResource alloc] initWithURL:[NSURL fileURLWithPath:missing]
						    writable:YES];
	controller_unload(filesystem, other, EINVAL);
	assert(filesystem.lastTransport.isClaimed && volume.lifecycle == NTFSVolumeLoaded);
	/* A fresh daemon proxy with the exact same URL closes the original owner. */
	proxy = [[ImageVolumePathResource alloc] initWithURL:resource.url writable:NO];
	controller_unload(filesystem, proxy, 0);
	assert(!filesystem.lastTransport.isClaimed && volume.lifecycle == NTFSVolumeInvalidated);
	filesystem.lastTransport = nil;
	assert(probeScopeStarts == 4 && probeScopeStops == 3);
	volume = controller_load(filesystem, resource, selection, 0);
	root = [volume activateWithOptions:nil error:&error];
	assert(root != nil && error == nil);
	file = lookup_item(volume, root, @"fragmented.bin");
	owner = filesystem.lastTransport.fileOwnerUserID;
	assert(volume.nativeUserID == owner && owner == geteuid());
	starts = probeScopeStarts;
	stops = probeScopeStops;
	filesystem.lastTransport.nextWrite = ^{
	  ImageProbeFileSystem *retained = weakFilesystem;
	  ImageControllerOptions *options = [[ImageControllerOptions alloc] init];

	  assert(retained != nil && volume.lifecycle == NTFSVolumeWriting);
	  options.taskOptions = @[];
	  [retained unloadResource:proxy
			   options:(FSTaskOptions *)options
		      replyHandler:^(NSError *failure) {
			assert(failure == nil && volume.lifecycle == NTFSVolumeInvalidated &&
			    !retained.lastTransport.isClaimed);
			unloaded = YES;
			dispatch_semaphore_signal(drained);
		      }];
	  assert(!unloaded && volume.lifecycle == NTFSVolumeInvalidating);
	  controller_load(retained, resource, selection, EBUSY);
	  controller_unload(retained, resource, EBUSY);
	};
	result = [volume overwriteImageItem:file
				     offset:TEST_IMAGE_FILE_OFFSET
				      bytes:payload.bytes
				     length:payload.length
				   fileTime:TEST_IMAGE_FILE_TIME
				  completed:&committed];
	assert(result == NTFS_OK && committed == payload.length);
	assert(dispatch_semaphore_wait(drained,
		   dispatch_time(
		       DISPATCH_TIME_NOW, TEST_IMAGE_DRAIN_WAIT_SECONDS * NSEC_PER_SEC)) == 0);
	assert(unloaded && volume.lifecycle == NTFSVolumeInvalidated &&
	    !filesystem.lastTransport.isClaimed && filesystem.lastTransport.nativeWrites > 0 &&
	    filesystem.lastTransport.nativeBarriers == TEST_IMAGE_WRITE_BARRIERS + 1 &&
	    probeScopeStarts == starts && probeScopeStops == stops);
	assert([[NSData dataWithContentsOfFile:path] isEqualToData:expected]);
	filesystem.lastTransport = nil;
	assert(probeScopeStops == stops + 1);
	volume = controller_load(filesystem, resource, selection, 0);
	assert(volume.lifecycle == NTFSVolumeLoaded && filesystem.lastTransport.isClaimed &&
	    filesystem.lastTransport.nativeWrites == 0 &&
	    filesystem.lastTransport.nativeBarriers == 1);
	controller_unload(filesystem, resource, 0);
	filesystem.lastTransport = nil;
	assert(probeScopeStarts == probeScopeStops + 1 &&
	    [[NSData dataWithContentsOfFile:path] isEqualToData:expected]);
	assert([NSFileManager.defaultManager removeItemAtPath:path error:&error]);
	puts("PASS: modern image controller recovered ownership, exact URL unload, "
	     "reentrant mutation drain, durable bytes and fresh reopen");
}

static void
deactivate_volume(NTFSVolume *volume, void (^reply)(NSError *))
{
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
	if (@available(macOS 27.0, *)) {
		[(NTFSModernVolume *)volume deactivateVolumeWithOptions:0 replyHandler:reply];
		return;
	}
#endif
	[(NTFSLegacyVolume *)volume deactivateWithOptions:0 replyHandler:reply];
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
	__block BOOL unmounted = NO, mounted = NO, synced = NO, deactivated = NO;
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
	if (mode == ImageVolumeReentrantUnmount || mode == ImageVolumeReentrantInvalidate ||
	    mode == ImageVolumeReentrantDeactivate) {
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
		  } else if (mode == ImageVolumeReentrantDeactivate) {
			  deactivate_volume(volume, ^(NSError *failure) {
			    assert(failure == nil && volume.lifecycle == NTFSVolumeInvalidated &&
				!callbackTransport.isClaimed);
			    deactivated = YES;
			    dispatch_semaphore_signal(drained);
			  });
			  assert(!deactivated && volume.lifecycle == NTFSVolumeInvalidating);
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
	if (mode == ImageVolumeReentrantInvalidate || mode == ImageVolumeReentrantDeactivate) {
		if (mode == ImageVolumeReentrantDeactivate) {
			assert(dispatch_semaphore_wait(drained,
				   dispatch_time(DISPATCH_TIME_NOW,
				       TEST_IMAGE_DRAIN_WAIT_SECONDS * NSEC_PER_SEC)) == 0 &&
			    deactivated);
		}
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

static void
image_access_reply_case(
    NSString *path, NSData *source, NSData *payload, NSData *expected, BOOL lateAllocationFailure)
{
	__attribute__((objc_precise_lifetime)) ImageVolumeTransport *transport;
	ImageVolumePathResource *peer;
	NTFSVolume *volume;
	FSItem *root, *file;
	FSItemAttributes *before, *after;
	ImageWriteReply *prepared, *returned;
	id value;
	NSError *error = nil;
	BOOL allowed;
	__block BOOL builderCalled = NO, cleanupCalled = NO;
	NSUInteger writes, barriers;
	uid_t owner, foreign;
	uint64_t now;
	size_t nested;

	assert([NSFileManager.defaultManager createFileAtPath:path
						     contents:source
						   attributes:@{
							   NSFilePosixPermissions : @0600
						   }]);
	peer = [[ImageVolumePathResource alloc] initWithURL:[NSURL fileURLWithPath:path]
						   writable:YES];
	transport = [[ImageVolumeTransport alloc] initWithResource:peer error:&error];
	assert(transport != nil && error == nil);
	owner = transport.fileOwnerUserID;
	foreign = owner == (uid_t)-1 ? owner - 1 : owner + 1;
	assert(owner == geteuid() && transport.fileOwnerGroupID == getegid());
	volume = ntfs_image_editing_volume_create(transport, &error);
	assert(volume != nil && error == nil && volume.nativeImageEditing && transport.isClaimed &&
	    volume.nativeAccessMode == NTFSNativeAccessImageEditing);
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
	if (@available(macOS 27.0, *)) {
		assert((volume.requestedMountOptions & FSMountOptionsReadOnly) == 0);
	} else
#endif
	{
		assert((volume.requestedMountOptions & FSMountOptionsReadOnly) != 0);
	}
	assert([volume activateExtraction:&error] == nil && error.code == EINVAL);
	root = [volume activateWithOptions:nil error:&error];
	assert(root != nil && error == nil);
	file = lookup_item(volume, root, @"fragmented.bin");
	before = [volume attributes:file error:&error];
	assert(before != nil && error == nil && before.uid == owner &&
	    before.gid == transport.fileOwnerGroupID && (before.mode & S_IWUSR) != 0 &&
	    (before.mode & (S_IRWXG | S_IRWXO)) == 0);
	writes = transport.nativeWrites;
	barriers = transport.nativeBarriers;
	assert([volume checkImageAccessToItem:file
			      requestedAccess:FSAccessReadData | FSAccessWriteData
				   realUserID:owner
			      effectiveUserID:owner
				      allowed:&allowed] == nil &&
	    allowed);
	assert([volume checkImageAccessToItem:file
			      requestedAccess:FSAccessReadData | FSAccessWriteData
				   realUserID:foreign
			      effectiveUserID:owner
				      allowed:&allowed] == nil &&
	    !allowed);
	assert([volume checkImageAccessToItem:file
			      requestedAccess:FSAccessReadData
				   realUserID:owner
			      effectiveUserID:foreign
				      allowed:&allowed] == nil &&
	    !allowed);
	if (owner != 0) {
		assert([volume checkImageAccessToItem:file
				      requestedAccess:FSAccessReadData | FSAccessWriteData
					   realUserID:0
				      effectiveUserID:0
					      allowed:&allowed] == nil &&
		    !allowed);
	}
	assert([volume checkImageAccessToItem:file
			      requestedAccess:FSAccessWriteData | FSAccessWriteAttributes
				   realUserID:owner
			      effectiveUserID:owner
				      allowed:&allowed] == nil &&
	    !allowed);
	assert([volume checkImageAccessToItem:root
			      requestedAccess:FSAccessSearch | FSAccessListDirectory
				   realUserID:owner
			      effectiveUserID:owner
				      allowed:&allowed] == nil &&
	    allowed);
	assert([volume checkImageAccessToItem:root
			      requestedAccess:FSAccessAddFile
				   realUserID:owner
			      effectiveUserID:owner
				      allowed:&allowed] == nil &&
	    !allowed);
	value = [volume writeImageContents:payload
				    toFile:file
				  atOffset:TEST_IMAGE_FILE_OFFSET
				  fileTime:TEST_IMAGE_FILE_TIME
			      prepareReply:^id(FSItemAttributes *attrs, size_t length) {
				(void)attrs;
				(void)length;
				builderCalled = YES;
				return @"unopened";
			      }
				     error:&error];
	assert(value == nil && error.code == EACCES && !builderCalled);
	error = [volume openImageItem:file
			    withModes:FSVolumeOpenModesWrite
			   realUserID:foreign
		      effectiveUserID:owner];
	assert(error.code == EACCES && [volume imageReadErrorForItem:file].code == EACCES);
	assert([volume openImageItem:file
			   withModes:FSVolumeOpenModesRead
			  realUserID:owner
		     effectiveUserID:owner] == nil);
	assert([volume imageReadErrorForItem:file] == nil);
	assert([volume closeImageItem:file keepingModes:FSVolumeOpenModesWrite].code == EINVAL);
	assert([volume closeImageItem:file keepingModes:0] == nil);
	assert([volume imageReadErrorForItem:file].code == EACCES);
	assert([volume openImageItem:file
			   withModes:FSVolumeOpenModesRead | FSVolumeOpenModesWrite
			  realUserID:owner
		     effectiveUserID:owner] == nil);
	assert(![volume reclaimIfEligible:file
				  cleanup:^{
				    cleanupCalled = YES;
				  }] &&
	    !cleanupCalled);
	value = [volume writeImageContents:payload
				    toFile:file
				  atOffset:TEST_IMAGE_FILE_OFFSET
				  fileTime:TEST_IMAGE_FILE_TIME
			      prepareReply:^id(FSItemAttributes *attrs, size_t length) {
				builderCalled = YES;
				assert(length == payload.length &&
				    attrs.modifyTime.tv_sec == TEST_IMAGE_FILE_SECONDS &&
				    attrs.modifyTime.tv_nsec == TEST_IMAGE_FILE_NANOSECONDS);
				return nil;
			      }
				     error:&error];
	assert(value == nil && error.code == ENOMEM && builderCalled);
	assert(transport.nativeWrites == writes && transport.nativeBarriers == barriers &&
	    [[NSData dataWithContentsOfFile:path] isEqualToData:source]);
	prepared = [[ImageWriteReply alloc] init];
	if (lateAllocationFailure) {
		transport.denyAfterBarrier = barriers + TEST_IMAGE_WRITE_BARRIERS;
	}
	returned = [volume writeImageContents:payload
				       toFile:file
				     atOffset:TEST_IMAGE_FILE_OFFSET
				     fileTime:TEST_IMAGE_FILE_TIME
				 prepareReply:^id(FSItemAttributes *attrs, size_t length) {
				   size_t completed = SIZE_MAX;

				   assert([volume overwriteImageItem:file
							      offset:TEST_IMAGE_FILE_OFFSET
							       bytes:payload.bytes
							      length:payload.length
							    fileTime:TEST_IMAGE_FILE_TIME
							   completed:&completed] == NTFS_BUSY &&
				       completed == 0);
				   prepared.attributes = attrs;
				   prepared.bytes = length;
				   return prepared;
				 }
					error:&error];
	assert(returned == prepared && error == nil && returned.bytes == payload.length &&
	    returned.attributes.fileID == before.fileID &&
	    returned.attributes.modifyTime.tv_sec == TEST_IMAGE_FILE_SECONDS &&
	    returned.attributes.modifyTime.tv_nsec == TEST_IMAGE_FILE_NANOSECONDS &&
	    returned.attributes.changeTime.tv_sec == TEST_IMAGE_FILE_SECONDS);
	assert(transport.nativeWrites > writes &&
	    transport.nativeBarriers == barriers + TEST_IMAGE_WRITE_BARRIERS &&
	    [[NSData dataWithContentsOfFile:path] isEqualToData:expected]);
	assert([volume closeImageItem:file keepingModes:FSVolumeOpenModesRead] == nil);
	assert([volume closeImageItem:file
			 keepingModes:FSVolumeOpenModesRead | FSVolumeOpenModesWrite]
		   .code == EINVAL);
	assert([volume closeImageItem:file keepingModes:0] == nil);
	assert([volume imageReadErrorForItem:file].code == EACCES);
	if (lateAllocationFailure) {
		assert(transport.denyAllocations);
		error = [volume openImageItem:file
				    withModes:FSVolumeOpenModesRead
				   realUserID:owner
			      effectiveUserID:owner];
		assert(error.code == ENOMEM);
		transport.denyAllocations = NO;
	}
	assert([volume openImageItem:file
			   withModes:FSVolumeOpenModesRead
			  realUserID:owner
		     effectiveUserID:owner] == nil);
	after = [volume attributes:file error:&error];
	assert(after != nil && error == nil && after.modifyTime.tv_sec == TEST_IMAGE_FILE_SECONDS &&
	    after.modifyTime.tv_nsec == TEST_IMAGE_FILE_NANOSECONDS &&
	    after.changeTime.tv_sec == TEST_IMAGE_FILE_SECONDS);
	assert([volume closeImageItem:file keepingModes:0] == nil);
	assert([volume currentImageFileTime:&now] == NTFS_OK && now != 0 && now <= INT64_MAX);
	nested = SIZE_MAX;
	[volume invalidate];
	assert(volume.lifecycle == NTFSVolumeInvalidated && !transport.isClaimed);
	assert([volume overwriteImageItem:file
				   offset:0
				    bytes:NULL
				   length:0
				 fileTime:now
				completed:&nested] == NTFS_STALE &&
	    nested == 0);
	assert([NSFileManager.defaultManager removeItemAtPath:path error:&error]);
}

static void
image_metadata_authority_case(NSString *path, NSData *source)
{
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
	if (@available(macOS 27.0, *)) {
		__attribute__((objc_precise_lifetime)) ImageVolumeTransport *transport;
		ImageVolumePathResource *peer;
		ImageCallerContext *subject = [[ImageCallerContext alloc] init];
		FSItemGetAttributesRequest *request = [[FSItemGetAttributesRequest alloc] init];
		NTFSModernVolume *volume;
		FSItem *root, *file;
		NSError *error = nil;
		NSUInteger writes, barriers;
		uid_t owner, foreign;
		__block NSUInteger replies = 0;

		assert([NSFileManager.defaultManager createFileAtPath:path
							     contents:source
							   attributes:@{
								   NSFilePosixPermissions : @0600
							   }]);
		peer = [[ImageVolumePathResource alloc] initWithURL:[NSURL fileURLWithPath:path]
							   writable:YES];
		transport = [[ImageVolumeTransport alloc] initWithResource:peer error:&error];
		assert(transport != nil && error == nil);
		volume = (NTFSModernVolume *)ntfs_image_editing_volume_create(transport, &error);
		assert([volume isKindOfClass:NTFSModernVolume.class] && error == nil);
		owner = transport.fileOwnerUserID;
		foreign = owner == 0 ? owner + 1 : 0;
		root = [volume activateWithOptions:nil error:&error];
		assert(root != nil && error == nil);
		file = lookup_item(volume, root, @"fragmented.bin");
		writes = transport.nativeWrites;
		barriers = transport.nativeBarriers;
		request.wantedAttributes = FSItemAttributeType | FSItemAttributeMode |
		    FSItemAttributeUID | FSItemAttributeGID | FSItemAttributeFileID;
		subject.realUserID = 0;
		subject.effectiveUserID = 0;
		[volume getAttributes:request
			       ofItem:root
			      context:(FSContext *)subject
			 replyHandler:^(FSGetAttributesResult *result, NSError *failure) {
			   assert(result != nil && failure == nil);
			   replies++;
			 }];
		subject.realUserID = foreign;
		subject.effectiveUserID = foreign;
		[volume getAttributes:request
			       ofItem:file
			      context:(FSContext *)subject
			 replyHandler:^(FSGetAttributesResult *result, NSError *failure) {
			   assert(result != nil && failure == nil);
			   replies++;
			 }];
		assert(replies == 2 && [volume imageReadErrorForItem:file].code == EACCES);
		[volume openItem:file
		       withModes:FSVolumeOpenModesRead | FSVolumeOpenModesWrite
			 context:(FSContext *)subject
		    replyHandler:^(NSError *failure) {
		      assert(failure.code == EACCES);
		      replies++;
		    }];
		[volume lookupItemNamed:[FSFileName nameWithString:@"fragmented.bin"]
			    inDirectory:root
				context:(FSContext *)subject
			   replyHandler:^(FSLookupItemResult *result, NSError *failure) {
			     assert(result == nil && failure.code == EACCES);
			     replies++;
			   }];
		assert(replies == 4 && [volume imageReadErrorForItem:file].code == EACCES &&
		    transport.nativeWrites == writes && transport.nativeBarriers == barriers &&
		    [[NSData dataWithContentsOfFile:path] isEqualToData:source]);
		[transport invalidate];
		[volume getAttributes:request
			       ofItem:file
			      context:(FSContext *)subject
			 replyHandler:^(FSGetAttributesResult *result, NSError *failure) {
			   assert(result == nil && failure.code == EIO);
			   replies++;
			 }];
		assert(replies == 5 && transport.nativeWrites == writes &&
		    transport.nativeBarriers == barriers);
		[volume invalidate];
		assert(!transport.isClaimed && volume.lifecycle == NTFSVolumeInvalidated);
		assert([NSFileManager.defaultManager removeItemAtPath:path error:&error]);
		puts("PASS: native vnode attributes preserve owner data authorization, backing "
		     "revocation and unchanged image bytes");
		return;
	}
#endif
	(void)path;
	(void)source;
	puts("SKIP: native vnode attribute authority requires the macOS 27 runtime");
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
	image_access_reply_case(path, source, payload, expected, NO);
	image_access_reply_case(path, source, payload, expected, YES);
	image_metadata_authority_case(path, source);
	image_probe_case(path, source);
	image_controller_case(path, source, payload, expected);
	assert([NSFileManager.defaultManager removeItemAtPath:directory error:&error]);
	printf("PASS: private FSKit image item identity, view replacement, allocation retry, "
	       "mutation drain and poison\n");
	printf("PASS: private image native-owner access, open capabilities and preallocated "
	       "durable reply\n");
	printf("PASS: authorized image probe scope refusal and balance, released read claim and "
	       "unchanged source without recovery\n");
}
