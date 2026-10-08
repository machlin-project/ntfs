/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "fskit_image_volume.h"
#import "NTFSImageVolume.h"
#import "NTFSFileSystem.h"
#import "fskit_resource.h"
#include <ntfs/validate.h>
#include <ntfs/security.h>
#include "fixture.h"
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

enum {
	TEST_IMAGE_FILE_OFFSET = 123,
	TEST_IMAGE_WRITE_BARRIERS = 10,
	TEST_RESIDENT_WRITE_BARRIERS = 9,
	TEST_RESIDENT_FILE_OFFSET = 5,
	TEST_IMAGE_FILE_NANOSECONDS = 661343100,
	TEST_IMAGE_READ_SAMPLE = 64,
	TEST_IMAGE_SHORT_DIVISOR = 2,
	TEST_IMAGE_DRAIN_WAIT_SECONDS = 5,
	TEST_IMAGE_MUTATION_WRITE_BYTES = 8193,
	TEST_IMAGE_MUTATION_GAP_BYTES = 257,
	TEST_IMAGE_MUTATION_SHRINK_BYTES = 19,
	TEST_IMAGE_MUTATION_REUSE_CYCLES = 16,
	TEST_IMAGE_FIRST_USER_RECORD = 16,
	TEST_IMAGE_ORACLE_DEPTH = 16,
	TEST_IMAGE_ORACLE_ITEMS = 1024,
	TEST_IMAGE_ORACLE_STREAMS = 16
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

static void
image_stream_oracle(struct ntfs_node *actual, struct ntfs_node *expected)
{
	struct ntfs_stream_catalog *catalog[2];
	struct ntfs_stream *stream[2];
	struct ntfs_stream_name names[2];
	uint8_t bytes[2][TEST_CLUSTER_BYTES];
	uint64_t offset, size;
	size_t amount, copied[2];
	uint32_t index, count;

	assert(ntfs_stream_catalog_open(actual, TEST_IMAGE_ORACLE_STREAMS, &catalog[0]) == NTFS_OK);
	assert(
	    ntfs_stream_catalog_open(expected, TEST_IMAGE_ORACLE_STREAMS, &catalog[1]) == NTFS_OK);
	count = ntfs_stream_catalog_count(catalog[0]);
	assert(count == ntfs_stream_catalog_count(catalog[1]));
	for (index = 0; index < count; index++) {
		assert(ntfs_stream_catalog_entry(catalog[0], index, &names[0]) == NTFS_OK);
		assert(ntfs_stream_catalog_entry(catalog[1], index, &names[1]) == NTFS_OK);
		assert(names[0].length == names[1].length &&
		    memcmp(names[0].units, names[1].units,
			(size_t)names[0].length * sizeof(*names[0].units)) == 0);
		assert(ntfs_stream_open(actual, names[0].units, names[0].length, &stream[0]) ==
		    NTFS_OK);
		assert(ntfs_stream_open(expected, names[1].units, names[1].length, &stream[1]) ==
		    NTFS_OK);
		size = ntfs_stream_size(stream[0]);
		assert(size == ntfs_stream_size(stream[1]));
		for (offset = 0; offset < size; offset += amount) {
			amount = size - offset > sizeof(bytes[0]) ? sizeof(bytes[0])
								  : (size_t)(size - offset);
			assert(ntfs_stream_read(stream[0], offset, bytes[0], amount, &copied[0]) ==
				NTFS_OK &&
			    copied[0] == amount);
			assert(ntfs_stream_read(stream[1], offset, bytes[1], amount, &copied[1]) ==
				NTFS_OK &&
			    copied[1] == amount);
			assert(memcmp(bytes[0], bytes[1], amount) == 0);
		}
		ntfs_stream_close(stream[0]);
		ntfs_stream_close(stream[1]);
	}
	ntfs_stream_catalog_close(catalog[0]);
	ntfs_stream_catalog_close(catalog[1]);
}

static void
image_node_oracle(struct ntfs_node *actual, struct ntfs_node *expected,
    struct ntfs_volume *actualVolume, struct ntfs_volume *expectedVolume, unsigned depth,
    unsigned *items, const struct ntfs_stat *changed)
{
	struct ntfs_stat stat[2] = {0};
	struct ntfs_link_counts links[2] = {0};
	struct ntfs_security *security[2];
	struct ntfs_directory *directory[2];
	struct ntfs_dirent entry[2];
	struct ntfs_node *child[2];
	NSMutableData *descriptor[2];
	size_t bytes, copied;
	uint64_t expectedEntrySize;
	uint32_t expectedEntryAttributes;
	enum ntfs_result result[2];

	assert(depth < TEST_IMAGE_ORACLE_DEPTH && (*items)++ < TEST_IMAGE_ORACLE_ITEMS);
	assert(ntfs_node_stat(actual, &stat[0]) == NTFS_OK);
	assert(ntfs_node_stat(expected, &stat[1]) == NTFS_OK);
	assert(stat[0].reference == stat[1].reference && stat[0].size == stat[1].size &&
	    stat[0].allocated_size == stat[1].allocated_size &&
	    stat[0].file_attributes == stat[1].file_attributes &&
	    stat[0].security_id == stat[1].security_id && stat[0].links == stat[1].links &&
	    stat[0].directory == stat[1].directory && stat[0].reparse == stat[1].reparse &&
	    stat[0].case_sensitive == stat[1].case_sensitive);
	assert(stat[0].created.seconds == stat[1].created.seconds &&
	    stat[0].created.nanoseconds == stat[1].created.nanoseconds &&
	    stat[0].modified.seconds == stat[1].modified.seconds &&
	    stat[0].modified.nanoseconds == stat[1].modified.nanoseconds &&
	    stat[0].changed.seconds == stat[1].changed.seconds &&
	    stat[0].changed.nanoseconds == stat[1].changed.nanoseconds &&
	    stat[0].accessed.seconds == stat[1].accessed.seconds &&
	    stat[0].accessed.nanoseconds == stat[1].accessed.nanoseconds);
	assert(ntfs_node_link_counts(actual, &links[0]) == NTFS_OK);
	assert(ntfs_node_link_counts(expected, &links[1]) == NTFS_OK);
	assert(links[0].physical_names == links[1].physical_names &&
	    links[0].primary_names == links[1].primary_names &&
	    links[0].dos_aliases == links[1].dos_aliases);
	assert(ntfs_security_open(actual, &security[0]) == NTFS_OK);
	assert(ntfs_security_open(expected, &security[1]) == NTFS_OK);
	bytes = ntfs_security_size(security[0]);
	assert(bytes == ntfs_security_size(security[1]));
	descriptor[0] = [NSMutableData dataWithLength:bytes];
	descriptor[1] = [NSMutableData dataWithLength:bytes];
	assert(descriptor[0] != nil && descriptor[1] != nil);
	assert(ntfs_security_copy(security[0], descriptor[0].mutableBytes, bytes, &copied) ==
		NTFS_OK &&
	    copied == bytes);
	assert(ntfs_security_copy(security[1], descriptor[1].mutableBytes, bytes, &copied) ==
		NTFS_OK &&
	    copied == bytes);
	assert([descriptor[0] isEqualToData:descriptor[1]]);
	ntfs_security_close(security[0]);
	ntfs_security_close(security[1]);
	image_stream_oracle(actual, expected);
	if (!stat[0].directory) {
		return;
	}
	assert(ntfs_directory_open(actual, &directory[0]) == NTFS_OK);
	assert(ntfs_directory_open(expected, &directory[1]) == NTFS_OK);
	for (;;) {
		result[0] = ntfs_directory_next(directory[0], &entry[0]);
		result[1] = ntfs_directory_next(directory[1], &entry[1]);
		assert(result[0] == result[1]);
		if (result[0] == NTFS_END) {
			break;
		}
		expectedEntrySize = entry[1].size;
		expectedEntryAttributes = entry[1].file_attributes;
		if (entry[1].reference == changed->reference) {
			/* General mutation refreshes FILE_NAME/index cached size and archive
			 * attributes from final file metadata. The older bounded golden leaves
			 * those caches untouched; its independently authored SI/data remain the
			 * oracle for the complete file's visible values. */
			expectedEntrySize = changed->size;
			expectedEntryAttributes = changed->file_attributes;
		}
		assert(result[0] == NTFS_OK && entry[0].reference == entry[1].reference &&
		    entry[0].parent_reference == entry[1].parent_reference &&
		    entry[0].size == expectedEntrySize &&
		    entry[0].file_attributes == expectedEntryAttributes &&
		    entry[0].name_namespace == entry[1].name_namespace &&
		    entry[0].name_length == entry[1].name_length &&
		    memcmp(entry[0].name, entry[1].name,
			entry[0].name_length * sizeof(*entry[0].name)) == 0);
		/* The expected initialized-range image has a different qualified journal.
		 * Compare every original user object and stream, leaving system content to
		 * complete metadata/allocation validation and the journal's C tests. */
		if ((entry[0].reference & NTFS_REFERENCE_RECORD_MASK) <
		    TEST_IMAGE_FIRST_USER_RECORD) {
			continue;
		}
		assert(ntfs_node_open(actualVolume, entry[0].reference, &child[0]) == NTFS_OK);
		assert(ntfs_node_open(expectedVolume, entry[1].reference, &child[1]) == NTFS_OK);
		image_node_oracle(
		    child[0], child[1], actualVolume, expectedVolume, depth + 1, items, changed);
		ntfs_node_close(child[0]);
		ntfs_node_close(child[1]);
	}
	ntfs_directory_close(directory[0]);
	ntfs_directory_close(directory[1]);
}

static void
image_general_write_oracle(NSString *path, NSData *expected)
{
	TestReader *reader[2] = {[[TestReader alloc] init], [[TestReader alloc] init]};
	NTFSResource *resource[2];
	struct ntfs_environment environment[2];
	struct ntfs_validation_report report;
	struct ntfs_volume *volume[2];
	struct ntfs_node *root[2];
	struct ntfs_node *changedNode;
	struct ntfs_stat changed;
	const uint16_t changedName[] = {
	    'f', 'r', 'a', 'g', 'm', 'e', 'n', 't', 'e', 'd', '.', 'b', 'i', 'n'};
	uint64_t freeClusters[2];
	unsigned items = 0, index;

	assert([NSData dataWithContentsOfFile:path].length == expected.length);
	/* This test reader advertises 4-KiB physical I/O. Pad its immutable copy
	 * for the source's final backup-boot sector; no disk byte is moved. */
	[reader[0] setAlignedImage:[NSData dataWithContentsOfFile:path]];
	[reader[1] setAlignedImage:expected];
	for (index = 0; index < 2; index++) {
		resource[index] = [[NTFSResource alloc] initWithReader:reader[index]];
		environment[index] = [resource[index] environment];
		assert(ntfs_validate(&environment[index], NULL, NULL, &report) == NTFS_OK &&
		    report.complete);
		assert(ntfs_mount(&environment[index], NULL, &volume[index]) == NTFS_OK);
		assert(ntfs_count_free_clusters(volume[index], &freeClusters[index]) == NTFS_OK);
		assert(ntfs_root(volume[index], &root[index]) == NTFS_OK);
	}
	assert(freeClusters[0] == freeClusters[1]);
	assert(ntfs_lookup(root[1], changedName, sizeof(changedName) / sizeof(*changedName),
		   &changedNode) == NTFS_OK);
	assert(ntfs_node_stat(changedNode, &changed) == NTFS_OK);
	ntfs_node_close(changedNode);
	image_node_oracle(root[0], root[1], volume[0], volume[1], 0, &items, &changed);
	assert(items > 1);
	for (index = 0; index < 2; index++) {
		ntfs_node_close(root[index]);
		assert(ntfs_unmount(volume[index]) == NTFS_OK);
	}
}

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
	NSData *committedImage;
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
	    filesystem.lastTransport.nativeBarriers > 1 && probeScopeStarts == starts &&
	    probeScopeStops == stops);
	image_general_write_oracle(path, expected);
	committedImage = [NSData dataWithContentsOfFile:path];
	filesystem.lastTransport = nil;
	assert(probeScopeStops == stops + 1);
	volume = controller_load(filesystem, resource, selection, 0);
	assert(volume.lifecycle == NTFSVolumeLoaded && filesystem.lastTransport.isClaimed &&
	    filesystem.lastTransport.nativeWrites == 0 &&
	    filesystem.lastTransport.nativeBarriers == 1);
	controller_unload(filesystem, resource, 0);
	filesystem.lastTransport = nil;
	assert(probeScopeStarts == probeScopeStops + 1 &&
	    [[NSData dataWithContentsOfFile:path] isEqualToData:committedImage]);
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
image_volume_case(NSString *path, NSData *source, NSData *payload, NSData *expected,
    NSString *fileName, NSString *neighborName, NSUInteger offset, NSUInteger writeBarriers,
    BOOL residentData, ImageVolumeCase mode)
{
	__attribute__((objc_precise_lifetime)) ImageVolumeTransport *transport;
	__weak ImageVolumeTransport *callbackTransport;
	ImageVolumePathResource *peer;
	NTFSVolume *volume;
	FSItem *root, *file, *neighbor, *again, *reentrantReadItem;
	FSItemAttributes *before, *after;
	NSArray<FSFileName *> *xattrs, *freshXattrs;
	NSMutableData *read = [NSMutableData dataWithLength:payload.length];
	NSData *uncertain;
	uint8_t sample[TEST_IMAGE_READ_SAMPLE];
	size_t completed, committed;
	NSUInteger writes, barriers, index, reentrantReadOffset;
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
	file = lookup_item(volume, root, fileName);
	neighbor = lookup_item(volume, root, neighborName);
	before = [volume attributes:file error:&error];
	assert(before != nil && error == nil);
	xattrs = [volume xattrsForItem:file error:&error];
	assert(xattrs != nil && error == nil);
	assert([volume readItem:file
			 offset:offset
			  bytes:sample
			 length:sizeof(sample)
		      completed:&completed] == NTFS_OK &&
	    completed == sizeof(sample));
	/* Resident data is already present in its immutable FILE snapshot. Read a
	 * nonresident neighbor to enter the native read callback while the owning
	 * volume operation still excludes a nested resident mutation. */
	reentrantReadItem = residentData ? neighbor : file;
	reentrantReadOffset = residentData ? TEST_IMAGE_FILE_OFFSET : offset;
	writes = transport.nativeWrites;
	transport.nextRead = ^{
	  size_t nested = SIZE_MAX;

	  assert([volume overwriteImageItem:file
				     offset:offset
				      bytes:payload.bytes
				     length:payload.length
				   fileTime:TEST_IMAGE_FILE_TIME
				  completed:&nested] == NTFS_BUSY &&
	      nested == 0);
	};
	assert([volume readItem:reentrantReadItem
			 offset:reentrantReadOffset
			  bytes:sample
			 length:sizeof(sample)
		      completed:&completed] == NTFS_OK &&
	    completed == sizeof(sample));
	assert(transport.nextRead == nil && transport.nativeWrites == writes);
	transport.shortWrite = mode == ImageVolumeShortWrite;
	if (mode == ImageVolumeAllocationFailure) {
		transport.denyAfterBarrier = transport.nativeBarriers + writeBarriers;
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
				   offset:offset
				    bytes:sample
				   length:sizeof(sample)
				completed:&nested] == NTFS_STALE &&
		      nested == 0);
		  assert([volume overwriteImageItem:file
					     offset:offset
					      bytes:payload.bytes
					     length:payload.length
					   fileTime:TEST_IMAGE_FILE_TIME
					  completed:&nested] == NTFS_STALE &&
		      nested == 0);
		};
	}
	result = [volume overwriteImageItem:file
				     offset:offset
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
					   offset:offset
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
				 offset:offset
				  bytes:sample
				 length:sizeof(sample)
			      completed:&completed] == NTFS_IO &&
		    completed == 0);
		assert([volume overwriteImageItem:file
					   offset:offset
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
					 offset:offset
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
		assert(after != nil && error == nil && after.fileID == before.fileID &&
		    after.size == before.size && after.mode == before.mode);
		assert(after.modifyTime.tv_sec == TEST_IMAGE_FILE_SECONDS &&
		    after.modifyTime.tv_nsec == TEST_IMAGE_FILE_NANOSECONDS &&
		    after.changeTime.tv_sec == TEST_IMAGE_FILE_SECONDS &&
		    after.changeTime.tv_nsec == TEST_IMAGE_FILE_NANOSECONDS);
		again = lookup_item(volume, root, fileName);
		assert(again == file && lookup_item(volume, root, neighborName) == neighbor);
		assert([volume attributes:neighbor error:&error] != nil && error == nil);
		freshXattrs = [volume xattrsForItem:file error:&error];
		assert(freshXattrs != nil && error == nil && freshXattrs.count == xattrs.count);
		/* FSFileName instances can be recreated when a catalog closes. Compare
		 * the native name bytes, without imposing NSObject pointer equality. */
		for (index = 0; index < xattrs.count; index++) {
			assert([freshXattrs[index].data isEqualToData:xattrs[index].data]);
		}
		assert([volume readItem:file
				 offset:offset
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
image_lazy_view_drain_case(
    NSString *path, NSData *source, NSData *payload, NSData *expected, ImageVolumeCase mode,
    BOOL overlappingUnmount)
{
	__attribute__((objc_precise_lifetime)) ImageVolumeTransport *transport;
	__weak ImageVolumeTransport *callbackTransport;
	ImageVolumePathResource *peer;
	NTFSVolume *volume;
	FSItem *root, *file;
	NSError *error = nil;
	size_t completed;
	NSUInteger writes, barriers, index, expectedReplies = overlappingUnmount ? 2 : 1;
	__block NSUInteger callbacks = 0, replies = 0, mountReplies = 0;
	dispatch_semaphore_t drained = dispatch_semaphore_create(0);

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
	assert([volume overwriteImageItem:file
				     offset:TEST_IMAGE_FILE_OFFSET
				      bytes:payload.bytes
				     length:payload.length
				   fileTime:TEST_IMAGE_FILE_TIME
				  completed:&completed] == NTFS_OK &&
	    completed == payload.length);
	assert([[NSData dataWithContentsOfFile:path] isEqualToData:expected]);
	writes = transport.nativeWrites;
	barriers = transport.nativeBarriers;
	/* No immutable view exists after the committed write. This first native
	 * read belongs to an unpublished ntfs_mount, before a read scope exists.
	 * Teardown must neither reply nor release ownership inside that call. */
	transport.nextRead = ^{
	  void (^completedReply)(void) = ^{
	    @synchronized(volume) {
		    replies++;
	    }
	    dispatch_semaphore_signal(drained);
	  };

	  callbacks++;
	  assert(callbackTransport.isClaimed);
	  if (overlappingUnmount) {
		  assert(mode == ImageVolumeReentrantDeactivate);
		  [volume unmountWithReplyHandler:^{
		    assert(volume.lifecycle != NTFSVolumeActive);
		    completedReply();
		  }];
		  assert(replies == 0 && volume.lifecycle == NTFSVolumeDraining);
	  }
	  if (mode == ImageVolumeReentrantUnmount) {
		  [volume unmountWithReplyHandler:^{
		    assert(volume.lifecycle == NTFSVolumeUnmounted);
		    completedReply();
		  }];
		  assert(volume.lifecycle == NTFSVolumeDraining);
	  } else if (mode == ImageVolumeReentrantDeactivate) {
		  deactivate_volume(volume, ^(NSError *failure) {
		    assert(failure == nil && volume.lifecycle == NTFSVolumeInvalidated);
		    completedReply();
		  });
		  assert(volume.lifecycle == NTFSVolumeInvalidating);
	  } else {
		  assert(mode == ImageVolumeReentrantInvalidate);
		  [volume invalidateWithReplyHandler:^{
		    assert(volume.lifecycle == NTFSVolumeInvalidated);
		    completedReply();
		  }];
		  assert(volume.lifecycle == NTFSVolumeInvalidating);
	  }
	  assert(replies == 0 && callbackTransport.isClaimed);
	};
	assert([volume attributes:file error:&error] == nil && error.code == ESTALE);
	assert(callbacks == 1 && transport.nextRead == nil);
	for (index = 0; index < expectedReplies; index++) {
		assert(dispatch_semaphore_wait(drained,
			   dispatch_time(DISPATCH_TIME_NOW,
			       TEST_IMAGE_DRAIN_WAIT_SECONDS * NSEC_PER_SEC)) == 0);
	}
	assert(replies == expectedReplies);
	if (mode == ImageVolumeReentrantUnmount) {
		assert(transport.isClaimed && transport.isAvailable);
		[volume mountWithOptions:nil
			    replyHandler:^(NSError *failure) {
			      assert(failure == nil);
			      mountReplies++;
			    }];
		assert(mountReplies == 1 && volume.lifecycle == NTFSVolumeActive);
		assert([volume attributes:file error:&error] != nil && error == nil);
	} else {
		assert(volume.lifecycle == NTFSVolumeInvalidated && !transport.isClaimed);
		assert([volume attributes:file error:&error] == nil && error.code == ESTALE);
	}
	assert(transport.nativeWrites == writes && transport.nativeBarriers == barriers &&
	    [[NSData dataWithContentsOfFile:path] isEqualToData:expected]);
	[volume invalidate];
	assert(volume.lifecycle == NTFSVolumeInvalidated && !transport.isClaimed &&
	    replies == expectedReplies);
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
	    allowed);
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
	    allowed);
	assert([volume checkImageAccessToItem:file
			      requestedAccess:FSAccessWriteSecurity
				   realUserID:owner
			      effectiveUserID:owner
				      allowed:&allowed] == nil &&
	    !allowed);
	value = [volume writeImageContents:payload
				    toFile:file
				  atOffset:TEST_IMAGE_FILE_OFFSET
				  fileTime:TEST_IMAGE_FILE_TIME
			      prepareReply:^id(FSItemAttributes *attrs, size_t length,
				  id __attribute__((unused)) freeSpace) {
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
			      prepareReply:^id(FSItemAttributes *attrs, size_t length,
				  id __attribute__((unused)) freeSpace) {
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
		transport.denyAfterBarrier = barriers + 1;
	}
	returned = [volume writeImageContents:payload
				       toFile:file
				     atOffset:TEST_IMAGE_FILE_OFFSET
				     fileTime:TEST_IMAGE_FILE_TIME
				 prepareReply:^id(FSItemAttributes *attrs, size_t length,
				     id __attribute__((unused)) freeSpace) {
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
	assert(transport.nativeWrites > writes && transport.nativeBarriers > barriers);
	image_general_write_oracle(path, expected);
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
			image_volume_case(path, source, payload, expected, @"fragmented.bin",
			    @"hello.txt", TEST_IMAGE_FILE_OFFSET, TEST_IMAGE_WRITE_BARRIERS, NO,
			    mode);
		}
	}
	for (mode = ImageVolumeReentrantUnmount; mode <= ImageVolumeReentrantDeactivate; mode++) {
		@autoreleasepool {
			image_lazy_view_drain_case(path, source, payload, expected, mode, NO);
		}
	}
	image_lazy_view_drain_case(
	    path, source, payload, expected, ImageVolumeReentrantDeactivate, YES);
	puts("PASS: lazy image view acquisition drains reentrant and overlapping teardown "
	     "before replies, with unchanged bytes and remount retry");
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

void
ntfs_test_fskit_resident_image_volume(NSString *fixtures)
{
	NSString *directory = [NSTemporaryDirectory()
	    stringByAppendingPathComponent:[@"machlin-ntfs-resident-image-volume-"
					       stringByAppendingString:NSUUID.UUID.UUIDString]];
	NSString *path = [directory stringByAppendingPathComponent:@"owned.img"];
	NSArray<NSString *> *profiles =
	    @[ @"ordinary", @"odd-length", @"whole-value", @"named-stream-preserved" ];
	NSString *profile, *input;
	NSData *source, *payload, *expected;
	ImageVolumeCase mode;
	NSUInteger offset;
	NSError *error = nil;

	assert([NSFileManager.defaultManager createDirectoryAtPath:directory
				       withIntermediateDirectories:NO
							attributes:@{
								NSFilePosixPermissions : @0700
							}
							     error:&error]);
	for (profile in profiles) {
		input = [fixtures stringByAppendingPathComponent:profile];
		source = [NSData
		    dataWithContentsOfFile:[input stringByAppendingPathComponent:@"source.img"]];
		payload = [NSData
		    dataWithContentsOfFile:[input stringByAppendingPathComponent:@"payload.input"]];
		expected = [NSData dataWithContentsOfFile:
			[input stringByAppendingPathComponent:@"execute-final.img"]];
		offset = [profile isEqualToString:@"whole-value"] ? 0 : TEST_RESIDENT_FILE_OFFSET;
		assert(source != nil && payload != nil && expected != nil);
		for (mode = ImageVolumeNormal; mode < ImageVolumeCaseCount; mode++) {
			@autoreleasepool {
				image_volume_case(path, source, payload, expected, @"hello.txt",
				    @"fragmented.bin", offset, TEST_RESIDENT_WRITE_BARRIERS, YES,
				    mode);
			}
		}
		printf(
		    "PASS: resident image %s complete FILE/WAL bytes, identity, view replacement, "
		    "allocation retry, mutation drain and poison\n",
		    profile.UTF8String);
	}
	assert([NSFileManager.defaultManager removeItemAtPath:directory error:&error]);
}

@interface ImageMutationReply : NSObject
@property(strong) FSItem *item;
@property(strong) FSFileName *name;
@property(strong) FSItemAttributes *attributes, *sourceDirectory, *destinationDirectory, *overItem;
@end

@implementation ImageMutationReply
@end

static id
mutation_reply(FSItem *item, FSFileName *name, FSItemAttributes *attributes,
    FSItemAttributes *source, FSItemAttributes *destination, FSItemAttributes *over,
    id __attribute__((unused)) freeSpace)
{
	ImageMutationReply *result = [[ImageMutationReply alloc] init];

	result.item = item;
	result.name = name;
	result.attributes = attributes;
	result.sourceDirectory = source;
	result.destinationDirectory = destination;
	result.overItem = over;
	return result;
}

static FSItem *
create_image_component(NTFSVolume *volume, FSItem *parent, NSString *name, FSItemType type)
{
	ImageMutationReply *result;
	FSItemSetAttributesRequest *attributes = [[FSItemSetAttributesRequest alloc] init];
	NSError *error = nil;

	attributes.mode = type == FSItemTypeDirectory ? S_IRWXU : S_IRUSR | S_IWUSR;
	attributes.uid = volume.nativeUserID;
	attributes.gid = volume.nativeGroupID;
	attributes.flags = 0;
	result = [volume
	    createImageItemNamed:[FSFileName nameWithString:name]
			    type:type
		     inDirectory:parent
		      attributes:attributes
			fileTime:TEST_IMAGE_FILE_TIME
		    prepareReply:^id(FSItem *item, FSFileName *stored, FSItemAttributes *attrs,
			FSItemAttributes *src, FSItemAttributes *dst, FSItemAttributes *over,
			id __attribute__((unused)) freeSpace) {
		      return mutation_reply(item, stored, attrs, src, dst, over, freeSpace);
		    }
			   error:&error];
	assert(result != nil && result.item != nil && error == nil &&
	    result.attributes.type == type && result.attributes.size == 0 &&
	    result.attributes.linkCount == 1 &&
	    result.sourceDirectory.type == FSItemTypeDirectory &&
	    result.attributes.mode == attributes.mode &&
	    (attributes.consumedAttributes &
		(FSItemAttributeMode | FSItemAttributeUID | FSItemAttributeGID |
		    FSItemAttributeFlags)) ==
		(FSItemAttributeMode | FSItemAttributeUID | FSItemAttributeGID |
		    FSItemAttributeFlags));
	return result.item;
}

static FSItemSetAttributesRequest *
creation_attributes(NTFSVolume *volume, FSItemType type)
{
	FSItemSetAttributesRequest *attributes = [[FSItemSetAttributesRequest alloc] init];

	attributes.type = type;
	attributes.mode = type == FSItemTypeDirectory ? S_IRWXU : S_IRUSR | S_IWUSR;
	attributes.uid = volume.nativeUserID;
	attributes.gid = volume.nativeGroupID;
	attributes.flags = 0;
	attributes.size = 0;
	attributes.birthTime = (struct timespec){-1, 123456789};
	attributes.modifyTime = (struct timespec){0, 100};
	attributes.changeTime =
	    (struct timespec){TEST_IMAGE_FILE_SECONDS, TEST_IMAGE_FILE_NANOSECONDS};
	attributes.accessTime = (struct timespec){-11644473600, 0};
	return attributes;
}

static void
image_creation_attribute_contract(
    NTFSVolume *volume, FSItem *root, ImageVolumeTransport *transport, NSString *path)
{
	FSItemAttribute expected = FSItemAttributeType | FSItemAttributeMode | FSItemAttributeUID |
	    FSItemAttributeGID | FSItemAttributeFlags | FSItemAttributeSize |
	    FSItemAttributeBirthTime | FSItemAttributeModifyTime | FSItemAttributeChangeTime |
	    FSItemAttributeAccessTime;
	NTFSImageMutationReply build = ^id(FSItem *item, FSFileName *name, FSItemAttributes *attrs,
	    FSItemAttributes *src, FSItemAttributes *dst, FSItemAttributes *over,
	    id __attribute__((unused)) freeSpace) {
	  return mutation_reply(item, name, attrs, src, dst, over, freeSpace);
	};
	FSItemSetAttributesRequest *attributes;
	FSItemAttributes *actual;
	ImageMutationReply *result;
	FSFileName *name;
	FSItemType type;
	NSError *error = nil;
	NSData *before = [NSData dataWithContentsOfFile:path];
	NSUInteger index, kind, writes = transport.nativeWrites,
				barriers = transport.nativeBarriers;

	for (index = 0; index < 12; index++) {
		attributes = creation_attributes(volume, FSItemTypeFile);
		switch (index) {
		case 0:
			attributes.mode |= S_IRGRP;
			break;
		case 1:
			attributes.uid++;
			break;
		case 2:
			attributes.gid++;
			break;
		case 3:
			attributes.flags = UF_IMMUTABLE;
			break;
		case 4:
			attributes.size = 1;
			break;
		case 5:
			attributes.type = FSItemTypeDirectory;
			break;
		case 6:
			attributes.birthTime = (struct timespec){-11644473601, 0};
			break;
		case 7:
			attributes.modifyTime = (struct timespec){0, -1};
			break;
		case 8:
			attributes.changeTime = (struct timespec){0, NSEC_PER_SEC};
			break;
		case 9:
			attributes.accessTime = (struct timespec){INT64_MAX, 0};
			break;
		case 10:
			attributes.allocSize = 0;
			break;
		default:
			attributes.backupTime = (struct timespec){0, 0};
			break;
		}
		result =
		    [volume createImageItemNamed:[FSFileName nameWithString:@"attribute-refusal"]
					    type:FSItemTypeFile
				     inDirectory:root
				      attributes:attributes
					fileTime:TEST_IMAGE_FILE_TIME
				    prepareReply:build
					   error:&error];
		assert(result == nil && error != nil && attributes.consumedAttributes == 0 &&
		    transport.nativeWrites == writes && transport.nativeBarriers == barriers &&
		    [[NSData dataWithContentsOfFile:path] isEqualToData:before]);
	}
	attributes = creation_attributes(volume, FSItemTypeFile);
	result = [volume
	    createImageItemNamed:[FSFileName nameWithString:@"attribute-abandon"]
			    type:FSItemTypeFile
		     inDirectory:root
		      attributes:attributes
			fileTime:TEST_IMAGE_FILE_TIME
		    prepareReply:^id(FSItem *item, FSFileName *name, FSItemAttributes *attrs,
			FSItemAttributes *src, FSItemAttributes *dst, FSItemAttributes *over,
			id __attribute__((unused)) freeSpace) {
		      (void)item;
		      (void)name;
		      (void)src;
		      (void)dst;
		      (void)over;
		      assert(attrs.birthTime.tv_sec == -1 && attrs.birthTime.tv_nsec == 123456700 &&
			  attributes.consumedAttributes == 0);
		      return nil;
		    }
			   error:&error];
	assert(result == nil && error.code == ENOMEM && attributes.consumedAttributes == 0 &&
	    transport.nativeWrites == writes && transport.nativeBarriers == barriers &&
	    [[NSData dataWithContentsOfFile:path] isEqualToData:before]);
	for (kind = 0; kind < 2; kind++) {
		type = kind == 0 ? FSItemTypeFile : FSItemTypeDirectory;
		name = [FSFileName
		    nameWithString:kind == 0 ? @"attribute-file" : @"attribute-directory"];
		attributes = creation_attributes(volume, type);
		result = [volume createImageItemNamed:name
						 type:type
					  inDirectory:root
					   attributes:attributes
					     fileTime:TEST_IMAGE_FILE_TIME
					 prepareReply:build
						error:&error];
		assert(result != nil && error == nil && attributes.consumedAttributes == expected);
		actual = [volume attributes:result.item error:&error];
		assert(actual != nil && error == nil && actual.mode == attributes.mode &&
		    actual.uid == attributes.uid && actual.gid == attributes.gid &&
		    actual.flags == 0 && [actual isValid:FSItemAttributeFlags] &&
		    actual.size == 0 && actual.birthTime.tv_sec == -1 &&
		    actual.birthTime.tv_nsec == 123456700 && actual.modifyTime.tv_sec == 0 &&
		    actual.modifyTime.tv_nsec == 100 &&
		    actual.changeTime.tv_sec == TEST_IMAGE_FILE_SECONDS &&
		    actual.changeTime.tv_nsec == TEST_IMAGE_FILE_NANOSECONDS &&
		    actual.accessTime.tv_sec == -11644473600 && actual.accessTime.tv_nsec == 0);
		assert(result.sourceDirectory.changeTime.tv_sec == TEST_IMAGE_FILE_SECONDS &&
		    result.sourceDirectory.changeTime.tv_nsec == TEST_IMAGE_FILE_NANOSECONDS);
		result = [volume removeImageItem:result.item
					   named:name
				   fromDirectory:root
					fileTime:TEST_IMAGE_FILE_TIME
				    prepareReply:build
					   error:&error];
		assert(result != nil && error == nil);
	}
}

void
ntfs_test_fskit_image_mutation(NSString *fixtures)
{
	NSString *directory = [NSTemporaryDirectory()
	    stringByAppendingPathComponent:[@"machlin-ntfs-image-mutation-"
					       stringByAppendingString:NSUUID.UUID.UUIDString]];
	NSString *path = [directory stringByAppendingPathComponent:@"owned.img"];
	NSData *source =
	    [NSData dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:@"source.img"]];
	NSMutableData *payload = [NSMutableData dataWithLength:TEST_IMAGE_MUTATION_WRITE_BYTES];
	NSMutableData *wanted =
	    [NSMutableData dataWithLength:TEST_IMAGE_MUTATION_GAP_BYTES + payload.length];
	NSMutableData *actual;
	ImageVolumePathResource *peer;
	ImageVolumeTransport *transport;
	NTFSVolume *volume;
	FSItem *root, *left, *right, *nested, *deep, *file, *victim, *temporary;
	FSItemAttributes *before, *after;
	FSItemSetAttributesRequest *attributes;
	ImageMutationReply *result;
	ImageWriteReply *written;
	NSError *error = nil;
	NTFSImageMutationReply build = ^id(FSItem *item, FSFileName *name,
	    FSItemAttributes *itemAttrs, FSItemAttributes *src, FSItemAttributes *dst,
	    FSItemAttributes *over, id __attribute__((unused)) freeSpace) {
	  return mutation_reply(item, name, itemAttrs, src, dst, over, freeSpace);
	};
	uint8_t *bytes = payload.mutableBytes;
	NSUInteger index, writes, barriers;
	uid_t owner;
	size_t completed;
	enum ntfs_result status;

	assert(source != nil &&
	    [NSFileManager.defaultManager createDirectoryAtPath:directory
				    withIntermediateDirectories:NO
						     attributes:nil
							  error:&error]);
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
	volume = ntfs_image_editing_volume_create(transport, &error);
	assert(volume != nil && error == nil);
	root = [volume activateWithOptions:nil error:&error];
	assert(root != nil && error == nil);
	writes = transport.nativeWrites;
	barriers = transport.nativeBarriers;
	result = [volume
	    createImageItemNamed:[FSFileName nameWithString:@"abandoned"]
			    type:FSItemTypeFile
		     inDirectory:root
		      attributes:nil
			fileTime:TEST_IMAGE_FILE_TIME
		    prepareReply:^id(FSItem *item, FSFileName *name, FSItemAttributes *attrs,
			FSItemAttributes *src, FSItemAttributes *dst, FSItemAttributes *over,
			id __attribute__((unused)) freeSpace) {
		      assert(item != nil && name != nil && attrs.size == 0 && src != nil &&
			  dst == nil && over == nil);
		      return nil;
		    }
			   error:&error];
	assert(result == nil && error.code == ENOMEM && transport.nativeWrites == writes &&
	    transport.nativeBarriers == barriers &&
	    [[NSData dataWithContentsOfFile:path] isEqualToData:source]);
	image_creation_attribute_contract(volume, root, transport, path);
	left = create_image_component(volume, root, @"left", FSItemTypeDirectory);
	right = create_image_component(volume, root, @"right", FSItemTypeDirectory);
	nested = create_image_component(volume, left, @"nested", FSItemTypeDirectory);
	deep = create_image_component(volume, nested, @"deep", FSItemTypeDirectory);
	file = create_image_component(volume, deep, @"data.bin", FSItemTypeFile);
	before = [volume attributes:file error:&error];
	assert(before != nil && error == nil);
	assert([volume openImageItem:file
			   withModes:FSVolumeOpenModesRead | FSVolumeOpenModesWrite
			  realUserID:owner
		     effectiveUserID:owner] == nil);
	for (index = 0; index < payload.length; index++) {
		bytes[index] = (uint8_t)(index * 17u + 3u);
	}
	memcpy((uint8_t *)wanted.mutableBytes + TEST_IMAGE_MUTATION_GAP_BYTES, payload.bytes,
	    payload.length);
	transport.denyAfterBarrier = transport.nativeBarriers + 1;
	written = [volume writeImageContents:payload
				      toFile:file
				    atOffset:TEST_IMAGE_MUTATION_GAP_BYTES
				    fileTime:TEST_IMAGE_FILE_TIME
				prepareReply:^id(FSItemAttributes *attrs, size_t count,
				    id __attribute__((unused)) freeSpace) {
				  ImageWriteReply *reply = [[ImageWriteReply alloc] init];

				  assert(attrs.size == wanted.length &&
				      attrs.fileID == before.fileID && count == payload.length);
				  reply.attributes = attrs;
				  reply.bytes = count;
				  return reply;
				}
				       error:&error];
	assert(written != nil && error == nil && written.bytes == payload.length &&
	    transport.denyAllocations);
	assert([volume attributes:file error:&error] == nil && error.code == ENOMEM);
	transport.denyAllocations = NO;
	transport.denyAfterBarrier = 0;
	actual = [NSMutableData dataWithLength:wanted.length];
	status = [volume readItem:file
			   offset:0
			    bytes:actual.mutableBytes
			   length:actual.length
			completed:&completed];
	assert(status == NTFS_OK && completed == actual.length && [actual isEqualToData:wanted]);
	attributes = [[FSItemSetAttributesRequest alloc] init];
	attributes.size = TEST_IMAGE_MUTATION_SHRINK_BYTES;
	result = [volume setImageAttributes:attributes
				     onItem:file
				   fileTime:TEST_IMAGE_FILE_TIME
			       prepareReply:build
				      error:&error];
	assert(result != nil && error == nil &&
	    result.attributes.size == TEST_IMAGE_MUTATION_SHRINK_BYTES &&
	    [attributes wasAttributeConsumed:FSItemAttributeSize]);
	attributes = [[FSItemSetAttributesRequest alloc] init];
	attributes.size = wanted.length;
	result = [volume setImageAttributes:attributes
				     onItem:file
				   fileTime:TEST_IMAGE_FILE_TIME
			       prepareReply:build
				      error:&error];
	assert(result != nil && error == nil && result.attributes.size == wanted.length);
	memset(wanted.mutableBytes, 0, wanted.length);
	status = [volume readItem:file
			   offset:0
			    bytes:actual.mutableBytes
			   length:actual.length
			completed:&completed];
	assert(status == NTFS_OK && completed == actual.length && [actual isEqualToData:wanted]);
	writes = transport.nativeWrites;
	barriers = transport.nativeBarriers;
	assert([volume removeImageItem:file
				 named:[FSFileName nameWithString:@"data.bin"]
			 fromDirectory:deep
			      fileTime:TEST_IMAGE_FILE_TIME
			  prepareReply:build
				 error:&error] == nil &&
	    error.code == ENOTSUP && transport.nativeWrites == writes &&
	    transport.nativeBarriers == barriers);
	assert([volume closeImageItem:file keepingModes:0] == nil);
	result = [volume renameImageItem:nested
			     inDirectory:left
				   named:[FSFileName nameWithString:@"nested"]
			       toNewName:[FSFileName nameWithString:@"moved"]
			     inDirectory:right
				overItem:nil
				fileTime:TEST_IMAGE_FILE_TIME
			    prepareReply:build
				   error:&error];
	assert(result != nil && error == nil && result.destinationDirectory != nil);
	assert(lookup_item(volume, right, @"moved") == nested &&
	    lookup_item(volume, nested, @"deep") == deep &&
	    lookup_item(volume, deep, @"data.bin") == file);
	victim = create_image_component(volume, right, @"replaced.bin", FSItemTypeFile);
	result = [volume renameImageItem:file
			     inDirectory:deep
				   named:[FSFileName nameWithString:@"data.bin"]
			       toNewName:[FSFileName nameWithString:@"replaced.bin"]
			     inDirectory:right
				overItem:victim
				fileTime:TEST_IMAGE_FILE_TIME
			    prepareReply:build
				   error:&error];
	assert(result != nil && error == nil && result.attributes.fileID == before.fileID &&
	    result.overItem.linkCount == 0 && lookup_item(volume, right, @"replaced.bin") == file);
	assert([volume attributes:victim error:&error] == nil && error.code == ESTALE);
	writes = transport.nativeWrites;
	barriers = transport.nativeBarriers;
	assert([volume removeImageItem:nested
				 named:[FSFileName nameWithString:@"moved"]
			 fromDirectory:right
			      fileTime:TEST_IMAGE_FILE_TIME
			  prepareReply:build
				 error:&error] == nil &&
	    error.code == ENOTEMPTY && transport.nativeWrites == writes &&
	    transport.nativeBarriers == barriers);
	result = [volume removeImageItem:file
				   named:[FSFileName nameWithString:@"replaced.bin"]
			   fromDirectory:right
				fileTime:TEST_IMAGE_FILE_TIME
			    prepareReply:build
				   error:&error];
	assert(result != nil && error == nil && result.attributes.linkCount == 0);
	result = [volume removeImageItem:deep
				   named:[FSFileName nameWithString:@"deep"]
			   fromDirectory:nested
				fileTime:TEST_IMAGE_FILE_TIME
			    prepareReply:build
				   error:&error];
	assert(result != nil && error == nil);
	result = [volume removeImageItem:nested
				   named:[FSFileName nameWithString:@"moved"]
			   fromDirectory:right
				fileTime:TEST_IMAGE_FILE_TIME
			    prepareReply:build
				   error:&error];
	assert(result != nil && error == nil);
	for (index = 0; index < TEST_IMAGE_MUTATION_REUSE_CYCLES; index++) {
		temporary = create_image_component(volume, root, @"reuse.bin", FSItemTypeFile);
		after = [volume attributes:temporary error:&error];
		assert(after != nil && error == nil && after.fileID != before.fileID);
		result = [volume removeImageItem:temporary
					   named:[FSFileName nameWithString:@"reuse.bin"]
				   fromDirectory:root
					fileTime:TEST_IMAGE_FILE_TIME
				    prepareReply:build
					   error:&error];
		assert(result != nil && error == nil && result.attributes.linkCount == 0);
	}
	[volume invalidate];
	assert(!transport.isClaimed && volume.lifecycle == NTFSVolumeInvalidated);
	assert([NSFileManager.defaultManager removeItemAtPath:directory error:&error]);
	puts("PASS: image create/mkdir/growing write/resize/rename/replace/unlink/rmdir, held "
	     "descendant "
	     "ancestry, generation reuse, no-write reply failure and allocation-free durable "
	     "publication");
}
