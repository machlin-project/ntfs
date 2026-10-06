/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSVolume.h"
#import "NTFSFileSystem.h"
#import "fskit_access.h"
#import "fskit_resource.h"
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

@interface AccessOptions : NSObject
@property(copy) NSArray<NSString *> *taskOptions;
@end

@implementation AccessOptions
@end

/* Like the maintenance component, model a daemon-supplied block resource
 * through public messages without constructing or acquiring a real device. */
@interface AccessReader : TestReader
@end

@implementation AccessReader

- (BOOL)isKindOfClass:(Class)type
{
	return type == FSBlockDeviceResource.class || [super isKindOfClass:type];
}

@end

@interface AccessFileSystem : NTFSFileSystem
@property FaultResource *preparedResource;
@property NSUInteger resourceCreations;
@end

@implementation AccessFileSystem

- (NTFSResource *)newResourceWithReader:(id<NTFSBlockReader>)reader
{
	(void)reader;
	self.resourceCreations++;
	return self.preparedResource;
}

@end

static FSTaskOptions *
options(NSArray<NSString *> *arguments)
{
	AccessOptions *value = [[AccessOptions alloc] init];

	value.taskOptions = arguments;
	return (FSTaskOptions *)value;
}

static BOOL
expected_error(NSError *error, NSInteger code)
{
	return code == 0 ? error == nil
			 : [error.domain isEqualToString:NSPOSIXErrorDomain] && error.code == code;
}

static void
check_options(
    NSArray<NSString *> *arguments, enum ntfs_result expected, NTFSNativeAccessMode selected)
{
	struct {
		NSUInteger before;
		NTFSNativeAccessMode value;
		NSUInteger after;
	} frame = {NSUIntegerMax, NTFSNativeAccessExtraction, NSUIntegerMax};
	enum ntfs_result result;

	result = ntfs_native_access_mode(arguments, &frame.value);
	assert(result == expected && frame.value == selected && frame.before == NSUIntegerMax &&
	    frame.after == NSUIntegerMax);
}

static void
test_options(void)
{
	NSMutableArray<NSString *> *arguments = [NSMutableArray array];
	NSString *prefix = @"ntfs-access=extract,";
	NSString *limit;
	NSUInteger i;

	assert([NTFSExtractionAccessOption isEqualToString:@"ntfs-access=extract"]);
	assert([NTFSImageEditingAccessOption isEqualToString:@"ntfs-access=image-edit"]);
	check_options(nil, NTFS_OK, NTFSNativeAccessUnselected);
	check_options(@[], NTFS_OK, NTFSNativeAccessUnselected);
	check_options(@[ @"-o", @"ro" ], NTFS_OK, NTFSNativeAccessUnselected);
	check_options(@[ @"ntfs-accessible=extract", @"" ], NTFS_OK, NTFSNativeAccessUnselected);
	check_options(@[ @"ntfs-access=extract" ], NTFS_OK, NTFSNativeAccessExtraction);
	check_options(@[ @"ntfs-access=image-edit" ], NTFS_OK, NTFSNativeAccessImageEditing);
	check_options(
	    @[ @"-o", @"rw,ntfs-access=image-edit" ], NTFS_OK, NTFSNativeAccessImageEditing);
	check_options(@[ @"ntfs-access=image-edit,ntfs-access=extract" ], NTFS_INVALID,
	    NTFSNativeAccessUnselected);
	check_options(@[ @"-o", @"ro,windows-root=C:,ntfs-access=extract" ], NTFS_OK,
	    NTFSNativeAccessExtraction);
	check_options(@[ @"ntfs-access" ], NTFS_INVALID, NTFSNativeAccessUnselected);
	check_options(@[ @"ntfs-access=" ], NTFS_INVALID, NTFSNativeAccessUnselected);
	check_options(@[ @"ntfs-access=windows" ], NTFS_UNSUPPORTED, NTFSNativeAccessUnselected);
	check_options(
	    @[ @"ntfs-access=extractable" ], NTFS_UNSUPPORTED, NTFSNativeAccessUnselected);
	check_options(@[ @"ntfs-access=extract", @"ntfs-access=extract" ], NTFS_INVALID,
	    NTFSNativeAccessUnselected);
	check_options(@[ @"ntfs-access=extract,ntfs-access=windows" ], NTFS_INVALID,
	    NTFSNativeAccessUnselected);
	check_options(
	    @[ @"ntfs-access=extract", (id) @0 ], NTFS_INVALID, NTFSNativeAccessUnselected);
	check_options((id)NSNull.null, NTFS_INVALID, NTFSNativeAccessUnselected);
	assert(ntfs_native_access_mode(@[ @"ntfs-access=extract" ], NULL) == NTFS_INVALID);
	for (i = 0; i < NTFS_FSKIT_OPTION_LIMIT - 1; i++) {
		[arguments addObject:@"ro"];
	}
	[arguments addObject:@"ntfs-access=extract"];
	check_options(arguments, NTFS_OK, NTFSNativeAccessExtraction);
	[arguments addObject:@"ro"];
	check_options(arguments, NTFS_RANGE, NTFSNativeAccessUnselected);
	limit = [prefix stringByPaddingToLength:PATH_MAX withString:@"x" startingAtIndex:0];
	check_options(@[ limit ], NTFS_OK, NTFSNativeAccessExtraction);
	check_options(
	    @[ [limit stringByAppendingString:@"x"] ], NTFS_INVALID, NTFSNativeAccessUnselected);
	assert(ntfs_native_image_options(nil) == NTFS_OK);
	assert(
	    ntfs_native_image_options(@[ @"-o", @"rw,owners,ntfs-access=image-edit" ]) == NTFS_OK);
	assert(
	    ntfs_native_image_options(@[ @"-f", @"ntfs-access=image-edit" ]) == NTFS_UNSUPPORTED);
	assert(ntfs_native_image_options(@[ @"ntfs-access=image-edit,windows-root=C:" ]) ==
	    NTFS_UNSUPPORTED);
	assert(
	    ntfs_native_image_options(@[ @"ntfs-access=image-edit,unknown" ]) == NTFS_UNSUPPORTED);
	assert(ntfs_native_image_options(@[ @"ntfs-access=extract" ]) == NTFS_INVALID);
	assert(ntfs_native_image_options(@[ @"-o" ]) == NTFS_INVALID);
	assert(ntfs_native_image_options(@[ @"-o", @"-o", @"ntfs-access=image-edit" ]) ==
	    NTFS_INVALID);
	puts(
	    "PASS: bounded native extraction option parsing, ambiguity refusal and guarded output");
}

static FSItem *
activate(NTFSVolume *volume, NSArray<NSString *> *arguments, BOOL modern, NSInteger expected)
{
	__block FSItem *root = nil;
	__block NSUInteger replies = 0;

	if (modern) {
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
		if (@available(macOS 27.0, *)) {
			[(NTFSModernVolume *)volume
			    activateVolumeWithOptions:options(arguments)
					 replyHandler:^(FSActivateResult *result, NSError *error) {
					   assert(expected_error(error, expected) &&
					       ((result != nil) == (expected == 0)));
					   replies++;
					 }];
			if (expected == 0) {
				NSError *error = nil;

				/* Result objects expose no root accessor. Reuse the selected
				 * policy through the engine, without selecting it again. */
				root = [volume activateWithOptions:nil error:&error];
				assert(root != nil && error == nil);
			}
		}
#endif
	} else {
		[(NTFSLegacyVolume *)volume activateWithOptions:options(arguments)
						   replyHandler:^(FSItem *item, NSError *error) {
						     assert(expected_error(error, expected) &&
							 ((item != nil) == (expected == 0)));
						     root = item;
						     replies++;
						   }];
	}
	assert(replies == 1);
	return root;
}

static void
mount(NTFSVolume *volume, NSArray<NSString *> *arguments, NSInteger expected)
{
	__block NSUInteger replies = 0;

	[volume mountWithOptions:options(arguments)
		    replyHandler:^(NSError *error) {
		      assert(expected_error(error, expected));
		      replies++;
		    }];
	assert(replies == 1);
}

static void
presentation(NTFSVolume *volume, FSItem *item, BOOL directory, uid_t user, gid_t group)
{
	NSError *error = nil;
	FSItemAttributes *attrs = [volume attributes:item error:&error];

	assert(attrs != nil && error == nil && attrs.uid == user && attrs.gid == group &&
	    attrs.type == (directory ? FSItemTypeDirectory : FSItemTypeFile) &&
	    attrs.mode == (directory ? (S_IRUSR | S_IXUSR) : S_IRUSR) &&
	    attrs.inhibitKernelOffloadedIO);
}

static void
test_volume(NSData *image, Class selected, BOOL modern)
{
	AccessReader *reader = [[AccessReader alloc] init];
	FaultResource *resource;
	struct ntfs_environment env;
	struct ntfs_volume *core = NULL;
	NTFSVolume *volume;
	FSItem *root, *file;
	FSFileName *stored = nil;
	NSError *error = nil;
	NSUInteger reads, allocations, live;
	uid_t user = geteuid();
	gid_t group = getegid();
	__block NSUInteger replies = 0;

	[reader setAlignedImage:image];
	resource = [[FaultResource alloc] initWithReader:reader];
	env = resource.environment;
	assert(ntfs_mount(&env, NULL, &core) == NTFS_OK);
	assert([[selected alloc] initWithCore:core
				     resource:resource
		      maximumDirectoryEntries:NTFS_FSKIT_DIRECTORY_ENTRY_LIMIT
				   linkPolicy:nil
				   accessMode:(NTFSNativeAccessMode)NSUIntegerMax] == nil);
	volume = [[selected alloc] initWithCore:core resource:resource];
	assert(volume != nil && volume.nativeAccessMode == NTFSNativeAccessUnselected &&
	    volume.nativeUserID == user && volume.nativeGroupID == group);
	reads = reader.reads;
	allocations = resource.allocations;
	live = resource.liveAllocations;
	assert(activate(volume, nil, modern, EACCES) == nil);
	assert(activate(volume, @[], modern, EACCES) == nil);
	assert(activate(volume, @[ @"-o", @"ro" ], modern, EACCES) == nil);
	assert(activate(volume, @[ @"ntfs-access=windows" ], modern, ENOTSUP) == nil);
	assert(activate(volume, @[ @"ntfs-access=image-edit" ], modern, ENOTSUP) == nil);
	assert(activate(volume, @[ @"ntfs-access=" ], modern, EINVAL) == nil);
	assert(activate(volume, @[ @"ntfs-access=extract,ntfs-access=extract" ], modern, EINVAL) ==
	    nil);
	assert(activate(volume, (id)NSNull.null, modern, EINVAL) == nil);
	assert(volume.nativeAccessMode == NTFSNativeAccessUnselected &&
	    volume.lifecycle == NTFSVolumeLoaded && reader.reads == reads &&
	    resource.allocations == allocations && resource.liveAllocations == live);
	mount(volume, nil, ESTALE);
	resource.failAllocation = YES;
	assert(activate(volume, @[ @"ntfs-access=extract" ], modern, ENOMEM) == nil);
	resource.failAllocation = NO;
	assert(volume.nativeAccessMode == NTFSNativeAccessUnselected &&
	    volume.lifecycle == NTFSVolumeLoaded);
	root = activate(volume, @[ @"-o", @"ro,ntfs-access=extract" ], modern, 0);
	assert(root != nil && volume.nativeAccessMode == NTFSNativeAccessExtraction);
	presentation(volume, root, YES, user, group);
	file = [volume lookup:[FSFileName nameWithString:@"hello.txt"]
		  inDirectory:root
		   storedName:&stored
			error:&error];
	assert(file != nil && error == nil &&
	    [stored.data isEqualToData:[@"hello.txt" dataUsingEncoding:NSUTF8StringEncoding]]);
	presentation(volume, file, NO, user, group);
	assert(volume.requestedMountOptions == FSMountOptionsReadOnly &&
	    volume.restrictsOwnershipChanges &&
	    volume.supportedVolumeCapabilities.doesNotSupportSettingFilePermissions);
	reads = reader.reads;
	allocations = resource.allocations;
	live = resource.liveAllocations;
	assert(activate(volume, @[ @"ntfs-access=windows" ], modern, ENOTSUP) == nil);
	mount(volume, @[ @"ntfs-access=windows" ], ENOTSUP);
	mount(volume, @[ @"ntfs-access=image-edit" ], ENOTSUP);
	mount(volume, @[ @"ntfs-access=extract,ntfs-access=extract" ], EINVAL);
	assert(reader.reads == reads && resource.allocations == allocations &&
	    resource.liveAllocations == live && volume.lifecycle == NTFSVolumeActive &&
	    volume.nativeAccessMode == NTFSNativeAccessExtraction);
	[volume unmountWithReplyHandler:^{
	  replies++;
	}];
	assert(replies == 1 && volume.lifecycle == NTFSVolumeUnmounted);
	mount(volume, nil, 0);
	presentation(volume, root, YES, user, group);
	presentation(volume, file, NO, user, group);
	reader.revoked = YES;
	assert(activate(volume, nil, modern, EIO) == nil);
	assert([volume attributes:file error:&error] == nil && error.code == EIO);
	[volume invalidate];
	assert(activate(volume, @[ @"ntfs-access=windows" ], modern, ESTALE) == nil);
	assert(
	    resource.liveAllocations == 0 && volume.nativeAccessMode == NTFSNativeAccessExtraction);
	assert(
	    [reader.image subdataWithRange:NSMakeRange(0, image.length)].length == image.length &&
	    [[reader.image subdataWithRange:NSMakeRange(0, image.length)] isEqualToData:image]);
	puts(modern ? "PASS: modern explicit extraction activation, stable metadata and refusal "
		      "lifetime"
		    : "PASS: legacy explicit extraction activation, stable metadata and refusal "
		      "lifetime");
}

static NTFSVolume *
load(AccessFileSystem *filesystem, AccessReader *reader, NSArray<NSString *> *arguments,
    NSInteger expected)
{
	__block NTFSVolume *volume = nil;
	__block NSUInteger replies = 0;

	[filesystem
	    loadResource:(FSResource *)reader
		 options:options(arguments)
	    replyHandler:^(FSVolume *loaded, NSError *error) {
	      assert(expected_error(error, expected) && ((loaded != nil) == (expected == 0)));
	      volume = (NTFSVolume *)loaded;
	      replies++;
	    }];
	assert(replies == 1);
	return volume;
}

static void
unload(AccessFileSystem *filesystem, AccessReader *reader)
{
	__block NSUInteger replies = 0;

	[filesystem unloadResource:(FSResource *)reader
			   options:options(@[])
		      replyHandler:^(NSError *error) {
			assert(error == nil);
			replies++;
		      }];
	assert(replies == 1 && filesystem.preparedResource.liveAllocations == 0);
}

static void
test_load(NSData *image)
{
	AccessReader *reader = [[AccessReader alloc] init];
	AccessFileSystem *filesystem = [[AccessFileSystem alloc] init];
	NTFSVolume *volume;
	FSItem *root;
	NSError *error = nil;
	uid_t user = geteuid();
	gid_t group = getegid();
	__block NSUInteger replies = 0;

	[reader setAlignedImage:image];
	filesystem.preparedResource = [[FaultResource alloc] initWithReader:reader];
	assert(load(filesystem, reader, @[ @"ntfs-access=image-edit" ], ENOTSUP) == nil);
	assert(load(filesystem, reader, @[ @"-f", @"ntfs-access=windows" ], ENOTSUP) == nil);
	assert(load(filesystem, reader, @[ @"ntfs-access=extract,ntfs-access=extract" ], EINVAL) ==
	    nil);
	assert(load(filesystem, reader, (id)NSNull.null, EINVAL) == nil);
	assert(filesystem.resourceCreations == 0 && reader.reads == 0 &&
	    filesystem.preparedResource.allocations == 0);
	volume = load(filesystem, reader, @[], 0);
	assert(volume.nativeAccessMode == NTFSNativeAccessUnselected);
	assert([volume activateWithOptions:nil error:&error] == nil && error.code == EACCES);
	mount(volume, nil, ESTALE);
	unload(filesystem, reader);
	volume = load(filesystem, reader, @[ @"-o", @"ntfs-access=extract,windows-root=C:" ], 0);
	assert(volume.nativeAccessMode == NTFSNativeAccessExtraction);
	root = [volume activateWithOptions:nil error:&error];
	assert(root != nil && error == nil);
	presentation(volume, root, YES, user, group);
	[volume unmountWithReplyHandler:^{
	  replies++;
	}];
	assert(replies == 1);
	mount(volume, @[], 0);
	presentation(volume, root, YES, user, group);
	unload(filesystem, reader);
	assert([volume attributes:root error:&error] == nil && error.code == ESTALE);
	assert([[reader.image subdataWithRange:NSMakeRange(0, image.length)] isEqualToData:image]);
	puts("PASS: unary load-selected extraction and zero-I/O policy refusal");
}

void
ntfs_test_fskit_access(NSData *image, BOOL modern)
{
	Class selected = NTFSLegacyVolume.class;

	if (modern) {
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
		if (@available(macOS 27.0, *)) {
			selected = NTFSModernVolume.class;
		} else {
			puts("SKIP: modern extraction activation requires macOS 27 runtime");
			return;
		}
#else
		puts("SKIP: modern extraction activation requires macOS 27 SDK/runtime");
		return;
#endif
	} else {
		test_options();
		test_load(image);
	}
	test_volume(image, selected, modern);
}
