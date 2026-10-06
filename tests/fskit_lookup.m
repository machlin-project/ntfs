/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "fskit_lookup.h"
#import "fskit_resource.h"
#import "fskit_lifecycle.h"
#import "NTFSVolume.h"
#include "fixture.h"
#include <assert.h>
#include <errno.h>
#include <string.h>

enum {
	TEST_LOOKUP_PARTIAL_ERROR,
	TEST_LOOKUP_FULL_ERROR,
	TEST_LOOKUP_READ_ERROR_MODES,
	TEST_LOOKUP_PARTIAL_FILL_DIVISOR = 2,
	TEST_LOOKUP_CORE_DIMENSIONS = NTFS_OPERATION_LIMIT_WORK,
	TEST_LOOKUP_PHYSICAL_DIMENSIONS = 2,
	TEST_LOOKUP_BOUNDARY_VARIANTS = 2
};

@interface LookupReader : TestReader
@property NSUInteger fillErrorAt;
@property NSUInteger fillErrorMode;
@end

@implementation LookupReader

- (size_t)readInto:(void *)buffer
	startingAt:(off_t)offset
	    length:(size_t)length
	     error:(NSError **)error
{
	size_t copied;

	if (self.fillErrorAt != 0 && self.reads + 1 == self.fillErrorAt) {
		assert(offset >= 0 && (uint64_t)offset <= self.image.length &&
		    length <= self.image.length - (size_t)offset);
		self.reads++;
		copied = self.fillErrorMode == TEST_LOOKUP_FULL_ERROR
		    ? length
		    : length / TEST_LOOKUP_PARTIAL_FILL_DIVISOR;
		memcpy(buffer, (const uint8_t *)self.image.bytes + offset, copied);
		*error = [NSError errorWithDomain:NSPOSIXErrorDomain code:EIO userInfo:nil];
		return copied;
	}
	return [super readInto:buffer startingAt:offset length:length error:error];
}

@end

static NTFSVolume *
lookup_owner(NSData *image, BOOL modern, LookupReader **readerOut, FaultResource **resourceOut,
    struct ntfs_volume **coreOut, FSItem **rootOut)
{
	LookupReader *reader = [[LookupReader alloc] init];
	FaultResource *resource;
	NTFSVolume *volume = nil;
	struct ntfs_environment env;
	struct ntfs_limits limits;
	struct ntfs_volume *core = NULL;
	NSError *error = nil;

	assert(image != nil);
	[reader setAlignedImage:image];
	resource = [[FaultResource alloc] initWithReader:reader];
	env = [resource environment];
	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	assert(ntfs_mount(&env, &limits, &core) == NTFS_OK);
	if (modern) {
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
		if (@available(macOS 27.0, *)) {
			volume = [[NTFSModernVolume alloc] initWithCore:core resource:resource];
		}
#endif
	} else {
		volume = [[NTFSLegacyVolume alloc] initWithCore:core resource:resource];
	}
	assert(volume != nil);
	*rootOut = [volume activateExtraction:&error];
	assert(*rootOut != nil && error == nil);
	*readerOut = reader;
	*resourceOut = resource;
	*coreOut = core;
	return volume;
}

static FSItem *
lookup_item(NTFSVolume *volume, FSItem *directory, NSString *name)
{
	FSFileName *stored = nil;
	NSError *error = nil;
	FSItem *item;

	item = [volume lookup:[FSFileName nameWithString:name]
		  inDirectory:directory
		   storedName:&stored
			error:&error];
	assert(item != nil && error == nil && [stored.string isEqualToString:name]);
	return item;
}

/* Modern result objects are opaque. Check their presence/error/count framing;
 * identity and canonical spelling are independently checked on the shared path. */
static id
lookup_reply(
    NTFSVolume *volume, FSItem *directory, NSString *name, BOOL modern, NSInteger errorCode)
{
	__block NSUInteger replies = 0;
	__block id observed = nil;
	__block NSError *observedError = nil;

	if (modern) {
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
		if (@available(macOS 27.0, *)) {
			[(NTFSModernVolume *)volume
			    lookupItemNamed:[FSFileName nameWithString:name]
				inDirectory:directory
				    context:(FSContext *)[[NSObject alloc] init]
			       replyHandler:^(FSLookupItemResult *result, NSError *error) {
				 observed = result;
				 observedError = error;
				 replies++;
			       }];
		}
#endif
	} else {
		[(NTFSLegacyVolume *)volume
		    lookupItemNamed:[FSFileName nameWithString:name]
			inDirectory:directory
		       replyHandler:^(FSItem *item, FSFileName *stored, NSError *error) {
			 assert(item == nil ? stored == nil : [stored.string isEqualToString:name]);
			 observed = item;
			 observedError = error;
			 replies++;
		       }];
	}
	assert(replies == 1 && (observed != nil) == (observedError == nil));
	assert(errorCode == 0 ? observedError == nil
			      : observedError.code == errorCode &&
		    [observedError.domain isEqualToString:NSPOSIXErrorDomain]);
	return observed;
}

static NTFSVolume *
orphan_owner(NSData *image, BOOL modern, LookupReader **readerOut, FaultResource **resourceOut,
    struct ntfs_volume **coreOut, FSItem **childOut)
{
	NTFSVolume *volume;
	__attribute__((objc_precise_lifetime)) FSItem *child = nil;
	__weak FSItem *releasedRoot;
	__weak FSItem *releasedParent;

	@autoreleasepool {
		__attribute__((objc_precise_lifetime)) FSItem *root = nil;
		__attribute__((objc_precise_lifetime)) FSItem *parent = nil;

		volume = lookup_owner(image, modern, readerOut, resourceOut, coreOut, &root);
		parent = lookup_item(volume, root, @"first");
		child = lookup_item(volume, parent, @"second");
		releasedRoot = root;
		releasedParent = parent;
		parent = nil;
		root = nil;
	}
	assert(releasedRoot == nil);
	assert(releasedParent == nil);
	*childOut = child;
	return volume;
}

static void
cached_lookup(NTFSVolume *volume, FSItem *directory, FSItem *parent, BOOL modern,
    LookupReader *reader, FaultResource *resource)
{
	NSUInteger reads = reader.reads, allocations = resource.allocations;
	id result;

	reader.failReadAt = reads + 1;
	resource.failAllocationAt = allocations + 1;
	assert(lookup_item(volume, directory, @".") == directory);
	assert(lookup_item(volume, directory, @"..") == parent);
	result = lookup_reply(volume, directory, @".", modern, 0);
	assert(modern || result == directory);
	result = lookup_reply(volume, directory, @"..", modern, 0);
	assert(modern || result == parent);
	assert(reader.reads == reads && resource.allocations == allocations);
	reader.failReadAt = 0;
	resource.failAllocationAt = 0;
}

static void
test_lookup_reserved_names(NSString *fixtures, BOOL modern)
{
	NSArray<NSString *> *const images = @[ @"namespace.img", @"namespace-sensitive.img" ];
	NSArray<NSArray<NSNumber *> *> *const dotUnits = @[ @[ @('.') ], @[ @('.'), @('.') ] ];
	NSArray<NSDictionary *> *manifest;
	NSDictionary *entry;
	NSString *name;
	NSData *image;
	LookupReader *reader;
	FaultResource *resource;
	struct ntfs_volume *core;
	NTFSVolume *volume;
	FSItem *root, *file;
	FSItemAttributes *attributes;
	NSError *error = nil;
	NSUInteger count;

	manifest = [NSJSONSerialization
	    JSONObjectWithData:[NSData dataWithContentsOfFile:
				       [fixtures stringByAppendingPathComponent:@"namespace.json"]]
		       options:0
			 error:NULL];
	assert(manifest.count != 0);
	for (name in images) {
		image =
		    [NSData dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:name]];
		volume = lookup_owner(image, modern, &reader, &resource, &core, &root);
		cached_lookup(volume, root, root, modern, reader, resource);
		count = 0;
		for (entry in manifest) {
			if ([dotUnits containsObject:entry[@"units"]]) {
				file = lookup_item(volume, root, entry[@"native"]);
				attributes = [volume attributes:file error:&error];
				assert(error == nil && attributes.type == FSItemTypeFile &&
				    attributes.fileID ==
					[entry[@"reference"] unsignedLongLongValue] &&
				    attributes.fileID != FSItemIDRootDirectory);
				lookup_reply(volume, root, entry[@"native"], modern, 0);
				count++;
			}
		}
		assert(count == dotUnits.count);
		[volume invalidate];
		assert(resource.liveAllocations == 0);
	}
}

static void
test_lookup_identity(NSData *standard, NSData *nested, BOOL modern)
{
	LookupReader *reader;
	FaultResource *resource;
	struct ntfs_volume *core;
	NTFSVolume *volume, *otherVolume;
	FSItem *root, *parent, *child, *file, *otherRoot;
	LookupReader *otherReader;
	FaultResource *otherResource;
	struct ntfs_volume *otherCore;
	FSItemID parentID, childID;
	NSError *error = nil;
	__block NSUInteger replies = 0;
	NSUInteger reads, allocations;

	volume = lookup_owner(standard, modern, &reader, &resource, &core, &root);
	cached_lookup(volume, root, root, modern, reader, resource);
	file = lookup_item(volume, root, @"hello.txt");
	lookup_reply(volume, file, @".", modern, ENOTDIR);
	lookup_reply(volume, file, @"..", modern, ENOTDIR);
	lookup_reply(volume, root, @"...", modern, ENOENT);
	otherVolume =
	    lookup_owner(standard, modern, &otherReader, &otherResource, &otherCore, &otherRoot);
	lookup_reply(volume, otherRoot, @".", modern, ESTALE);
	lookup_reply(volume, otherRoot, @"..", modern, ESTALE);
	lookup_reply(volume, [[FSItem alloc] init], @"..", modern, ESTALE);
	[otherVolume invalidate];
	assert(otherResource.liveAllocations == 0);
	[volume invalidate];
	assert(resource.liveAllocations == 0);
	volume = lookup_owner(nested, modern, &reader, &resource, &core, &root);
	parent = lookup_item(volume, root, @"first");
	child = lookup_item(volume, parent, @"second");
	parentID = [volume attributes:parent error:&error].fileID;
	childID = [volume attributes:child error:&error].fileID;
	assert(error == nil && parentID != FSItemIDRootDirectory && childID != parentID);
	cached_lookup(volume, parent, root, modern, reader, resource);
	cached_lookup(volume, child, parent, modern, reader, resource);
	[volume invalidate];
	assert(resource.liveAllocations == 0);
	volume = orphan_owner(nested, modern, &reader, &resource, &core, &child);
	assert([volume attributes:child error:&error].fileID == childID && error == nil);
	[volume unmountWithReplyHandler:^{
	  replies++;
	}];
	reads = reader.reads;
	allocations = resource.allocations;
	lookup_reply(volume, child, @".", modern, ESTALE);
	lookup_reply(volume, child, @"..", modern, ESTALE);
	assert(reader.reads == reads && resource.allocations == allocations);
	[volume mountWithOptions:nil
		    replyHandler:^(NSError *failure) {
		      assert(failure == nil);
		      replies++;
		    }];
	assert(replies == 2);
	parent = lookup_item(volume, child, @"..");
	assert([volume attributes:parent error:&error].fileID == parentID && error == nil);
	root = lookup_item(volume, parent, @"..");
	assert(
	    [volume attributes:root error:&error].fileID == FSItemIDRootDirectory && error == nil);
	cached_lookup(volume, child, parent, modern, reader, resource);
	cached_lookup(volume, parent, root, modern, reader, resource);
	cached_lookup(volume, root, root, modern, reader, resource);
	reader.revoked = YES;
	reads = reader.reads;
	allocations = resource.allocations;
	lookup_reply(volume, child, @".", modern, EIO);
	lookup_reply(volume, child, @"..", modern, EIO);
	reader.revoked = NO;
	lookup_reply(volume, root, @"..", modern, EIO);
	assert(reader.reads == reads && resource.allocations == allocations);
	[volume invalidate];
	assert(resource.liveAllocations == 0);
	lookup_reply(volume, child, @".", modern, ESTALE);
	lookup_reply(volume, child, @"..", modern, ESTALE);
	volume = orphan_owner(nested, modern, &reader, &resource, &core, &child);
	reader.revokeDuringRead = YES;
	lookup_reply(volume, child, @"..", modern, EIO);
	reader.revokeDuringRead = NO;
	reader.revoked = NO;
	reads = reader.reads;
	allocations = resource.allocations;
	lookup_reply(volume, child, @"..", modern, EIO);
	assert(reader.reads == reads && resource.allocations == allocations);
	[volume invalidate];
	assert(resource.liveAllocations == 0);
}

static void
test_lookup_faults(NSData *nested, BOOL modern)
{
	LookupReader *reader;
	FaultResource *resource;
	struct ntfs_volume *core;
	NTFSVolume *volume;
	FSItem *child;
	__attribute__((objc_precise_lifetime)) id result;
	NSUInteger reads, allocations, readCount, allocationCount, live, i, mode;

	volume = orphan_owner(nested, modern, &reader, &resource, &core, &child);
	reads = reader.reads;
	allocations = resource.allocations;
	result = lookup_reply(volume, child, @"..", modern, 0);
	readCount = reader.reads - reads;
	allocationCount = resource.allocations - allocations;
	assert(readCount != 0 && allocationCount != 0);
	[volume invalidate];
	assert(resource.liveAllocations == 0);
	result = nil;
	for (i = 1; i <= allocationCount; i++) {
		@autoreleasepool {
			volume = orphan_owner(nested, modern, &reader, &resource, &core, &child);
			live = resource.liveAllocations;
			resource.failAllocationAt = resource.allocations + i;
			lookup_reply(volume, child, @"..", modern, ENOMEM);
			assert(resource.liveAllocations == live);
			resource.failAllocationAt = 0;
			result = lookup_reply(volume, child, @"..", modern, 0);
			[volume invalidate];
			assert(resource.liveAllocations == 0);
			result = nil;
		}
	}
	for (mode = 0; mode < TEST_LOOKUP_READ_ERROR_MODES; mode++) {
		for (i = 1; i <= readCount; i++) {
			@autoreleasepool {
				volume =
				    orphan_owner(nested, modern, &reader, &resource, &core, &child);
				live = resource.liveAllocations;
				reader.fillErrorAt = reader.reads + i;
				reader.fillErrorMode = mode;
				lookup_reply(volume, child, @"..", modern, EIO);
				assert(resource.liveAllocations == live);
				reader.fillErrorAt = 0;
				result = lookup_reply(volume, child, @"..", modern, 0);
				[volume invalidate];
				assert(resource.liveAllocations == 0);
				result = nil;
			}
		}
	}
	printf("PASS: %s parent lookup %lu allocation and %lu partial/full read faults\n",
	    modern ? "modern" : "legacy", (unsigned long)allocationCount,
	    (unsigned long)(readCount * TEST_LOOKUP_READ_ERROR_MODES));
}

static uint64_t
lookup_usage(const struct ntfs_operation_usage *usage, enum ntfs_operation_limit dimension)
{
	switch (dimension) {
	case NTFS_OPERATION_LIMIT_READ_CALLS:
		return usage->read_calls;
	case NTFS_OPERATION_LIMIT_READ_BYTES:
		return usage->read_bytes;
	case NTFS_OPERATION_LIMIT_ALLOCATION_CALLS:
		return usage->allocation_calls;
	case NTFS_OPERATION_LIMIT_ALLOCATION_BYTES:
		return usage->allocation_bytes;
	case NTFS_OPERATION_LIMIT_WORK:
		return usage->work;
	default:
		assert(false);
		return 0;
	}
}

static void
lookup_limit(
    struct ntfs_operation_limits *limits, enum ntfs_operation_limit dimension, uint64_t value)
{
	switch (dimension) {
	case NTFS_OPERATION_LIMIT_READ_CALLS:
		limits->read_calls = value;
		break;
	case NTFS_OPERATION_LIMIT_READ_BYTES:
		limits->read_bytes = value;
		break;
	case NTFS_OPERATION_LIMIT_ALLOCATION_CALLS:
		limits->allocation_calls = value;
		break;
	case NTFS_OPERATION_LIMIT_ALLOCATION_BYTES:
		limits->allocation_bytes = value;
		break;
	case NTFS_OPERATION_LIMIT_WORK:
		limits->work = value;
		break;
	default:
		assert(false);
	}
}

static void
test_lookup_budgets(NSData *nested, BOOL modern)
{
	LookupReader *reader;
	FaultResource *resource;
	struct ntfs_volume *core;
	NTFSVolume *volume;
	FSItem *child;
	__attribute__((objc_precise_lifetime)) id result;
	struct ntfs_operation operation = {0};
	struct ntfs_operation_usage baseline, usage;
	struct ntfs_operation_limits limits;
	struct ntfs_resource_read_budget physical = {0};
	uint64_t amount, expected, physicalCalls, physicalBytes;
	NSUInteger dimensions, below, boundaries = 0, reads, allocations, live;
	enum ntfs_operation_limit dimension;
	NSInteger errorCode;

	volume = orphan_owner(nested, modern, &reader, &resource, &core, &child);
	ntfs_operation_default_limits(&limits);
	assert(ntfs_operation_begin(core, &limits, &operation) == NTFS_OK);
	assert([resource beginReadBudget:&physical limits:&limits] == NTFS_OK);
	result = lookup_reply(volume, child, @"..", modern, 0);
	physicalCalls = physical.calls;
	physicalBytes = physical.bytes;
	assert([resource endReadBudget:&physical] == NTFS_OK);
	assert(ntfs_operation_end(&operation, &baseline) == NTFS_OK &&
	    baseline.exhausted == NTFS_OPERATION_LIMIT_NONE);
	assert(physicalCalls != 0 && physicalBytes != 0);
	[volume invalidate];
	assert(resource.liveAllocations == 0);
	result = nil;
	for (dimensions = 0; dimensions < TEST_LOOKUP_CORE_DIMENSIONS; dimensions++) {
		dimension = NTFS_OPERATION_LIMIT_READ_CALLS + dimensions;
		amount = lookup_usage(&baseline, dimension);
		assert(amount != 0);
		for (below = 0; below < TEST_LOOKUP_BOUNDARY_VARIANTS; below++) {
			if (amount <= below) {
				/* Public operation limits must stay positive. */
				continue;
			}
			@autoreleasepool {
				volume =
				    orphan_owner(nested, modern, &reader, &resource, &core, &child);
				ntfs_operation_default_limits(&limits);
				lookup_limit(&limits, dimension, amount - below);
				reads = reader.reads;
				allocations = resource.allocations;
				live = resource.liveAllocations;
				assert(ntfs_operation_begin(core, &limits, &operation) == NTFS_OK);
				errorCode = below == 0 ? 0
				    : dimension == NTFS_OPERATION_LIMIT_ALLOCATION_CALLS ||
					dimension == NTFS_OPERATION_LIMIT_ALLOCATION_BYTES
				    ? ENOMEM
				    : EOVERFLOW;
				result = lookup_reply(volume, child, @"..", modern, errorCode);
				assert(ntfs_operation_end(&operation, &usage) == NTFS_OK);
				expected = below == 0 ? NTFS_OPERATION_LIMIT_NONE : dimension;
				assert(usage.exhausted == expected &&
				    lookup_usage(&usage, dimension) <= amount - below &&
				    resource.allocations - allocations == usage.allocation_calls);
				assert(reader.reads - reads <= usage.read_calls);
				if (below != 0) {
					assert(resource.liveAllocations == live);
					result = lookup_reply(volume, child, @"..", modern, 0);
				}
				[volume invalidate];
				assert(resource.liveAllocations == 0);
				result = nil;
				boundaries++;
			}
		}
	}
	for (dimensions = 0; dimensions < TEST_LOOKUP_PHYSICAL_DIMENSIONS; dimensions++) {
		amount = dimensions == 0 ? physicalCalls : physicalBytes;
		for (below = 0; below < TEST_LOOKUP_BOUNDARY_VARIANTS; below++) {
			if (amount <= below) {
				continue;
			}
			@autoreleasepool {
				volume =
				    orphan_owner(nested, modern, &reader, &resource, &core, &child);
				ntfs_operation_default_limits(&limits);
				if (dimensions == 0) {
					limits.read_calls = amount - below;
				} else {
					limits.read_bytes = amount - below;
				}
				reads = reader.reads;
				live = resource.liveAllocations;
				assert([resource beginReadBudget:&physical
							  limits:&limits] == NTFS_OK);
				result = lookup_reply(
				    volume, child, @"..", modern, below == 0 ? 0 : EOVERFLOW);
				assert(physical.calls == reader.reads - reads &&
				    physical.calls <= limits.read_calls &&
				    physical.bytes <= limits.read_bytes);
				assert([resource endReadBudget:&physical] == NTFS_OK);
				if (below != 0) {
					assert(resource.liveAllocations == live);
					result = lookup_reply(volume, child, @"..", modern, 0);
				}
				[volume invalidate];
				assert(resource.liveAllocations == 0);
				result = nil;
				boundaries++;
			}
		}
	}
	printf("PASS: %s parent lookup %lu core/physical operation boundaries\n",
	    modern ? "modern" : "legacy", (unsigned long)boundaries);
}

void
ntfs_test_fskit_lookup(NSData *standard, NSString *fixtures, BOOL modern)
{
	NSData *nested;

	if (modern && !ntfs_test_modern_runtime_available()) {
		puts("SKIP: modern dot lookup requires the macOS 27 SDK/runtime");
		return;
	}
	nested = [NSData
	    dataWithContentsOfFile:[fixtures
				       stringByAppendingPathComponent:@"validation-nested.img"]];
	test_lookup_identity(standard, nested, modern);
	test_lookup_reserved_names(fixtures, modern);
	test_lookup_faults(nested, modern);
	test_lookup_budgets(nested, modern);
	printf("PASS: %s dot lookup identities, released ancestry, remount and revocation\n",
	    modern ? "modern" : "legacy");
}
