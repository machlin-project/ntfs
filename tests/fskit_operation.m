/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSVolume.h"
#import "fskit_resource.h"
#import "fskit_operation.h"
#include "fixture.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

enum { TEST_GUARD = 0xa5, TEST_CHILD_READS = 2 };

@interface BudgetReader : TestReader
@property uint64_t physicalBytes;
@property(copy) void (^beforeRead)(void);
@end

@implementation BudgetReader

- (size_t)readInto:(void *)buffer
	startingAt:(off_t)offset
	    length:(size_t)length
	     error:(NSError **)error
{
	self.physicalBytes += length;
	if (self.beforeRead != nil) {
		self.beforeRead();
	}
	return [super readInto:buffer startingAt:offset length:length error:error];
}

@end

@protocol TestOperationPolicy <NSObject>
@property struct ntfs_operation_limits requestLimits;
@property BOOL limited;
@end

@interface BudgetLegacyVolume : NTFSLegacyVolume <TestOperationPolicy>
@property struct ntfs_operation_limits requestLimits;
@property BOOL limited;
@end

@implementation BudgetLegacyVolume

- (struct ntfs_operation_limits)operationLimits
{
	return self.limited ? self.requestLimits : [super operationLimits];
}

@end

#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
API_AVAILABLE(macos(27.0))
@interface BudgetModernVolume : NTFSModernVolume <TestOperationPolicy>
@property struct ntfs_operation_limits requestLimits;
@property BOOL limited;
@end

@implementation BudgetModernVolume

- (struct ntfs_operation_limits)operationLimits
{
	return self.limited ? self.requestLimits : [super operationLimits];
}

@end
#endif

@interface BudgetPacker : NSObject
@property NSString *stopName;
@property FSDirectoryCookie cookie;
@property NSUInteger calls;
@property BOOL stopped;
@property(copy) void (^action)(void);
@end

@implementation BudgetPacker

- (BOOL)packEntryWithName:(FSFileName *)name
		 itemType:(FSItemType)type
		   itemID:(FSItemID)itemID
	       nextCookie:(FSDirectoryCookie)cookie
	       attributes:(FSItemAttributes *)attributes
{
	(void)type;
	assert(itemID != FSItemIDInvalid && attributes == nil);
	self.calls++;
	if ([name.string isEqualToString:self.stopName]) {
		self.stopped = YES;
		if (self.action != nil) {
			self.action();
		}
		return NO;
	}
	self.cookie = cookie;
	return YES;
}

@end

static void
poisoned(const uint8_t *bytes, size_t length)
{
	size_t i;

	for (i = 0; i < length; i++) {
		assert(bytes[i] == TEST_GUARD);
	}
}

static void
resource_budgets(NSData *image)
{
	BudgetReader *reader = [[BudgetReader alloc] init];
	NTFSResource *resource;
	struct ntfs_resource_read_budget parent = {0}, child = {0},
					 scopes[NTFS_OPERATION_MAX_DEPTH + 1] = {0};
	struct ntfs_operation_limits limits;
	struct ntfs_resource_read_budget *parentPointer = &parent, *childPointer = &child;
	const struct ntfs_operation_limits *limitsPointer = &limits;
	uint8_t *allocation, *bytes;
	size_t capacity = NTFS_RESOURCE_WINDOW + 3 * TEST_PHYSICAL_BLOCK_BYTES, i;
	NSUInteger calls;

	reader.image = image;
	resource = [[NTFSResource alloc] initWithReader:reader];
	assert(resource != nil &&
	    posix_memalign((void **)&allocation, TEST_PHYSICAL_BLOCK_BYTES, capacity) == 0);
	bytes = allocation + TEST_PHYSICAL_BLOCK_BYTES;
	memset(allocation, TEST_GUARD, capacity);
	ntfs_operation_default_limits(&limits);
	limits.read_bytes = TEST_PHYSICAL_BLOCK_BYTES - 1;
	assert([resource beginReadBudget:&parent limits:&limits] == NTFS_OK);
	assert([resource readAt:1 bytes:bytes length:1] == NTFS_RANGE && reader.reads == 0);
	assert(parent.calls == 0 && parent.bytes == 0 &&
	    parent.exhausted == NTFS_OPERATION_LIMIT_READ_BYTES);
	poisoned(allocation, capacity);
	assert([resource endReadBudget:&parent] == NTFS_OK && resource.isAvailable);
	ntfs_operation_default_limits(&limits);
	limits.read_calls = 1;
	assert([resource beginReadBudget:&parent limits:&limits] == NTFS_OK);
	assert([resource readAt:0 bytes:bytes length:NTFS_RESOURCE_WINDOW + 1] == NTFS_RANGE);
	assert(parent.calls == 1 && parent.bytes == NTFS_RESOURCE_WINDOW && reader.reads == 1);
	assert(memcmp(bytes, image.bytes, NTFS_RESOURCE_WINDOW) == 0);
	poisoned(allocation, TEST_PHYSICAL_BLOCK_BYTES);
	poisoned(bytes + NTFS_RESOURCE_WINDOW,
	    capacity - TEST_PHYSICAL_BLOCK_BYTES - NTFS_RESOURCE_WINDOW);
	assert([resource endReadBudget:&parent] == NTFS_OK);
	assert([resource readAt:0 bytes:bytes length:NTFS_RESOURCE_WINDOW + 1] == NTFS_OK);
	assert(memcmp(bytes, image.bytes, NTFS_RESOURCE_WINDOW + 1) == 0 && reader.reads == 3);
	ntfs_operation_default_limits(&limits);
	limits.read_calls = TEST_CHILD_READS;
	assert([resource beginReadBudget:&parent limits:&limits] == NTFS_OK);
	for (i = 0; i < TEST_CHILD_READS; i++) {
		assert([resource beginReadBudget:&child limits:&limits] == NTFS_OK);
		assert([resource endReadBudget:&parent] == NTFS_BUSY);
		assert([resource readAt:1 bytes:bytes length:1] == NTFS_OK);
		assert(child.calls == 1 && child.bytes == TEST_PHYSICAL_BLOCK_BYTES);
		assert([resource endReadBudget:&child] == NTFS_OK);
	}
	calls = reader.reads;
	assert([resource beginReadBudget:&child limits:&limits] == NTFS_OK);
	assert([resource readAt:1 bytes:bytes length:1] == NTFS_RANGE && reader.reads == calls);
	assert(parent.calls == TEST_CHILD_READS && child.calls == 0 &&
	    [resource readBudgetResult] == NTFS_RANGE);
	assert([resource endReadBudget:&child] == NTFS_OK &&
	    [resource endReadBudget:&parent] == NTFS_OK);
	assert([resource endReadBudget:&parent] == NTFS_INVALID);
	ntfs_operation_default_limits(&limits);
	for (i = 0; i < NTFS_OPERATION_MAX_DEPTH; i++) {
		assert([resource beginReadBudget:&scopes[i] limits:&limits] == NTFS_OK);
	}
	assert([resource beginReadBudget:&scopes[NTFS_OPERATION_MAX_DEPTH]
				  limits:&limits] == NTFS_BUSY);
	for (i = NTFS_OPERATION_MAX_DEPTH; i != 0; i--) {
		assert([resource endReadBudget:&scopes[i - 1]] == NTFS_OK);
	}
	assert([resource beginReadBudget:&parent limits:&limits] == NTFS_OK);
	reader.failed = YES;
	assert([resource readAt:1 bytes:bytes length:1] == NTFS_IO && parent.calls == 1);
	reader.failed = NO;
	assert([resource readAt:1 bytes:bytes length:1] == NTFS_OK && parent.calls == 2);
	assert(
	    [resource readBudgetResult] == NTFS_OK && [resource endReadBudget:&parent] == NTFS_OK);
	assert([resource beginReadBudget:&parent limits:&limits] == NTFS_OK);
	reader.beforeRead = ^{
	  assert([resource endReadBudget:parentPointer] == NTFS_BUSY);
	  assert([resource beginReadBudget:childPointer limits:limitsPointer] == NTFS_BUSY);
	  assert([resource readAt:1 bytes:bytes length:1] == NTFS_BUSY);
	};
	assert([resource readAt:1 bytes:bytes length:1] == NTFS_OK && parent.calls == 1);
	reader.beforeRead = nil;
	assert([resource endReadBudget:&parent] == NTFS_OK);
	free(allocation);
	puts("PASS: physical fragment/rounding quotas refuse before callbacks; nested credits, "
	     "guards, failed attempts, LIFO/depth and fresh retry");
}

static NTFSVolume<TestOperationPolicy> *
new_volume(NSData *image, BOOL modern, BudgetReader **reader_out, FaultResource **resource_out,
    struct ntfs_volume **core_out, FSItem **root_out)
{
	BudgetReader *reader = [[BudgetReader alloc] init];
	FaultResource *resource;
	struct ntfs_environment env;
	struct ntfs_limits limits;
	struct ntfs_volume *core;
	NTFSVolume<TestOperationPolicy> *volume = nil;
	NSError *error = nil;

	reader.image = image;
	resource = [[FaultResource alloc] initWithReader:reader];
	env = [resource environment];
	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	assert(ntfs_mount(&env, &limits, &core) == NTFS_OK);
	if (modern) {
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
		if (@available(macOS 27.0, *)) {
			volume = [[BudgetModernVolume alloc] initWithCore:core resource:resource];
		}
#endif
	} else {
		volume = [[BudgetLegacyVolume alloc] initWithCore:core resource:resource];
	}
	assert(volume != nil);
	*root_out = [volume activate:&error];
	assert(*root_out != nil && error == nil);
	*reader_out = reader;
	*resource_out = resource;
	*core_out = core;
	return volume;
}

static FSItem *
file_item(NTFSVolume *volume, FSItem *root, NSString *filename)
{
	FSFileName *stored;
	NSError *error = nil;
	FSItem *file = [volume lookup:[FSFileName nameWithString:filename]
			  inDirectory:root
			   storedName:&stored
				error:&error];

	assert(file != nil && error == nil && [stored.string isEqualToString:filename]);
	return file;
}

static void
read_error(NTFSVolume *volume, FSItem *file, BOOL modern, NSMutableData *bytes, NSInteger code)
{
	__block NSUInteger replies = 0;

	if (modern) {
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
		if (@available(macOS 27.0, *)) {
			[(NTFSModernVolume *)volume
			    readFromFile:file
				  offset:0
				  length:bytes.length
			      intoBuffer:(FSMutableFileDataBuffer *)bytes
			    replyHandler:^(FSReadFileResult *result, NSError *error) {
			      assert(result == nil && error.code == code);
			      replies++;
			    }];
		}
#endif
	} else {
		[(NTFSLegacyVolume *)volume readFromFile:file
						  offset:0
						  length:bytes.length
					      intoBuffer:(FSMutableFileDataBuffer *)bytes
					    replyHandler:^(size_t count, NSError *error) {
					      assert(count == 0 && error.code == code);
					      replies++;
					    }];
	}
	assert(replies == 1);
}

static void
native_read_and_allocation(NSData *image, BOOL modern)
{
	BudgetReader *reader;
	FaultResource *resource;
	struct ntfs_volume *core;
	FSItem *root, *file;
	NTFSVolume<TestOperationPolicy> *volume =
	    new_volume(image, modern, &reader, &resource, &core, &root);
	NSMutableData *bytes = [NSMutableData dataWithLength:TEST_FRAGMENTED_BYTES];
	struct ntfs_operation_limits limits;
	struct ntfs_operation_usage usage;
	NSError *error = nil;
	size_t done;
	NSUInteger calls, allocations, live;
	uint64_t physical;
	__block NSUInteger replies = 0;

	file = file_item(volume, root, @"fragmented.bin");
	assert([volume readItem:file
			 offset:0
			  bytes:bytes.mutableBytes
			 length:bytes.length
		      completed:&done] == NTFS_OK &&
	    done == bytes.length);
	ntfs_get_operation_limits(core, &limits);
	limits.read_bytes = 2 * TEST_PHYSICAL_BLOCK_BYTES;
	volume.requestLimits = limits;
	volume.limited = YES;
	calls = reader.reads;
	physical = reader.physicalBytes;
	assert([volume readItem:file
			 offset:0
			  bytes:bytes.mutableBytes
			 length:bytes.length
		      completed:&done] == NTFS_OK &&
	    done == bytes.length);
	assert(reader.reads - calls == 2 && reader.physicalBytes - physical == limits.read_bytes);
	ntfs_get_operation_usage(core, &usage);
	assert(usage.read_bytes == TEST_FRAGMENTED_BYTES &&
	    usage.exhausted == NTFS_OPERATION_LIMIT_NONE);
	limits.read_bytes = TEST_FRAGMENTED_BYTES;
	volume.requestLimits = limits;
	calls = reader.reads;
	read_error(volume, file, modern, bytes, EOVERFLOW);
	assert(reader.reads - calls == 1);
	ntfs_get_operation_usage(core, &usage);
	assert(usage.read_bytes == TEST_FRAGMENTED_BYTES &&
	    usage.exhausted == NTFS_OPERATION_LIMIT_NONE);
	volume.limited = NO;
	file = file_item(volume, root, @"hello.txt");
	assert([volume readItem:file
			 offset:0
			  bytes:bytes.mutableBytes
			 length:bytes.length
		      completed:&done] == NTFS_OK);
	assert([volume readItem:file
			 offset:0
			  bytes:bytes.mutableBytes
			 length:bytes.length
		      completed:&done] == NTFS_OK);
	ntfs_get_operation_usage(core, &usage);
	ntfs_get_operation_limits(core, &limits);
	limits.work = usage.work - 1;
	volume.requestLimits = limits;
	volume.limited = YES;
	memset(bytes.mutableBytes, TEST_GUARD, bytes.length);
	calls = reader.reads;
	read_error(volume, file, modern, bytes, EOVERFLOW);
	assert(reader.reads == calls);
	poisoned(bytes.bytes, bytes.length);
	volume.limited = NO;
	assert([volume readItem:file
			 offset:0
			  bytes:bytes.mutableBytes
			 length:bytes.length
		      completed:&done] == NTFS_OK &&
	    done == strlen("Hello from NTFS.\n"));
	ntfs_get_operation_limits(core, &limits);
	limits.allocation_calls = 1;
	volume.requestLimits = limits;
	volume.limited = YES;
	allocations = resource.allocations;
	live = resource.liveAllocations;
	/* Actual handler publication must preserve a null item/name on refusal. */
	if (modern) {
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
		if (@available(macOS 27.0, *)) {
			[(NTFSModernVolume *)volume
			    lookupItemNamed:[FSFileName nameWithString:@"middle.dat"]
				inDirectory:root
				    context:(FSContext *)[[NSObject alloc] init]
			       replyHandler:^(FSLookupItemResult *result, NSError *e) {
				 assert(result == nil && e.code == ENOMEM);
				 replies++;
			       }];
		}
#endif
	} else {
		[(NTFSLegacyVolume *)volume
		    lookupItemNamed:[FSFileName nameWithString:@"middle.dat"]
			inDirectory:root
		       replyHandler:^(FSItem *item, FSFileName *stored, NSError *e) {
			 assert(item == nil && stored == nil && e.code == ENOMEM);
			 replies++;
		       }];
	}
	assert(replies == 1 && resource.allocations - allocations == 1 &&
	    resource.liveAllocations == live);
	volume.limited = NO;
	assert([volume attributes:file error:&error] != nil && error == nil);
	[volume invalidate];
	assert(resource.liveAllocations == 0);
}

static void
enumeration_budgets(NSData *image, BOOL modern, BOOL opaque)
{
	BudgetReader *reader;
	FaultResource *resource;
	struct ntfs_volume *core;
	FSItem *root, *file;
	NTFSVolume<TestOperationPolicy> *volume =
	    new_volume(image, modern, &reader, &resource, &core, &root);
	BudgetPacker *packer = [[BudgetPacker alloc] init];
	struct ntfs_operation_limits limits;
	struct ntfs_operation_usage baseline;
	uint8_t *bytes = malloc(TEST_SECTOR_BYTES);
	NSUInteger calls;
	size_t done;
	NSError *error;
	__block NSUInteger rejected = 0;
	__block size_t nested_done = 0;
	__block enum ntfs_result nested_result;

	assert(bytes != NULL);
	packer.stopName = @"hello.txt";
	assert([volume enumerate:root
			  cookie:FSDirectoryCookieInitial
			verifier:0
		      attributes:NO
			  packer:(FSDirectoryEntryPacker *)packer] == nil &&
	    packer.stopped);
	packer.calls = 0;
	packer.stopped = NO;
	assert([volume enumerate:root
			  cookie:packer.cookie
			verifier:volume.directoryVerifier
		      attributes:NO
			  packer:(FSDirectoryEntryPacker *)packer] == nil &&
	    packer.calls == 1);
	ntfs_get_operation_usage(core, &baseline);
	ntfs_get_operation_limits(core, &limits);
	limits.work = baseline.work - 1;
	volume.requestLimits = limits;
	volume.limited = YES;
	packer.calls = 0;
	error = [volume enumerate:root
			   cookie:packer.cookie
			 verifier:volume.directoryVerifier
		       attributes:NO
			   packer:(FSDirectoryEntryPacker *)packer];
	assert(error.code == EOVERFLOW && packer.calls == 0);
	volume.limited = NO;
	packer.calls = 0;
	assert([volume enumerate:root
			  cookie:packer.cookie
			verifier:volume.directoryVerifier
		      attributes:NO
			  packer:(FSDirectoryEntryPacker *)packer] == nil &&
	    packer.calls == 1);
	if (!opaque) {
		file = file_item(volume, root, @"middle.dat");
		assert([volume readItem:file
				 offset:0
				  bytes:bytes
				 length:TEST_SECTOR_BYTES
			      completed:&done] == NTFS_OK &&
		    done != 0);
		ntfs_get_operation_limits(core, &limits);
		limits.work = baseline.work + done;
		volume.requestLimits = limits;
		volume.limited = YES;
		packer.action = ^{
		  assert([volume readItem:file
				   offset:0
				    bytes:bytes
				   length:TEST_SECTOR_BYTES
				completed:&nested_done] == NTFS_OK &&
		      nested_done == done);
		  nested_result = [volume readItem:file
					    offset:0
					     bytes:bytes
					    length:TEST_SECTOR_BYTES
					 completed:&nested_done];
		  assert(nested_result == NTFS_RANGE && nested_done == 0);
		  rejected++;
		};
		packer.calls = 0;
		calls = reader.reads;
		error = [volume enumerate:root
				   cookie:packer.cookie
				 verifier:volume.directoryVerifier
			       attributes:NO
				   packer:(FSDirectoryEntryPacker *)packer];
		assert(error.code == EOVERFLOW && packer.calls == 1 && rejected == 1 &&
		    reader.reads - calls == baseline.read_calls);
		packer.action = nil;
		volume.limited = NO;
	}
	/* Terminal reentry detaches both caller-owned stack scopes. Their retained
	 * resource remains alive until wrapper finally closes the physical budget. */
	packer.action = ^{
	  [volume invalidate];
	};
	error = [volume enumerate:root
			   cookie:packer.cookie
			 verifier:volume.directoryVerifier
		       attributes:NO
			   packer:(FSDirectoryEntryPacker *)packer];
	assert(error.code == ESTALE && resource.liveAllocations == 0);
	packer.action = nil;
	free(bytes);
}

void
ntfs_test_fskit_operation(NSString *fixtures, BOOL modern)
{
	NSData *image = [NSData
	    dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:@"standard.img"]];
	NSData *opaque = [NSData
	    dataWithContentsOfFile:[fixtures
				       stringByAppendingPathComponent:@"reparse-unknown.img"]];

	assert(image != nil && opaque != nil);
	if (modern) {
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
		if (@available(macOS 27.0, *)) {
		} else {
			puts("SKIP: modern operation-budget replies require the macOS 27 runtime");
			return;
		}
#else
		puts("SKIP: modern operation-budget replies require the macOS 27 SDK/runtime");
		return;
#endif
	} else {
		resource_budgets(image);
	}
	native_read_and_allocation(image, modern);
	enumeration_budgets(image, modern, NO);
	enumeration_budgets(opaque, modern, YES);
	puts("PASS: native operation quotas, physical versus logical reads, exact error replies, "
	     "retry, names-only provider refusal, nested packer credits and terminal scope "
	     "teardown");
}
