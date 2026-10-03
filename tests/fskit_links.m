/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "fskit_links.h"
#import "fskit_resource.h"
#import "fskit_lifecycle.h"
#import "NTFSVolume.h"
#include "fixture.h"
#include <assert.h>
#include <errno.h>
#include <string.h>

enum {
	TEST_LINK_DATA_FIRST_LCN = 128,
	TEST_LINK_DATA_END_LCN = 131,
	TEST_LINK_READ_BYTES = 32,
	TEST_LINK_BUFFER_FILL = 0xa6,
	TEST_LINK_PAGE_CAPACITY = 1,
	TEST_LINK_CHAIN_RECORDS = 63,
	TEST_LINK_ROOT_BASE_ENTRIES = 3,
	TEST_LINK_ROOT_DOT_ENTRIES = 2,
	/* One page per authored edge/prefix entry, then an empty EOF page. */
	TEST_LINK_PAGE_LIMIT =
	    TEST_LINK_CHAIN_RECORDS + TEST_LINK_ROOT_BASE_ENTRIES + TEST_LINK_ROOT_DOT_ENTRIES + 1
};

static NSString *const reparseXattr = @"org.machlin.ntfs.reparse";

@interface LinkOptions : NSObject
@property NSArray<NSString *> *taskOptions;
@end

@implementation LinkOptions
@end

@interface LinkReader : TestReader
@property BOOL fullReadFailure;
@property uint64_t physicalBytes;
@end

@implementation LinkReader

- (size_t)readInto:(void *)buffer
	startingAt:(off_t)offset
	    length:(size_t)length
	     error:(NSError **)error
{
	uint64_t first = (uint64_t)TEST_LINK_DATA_FIRST_LCN * TEST_CLUSTER_BYTES;
	uint64_t end = (uint64_t)TEST_LINK_DATA_END_LCN * TEST_CLUSTER_BYTES;

	self.physicalBytes += length;
	assert(offset >= 0 &&
	    (length == 0 || (uint64_t)offset >= end ||
		((uint64_t)offset < first && length <= first - (uint64_t)offset)));
	if (self.failReadAt != 0 && self.reads + 1 == self.failReadAt) {
		size_t copied = self.fullReadFailure ? length : length / 2;

		assert((uint64_t)offset <= self.image.length &&
		    copied <= self.image.length - (uint64_t)offset);
		memcpy(buffer, (const uint8_t *)self.image.bytes + offset, copied);
	}
	return [super readInto:buffer startingAt:offset length:length error:error];
}

@end

@interface LinkPacker : NSObject
@property BOOL attributes;
@property NSMutableArray<NSDictionary *> *rows;
@property FSDirectoryCookie cookie;
@end

@implementation LinkPacker

- (BOOL)packEntryWithName:(FSFileName *)name
		 itemType:(FSItemType)type
		   itemID:(FSItemID)itemID
	       nextCookie:(FSDirectoryCookie)cookie
	       attributes:(FSItemAttributes *)attributes
{
	assert(itemID != FSItemIDInvalid && cookie != FSDirectoryCookieInitial);
	assert((attributes != nil) == self.attributes);
	if (attributes != nil) {
		assert(attributes.type == type && attributes.fileID == itemID &&
		    [attributes isValid:FSItemAttributeSize] &&
		    [attributes isValid:FSItemAttributeAllocSize]);
	}
	if (self.rows.count == TEST_LINK_PAGE_CAPACITY) {
		return NO;
	}
	[self.rows addObject:@{
		@"name" : name.string,
		@"type" : @(type),
		@"attributes" : attributes != nil ? (id)attributes : NSNull.null
	}];
	self.cookie = cookie;
	return YES;
}

@end

static BOOL
link_error(NSError *error, NSInteger code)
{
	BOOL matches = code == 0
	    ? error == nil
	    : [error.domain isEqualToString:NSPOSIXErrorDomain] && error.code == code;

	if (!matches) {
		fprintf(stderr, "link reply: expected %ld, received %s/%ld\n", (long)code,
		    error == nil ? "none" : error.domain.UTF8String, (long)error.code);
	}
	return matches;
}

static NSInteger
link_code(NSString *name)
{
	NSDictionary *codes = @{
		@"ok" : @0,
		@"unsupported" : @(ENOTSUP),
		@"range" : @(EOVERFLOW),
		@"corrupt" : @(EIO),
		@"not-directory" : @(ENOTDIR),
		@"loop" : @(ELOOP)
	};
	NSNumber *value = codes[name];

	assert(value != nil);
	return value.integerValue;
}

static FSTaskOptions *
link_options(NSArray<NSString *> *roots)
{
	LinkOptions *options = [[LinkOptions alloc] init];
	NSMutableArray<NSString *> *values = [NSMutableArray array];
	NSString *root;

	for (root in roots) {
		[values addObject:[@"windows-root=" stringByAppendingString:root]];
	}
	options.taskOptions = @[
		@"-o",
		[[@[ @"ro", @"ntfs-access=extract" ] arrayByAddingObjectsFromArray:values]
		    componentsJoinedByString:@","]
	];
	return (FSTaskOptions *)options;
}

static FSItem *
link_activate(NTFSVolume *volume, FSTaskOptions *options, BOOL modern, NSInteger code)
{
	__block FSItem *root = nil;
	__block NSUInteger replies = 0;

	if (modern) {
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
		if (@available(macOS 27.0, *)) {
			[(NTFSModernVolume *)volume
			    activateVolumeWithOptions:options
					 replyHandler:^(FSActivateResult *result, NSError *error) {
					   assert(link_error(error, code) &&
					       ((result != nil) == (code == 0)));
					   replies++;
					 }];
			if (code == 0) {
				NSError *error = nil;

				root = [volume activateExtraction:&error];
				assert(root != nil && error == nil);
			}
		}
#endif
	} else {
		[(NTFSLegacyVolume *)volume
		    activateWithOptions:options
			   replyHandler:^(FSItem *item, NSError *error) {
			     assert(link_error(error, code) && ((item != nil) == (code == 0)));
			     root = item;
			     replies++;
			   }];
	}
	assert(replies == 1);
	return root;
}

static NTFSVolume *
link_owner(NSData *image, NSDictionary *test, BOOL modern, TestReader **readerOut,
    FaultResource **resourceOut, FSItem **rootOut, struct ntfs_volume **coreOut)
{
	LinkReader *reader = [[LinkReader alloc] init];
	FaultResource *resource;
	struct ntfs_environment env;
	struct ntfs_limits limits;
	struct ntfs_volume *core = NULL;
	NTFSVolume *volume = nil;
	NSNumber *maximum = test[@"maximum"];
	uint32_t budget = maximum == (id)NSNull.null ? NTFS_FSKIT_DIRECTORY_ENTRY_LIMIT
						     : maximum.unsignedIntValue;

	assert(image != nil);
	reader.image = image;
	resource = [[FaultResource alloc] initWithReader:reader];
	env = [resource environment];
	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	assert(ntfs_mount(&env, &limits, &core) == NTFS_OK);
	if (modern) {
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
		if (@available(macOS 27.0, *)) {
			volume = [[NTFSModernVolume alloc] initWithCore:core
							       resource:resource
						maximumDirectoryEntries:budget];
		}
#endif
	} else {
		volume = [[NTFSLegacyVolume alloc] initWithCore:core
						       resource:resource
					maximumDirectoryEntries:budget];
	}
	assert(volume != nil);
	*rootOut = link_activate(volume, link_options(test[@"roots"]), modern, 0);
	*readerOut = reader;
	*resourceOut = resource;
	if (coreOut != NULL) {
		*coreOut = core;
	}
	return volume;
}

static FSItem *
link_lookup(NTFSVolume *volume, FSItem *parent, NSString *name, BOOL modern, NSInteger code)
{
	__block FSItem *item = nil;
	__block NSUInteger replies = 0;
	FSFileName *spelling = [FSFileName nameWithString:name];

	if (modern) {
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
		if (@available(macOS 27.0, *)) {
			[(NTFSModernVolume *)volume
			    lookupItemNamed:spelling
				inDirectory:parent
				    context:(FSContext *)[[NSObject alloc] init]
			       replyHandler:^(FSLookupItemResult *result, NSError *error) {
				 assert(
				     link_error(error, code) && ((result != nil) == (code == 0)));
				 replies++;
			       }];
			if (code == 0) {
				NSError *error = nil;
				FSFileName *stored;

				item = [volume lookup:spelling
					  inDirectory:parent
					   storedName:&stored
						error:&error];
				assert(item != nil && error == nil);
			}
		}
#endif
	} else {
		[(NTFSLegacyVolume *)volume
		    lookupItemNamed:spelling
			inDirectory:parent
		       replyHandler:^(FSItem *found, FSFileName *stored, NSError *error) {
			 if (!link_error(error, code) || ((found != nil) != (code == 0))) {
				 fprintf(stderr,
				     "link lookup mismatch: expected=%ld actual=%ld item=%s\n",
				     (long)code, (long)error.code,
				     found != nil ? "present" : "nil");
			 }
			 assert(link_error(error, code) && ((found != nil) == (code == 0)));
			 assert(
			     code == 0 ? [stored.data isEqualToData:spelling.data] : stored == nil);
			 item = found;
			 replies++;
		       }];
	}
	assert(replies == 1);
	return item;
}

static void
link_read(NTFSVolume *volume, FSItem *item, NSString *expected, BOOL modern, NSInteger code)
{
	NSError *error = nil;
	FSFileName *target = [volume symbolicLink:item error:&error];
	__block NSUInteger replies = 0;

	assert(link_error(error, code) && ((target != nil) == (code == 0)));
	if (target != nil) {
		assert(
		    [target.data isEqualToData:[expected dataUsingEncoding:NSUTF8StringEncoding]]);
	}
	if (modern) {
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
		if (@available(macOS 27.0, *)) {
			[(NTFSModernVolume *)volume
			    readSymbolicLink:item
				     context:(FSContext *)[[NSObject alloc] init]
				replyHandler:^(FSReadSymlinkResult *result, NSError *e) {
				  assert(link_error(e, code) && ((result != nil) == (code == 0)));
				  replies++;
				}];
		}
#endif
	} else {
		[(NTFSLegacyVolume *)volume
		    readSymbolicLink:item
			replyHandler:^(FSFileName *value, NSError *e) {
			  assert(link_error(e, code) && ((value != nil) == (code == 0)));
			  assert(code != 0 || [value.data isEqualToData:target.data]);
			  replies++;
			}];
	}
	assert(replies == 1);
}

static NSArray<NSDictionary *> *
link_pages(NTFSVolume *volume, FSItem *parent, BOOL attributes, BOOL modern, NSInteger code)
{
	NSMutableArray<NSDictionary *> *rows = [NSMutableArray array];
	FSDirectoryCookie cookie = FSDirectoryCookieInitial;
	NSUInteger pages;

	for (pages = 0; pages < TEST_LINK_PAGE_LIMIT; pages++) {
		LinkPacker *packer = [[LinkPacker alloc] init];
		FSItemGetAttributesRequest *request =
		    attributes ? [[FSItemGetAttributesRequest alloc] init] : nil;
		__block NSError *failure = nil;
		__block NSUInteger replies = 0;

		packer.attributes = attributes;
		packer.rows = [NSMutableArray array];
		packer.cookie = cookie;
		request.wantedAttributes = FSItemAttributeType | FSItemAttributeFileID |
		    FSItemAttributeSize | FSItemAttributeAllocSize;
		if (modern) {
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
			if (@available(macOS 27.0, *)) {
				[(NTFSModernVolume *)volume
				     enumerateDirectory:parent
				       startingAtCookie:cookie
					       verifier:cookie == FSDirectoryCookieInitial
					? FSDirectoryVerifierInitial
					: volume.directoryVerifier
				    providingAttributes:request
					    usingPacker:(FSDirectoryEntryPacker *)packer
						context:(FSContext *)[[NSObject alloc] init]
					   replyHandler:^(
					       FSEnumerateDirectoryResult *result, NSError *error) {
					     assert((result != nil) == (error == nil));
					     failure = error;
					     replies++;
					   }];
			}
#endif
		} else {
			[(NTFSLegacyVolume *)volume
			     enumerateDirectory:parent
			       startingAtCookie:cookie
				       verifier:cookie == FSDirectoryCookieInitial
				? FSDirectoryVerifierInitial
				: volume.directoryVerifier
			    providingAttributes:request
				    usingPacker:(FSDirectoryEntryPacker *)packer
				   replyHandler:^(FSDirectoryVerifier verifier, NSError *error) {
				     assert(verifier == volume.directoryVerifier);
				     failure = error;
				     replies++;
				   }];
		}
		assert(replies == 1);
		[rows addObjectsFromArray:packer.rows];
		if (failure != nil || packer.rows.count == 0) {
			assert(link_error(failure, code));
			return rows;
		}
		assert(packer.cookie != cookie);
		cookie = packer.cookie;
	}
	assert(!"link enumeration failed to terminate within its authored page bound");
	return nil;
}

static void
link_case(NSString *fixtures, NSDictionary *test, BOOL modern)
{
	NSData *image = [NSData
	    dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:test[@"image"]]];
	TestReader *reader;
	FaultResource *resource;
	FSItem *root, *parent, *item;
	NTFSVolume *volume = link_owner(image, test, modern, &reader, &resource, &root, NULL);
	NSArray<NSDictionary *> *rows;
	NSDictionary *row;
	NSError *error = nil;
	FSItemAttributes *attributes;
	NSData *raw = [[NSData alloc] initWithBase64EncodedString:test[@"raw"] options:0];
	NSString *expected = test[@"target"] == NSNull.null ? nil : test[@"target"];
	NSInteger code = link_code(test[@"code"]);
	NSUInteger reads, matches = 0;
	__block NSUInteger replies = 0;
	uint8_t bytes[TEST_LINK_READ_BYTES];
	size_t done, i;

	assert(raw != nil);
	parent =
	    [test[@"nested"] boolValue] ? link_lookup(volume, root, @"Folder", modern, 0) : root;
	item = link_lookup(volume, parent, @"hello.txt", modern, code);
	link_read(volume, parent, nil, modern, EINVAL);
	if (test[@"maximum"] == NSNull.null) {
		rows = link_pages(volume, parent, NO, modern, link_code(test[@"inventory_code"]));
		for (row in rows) {
			if ([row[@"name"] isEqualToString:@"hello.txt"]) {
				assert([row[@"type"] unsignedIntegerValue] ==
				    ([test[@"type"] isEqualToString:@"unknown"]
					    ? FSItemTypeUnknown
					    : FSItemTypeSymlink));
				matches++;
			}
		}
		assert(matches == ([test[@"inventory_code"] isEqualToString:@"ok"] ? 1 : 0));
		rows = link_pages(volume, parent, YES, modern, code);
		rows = link_pages(volume, parent, YES, modern, code);
		for (row in rows) {
			if ([row[@"name"] isEqualToString:@"hello.txt"]) {
				attributes = row[@"attributes"];
				assert(code == 0 && attributes.type == FSItemTypeSymlink &&
				    attributes.size ==
					[expected
					    lengthOfBytesUsingEncoding:NSUTF8StringEncoding] &&
				    attributes.allocSize ==
					[test[@"allocated"] unsignedLongLongValue]);
			}
		}
	}
	if (code == 0) {
		reads = reader.reads;
		link_read(volume, item, expected, modern, 0);
		assert(reader.reads == reads);
		attributes = [volume attributes:item error:&error];
		assert(error == nil && attributes.type == FSItemTypeSymlink &&
		    attributes.size == [expected lengthOfBytesUsingEncoding:NSUTF8StringEncoding] &&
		    attributes.allocSize == [test[@"allocated"] unsignedLongLongValue]);
		assert([[volume xattrNamed:[FSFileName nameWithString:reparseXattr]
				    ofItem:item
				     error:&error] isEqualToData:raw] &&
		    error == nil);
		assert([volume xattrsForItem:item error:&error].count == 1 && error == nil);
		memset(bytes, TEST_LINK_BUFFER_FILL, sizeof(bytes));
		assert([volume readItem:item
				 offset:0
				  bytes:bytes
				 length:sizeof(bytes)
			      completed:&done] == NTFS_UNSUPPORTED &&
		    done == 0);
		for (i = 0; i < sizeof(bytes); i++) {
			assert(bytes[i] == TEST_LINK_BUFFER_FILL);
		}
		assert(link_lookup(volume, item, @"child", modern, ENOTDIR) == nil);
		[volume unmountWithReplyHandler:^{
		  replies++;
		}];
		assert(replies == 1 && volume.lifecycle == NTFSVolumeUnmounted);
		link_read(volume, item, nil, modern, ESTALE);
		[volume mountWithOptions:nil
			    replyHandler:^(NSError *e) {
			      assert(e == nil);
			    }];
		reads = reader.reads;
		link_read(volume, item, expected, modern, 0);
		assert(reader.reads == reads);
		assert([[volume xattrNamed:[FSFileName nameWithString:reparseXattr]
				    ofItem:item
				     error:&error] isEqualToData:raw] &&
		    error == nil);
		reader.revoked = YES;
		link_read(volume, item, nil, modern, EIO);
		assert([volume attributes:item error:&error] == nil && link_error(error, EIO));
		assert([volume xattrNamed:[FSFileName nameWithString:reparseXattr]
				   ofItem:item
				    error:&error] == nil &&
		    link_error(error, EIO));
	}
	[volume invalidate];
	assert(resource.liveAllocations == 0 && [reader.image isEqualToData:image]);
}

static NSData *
link_raw(NTFSLegacyVolume *volume, FSItem *item, NSInteger code)
{
	__block NSData *raw = nil;
	__block NSUInteger replies = 0;

	[volume getXattrNamed:[FSFileName nameWithString:reparseXattr]
		       ofItem:item
		 replyHandler:^(NSData *data, NSError *error) {
		   assert(link_error(error, code) && ((data != nil) == (code == 0)));
		   raw = data;
		   replies++;
		 }];
	assert(replies == 1);
	return raw;
}

static void
link_fault(NSString *fixtures, NSDictionary *test, BOOL metadata, NSUInteger allocation,
    NSUInteger read, BOOL fullFailure, NSUInteger *allocations, NSUInteger *reads)
{
	@autoreleasepool {
		NSData *image = [NSData
		    dataWithContentsOfFile:[fixtures
					       stringByAppendingPathComponent:test[@"image"]]];
		TestReader *reader;
		FaultResource *resource;
		FSItem *root, *item;
		NTFSVolume *volume = link_owner(image, test, NO, &reader, &resource, &root, NULL);
		NSInteger code = allocation != 0 ? ENOMEM : (read != 0 ? EIO : 0);
		NSData *raw, *expected;

		if (metadata) {
			item = link_lookup(volume, root, @"hello.txt", NO, 0);
			[volume unmountWithReplyHandler:^{
			}];
			[volume mountWithOptions:nil
				    replyHandler:^(NSError *e) {
				      assert(e == nil);
				    }];
		}

		resource.allocations = 0;
		reader.reads = 0;
		resource.failAllocationAt = allocation;
		reader.failReadAt = read;
		((LinkReader *)reader).fullReadFailure = fullFailure;
		if (metadata) {
			raw = link_raw((NTFSLegacyVolume *)volume, item, code);
		} else {
			item = link_lookup(volume, root, @"hello.txt", NO, code);
		}
		if (allocations != NULL) {
			*allocations = resource.allocations;
			*reads = reader.reads;
		}
		resource.failAllocationAt = 0;
		reader.failReadAt = 0;
		if (!metadata && code != 0) {
			item = link_lookup(volume, root, @"hello.txt", NO, 0);
		}
		if (metadata) {
			expected = [[NSData alloc] initWithBase64EncodedString:test[@"raw"]
								       options:0];
			raw = link_raw((NTFSLegacyVolume *)volume, item, 0);
			assert([raw isEqualToData:expected]);
		}
		link_read(volume, item, test[@"target"], NO, 0);
		[volume invalidate];
		assert(resource.liveAllocations == 0 && [reader.image isEqualToData:image]);
	}
}

static void
link_configuration(NSString *fixtures, NSDictionary *test, BOOL modern)
{
	NSData *image = [NSData
	    dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:test[@"image"]]];
	TestReader *reader;
	FaultResource *resource;
	FSItem *root;
	NTFSVolume *volume = link_owner(image, test, modern, &reader, &resource, &root, NULL);
	NTFSLinkPolicy *policy;

	assert(link_activate(volume, link_options(@[ @"D:" ]), modern, EINVAL) == nil);
	assert(link_activate(volume, link_options(test[@"roots"]), modern, 0) == root);
	assert(link_activate(volume, link_options(@[ @"C:", @"c:" ]), modern, EINVAL) == nil);
	assert(link_activate(volume, link_options(@[ @"Volume{invalid}" ]), modern, EINVAL) == nil);
	assert(ntfs_native_link_policy(0, @[ @"-o", @"windows-root" ], &policy) == NTFS_INVALID &&
	    policy == nil);
	assert(ntfs_native_link_policy(0, @[ @"windows-root=C:" ], NULL) == NTFS_INVALID);
	[volume invalidate];
	assert(resource.liveAllocations == 0);
}

struct link_budget_usage {
	struct ntfs_operation_usage core;
	uint64_t physicalCalls, physicalBytes;
};

enum {
	TEST_LINK_LOGICAL_READ_CALLS,
	TEST_LINK_LOGICAL_READ_BYTES,
	TEST_LINK_ALLOCATION_CALLS,
	TEST_LINK_ALLOCATION_BYTES,
	TEST_LINK_WORK,
	TEST_LINK_PHYSICAL_READ_CALLS,
	TEST_LINK_PHYSICAL_READ_BYTES,
	TEST_LINK_BUDGET_DIMENSIONS,
	TEST_LINK_CORE_BUDGETS = TEST_LINK_PHYSICAL_READ_CALLS,
	TEST_LINK_PHYSICAL_BUDGETS = TEST_LINK_BUDGET_DIMENSIONS - TEST_LINK_CORE_BUDGETS
};

static void
link_budget_run(NSString *fixtures, NSDictionary *test,
    const struct ntfs_operation_limits *coreLimits,
    const struct ntfs_operation_limits *physicalLimits, NSInteger code,
    enum ntfs_operation_limit refused, struct link_budget_usage *observation)
{
	@autoreleasepool {
		NSData *image = [NSData
		    dataWithContentsOfFile:[fixtures
					       stringByAppendingPathComponent:test[@"image"]]];
		TestReader *reader;
		FaultResource *resource;
		FSItem *root, *item;
		struct ntfs_volume *core;
		struct ntfs_operation operation = {0};
		struct ntfs_resource_read_budget physical = {0};
		struct ntfs_operation_limits defaults;
		struct ntfs_operation_usage usage;
		NTFSVolume *volume = link_owner(image, test, NO, &reader, &resource, &root, &core);
		enum ntfs_result coreResult, physicalResult;

		ntfs_operation_default_limits(&defaults);
		reader.reads = 0;
		((LinkReader *)reader).physicalBytes = 0;
		resource.allocations = 0;
		assert(ntfs_operation_begin(core, coreLimits, &operation) == NTFS_OK);
		assert([resource beginReadBudget:&physical
					  limits:physicalLimits != NULL ? physicalLimits
									: &defaults] == NTFS_OK);
		item = link_lookup(volume, root, @"hello.txt", NO, code);
		coreResult = ntfs_operation_result(&operation);
		physicalResult = [resource readBudgetResult];
		assert([resource endReadBudget:&physical] == NTFS_OK);
		assert(ntfs_operation_end(&operation, &usage) == NTFS_OK);
		assert(physical.calls == reader.reads &&
		    physical.bytes == ((LinkReader *)reader).physicalBytes);
		assert(usage.allocation_calls == resource.allocations);
		if (code == 0) {
			assert(coreResult == NTFS_OK && physicalResult == NTFS_OK &&
			    usage.exhausted == NTFS_OPERATION_LIMIT_NONE &&
			    physical.exhausted == NTFS_OPERATION_LIMIT_NONE);
		} else {
			assert((code == EOVERFLOW || code == ENOMEM) && item == nil);
			assert(coreLimits != NULL
				? coreResult == (code == ENOMEM ? NTFS_NO_MEMORY : NTFS_RANGE) &&
				    usage.exhausted == refused
				: code == EOVERFLOW && physicalResult == NTFS_RANGE &&
				    physical.exhausted == refused);
		}
		if (observation != NULL) {
			*observation =
			    (struct link_budget_usage){usage, physical.calls, physical.bytes};
		}
		/* Sealing either ancestor must leave ordinary retry and cleanup usable. */
		if (code != 0) {
			item = link_lookup(volume, root, @"hello.txt", NO, 0);
		}
		link_read(volume, item, test[@"target"], NO, 0);
		[volume invalidate];
		assert(resource.liveAllocations == 0 && [reader.image isEqualToData:image]);
	}
}

static void
link_budgets(NSString *fixtures, NSDictionary *test)
{
	struct link_budget_usage observed;
	struct ntfs_operation_limits limits;
	uint64_t *selected;
	NSUInteger dimension;
	BOOL below;
	NSInteger code;
	enum ntfs_operation_limit refused;

	link_budget_run(fixtures, test, NULL, NULL, 0, NTFS_OPERATION_LIMIT_NONE, &observed);
	for (dimension = 0; dimension < TEST_LINK_CORE_BUDGETS + TEST_LINK_PHYSICAL_BUDGETS;
	    dimension++) {
		for (below = NO;; below = YES) {
			ntfs_operation_default_limits(&limits);
			switch (dimension) {
			case TEST_LINK_LOGICAL_READ_CALLS:
				selected = &limits.read_calls;
				*selected = observed.core.read_calls;
				refused = NTFS_OPERATION_LIMIT_READ_CALLS;
				break;
			case TEST_LINK_LOGICAL_READ_BYTES:
				selected = &limits.read_bytes;
				*selected = observed.core.read_bytes;
				refused = NTFS_OPERATION_LIMIT_READ_BYTES;
				break;
			case TEST_LINK_ALLOCATION_CALLS:
				selected = &limits.allocation_calls;
				*selected = observed.core.allocation_calls;
				refused = NTFS_OPERATION_LIMIT_ALLOCATION_CALLS;
				break;
			case TEST_LINK_ALLOCATION_BYTES:
				selected = &limits.allocation_bytes;
				*selected = observed.core.allocation_bytes;
				refused = NTFS_OPERATION_LIMIT_ALLOCATION_BYTES;
				break;
			case TEST_LINK_WORK:
				selected = &limits.work;
				*selected = observed.core.work;
				refused = NTFS_OPERATION_LIMIT_WORK;
				break;
			case TEST_LINK_PHYSICAL_READ_CALLS:
				selected = &limits.read_calls;
				*selected = observed.physicalCalls;
				refused = NTFS_OPERATION_LIMIT_READ_CALLS;
				break;
			default:
				selected = &limits.read_bytes;
				*selected = observed.physicalBytes;
				refused = NTFS_OPERATION_LIMIT_READ_BYTES;
				break;
			}
			assert(*selected > 1);
			*selected -= below ? 1 : 0;
			code = refused == NTFS_OPERATION_LIMIT_ALLOCATION_CALLS ||
				refused == NTFS_OPERATION_LIMIT_ALLOCATION_BYTES
			    ? ENOMEM
			    : EOVERFLOW;
			fprintf(stderr, "link budget: %s dimension=%lu below=%u credits=%llu\n",
			    [test[@"image"] UTF8String], (unsigned long)dimension, (unsigned)below,
			    (unsigned long long)*selected);
			link_budget_run(fixtures, test,
			    dimension < TEST_LINK_CORE_BUDGETS ? &limits : NULL,
			    dimension < TEST_LINK_CORE_BUDGETS ? NULL : &limits, below ? code : 0,
			    below ? refused : NTFS_OPERATION_LIMIT_NONE, NULL);
			if (below) {
				break;
			}
		}
	}
	printf("PASS: native link %s, %u core/physical exact-one-below boundaries, fresh retry "
	       "and exact cleanup\n",
	    [test[@"image"] UTF8String], (TEST_LINK_CORE_BUDGETS + TEST_LINK_PHYSICAL_BUDGETS) * 2);
}

void
ntfs_test_fskit_links(NSString *fixtures, BOOL modern)
{
	NSArray<NSDictionary *> *tests;
	NSDictionary *test, *listed = nil, *drive = nil, *alias = nil, *chain = nil,
			    *chainAlias = nil;
	NSArray<NSDictionary *> *faultTests;
	BOOL metadata;
	NSUInteger allocations, reads, fault;

	if (modern && !ntfs_test_native_reclaim_available()) {
		puts("SKIP: modern link projection requires the macOS 27 SDK/runtime");
		return;
	}
	tests = [NSJSONSerialization
	    JSONObjectWithData:[NSData
				   dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:
								  @"native-links.json"]]
		       options:0
			 error:NULL];
	assert(tests.count != 0);
	for (test in tests) {
		@autoreleasepool {
			fprintf(stderr, "link case: %s\n", [test[@"image"] UTF8String]);
			link_case(fixtures, test, modern);
		}
		if ([test[@"image"] isEqualToString:@"native-link-listed.img"]) {
			listed = test;
		}
		if ([test[@"image"] isEqualToString:@"native-link-win32.img"]) {
			drive = test;
		}
		if ([test[@"image"] isEqualToString:@"native-link-reserved.img"]) {
			alias = test;
		}
		if ([test[@"image"] isEqualToString:@"native-link-chain-listed.img"]) {
			chain = test;
		}
		if ([test[@"image"] isEqualToString:@"native-link-chain-alias.img"]) {
			chainAlias = test;
		}
	}
	assert(drive != nil && listed != nil && alias != nil && chain != nil && chainAlias != nil);
	link_configuration(fixtures, drive, modern);
	if (!modern) {
		link_budgets(fixtures, chain);
		link_budgets(fixtures, chainAlias);
		faultTests = @[ listed, alias, chain, chainAlias ];
		for (test in faultTests) {
			for (metadata = NO;; metadata = YES) {
				link_fault(
				    fixtures, test, metadata, 0, 0, NO, &allocations, &reads);
				for (fault = 1; fault <= allocations; fault++) {
					link_fault(
					    fixtures, test, metadata, fault, 0, NO, NULL, NULL);
				}
				for (fault = 1; fault <= reads; fault++) {
					link_fault(
					    fixtures, test, metadata, 0, fault, NO, NULL, NULL);
					link_fault(
					    fixtures, test, metadata, 0, fault, YES, NULL, NULL);
				}
				printf("PASS: native link %s %s, %lu allocation/%lu read fault "
				       "partial/full read positions, retry, exact replies and "
				       "cleanup\n",
				    [test[@"image"] UTF8String], metadata ? "metadata" : "lookup",
				    (unsigned long)allocations, (unsigned long)reads);
				if (metadata) {
					break;
				}
			}
		}
	}
	printf("PASS: %s link projection, %lu independent path/storage verdicts, explicit root "
	       "bindings, aliases, inode limits, pages, raw metadata, remount and revocation\n",
	    modern ? "modern" : "legacy", (unsigned long)tests.count);
}
