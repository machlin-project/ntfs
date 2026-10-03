/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "fskit_enumeration.h"
#import "fskit_resource.h"
#import "fskit_lifecycle.h"
#import "NTFSVolume.h"
#import "NTFSNames.h"
#include "fixture.h"
#include <assert.h>
#include <errno.h>

enum {
	TEST_ENUMERATION_DOT_ENTRIES = 2,
	TEST_ENUMERATION_CURRENT_ENTRY = 0,
	TEST_ENUMERATION_PARENT_ENTRY = 1,
	TEST_ENUMERATION_FIRST_CAPACITY = 1,
	TEST_ENUMERATION_SECOND_CAPACITY = 2,
	TEST_ENUMERATION_SCAN_LIMIT = 1,
	TEST_ENUMERATION_INDEX_LCN = 100,
	TEST_ENUMERATION_INDEX_PROBE_BLOCKS = 2,
	TEST_ENUMERATION_THIRD_POSITION = 3,
	TEST_ENUMERATION_READERS = 2,
	TEST_CONTINUATION_REUSE = 0,
	TEST_CONTINUATION_FAILED_OPEN,
	TEST_CONTINUATION_EVICTION,
	TEST_CONTINUATION_PRESSURE,
	TEST_CONTINUATION_MODES,
	TEST_ENUMERATION_OBSERVE_ERROR = -1
};

@interface EnumerationPacker : NSObject
@property NSUInteger capacity;
@property BOOL expectsAttributes;
@property NSMutableArray<NSString *> *names;
@property NSMutableArray<NSNumber *> *identifiers;
@property NSMutableArray<NSNumber *> *types;
@property FSDirectoryCookie cookie;
@property(copy) void (^beforePacking)(void);
@end

@implementation EnumerationPacker

- (BOOL)packEntryWithName:(FSFileName *)name
		 itemType:(FSItemType)type
		   itemID:(FSItemID)itemID
	       nextCookie:(FSDirectoryCookie)cookie
	       attributes:(FSItemAttributes *)attributes
{
	assert(itemID != FSItemIDInvalid && cookie != FSDirectoryCookieInitial);
	assert(type == FSItemTypeFile || type == FSItemTypeDirectory);
	if (self.expectsAttributes) {
		assert(attributes != nil && attributes.type == type && attributes.fileID == itemID);
	} else {
		assert(attributes == nil);
	}
	if (self.beforePacking != nil) {
		self.beforePacking();
	}
	if (self.names.count == self.capacity) {
		return NO;
	}
	[self.names addObject:name.string];
	[self.identifiers addObject:@(itemID)];
	[self.types addObject:@(type)];
	self.cookie = cookie;
	return YES;
}

@end

static EnumerationPacker *
enumeration_packer(NSUInteger capacity, BOOL attributes)
{
	EnumerationPacker *packer = [[EnumerationPacker alloc] init];

	packer.capacity = capacity;
	packer.expectsAttributes = attributes;
	packer.names = [NSMutableArray array];
	packer.identifiers = [NSMutableArray array];
	packer.types = [NSMutableArray array];
	return packer;
}

static NSError *
enumeration_reply(NTFSVolume *volume, FSItem *directory, FSDirectoryCookie cookie,
    FSDirectoryVerifier verifier, EnumerationPacker *packer, BOOL modern, NSInteger errorCode)
{
	FSItemGetAttributesRequest *attributes =
	    packer.expectsAttributes ? [[FSItemGetAttributesRequest alloc] init] : nil;
	__block NSUInteger replies = 0;
	__block NSError *observed = nil;

	if (attributes != nil) {
		attributes.wantedAttributes =
		    FSItemAttributeType | FSItemAttributeFileID | FSItemAttributeSize;
	}
	if (modern) {
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
		if (@available(macOS 27.0, *)) {
			/* Opaque context double: this handler does not consume identities. */
			[(NTFSModernVolume *)volume
			     enumerateDirectory:directory
			       startingAtCookie:cookie
				       verifier:verifier
			    providingAttributes:attributes
				    usingPacker:(FSDirectoryEntryPacker *)packer
					context:(FSContext *)[[NSObject alloc] init]
				   replyHandler:^(
				       FSEnumerateDirectoryResult *result, NSError *error) {
				     assert((result != nil) == (error == nil));
				     assert(error == nil ||
					 [error.domain isEqualToString:NSPOSIXErrorDomain]);
				     if (errorCode != TEST_ENUMERATION_OBSERVE_ERROR) {
					     assert(errorCode == 0 ? error == nil
								   : error.code == errorCode);
				     }
				     observed = error;
				     replies++;
				   }];
		}
#endif
	} else {
		[(NTFSLegacyVolume *)volume
		     enumerateDirectory:directory
		       startingAtCookie:cookie
			       verifier:verifier
		    providingAttributes:attributes
			    usingPacker:(FSDirectoryEntryPacker *)packer
			   replyHandler:^(FSDirectoryVerifier current, NSError *error) {
			     assert(error == nil
				     ? current == volume.directoryVerifier
				     : [error.domain isEqualToString:NSPOSIXErrorDomain]);
			     if (errorCode != TEST_ENUMERATION_OBSERVE_ERROR) {
				     assert(
					 errorCode == 0 ? error == nil : error.code == errorCode);
			     }
			     observed = error;
			     replies++;
			   }];
	}
	assert(replies == 1);
	return observed;
}

static NTFSVolume *
enumeration_owner(NSData *image, BOOL modern, uint32_t maximum, TestReader **readerOut,
    FaultResource **resourceOut, FSItem **rootOut)
{
	TestReader *reader = [[TestReader alloc] init];
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
			volume = [[NTFSModernVolume alloc] initWithCore:core
							       resource:resource
						maximumDirectoryEntries:maximum];
		}
#endif
	} else {
		volume = [[NTFSLegacyVolume alloc] initWithCore:core
						       resource:resource
					maximumDirectoryEntries:maximum];
	}
	assert(volume != nil);
	*rootOut = [volume activateExtraction:&error];
	assert(*rootOut != nil && error == nil);
	*readerOut = reader;
	*resourceOut = resource;
	return volume;
}

static void
test_directory_views(NTFSVolume *volume, FSItem *directory, FSItemID parentID,
    NSArray<NSString *> *expected, BOOL modern, TestReader *reader, FaultResource *resource)
{
	NSMutableArray<NSString *> *names = [NSMutableArray array];
	NSMutableArray<NSString *> *withAttributes = [NSMutableArray array];
	NSMutableArray<NSString *> *expectedNames =
	    [NSMutableArray arrayWithArray:@[ @".", @".." ]];
	EnumerationPacker *page;
	FSDirectoryCookie namesCookie = FSDirectoryCookieInitial;
	FSDirectoryCookie attributesCookie = FSDirectoryCookieInitial;
	FSDirectoryCookie firstCookie;
	FSItemID ownID;
	NSError *error = nil;
	NSUInteger reads, allocations, round;

	[expectedNames addObjectsFromArray:expected];
	ownID = [volume attributes:directory error:&error].fileID;
	assert(error == nil && ownID != FSItemIDInvalid);
	/* The virtual prefix needs neither core allocation nor resource I/O. */
	reads = reader.reads;
	allocations = resource.allocations;
	resource.failAllocation = YES;
	reader.failed = YES;
	page = enumeration_packer(0, NO);
	enumeration_reply(volume, directory, FSDirectoryCookieInitial, FSDirectoryVerifierInitial,
	    page, modern, 0);
	assert(page.names.count == 0 && page.cookie == FSDirectoryCookieInitial);
	page = enumeration_packer(TEST_ENUMERATION_FIRST_CAPACITY, NO);
	enumeration_reply(volume, directory, FSDirectoryCookieInitial, FSDirectoryVerifierInitial,
	    page, modern, 0);
	assert(([page.names isEqualToArray:@[ @"." ]]) &&
	    page.identifiers.firstObject.unsignedLongLongValue == ownID);
	firstCookie = page.cookie;
	page = enumeration_packer(0, NO);
	enumeration_reply(
	    volume, directory, firstCookie, volume.directoryVerifier, page, modern, 0);
	assert(
	    page.names.count == 0 && reader.reads == reads && resource.allocations == allocations);
	resource.failAllocation = NO;
	reader.failed = NO;
	for (round = 0; round <= expectedNames.count; round++) {
		page = enumeration_packer(TEST_ENUMERATION_FIRST_CAPACITY, NO);
		enumeration_reply(volume, directory, namesCookie,
		    namesCookie == FSDirectoryCookieInitial ? FSDirectoryVerifierInitial
							    : volume.directoryVerifier,
		    page, modern, 0);
		if (names.count < TEST_ENUMERATION_DOT_ENTRIES && page.names.count != 0) {
			assert(page.types.firstObject.unsignedIntegerValue == FSItemTypeDirectory);
			assert(page.identifiers.firstObject.unsignedLongLongValue ==
			    (names.count == TEST_ENUMERATION_CURRENT_ENTRY ? ownID : parentID));
		}
		[names addObjectsFromArray:page.names];
		if (page.names.count != 0) {
			namesCookie = page.cookie;
		}
		page = enumeration_packer(TEST_ENUMERATION_SECOND_CAPACITY, YES);
		enumeration_reply(volume, directory, attributesCookie,
		    attributesCookie == FSDirectoryCookieInitial ? FSDirectoryVerifierInitial
								 : volume.directoryVerifier,
		    page, modern, 0);
		[withAttributes addObjectsFromArray:page.names];
		if (page.names.count != 0) {
			attributesCookie = page.cookie;
		}
		page = enumeration_packer(0, NO);
		enumeration_reply(volume, directory, FSDirectoryCookieInitial,
		    FSDirectoryVerifierInitial, page, modern, 0);
		assert(page.names.count == 0);
	}
	assert([names isEqualToArray:expectedNames] && [withAttributes isEqualToArray:expected]);
	page = enumeration_packer(TEST_ENUMERATION_FIRST_CAPACITY, NO);
	enumeration_reply(
	    volume, directory, namesCookie, volume.directoryVerifier, page, modern, 0);
	assert(page.names.count == 0);
	page = enumeration_packer(TEST_ENUMERATION_FIRST_CAPACITY, YES);
	enumeration_reply(volume, directory, namesCookie, volume.directoryVerifier, page, modern,
	    FSErrorInvalidDirectoryCookie);
	if (attributesCookie != FSDirectoryCookieInitial) {
		page = enumeration_packer(TEST_ENUMERATION_FIRST_CAPACITY, NO);
		enumeration_reply(volume, directory, attributesCookie, volume.directoryVerifier,
		    page, modern, FSErrorInvalidDirectoryCookie);
	}
	page = enumeration_packer(TEST_ENUMERATION_FIRST_CAPACITY, NO);
	enumeration_reply(volume, directory, namesCookie, volume.directoryVerifier ^ UINT64_C(1),
	    page, modern, FSErrorInvalidDirectoryCookie);
	assert(page.names.count == 0);
	page = enumeration_packer(TEST_ENUMERATION_FIRST_CAPACITY, NO);
	enumeration_reply(volume, directory, namesCookie + 1, volume.directoryVerifier, page,
	    modern, FSErrorInvalidDirectoryCookie);
	assert(page.names.count == 0);
	page = enumeration_packer(TEST_ENUMERATION_FIRST_CAPACITY, YES);
	enumeration_reply(volume, directory, attributesCookie + 1, volume.directoryVerifier, page,
	    modern, FSErrorInvalidDirectoryCookie);
	assert(page.names.count == 0);
	page = enumeration_packer(TEST_ENUMERATION_FIRST_CAPACITY, NO);
	enumeration_reply(volume, directory, UINT64_MAX, volume.directoryVerifier, page, modern,
	    FSErrorInvalidDirectoryCookie);
	assert(page.names.count == 0);
}

struct enumeration_work {
	NSUInteger allocations, reads;
};

static struct enumeration_work
test_enumeration_fault(NSData *image, NSArray<NSString *> *expected, NSUInteger failedAllocation,
    NSUInteger failedRead)
{
	struct enumeration_work work;

	@autoreleasepool {
		TestReader *reader;
		FaultResource *resource;
		NTFSVolume *volume;
		FSItem *root;
		NSData *original = [[NSData alloc] initWithBytes:image.bytes length:image.length];
		EnumerationPacker *page;
		NSMutableArray<NSString *> *expectedNames =
		    [NSMutableArray arrayWithArray:@[ @".", @".." ]];
		NSUInteger allocations, reads;
		NSInteger errorCode;

		[expectedNames addObjectsFromArray:expected];
		volume = enumeration_owner(
		    image, NO, NTFS_FSKIT_DIRECTORY_ENTRY_LIMIT, &reader, &resource, &root);
		allocations = resource.allocations;
		reads = reader.reads;
		resource.failAllocationAt =
		    failedAllocation == 0 ? 0 : allocations + failedAllocation;
		reader.failReadAt = failedRead == 0 ? 0 : reads + failedRead;
		errorCode = failedAllocation != 0 ? ENOMEM : failedRead != 0 ? EIO : 0;
		page = enumeration_packer(expectedNames.count + 1, NO);
		enumeration_reply(volume, root, FSDirectoryCookieInitial,
		    FSDirectoryVerifierInitial, page, NO, errorCode);
		work.allocations = resource.allocations - allocations;
		work.reads = reader.reads - reads;
		if (errorCode == 0) {
			assert([page.names isEqualToArray:expectedNames]);
		} else {
			resource.failAllocationAt = 0;
			reader.failReadAt = 0;
			page = enumeration_packer(expectedNames.count + 1, NO);
			enumeration_reply(volume, root, FSDirectoryCookieInitial,
			    FSDirectoryVerifierInitial, page, NO, 0);
			assert([page.names isEqualToArray:expectedNames]);
		}
		[volume invalidate];
		assert(resource.liveAllocations == 0 && [image isEqualToData:original]);
	}
	return work;
}

static void
test_saved_continuations(NSData *image, BOOL modern, BOOL separateViews, NSUInteger mode)
{
	TestReader *reader;
	FaultResource *resource;
	NTFSVolume *volume;
	FSItem *root;
	EnumerationPacker *first, *second, *page;
	FSDirectoryCookie firstCookie, secondCookie, thirdCookie;
	NSUInteger observed, retained;
	NSData *original = [[NSData alloc] initWithBytes:image.bytes length:image.length];

	volume = enumeration_owner(
	    image, modern, NTFS_FSKIT_DIRECTORY_ENTRY_LIMIT, &reader, &resource, &root);
	[volume.readCachePolicy applyPressure:DISPATCH_MEMORYPRESSURE_NORMAL];
	reader.observedStart = (uint64_t)TEST_ENUMERATION_INDEX_LCN * TEST_CLUSTER_BYTES;
	reader.observedEnd =
	    reader.observedStart + TEST_ENUMERATION_INDEX_PROBE_BLOCKS * TEST_CLUSTER_BYTES;
	first = enumeration_packer(
	    TEST_ENUMERATION_FIRST_CAPACITY + (separateViews ? TEST_ENUMERATION_DOT_ENTRIES : 0),
	    !separateViews);
	enumeration_reply(
	    volume, root, FSDirectoryCookieInitial, FSDirectoryVerifierInitial, first, modern, 0);
	second = enumeration_packer(TEST_ENUMERATION_SECOND_CAPACITY, YES);
	enumeration_reply(
	    volume, root, FSDirectoryCookieInitial, FSDirectoryVerifierInitial, second, modern, 0);
	firstCookie = first.cookie;
	secondCookie = second.cookie;
	assert(firstCookie != secondCookie && reader.observedReads != 0);
	reader.refuseObservedReads = YES;
	observed = reader.observedReads;
	page = enumeration_packer(0, !separateViews);
	enumeration_reply(volume, root, firstCookie, volume.directoryVerifier, page, modern, 0);
	page = enumeration_packer(0, YES);
	enumeration_reply(volume, root, secondCookie, volume.directoryVerifier, page, modern, 0);
	assert(reader.observedReads == observed);
	reader.refuseObservedReads = NO;
	if (mode == TEST_CONTINUATION_FAILED_OPEN) {
		resource.failAllocationAt = resource.allocations + 1;
		page = enumeration_packer(TEST_ENUMERATION_FIRST_CAPACITY, YES);
		enumeration_reply(volume, root, FSDirectoryCookieInitial,
		    FSDirectoryVerifierInitial, page, modern, ENOMEM);
		assert(page.names.count == 0);
		resource.failAllocationAt = 0;
		reader.refuseObservedReads = YES;
		observed = reader.observedReads;
		page = enumeration_packer(0, YES);
		enumeration_reply(
		    volume, root, secondCookie, volume.directoryVerifier, page, modern, 0);
		assert(reader.observedReads == observed);
	} else if (mode == TEST_CONTINUATION_EVICTION) {
		page = enumeration_packer(TEST_ENUMERATION_THIRD_POSITION, YES);
		enumeration_reply(volume, root, FSDirectoryCookieInitial,
		    FSDirectoryVerifierInitial, page, modern, 0);
		thirdCookie = page.cookie;
		reader.refuseObservedReads = YES;
		observed = reader.observedReads;
		page = enumeration_packer(0, YES);
		enumeration_reply(
		    volume, root, thirdCookie, volume.directoryVerifier, page, modern, 0);
		assert(reader.observedReads == observed);
		page = enumeration_packer(0, !separateViews);
		enumeration_reply(
		    volume, root, firstCookie, volume.directoryVerifier, page, modern, EIO);
		assert(reader.observedReads > observed);
	} else if (mode == TEST_CONTINUATION_PRESSURE) {
		retained = resource.liveAllocations;
		[volume.readCachePolicy applyPressure:DISPATCH_MEMORYPRESSURE_WARN];
		reader.refuseObservedReads = YES;
		observed = reader.observedReads;
		page = enumeration_packer(0, YES);
		enumeration_reply(
		    volume, root, secondCookie, volume.directoryVerifier, page, modern, 0);
		assert(reader.observedReads == observed && resource.liveAllocations < retained);
		page = enumeration_packer(0, !separateViews);
		enumeration_reply(
		    volume, root, firstCookie, volume.directoryVerifier, page, modern, EIO);
		assert(reader.observedReads > observed);
	}
	reader.refuseObservedReads = NO;
	[volume invalidate];
	assert(resource.liveAllocations == 0 && [image isEqualToData:original]);
}

static void
test_continuation_reentry(NSData *image, BOOL modern)
{
	TestReader *reader;
	FaultResource *resource;
	NTFSVolume *volume;
	FSItem *root;
	EnumerationPacker *outer, *inner, *third, *page;
	NSUInteger observed;
	__block NSUInteger nested = 0;

	volume = enumeration_owner(
	    image, modern, NTFS_FSKIT_DIRECTORY_ENTRY_LIMIT, &reader, &resource, &root);
	[volume.readCachePolicy applyPressure:DISPATCH_MEMORYPRESSURE_NORMAL];
	outer = enumeration_packer(TEST_ENUMERATION_FIRST_CAPACITY, YES);
	inner = enumeration_packer(TEST_ENUMERATION_SECOND_CAPACITY, YES);
	third = enumeration_packer(0, YES);
	outer.beforePacking = ^{
	  if (nested == 0) {
		  nested++;
		  enumeration_reply(volume, root, FSDirectoryCookieInitial,
		      FSDirectoryVerifierInitial, inner, modern, 0);
	  }
	};
	inner.beforePacking = ^{
	  if (nested == 1) {
		  NSUInteger allocations = resource.allocations, reads = reader.reads;

		  nested++;
		  enumeration_reply(volume, root, FSDirectoryCookieInitial,
		      FSDirectoryVerifierInitial, third, modern, EBUSY);
		  assert(third.names.count == 0 && resource.allocations == allocations &&
		      reader.reads == reads);
	  }
	};
	enumeration_reply(
	    volume, root, FSDirectoryCookieInitial, FSDirectoryVerifierInitial, outer, modern, 0);
	assert(nested == TEST_ENUMERATION_READERS &&
	    ([outer.names isEqualToArray:@[ @"compressed.bin" ]]) &&
	    ([inner.names isEqualToArray:@[ @"compressed.bin", @"extended.bin" ]]));
	reader.observedStart = (uint64_t)TEST_ENUMERATION_INDEX_LCN * TEST_CLUSTER_BYTES;
	reader.observedEnd =
	    reader.observedStart + TEST_ENUMERATION_INDEX_PROBE_BLOCKS * TEST_CLUSTER_BYTES;
	reader.refuseObservedReads = YES;
	observed = reader.observedReads;
	page = enumeration_packer(0, YES);
	enumeration_reply(volume, root, outer.cookie, volume.directoryVerifier, page, modern, 0);
	page = enumeration_packer(0, YES);
	enumeration_reply(volume, root, inner.cookie, volume.directoryVerifier, page, modern, 0);
	assert(reader.observedReads == observed);
	[volume invalidate];
	assert(resource.liveAllocations == 0);
}

static void
test_enumeration_remount_in_packer(NSData *image, BOOL modern, BOOL attributes)
{
	TestReader *reader;
	FaultResource *resource;
	NTFSVolume *volume;
	FSItem *root;
	EnumerationPacker *page, *retry;
	__block NSUInteger teardowns = 0;

	volume = enumeration_owner(
	    image, modern, NTFS_FSKIT_DIRECTORY_ENTRY_LIMIT, &reader, &resource, &root);
	page = enumeration_packer(TEST_ENUMERATION_FIRST_CAPACITY, attributes);
	page.beforePacking = ^{
	  [volume unmountWithReplyHandler:^{
	    assert(volume.lifecycle == NTFSVolumeUnmounted);
	    teardowns++;
	  }];
	  [volume mountWithOptions:nil
		      replyHandler:^(NSError *error) {
			assert(error == nil && volume.lifecycle == NTFSVolumeActive);
			teardowns++;
		      }];
	};
	enumeration_reply(volume, root, FSDirectoryCookieInitial, FSDirectoryVerifierInitial, page,
	    modern, ESTALE);
	assert(teardowns == TEST_ENUMERATION_READERS && page.names.count == 1);
	retry = enumeration_packer(TEST_ENUMERATION_FIRST_CAPACITY, attributes);
	enumeration_reply(
	    volume, root, FSDirectoryCookieInitial, FSDirectoryVerifierInitial, retry, modern, 0);
	assert([retry.names isEqualToArray:page.names]);
	[volume invalidate];
	assert(resource.liveAllocations == 0);
}

static void
test_completed_continuation_reuse(NSData *image, NSArray<NSString *> *expected, BOOL modern)
{
	TestReader *reader;
	FaultResource *resource;
	NTFSVolume *volume;
	FSItem *root;
	EnumerationPacker *page;
	FSDirectoryCookie endCookie;
	NSUInteger retained, reads, allocations;

	volume = enumeration_owner(
	    image, modern, NTFS_FSKIT_DIRECTORY_ENTRY_LIMIT, &reader, &resource, &root);
	[volume.readCachePolicy applyPressure:DISPATCH_MEMORYPRESSURE_NORMAL];
	page = enumeration_packer(expected.count + 1, YES);
	enumeration_reply(
	    volume, root, FSDirectoryCookieInitial, FSDirectoryVerifierInitial, page, modern, 0);
	assert([page.names isEqualToArray:expected]);
	retained = resource.liveAllocations;
	page = enumeration_packer(expected.count + 1, YES);
	enumeration_reply(
	    volume, root, FSDirectoryCookieInitial, FSDirectoryVerifierInitial, page, modern, 0);
	assert([page.names isEqualToArray:expected] && resource.liveAllocations == retained);
	endCookie = page.cookie;
	reads = reader.reads;
	allocations = resource.allocations;
	reader.failed = YES;
	resource.failAllocation = YES;
	page = enumeration_packer(TEST_ENUMERATION_FIRST_CAPACITY, YES);
	enumeration_reply(volume, root, endCookie, volume.directoryVerifier, page, modern, 0);
	assert(
	    page.names.count == 0 && reader.reads == reads && resource.allocations == allocations);
	[volume invalidate];
	assert(resource.liveAllocations == 0);
}

static void
test_enumeration_retired_bridge(NSData *image, BOOL modern)
{
	TestReader *reader;
	FaultResource *resource;
	NTFSVolume *volume;
	FSItem *root;
	EnumerationPacker *page;
	__block NSUInteger retired = 0;

	volume = enumeration_owner(
	    image, modern, NTFS_FSKIT_DIRECTORY_ENTRY_LIMIT, &reader, &resource, &root);
	page = enumeration_packer(TEST_ENUMERATION_FIRST_CAPACITY, YES);
	page.beforePacking = ^{
	  [volume invalidate];
	  assert(volume.lifecycle == NTFSVolumeInvalidated);
	  /* All mounted children are closed; the in-flight bridge alone retains its
	   * allocator/storage until the native call has finished using that pointer. */
	  assert(resource.liveAllocations == 1);
	  retired++;
	};
	enumeration_reply(volume, root, FSDirectoryCookieInitial, FSDirectoryVerifierInitial, page,
	    modern, ESTALE);
	assert(retired == 1 && page.names.count == 1 && resource.liveAllocations == 0);
}

static void
test_enumeration_recursive_remount(NSData *image, BOOL modern)
{
	TestReader *reader;
	FaultResource *resource;
	NTFSVolume *volume;
	FSItem *root;
	EnumerationPacker *outer, *inner, *third;
	__block NSUInteger rejected = 0;

	volume = enumeration_owner(
	    image, modern, NTFS_FSKIT_DIRECTORY_ENTRY_LIMIT, &reader, &resource, &root);
	outer = enumeration_packer(TEST_ENUMERATION_FIRST_CAPACITY, YES);
	inner = enumeration_packer(0, YES);
	third = enumeration_packer(0, YES);
	inner.beforePacking = ^{
	  [volume unmountWithReplyHandler:^{
	    assert(volume.lifecycle == NTFSVolumeUnmounted);
	  }];
	  [volume mountWithOptions:nil
		      replyHandler:^(NSError *error) {
			assert(error == nil && volume.lifecycle == NTFSVolumeActive);
		      }];
	  enumeration_reply(volume, root, FSDirectoryCookieInitial, FSDirectoryVerifierInitial,
	      third, modern, EBUSY);
	  rejected++;
	};
	outer.beforePacking = ^{
	  [volume unmountWithReplyHandler:^{
	    assert(volume.lifecycle == NTFSVolumeUnmounted);
	  }];
	  [volume mountWithOptions:nil
		      replyHandler:^(NSError *error) {
			assert(error == nil && volume.lifecycle == NTFSVolumeActive);
		      }];
	  enumeration_reply(volume, root, FSDirectoryCookieInitial, FSDirectoryVerifierInitial,
	      inner, modern, ESTALE);
	};
	enumeration_reply(volume, root, FSDirectoryCookieInitial, FSDirectoryVerifierInitial, outer,
	    modern, ESTALE);
	assert(rejected == 1 && outer.names.count == 1 && inner.names.count == 0 &&
	    third.names.count == 0);
	[volume invalidate];
	assert(resource.liveAllocations == 0);
}

static struct enumeration_work
test_interleaved_enumeration_fault(NSData *image, NSArray<NSString *> *expected,
    NSUInteger failedAllocation, NSUInteger failedRead)
{
	struct enumeration_work work;

	@autoreleasepool {
		TestReader *reader;
		FaultResource *resource;
		NTFSVolume *volume;
		FSItem *root;
		EnumerationPacker *page;
		NSMutableArray<NSString *> *names[TEST_ENUMERATION_READERS];
		FSDirectoryCookie cookies[TEST_ENUMERATION_READERS] = {
		    FSDirectoryCookieInitial, FSDirectoryCookieInitial};
		BOOL finished[TEST_ENUMERATION_READERS] = {NO, NO}, failed = NO;
		NSUInteger allocations, reads, index, round;
		NSError *error;
		NSData *original = [[NSData alloc] initWithBytes:image.bytes length:image.length];
		NSInteger expectedError = failedAllocation != 0 ? ENOMEM
		    : failedRead != 0				? EIO
								: 0;

		volume = enumeration_owner(
		    image, NO, NTFS_FSKIT_DIRECTORY_ENTRY_LIMIT, &reader, &resource, &root);
		[volume.readCachePolicy applyPressure:DISPATCH_MEMORYPRESSURE_NORMAL];
		allocations = resource.allocations;
		reads = reader.reads;
		resource.failAllocationAt =
		    failedAllocation == 0 ? 0 : allocations + failedAllocation;
		reader.failReadAt = failedRead == 0 ? 0 : reads + failedRead;
		for (index = 0; index < TEST_ENUMERATION_READERS; index++) {
			names[index] = [NSMutableArray array];
		}
		for (round = 0; round <= expected.count && !failed; round++) {
			for (index = 0; index < TEST_ENUMERATION_READERS && !failed; index++) {
				if (finished[index]) {
					continue;
				}
				page = enumeration_packer(index == 0
					? TEST_ENUMERATION_FIRST_CAPACITY
					: TEST_ENUMERATION_SECOND_CAPACITY,
				    YES);
				error = enumeration_reply(volume, root, cookies[index],
				    cookies[index] == FSDirectoryCookieInitial
					? FSDirectoryVerifierInitial
					: volume.directoryVerifier,
				    page, NO, TEST_ENUMERATION_OBSERVE_ERROR);
				[names[index] addObjectsFromArray:page.names];
				assert(names[index].count <= expected.count &&
				    [names[index]
					isEqualToArray:[expected
							   subarrayWithRange:NSMakeRange(0,
										 names[index]
										     .count)]]);
				if (error != nil) {
					assert(error.code == expectedError && expectedError != 0);
					failed = YES;
				} else if (page.names.count == 0) {
					assert([names[index] isEqualToArray:expected]);
					finished[index] = YES;
				} else {
					cookies[index] = page.cookie;
				}
			}
		}
		assert(failed == (expectedError != 0));
		if (!failed) {
			for (index = 0; index < TEST_ENUMERATION_READERS; index++) {
				assert(finished[index] && [names[index] isEqualToArray:expected]);
			}
		}
		work.allocations = resource.allocations - allocations;
		work.reads = reader.reads - reads;
		resource.failAllocationAt = 0;
		reader.failReadAt = 0;
		page = enumeration_packer(expected.count + 1, YES);
		enumeration_reply(volume, root, FSDirectoryCookieInitial,
		    FSDirectoryVerifierInitial, page, NO, 0);
		assert([page.names isEqualToArray:expected]);
		[volume invalidate];
		assert(resource.liveAllocations == 0 && [image isEqualToData:original]);
	}
	return work;
}

static void
test_enumeration_revocation(NSData *image, BOOL modern, BOOL attributes)
{
	TestReader *reader;
	FaultResource *resource;
	NTFSVolume *volume;
	FSItem *root;
	EnumerationPacker *page;
	NSUInteger allocations, reads;

	volume = enumeration_owner(
	    image, modern, NTFS_FSKIT_DIRECTORY_ENTRY_LIMIT, &reader, &resource, &root);
	page = enumeration_packer(0, attributes);
	page.beforePacking = ^{
	  reader.revoked = YES;
	};
	enumeration_reply(
	    volume, root, FSDirectoryCookieInitial, FSDirectoryVerifierInitial, page, modern, EIO);
	assert(page.names.count == 0);
	reader.revoked = NO;
	allocations = resource.allocations;
	reads = reader.reads;
	page = enumeration_packer(TEST_ENUMERATION_FIRST_CAPACITY, attributes);
	enumeration_reply(
	    volume, root, FSDirectoryCookieInitial, FSDirectoryVerifierInitial, page, modern, EIO);
	assert(
	    page.names.count == 0 && resource.allocations == allocations && reader.reads == reads);
	[volume invalidate];
	assert(resource.liveAllocations == 0);
}

static void
test_enumeration_budget(NSData *image, BOOL modern)
{
	TestReader *reader;
	FaultResource *resource;
	NTFSVolume *volume;
	FSItem *root;
	EnumerationPacker *page, *retry;
	NSUInteger reads, allocations;

	volume = enumeration_owner(
	    image, modern, TEST_ENUMERATION_SCAN_LIMIT, &reader, &resource, &root);
	page = enumeration_packer(TEST_FILE_COUNT + TEST_ENUMERATION_DOT_ENTRIES, NO);
	enumeration_reply(volume, root, FSDirectoryCookieInitial, FSDirectoryVerifierInitial, page,
	    modern, EOVERFLOW);
	assert(([page.names isEqualToArray:@[ @".", @"..", @"compressed.bin" ]]));
	reads = reader.reads;
	allocations = resource.allocations;
	retry = enumeration_packer(TEST_ENUMERATION_FIRST_CAPACITY, NO);
	enumeration_reply(
	    volume, root, page.cookie, volume.directoryVerifier, retry, modern, EOVERFLOW);
	assert(
	    retry.names.count == 0 && reader.reads == reads && resource.allocations == allocations);
	retry = enumeration_packer(TEST_ENUMERATION_FIRST_CAPACITY, NO);
	enumeration_reply(
	    volume, root, FSDirectoryCookieInitial, FSDirectoryVerifierInitial, retry, modern, 0);
	assert(([retry.names isEqualToArray:@[ @"." ]]));
	[volume invalidate];
	assert(resource.liveAllocations == 0);
}

static void
test_directory_parent_conflicts(NSString *fixtures, BOOL modern)
{
	NSArray<NSString *> *const cases =
	    @[ @"case-directory-self.img", @"case-directory-two-parents.img" ];
	NSString *fixture, *lookupName;
	TestReader *reader;
	FaultResource *resource;
	NTFSVolume *volume;
	FSItem *root, *sensitive, *other;
	FSFileName *stored;
	NSError *error = nil;
	FSItemID identity;
	NSUInteger reads;

	for (fixture in cases) {
		volume = enumeration_owner(
		    [NSData
			dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:fixture]],
		    modern, NTFS_FSKIT_DIRECTORY_ENTRY_LIMIT, &reader, &resource, &root);
		sensitive = [volume lookup:[FSFileName nameWithString:@"Sensitive"]
			       inDirectory:root
				storedName:&stored
				     error:&error];
		assert(sensitive != nil && error == nil);
		identity = [volume attributes:sensitive error:&error].fileID;
		if ([fixture isEqualToString:@"case-directory-self.img"]) {
			other = sensitive;
			lookupName = @"Self";
		} else {
			other = [volume lookup:[FSFileName nameWithString:@"Insensitive"]
				   inDirectory:root
				    storedName:&stored
					 error:&error];
			assert(other != nil && error == nil);
			lookupName = @"OtherSensitive";
		}
		assert([volume lookup:[FSFileName nameWithString:lookupName]
			   inDirectory:other
			    storedName:&stored
				 error:&error] == nil &&
		    stored == nil && error.code == EIO);
		reads = reader.reads;
		assert(
		    [volume attributes:sensitive error:&error].fileID == identity && error == nil);
		assert(reader.reads == reads);
		[volume invalidate];
		assert(resource.liveAllocations == 0);
	}
}

static void
test_directory_parent_lifetime(NSData *image, BOOL modern)
{
	TestReader *reader = nil;
	FaultResource *resource = nil;
	NTFSVolume *volume = nil;
	__attribute__((objc_precise_lifetime)) FSItem *child = nil;
	__weak FSItem *releasedRoot;
	__weak FSItem *releasedParent;
	FSItemID parentID;
	EnumerationPacker *page;
	__block NSUInteger replies = 0;

	@autoreleasepool {
		__attribute__((objc_precise_lifetime)) FSItem *root = nil;
		__attribute__((objc_precise_lifetime)) FSItem *parent = nil;
		FSFileName *stored;
		NSError *error = nil;

		volume = enumeration_owner(
		    image, modern, NTFS_FSKIT_DIRECTORY_ENTRY_LIMIT, &reader, &resource, &root);
		parent = [volume lookup:[FSFileName nameWithString:@"first"]
			    inDirectory:root
			     storedName:&stored
				  error:&error];
		assert(parent != nil && error == nil);
		parentID = [volume attributes:parent error:&error].fileID;
		child = [volume lookup:[FSFileName nameWithString:@"second"]
			   inDirectory:parent
			    storedName:&stored
				 error:&error];
		assert(child != nil && error == nil);
		releasedRoot = root;
		releasedParent = parent;
		/* Release the test's references before draining temporary native owners. */
		parent = nil;
		root = nil;
	}
	assert(releasedRoot == nil && releasedParent == nil);
	test_directory_views(volume, child, parentID, @[], modern, reader, resource);
	[volume unmountWithReplyHandler:^{
	  replies++;
	}];
	[volume mountWithOptions:nil
		    replyHandler:^(NSError *error) {
		      assert(error == nil);
		      replies++;
		    }];
	assert(replies == 2);
	page = enumeration_packer(TEST_ENUMERATION_DOT_ENTRIES, NO);
	enumeration_reply(
	    volume, child, FSDirectoryCookieInitial, FSDirectoryVerifierInitial, page, modern, 0);
	assert(([page.names isEqualToArray:@[ @".", @".." ]]) &&
	    page.identifiers[TEST_ENUMERATION_PARENT_ENTRY].unsignedLongLongValue == parentID);
	[volume invalidate];
	assert(resource.liveAllocations == 0);
}

void
ntfs_test_fskit_enumeration(NSData *standard, NSString *fixtures, BOOL modern)
{
	NSArray<NSString *> *const ordinary = @[
		@"compressed.bin", @"extended.bin", @"fragmented.bin", @"hello.txt", @"middle.dat",
		@"sparse.bin", @"streamed.txt", @"tail.bin", @"Ωmega.txt"
	];
	NSArray<NSString *> *const continuationImages = @[
		@"standard.img", @"nested-index.img", @"namespace-hidden.img",
		@"namespace-large.img"
	];
	NSString *continuationImage;
	NSArray<NSDictionary *> *manifest;
	NSDictionary *entry;
	NSMutableArray<NSString *> *aliases = [NSMutableArray array];
	TestReader *reader;
	FaultResource *resource;
	NTFSVolume *volume;
	FSItem *root, *first, *second, *file;
	FSFileName *stored;
	NSError *error = nil;
	NSData *image;
	EnumerationPacker *page;
	struct enumeration_work work;
	NSUInteger i, mode, view;

	if (modern && !ntfs_test_native_reclaim_available()) {
		puts("SKIP: modern enumeration views require the macOS 27 SDK/runtime");
		return;
	}
	volume = enumeration_owner(
	    standard, modern, NTFS_FSKIT_DIRECTORY_ENTRY_LIMIT, &reader, &resource, &root);
	test_directory_views(
	    volume, root, FSItemIDRootDirectory, ordinary, modern, reader, resource);
	file = [volume lookup:[FSFileName nameWithString:@"hello.txt"]
		  inDirectory:root
		   storedName:&stored
			error:&error];
	assert(file != nil && error == nil);
	page = enumeration_packer(TEST_ENUMERATION_FIRST_CAPACITY, NO);
	enumeration_reply(volume, file, FSDirectoryCookieInitial, FSDirectoryVerifierInitial, page,
	    modern, ENOTDIR);
	[volume invalidate];
	assert(resource.liveAllocations == 0);
	image = [NSData
	    dataWithContentsOfFile:[fixtures
				       stringByAppendingPathComponent:@"namespace-hidden.img"]];
	manifest = [NSJSONSerialization
	    JSONObjectWithData:[NSData dataWithContentsOfFile:
				       [fixtures stringByAppendingPathComponent:@"namespace.json"]]
		       options:0
			 error:NULL];
	assert(manifest.count != 0);
	for (entry in manifest) {
		[aliases addObject:entry[@"native"]];
	}
	volume = enumeration_owner(
	    image, modern, NTFS_FSKIT_DIRECTORY_ENTRY_LIMIT, &reader, &resource, &root);
	test_directory_views(
	    volume, root, FSItemIDRootDirectory, aliases, modern, reader, resource);
	[volume invalidate];
	assert(resource.liveAllocations == 0);
	image = [NSData
	    dataWithContentsOfFile:[fixtures
				       stringByAppendingPathComponent:@"validation-nested.img"]];
	volume = enumeration_owner(
	    image, modern, NTFS_FSKIT_DIRECTORY_ENTRY_LIMIT, &reader, &resource, &root);
	first = [volume lookup:[FSFileName nameWithString:@"first"]
		   inDirectory:root
		    storedName:&stored
			 error:&error];
	assert(first != nil && error == nil);
	second = [volume lookup:[FSFileName nameWithString:@"second"]
		    inDirectory:first
		     storedName:&stored
			  error:&error];
	assert(second != nil && error == nil);
	test_directory_views(
	    volume, first, FSItemIDRootDirectory, @[ @"second" ], modern, reader, resource);
	test_directory_views(volume, second, [volume attributes:first error:&error].fileID, @[],
	    modern, reader, resource);
	assert(error == nil);
	[volume invalidate];
	assert(resource.liveAllocations == 0);
	test_directory_parent_lifetime(image, modern);
	test_directory_parent_conflicts(fixtures, modern);
	test_enumeration_budget(standard, modern);
	test_enumeration_revocation(standard, modern, NO);
	test_enumeration_revocation(standard, modern, YES);
	for (continuationImage in continuationImages) {
		image = [NSData
		    dataWithContentsOfFile:[fixtures
					       stringByAppendingPathComponent:continuationImage]];
		for (view = 0; view < TEST_ENUMERATION_READERS; view++) {
			for (mode = 0; mode < TEST_CONTINUATION_MODES; mode++) {
				@autoreleasepool {
					test_saved_continuations(image, modern, view != 0, mode);
				}
			}
		}
	}
	test_continuation_reentry(standard, modern);
	test_enumeration_remount_in_packer(standard, modern, NO);
	test_enumeration_remount_in_packer(standard, modern, YES);
	test_enumeration_retired_bridge(standard, modern);
	test_enumeration_recursive_remount(standard, modern);
	test_completed_continuation_reuse(standard, ordinary, modern);
	if (!modern) {
		image = [NSData
		    dataWithContentsOfFile:[fixtures
					       stringByAppendingPathComponent:@"nested-index.img"]];
		work = test_enumeration_fault(image, ordinary, 0, 0);
		assert(work.allocations != 0 && work.reads != 0);
		for (i = 1; i <= work.allocations; i++) {
			test_enumeration_fault(image, ordinary, i, 0);
		}
		for (i = 1; i <= work.reads; i++) {
			test_enumeration_fault(image, ordinary, 0, i);
		}
		printf(
		    "PASS: names-only enumeration, %lu allocation and %lu I/O failure positions, "
		    "exactly-once failures, rewind retry, unchanged image and cleanup\n",
		    (unsigned long)work.allocations, (unsigned long)work.reads);
		work = test_interleaved_enumeration_fault(image, ordinary, 0, 0);
		assert(work.allocations != 0 && work.reads != 0);
		for (i = 1; i <= work.allocations; i++) {
			test_interleaved_enumeration_fault(image, ordinary, i, 0);
		}
		for (i = 1; i <= work.reads; i++) {
			test_interleaved_enumeration_fault(image, ordinary, 0, i);
		}
		printf(
		    "PASS: interleaved pagination, %lu allocation and %lu I/O failure positions, "
		    "exactly-once replies, exact prefixes, rewind retry and cleanup\n",
		    (unsigned long)work.allocations, (unsigned long)work.reads);
	}
	printf("PASS: %s saved continuations, 32 layout/view/reuse/eviction/fault/pressure cases, "
	       "pinned callback reentry, remount invalidation, retired bridge lifetime and "
	       "bounded recursive remount, completed-scan reuse and cached EOF\n",
	    modern ? "modern" : "legacy");
	printf("PASS: %s enumeration views, dot/parent IDs, stable aliases, interleaving, "
	       "empty directories, native cookie errors, scan bounds, packer revocation and "
	       "exactly-once replies\n",
	    modern ? "modern" : "legacy");
}
