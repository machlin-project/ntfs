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
	TEST_ENUMERATION_SCAN_LIMIT = 1
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

static void
enumeration_reply(NTFSVolume *volume, FSItem *directory, FSDirectoryCookie cookie,
    FSDirectoryVerifier verifier, EnumerationPacker *packer, BOOL modern, NSInteger errorCode)
{
	FSItemGetAttributesRequest *attributes =
	    packer.expectsAttributes ? [[FSItemGetAttributesRequest alloc] init] : nil;
	__block NSUInteger replies = 0;

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
				     assert((result != nil) == (errorCode == 0));
				     assert(errorCode == 0
					     ? error == nil
					     : [error.domain isEqualToString:NSPOSIXErrorDomain] &&
						 error.code == errorCode);
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
			     assert(errorCode == 0
				     ? error == nil && current == volume.directoryVerifier
				     : [error.domain isEqualToString:NSPOSIXErrorDomain] &&
					 error.code == errorCode);
			     replies++;
			   }];
	}
	assert(replies == 1);
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
						maximumDirectoryEntries:maximum];
		}
#endif
	} else {
		volume = [[NTFSLegacyVolume alloc] initWithCore:core
						       resource:resource
					maximumDirectoryEntries:maximum];
	}
	assert(volume != nil);
	*rootOut = [volume activate:&error];
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
	NSUInteger i;

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
	}
	printf("PASS: %s enumeration views, dot/parent IDs, stable aliases, interleaving, "
	       "empty directories, native cookie errors, scan bounds, packer revocation and "
	       "exactly-once replies\n",
	    modern ? "modern" : "legacy");
}
