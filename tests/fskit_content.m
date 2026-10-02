/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "fskit_content.h"
#import "fskit_resource.h"
#import "fskit_lifecycle.h"
#import "NTFSVolume.h"
#include "fixture.h"
#include <ntfs/wof.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

enum {
	TEST_CONTENT_DATA_FIRST_LCN = 128,
	TEST_CONTENT_DATA_LAST_LCN = 130,
	TEST_CONTENT_EXTENTS = 2,
	TEST_CONTENT_READ_BYTES = 32,
	TEST_CONTENT_GUARD_BYTE = 0xa6,
	TEST_CONTENT_DOT_ENTRIES = 2,
	TEST_CONTENT_PAGE_CAPACITY = 1,
	TEST_WOF_XATTR_COUNT = 3,
	TEST_WOF_PAGE_BACKING_CLUSTERS = 73,
	TEST_WOF_PAGE_ENTRIES = 4096 / sizeof(uint32_t),
	TEST_WOF_CROSS_PREFIX_BYTES = 7,
	TEST_WOF_CROSS_TAIL_BYTES = 19
};

static NSString *const plainADS = @"org.machlin.ntfs.stream.00000001";
static NSString *const streamManifest = @"org.machlin.ntfs.streams";

@interface ContentReader : TestReader
@end

@implementation ContentReader

- (size_t)readInto:(void *)buffer
	startingAt:(off_t)offset
	    length:(size_t)length
	     error:(NSError **)error
{
	uint64_t first = (uint64_t)TEST_CONTENT_DATA_FIRST_LCN * TEST_CLUSTER_BYTES;
	uint64_t end = (uint64_t)(TEST_CONTENT_DATA_LAST_LCN + 1) * TEST_CLUSTER_BYTES;

	assert(offset >= 0 &&
	    (length == 0 || (uint64_t)offset >= end ||
		((uint64_t)offset < first && length <= first - (uint64_t)offset)));
	return [super readInto:buffer startingAt:offset length:length error:error];
}

@end

@interface ContentPacker : NSObject
@property NSUInteger capacity;
@property BOOL expectsAttributes;
@property NSMutableArray<NSString *> *names;
@property NSMutableArray<NSNumber *> *types;
@property NSMutableArray<FSItemAttributes *> *attributes;
@property FSDirectoryCookie cookie;
@end

@implementation ContentPacker

- (BOOL)packEntryWithName:(FSFileName *)name
		 itemType:(FSItemType)type
		   itemID:(FSItemID)itemID
	       nextCookie:(FSDirectoryCookie)cookie
	       attributes:(FSItemAttributes *)attributes
{
	assert(type == FSItemTypeFile || type == FSItemTypeDirectory || type == FSItemTypeSymlink ||
	    type == FSItemTypeUnknown);
	assert(itemID != FSItemIDInvalid && cookie != FSDirectoryCookieInitial);
	if (self.expectsAttributes) {
		assert(attributes != nil && attributes.type == type && attributes.fileID == itemID);
		assert([attributes isValid:FSItemAttributeSize] &&
		    [attributes isValid:FSItemAttributeAllocSize]);
	} else {
		assert(attributes == nil);
	}
	if (self.names.count == self.capacity) {
		return NO;
	}
	[self.names addObject:name.string];
	[self.types addObject:@(type)];
	if (attributes != nil) {
		[self.attributes addObject:attributes];
	}
	self.cookie = cookie;
	return YES;
}

@end

static ContentPacker *
content_packer(NSUInteger capacity, BOOL attributes)
{
	ContentPacker *packer = [[ContentPacker alloc] init];

	packer.capacity = capacity;
	packer.expectsAttributes = attributes;
	packer.names = [NSMutableArray array];
	packer.types = [NSMutableArray array];
	packer.attributes = [NSMutableArray array];
	return packer;
}

static BOOL
content_error(NSError *error, NSInteger code)
{
	BOOL matches = code == 0
	    ? error == nil
	    : [error.domain isEqualToString:NSPOSIXErrorDomain] && error.code == code;

	if (!matches) {
		fprintf(stderr, "content reply: expected POSIX error %ld, received %s error %ld\n",
		    (long)code, error == nil ? "none" : error.domain.UTF8String, (long)error.code);
	}
	return matches;
}

static NTFSVolume *
content_owner(NSData *image, BOOL modern, TestReader **readerOut, FaultResource **resourceOut,
    FSItem **rootOut)
{
	ContentReader *reader = [[ContentReader alloc] init];
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
			volume = [[NTFSModernVolume alloc] initWithCore:core resource:resource];
		}
#endif
	} else {
		volume = [[NTFSLegacyVolume alloc] initWithCore:core resource:resource];
	}
	assert(volume != nil);
	*rootOut = [volume activate:&error];
	assert(*rootOut != nil && error == nil);
	*readerOut = reader;
	*resourceOut = resource;
	return volume;
}

static void
content_enumerate(NTFSVolume *volume, FSItem *root, FSDirectoryCookie cookie, ContentPacker *packer,
    BOOL modern, NSInteger code)
{
	FSItemGetAttributesRequest *request =
	    packer.expectsAttributes ? [[FSItemGetAttributesRequest alloc] init] : nil;
	__block NSUInteger replies = 0;

	request.wantedAttributes = FSItemAttributeType | FSItemAttributeFileID |
	    FSItemAttributeSize | FSItemAttributeAllocSize;
	if (modern) {
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
		if (@available(macOS 27.0, *)) {
			[(NTFSModernVolume *)volume
			     enumerateDirectory:root
			       startingAtCookie:cookie
				       verifier:cookie == FSDirectoryCookieInitial
				? FSDirectoryVerifierInitial
				: volume.directoryVerifier
			    providingAttributes:request
				    usingPacker:(FSDirectoryEntryPacker *)packer
					context:(FSContext *)[[NSObject alloc] init]
				   replyHandler:^(
				       FSEnumerateDirectoryResult *result, NSError *error) {
				     assert(content_error(error, code) &&
					 ((result != nil) == (code == 0)));
				     replies++;
				   }];
		}
#endif
	} else {
		[(NTFSLegacyVolume *)volume
		     enumerateDirectory:root
		       startingAtCookie:cookie
			       verifier:cookie == FSDirectoryCookieInitial
			? FSDirectoryVerifierInitial
			: volume.directoryVerifier
		    providingAttributes:request
			    usingPacker:(FSDirectoryEntryPacker *)packer
			   replyHandler:^(FSDirectoryVerifier verifier, NSError *error) {
			     BOOL matches = content_error(error, code);

			     if (!matches) {
				     fprintf(stderr,
					 "content enumeration: cookie %llu, attributes %d\n",
					 (unsigned long long)cookie, packer.expectsAttributes);
			     }
			     assert(matches && verifier == volume.directoryVerifier);
			     replies++;
			   }];
	}
	assert(replies == 1);
}

static FSItem *
content_lookup(NTFSVolume *volume, FSItem *root, BOOL modern, NSInteger code)
{
	FSFileName *name = [FSFileName nameWithString:@"hello.txt"];
	FSFileName *stored;
	NSError *error = nil;
	FSItem *item = [volume lookup:name inDirectory:root storedName:&stored error:&error];
	__block NSUInteger replies = 0;

	assert(content_error(error, code) && ((item != nil) == (code == 0)));
	assert(code == 0 ? [stored.data isEqualToData:name.data] : stored == nil);
	if (modern) {
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
		if (@available(macOS 27.0, *)) {
			[(NTFSModernVolume *)volume
			    lookupItemNamed:name
				inDirectory:root
				    context:(FSContext *)[[NSObject alloc] init]
			       replyHandler:^(FSLookupItemResult *result, NSError *e) {
				 assert(content_error(e, code) && ((result != nil) == (code == 0)));
				 replies++;
			       }];
		}
#endif
	} else {
		[(NTFSLegacyVolume *)volume
		    lookupItemNamed:name
			inDirectory:root
		       replyHandler:^(FSItem *found, FSFileName *spelling, NSError *e) {
			 assert(content_error(e, code) && found == item);
			 assert(
			     code == 0 ? [spelling.data isEqualToData:name.data] : spelling == nil);
			 replies++;
		       }];
	}
	assert(replies == 1);
	return item;
}

static void
content_read_rejected(NTFSVolume *volume, FSItem *file, BOOL modern, NSInteger code)
{
	NSMutableData *buffer = [NSMutableData dataWithLength:TEST_CONTENT_READ_BYTES];
	NSData *original;
	__block NSUInteger replies = 0;

	memset(buffer.mutableBytes, TEST_CONTENT_GUARD_BYTE, buffer.length);
	original = [buffer copy];
	if (modern) {
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
		if (@available(macOS 27.0, *)) {
			[(NTFSModernVolume *)volume
			    readFromFile:file
				  offset:0
				  length:buffer.length
			      intoBuffer:(FSMutableFileDataBuffer *)buffer
			    replyHandler:^(FSReadFileResult *result, NSError *error) {
			      assert(result == nil && content_error(error, code));
			      replies++;
			    }];
		}
#endif
	} else {
		[(NTFSLegacyVolume *)volume readFromFile:file
						  offset:0
						  length:buffer.length
					      intoBuffer:(FSMutableFileDataBuffer *)buffer
					    replyHandler:^(size_t count, NSError *error) {
					      assert(count == 0 && content_error(error, code));
					      replies++;
					    }];
	}
	assert(replies == 1 && [buffer isEqualToData:original]);
}

static void
content_attributes(NTFSVolume *volume, FSItem *file, uint64_t size, uint64_t allocated, BOOL modern)
{
	FSItemGetAttributesRequest *request = [[FSItemGetAttributesRequest alloc] init];
	NSError *error = nil;
	FSItemAttributes *attributes = [volume attributes:file error:&error];
	__block NSUInteger replies = 0;

	assert(error == nil && attributes.type == FSItemTypeFile && attributes.size == size &&
	    attributes.allocSize == allocated);
	request.wantedAttributes = FSItemAttributeType | FSItemAttributeFileID |
	    FSItemAttributeSize | FSItemAttributeAllocSize;
	if (modern) {
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
		if (@available(macOS 27.0, *)) {
			[(NTFSModernVolume *)volume
			    getAttributes:request
				   ofItem:file
				  context:(FSContext *)[[NSObject alloc] init]
			     replyHandler:^(FSGetAttributesResult *result, NSError *e) {
			       assert(result != nil && e == nil);
			       replies++;
			     }];
		}
#endif
	} else {
		[(NTFSLegacyVolume *)volume
		    getAttributes:request
			   ofItem:file
		     replyHandler:^(FSItemAttributes *attrs, NSError *e) {
		       assert(e == nil && attrs.size == size && attrs.allocSize == allocated &&
			   attrs.fileID == attributes.fileID);
		       replies++;
		     }];
	}
	assert(replies == 1);
}

static void
content_case(NSData *image, BOOL modern, BOOL empty, NSInteger errorCode)
{
	TestReader *reader;
	FaultResource *resource;
	NTFSVolume *volume;
	FSItem *root, *file;
	ContentPacker *page;
	FSDirectoryCookie cookie = FSDirectoryCookieInitial;
	NSMutableArray<NSString *> *names = [NSMutableArray array];
	NSArray<NSString *> *const expected = @[
		@"compressed.bin", @"extended.bin", @"fragmented.bin", @"hello.txt", @"middle.dat",
		@"sparse.bin", @"streamed.txt", @"tail.bin", @"Ωmega.txt"
	];
	uint64_t size = empty ? 0 : TEST_FRAGMENTED_BYTES;
	uint64_t allocated = empty ? 0 : TEST_CLUSTER_BYTES * TEST_CONTENT_EXTENTS;
	NSUInteger i, reads, allocations;
	FSItemAttributes *hello;
	NSError *error = nil;
	NSArray<FSFileName *> *xattrs;
	NSData *payload;
	__block NSUInteger replies = 0;

	volume = content_owner(image, modern, &reader, &resource, &root);
	file = content_lookup(volume, root, modern, errorCode);
	if (errorCode != 0) {
		page = content_packer(TEST_FILE_COUNT + 1, YES);
		content_enumerate(volume, root, cookie, page, modern, errorCode);
		cookie = page.cookie;
		page = content_packer(TEST_FILE_COUNT + 1, YES);
		content_enumerate(volume, root, cookie, page, modern, errorCode);
		assert(page.names.count == 0);
		page = content_packer(TEST_FILE_COUNT + TEST_CONTENT_DOT_ENTRIES + 1, NO);
		content_enumerate(volume, root, FSDirectoryCookieInitial, page, modern, 0);
		assert(([[page.names
		    subarrayWithRange:NSMakeRange(TEST_CONTENT_DOT_ENTRIES, TEST_FILE_COUNT)]
		    isEqualToArray:expected]));
	} else {
		content_attributes(volume, file, size, allocated, modern);
		for (i = 0; i <= TEST_FILE_COUNT; i++) {
			page = content_packer(TEST_CONTENT_PAGE_CAPACITY, YES);
			content_enumerate(volume, root, cookie, page, modern, 0);
			[names addObjectsFromArray:page.names];
			if ([page.names.firstObject isEqualToString:@"hello.txt"]) {
				hello = page.attributes.firstObject;
				assert(hello.size == size && hello.allocSize == allocated);
			}
			if (page.names.count != 0) {
				cookie = page.cookie;
			}
		}
		assert([names isEqualToArray:expected]);
		content_read_rejected(volume, file, modern, ENOTSUP);
		xattrs = [volume xattrsForItem:file error:&error];
		assert(error == nil && xattrs.count != 0);
		payload = [volume xattrNamed:[FSFileName nameWithString:streamManifest]
				      ofItem:file
				       error:&error];
		assert(payload != nil && error == nil);
		payload = [volume xattrNamed:[FSFileName nameWithString:plainADS]
				      ofItem:file
				       error:&error];
		assert(error == nil &&
		    [payload isEqualToData:[@"independent stream payload"
					       dataUsingEncoding:NSUTF8StringEncoding]]);
		[volume unmountWithReplyHandler:^{
		  replies++;
		}];
		[volume mountWithOptions:nil
			    replyHandler:^(NSError *e) {
			      assert(e == nil);
			      replies++;
			    }];
		assert(replies == 2);
		content_attributes(volume, file, size, allocated, modern);
		content_read_rejected(volume, file, modern, ENOTSUP);
		reader.revoked = YES;
		reads = reader.reads;
		allocations = resource.allocations;
		assert([volume attributes:file error:&error] == nil && error.code == EIO);
		content_read_rejected(volume, file, modern, EIO);
		assert([volume xattrsForItem:file error:&error] == nil && error.code == EIO);
		assert(reader.reads == reads && resource.allocations == allocations);
	}
	[volume invalidate];
	assert(resource.liveAllocations == 0);
}

static void
wof_read(NTFSVolume *volume, FSItem *file, NSData *oracle, off_t offset, size_t length, BOOL modern,
    NSInteger code)
{
	NSMutableData *buffer = [NSMutableData dataWithLength:length + TEST_CONTENT_READ_BYTES];
	size_t completed = 0, expected, i;
	__block NSUInteger replies = 0;

	expected = (uint64_t)offset >= oracle.length
	    ? 0
	    : (length < oracle.length - (size_t)offset ? length : oracle.length - (size_t)offset);
	memset(buffer.mutableBytes, TEST_CONTENT_GUARD_BYTE, buffer.length);
	if (modern) {
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
		if (@available(macOS 27.0, *)) {
			[(NTFSModernVolume *)volume
			    readFromFile:file
				  offset:offset
				  length:length
			      intoBuffer:(FSMutableFileDataBuffer *)buffer
			    replyHandler:^(FSReadFileResult *result, NSError *error) {
			      assert(content_error(error, code));
			      assert((result != nil) == (code == 0));
			      replies++;
			    }];
		}
#endif
	} else {
		[(NTFSLegacyVolume *)volume readFromFile:file
						  offset:offset
						  length:length
					      intoBuffer:(FSMutableFileDataBuffer *)buffer
					    replyHandler:^(size_t count, NSError *error) {
					      assert(content_error(error, code));
					      assert(count == (code == 0 ? expected : 0));
					      replies++;
					    }];
	}
	assert(replies == 1);
	if (code == 0) {
		completed = expected;
		assert(completed == 0 ||
		    memcmp(buffer.bytes, (const uint8_t *)oracle.bytes + offset, completed) == 0);
	}
	for (i = completed; i < buffer.length; i++) {
		assert(((const uint8_t *)buffer.bytes)[i] == TEST_CONTENT_GUARD_BYTE);
	}
}

static void
wof_case(NSString *fixtures, NSString *name, NSUInteger clusters, BOOL modern, NSInteger readError)
{
	NSString *stem =
	    [fixtures stringByAppendingPathComponent:[@"wof-file-" stringByAppendingString:name]];
	NSData *image =
	    [NSData dataWithContentsOfFile:[stem stringByAppendingPathExtension:@"img"]];
	NSData *oracle =
	    [NSData dataWithContentsOfFile:[stem stringByAppendingPathExtension:@"data"]];
	NSData *packet =
	    [NSData dataWithContentsOfFile:[stem stringByAppendingPathExtension:@"reparse"]];
	NSData *manifest =
	    [NSData dataWithContentsOfFile:[stem stringByAppendingPathExtension:@"streams"]];
	NSData *original = [image copy], *payload;
	TestReader *reader;
	FaultResource *resource;
	NTFSVolume *volume;
	FSItem *root, *file;
	ContentPacker *page;
	NSArray<FSFileName *> *xattrs;
	FSFileName *xattr;
	NSMutableArray<NSString *> *names = [NSMutableArray array];
	NSUInteger index, reads, allocations;
	off_t offset = 0;
	size_t length = NTFS_WOF_UNIT_32K;
	NSError *error = nil;
	__block NSUInteger replies = 0;

	assert(image != nil && oracle != nil && packet != nil && manifest != nil);
	volume = content_owner(image, modern, &reader, &resource, &root);
	file = content_lookup(volume, root, modern, 0);
	content_attributes(
	    volume, file, oracle.length, (uint64_t)clusters * TEST_CLUSTER_BYTES, modern);
	page = content_packer(TEST_FILE_COUNT + TEST_CONTENT_DOT_ENTRIES, NO);
	content_enumerate(volume, root, FSDirectoryCookieInitial, page, modern, 0);
	index = [page.names indexOfObject:@"hello.txt"];
	assert(index != NSNotFound && page.types[index].unsignedIntegerValue == FSItemTypeFile);
	page = content_packer(TEST_FILE_COUNT, YES);
	content_enumerate(volume, root, FSDirectoryCookieInitial, page, modern, 0);
	index = [page.names indexOfObject:@"hello.txt"];
	assert(index != NSNotFound && page.attributes[index].type == FSItemTypeFile &&
	    page.attributes[index].size == oracle.length &&
	    page.attributes[index].allocSize == (uint64_t)clusters * TEST_CLUSTER_BYTES);
	xattrs = [volume xattrsForItem:file error:&error];
	assert(error == nil && xattrs.count == TEST_WOF_XATTR_COUNT);
	for (xattr in xattrs) {
		[names addObject:xattr.string];
	}
	assert([names containsObject:streamManifest] &&
	    [names containsObject:@"org.machlin.ntfs.reparse"] &&
	    [names containsObject:@"org.machlin.ntfs.stream.00000002"] &&
	    ![names containsObject:plainADS]);
	payload = [volume xattrNamed:[FSFileName nameWithString:streamManifest]
			      ofItem:file
			       error:&error];
	/* The lossless manifest includes the provider storage, even though its
	 * encoded byte stream has no public xattr alias. */
	assert(error == nil && [payload isEqualToData:manifest]);
	payload = [volume xattrNamed:[FSFileName nameWithString:@"org.machlin.ntfs.reparse"]
			      ofItem:file
			       error:&error];
	assert(error == nil && [payload isEqualToData:packet]);
	payload = [volume xattrNamed:[FSFileName nameWithString:@"org.machlin.ntfs.stream.00000002"]
			      ofItem:file
			       error:&error];
	assert(error == nil &&
	    [payload
		isEqualToData:[@"independent WOF notes" dataUsingEncoding:NSUTF8StringEncoding]]);
	assert([volume xattrNamed:[FSFileName nameWithString:plainADS] ofItem:file
			    error:&error] == nil &&
	    error.code == ENOATTR);
	if ([name isEqualToString:@"pages"]) {
		offset = (off_t)(TEST_WOF_PAGE_ENTRIES - 1) * NTFS_WOF_UNIT_4K -
		    TEST_WOF_CROSS_PREFIX_BYTES;
		length = NTFS_WOF_UNIT_4K + TEST_WOF_CROSS_TAIL_BYTES;
	}
	wof_read(volume, file, oracle, offset, length, modern, readError);
	[volume unmountWithReplyHandler:^{
	  replies++;
	}];
	[volume mountWithOptions:nil
		    replyHandler:^(NSError *e) {
		      assert(e == nil);
		      replies++;
		    }];
	assert(replies == 2);
	content_attributes(
	    volume, file, oracle.length, (uint64_t)clusters * TEST_CLUSTER_BYTES, modern);
	payload = [volume xattrNamed:[FSFileName nameWithString:@"org.machlin.ntfs.reparse"]
			      ofItem:file
			       error:&error];
	assert(error == nil && [payload isEqualToData:packet]);
	wof_read(volume, file, oracle, offset, length, modern, readError);
	reader.revoked = YES;
	reads = reader.reads;
	allocations = resource.allocations;
	wof_read(volume, file, oracle, offset, length, modern, EIO);
	assert([volume xattrsForItem:file error:&error] == nil && error.code == EIO);
	assert([volume attributes:file error:&error] == nil && error.code == EIO);
	assert(reader.reads == reads && resource.allocations == allocations);
	[volume invalidate];
	assert(resource.liveAllocations == 0 && [image isEqualToData:original]);
}

void
ntfs_test_fskit_content(NSString *fixtures, BOOL modern)
{
	NSArray<NSString *> *const supportedMetadata = @[
		@"stat-encrypted.img", @"stat-format.img", @"stat-unit.img",
		@"stat-listed-encrypted.img", @"stat-nonresident-list.img",
		@"stat-empty-encrypted.img"
	];
	NSDictionary<NSString *, NSNumber *> *const rejectedMetadata = @{
		@"stat-bad-vdl.img" : @(EIO),
		@"stat-bad-allocation.img" : @(EIO),
		@"stat-short-mapping.img" : @(EIO),
		@"stat-resident-flags.img" : @(EIO),
		@"stat-bad-physical.img" : @(EIO),
		@"stat-stale-extension.img" : @(ESTALE),
		@"stat-gap.img" : @(EIO),
		@"stat-continuation-flags.img" : @(EIO),
		@"stat-unknown-flags.img" : @(ENOTSUP),
		@"reparse-relative.img" : @(ENOTSUP)
	};
	NSDictionary<NSString *, NSNumber *> *const wofMetadata = @{
		@"4k" : @2,
		@"8k" : @3,
		@"16k" : @5,
		@"resident" : @0,
		@"empty" : @0,
		@"exact" : @2,
		@"vdl-full" : @2,
		@"pages" : @(TEST_WOF_PAGE_BACKING_CLUSTERS),
		@"listed" : @3,
		@"nonresident-list" : @3,
		@"lzx" : @17,
		@"backing-efs" : @2,
		@"codec" : @2,
		@"duplicate" : @2
	};
	NSString *name;
	NSData *image, *original;

	if (modern && !ntfs_test_native_reclaim_available()) {
		puts("SKIP: modern content metadata requires the macOS 27 SDK/runtime");
		return;
	}
	for (name in supportedMetadata) {
		@autoreleasepool {
			image = [NSData
			    dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:name]];
			original = [[NSData alloc] initWithBytes:image.bytes length:image.length];
			content_case(
			    image, modern, [name isEqualToString:@"stat-empty-encrypted.img"], 0);
			assert([image isEqualToData:original]);
		}
	}
	for (name in rejectedMetadata) {
		@autoreleasepool {
			image = [NSData
			    dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:name]];
			content_case(image, modern, NO, rejectedMetadata[name].integerValue);
		}
	}
	for (name in wofMetadata) {
		@autoreleasepool {
			NSInteger readError = 0;

			if ([name isEqualToString:@"lzx"] ||
			    [name isEqualToString:@"backing-efs"]) {
				readError = ENOTSUP;
			} else if ([name isEqualToString:@"codec"] ||
			    [name isEqualToString:@"duplicate"]) {
				readError = EIO;
			}
			wof_case(fixtures, name, wofMetadata[name].unsignedIntegerValue, modern,
			    readError);
		}
	}
	printf("PASS: %s content metadata, six encoded-stream pages, ten explicit rejections, "
	       "truthful sizes, independent ADS, zero-byte read errors, remount/revocation, "
	       "exactly-once callbacks and no default-content I/O\n",
	    modern ? "modern" : "legacy");
	printf("PASS: %s WOF content, 14 provider metadata verdicts, raw/XPRESS byte oracles, "
	       "page crossing, opaque backing inventory, ADS/reparse xattrs, remount/revocation "
	       "and exactly-once reads\n",
	    modern ? "modern" : "legacy");
}
