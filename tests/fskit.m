/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSVolume.h"
#import "NTFSNames.h"
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <limits.h>
#include "fixture.h"
#import "fskit_lifecycle.h"
#import "fskit_enumeration.h"
#import "fskit_content.h"
#import "fskit_links.h"
#import "fskit_resource.h"
#import "fskit_pressure.h"
#import "fskit_read_path.h"
#import "fskit_operation.h"
#import "fskit_lookup.h"
#import "fskit_maintenance.h"

@implementation TestReader

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
	assert(offset >= 0 && (uint64_t)offset % TEST_PHYSICAL_BLOCK_BYTES == 0 &&
	    length % TEST_PHYSICAL_BLOCK_BYTES == 0);
	assert((uintptr_t)buffer % TEST_PHYSICAL_BLOCK_BYTES == 0 &&
	    (uint64_t)offset <= self.image.length && length <= self.image.length - (size_t)offset);
	self.reads++;
	if ((uint64_t)offset < self.observedEnd && self.observedStart < (uint64_t)offset + length) {
		self.observedReads++;
		if (self.refuseObservedReads) {
			*error = [NSError errorWithDomain:NSPOSIXErrorDomain code:EIO userInfo:nil];
			return 0;
		}
	}
	if (self.revokeDuringRead) {
		self.revoked = YES;
	}
	if (self.failed || self.reads == self.failReadAt) {
		*error = [NSError errorWithDomain:NSPOSIXErrorDomain code:EIO userInfo:nil];
		return 0;
	}
	memcpy(buffer, (const uint8_t *)self.image.bytes + offset, length);
	return self.shortRead ? length - 1 : length;
}

@end

@interface RevokedGeometryReader : TestReader
@end
@implementation RevokedGeometryReader

- (uint64_t)blockSize
{
	/* Rejected acquisition must not inspect unavailable device geometry. */
	assert(false);
	return 0;
}

@end

static void
test_result_and_resource_admission(void)
{
	RevokedGeometryReader *reader = [[RevokedGeometryReader alloc] init];
	NSObject *result = [[NSObject alloc] init];
	NSError *operationError = [NSError errorWithDomain:@"test.original.operation"
						      code:ENOMEM
						  userInfo:@{@"witness" : @"retained"}];
	NSError *constructionError;

	reader.revoked = YES;
	assert([[NTFSResource alloc] initWithReader:reader] == nil && reader.reads == 0);
	assert([[NTFSResource alloc] initWithReader:nil] == nil);
	/* Test the native result boundary without a macOS-27 result-class dependency.
	 * An existing operation failure outranks an absent or already-created result. */
	assert(ntfs_native_result_error(nil, operationError) == operationError);
	assert(ntfs_native_result_error(result, operationError) == operationError);
	assert(ntfs_native_result_error(result, nil) == nil);
	constructionError = ntfs_native_result_error(nil, nil);
	assert([constructionError.domain isEqualToString:NSPOSIXErrorDomain] &&
	    constructionError.code == EIO);
	puts("PASS: native result construction errors and revoked resource acquisition");
}

@implementation FaultResource

- (void *)allocateSize:(size_t)size
{
	void *bytes;

	self.allocations++;
	if (self.failAllocation || self.allocations == self.failAllocationAt) {
		return NULL;
	}
	bytes = [super allocateSize:size];
	if (bytes != NULL) {
		self.liveAllocations++;
	}
	return bytes;
}

- (void)releaseBytes:(void *)bytes size:(size_t)size
{
	if (bytes != NULL) {
		assert(self.liveAllocations != 0);
		self.liveAllocations--;
	}
	[super releaseBytes:bytes size:size];
}

@end

@interface TestPacker : NSObject
@property NSUInteger capacity;
@property NSMutableArray<NSString *> *names;
@property FSDirectoryCookie lastCookie;
@end
@implementation TestPacker

- (BOOL)packEntryWithName:(FSFileName *)name
		 itemType:(FSItemType)type
		   itemID:(FSItemID)itemID
	       nextCookie:(FSDirectoryCookie)cookie
	       attributes:(FSItemAttributes *)attributes
{
	assert(
	    (type == FSItemTypeFile || type == FSItemTypeDirectory) && itemID != FSItemIDInvalid);
	assert(attributes != nil && attributes.type == type && attributes.fileID == itemID);
	if (self.names.count == self.capacity) {
		return NO;
	}
	[self.names addObject:name.string];
	self.lastCookie = cookie;
	return YES;
}

@end

static void
test_volume(NSData *image)
{
	enum { SMALL_UNALIGNED_OFFSET = 3, MUTATION_REPLY_COUNT = 2 };

	const char hello[] = "Hello from NTFS.\n";
	TestReader *reader = [[TestReader alloc] init];
	NTFSResource *resource;
	NTFSLegacyVolume *volume;
	struct ntfs_environment env;
	struct ntfs_volume *core = NULL;
	FSItem *root, *file, *again;
	FSFileName *stored;
	FSItemAttributes *attrs;
	NSError *error = nil;
	TestPacker *packer;
	NSMutableArray<NSString *> *names = [NSMutableArray array];
	FSDirectoryCookie cookie = 0;
	enum ntfs_result status;
	size_t done;
	uint8_t buffer[TEST_MFT_RECORD_BYTES + 1];
	NSUInteger before, batch, i;
	__block NSUInteger replies = 0;

	reader.image = image;
	resource = [[NTFSResource alloc] initWithReader:reader];
	assert(resource != nil);
	assert([resource readAt:TEST_SECTOR_BYTES - 1 bytes:buffer
			 length:sizeof(buffer)] == NTFS_OK);
	assert(memcmp(buffer, (const uint8_t *)image.bytes + TEST_SECTOR_BYTES - 1,
		   sizeof(buffer)) == 0);
	reader.shortRead = YES;
	assert([resource readAt:SMALL_UNALIGNED_OFFSET bytes:buffer
			 length:sizeof(uint64_t)] == NTFS_IO);
	reader.shortRead = NO;
	before = reader.reads;
	assert([resource readAt:UINT64_MAX bytes:buffer length:sizeof(uint64_t)] == NTFS_IO &&
	    reader.reads == before);
	env = [resource environment];
	assert(ntfs_mount(&env, NULL, &core) == NTFS_OK);
	volume = [[NTFSLegacyVolume alloc] initWithCore:core resource:resource];
	assert(volume != nil);
	root = [volume activate:&error];
	assert(root != nil && error == nil);
	file = [volume lookup:[FSFileName nameWithString:@"HELLO.TXT"]
		  inDirectory:root
		   storedName:&stored
			error:&error];
	assert(file != nil && error == nil && [stored.string isEqualToString:@"hello.txt"]);
	again = [volume lookup:[FSFileName nameWithString:@"hello.txt"]
		   inDirectory:root
		    storedName:&stored
			 error:&error];
	assert(file == again);
	attrs = [volume attributes:file error:&error];
	assert(error == nil && attrs.size == sizeof(hello) - 1 && attrs.mode == S_IRUSR);
	status = [volume readItem:file offset:0 bytes:buffer length:sizeof(buffer) completed:&done];
	assert(status == NTFS_OK && done == sizeof(hello) - 1 && memcmp(buffer, hello, done) == 0);
	assert([volume readItem:file offset:-1 bytes:buffer length:1
		      completed:&done] == NTFS_INVALID &&
	    done == 0);
	[volume writeContents:[NSData data]
		       toFile:file
		     atOffset:0
		 replyHandler:^(size_t written, NSError *e) {
		   assert(written == 0 && e.code == EROFS);
		   replies++;
		 }];
	[volume setAttributes:[[FSItemSetAttributesRequest alloc] init]
		       onItem:file
		 replyHandler:^(FSItemAttributes *a, NSError *e) {
		   assert(a == nil && e.code == EROFS);
		   replies++;
		 }];
	assert(replies == MUTATION_REPLY_COUNT);
	for (batch = 0; batch <= TEST_FILE_COUNT / TEST_DIRECTORY_BATCH_CAPACITY + 1; batch++) {
		packer = [[TestPacker alloc] init];
		packer.capacity = TEST_DIRECTORY_BATCH_CAPACITY;
		packer.names = [NSMutableArray array];
		error = [volume enumerate:root
				   cookie:cookie
				 verifier:cookie == 0 ? 0 : volume.directoryVerifier
			       attributes:YES
				   packer:(FSDirectoryEntryPacker *)packer];
		assert(error == nil);
		[names addObjectsFromArray:packer.names];
		if (packer.names.count == 0) {
			break;
		}
		cookie = packer.lastCookie;
	}
	assert(
	    names.count == TEST_FILE_COUNT && [NSSet setWithArray:names].count == TEST_FILE_COUNT);
	packer = [[TestPacker alloc] init];
	packer.capacity = 1;
	packer.names = [NSMutableArray array];
	assert([volume enumerate:root
			  cookie:1
			verifier:volume.directoryVerifier
		      attributes:YES
			  packer:(FSDirectoryEntryPacker *)packer] == nil);
	assert([packer.names.firstObject isEqualToString:names[1]]);
	assert([volume enumerate:root
			  cookie:1
			verifier:volume.directoryVerifier ^ 1
		      attributes:YES
			  packer:(FSDirectoryEntryPacker *)packer]
		   .code == FSErrorInvalidDirectoryCookie);
	[volume reclaimItem:file
	       replyHandler:^(NSError *e) {
		 assert(e == nil);
		 replies++;
	       }];
	assert([volume readItem:file offset:0 bytes:buffer length:1 completed:&done] ==
	    (ntfs_test_native_reclaim_available() ? NTFS_STALE : NTFS_OK));
	assert(done == (ntfs_test_native_reclaim_available() ? 0 : 1));
	file = [volume lookup:[FSFileName nameWithString:@"fragmented.bin"]
		  inDirectory:root
		   storedName:&stored
			error:&error];
	assert(file != nil);
	reader.failed = YES;
	assert([volume readItem:file
			 offset:TEST_CLUSTER_BYTES - TEST_CROSS_CLUSTER_PREFIX_BYTES
			  bytes:buffer
			 length:TEST_READ_WINDOW_BYTES
		      completed:&done] == NTFS_IO);
	reader.failed = NO;
	dispatch_apply(TEST_CONCURRENT_READS,
	    dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^(size_t index) {
	      uint8_t bytes[TEST_READ_WINDOW_BYTES];
	      size_t completed, j;
	      enum ntfs_result result;

	      result = [volume readItem:file
				 offset:(off_t)index
				  bytes:bytes
				 length:sizeof(bytes)
			      completed:&completed];
	      assert(result == NTFS_OK && completed == sizeof(bytes));
	      for (j = 0; j < completed; j++) {
		      assert(bytes[j] ==
			  (uint8_t)((index + j) * TEST_PATTERN_MULTIPLIER + TEST_PATTERN_ADDEND));
	      }
	    });
	for (i = 0; i < TEST_INVALIDATE_REPETITIONS; i++) {
		[volume invalidate];
	}
	assert([volume readItem:file offset:0 bytes:buffer length:1 completed:&done] == NTFS_STALE);
	assert([volume activate:&error] == nil && error.code == ESTALE);
}

static void
test_revocation(NSData *image)
{
	TestReader *reader;
	NTFSResource *resource;
	NTFSLegacyVolume *volume;
	struct ntfs_environment env;
	struct ntfs_volume *core;
	FSItem *root, *resident, *compressed;
	FSFileName *stored;
	NSError *error = nil;
	TestPacker *packer;
	uint8_t buffer[TEST_READ_WINDOW_BYTES];
	size_t done;
	NSUInteger reads;
	__block NSUInteger replies = 0;

	reader = [[TestReader alloc] init];
	reader.image = image;
	resource = [[NTFSResource alloc] initWithReader:reader];
	env = [resource environment];
	assert(ntfs_mount(&env, NULL, &core) == NTFS_OK);
	volume = [[NTFSLegacyVolume alloc] initWithCore:core resource:resource];
	root = [volume activate:&error];
	assert(root != nil && error == nil);
	resident = [volume lookup:[FSFileName nameWithString:@"hello.txt"]
		      inDirectory:root
		       storedName:&stored
			    error:&error];
	compressed = [volume lookup:[FSFileName nameWithString:@"compressed.bin"]
			inDirectory:root
			 storedName:&stored
			      error:&error];
	assert(resident != nil && compressed != nil);
	assert([volume readItem:resident
			 offset:0
			  bytes:buffer
			 length:sizeof(buffer)
		      completed:&done] == NTFS_OK);
	assert([volume readItem:compressed
			 offset:0
			  bytes:buffer
			 length:sizeof(buffer)
		      completed:&done] == NTFS_OK);
	reads = reader.reads;
	reader.revoked = YES;
	assert([volume readItem:resident offset:0 bytes:buffer length:1
		      completed:&done] == NTFS_IO &&
	    done == 0);
	assert([volume readItem:compressed offset:0 bytes:buffer length:1
		      completed:&done] == NTFS_IO &&
	    done == 0);
	assert([volume attributes:resident error:&error] == nil && error.code == EIO);
	assert([volume lookup:[FSFileName nameWithString:@"hello.txt"]
		   inDirectory:root
		    storedName:&stored
			 error:&error] == nil &&
	    error.code == EIO);
	packer = [[TestPacker alloc] init];
	packer.capacity = 1;
	packer.names = [NSMutableArray array];
	assert([volume enumerate:root
			  cookie:0
			verifier:0
		      attributes:YES
			  packer:(FSDirectoryEntryPacker *)packer]
		   .code == EIO);
	[volume synchronizeWithFlags:0
			replyHandler:^(NSError *e) {
			  assert(e.code == EIO);
			  replies++;
			}];
	assert(replies == 1 && reader.reads == reads);
	/* A reused reader cannot revive the failed owner. Reclamation and teardown
	 * release retained children without attempting any more device I/O. */
	reader.revoked = NO;
	assert(!resource.isAvailable);
	assert([volume readItem:compressed offset:0 bytes:buffer length:1
		      completed:&done] == NTFS_IO);
	[volume reclaimItem:resident
	       replyHandler:^(NSError *e) {
		 assert(e == nil);
	       }];
	[volume invalidate];
	assert(reader.reads == reads);
	assert([volume readItem:compressed offset:0 bytes:buffer length:1
		      completed:&done] == NTFS_STALE);

	resource = [[NTFSResource alloc] initWithReader:reader];
	reader.revokeDuringRead = YES;
	assert([resource readAt:0 bytes:buffer length:sizeof(buffer)] == NTFS_IO);
	assert(!resource.isAvailable);
}

struct test_ads_header {
	uint8_t magic[8], version[4], count[4], reference[8];
};

struct test_ads_entry {
	uint8_t index[4], units[2], reserved[2];
};

enum { TEST_ADS_MANIFEST_VERSION = 1, TEST_UNPAIRED_HIGH_SURROGATE = 0xd800 };

static uint64_t
test_little(const uint8_t *bytes, size_t length)
{
	uint64_t value = 0;
	size_t i;

	for (i = 0; i < length; i++) {
		value |= (uint64_t)bytes[i] << (i * CHAR_BIT);
	}
	return value;
}

static void
test_ads(NSData *image, NSString *fileName, const uint16_t *name, uint16_t nameLength,
    uint32_t index, NSData *payload, BOOL fragmented)
{
	TestReader *reader = [[TestReader alloc] init];
	FaultResource *resource;
	NTFSLegacyVolume *volume;
	struct ntfs_environment env;
	struct ntfs_volume *core = NULL;
	FSItem *root, *item;
	FSFileName *stored, *alias, *manifestName;
	NSError *error = nil;
	NSData *data;
	const struct test_ads_header *header;
	const struct test_ads_entry *entry;
	const uint8_t *bytes;
	uint16_t unit;
	size_t i, position;
	NSUInteger reads;
	__block NSUInteger replies = 0;

	reader.image = image;
	resource = [[FaultResource alloc] initWithReader:reader];
	env = [resource environment];
	assert(ntfs_mount(&env, NULL, &core) == NTFS_OK);
	volume = [[NTFSLegacyVolume alloc] initWithCore:core resource:resource];
	root = [volume activate:&error];
	assert(root != nil && error == nil);
	item = fileName != nil ? [volume lookup:[FSFileName nameWithString:fileName]
				     inDirectory:root
				      storedName:&stored
					   error:&error]
			       : root;
	assert(item != nil && error == nil);
	alias = [FSFileName nameWithString:index == 0 ? @"org.machlin.ntfs.stream.00000000"
						      : @"org.machlin.ntfs.stream.00000001"];
	manifestName = [FSFileName nameWithString:@"org.machlin.ntfs.streams"];
	assert(alias.data.length <= XATTR_MAXNAMELEN);
	resource.failAllocation = YES;
	[volume listXattrsOfItem:item
		    replyHandler:^(NSArray<FSFileName *> *names, NSError *e) {
		      assert(names == nil && e.code == ENOMEM);
		      replies++;
		    }];
	assert(replies == 1);
	resource.failAllocation = NO;
	replies = 0;
	[volume listXattrsOfItem:item
		    replyHandler:^(NSArray<FSFileName *> *names, NSError *e) {
		      assert(e == nil && names.count == (fileName == nil ? 3u : 2u));
		      assert([names[0].data isEqualToData:manifestName.data] &&
			  [names.lastObject.data isEqualToData:alias.data]);
		      replies++;
		    }];
	assert(replies == 1);
	data = [volume xattrNamed:manifestName ofItem:item error:&error];
	assert(data != nil && error == nil);
	assert(data.length == sizeof(*header) + sizeof(*entry) + nameLength * sizeof(uint16_t));
	bytes = data.bytes;
	header = (const void *)bytes;
	assert(memcmp(header->magic, "NTFSADS", sizeof(header->magic)) == 0);
	assert(test_little(header->version, sizeof(header->version)) == TEST_ADS_MANIFEST_VERSION);
	assert(test_little(header->count, sizeof(header->count)) == 1);
	assert(test_little(header->reference, sizeof(header->reference)) != 0);
	entry = (const void *)(bytes + sizeof(*header));
	assert(test_little(entry->index, sizeof(entry->index)) == index);
	assert(test_little(entry->units, sizeof(entry->units)) == nameLength);
	assert(test_little(entry->reserved, sizeof(entry->reserved)) == 0);
	position = sizeof(*header) + sizeof(*entry);
	for (i = 0; i < nameLength; i++) {
		unit = (uint16_t)test_little(bytes + position, sizeof(uint16_t));
		assert(unit == name[i]);
		position += sizeof(uint16_t);
	}
	replies = 0;
	[volume getXattrNamed:alias
		       ofItem:item
		 replyHandler:^(NSData *value, NSError *e) {
		   if (payload == nil) {
			   assert(value == nil && e.code == E2BIG);
		   } else {
			   assert(e == nil && [value isEqualToData:payload]);
		   }
		   replies++;
		 }];
	assert(replies == 1);
	if (fragmented) {
		reader.failed = YES;
		assert(
		    [volume xattrNamed:alias ofItem:item error:&error] == nil && error.code == EIO);
		reader.failed = NO;
		assert([[volume xattrNamed:alias ofItem:item error:&error] isEqualToData:payload] &&
		    error == nil);
	}
	assert([volume xattrNamed:[FSFileName nameWithString:@"com.apple.ResourceFork"]
			   ofItem:item
			    error:&error] == nil &&
	    error.code == ENOATTR);
	assert([volume xattrNamed:[FSFileName nameWithString:@"org.machlin.ntfs.stream.ffffffff"]
			   ofItem:item
			    error:&error] == nil &&
	    error.code == ENOATTR);
	assert([volume xattrNamed:[FSFileName nameWithString:@"org.machlin.ntfs.stream.0000000g"]
			   ofItem:item
			    error:&error] == nil &&
	    error.code == ENOATTR);
	if (index != 0) {
		assert([volume xattrNamed:[FSFileName
					      nameWithString:@"org.machlin.ntfs.stream.00000000"]
				   ofItem:item
				    error:&error] == nil &&
		    error.code == ENOATTR);
	}
	replies = 0;
	[volume setXattrNamed:alias
		       toData:payload != nil ? payload : [NSData data]
		       onItem:item
		       policy:FSSetXattrPolicyAlwaysSet
		 replyHandler:^(NSError *e) {
		   assert(e.code == EROFS);
		   replies++;
		 }];
	assert(replies == 1);
	if (fragmented) {
		reader.revokeDuringRead = YES;
		replies = 0;
		[volume getXattrNamed:alias
			       ofItem:item
			 replyHandler:^(NSData *value, NSError *e) {
			   assert(value == nil && e.code == EIO);
			   replies++;
			 }];
		assert(replies == 1 && reader.revoked && !resource.isAvailable);
	} else {
		reader.revoked = YES;
	}
	reads = reader.reads;
	assert([volume xattrsForItem:item error:&error] == nil && error.code == EIO);
	assert([volume xattrNamed:alias ofItem:item error:&error] == nil && error.code == EIO);
	assert(
	    [volume xattrNamed:manifestName ofItem:item error:&error] == nil && error.code == EIO);
	assert(reader.reads == reads);
	reader.revoked = NO;
	assert([volume xattrsForItem:item error:&error] == nil && error.code == EIO);
	[volume invalidate];
	assert(reader.reads == reads);
	assert([volume xattrsForItem:item error:&error] == nil && error.code == ESTALE);
}

struct test_names_header {
	uint8_t signature[8], version[4], entries[4], parent[8];
};

struct test_names_entry {
	uint8_t index[4], file[8], units[2], name_namespace, reserved;
};

enum {
	TEST_NAMES_MANIFEST_VERSION = 1,
	TEST_NAMESPACE_ROOT_SEQUENCE = 1,
	TEST_NAMESPACE_FILE_SEQUENCE = 7,
	TEST_NAMESPACE_FILE_RECORD = 24,
	TEST_NAMESPACE_OMEGA = 0x03a9
};

static void
check_names_manifest(
    NSData *data, NSArray<NSDictionary *> *names, NSUInteger first, NSUInteger count)
{
	const struct test_names_header *header;
	const struct test_names_entry *entry;
	const uint8_t *bytes = data.bytes;
	NSArray<NSNumber *> *units;
	NSDictionary *expected;
	size_t position = sizeof(*header), i, j;

	assert(data != nil && data.length >= sizeof(*header));
	header = (const void *)bytes;
	assert(memcmp(header->signature, "NTFSNAM", sizeof(header->signature)) == 0);
	assert(
	    test_little(header->version, sizeof(header->version)) == TEST_NAMES_MANIFEST_VERSION &&
	    test_little(header->entries, sizeof(header->entries)) == count);
	assert(test_little(header->parent, sizeof(header->parent)) ==
	    (((uint64_t)TEST_NAMESPACE_ROOT_SEQUENCE << NTFS_REFERENCE_SEQUENCE_SHIFT) |
		NTFS_ROOT_RECORD));
	for (i = first; i < first + count; i++) {
		expected = names[i - first];
		units = expected[@"units"];
		assert(sizeof(*entry) <= data.length - position);
		entry = (const void *)(bytes + position);
		assert(test_little(entry->index, sizeof(entry->index)) == i &&
		    test_little(entry->file, sizeof(entry->file)) ==
			[expected[@"reference"] unsignedLongLongValue]);
		assert(test_little(entry->units, sizeof(entry->units)) == units.count &&
		    entry->name_namespace == NTFS_NAMESPACE_WIN32 && entry->reserved == 0);
		position += sizeof(*entry);
		for (j = 0; j < units.count; j++) {
			assert(sizeof(uint16_t) <= data.length - position);
			assert(test_little(bytes + position, sizeof(uint16_t)) ==
			    units[j].unsignedIntValue);
			position += sizeof(uint16_t);
		}
	}
	assert(position == data.length);
}

static void
test_namespace(NSData *image, NSArray<NSDictionary *> *names, BOOL caseSensitive)
{
	TestReader *reader = [[TestReader alloc] init];
	FaultResource *resource;
	NTFSLegacyVolume *volume;
	struct ntfs_environment env;
	struct ntfs_volume *core = NULL;
	FSItem *root, *file, *identity = nil;
	FSFileName *stored, *alias;
	FSItemAttributes *attributes;
	NSError *error = nil;
	TestPacker *packer;
	NSData *manifest;
	NSMutableArray<NSString *> *enumerated = [NSMutableArray array];
	NSMutableArray<NSString *> *expected = [NSMutableArray array];
	FSDirectoryCookie cookie = 0;
	NSUInteger i, reads, ordinary = NSNotFound, projected = NSNotFound;
	__block NSUInteger replies = 0;
	size_t completed;
	uint8_t buffer[TEST_READ_WINDOW_BYTES];
	const char payload[] = "Hello from NTFS.\n";

	assert(image != nil && names.count != 0);
	reader.image = image;
	resource = [[FaultResource alloc] initWithReader:reader];
	env = [resource environment];
	assert(ntfs_mount(&env, NULL, &core) == NTFS_OK);
	volume = [[NTFSLegacyVolume alloc] initWithCore:core resource:resource];
	root = [volume activate:&error];
	assert(root != nil && error == nil && volume.maximumNameLength == NAME_MAX);
	resource.failAllocation = YES;
	[volume getXattrNamed:[FSFileName nameWithString:@"org.machlin.ntfs.names"]
		       ofItem:root
		 replyHandler:^(NSData *value, NSError *e) {
		   assert(value == nil && e.code == ENOMEM);
		   replies++;
		 }];
	assert(replies == 1);
	resource.failAllocation = NO;
	[volume getXattrNamed:[FSFileName nameWithString:@"org.machlin.ntfs.names"]
		       ofItem:root
		 replyHandler:^(NSData *value, NSError *e) {
		   assert(e == nil);
		   check_names_manifest(value, names, 0, names.count);
		   replies++;
		 }];
	assert(replies == 2);
	for (i = 0; i < names.count; i++) {
		[expected addObject:names[i][@"native"]];
		if ([expected.lastObject hasPrefix:@"~ntfs-"]) {
			projected = i;
		} else {
			ordinary = i;
		}
	}
	for (i = 0; i <= names.count / TEST_DIRECTORY_BATCH_CAPACITY + 1; i++) {
		packer = [[TestPacker alloc] init];
		packer.capacity = TEST_DIRECTORY_BATCH_CAPACITY;
		packer.names = [NSMutableArray array];
		assert([volume enumerate:root
				  cookie:cookie
				verifier:cookie == 0 ? 0 : volume.directoryVerifier
			      attributes:YES
				  packer:(FSDirectoryEntryPacker *)packer] == nil);
		[enumerated addObjectsFromArray:packer.names];
		if (packer.names.count == 0) {
			break;
		}
		cookie = packer.lastCookie;
	}
	assert([enumerated isEqualToArray:expected] &&
	    [NSSet setWithArray:enumerated].count == names.count);
	for (i = 0; i < names.count; i++) {
		alias = [FSFileName nameWithString:expected[i]];
		assert(alias.data.length <= NAME_MAX);
		file = [volume lookup:alias inDirectory:root storedName:&stored error:&error];
		assert(file != nil && error == nil && [stored.data isEqualToData:alias.data]);
		assert(identity == nil || identity == file);
		identity = file;
		attributes = [volume attributes:file error:&error];
		assert(error == nil && attributes.linkCount == names.count);
		assert([volume readItem:file
				 offset:0
				  bytes:buffer
				 length:sizeof(buffer)
			      completed:&completed] == NTFS_OK &&
		    completed == sizeof(payload) - 1 && memcmp(buffer, payload, completed) == 0);
		manifest = [volume
		    xattrNamed:[FSFileName nameWithString:
				       [NSString stringWithFormat:@"org.machlin.ntfs.name.%08x",
					   (uint32_t)i]]
			ofItem:root
			 error:&error];
		assert(error == nil);
		check_names_manifest(manifest, @[ names[i] ], i, 1);
	}
	assert(ordinary != NSNotFound && projected != NSNotFound);
	alias = [FSFileName nameWithString:[expected[projected] uppercaseString]];
	if (caseSensitive) {
		assert([volume lookup:alias inDirectory:root storedName:&stored
				 error:&error] == nil &&
		    stored == nil && error.code == ENOENT);
	} else {
		assert([volume lookup:alias inDirectory:root storedName:&stored
				 error:&error] == identity &&
		    error == nil && [stored.string isEqualToString:expected[projected]]);
	}
	alias = [FSFileName nameWithString:@"HELLO.TXT"];
	if (caseSensitive) {
		assert([volume lookup:alias inDirectory:root storedName:&stored
				 error:&error] == nil &&
		    stored == nil && error.code == ENOENT);
	} else {
		assert([volume lookup:alias inDirectory:root storedName:&stored
				 error:&error] == identity &&
		    error == nil && [stored.string isEqualToString:@"hello.txt"]);
	}
	alias =
	    [FSFileName nameWithString:[NSString stringWithFormat:@"~ntfs-0007000000000018-%08x",
					   (uint32_t)ordinary]];
	assert([volume lookup:alias inDirectory:root storedName:&stored error:&error] == nil &&
	    stored == nil && error.code == ENOENT);
	alias =
	    [FSFileName nameWithString:[NSString stringWithFormat:@"~ntfs-0008000000000018-%08x",
					   (uint32_t)projected]];
	assert([volume lookup:alias inDirectory:root storedName:&stored error:&error] == nil &&
	    stored == nil && error.code == ENOENT);
	reads = reader.reads;
	assert([volume lookup:[FSFileName nameWithString:@"~literal"]
		   inDirectory:root
		    storedName:&stored
			 error:&error] == nil &&
	    error.code == ENOENT);
	assert([volume lookup:[FSFileName nameWithString:@"~ntfs-0000000000000018-00000000"]
		   inDirectory:root
		    storedName:&stored
			 error:&error] == nil &&
	    error.code == ENOENT);
	assert(reader.reads == reads);
	assert([volume xattrNamed:[FSFileName nameWithString:@"org.machlin.ntfs.name.ffffffff"]
			   ofItem:root
			    error:&error] == nil &&
	    error.code == E2BIG);
	assert([volume xattrNamed:[FSFileName nameWithString:@"org.machlin.ntfs.name.000000ff"]
			   ofItem:root
			    error:&error] == nil &&
	    error.code == ENOATTR);
	assert([volume xattrNamed:[FSFileName nameWithString:@"org.machlin.ntfs.names"]
			   ofItem:identity
			    error:&error] == nil &&
	    error.code == ENOATTR);
	alias = [FSFileName nameWithString:[@"x" stringByPaddingToLength:NAME_MAX + 1
							      withString:@"x"
							 startingAtIndex:0]];
	assert([volume lookup:alias inDirectory:root storedName:&stored error:&error] == nil &&
	    stored == nil && error.code == ENAMETOOLONG);
	/* Reversal and lookups must not advance a pending native enumeration entry. */
	packer = [[TestPacker alloc] init];
	packer.capacity = 0;
	packer.names = [NSMutableArray array];
	assert([volume enumerate:root
			  cookie:0
			verifier:0
		      attributes:YES
			  packer:(FSDirectoryEntryPacker *)packer] == nil &&
	    packer.names.count == 0);
	assert([volume xattrNamed:[FSFileName nameWithString:@"org.machlin.ntfs.names"]
			   ofItem:root
			    error:&error] != nil &&
	    error == nil);
	packer.capacity = 1;
	assert([volume enumerate:root
			  cookie:0
			verifier:0
		      attributes:YES
			  packer:(FSDirectoryEntryPacker *)packer] == nil &&
	    [packer.names.firstObject isEqualToString:expected[0]]);
	manifest = [volume xattrNamed:[FSFileName nameWithString:@"org.machlin.ntfs.name.00000000"]
			       ofItem:root
				error:&error];
	check_names_manifest(manifest, @[ names[0] ], 0, 1);
	packer.names = [NSMutableArray array];
	assert([volume enumerate:root
			  cookie:packer.lastCookie
			verifier:volume.directoryVerifier
		      attributes:YES
			  packer:(FSDirectoryEntryPacker *)packer] == nil &&
	    [packer.names.firstObject isEqualToString:expected[1]]);
	reader.revokeDuringRead = YES;
	replies = 0;
	[volume getXattrNamed:[FSFileName nameWithString:@"org.machlin.ntfs.names"]
		       ofItem:root
		 replyHandler:^(NSData *value, NSError *e) {
		   assert(value == nil && e.code == EIO);
		   replies++;
		 }];
	assert(replies == 1 && !resource.isAvailable);
	reads = reader.reads;
	assert([volume lookup:[FSFileName nameWithString:expected[projected]]
		   inDirectory:root
		    storedName:&stored
			 error:&error] == nil &&
	    error.code == EIO);
	assert([volume xattrNamed:[FSFileName nameWithString:@"org.machlin.ntfs.name.00000000"]
			   ofItem:root
			    error:&error] == nil &&
	    error.code == EIO && reader.reads == reads);
	[volume invalidate];
	assert(reader.reads == reads);
}

static void
case_reply(NTFSVolume *volume, FSItem *parent, NSString *name, FSItem *expectedItem,
    NSString *expectedSpelling, int expectedError, BOOL modern)
{
	FSFileName *request = [FSFileName nameWithString:name];
	__block NSUInteger replies = 0;

	if (modern) {
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
		if (@available(macOS 27.0, *)) {
			NSObject *opaqueContext = [[NSObject alloc] init];

			/* This bridge currently ignores context. Test reply framing with an
			 * opaque nonnull double; this is not native identity/authorization
			 * evidence. */
			[(NTFSModernVolume *)volume
			    lookupItemNamed:request
				inDirectory:parent
				    context:(FSContext *)opaqueContext
			       replyHandler:^(FSLookupItemResult *result, NSError *error) {
				 assert(error.code == expectedError);
				 assert((result != nil) == (expectedItem != nil));
				 replies++;
			       }];
		}
#endif
	} else {
		[(NTFSLegacyVolume *)volume
		    lookupItemNamed:request
			inDirectory:parent
		       replyHandler:^(FSItem *item, FSFileName *stored, NSError *error) {
			 assert(error.code == expectedError && item == expectedItem);
			 assert(expectedSpelling != nil
				 ? [stored.string isEqualToString:expectedSpelling]
				 : stored == nil);
			 replies++;
		       }];
	}
	assert(replies == 1);
}

static void
test_case_policy(NSData *image, BOOL rootSensitive, BOOL modern)
{
	TestReader *reader = [[TestReader alloc] init];
	FaultResource *resource;
	NTFSVolume *volume = nil;
	struct ntfs_environment env;
	struct ntfs_volume *core = NULL;
	FSItem *root, *sensitive, *insensitive, *upper, *lower;
	FSFileName *stored;
	NSError *error = nil;
	TestPacker *packer;
	uint8_t bytes[TEST_READ_WINDOW_BYTES];
	size_t completed;
	const char payload[] = "case-file/foo.txt";

	assert(image != nil);
	reader.image = image;
	resource = [[FaultResource alloc] initWithReader:reader];
	env = [resource environment];
	assert(ntfs_mount(&env, NULL, &core) == NTFS_OK);
	if (modern) {
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
		if (@available(macOS 27.0, *)) {
			volume = [[NTFSModernVolume alloc] initWithCore:core resource:resource];
		}
#endif
		if (volume == nil) {
			assert(ntfs_unmount(core) == NTFS_OK && resource.liveAllocations == 0);
			puts("SKIP: modern case-policy replies require the macOS 27 runtime");
			return;
		}
	} else {
		volume = [[NTFSLegacyVolume alloc] initWithCore:core resource:resource];
	}
	root = [volume activate:&error];
	assert(root != nil && error == nil);
	assert(volume.supportedVolumeCapabilities.caseFormat == FSVolumeCaseFormatSensitive);
	sensitive = [volume lookup:[FSFileName nameWithString:@"Sensitive"]
		       inDirectory:root
			storedName:&stored
			     error:&error];
	assert(sensitive != nil && error == nil && [stored.string isEqualToString:@"Sensitive"]);
	insensitive = [volume lookup:[FSFileName nameWithString:@"Insensitive"]
			 inDirectory:root
			  storedName:&stored
			       error:&error];
	assert(insensitive != nil && insensitive != sensitive && error == nil);
	case_reply(volume, root, @"SENSITIVE", rootSensitive ? nil : sensitive,
	    rootSensitive ? nil : @"Sensitive", rootSensitive ? ENOENT : 0, modern);
	upper = [volume lookup:[FSFileName nameWithString:@"Foo.txt"]
		   inDirectory:sensitive
		    storedName:&stored
			 error:&error];
	assert(upper != nil && error == nil && [stored.string isEqualToString:@"Foo.txt"]);
	lower = [volume lookup:[FSFileName nameWithString:@"foo.txt"]
		   inDirectory:sensitive
		    storedName:&stored
			 error:&error];
	assert(lower != nil && lower != upper && error == nil &&
	    [stored.string isEqualToString:@"foo.txt"]);
	assert([volume readItem:lower
			 offset:0
			  bytes:bytes
			 length:sizeof(bytes)
		      completed:&completed] == NTFS_OK &&
	    completed == sizeof(payload) - 1 && memcmp(bytes, payload, completed) == 0);
	case_reply(volume, sensitive, @"Foo.txt", upper, @"Foo.txt", 0, modern);
	case_reply(volume, sensitive, @"foo.txt", lower, @"foo.txt", 0, modern);
	case_reply(volume, sensitive, @"FOO.txt", nil, nil, ENOENT, modern);
	case_reply(volume, insensitive, @"foo.txt", upper, @"Foo.txt", 0, modern);
	case_reply(volume, insensitive, @"FOO.txt", upper, @"Foo.txt", 0, modern);
	packer = [[TestPacker alloc] init];
	packer.capacity = TEST_DIRECTORY_BATCH_CAPACITY;
	packer.names = [NSMutableArray array];
	assert([volume enumerate:sensitive
			  cookie:0
			verifier:0
		      attributes:YES
			  packer:(FSDirectoryEntryPacker *)packer] == nil);
	assert(([packer.names isEqualToArray:@[ @"Foo.txt", @"foo.txt" ]]));
	packer = [[TestPacker alloc] init];
	packer.capacity = TEST_DIRECTORY_BATCH_CAPACITY;
	packer.names = [NSMutableArray array];
	assert([volume enumerate:root
			  cookie:0
			verifier:0
		      attributes:YES
			  packer:(FSDirectoryEntryPacker *)packer] == nil);
	assert(([packer.names isEqualToArray:@[ @"Insensitive", @"Sensitive" ]]));
	reader.revoked = YES;
	case_reply(volume, sensitive, @"Foo.txt", nil, nil, EIO, modern);
	[volume invalidate];
	assert(resource.liveAllocations == 0);
}

static void
test_namespace_large(NSData *image)
{
	enum { ENTRY_COUNT = 2000, PREFIX_UNITS = 4 };

	TestReader *reader = [[TestReader alloc] init];
	NTFSResource *resource;
	NTFSLegacyVolume *volume;
	struct ntfs_environment env;
	struct ntfs_volume *core = NULL;
	FSItem *root, *file;
	FSFileName *stored, *alias;
	NSError *error = nil;
	NSData *manifest;
	NSMutableArray<NSNumber *> *units = [NSMutableArray array];
	NSDictionary *expected;
	NSString *prefix;
	NSUInteger i;

	assert(image != nil);
	reader.image = image;
	resource = [[NTFSResource alloc] initWithReader:reader];
	env = [resource environment];
	assert(ntfs_mount(&env, NULL, &core) == NTFS_OK);
	volume = [[NTFSLegacyVolume alloc] initWithCore:core resource:resource];
	root = [volume activate:&error];
	assert(root != nil && error == nil);
	assert([volume xattrNamed:[FSFileName nameWithString:@"org.machlin.ntfs.names"]
			   ofItem:root
			    error:&error] == nil &&
	    error.code == E2BIG);
	/* A bounded single-link response remains available after complete-list overflow. */
	prefix = [NSString stringWithFormat:@"%04u", ENTRY_COUNT - 1];
	for (i = 0; i < PREFIX_UNITS; i++) {
		[units addObject:@([prefix characterAtIndex:i])];
	}
	for (i = PREFIX_UNITS; i < NTFS_NAME_MAX; i++) {
		[units addObject:@(TEST_NAMESPACE_OMEGA)];
	}
	expected = @{
		@"units" : units,
		@"reference" :
		    @(((uint64_t)TEST_NAMESPACE_FILE_SEQUENCE << NTFS_REFERENCE_SEQUENCE_SHIFT) |
			TEST_NAMESPACE_FILE_RECORD)
	};
	/* The consumer accepts the selected ordinal rather than treating it as a page. */
	manifest = [volume
	    xattrNamed:[FSFileName
			   nameWithString:[NSString stringWithFormat:@"org.machlin.ntfs.name.%08x",
					      ENTRY_COUNT - 1]]
		ofItem:root
		 error:&error];
	assert(error == nil &&
	    manifest.length ==
		sizeof(struct test_names_header) + sizeof(struct test_names_entry) +
		    NTFS_NAME_MAX * sizeof(uint16_t));
	check_names_manifest(manifest, @[ expected ], ENTRY_COUNT - 1, 1);
	alias =
	    [FSFileName nameWithString:[NSString stringWithFormat:@"~ntfs-0007000000000018-%08x",
					   ENTRY_COUNT - 1]];
	file = [volume lookup:alias inDirectory:root storedName:&stored error:&error];
	assert(file != nil && error == nil && [stored.data isEqualToData:alias.data]);
	[volume invalidate];
}

static void
test_namespace_rejection(NSData *image, BOOL stale)
{
	TestReader *reader = [[TestReader alloc] init];
	NTFSResource *resource;
	NTFSLegacyVolume *volume;
	struct ntfs_environment env;
	struct ntfs_volume *core = NULL;
	FSItem *root;
	FSFileName *stored;
	NSError *error = nil;
	TestPacker *packer;

	assert(image != nil);
	reader.image = image;
	resource = [[NTFSResource alloc] initWithReader:reader];
	env = [resource environment];
	assert(ntfs_mount(&env, NULL, &core) == NTFS_OK);
	volume = [[NTFSLegacyVolume alloc] initWithCore:core resource:resource];
	root = [volume activate:&error];
	assert(root != nil);
	assert([volume lookup:[FSFileName nameWithString:@"~ntfs-0007000000000018-00000000"]
		   inDirectory:root
		    storedName:&stored
			 error:&error] == nil &&
	    stored == nil && error.code == (stale ? ESTALE : EIO));
	packer = [[TestPacker alloc] init];
	packer.names = [NSMutableArray array];
	packer.capacity = 1;
	assert([volume enumerate:root
			  cookie:0
			verifier:0
		      attributes:YES
			  packer:(FSDirectoryEntryPacker *)packer]
		   .code == (stale ? ESTALE : EIO));
	if (!stale) {
		assert([volume xattrNamed:[FSFileName nameWithString:@"org.machlin.ntfs.names"]
				   ofItem:root
				    error:&error] == nil &&
		    error.code == EIO);
	}
	[volume invalidate];
}

static void
namespace_operation(NTFSLegacyVolume *volume, FSItem *root, NSArray<NSDictionary *> *names,
    BOOL lookup, int expectedError)
{
	FSFileName *alias = [FSFileName nameWithString:names.lastObject[@"native"]];
	__block NSUInteger replies = 0;

	if (lookup) {
		[volume
		    lookupItemNamed:alias
			inDirectory:root
		       replyHandler:^(FSItem *item, FSFileName *stored, NSError *error) {
			 if (error.code != expectedError) {
				 fprintf(stderr, "Namespace alias error: expected=%d actual=%ld\n",
				     expectedError, (long)error.code);
			 }
			 assert(error.code == expectedError);
			 if (expectedError == 0) {
				 assert(item != nil && [stored.data isEqualToData:alias.data]);
			 } else {
				 assert(item == nil && stored == nil);
			 }
			 replies++;
		       }];
	} else {
		[volume getXattrNamed:[FSFileName nameWithString:@"org.machlin.ntfs.names"]
			       ofItem:root
			 replyHandler:^(NSData *value, NSError *error) {
			   assert(error.code == expectedError);
			   if (expectedError == 0) {
				   check_names_manifest(value, names, 0, names.count);
			   } else {
				   assert(value == nil);
			   }
			   replies++;
			 }];
	}
	assert(replies == 1);
}

static void
namespace_fault_run(NSData *image, NSArray<NSDictionary *> *names, BOOL lookup,
    NSUInteger failAllocation, NSUInteger failRead, NSUInteger *allocations, NSUInteger *reads)
{
	TestReader *reader = [[TestReader alloc] init];
	FaultResource *resource;
	NTFSLegacyVolume *volume;
	struct ntfs_environment env;
	struct ntfs_limits limits;
	struct ntfs_volume *core = NULL;
	FSItem *root;
	NSError *error = nil;
	NSUInteger startAllocations, startReads;
	int expectedError;

	reader.image = image;
	resource = [[FaultResource alloc] initWithReader:reader];
	env = [resource environment];
	/* Cache insertion is best effort. Disable it for the sweep of allocations
	 * that are required to complete an operation; ordinary cases keep it enabled. */
	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	assert(ntfs_mount(&env, &limits, &core) == NTFS_OK);
	volume = [[NTFSLegacyVolume alloc] initWithCore:core resource:resource];
	root = [volume activate:&error];
	assert(root != nil && error == nil);
	startAllocations = resource.allocations;
	startReads = reader.reads;
	resource.failAllocationAt = failAllocation == 0 ? 0 : startAllocations + failAllocation;
	reader.failReadAt = failRead == 0 ? 0 : startReads + failRead;
	expectedError = failAllocation != 0 ? ENOMEM : failRead != 0 ? EIO : 0;
	namespace_operation(volume, root, names, lookup, expectedError);
	if (allocations != NULL) {
		*allocations = resource.allocations - startAllocations;
	}
	if (reads != NULL) {
		*reads = reader.reads - startReads;
	}
	resource.failAllocationAt = 0;
	reader.failReadAt = 0;
	if (expectedError != 0) {
		namespace_operation(volume, root, names, lookup, 0);
	}
	[volume invalidate];
	assert(resource.liveAllocations == 0);
}

static void
test_namespace_faults(NSData *image, NSArray<NSDictionary *> *names)
{
	NSUInteger mode, i, allocations, reads;

	for (mode = 0; mode < 2; mode++) {
		namespace_fault_run(image, names, mode != 0, 0, 0, &allocations, &reads);
		assert(allocations != 0 && reads != 0);
		for (i = 1; i <= allocations; i++) {
			namespace_fault_run(image, names, mode != 0, i, 0, NULL, NULL);
		}
		for (i = 1; i <= reads; i++) {
			namespace_fault_run(image, names, mode != 0, 0, i, NULL, NULL);
		}
		printf("PASS: namespace %s, %lu allocation and %lu I/O failure positions, "
		       "exactly one reply, retry and cleanup\n",
		    mode == 0 ? "manifest" : "alias", (unsigned long)allocations,
		    (unsigned long)reads);
	}
}

static void
test_namespace_budget(NSData *image, NSArray<NSDictionary *> *names)
{
	enum { SCAN_LIMIT = 4, VISIBLE_PREFIX = 3 };

	TestReader *reader = [[TestReader alloc] init];
	FaultResource *resource;
	NTFSLegacyVolume *volume;
	struct ntfs_environment env;
	struct ntfs_volume *core = NULL;
	FSItem *root;
	NSError *error = nil;
	TestPacker *packer;
	NSData *manifest;
	NSUInteger reads;

	reader.image = image;
	resource = [[FaultResource alloc] initWithReader:reader];
	env = [resource environment];
	assert(ntfs_mount(&env, NULL, &core) == NTFS_OK);
	assert([[NTFSLegacyVolume alloc] initWithCore:core
					     resource:resource
			      maximumDirectoryEntries:0] == nil);
	assert([[NTFSLegacyVolume alloc] initWithCore:core
					     resource:resource
			      maximumDirectoryEntries:NTFS_FSKIT_DIRECTORY_ENTRY_LIMIT + 1] == nil);
	volume = [[NTFSLegacyVolume alloc] initWithCore:core
					       resource:resource
				maximumDirectoryEntries:SCAN_LIMIT];
	root = [volume activate:&error];
	assert(root != nil && error == nil);
	packer = [[TestPacker alloc] init];
	packer.names = [NSMutableArray array];
	packer.capacity = names.count;
	assert([volume enumerate:root
			  cookie:0
			verifier:0
		      attributes:YES
			  packer:(FSDirectoryEntryPacker *)packer]
		    .code == EOVERFLOW &&
	    packer.names.count == VISIBLE_PREFIX && packer.lastCookie == VISIBLE_PREFIX);
	/* Retry cannot turn the exhausted cursor into successful truncated enumeration. */
	reads = reader.reads;
	assert([volume enumerate:root
			  cookie:packer.lastCookie
			verifier:volume.directoryVerifier
		      attributes:YES
			  packer:(FSDirectoryEntryPacker *)packer]
		    .code == EOVERFLOW &&
	    reader.reads == reads && packer.names.count == VISIBLE_PREFIX);
	assert([volume xattrNamed:[FSFileName nameWithString:@"org.machlin.ntfs.names"]
			   ofItem:root
			    error:&error] == nil &&
	    error.code == E2BIG);
	manifest = [volume xattrNamed:[FSFileName nameWithString:@"org.machlin.ntfs.name.00000000"]
			       ofItem:root
				error:&error];
	assert(error == nil);
	check_names_manifest(manifest, @[ names[0] ], 0, 1);
	/* A new rewind resets the failed continuation while preserving the same cap. */
	packer.names = [NSMutableArray array];
	packer.capacity = 1;
	assert([volume enumerate:root
			  cookie:0
			verifier:0
		      attributes:YES
			  packer:(FSDirectoryEntryPacker *)packer] == nil &&
	    [packer.names.firstObject isEqualToString:names[0][@"native"]]);
	[volume invalidate];
	assert(resource.liveAllocations == 0);
}

int
main(int argc, char **argv)
{
	@autoreleasepool {
		NSData *image;
		NSString *fixtures;
		const uint16_t notes[] = {'n', 'o', 't', 'e', 's'};
		uint16_t longName[NTFS_NAME_MAX];
		NSMutableData *fragmented;
		NSArray<NSDictionary *> *names;
		uint8_t *bytes;
		size_t i;

		assert(argc == 2);
		test_result_and_resource_admission();
		ntfs_test_fskit_read_path();
		image = [NSData dataWithContentsOfFile:@(argv[1])];
		assert(image != nil);
		test_volume(image);
		test_revocation(image);
		ntfs_test_fskit_lifecycle(image, NO);
		ntfs_test_fskit_lifecycle(image, YES);
		test_ads(image, @"streamed.txt", notes, sizeof(notes) / sizeof(notes[0]), 1,
		    [@"alternate payload" dataUsingEncoding:NSUTF8StringEncoding], NO);
		fixtures = [@(argv[1]) stringByDeletingLastPathComponent];
		ntfs_test_fskit_maintenance(fixtures);
		ntfs_test_fskit_operation(fixtures, NO);
		ntfs_test_fskit_operation(fixtures, YES);
		ntfs_test_fskit_pressure(fixtures, NO);
		ntfs_test_fskit_pressure(fixtures, YES);
		ntfs_test_fskit_enumeration(image, fixtures, NO);
		ntfs_test_fskit_enumeration(image, fixtures, YES);
		ntfs_test_fskit_lookup(image, fixtures, NO);
		ntfs_test_fskit_lookup(image, fixtures, YES);
		ntfs_test_fskit_content(fixtures, NO);
		ntfs_test_fskit_content(fixtures, YES);
		ntfs_test_fskit_links(fixtures, NO);
		ntfs_test_fskit_links(fixtures, YES);
		longName[0] = TEST_UNPAIRED_HIGH_SURROGATE;
		for (i = 1; i < NTFS_NAME_MAX; i++) {
			longName[i] = 'x';
		}
		test_ads([NSData dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:
								@"catalog-long-unpaired.img"]],
		    @"hello.txt", longName, NTFS_NAME_MAX, 1,
		    [@"catalog payload" dataUsingEncoding:NSUTF8StringEncoding], NO);
		test_ads([NSData dataWithContentsOfFile:
				 [fixtures stringByAppendingPathComponent:@"directory-ads.img"]],
		    nil, notes, sizeof(notes) / sizeof(notes[0]), 0,
		    [@"independent stream payload" dataUsingEncoding:NSUTF8StringEncoding], NO);
		test_ads([NSData dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:
								@"catalog-oversized.img"]],
		    @"hello.txt", notes, sizeof(notes) / sizeof(notes[0]), 1, nil, NO);
		fragmented = [NSMutableData dataWithLength:TEST_FRAGMENTED_BYTES];
		bytes = fragmented.mutableBytes;
		for (i = 0; i < fragmented.length; i++) {
			bytes[i] = (uint8_t)(i * TEST_PATTERN_MULTIPLIER + TEST_PATTERN_ADDEND);
		}
		test_ads([NSData dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:
								@"catalog-fragmented.img"]],
		    @"hello.txt", notes, sizeof(notes) / sizeof(notes[0]), 1, fragmented, YES);
		names = [NSJSONSerialization JSONObjectWithData:
			[NSData dataWithContentsOfFile:
				[fixtures stringByAppendingPathComponent:@"namespace.json"]]
							options:0
							  error:nil];
		test_namespace([NSData dataWithContentsOfFile:
				       [fixtures stringByAppendingPathComponent:@"namespace.img"]],
		    names, NO);
		test_namespace(
		    [NSData dataWithContentsOfFile:
			    [fixtures stringByAppendingPathComponent:@"namespace-hidden.img"]],
		    names, NO);
		test_namespace(
		    [NSData dataWithContentsOfFile:
			    [fixtures stringByAppendingPathComponent:@"namespace-sensitive.img"]],
		    names, YES);
		test_case_policy(
		    [NSData dataWithContentsOfFile:
			    [fixtures stringByAppendingPathComponent:@"case-mixed.img"]],
		    NO, NO);
		test_case_policy(
		    [NSData dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:
							   @"case-mixed-sensitive-root.img"]],
		    YES, NO);
		test_case_policy(
		    [NSData dataWithContentsOfFile:
			    [fixtures stringByAppendingPathComponent:@"case-mixed.img"]],
		    NO, YES);
		test_case_policy(
		    [NSData dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:
							   @"case-mixed-sensitive-root.img"]],
		    YES, YES);
		test_namespace_faults(
		    [NSData dataWithContentsOfFile:
			    [fixtures stringByAppendingPathComponent:@"namespace.img"]],
		    names);
		test_namespace_budget(
		    [NSData dataWithContentsOfFile:
			    [fixtures stringByAppendingPathComponent:@"namespace-hidden.img"]],
		    names);
		test_namespace_large([NSData dataWithContentsOfFile:
			[fixtures stringByAppendingPathComponent:@"namespace-large.img"]]);
		test_namespace_rejection(
		    [NSData dataWithContentsOfFile:
			    [fixtures stringByAppendingPathComponent:@"namespace-invalid.img"]],
		    NO);
		test_namespace_rejection(
		    [NSData dataWithContentsOfFile:
			    [fixtures stringByAppendingPathComponent:@"namespace-stale.img"]],
		    YES);
		puts("PASS: FSKit resource alignment/short I/O, identity, canonical names, "
		     "pagination, lossless filename/ADS projection and bounded replies, concurrent "
		     "reads, "
		     "revocation and teardown");
	}
	return 0;
}
