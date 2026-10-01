/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSVolume.h"
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <limits.h>
#include "fixture.h"

@interface TestReader : NSObject <NTFSBlockReader>
@property NSData *image;
@property BOOL shortRead;
@property BOOL failed;
@property(getter=isRevoked) BOOL revoked;
@property BOOL revokeDuringRead;
@property NSUInteger reads;
@end
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
	if (self.revokeDuringRead) {
		self.revoked = YES;
	}
	if (self.failed) {
		*error = [NSError errorWithDomain:NSPOSIXErrorDomain code:EIO userInfo:nil];
		return 0;
	}
	memcpy(buffer, (const uint8_t *)self.image.bytes + offset, length);
	return self.shortRead ? length - 1 : length;
}

@end

@interface FaultResource : NTFSResource
@property BOOL failAllocation;
@end
@implementation FaultResource

- (void *)allocateSize:(size_t)size
{
	return self.failAllocation ? NULL : [super allocateSize:size];
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
	assert(type == FSItemTypeFile && itemID != FSItemIDInvalid);
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
		   .code == EINVAL);
	[volume reclaimItem:file
	       replyHandler:^(NSError *e) {
		 assert(e == nil);
		 replies++;
	       }];
	assert([volume readItem:file offset:0 bytes:buffer length:1 completed:&done] == NTFS_STALE);
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
		      assert(e == nil && names.count == 2);
		      assert([names[0].data isEqualToData:manifestName.data] &&
			  [names[1].data isEqualToData:alias.data]);
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

int
main(int argc, char **argv)
{
	@autoreleasepool {
		NSData *image;
		NSString *fixtures;
		const uint16_t notes[] = {'n', 'o', 't', 'e', 's'};
		uint16_t longName[NTFS_NAME_MAX];
		NSMutableData *fragmented;
		uint8_t *bytes;
		size_t i;

		assert(argc == 2);
		image = [NSData dataWithContentsOfFile:@(argv[1])];
		assert(image != nil);
		test_volume(image);
		test_revocation(image);
		test_ads(image, @"streamed.txt", notes, sizeof(notes) / sizeof(notes[0]), 1,
		    [@"alternate payload" dataUsingEncoding:NSUTF8StringEncoding], NO);
		fixtures = [@(argv[1]) stringByDeletingLastPathComponent];
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
		puts("PASS: FSKit resource alignment/short I/O, identity, canonical names, "
		     "pagination, ADS/UTF-16 projection and bounded replies, concurrent reads, "
		     "revocation and teardown");
	}
	return 0;
}
