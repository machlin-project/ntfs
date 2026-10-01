/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSVolume.h"
#include <assert.h>
#include <errno.h>
#include <string.h>

@interface TestReader : NSObject <NTFSBlockReader>
@property NSData *image;
@property BOOL shortRead;
@property BOOL failed;
@property NSUInteger reads;
@end
@implementation TestReader

- (uint64_t)blockSize
{
	return 512;
}

- (uint64_t)physicalBlockSize
{
	return 4096;
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
	assert(offset >= 0 && (uint64_t)offset % 4096 == 0 && length % 4096 == 0);
	assert((uintptr_t)buffer % 4096 == 0 && (uint64_t)offset <= self.image.length &&
	    length <= self.image.length - (size_t)offset);
	self.reads++;
	if (self.failed) {
		*error = [NSError errorWithDomain:NSPOSIXErrorDomain code:EIO userInfo:nil];
		return 0;
	}
	memcpy(buffer, (const uint8_t *)self.image.bytes + offset, length);
	return self.shortRead ? length - 1 : length;
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
	uint8_t buffer[1025];
	NSUInteger before, batch, i;
	__block NSUInteger replies = 0;

	reader.image = image;
	resource = [[NTFSResource alloc] initWithReader:reader];
	assert(resource != nil);
	assert([resource readAt:511 bytes:buffer length:sizeof(buffer)] == NTFS_OK);
	assert(memcmp(buffer, (const uint8_t *)image.bytes + 511, sizeof(buffer)) == 0);
	reader.shortRead = YES;
	assert([resource readAt:3 bytes:buffer length:8] == NTFS_IO);
	reader.shortRead = NO;
	before = reader.reads;
	assert([resource readAt:UINT64_MAX bytes:buffer length:8] == NTFS_IO &&
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
	assert(error == nil && attrs.size == 17 && attrs.mode == 0400);
	status = [volume readItem:file offset:0 bytes:buffer length:sizeof(buffer) completed:&done];
	assert(status == NTFS_OK && done == 17 && memcmp(buffer, "Hello from NTFS.\n", done) == 0);
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
	assert(replies == 2);
	for (batch = 0; batch < 8; batch++) {
		packer = [[TestPacker alloc] init];
		packer.capacity = 2;
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
	assert(names.count == 9 && [NSSet setWithArray:names].count == 9);
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
	assert([volume readItem:file offset:4090 bytes:buffer length:513
		      completed:&done] == NTFS_IO);
	reader.failed = NO;
	dispatch_apply(64, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^(size_t index) {
	  uint8_t bytes[513];
	  size_t completed, j;
	  enum ntfs_result result;

	  result = [volume readItem:file
			     offset:(off_t)index
			      bytes:bytes
			     length:sizeof(bytes)
			  completed:&completed];
	  assert(result == NTFS_OK && completed == sizeof(bytes));
	  for (j = 0; j < completed; j++) {
		  assert(bytes[j] == (uint8_t)((index + j) * 13 + 7));
	  }
	});
	for (i = 0; i < 3; i++) {
		[volume invalidate];
	}
	assert([volume readItem:file offset:0 bytes:buffer length:1 completed:&done] == NTFS_STALE);
	assert([volume activate:&error] == nil && error.code == ESTALE);
}

int
main(int argc, char **argv)
{
	@autoreleasepool {
		NSData *image;

		assert(argc == 2);
		image = [NSData dataWithContentsOfFile:@(argv[1])];
		assert(image != nil);
		test_volume(image);
		puts("PASS: FSKit resource alignment/short I/O, identity, canonical names, "
		     "pagination, read-only replies, concurrent reads and teardown");
	}
	return 0;
}
