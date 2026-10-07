/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "fskit_image_transport.h"
#import "NTFSImageTransport.h"
#include "../core/write_owner.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum {
	TEST_IMAGE_BYTES = 8 * NTFS_OVERWRITE_MIN_ALIGNMENT,
	TEST_WRITE_OFFSET = NTFS_OVERWRITE_MIN_ALIGNMENT,
	TEST_WRITE_BYTES = NTFS_OVERWRITE_MIN_ALIGNMENT,
	TEST_SHORT_DIVISOR = 2,
	TEST_WRITTEN_BYTE = 0x5a,
	TEST_FILE_OFFSET = 123,
	TEST_FILE_NANOSECONDS = 661343100
};

#define TEST_FILE_REFERENCE (UINT64_C(7) << NTFS_REFERENCE_SEQUENCE_SHIFT | UINT64_C(25))
#define TEST_FILE_TIME UINT64_C(134357146906613431)
#define TEST_FILE_SECONDS INT64_C(1791241090)

/* Local component peers supply the public resource properties. These tests do
 * not claim that a client proxy authorizes a sandboxed installed extension. */
@interface TestImagePathResource : FSPathURLResource
@property BOOL revokedForTest;
@property(strong) NSURL *replacementURL;
@end

@implementation TestImagePathResource

- (BOOL)isRevoked
{
	return _revokedForTest;
}

- (NSURL *)url
{
	return _replacementURL == nil ? super.url : _replacementURL;
}

@end

@interface NTFSImageTransport (NativeTransfers)
- (BOOL)beginSecurityScopeForURL:(NSURL *)url;
- (void)endSecurityScopeForURL:(NSURL *)url;
- (enum ntfs_result)transferWriteAt:(uint64_t)offset
			      bytes:(const void *)bytes
			     length:(size_t)length
			  completed:(size_t *)completed;
- (enum ntfs_result)transferPersist;
@end

/* Component scope outcomes test balance and pre-open refusal only. Actual
 * authorization still requires the installed sandboxed extension. */
static BOOL scopeBeginSucceeds, scopeRevokesResource;
static NSUInteger scopeBeginCount, scopeEndCount;
static TestImagePathResource *scopeResource;

@interface ScopeImageTransport : NTFSImageTransport
@end

@implementation ScopeImageTransport

- (BOOL)beginSecurityScopeForURL:(NSURL *)url
{
	assert(url == scopeResource.url);
	scopeBeginCount++;
	if (scopeRevokesResource) {
		scopeResource.revokedForTest = YES;
	}
	return scopeBeginSucceeds;
}

- (void)endSecurityScopeForURL:(NSURL *)url
{
	assert(url == scopeResource.url);
	scopeEndCount++;
}

@end

@interface FaultImageTransport : NTFSImageTransport
@property BOOL shortWrite;
@property BOOL refusePersistence;
@property BOOL reenterWrite;
@property BOOL unclaimDuringWrite;
@property(strong) NTFSImageTransport *competitor;
@property NSUInteger nativeWrites, nativeBarriers;
@end

@implementation FaultImageTransport

- (enum ntfs_result)transferWriteAt:(uint64_t)offset
			      bytes:(const void *)bytes
			     length:(size_t)length
			  completed:(size_t *)completed
{
	struct ntfs_overwrite_environment environment;
	struct ntfs_overwrite_environment second;
	size_t nested = SIZE_MAX;
	enum ntfs_result result;

	_nativeWrites++;
	if (_reenterWrite) {
		environment = [self overwriteEnvironment];
		assert(environment.write(environment.reader.context, offset, bytes, length,
			   &nested) == NTFS_BUSY &&
		    nested == 0);
		assert([self newReadResource] == nil);
	}
	result = [super transferWriteAt:offset
				  bytes:bytes
				 length:_shortWrite ? length / TEST_SHORT_DIVISOR : length
			      completed:completed];
	if (_unclaimDuringWrite) {
		environment = [self overwriteEnvironment];
		environment.unclaim(environment.reader.context);
		assert(self.isClaimed);
		second = [_competitor overwriteEnvironment];
		assert(second.claim(second.reader.context) == NTFS_BUSY);
	}
	return result;
}

- (enum ntfs_result)transferPersist
{
	_nativeBarriers++;
	return _refusePersistence ? NTFS_UNSUPPORTED : [super transferPersist];
}

@end

static TestImagePathResource *
path_resource(NSString *path)
{
	return [[TestImagePathResource alloc] initWithURL:[NSURL fileURLWithPath:path]
						 writable:YES];
}

static void
create_image(NSString *path, NSData *bytes)
{
	assert([NSFileManager.defaultManager createFileAtPath:path
						     contents:bytes
						   attributes:@{
							   NSFilePosixPermissions : @0600
						   }]);
}

static void
ownership_and_readers(NSString *path, NSData *source)
{
	TestImagePathResource *peer = path_resource(path);
	__attribute__((objc_precise_lifetime)) NTFSImageTransport *transport, *competitor;
	__attribute__((objc_precise_lifetime)) NTFSResource *resource;
	struct ntfs_overwrite_environment environment, second;
	struct ntfs_environment view;
	NSMutableData *expected = [source mutableCopy];
	uint8_t patch[TEST_WRITE_BYTES], read[TEST_WRITE_BYTES];
	void *firstAllocation, *secondAllocation;
	size_t completed;
	NSError *error = nil;

	memset(patch, TEST_WRITTEN_BYTE, sizeof(patch));
	transport = [[NTFSImageTransport alloc] initWithResource:peer error:&error];
	assert(transport != nil && error == nil && transport.isAvailable && !transport.isClaimed);
	assert([transport newReadResource] == nil);
	competitor = [[NTFSImageTransport alloc] initWithResource:path_resource(path) error:&error];
	assert(competitor != nil && error == nil);
	environment = [transport overwriteEnvironment];
	second = [competitor overwriteEnvironment];
	firstAllocation = environment.reader.allocate(environment.reader.context, sizeof(read));
	assert(firstAllocation != NULL && !transport.isClaimed);
	environment.reader.release(environment.reader.context, firstAllocation, sizeof(read));
	assert(environment.claim(environment.reader.context) == NTFS_OK && transport.isClaimed);
	assert(environment.claim(environment.reader.context) == NTFS_BUSY);
	assert(second.claim(second.reader.context) == NTFS_BUSY && !competitor.isClaimed);
	resource = [transport newReadResource];
	assert(resource != nil && resource.isAvailable);
	view = [resource environment];
	assert(view.api_version == NTFS_API_VERSION);
	assert(view.read(view.context, TEST_WRITE_OFFSET, read, sizeof(read)) == NTFS_OK);
	assert(memcmp(read, (const uint8_t *)source.bytes + TEST_WRITE_OFFSET, sizeof(read)) == 0);
	assert(environment.write(environment.reader.context, TEST_WRITE_OFFSET, patch,
		   sizeof(patch), &completed) == NTFS_BUSY &&
	    completed == 0);
	assert([transport performExclusiveAccess:^{
	  assert(NO);
	  return NTFS_OK;
	}] == NTFS_BUSY);
	assert([[NSData dataWithContentsOfFile:path] isEqualToData:source]);
	/* Independent views and the write transport share one live allocation cap. */
	firstAllocation = environment.reader.allocate(
	    environment.reader.context, NTFS_CORE_MEMORY_LIMIT / TEST_SHORT_DIVISOR);
	secondAllocation = view.allocate(view.context, NTFS_CORE_MEMORY_LIMIT / TEST_SHORT_DIVISOR);
	assert(firstAllocation != NULL && secondAllocation != NULL);
	assert(environment.reader.allocate(environment.reader.context, 1) == NULL);
	assert(view.allocate(view.context, 1) == NULL);
	view.release(view.context, secondAllocation, NTFS_CORE_MEMORY_LIMIT / TEST_SHORT_DIVISOR);
	environment.reader.release(environment.reader.context, firstAllocation,
	    NTFS_CORE_MEMORY_LIMIT / TEST_SHORT_DIVISOR);
	environment.unclaim(environment.reader.context);
	assert(!resource.isAvailable && !transport.isClaimed);
	assert(environment.claim(environment.reader.context) == NTFS_BUSY);
	resource = nil;
	assert(environment.claim(environment.reader.context) == NTFS_OK);
	assert([transport performExclusiveAccess:^{
	  assert([transport newReadResource] == nil);
	  assert([transport performExclusiveAccess:^{
	    return NTFS_OK;
	  }] == NTFS_BUSY);
	  return NTFS_OK;
	}] == NTFS_OK);
	assert(environment.write(environment.reader.context, TEST_WRITE_OFFSET + 1, patch,
		   sizeof(patch), &completed) == NTFS_INVALID &&
	    completed == 0);
	assert(environment.write(environment.reader.context, TEST_IMAGE_BYTES, patch, sizeof(patch),
		   &completed) == NTFS_INVALID &&
	    completed == 0);
	assert(transport.isAvailable);
	assert(environment.write(environment.reader.context, TEST_WRITE_OFFSET, patch,
		   sizeof(patch), &completed) == NTFS_OK &&
	    completed == sizeof(patch));
	assert(environment.persist(environment.reader.context) == NTFS_OK);
	memcpy((uint8_t *)expected.mutableBytes + TEST_WRITE_OFFSET, patch, sizeof(patch));
	assert([[NSData dataWithContentsOfFile:path] isEqualToData:expected]);
	resource = [transport newReadResource];
	assert(resource != nil && resource.isAvailable);
	view = [resource environment];
	assert(view.read(view.context, TEST_WRITE_OFFSET, read, sizeof(read)) == NTFS_OK);
	assert(memcmp(read, patch, sizeof(read)) == 0);
	peer.revokedForTest = YES;
	assert(!resource.isAvailable && !transport.isAvailable);
	assert(environment.write(environment.reader.context, TEST_WRITE_OFFSET, patch,
		   sizeof(patch), &completed) == NTFS_IO &&
	    completed == 0);
	assert(environment.persist(environment.reader.context) == NTFS_IO);
	peer.revokedForTest = NO;
	assert(!resource.isAvailable && !transport.isAvailable);
	resource = nil;
	environment.unclaim(environment.reader.context);
	assert(second.claim(second.reader.context) == NTFS_OK);
	second.unclaim(second.reader.context);
}

static void
native_failures(NSString *path, NSData *source)
{
	__attribute__((objc_precise_lifetime)) FaultImageTransport *transport;
	NTFSResource *resource;
	struct ntfs_overwrite_environment environment;
	NSMutableData *expected;
	uint8_t patch[TEST_WRITE_BYTES];
	size_t completed, mode, writes, barriers;
	NSError *error;

	memset(patch, TEST_WRITTEN_BYTE, sizeof(patch));
	for (mode = 0; mode < 4; mode++) {
		create_image(path, source);
		transport = [[FaultImageTransport alloc] initWithResource:path_resource(path)
								    error:&error];
		assert(transport != nil && error == nil);
		environment = [transport overwriteEnvironment];
		assert(environment.claim(environment.reader.context) == NTFS_OK);
		transport.shortWrite = mode == 0;
		transport.refusePersistence = mode == 1;
		transport.reenterWrite = mode == 2;
		transport.unclaimDuringWrite = mode == 3;
		if (mode == 3) {
			transport.competitor =
			    [[NTFSImageTransport alloc] initWithResource:path_resource(path)
								   error:&error];
			assert(transport.competitor != nil && error == nil);
		}
		if (mode != 1) {
			assert(
			    environment.write(environment.reader.context, TEST_WRITE_OFFSET, patch,
				sizeof(patch), &completed) == (mode == 2 ? NTFS_OK : NTFS_IO));
			assert(completed ==
			    (mode == 0 ? sizeof(patch) / TEST_SHORT_DIVISOR : sizeof(patch)));
		} else {
			assert(environment.persist(environment.reader.context) == NTFS_IO);
		}
		expected = [source mutableCopy];
		if (mode != 1) {
			memcpy(
			    (uint8_t *)expected.mutableBytes + TEST_WRITE_OFFSET, patch, completed);
		}
		assert([[NSData dataWithContentsOfFile:path] isEqualToData:expected]);
		if (mode == 2) {
			assert(environment.persist(environment.reader.context) == NTFS_OK);
			resource = [transport newReadResource];
			assert(resource != nil && resource.isAvailable);
			[transport invalidate];
			assert(!resource.isAvailable);
			resource = nil;
		}
		assert(!transport.isAvailable);
		writes = transport.nativeWrites;
		barriers = transport.nativeBarriers;
		assert(environment.write(environment.reader.context, TEST_WRITE_OFFSET, patch,
			   sizeof(patch), &completed) == NTFS_IO &&
		    completed == 0);
		assert(environment.persist(environment.reader.context) == NTFS_IO);
		assert(transport.nativeWrites == writes && transport.nativeBarriers == barriers);
		assert([transport newReadResource] == nil);
		if (mode == 3) {
			struct ntfs_overwrite_environment second =
			    [transport.competitor overwriteEnvironment];

			assert(!transport.isClaimed);
			assert(second.claim(second.reader.context) == NTFS_OK);
			second.unclaim(second.reader.context);
		}
		environment.unclaim(environment.reader.context);
		assert(environment.claim(environment.reader.context) == NTFS_IO);
		transport = nil;
		assert([NSFileManager.defaultManager removeItemAtPath:path error:&error]);
	}
}

static void
path_admission(NSString *directory, NSData *source)
{
	NSString *path = [directory stringByAppendingPathComponent:@"admission.img"];
	NSString *alias = [directory stringByAppendingPathComponent:@"alias.img"];
	TestImagePathResource *peer;
	__attribute__((objc_precise_lifetime)) NTFSImageTransport *transport;
	NTFSResource *resource;
	struct ntfs_overwrite_environment environment;
	uint8_t read[TEST_WRITE_BYTES];
	NSError *error;

	assert([[NTFSImageTransport alloc] initWithResource:nil error:&error] == nil &&
	    error.code == EINVAL);
	peer = path_resource(path);
	peer.replacementURL = [NSURL URLWithString:@"https://example.invalid/image"];
	assert([[NTFSImageTransport alloc] initWithResource:peer error:&error] == nil);
	create_image(path, source);
	peer = [[TestImagePathResource alloc] initWithURL:[NSURL fileURLWithPath:path] writable:NO];
	assert([[NTFSImageTransport alloc] initWithResource:peer error:&error] == nil &&
	    error.code == EROFS);
	assert([[NTFSImageTransport alloc] initWithResource:path_resource(directory)
						      error:&error] == nil);
	assert([NSFileManager.defaultManager createSymbolicLinkAtPath:alias
						  withDestinationPath:path
								error:&error]);
	assert([[NTFSImageTransport alloc] initWithResource:path_resource(alias)
						      error:&error] == nil);
	assert([NSFileManager.defaultManager removeItemAtPath:alias error:&error]);
	assert([NSFileManager.defaultManager linkItemAtPath:path toPath:alias error:&error]);
	assert([[NTFSImageTransport alloc] initWithResource:path_resource(path)
						      error:&error] == nil);
	assert([NSFileManager.defaultManager removeItemAtPath:alias error:&error]);
	transport = [[NTFSImageTransport alloc] initWithResource:path_resource(path) error:&error];
	assert(transport != nil);
	environment = [transport overwriteEnvironment];
	assert(environment.claim(environment.reader.context) == NTFS_OK);
	resource = [transport newReadResource];
	assert(resource != nil && resource.isAvailable);
	assert(truncate(path.fileSystemRepresentation, TEST_WRITE_BYTES) == 0);
	assert(!resource.isAvailable);
	assert(
	    environment.reader.read(environment.reader.context, 0, read, sizeof(read)) == NTFS_IO);
	assert(!transport.isAvailable);
	environment.unclaim(environment.reader.context);
	resource = nil;
	transport = nil;
	assert([NSFileManager.defaultManager removeItemAtPath:path error:&error]);
	create_image(path, source);
	transport = [[NTFSImageTransport alloc] initWithResource:path_resource(path) error:&error];
	assert(transport != nil);
	environment = [transport overwriteEnvironment];
	assert(environment.claim(environment.reader.context) == NTFS_OK);
	resource = [transport newReadResource];
	assert(resource != nil && resource.isAvailable);
	assert([NSFileManager.defaultManager moveItemAtPath:path toPath:alias error:&error]);
	create_image(path, source);
	assert(!resource.isAvailable);
	assert(
	    environment.reader.read(environment.reader.context, 0, read, sizeof(read)) == NTFS_IO);
	assert(!transport.isAvailable);
	environment.unclaim(environment.reader.context);
	resource = nil;
}

static void
timestamped_core_write(NSString *directory, NSString *fixtures)
{
	NSString *path = [directory stringByAppendingPathComponent:@"timestamped.img"];
	NSData *source =
	    [NSData dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:@"source.img"]];
	NSData *payload = [NSData
	    dataWithContentsOfFile:[fixtures
				       stringByAppendingPathComponent:@"execute-payload.input"]];
	NSData *expected = [NSData
	    dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:@"execute-final.img"]];
	__attribute__((objc_precise_lifetime)) NTFSImageTransport *transport;
	__attribute__((objc_precise_lifetime)) NTFSResource *resource;
	struct ntfs_overwrite_environment environment;
	struct ntfs_overwrite *owner = NULL;
	struct ntfs_overwrite_admission *admission = calloc(1, sizeof(*admission));
	struct ntfs_write_range_report written;
	struct ntfs_write_recovery_report recovered;
	struct ntfs_environment view;
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *node = NULL;
	struct ntfs_stat stat;
	enum ntfs_result result;
	NSError *error;

	assert(source != nil && payload != nil && expected != nil && admission != NULL);
	create_image(path, source);
	transport = [[NTFSImageTransport alloc] initWithResource:path_resource(path) error:&error];
	assert(transport != nil && error == nil);
	environment = [transport overwriteEnvironment];
	result = ntfs_write_owner_open(&environment, admission, &recovered, &owner);
	if (result != NTFS_OK) {
		fprintf(stderr,
		    "image owner admission result=%u claimed=%u available=%u "
		    "stage=%u writes=%u barriers=%u\n",
		    result, transport.isClaimed, transport.isAvailable, recovered.durable_stage,
		    recovered.writes, recovered.barriers);
	}
	assert(result == NTFS_OK);
	assert(owner != NULL && admission->claimed && admission->quiescent && recovered.completed);
	assert(ntfs_write_existing_range(owner, TEST_FILE_REFERENCE, TEST_FILE_OFFSET,
		   payload.bytes, payload.length, TEST_FILE_TIME, &written) == NTFS_OK);
	assert(written.execution.completed && written.completed_bytes == payload.length);
	assert([[NSData dataWithContentsOfFile:path] isEqualToData:expected]);
	resource = [transport newReadResource];
	assert(resource != nil && resource.isAvailable);
	view = [resource environment];
	assert(ntfs_mount(&view, NULL, &volume) == NTFS_OK);
	assert(ntfs_node_open(volume, TEST_FILE_REFERENCE, &node) == NTFS_OK);
	assert(ntfs_node_stat(node, &stat) == NTFS_OK &&
	    stat.modified.seconds == TEST_FILE_SECONDS &&
	    stat.changed.seconds == TEST_FILE_SECONDS &&
	    stat.modified.nanoseconds == TEST_FILE_NANOSECONDS &&
	    stat.changed.nanoseconds == TEST_FILE_NANOSECONDS);
	ntfs_node_close(node);
	assert(ntfs_unmount(volume) == NTFS_OK);
	resource = nil;
	ntfs_overwrite_close(owner);
	owner = NULL;
	assert(ntfs_write_owner_open(&environment, admission, &recovered, &owner) == NTFS_OK);
	assert(recovered.completed && recovered.writes == 0 && recovered.barriers == 1);
	assert([[NSData dataWithContentsOfFile:path] isEqualToData:expected]);
	ntfs_overwrite_close(owner);
	free(admission);
}

static void
security_scope_admission(NSString *directory, NSData *source)
{
	NSString *path = [directory stringByAppendingPathComponent:@"scoped.img"];
	NSString *missing = [directory stringByAppendingPathComponent:@"absent.img"];
	__attribute__((objc_precise_lifetime)) NTFSImageTransport *transport;
	NSError *error;
	NSUInteger mode;

	create_image(path, source);
	/* Scope outcomes are explicit: this unsandboxed component process cannot
	 * establish native denial for a plain URL. A denied scope must precede an
	 * absent backing object, and a granted scope balances failed opens too. */
	for (mode = 0; mode < 4; mode++) {
		scopeBeginCount = scopeEndCount = 0;
		scopeBeginSucceeds = mode != 0;
		scopeRevokesResource = mode == 3;
		scopeResource = path_resource(mode == 0 || mode == 2 ? missing : path);
		transport = [[ScopeImageTransport alloc] initWithResource:scopeResource
						     requireSecurityScope:YES
								    error:&error];
		if (mode == 1) {
			assert(transport != nil && error == nil && transport.isAvailable);
		} else {
			assert(transport == nil &&
			    error.code ==
				(mode == 0	    ? EACCES
					: mode == 2 ? ENOENT
						    : EIO));
		}
		transport = nil;
		assert(scopeBeginCount == 1 && scopeEndCount == (scopeBeginSucceeds ? 1 : 0));
		assert([[NSData dataWithContentsOfFile:path] isEqualToData:source]);
	}
	scopeResource = nil;
	assert([NSFileManager.defaultManager removeItemAtPath:path error:&error]);
}

void
ntfs_test_fskit_image_transport(NSString *fixtures)
{
	NSString *directory = [NSTemporaryDirectory()
	    stringByAppendingPathComponent:[@"machlin-ntfs-image-"
					       stringByAppendingString:NSUUID.UUID.UUIDString]];
	NSString *path = [directory stringByAppendingPathComponent:@"owned.img"];
	NSMutableData *source = [NSMutableData dataWithLength:TEST_IMAGE_BYTES];
	uint8_t *bytes = source.mutableBytes;
	size_t index;
	NSError *error;

	for (index = 0; index < source.length; index++) {
		bytes[index] = (uint8_t)index;
	}
	assert([NSFileManager.defaultManager createDirectoryAtPath:directory
				       withIntermediateDirectories:NO
							attributes:@{
								NSFilePosixPermissions : @0700
							}
							     error:&error]);
	create_image(path, source);
	ownership_and_readers(path, source);
	assert([NSFileManager.defaultManager removeItemAtPath:path error:&error]);
	native_failures(path, source);
	path_admission(directory, source);
	security_scope_admission(directory, source);
	timestamped_core_write(directory, fixtures);
	assert([NSFileManager.defaultManager removeItemAtPath:directory error:&error]);
	puts("PASS: authorized image transport, required scope admission/balance, reader "
	     "exclusion, shared allocation cap, "
	     "real persistence, poison, timestamped private C write and idempotent reopen");
}
