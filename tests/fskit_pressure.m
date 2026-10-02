/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "fskit_pressure.h"
#import "fskit_resource.h"
#import "fskit_lifecycle.h"
#import "NTFSVolume.h"
#include "fixture.h"
#include <ntfs/wof.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <string.h>

enum {
	TEST_PRESSURE_TIMEOUT_SECONDS = 5,
	TEST_PRESSURE_READ_BYTES = 32,
	TEST_PRESSURE_GUARD_BYTE = 0xad,
	TEST_PRESSURE_PAGE_CAPACITY = 1,
	TEST_PRESSURE_SECOND_CAPACITY = 2
};

static dispatch_time_t
pressure_deadline(void)
{
	return dispatch_time(DISPATCH_TIME_NOW, TEST_PRESSURE_TIMEOUT_SECONDS * NSEC_PER_SEC);
}

static void
pressure_wait(dispatch_semaphore_t semaphore)
{
	assert(dispatch_semaphore_wait(semaphore, pressure_deadline()) == 0);
}

/* A Dispatch data source drives the actual observer callback without changing
 * host pressure. It does not prove native memory-pressure notification delivery. */
@interface PressurePolicy : NTFSReadCachePolicy
@property dispatch_source_t injectedSource;
@property dispatch_queue_t notificationQueue;
@property dispatch_semaphore_t delivered;
@end

@implementation PressurePolicy

- (instancetype)init
{
	self = [super init];
	if (self != nil) {
		_notificationQueue =
		    dispatch_queue_create("ntfs.test.pressure", DISPATCH_QUEUE_SERIAL);
		_delivered = dispatch_semaphore_create(0);
	}
	return self;
}

- (dispatch_source_t)newPressureSource
{
	self.injectedSource =
	    dispatch_source_create(DISPATCH_SOURCE_TYPE_DATA_OR, 0, 0, self.notificationQueue);
	return self.injectedSource;
}

- (void)applyPressure:(dispatch_source_memorypressure_flags_t)flags
{
	[super applyPressure:flags];
	dispatch_semaphore_signal(self.delivered);
}

@end

@interface MissingPressurePolicy : NTFSReadCachePolicy
@end

@implementation MissingPressurePolicy

- (dispatch_source_t)newPressureSource
{
	return nil;
}

@end

static void
pressure_notify(NTFSVolume *volume, dispatch_source_memorypressure_flags_t flags)
{
	PressurePolicy *policy = (PressurePolicy *)volume.readCachePolicy;

	assert(flags != 0 && [policy isKindOfClass:PressurePolicy.class]);
	dispatch_source_merge_data(policy.injectedSource, flags);
	pressure_wait(policy.delivered);
}

static void
test_policy_observation(void)
{
	NTFSReadCachePolicy *policy = [[PressurePolicy alloc] init];
	MissingPressurePolicy *missing = [[MissingPressurePolicy alloc] init];
	const dispatch_source_memorypressure_flags_t unknown = 1UL
	    << (sizeof(dispatch_source_memorypressure_flags_t) * CHAR_BIT - 1);
	__weak NTFSReadCachePolicy *unowned;

	assert(!policy.retentionActive);
	[policy start];
	assert(policy.retentionActive);
	[policy applyPressure:DISPATCH_MEMORYPRESSURE_NORMAL | DISPATCH_MEMORYPRESSURE_WARN];
	assert(!policy.retentionActive);
	[policy applyPressure:0];
	[policy applyPressure:unknown];
	assert(!policy.retentionActive);
	[policy applyPressure:DISPATCH_MEMORYPRESSURE_NORMAL];
	assert(policy.retentionActive);
	[policy applyPressure:DISPATCH_MEMORYPRESSURE_NORMAL | DISPATCH_MEMORYPRESSURE_CRITICAL];
	assert(!policy.retentionActive);
	[policy stop];
	[policy applyPressure:DISPATCH_MEMORYPRESSURE_NORMAL];
	assert(!policy.retentionActive);
	[policy start];
	assert(!policy.retentionActive);
	[policy applyPressure:DISPATCH_MEMORYPRESSURE_NORMAL];
	assert(policy.retentionActive);
	[policy stop];
	[policy stop];
	[missing start];
	[missing applyPressure:DISPATCH_MEMORYPRESSURE_NORMAL];
	assert(!missing.retentionActive);
	[missing stop];
	[missing start];
	assert(!missing.retentionActive);
	[missing stop];
	@autoreleasepool {
		PressurePolicy *temporary = [[PressurePolicy alloc] init];

		unowned = temporary;
		[temporary start];
	}
	assert(unowned == nil);
	puts("PASS: pressure coalescing, unavailable observation, restart and observer ownership");
}

@interface PressureLegacyVolume : NTFSLegacyVolume
@end

@implementation PressureLegacyVolume

- (NTFSReadCachePolicy *)newReadCachePolicy
{
	return [[PressurePolicy alloc] init];
}

@end

#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
API_AVAILABLE(macos(27.0))
@interface PressureModernVolume : NTFSModernVolume
@end

@implementation PressureModernVolume

- (NTFSReadCachePolicy *)newReadCachePolicy
{
	return [[PressurePolicy alloc] init];
}

@end
#endif

@interface PressureReader : TestReader
@property BOOL blockNextRead;
@property dispatch_semaphore_t entered;
@property dispatch_semaphore_t resume;
@end

@implementation PressureReader

- (size_t)readInto:(void *)buffer
	startingAt:(off_t)offset
	    length:(size_t)length
	     error:(NSError **)error
{
	BOOL blocked;

	@synchronized(self) {
		blocked = self.blockNextRead;
		self.blockNextRead = NO;
	}
	if (blocked) {
		dispatch_semaphore_signal(self.entered);
		pressure_wait(self.resume);
	}
	return [super readInto:buffer startingAt:offset length:length error:error];
}

@end

@interface PressureResource : FaultResource
@property NSUInteger liveBytes;
@end

@implementation PressureResource

- (void *)allocateSize:(size_t)size
{
	void *bytes;

	@synchronized(self) {
		bytes = [super allocateSize:size];
		if (bytes != NULL) {
			self.liveBytes += size;
		}
	}
	return bytes;
}

- (void)releaseBytes:(void *)bytes size:(size_t)size
{
	@synchronized(self) {
		if (bytes != NULL) {
			assert(size <= self.liveBytes);
			self.liveBytes -= size;
		}
		[super releaseBytes:bytes size:size];
	}
}

@end

@interface PressureBuffer : NSObject
@property NSMutableData *data;
@property(readonly) NSUInteger length;
- (void *)mutableBytes;
@end

@implementation PressureBuffer

- (NSUInteger)length
{
	return TEST_PRESSURE_READ_BYTES;
}

- (void *)mutableBytes
{
	return (uint8_t *)self.data.mutableBytes + 1;
}

@end

static void
pressure_read(NTFSVolume *volume, FSItem *item, NSData *original, size_t offset, BOOL modern,
    NSInteger errorCode)
{
	PressureBuffer *buffer = [[PressureBuffer alloc] init];
	__block NSUInteger replies = 0;
	const uint8_t *bytes;
	size_t i;

	assert(offset <= original.length && TEST_PRESSURE_READ_BYTES <= original.length - offset);
	buffer.data = [NSMutableData dataWithLength:TEST_PRESSURE_READ_BYTES + 2];
	memset(buffer.data.mutableBytes, TEST_PRESSURE_GUARD_BYTE, buffer.data.length);
	if (modern) {
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
		if (@available(macOS 27.0, *)) {
			[(NTFSModernVolume *)volume
			    readFromFile:item
				  offset:(off_t)offset
				  length:buffer.length
			      intoBuffer:(FSMutableFileDataBuffer *)buffer
			    replyHandler:^(FSReadFileResult *result, NSError *error) {
			      assert(
				  (result != nil) == (errorCode == 0) && error.code == errorCode);
			      replies++;
			    }];
		}
#endif
	} else {
		[(NTFSLegacyVolume *)volume readFromFile:item
						  offset:(off_t)offset
						  length:buffer.length
					      intoBuffer:(FSMutableFileDataBuffer *)buffer
					    replyHandler:^(size_t done, NSError *error) {
					      assert(done == (errorCode == 0 ? buffer.length : 0) &&
						  error.code == errorCode);
					      replies++;
					    }];
	}
	assert(replies == 1);
	bytes = buffer.data.bytes;
	assert(bytes[0] == TEST_PRESSURE_GUARD_BYTE &&
	    bytes[buffer.data.length - 1] == TEST_PRESSURE_GUARD_BYTE);
	if (errorCode == 0) {
		assert(memcmp(bytes + 1, (const uint8_t *)original.bytes + offset, buffer.length) ==
		    0);
	} else {
		for (i = 1; i <= buffer.length; i++) {
			assert(bytes[i] == TEST_PRESSURE_GUARD_BYTE);
		}
	}
}

static NTFSVolume *
pressure_owner(NSData *image, BOOL modern, PressureReader **readerOut,
    PressureResource **resourceOut, FSItem **rootOut)
{
	PressureReader *reader = [[PressureReader alloc] init];
	PressureResource *resource;
	NTFSVolume *volume = nil;
	struct ntfs_environment env;
	struct ntfs_limits limits;
	struct ntfs_volume *core = NULL;
	NSError *error = nil;

	assert(image != nil);
	reader.image = image;
	reader.entered = dispatch_semaphore_create(0);
	reader.resume = dispatch_semaphore_create(0);
	resource = [[PressureResource alloc] initWithReader:reader];
	env = resource.environment;
	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	assert(ntfs_mount(&env, &limits, &core) == NTFS_OK);
	if (modern) {
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
		if (@available(macOS 27.0, *)) {
			volume = [[PressureModernVolume alloc] initWithCore:core resource:resource];
		}
#endif
	} else {
		volume = [[PressureLegacyVolume alloc] initWithCore:core resource:resource];
	}
	assert(volume != nil);
	*rootOut = [volume activate:&error];
	assert(*rootOut != nil && error == nil && volume.readCachePolicy.retentionActive);
	*readerOut = reader;
	*resourceOut = resource;
	return volume;
}

static FSItem *
pressure_lookup(NTFSVolume *volume, FSItem *root, NSString *name)
{
	FSFileName *stored = nil;
	NSError *error = nil;
	FSItem *item = [volume lookup:[FSFileName nameWithString:name]
			  inDirectory:root
			   storedName:&stored
				error:&error];

	if (item == nil || error != nil || ![stored.string isEqualToString:name]) {
		fprintf(stderr, "pressure lookup %s: stored=%s error=%ld\n", name.UTF8String,
		    stored.string != nil ? stored.string.UTF8String : "(none)", (long)error.code);
	}
	assert(item != nil && error == nil && [stored.string isEqualToString:name]);
	return item;
}

static void
test_content_pressure(NSString *fixtures, NSString *imageName, NSString *fileName, NSData *original,
    NSData *wire, BOOL modern)
{
	NSData *image =
	    [NSData dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:imageName]];
	PressureReader *reader;
	PressureResource *resource;
	FSItem *root, *item, *again;
	NTFSVolume *volume = pressure_owner(image, modern, &reader, &resource, &root);
	NSError *error = nil;
	NSData *manifest, *savedWire = nil;
	FSItemAttributes *attributes;
	NSUInteger retained, transient, reads;
	__block NSUInteger replies = 0;

	item = pressure_lookup(volume, root, fileName);
	attributes = [volume attributes:item error:&error];
	assert(attributes != nil && error == nil && attributes.size == original.length);
	pressure_read(volume, item, original, 0, modern, 0);
	manifest = [volume xattrNamed:[FSFileName nameWithString:@"org.machlin.ntfs.streams"]
			       ofItem:item
				error:&error];
	assert(manifest != nil && error == nil);
	if (wire != nil) {
		savedWire =
		    [volume xattrNamed:[FSFileName nameWithString:@"org.machlin.ntfs.reparse"]
				ofItem:item
				 error:&error];
		assert(error == nil && [savedWire isEqualToData:wire]);
	}
	retained = resource.liveBytes;
	reads = reader.reads;
	pressure_read(volume, item, original, 0, modern, 0);
	assert(resource.liveBytes == retained && reader.reads == reads);
	pressure_notify(volume, DISPATCH_MEMORYPRESSURE_NORMAL | DISPATCH_MEMORYPRESSURE_WARN);
	/* The notification itself touches neither dormant items nor core allocations. */
	assert(!volume.readCachePolicy.retentionActive && resource.liveBytes == retained &&
	    reader.reads == reads);
	pressure_read(volume, item, original, 0, modern, 0);
	transient = resource.liveBytes;
	assert(transient < retained && reader.reads > reads);
	assert([volume xattrNamed:[FSFileName nameWithString:@"org.machlin.ntfs.streams"]
			   ofItem:item
			    error:&error] != nil &&
	    error == nil);
	assert(resource.liveBytes == transient);
	assert([[volume xattrsForItem:item error:&error] count] != 0 && error == nil);
	assert(resource.liveBytes == transient);
	if (wire != nil) {
		assert([[volume xattrNamed:[FSFileName nameWithString:@"org.machlin.ntfs.reparse"]
				    ofItem:item
				     error:&error] isEqualToData:wire] &&
		    error == nil);
		assert([savedWire isEqualToData:wire] && resource.liveBytes == transient);
	}
	again = pressure_lookup(volume, root, fileName);
	assert(again == item && resource.liveBytes == transient);
	assert([volume attributes:item error:&error].size == attributes.size && error == nil);
	pressure_notify(volume, DISPATCH_MEMORYPRESSURE_NORMAL);
	assert(volume.readCachePolicy.retentionActive);
	pressure_read(volume, item, original, 0, modern, 0);
	assert(resource.liveBytes > transient);
	reads = reader.reads;
	pressure_read(volume, item, original, 0, modern, 0);
	assert(reader.reads == reads);
	pressure_notify(volume, DISPATCH_MEMORYPRESSURE_CRITICAL);
	[volume unmountWithReplyHandler:^{
	  replies++;
	}];
	assert(replies == 1 && !volume.readCachePolicy.retentionActive);
	[volume mountWithOptions:nil
		    replyHandler:^(NSError *e) {
		      assert(e == nil);
		      replies++;
		    }];
	assert(replies == 2 && !volume.readCachePolicy.retentionActive);
	pressure_read(volume, item, original, 0, modern, 0);
	assert(resource.liveBytes == transient);
	pressure_notify(volume, DISPATCH_MEMORYPRESSURE_NORMAL);
	assert(pressure_lookup(volume, root, fileName) == item);
	assert([[volume xattrNamed:[FSFileName nameWithString:@"org.machlin.ntfs.streams"]
			    ofItem:item
			     error:&error] isEqualToData:manifest] &&
	    error == nil);
	printf("pressure cache %s: retained=%zu transient=%zu released=%zu bytes\n",
	    imageName.UTF8String, (size_t)retained, (size_t)transient,
	    (size_t)(retained - transient));
	[volume invalidate];
	assert(resource.liveBytes == 0 && resource.liveAllocations == 0 &&
	    !volume.readCachePolicy.retentionActive);
}

static void
test_pressure_blocked_read(NSString *fixtures, NSData *original, BOOL modern)
{
	NSData *image = [NSData
	    dataWithContentsOfFile:[fixtures
				       stringByAppendingPathComponent:@"wof-file-lzx-packed.img"]];
	PressureReader *reader;
	PressureResource *resource;
	FSItem *root;
	NTFSVolume *volume = pressure_owner(image, modern, &reader, &resource, &root);
	FSItem *item = pressure_lookup(volume, root, @"hello.txt");
	dispatch_semaphore_t finished = dispatch_semaphore_create(0);
	NSUInteger bytes;

	pressure_read(volume, item, original, 0, modern, 0);
	reader.blockNextRead = YES;
	dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
	  @autoreleasepool {
		  pressure_read(volume, item, original, NTFS_WOF_UNIT_32K, modern, 0);
		  dispatch_semaphore_signal(finished);
	  }
	});
	pressure_wait(reader.entered);
	bytes = resource.liveBytes;
	pressure_notify(volume, DISPATCH_MEMORYPRESSURE_WARN);
	assert(!volume.readCachePolicy.retentionActive && resource.liveBytes == bytes);
	dispatch_semaphore_signal(reader.resume);
	pressure_wait(finished);
	assert(resource.liveBytes < bytes);
	[volume invalidate];
	assert(resource.liveBytes == 0 && resource.liveAllocations == 0);
}

static void
test_pressure_reopen_faults(NSString *fixtures, NSData *original, BOOL modern)
{
	NSData *image = [NSData
	    dataWithContentsOfFile:[fixtures
				       stringByAppendingPathComponent:@"wof-file-lzx-packed.img"]];
	PressureReader *reader;
	PressureResource *resource;
	FSItem *root;
	NTFSVolume *volume = pressure_owner(image, modern, &reader, &resource, &root);
	FSItem *item = pressure_lookup(volume, root, @"hello.txt");
	NSError *error = nil;
	NSUInteger base, allocations, reads, startAllocations, startReads, index;
	NSData *manifest;

	pressure_notify(volume, DISPATCH_MEMORYPRESSURE_CRITICAL);
	assert([volume attributes:item error:&error] != nil && error == nil);
	base = resource.liveBytes;
	startAllocations = resource.allocations;
	startReads = reader.reads;
	pressure_read(volume, item, original, 0, modern, 0);
	allocations = resource.allocations - startAllocations;
	reads = reader.reads - startReads;
	assert(allocations != 0 && reads != 0 && resource.liveBytes == base);
	for (index = 1; index <= allocations; index++) {
		resource.failAllocationAt = resource.allocations + index;
		pressure_read(volume, item, original, 0, modern, ENOMEM);
		assert(resource.liveBytes == base);
		resource.failAllocationAt = 0;
		pressure_read(volume, item, original, 0, modern, 0);
		assert(resource.liveBytes == base);
	}
	for (index = 1; index <= reads; index++) {
		reader.failReadAt = reader.reads + index;
		pressure_read(volume, item, original, 0, modern, EIO);
		assert(resource.liveBytes == base);
		reader.failReadAt = 0;
		pressure_read(volume, item, original, 0, modern, 0);
		assert(resource.liveBytes == base);
	}
	resource.failAllocationAt = resource.allocations + 1;
	assert([volume xattrNamed:[FSFileName nameWithString:@"org.machlin.ntfs.streams"]
			   ofItem:item
			    error:&error] == nil &&
	    error.code == ENOMEM);
	assert(resource.liveBytes == base);
	resource.failAllocationAt = 0;
	manifest = [volume xattrNamed:[FSFileName nameWithString:@"org.machlin.ntfs.streams"]
			       ofItem:item
				error:&error];
	assert(manifest != nil && error == nil && resource.liveBytes == base);
	pressure_notify(volume, DISPATCH_MEMORYPRESSURE_NORMAL);
	pressure_read(volume, item, original, 0, modern, 0);
	reader.revoked = YES;
	startReads = reader.reads;
	pressure_notify(volume, DISPATCH_MEMORYPRESSURE_WARN);
	pressure_read(volume, item, original, 0, modern, EIO);
	reader.revoked = NO;
	pressure_notify(volume, DISPATCH_MEMORYPRESSURE_NORMAL);
	pressure_read(volume, item, original, 0, modern, EIO);
	assert(reader.reads == startReads);
	[volume invalidate];
	assert(resource.liveBytes == 0 && resource.liveAllocations == 0 && [manifest length] != 0);
	printf(
	    "pressure LZX reopen faults: %zu allocation/%zu read positions and catalog failure\n",
	    (size_t)allocations, (size_t)reads);
}

@interface PressurePacker : NSObject
@property NSUInteger capacity;
@property NSMutableArray<NSString *> *names;
@property FSDirectoryCookie cookie;
@property(copy) void (^beforePacking)(void);
@end

@implementation PressurePacker

- (BOOL)packEntryWithName:(FSFileName *)name
		 itemType:(FSItemType)type
		   itemID:(FSItemID)itemID
	       nextCookie:(FSDirectoryCookie)cookie
	       attributes:(FSItemAttributes *)attributes
{
	assert(attributes != nil && attributes.type == type && attributes.fileID == itemID);
	if (self.beforePacking != nil) {
		self.beforePacking();
	}
	if (self.names.count == self.capacity) {
		return NO;
	}
	[self.names addObject:name.string];
	self.cookie = cookie;
	return YES;
}

@end

static PressurePacker *
pressure_page(NTFSVolume *volume, FSItem *root, FSDirectoryCookie cookie, NSUInteger capacity)
{
	PressurePacker *page = [[PressurePacker alloc] init];

	page.capacity = capacity;
	page.names = [NSMutableArray array];
	page.beforePacking = ^{
	  /* This runs inside enumeration's operation monitor. Observation must remain
	   * independent, and a full packer must preserve its unconsumed entry. */
	  pressure_notify(volume, DISPATCH_MEMORYPRESSURE_CRITICAL);
	};
	assert([volume enumerate:root
			  cookie:cookie
			verifier:cookie == FSDirectoryCookieInitial ? 0 : volume.directoryVerifier
		      attributes:YES
			  packer:(FSDirectoryEntryPacker *)page] == nil);
	return page;
}

static void
test_pressure_namespace(NSString *fixtures, BOOL modern)
{
	NSData *image = [NSData
	    dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:@"standard.img"]];
	PressureReader *reader;
	PressureResource *resource;
	FSItem *root;
	NTFSVolume *volume = pressure_owner(image, modern, &reader, &resource, &root);
	FSItem *item = pressure_lookup(volume, root, @"streamed.txt");
	NSError *error = nil;
	NSData *ads, *manifest;
	NSMutableArray<NSString *> *first = [NSMutableArray array],
				   *second = [NSMutableArray array];
	NSArray<NSString *> *expected = @[
		@"compressed.bin", @"extended.bin", @"fragmented.bin", @"hello.txt", @"middle.dat",
		@"sparse.bin", @"streamed.txt", @"tail.bin", @"Ωmega.txt"
	];
	PressurePacker *page;
	FSDirectoryCookie firstCookie = FSDirectoryCookieInitial,
			  secondCookie = FSDirectoryCookieInitial;
	NSUInteger round;

	ads = [volume xattrNamed:[FSFileName nameWithString:@"org.machlin.ntfs.stream.00000001"]
			  ofItem:item
			   error:&error];
	assert(error == nil &&
	    [ads isEqualToData:[@"alternate payload" dataUsingEncoding:NSUTF8StringEncoding]]);
	for (round = 0; round <= TEST_FILE_COUNT; round++) {
		page = pressure_page(volume, root, firstCookie, TEST_PRESSURE_PAGE_CAPACITY);
		[first addObjectsFromArray:page.names];
		if (page.names.count != 0) {
			firstCookie = page.cookie;
		}
		manifest = [volume xattrNamed:[FSFileName nameWithString:@"org.machlin.ntfs.names"]
				       ofItem:root
					error:&error];
		assert(manifest != nil && error == nil);
		assert([[volume xattrNamed:[FSFileName
					       nameWithString:@"org.machlin.ntfs.stream.00000001"]
				    ofItem:item
				     error:&error] isEqualToData:ads] &&
		    error == nil);
		page = pressure_page(volume, root, FSDirectoryCookieInitial, 0);
		assert(page.names.count == 0 && page.cookie == FSDirectoryCookieInitial);
		pressure_notify(volume, DISPATCH_MEMORYPRESSURE_NORMAL);
		page = pressure_page(volume, root, secondCookie, TEST_PRESSURE_SECOND_CAPACITY);
		[second addObjectsFromArray:page.names];
		if (page.names.count != 0) {
			secondCookie = page.cookie;
		}
	}
	assert([first isEqualToArray:expected] && [second isEqualToArray:expected]);
	assert(firstCookie == TEST_FILE_COUNT && secondCookie == TEST_FILE_COUNT);
	assert(pressure_lookup(volume, root, @"streamed.txt") == item);
	[volume invalidate];
	assert(resource.liveBytes == 0 && resource.liveAllocations == 0);
}

static void
test_pressure_link(NSString *fixtures, BOOL modern)
{
	NSString *imageName = @"native-link-relative.img";
	NSData *image =
	    [NSData dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:imageName]];
	NSArray<NSDictionary *> *cases = [NSJSONSerialization
	    JSONObjectWithData:[NSData
				   dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:
								  @"native-links.json"]]
		       options:0
			 error:NULL];
	NSDictionary *witness;
	NSData *wire = nil;
	PressureReader *reader;
	PressureResource *resource;
	FSItem *root;
	NTFSVolume *volume = pressure_owner(image, modern, &reader, &resource, &root);
	FSItem *item = pressure_lookup(volume, root, @"hello.txt");
	NSError *error = nil;
	FSFileName *target = [volume symbolicLink:item error:&error];
	NSData *data;
	NSUInteger retained = resource.liveBytes;

	for (witness in cases) {
		if ([witness[@"image"] isEqualToString:imageName]) {
			wire = [[NSData alloc] initWithBase64EncodedString:witness[@"raw"]
								   options:0];
			assert([target.string isEqualToString:witness[@"target"]]);
			break;
		}
	}
	assert(target != nil && error == nil && wire != nil);
	pressure_notify(volume, DISPATCH_MEMORYPRESSURE_WARN);
	assert([volume symbolicLink:item error:&error] == target && error == nil);
	assert(resource.liveBytes < retained);
	data = [volume xattrNamed:[FSFileName nameWithString:@"org.machlin.ntfs.reparse"]
			   ofItem:item
			    error:&error];
	assert(error == nil && [data isEqualToData:wire]);
	assert(pressure_lookup(volume, root, @"hello.txt") == item);
	assert([volume symbolicLink:item error:&error] == target && error == nil);
	[volume invalidate];
	assert(
	    [data isEqualToData:wire] && resource.liveBytes == 0 && resource.liveAllocations == 0);
}

void
ntfs_test_fskit_pressure(NSString *fixtures, BOOL modern)
{
	NSData *lzx, *xpress, *wireLZX, *wireXPRESS;
	NSMutableData *lznt1;

	if (modern && !ntfs_test_native_reclaim_available()) {
		puts("SKIP: modern FSKit pressure runtime requires macOS 27");
		return;
	}
	if (!modern) {
		test_policy_observation();
	}
	lzx = [NSData
	    dataWithContentsOfFile:[fixtures
				       stringByAppendingPathComponent:@"wof-file-lzx-packed.data"]];
	xpress = [NSData
	    dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:@"wof-file-4k.data"]];
	wireLZX = [NSData dataWithContentsOfFile:
		[fixtures stringByAppendingPathComponent:@"wof-file-lzx-packed.reparse"]];
	wireXPRESS = [NSData
	    dataWithContentsOfFile:[fixtures
				       stringByAppendingPathComponent:@"wof-file-4k.reparse"]];
	lznt1 = [NSMutableData dataWithLength:TEST_COMPRESSION_UNIT_BYTES];
	memset(lznt1.mutableBytes, 'Z', lznt1.length);
	assert(lzx != nil && xpress != nil && wireLZX != nil && wireXPRESS != nil);
	test_content_pressure(fixtures, @"standard.img", @"compressed.bin", lznt1, nil, modern);
	test_content_pressure(
	    fixtures, @"wof-file-4k.img", @"hello.txt", xpress, wireXPRESS, modern);
	test_content_pressure(
	    fixtures, @"wof-file-lzx-packed.img", @"hello.txt", lzx, wireLZX, modern);
	test_pressure_blocked_read(fixtures, lzx, modern);
	test_pressure_reopen_faults(fixtures, lzx, modern);
	test_pressure_namespace(fixtures, modern);
	test_pressure_link(fixtures, modern);
	puts("PASS: pressure cache release, exact bytes, identities, remount and blocked read");
}
