/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "fskit_maintenance.h"
#import "fskit_resource.h"
#import "fskit_lifecycle.h"
#import "NTFSFileSystem.h"
#import "NTFSCheckTask.h"
#import "NTFSVolume.h"
#include "fixture.h"
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <time.h>

enum {
	/* Allow callback cleanup after the native cancellation drain times out. */
	TEST_CHECK_COMPLETION_GRACE_SECONDS = 10,
	TEST_CHECK_TIMEOUT_SECONDS =
	    NTFS_CHECK_CANCEL_DRAIN_SECONDS + TEST_CHECK_COMPLETION_GRACE_SECONDS,
	TEST_CHECK_STATE_POLL_NANOSECONDS = NSEC_PER_MSEC,
	TEST_CHECK_REPORT_LOGS = 2,
	TEST_CHECK_QUICK_ARGUMENT_INDEX = 2
};

enum check_limit_dimension {
	CHECK_LIMIT_MEMORY,
	CHECK_LIMIT_READ_CALLS,
	CHECK_LIMIT_READ_BYTES,
	CHECK_LIMIT_WORK,
	CHECK_LIMIT_DIMENSIONS
};

static dispatch_time_t
deadline(void)
{
	return dispatch_time(DISPATCH_TIME_NOW, TEST_CHECK_TIMEOUT_SECONDS * NSEC_PER_SEC);
}

static void
wait_semaphore(dispatch_semaphore_t semaphore)
{
	assert(dispatch_semaphore_wait(semaphore, deadline()) == 0);
}

/* These public-message doubles exercise the real controller without acquiring
 * a native device or pretending that an installed daemon issued the FSTask. */
@interface CheckOptions : NSObject
@property(copy) NSArray<NSString *> *taskOptions;
@end
@implementation CheckOptions
@end

static FSTaskOptions *
options(NSArray<NSString *> *arguments)
{
	CheckOptions *value = [[CheckOptions alloc] init];

	value.taskOptions = arguments;
	return (FSTaskOptions *)value;
}

@interface CheckReader : TestReader
@property NSUInteger blockReadAt;
@property NSUInteger partialReadAt;
@property BOOL fullFailedRead;
@property uint64_t readBytes;
@property dispatch_semaphore_t entered;
@property dispatch_semaphore_t resume;
@end

@implementation CheckReader

- (instancetype)init
{
	self = [super init];
	if (self != nil) {
		_entered = dispatch_semaphore_create(0);
		_resume = dispatch_semaphore_create(0);
	}
	return self;
}

- (BOOL)isKindOfClass:(Class)type
{
	return type == FSBlockDeviceResource.class || [super isKindOfClass:type];
}

- (size_t)readInto:(void *)buffer
	startingAt:(off_t)offset
	    length:(size_t)length
	     error:(NSError **)error
{
	NSUInteger next = self.reads + 1;
	size_t partial;

	if (next == self.blockReadAt) {
		dispatch_semaphore_signal(self.entered);
		wait_semaphore(self.resume);
	}
	self.readBytes += length;
	if (next == self.partialReadAt) {
		partial = self.fullFailedRead ? length : length / 2;
		assert(offset >= 0 && (uint64_t)offset <= self.image.length &&
		    length <= self.image.length - (uint64_t)offset);
		memcpy(buffer, (const uint8_t *)self.image.bytes + offset, partial);
		self.reads++;
		*error = [NSError errorWithDomain:NSPOSIXErrorDomain code:EIO userInfo:nil];
		return partial;
	}
	return [super readInto:buffer startingAt:offset length:length error:error];
}

@end

@interface CheckTask : NSObject
@property(copy) NSError * (^cancellationHandler)(void);
@property(copy) void (^completed)(void);
@property dispatch_semaphore_t terminal;
@property NSUInteger completions;
@property NSError *failure;
@property NSMutableArray<NSString *> *messages;
- (void)logMessage:(NSString *)message;
- (void)didCompleteWithError:(NSError *)error;
@end

@implementation CheckTask

- (instancetype)init
{
	self = [super init];
	if (self != nil) {
		_terminal = dispatch_semaphore_create(0);
		_messages = [NSMutableArray array];
	}
	return self;
}

- (void)logMessage:(NSString *)message
{
	@synchronized(self) {
		assert(self.completions == 0 && message != nil);
		[self.messages addObject:message];
	}
}

- (void)didCompleteWithError:(NSError *)error
{
	void (^callback)(void);

	@synchronized(self) {
		assert(self.completions == 0);
		self.completions++;
		self.failure = error;
		callback = self.completed;
	}
	if (callback != nil) {
		callback();
	}
	dispatch_semaphore_signal(self.terminal);
}

@end

@interface CheckBudgetResource : FaultResource
@end

@implementation CheckBudgetResource

- (enum ntfs_result)beginReadBudget:(struct ntfs_resource_read_budget *)budget
			     limits:(const struct ntfs_operation_limits *)limits
{
	struct ntfs_operation_limits tightened = *limits;

	/* This logical-sector credit cannot admit a physical aligned fragment. */
	tightened.read_bytes = NTFS_RESOURCE_MIN_ALIGNMENT;
	return [super beginReadBudget:budget limits:&tightened];
}

@end

@interface CheckFileSystem : NTFSFileSystem
@property FaultResource *lastResource;
@property BOOL refuseOwner;
@property BOOL failAllocation;
@property NSUInteger failAllocationAt;
@property uint32_t recordLimit;
@property BOOL refusePhysicalBudget;
@end

@implementation CheckFileSystem

- (NTFSResource *)newResourceWithReader:(id<NTFSBlockReader>)reader
{
	FaultResource *resource;
	Class selected =
	    self.refusePhysicalBudget ? CheckBudgetResource.class : FaultResource.class;

	if (self.refuseOwner) {
		return nil;
	}
	resource = [[selected alloc] initWithReader:reader];
	resource.failAllocation = self.failAllocation;
	resource.failAllocationAt = self.failAllocationAt;
	self.lastResource = resource;
	return resource;
}

- (struct ntfs_validation_limits)validationLimits
{
	struct ntfs_validation_limits limits = [super validationLimits];

	if (self.recordLimit != 0) {
		limits.max_records = self.recordLimit;
	}
	return limits;
}

@end

static CheckReader *
reader_for(NSData *image)
{
	CheckReader *reader = [[CheckReader alloc] init];

	assert(image != nil);
	/* A reserved logical sector may end inside the fake device's physical
	 * block. Pad the backing resource without moving the declared boot copy. */
	[reader setAlignedImage:image];
	return reader;
}

static NTFSVolume *
load(CheckFileSystem *fileSystem, CheckReader *reader, BOOL force, int expected)
{
	__block NTFSVolume *volume;
	__block NSUInteger replies = 0;

	[fileSystem loadResource:(FSResource *)reader
			 options:options(force ? @[ @"-f" ] : @[])
		    replyHandler:^(FSVolume *value, NSError *error) {
		      assert((expected == 0 ? error == nil
					    : [error.domain isEqualToString:NSPOSIXErrorDomain] &&
				  error.code == expected));
		      assert(expected == 0 ? value != nil : value == nil);
		      volume = (NTFSVolume *)value;
		      replies++;
		    }];
	assert(replies == 1);
	return volume;
}

static void
unload(CheckFileSystem *fileSystem, CheckReader *reader, int expected)
{
	__block NSUInteger replies = 0;

	[fileSystem unloadResource:(FSResource *)reader
			   options:options(@[])
		      replyHandler:^(NSError *error) {
			assert(expected == 0 ? error == nil : error.code == expected);
			replies++;
		      }];
	assert(replies == 1);
}

static NSProgress *
start(CheckFileSystem *fileSystem, CheckTask *task, NSArray<NSString *> *arguments)
{
	NSError *error = [NSError errorWithDomain:@"test.initial" code:EIO userInfo:nil];
	NSProgress *progress = [fileSystem startCheckWithTask:(FSTask *)task
						      options:options(arguments)
							error:&error];

	assert(progress != nil && error == nil &&
	    progress.totalUnitCount == NTFS_CHECK_PROGRESS_UNITS);
	return progress;
}

static void
finish(CheckTask *task, NSProgress *progress, int expected, BOOL refused)
{
	wait_semaphore(task.terminal);
	assert(task.completions == 1 &&
	    (expected == 0 ? task.failure == nil
			   : [task.failure.domain isEqualToString:NSPOSIXErrorDomain] &&
			task.failure.code == expected));
	assert(progress.completedUnitCount == NTFS_CHECK_PROGRESS_UNITS &&
	    task.cancellationHandler == nil && progress.cancellationHandler == nil);
	assert(task.messages.count == (refused ? 0 : TEST_CHECK_REPORT_LOGS));
	assert(refused ? !progress.cancellable : progress.cancellable);
	if (!refused) {
		assert([task.messages.firstObject
		    containsString:expected == 0 ? @"success" : @"complete=0"]);
	}
}

static void
temporary_statistics(NTFSVolume *volume, int mountError)
{
	FSStatFSResult *stats = volume.volumeStatistics;
	FSVolumeSupportedCapabilities *caps = volume.supportedVolumeCapabilities;
	NSError *error = nil;
	__block NSUInteger replies = 0;
	int expected = volume.lifecycle == NTFSVolumeInvalidated ? ESTALE : mountError;

	assert(volume.maintenanceOnly && stats.blockSize == NTFS_RESOURCE_MIN_ALIGNMENT &&
	    stats.ioSize == stats.blockSize && stats.totalBlocks == 0 && stats.freeBlocks == 0 &&
	    stats.availableBlocks == 0 && stats.usedBlocks == 0 && stats.totalBytes == 0 &&
	    stats.freeBytes == 0 && stats.availableBytes == 0 && stats.usedBytes == 0 &&
	    stats.totalFiles == 0 && stats.freeFiles == 0 &&
	    [stats.fileSystemTypeName isEqualToString:@"machlinntfs"]);
	assert(!caps.supportsPersistentObjectIDs && !caps.supportsSymbolicLinks &&
	    !caps.supportsSparseFiles && !caps.supportsFastStatFS);
	assert([volume activate:&error] == nil && error.code == expected);
	[volume mountWithOptions:options(@[])
		    replyHandler:^(NSError *failure) {
		      assert(failure.code == expected);
		      replies++;
		    }];
	assert(replies == 1);
}

static void
test_temporary_family(NSData *image, BOOL modern)
{
	CheckReader *reader = reader_for(image);
	FaultResource *resource = [[FaultResource alloc] initWithReader:reader];
	Class selected = NTFSLegacyVolume.class;
	NTFSVolume *volume;

	if (modern) {
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
		if (@available(macOS 27.0, *)) {
			selected = NTFSModernVolume.class;
		} else {
			puts("SKIP: modern temporary maintenance identity requires macOS 27 "
			     "runtime");
			return;
		}
#else
		puts("SKIP: modern temporary maintenance identity requires macOS 27 SDK/runtime");
		return;
#endif
	}
	volume = [[selected alloc] initForCheckWithResource:resource mountError:NTFS_CORRUPT];
	assert(volume != nil && reader.reads == 0 && resource.allocations == 0);
	temporary_statistics(volume, EIO);
	assert([volume beginMaintenance] == NTFS_OK && [volume beginMaintenance] == NTFS_BUSY);
	assert([volume maintenanceAdmissionResult] == NTFS_OK);
	[volume endMaintenanceWithResult:NTFS_CORRUPT completeCheck:YES cancelled:NO];
	[volume invalidate];
	temporary_statistics(volume, EIO);
	assert([volume beginMaintenance] == NTFS_STALE && reader.reads == 0 &&
	    resource.liveAllocations == 0);
	printf("PASS: %s temporary maintenance identity, no geometry/I/O and retired statistics\n",
	    modern ? "modern" : "legacy");
}

static struct ntfs_validation_report
helper_run(NSData *image, BOOL quick, const struct ntfs_validation_limits *limits,
    NSUInteger failAllocation, NSUInteger failRead, BOOL fullFailure, NSUInteger *allocations,
    NSUInteger *reads, uint64_t *readBytes)
{
	CheckReader *reader = reader_for(image);
	FaultResource *resource = [[FaultResource alloc] initWithReader:reader];
	NTFSCheckTask *check;
	struct ntfs_validation_report report;
	enum ntfs_result result;
	NSError *error;
	NSData *original = [image copy];

	resource.failAllocationAt = failAllocation;
	reader.partialReadAt = failRead;
	reader.fullFailedRead = fullFailure;
	check = [[NTFSCheckTask alloc] initWithResource:resource
						  quick:quick
					      admission:nil
						 limits:limits];
	assert(![check validationReport:&report]);
	result = [check run];
	error = [check sealResult:result];
	assert([check validationReport:&report] && ![check validationReport:NULL]);
	assert(report.result == check.result && (result == NTFS_OK ? error == nil : error != nil));
	assert(report.complete == (!quick && result == NTFS_OK));
	assert(resource.liveAllocations == 0 && [image isEqualToData:original]);
	if (result == NTFS_OK) {
		assert(report.stage == (quick ? NTFS_VALIDATION_MOUNT : NTFS_VALIDATION_FINISHED));
	}
	assert([check run] == NTFS_BUSY && [check sealResult:NTFS_OK].code == EBUSY);
	[check cancel];
	assert(!check.cancelled);
	if (allocations != NULL) {
		*allocations = resource.allocations;
	}
	if (reads != NULL) {
		*reads = reader.reads;
	}
	if (readBytes != NULL) {
		*readBytes = reader.readBytes;
	}
	return report;
}

static void
test_helper_faults(NSData *image)
{
	struct ntfs_validation_report baseline, report;
	struct ntfs_validation_limits limits;
	CheckReader *reader;
	FaultResource *resource;
	NTFSCheckTask *check;
	NSUInteger mode, full, i, allocations, reads, failures = 0, optional = 0;
	uint64_t readBytes;
	__weak FaultResource *retired;

	for (mode = 0; mode < 2; mode++) {
		baseline =
		    helper_run(image, mode != 0, NULL, 0, 0, NO, &allocations, &reads, &readBytes);
		assert(
		    baseline.result == NTFS_OK && allocations != 0 && reads != 0 && readBytes != 0);
		if (mode == 0) {
			assert(baseline.records_scanned != 0 && baseline.directories != 0 &&
			    baseline.mirror_records_compared != 0);
		}
		for (i = 1; i <= allocations; i++) {
			@autoreleasepool {
				report =
				    helper_run(image, mode != 0, NULL, i, 0, NO, NULL, NULL, NULL);
				if (report.result == NTFS_OK) {
					/* Record-cache allocation is optional; a complete
					 * successful inventory remains mandatory when its storage
					 * is refused. */
					assert(report.records_scanned == baseline.records_scanned &&
					    report.claimed_clusters == baseline.claimed_clusters);
					optional++;
				} else {
					assert(report.result == NTFS_NO_MEMORY && !report.complete);
					failures++;
				}
			}
		}
		for (full = 0; full < 2; full++) {
			for (i = 1; i <= reads; i++) {
				@autoreleasepool {
					report = helper_run(image, mode != 0, NULL, 0, i, full != 0,
					    NULL, NULL, NULL);
					assert(report.result == NTFS_IO && !report.complete);
				}
			}
		}
		/* Fresh exact retries use new resource/diagnostic owners. */
		report = helper_run(image, mode != 0, NULL, 0, 0, NO, NULL, NULL, NULL);
		assert(report.result == NTFS_OK);
		printf(
		    "PASS: %s check helper, %lu allocation and %lu partial/full read positions\n",
		    mode == 0 ? "full" : "quick", (unsigned long)allocations, (unsigned long)reads);
	}
	assert(failures != 0);
	baseline = helper_run(image, NO, NULL, 0, 0, NO, NULL, &reads, &readBytes);
	for (mode = 0; mode < CHECK_LIMIT_DIMENSIONS; mode++) {
		for (i = 0; i < 2; i++) {
			ntfs_validation_default_limits(&limits);
			switch (mode) {
			case CHECK_LIMIT_MEMORY:
				limits.max_memory_bytes = baseline.peak_memory_bytes - i;
				break;
			case CHECK_LIMIT_READ_CALLS:
				limits.max_read_calls = baseline.read_calls - i;
				break;
			case CHECK_LIMIT_READ_BYTES:
				limits.max_read_bytes = MAX(readBytes, baseline.read_bytes) - i;
				break;
			case CHECK_LIMIT_WORK:
				limits.max_work_units = baseline.work_units - i;
				break;
			default:
				assert(false);
			}
			report = helper_run(image, NO, &limits, 0, 0, NO, NULL, NULL, NULL);
			assert(report.result == (i == 0 ? NTFS_OK : NTFS_RANGE));
		}
	}
	reader = reader_for(image);
	resource = [[FaultResource alloc] initWithReader:reader];
	check = [[NTFSCheckTask alloc] initWithResource:resource
						  quick:NO
					      admission:nil
						 limits:NULL];
	[check cancel];
	assert([check run] == NTFS_IO && [check sealResult:NTFS_IO].code == ECANCELED &&
	    reader.reads == 0 && resource.allocations == 0 && check.cancelled);
	assert([check validationReport:&report] && !report.complete);
	@autoreleasepool {
		CheckReader *temporaryReader = reader_for(image);
		FaultResource *temporary = [[FaultResource alloc] initWithReader:temporaryReader];

		retired = temporary;
		check = [[NTFSCheckTask alloc] initWithResource:temporary
							  quick:NO
						      admission:nil
							 limits:NULL];
		assert([check sealResult:NTFS_OK].code == EBUSY);
		assert([check run] == NTFS_OK && [check sealResult:NTFS_OK] == nil &&
		    temporary.liveAllocations == 0);
	}
	assert(retired == nil);
	[check cancel];
	assert(!check.cancelled && [check validationReport:&report] && report.complete);
	printf(
	    "PASS: checker exact/one-below memory/physical-I/O/work bounds and early cancellation; "
	    "%lu required failures/%lu optional omissions\n",
	    (unsigned long)failures, (unsigned long)optional);
}

static void
test_refusals(NSData *image)
{
	CheckFileSystem *fileSystem = [[CheckFileSystem alloc] init];
	CheckReader *reader = reader_for(image);
	NTFSVolume *volume;
	CheckTask *task;
	NSProgress *progress;
	NSError *error = nil;
	NSArray<NSArray<NSString *> *> *arguments = @[
		@[ @"-y" ], @[ @"-p" ], @[ @"--repair" ], @[ @"-q", @"-y" ],
		@[ @"-n", @"unexpected" ]
	];
	const int expected[] = {EROFS, EROFS, EINVAL, EROFS, EINVAL};
	NSMutableArray<NSString *> *tooMany = [NSMutableArray array];
	NSUInteger i, reads, allocations;
	FSContainerStatus *status;

	task = [[CheckTask alloc] init];
	finish(task, start(fileSystem, task, @[]), ESTALE, YES);
	volume = load(fileSystem, reader, NO, 0);
	status = fileSystem.containerStatus;
	reads = reader.reads;
	allocations = fileSystem.lastResource.allocations;
	for (i = 0; i < arguments.count; i++) {
		task = [[CheckTask alloc] init];
		finish(task, start(fileSystem, task, arguments[i]), expected[i], YES);
	}
	for (i = 0; i <= NTFS_CHECK_OPTION_LIMIT; i++) {
		[tooMany addObject:@"-n"];
	}
	task = [[CheckTask alloc] init];
	finish(task, start(fileSystem, task, tooMany), EOVERFLOW, YES);
	task = [[CheckTask alloc] init];
	progress = [fileSystem startFormatWithTask:(FSTask *)task
					   options:options(@[])
					     error:&error];
	assert(progress != nil && error == nil);
	finish(task, progress, EROFS, YES);
	assert(reader.reads == reads && fileSystem.lastResource.allocations == allocations &&
	    fileSystem.containerStatus == status && volume.lifecycle == NTFSVolumeLoaded);
	unload(fileSystem, reader, 0);
	assert(fileSystem.lastResource.liveAllocations == 0);
	puts("PASS: asynchronous read-only/option/unloaded refusals without I/O or ownership "
	     "changes");
}

static void
test_controller_modes(NSData *image)
{
	CheckFileSystem *fileSystem = [[CheckFileSystem alloc] init];
	CheckReader *reader = reader_for(image);
	NTFSVolume *volume = load(fileSystem, reader, NO, 0);
	CheckTask *task;
	NSProgress *progress;
	NSUInteger live = fileSystem.lastResource.liveAllocations, i;
	NSArray<NSArray<NSString *> *> *arguments =
	    @[ @[], @[ @"-n" ], @[ @"-q" ], @[ @"-q", @"-f" ] ];
	NSData *original = [image copy];
	NSError *error = nil;
	__block NSUInteger callbacks = 0;

	for (i = 0; i < arguments.count; i++) {
		task = [[CheckTask alloc] init];
		progress = start(fileSystem, task, arguments[i]);
		finish(task, progress, 0, NO);
		assert([task.messages.firstObject
		    containsString:i == TEST_CHECK_QUICK_ARGUMENT_INDEX ? @"complete=0"
									: @"complete=1"]);
		assert(fileSystem.lastResource.liveAllocations == live &&
		    volume.lifecycle == NTFSVolumeLoaded);
	}
	/* A full partial inventory blocks activation. A successful quick check and
	 * an interrupted full check cannot clear that failure; full clean retry can. */
	fileSystem.recordLimit = 1;
	task = [[CheckTask alloc] init];
	finish(task, start(fileSystem, task, @[]), EOVERFLOW, NO);
	assert([volume activate:&error] == nil && error.code == EOVERFLOW);
	fileSystem.recordLimit = 0;
	task = [[CheckTask alloc] init];
	finish(task, start(fileSystem, task, @[ @"-q" ]), 0, NO);
	assert([volume activate:&error] == nil && error.code == EOVERFLOW);
	reader.blockReadAt = reader.reads + 1;
	task = [[CheckTask alloc] init];
	progress = start(fileSystem, task, @[]);
	wait_semaphore(reader.entered);
	[progress cancel];
	dispatch_semaphore_signal(reader.resume);
	finish(task, progress, ECANCELED, NO);
	assert([volume activate:&error] == nil && error.code == EOVERFLOW);
	task = [[CheckTask alloc] init];
	task.completed = ^{
	  /* Native completion is outside all owning monitors and sees committed state. */
	  @autoreleasepool {
		  NSError *activationError = nil;
		  FSItem *root = [volume activate:&activationError];

		  assert(root != nil && activationError == nil);
		  unload(fileSystem, reader, 0);
		  callbacks++;
	  }
	};
	finish(task, start(fileSystem, task, @[ @"-f" ]), 0, NO);
	assert(callbacks == 1 && volume.lifecycle == NTFSVolumeInvalidated &&
	    fileSystem.lastResource.liveAllocations == 0 && [image isEqualToData:original]);
	volume = load(fileSystem, reader, NO, 0);
	@autoreleasepool {
		FSItem *root = [volume activate:&error];

		assert(root != nil && error == nil);
		task = [[CheckTask alloc] init];
		finish(task, start(fileSystem, task, @[]), EBUSY, YES);
		[volume unmountWithReplyHandler:^{
		  callbacks++;
		}];
		assert(callbacks == 2 && volume.lifecycle == NTFSVolumeUnmounted);
		task = [[CheckTask alloc] init];
		finish(task, start(fileSystem, task, @[]), EBUSY, YES);
		assert(root != nil);
	}
	task = [[CheckTask alloc] init];
	finish(task, start(fileSystem, task, @[]), 0, NO);
	unload(fileSystem, reader, 0);
	assert(fileSystem.lastResource.liveAllocations == 0);
	puts("PASS: controller quick/full/forced modes, sticky diagnostic failure, held items and "
	     "reentry");
}

static void
test_forced_loads(NSData *image, NSData *corrupt, NSString *fixtures)
{
	CheckFileSystem *fileSystem = [[CheckFileSystem alloc] init];
	CheckReader *reader;
	CheckReader *freshReader;
	CheckTask *task;
	NTFSVolume *volume;
	NSData *invalid = [NSMutableData dataWithLength:image.length];
	NSData *dirty =
	    [NSData dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:@"dirty.img"]];
	NSData *version = [NSData
	    dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:@"version.img"]];
	NSArray<NSData *> *images;
	const int expected[] = {EIO, EIO, EIO, ENOTSUP};
	NSUInteger mode, before;

	assert(dirty != nil && version != nil);
	images = @[ invalid, corrupt, dirty, version ];
	for (mode = 0; mode < images.count; mode++) {
		reader = reader_for(images[mode]);
		load(fileSystem, reader, NO, expected[mode]);
		volume = load(fileSystem, reader, YES, 0);
		temporary_statistics(volume, expected[mode]);
		task = [[CheckTask alloc] init];
		finish(task, start(fileSystem, task, @[ @"-f" ]), expected[mode], NO);
		assert(volume.lifecycle == NTFSVolumeInvalidated &&
		    fileSystem.lastResource.liveAllocations == 0);
		temporary_statistics(volume, expected[mode]);
		freshReader = reader_for(image);
		load(fileSystem, freshReader, NO, 0);
		unload(fileSystem, nil, EINVAL);
		[volume invalidate];
		/* The controller still owns the freshly loaded source; old-volume
		 * callbacks and retirement cannot release it. */
		assert(fileSystem.lastResource.liveAllocations != 0);
		unload(fileSystem, freshReader, 0);
		assert(fileSystem.lastResource.liveAllocations == 0);
	}
	reader = reader_for(image);
	reader.failed = YES;
	assert(load(fileSystem, reader, YES, EIO) == nil &&
	    fileSystem.lastResource.liveAllocations == 0);
	reader.failed = NO;
	fileSystem.failAllocation = YES;
	assert(load(fileSystem, reader, YES, ENOMEM) == nil &&
	    fileSystem.lastResource.liveAllocations == 0);
	fileSystem.failAllocation = NO;
	fileSystem.refusePhysicalBudget = YES;
	before = reader.reads;
	assert(load(fileSystem, reader, YES, EOVERFLOW) == nil && reader.reads == before &&
	    fileSystem.lastResource.liveAllocations == 0);
	fileSystem.refusePhysicalBudget = NO;
	fileSystem.refuseOwner = YES;
	assert(load(fileSystem, reader, YES, EINVAL) == nil);
	fileSystem.refuseOwner = NO;
	reader.revoked = YES;
	assert(load(fileSystem, reader, YES, EINVAL) == nil);
	puts("PASS: forced geometry-free identity and failure retirement; "
	     "I/O/allocation/acquisition stay errors");
}

static void
test_inventory_verdicts(NSString *fixtures)
{
	NSArray<NSString *> *names = @[
		@"validation-filename-mismatch.img", @"validation-allocated-unclaimed-cluster.img",
		@"validation-dos.img", @"validation-boot-signature.img"
	];
	const int expected[] = {EIO, EIO, ENOTSUP, EIO};
	NSData *image, *original;
	CheckFileSystem *fileSystem;
	CheckReader *reader;
	NTFSVolume *volume;
	CheckTask *task;
	NSError *error = nil;
	NSUInteger i, live;

	for (i = 0; i < names.count; i++) {
		image = [NSData
		    dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:names[i]]];
		original = [image copy];
		reader = reader_for(image);
		fileSystem = [[CheckFileSystem alloc] init];
		volume = load(fileSystem, reader, NO, 0);
		live = fileSystem.lastResource.liveAllocations;
		task = [[CheckTask alloc] init];
		finish(task, start(fileSystem, task, @[ @"-q" ]), 0, NO);
		task = [[CheckTask alloc] init];
		finish(task, start(fileSystem, task, @[ @"-n" ]), expected[i], NO);
		assert([volume activate:&error] == nil && error.code == expected[i] &&
		    [image isEqualToData:original] &&
		    fileSystem.lastResource.liveAllocations == live);
		unload(fileSystem, reader, 0);
		assert(fileSystem.lastResource.liveAllocations == 0);
	}
	puts("PASS: mountable corrupt/unsupported inventory verdicts stay partial and block "
	     "activation");
}

static void
test_gated_load(NSData *image)
{
	CheckFileSystem *fileSystem = [[CheckFileSystem alloc] init];
	CheckReader *reader = reader_for(image);
	CheckTask *task = [[CheckTask alloc] init];
	dispatch_semaphore_t loaded = dispatch_semaphore_create(0);
	__block NTFSVolume *volume = nil;

	reader.blockReadAt = 1;
	dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
	  volume = load(fileSystem, reader, NO, 0);
	  dispatch_semaphore_signal(loaded);
	});
	wait_semaphore(reader.entered);
	load(fileSystem, reader, NO, EBUSY);
	unload(fileSystem, reader, EBUSY);
	finish(task, start(fileSystem, task, @[]), EBUSY, YES);
	assert(volume == nil && fileSystem.lastResource.liveAllocations != 0);
	dispatch_semaphore_signal(reader.resume);
	wait_semaphore(loaded);
	assert(volume != nil && volume.lifecycle == NTFSVolumeLoaded);
	unload(fileSystem, reader, 0);
	assert(fileSystem.lastResource.liveAllocations == 0);
	puts("PASS: load reservation admits prompt busy replies while physical I/O is blocked");
}

static void
wait_state(NTFSVolume *volume, NTFSVolumeLifecycle state)
{
	struct timespec startTime, now;
	const struct timespec interval = {0, TEST_CHECK_STATE_POLL_NANOSECONDS};

	assert(clock_gettime(CLOCK_MONOTONIC, &startTime) == 0);
	while (volume.lifecycle != state) {
		assert(clock_gettime(CLOCK_MONOTONIC, &now) == 0 &&
		    now.tv_sec - startTime.tv_sec < TEST_CHECK_TIMEOUT_SECONDS);
		nanosleep(&interval, NULL);
	}
}

static void
test_gated_admission(NSData *image)
{
	CheckFileSystem *fileSystem = [[CheckFileSystem alloc] init];
	CheckReader *reader = reader_for(image);
	NTFSVolume *volume = load(fileSystem, reader, NO, 0);
	CheckTask *task;
	FSFileName *stored;
	NSError *error = nil;
	dispatch_semaphore_t drained = dispatch_semaphore_create(0);
	dispatch_semaphore_t entered = dispatch_semaphore_create(0);
	dispatch_semaphore_t resume = dispatch_semaphore_create(0);
	__block enum ntfs_result result = NTFS_INVALID;
	__block size_t completed = 0;
	__block uint8_t byte = 0;

	@autoreleasepool {
		FSItem *root = [volume activate:&error];
		FSItem *file = [volume lookup:[FSFileName nameWithString:@"fragmented.bin"]
				  inDirectory:root
				   storedName:&stored
					error:&error];

		assert(root != nil && file != nil && error == nil);
		reader.blockReadAt = reader.reads + 1;
		dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
		  result = [volume readItem:file
				     offset:0
				      bytes:&byte
				     length:sizeof(byte)
				  completed:&completed];
		  dispatch_semaphore_signal(drained);
		});
		wait_semaphore(reader.entered);
		task = [[CheckTask alloc] init];
		finish(task, start(fileSystem, task, @[]), EBUSY, YES);
		assert(result == NTFS_INVALID && completed == 0);
		dispatch_semaphore_signal(reader.resume);
		wait_semaphore(drained);
		assert(result == NTFS_OK && completed == sizeof(byte));
		unload(fileSystem, reader, 0);
		assert(fileSystem.lastResource.liveAllocations == 0);
	}
	reader = reader_for(image);
	volume = load(fileSystem, reader, NO, 0);
	dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
	  [volume performItemPublication:^{
	    dispatch_semaphore_signal(entered);
	    wait_semaphore(resume);
	  }];
	  dispatch_semaphore_signal(drained);
	});
	wait_semaphore(entered);
	task = [[CheckTask alloc] init];
	finish(task, start(fileSystem, task, @[]), EBUSY, YES);
	assert(volume.lifecycle == NTFSVolumeLoaded);
	dispatch_semaphore_signal(resume);
	wait_semaphore(drained);
	unload(fileSystem, reader, 0);
	assert(fileSystem.lastResource.liveAllocations == 0);
	puts("PASS: checker admission refuses blocked active reads/publication without waiting for "
	     "their monitors");
}

enum check_gate_scenario {
	CHECK_PROGRESS_CANCEL,
	CHECK_NATIVE_CANCEL_TIMEOUT,
	CHECK_REVOKE,
	CHECK_UNMOUNT,
	CHECK_INVALIDATE,
	CHECK_GATE_SCENARIOS
};

static void
test_gated_checks(NSData *image)
{
	NSUInteger scenario, live, replies;
	CheckFileSystem *fileSystem;
	CheckReader *reader;
	NTFSVolume *volume;
	CheckTask *task, *other;
	NSProgress *progress, *refusal;
	NSError *error, *cancelError;
	NSError * (^cancel)(void);
	dispatch_semaphore_t drained;
	int expected;
	__block NSUInteger callbacks;

	for (scenario = 0; scenario < CHECK_GATE_SCENARIOS; scenario++) {
		fileSystem = [[CheckFileSystem alloc] init];
		reader = reader_for(image);
		volume = load(fileSystem, reader, NO, 0);
		live = fileSystem.lastResource.liveAllocations;
		reader.blockReadAt = reader.reads + 1;
		task = [[CheckTask alloc] init];
		progress = start(fileSystem, task, @[]);
		wait_semaphore(reader.entered);
		assert(volume.lifecycle == NTFSVolumeChecking &&
		    fileSystem.lastResource.liveAllocations > live && task.completions == 0);
		cancel = task.cancellationHandler;
		assert(cancel != nil && [volume activate:&error] == nil && error.code == EBUSY);
		load(fileSystem, reader, NO, EBUSY);
		unload(fileSystem, reader, EBUSY);
		other = [[CheckTask alloc] init];
		finish(other, start(fileSystem, other, @[]), EBUSY, YES);
		other = [[CheckTask alloc] init];
		refusal = [fileSystem startFormatWithTask:(FSTask *)other
						  options:options(@[])
						    error:&error];
		assert(refusal != nil && error == nil);
		finish(other, refusal, EROFS, YES);
		assert(task.completions == 0 && volume.lifecycle == NTFSVolumeChecking);
		refusal = [fileSystem startCheckWithTask:(FSTask *)task
						 options:options(@[ @"-y" ])
						   error:&error];
		assert(refusal == nil && error.code == EBUSY && task.completions == 0 &&
		    task.cancellationHandler != nil);
		refusal = [fileSystem startFormatWithTask:(FSTask *)task
						  options:options(@[])
						    error:&error];
		assert(refusal == nil && error.code == EBUSY && task.completions == 0);
		callbacks = 0;
		[volume mountWithOptions:options(@[])
			    replyHandler:^(NSError *failure) {
			      assert(failure.code == EBUSY);
			      callbacks++;
			    }];
		assert(callbacks == 1);
		drained = dispatch_semaphore_create(0);
		expected = ECANCELED;
		switch (scenario) {
		case CHECK_PROGRESS_CANCEL:
			[progress cancel];
			assert(progress.cancelled);
			break;
		case CHECK_NATIVE_CANCEL_TIMEOUT:
			cancelError = cancel();
			assert([cancelError.domain isEqualToString:NSPOSIXErrorDomain] &&
			    cancelError.code == ETIMEDOUT && task.completions == 0 &&
			    fileSystem.lastResource.liveAllocations > live);
			unload(fileSystem, reader, EBUSY);
			break;
		case CHECK_REVOKE:
			reader.revoked = YES;
			expected = EIO;
			break;
		case CHECK_UNMOUNT: {
			dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
			  [volume unmountWithReplyHandler:^{
			    dispatch_semaphore_signal(drained);
			  }];
			});
			wait_state(volume, NTFSVolumeDraining);
			expected = ESTALE;
			break;
		}
		case CHECK_INVALIDATE: {
			dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
			  [volume invalidate];
			  dispatch_semaphore_signal(drained);
			});
			wait_state(volume, NTFSVolumeInvalidating);
			expected = ESTALE;
			break;
		}
		default:
			assert(false);
		}
		assert(task.completions == 0 && fileSystem.lastResource.liveAllocations > live);
		dispatch_semaphore_signal(reader.resume);
		finish(task, progress, expected, NO);
		if (scenario == CHECK_UNMOUNT || scenario == CHECK_INVALIDATE) {
			wait_semaphore(drained);
			assert(volume.lifecycle ==
			    (scenario == CHECK_UNMOUNT ? NTFSVolumeUnmounted
						       : NTFSVolumeInvalidated));
		}
		assert(cancel() == nil && task.completions == 1);
		unload(fileSystem, reader, 0);
		assert(fileSystem.lastResource.liveAllocations == 0);
		reader = reader_for(image);
		load(fileSystem, reader, NO, 0);
		replies = task.completions;
		assert(cancel() == nil && task.completions == replies);
		other = [[CheckTask alloc] init];
		finish(other, start(fileSystem, other, @[]), 0, NO);
		unload(fileSystem, reader, 0);
		assert(fileSystem.lastResource.liveAllocations == 0);
	}
	puts("PASS: gated check cancellation/timeout/revocation/unmount/invalidate, retained "
	     "storage and late hooks");
}

void
ntfs_test_fskit_maintenance(NSString *fixtures)
{
	NSData *image = [NSData
	    dataWithContentsOfFile:[fixtures
				       stringByAppendingPathComponent:@"validation-standard.img"]];
	NSData *corrupt = [NSData
	    dataWithContentsOfFile:[fixtures stringByAppendingPathComponent:@"torn-mft.img"]];

	assert(image != nil && corrupt != nil);
	test_temporary_family(image, NO);
	test_temporary_family(image, YES);
	test_helper_faults(image);
	test_refusals(image);
	test_controller_modes(image);
	test_forced_loads(image, corrupt, fixtures);
	test_inventory_verdicts(fixtures);
	test_gated_load(image);
	test_gated_admission(image);
	test_gated_checks(image);
}
