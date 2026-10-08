/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSCheckTask.h"
#include <errno.h>

@interface NTFSCheckTask ()
- (enum ntfs_result)admissionResult;
- (void *)allocateSize:(size_t)size;
- (void)releaseBytes:(void *)bytes size:(size_t)size;
- (enum ntfs_result)readAt:(uint64_t)offset bytes:(void *)bytes length:(size_t)length;
@end

static void *
native_check_allocate(void *context, size_t size)
{
	return [(__bridge NTFSCheckTask *)context allocateSize:size];
}

static void
native_check_release(void *context, void *bytes, size_t size)
{
	[(__bridge NTFSCheckTask *)context releaseBytes:bytes size:size];
}

static enum ntfs_result
native_check_read(void *context, uint64_t offset, void *bytes, size_t length)
{
	return [(__bridge NTFSCheckTask *)context readAt:offset bytes:bytes length:length];
}

@implementation NTFSCheckTask {
	NTFSResource *_resource;
	enum ntfs_result (^_admission)(void);
	struct ntfs_validation_limits _limits;
	struct ntfs_validation_report _report;
	enum ntfs_result _result;
	BOOL _quick, _started, _cancelled, _sealed;
}

- (instancetype)initWithResource:(NTFSResource *)resource
			   quick:(BOOL)quick
		       admission:(enum ntfs_result (^)(void))admission
			  limits:(const struct ntfs_validation_limits *)limits
{
	if (resource == nil) {
		return nil;
	}
	self = [super init];
	if (self != nil) {
		_resource = resource;
		_admission = [admission copy];
		_quick = quick;
		ntfs_validation_default_limits(&_limits);
		if (limits != NULL) {
			_limits = *limits;
		}
	}
	return self;
}

- (void)cancel
{
	@synchronized(self) {
		if (!_sealed) {
			_cancelled = YES;
		}
	}
}

- (BOOL)cancelled
{
	@synchronized(self) {
		return _cancelled;
	}
}

- (enum ntfs_result)admissionResult
{
	enum ntfs_result result;

	if (self.cancelled) {
		return NTFS_IO;
	}
	result = _admission == nil ? NTFS_OK : _admission();
	return result == NTFS_OK && !_resource.isAvailable ? NTFS_IO : result;
}

- (void *)allocateSize:(size_t)size
{
	return [self admissionResult] == NTFS_OK ? [_resource allocateSize:size] : NULL;
}

- (void)releaseBytes:(void *)bytes size:(size_t)size
{
	/* Cleanup remains unconditional after cancellation, revocation or refusal. */
	[_resource releaseBytes:bytes size:size];
}

- (enum ntfs_result)readAt:(uint64_t)offset bytes:(void *)bytes length:(size_t)length
{
	enum ntfs_result result = [self admissionResult];

	if (result == NTFS_OK) {
		result = [_resource readAt:offset bytes:bytes length:length];
	}
	return result == NTFS_OK ? [self admissionResult] : result;
}

- (enum ntfs_result)run
{
	struct ntfs_environment environment;
	struct ntfs_operation_limits limits;
	struct ntfs_resource_read_budget budget = {0};
	struct ntfs_volume *core = NULL;
	enum ntfs_result result;

	@synchronized(self) {
		if (_started || _sealed) {
			return NTFS_BUSY;
		}
		_started = YES;
	}
	result = [self admissionResult];
	if (result != NTFS_OK) {
		return result;
	}
	environment = [_resource environment];
	environment.context = (__bridge void *)self;
	environment.read = native_check_read;
	environment.allocate = native_check_allocate;
	environment.release = native_check_release;
	ntfs_operation_default_limits(&limits);
	if (!_quick) {
		limits.read_calls = _limits.max_read_calls;
		limits.read_bytes = _limits.max_read_bytes;
	}
	result = [_resource beginReadBudget:&budget limits:&limits];
	if (result != NTFS_OK) {
		return result;
	}
	@try {
		if (_quick) {
			result = ntfs_mount(&environment, NULL, &core);
			if (core != NULL) {
				(void)ntfs_unmount(core);
			}
			_report.stage = NTFS_VALIDATION_MOUNT;
			_report.result = result;
			/* Mount eligibility does not publish a complete inventory verdict. */
		} else {
			result = ntfs_validate(&environment, NULL, &_limits, &_report);
			if (result == NTFS_OK && !_report.complete) {
				result = NTFS_IO;
			}
		}
		if (result == NTFS_OK) {
			result = [_resource readBudgetResult];
		}
		if (result == NTFS_OK) {
			result = [self admissionResult];
		}
	} @finally {
		(void)[_resource endReadBudget:&budget];
	}
	return result;
}

- (NSError *)sealResult:(enum ntfs_result)result
{
	@synchronized(self) {
		enum ntfs_result admission;

		if (!_started || _sealed) {
			return ntfs_error(NTFS_BUSY);
		}
		admission = [self admissionResult];
		if (admission != NTFS_OK) {
			result = admission;
		}
		_sealed = YES;
		_result = _cancelled ? NTFS_IO : result;
		_report.result = _result;
		if (_result != NTFS_OK) {
			_report.complete = false;
		}
		/* A copied late cancellation handler retains only the sealed verdict,
		 * never an old volume, device owner or its aligned transport window. */
		_admission = nil;
		_resource = nil;
		return _cancelled
		    ? [NSError errorWithDomain:NSPOSIXErrorDomain code:ECANCELED userInfo:nil]
		    : ntfs_error(_result);
	}
}

- (enum ntfs_result)result
{
	@synchronized(self) {
		return _result;
	}
}

- (BOOL)validationReport:(struct ntfs_validation_report *)report
{
	@synchronized(self) {
		if (!_sealed || report == NULL) {
			return NO;
		}
		*report = _report;
		return YES;
	}
}

@end
