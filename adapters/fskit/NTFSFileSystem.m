/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSFileSystem.h"
#import "NTFSVolume.h"
#import "NTFSCheckTask.h"
#import "NTFSImageTransport.h"
#import "NTFSImageVolume.h"
#include <errno.h>

typedef NS_ENUM(NSUInteger, NTFSFileSystemPhase) {
	NTFSFileSystemIdle,
	NTFSFileSystemLoading,
	NTFSFileSystemUnloading,
	NTFSFileSystemChecking
};

static BOOL
checkable_mount_failure(enum ntfs_result result)
{
	return result == NTFS_NOT_NTFS || result == NTFS_CORRUPT || result == NTFS_DIRTY ||
	    result == NTFS_UNSUPPORTED;
}

static enum ntfs_result
check_options(NSArray<NSString *> *arguments, BOOL *quick)
{
	BOOL force = NO, repair = NO;
	NSString *argument;

	*quick = NO;
	if (arguments.count > NTFS_CHECK_OPTION_LIMIT) {
		return NTFS_RANGE;
	}
	for (argument in arguments) {
		if ([argument isEqualToString:@"-q"]) {
			*quick = YES;
		} else if ([argument isEqualToString:@"-f"]) {
			force = YES;
		} else if ([argument isEqualToString:@"-y"] || [argument isEqualToString:@"-p"]) {
			repair = YES;
		} else if (![argument isEqualToString:@"-n"]) {
			return NTFS_INVALID;
		}
	}
	*quick = *quick && !force;
	return repair ? NTFS_READ_ONLY : NTFS_OK;
}

@interface NTFSFileSystem ()
- (void)loadImageResource:(FSPathURLResource *)resource
		  options:(FSTaskOptions *)options
	     replyHandler:(void (^)(FSVolume *, NSError *))reply;
@end

@implementation NTFSFileSystem {
	NTFSVolume *_volume;
	FSResource *_resource;
	NTFSResource *_resourceOwner;
	NTFSFileSystemPhase _phase;
	NTFSCheckTask *_check;
	FSTask *_maintenanceTask;
}

- (NTFSResource *)newResourceWithReader:(id<NTFSBlockReader>)reader
{
	return [[NTFSResource alloc] initWithReader:reader];
}

- (NTFSImageTransport *)newImageTransportWithResource:(FSPathURLResource *)resource
						error:(NSError **)error
{
	return [[NTFSImageTransport alloc] initWithResource:resource
				       requireSecurityScope:YES
						      error:error];
}

- (struct ntfs_validation_limits)validationLimits
{
	struct ntfs_validation_limits limits;

	ntfs_validation_default_limits(&limits);
	return limits;
}

- (void)probeResource:(FSResource *)resource
	 replyHandler:(void (^)(FSProbeResult *, NSError *))reply
{
	__attribute__((objc_precise_lifetime)) NTFSResource *owner = nil;
	__attribute__((objc_precise_lifetime)) NTFSImageTransport *image = nil;
	struct ntfs_overwrite_environment imageEnvironment = {0};
	struct ntfs_environment env;
	struct ntfs_info info;
	struct ntfs_operation_limits limits;
	struct ntfs_resource_read_budget budget = {0};
	enum ntfs_result result = NTFS_OK;
	NSError *error = nil;
	FSProbeResult *probe;

	if ([resource isKindOfClass:FSPathURLResource.class]) {
		image = [self newImageTransportWithResource:(FSPathURLResource *)resource
						      error:&error];
		if (image == nil) {
			reply(nil, error != nil ? error : ntfs_error(NTFS_NO_MEMORY));
			return;
		}
		imageEnvironment = [image overwriteEnvironment];
		result = [image performExclusiveAccess:^{
		  return imageEnvironment.claim(imageEnvironment.reader.context);
		}];
		if (result == NTFS_OK) {
			owner = [image newReadResource];
			if (owner == nil) {
				result = image.isAvailable ? NTFS_NO_MEMORY : NTFS_IO;
			}
		}
	} else if ([resource isKindOfClass:FSBlockDeviceResource.class]) {
		owner = [self newResourceWithReader:(id<NTFSBlockReader>)resource];
		if (owner == nil) {
			result = NTFS_INVALID;
		}
	} else {
		reply(FSProbeResult.notRecognizedProbeResult, nil);
		return;
	}
	if (result == NTFS_OK) {
		env = [owner environment];
		ntfs_operation_default_limits(&limits);
		result = [owner beginReadBudget:&budget limits:&limits];
		if (result == NTFS_OK) {
			@try {
				/* Probe publishes no write owner and never performs recovery. */
				result = ntfs_probe(&env, &info);
			} @finally {
				(void)[owner endReadBudget:&budget];
			}
		}
	}
	if (image != nil) {
		/* Drop the immutable lease before the claim. No image owner escapes. */
		owner = nil;
		imageEnvironment.unclaim(imageEnvironment.reader.context);
	}
	if (result == NTFS_NOT_NTFS) {
		probe = FSProbeResult.notRecognizedProbeResult;
	} else if (result != NTFS_OK) {
		reply(nil, ntfs_error(result));
		return;
	} else {
		probe = [FSProbeResult
		    usableProbeResultWithName:@"NTFS"
				  containerID:[[FSContainerIdentifier alloc]
						  initWithUUID:ntfs_uuid(info.serial)]];
	}
	reply(probe, ntfs_native_result_error(probe, nil));
}

- (void)loadResource:(FSResource *)resource
	     options:(FSTaskOptions *)options
	replyHandler:(void (^)(FSVolume *, NSError *))reply
{
	__attribute__((objc_precise_lifetime)) NTFSResource *owner = nil;
	NTFSVolume *loaded = nil;
	NTFSLinkPolicy *policy = nil;
	struct ntfs_environment env;
	struct ntfs_volume *core = NULL;
	struct ntfs_info info;
	struct ntfs_operation_limits limits;
	struct ntfs_resource_read_budget budget = {0};
	enum ntfs_result result = NTFS_OK, mountResult = NTFS_OK;
	BOOL reserved = NO, force = NO;
	NTFSNativeAccessMode accessMode = NTFSNativeAccessUnselected;

	if ([resource isKindOfClass:FSPathURLResource.class]) {
		[self loadImageResource:(FSPathURLResource *)resource
				options:options
			   replyHandler:reply];
		return;
	}
	@synchronized(self) {
		if (_phase != NTFSFileSystemIdle || _volume != nil) {
			result = NTFS_BUSY;
		} else if (![resource isKindOfClass:FSBlockDeviceResource.class]) {
			result = NTFS_UNSUPPORTED;
		} else {
			_phase = NTFSFileSystemLoading;
			reserved = YES;
		}
	}
	if (!reserved) {
		reply(nil, ntfs_error(result));
		return;
	}
	/* Never hold the controller monitor across core I/O or volume ownership. */
	result = ntfs_native_access_mode(options.taskOptions, &accessMode);
	if (result == NTFS_OK && accessMode == NTFSNativeAccessImageEditing) {
		/* A block resource has no qualified offline-image ownership contract. */
		result = NTFS_UNSUPPORTED;
	}
	if (result == NTFS_OK) {
		force = [options.taskOptions containsObject:@"-f"];
		owner = [self newResourceWithReader:(id<NTFSBlockReader>)resource];
	}
	if (result == NTFS_OK && owner == nil) {
		result = NTFS_INVALID;
	}
	if (owner != nil) {
		env = [owner environment];
		ntfs_operation_default_limits(&limits);
		result = [owner beginReadBudget:&budget limits:&limits];
		if (result == NTFS_OK) {
			@try {
				mountResult = ntfs_mount(&env, NULL, &core);
				result = mountResult;
				if (result == NTFS_OK) {
					ntfs_get_info(core, &info);
					result = ntfs_native_link_policy(
					    info.serial, options.taskOptions, &policy);
					if (result == NTFS_OK) {
						loaded = ntfs_volume_create_with_policies(
						    core, owner, policy, accessMode);
						if (loaded == nil) {
							result = NTFS_IO;
						}
					}
				}
				if (result == NTFS_OK) {
					result = [owner readBudgetResult];
				}
			} @finally {
				(void)[owner endReadBudget:&budget];
			}
		}
		if (result == NTFS_OK && !owner.isAvailable) {
			result = NTFS_IO;
		}
		if (result != NTFS_OK && core != NULL) {
			if (loaded != nil) {
				[loaded invalidate];
				loaded = nil;
			} else {
				(void)ntfs_unmount(core);
			}
			core = NULL;
		}
		/* Only an explicit forced checker load may publish a geometry-free,
		 * nonmountable unary identity. I/O, quota, allocator, policy and result
		 * construction failures never become successful maintenance loads. */
		if (force && result == mountResult && checkable_mount_failure(mountResult) &&
		    owner.isAvailable) {
			loaded = ntfs_volume_create_for_check(owner, mountResult);
			result = loaded == nil ? NTFS_NO_MEMORY : NTFS_OK;
		}
	}
	@synchronized(self) {
		if (result == NTFS_OK) {
			_volume = loaded;
			_resource = resource;
			_resourceOwner = owner;
			self.containerStatus = loaded.maintenanceOnly
			    ? [FSContainerStatus blockedWithStatus:ntfs_error(mountResult)]
			    : FSContainerStatus.ready;
		} else {
			self.containerStatus =
			    [FSContainerStatus blockedWithStatus:ntfs_error(result)];
		}
		_phase = NTFSFileSystemIdle;
	}
	reply(loaded, ntfs_error(result));
}

/* The complete image operation owns policy, scope and recovery before publication.
 * Block devices keep their independent immutable extraction contract. */
- (void)loadImageResource:(FSPathURLResource *)resource
		  options:(FSTaskOptions *)options
	     replyHandler:(void (^)(FSVolume *, NSError *))reply
{
	__attribute__((objc_precise_lifetime)) NTFSImageTransport *image = nil;
	NTFSVolume *loaded = nil;
	NTFSNativeAccessMode selected = NTFSNativeAccessUnselected;
	enum ntfs_result result = NTFS_OK;
	NSError *failure = nil;
	BOOL reserved = NO, modern = NO;

	@synchronized(self) {
		if (_phase != NTFSFileSystemIdle || _volume != nil) {
			result = NTFS_BUSY;
		} else if (![resource isKindOfClass:FSPathURLResource.class]) {
			result = NTFS_UNSUPPORTED;
		} else {
			_phase = NTFSFileSystemLoading;
			reserved = YES;
		}
	}
	if (!reserved) {
		reply(nil, ntfs_error(result));
		return;
	}
	result = ntfs_native_access_mode(options.taskOptions, &selected);
	if (result == NTFS_OK && selected == NTFSNativeAccessUnselected) {
		failure = [NSError errorWithDomain:NSPOSIXErrorDomain code:EACCES userInfo:nil];
	} else if (result == NTFS_OK && selected != NTFSNativeAccessImageEditing) {
		result = NTFS_UNSUPPORTED;
	} else if (result == NTFS_OK) {
		result = ntfs_native_image_options(options.taskOptions);
	}
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
	if (@available(macOS 27.0, *)) {
		modern = YES;
	}
#endif
	if (failure == nil && result == NTFS_OK && !modern) {
		result = NTFS_UNSUPPORTED;
	}
	if (failure == nil) {
		failure = ntfs_error(result);
	}
	if (failure == nil) {
		/* Policy is complete before scope, open, claim or recovery. Keep the
		 * daemon's original resource; no URL reconstruction or forced load. */
		image = [self newImageTransportWithResource:resource error:&failure];
		failure = ntfs_native_result_error(image, failure);
	}
	if (failure == nil) {
		loaded = ntfs_image_editing_volume_create(image, &failure);
		failure = ntfs_native_result_error(loaded, failure);
		if (failure == nil && !image.isAvailable) {
			failure = ntfs_error(NTFS_IO);
		}
	}
	if (failure != nil && loaded != nil) {
		[loaded invalidate];
		loaded = nil;
	}
	@synchronized(self) {
		if (failure == nil) {
			_volume = loaded;
			_resource = resource;
			_resourceOwner = nil;
			self.containerStatus = FSContainerStatus.ready;
		} else {
			self.containerStatus = [FSContainerStatus blockedWithStatus:failure];
		}
		_phase = NTFSFileSystemIdle;
	}
	reply(loaded, failure);
}

- (void)unloadResource:(FSResource *)resource
	       options:(FSTaskOptions *)options
	  replyHandler:(void (^)(NSError *))reply
{
	NTFSVolume *volume = nil;
	enum ntfs_result result = NTFS_OK;
	BOOL reserved = NO;
	void (^retire)(void);

	(void)options;
	@synchronized(self) {
		if (_phase != NTFSFileSystemIdle) {
			result = NTFS_BUSY;
		} else if (_resource != nil && _resource != resource &&
		    !([_resource isKindOfClass:FSPathURLResource.class] &&
			[resource isKindOfClass:FSPathURLResource.class] &&
			[((FSPathURLResource *)_resource).url
			    isEqual:((FSPathURLResource *)resource).url])) {
			result = NTFS_INVALID;
		} else {
			_phase = NTFSFileSystemUnloading;
			volume = _volume;
			reserved = YES;
		}
	}
	if (!reserved) {
		reply(ntfs_error(result));
		return;
	}
	retire = ^{
	  @synchronized(self) {
		  self->_volume = nil;
		  self->_resource = nil;
		  self->_resourceOwner = nil;
		  self->_phase = NTFSFileSystemIdle;
		  self.containerStatus =
		      [FSContainerStatus notReadyWithStatus:ntfs_error(NTFS_STALE)];
	  }
	  reply(nil);
	};
	if (volume == nil) {
		retire();
	} else {
		[volume invalidateWithReplyHandler:retire];
	}
}

- (NSProgress *)completeRejectedTask:(FSTask *)task error:(NSError *)failure
{
	NSProgress *progress = [NSProgress progressWithTotalUnitCount:NTFS_CHECK_PROGRESS_UNITS];

	/* ext4's installed framework history requires asynchronous refusal for
	 * maintenance. Refusal claims no device and offers no cancellation hook. */
	progress.cancellable = NO;
	dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
	  @autoreleasepool {
		  progress.completedUnitCount = NTFS_CHECK_PROGRESS_UNITS;
		  [task didCompleteWithError:failure];
	  }
	});
	return progress;
}

- (NSProgress *)startCheckWithTask:(FSTask *)task
			   options:(FSTaskOptions *)options
			     error:(NSError **)error
{
	NTFSVolume *volume = nil;
	NTFSResource *owner = nil;
	FSContainerStatus *previousStatus = nil;
	NTFSCheckTask *check;
	NSProgress *progress;
	dispatch_group_t group;
	struct ntfs_validation_limits limits;
	enum ntfs_result result;
	BOOL quick;

	if (error != NULL) {
		*error = nil;
	}
	if (task == nil) {
		if (error != NULL) {
			*error = ntfs_error(NTFS_INVALID);
		}
		return nil;
	}
	result = check_options(options.taskOptions, &quick);
	@synchronized(self) {
		/* Completing a repeated FSTask would terminate its existing operation. */
		if (_maintenanceTask == task) {
			if (error != NULL) {
				*error = ntfs_error(NTFS_BUSY);
			}
			return nil;
		}
		if (result == NTFS_OK) {
			if (_phase != NTFSFileSystemIdle) {
				result = NTFS_BUSY;
			} else if (_volume.nativeImageEditing) {
				result = NTFS_UNSUPPORTED;
			} else if (_volume == nil || _resourceOwner == nil) {
				result = NTFS_STALE;
			} else {
				_phase = NTFSFileSystemChecking;
				_maintenanceTask = task;
				volume = _volume;
				owner = _resourceOwner;
				previousStatus = self.containerStatus;
			}
		}
	}
	if (result != NTFS_OK) {
		return [self completeRejectedTask:task error:ntfs_error(result)];
	}
	result = [volume beginMaintenance];
	limits = [self validationLimits];
	check = result == NTFS_OK
	    ? [[NTFSCheckTask alloc] initWithResource:owner
						quick:quick
					    admission:^{
					      return [volume maintenanceAdmissionResult];
					    }
					       limits:&limits]
	    : nil;
	if (result == NTFS_OK && check == nil) {
		result = NTFS_NO_MEMORY;
		[volume endMaintenanceWithResult:result completeCheck:NO cancelled:YES];
	}
	if (result != NTFS_OK) {
		@synchronized(self) {
			_phase = NTFSFileSystemIdle;
			_maintenanceTask = nil;
		}
		return [self completeRejectedTask:task error:ntfs_error(result)];
	}
	group = dispatch_group_create();
	dispatch_group_enter(group);
	progress = [NSProgress progressWithTotalUnitCount:NTFS_CHECK_PROGRESS_UNITS];
	progress.cancellable = YES;
	progress.cancellationHandler = ^{
	  [check cancel];
	};
	task.cancellationHandler = ^NSError * {
	  [check cancel];
	  if (dispatch_group_wait(group,
		  dispatch_time(DISPATCH_TIME_NOW,
		      (int64_t)NTFS_CHECK_CANCEL_DRAIN_SECONDS * NSEC_PER_SEC)) != 0) {
		  /* FSKit escalates this to container termination. Borrowed resource
		   * storage stays owned until the outstanding exact read returns. */
		  return [NSError errorWithDomain:NSPOSIXErrorDomain code:ETIMEDOUT userInfo:nil];
	  }
	  return nil;
	};
	@synchronized(self) {
		_check = check;
		self.containerStatus = [FSContainerStatus notReadyWithStatus:ntfs_error(NTFS_BUSY)];
	}
	dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
	  @autoreleasepool {
		  struct ntfs_validation_report report = {0};
		  enum ntfs_result checked;
		  NSError *failure;

		  /* The retained mounted core and this private diagnostic share one
		   * resource pool. Serialize both run and terminal admission against
		   * native teardown before releasing any owning diagnostic storage. */
		  @synchronized(volume) {
			  checked = [check run];
			  failure = [check sealResult:checked];
			  [volume endMaintenanceWithResult:check.result
					     completeCheck:!quick
						 cancelled:check.cancelled];
		  }
		  if (volume.maintenanceOnly) {
			  [volume invalidate];
		  }
		  progress.cancellationHandler = nil;
		  task.cancellationHandler = nil;
		  progress.completedUnitCount = NTFS_CHECK_PROGRESS_UNITS;
		  @synchronized(self) {
			  if (self->_check == check) {
				  self->_check = nil;
				  self->_phase = NTFSFileSystemIdle;
				  if (volume.maintenanceOnly) {
					  self->_volume = nil;
					  self->_resource = nil;
					  self->_resourceOwner = nil;
					  self.containerStatus =
					      [FSContainerStatus notReadyWithStatus:failure != nil
						      ? failure
						      : ntfs_error(NTFS_STALE)];
				  } else if (check.cancelled || (quick && failure == nil)) {
					  self.containerStatus = previousStatus;
				  } else {
					  self.containerStatus = failure == nil
					      ? FSContainerStatus.ready
					      : [FSContainerStatus blockedWithStatus:failure];
				  }
			  }
		  }
		  /* The drain group covers resource ownership and controller cleanup.
		   * Release it before calling foreign task code so callback reentry
		   * cannot wait on its own completion. Replies remain exactly once. */
		  dispatch_group_leave(group);
		  (void)[check validationReport:&report];
		  [task logMessage:
			  [NSString stringWithFormat:@"NTFS read-only %@: %s; complete=%u stage=%u "
						     @"records=%llu reads=%llu bytes=%llu",
			      quick ? @"mount check" : @"metadata check",
			      ntfs_result_string(check.result), (unsigned)report.complete,
			      (unsigned)report.stage, (unsigned long long)report.records_scanned,
			      (unsigned long long)report.read_calls,
			      (unsigned long long)report.read_bytes]];
		  [task logMessage:quick
			  ? @"Mount eligibility only; no complete metadata inventory."
			  : @"Supported metadata inventory only; no repair, journal replay, or "
			    @"authorization."];
		  [task didCompleteWithError:failure];
		  @synchronized(self) {
			  if (self->_maintenanceTask == task) {
				  self->_maintenanceTask = nil;
			  }
		  }
	  }
	});
	return progress;
}

- (NSProgress *)startFormatWithTask:(FSTask *)task
			    options:(FSTaskOptions *)options
			      error:(NSError **)error
{
	(void)options;
	if (error != NULL) {
		*error = nil;
	}
	if (task == nil) {
		if (error != NULL) {
			*error = ntfs_error(NTFS_INVALID);
		}
		return nil;
	}
	@synchronized(self) {
		if (_maintenanceTask == task) {
			if (error != NULL) {
				*error = ntfs_error(NTFS_BUSY);
			}
			return nil;
		}
	}
	return [self completeRejectedTask:task error:ntfs_error(NTFS_READ_ONLY)];
}

@end
