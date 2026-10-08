/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSVolumeInternal.h"
#include "../../core/write_owner.h"
#include <errno.h>
#include <limits.h>
#include <os/log.h>
#include <unistd.h>

static enum ntfs_result
native_access_selection(NSArray<NSString *> *arguments, NTFSNativeAccessMode current, BOOL editing,
    NTFSNativeAccessMode *selected)
{
	NTFSNativeAccessMode requested;
	enum ntfs_result result;

	*selected = current;
	result = ntfs_native_access_mode(arguments, &requested);
	if (result != NTFS_OK) {
		return result;
	}
	if (requested == NTFSNativeAccessImageEditing && !editing) {
		return NTFS_UNSUPPORTED;
	}
	if (current != NTFSNativeAccessUnselected && requested != NTFSNativeAccessUnselected &&
	    requested != current) {
		return NTFS_INVALID;
	}
	if (editing) {
		result = ntfs_native_image_options(arguments);
		if (result != NTFS_OK) {
			return result;
		}
	}
	if (requested != NTFSNativeAccessUnselected) {
		*selected = requested;
	}
	return NTFS_OK;
}

@implementation NTFSVolume

- (instancetype)initWithCore:(struct ntfs_volume *)core resource:(NTFSResource *)resource
{
	return [self initWithCore:core
			   resource:resource
	    maximumDirectoryEntries:NTFS_FSKIT_DIRECTORY_ENTRY_LIMIT];
}

- (instancetype)initWithCore:(struct ntfs_volume *)core
		    resource:(NTFSResource *)resource
     maximumDirectoryEntries:(uint32_t)maximum
{
	return [self initWithCore:core
			   resource:resource
	    maximumDirectoryEntries:maximum
			 linkPolicy:nil];
}

- (instancetype)initWithCore:(struct ntfs_volume *)core
		    resource:(NTFSResource *)resource
     maximumDirectoryEntries:(uint32_t)maximum
		  linkPolicy:(NTFSLinkPolicy *)policy
{
	return [self initWithCore:core
			   resource:resource
	    maximumDirectoryEntries:maximum
			 linkPolicy:policy
			 accessMode:NTFSNativeAccessUnselected];
}

- (instancetype)initWithCore:(struct ntfs_volume *)core
		    resource:(NTFSResource *)resource
     maximumDirectoryEntries:(uint32_t)maximum
		  linkPolicy:(NTFSLinkPolicy *)policy
		  accessMode:(NTFSNativeAccessMode)mode
{
	struct ntfs_info info;
	struct ntfs_operation operation = {0};
	struct ntfs_resource_read_budget budget = {0};
	struct ntfs_operation_limits limits;
	uint64_t freeClusters;
	NSString *label;
	enum ntfs_result result;

	if ((mode != NTFSNativeAccessUnselected && mode != NTFSNativeAccessExtraction) ||
	    core == NULL || resource == nil || maximum == 0 ||
	    maximum > NTFS_FSKIT_DIRECTORY_ENTRY_LIMIT) {
		return nil;
	}
	ntfs_get_info(core, &info);
	if (policy == nil) {
		policy = [[NTFSLinkPolicy alloc] initWithVolumeSerial:info.serial windowsRoots:nil];
	}
	if (policy == nil || policy.volumeSerial != info.serial) {
		return nil;
	}
	ntfs_get_operation_limits(core, &limits);
	result = ntfs_operation_begin(core, &limits, &operation);
	if (result != NTFS_OK) {
		return nil;
	}
	result = [resource beginReadBudget:&budget limits:&limits];
	if (result != NTFS_OK) {
		(void)ntfs_operation_end(&operation, NULL);
		return nil;
	}
	@try {
		result = ntfs_count_free_clusters(core, &freeClusters);
		if (result == NTFS_OK) {
			result = [resource readBudgetResult];
		}
	} @finally {
		(void)[resource endReadBudget:&budget];
		(void)ntfs_operation_end(&operation, NULL);
	}
	if (result != NTFS_OK) {
		return nil;
	}
	label = [NSString stringWithUTF8String:info.label];
	self = [super
	    initWithVolumeID:[[FSVolumeIdentifier alloc] initWithUUID:ntfs_uuid(info.serial)]
		  volumeName:[FSFileName nameWithString:label.length != 0 ? label : @"NTFS"]];
	if (self != nil) {
		_lifecycleLock = [[NSLock alloc] init];
		_publicationLock = [[NSRecursiveLock alloc] init];
		_readCachePolicy = [self newReadCachePolicy];
		_lifecycle = NTFSVolumeLoaded;
		_core = core;
		_info = info;
		_resource = resource;
		_freeClusters = freeClusters;
		_maximumDirectoryEntries = maximum;
		_items = [NSMapTable strongToWeakObjectsMapTable];
		_paths = [NSMapTable strongToWeakObjectsMapTable];
		_linkPolicy = policy;
		_nativeAccessMode = mode;
		_nativeUserID = geteuid();
		_nativeGroupID = getegid();
		_directoryVerifier =
		    ((uint64_t)arc4random() << (sizeof(uint32_t) * CHAR_BIT)) | arc4random() | 1;
	}
	return self;
}

- (instancetype)initForCheckWithResource:(NTFSResource *)resource mountError:(enum ntfs_result)error
{
	if (resource == nil || error == NTFS_OK) {
		return nil;
	}
	self = [super initWithVolumeID:[[FSVolumeIdentifier alloc] initWithUUID:NSUUID.UUID]
			    volumeName:[FSFileName nameWithString:@"NTFS check"]];
	if (self != nil) {
		_lifecycleLock = [[NSLock alloc] init];
		_publicationLock = [[NSRecursiveLock alloc] init];
		_readCachePolicy = [self newReadCachePolicy];
		_lifecycle = NTFSVolumeLoaded;
		_resource = resource;
		_items = [NSMapTable strongToWeakObjectsMapTable];
		_paths = [NSMapTable strongToWeakObjectsMapTable];
		_maximumDirectoryEntries = NTFS_FSKIT_DIRECTORY_ENTRY_LIMIT;
		_maintenanceOnly = YES;
		_mountError = error;
	}
	return self;
}

- (BOOL)maintenanceOnly
{
	return _maintenanceOnly;
}

- (enum ntfs_result)beginMaintenance
{
	enum ntfs_result result = NTFS_BUSY;
	NTFSVolumeLifecycle state = self.lifecycle;

	if (state == NTFSVolumeInvalidating || state == NTFSVolumeInvalidated) {
		return NTFS_STALE;
	}
	if ((state != NTFSVolumeLoaded && state != NTFSVolumeUnmounted) ||
	    ![_publicationLock tryLock]) {
		/* A checker must not wait behind an active read or item publication
		 * before its task cancellation handler can even be installed. */
		return NTFS_BUSY;
	}
	@try {
		@synchronized(self) {
			state = self.lifecycle;
			if (state == NTFSVolumeInvalidating || state == NTFSVolumeInvalidated) {
				result = NTFS_STALE;
			} else if ((state == NTFSVolumeLoaded || state == NTFSVolumeUnmounted) &&
			    self->_items.objectEnumerator.allObjects.count == 0) {
				if (!self->_resource.isAvailable) {
					result = NTFS_IO;
				} else {
					[self->_lifecycleLock lock];
					if (self->_lifecycle == state &&
					    self->_pendingUnmounts == 0) {
						self->_beforeMaintenance = state;
						self->_lifecycle = NTFSVolumeChecking;
						result = NTFS_OK;
					}
					[self->_lifecycleLock unlock];
				}
			}
		}
	} @finally {
		[_publicationLock unlock];
	}
	return result;
}

- (enum ntfs_result)maintenanceAdmissionResult
{
	return self.lifecycle != NTFSVolumeChecking ? NTFS_STALE
	    : _resource.isAvailable		    ? NTFS_OK
						    : NTFS_IO;
}

- (void)endMaintenanceWithResult:(enum ntfs_result)result
		   completeCheck:(BOOL)complete
		       cancelled:(BOOL)cancelled
{
	@synchronized(self) {
		[_lifecycleLock lock];
		if (_lifecycle == NTFSVolumeChecking) {
			_lifecycle = _beforeMaintenance;
			/* A quick mount check or interrupted inventory cannot clear a
			 * previously observed whole-diagnostic failure. */
			if (!cancelled && (complete || result != NTFS_OK)) {
				_checkFailure = result;
			}
		}
		[_lifecycleLock unlock];
	}
}

- (struct ntfs_operation_limits)operationLimits
{
	struct ntfs_operation_limits limits;

	ntfs_get_operation_limits(_core, &limits);
	return limits;
}

- (enum ntfs_result)beginOperation:(struct ntfs_operation *)operation
			readBudget:(struct ntfs_resource_read_budget *)budget
		  retainedResource:(NTFSResource *__strong *)resource
			activating:(BOOL)activating
{
	struct ntfs_operation_limits limits;
	enum ntfs_result result;
	NTFSVolumeLifecycle state;

	*resource = nil;
	result = [self ensureImageView];
	if (result != NTFS_OK) {
		return result;
	}
	if (activating) {
		state = self.lifecycle;
		result = state != NTFSVolumeLoaded && state != NTFSVolumeActive ? NTFS_STALE
		    : _maintenanceOnly						? _mountError
		    : _checkFailure != NTFS_OK					? _checkFailure
		    : _core == NULL						? NTFS_STALE
		    : _resource.isAvailable					? NTFS_OK
										: NTFS_IO;
	} else {
		result = [self admissionResult];
	}
	if (result != NTFS_OK) {
		return result;
	}
	limits = [self operationLimits];
	result = ntfs_operation_begin(_core, &limits, operation);
	if (result != NTFS_OK) {
		return result;
	}
	*resource = _resource;
	result = [(*resource) beginReadBudget:budget limits:&limits];
	if (result != NTFS_OK) {
		(void)ntfs_operation_end(operation, NULL);
		*resource = nil;
	} else {
		_readOperations++;
	}
	return result;
}

- (void)endReadOperation:(struct ntfs_operation *)operation
{
	NSAssert(_readOperations != 0, @"NTFS native operation accounting");
	(void)ntfs_operation_end(operation, NULL);
	_readOperations--;
}

- (FSItem *)lookup:(FSFileName *)name
       inDirectory:(FSItem *)directory
	storedName:(FSFileName **)stored
	     error:(NSError **)error
{
	@synchronized(self) {
		struct ntfs_operation operation = {0};
		struct ntfs_resource_read_budget budget = {0};
		__attribute__((objc_precise_lifetime)) NTFSResource *resource = nil;
		enum ntfs_result status;
		FSItem *value;

		*error = nil;
		*stored = nil;
		status = [self beginOperation:&operation
				   readBudget:&budget
			     retainedResource:&resource
				   activating:NO];
		if (status != NTFS_OK) {
			*error = ntfs_error(status);
			return nil;
		}
		@try {
			value = [self performLookup:name
					inDirectory:directory
					 storedName:stored
					      error:error];
			if (*error == nil) {
				status = ntfs_operation_result(&operation);
				if (status == NTFS_OK) {
					status = [resource readBudgetResult];
				}
				if (status != NTFS_OK) {
					value = nil;
					*error = ntfs_error(status);
					*stored = nil;
				}
			}
			return value;
		} @finally {
			(void)[resource endReadBudget:&budget];
			[self endReadOperation:&operation];
		}
	}
}

- (FSItemAttributes *)attributes:(FSItem *)item error:(NSError **)error
{
	@synchronized(self) {
		struct ntfs_operation operation = {0};
		struct ntfs_resource_read_budget budget = {0};
		__attribute__((objc_precise_lifetime)) NTFSResource *resource = nil;
		enum ntfs_result status;
		FSItemAttributes *value;

		*error = nil;

		status = [self beginOperation:&operation
				   readBudget:&budget
			     retainedResource:&resource
				   activating:NO];
		if (status != NTFS_OK) {
			*error = ntfs_error(status);
			return nil;
		}
		@try {
			value = [self performAttributes:item error:error];
			if (*error == nil) {
				status = ntfs_operation_result(&operation);
				if (status == NTFS_OK) {
					status = [resource readBudgetResult];
				}
				if (status != NTFS_OK) {
					value = nil;
					*error = ntfs_error(status);
				}
			}
			return value;
		} @finally {
			(void)[resource endReadBudget:&budget];
			[self endReadOperation:&operation];
		}
	}
}

- (FSFileName *)symbolicLink:(FSItem *)item error:(NSError **)error
{
	@synchronized(self) {
		struct ntfs_operation operation = {0};
		struct ntfs_resource_read_budget budget = {0};
		__attribute__((objc_precise_lifetime)) NTFSResource *resource = nil;
		enum ntfs_result status;
		FSFileName *value;

		*error = nil;

		status = [self beginOperation:&operation
				   readBudget:&budget
			     retainedResource:&resource
				   activating:NO];
		if (status != NTFS_OK) {
			*error = ntfs_error(status);
			return nil;
		}
		@try {
			value = [self performSymbolicLink:item error:error];
			if (*error == nil) {
				status = ntfs_operation_result(&operation);
				if (status == NTFS_OK) {
					status = [resource readBudgetResult];
				}
				if (status != NTFS_OK) {
					value = nil;
					*error = ntfs_error(status);
				}
			}
			return value;
		} @finally {
			(void)[resource endReadBudget:&budget];
			[self endReadOperation:&operation];
		}
	}
}

- (NSArray<FSFileName *> *)xattrsForItem:(FSItem *)item error:(NSError **)error
{
	@synchronized(self) {
		struct ntfs_operation operation = {0};
		struct ntfs_resource_read_budget budget = {0};
		__attribute__((objc_precise_lifetime)) NTFSResource *resource = nil;
		enum ntfs_result status;
		NSArray<FSFileName *> *value;

		*error = nil;

		status = [self beginOperation:&operation
				   readBudget:&budget
			     retainedResource:&resource
				   activating:NO];
		if (status != NTFS_OK) {
			*error = ntfs_error(status);
			return nil;
		}
		@try {
			value = [self performXattrsForItem:item error:error];
			if (*error == nil) {
				status = ntfs_operation_result(&operation);
				if (status == NTFS_OK) {
					status = [resource readBudgetResult];
				}
				if (status != NTFS_OK) {
					value = nil;
					*error = ntfs_error(status);
				}
			}
			return value;
		} @finally {
			(void)[resource endReadBudget:&budget];
			[self endReadOperation:&operation];
		}
	}
}

- (NSData *)xattrNamed:(FSFileName *)name ofItem:(FSItem *)item error:(NSError **)error
{
	@synchronized(self) {
		struct ntfs_operation operation = {0};
		struct ntfs_resource_read_budget budget = {0};
		__attribute__((objc_precise_lifetime)) NTFSResource *resource = nil;
		enum ntfs_result status;
		NSData *value;

		*error = nil;

		status = [self beginOperation:&operation
				   readBudget:&budget
			     retainedResource:&resource
				   activating:NO];
		if (status != NTFS_OK) {
			*error = ntfs_error(status);
			return nil;
		}
		@try {
			value = [self performXattrNamed:name ofItem:item error:error];
			if (*error == nil) {
				status = ntfs_operation_result(&operation);
				if (status == NTFS_OK) {
					status = [resource readBudgetResult];
				}
				if (status != NTFS_OK) {
					value = nil;
					*error = ntfs_error(status);
				}
			}
			return value;
		} @finally {
			(void)[resource endReadBudget:&budget];
			[self endReadOperation:&operation];
		}
	}
}

- (NSError *)enumerate:(FSItem *)directory
		cookie:(FSDirectoryCookie)cookie
	      verifier:(FSDirectoryVerifier)verifier
	    attributes:(BOOL)attributes
		packer:(FSDirectoryEntryPacker *)packer
{
	@synchronized(self) {
		struct ntfs_operation operation = {0};
		struct ntfs_resource_read_budget budget = {0};
		__attribute__((objc_precise_lifetime)) NTFSResource *resource = nil;
		enum ntfs_result status;
		NSError *value;

		status = [self beginOperation:&operation
				   readBudget:&budget
			     retainedResource:&resource
				   activating:NO];
		if (status != NTFS_OK) {
			return ntfs_error(status);
		}
		@try {
			value = [self performEnumeration:directory
						  cookie:cookie
						verifier:verifier
					      attributes:attributes
						  packer:packer];
			if (value == nil) {
				status = ntfs_operation_result(&operation);
				if (status == NTFS_OK) {
					status = [resource readBudgetResult];
				}
				if (status != NTFS_OK) {
					value = ntfs_error(status);
				}
			}
			return value;
		} @finally {
			(void)[resource endReadBudget:&budget];
			[self endReadOperation:&operation];
		}
	}
}

- (enum ntfs_result)readItem:(FSItem *)item
		      offset:(off_t)offset
		       bytes:(void *)bytes
		      length:(size_t)length
		   completed:(size_t *)completed
{
	@synchronized(self) {
		struct ntfs_operation operation = {0};
		struct ntfs_resource_read_budget budget = {0};
		__attribute__((objc_precise_lifetime)) NTFSResource *resource = nil;
		enum ntfs_result status;
		enum ntfs_result value;

		if (completed == NULL) {
			return NTFS_INVALID;
		}
		*completed = 0;
		status = [self beginOperation:&operation
				   readBudget:&budget
			     retainedResource:&resource
				   activating:NO];
		if (status != NTFS_OK) {
			return status;
		}
		@try {
			value = [self performReadItem:item
					       offset:offset
						bytes:bytes
					       length:length
					    completed:completed];
			if (value == NTFS_OK) {
				status = ntfs_operation_result(&operation);
				if (status == NTFS_OK) {
					status = [resource readBudgetResult];
				}
				if (status != NTFS_OK) {
					value = status;
					*completed = 0;
				}
			}
			return value;
		} @finally {
			(void)[resource endReadBudget:&budget];
			[self endReadOperation:&operation];
		}
	}
}

- (FSItem *)activateWithOptions:(FSTaskOptions *)options error:(NSError **)error
{
	return [self activateWithArguments:options.taskOptions error:error];
}

- (FSItem *)activateWithArguments:(NSArray<NSString *> *)arguments error:(NSError **)error
{
	if (self.lifecycle == NTFSVolumeChecking) {
		*error = ntfs_error(NTFS_BUSY);
		return nil;
	}
	@synchronized(self) {
		struct ntfs_operation operation = {0};
		struct ntfs_resource_read_budget budget = {0};
		__attribute__((objc_precise_lifetime)) NTFSResource *resource = nil;
		enum ntfs_result status;
		FSItem *value;
		NTFSNativeAccessMode selected;
		NTFSVolumeLifecycle state;

		*error = nil;
		state = self.lifecycle;
		if (_nativeImageEditing &&
		    (state == NTFSVolumeLoaded || state == NTFSVolumeActive)) {
			status =
			    native_access_selection(arguments, _nativeAccessMode, YES, &selected);
			if (status != NTFS_OK) {
				*error = ntfs_error(status);
				return nil;
			}
		}

		status = [self beginOperation:&operation
				   readBudget:&budget
			     retainedResource:&resource
				   activating:YES];
		if (status != NTFS_OK) {
			*error = ntfs_error(status);
			return nil;
		}
		@try {
			value = [self performActivation:arguments error:error];
			if (*error == nil) {
				status = ntfs_operation_result(&operation);
				if (status == NTFS_OK) {
					status = [resource readBudgetResult];
				}
				if (status != NTFS_OK) {
					value = nil;
					*error = ntfs_error(status);
				}
			}
			return value;
		} @finally {
			(void)[resource endReadBudget:&budget];
			[self endReadOperation:&operation];
		}
	}
}

- (void)dealloc
{
	[self invalidate];
}

- (NTFSReadCachePolicy *)newReadCachePolicy
{
	return [[NTFSReadCachePolicy alloc] init];
}

- (NTFSReadCachePolicy *)readCachePolicy
{
	return _readCachePolicy;
}

- (void)performItemPublication:(void (^)(void))publication
{
	[_publicationLock lock];
	@try {
		publication();
	} @finally {
		[_publicationLock unlock];
	}
}

- (BOOL)reclaimIfEligible:(FSItem *)item cleanup:(void (^)(void))cleanup
{
	if ([item isKindOfClass:NTFSItem.class] && ((NTFSItem *)item)->nativeOpenModes != 0) {
		return NO;
	}
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
	if (@available(macOS 27.0, *)) {
		return [item tryReclaimWithBlock:cleanup];
	}
#endif
	(void)item;
	(void)cleanup;
	return NO;
}

- (void)invalidate
{
	enum ntfs_result result;
	NTFSItem *item;

	/* Never hold this lock while waiting for the core's operation monitor. */
	[_lifecycleLock lock];
	if (_lifecycle != NTFSVolumeInvalidated) {
		_lifecycle = NTFSVolumeInvalidating;
	}
	[_lifecycleLock unlock];
	/* Reentry already owns this monitor. Do not wait for publication while a
	 * deferred teardown on another thread may be waiting for this same call. */
	@synchronized(self) {
		if (_imageMutationActive || _imageViewOpening) {
			return;
		}
	}
	/* This method also runs from dealloc; do not capture the owner in a block. */
	[_publicationLock lock];
	@try {
		@synchronized(self) {
			if (_imageMutationActive || _imageViewOpening) {
				/* A native transfer or unpublished mount can reenter the owner.
				 * Admission is closed; release ownership after that call returns. */
				return;
			}
			[_readCachePolicy stop];
			for (item in _items.objectEnumerator.allObjects) {
				[self releaseItem:item];
			}
			[_items removeAllObjects];
			[_paths removeAllObjects];
			if (_core != NULL) {
				result = ntfs_unmount(_core);
				NSAssert(result == NTFS_OK, @"NTFS object leak");
				if (result == NTFS_OK) {
					_core = NULL;
				}
			}
			_active = NO;
			if (_core == NULL) {
				_resource = nil;
				ntfs_overwrite_close(_writeOwner);
				_writeOwner = NULL;
				_imageTransport = nil;
				_imageViewPending = NO;
				[_lifecycleLock lock];
				_lifecycle = NTFSVolumeInvalidated;
				[_lifecycleLock unlock];
			}
		}
	} @finally {
		[_publicationLock unlock];
	}
}

- (void)invalidateWithReplyHandler:(void (^)(void))reply
{
	BOOL deferred;

	[self invalidate];
	@synchronized(self) {
		deferred = _imageMutationActive || _imageViewOpening;
	}
	if (deferred) {
		/* Reentrant native deactivation cannot wait on its own C call. The
		 * other execution context waits for publication and completes teardown
		 * before allowing FSKit to acknowledge that the volume is inactive. */
		dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
		  [self invalidateWithReplyHandler:reply];
		});
	} else {
		reply();
	}
}

- (NTFSVolumeLifecycle)lifecycle
{
	NTFSVolumeLifecycle state;

	[_lifecycleLock lock];
	state = _lifecycle;
	[_lifecycleLock unlock];
	return state;
}

- (enum ntfs_result)admissionResult
{
	if (_core == NULL || !_active || self.lifecycle != NTFSVolumeActive) {
		return NTFS_STALE;
	}
	return _resource.isAvailable ? [self operationBudgetResult] : NTFS_IO;
}

- (enum ntfs_result)operationBudgetResult
{
	enum ntfs_result result;

	result = ntfs_operation_check(_core);
	return result == NTFS_OK ? [_resource readBudgetResult] : result;
}

- (FSItem *)activateExtraction:(NSError **)error
{
	return [self activateWithArguments:@[ NTFSExtractionAccessOption ] error:error];
}

- (FSItem *)performActivation:(NSArray<NSString *> *)arguments error:(NSError **)error
{
	struct ntfs_node *root = NULL;
	struct ntfs_info info;
	enum ntfs_result result;
	NTFSItem *item;
	NTFSLinkPolicy *policy;
	NTFSVolumeLifecycle state;
	NTFSNativeAccessMode requested;

	*error = nil;
	@synchronized(self) {
		state = self.lifecycle;
		if (_core == NULL || (state != NTFSVolumeLoaded && state != NTFSVolumeActive)) {
			*error = ntfs_error(NTFS_STALE);
			return nil;
		}
		if (!_resource.isAvailable) {
			*error = ntfs_error(NTFS_IO);
			return nil;
		}
		result = native_access_selection(
		    arguments, _nativeAccessMode, _nativeImageEditing, &requested);
		if (result != NTFS_OK) {
			*error = ntfs_error(result);
			return nil;
		}
		if (requested == NTFSNativeAccessUnselected) {
			*error = [NSError
			    errorWithDomain:NSPOSIXErrorDomain
				       code:EACCES
				   userInfo:@{
					   NSLocalizedDescriptionKey :
					       @"Select read-only extraction access explicitly. "
					       @"Windows permissions are not enforced."
				   }];
			return nil;
		}
		ntfs_get_info(_core, &info);
		result = ntfs_native_link_policy(info.serial, arguments, &policy);
		if (result == NTFS_OK && policy.windowsRoots.count != 0) {
			if (state == NTFSVolumeLoaded && _linkPolicy.windowsRoots.count == 0) {
				_linkPolicy = policy;
			} else if (![[NSSet setWithArray:policy.windowsRoots]
				       isEqualToSet:[NSSet
							setWithArray:_linkPolicy.windowsRoots]]) {
				result = NTFS_INVALID;
			}
		}
		if (result != NTFS_OK) {
			*error = ntfs_error(result);
			return nil;
		}
		result = ntfs_root(_core, &root);
		if (result != NTFS_OK) {
			*error = ntfs_error(result);
			return nil;
		}
		item = [self adoptNode:root parentReference:0 containingPath:nil error:error];
		if (item != nil) {
			[_lifecycleLock lock];
			if (_lifecycle == NTFSVolumeLoaded || _lifecycle == NTFSVolumeActive) {
				if (_nativeAccessMode == NTFSNativeAccessUnselected) {
					_nativeAccessMode = requested;
				}
				_active = YES;
				_lifecycle = NTFSVolumeActive;
			} else {
				item = nil;
				*error = ntfs_error(NTFS_STALE);
			}
			[_lifecycleLock unlock];
			if (item != nil) {
				[_readCachePolicy start];
			}
		}
		return item;
	}
}

- (FSDirectoryVerifier)directoryVerifier
{
	return _directoryVerifier;
}

- (void)reclaimItem:(FSItem *)item replyHandler:(void (^)(NSError *))reply
{
	__block NSError *error = nil;

	[self performItemPublication:^{
	  NTFSItem *value;

	  @synchronized(self) {
		  if (self->_imageTransport != nil && [item isKindOfClass:NTFSItem.class] &&
		      ((NTFSItem *)item).owner == self) {
			  /* Reclaim must release an identity even when a replacement read
			   * view cannot allocate. It need not reopen a core node first. */
			  value = (NTFSItem *)item;
		  } else {
			  value = [self checkedItem:item];
		  }
		  if (value == nil) {
			  error = ntfs_error(self->_itemAdmission);
		  } else {
			  [self reclaimIfEligible:value
					  cleanup:^{
					    [self->_items
						removeObjectForKey:@(value->stat.reference)];
					    [self releaseItem:value];
					  }];
		  }
	  }
	}];
	reply(error);
}

- (void)mountWithOptions:(FSTaskOptions *)options replyHandler:(void (^)(NSError *))reply
{
	NSError *error;
	enum ntfs_result result;
	NTFSVolumeLifecycle state;
	NTFSNativeAccessMode requested;

	if (self.lifecycle == NTFSVolumeChecking) {
		reply(ntfs_error(NTFS_BUSY));
		return;
	}
	@synchronized(self) {
		state = self.lifecycle;
		result = NTFS_OK;
		if (_nativeImageEditing &&
		    (state == NTFSVolumeActive || state == NTFSVolumeUnmounted)) {
			result = native_access_selection(
			    options.taskOptions, _nativeAccessMode, YES, &requested);
		}
		if (result == NTFS_OK) {
			result = [self ensureImageView];
		}
		if (result == NTFS_OK) {
			result = state == NTFSVolumeInvalidating ||
				state == NTFSVolumeInvalidated || state == NTFSVolumeDraining ||
				state == NTFSVolumeChecking
			    ? NTFS_STALE
			    : _maintenanceOnly	       ? _mountError
			    : _checkFailure != NTFS_OK ? _checkFailure
			    : _core == NULL || !_active ||
				(state != NTFSVolumeActive && state != NTFSVolumeUnmounted)
			    ? NTFS_STALE
			    : NTFS_OK;
		}
		if (result == NTFS_OK && !_resource.isAvailable) {
			result = NTFS_IO;
		}
		if (result == NTFS_OK) {
			result = native_access_selection(options.taskOptions, _nativeAccessMode,
			    _nativeImageEditing, &requested);
		}
		if (result == NTFS_OK) {
			[_lifecycleLock lock];
			if (_lifecycle == NTFSVolumeActive || _lifecycle == NTFSVolumeUnmounted) {
				_lifecycle = NTFSVolumeActive;
			} else {
				result = NTFS_STALE;
			}
			[_lifecycleLock unlock];
			if (result == NTFS_OK) {
				[_readCachePolicy start];
			}
		}
		error = ntfs_error(result);
	}
	if (_nativeImageEditing) {
		os_log_info(OS_LOG_DEFAULT,
		    "NTFS image mount reply: status=%u state=%lu options=%lu", (unsigned)result,
		    (unsigned long)state, (unsigned long)options.taskOptions.count);
	}
	reply(error);
}

- (void)unmountWithReplyHandler:(void (^)(void))reply
{
	[_lifecycleLock lock];
	_pendingUnmounts++;
	if (_lifecycle != NTFSVolumeInvalidating && _lifecycle != NTFSVolumeInvalidated) {
		_lifecycle = NTFSVolumeDraining;
	}
	[_lifecycleLock unlock];
	[self finishUnmountWithReplyHandler:reply];
}

- (void)finishUnmountWithReplyHandler:(void (^)(void))reply
{
	__block BOOL deferred = NO;

	@synchronized(self) {
		deferred = _imageMutationActive || _imageViewOpening;
	}
	if (!deferred) {
		[self performItemPublication:^{
		  NTFSItem *item;

		  @synchronized(self) {
			  if (self->_imageMutationActive || self->_imageViewOpening) {
				  deferred = YES;
				  return;
			  }
			  [self->_readCachePolicy stop];
			  for (item in self->_items.objectEnumerator.allObjects) {
				  [self clearItemCaches:item];
			  }
			  [self->_lifecycleLock lock];
			  self->_pendingUnmounts--;
			  if (self->_pendingUnmounts == 0 && self->_lifecycle == NTFSVolumeDraining) {
				  self->_lifecycle = NTFSVolumeUnmounted;
			  }
			  [self->_lifecycleLock unlock];
		  }
		}];
	}
	if (deferred) {
		/* Reentrant unmount cannot wait on its own acquisition or mutation. A different
		 * execution context drains publication before completing the reply. */
		dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
		  [self finishUnmountWithReplyHandler:reply];
		});
	} else {
		reply();
	}
}

- (void)synchronizeWithFlags:(FSSyncFlags)flags replyHandler:(void (^)(NSError *))reply
{
	NSError *error;
	struct ntfs_overwrite_environment environment;
	enum ntfs_result result;

	(void)flags;
	@synchronized(self) {
		if (_imageTransport == nil) {
			result = [self admissionResult];
		} else if (self.lifecycle != NTFSVolumeActive || !_active) {
			result = NTFS_STALE;
		} else {
			/* The writer already persisted its complete transaction. A later
			 * native sync still reaches the real barrier, without allocating a
			 * replacement view or requiring its metadata to be readable. */
			environment = [_imageTransport overwriteEnvironment];
			result = environment.persist(environment.reader.context);
			if (result != NTFS_OK) {
				[_imageTransport invalidate];
			}
		}
		error = ntfs_error(result);
	}
	reply(error);
}

- (FSMountOptions)requestedMountOptions
{
#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0
	if (@available(macOS 27.0, *)) {
		if (_nativeImageEditing) {
			return 0;
		}
	}
#endif
	return FSMountOptionsReadOnly;
}

- (NTFSNativeAccessMode)nativeAccessMode
{
	@synchronized(self) {
		return _nativeAccessMode;
	}
}

- (uid_t)nativeUserID
{
	return _nativeUserID;
}

- (gid_t)nativeGroupID
{
	return _nativeGroupID;
}

- (FSVolumeSupportedCapabilities *)supportedVolumeCapabilities
{
	FSVolumeSupportedCapabilities *caps = [[FSVolumeSupportedCapabilities alloc] init];

	if (_maintenanceOnly) {
		return caps;
	}
	caps.supportsPersistentObjectIDs = YES;
	caps.supportsSymbolicLinks = YES;
	caps.supports64BitObjectIDs = YES;
	caps.supportsSparseFiles = YES;
	caps.supportsZeroRuns = YES;
	caps.supportsFastStatFS = YES;
	caps.supports2TBFiles = YES;
	caps.doesNotSupportSettingFilePermissions = YES;
	/* The SDK exposes only a volume-wide format. Preserve distinct native
	 * cache keys for sensitive directories; insensitive lookup still returns
	 * the canonical stored spelling through the directory's core policy. */
	caps.caseFormat = FSVolumeCaseFormatSensitive;
	return caps;
}

- (FSStatFSResult *)volumeStatistics
{
	FSStatFSResult *s = [[FSStatFSResult alloc] initWithFileSystemTypeName:@"machlinntfs"];

	if (_maintenanceOnly) {
		/* Required native statistics have a valid accounting unit without
		 * inventing filesystem geometry, including after owner retirement. */
		s.blockSize = NTFS_RESOURCE_MIN_ALIGNMENT;
		s.ioSize = NTFS_RESOURCE_MIN_ALIGNMENT;
		s.totalBlocks = 0;
		s.freeBlocks = 0;
		s.availableBlocks = 0;
		s.usedBlocks = 0;
		s.totalBytes = 0;
		s.freeBytes = 0;
		s.availableBytes = 0;
		s.usedBytes = 0;
		s.totalFiles = 0;
		s.freeFiles = 0;
		return s;
	}
	s.blockSize = _info.cluster_size;
	s.ioSize = NTFS_RESOURCE_WINDOW;
	s.totalBlocks = _info.cluster_count;
	s.freeBlocks = _freeClusters;
	s.availableBlocks = _nativeImageEditing ? _freeClusters : 0;
	s.usedBlocks = s.totalBlocks - s.freeBlocks;
	s.totalBytes = s.totalBlocks * _info.cluster_size;
	s.freeBytes = s.freeBlocks * _info.cluster_size;
	s.usedBytes = s.usedBlocks * _info.cluster_size;
	s.availableBytes = s.availableBlocks * _info.cluster_size;
	return s;
}

- (NSInteger)maximumLinkCount
{
	return UINT16_MAX;
}

- (NSInteger)maximumNameLength
{
	return NTFS_FSKIT_NATIVE_NAME_BYTES;
}

- (BOOL)restrictsOwnershipChanges
{
	return YES;
}

- (BOOL)truncatesLongNames
{
	return NO;
}

- (NSInteger)maximumXattrSize
{
	return NTFS_FSKIT_XATTR_BYTES;
}

- (NSInteger)maximumXattrSizeInBits
{
	return NTFS_FSKIT_XATTR_SIZE_BITS;
}

- (uint64_t)maximumFileSize
{
	return INT64_MAX;
}

- (NSInteger)maximumFileSizeInBits
{
	return sizeof(int64_t) * CHAR_BIT - 1;
}

@end
