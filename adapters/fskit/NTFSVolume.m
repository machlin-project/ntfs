/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSVolume.h"
#import "NTFSNames.h"
#import "NTFSImageVolume.h"
#include "../../core/write_internal.h"
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <string.h>
#include <ntfs/wof.h>

enum {
	NTFS_FSKIT_ITEM_LIMIT = 16384,
	/* Ancestry tokens have their own bound and retain no filesystem items. */
	NTFS_FSKIT_PATH_LIMIT = NTFS_FSKIT_ITEM_LIMIT,
	NTFS_FSKIT_STREAM_LIMIT = 1024,
	NTFS_FSKIT_XATTR_SIZE_BITS = 20,
	NTFS_FSKIT_XATTR_BYTES = (1u << NTFS_FSKIT_XATTR_SIZE_BITS) - 1,
	NTFS_STREAM_MANIFEST_VERSION = 1,
	NTFS_HEX_DIGITS_PER_BYTE = 2,
	NTFS_HEX_NIBBLE_BITS = 4,
	NTFS_HEX_DECIMAL_DIGITS = 10,
	NTFS_STREAM_ALIAS_DIGITS = sizeof(uint32_t) * NTFS_HEX_DIGITS_PER_BYTE,
	NTFS_DIRECTORY_CURRENT_ENTRY = 0,
	NTFS_DIRECTORY_VIRTUAL_ENTRIES = 2,
	/* Two held continuations cover interleaved readers without an unbounded
	 * cookie cache. Each still consumes the resource's aggregate memory budget. */
	NTFS_DIRECTORY_CONTINUATIONS = 2,
	NTFS_READ_ONLY_FILE_MODE = S_IRUSR,
	NTFS_READ_ONLY_DIRECTORY_MODE = S_IRUSR | S_IXUSR
};

static NSString *const streamManifestName = @"org.machlin.ntfs.streams";
static NSString *const streamAliasPrefix = @"org.machlin.ntfs.stream.";
static NSString *const namesManifestName = @"org.machlin.ntfs.names";
static NSString *const nameEntryPrefix = @"org.machlin.ntfs.name.";
static NSString *const reparseAttributeName = @"org.machlin.ntfs.reparse";

/* Keep native view positions separate from stored visible-link ordinals. */
static const FSDirectoryCookie namesOnlyCookieTag = UINT64_C(1)
    << (sizeof(FSDirectoryCookie) * CHAR_BIT - 1);

static NSError *
invalid_directory_cookie(void)
{
	return [NSError errorWithDomain:NSPOSIXErrorDomain
				   code:FSErrorInvalidDirectoryCookie
			       userInfo:nil];
}

static FSDirectoryCookie
directory_cookie(uint64_t position, BOOL attributes)
{
	return attributes ? position
			  : namesOnlyCookieTag | (position + NTFS_DIRECTORY_VIRTUAL_ENTRIES);
}

static BOOL
directory_lookup_name(FSFileName *name, BOOL *parent)
{
	NSData *data = name.data;

	if (data.length == sizeof(".") - 1 && memcmp(data.bytes, ".", sizeof(".") - 1) == 0) {
		*parent = NO;
		return YES;
	}
	if (data.length == sizeof("..") - 1 && memcmp(data.bytes, "..", sizeof("..") - 1) == 0) {
		*parent = YES;
		return YES;
	}
	return NO;
}

/* Native xattrs have a bounded name; the immutable catalog supplies the reverse
 * mapping. These byte-array records preserve original UTF-16 without NSString. */
struct stream_manifest_header {
	uint8_t magic[8], version[4], count[4], reference[8];
};

struct stream_manifest_entry {
	uint8_t index[4], name_length[2], reserved[2];
};

_Static_assert(sizeof(struct stream_manifest_header) == 24, "stream manifest header");
_Static_assert(sizeof(struct stream_manifest_entry) == 8, "stream manifest entry");

static void
store_little(uint8_t *bytes, size_t width, uint64_t value)
{
	size_t i;

	for (i = 0; i < width; i++) {
		bytes[i] = (uint8_t)(value >> (i * CHAR_BIT));
	}
}

static FSFileName *
stream_alias(uint32_t index)
{
	return [FSFileName nameWithString:[NSString stringWithFormat:@"%@%0*x", streamAliasPrefix,
					      NTFS_STREAM_ALIAS_DIGITS, index]];
}

static BOOL
ordinal_xattr_index(FSFileName *name, NSString *aliasPrefix, uint32_t *out)
{
	NSData *prefix = [aliasPrefix dataUsingEncoding:NSASCIIStringEncoding];
	NSData *data = name.data;
	const uint8_t *bytes = data.bytes;
	size_t i;
	uint32_t value = 0, digit;

	*out = 0;
	if (data.length != prefix.length + NTFS_STREAM_ALIAS_DIGITS ||
	    memcmp(bytes, prefix.bytes, prefix.length) != 0) {
		return NO;
	}
	for (i = prefix.length; i < data.length; i++) {
		if (bytes[i] >= '0' && bytes[i] <= '9') {
			digit = bytes[i] - '0';
		} else if (bytes[i] >= 'a' && bytes[i] <= 'f') {
			digit = bytes[i] - 'a' + NTFS_HEX_DECIMAL_DIGITS;
		} else {
			return NO;
		}
		value = (value << NTFS_HEX_NIBBLE_BITS) | digit;
	}
	*out = value;
	return YES;
}

struct ntfs_directory_continuation {
	struct ntfs_directory *cursor;
	struct ntfs_dirent pending_entry;
	uint64_t position;
	uint32_t inspected_entries;
	enum ntfs_result failure;
	BOOL pending, attributes, in_use, complete;
};

static void
close_directory_continuation(struct ntfs_directory_continuation *continuation)
{
	ntfs_directory_close(continuation->cursor);
	memset(continuation, 0, sizeof(*continuation));
}

/* Allocate only for enumerated directories, through the same bounded allocator
 * as the core. An in-flight native call retains this bridge across teardown;
 * clear closes its core children before the mounted owner can be released. */
@interface NTFSDirectoryContinuations : NSObject {
      @public
	struct ntfs_directory_continuation *states;
	NSUInteger mostRecent;
      @private
	NTFSResource *_allocator;
}
- (instancetype)initWithResource:(NTFSResource *)resource;
- (void)clear;
@end

@implementation NTFSDirectoryContinuations

- (instancetype)initWithResource:(NTFSResource *)resource
{
	self = [super init];
	if (self != nil) {
		_allocator = resource;
		states = [resource allocateSize:NTFS_DIRECTORY_CONTINUATIONS * sizeof(*states)];
		if (states == NULL) {
			return nil;
		}
		memset(states, 0, NTFS_DIRECTORY_CONTINUATIONS * sizeof(*states));
	}
	return self;
}

- (void)clear
{
	NSUInteger i;

	if (states != NULL) {
		for (i = 0; i < NTFS_DIRECTORY_CONTINUATIONS; i++) {
			close_directory_continuation(&states[i]);
		}
	}
	mostRecent = 0;
}

- (void)dealloc
{
	[self clear];
	if (states != NULL) {
		[_allocator releaseBytes:states
				    size:NTFS_DIRECTORY_CONTINUATIONS * sizeof(*states)];
	}
}

@end

@interface NTFSItem : FSItem {
      @public
	struct ntfs_node *node;
	struct ntfs_stream *stream;
	struct ntfs_stream_catalog *catalog;
	struct ntfs_reparse *reparse;
	FSFileName *linkTarget;
	BOOL wof;
	NTFSDirectoryPath *directoryPath;
	NTFSDirectoryContinuations *continuations;
	uint64_t continuationEpoch;
	uint32_t activeEnumerations;
	/* Owning native namespace edge, obtained from a checked index lookup.
	 * Files may have many parents; only directories use this reference. */
	uint64_t parentReference;
	struct ntfs_stat stat;
	struct ntfs_link_counts links;
}
@property(strong) NTFSVolume *owner;
@end

@interface NTFSVolume (NTFSItemLifetime)
- (void)releaseUnreferencedItem:(NTFSItem *)item;
@end

@implementation NTFSItem

- (void)dealloc
{
	__attribute__((objc_precise_lifetime)) NTFSVolume *owner = _owner;

	[owner releaseUnreferencedItem:self];
}

@end

static FSItemID
item_id(uint64_t reference)
{
	return (reference & NTFS_REFERENCE_RECORD_MASK) == NTFS_ROOT_RECORD ? FSItemIDRootDirectory
									    : (FSItemID)reference;
}

@interface NTFSVolume (OperationBodies)
- (FSItem *)performLookup:(FSFileName *)name
	      inDirectory:(FSItem *)directory
	       storedName:(FSFileName **)stored
		    error:(NSError **)error;
- (FSItemAttributes *)performAttributes:(FSItem *)item error:(NSError **)error;
- (FSFileName *)performSymbolicLink:(FSItem *)item error:(NSError **)error;
- (NSArray<FSFileName *> *)performXattrsForItem:(FSItem *)item error:(NSError **)error;
- (NSData *)performXattrNamed:(FSFileName *)name ofItem:(FSItem *)item error:(NSError **)error;
- (NSError *)performEnumeration:(FSItem *)directory
			 cookie:(FSDirectoryCookie)cookie
		       verifier:(FSDirectoryVerifier)verifier
		     attributes:(BOOL)attributes
			 packer:(FSDirectoryEntryPacker *)packer;
- (enum ntfs_result)performReadItem:(FSItem *)item
			     offset:(off_t)offset
			      bytes:(void *)bytes
			     length:(size_t)length
			  completed:(size_t *)completed;
- (FSItem *)activateWithArguments:(NSArray<NSString *> *)arguments error:(NSError **)error;
- (FSItem *)performActivation:(NSArray<NSString *> *)arguments error:(NSError **)error;
- (enum ntfs_result)operationBudgetResult;
- (enum ntfs_result)ensureImageView;
- (void)finishUnmountWithReplyHandler:(void (^)(void))reply;
- (void)attachImageTransport:(NTFSImageTransport *)transport
		  writeOwner:(struct ntfs_overwrite *)owner;
@end

NTFSVolume *
ntfs_image_volume_create(NTFSImageTransport *transport, NSError **error)
{
	struct ntfs_overwrite_environment environment;
	struct ntfs_overwrite_admission *admission = NULL;
	__block struct ntfs_write_recovery_report recovered;
	__block struct ntfs_overwrite *owner = NULL;
	struct ntfs_environment view;
	struct ntfs_volume *core = NULL;
	__attribute__((objc_precise_lifetime)) NTFSResource *resource = nil;
	NTFSVolume *volume = nil;
	enum ntfs_result result = NTFS_INVALID;

	if (transport != nil) {
		environment = [transport overwriteEnvironment];
		admission =
		    environment.reader.allocate(environment.reader.context, sizeof(*admission));
		result = admission == NULL ? NTFS_NO_MEMORY : [transport performExclusiveAccess:^{
		  return ntfs_write_owner_open(&environment, admission, &recovered, &owner);
		}];
		if (admission != NULL) {
			environment.reader.release(
			    environment.reader.context, admission, sizeof(*admission));
		}
	}
	if (result == NTFS_OK) {
		resource = [transport newReadResource];
		result = resource != nil    ? NTFS_OK
		    : transport.isAvailable ? NTFS_NO_MEMORY
					    : NTFS_IO;
	}
	if (result == NTFS_OK) {
		view = [resource environment];
		result = ntfs_mount(&view, NULL, &core);
	}
	if (result == NTFS_OK) {
		volume = ntfs_volume_create_with_policies(
		    core, resource, nil, NTFSNativeAccessExtraction);
		if (volume == nil) {
			result = NTFS_NO_MEMORY;
		} else {
			[volume attachImageTransport:transport writeOwner:owner];
		}
	}
	if (result != NTFS_OK) {
		(void)ntfs_unmount(core);
		resource = nil;
		ntfs_overwrite_close(owner);
	}
	if (error != NULL) {
		*error = ntfs_error(result);
	}
	return volume;
}

@implementation NTFSVolume {
	struct ntfs_volume *_core;
	struct ntfs_info _info;
	NTFSResource *_resource;
	NSMapTable<NSNumber *, NTFSItem *> *_items;
	NSMapTable<NSNumber *, NTFSDirectoryPath *> *_paths;
	NTFSLinkPolicy *_linkPolicy;
	NTFSNativeAccessMode _nativeAccessMode;
	uid_t _nativeUserID;
	gid_t _nativeGroupID;
	FSDirectoryVerifier _directoryVerifier;
	uint64_t _freeClusters;
	uint32_t _maximumDirectoryEntries;
	BOOL _active;
	NSLock *_lifecycleLock;
	NSRecursiveLock *_publicationLock;
	NTFSVolumeLifecycle _lifecycle;
	NSUInteger _pendingUnmounts;
	NTFSReadCachePolicy *_readCachePolicy;
	BOOL _maintenanceOnly;
	NTFSVolumeLifecycle _beforeMaintenance;
	enum ntfs_result _mountError, _checkFailure;
	NTFSImageTransport *_imageTransport;
	struct ntfs_overwrite *_writeOwner;
	NSUInteger _readOperations;
	BOOL _imageViewPending, _imageViewOpening, _imageMutationActive;
	enum ntfs_result _itemAdmission;
}

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

- (void)attachImageTransport:(NTFSImageTransport *)transport
		  writeOwner:(struct ntfs_overwrite *)owner
{
	NSAssert(_imageTransport == nil && _writeOwner == NULL, @"NTFS image owner binding");
	_imageTransport = transport;
	_writeOwner = owner;
}

- (enum ntfs_result)ensureImageView
{
	__attribute__((objc_precise_lifetime)) NTFSResource *resource;
	struct ntfs_environment environment;
	struct ntfs_volume *core = NULL;
	struct ntfs_info info;
	enum ntfs_result result;
	NTFSVolumeLifecycle state;

	if (!_imageViewPending) {
		return NTFS_OK;
	}
	state = self.lifecycle;
	if (_imageViewOpening || state == NTFSVolumeWriting) {
		return NTFS_BUSY;
	}
	if (state != NTFSVolumeLoaded && state != NTFSVolumeActive &&
	    state != NTFSVolumeUnmounted) {
		return NTFS_STALE;
	}
	if (!_imageTransport.isAvailable) {
		return NTFS_IO;
	}
	_imageViewOpening = YES;
	@try {
		resource = [_imageTransport newReadResource];
		if (resource == nil) {
			return _imageTransport.isAvailable ? NTFS_NO_MEMORY : NTFS_IO;
		}
		environment = [resource environment];
		result = ntfs_mount(&environment, NULL, &core);
		if (result == NTFS_OK) {
			ntfs_get_info(core, &info);
			if (info.serial != _info.serial || info.size_bytes != _info.size_bytes ||
			    info.cluster_count != _info.cluster_count ||
			    info.sector_size != _info.sector_size ||
			    info.cluster_size != _info.cluster_size ||
			    info.record_size != _info.record_size ||
			    info.index_size != _info.index_size) {
				result = NTFS_STALE;
			}
		}
		if (result == NTFS_OK) {
			_core = core;
			_resource = resource;
			_imageViewPending = NO;
		} else {
			(void)ntfs_unmount(core);
			if (result != NTFS_NO_MEMORY) {
				[_imageTransport invalidate];
			}
		}
		return result;
	} @finally {
		_imageViewOpening = NO;
	}
}

- (enum ntfs_result)detachImageView
{
	NTFSItem *item;
	enum ntfs_result result;

	for (item in _items.objectEnumerator.allObjects) {
		[self clearItemCaches:item];
		ntfs_node_close(item->node);
		item->node = NULL;
		/* The path remains a numeric ancestry token. Its old core pointer is
		 * never followed; rebind it before any native consumer can use it. */
	}
	[_paths removeAllObjects];
	result = ntfs_unmount(_core);
	if (result == NTFS_OK) {
		_core = NULL;
		_resource = nil;
		_imageViewPending = YES;
	}
	return result;
}

- (enum ntfs_result)overwriteImageItem:(FSItem *)item
				offset:(off_t)offset
				 bytes:(const void *)bytes
				length:(size_t)length
			      fileTime:(uint64_t)fileTime
			     completed:(size_t *)completed
{
	__block enum ntfs_result result;
	__block struct ntfs_write_range_report written = {0};
	NTFSItem *value;
	uint64_t reference;

	if (completed == NULL) {
		return NTFS_INVALID;
	}
	*completed = 0;
	[_publicationLock lock];
	@try {
		@synchronized(self) {
			if (self.lifecycle == NTFSVolumeInvalidating ||
			    self.lifecycle == NTFSVolumeInvalidated) {
				return NTFS_STALE;
			}
			if (_imageTransport == nil || _writeOwner == NULL) {
				return NTFS_UNSUPPORTED;
			}
			if (_readOperations != 0 || _imageViewOpening) {
				return NTFS_BUSY;
			}
			result = [self ensureImageView];
			if (result == NTFS_OK) {
				result = [self admissionResult];
			}
			if (result != NTFS_OK) {
				return result;
			}
			value = [self checkedItem:item];
			if (value == nil) {
				return _itemAdmission;
			}
			if (offset < 0 || (length != 0 && bytes == NULL) || fileTime > INT64_MAX) {
				return NTFS_INVALID;
			}
			if (length > NTFS_OVERWRITE_MAX_BYTES) {
				return NTFS_RANGE;
			}
			if (length == 0) {
				return NTFS_OK;
			}
			reference = value->stat.reference;
			[_lifecycleLock lock];
			if (_lifecycle == NTFSVolumeActive && _pendingUnmounts == 0) {
				_lifecycle = NTFSVolumeWriting;
				result = NTFS_OK;
			} else {
				result = NTFS_STALE;
			}
			[_lifecycleLock unlock];
			if (result != NTFS_OK) {
				return result;
			}
			_imageMutationActive = YES;
			@try {
				result = [self detachImageView];
				if (result == NTFS_OK) {
					result = [_imageTransport performExclusiveAccess:^{
					  return ntfs_write_existing_range(self->_writeOwner,
					      reference, (uint64_t)offset, bytes, length, fileTime,
					      &written);
					}];
				}
				if (written.execution.poisoned) {
					[_imageTransport invalidate];
				}
				if (result == NTFS_OK) {
					*completed = (size_t)written.completed_bytes;
				}
				/* No allocation follows durable completion. The next read mounts
				 * a fresh immutable view and lazily rebinds its stable FSItem. */
				return result;
			} @finally {
				BOOL invalidating;

				_imageMutationActive = NO;
				[_lifecycleLock lock];
				invalidating = _lifecycle == NTFSVolumeInvalidating;
				if (_lifecycle == NTFSVolumeWriting) {
					_lifecycle = NTFSVolumeActive;
				}
				[_lifecycleLock unlock];
				if (invalidating) {
					[self invalidate];
				}
			}
		}
	} @finally {
		[_publicationLock unlock];
	}
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

		*error = nil;

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

/* The caller holds the operation monitor. Cursor continuation, pending entry,
 * checked node, native target and namespace identity have separate lifetimes. */
- (void)releaseReadCaches:(NTFSItem *)item
{
	ntfs_reparse_close(item->reparse);
	item->reparse = NULL;
	ntfs_stream_catalog_close(item->catalog);
	item->catalog = NULL;
	ntfs_stream_close(item->stream);
	item->stream = NULL;
}

- (void)finishReadCaches:(NTFSItem *)item
{
	NTFSDirectoryContinuations *continuations = item->continuations;
	NSUInteger i;

	if (!_readCachePolicy.retentionActive) {
		[self releaseReadCaches:item];
		/* Keep the last active continuation under pressure; older positions are
		 * optional and can be reconstructed without changing any native cookie. */
		for (i = 0; continuations != nil && i < NTFS_DIRECTORY_CONTINUATIONS; i++) {
			if (i != continuations->mostRecent && !continuations->states[i].in_use) {
				close_directory_continuation(&continuations->states[i]);
			}
		}
	}
}

- (void)clearItemCaches:(NTFSItem *)item
{
	[self releaseReadCaches:item];
	[item->continuations clear];
	item->continuations = nil;
	/* In-flight enumeration must observe this even after a reentrant remount;
	 * the immutable owner's persistent directory verifier remains unchanged. */
	item->continuationEpoch++;
}

- (enum ntfs_result)directoryContinuationForItem:(NTFSItem *)item
					position:(uint64_t)position
				      attributes:(BOOL)attributes
					 initial:(BOOL)initial
				    continuation:(struct ntfs_directory_continuation **)out
{
	NTFSDirectoryContinuations *continuations;
	struct ntfs_directory_continuation *candidate, *selected = NULL;
	NSUInteger i, index, selectedIndex = NTFS_DIRECTORY_CONTINUATIONS;
	enum ntfs_result result;

	*out = NULL;
	if (item->continuations == nil) {
		item->continuations =
		    [[NTFSDirectoryContinuations alloc] initWithResource:_resource];
		if (item->continuations == nil) {
			return NTFS_NO_MEMORY;
		}
	}
	continuations = item->continuations;
	if (!initial) {
		/* Prefer an exact saved position, then the closest earlier position in
		 * the same native view. No cursor is copied or rewound in place. */
		for (i = 0; i < NTFS_DIRECTORY_CONTINUATIONS; i++) {
			index = (continuations->mostRecent + i) % NTFS_DIRECTORY_CONTINUATIONS;
			candidate = &continuations->states[index];
			if (candidate->cursor != NULL && !candidate->in_use &&
			    candidate->attributes == attributes &&
			    candidate->position <= position &&
			    (selected == NULL || candidate->position > selected->position)) {
				selected = candidate;
				selectedIndex = index;
				if (candidate->position == position) {
					break;
				}
			}
		}
	}
	if (selected == NULL) {
		/* A packer can call back into this monitor. Pinned continuations must
		 * neither be advanced by that call nor be evicted beneath its caller. */
		for (i = 0; i < NTFS_DIRECTORY_CONTINUATIONS; i++) {
			if (continuations->states[i].complete && !continuations->states[i].in_use) {
				selectedIndex = i;
				break;
			}
		}
		/* Prefer replacing a completed scan to retaining an EOF-only cursor
		 * alongside a new scan. Sequential callers then keep one core cursor. */
		for (i = 0; i < NTFS_DIRECTORY_CONTINUATIONS; i++) {
			if (selectedIndex != NTFS_DIRECTORY_CONTINUATIONS) {
				break;
			}
			if (continuations->states[i].cursor == NULL &&
			    !continuations->states[i].in_use) {
				selectedIndex = i;
				break;
			}
		}
		if (selectedIndex == NTFS_DIRECTORY_CONTINUATIONS) {
			for (i = 1; i <= NTFS_DIRECTORY_CONTINUATIONS; i++) {
				index =
				    (continuations->mostRecent + i) % NTFS_DIRECTORY_CONTINUATIONS;
				if (!continuations->states[index].in_use) {
					selectedIndex = index;
					break;
				}
			}
		}
		if (selectedIndex == NTFS_DIRECTORY_CONTINUATIONS) {
			return NTFS_BUSY;
		}
		selected = &continuations->states[selectedIndex];
		/* Evict before construction: even a failed open keeps at most two core
		 * cursors. The other held continuation remains unchanged. */
		close_directory_continuation(selected);
		result = ntfs_directory_open(item->node, &selected->cursor);
		if (result != NTFS_OK) {
			return result;
		}
		selected->attributes = attributes;
	}
	continuations->mostRecent = selectedIndex;
	selected->in_use = YES;
	*out = selected;
	return NTFS_OK;
}

- (void)releaseItem:(NTFSItem *)item
{
	[self clearItemCaches:item];
	ntfs_node_close(item->node);
	item->node = NULL;
	item->linkTarget = nil;
	item->directoryPath = nil;
	item.owner = nil;
}

- (void)releaseUnreferencedItem:(NTFSItem *)item
{
	NTFSItem *current;

	@synchronized(self) {
		current = [_items objectForKey:@(item->stat.reference)];
		if (current == nil || current == item) {
			[_items removeObjectForKey:@(item->stat.reference)];
		}
		[self releaseItem:item];
	}
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
	/* This method also runs from dealloc; do not capture the owner in a block. */
	[_publicationLock lock];
	@try {
		@synchronized(self) {
			if (_imageMutationActive) {
				/* A native transfer can reenter the owner. Admission is already
				 * closed; release the C owner only after its call has returned. */
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

- (NTFSVolumeLifecycle)lifecycle
{
	NTFSVolumeLifecycle state;

	[_lifecycleLock lock];
	state = _lifecycle;
	[_lifecycleLock unlock];
	return state;
}

- (NTFSItem *)checkedItem:(FSItem *)item
{
	NTFSItem *value;

	_itemAdmission = NTFS_STALE;
	if (_core == NULL || !_active || ![item isKindOfClass:NTFSItem.class]) {
		return nil;
	}
	value = (NTFSItem *)item;
	if (value.owner != self) {
		return nil;
	}
	if (value->node == NULL && _imageTransport != nil) {
		_itemAdmission = [self rebindImageItem:value];
		if (_itemAdmission != NTFS_OK) {
			return nil;
		}
	} else if (value->node == NULL) {
		return nil;
	}
	_itemAdmission = NTFS_OK;
	[self finishReadCaches:value];
	return value;
}

- (NTFSDirectoryPath *)rebindImagePath:(NTFSDirectoryPath *)old result:(enum ntfs_result *)result
{
	NSMutableArray<NTFSDirectoryPath *> *ancestry = [NSMutableArray array];
	NTFSDirectoryPath *entry, *path = nil, *found;
	struct ntfs_node *node = NULL;
	struct ntfs_stat stat;
	NSUInteger index;

	*result = NTFS_OK;
	for (entry = old; entry != nil; entry = entry.parent) {
		if (ancestry.count >= NTFS_FSKIT_LINK_COMPONENT_LIMIT) {
			*result = NTFS_RANGE;
			return nil;
		}
		[ancestry addObject:entry];
	}
	for (index = ancestry.count; index != 0; index--) {
		entry = ancestry[index - 1];
		found = [_paths objectForKey:@(entry.reference)];
		if (found != nil) {
			if (found.volume != _core || found.parent.reference != path.reference) {
				*result = NTFS_CORRUPT;
				return nil;
			}
			path = found;
			continue;
		}
		*result = ntfs_node_open(_core, entry.reference, &node);
		if (*result == NTFS_OK) {
			*result = ntfs_node_metadata(node, &stat);
			if (*result == NTFS_OK && (!stat.directory || stat.reparse)) {
				*result = NTFS_CORRUPT;
			}
		}
		ntfs_node_close(node);
		node = NULL;
		if (*result != NTFS_OK) {
			return nil;
		}
		if (_paths.count >= NTFS_FSKIT_PATH_LIMIT) {
			*result = NTFS_NO_MEMORY;
			return nil;
		}
		path = [[NTFSDirectoryPath alloc] initWithVolume:_core
						       reference:entry.reference
							  parent:path];
		if (path == nil) {
			*result = NTFS_NO_MEMORY;
			return nil;
		}
		[_paths setObject:path forKey:@(entry.reference)];
	}
	return path;
}

- (enum ntfs_result)rebindImageItem:(NTFSItem *)item
{
	struct ntfs_node *node = NULL;
	struct ntfs_stat stat;
	struct ntfs_link_counts links;
	NTFSDirectoryPath *path = nil;
	enum ntfs_result result;

	/* The private writer changes initialized data and SI timestamps only. Full
	 * sequence references, namespace ancestry, reparse targets and allocation
	 * remain fixed by its validated transaction, not by a same-serial guess. */
	result = ntfs_node_open(_core, item->stat.reference, &node);
	if (result == NTFS_OK) {
		result = ntfs_node_metadata(node, &stat);
	}
	if (result == NTFS_OK &&
	    (stat.directory != item->stat.directory || stat.reparse != item->stat.reparse)) {
		result = NTFS_STALE;
	}
	if (result == NTFS_OK && (!stat.reparse || item->wof)) {
		result = ntfs_node_stat(node, &stat);
	}
	if (result == NTFS_OK) {
		result = ntfs_node_link_counts(node, &links);
	}
	if (result == NTFS_OK && item->directoryPath != nil) {
		path = [self rebindImagePath:item->directoryPath result:&result];
	}
	if (result == NTFS_OK) {
		if (item->linkTarget != nil) {
			stat.size = item->stat.size;
			stat.allocated_size = item->stat.allocated_size;
		}
		item->node = node;
		item->stat = stat;
		item->links = links;
		item->directoryPath = path;
	} else {
		ntfs_node_close(node);
	}
	return result;
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

- (NTFSItem *)adoptNode:(struct ntfs_node *)node
	parentReference:(uint64_t)parentReference
	 containingPath:(NTFSDirectoryPath *)containingPath
		  error:(NSError **)error
{
	struct ntfs_stat stat;
	struct ntfs_link_counts links = {0};
	struct ntfs_reparse *snapshot = NULL;
	struct ntfs_reparse_info reparseInfo;
	struct ntfs_wof_info wofInfo;
	enum ntfs_result result;
	NTFSItem *item;
	NTFSDirectoryPath *path = nil;
	FSFileName *target = nil;
	NTFSVolumeLifecycle state;
	BOOL wof = NO;

	result = ntfs_node_metadata(node, &stat);
	if (result == NTFS_OK && !stat.reparse) {
		result = ntfs_node_stat(node, &stat);
	}
	if (result == NTFS_OK) {
		result = ntfs_node_link_counts(node, &links);
	}
	state = self.lifecycle;
	if (result == NTFS_OK && state != NTFSVolumeLoaded && state != NTFSVolumeActive) {
		result = NTFS_STALE;
	}
	if (result == NTFS_OK && !_resource.isAvailable) {
		result = NTFS_IO;
	}
	if (result != NTFS_OK) {
		ntfs_node_close(node);
		*error = ntfs_error(result);
		return nil;
	}
	if (stat.reparse) {
		result = ntfs_reparse_open(node, &snapshot);
		if (result == NTFS_OK) {
			ntfs_reparse_get_info(snapshot, &reparseInfo);
			if (reparseInfo.kind == NTFS_REPARSE_WOF) {
				result = ntfs_reparse_wof_info(snapshot, &wofInfo);
				if (result == NTFS_OK) {
					result = ntfs_node_stat(node, &stat);
					wof = result == NTFS_OK;
				}
			} else {
				/* Only readlink projection depends on a unique owning edge. */
				result = links.primary_names != 1
				    ? NTFS_UNSUPPORTED
				    : ntfs_native_link_target(_core, snapshot, stat.reference,
					  containingPath, _linkPolicy, _maximumDirectoryEntries,
					  &target);
			}
		}
		if (result == NTFS_OK && !wof) {
			stat.size = target.data.length;
			stat.allocated_size = ntfs_reparse_allocated_size(snapshot);
		}
	} else if (stat.directory) {
		if (item_id(stat.reference) == FSItemIDRootDirectory) {
			if (parentReference != 0 && parentReference != stat.reference) {
				ntfs_node_close(node);
				*error = ntfs_error(NTFS_CORRUPT);
				return nil;
			}
			parentReference = stat.reference;
		} else if (parentReference >> NTFS_REFERENCE_SEQUENCE_SHIFT == 0 ||
		    parentReference == stat.reference || containingPath == nil ||
		    containingPath.volume != _core || containingPath.reference != parentReference) {
			ntfs_node_close(node);
			*error = ntfs_error(NTFS_CORRUPT);
			return nil;
		}
		path = [_paths objectForKey:@(stat.reference)];
		if (path != nil &&
		    (path.parent == nil ? parentReference != stat.reference
					: path.parent.reference != parentReference)) {
			result = NTFS_CORRUPT;
		} else if (path == nil) {
			if (_paths.count >= NTFS_FSKIT_PATH_LIMIT) {
				result = NTFS_NO_MEMORY;
			} else if (containingPath.depth >= NTFS_FSKIT_LINK_COMPONENT_LIMIT) {
				result = NTFS_RANGE;
			} else {
				path = [[NTFSDirectoryPath alloc] initWithVolume:_core
								       reference:stat.reference
									  parent:containingPath];
				result = path == nil ? NTFS_CORRUPT : NTFS_OK;
				if (result == NTFS_OK) {
					[_paths setObject:path forKey:@(stat.reference)];
				}
			}
		}
	}
	if (result == NTFS_OK) {
		state = self.lifecycle;
		if (state != NTFSVolumeLoaded && state != NTFSVolumeActive) {
			result = NTFS_STALE;
		} else if (!_resource.isAvailable) {
			result = NTFS_IO;
		}
	}
	if (result != NTFS_OK) {
		ntfs_reparse_close(snapshot);
		ntfs_node_close(node);
		*error = ntfs_error(result);
		return nil;
	}
	item = [_items objectForKey:@(stat.reference)];
	if (item != nil) {
		ntfs_reparse_close(snapshot);
		ntfs_node_close(node);
		if (path != nil && item->parentReference != parentReference) {
			*error = ntfs_error(NTFS_CORRUPT);
			return nil;
		}
		if (item->wof != wof ||
		    (target != nil && ![item->linkTarget.data isEqualToData:target.data])) {
			/* One native inode cannot cache different projected readlink bytes
			 * for distinct hard-link edges. Preserve explicit ambiguity. */
			*error = ntfs_error(NTFS_UNSUPPORTED);
			return nil;
		}
		[self finishReadCaches:item];
		return item;
	}
	if (_items.count >= NTFS_FSKIT_ITEM_LIMIT) {
		ntfs_reparse_close(snapshot);
		ntfs_node_close(node);
		*error = ntfs_error(NTFS_NO_MEMORY);
		return nil;
	}
	item = [[NTFSItem alloc] init];
	item->node = node;
	item->stat = stat;
	item->links = links;
	item->parentReference = path != nil ? parentReference : 0;
	item->directoryPath = path;
	item->reparse = snapshot;
	item->linkTarget = target;
	item->wof = wof;
	item.owner = self;
	[_items setObject:item forKey:@(stat.reference)];
	[self finishReadCaches:item];
	return item;
}

- (NTFSItem *)directoryItemAtPath:(NTFSDirectoryPath *)path error:(NSError **)error
{
	struct ntfs_node *node = NULL;
	struct ntfs_stat stat;
	enum ntfs_result result;
	NTFSItem *item;

	if (path == nil || path.volume != _core) {
		*error = ntfs_error(NTFS_CORRUPT);
		return nil;
	}
	item = [_items objectForKey:@(path.reference)];
	if (item != nil) {
		if ([self checkedItem:item] != item) {
			*error = ntfs_error(_itemAdmission);
			return nil;
		}
		if (item->directoryPath != path) {
			*error = ntfs_error(NTFS_CORRUPT);
			return nil;
		}
		return item;
	}
	/* A child retains numeric ancestry after its parent's FSItem is released.
	 * Reopen the complete sequence-bearing reference, never an inferred name
	 * or a record number stripped of its sequence. */
	result = ntfs_node_open(_core, path.reference, &node);
	if (result == NTFS_OK) {
		result = ntfs_node_metadata(node, &stat);
	}
	if (result == NTFS_OK && (!stat.directory || stat.reparse)) {
		result = NTFS_CORRUPT;
	}
	if (result == NTFS_OK) {
		result = [self admissionResult];
	}
	if (result != NTFS_OK) {
		ntfs_node_close(node);
		*error = ntfs_error(result);
		return nil;
	}
	return [self adoptNode:node
	       parentReference:path.parent == nil ? path.reference : path.parent.reference
		containingPath:path.parent
			 error:error];
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
		result = ntfs_native_access_mode(arguments, &requested);
		if (result != NTFS_OK) {
			*error = ntfs_error(result);
			return nil;
		}
		if (requested == NTFSNativeAccessUnselected &&
		    _nativeAccessMode == NTFSNativeAccessUnselected) {
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
				_nativeAccessMode = NTFSNativeAccessExtraction;
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

- (FSItem *)performLookup:(FSFileName *)name
	      inDirectory:(FSItem *)directory
	       storedName:(FSFileName **)stored
		    error:(NSError **)error
{
	uint16_t units[NTFS_NAME_MAX];
	size_t length;
	struct ntfs_node *node = NULL;
	struct ntfs_dirent entry;
	uint64_t reference;
	uint32_t ordinal;
	BOOL projected, virtualParent;
	enum ntfs_result result;
	NTFSItem *parent, *item;
	NTFSDirectoryPath *path;

	*error = nil;
	*stored = nil;
	@synchronized(self) {
		result = [self admissionResult];
		if (result != NTFS_OK) {
			*error = ntfs_error(result);
			return nil;
		}
		parent = [self checkedItem:directory];
		if (parent == nil) {
			*error = ntfs_error(_itemAdmission);
			return nil;
		}
		if (parent->directoryPath == nil) {
			*error = ntfs_error(NTFS_NOT_DIRECTORY);
			return nil;
		}
		if (name.data.length > NTFS_FSKIT_NATIVE_NAME_BYTES) {
			*error = [NSError errorWithDomain:NSPOSIXErrorDomain
						     code:ENAMETOOLONG
						 userInfo:nil];
			return nil;
		}
		if (directory_lookup_name(name, &virtualParent)) {
			path = parent->directoryPath;
			if (virtualParent && path.parent != nil) {
				path = path.parent;
			}
			item = path == parent->directoryPath
			    ? parent
			    : [self directoryItemAtPath:path error:error];
			if (item != nil) {
				result = [self admissionResult];
				if (result == NTFS_OK) {
					*stored = [FSFileName
					    nameWithString:virtualParent ? @".." : @"."];
					result = *stored == nil ? NTFS_NO_MEMORY : NTFS_OK;
				}
				if (result != NTFS_OK) {
					*stored = nil;
					*error = ntfs_error(result);
					item = nil;
				}
			}
			return item;
		}
		if (ntfs_native_name_reserved(name)) {
			result = NTFS_NOT_FOUND;
			if (ntfs_native_alias_parse(name, &reference, &ordinal)) {
				result = ntfs_native_entry_at(
				    parent->node, ordinal, _maximumDirectoryEntries, &entry);
				if (result == NTFS_END ||
				    (result == NTFS_OK && entry.reference != reference)) {
					result = NTFS_NOT_FOUND;
				}
				if (result == NTFS_OK) {
					result = ntfs_native_entry_name(
					    &entry, ordinal, stored, &projected);
					if (result == NTFS_OK &&
					    (!projected ||
						(parent->stat.case_sensitive &&
						    ![name.data isEqualToData:(*stored).data]))) {
						result = NTFS_NOT_FOUND;
					}
				}
				if (result == NTFS_OK) {
					result = ntfs_node_open(_core, reference, &node);
				}
			}
		} else {
			result = ntfs_utf8_to_utf16(
			    name.data.bytes, name.data.length, units, NTFS_NAME_MAX, &length);
			if (result == NTFS_OK) {
				result =
				    ntfs_lookup_entry(parent->node, units, length, &node, &entry);
			}
			if (result == NTFS_OK) {
				result = ntfs_native_entry_name(&entry, 0, stored, &projected);
				if (result == NTFS_OK && projected) {
					result = NTFS_NOT_FOUND;
				}
			}
		}
		if (result == NTFS_OK && !ntfs_native_entry_visible(&entry)) {
			result = NTFS_NOT_FOUND;
		}
		if (result == NTFS_OK) {
			result = [self admissionResult];
		}
		if (result != NTFS_OK) {
			ntfs_node_close(node);
			*stored = nil;
			*error = ntfs_error(result);
			return nil;
		}
		parent = [self adoptNode:node
			 parentReference:entry.parent_reference
			  containingPath:parent->directoryPath
				   error:error];
		if (parent == nil) {
			*stored = nil;
		}
		return parent;
	}
}

- (FSItemAttributes *)performAttributes:(FSItem *)item error:(NSError **)error
{
	NTFSItem *value;
	enum ntfs_result result;

	*error = nil;
	@synchronized(self) {
		result = [self admissionResult];
		if (result != NTFS_OK) {
			*error = ntfs_error(result);
			return nil;
		}
		value = [self checkedItem:item];
		if (value == nil) {
			*error = ntfs_error(_itemAdmission);
			return nil;
		}
		return [self attributesForStat:&value->stat
				    linkCounts:&value->links
				  symbolicLink:value->linkTarget != nil];
	}
}

- (FSItemAttributes *)attributesForStat:(const struct ntfs_stat *)stat
			     linkCounts:(const struct ntfs_link_counts *)links
			   symbolicLink:(BOOL)link
{
	FSItemAttributes *attrs = [[FSItemAttributes alloc] init];

	/* Extraction presentation has one stable native identity. Neither this
	 * snapshot nor mode bits authenticate a Windows principal. */
	attrs.uid = _nativeUserID;
	attrs.gid = _nativeGroupID;
	attrs.mode =
	    stat->directory && !link ? NTFS_READ_ONLY_DIRECTORY_MODE : NTFS_READ_ONLY_FILE_MODE;
	attrs.type =
	    link ? FSItemTypeSymlink : (stat->directory ? FSItemTypeDirectory : FSItemTypeFile);
	attrs.fileID = item_id(stat->reference);
	attrs.linkCount = links->primary_names;
	attrs.size = stat->size;
	attrs.allocSize = stat->allocated_size;
	attrs.inhibitKernelOffloadedIO = YES;
	attrs.birthTime = (struct timespec){stat->created.seconds, stat->created.nanoseconds};
	attrs.modifyTime = (struct timespec){stat->modified.seconds, stat->modified.nanoseconds};
	attrs.changeTime = (struct timespec){stat->changed.seconds, stat->changed.nanoseconds};
	attrs.accessTime = (struct timespec){stat->accessed.seconds, stat->accessed.nanoseconds};
	return attrs;
}

- (FSFileName *)performSymbolicLink:(FSItem *)item error:(NSError **)error
{
	NTFSItem *value;
	enum ntfs_result result;

	*error = nil;
	@synchronized(self) {
		result = [self admissionResult];
		if (result != NTFS_OK) {
			*error = ntfs_error(result);
			return nil;
		}
		value = [self checkedItem:item];
		if (value == nil) {
			*error = ntfs_error(_itemAdmission);
			return nil;
		}
		if (value->linkTarget == nil) {
			*error = ntfs_error(NTFS_INVALID);
			return nil;
		}
		return value->linkTarget;
	}
}

- (enum ntfs_result)performReadItem:(FSItem *)item
			     offset:(off_t)offset
			      bytes:(void *)bytes
			     length:(size_t)length
			  completed:(size_t *)completed
{
	NTFSItem *value;
	enum ntfs_result result = NTFS_OK;

	*completed = 0;
	@synchronized(self) {
		result = [self admissionResult];
		if (result != NTFS_OK) {
			return result;
		}
		value = [self checkedItem:item];
		if (value == nil) {
			return _itemAdmission;
		}
		@try {
			if (offset < 0) {
				return NTFS_INVALID;
			}
			if (value->linkTarget != nil) {
				return NTFS_UNSUPPORTED;
			}
			if (value->stream == NULL) {
				result = ntfs_stream_open(value->node, NULL, 0, &value->stream);
			}
			if (result == NTFS_OK) {
				result = ntfs_stream_read(
				    value->stream, (uint64_t)offset, bytes, length, completed);
			}
			if (result == NTFS_OK) {
				result = [self admissionResult];
			}
			if (result != NTFS_OK) {
				*completed = 0;
			}
			return result;
		} @finally {
			[self finishReadCaches:value];
		}
	}
}

- (struct ntfs_stream_catalog *)catalogForItem:(NTFSItem *)item error:(NSError **)error
{
	enum ntfs_result result;

	if (item->catalog == NULL) {
		result =
		    ntfs_stream_catalog_open(item->node, NTFS_FSKIT_STREAM_LIMIT, &item->catalog);
		if (result != NTFS_OK) {
			*error = ntfs_error(result);
			return NULL;
		}
	}
	result = [self admissionResult];
	if (result != NTFS_OK) {
		*error = ntfs_error(result);
		return NULL;
	}
	return item->catalog;
}

- (NSArray<FSFileName *> *)performXattrsForItem:(FSItem *)item error:(NSError **)error
{
	NTFSItem *value;
	NSMutableArray<FSFileName *> *names;
	struct ntfs_stream_catalog *catalog;
	struct ntfs_stream_name name;
	uint32_t i;
	enum ntfs_result result;

	*error = nil;
	@synchronized(self) {
		result = [self admissionResult];
		if (result != NTFS_OK) {
			*error = ntfs_error(result);
			return nil;
		}
		value = [self checkedItem:item];
		if (value == nil) {
			*error = ntfs_error(_itemAdmission);
			return nil;
		}
		@try {
			if (value->linkTarget != nil) {
				return @[ [FSFileName nameWithString:reparseAttributeName] ];
			}
			catalog = [self catalogForItem:value error:error];
			if (catalog == NULL) {
				return nil;
			}
			names = [NSMutableArray
			    arrayWithObject:[FSFileName nameWithString:streamManifestName]];
			if (value->wof) {
				[names addObject:[FSFileName nameWithString:reparseAttributeName]];
			}
			if (value->stat.directory) {
				[names addObject:[FSFileName nameWithString:namesManifestName]];
			}
			for (i = 0; i < ntfs_stream_catalog_count(catalog); i++) {
				result = ntfs_stream_catalog_entry(catalog, i, &name);
				if (result != NTFS_OK) {
					*error = ntfs_error(result);
					return nil;
				}
				if (name.length != 0 &&
				    !(value->wof &&
					ntfs_wof_is_backing_stream(name.units, name.length))) {
					[names addObject:stream_alias(i)];
				}
			}
			result = [self admissionResult];
			if (result != NTFS_OK) {
				*error = ntfs_error(result);
				return nil;
			}
			return names;
		} @finally {
			[self finishReadCaches:value];
		}
	}
}

- (NSData *)streamManifest:(NTFSItem *)item
		   catalog:(struct ntfs_stream_catalog *)catalog
		     error:(NSError **)error
{
	struct stream_manifest_header *header;
	struct stream_manifest_entry *entry;
	struct ntfs_stream_name name;
	NSMutableData *data;
	uint8_t *bytes;
	size_t size = sizeof(*header), position, j;
	uint32_t i, count = 0;
	enum ntfs_result result;

	for (i = 0; i < ntfs_stream_catalog_count(catalog); i++) {
		result = ntfs_stream_catalog_entry(catalog, i, &name);
		if (result != NTFS_OK) {
			*error = ntfs_error(result);
			return nil;
		}
		if (name.length != 0) {
			size += sizeof(*entry) + (size_t)name.length * sizeof(uint16_t);
			count++;
		}
	}
	if (size > NTFS_FSKIT_XATTR_BYTES) {
		*error = [NSError errorWithDomain:NSPOSIXErrorDomain code:E2BIG userInfo:nil];
		return nil;
	}
	data = [NSMutableData dataWithLength:size];
	bytes = data.mutableBytes;
	header = (void *)bytes;
	memcpy(header->magic, "NTFSADS", sizeof(header->magic));
	store_little(header->version, sizeof(header->version), NTFS_STREAM_MANIFEST_VERSION);
	store_little(header->count, sizeof(header->count), count);
	store_little(header->reference, sizeof(header->reference), item->stat.reference);
	position = sizeof(*header);
	for (i = 0; i < ntfs_stream_catalog_count(catalog); i++) {
		result = ntfs_stream_catalog_entry(catalog, i, &name);
		if (result != NTFS_OK) {
			*error = ntfs_error(result);
			return nil;
		}
		if (name.length == 0) {
			continue;
		}
		entry = (void *)(bytes + position);
		store_little(entry->index, sizeof(entry->index), i);
		store_little(entry->name_length, sizeof(entry->name_length), name.length);
		position += sizeof(*entry);
		for (j = 0; j < name.length; j++) {
			store_little(bytes + position, sizeof(uint16_t), name.units[j]);
			position += sizeof(uint16_t);
		}
	}
	return data;
}

- (NSData *)performXattrNamed:(FSFileName *)name ofItem:(FSItem *)item error:(NSError **)error
{
	NTFSItem *value;
	struct ntfs_stream_catalog *catalog;
	struct ntfs_stream_name streamName;
	struct ntfs_stream *stream = NULL;
	NSMutableData *data = nil;
	NSData *manifest;
	uint64_t size;
	uint32_t index = 0;
	size_t completed = 0, reparseSize = 0;
	enum ntfs_result result;

	*error = nil;
	@synchronized(self) {
		result = [self admissionResult];
		if (result != NTFS_OK) {
			*error = ntfs_error(result);
			return nil;
		}
		value = [self checkedItem:item];
		if (value == nil) {
			*error = ntfs_error(_itemAdmission);
			return nil;
		}
		@try {
			if (value->linkTarget != nil ||
			    (value->wof &&
				[name.data
				    isEqualToData:[FSFileName nameWithString:reparseAttributeName]
						      .data])) {
				if (![name.data
					isEqualToData:[FSFileName
							  nameWithString:reparseAttributeName]
							  .data]) {
					*error = [NSError errorWithDomain:NSPOSIXErrorDomain
								     code:ENOATTR
								 userInfo:nil];
					return nil;
				}
				result = NTFS_OK;
				if (value->reparse == NULL) {
					result = ntfs_reparse_open(value->node, &value->reparse);
				}
				if (result == NTFS_OK) {
					result = ntfs_reparse_bytes(
					    value->reparse, NULL, 0, &reparseSize);
					if (result == NTFS_RANGE) {
						data = [NSMutableData dataWithLength:reparseSize];
						result = ntfs_reparse_bytes(value->reparse,
						    data.mutableBytes, data.length, &reparseSize);
					}
				}
				if (result == NTFS_OK) {
					result = [self admissionResult];
				}
				if (result != NTFS_OK) {
					*error = ntfs_error(result);
					return nil;
				}
				return data;
			}
			if ([name.data
				isEqualToData:[FSFileName nameWithString:namesManifestName].data] ||
			    ordinal_xattr_index(name, nameEntryPrefix, &index)) {
				if (!value->stat.directory) {
					*error = [NSError errorWithDomain:NSPOSIXErrorDomain
								     code:ENOATTR
								 userInfo:nil];
					return nil;
				}
				result = ntfs_native_names_manifest(value->node,
				    value->stat.reference, _maximumDirectoryEntries,
				    ![name.data
					isEqualToData:[FSFileName nameWithString:namesManifestName]
							  .data],
				    index, NTFS_FSKIT_XATTR_BYTES, &manifest);
				if (result == NTFS_NOT_FOUND) {
					*error = [NSError errorWithDomain:NSPOSIXErrorDomain
								     code:ENOATTR
								 userInfo:nil];
					return nil;
				}
				if (result == NTFS_RANGE) {
					*error = [NSError errorWithDomain:NSPOSIXErrorDomain
								     code:E2BIG
								 userInfo:nil];
					return nil;
				}
				if (result == NTFS_OK) {
					result = [self admissionResult];
				}
				if (result != NTFS_OK) {
					*error = ntfs_error(result);
					return nil;
				}
				return manifest;
			}
			catalog = [self catalogForItem:value error:error];
			if (catalog == NULL) {
				return nil;
			}
			if ([name.data isEqualToData:[FSFileName nameWithString:streamManifestName]
							 .data]) {
				manifest = [self streamManifest:value catalog:catalog error:error];
				if (manifest != nil) {
					result = [self admissionResult];
					if (result != NTFS_OK) {
						*error = ntfs_error(result);
						return nil;
					}
				}
				return manifest;
			}
			if (!ordinal_xattr_index(name, streamAliasPrefix, &index) ||
			    ntfs_stream_catalog_entry(catalog, index, &streamName) != NTFS_OK ||
			    streamName.length == 0 ||
			    (value->wof &&
				ntfs_wof_is_backing_stream(streamName.units, streamName.length))) {
				*error = [NSError errorWithDomain:NSPOSIXErrorDomain
							     code:ENOATTR
							 userInfo:nil];
				return nil;
			}
			result = ntfs_stream_open(
			    value->node, streamName.units, streamName.length, &stream);
			if (result == NTFS_OK) {
				size = ntfs_stream_size(stream);
				if (size > NTFS_FSKIT_XATTR_BYTES) {
					ntfs_stream_close(stream);
					*error = [NSError errorWithDomain:NSPOSIXErrorDomain
								     code:E2BIG
								 userInfo:nil];
					return nil;
				}
				data = [NSMutableData dataWithLength:(NSUInteger)size];
				result = ntfs_stream_read(
				    stream, 0, data.mutableBytes, (size_t)size, &completed);
				if (result == NTFS_OK && completed != size) {
					result = NTFS_IO;
				}
			}
			ntfs_stream_close(stream);
			if (result == NTFS_OK) {
				result = [self admissionResult];
			}
			if (result != NTFS_OK) {
				*error = ntfs_error(result);
				return nil;
			}
			return data;
		} @finally {
			[self finishReadCaches:value];
		}
	}
}

- (NSError *)performEnumeration:(FSItem *)directory
			 cookie:(FSDirectoryCookie)cookie
		       verifier:(FSDirectoryVerifier)verifier
		     attributes:(BOOL)attributes
			 packer:(FSDirectoryEntryPacker *)packer
{
	NTFSItem *item;
	__attribute__((objc_precise_lifetime)) NTFSDirectoryContinuations *continuations = nil;
	struct ntfs_directory_continuation *continuation = NULL;
	struct ntfs_node *node = NULL;
	struct ntfs_reparse *snapshot = NULL;
	struct ntfs_stat stat;
	struct ntfs_link_counts links;
	struct ntfs_reparse_info reparseInfo;
	struct ntfs_wof_info wofInfo;
	FSFileName *name;
	FSItemAttributes *attrs;
	FSItemType type;
	FSFileName *target;
	BOOL projected, packed;
	uint64_t requestedPosition, reference, maximumPosition, operationEpoch;
	enum ntfs_result result;

	@synchronized(self) {
		result = [self admissionResult];
		if (result != NTFS_OK) {
			return ntfs_error(result);
		}
		item = [self checkedItem:directory];
		if (item == nil) {
			return ntfs_error(_itemAdmission);
		}
		if (item->directoryPath == nil) {
			return ntfs_error(NTFS_NOT_DIRECTORY);
		}
		/* Keep the native call depth bounded even if a packer drains/remounts
		 * this item and recursively enters a newly constructed cursor cache. */
		if (item->activeEnumerations == NTFS_DIRECTORY_CONTINUATIONS) {
			return ntfs_error(NTFS_BUSY);
		}
		item->activeEnumerations++;
		@try {
			operationEpoch = item->continuationEpoch;
			requestedPosition = cookie & ~namesOnlyCookieTag;
			maximumPosition = (uint64_t)_maximumDirectoryEntries +
			    (attributes ? 0 : NTFS_DIRECTORY_VIRTUAL_ENTRIES);
			if ((cookie != FSDirectoryCookieInitial &&
				verifier != _directoryVerifier) ||
			    (attributes && (cookie & namesOnlyCookieTag) != 0) ||
			    (!attributes && cookie != FSDirectoryCookieInitial &&
				(cookie & namesOnlyCookieTag) == 0) ||
			    cookie == namesOnlyCookieTag || requestedPosition > maximumPosition) {
				return invalid_directory_cookie();
			}
			if (!attributes) {
				while (requestedPosition < NTFS_DIRECTORY_VIRTUAL_ENTRIES) {
					result = [self admissionResult];
					if (result == NTFS_OK &&
					    operationEpoch != item->continuationEpoch) {
						result = NTFS_STALE;
					}
					if (result != NTFS_OK) {
						return ntfs_error(result);
					}
					name = [FSFileName nameWithString:requestedPosition ==
						    NTFS_DIRECTORY_CURRENT_ENTRY
						? @"."
						: @".."];
					reference =
					    requestedPosition == NTFS_DIRECTORY_CURRENT_ENTRY
					    ? item->stat.reference
					    : item->parentReference;
					packed = [packer packEntryWithName:name
								  itemType:FSItemTypeDirectory
								    itemID:item_id(reference)
								nextCookie:namesOnlyCookieTag |
					    (requestedPosition + 1)
								attributes:nil];
					result = [self admissionResult];
					if (result == NTFS_OK &&
					    operationEpoch != item->continuationEpoch) {
						result = NTFS_STALE;
					}
					if (result != NTFS_OK) {
						return ntfs_error(result);
					}
					if (!packed) {
						return nil;
					}
					requestedPosition++;
				}
				requestedPosition -= NTFS_DIRECTORY_VIRTUAL_ENTRIES;
			}
			result =
			    [self directoryContinuationForItem:item
						      position:requestedPosition
						    attributes:attributes
						       initial:cookie == FSDirectoryCookieInitial
						  continuation:&continuation];
			if (result != NTFS_OK) {
				return ntfs_error(result);
			}
			continuations = item->continuations;
			/* The C pointer lives in this precisely retained bridge, including
			 * when a packer detaches it from the item during native teardown. */
			(void)continuations;
			if (continuation->failure != NTFS_OK) {
				return ntfs_error(continuation->failure);
			}
			for (;;) {
				if (!continuation->pending) {
					result = ntfs_directory_next(
					    continuation->cursor, &continuation->pending_entry);
					if (result == NTFS_END) {
						continuation->complete = YES;
						result = [self admissionResult];
						if (result == NTFS_OK &&
						    operationEpoch != item->continuationEpoch) {
							result = NTFS_STALE;
						}
						if (result != NTFS_OK) {
							return ntfs_error(result);
						}
						return continuation->position < requestedPosition
						    ? invalid_directory_cookie()
						    : nil;
					}
					if (result != NTFS_OK) {
						return ntfs_error(result);
					}
					if (continuation->inspected_entries++ ==
					    _maximumDirectoryEntries) {
						continuation->failure = NTFS_RANGE;
						return ntfs_error(NTFS_RANGE);
					}
					if (!ntfs_native_entry_visible(
						&continuation->pending_entry)) {
						continue;
					}
					continuation->pending = YES;
				}
				if (continuation->position < requestedPosition) {
					continuation->pending = NO;
					continuation->position++;
					continue;
				}
				result = ntfs_native_entry_name(&continuation->pending_entry,
				    (uint32_t)continuation->position, &name, &projected);
				if (result != NTFS_OK) {
					return ntfs_error(result);
				}
				attrs = nil;
				/* The index's cached attributes cannot distinguish a native link
				 * from opaque provider data. Classify checked base metadata in both
				 * views; only the attribute-requested view requires complete sizes.
				 */
				{
					result = ntfs_node_open(
					    _core, continuation->pending_entry.reference, &node);
					if (result != NTFS_OK) {
						return ntfs_error(result);
					}
					result = ntfs_node_metadata(node, &stat);
					if (result == NTFS_OK && attributes && !stat.reparse) {
						result = ntfs_node_stat(node, &stat);
					}
					if (result == NTFS_OK && attributes) {
						result = ntfs_node_link_counts(node, &links);
					}
					type = FSItemTypeUnknown;
					if (result == NTFS_OK && stat.reparse) {
						result = ntfs_reparse_open(node, &snapshot);
						if (result == NTFS_OK) {
							ntfs_reparse_get_info(
							    snapshot, &reparseInfo);
							if (reparseInfo.kind ==
								NTFS_REPARSE_SYMLINK ||
							    reparseInfo.kind ==
								NTFS_REPARSE_MOUNT_POINT) {
								type = FSItemTypeSymlink;
							}
							if (reparseInfo.kind == NTFS_REPARSE_WOF) {
								result = ntfs_reparse_wof_info(
								    snapshot, &wofInfo);
								if (result == NTFS_OK &&
								    stat.directory) {
									result = NTFS_CORRUPT;
								}
								if (result == NTFS_OK) {
									type = FSItemTypeFile;
									if (attributes) {
										result =
										    ntfs_node_stat(
											node,
											&stat);
									}
								}
							} else if (attributes) {
								result = links.primary_names != 1
								    ? NTFS_UNSUPPORTED
								    : ntfs_native_link_target(_core,
									  snapshot, stat.reference,
									  item->directoryPath,
									  _linkPolicy,
									  _maximumDirectoryEntries,
									  &target);
								if (result == NTFS_OK) {
									stat.size =
									    target.data.length;
									stat.allocated_size =
									    ntfs_reparse_allocated_size(
										snapshot);
								}
							}
						}
						if (!attributes &&
						    (result == NTFS_UNSUPPORTED ||
							result == NTFS_RANGE)) {
							result = NTFS_OK;
						}
					} else if (result == NTFS_OK) {
						type = stat.directory ? FSItemTypeDirectory
								      : FSItemTypeFile;
					}
					ntfs_reparse_close(snapshot);
					snapshot = NULL;
					ntfs_node_close(node);
					node = NULL;
					if (result != NTFS_OK) {
						return ntfs_error(result);
					}
					if (attributes) {
						attrs = [self
						    attributesForStat:&stat
							   linkCounts:&links
							 symbolicLink:type == FSItemTypeSymlink];
					}
				}
				result = [self admissionResult];
				if (result == NTFS_OK &&
				    operationEpoch != item->continuationEpoch) {
					result = NTFS_STALE;
				}
				if (result != NTFS_OK) {
					return ntfs_error(result);
				}
				packed = [packer
				    packEntryWithName:name
					     itemType:type
					       itemID:item_id(continuation->pending_entry.reference)
					   nextCookie:directory_cookie(
							  continuation->position + 1, attributes)
					   attributes:attrs];
				result = [self admissionResult];
				if (result == NTFS_OK &&
				    operationEpoch != item->continuationEpoch) {
					result = NTFS_STALE;
				}
				if (result != NTFS_OK) {
					return ntfs_error(result);
				}
				if (!packed) {
					return nil;
				}
				continuation->position++;
				continuation->pending = NO;
			}
		} @finally {
			if (continuation != NULL) {
				continuation->in_use = NO;
			}
			[self finishReadCaches:item];
			item->activeEnumerations--;
		}
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
		result = [self ensureImageView];
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
			result = ntfs_native_access_mode(options.taskOptions, &requested);
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

	[self performItemPublication:^{
	  NTFSItem *item;

	  @synchronized(self) {
		  if (self->_imageMutationActive) {
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
	if (deferred) {
		/* A reentrant unmount cannot wait on its own mutation. A different
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
	s.availableBlocks = 0;
	s.usedBlocks = s.totalBlocks - s.freeBlocks;
	s.totalBytes = s.totalBlocks * _info.cluster_size;
	s.freeBytes = s.freeBlocks * _info.cluster_size;
	s.usedBytes = s.usedBlocks * _info.cluster_size;
	s.availableBytes = 0;
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
