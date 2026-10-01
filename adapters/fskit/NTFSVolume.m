/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSVolume.h"
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>

enum {
	NTFS_FSKIT_ITEM_LIMIT = 16384,
	NTFS_FSKIT_DIRECTORY_COOKIE_LIMIT = 1048576,
	NTFS_READ_ONLY_FILE_MODE = S_IRUSR,
	NTFS_READ_ONLY_DIRECTORY_MODE = S_IRUSR | S_IXUSR
};

@interface NTFSItem : FSItem {
      @public
	struct ntfs_node *node;
	struct ntfs_stream *stream;
	struct ntfs_directory *cursor;
	struct ntfs_dirent pendingEntry;
	BOOL pending;
	uint64_t position;
	struct ntfs_stat stat;
}
@property(weak) NTFSVolume *owner;
@end
@implementation NTFSItem
@end

static FSItemID
item_id(uint64_t reference)
{
	return (reference & NTFS_REFERENCE_RECORD_MASK) == NTFS_ROOT_RECORD ? FSItemIDRootDirectory
									    : (FSItemID)reference;
}

static BOOL
visible(const struct ntfs_dirent *entry)
{
	return (entry->reference & NTFS_REFERENCE_RECORD_MASK) >= NTFS_FIRST_USER_RECORD &&
	    entry->name_namespace != NTFS_NAMESPACE_DOS;
}

@implementation NTFSVolume {
	struct ntfs_volume *_core;
	struct ntfs_info _info;
	NTFSResource *_resource;
	NSMutableDictionary<NSNumber *, NTFSItem *> *_items;
	FSDirectoryVerifier _directoryVerifier;
	uint64_t _freeClusters;
	BOOL _active;
}

- (instancetype)initWithCore:(struct ntfs_volume *)core resource:(NTFSResource *)resource
{
	struct ntfs_info info;
	uint64_t freeClusters;
	NSString *label;

	ntfs_get_info(core, &info);
	if (ntfs_count_free_clusters(core, &freeClusters) != NTFS_OK) {
		return nil;
	}
	label = [NSString stringWithUTF8String:info.label];
	self = [super
	    initWithVolumeID:[[FSVolumeIdentifier alloc] initWithUUID:ntfs_uuid(info.serial)]
		  volumeName:[FSFileName nameWithString:label.length != 0 ? label : @"NTFS"]];
	if (self != nil) {
		_core = core;
		_info = info;
		_resource = resource;
		_freeClusters = freeClusters;
		_items = [NSMutableDictionary dictionary];
		_directoryVerifier =
		    ((uint64_t)arc4random() << (sizeof(uint32_t) * CHAR_BIT)) | arc4random() | 1;
	}
	return self;
}

- (void)dealloc
{
	[self invalidate];
}

- (void)releaseItem:(NTFSItem *)item
{
	ntfs_directory_close(item->cursor);
	item->cursor = NULL;
	ntfs_stream_close(item->stream);
	item->stream = NULL;
	ntfs_node_close(item->node);
	item->node = NULL;
	item.owner = nil;
}

- (void)invalidate
{
	enum ntfs_result result;

	@synchronized(self) {
		for (NTFSItem *item in _items.allValues) {
			[self releaseItem:item];
		}
		[_items removeAllObjects];
		if (_core != NULL) {
			result = ntfs_unmount(_core);
			NSAssert(result == NTFS_OK, @"NTFS object leak");
			if (result == NTFS_OK) {
				_core = NULL;
			}
		}
		_active = NO;
		_resource = nil;
	}
}

- (NTFSItem *)checkedItem:(FSItem *)item
{
	NTFSItem *value;

	if (_core == NULL || !_active || ![item isKindOfClass:NTFSItem.class]) {
		return nil;
	}
	value = (NTFSItem *)item;
	return value.owner == self && value->node != NULL ? value : nil;
}

- (enum ntfs_result)admissionResult
{
	if (_core == NULL || !_active) {
		return NTFS_STALE;
	}
	return _resource.isAvailable ? NTFS_OK : NTFS_IO;
}

- (NTFSItem *)adoptNode:(struct ntfs_node *)node error:(NSError **)error
{
	struct ntfs_stat stat;
	enum ntfs_result result;
	NTFSItem *item;

	result = ntfs_node_stat(node, &stat);
	if (result != NTFS_OK) {
		ntfs_node_close(node);
		*error = ntfs_error(result);
		return nil;
	}
	if (stat.reparse) {
		ntfs_node_close(node);
		*error = ntfs_error(NTFS_UNSUPPORTED);
		return nil;
	}
	item = _items[@(stat.reference)];
	if (item != nil) {
		ntfs_node_close(node);
		return item;
	}
	if (_items.count >= NTFS_FSKIT_ITEM_LIMIT) {
		ntfs_node_close(node);
		*error = ntfs_error(NTFS_NO_MEMORY);
		return nil;
	}
	item = [[NTFSItem alloc] init];
	item->node = node;
	item->stat = stat;
	item.owner = self;
	_items[@(stat.reference)] = item;
	return item;
}

- (FSItem *)activate:(NSError **)error
{
	struct ntfs_node *root = NULL;
	enum ntfs_result result;
	NTFSItem *item;

	*error = nil;
	@synchronized(self) {
		if (_core == NULL) {
			*error = ntfs_error(NTFS_STALE);
			return nil;
		}
		if (!_resource.isAvailable) {
			*error = ntfs_error(NTFS_IO);
			return nil;
		}
		result = ntfs_root(_core, &root);
		if (result != NTFS_OK) {
			*error = ntfs_error(result);
			return nil;
		}
		item = [self adoptNode:root error:error];
		_active = item != nil;
		return item;
	}
}

- (FSItem *)lookup:(FSFileName *)name
       inDirectory:(FSItem *)directory
	storedName:(FSFileName **)stored
	     error:(NSError **)error
{
	uint16_t units[NTFS_NAME_MAX];
	size_t length;
	struct ntfs_node *node = NULL;
	struct ntfs_dirent entry;
	enum ntfs_result result;
	NTFSItem *parent;

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
			*error = ntfs_error(NTFS_STALE);
			return nil;
		}
		result = ntfs_utf8_to_utf16(
		    name.data.bytes, name.data.length, units, NTFS_NAME_MAX, &length);
		if (result == NTFS_OK) {
			result = ntfs_lookup_entry(parent->node, units, length, &node, &entry);
		}
		if (result == NTFS_OK && !visible(&entry)) {
			result = NTFS_NOT_FOUND;
		}
		if (result != NTFS_OK) {
			ntfs_node_close(node);
			*error = ntfs_error(result);
			return nil;
		}
		*stored = ntfs_filename(entry.name, entry.name_length);
		if (*stored == nil) {
			ntfs_node_close(node);
			*error = ntfs_error(NTFS_UNSUPPORTED);
			return nil;
		}
		return [self adoptNode:node error:error];
	}
}

- (FSItemAttributes *)attributes:(FSItem *)item error:(NSError **)error
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
			*error = ntfs_error(NTFS_STALE);
			return nil;
		}
		return [self attributesForStat:&value->stat];
	}
}

- (FSItemAttributes *)attributesForStat:(const struct ntfs_stat *)stat
{
	FSItemAttributes *attrs = [[FSItemAttributes alloc] init];

	/* Explicit single-user read-only presentation. Windows ACL
	 * translation is a separate, unaccepted contract. */
	attrs.uid = geteuid();
	attrs.gid = getegid();
	attrs.mode = stat->directory ? NTFS_READ_ONLY_DIRECTORY_MODE : NTFS_READ_ONLY_FILE_MODE;
	attrs.type = stat->directory ? FSItemTypeDirectory : FSItemTypeFile;
	attrs.fileID = item_id(stat->reference);
	attrs.linkCount = stat->links;
	attrs.size = stat->size;
	attrs.allocSize = stat->allocated_size;
	attrs.inhibitKernelOffloadedIO = YES;
	attrs.birthTime = (struct timespec){stat->created.seconds, stat->created.nanoseconds};
	attrs.modifyTime = (struct timespec){stat->modified.seconds, stat->modified.nanoseconds};
	attrs.changeTime = (struct timespec){stat->changed.seconds, stat->changed.nanoseconds};
	attrs.accessTime = (struct timespec){stat->accessed.seconds, stat->accessed.nanoseconds};
	return attrs;
}

- (enum ntfs_result)readItem:(FSItem *)item
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
			return NTFS_STALE;
		}
		if (offset < 0) {
			return NTFS_INVALID;
		}
		if (value->stream == NULL) {
			result = ntfs_stream_open(value->node, NULL, 0, &value->stream);
		}
		if (result == NTFS_OK) {
			result = ntfs_stream_read(
			    value->stream, (uint64_t)offset, bytes, length, completed);
		}
		if (result == NTFS_OK && !_resource.isAvailable) {
			*completed = 0;
			result = NTFS_IO;
		}
		return result;
	}
}

- (NSError *)enumerate:(FSItem *)directory
		cookie:(FSDirectoryCookie)cookie
	      verifier:(FSDirectoryVerifier)verifier
	    attributes:(BOOL)attributes
		packer:(FSDirectoryEntryPacker *)packer
{
	NTFSItem *item;
	struct ntfs_node *node = NULL;
	struct ntfs_stat stat;
	FSFileName *name;
	FSItemAttributes *attrs;
	enum ntfs_result result;

	@synchronized(self) {
		result = [self admissionResult];
		if (result != NTFS_OK) {
			return ntfs_error(result);
		}
		item = [self checkedItem:directory];
		if (item == nil) {
			return ntfs_error(NTFS_STALE);
		}
		if (cookie > NTFS_FSKIT_DIRECTORY_COOKIE_LIMIT ||
		    (cookie != 0 && verifier != _directoryVerifier)) {
			return ntfs_error(NTFS_INVALID);
		}
		if (cookie == 0 || item->cursor == NULL || item->position != cookie) {
			ntfs_directory_close(item->cursor);
			item->cursor = NULL;
			item->position = 0;
			item->pending = NO;
			result = ntfs_directory_open(item->node, &item->cursor);
			if (result != NTFS_OK) {
				return ntfs_error(result);
			}
		}
		for (;;) {
			if (!item->pending) {
				result = ntfs_directory_next(item->cursor, &item->pendingEntry);
				if (result == NTFS_END) {
					return item->position < cookie ? ntfs_error(NTFS_INVALID)
								       : nil;
				}
				if (result != NTFS_OK) {
					return ntfs_error(result);
				}
				if (!visible(&item->pendingEntry)) {
					continue;
				}
				item->pending = YES;
			}
			if (item->position < cookie) {
				item->pending = NO;
				item->position++;
				continue;
			}
			name =
			    ntfs_filename(item->pendingEntry.name, item->pendingEntry.name_length);
			if (name == nil) {
				return ntfs_error(NTFS_UNSUPPORTED);
			}
			attrs = nil;
			if (attributes) {
				result = ntfs_node_open(_core, item->pendingEntry.reference, &node);
				if (result != NTFS_OK) {
					return ntfs_error(result);
				}
				result = ntfs_node_stat(node, &stat);
				ntfs_node_close(node);
				node = NULL;
				if (result != NTFS_OK) {
					return ntfs_error(result);
				}
				if (stat.reparse) {
					return ntfs_error(NTFS_UNSUPPORTED);
				}
				attrs = [self attributesForStat:&stat];
			}
			if (![packer packEntryWithName:name
					      itemType:(item->pendingEntry.file_attributes &
							   NTFS_FILE_ATTRIBUTE_DIRECTORY)
				    ? FSItemTypeDirectory
				    : FSItemTypeFile
						itemID:item_id(item->pendingEntry.reference)
					    nextCookie:item->position + 1
					    attributes:attrs]) {
				return nil;
			}
			item->position++;
			item->pending = NO;
		}
	}
}

- (FSDirectoryVerifier)directoryVerifier
{
	return _directoryVerifier;
}

- (void)reclaimItem:(FSItem *)item replyHandler:(void (^)(NSError *))reply
{
	NTFSItem *value;
	NSError *error = nil;

	@synchronized(self) {
		value = [self checkedItem:item];
		if (value == nil) {
			error = ntfs_error(NTFS_STALE);
		} else {
			[_items removeObjectForKey:@(value->stat.reference)];
			[self releaseItem:value];
		}
	}
	reply(error);
}

- (void)mountWithOptions:(FSTaskOptions *)options replyHandler:(void (^)(NSError *))reply
{
	NSError *error;

	(void)options;
	@synchronized(self) {
		error = ntfs_error([self admissionResult]);
	}
	reply(error);
}

- (void)unmountWithReplyHandler:(void (^)(void))reply
{
	reply();
}

- (void)synchronizeWithFlags:(FSSyncFlags)flags replyHandler:(void (^)(NSError *))reply
{
	NSError *error;

	(void)flags;
	@synchronized(self) {
		error = ntfs_error(_core == NULL ? NTFS_STALE
			: _resource.isAvailable	 ? NTFS_OK
						 : NTFS_IO);
	}
	reply(error);
}

- (FSMountOptions)requestedMountOptions
{
	return FSMountOptionsReadOnly;
}

- (FSVolumeSupportedCapabilities *)supportedVolumeCapabilities
{
	FSVolumeSupportedCapabilities *caps = [[FSVolumeSupportedCapabilities alloc] init];

	caps.supportsPersistentObjectIDs = YES;
	caps.supports64BitObjectIDs = YES;
	caps.supportsSparseFiles = YES;
	caps.supportsZeroRuns = YES;
	caps.supportsFastStatFS = YES;
	caps.supports2TBFiles = YES;
	caps.doesNotSupportSettingFilePermissions = YES;
	caps.caseFormat = FSVolumeCaseFormatInsensitiveCasePreserving;
	return caps;
}

- (FSStatFSResult *)volumeStatistics
{
	FSStatFSResult *s = [[FSStatFSResult alloc] initWithFileSystemTypeName:@"machlinntfs"];

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
	return NTFS_UTF8_NAME_MAX;
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
	return 0;
}

- (NSInteger)maximumXattrSizeInBits
{
	return 0;
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
