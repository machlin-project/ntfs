/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSVolume.h"
#import "NTFSNames.h"
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <string.h>

enum {
	NTFS_FSKIT_ITEM_LIMIT = 16384,
	NTFS_FSKIT_STREAM_LIMIT = 1024,
	NTFS_FSKIT_XATTR_SIZE_BITS = 20,
	NTFS_FSKIT_XATTR_BYTES = (1u << NTFS_FSKIT_XATTR_SIZE_BITS) - 1,
	NTFS_STREAM_MANIFEST_VERSION = 1,
	NTFS_HEX_DIGITS_PER_BYTE = 2,
	NTFS_HEX_NIBBLE_BITS = 4,
	NTFS_HEX_DECIMAL_DIGITS = 10,
	NTFS_STREAM_ALIAS_DIGITS = sizeof(uint32_t) * NTFS_HEX_DIGITS_PER_BYTE,
	NTFS_READ_ONLY_FILE_MODE = S_IRUSR,
	NTFS_READ_ONLY_DIRECTORY_MODE = S_IRUSR | S_IXUSR
};

static NSString *const streamManifestName = @"org.machlin.ntfs.streams";
static NSString *const streamAliasPrefix = @"org.machlin.ntfs.stream.";
static NSString *const namesManifestName = @"org.machlin.ntfs.names";
static NSString *const nameEntryPrefix = @"org.machlin.ntfs.name.";

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

@interface NTFSItem : FSItem {
      @public
	struct ntfs_node *node;
	struct ntfs_stream *stream;
	struct ntfs_directory *cursor;
	struct ntfs_stream_catalog *catalog;
	struct ntfs_dirent pendingEntry;
	BOOL pending;
	uint64_t position;
	uint32_t inspectedEntries;
	enum ntfs_result cursorFailure;
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

@implementation NTFSVolume {
	struct ntfs_volume *_core;
	struct ntfs_info _info;
	NTFSResource *_resource;
	NSMutableDictionary<NSNumber *, NTFSItem *> *_items;
	FSDirectoryVerifier _directoryVerifier;
	uint64_t _freeClusters;
	uint32_t _maximumDirectoryEntries;
	BOOL _active;
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
	struct ntfs_info info;
	uint64_t freeClusters;
	NSString *label;

	if (maximum == 0 || maximum > NTFS_FSKIT_DIRECTORY_ENTRY_LIMIT) {
		return nil;
	}
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
		_maximumDirectoryEntries = maximum;
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
	ntfs_stream_catalog_close(item->catalog);
	item->catalog = NULL;
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
	if (result == NTFS_OK && !_resource.isAvailable) {
		result = NTFS_IO;
	}
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
	uint64_t reference;
	uint32_t ordinal;
	BOOL projected;
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
		if (name.data.length > NTFS_FSKIT_NATIVE_NAME_BYTES) {
			*error = [NSError errorWithDomain:NSPOSIXErrorDomain
						     code:ENAMETOOLONG
						 userInfo:nil];
			return nil;
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
					if (result == NTFS_OK && !projected) {
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
		if (result == NTFS_OK && !_resource.isAvailable) {
			result = NTFS_IO;
		}
		if (result != NTFS_OK) {
			ntfs_node_close(node);
			*stored = nil;
			*error = ntfs_error(result);
			return nil;
		}
		parent = [self adoptNode:node error:error];
		if (parent == nil) {
			*stored = nil;
		}
		return parent;
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
	if (!_resource.isAvailable) {
		*error = ntfs_error(NTFS_IO);
		return NULL;
	}
	return item->catalog;
}

- (NSArray<FSFileName *> *)xattrsForItem:(FSItem *)item error:(NSError **)error
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
			*error = ntfs_error(NTFS_STALE);
			return nil;
		}
		catalog = [self catalogForItem:value error:error];
		if (catalog == NULL) {
			return nil;
		}
		names =
		    [NSMutableArray arrayWithObject:[FSFileName nameWithString:streamManifestName]];
		if (value->stat.directory) {
			[names addObject:[FSFileName nameWithString:namesManifestName]];
		}
		for (i = 0; i < ntfs_stream_catalog_count(catalog); i++) {
			result = ntfs_stream_catalog_entry(catalog, i, &name);
			if (result != NTFS_OK) {
				*error = ntfs_error(result);
				return nil;
			}
			if (name.length != 0) {
				[names addObject:stream_alias(i)];
			}
		}
		if (!_resource.isAvailable) {
			*error = ntfs_error(NTFS_IO);
			return nil;
		}
		return names;
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

- (NSData *)xattrNamed:(FSFileName *)name ofItem:(FSItem *)item error:(NSError **)error
{
	NTFSItem *value;
	struct ntfs_stream_catalog *catalog;
	struct ntfs_stream_name streamName;
	struct ntfs_stream *stream = NULL;
	NSMutableData *data = nil;
	NSData *manifest;
	uint64_t size;
	uint32_t index = 0;
	size_t completed = 0;
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
		if ([name.data isEqualToData:[FSFileName nameWithString:namesManifestName].data] ||
		    ordinal_xattr_index(name, nameEntryPrefix, &index)) {
			if (!value->stat.directory) {
				*error = [NSError errorWithDomain:NSPOSIXErrorDomain
							     code:ENOATTR
							 userInfo:nil];
				return nil;
			}
			result = ntfs_native_names_manifest(value->node, value->stat.reference,
			    _maximumDirectoryEntries,
			    ![name.data
				isEqualToData:[FSFileName nameWithString:namesManifestName].data],
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
			if (result == NTFS_OK && !_resource.isAvailable) {
				result = NTFS_IO;
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
		if ([name.data isEqualToData:[FSFileName nameWithString:streamManifestName].data]) {
			manifest = [self streamManifest:value catalog:catalog error:error];
			if (manifest != nil && !_resource.isAvailable) {
				*error = ntfs_error(NTFS_IO);
				return nil;
			}
			return manifest;
		}
		if (!ordinal_xattr_index(name, streamAliasPrefix, &index) ||
		    ntfs_stream_catalog_entry(catalog, index, &streamName) != NTFS_OK ||
		    streamName.length == 0) {
			*error = [NSError errorWithDomain:NSPOSIXErrorDomain
						     code:ENOATTR
						 userInfo:nil];
			return nil;
		}
		result =
		    ntfs_stream_open(value->node, streamName.units, streamName.length, &stream);
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
		if (result == NTFS_OK && !_resource.isAvailable) {
			result = NTFS_IO;
		}
		if (result != NTFS_OK) {
			*error = ntfs_error(result);
			return nil;
		}
		return data;
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
	BOOL projected;
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
		if (cookie > _maximumDirectoryEntries ||
		    (cookie != 0 && verifier != _directoryVerifier)) {
			return ntfs_error(NTFS_INVALID);
		}
		if (cookie == 0 || item->cursor == NULL || item->position != cookie) {
			ntfs_directory_close(item->cursor);
			item->cursor = NULL;
			item->position = 0;
			item->inspectedEntries = 0;
			item->cursorFailure = NTFS_OK;
			item->pending = NO;
			result = ntfs_directory_open(item->node, &item->cursor);
			if (result != NTFS_OK) {
				return ntfs_error(result);
			}
		}
		if (item->cursorFailure != NTFS_OK) {
			return ntfs_error(item->cursorFailure);
		}
		for (;;) {
			if (!item->pending) {
				result = ntfs_directory_next(item->cursor, &item->pendingEntry);
				if (result == NTFS_END) {
					if (!_resource.isAvailable) {
						return ntfs_error(NTFS_IO);
					}
					return item->position < cookie ? ntfs_error(NTFS_INVALID)
								       : nil;
				}
				if (result != NTFS_OK) {
					return ntfs_error(result);
				}
				if (item->inspectedEntries++ == _maximumDirectoryEntries) {
					item->cursorFailure = NTFS_RANGE;
					return ntfs_error(NTFS_RANGE);
				}
				if (!ntfs_native_entry_visible(&item->pendingEntry)) {
					continue;
				}
				item->pending = YES;
			}
			if (item->position < cookie) {
				item->pending = NO;
				item->position++;
				continue;
			}
			result = ntfs_native_entry_name(
			    &item->pendingEntry, (uint32_t)item->position, &name, &projected);
			if (result != NTFS_OK) {
				return ntfs_error(result);
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
			if (!_resource.isAvailable) {
				return ntfs_error(NTFS_IO);
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
