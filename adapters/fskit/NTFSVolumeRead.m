/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSVolumeInternal.h"
#include <errno.h>
#include <limits.h>
#include <ntfs/wof.h>
#include <string.h>

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

@implementation NTFSVolume (ReadOperations)

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
	if (_nativeImageEditing && !link &&
	    (image_file_write_type(stat) || image_directory_write_type(stat))) {
		attrs.mode |= S_IWUSR;
		attrs.flags = 0;
	}
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

@end
