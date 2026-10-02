/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSLinks.h"
#include <string.h>

static NSString *const volumePrefix = @"Volume{";
static NSString *const rootOptionPrefix = @"windows-root=";
static const char ntPrefix[] = "\\??\\";
static const char win32Prefix[] = "\\\\?\\";

static NSString *
canonical_root(NSString *root)
{
	NSString *guid;
	NSUUID *uuid;
	unichar letter;

	if (root.length == sizeof("C:") - 1 && [root characterAtIndex:root.length - 1] == ':') {
		letter = [root characterAtIndex:0];
		if ((letter >= 'A' && letter <= 'Z') || (letter >= 'a' && letter <= 'z')) {
			return root.uppercaseString;
		}
		return nil;
	}
	if (root.length <= volumePrefix.length ||
	    ![root.lowercaseString hasPrefix:volumePrefix.lowercaseString] ||
	    ![root hasSuffix:@"}"]) {
		return nil;
	}
	guid = [root substringWithRange:NSMakeRange(volumePrefix.length,
					    root.length - volumePrefix.length - 1)];
	uuid = [[NSUUID alloc] initWithUUIDString:guid];
	if (uuid == nil ||
	    ![guid.lowercaseString isEqualToString:uuid.UUIDString.lowercaseString]) {
		return nil;
	}
	return
	    [[NSString stringWithFormat:@"%@%@}", volumePrefix, uuid.UUIDString] uppercaseString];
}

@implementation NTFSLinkPolicy

- (instancetype)initWithVolumeSerial:(uint64_t)serial windowsRoots:(NSArray<NSString *> *)roots
{
	NSMutableArray<NSString *> *canonical = [NSMutableArray array];
	NSString *root, *value;

	if (roots.count > NTFS_FSKIT_WINDOWS_ROOT_LIMIT) {
		return nil;
	}
	for (root in roots) {
		if (![root isKindOfClass:NSString.class]) {
			return nil;
		}
		value = canonical_root(root);
		if (value == nil || [canonical containsObject:value]) {
			return nil;
		}
		[canonical addObject:value];
	}
	self = [super init];
	if (self != nil) {
		_volumeSerial = serial;
		_windowsRoots = [canonical copy];
	}
	return self;
}

- (BOOL)ownsWindowsRoot:(NSString *)root
{
	NSString *value = canonical_root(root);

	return value != nil && [_windowsRoots containsObject:value];
}

@end

@implementation NTFSDirectoryPath

- (instancetype)initWithVolume:(struct ntfs_volume *)volume
		     reference:(uint64_t)reference
			parent:(NTFSDirectoryPath *)parent
{
	NTFSDirectoryPath *ancestor;

	if (volume == NULL || reference >> NTFS_REFERENCE_SEQUENCE_SHIFT == 0 ||
	    (parent == nil && (reference & NTFS_REFERENCE_RECORD_MASK) != NTFS_ROOT_RECORD) ||
	    (parent != nil &&
		(parent.volume != volume || parent.depth >= NTFS_FSKIT_LINK_COMPONENT_LIMIT))) {
		return nil;
	}
	for (ancestor = parent; ancestor != nil; ancestor = ancestor.parent) {
		if (ancestor.reference == reference) {
			return nil;
		}
	}
	self = [super init];
	if (self != nil) {
		_volume = volume;
		_reference = reference;
		_parent = parent;
		_depth = parent == nil ? 0 : parent.depth + 1;
	}
	return self;
}

@end

enum ntfs_result
ntfs_native_link_policy(uint64_t serial, NSArray<NSString *> *options, NTFSLinkPolicy **out)
{
	NSMutableArray<NSString *> *roots = [NSMutableArray array];
	NSString *option, *part;
	NTFSLinkPolicy *policy;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	*out = nil;
	if (options.count > NTFS_FSKIT_OPTION_LIMIT) {
		return NTFS_RANGE;
	}
	for (option in options) {
		if (![option isKindOfClass:NSString.class] || option.length > PATH_MAX) {
			return NTFS_INVALID;
		}
		for (part in [option componentsSeparatedByString:@","]) {
			if ([part hasPrefix:rootOptionPrefix]) {
				if (roots.count == NTFS_FSKIT_WINDOWS_ROOT_LIMIT) {
					return NTFS_RANGE;
				}
				[roots addObject:[part substringFromIndex:rootOptionPrefix.length]];
			} else if ([part isEqualToString:@"windows-root"]) {
				return NTFS_INVALID;
			}
		}
	}
	policy = [[NTFSLinkPolicy alloc] initWithVolumeSerial:serial windowsRoots:roots];
	if (policy == nil) {
		return NTFS_INVALID;
	}
	*out = policy;
	return NTFS_OK;
}

static BOOL
separator(uint16_t unit)
{
	return unit == '\\' || unit == '/';
}

static BOOL
prefix_matches(const uint16_t *units, size_t count, const char *prefix, size_t length)
{
	size_t i;

	if (count < length) {
		return NO;
	}
	for (i = 0; i < length; i++) {
		if (units[i] != (uint8_t)prefix[i]) {
			return NO;
		}
	}
	return YES;
}

static enum ntfs_result
append_component(NSMutableData *output, FSFileName *component)
{
	static const uint8_t slash = '/';
	size_t prefix = output.length != 0 ? sizeof(slash) : 0;

	if (component.data.length > NTFS_FSKIT_LINK_TARGET_BYTES - output.length ||
	    prefix > NTFS_FSKIT_LINK_TARGET_BYTES - output.length - component.data.length) {
		return NTFS_RANGE;
	}
	if (prefix != 0) {
		[output appendBytes:&slash length:sizeof(slash)];
	}
	[output appendData:component.data];
	return NTFS_OK;
}

static enum ntfs_result
plain_component(const uint16_t *units, size_t count, FSFileName **out)
{
	struct ntfs_dirent entry = {0};
	BOOL projected;
	enum ntfs_result result;

	if (count == 0 || count > NTFS_NAME_MAX) {
		return NTFS_UNSUPPORTED;
	}
	entry.name_length = (uint16_t)count;
	memcpy(entry.name, units, count * sizeof(*units));
	result = ntfs_native_entry_name(&entry, 0, out, &projected);
	return result == NTFS_OK && projected ? NTFS_UNSUPPORTED : result;
}

static BOOL
same_entry(const struct ntfs_dirent *a, const struct ntfs_dirent *b)
{
	return a->reference == b->reference && a->name_namespace == b->name_namespace &&
	    a->name_length == b->name_length &&
	    memcmp(a->name, b->name, (size_t)a->name_length * sizeof(a->name[0])) == 0;
}

static enum ntfs_result
target_entry_name(struct ntfs_node *parent, const struct ntfs_dirent *target, uint32_t *remaining,
    FSFileName **out)
{
	struct ntfs_directory *cursor = NULL;
	struct ntfs_dirent entry;
	uint32_t ordinal = 0;
	BOOL projected, dos = target->name_namespace == NTFS_NAMESPACE_DOS;
	enum ntfs_result result;

	if (ntfs_native_entry_visible(target)) {
		result = ntfs_native_entry_name(target, 0, out, &projected);
		if (result != NTFS_OK || !projected) {
			return result;
		}
	} else if (!dos) {
		return NTFS_UNSUPPORTED;
	}
	*out = nil;
	result = ntfs_directory_open(parent, &cursor);
	while (result == NTFS_OK && (result = ntfs_directory_next(cursor, &entry)) == NTFS_OK) {
		if (*remaining == 0) {
			result = NTFS_RANGE;
			break;
		}
		(*remaining)--;
		if (!ntfs_native_entry_visible(&entry)) {
			continue;
		}
		if (dos ? entry.reference == target->reference : same_entry(&entry, target)) {
			result = ntfs_native_entry_name(&entry, ordinal, out, &projected);
			break;
		}
		ordinal++;
	}
	ntfs_directory_close(cursor);
	return result == NTFS_END ? NTFS_UNSUPPORTED : result;
}

enum ntfs_result
ntfs_native_link_target(struct ntfs_volume *volume, const struct ntfs_reparse *snapshot,
    NTFSDirectoryPath *source, NTFSLinkPolicy *policy, uint32_t maximum, FSFileName **out)
{
	struct ntfs_reparse_info info;
	struct ntfs_info volumeInfo;
	struct ntfs_node *parent = NULL, *child = NULL;
	struct ntfs_dirent entry;
	struct ntfs_stat stat;
	NSMutableData *raw, *output = [NSMutableData data];
	const uint16_t *units;
	NTFSDirectoryPath *path = source, *root;
	FSFileName *name;
	NSString *windowsRoot;
	size_t count, position = 0, start, length, i;
	NSUInteger depth, components = 0;
	uint32_t remaining = maximum;
	BOOL fromRoot = NO, dangling = NO, last, relative;
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	*out = nil;
	if (volume == NULL || snapshot == NULL || source == nil || source.volume != volume ||
	    policy == nil || maximum == 0 || maximum > NTFS_FSKIT_DIRECTORY_ENTRY_LIMIT) {
		return NTFS_INVALID;
	}
	ntfs_get_info(volume, &volumeInfo);
	if (policy.volumeSerial != volumeInfo.serial) {
		return NTFS_INVALID;
	}
	ntfs_reparse_get_info(snapshot, &info);
	if (info.kind != NTFS_REPARSE_SYMLINK && info.kind != NTFS_REPARSE_MOUNT_POINT) {
		return NTFS_UNSUPPORTED;
	}
	count = info.substitute_length;
	raw = [NSMutableData dataWithLength:count * sizeof(uint16_t)];
	result = ntfs_reparse_name(
	    snapshot, NTFS_REPARSE_SUBSTITUTE_NAME, raw.mutableBytes, count, &length);
	if (result != NTFS_OK) {
		return result;
	}
	units = raw.bytes;
	relative =
	    info.kind == NTFS_REPARSE_SYMLINK && (info.flags & NTFS_REPARSE_SYMLINK_RELATIVE) != 0;
	if (relative) {
		if (separator(units[0])) {
			if (count > 1 && separator(units[1])) {
				return NTFS_UNSUPPORTED;
			}
			fromRoot = YES;
			position++;
		}
	} else {
		if (prefix_matches(units, count, ntPrefix, sizeof(ntPrefix) - 1)) {
			position = sizeof(ntPrefix) - 1;
		} else if (prefix_matches(units, count, win32Prefix, sizeof(win32Prefix) - 1)) {
			position = sizeof(win32Prefix) - 1;
		}
		start = position;
		while (position < count && !separator(units[position])) {
			position++;
		}
		if (position == count || position == start) {
			return NTFS_UNSUPPORTED;
		}
		windowsRoot = [[NSString alloc] initWithCharacters:units + start
							    length:position - start];
		if (![policy ownsWindowsRoot:windowsRoot]) {
			return NTFS_UNSUPPORTED;
		}
		position++;
		fromRoot = YES;
	}
	root = source;
	while (root.parent != nil) {
		root = root.parent;
	}
	if (fromRoot) {
		for (i = 0; i < source.depth; i++) {
			result = append_component(output, [FSFileName nameWithString:@".."]);
			if (result != NTFS_OK) {
				return result;
			}
		}
		path = root;
	}
	depth = path.depth;
	result = NTFS_OK;
	while (position < count) {
		while (position < count && separator(units[position])) {
			position++;
		}
		if (position == count) {
			break;
		}
		if (++components > NTFS_FSKIT_LINK_COMPONENT_LIMIT) {
			result = NTFS_RANGE;
			break;
		}
		start = position;
		while (position < count && !separator(units[position])) {
			if (units[position] == ':') {
				result = NTFS_UNSUPPORTED;
				goto finish;
			}
			position++;
		}
		length = position - start;
		if (length > NTFS_NAME_MAX) {
			result = NTFS_UNSUPPORTED;
			break;
		}
		last = YES;
		for (i = position; i < count; i++) {
			if (!separator(units[i])) {
				last = NO;
				break;
			}
		}
		if (units[start] == '.' &&
		    (length == 1 || (length == 2 && units[start + 1] == '.'))) {
			if (length == 2) {
				if (depth == 0) {
					result = NTFS_UNSUPPORTED;
					break;
				}
				depth--;
				if (!dangling) {
					path = path.parent;
				}
			}
			name = [FSFileName nameWithString:length == 1 ? @"." : @".."];
		} else if (dangling) {
			result = plain_component(units + start, length, &name);
			depth++;
		} else {
			result = ntfs_node_open(volume, path.reference, &parent);
			if (result == NTFS_OK) {
				result = ntfs_lookup_entry(
				    parent, units + start, length, &child, &entry);
			}
			if (result == NTFS_NOT_FOUND) {
				result = plain_component(units + start, length, &name);
				dangling = YES;
				depth++;
			} else if (result == NTFS_OK) {
				result = target_entry_name(parent, &entry, &remaining, &name);
				if (result == NTFS_OK && !last) {
					result = ntfs_node_metadata(child, &stat);
					if (result == NTFS_OK && stat.reparse) {
						/* Translating beyond a filter-owned intermediary
						 * requires a separate checked reparse-resolution
						 * operation. */
						result = NTFS_UNSUPPORTED;
					} else if (result == NTFS_OK && !stat.directory) {
						result = NTFS_NOT_DIRECTORY;
					} else if (result == NTFS_OK &&
					    path.depth >= NTFS_FSKIT_LINK_COMPONENT_LIMIT) {
						result = NTFS_RANGE;
					} else if (result == NTFS_OK) {
						path = [[NTFSDirectoryPath alloc]
						    initWithVolume:volume
							 reference:entry.reference
							    parent:path];
						result = path == nil ? NTFS_CORRUPT : NTFS_OK;
						depth = path.depth;
					}
				}
			}
			ntfs_node_close(child);
			child = NULL;
			ntfs_node_close(parent);
			parent = NULL;
		}
		if (result != NTFS_OK) {
			break;
		}
		result = append_component(output, name);
		if (result != NTFS_OK) {
			break;
		}
	}
finish:
	ntfs_node_close(child);
	ntfs_node_close(parent);
	/* Keep the native directory requirement of a trailing separator. */
	if (result == NTFS_OK && separator(units[count - 1]) && output.length != 0) {
		static const uint8_t slash = '/';

		if (output.length == NTFS_FSKIT_LINK_TARGET_BYTES) {
			result = NTFS_RANGE;
		} else {
			[output appendBytes:&slash length:sizeof(slash)];
		}
	}
	if (result == NTFS_OK) {
		if (output.length == 0) {
			*out = [FSFileName nameWithString:@"."];
		} else {
			*out = [FSFileName nameWithData:output];
		}
	}
	return result;
}
