/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSVolumeInternal.h"
#include <ntfs/wof.h>
#include <string.h>

static void
native_directory_continuation_close(struct ntfs_directory_continuation *continuation)
{
	ntfs_directory_close(continuation->cursor);
	memset(continuation, 0, sizeof(*continuation));
}

/* Allocate only for enumerated directories, through the same bounded allocator
 * as the core. An in-flight native call retains this bridge across teardown;
 * clear closes its core children before the mounted owner can be released. */
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
			native_directory_continuation_close(&states[i]);
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

@implementation NTFSItem

- (void)dealloc
{
	__attribute__((objc_precise_lifetime)) NTFSVolume *owner = _owner;

	[owner releaseUnreferencedItem:self];
}

@end

@implementation NTFSVolume (ItemStorage)

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
				native_directory_continuation_close(&continuations->states[i]);
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
		native_directory_continuation_close(selected);
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
	item->nativeOpenModes = 0;
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

- (NTFSItem *)checkedItem:(FSItem *)item
{
	NTFSItem *value;

	_itemAdmission = NTFS_STALE;
	if (_core == NULL || !_active || ![item isKindOfClass:NTFSItem.class]) {
		return nil;
	}
	value = (NTFSItem *)item;
	if (value.owner != self || value->retired) {
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

	/* Complete sequence references survive ordinary mutations. Ancestry tokens
	 * are prepared before namespace publication and rebound to this exact fresh
	 * core epoch. Retired identities can never reopen reused FILE storage. */
	result = ntfs_node_open(_core, item->stat.reference, &node);
	if (result != NTFS_OK) {
		goto done;
	}
	result = ntfs_node_metadata(node, &stat);
	if (result != NTFS_OK) {
		goto done;
	}
	if (stat.directory != item->stat.directory || stat.reparse != item->stat.reparse) {
		result = NTFS_STALE;
		goto done;
	}
	if (!stat.reparse || item->wof) {
		result = ntfs_node_stat(node, &stat);
		if (result != NTFS_OK) {
			goto done;
		}
	}
	result = ntfs_node_link_counts(node, &links);
	if (result != NTFS_OK) {
		goto done;
	}
	if (item->directoryPath != nil) {
		path = [self rebindImagePath:item->directoryPath result:&result];
		if (result != NTFS_OK) {
			goto done;
		}
	}
	if (item->linkTarget != nil) {
		stat.size = item->stat.size;
		stat.allocated_size = item->stat.allocated_size;
	}
	item->node = node;
	item->stat = stat;
	item->links = links;
	item->directoryPath = path;
	return result;

done:
	ntfs_node_close(node);
	return result;
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

@end
