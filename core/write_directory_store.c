/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_mutation_internal.h"
#include <ntfs/record.h>

struct ntfs_mutation_index_builder {
	struct ntfs_write_mutation_plan *plan;
	struct ntfs_mutation_directory *directory;
	uint8_t **blocks;
	size_t count, capacity;
};

static size_t
mutation_index_entry_bytes(const struct ntfs_mutation_key *key, bool child)
{
	size_t bytes = sizeof(struct ntfs_disk_index_entry) + key->bytes;

	return ntfs_mutation_align_bytes(bytes) + (child ? sizeof(uint64_t) : 0);
}

static size_t
mutation_index_entry_encode(
    uint8_t *buffer, const struct ntfs_mutation_key *key, bool child, uint64_t vcn)
{
	struct ntfs_disk_index_entry *entry = (void *)buffer;
	size_t bytes = key == NULL ? sizeof(*entry) + (child ? sizeof(uint64_t) : 0)
				   : mutation_index_entry_bytes(key, child);

	ntfs_zero(buffer, bytes);
	ntfs_put_u16(entry->length, (uint16_t)bytes);
	ntfs_put_u16(
	    entry->flags, (key == NULL ? NTFS_INDEX_END : 0) | (child ? NTFS_INDEX_CHILD : 0));
	if (key != NULL) {
		ntfs_put_u64(entry->reference, key->reference);
		ntfs_put_u16(entry->key_length, key->bytes);
		ntfs_copy(buffer + sizeof(*entry), key->value, key->bytes);
	}
	if (child) {
		ntfs_put_u64(buffer + bytes - sizeof(uint64_t), vcn);
	}
	return bytes;
}

static enum ntfs_result
mutation_index_node_build(struct ntfs_mutation_index_builder *tree, size_t first, size_t end,
    unsigned depth, uint64_t *out)
{
	struct ntfs_disk_index_block *block;
	uint8_t *buffer, **blocks;
	size_t index, total, position, median, capacity;
	uint64_t left, right;
	enum ntfs_result result;
	bool leaf;

	if (depth == NTFS_DIRECTORY_DEPTH || tree->count == NTFS_MUTATION_MAX_REGIONS) {
		return NTFS_RANGE;
	}
	if (tree->count == tree->capacity) {
		capacity = tree->capacity == 0 ? NTFS_MUTATION_INITIAL_REGIONS
					       : tree->capacity * NTFS_VECTOR_GROWTH;
		blocks = ntfs_mutation_allocate(tree->plan, capacity * sizeof(*blocks));
		if (blocks == NULL) {
			return NTFS_NO_MEMORY;
		}
		ntfs_copy(blocks, tree->blocks, tree->count * sizeof(*blocks));
		ntfs_mutation_release(tree->plan, tree->blocks, tree->capacity * sizeof(*blocks));
		tree->blocks = blocks;
		tree->capacity = capacity;
	}
	buffer = ntfs_mutation_allocate(tree->plan, NTFS_WRITE_CLUSTER_BYTES);
	if (buffer == NULL) {
		return NTFS_NO_MEMORY;
	}
	*out = tree->count;
	tree->blocks[tree->count++] = buffer;
	block = (void *)buffer;
	ntfs_copy(block->mst.magic, "INDX", sizeof(block->mst.magic));
	ntfs_put_u16(block->mst.usa_offset, sizeof(*block));
	ntfs_put_u16(block->mst.usa_count, NTFS_WRITE_CLUSTER_BYTES / NTFS_MST_STRIDE + 1);
	ntfs_put_u64(block->vcn, *out);
	ntfs_put_u32(block->header.entries_offset,
	    NTFS_MUTATION_INDEX_ENTRIES_OFFSET - offsetof(struct ntfs_disk_index_block, header));
	ntfs_put_u32(block->header.allocated,
	    NTFS_WRITE_CLUSTER_BYTES - offsetof(struct ntfs_disk_index_block, header));
	total = sizeof(struct ntfs_disk_index_entry);
	result = ntfs_mutation_work(tree->plan, end - first);
	if (result != NTFS_OK) {
		return result;
	}
	for (index = first; index < end; index++) {
		total += mutation_index_entry_bytes(&tree->directory->keys[index], false);
	}
	leaf = total <= NTFS_WRITE_CLUSTER_BYTES - NTFS_MUTATION_INDEX_ENTRIES_OFFSET;
	position = NTFS_MUTATION_INDEX_ENTRIES_OFFSET;
	if (leaf) {
		for (index = first; index < end; index++) {
			position += mutation_index_entry_encode(
			    buffer + position, &tree->directory->keys[index], false, 0);
		}
		position += mutation_index_entry_encode(buffer + position, NULL, false, 0);
	} else {
		median = first + (end - first) / 2u;
		result = mutation_index_node_build(tree, first, median, depth + 1u, &left);
		if (result != NTFS_OK) {
			return result;
		}
		result = mutation_index_node_build(tree, median + 1u, end, depth + 1u, &right);
		if (result != NTFS_OK) {
			return result;
		}
		block->header.flags = NTFS_INDEX_LARGE;
		position += mutation_index_entry_encode(
		    buffer + position, &tree->directory->keys[median], true, left);
		position += mutation_index_entry_encode(buffer + position, NULL, true, right);
	}
	ntfs_put_u32(block->header.used,
	    (uint32_t)(position - offsetof(struct ntfs_disk_index_block, header)));
	return NTFS_OK;
}

static void
mutation_index_root_encode(uint8_t *buffer, size_t entries, bool child)
{
	struct ntfs_disk_index_root *root = (void *)buffer;
	struct ntfs_disk_index_header *header = (void *)(buffer + sizeof(*root));

	ntfs_zero(buffer, sizeof(*root) + sizeof(*header));
	ntfs_put_u32(root->type, NTFS_ATTR_FILENAME);
	ntfs_put_u32(root->collation, NTFS_COLLATION_FILENAME);
	ntfs_put_u32(root->block_size, NTFS_WRITE_CLUSTER_BYTES);
	root->clusters_per_block = 1;
	ntfs_put_u32(header->entries_offset, sizeof(*header));
	ntfs_put_u32(header->used, (uint32_t)(sizeof(*header) + entries));
	ntfs_put_u32(header->allocated, (uint32_t)(sizeof(*header) + entries));
	header->flags = child ? NTFS_INDEX_LARGE : 0;
}

static size_t
mutation_directory_attribute_length(struct ntfs_mutation_record *record, uint32_t type)
{
	struct ntfs_attr_view attribute;

	return ntfs_attr_find(record->bytes, sizeof(record->bytes), type, ntfs_mutation_index_name,
		   4, UINT16_MAX, &attribute) == NTFS_OK
	    ? attribute.length
	    : 0;
}

static enum ntfs_result
mutation_directory_original_streams(struct ntfs_write_mutation_plan *plan,
    const struct ntfs_mutation_record *record, struct ntfs_stream **allocation,
    struct ntfs_stream **bitmap)
{
	struct ntfs_node *node = NULL;
	bool allocated;
	enum ntfs_result result;

	*allocation = NULL;
	*bitmap = NULL;
	result =
	    ntfs_mutation_bitmap_test(plan, &plan->mft_bitmap, record->number, true, &allocated);
	if (result != NTFS_OK || !allocated) {
		return result;
	}
	/* This node and both streams read the immutable original volume, even when
	 * this directory was already rebuilt earlier in the same mutation. */
	result = ntfs_node_open_impl(plan->volume, record->reference, &node);
	if (result == NTFS_OK) {
		result = ntfs_attribute_open(node, NTFS_ATTR_INDEX_ALLOCATION,
		    ntfs_mutation_index_name, NTFS_WRITE_MUTATION_TARGET_NAME_UNITS, allocation);
		if (result == NTFS_NOT_FOUND) {
			result = NTFS_OK;
		} else if (result == NTFS_OK) {
			result =
			    ntfs_attribute_open(node, NTFS_ATTR_BITMAP, ntfs_mutation_index_name,
				NTFS_WRITE_MUTATION_TARGET_NAME_UNITS, bitmap);
		}
	}
	ntfs_node_close(node);
	return result;
}

static enum ntfs_result
mutation_index_predecessor(struct ntfs_mutation_patch *patch, uint64_t vcn,
    struct ntfs_stream *allocation, struct ntfs_stream *bitmap)
{
	const struct ntfs_run *run;
	uint8_t bit;
	uint64_t physical;
	enum ntfs_result result;

	if (patch->bound || allocation == NULL ||
	    !ntfs_bounds(vcn * NTFS_WRITE_CLUSTER_BYTES, NTFS_WRITE_CLUSTER_BYTES,
		allocation->initialized)) {
		return NTFS_OK;
	}
	if (allocation->resident || bitmap == NULL || vcn / NTFS_BITS_PER_BYTE >= bitmap->size) {
		return NTFS_CORRUPT;
	}
	result = ntfs_stream_exact(bitmap, vcn / NTFS_BITS_PER_BYTE, &bit, sizeof(bit));
	if (result != NTFS_OK || (bit & (1u << (vcn % NTFS_BITS_PER_BYTE))) == 0) {
		return result;
	}
	run = ntfs_run_find(allocation, vcn);
	if (run == NULL || run->lcn == NTFS_HOLE) {
		return NTFS_CORRUPT;
	}
	physical = (run->lcn + vcn - run->vcn) * NTFS_WRITE_CLUSTER_BYTES;
	if (physical != patch->physical) {
		return NTFS_CORRUPT;
	}
	patch->predecessor.index_allocated = true;
	return NTFS_OK;
}

enum ntfs_result
ntfs_mutation_directory_store(struct ntfs_write_mutation_plan *plan,
    struct ntfs_mutation_directory *directory, bool namespace_change)
{
	struct ntfs_mutation_index_builder tree = {0};
	struct ntfs_mutation_record *record = directory->record;
	const struct ntfs_disk_record *header = (const void *)record->bytes;
	struct ntfs_stream *old = NULL, *old_bitmap = NULL, *allocation = NULL,
			   *bitmap_stream = NULL, *original = NULL, *original_bitmap = NULL;
	struct ntfs_stream empty = {0};
	struct ntfs_run *runs = NULL, *bitmap_runs = NULL;
	const struct ntfs_run *run;
	struct ntfs_mutation_patch *patch;
	uint8_t *root = NULL, *bitmap = NULL;
	uint64_t top, physical;
	size_t total, position, index, count = 0, bitmap_count = 0, bitmap_bytes = 0,
				       root_bytes = 0, unused, available;
	enum ntfs_result result;
	bool inline_root;

	result = ntfs_mutation_stream(
	    plan, record, NTFS_ATTR_INDEX_ALLOCATION, ntfs_mutation_index_name, 4, &old);
	if (result == NTFS_NOT_FOUND) {
		result = NTFS_OK;
	}
	if (result == NTFS_OK) {
		result = ntfs_mutation_stream(
		    plan, record, NTFS_ATTR_BITMAP, ntfs_mutation_index_name, 4, &old_bitmap);
		if (result == NTFS_NOT_FOUND) {
			result = NTFS_OK;
		}
	}
	if (result != NTFS_OK) {
		goto done;
	}
	result = mutation_directory_original_streams(plan, record, &original, &original_bitmap);
	if (result != NTFS_OK) {
		goto done;
	}
	total = sizeof(struct ntfs_disk_index_root) + sizeof(struct ntfs_disk_index_header) +
	    sizeof(struct ntfs_disk_index_entry);
	for (index = 0; index < directory->count; index++) {
		total += mutation_index_entry_bytes(&directory->keys[index], false);
	}
	unused = mutation_directory_attribute_length(record, NTFS_ATTR_INDEX_ROOT) +
	    mutation_directory_attribute_length(record, NTFS_ATTR_INDEX_ALLOCATION) +
	    mutation_directory_attribute_length(record, NTFS_ATTR_BITMAP);
	available = NTFS_WRITE_RECORD_BYTES - (ntfs_u32(header->used) - unused);
	inline_root = total <= NTFS_WRITE_RECORD_BYTES &&
	    ((sizeof(struct ntfs_disk_attr) + sizeof(struct ntfs_disk_resident) +
		 4 * NTFS_UTF16_UNIT_BYTES + total + NTFS_WIRE_ALIGNMENT - 1u) &
		~(size_t)(NTFS_WIRE_ALIGNMENT - 1u)) <= available;
	root_bytes = inline_root ? total : NTFS_WRITE_RECORD_BYTES;
	root = ntfs_mutation_allocate(plan, root_bytes);
	if (root == NULL) {
		result = NTFS_NO_MEMORY;
		goto done;
	}
	if (inline_root) {
		position =
		    sizeof(struct ntfs_disk_index_root) + sizeof(struct ntfs_disk_index_header);
		for (index = 0; index < directory->count; index++) {
			position += mutation_index_entry_encode(
			    root + position, &directory->keys[index], false, 0);
		}
		position += mutation_index_entry_encode(root + position, NULL, false, 0);
		mutation_index_root_encode(root,
		    position - sizeof(struct ntfs_disk_index_root) -
			sizeof(struct ntfs_disk_index_header),
		    false);
		result = ntfs_mutation_attribute_remove(
		    plan, record, NTFS_ATTR_INDEX_ALLOCATION, ntfs_mutation_index_name, 4);
		if (result == NTFS_OK) {
			result = ntfs_mutation_attribute_remove(
			    plan, record, NTFS_ATTR_BITMAP, ntfs_mutation_index_name, 4);
		}
		if (result == NTFS_OK && old != NULL) {
			result = ntfs_mutation_free_runs(plan, old, 0);
		}
		if (result == NTFS_OK && old_bitmap != NULL) {
			result = ntfs_mutation_free_runs(plan, old_bitmap, 0);
		}
	} else {
		tree.plan = plan;
		tree.directory = directory;
		result = mutation_index_node_build(&tree, 0, directory->count, 0, &top);
		if (result != NTFS_OK) {
			goto done;
		}
		position =
		    sizeof(struct ntfs_disk_index_root) + sizeof(struct ntfs_disk_index_header);
		position += mutation_index_entry_encode(root + position, NULL, true, top);
		mutation_index_root_encode(root,
		    position - sizeof(struct ntfs_disk_index_root) -
			sizeof(struct ntfs_disk_index_header),
		    true);
		/* Reclaim the private inline root before adding external attributes.
		 * Only the complete final record is sealed or published. */
		result = ntfs_mutation_resident(plan, record, NTFS_ATTR_INDEX_ROOT,
		    ntfs_mutation_index_name, 4, root, position, 0);
		if (result != NTFS_OK) {
			goto done;
		}
		empty.resident = true;
		result = ntfs_mutation_resize_runs(
		    plan, old == NULL ? &empty : old, tree.count, &runs, &count);
		if (result == NTFS_OK) {
			result = ntfs_mutation_nonresident(plan, record, NTFS_ATTR_INDEX_ALLOCATION,
			    ntfs_mutation_index_name, 4, runs, count,
			    tree.count * NTFS_WRITE_CLUSTER_BYTES,
			    tree.count * NTFS_WRITE_CLUSTER_BYTES, 0);
		}
		if (result == NTFS_OK) {
			result = ntfs_mutation_stream(plan, record, NTFS_ATTR_INDEX_ALLOCATION,
			    ntfs_mutation_index_name, 4, &allocation);
		}
		for (index = 0; result == NTFS_OK && index < tree.count; index++) {
			run = ntfs_run_find(allocation, index);
			if (run == NULL || run->lcn == NTFS_HOLE) {
				result = NTFS_CORRUPT;
				break;
			}
			physical = (run->lcn + index - run->vcn) * NTFS_WRITE_CLUSTER_BYTES;
			result =
			    ntfs_mutation_patch(plan, physical, NTFS_WRITE_MUTATION_INDEX, &patch);
			if (result == NTFS_OK) {
				result = mutation_index_predecessor(
				    patch, index, original, original_bitmap);
			}
			if (result == NTFS_OK) {
				result = ntfs_record_protect(tree.blocks[index],
				    NTFS_WRITE_CLUSTER_BYTES, plan->protected_record,
				    NTFS_WRITE_CLUSTER_BYTES);
			}
			if (result == NTFS_OK) {
				result = ntfs_write_guard_frame(patch->before,
				    NTFS_WRITE_CLUSTER_BYTES, plan->protected_record, plan->guard);
			}
			if (result == NTFS_OK) {
				result = ntfs_mutation_stream_write(plan, record,
				    NTFS_ATTR_INDEX_ALLOCATION, ntfs_mutation_index_name,
				    NTFS_WRITE_MUTATION_TARGET_NAME_UNITS, allocation,
				    index * NTFS_WRITE_CLUSTER_BYTES, plan->protected_record,
				    NTFS_WRITE_CLUSTER_BYTES, NTFS_WRITE_MUTATION_INDEX);
			}
		}
		if (result != NTFS_OK) {
			goto done;
		}
		bitmap_bytes = (tree.count + NTFS_BITS_PER_BYTE - 1u) / NTFS_BITS_PER_BYTE;
		bitmap_bytes =
		    (bitmap_bytes + NTFS_WIRE_ALIGNMENT - 1u) & ~(size_t)(NTFS_WIRE_ALIGNMENT - 1u);
		bitmap = ntfs_mutation_allocate(plan, bitmap_bytes);
		if (bitmap == NULL) {
			result = NTFS_NO_MEMORY;
			goto done;
		}
		for (index = 0; index < tree.count; index++) {
			ntfs_mutation_set_bit(bitmap, index, true);
		}
		result = ntfs_mutation_resident(plan, record, NTFS_ATTR_BITMAP,
		    ntfs_mutation_index_name, 4, bitmap, bitmap_bytes, 0);
		if (result == NTFS_OK && old_bitmap != NULL) {
			result = ntfs_mutation_free_runs(plan, old_bitmap, 0);
		} else if (result == NTFS_NO_SPACE) {
			result = ntfs_mutation_resize_runs(plan,
			    old_bitmap == NULL ? &empty : old_bitmap,
			    bitmap_bytes / NTFS_WRITE_CLUSTER_BYTES +
				(bitmap_bytes % NTFS_WRITE_CLUSTER_BYTES != 0),
			    &bitmap_runs, &bitmap_count);
			if (result == NTFS_OK) {
				result = ntfs_mutation_nonresident(plan, record, NTFS_ATTR_BITMAP,
				    ntfs_mutation_index_name, 4, bitmap_runs, bitmap_count,
				    bitmap_bytes, bitmap_bytes, 0);
			}
			if (result == NTFS_OK) {
				result = ntfs_mutation_stream(plan, record, NTFS_ATTR_BITMAP,
				    ntfs_mutation_index_name, 4, &bitmap_stream);
			}
			if (result == NTFS_OK) {
				result = ntfs_mutation_stream_write(plan, record, NTFS_ATTR_BITMAP,
				    ntfs_mutation_index_name, NTFS_WRITE_MUTATION_TARGET_NAME_UNITS,
				    bitmap_stream, 0, bitmap, bitmap_bytes,
				    NTFS_WRITE_MUTATION_BITMAP);
			}
		}
	}
	if (result == NTFS_OK && inline_root) {
		result = ntfs_mutation_resident(plan, record, NTFS_ATTR_INDEX_ROOT,
		    ntfs_mutation_index_name, 4, root, position, 0);
	}
	if (result == NTFS_OK && namespace_change) {
		result = ntfs_mutation_touch(record, plan->filetime, false);
	}

done:
	for (index = 0; index < tree.count; index++) {
		ntfs_mutation_release(plan, tree.blocks[index], NTFS_WRITE_CLUSTER_BYTES);
	}
	ntfs_mutation_release(plan, tree.blocks, tree.capacity * sizeof(*tree.blocks));
	ntfs_mutation_release(plan, root, root == NULL ? 0 : root_bytes);
	ntfs_mutation_release(plan, bitmap, bitmap_bytes);
	ntfs_mutation_release(plan, runs, NTFS_MUTATION_MAX_RUNS * sizeof(*runs));
	ntfs_mutation_release(plan, bitmap_runs, NTFS_MUTATION_MAX_RUNS * sizeof(*bitmap_runs));
	ntfs_stream_close(allocation);
	ntfs_stream_close(bitmap_stream);
	ntfs_stream_close(old);
	ntfs_stream_close(old_bitmap);
	ntfs_stream_close(original);
	ntfs_stream_close(original_bitmap);
	return result;
}
