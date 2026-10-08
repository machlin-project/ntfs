/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_directory_internal.h"
#include <ntfs/record.h>

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
	struct ntfs_mutation_index_tree *tree = directory->tree;
	struct ntfs_mutation_index_node *node;
	struct ntfs_disk_index_block *block;
	struct ntfs_mutation_record *record = directory->record;
	const struct ntfs_disk_record *header = (const void *)record->bytes;
	struct ntfs_stream *old = NULL, *old_bitmap = NULL, *allocation = NULL,
			   *bitmap_stream = NULL, *original = NULL, *original_bitmap = NULL;
	struct ntfs_stream empty = {0};
	struct ntfs_run *runs = NULL, *bitmap_runs = NULL;
	const struct ntfs_run *run;
	struct ntfs_mutation_patch *patch;
	uint8_t *root = NULL, *bitmap = NULL;
	uint64_t physical, slots = 0;
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
		total += ntfs_mutation_align_bytes(
		    sizeof(struct ntfs_disk_index_entry) + directory->keys[index].bytes);
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
			position += ntfs_mutation_index_encode(
			    root + position, &directory->keys[index], false, 0);
		}
		position += ntfs_mutation_index_encode(root + position, NULL, false, 0);
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
		if (tree == NULL || tree->root == NULL) {
			result = NTFS_CORRUPT;
			goto done;
		}
		for (index = 0; index < tree->count; index++) {
			node = tree->nodes[index];
			if (node->live && node->vcn >= slots) {
				slots = node->vcn + 1;
			}
		}
		/* Expanding the external allocation may enlarge both named attributes.
		 * Keep the resident root minimal before reserving that FILE space. Only
		 * the old root's entries move; unrelated external nodes keep their VCNs. */
		if ((old == NULL || slots > old->size / NTFS_WRITE_CLUSTER_BYTES) &&
		    tree->root->used > sizeof(struct ntfs_disk_index_entry) + sizeof(uint64_t)) {
			result = ntfs_mutation_index_fit_root(plan, directory,
			    sizeof(struct ntfs_disk_index_entry) + sizeof(uint64_t));
			if (result != NTFS_OK) {
				goto done;
			}
			for (index = 0; index < tree->count; index++) {
				if (tree->nodes[index]->live && tree->nodes[index]->vcn >= slots) {
					slots = tree->nodes[index]->vcn + 1;
				}
			}
		}
		if (slots == 0 || slots > NTFS_MUTATION_MAX_BITMAP_BYTES * NTFS_BITS_PER_BYTE) {
			result = NTFS_RANGE;
			goto done;
		}
		position =
		    sizeof(struct ntfs_disk_index_root) + sizeof(struct ntfs_disk_index_header);
		ntfs_copy(root + position, tree->root->entries, tree->root->used);
		position += tree->root->used;
		mutation_index_root_encode(root, tree->root->used, tree->root->child);
		/* Reclaim the private inline root before adding external attributes.
		 * Only the complete final record is sealed or published. */
		result = ntfs_mutation_resident(plan, record, NTFS_ATTR_INDEX_ROOT,
		    ntfs_mutation_index_name, 4, root, position, 0);
		if (result != NTFS_OK) {
			goto done;
		}
		empty.resident = true;
		if (old != NULL && old->size == slots * NTFS_WRITE_CLUSTER_BYTES) {
			allocation = old;
			allocation->shared_references++;
		} else {
			result = ntfs_mutation_resize_runs(
			    plan, old == NULL ? &empty : old, slots, &runs, &count);
			if (result == NTFS_OK) {
				result = ntfs_mutation_nonresident(plan, record,
				    NTFS_ATTR_INDEX_ALLOCATION, ntfs_mutation_index_name, 4, runs,
				    count, slots * NTFS_WRITE_CLUSTER_BYTES,
				    slots * NTFS_WRITE_CLUSTER_BYTES, 0);
			}
			if (result == NTFS_OK) {
				result =
				    ntfs_mutation_stream(plan, record, NTFS_ATTR_INDEX_ALLOCATION,
					ntfs_mutation_index_name, 4, &allocation);
			}
		}
		for (index = 0; result == NTFS_OK && index < tree->count; index++) {
			node = tree->nodes[index];
			if (!node->live || !node->dirty) {
				continue;
			}
			run = ntfs_run_find(allocation, node->vcn);
			if (run == NULL || run->lcn == NTFS_HOLE) {
				result = NTFS_CORRUPT;
				break;
			}
			physical = (run->lcn + node->vcn - run->vcn) * NTFS_WRITE_CLUSTER_BYTES;
			result =
			    ntfs_mutation_patch(plan, physical, NTFS_WRITE_MUTATION_INDEX, &patch);
			if (result == NTFS_OK) {
				result = mutation_index_predecessor(
				    patch, node->vcn, original, original_bitmap);
			}
			if (result == NTFS_OK) {
				ntfs_zero(plan->scratch, NTFS_WRITE_CLUSTER_BYTES);
				block = (void *)plan->scratch;
				ntfs_copy(block->mst.magic, "INDX", sizeof(block->mst.magic));
				ntfs_put_u16(block->mst.usa_offset, sizeof(*block));
				ntfs_put_u16(block->mst.usa_count,
				    NTFS_WRITE_CLUSTER_BYTES / NTFS_MST_STRIDE + 1);
				ntfs_put_u64(block->vcn, node->vcn);
				ntfs_put_u32(block->header.entries_offset,
				    NTFS_MUTATION_INDEX_ENTRIES_OFFSET -
					offsetof(struct ntfs_disk_index_block, header));
				ntfs_put_u32(block->header.used,
				    NTFS_MUTATION_INDEX_ENTRIES_OFFSET -
					offsetof(struct ntfs_disk_index_block, header) +
					(uint32_t)node->used);
				ntfs_put_u32(block->header.allocated,
				    NTFS_WRITE_CLUSTER_BYTES -
					offsetof(struct ntfs_disk_index_block, header));
				block->header.flags = node->child ? NTFS_INDEX_LARGE : 0;
				ntfs_copy(plan->scratch + NTFS_MUTATION_INDEX_ENTRIES_OFFSET,
				    node->entries, node->used);
				result =
				    ntfs_record_protect(plan->scratch, NTFS_WRITE_CLUSTER_BYTES,
					plan->protected_record, NTFS_WRITE_CLUSTER_BYTES);
			}
			if (result == NTFS_OK) {
				result = ntfs_write_guard_frame(patch->before,
				    NTFS_WRITE_CLUSTER_BYTES, plan->protected_record, plan->guard);
			}
			if (result == NTFS_OK) {
				result = ntfs_mutation_stream_write(plan, record,
				    NTFS_ATTR_INDEX_ALLOCATION, ntfs_mutation_index_name,
				    NTFS_WRITE_MUTATION_TARGET_NAME_UNITS, allocation,
				    node->vcn * NTFS_WRITE_CLUSTER_BYTES, plan->protected_record,
				    NTFS_WRITE_CLUSTER_BYTES, NTFS_WRITE_MUTATION_INDEX);
			}
		}
		if (result != NTFS_OK) {
			goto done;
		}
		bitmap_bytes = (slots + NTFS_BITS_PER_BYTE - 1u) / NTFS_BITS_PER_BYTE;
		bitmap_bytes =
		    (bitmap_bytes + NTFS_WIRE_ALIGNMENT - 1u) & ~(size_t)(NTFS_WIRE_ALIGNMENT - 1u);
		bitmap = ntfs_mutation_allocate(plan, bitmap_bytes);
		if (bitmap == NULL) {
			result = NTFS_NO_MEMORY;
			goto done;
		}
		for (index = 0; index < tree->count; index++) {
			if (tree->nodes[index]->live) {
				ntfs_mutation_set_bit(bitmap, tree->nodes[index]->vcn, true);
			}
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
