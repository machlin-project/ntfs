/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_mutation_internal.h"
#include <ntfs/record.h>

struct mutation_tree {
	struct ntfs_write_mutation_plan *plan;
	struct ntfs_mutation_directory *directory;
	uint8_t **blocks;
	size_t count, capacity;
};

static size_t
entry_bytes(const struct ntfs_mutation_key *key, bool child)
{
	size_t bytes = sizeof(struct ntfs_disk_index_entry) + key->bytes;

	return ((bytes + NTFS_WIRE_ALIGNMENT - 1u) & ~(size_t)(NTFS_WIRE_ALIGNMENT - 1u)) +
	    (child ? sizeof(uint64_t) : 0);
}

static int
compare(struct ntfs_write_mutation_plan *plan, const struct ntfs_mutation_key *left,
    const struct ntfs_mutation_key *right)
{
	const struct ntfs_disk_filename *a = (const void *)left->value;
	const struct ntfs_disk_filename *b = (const void *)right->value;
	size_t index, count = a->length < b->length ? a->length : b->length;
	uint16_t x, y, folded_x, folded_y;
	int exact = 0;

	for (index = 0; index < count; index++) {
		x = ntfs_u16(left->value + sizeof(*a) + index * NTFS_UTF16_UNIT_BYTES);
		y = ntfs_u16(right->value + sizeof(*b) + index * NTFS_UTF16_UNIT_BYTES);
		if (exact == 0 && x != y) {
			exact = x < y ? -1 : 1;
		}
		folded_x = ntfs_u16(plan->volume->upcase + (size_t)x * NTFS_UTF16_UNIT_BYTES);
		folded_y = ntfs_u16(plan->volume->upcase + (size_t)y * NTFS_UTF16_UNIT_BYTES);
		if (folded_x != folded_y) {
			return folded_x < folded_y ? -1 : 1;
		}
	}
	return a->length == b->length ? exact : a->length < b->length ? -1 : 1;
}

static enum ntfs_result
reserve_keys(struct ntfs_write_mutation_plan *plan, struct ntfs_mutation_directory *directory)
{
	struct ntfs_mutation_key *keys;
	size_t capacity;

	if (directory->count == NTFS_MUTATION_MAX_KEYS) {
		return NTFS_RANGE;
	}
	if (directory->count < directory->capacity) {
		return NTFS_OK;
	}
	capacity = directory->capacity == 0 ? NTFS_MUTATION_INITIAL_KEYS
					    : directory->capacity * NTFS_VECTOR_GROWTH;
	keys = ntfs_mutation_allocate(plan, capacity * sizeof(*keys));
	if (keys == NULL) {
		return NTFS_NO_MEMORY;
	}
	ntfs_copy(keys, directory->keys, directory->count * sizeof(*keys));
	ntfs_mutation_release(plan, directory->keys, directory->capacity * sizeof(*keys));
	directory->keys = keys;
	directory->capacity = capacity;
	return NTFS_OK;
}

static enum ntfs_result
append_key(struct ntfs_write_mutation_plan *plan, struct ntfs_mutation_directory *directory,
    const struct ntfs_disk_index_entry *entry)
{
	const struct ntfs_disk_filename *filename =
	    (const void *)((const uint8_t *)entry + sizeof(*entry));
	struct ntfs_mutation_key *key;
	size_t bytes = ntfs_u16(entry->key_length);
	enum ntfs_result result;

	if (bytes < sizeof(*filename) || bytes > NTFS_MUTATION_FILENAME_BYTES ||
	    filename->length == 0 || filename->name_namespace > NTFS_NAMESPACE_WIN32_DOS ||
	    bytes != sizeof(*filename) + filename->length * NTFS_UTF16_UNIT_BYTES ||
	    ntfs_u64(filename->parent) != directory->record->reference ||
	    ntfs_u64(entry->reference) >> NTFS_REFERENCE_SEQUENCE_SHIFT == 0) {
		return NTFS_CORRUPT;
	}
	result = reserve_keys(plan, directory);
	if (result != NTFS_OK) {
		return result;
	}
	key = &directory->keys[directory->count];
	key->reference = ntfs_u64(entry->reference);
	key->bytes = (uint16_t)bytes;
	ntfs_copy(key->value, filename, bytes);
	if (directory->count != 0 &&
	    compare(plan, &directory->keys[directory->count - 1u], key) >= 0) {
		return NTFS_CORRUPT;
	}
	directory->count++;
	return NTFS_OK;
}

static enum ntfs_result
walk(struct ntfs_write_mutation_plan *plan, struct ntfs_mutation_directory *directory,
    const uint8_t *buffer, size_t bytes, size_t header_offset, struct ntfs_stream *allocation,
    struct ntfs_stream *bitmap, struct ntfs_index_visited *visited, unsigned depth)
{
	const struct ntfs_disk_index_header *header;
	const struct ntfs_disk_index_entry *entry;
	const struct ntfs_disk_index_block *block;
	uint8_t *child = NULL;
	uint8_t bit;
	uint64_t vcn;
	size_t position, end, length, trailer, key_bytes;
	uint16_t flags;
	enum ntfs_result result;

	if (depth == NTFS_DIRECTORY_DEPTH || !ntfs_bounds(header_offset, sizeof(*header), bytes)) {
		return NTFS_CORRUPT;
	}
	header = (const void *)(buffer + header_offset);
	position = ntfs_u32(header->entries_offset);
	end = ntfs_u32(header->used);
	if (position < sizeof(*header) || position % NTFS_WIRE_ALIGNMENT != 0 || end < position ||
	    end > ntfs_u32(header->allocated) ||
	    ntfs_u32(header->allocated) > bytes - header_offset ||
	    (header->flags & ~NTFS_INDEX_LARGE) != 0) {
		return NTFS_CORRUPT;
	}
	position += header_offset;
	end += header_offset;
	for (;;) {
		if (!ntfs_bounds(position, sizeof(*entry), end)) {
			return NTFS_CORRUPT;
		}
		entry = (const void *)(buffer + position);
		flags = ntfs_u16(entry->flags);
		length = ntfs_u16(entry->length);
		key_bytes = ntfs_u16(entry->key_length);
		trailer = (flags & NTFS_INDEX_CHILD) != 0 ? sizeof(uint64_t) : 0;
		if ((flags & ~(NTFS_INDEX_END | NTFS_INDEX_CHILD)) != 0 ||
		    ((flags & NTFS_INDEX_CHILD) != 0) !=
			((header->flags & NTFS_INDEX_LARGE) != 0) ||
		    length < sizeof(*entry) + trailer || length % NTFS_WIRE_ALIGNMENT != 0 ||
		    !ntfs_bounds(position, length, end) ||
		    key_bytes > length - sizeof(*entry) - trailer) {
			return NTFS_CORRUPT;
		}
		if (trailer != 0) {
			if (allocation == NULL || bitmap == NULL) {
				return NTFS_CORRUPT;
			}
			vcn = ntfs_u64(buffer + position + length - sizeof(uint64_t));
			if (vcn >= allocation->size / NTFS_WRITE_CLUSTER_BYTES) {
				return NTFS_CORRUPT;
			}
			result = ntfs_mutation_stream_read(
			    plan, bitmap, vcn / NTFS_BITS_PER_BYTE, &bit, sizeof(bit));
			if (result != NTFS_OK) {
				return result;
			}
			if ((bit & (1u << (vcn % NTFS_BITS_PER_BYTE))) == 0) {
				return NTFS_CORRUPT;
			}
			result = ntfs_index_visit(plan->volume, visited, vcn, NULL, NULL);
			if (result != NTFS_OK) {
				return result;
			}
			child = ntfs_mutation_allocate(plan, NTFS_WRITE_CLUSTER_BYTES);
			if (child == NULL) {
				return NTFS_NO_MEMORY;
			}
			result = ntfs_mutation_stream_read(plan, allocation,
			    vcn * NTFS_WRITE_CLUSTER_BYTES, child, NTFS_WRITE_CLUSTER_BYTES);
			if (result == NTFS_OK) {
				result = ntfs_fixup(child, NTFS_WRITE_CLUSTER_BYTES, "INDX");
			}
			block = (const void *)child;
			if (result == NTFS_OK && ntfs_u64(block->vcn) != vcn) {
				result = NTFS_CORRUPT;
			}
			if (result == NTFS_OK) {
				result = walk(plan, directory, child, NTFS_WRITE_CLUSTER_BYTES,
				    offsetof(struct ntfs_disk_index_block, header), allocation,
				    bitmap, visited, depth + 1u);
			}
			ntfs_mutation_release(plan, child, NTFS_WRITE_CLUSTER_BYTES);
			child = NULL;
			if (result != NTFS_OK) {
				return result;
			}
		}
		if ((flags & NTFS_INDEX_END) != 0) {
			return key_bytes == 0 && position + length == end ? NTFS_OK : NTFS_CORRUPT;
		}
		result = append_key(plan, directory, entry);
		if (result != NTFS_OK) {
			return result;
		}
		position += length;
	}
}

static enum ntfs_result
check_bitmap(struct ntfs_write_mutation_plan *plan, const struct ntfs_stream *allocation,
    const struct ntfs_stream *bitmap, const struct ntfs_index_visited *visited)
{
	uint8_t bytes[NTFS_INDEX_BITMAP_SCAN_BYTES];
	uint64_t offset, used = 0, slot;
	size_t take, byte;
	unsigned bit;
	enum ntfs_result result;

	if (bitmap == NULL) {
		return allocation == NULL && visited->count == 0 ? NTFS_OK : NTFS_CORRUPT;
	}
	if (allocation == NULL || allocation->size % NTFS_WRITE_CLUSTER_BYTES != 0 ||
	    allocation->initialized != allocation->size || bitmap->initialized != bitmap->size) {
		return NTFS_CORRUPT;
	}
	for (offset = 0; offset < bitmap->size; offset += take) {
		take = bitmap->size - offset < sizeof(bytes) ? (size_t)(bitmap->size - offset)
							     : sizeof(bytes);
		result = ntfs_mutation_stream_read(plan, bitmap, offset, bytes, take);
		if (result != NTFS_OK) {
			return result;
		}
		for (byte = 0; byte < take; byte++) {
			for (bit = 0; bit < NTFS_BITS_PER_BYTE; bit++) {
				if ((bytes[byte] & (1u << bit)) == 0) {
					continue;
				}
				slot = (offset + byte) * NTFS_BITS_PER_BYTE + bit;
				if (slot >= allocation->size / NTFS_WRITE_CLUSTER_BYTES) {
					return NTFS_CORRUPT;
				}
				used++;
			}
		}
	}
	return used == visited->count ? NTFS_OK : NTFS_CORRUPT;
}

enum ntfs_result
ntfs_mutation_directory_open(struct ntfs_write_mutation_plan *plan,
    struct ntfs_mutation_record *record, struct ntfs_mutation_directory *directory)
{
	struct ntfs_attr_view root, standard;
	struct ntfs_stream *allocation = NULL, *bitmap = NULL;
	struct ntfs_index_visited visited = {0};
	const struct ntfs_disk_index_root *header;
	const struct ntfs_disk_standard *information;
	const struct ntfs_disk_standard_policy *policy;
	const uint8_t *value;
	size_t bytes;
	enum ntfs_result result;

	ntfs_zero(directory, sizeof(*directory));
	directory->record = record;
	result = ntfs_mutation_record_admit(record, true, true);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_attr_find(record->bytes, sizeof(record->bytes), NTFS_ATTR_STANDARD, NULL, 0,
	    UINT16_MAX, &standard);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_attr_value(&standard, &value, &bytes);
	if (result != NTFS_OK) {
		return result;
	}
	information = (const void *)value;
	policy = (const void *)information->version;
	if (ntfs_u32(information->max_versions) != 0 ||
	    (policy->directory_flags != NTFS_STANDARD_DIRECTORY_CASE_INSENSITIVE &&
		policy->directory_flags != NTFS_STANDARD_DIRECTORY_CASE_SENSITIVE)) {
		return NTFS_UNSUPPORTED;
	}
	directory->case_sensitive =
	    policy->directory_flags == NTFS_STANDARD_DIRECTORY_CASE_SENSITIVE;
	result = ntfs_attr_find(record->bytes, sizeof(record->bytes), NTFS_ATTR_INDEX_ROOT,
	    ntfs_mutation_index_name, 4, UINT16_MAX, &root);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_attr_value(&root, &value, &bytes);
	if (result != NTFS_OK) {
		return result;
	}
	if (bytes < sizeof(*header) + sizeof(struct ntfs_disk_index_header)) {
		return NTFS_CORRUPT;
	}
	header = (const void *)value;
	if (ntfs_u32(header->type) != NTFS_ATTR_FILENAME ||
	    ntfs_u32(header->collation) != NTFS_COLLATION_FILENAME ||
	    ntfs_u32(header->block_size) != NTFS_WRITE_CLUSTER_BYTES ||
	    header->clusters_per_block != 1) {
		return NTFS_UNSUPPORTED;
	}
	result = ntfs_mutation_stream(
	    plan, record, NTFS_ATTR_INDEX_ALLOCATION, ntfs_mutation_index_name, 4, &allocation);
	if (result == NTFS_NOT_FOUND) {
		result = NTFS_OK;
	} else if (result == NTFS_OK) {
		result = ntfs_mutation_stream(
		    plan, record, NTFS_ATTR_BITMAP, ntfs_mutation_index_name, 4, &bitmap);
	}
	if (result == NTFS_OK) {
		result = walk(plan, directory, value, bytes, sizeof(*header), allocation, bitmap,
		    &visited, 0);
	}
	if (result == NTFS_OK) {
		result = check_bitmap(plan, allocation, bitmap, &visited);
	}
	ntfs_free(plan->volume, visited.values, visited.capacity * sizeof(*visited.values));
	ntfs_stream_close(allocation);
	ntfs_stream_close(bitmap);
	if (result != NTFS_OK) {
		ntfs_mutation_directory_close(plan, directory);
	}
	return result;
}

void
ntfs_mutation_directory_close(
    struct ntfs_write_mutation_plan *plan, struct ntfs_mutation_directory *directory)
{
	ntfs_mutation_release(
	    plan, directory->keys, directory->capacity * sizeof(*directory->keys));
	ntfs_zero(directory, sizeof(*directory));
}

enum ntfs_result
ntfs_mutation_directory_find(struct ntfs_write_mutation_plan *plan,
    struct ntfs_mutation_directory *directory, const struct ntfs_write_name *name, size_t *out)
{
	const struct ntfs_mutation_key *key;
	const struct ntfs_disk_filename *filename;
	size_t index, unit, found = SIZE_MAX;
	uint16_t left, right;
	bool same;
	enum ntfs_result result;

	*out = 0;
	result = ntfs_mutation_work(plan, directory->count * name->count);
	if (result != NTFS_OK) {
		return result;
	}
	for (index = 0; index < directory->count; index++) {
		key = &directory->keys[index];
		filename = (const void *)key->value;
		if (filename->length != name->count) {
			continue;
		}
		same = true;
		for (unit = 0; unit < name->count; unit++) {
			left =
			    ntfs_u16(key->value + sizeof(*filename) + unit * NTFS_UTF16_UNIT_BYTES);
			right = name->units[unit];
			if (!directory->case_sensitive) {
				left = ntfs_u16(
				    plan->volume->upcase + (size_t)left * NTFS_UTF16_UNIT_BYTES);
				right = ntfs_u16(
				    plan->volume->upcase + (size_t)right * NTFS_UTF16_UNIT_BYTES);
			}
			if (left != right) {
				same = false;
				break;
			}
		}
		if (same) {
			if (found != SIZE_MAX) {
				return NTFS_CORRUPT;
			}
			found = index;
		}
	}
	if (found == SIZE_MAX) {
		return NTFS_NOT_FOUND;
	}
	*out = found;
	return NTFS_OK;
}

enum ntfs_result
ntfs_mutation_directory_add(struct ntfs_write_mutation_plan *plan,
    struct ntfs_mutation_directory *directory, uint64_t reference, const void *value, size_t bytes)
{
	struct ntfs_mutation_key key = {0};
	size_t position, index;
	enum ntfs_result result;

	if (bytes > sizeof(key.value) || bytes < sizeof(struct ntfs_disk_filename)) {
		return NTFS_CORRUPT;
	}
	key.reference = reference;
	key.bytes = (uint16_t)bytes;
	ntfs_copy(key.value, value, bytes);
	for (position = 0; position < directory->count; position++) {
		if (compare(plan, &directory->keys[position], &key) >= 0) {
			break;
		}
	}
	if (position < directory->count && compare(plan, &directory->keys[position], &key) == 0) {
		return NTFS_EXISTS;
	}
	result = reserve_keys(plan, directory);
	if (result != NTFS_OK) {
		return result;
	}
	for (index = directory->count; index > position; index--) {
		directory->keys[index] = directory->keys[index - 1u];
	}
	directory->keys[position] = key;
	directory->count++;
	return NTFS_OK;
}

void
ntfs_mutation_directory_remove(struct ntfs_mutation_directory *directory, size_t position)
{
	size_t index;

	for (index = position + 1u; index < directory->count; index++) {
		directory->keys[index - 1u] = directory->keys[index];
	}
	directory->count--;
}

static size_t
encode_entry(uint8_t *buffer, const struct ntfs_mutation_key *key, bool child, uint64_t vcn)
{
	struct ntfs_disk_index_entry *entry = (void *)buffer;
	size_t bytes =
	    key == NULL ? sizeof(*entry) + (child ? sizeof(uint64_t) : 0) : entry_bytes(key, child);

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
build_node(struct mutation_tree *tree, size_t first, size_t end, unsigned depth, uint64_t *out)
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
		total += entry_bytes(&tree->directory->keys[index], false);
	}
	leaf = total <= NTFS_WRITE_CLUSTER_BYTES - NTFS_MUTATION_INDEX_ENTRIES_OFFSET;
	position = NTFS_MUTATION_INDEX_ENTRIES_OFFSET;
	if (leaf) {
		for (index = first; index < end; index++) {
			position += encode_entry(
			    buffer + position, &tree->directory->keys[index], false, 0);
		}
		position += encode_entry(buffer + position, NULL, false, 0);
	} else {
		median = first + (end - first) / 2u;
		result = build_node(tree, first, median, depth + 1u, &left);
		if (result != NTFS_OK) {
			return result;
		}
		result = build_node(tree, median + 1u, end, depth + 1u, &right);
		if (result != NTFS_OK) {
			return result;
		}
		block->header.flags = NTFS_INDEX_LARGE;
		position +=
		    encode_entry(buffer + position, &tree->directory->keys[median], true, left);
		position += encode_entry(buffer + position, NULL, true, right);
	}
	ntfs_put_u32(block->header.used,
	    (uint32_t)(position - offsetof(struct ntfs_disk_index_block, header)));
	return NTFS_OK;
}

static void
encode_root(uint8_t *buffer, size_t entries, bool child)
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
attribute_length(struct ntfs_mutation_record *record, uint32_t type)
{
	struct ntfs_attr_view attribute;

	return ntfs_attr_find(record->bytes, sizeof(record->bytes), type, ntfs_mutation_index_name,
		   4, UINT16_MAX, &attribute) == NTFS_OK
	    ? attribute.length
	    : 0;
}

static enum ntfs_result
original_index_streams(struct ntfs_write_mutation_plan *plan,
    const struct ntfs_mutation_record *record, struct ntfs_stream **allocation,
    struct ntfs_stream **bitmap)
{
	struct ntfs_node *node = NULL;
	enum ntfs_result result;

	*allocation = NULL;
	*bitmap = NULL;
	if (!ntfs_mutation_bit(
		plan->mft_bitmap.before, plan->mft_bitmap.original_bytes, record->number)) {
		return NTFS_OK;
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
index_predecessor(struct ntfs_mutation_patch *patch, uint64_t vcn, struct ntfs_stream *allocation,
    struct ntfs_stream *bitmap)
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
	struct mutation_tree tree = {0};
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
	result = original_index_streams(plan, record, &original, &original_bitmap);
	if (result != NTFS_OK) {
		goto done;
	}
	total = sizeof(struct ntfs_disk_index_root) + sizeof(struct ntfs_disk_index_header) +
	    sizeof(struct ntfs_disk_index_entry);
	for (index = 0; index < directory->count; index++) {
		total += entry_bytes(&directory->keys[index], false);
	}
	unused = attribute_length(record, NTFS_ATTR_INDEX_ROOT) +
	    attribute_length(record, NTFS_ATTR_INDEX_ALLOCATION) +
	    attribute_length(record, NTFS_ATTR_BITMAP);
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
			position +=
			    encode_entry(root + position, &directory->keys[index], false, 0);
		}
		position += encode_entry(root + position, NULL, false, 0);
		encode_root(root,
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
		result = build_node(&tree, 0, directory->count, 0, &top);
		if (result != NTFS_OK) {
			goto done;
		}
		position =
		    sizeof(struct ntfs_disk_index_root) + sizeof(struct ntfs_disk_index_header);
		position += encode_entry(root + position, NULL, true, top);
		encode_root(root,
		    position - sizeof(struct ntfs_disk_index_root) -
			sizeof(struct ntfs_disk_index_header),
		    true);
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
				result = index_predecessor(patch, index, original, original_bitmap);
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
	if (result == NTFS_OK) {
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
