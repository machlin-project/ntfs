/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_directory_internal.h"
#include <ntfs/record.h>

int
ntfs_mutation_key_compare(struct ntfs_write_mutation_plan *plan,
    const struct ntfs_mutation_key *left, const struct ntfs_mutation_key *right)
{
	const struct ntfs_disk_filename *left_name = (const void *)left->value;
	const struct ntfs_disk_filename *right_name = (const void *)right->value;
	size_t index,
	    count = left_name->length < right_name->length ? left_name->length : right_name->length;
	uint16_t left_unit, right_unit, folded_x, folded_y;
	int exact = 0;

	for (index = 0; index < count; index++) {
		left_unit =
		    ntfs_u16(left->value + sizeof(*left_name) + index * NTFS_UTF16_UNIT_BYTES);
		right_unit =
		    ntfs_u16(right->value + sizeof(*right_name) + index * NTFS_UTF16_UNIT_BYTES);
		if (exact == 0 && left_unit != right_unit) {
			exact = left_unit < right_unit ? -1 : 1;
		}
		folded_x =
		    ntfs_u16(plan->volume->upcase + (size_t)left_unit * NTFS_UTF16_UNIT_BYTES);
		folded_y =
		    ntfs_u16(plan->volume->upcase + (size_t)right_unit * NTFS_UTF16_UNIT_BYTES);
		if (folded_x != folded_y) {
			return folded_x < folded_y ? -1 : 1;
		}
	}
	return left_name->length == right_name->length ? exact
	    : left_name->length < right_name->length   ? -1
						       : 1;
}

static enum ntfs_result
mutation_directory_keys_reserve(
    struct ntfs_write_mutation_plan *plan, struct ntfs_mutation_directory *directory)
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
mutation_directory_key_append(struct ntfs_write_mutation_plan *plan,
    struct ntfs_mutation_directory *directory, const struct ntfs_disk_index_entry *entry)
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
	result = mutation_directory_keys_reserve(plan, directory);
	if (result != NTFS_OK) {
		return result;
	}
	key = &directory->keys[directory->count];
	key->reference = ntfs_u64(entry->reference);
	key->bytes = (uint16_t)bytes;
	ntfs_copy(key->value, filename, bytes);
	if (directory->count != 0 &&
	    ntfs_mutation_key_compare(plan, &directory->keys[directory->count - 1u], key) >= 0) {
		return NTFS_CORRUPT;
	}
	directory->count++;
	return NTFS_OK;
}

static enum ntfs_result
mutation_directory_walk(struct ntfs_write_mutation_plan *plan,
    struct ntfs_mutation_directory *directory, const uint8_t *buffer, size_t bytes,
    size_t header_offset, struct ntfs_stream *allocation, struct ntfs_stream *bitmap,
    struct ntfs_index_visited *visited, unsigned depth, uint64_t node_vcn)
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
	result = ntfs_mutation_index_load(
	    plan, directory, node_vcn, buffer + header_offset, bytes - header_offset);
	if (result != NTFS_OK) {
		return result;
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
				result = mutation_directory_walk(plan, directory, child,
				    NTFS_WRITE_CLUSTER_BYTES,
				    offsetof(struct ntfs_disk_index_block, header), allocation,
				    bitmap, visited, depth + 1u, vcn);
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
		result = mutation_directory_key_append(plan, directory, entry);
		if (result != NTFS_OK) {
			return result;
		}
		position += length;
	}
}

static enum ntfs_result
mutation_directory_bitmap_check(struct ntfs_write_mutation_plan *plan,
    const struct ntfs_stream *allocation, const struct ntfs_stream *bitmap,
    const struct ntfs_index_visited *visited)
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
		result = mutation_directory_walk(plan, directory, value, bytes, sizeof(*header),
		    allocation, bitmap, &visited, 0, NTFS_MUTATION_INDEX_ROOT_VCN);
	}
	if (result == NTFS_OK) {
		result = mutation_directory_bitmap_check(plan, allocation, bitmap, &visited);
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
	ntfs_mutation_index_close(plan, directory->tree);
	ntfs_mutation_release(
	    plan, directory->keys, directory->capacity * sizeof(*directory->keys));
	ntfs_zero(directory, sizeof(*directory));
}

static int
mutation_directory_name_compare(struct ntfs_write_mutation_plan *plan,
    const struct ntfs_mutation_key *key, const struct ntfs_write_name *name, bool exact)
{
	const struct ntfs_disk_filename *filename = (const void *)key->value;
	size_t unit, count = filename->length < name->count ? filename->length : name->count;
	uint16_t left, right, folded_left, folded_right;
	int tie = 0;

	for (unit = 0; unit < count; unit++) {
		left = ntfs_u16(key->value + sizeof(*filename) + unit * NTFS_UTF16_UNIT_BYTES);
		right = name->units[unit];
		if (tie == 0 && left != right) {
			tie = left < right ? -1 : 1;
		}
		folded_left = ntfs_u16(plan->volume->upcase + (size_t)left * NTFS_UTF16_UNIT_BYTES);
		folded_right =
		    ntfs_u16(plan->volume->upcase + (size_t)right * NTFS_UTF16_UNIT_BYTES);
		if (folded_left != folded_right) {
			return folded_left < folded_right ? -1 : 1;
		}
	}
	return filename->length == name->count ? (exact ? tie : 0)
	    : filename->length < name->count   ? -1
					       : 1;
}

enum ntfs_result
ntfs_mutation_directory_find(struct ntfs_write_mutation_plan *plan,
    struct ntfs_mutation_directory *directory, const struct ntfs_write_name *name, size_t *out)
{
	size_t first = 0, end = directory->count, middle;
	enum ntfs_result result;

	*out = 0;
	while (first < end) {
		result = ntfs_mutation_work(plan, name->count);
		if (result != NTFS_OK) {
			return result;
		}
		middle = first + (end - first) / 2;
		if (mutation_directory_name_compare(
			plan, &directory->keys[middle], name, directory->case_sensitive) < 0) {
			first = middle + 1;
		} else {
			end = middle;
		}
	}
	if (first == directory->count ||
	    mutation_directory_name_compare(
		plan, &directory->keys[first], name, directory->case_sensitive) != 0) {
		return NTFS_NOT_FOUND;
	}
	if (first + 1 < directory->count &&
	    mutation_directory_name_compare(
		plan, &directory->keys[first + 1], name, directory->case_sensitive) == 0) {
		return NTFS_CORRUPT;
	}
	*out = first;
	return NTFS_OK;
}

enum ntfs_result
ntfs_mutation_directory_add(struct ntfs_write_mutation_plan *plan,
    struct ntfs_mutation_directory *directory, uint64_t reference, const void *value, size_t bytes)
{
	struct ntfs_mutation_key key = {0};
	size_t position, index, end, middle;
	enum ntfs_result result;

	if (bytes > sizeof(key.value) || bytes < sizeof(struct ntfs_disk_filename)) {
		return NTFS_CORRUPT;
	}
	key.reference = reference;
	key.bytes = (uint16_t)bytes;
	ntfs_copy(key.value, value, bytes);
	position = 0;
	end = directory->count;
	while (position < end) {
		middle = position + (end - position) / 2;
		if (ntfs_mutation_key_compare(plan, &directory->keys[middle], &key) < 0) {
			position = middle + 1;
		} else {
			end = middle;
		}
	}
	if (position < directory->count &&
	    ntfs_mutation_key_compare(plan, &directory->keys[position], &key) == 0) {
		return NTFS_EXISTS;
	}
	result = mutation_directory_keys_reserve(plan, directory);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_mutation_index_edit(plan, directory, &key, false);
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

enum ntfs_result
ntfs_mutation_directory_remove(struct ntfs_write_mutation_plan *plan,
    struct ntfs_mutation_directory *directory, size_t position)
{
	size_t index;
	enum ntfs_result result;

	if (position >= directory->count) {
		return NTFS_RANGE;
	}
	result = ntfs_mutation_index_edit(plan, directory, &directory->keys[position], true);
	if (result != NTFS_OK) {
		return result;
	}
	for (index = position + 1u; index < directory->count; index++) {
		directory->keys[index - 1u] = directory->keys[index];
	}
	directory->count--;
	return NTFS_OK;
}

enum ntfs_result
ntfs_mutation_directory_update(struct ntfs_write_mutation_plan *plan,
    struct ntfs_mutation_directory *directory, size_t position, const void *value, size_t bytes)
{
	struct ntfs_mutation_key key;
	enum ntfs_result result;

	if (position >= directory->count || bytes != directory->keys[position].bytes) {
		return NTFS_RANGE;
	}
	key = directory->keys[position];
	ntfs_copy(key.value, value, bytes);
	if (ntfs_mutation_key_compare(plan, &key, &directory->keys[position]) != 0) {
		return NTFS_INVALID;
	}
	result = ntfs_mutation_index_edit(plan, directory, &key, false);
	if (result == NTFS_OK) {
		directory->keys[position] = key;
	}
	return result;
}
