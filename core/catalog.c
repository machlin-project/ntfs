/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"

struct catalog_entry {
	struct ntfs_stream_name name;
	uint64_t reference;
	uint16_t instance;
};

struct ntfs_stream_catalog {
	struct ntfs_volume *volume;
	struct catalog_entry *entries;
	uint32_t count, capacity, maximum;
	bool external;
};

static int
catalog_compare(const struct ntfs_stream_name *left, const struct ntfs_stream_name *right)
{
	size_t i, length = left->length < right->length ? left->length : right->length;

	for (i = 0; i < length; i++) {
		if (left->units[i] != right->units[i]) {
			return left->units[i] < right->units[i] ? -1 : 1;
		}
	}
	return left->length < right->length ? -1 : left->length != right->length;
}

static enum ntfs_result
catalog_compare_work(const struct ntfs_stream_catalog *catalog, const struct ntfs_stream_name *left,
    const struct ntfs_stream_name *right, int *out)
{
	size_t length = left->length < right->length ? left->length : right->length;
	enum ntfs_result result;

	result = ntfs_work(catalog->volume, 1 + length);
	if (result == NTFS_OK) {
		*out = catalog_compare(left, right);
	}
	return result;
}

static enum ntfs_result
catalog_sift(struct ntfs_stream_catalog *catalog, uint32_t root, uint32_t count)
{
	struct catalog_entry *entries = catalog->entries;
	struct catalog_entry temporary;
	uint32_t child;
	int comparison;
	enum ntfs_result result;

	while (root < count / 2) {
		child = root * 2 + 1;
		if (child + 1 < count) {
			result = catalog_compare_work(
			    catalog, &entries[child].name, &entries[child + 1].name, &comparison);
			if (result != NTFS_OK) {
				return result;
			}
			if (comparison < 0) {
				child++;
			}
		}
		result = catalog_compare_work(
		    catalog, &entries[root].name, &entries[child].name, &comparison);
		if (result != NTFS_OK) {
			return result;
		}
		if (comparison >= 0) {
			break;
		}
		temporary = entries[root];
		entries[root] = entries[child];
		entries[child] = temporary;
		root = child;
	}
	return NTFS_OK;
}

static enum ntfs_result
catalog_sort(struct ntfs_stream_catalog *catalog)
{
	struct catalog_entry temporary;
	uint32_t i;
	int comparison;
	enum ntfs_result result;

	for (i = catalog->count / 2; i != 0; i--) {
		result = catalog_sift(catalog, i - 1, catalog->count);
		if (result != NTFS_OK) {
			return result;
		}
	}
	for (i = catalog->count; i > 1; i--) {
		temporary = catalog->entries[0];
		catalog->entries[0] = catalog->entries[i - 1];
		catalog->entries[i - 1] = temporary;
		result = catalog_sift(catalog, 0, i - 1);
		if (result != NTFS_OK) {
			return result;
		}
	}
	for (i = 1; i < catalog->count; i++) {
		result = catalog_compare_work(
		    catalog, &catalog->entries[i - 1].name, &catalog->entries[i].name, &comparison);
		if (result != NTFS_OK) {
			return result;
		}
		if (comparison == 0) {
			return NTFS_CORRUPT;
		}
	}
	return NTFS_OK;
}

static enum ntfs_result
catalog_add(struct ntfs_stream_catalog *catalog, const uint8_t *name, uint8_t length,
    uint64_t reference, uint16_t instance)
{
	struct catalog_entry *entries, *entry;
	uint32_t capacity;
	size_t i;

	if (catalog->count == catalog->maximum) {
		return NTFS_RANGE;
	}
	if (catalog->count == catalog->capacity) {
		capacity = catalog->capacity == 0 ? NTFS_CATALOG_INITIAL_CAPACITY
						  : catalog->capacity * NTFS_VECTOR_GROWTH;
		if (capacity > catalog->maximum) {
			capacity = catalog->maximum;
		}
		entries = ntfs_alloc(catalog->volume, (size_t)capacity * sizeof(*entries));
		if (entries == NULL) {
			return NTFS_NO_MEMORY;
		}
		ntfs_copy(entries, catalog->entries, (size_t)catalog->count * sizeof(*entries));
		ntfs_free(catalog->volume, catalog->entries,
		    (size_t)catalog->capacity * sizeof(*entries));
		catalog->entries = entries;
		catalog->capacity = capacity;
	}
	entry = &catalog->entries[catalog->count++];
	entry->name.length = length;
	for (i = 0; i < length; i++) {
		entry->name.units[i] = ntfs_u16(name + i * NTFS_UTF16_UNIT_BYTES);
	}
	entry->reference = reference;
	entry->instance = instance;
	return NTFS_OK;
}

static uint64_t
attribute_lowest(const struct ntfs_attr_view *attr)
{
	const struct ntfs_disk_nonresident *nonresident;

	if (!attr->disk->nonresident) {
		return 0;
	}
	nonresident = (const void *)(attr->bytes + sizeof(struct ntfs_disk_attr));
	return ntfs_u64(nonresident->lowest);
}

static enum ntfs_result
catalog_from_record(struct ntfs_node *node, struct ntfs_stream_catalog *catalog)
{
	const struct ntfs_disk_record *header = (const void *)node->record;
	struct ntfs_attr_view attr;
	uint32_t position = ntfs_u16(header->attrs_offset);
	enum ntfs_result result;

	result = ntfs_work(node->volume, node->volume->info.record_size);
	if (result != NTFS_OK) {
		return result;
	}
	while ((result = ntfs_attr_at(node->record, ntfs_u32(header->used), &position, &attr)) ==
	    NTFS_OK) {
		if (attr.type != NTFS_ATTRIBUTE_DATA) {
			continue;
		}
		if (attribute_lowest(&attr) != 0) {
			return NTFS_CORRUPT;
		}
		result = catalog_add(catalog, attr.bytes + ntfs_u16(attr.disk->name_offset),
		    attr.disk->name_length, node->reference, attr.instance);
		if (result != NTFS_OK) {
			return result;
		}
	}
	return result == NTFS_END ? NTFS_OK : result;
}

static enum ntfs_result
catalog_from_list(
    struct ntfs_node *node, struct ntfs_stream_catalog *catalog, const uint8_t *bytes, size_t size)
{
	struct ntfs_volume *v = node->volume;
	const struct ntfs_disk_attr_list *entry;
	const struct ntfs_disk_record *header;
	struct ntfs_attr_view attr;
	struct ntfs_stream_name name = {0};
	uint8_t *record = NULL;
	uint64_t reference, loaded_reference = 0;
	size_t offset = 0, i;
	enum ntfs_result result;

	while ((result = ntfs_list_entry_at(bytes, size, &offset, &entry)) == NTFS_OK) {
		result = ntfs_work(v, ntfs_u16(entry->length));
		if (result != NTFS_OK) {
			break;
		}
		if (ntfs_u32(entry->type) != NTFS_ATTRIBUTE_DATA) {
			continue;
		}
		reference = ntfs_u64(entry->reference);
		if (reference >> NTFS_REFERENCE_SEQUENCE_SHIFT == 0 ||
		    ntfs_u16(entry->instance) == UINT16_MAX) {
			result = NTFS_CORRUPT;
			break;
		}
		if (ntfs_u64(entry->lowest) != 0) {
			continue;
		}
		if (catalog->count == catalog->maximum) {
			result = NTFS_RANGE;
			break;
		}
		if (reference != loaded_reference) {
			if (record != node->record) {
				ntfs_free(v, record, v->info.record_size);
			}
			record = NULL;
			if (reference == node->reference) {
				record = node->record;
			} else {
				result = ntfs_record_read(
				    v, reference & NTFS_REFERENCE_RECORD_MASK, &record);
				if (result != NTFS_OK) {
					break;
				}
				header = (const void *)record;
				if (ntfs_u16(header->sequence) !=
					reference >> NTFS_REFERENCE_SEQUENCE_SHIFT ||
				    ntfs_u64(header->base_reference) != node->reference) {
					result = NTFS_STALE;
					break;
				}
			}
			loaded_reference = reference;
		}
		name.length = entry->name_length;
		for (i = 0; i < name.length; i++) {
			name.units[i] = ntfs_u16((const uint8_t *)entry + entry->name_offset +
			    i * NTFS_UTF16_UNIT_BYTES);
		}
		result = ntfs_work(v, v->info.record_size);
		if (result == NTFS_OK) {
			result = ntfs_listed_attribute(record, NTFS_ATTRIBUTE_DATA, name.units,
			    name.length, ntfs_u16(entry->instance), 0, &attr);
		}
		if (result != NTFS_OK) {
			break;
		}
		result = catalog_add(catalog, attr.bytes + ntfs_u16(attr.disk->name_offset),
		    attr.disk->name_length, reference, attr.instance);
		if (result != NTFS_OK) {
			break;
		}
	}
	if (record != node->record) {
		ntfs_free(v, record, v->info.record_size);
	}
	return result == NTFS_END ? NTFS_OK : result;
}

static enum ntfs_result
catalog_check_base(struct ntfs_node *node, const struct ntfs_stream_catalog *catalog)
{
	const struct ntfs_disk_record *header = (const void *)node->record;
	const struct catalog_entry *entry;
	struct ntfs_attr_view attr;
	struct ntfs_stream_name name = {0};
	uint32_t position = ntfs_u16(header->attrs_offset), low, high, middle;
	size_t i;
	int comparison;
	enum ntfs_result result;

	result = ntfs_work(node->volume, node->volume->info.record_size);
	if (result != NTFS_OK) {
		return result;
	}
	while ((result = ntfs_attr_at(node->record, ntfs_u32(header->used), &position, &attr)) ==
	    NTFS_OK) {
		if (attr.type != NTFS_ATTRIBUTE_DATA || attribute_lowest(&attr) != 0) {
			continue;
		}
		name.length = attr.disk->name_length;
		for (i = 0; i < name.length; i++) {
			name.units[i] = ntfs_u16(attr.bytes + ntfs_u16(attr.disk->name_offset) +
			    i * NTFS_UTF16_UNIT_BYTES);
		}
		low = 0;
		high = catalog->count;
		while (low < high) {
			middle = low + (high - low) / 2;
			result = catalog_compare_work(
			    catalog, &catalog->entries[middle].name, &name, &comparison);
			if (result != NTFS_OK) {
				return result;
			}
			if (comparison < 0) {
				low = middle + 1;
			} else {
				high = middle;
			}
		}
		if (low == catalog->count) {
			return NTFS_CORRUPT;
		}
		entry = &catalog->entries[low];
		result = catalog_compare_work(catalog, &entry->name, &name, &comparison);
		if (result != NTFS_OK) {
			return result;
		}
		if (comparison != 0 || entry->reference != node->reference ||
		    entry->instance != attr.instance) {
			return NTFS_CORRUPT;
		}
	}
	return result == NTFS_END ? NTFS_OK : result;
}

enum ntfs_result
ntfs_stream_catalog_open_impl(
    struct ntfs_node *node, uint32_t maximum, struct ntfs_stream_catalog **out)
{
	struct ntfs_stream_catalog *catalog;
	struct ntfs_stat metadata;
	uint8_t *bytes = NULL;
	size_t size = 0;
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	*out = NULL;
	if (node == NULL || maximum == 0 || maximum > NTFS_MAX_STREAM_CATALOG_ENTRIES) {
		return NTFS_INVALID;
	}
	if (node->volume->children == UINT32_MAX) {
		return NTFS_RANGE;
	}
	result = ntfs_node_metadata(node, &metadata);
	if (result != NTFS_OK) {
		return result;
	}
	catalog = ntfs_alloc(node->volume, sizeof(*catalog));
	if (catalog == NULL) {
		return NTFS_NO_MEMORY;
	}
	catalog->volume = node->volume;
	catalog->maximum = maximum;
	result = ntfs_attribute_list_read(node, &bytes, &size);
	if (result == NTFS_NOT_FOUND) {
		result = catalog_from_record(node, catalog);
	} else if (result == NTFS_OK) {
		result = catalog_from_list(node, catalog, bytes, size);
	}
	ntfs_free(node->volume, bytes, size);
	if (result == NTFS_OK) {
		result = catalog_sort(catalog);
	}
	if (result == NTFS_OK) {
		result = catalog_check_base(node, catalog);
	}
	if (result != NTFS_OK) {
		ntfs_stream_catalog_close(catalog);
		return result;
	}
	catalog->external = true;
	node->volume->children++;
	*out = catalog;
	return NTFS_OK;
}

uint32_t
ntfs_stream_catalog_count(const struct ntfs_stream_catalog *catalog)
{
	return catalog != NULL ? catalog->count : 0;
}

enum ntfs_result
ntfs_stream_catalog_entry_impl(
    const struct ntfs_stream_catalog *catalog, uint32_t index, struct ntfs_stream_name *out)
{
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (catalog == NULL) {
		return NTFS_INVALID;
	}
	if (index >= catalog->count) {
		return NTFS_END;
	}
	result = ntfs_work(catalog->volume, sizeof(*out));
	if (result != NTFS_OK) {
		return result;
	}
	*out = catalog->entries[index].name;
	return NTFS_OK;
}

void
ntfs_stream_catalog_close(struct ntfs_stream_catalog *catalog)
{
	struct ntfs_volume *v;

	if (catalog == NULL) {
		return;
	}
	v = catalog->volume;
	if (catalog->external) {
		v->children--;
	}
	ntfs_free(v, catalog->entries, (size_t)catalog->capacity * sizeof(*catalog->entries));
	ntfs_free(v, catalog, sizeof(*catalog));
}

struct ntfs_volume *
ntfs_catalog_volume(const struct ntfs_stream_catalog *object)
{
	return object == NULL ? NULL : object->volume;
}
