/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"

enum { LINKS_HEAP_ARITY = 2 };

struct link_location {
	uint64_t reference;
	uint16_t instance;
	bool seen;
};

static int
location_compare(const struct link_location *first, const struct link_location *second)
{
	if (first->reference != second->reference) {
		return first->reference < second->reference ? -1 : 1;
	}
	if (first->instance != second->instance) {
		return first->instance < second->instance ? -1 : 1;
	}
	return 0;
}

static void
location_swap(struct link_location *first, struct link_location *second)
{
	struct link_location saved = *first;

	*first = *second;
	*second = saved;
}

static enum ntfs_result
location_sift(struct ntfs_volume *v, struct link_location *locations, uint32_t root, uint32_t count)
{
	uint32_t child;
	enum ntfs_result result;

	while (root < count / LINKS_HEAP_ARITY) {
		result = ntfs_work(v, (LINKS_HEAP_ARITY + 1) * sizeof(*locations));
		if (result != NTFS_OK) {
			return result;
		}
		child = root * LINKS_HEAP_ARITY + 1;
		if (child + 1 < count &&
		    location_compare(&locations[child], &locations[child + 1]) < 0) {
			child++;
		}
		if (location_compare(&locations[root], &locations[child]) >= 0) {
			break;
		}
		location_swap(&locations[root], &locations[child]);
		root = child;
	}
	return NTFS_OK;
}

static enum ntfs_result
locations_sort(struct ntfs_volume *v, struct link_location *locations, uint32_t count)
{
	uint32_t index;
	enum ntfs_result result;

	for (index = count / LINKS_HEAP_ARITY; index != 0; index--) {
		result = location_sift(v, locations, index - 1, count);
		if (result != NTFS_OK) {
			return result;
		}
	}
	for (index = count; index > 1; index--) {
		result = ntfs_work(v, LINKS_HEAP_ARITY * sizeof(*locations));
		if (result != NTFS_OK) {
			return result;
		}
		location_swap(&locations[0], &locations[index - 1]);
		result = location_sift(v, locations, 0, index - 1);
		if (result != NTFS_OK) {
			return result;
		}
	}
	return NTFS_OK;
}

static enum ntfs_result
filename_count(const struct ntfs_attr_view *attribute, struct ntfs_link_counts *counts)
{
	const struct ntfs_disk_filename *name;
	const uint8_t *value;
	size_t bytes, index;
	uint16_t unit;
	enum ntfs_result result;

	result = ntfs_attr_value(attribute, &value, &bytes);
	if (result != NTFS_OK || attribute->flags != 0 || attribute->disk->name_length != 0 ||
	    bytes < sizeof(*name)) {
		return NTFS_CORRUPT;
	}
	name = (const void *)value;
	if (name->length == 0 || name->name_namespace > NTFS_NAMESPACE_WIN32_DOS ||
	    bytes != sizeof(*name) + (size_t)name->length * NTFS_UTF16_UNIT_BYTES ||
	    ntfs_u64(name->parent) >> NTFS_REFERENCE_SEQUENCE_SHIFT == 0 ||
	    counts->physical_names == UINT16_MAX) {
		return NTFS_CORRUPT;
	}
	for (index = 0; index < name->length; index++) {
		unit = ntfs_u16(value + sizeof(*name) + index * NTFS_UTF16_UNIT_BYTES);
		if (unit == 0 || unit == '/') {
			return NTFS_CORRUPT;
		}
	}
	counts->physical_names++;
	if (name->name_namespace == NTFS_NAMESPACE_DOS) {
		counts->dos_aliases++;
	} else {
		counts->primary_names++;
	}
	return NTFS_OK;
}

static enum ntfs_result
record_count(struct ntfs_node *node, const uint8_t *record, struct link_location *locations,
    uint32_t count, bool listed, struct ntfs_link_counts *counts)
{
	const struct ntfs_disk_record *header = (const void *)record;
	struct ntfs_attr_view attribute;
	uint32_t position = ntfs_u16(header->attrs_offset), low, high, middle, seen = 0;
	enum ntfs_result result;

	result = ntfs_work(node->volume, node->volume->info.record_size);
	if (result != NTFS_OK) {
		return result;
	}
	while ((result = ntfs_attr_at(record, ntfs_u32(header->used), &position, &attribute)) ==
	    NTFS_OK) {
		result = ntfs_work(node->volume, attribute.length);
		if (result != NTFS_OK) {
			return result;
		}
		if (attribute.type != NTFS_ATTR_FILENAME) {
			continue;
		}
		if (seen == count) {
			return NTFS_CORRUPT;
		}
		if (listed) {
			low = 0;
			high = count;
			while (low < high) {
				result = ntfs_work(node->volume, sizeof(*locations));
				if (result != NTFS_OK) {
					return result;
				}
				middle = low + (high - low) / LINKS_HEAP_ARITY;
				if (locations[middle].instance < attribute.instance) {
					low = middle + 1;
				} else {
					high = middle;
				}
			}
			if (low == count || locations[low].instance != attribute.instance ||
			    locations[low].seen) {
				return NTFS_CORRUPT;
			}
			locations[low].seen = true;
		} else if (locations != NULL) {
			locations[seen] =
			    (struct link_location){node->reference, attribute.instance, false};
		}
		result = filename_count(&attribute, counts);
		if (result != NTFS_OK) {
			return result;
		}
		seen++;
	}
	if (result != NTFS_END) {
		return result;
	}
	return seen == count ? NTFS_OK : NTFS_CORRUPT;
}

static enum ntfs_result
local_counts(struct ntfs_node *node, uint16_t physical, struct ntfs_link_counts *counts)
{
	struct link_location *locations = NULL;
	size_t allocation = (size_t)physical * sizeof(*locations);
	uint32_t index;
	enum ntfs_result result;

	if (physical > 1) {
		locations = ntfs_alloc(node->volume, allocation);
		if (locations == NULL) {
			return NTFS_NO_MEMORY;
		}
	}
	result = record_count(node, node->record, locations, physical, false, counts);
	if (result == NTFS_OK && locations != NULL) {
		result = locations_sort(node->volume, locations, physical);
	}
	for (index = 1; result == NTFS_OK && index < physical; index++) {
		result = ntfs_work(node->volume, LINKS_HEAP_ARITY * sizeof(*locations));
		if (result == NTFS_OK &&
		    locations[index].instance == locations[index - 1].instance) {
			result = NTFS_CORRUPT;
		}
	}
	ntfs_free(node->volume, locations, allocation);
	return result;
}

static enum ntfs_result
listed_counts(struct ntfs_node *node, const uint8_t *bytes, size_t size, uint16_t physical,
    struct ntfs_link_counts *counts)
{
	struct ntfs_volume *v = node->volume;
	struct link_location *locations;
	const struct ntfs_disk_attr_list *entry;
	const struct ntfs_disk_record *header;
	uint8_t *record = NULL;
	uint32_t count = 0, first, end;
	uint64_t reference;
	size_t offset = 0, allocation = (size_t)physical * sizeof(*locations);
	bool base_seen = false;
	enum ntfs_result result;

	locations = ntfs_alloc(v, allocation);
	if (locations == NULL) {
		return NTFS_NO_MEMORY;
	}
	while ((result = ntfs_list_entry_at(bytes, size, &offset, &entry)) == NTFS_OK) {
		result = ntfs_work(v, ntfs_u16(entry->length));
		if (result != NTFS_OK) {
			break;
		}
		if (ntfs_u32(entry->type) != NTFS_ATTR_FILENAME) {
			continue;
		}
		reference = ntfs_u64(entry->reference);
		if (count == physical || entry->name_length != 0 || ntfs_u64(entry->lowest) != 0 ||
		    reference >> NTFS_REFERENCE_SEQUENCE_SHIFT == 0 ||
		    ntfs_u16(entry->instance) == UINT16_MAX) {
			result = NTFS_CORRUPT;
			break;
		}
		locations[count++] =
		    (struct link_location){reference, ntfs_u16(entry->instance), false};
	}
	if (result == NTFS_END) {
		result = count == physical ? locations_sort(v, locations, count) : NTFS_CORRUPT;
	}
	for (first = 0; result == NTFS_OK && first < count; first = end) {
		end = first + 1;
		reference = locations[first].reference;
		while (end < count && locations[end].reference == reference) {
			result = ntfs_work(v, sizeof(*locations));
			if (result != NTFS_OK) {
				break;
			}
			if (locations[end].instance == locations[end - 1].instance) {
				result = NTFS_CORRUPT;
				break;
			}
			end++;
		}
		if (result != NTFS_OK) {
			break;
		}
		if (reference == node->reference) {
			base_seen = true;
			record = node->record;
		} else {
			result =
			    ntfs_record_read(v, reference & NTFS_REFERENCE_RECORD_MASK, &record);
			if (result != NTFS_OK) {
				break;
			}
			header = (const void *)record;
			if (ntfs_u16(header->sequence) !=
				reference >> NTFS_REFERENCE_SEQUENCE_SHIFT ||
			    ntfs_u64(header->base_reference) != node->reference) {
				result = NTFS_STALE;
			}
		}
		if (result == NTFS_OK) {
			result = record_count(
			    node, record, locations + first, end - first, true, counts);
		}
		if (record != node->record) {
			ntfs_free(v, record, v->info.record_size);
		}
		record = NULL;
	}
	if (result == NTFS_OK && !base_seen) {
		/* Even a list placing all names in extensions must account for every
		 * physical filename present in the base snapshot. */
		result = record_count(node, node->record, locations, 0, true, counts);
	}
	ntfs_free(v, locations, allocation);
	return result;
}

enum ntfs_result
ntfs_node_link_counts_impl(struct ntfs_node *node, struct ntfs_link_counts *out)
{
	struct ntfs_volume *v;
	struct ntfs_link_count_cache *cached;
	const struct ntfs_disk_record *header;
	struct ntfs_link_counts counts = {0};
	uint8_t *list = NULL;
	size_t bytes = 0;
	uint16_t physical;
	uint32_t index;
	enum ntfs_result result;

	if (node == NULL) {
		return NTFS_INVALID;
	}
	result = ntfs_work(node->volume, sizeof(*out));
	if (result != NTFS_OK) {
		return result;
	}
	if (node->link_counts_verified) {
		*out = node->link_counts;
		return NTFS_OK;
	}
	v = node->volume;
	header = (const void *)node->record;
	physical = ntfs_u16(header->links);
	if (physical == 0) {
		return NTFS_CORRUPT;
	}
	for (index = 0; v->cache != NULL && index < v->limits.record_cache_entries; index++) {
		cached = &v->cache[index].links;
		result = ntfs_work(v, sizeof(*cached));
		if (result != NTFS_OK) {
			return result;
		}
		if (cached->reference == node->reference) {
			if (cached->counts.physical_names != physical) {
				return NTFS_CORRUPT;
			}
			counts = cached->counts;
			goto verified;
		}
	}
	if (v->cache != NULL) {
		/* Charge publication before cold I/O. Failed inventories never publish. */
		result = ntfs_work(v, sizeof(*cached));
		if (result != NTFS_OK) {
			return result;
		}
	}
	result = ntfs_attribute_list_read(node, &list, &bytes);
	if (result == NTFS_NOT_FOUND) {
		result = local_counts(node, physical, &counts);
	} else if (result == NTFS_OK) {
		result = listed_counts(node, list, bytes, physical, &counts);
	}
	ntfs_free(node->volume, list, bytes);
	if (result != NTFS_OK) {
		return result;
	}
	if (counts.physical_names != physical || counts.primary_names == 0) {
		return NTFS_CORRUPT;
	}
	if (v->cache != NULL) {
		cached = &v->cache[v->next_link_cache].links;
		cached->counts = counts;
		cached->reference = node->reference;
		v->next_link_cache++;
		if (v->next_link_cache == v->limits.record_cache_entries) {
			v->next_link_cache = 0;
		}
	}
verified:
	node->link_counts = counts;
	node->link_counts_verified = true;
	*out = counts;
	return NTFS_OK;
}
