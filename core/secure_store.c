/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "secure_internal.h"

static const uint16_t sds_name[] = {'$', 'S', 'D', 'S'};

static void ntfs_secure_store_subject(
    struct ntfs_security_store_report *report, const struct ntfs_disk_security_locator *locator);
static enum ntfs_result ntfs_secure_find_locator(struct ntfs_volume *volume,
    const struct ntfs_disk_security_locator *locators, uint32_t count, uint32_t id,
    enum ntfs_result (*charge)(void *, uint64_t), void *context,
    const struct ntfs_disk_security_locator **out);
static void ntfs_secure_swap_locators(
    struct ntfs_disk_security_locator *left, struct ntfs_disk_security_locator *right);
static enum ntfs_result ntfs_secure_sift_offsets(struct ntfs_volume *volume,
    struct ntfs_disk_security_locator *locators, uint32_t root, uint32_t count,
    enum ntfs_result (*charge)(void *, uint64_t), void *context);
static enum ntfs_result ntfs_secure_sort_offsets(struct ntfs_volume *volume,
    struct ntfs_disk_security_locator *locators, uint32_t count,
    enum ntfs_result (*charge)(void *, uint64_t), void *context);

void
ntfs_security_store_default_limits(struct ntfs_security_store_limits *limits)
{
	if (limits != NULL) {
		limits->max_descriptors = NTFS_SECURITY_STORE_DEFAULT_DESCRIPTORS;
	}
}

static void
ntfs_secure_store_subject(
    struct ntfs_security_store_report *report, const struct ntfs_disk_security_locator *locator)
{
	report->security_id = ntfs_u32(locator->security_id);
	report->hash = ntfs_u32(locator->hash);
	report->offset = ntfs_u64(locator->offset);
	report->cluster = 0;
}

static enum ntfs_result
ntfs_secure_find_locator(struct ntfs_volume *volume,
    const struct ntfs_disk_security_locator *locators, uint32_t count, uint32_t id,
    enum ntfs_result (*charge)(void *, uint64_t), void *context,
    const struct ntfs_disk_security_locator **out)
{
	uint32_t first = 0, end = count, middle, found;
	enum ntfs_result result;

	*out = NULL;
	while (first < end) {
		result = ntfs_index_work(volume, charge, context, 1);
		if (result != NTFS_OK) {
			return result;
		}
		middle = first + (end - first) / NTFS_VECTOR_GROWTH;
		found = ntfs_u32(locators[middle].security_id);
		if (found == id) {
			*out = &locators[middle];
			return NTFS_OK;
		}
		if (found < id) {
			first = middle + 1;
		} else {
			end = middle;
		}
	}
	return NTFS_NOT_FOUND;
}

static void
ntfs_secure_swap_locators(
    struct ntfs_disk_security_locator *left, struct ntfs_disk_security_locator *right)
{
	struct ntfs_disk_security_locator temporary = *left;

	*left = *right;
	*right = temporary;
}

static enum ntfs_result
ntfs_secure_sift_offsets(struct ntfs_volume *volume, struct ntfs_disk_security_locator *locators,
    uint32_t root, uint32_t count, enum ntfs_result (*charge)(void *, uint64_t), void *context)
{
	uint32_t child;
	enum ntfs_result result;

	while (root < count / NTFS_VECTOR_GROWTH) {
		result = ntfs_index_work(volume, charge, context, 1);
		if (result != NTFS_OK) {
			return result;
		}
		child = root * NTFS_VECTOR_GROWTH + 1;
		if (child + 1 < count &&
		    ntfs_u64(locators[child].offset) < ntfs_u64(locators[child + 1].offset)) {
			child++;
		}
		if (ntfs_u64(locators[root].offset) >= ntfs_u64(locators[child].offset)) {
			break;
		}
		ntfs_secure_swap_locators(&locators[root], &locators[child]);
		root = child;
	}
	return NTFS_OK;
}

static enum ntfs_result
ntfs_secure_sort_offsets(struct ntfs_volume *volume, struct ntfs_disk_security_locator *locators,
    uint32_t count, enum ntfs_result (*charge)(void *, uint64_t), void *context)
{
	uint32_t index;
	enum ntfs_result result;

	for (index = count / NTFS_VECTOR_GROWTH; index != 0; index--) {
		result =
		    ntfs_secure_sift_offsets(volume, locators, index - 1, count, charge, context);
		if (result != NTFS_OK) {
			return result;
		}
	}
	for (index = count; index > 1; index--) {
		result = ntfs_index_work(volume, charge, context, 1);
		if (result != NTFS_OK) {
			return result;
		}
		ntfs_secure_swap_locators(&locators[0], &locators[index - 1]);
		result = ntfs_secure_sift_offsets(volume, locators, 0, index - 1, charge, context);
		if (result != NTFS_OK) {
			return result;
		}
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_security_store_validate_impl(struct ntfs_volume *volume,
    const struct ntfs_security_store_limits *limits, struct ntfs_security_store_report *report,
    enum ntfs_result (*charge)(void *, uint64_t), void *context,
    enum ntfs_result (*references)(void *, const struct ntfs_disk_security_locator *, uint32_t))
{
	struct ntfs_security_store_limits selected = {NTFS_SECURITY_STORE_DEFAULT_DESCRIPTORS};
	struct ntfs_node *node = NULL;
	struct ntfs_stream *store = NULL;
	struct ntfs_secure_index_cursor *cursor = NULL;
	struct ntfs_disk_security_locator *locators = NULL, *replacement;
	const struct ntfs_disk_security_locator *found;
	struct ntfs_disk_security_locator locator;
	struct ntfs_security snapshot;
	struct ntfs_stat stat;
	uint32_t count = 0, capacity = 0, grown, index;
	uint64_t previous_end = 0;
	enum ntfs_result result;

	if (report == NULL) {
		return NTFS_INVALID;
	}
	if (limits != NULL) {
		selected = *limits;
	}
	ntfs_zero(report, sizeof(*report));
	report->result = NTFS_INVALID;
	if (volume == NULL || selected.max_descriptors == 0 ||
	    selected.max_descriptors > NTFS_SECURITY_STORE_MAX_DESCRIPTORS) {
		return NTFS_INVALID;
	}
	result = ntfs_node_by_number(volume, NTFS_SECURE_RECORD, &node);
	if (result == NTFS_OK) {
		report->reference = node->reference;
		result = ntfs_node_metadata(node, &stat);
	}
	if (result != NTFS_OK) {
		goto finish;
	}
	if (stat.directory || stat.reparse) {
		result = NTFS_CORRUPT;
		goto finish;
	}
	result = ntfs_attribute_open(
	    node, NTFS_ATTRIBUTE_DATA, sds_name, sizeof(sds_name) / sizeof(sds_name[0]), &store);
	if (result != NTFS_OK) {
		result = result == NTFS_NOT_FOUND ? NTFS_CORRUPT : result;
		goto finish;
	}
	if (store->resident || store->flags != 0 || store->initialized != store->size) {
		result = NTFS_CORRUPT;
		goto finish;
	}
	report->stage = NTFS_SECURITY_STORE_SII;
	result = ntfs_secure_cursor_open(node, false, store->size, charge, context, &cursor);
	if (result != NTFS_OK) {
		goto finish;
	}
	while ((result = ntfs_secure_cursor_next(cursor, &locator)) == NTFS_OK) {
		ntfs_secure_store_subject(report, &locator);
		if (count == selected.max_descriptors) {
			report->descriptor_limit = true;
			result = NTFS_RANGE;
			goto finish;
		}
		if (count == capacity) {
			grown = capacity == 0 ? NTFS_CATALOG_INITIAL_CAPACITY
					      : capacity * NTFS_VECTOR_GROWTH;
			if (grown > selected.max_descriptors) {
				grown = selected.max_descriptors;
			}
			result = ntfs_index_work(
			    volume, charge, context, (uint64_t)count * sizeof(*locators));
			if (result != NTFS_OK) {
				goto finish;
			}
			replacement = ntfs_alloc(volume, (size_t)grown * sizeof(*replacement));
			if (replacement == NULL) {
				result = NTFS_NO_MEMORY;
				goto finish;
			}
			ntfs_copy(replacement, locators, (size_t)count * sizeof(*locators));
			ntfs_free(volume, locators, (size_t)capacity * sizeof(*locators));
			locators = replacement;
			capacity = grown;
		}
		locators[count++] = locator;
		report->sii_entries++;
	}
	if (result != NTFS_END) {
		goto finish;
	}
	report->sii_blocks = cursor->visited.count;
	report->stage = NTFS_SECURITY_STORE_SII_ALLOCATION;
	result = ntfs_index_check_allocation(volume, cursor->allocation, cursor->bitmap,
	    &cursor->visited, cursor->block_size, charge, context, &report->cluster);
	if (result != NTFS_OK) {
		goto finish;
	}
	ntfs_secure_cursor_close(cursor);
	cursor = NULL;
	report->stage = NTFS_SECURITY_STORE_SDH;
	report->security_id = 0;
	report->hash = 0;
	report->offset = 0;
	result = ntfs_secure_cursor_open(node, true, store->size, charge, context, &cursor);
	if (result != NTFS_OK) {
		goto finish;
	}
	while ((result = ntfs_secure_cursor_next(cursor, &locator)) == NTFS_OK) {
		ntfs_secure_store_subject(report, &locator);
		result = ntfs_secure_find_locator(volume, locators, count,
		    ntfs_u32(locator.security_id), charge, context, &found);
		if (result == NTFS_NOT_FOUND ||
		    (result == NTFS_OK && !ntfs_equal(found, &locator, sizeof(locator)))) {
			result = NTFS_CORRUPT;
		}
		if (result != NTFS_OK) {
			goto finish;
		}
		report->sdh_entries++;
	}
	if (result != NTFS_END || report->sdh_entries != count) {
		result = result == NTFS_END ? NTFS_CORRUPT : result;
		goto finish;
	}
	report->sdh_blocks = cursor->visited.count;
	report->stage = NTFS_SECURITY_STORE_SDH_ALLOCATION;
	result = ntfs_index_check_allocation(volume, cursor->allocation, cursor->bitmap,
	    &cursor->visited, cursor->block_size, charge, context, &report->cluster);
	if (result != NTFS_OK) {
		goto finish;
	}
	ntfs_secure_cursor_close(cursor);
	cursor = NULL;
	if (references != NULL) {
		result = references(context, locators, count);
		if (result != NTFS_OK) {
			goto finish;
		}
	}
	report->stage = NTFS_SECURITY_STORE_DESCRIPTORS;
	result = ntfs_secure_sort_offsets(volume, locators, count, charge, context);
	if (result != NTFS_OK) {
		goto finish;
	}
	for (index = 0; index < count; index++) {
		ntfs_secure_store_subject(report, &locators[index]);
		result = ntfs_index_work(volume, charge, context, sizeof(locator));
		if (result != NTFS_OK) {
			goto finish;
		}
		if (ntfs_u64(locators[index].offset) < previous_end) {
			result = NTFS_CORRUPT;
			goto finish;
		}
		previous_end = ntfs_u64(locators[index].offset) + ntfs_u32(locators[index].length);
	}
	for (index = 0; index < count; index++) {
		ntfs_secure_store_subject(report, &locators[index]);
		ntfs_zero(&snapshot, sizeof(snapshot));
		result = ntfs_secure_read_descriptor(
		    store, &locators[index], &snapshot, charge, context);
		ntfs_free(volume, snapshot.bytes, snapshot.size);
		if (result != NTFS_OK) {
			goto finish;
		}
		report->descriptors++;
		report->descriptor_bytes += snapshot.size;
	}
	report->complete = true;
	report->stage = NTFS_SECURITY_STORE_FINISHED;
	report->security_id = 0;
	report->hash = 0;
	report->offset = 0;
	report->cluster = 0;
	result = NTFS_OK;
finish:
	if (cursor != NULL) {
		if (cursor->by_hash) {
			report->sdh_blocks = cursor->visited.count;
		} else {
			report->sii_blocks = cursor->visited.count;
		}
	}
	ntfs_secure_cursor_close(cursor);
	ntfs_free(volume, locators, (size_t)capacity * sizeof(*locators));
	ntfs_stream_close(store);
	ntfs_node_close(node);
	report->result = result;
	return result;
}
