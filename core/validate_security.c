/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "validate_internal.h"

static enum ntfs_result ntfs_validation_security_references(
    void *context, const struct ntfs_disk_security_locator *locators, uint32_t count);
static enum ntfs_result ntfs_validation_unique_internal_child(
    struct ntfs_validation_context *validation, uint64_t parent, const uint16_t *name,
    uint16_t length, bool directory, uint64_t *reference);
static enum ntfs_result ntfs_validation_repair_metadata_reference(
    struct ntfs_validation_context *validation, uint64_t *reference);
static bool ntfs_validation_file_security_required(uint64_t record_number, bool reserved_inert);
static enum ntfs_result ntfs_validation_scan_file_security(
    struct ntfs_validation_context *validation);

static enum ntfs_result
ntfs_validation_security_references(
    void *context, const struct ntfs_disk_security_locator *locators, uint32_t count)
{
	struct ntfs_validation_context *validation = context;
	struct ntfs_validation_record *record;
	uint64_t index;
	uint32_t first, end, middle, id;
	bool found;
	enum ntfs_result result;

	for (index = 0; index < validation->report->record_slots; index++) {
		result = ntfs_index_work(
		    validation->volume, ntfs_validation_index_inventory_work, validation, 1);
		if (result != NTFS_OK) {
			return result;
		}
		record = &validation->records[index];
		if (record->reference == 0 || record->base != 0 || record->security_id == 0) {
			continue;
		}
		validation->report->record_number = index;
		validation->report->reference = record->reference;
		validation->report->related_reference =
		    validation->records[NTFS_SECURE_RECORD].reference;
		validation->report->attribute_type = NTFS_ATTR_STANDARD;
		first = 0;
		end = count;
		found = false;
		while (first < end) {
			result = ntfs_index_work(validation->volume,
			    ntfs_validation_index_inventory_work, validation, 1);
			if (result != NTFS_OK) {
				return result;
			}
			middle = first + (end - first) / VALIDATION_VECTOR_GROWTH;
			id = ntfs_u32(locators[middle].security_id);
			if (record->security_id == id) {
				found = true;
				break;
			}
			if (id < record->security_id) {
				first = middle + 1;
			} else {
				end = middle;
			}
		}
		if (!found) {
			return NTFS_CORRUPT;
		}
	}
	validation->report->record_number = NTFS_SECURE_RECORD;
	validation->report->reference = validation->records[NTFS_SECURE_RECORD].reference;
	validation->report->related_reference = 0;
	validation->report->attribute_type = NTFS_ATTRIBUTE_DATA;
	return NTFS_OK;
}

static enum ntfs_result
ntfs_validation_unique_internal_child(struct ntfs_validation_context *validation, uint64_t parent,
    const uint16_t *name, uint16_t length, bool directory, uint64_t *reference)
{
	const struct ntfs_validation_link *link;
	struct ntfs_validation_record *record;
	uint64_t match = 0;
	uint32_t first = 0, end = validation->link_count / VALIDATION_LINK_PAIR, middle, index;

	*reference = 0;
	validation->report->reference = parent;
	validation->report->record_number = parent & NTFS_REFERENCE_RECORD_MASK;
	validation->report->related_reference = 0;
	validation->report->attribute_type = NTFS_ATTR_FILENAME;
	validation->report->cluster = 0;
	/* The namespace pass has paired every physical name with its index entry
	 * and sorted the pairs by their complete, sequence-checked parent reference. */
	while (first < end) {
		if (ntfs_validation_charge(validation, sizeof(*link)) != NTFS_OK) {
			return validation->failure;
		}
		middle = first + (end - first) / VALIDATION_VECTOR_GROWTH;
		if (validation->links[middle * VALIDATION_LINK_PAIR].parent < parent) {
			first = middle + 1;
		} else {
			end = middle;
		}
	}
	for (index = first; index < validation->link_count / VALIDATION_LINK_PAIR; index++) {
		link = &validation->links[index * VALIDATION_LINK_PAIR];
		if (ntfs_validation_charge(
			validation, sizeof(*link) + (uint64_t)length * sizeof(*name)) != NTFS_OK) {
			return validation->failure;
		}
		if (link->parent != parent) {
			break;
		}
		if (link->length != length ||
		    !ntfs_equal(
			validation->names + link->offset, name, (size_t)length * sizeof(*name))) {
			continue;
		}
		if (match != 0) {
			*reference = 0;
			return NTFS_OK;
		}
		match = link->reference;
		record = ntfs_validation_checked_reference(validation, match);
		if (record == NULL) {
			return NTFS_STALE;
		}
		if (((record->flags & NTFS_RECORD_DIRECTORY) != 0) == directory &&
		    record->links == 1 && record->primary_names == 1 && record->dos_names == 0) {
			*reference = match;
		}
	}
	return NTFS_OK;
}

static enum ntfs_result
ntfs_validation_repair_metadata_reference(
    struct ntfs_validation_context *validation, uint64_t *reference)
{
	static const uint16_t extend[] = {'$', 'E', 'x', 't', 'e', 'n', 'd'};
	static const uint16_t metadata[] = {'$', 'R', 'm', 'M', 'e', 't', 'a', 'd', 'a', 't', 'a'};
	static const uint16_t repair[] = {'$', 'R', 'e', 'p', 'a', 'i', 'r'};
	uint64_t parent;
	enum ntfs_result result;

	*reference = 0;
	result = ntfs_validation_unique_internal_child(validation,
	    validation->records[NTFS_ROOT_RECORD].reference, extend,
	    sizeof(extend) / sizeof(*extend), true, &parent);
	if (result != NTFS_OK || parent == 0 ||
	    (parent & NTFS_REFERENCE_RECORD_MASK) != NTFS_EXTEND_RECORD) {
		return result;
	}
	result = ntfs_validation_unique_internal_child(
	    validation, parent, metadata, sizeof(metadata) / sizeof(*metadata), true, reference);
	if (result != NTFS_OK || *reference == 0) {
		return result;
	}
	parent = *reference;
	result = ntfs_validation_unique_internal_child(
	    validation, parent, repair, sizeof(repair) / sizeof(*repair), false, reference);
	if (result == NTFS_OK && *reference != 0 &&
	    !validation->records[*reference & NTFS_REFERENCE_RECORD_MASK].hidden_system) {
		*reference = 0;
	}
	return result;
}

static bool
ntfs_validation_file_security_required(uint64_t record_number, bool reserved_inert)
{
	if (reserved_inert) {
		return false;
	}
	switch (record_number) {
	case NTFS_MFT_RECORD:
	case NTFS_MFT_MIRROR_RECORD:
	case NTFS_LOGFILE_RECORD:
	case NTFS_BITMAP_RECORD:
	case NTFS_BAD_CLUSTERS_RECORD:
	case NTFS_UPCASE_RECORD:
		/* Fixed internal metadata can omit per-file security storage. A present
		 * descriptor is still checked; this supplies no access decision. */
		return false;
	default:
		return true;
	}
}

static enum ntfs_result
ntfs_validation_scan_file_security(struct ntfs_validation_context *validation)
{
	struct ntfs_validation_record *record;
	struct ntfs_node *node = NULL;
	uint64_t index, repair_reference;
	enum ntfs_result result;

	/* Omission is observed for the canonical internal $Repair object. Resolve
	 * checked ownership rather than assigning that purpose to a movable slot.
	 * Present packets and every nonzero indexed ID retain their ordinary checks. */
	result = ntfs_validation_repair_metadata_reference(validation, &repair_reference);
	if (result != NTFS_OK) {
		return result;
	}
	for (index = 0; index < validation->report->record_slots; index++) {
		result = ntfs_validation_charge(validation, 1);
		if (result != NTFS_OK) {
			return result;
		}
		record = &validation->records[index];
		if (record->reference == 0 || record->base != 0 || record->security_id != 0 ||
		    record->reserved_empty) {
			continue;
		}
		validation->report->record_number = index;
		validation->report->reference = record->reference;
		validation->report->related_reference = 0;
		validation->report->attribute_type = NTFS_ATTR_SECURITY_DESCRIPTOR;
		validation->report->cluster = 0;
		result = ntfs_operation_enter(validation->volume);
		if (result != NTFS_OK) {
			return result;
		}
		result = ntfs_node_open(validation->volume, record->reference, &node);
		if (result == NTFS_OK) {
			result = ntfs_security_file_validate(node,
			    ntfs_validation_file_security_required(index, record->reserved_inert) &&
				record->reference != repair_reference,
			    ntfs_validation_index_inventory_work, validation);
		}
		ntfs_node_close(node);
		node = NULL;
		ntfs_operation_leave(validation->volume);
		if (result != NTFS_OK) {
			return result;
		}
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_validation_scan_security(struct ntfs_validation_context *validation)
{
	struct ntfs_security_store_report report;
	struct ntfs_security_store_limits limits = {NTFS_SECURITY_STORE_MAX_DESCRIPTORS};
	uint64_t index;
	enum ntfs_result result;

	validation->report->stage = NTFS_VALIDATION_SECURITY;
	if (validation->report->record_slots <= NTFS_SECURE_RECORD ||
	    validation->records[NTFS_SECURE_RECORD].reference == 0) {
		if (!validation->has_security_ids) {
			return ntfs_validation_scan_file_security(validation);
		}
		for (index = 0; index < validation->report->record_slots; index++) {
			result = ntfs_validation_charge(validation, 1);
			if (result != NTFS_OK) {
				return result;
			}
			if (validation->records[index].base == 0 &&
			    validation->records[index].security_id != 0) {
				validation->report->record_number = index;
				validation->report->reference =
				    validation->records[index].reference;
				validation->report->related_reference = 0;
				validation->report->attribute_type = NTFS_ATTR_STANDARD;
				validation->report->cluster = 0;
				return NTFS_CORRUPT;
			}
		}
		return NTFS_CORRUPT;
	}
	validation->report->record_number = NTFS_SECURE_RECORD;
	validation->report->reference = validation->records[NTFS_SECURE_RECORD].reference;
	validation->report->related_reference = 0;
	validation->report->attribute_type = NTFS_ATTR_INDEX_ROOT;
	validation->report->cluster = 0;
	result = ntfs_operation_enter(validation->volume);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_security_store_validate_impl(validation->volume, &limits, &report,
	    ntfs_validation_index_inventory_work, validation, ntfs_validation_security_references);
	ntfs_operation_leave(validation->volume);
	validation->report->cluster = report.cluster;
	if (validation->report->record_number == NTFS_SECURE_RECORD) {
		if (report.stage == NTFS_SECURITY_STORE_SII_ALLOCATION ||
		    report.stage == NTFS_SECURITY_STORE_SDH_ALLOCATION) {
			validation->report->attribute_type = NTFS_ATTR_BITMAP;
		} else if (report.stage == NTFS_SECURITY_STORE_DESCRIPTORS) {
			validation->report->attribute_type = NTFS_ATTRIBUTE_DATA;
		}
	}
	return result == NTFS_OK ? ntfs_validation_scan_file_security(validation) : result;
}
