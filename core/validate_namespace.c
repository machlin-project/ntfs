/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "validate_internal.h"

static int ntfs_validation_compare_links(
    struct ntfs_validation_context *validation, const void *a, const void *b);
static enum ntfs_result ntfs_validation_check_directory_graph(
    struct ntfs_validation_context *validation);

static int
ntfs_validation_compare_links(
    struct ntfs_validation_context *validation, const void *left_input, const void *right_input)
{
	const struct ntfs_validation_link *left = left_input, *right = right_input;
	uint16_t left_unit, right_unit;
	size_t i, length = left->length < right->length ? left->length : right->length;

	if (ntfs_validation_charge(
		validation, (uint64_t)length * sizeof(uint16_t) + sizeof(*left)) != NTFS_OK) {
		return 0;
	}
	if (left->parent != right->parent) {
		return left->parent < right->parent ? -1 : 1;
	}
	if (left->reference != right->reference) {
		return left->reference < right->reference ? -1 : 1;
	}
	if (left->name_namespace != right->name_namespace) {
		return left->name_namespace < right->name_namespace ? -1 : 1;
	}
	for (i = 0; i < length; i++) {
		left_unit = validation->names[left->offset + i];
		right_unit = validation->names[right->offset + i];
		if (left_unit != right_unit) {
			return left_unit < right_unit ? -1 : 1;
		}
	}
	return left->length < right->length ? -1 : left->length != right->length;
}

static enum ntfs_result
ntfs_validation_check_directory_graph(struct ntfs_validation_context *validation)
{
	struct ntfs_validation_record *record;
	uint64_t i, next, root_reference;

	if (validation->report->record_slots <= NTFS_ROOT_RECORD ||
	    (validation->records[NTFS_ROOT_RECORD].flags & NTFS_RECORD_DIRECTORY) == 0) {
		return NTFS_CORRUPT;
	}
	root_reference = validation->records[NTFS_ROOT_RECORD].reference;
	if (validation->records[NTFS_ROOT_RECORD].primary_names != 1 ||
	    validation->records[NTFS_ROOT_RECORD].links != 1) {
		validation->report->reference = root_reference;
		validation->report->record_number = NTFS_ROOT_RECORD;
		validation->report->related_reference = root_reference;
		validation->report->attribute_type = NTFS_ATTR_FILENAME;
		return NTFS_CORRUPT;
	}

	for (i = 0; i < validation->report->record_slots; i++) {
		record = &validation->records[i];
		if (record->reference == 0 || record->base != 0 || record->reserved_inert ||
		    i == NTFS_ROOT_RECORD) {
			continue;
		}
		validation->report->reference = record->reference;
		validation->report->record_number = i;
		validation->report->related_reference = record->parent;
		validation->report->attribute_type = NTFS_ATTR_FILENAME;
		validation->report->cluster = 0;
		/* The FILE header counts physical names, including separate DOS aliases.
		 * Native logical hard-link counts are a separate presentation contract. */
		if ((uint32_t)record->primary_names + record->dos_names != record->links ||
		    record->primary_names == 0) {
			return NTFS_CORRUPT;
		}
		if ((record->flags & NTFS_RECORD_DIRECTORY) == 0) {
			continue;
		}
		if (record->parent == 0 || record->primary_names != 1) {
			return NTFS_CORRUPT;
		}
		next = record->reference;
		while (next != root_reference) {
			if (ntfs_validation_charge(validation, 1) != NTFS_OK) {
				return validation->failure;
			}
			record = ntfs_validation_checked_reference(validation, next);
			if (record == NULL || (record->flags & NTFS_RECORD_DIRECTORY) == 0) {
				return NTFS_CORRUPT;
			}
			if (record->directory_state == VALIDATION_DIRECTORY_VISITED) {
				break;
			}
			if (record->directory_state == VALIDATION_DIRECTORY_VISITING) {
				validation->report->related_reference = next;
				return NTFS_CORRUPT;
			}
			record->directory_state = VALIDATION_DIRECTORY_VISITING;
			next = record->parent;
		}
		next = validation->records[i].reference;
		while (next != root_reference) {
			if (ntfs_validation_charge(validation, 1) != NTFS_OK) {
				return validation->failure;
			}
			record = ntfs_validation_checked_reference(validation, next);
			if (record == NULL) {
				return NTFS_CORRUPT;
			}
			if (record->directory_state != VALIDATION_DIRECTORY_VISITING) {
				break;
			}
			record->directory_state = VALIDATION_DIRECTORY_VISITED;
			next = record->parent;
		}
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_validation_index_inventory_work(void *context, uint64_t units)
{
	return ntfs_validation_charge(context, units);
}

enum ntfs_result
ntfs_validation_scan_namespace(struct ntfs_validation_context *validation)
{
	struct ntfs_node *node = NULL;
	struct ntfs_directory *directory = NULL;
	struct ntfs_dirent entry;
	const struct ntfs_validation_link *first, *second;
	uint64_t i;
	int comparison;
	enum ntfs_result result = NTFS_OK;

	validation->report->stage = NTFS_VALIDATION_NAMESPACE;
	validation->report->attribute_type = NTFS_ATTR_INDEX_ROOT;
	validation->report->related_reference = 0;
	for (i = 0; i < validation->report->record_slots; i++) {
		if (validation->records[i].reference == 0 || validation->records[i].base != 0 ||
		    (validation->records[i].flags & NTFS_RECORD_DIRECTORY) == 0) {
			continue;
		}
		validation->report->reference = validation->records[i].reference;
		validation->report->record_number = i;
		validation->report->stage = NTFS_VALIDATION_NAMESPACE;
		validation->report->attribute_type = NTFS_ATTR_INDEX_ROOT;
		validation->report->cluster = 0;
		result =
		    ntfs_node_open(validation->volume, validation->records[i].reference, &node);
		if (result == NTFS_OK) {
			result = ntfs_directory_open(node, &directory);
		}
		if (result != NTFS_OK) {
			break;
		}
		while ((result = ntfs_directory_next(directory, &entry)) == NTFS_OK) {
			if (ntfs_validation_charge(validation, sizeof(entry)) != NTFS_OK) {
				result = validation->failure;
				break;
			}
			result = ntfs_validation_remember_link(validation, entry.parent_reference,
			    entry.reference, entry.name, entry.name_length, entry.name_namespace,
			    VALIDATION_INDEX_SOURCE);
			if (result != NTFS_OK) {
				break;
			}
		}
		if (result == NTFS_END) {
			/* Namespace pairing reports individual children. Inventory failures
			 * instead belong to the directory owning the allocation/bitmap. */
			validation->report->reference = validation->records[i].reference;
			validation->report->record_number = i;
			validation->report->related_reference = 0;
			validation->report->stage = NTFS_VALIDATION_INDEX_ALLOCATION;
			validation->report->attribute_type = NTFS_ATTR_BITMAP;
			result = ntfs_directory_check_allocation(directory, node,
			    ntfs_validation_index_inventory_work, validation,
			    &validation->report->cluster);
		}
		ntfs_directory_close(directory);
		directory = NULL;
		ntfs_node_close(node);
		node = NULL;
		if (result != NTFS_OK) {
			break;
		}
		validation->report->directories++;
		result = NTFS_OK;
	}
	ntfs_directory_close(directory);
	ntfs_node_close(node);
	if (result != NTFS_OK) {
		return result;
	}
	validation->report->stage = NTFS_VALIDATION_NAMESPACE;
	result = ntfs_validation_sort(validation, validation->links, sizeof(*validation->links),
	    validation->link_count, ntfs_validation_compare_links);
	if (result != NTFS_OK) {
		return result;
	}
	for (i = 0; i < validation->link_count; i += VALIDATION_LINK_PAIR) {
		first = &validation->links[i];
		validation->report->reference = first->reference;
		validation->report->record_number = first->reference & NTFS_REFERENCE_RECORD_MASK;
		validation->report->related_reference = first->parent;
		validation->report->attribute_type = NTFS_ATTR_FILENAME;
		if (i + 1 == validation->link_count) {
			return NTFS_CORRUPT;
		}
		second = &validation->links[i + 1];
		comparison = ntfs_validation_compare_links(validation, first, second);
		if (validation->failure != NTFS_OK) {
			return validation->failure;
		}
		if (comparison != 0 || first->source == second->source) {
			return NTFS_CORRUPT;
		}
		if (i + VALIDATION_LINK_PAIR < validation->link_count) {
			comparison = ntfs_validation_compare_links(
			    validation, first, &validation->links[i + VALIDATION_LINK_PAIR]);
			if (validation->failure != NTFS_OK) {
				return validation->failure;
			}
			if (comparison == 0) {
				return NTFS_CORRUPT;
			}
		}
	}
	return ntfs_validation_check_directory_graph(validation);
}
