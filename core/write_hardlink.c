/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_mutation_internal.h"

enum ntfs_result
ntfs_mutation_hardlink_count_admit(const struct ntfs_link_counts *counts)
{
	if (counts == NULL) {
		return NTFS_INVALID;
	}
	if (counts->primary_names == 0 || counts->physical_names !=
		(uint32_t)counts->primary_names + counts->dos_aliases) {
		return NTFS_CORRUPT;
	}
	if (counts->primary_names >= NTFS_MUTATION_MAX_PRIMARY_LINKS ||
	    counts->physical_names == UINT16_MAX) {
		return NTFS_TOO_MANY_LINKS;
	}
	return NTFS_OK;
}

/* Select a primary filename by its complete stored edge. Cache fields can differ
 * from the index, so the existing FILE_NAME supplies the copied cache bytes. */
static enum ntfs_result
mutation_hardlink_filename(struct ntfs_mutation_record *record,
    const struct ntfs_mutation_key *key, struct ntfs_attr_view *out)
{
	const struct ntfs_disk_record *header = (const void *)record->bytes;
	const struct ntfs_disk_filename *wanted = (const void *)key->value, *name;
	struct ntfs_attr_view attribute;
	const uint8_t *value;
	uint32_t position = ntfs_u16(header->attrs_offset);
	size_t bytes;
	bool found = false;
	enum ntfs_result result;

	if (wanted->name_namespace == NTFS_NAMESPACE_DOS) {
		return NTFS_UNSUPPORTED;
	}
	while ((result = ntfs_attr_at(
		    record->bytes, ntfs_u32(header->used), &position, &attribute)) == NTFS_OK) {
		if (attribute.type != NTFS_ATTR_FILENAME) {
			continue;
		}
		result = ntfs_attr_value(&attribute, &value, &bytes);
		if (result != NTFS_OK || bytes < sizeof(*name)) {
			return result == NTFS_OK ? NTFS_CORRUPT : result;
		}
		name = (const void *)value;
		if (bytes != key->bytes || ntfs_u64(name->parent) != ntfs_u64(wanted->parent) ||
		    name->name_namespace != wanted->name_namespace ||
		    !ntfs_equal(value + sizeof(*name), key->value + sizeof(*wanted),
			bytes - sizeof(*name))) {
			continue;
		}
		if (found) {
			return NTFS_CORRUPT;
		}
		*out = attribute;
		found = true;
	}
	return result != NTFS_END ? result : found ? NTFS_OK : NTFS_CORRUPT;
}

/* Append after the existing unnamed FILE_NAME attributes. The ordinary helper
 * replaces a unique attribute, so it must not be used for this additional edge. */
static enum ntfs_result
mutation_hardlink_append(struct ntfs_write_mutation_plan *plan,
    struct ntfs_mutation_record *record, const uint8_t *value, size_t bytes)
{
	struct ntfs_disk_record *header = (void *)record->bytes;
	struct ntfs_disk_attr *disk;
	struct ntfs_disk_resident *resident;
	struct ntfs_attr_view attribute, insertion = {0};
	uint8_t *buffer;
	uint32_t position = ntfs_u16(header->attrs_offset), start;
	uint16_t instance = ntfs_u16(header->next_instance), links = ntfs_u16(header->links);
	size_t offset = sizeof(*disk) + sizeof(*resident);
	size_t length = ntfs_mutation_align_bytes(offset + bytes);
	enum ntfs_result result;

	if (instance == UINT16_MAX) {
		return NTFS_RANGE;
	}
	if (links == UINT16_MAX) {
		return NTFS_TOO_MANY_LINKS;
	}
	for (;;) {
		start = position;
		result = ntfs_attr_at(record->bytes, ntfs_u32(header->used), &position, &attribute);
		if (result == NTFS_END) {
			if (insertion.bytes == NULL) {
				insertion.bytes = record->bytes + start;
			}
			break;
		}
		if (result != NTFS_OK) {
			return result;
		}
		if (attribute.instance == instance) {
			return NTFS_CORRUPT;
		}
		if (insertion.bytes == NULL && attribute.type > NTFS_ATTR_FILENAME) {
			insertion.bytes = record->bytes + start;
		}
	}
	if (length > NTFS_WRITE_RECORD_BYTES - ntfs_u32(header->used)) {
		return NTFS_NO_SPACE;
	}
	buffer = ntfs_mutation_allocate(plan, length);
	if (buffer == NULL) {
		return NTFS_NO_MEMORY;
	}
	disk = (void *)buffer;
	ntfs_put_u32(disk->type, NTFS_ATTR_FILENAME);
	ntfs_put_u32(disk->length, (uint32_t)length);
	ntfs_put_u16(disk->instance, instance);
	resident = (void *)(buffer + sizeof(*disk));
	ntfs_put_u32(resident->length, (uint32_t)bytes);
	ntfs_put_u16(resident->offset, (uint16_t)offset);
	resident->indexed = 1;
	ntfs_copy(buffer + offset, value, bytes);
	result = ntfs_mutation_record_replace(plan, record, &insertion, buffer, length);
	if (result == NTFS_OK) {
		ntfs_put_u16(header->next_instance, (uint16_t)(instance + 1u));
		ntfs_put_u16(header->links, (uint16_t)(links + 1u));
	}
	ntfs_mutation_release(plan, buffer, length);
	return result;
}

enum ntfs_result
ntfs_mutation_hardlink(
    struct ntfs_write_mutation_plan *plan, const struct ntfs_write_mutation_request *request)
{
	struct ntfs_mutation_directory source = {0}, destination_storage = {0}, *destination;
	struct ntfs_mutation_record *record, *parent;
	struct ntfs_node *node = NULL;
	struct ntfs_link_counts counts;
	struct ntfs_attr_view attribute;
	struct ntfs_disk_filename *name;
	const uint8_t *original = NULL;
	uint8_t value[NTFS_MUTATION_FILENAME_BYTES];
	size_t position = 0, bytes, index;
	enum ntfs_result result;

	result = ntfs_mutation_record_get(plan, request->reference, false, &record);
	if (result == NTFS_OK) {
		result = ntfs_mutation_record_admit(record, false, false);
	}
	if (result == NTFS_OK) {
		result = ntfs_node_open_impl(plan->volume, record->reference, &node);
	}
	if (result == NTFS_OK) {
		result = ntfs_node_link_counts_impl(node, &counts);
	}
	ntfs_node_close(node);
	if (result == NTFS_OK) {
		result = ntfs_mutation_hardlink_count_admit(&counts);
	}
	if (result != NTFS_OK) {
		goto done;
	}
	result = ntfs_mutation_record_get(plan, request->source.parent_reference, false, &parent);
	if (result == NTFS_OK) {
		result = ntfs_mutation_directory_open(plan, parent, &source);
	}
	if (result == NTFS_OK) {
		result = ntfs_mutation_directory_find(plan, &source, &request->source, &position);
	}
	if (result != NTFS_OK) {
		goto done;
	}
	if (source.keys[position].reference != record->reference) {
		result = NTFS_STALE;
		goto done;
	}
	result = mutation_hardlink_filename(record, &source.keys[position], &attribute);
	if (result == NTFS_OK) {
		result = ntfs_attr_value(&attribute, &original, &bytes);
	}
	if (result != NTFS_OK) {
		goto done;
	}
	ntfs_copy(value, original, sizeof(*name));
	name = (void *)value;
	ntfs_put_u64(name->parent, request->destination.parent_reference);
	name->length = (uint8_t)request->destination.count;
	name->name_namespace = NTFS_NAMESPACE_POSIX;
	bytes = sizeof(*name) + request->destination.count * NTFS_UTF16_UNIT_BYTES;
	for (index = 0; index < request->destination.count; index++) {
		ntfs_put_u16(value + sizeof(*name) + index * NTFS_UTF16_UNIT_BYTES,
		    request->destination.units[index]);
	}
	if (request->source.parent_reference == request->destination.parent_reference) {
		destination = &source;
	} else {
		result = ntfs_mutation_record_get(
		    plan, request->destination.parent_reference, false, &parent);
		if (result == NTFS_OK) {
			result = ntfs_mutation_directory_open(plan, parent, &destination_storage);
		}
		if (result != NTFS_OK) {
			goto done;
		}
		destination = &destination_storage;
	}
	result = ntfs_mutation_directory_find(plan, destination, &request->destination, &position);
	if (result != NTFS_NOT_FOUND) {
		result = result == NTFS_OK ? NTFS_EXISTS : result;
		goto done;
	}
	result = mutation_hardlink_append(plan, record, value, bytes);
	if (result == NTFS_OK) {
		result = ntfs_mutation_directory_add(plan, destination, record->reference, value, bytes);
	}
	if (result == NTFS_OK) {
		/* Exact storage preparation leaves all implicit timestamp policy open. */
		result = ntfs_mutation_directory_store(plan, destination, false);
	}
	if (result == NTFS_OK) {
		plan->reference = record->reference;
	}

done:
	ntfs_mutation_directory_close(plan, &destination_storage);
	ntfs_mutation_directory_close(plan, &source);
	return result;
}
