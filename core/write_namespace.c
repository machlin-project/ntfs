/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_mutation_internal.h"

static enum ntfs_result
mutation_namespace_changed(struct ntfs_mutation_record *record, uint64_t filetime)
{
	struct ntfs_attr_view attribute;
	struct ntfs_disk_standard *standard;
	const uint8_t *value;
	size_t bytes;
	enum ntfs_result result;

	result = ntfs_attr_find(record->bytes, sizeof(record->bytes), NTFS_ATTR_STANDARD, NULL, 0,
	    UINT16_MAX, &attribute);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_attr_value(&attribute, &value, &bytes);
	if (result != NTFS_OK || bytes != NTFS_WRITE_STANDARD_BYTES) {
		return result == NTFS_OK ? NTFS_UNSUPPORTED : result;
	}
	standard = (void *)value;
	ntfs_put_u64(standard->changed, filetime);
	record->changed = true;
	return NTFS_OK;
}

static void
mutation_namespace_creation_time_bytes(uint8_t *created, uint8_t *modified, uint8_t *changed_time,
    uint8_t *accessed, const struct ntfs_write_creation_times *times, uint64_t filetime)
{
	ntfs_put_u64(created,
	    (times->fields & NTFS_WRITE_CREATION_CREATED) != 0 ? times->created : filetime);
	ntfs_put_u64(modified,
	    (times->fields & NTFS_WRITE_CREATION_MODIFIED) != 0 ? times->modified : filetime);
	ntfs_put_u64(changed_time,
	    (times->fields & NTFS_WRITE_CREATION_CHANGED) != 0 ? times->changed : filetime);
	ntfs_put_u64(accessed,
	    (times->fields & NTFS_WRITE_CREATION_ACCESSED) != 0 ? times->accessed : filetime);
}

static void
mutation_namespace_filename(uint8_t *value, const struct ntfs_write_name *name,
    const struct ntfs_write_creation_times *times, uint64_t filetime, bool directory)
{
	struct ntfs_disk_filename *header = (void *)value;
	size_t index;

	ntfs_zero(value, sizeof(*header) + name->count * NTFS_UTF16_UNIT_BYTES);
	ntfs_put_u64(header->parent, name->parent_reference);
	mutation_namespace_creation_time_bytes(
	    header->created, header->modified, header->changed, header->accessed, times, filetime);
	ntfs_put_u32(header->attributes, directory ? NTFS_FILE_DIRECTORY : NTFS_FILE_ARCHIVE);
	header->length = (uint8_t)name->count;
	/* This edge has no DOS counterpart; use the qualified unpaired namespace. */
	header->name_namespace = NTFS_NAMESPACE_POSIX;
	for (index = 0; index < name->count; index++) {
		ntfs_put_u16(
		    value + sizeof(*header) + index * NTFS_UTF16_UNIT_BYTES, name->units[index]);
	}
}

static enum ntfs_result
mutation_namespace_create(struct ntfs_write_mutation_plan *plan,
    const struct ntfs_write_mutation_request *request, struct ntfs_mutation_directory *parent)
{
	struct ntfs_mutation_record *record;
	struct ntfs_disk_record *header;
	struct ntfs_disk_standard *standard;
	struct ntfs_mutation_directory empty = {0};
	uint8_t standard_bytes[NTFS_WRITE_STANDARD_BYTES], name_bytes[NTFS_MUTATION_FILENAME_BYTES];
	uint8_t *security = NULL;
	size_t security_bytes = 0, position, bytes;
	bool directory = request->kind == NTFS_WRITE_CREATE_DIRECTORY;
	enum ntfs_result result;

	result = ntfs_mutation_directory_find(plan, parent, &request->source, &position);
	if (result != NTFS_NOT_FOUND) {
		return result == NTFS_OK ? NTFS_EXISTS : result;
	}
	result = ntfs_mutation_security_inherit(
	    plan, parent->record, directory, &security, &security_bytes);
	if (result != NTFS_OK) {
		goto done;
	}
	result = ntfs_mutation_new_record(plan, &record);
	if (result != NTFS_OK) {
		goto done;
	}
	header = (void *)record->bytes;
	position = ntfs_u16(header->attrs_offset);
	ntfs_zero(record->bytes + position, sizeof(record->bytes) - position);
	ntfs_put_u32(record->bytes + position, NTFS_ATTR_END);
	ntfs_put_u32(header->used, (uint32_t)(position + NTFS_WIRE_ALIGNMENT));
	ntfs_put_u16(header->next_instance, 0);
	ntfs_put_u16(header->links, 1);
	ntfs_put_u16(header->flags, NTFS_RECORD_IN_USE | (directory ? NTFS_RECORD_DIRECTORY : 0));
	ntfs_put_u64(header->base_reference, 0);
	record->changed = true;
	ntfs_zero(standard_bytes, sizeof(standard_bytes));
	standard = (void *)standard_bytes;
	mutation_namespace_creation_time_bytes(standard->created, standard->modified,
	    standard->changed, standard->accessed, &request->creation_times, plan->filetime);
	ntfs_put_u32(standard->attributes, directory ? NTFS_FILE_DIRECTORY : NTFS_FILE_ARCHIVE);
	if (directory && parent->case_sensitive) {
		((struct ntfs_disk_standard_policy *)(void *)standard->version)->directory_flags =
		    NTFS_STANDARD_DIRECTORY_CASE_SENSITIVE;
	}
	result = ntfs_mutation_resident(
	    plan, record, NTFS_ATTR_STANDARD, NULL, 0, standard_bytes, sizeof(standard_bytes), 0);
	mutation_namespace_filename(
	    name_bytes, &request->source, &request->creation_times, plan->filetime, directory);
	bytes = sizeof(struct ntfs_disk_filename) + request->source.count * NTFS_UTF16_UNIT_BYTES;
	if (result == NTFS_OK) {
		result = ntfs_mutation_resident(
		    plan, record, NTFS_ATTR_FILENAME, NULL, 0, name_bytes, bytes, 0);
	}
	if (result == NTFS_OK) {
		result = ntfs_mutation_resident(plan, record, NTFS_ATTR_SECURITY_DESCRIPTOR, NULL,
		    0, security, security_bytes, 0);
	}
	if (result == NTFS_OK && directory) {
		empty.record = record;
		result = ntfs_mutation_directory_store(plan, &empty, false);
	} else if (result == NTFS_OK) {
		result =
		    ntfs_mutation_resident(plan, record, NTFS_ATTRIBUTE_DATA, NULL, 0, NULL, 0, 0);
	}
	if (result == NTFS_OK) {
		result =
		    ntfs_mutation_directory_add(plan, parent, record->reference, name_bytes, bytes);
	}
	if (result == NTFS_OK) {
		result = ntfs_mutation_directory_store(plan, parent, true);
	}
	if (result == NTFS_OK) {
		plan->reference = record->reference;
	}

done:
	ntfs_mutation_release(plan, security, NTFS_MUTATION_SECURITY_BYTES);
	return result;
}

static enum ntfs_result
mutation_namespace_find_filename(struct ntfs_mutation_record *record,
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
		if (name->name_namespace == NTFS_NAMESPACE_DOS) {
			/* Paired Win32/DOS removal needs its complete native pair contract. */
			return NTFS_UNSUPPORTED;
		}
		if (ntfs_u64(name->parent) != ntfs_u64(wanted->parent) ||
		    name->name_namespace != wanted->name_namespace || bytes != key->bytes ||
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

static enum ntfs_result
mutation_namespace_free_record(
    struct ntfs_write_mutation_plan *plan, struct ntfs_mutation_record *record)
{
	struct ntfs_disk_record *header = (void *)record->bytes;
	struct ntfs_attr_view attribute;
	struct ntfs_stream *stream = NULL;
	uint32_t position = ntfs_u16(header->attrs_offset);
	uint16_t sequence;
	enum ntfs_result result;

	while ((result = ntfs_attr_at(
		    record->bytes, ntfs_u32(header->used), &position, &attribute)) == NTFS_OK) {
		if (!attribute.disk->nonresident) {
			continue;
		}
		result = ntfs_stream_from_attr(plan->volume, &attribute, &stream);
		if (result != NTFS_OK) {
			return result;
		}
		if (stream->flags != 0 || stream->compression_unit != 0) {
			ntfs_stream_close(stream);
			return NTFS_UNSUPPORTED;
		}
		result = ntfs_mutation_free_runs(plan, stream, 0);
		ntfs_stream_close(stream);
		stream = NULL;
		if (result != NTFS_OK) {
			return result;
		}
	}
	if (result != NTFS_END) {
		return result;
	}
	sequence = (uint16_t)(ntfs_u16(header->sequence) + 1u);
	if (sequence == 0) {
		sequence = 1;
	}
	ntfs_put_u16(header->sequence, sequence);
	ntfs_put_u16(header->flags, 0);
	ntfs_mutation_set_bit(plan->mft_bitmap.after, record->number, false);
	record->reference = record->number | (uint64_t)sequence << NTFS_REFERENCE_SEQUENCE_SHIFT;
	record->changed = true;
	return NTFS_OK;
}

static enum ntfs_result
mutation_namespace_unlink_key(struct ntfs_write_mutation_plan *plan,
    struct ntfs_mutation_directory *parent, size_t position, bool directory)
{
	struct ntfs_mutation_record *record;
	struct ntfs_mutation_directory children = {0};
	struct ntfs_attr_view name;
	struct ntfs_disk_record *header;
	uint16_t links;
	enum ntfs_result result;

	result = ntfs_mutation_record_get(plan, parent->keys[position].reference, false, &record);
	if (result == NTFS_OK) {
		result = ntfs_mutation_record_admit(record, directory, false);
	}
	if (result == NTFS_OK && directory) {
		result = ntfs_mutation_directory_open(plan, record, &children);
		if (result == NTFS_OK && children.count != 0) {
			result = NTFS_NOT_EMPTY;
		}
		ntfs_mutation_directory_close(plan, &children);
	}
	if (result != NTFS_OK) {
		return result;
	}
	result = mutation_namespace_find_filename(record, &parent->keys[position], &name);
	if (result != NTFS_OK) {
		return result;
	}
	header = (void *)record->bytes;
	links = ntfs_u16(header->links);
	if (links == 0 || (directory && links != 1)) {
		return NTFS_CORRUPT;
	}
	if (links == 1) {
		result = mutation_namespace_free_record(plan, record);
	} else {
		result = ntfs_mutation_record_replace(plan, record, &name, NULL, 0);
		if (result == NTFS_OK) {
			ntfs_put_u16(header->links, (uint16_t)(links - 1u));
			result = mutation_namespace_changed(record, plan->filetime);
		}
	}
	if (result == NTFS_OK) {
		ntfs_mutation_directory_remove(parent, position);
	}
	return result;
}

static enum ntfs_result
mutation_namespace_replace_filename(struct ntfs_write_mutation_plan *plan,
    struct ntfs_mutation_record *record, const struct ntfs_attr_view *previous, const void *value,
    size_t bytes)
{
	struct ntfs_disk_attr *attribute;
	struct ntfs_disk_resident *resident;
	uint8_t *buffer;
	size_t offset = sizeof(*attribute) + sizeof(*resident);
	size_t length =
	    (offset + bytes + NTFS_WIRE_ALIGNMENT - 1u) & ~(size_t)(NTFS_WIRE_ALIGNMENT - 1u);
	enum ntfs_result result;

	buffer = ntfs_mutation_allocate(plan, length);
	if (buffer == NULL) {
		return NTFS_NO_MEMORY;
	}
	attribute = (void *)buffer;
	ntfs_put_u32(attribute->type, NTFS_ATTR_FILENAME);
	ntfs_put_u32(attribute->length, (uint32_t)length);
	ntfs_put_u16(attribute->instance, previous->instance);
	resident = (void *)(buffer + sizeof(*attribute));
	ntfs_put_u32(resident->length, (uint32_t)bytes);
	ntfs_put_u16(resident->offset, (uint16_t)offset);
	resident->indexed = 1;
	ntfs_copy(buffer + offset, value, bytes);
	result = ntfs_mutation_record_replace(plan, record, previous, buffer, length);
	ntfs_mutation_release(plan, buffer, length);
	return result;
}

static enum ntfs_result
mutation_namespace_directory_parent(const struct ntfs_mutation_record *record, uint64_t *out)
{
	const struct ntfs_disk_record *header = (const void *)record->bytes;
	struct ntfs_attr_view attribute;
	const struct ntfs_disk_filename *name;
	const uint8_t *value;
	uint64_t parent = 0, reference;
	uint32_t position = ntfs_u16(header->attrs_offset), namespaces = 0, namespace_bit;
	uint16_t count = 0, unit;
	size_t bytes, index;
	enum ntfs_result result;

	while ((result = ntfs_attr_at(
		    record->bytes, ntfs_u32(header->used), &position, &attribute)) == NTFS_OK) {
		if (attribute.type != NTFS_ATTR_FILENAME) {
			continue;
		}
		if (attribute.disk->nonresident != 0 || attribute.disk->name_length != 0 ||
		    attribute.flags != 0) {
			return NTFS_CORRUPT;
		}
		result = ntfs_attr_value(&attribute, &value, &bytes);
		if (result != NTFS_OK || bytes < sizeof(*name)) {
			return result == NTFS_OK ? NTFS_CORRUPT : result;
		}
		name = (const void *)value;
		reference = ntfs_u64(name->parent);
		if (name->length == 0 || name->name_namespace > NTFS_NAMESPACE_WIN32_DOS ||
		    bytes != sizeof(*name) + (size_t)name->length * NTFS_UTF16_UNIT_BYTES ||
		    reference >> NTFS_REFERENCE_SEQUENCE_SHIFT == 0 ||
		    reference == record->reference || (count != 0 && parent != reference)) {
			return NTFS_CORRUPT;
		}
		namespace_bit = 1u << name->name_namespace;
		if ((namespaces & namespace_bit) != 0) {
			return NTFS_CORRUPT;
		}
		for (index = 0; index < name->length; index++) {
			unit = ntfs_u16(value + sizeof(*name) + index * NTFS_UTF16_UNIT_BYTES);
			if (unit == 0 || unit == '/') {
				return NTFS_CORRUPT;
			}
		}
		parent = reference;
		namespaces |= namespace_bit;
		count++;
	}
	if (result != NTFS_END) {
		return result;
	}
	/* Read the shared edge of a native alias pair without mutating either name. */
	if (count != ntfs_u16(header->links) ||
	    (namespaces != (1u << NTFS_NAMESPACE_POSIX) &&
		namespaces != (1u << NTFS_NAMESPACE_WIN32) &&
		namespaces != (1u << NTFS_NAMESPACE_WIN32_DOS) &&
		namespaces != ((1u << NTFS_NAMESPACE_WIN32) | (1u << NTFS_NAMESPACE_DOS)))) {
		return NTFS_CORRUPT;
	}
	*out = parent;
	return NTFS_OK;
}

static enum ntfs_result
mutation_namespace_check_ancestry(
    struct ntfs_write_mutation_plan *plan, uint64_t directory, uint64_t parent)
{
	struct ntfs_mutation_record *record;
	uint32_t depth;
	enum ntfs_result result;

	for (depth = 0; depth < plan->volume->limits.max_directory_nodes; depth++) {
		if (parent == directory) {
			return NTFS_INVALID;
		}
		result = ntfs_mutation_record_get(plan, parent, false, &record);
		if (result != NTFS_OK) {
			return result;
		}
		if (record->number == NTFS_ROOT_RECORD) {
			return NTFS_OK;
		}
		result = ntfs_mutation_record_admit(record, true, true);
		if (result != NTFS_OK) {
			return result;
		}
		result = mutation_namespace_directory_parent(record, &parent);
		if (result != NTFS_OK) {
			return result;
		}
	}
	return NTFS_RANGE;
}

static bool
mutation_namespace_same_name(
    const struct ntfs_mutation_key *key, const struct ntfs_write_name *name)
{
	const struct ntfs_disk_filename *filename = (const void *)key->value;
	size_t index;

	if (filename->length != name->count) {
		return false;
	}
	for (index = 0; index < name->count; index++) {
		if (ntfs_u16(key->value + sizeof(*filename) + index * NTFS_UTF16_UNIT_BYTES) !=
		    name->units[index]) {
			return false;
		}
	}
	return true;
}

static enum ntfs_result
mutation_namespace_rename_entry(struct ntfs_write_mutation_plan *plan,
    const struct ntfs_write_mutation_request *request, struct ntfs_mutation_directory *source,
    size_t position)
{
	struct ntfs_mutation_directory destination_storage = {0}, *destination;
	struct ntfs_mutation_record *record, *parent, *victim;
	struct ntfs_mutation_key original;
	struct ntfs_attr_view attribute;
	struct ntfs_disk_filename *new_name;
	uint8_t value[NTFS_MUTATION_FILENAME_BYTES];
	size_t found = 0, bytes, index;
	bool directory;
	enum ntfs_result result, exists;

	original = source->keys[position];
	result = ntfs_mutation_record_get(plan, original.reference, false, &record);
	if (result != NTFS_OK) {
		return result;
	}
	directory =
	    (ntfs_u16(((const struct ntfs_disk_record *)(const void *)record->bytes)->flags) &
		NTFS_RECORD_DIRECTORY) != 0;
	result = ntfs_mutation_record_admit(record, directory, false);
	if (result != NTFS_OK) {
		return result;
	}
	plan->reference = record->reference;
	if (source->record->reference == request->destination.parent_reference) {
		destination = source;
	} else {
		result = ntfs_mutation_record_get(
		    plan, request->destination.parent_reference, false, &parent);
		if (result == NTFS_OK) {
			result = ntfs_mutation_directory_open(plan, parent, &destination_storage);
		}
		if (result != NTFS_OK) {
			return result;
		}
		destination = &destination_storage;
	}
	if (directory) {
		result = mutation_namespace_check_ancestry(
		    plan, record->reference, destination->record->reference);
		if (result != NTFS_OK) {
			goto done;
		}
	}
	exists = ntfs_mutation_directory_find(plan, destination, &request->destination, &found);
	if (exists != NTFS_OK && exists != NTFS_NOT_FOUND) {
		result = exists;
		goto done;
	}
	if (exists == NTFS_OK && destination->keys[found].reference == record->reference) {
		if (destination != source || found != position ||
		    mutation_namespace_same_name(&original, &request->destination)) {
			result = NTFS_OK;
			goto done;
		}
	} else if (exists == NTFS_OK) {
		if (!request->replace) {
			result = NTFS_EXISTS;
			goto done;
		}
		result = ntfs_mutation_record_get(
		    plan, destination->keys[found].reference, false, &victim);
		if (result != NTFS_OK) {
			goto done;
		}
		result = mutation_namespace_unlink_key(plan, destination, found, directory);
		if (result != NTFS_OK) {
			goto done;
		}
		if (destination == source && found < position) {
			position--;
		}
	}
	result = mutation_namespace_find_filename(record, &original, &attribute);
	if (result != NTFS_OK) {
		goto done;
	}
	ntfs_copy(value, original.value, sizeof(struct ntfs_disk_filename));
	new_name = (void *)value;
	ntfs_put_u64(new_name->parent, destination->record->reference);
	ntfs_put_u64(new_name->changed, plan->filetime);
	new_name->length = (uint8_t)request->destination.count;
	new_name->name_namespace = NTFS_NAMESPACE_POSIX;
	bytes = sizeof(*new_name) + request->destination.count * NTFS_UTF16_UNIT_BYTES;
	for (index = 0; index < request->destination.count; index++) {
		ntfs_put_u16(value + sizeof(*new_name) + index * NTFS_UTF16_UNIT_BYTES,
		    request->destination.units[index]);
	}
	result = mutation_namespace_replace_filename(plan, record, &attribute, value, bytes);
	if (result == NTFS_OK) {
		result = mutation_namespace_changed(record, plan->filetime);
	}
	if (result == NTFS_OK) {
		ntfs_mutation_directory_remove(source, position);
		result =
		    ntfs_mutation_directory_add(plan, destination, record->reference, value, bytes);
	}
	if (result == NTFS_OK) {
		result = ntfs_mutation_directory_store(plan, source, true);
	}
	if (result == NTFS_OK && destination != source) {
		result = ntfs_mutation_directory_store(plan, destination, true);
	}

done:
	ntfs_mutation_directory_close(plan, &destination_storage);
	return result;
}

enum ntfs_result
ntfs_mutation_namespace(
    struct ntfs_write_mutation_plan *plan, const struct ntfs_write_mutation_request *request)
{
	struct ntfs_mutation_directory source = {0};
	struct ntfs_mutation_record *parent;
	size_t position;
	enum ntfs_result result;

	result = ntfs_mutation_record_get(plan, request->source.parent_reference, false, &parent);
	if (result == NTFS_OK) {
		result = ntfs_mutation_directory_open(plan, parent, &source);
	}
	if (result != NTFS_OK) {
		return result;
	}
	if (request->kind == NTFS_WRITE_CREATE_FILE ||
	    request->kind == NTFS_WRITE_CREATE_DIRECTORY) {
		result = mutation_namespace_create(plan, request, &source);
		goto done;
	}
	result = ntfs_mutation_directory_find(plan, &source, &request->source, &position);
	if (result != NTFS_OK) {
		goto done;
	}
	plan->reference = source.keys[position].reference;
	if (request->kind == NTFS_WRITE_RENAME) {
		result = mutation_namespace_rename_entry(plan, request, &source, position);
	} else {
		result = mutation_namespace_unlink_key(
		    plan, &source, position, request->kind == NTFS_WRITE_REMOVE_DIRECTORY);
		if (result == NTFS_OK) {
			result = ntfs_mutation_directory_store(plan, &source, true);
		}
	}

done:
	ntfs_mutation_directory_close(plan, &source);
	return result;
}

enum ntfs_result
ntfs_mutation_filename_sizes(struct ntfs_write_mutation_plan *plan,
    struct ntfs_mutation_record *record, uint64_t size, uint64_t allocated)
{
	struct ntfs_mutation_directory directory = {0};
	struct ntfs_mutation_record *parent;
	struct ntfs_disk_record *header = (void *)record->bytes;
	struct ntfs_disk_filename *filename;
	struct ntfs_write_name name;
	struct ntfs_attr_view attribute;
	const uint8_t *value;
	uint16_t units[NTFS_NAME_MAX];
	uint32_t position = ntfs_u16(header->attrs_offset);
	size_t bytes, index, found;
	enum ntfs_result result;

	while ((result = ntfs_attr_at(
		    record->bytes, ntfs_u32(header->used), &position, &attribute)) == NTFS_OK) {
		if (attribute.type != NTFS_ATTR_FILENAME) {
			continue;
		}
		result = ntfs_attr_value(&attribute, &value, &bytes);
		if (result != NTFS_OK || bytes < sizeof(*filename)) {
			return result == NTFS_OK ? NTFS_CORRUPT : result;
		}
		filename = (void *)value;
		if (bytes != sizeof(*filename) + filename->length * NTFS_UTF16_UNIT_BYTES ||
		    filename->length == 0) {
			return NTFS_CORRUPT;
		}
		name.parent_reference = ntfs_u64(filename->parent);
		name.count = filename->length;
		name.units = units;
		for (index = 0; index < name.count; index++) {
			units[index] =
			    ntfs_u16(value + sizeof(*filename) + index * NTFS_UTF16_UNIT_BYTES);
		}
		result = ntfs_mutation_record_get(plan, name.parent_reference, false, &parent);
		if (result == NTFS_OK) {
			result = ntfs_mutation_directory_open(plan, parent, &directory);
		}
		if (result != NTFS_OK) {
			return result;
		}
		result = ntfs_mutation_directory_find(plan, &directory, &name, &found);
		if (result == NTFS_OK && directory.keys[found].reference != record->reference) {
			result = NTFS_STALE;
		}
		if (result == NTFS_OK) {
			ntfs_put_u64(filename->size, size);
			ntfs_put_u64(filename->allocated, allocated);
			ntfs_put_u64(filename->modified, plan->filetime);
			ntfs_put_u64(filename->changed, plan->filetime);
			ntfs_put_u32(filename->attributes,
			    ntfs_u32(filename->attributes) | NTFS_FILE_ARCHIVE);
			record->changed = true;
			ntfs_copy(directory.keys[found].value, value, bytes);
			result = ntfs_mutation_directory_store(plan, &directory, false);
		}
		ntfs_mutation_directory_close(plan, &directory);
		if (result != NTFS_OK) {
			return result;
		}
	}
	return result == NTFS_END ? NTFS_OK : result;
}
