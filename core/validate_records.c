/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "validate_internal.h"

static bool ntfs_validation_inert_reserved_record(const uint8_t *record);
static enum ntfs_result ntfs_validation_remember_stream(struct ntfs_validation_context *validation,
    struct ntfs_stream *stream, uint64_t reference, uint32_t type);
static enum ntfs_result ntfs_validation_remember_filename(
    struct ntfs_validation_context *validation, uint64_t owner, const struct ntfs_attr_view *attr,
    uint16_t *name);
static enum ntfs_result ntfs_validation_check_list(struct ntfs_validation_context *validation,
    struct ntfs_node *owner, const uint8_t *bytes, size_t size, uint16_t *name);
static enum ntfs_result ntfs_validation_listed_extent(struct ntfs_validation_context *validation,
    const uint8_t *bytes, size_t size, uint64_t reference, const struct ntfs_attr_view *attr,
    uint64_t lowest);

struct ntfs_validation_record *
ntfs_validation_checked_reference(struct ntfs_validation_context *validation, uint64_t reference)
{
	uint64_t number = reference & NTFS_REFERENCE_RECORD_MASK;
	struct ntfs_validation_record *record;

	if (reference >> NTFS_REFERENCE_SEQUENCE_SHIFT == 0 ||
	    number >= validation->report->record_slots) {
		return NULL;
	}
	record = &validation->records[number];
	return record->reference == reference && record->base == 0 ? record : NULL;
}

static bool
ntfs_validation_inert_reserved_record(const uint8_t *record)
{
	const struct ntfs_disk_record *header = (const void *)record;
	struct ntfs_attr_view attribute_view;
	const uint8_t *value;
	size_t size;
	uint32_t position = ntfs_u16(header->attrs_offset);
	unsigned standard = 0, security = 0, data = 0;
	enum ntfs_result result;

	while ((result = ntfs_attr_at(
		    record, ntfs_u32(header->used), &position, &attribute_view)) == NTFS_OK) {
		if (attribute_view.flags != 0 || attribute_view.disk->name_length != 0 ||
		    ntfs_attr_value(&attribute_view, &value, &size) != NTFS_OK) {
			return false;
		}
		switch (attribute_view.type) {
		case NTFS_ATTR_STANDARD:
			if (++standard != 1) {
				return false;
			}
			break;
		case NTFS_ATTR_SECURITY_DESCRIPTOR:
			if (++security != 1) {
				return false;
			}
			break;
		case NTFS_ATTRIBUTE_DATA:
			if (++data != 1 || size != 0) {
				return false;
			}
			break;
		default:
			return false;
		}
	}
	return result == NTFS_END && standard == 1 && data == 1;
}

enum ntfs_result
ntfs_validation_scan_records(struct ntfs_validation_context *validation)
{
	struct ntfs_node *mft = NULL;
	struct ntfs_stream *bitmap = NULL;
	const struct ntfs_disk_record *header;
	uint8_t *record = NULL, *bits = NULL;
	uint64_t count = validation->volume->mft->size / validation->volume->info.record_size,
		 bitmap_size, i;
	uint16_t flags;
	uint32_t position;
	struct ntfs_attr_view attribute_view;
	bool allocated;
	enum ntfs_result result;

	validation->report->stage = NTFS_VALIDATION_RECORDS;
	validation->report->record_slots = count;
	if (validation->volume->mft->size % validation->volume->info.record_size != 0) {
		return NTFS_CORRUPT;
	}
	if (count == 0 || count > validation->limits.max_records) {
		return ntfs_validation_limit_failure(validation, NTFS_VALIDATION_LIMIT_RECORDS);
	}
	if (count > SIZE_MAX / sizeof(*validation->records)) {
		return ntfs_validation_limit_failure(validation, NTFS_VALIDATION_LIMIT_MEMORY);
	}
	bitmap_size = (count + NTFS_BITS_PER_BYTE - 1) / NTFS_BITS_PER_BYTE;
	result = ntfs_node_by_number(validation->volume, NTFS_MFT_RECORD, &mft);
	if (result == NTFS_OK) {
		result = ntfs_attribute_open(mft, NTFS_ATTR_BITMAP, NULL, 0, &bitmap);
	}
	if (result != NTFS_OK) {
		if (result == NTFS_NOT_FOUND) {
			result = NTFS_CORRUPT;
		}
		goto finish;
	}
	if (bitmap->flags != 0 || bitmap->size < bitmap_size || bitmap->initialized < bitmap_size) {
		result = NTFS_CORRUPT;
		goto finish;
	}
	bits = ntfs_validation_allocate(validation, (size_t)bitmap_size);
	record = ntfs_validation_allocate(validation, validation->volume->info.record_size);
	validation->records =
	    ntfs_validation_allocate(validation, (size_t)count * sizeof(*validation->records));
	if (bits == NULL || record == NULL || validation->records == NULL) {
		result = NTFS_NO_MEMORY;
		goto finish;
	}
	ntfs_zero(validation->records, (size_t)count * sizeof(*validation->records));
	result = ntfs_stream_exact(bitmap, 0, bits, (size_t)bitmap_size);
	for (i = 0; result == NTFS_OK && i < count; i++) {
		validation->report->record_number = i;
		validation->report->reference = 0;
		validation->report->related_reference = 0;
		result = ntfs_validation_charge(validation, validation->volume->info.record_size);
		if (result == NTFS_OK) {
			result = ntfs_stream_exact(validation->volume->mft,
			    i * validation->volume->info.record_size, record,
			    validation->volume->info.record_size);
		}
		if (result != NTFS_OK) {
			break;
		}
		allocated = (bits[i / NTFS_BITS_PER_BYTE] & (1u << (i % NTFS_BITS_PER_BYTE))) != 0;
		header = (const void *)record;
		flags = ntfs_u16(header->flags);
		if (!allocated) {
			if (ntfs_equal(header->mst.magic, "FILE", sizeof(header->mst.magic)) &&
			    (flags & NTFS_RECORD_IN_USE) != 0) {
				result = NTFS_CORRUPT;
			}
			validation->report->records_scanned++;
			continue;
		}
		result = ntfs_record_validate(record, validation->volume->info.record_size);
		if (result != NTFS_OK) {
			break;
		}
		validation->records[i].reference =
		    i | (uint64_t)ntfs_u16(header->sequence) << NTFS_REFERENCE_SEQUENCE_SHIFT;
		validation->report->reference = validation->records[i].reference;
		validation->records[i].base = ntfs_u64(header->base_reference);
		validation->records[i].flags = flags;
		validation->records[i].links = ntfs_u16(header->links);
		position = ntfs_u16(header->attrs_offset);
		if (i >= VALIDATION_RESERVED_FIRST && i <= VALIDATION_RESERVED_LAST &&
		    flags == NTFS_RECORD_IN_USE && validation->records[i].base == 0 &&
		    validation->records[i].links == 0) {
			validation->records[i].reserved_empty =
			    ntfs_attr_at(record, ntfs_u32(header->used), &position,
				&attribute_view) == NTFS_END;
			validation->records[i].reserved_inert =
			    validation->records[i].reserved_empty ||
			    ntfs_validation_inert_reserved_record(record);
		}
		validation->report->records_scanned++;
		if (validation->records[i].base == 0) {
			validation->report->base_records++;
		} else {
			validation->report->extension_records++;
		}
	}
	for (i = 0; result == NTFS_OK && i < count; i++) {
		if (validation->records[i].reference == 0) {
			continue;
		}
		validation->report->reference = validation->records[i].reference;
		validation->report->record_number = i;
		validation->report->related_reference = validation->records[i].base;
		if (validation->records[i].base != 0 &&
		    ntfs_validation_checked_reference(validation, validation->records[i].base) ==
			NULL) {
			result = NTFS_STALE;
		}
	}
finish:
	ntfs_validation_release(validation, record, validation->volume->info.record_size);
	ntfs_validation_release(validation, bits, (size_t)bitmap_size);
	ntfs_stream_close(bitmap);
	ntfs_node_close(mft);
	return result;
}

static enum ntfs_result
ntfs_validation_remember_stream(struct ntfs_validation_context *validation,
    struct ntfs_stream *stream, uint64_t reference, uint32_t type)
{
	const struct ntfs_run *run;
	void *storage;
	uint32_t i;
	enum ntfs_result result;

	for (i = 0; i < stream->run_count; i++) {
		run = &stream->runs[i];
		if (ntfs_validation_charge(validation, sizeof(*run)) != NTFS_OK) {
			return validation->failure;
		}
		if (run->lcn == NTFS_HOLE) {
			continue;
		}
		storage = validation->runs;
		result = ntfs_validation_grow(validation, &storage, &validation->run_capacity,
		    validation->run_count + 1, sizeof(*validation->runs),
		    validation->limits.max_runs, NTFS_VALIDATION_LIMIT_RUNS);
		if (result != NTFS_OK) {
			return result;
		}
		validation->runs = storage;
		if (run->length > UINT64_MAX - validation->report->claimed_clusters) {
			return NTFS_CORRUPT;
		}
		validation->runs[validation->run_count++] =
		    (struct ntfs_validation_run){run->lcn, run->lcn + run->length, reference, type};
		validation->report->physical_runs++;
		validation->report->claimed_clusters += run->length;
	}
	validation->report->streams++;
	return NTFS_OK;
}

enum ntfs_result
ntfs_validation_remember_link(struct ntfs_validation_context *validation, uint64_t parent,
    uint64_t reference, const uint16_t *name, uint16_t length, uint8_t name_namespace,
    uint8_t source)
{
	struct ntfs_validation_record *owner =
	    ntfs_validation_checked_reference(validation, reference);
	struct ntfs_validation_record *directory =
	    ntfs_validation_checked_reference(validation, parent);
	void *storage;
	enum ntfs_result result;
	size_t i;

	validation->report->reference = reference;
	validation->report->record_number = reference & NTFS_REFERENCE_RECORD_MASK;
	validation->report->related_reference = parent;
	if (owner == NULL || directory == NULL) {
		return NTFS_STALE;
	}
	if ((directory->flags & NTFS_RECORD_DIRECTORY) == 0 || length == 0 ||
	    length > NTFS_NAME_MAX || name_namespace > NTFS_NAMESPACE_WIN32_DOS) {
		return NTFS_CORRUPT;
	}
	for (i = 0; i < length; i++) {
		if (name[i] == 0 || name[i] == '/') {
			return NTFS_CORRUPT;
		}
	}
	/* The root's self-name is a structural anchor, not a namespace edge. */
	if ((reference & NTFS_REFERENCE_RECORD_MASK) == NTFS_ROOT_RECORD) {
		if (parent != reference || length != 1 || name[0] != '.') {
			return NTFS_CORRUPT;
		}
		if (source == VALIDATION_FILENAME_SOURCE && ++owner->primary_names != 1) {
			return NTFS_CORRUPT;
		}
		return NTFS_OK;
	}
	storage = validation->links;
	result = ntfs_validation_grow(validation, &storage, &validation->link_capacity,
	    validation->link_count + 1, sizeof(*validation->links), validation->limits.max_links,
	    NTFS_VALIDATION_LIMIT_LINKS);
	if (result == NTFS_OK) {
		validation->links = storage;
		storage = validation->names;
		result = ntfs_validation_grow(validation, &storage, &validation->name_capacity,
		    validation->name_count + length, sizeof(*validation->names),
		    validation->limits.max_links * NTFS_NAME_MAX, NTFS_VALIDATION_LIMIT_LINKS);
	}
	if (result != NTFS_OK) {
		return result;
	}
	validation->names = storage;
	ntfs_copy(validation->names + validation->name_count, name, (size_t)length * sizeof(*name));
	validation->links[validation->link_count++] = (struct ntfs_validation_link){
	    parent, reference, validation->name_count, length, name_namespace, source};
	validation->name_count += length;
	if (source == VALIDATION_FILENAME_SOURCE) {
		if (name_namespace == NTFS_NAMESPACE_DOS) {
			if (owner->dos_names == UINT16_MAX) {
				return NTFS_CORRUPT;
			}
			owner->dos_names++;
		} else {
			if (owner->primary_names == UINT16_MAX) {
				return NTFS_CORRUPT;
			}
			owner->primary_names++;
			if ((owner->flags & NTFS_RECORD_DIRECTORY) != 0) {
				if (owner->parent != 0 && owner->parent != parent) {
					return NTFS_CORRUPT;
				}
				owner->parent = parent;
			}
		}
		validation->report->filename_attributes++;
	} else {
		validation->report->index_entries++;
	}
	return NTFS_OK;
}

static enum ntfs_result
ntfs_validation_remember_filename(struct ntfs_validation_context *validation, uint64_t owner,
    const struct ntfs_attr_view *attribute_view, uint16_t *name)
{
	const struct ntfs_disk_filename *file;
	const uint8_t *value;
	size_t size, i;
	enum ntfs_result result;

	result = ntfs_attr_value(attribute_view, &value, &size);
	if (result != NTFS_OK || attribute_view->flags != 0 ||
	    attribute_view->disk->name_length != 0 || size < sizeof(*file)) {
		return NTFS_CORRUPT;
	}
	file = (const void *)value;
	if (size != sizeof(*file) + (size_t)file->length * NTFS_UTF16_UNIT_BYTES) {
		return NTFS_CORRUPT;
	}
	for (i = 0; i < file->length; i++) {
		name[i] = ntfs_u16(value + sizeof(*file) + i * NTFS_UTF16_UNIT_BYTES);
	}
	return ntfs_validation_remember_link(validation, ntfs_u64(file->parent), owner, name,
	    file->length, file->name_namespace, VALIDATION_FILENAME_SOURCE);
}

static enum ntfs_result
ntfs_validation_check_list(struct ntfs_validation_context *validation, struct ntfs_node *owner,
    const uint8_t *bytes, size_t size, uint16_t *name)
{
	const struct ntfs_disk_attr_list *entry;
	const struct ntfs_validation_record *record;
	struct ntfs_attr_view attribute_view;
	uint8_t *loaded = NULL;
	uint64_t reference, number;
	size_t offset = 0, i;
	enum ntfs_result result;

	while ((result = ntfs_list_entry_at(bytes, size, &offset, &entry)) == NTFS_OK) {
		if (ntfs_validation_charge(validation, ntfs_u16(entry->length)) != NTFS_OK) {
			return validation->failure;
		}
		reference = ntfs_u64(entry->reference);
		number = reference & NTFS_REFERENCE_RECORD_MASK;
		validation->report->related_reference = reference;
		if (number >= validation->report->record_slots ||
		    reference >> NTFS_REFERENCE_SEQUENCE_SHIFT == 0) {
			return NTFS_STALE;
		}
		record = &validation->records[number];
		if (record->reference != reference ||
		    (reference != owner->reference && record->base != owner->reference)) {
			return NTFS_STALE;
		}
		for (i = 0; i < entry->name_length; i++) {
			name[i] = ntfs_u16((const uint8_t *)entry + entry->name_offset +
			    i * NTFS_UTF16_UNIT_BYTES);
		}
		if (reference == owner->reference) {
			loaded = owner->record;
			result = NTFS_OK;
		} else {
			result = ntfs_record_read(validation->volume, number, &loaded);
		}
		if (result == NTFS_OK) {
			result = ntfs_listed_attribute(loaded, ntfs_u32(entry->type), name,
			    entry->name_length, ntfs_u16(entry->instance), ntfs_u64(entry->lowest),
			    &attribute_view);
		}
		if (loaded != owner->record) {
			ntfs_free(validation->volume, loaded, validation->volume->info.record_size);
		}
		loaded = NULL;
		if (result != NTFS_OK) {
			return result;
		}
	}
	return result == NTFS_END ? NTFS_OK : result;
}

static enum ntfs_result
ntfs_validation_listed_extent(struct ntfs_validation_context *validation, const uint8_t *bytes,
    size_t size, uint64_t reference, const struct ntfs_attr_view *attribute_view, uint64_t lowest)
{
	const struct ntfs_disk_attr_list *entry;
	size_t offset = 0;
	bool found = false;
	enum ntfs_result result;

	while ((result = ntfs_list_entry_at(bytes, size, &offset, &entry)) == NTFS_OK) {
		if (ntfs_validation_charge(validation, ntfs_u16(entry->length)) != NTFS_OK) {
			return validation->failure;
		}
		if (ntfs_u64(entry->reference) != reference ||
		    ntfs_u32(entry->type) != attribute_view->type ||
		    ntfs_u64(entry->lowest) != lowest ||
		    entry->name_length != attribute_view->disk->name_length ||
		    (lowest == 0 && ntfs_u16(entry->instance) != attribute_view->instance)) {
			continue;
		}
		if (!ntfs_equal((const uint8_t *)entry + entry->name_offset,
			attribute_view->bytes + ntfs_u16(attribute_view->disk->name_offset),
			(size_t)entry->name_length * NTFS_UTF16_UNIT_BYTES)) {
			continue;
		}
		if (found) {
			return NTFS_CORRUPT;
		}
		found = true;
	}
	if (result != NTFS_END) {
		return result;
	}
	return found ? NTFS_OK : NTFS_CORRUPT;
}

enum ntfs_result
ntfs_validation_scan_attributes(struct ntfs_validation_context *validation)
{
	struct ntfs_node *owner = NULL;
	struct ntfs_stream *stream = NULL;
	struct ntfs_stat stat;
	const struct ntfs_disk_record *header;
	const struct ntfs_disk_nonresident *extent;
	struct ntfs_attr_view attribute_view;
	uint8_t *record = NULL, *list = NULL;
	/* List validation, filename admission and stream lookup consume names
	 * serially; retain one scan-owned UTF-16 buffer across those phases. */
	uint16_t name[NTFS_NAME_MAX];
	uint64_t i, owner_reference, lowest;
	uint32_t position;
	size_t list_size = 0, unit;
	enum ntfs_result result = NTFS_OK;

	validation->report->stage = NTFS_VALIDATION_ATTRIBUTES;
	for (i = 0; i < validation->report->record_slots; i++) {
		if (validation->records[i].reference == 0 ||
		    validation->records[i].reserved_empty) {
			continue;
		}
		validation->report->reference = validation->records[i].reference;
		validation->report->record_number = i;
		validation->report->related_reference = 0;
		validation->report->attribute_type = 0;
		owner_reference = validation->records[i].base != 0
		    ? validation->records[i].base
		    : validation->records[i].reference;
		result = ntfs_node_open(validation->volume, owner_reference, &owner);
		if (result == NTFS_OK) {
			result = ntfs_node_metadata(owner, &stat);
			if (result == NTFS_NOT_FOUND) {
				result = NTFS_CORRUPT;
			}
		}
		if (result != NTFS_OK) {
			break;
		}
		if (validation->records[i].base == 0) {
			validation->records[i].security_id = stat.security_id;
			validation->records[i].hidden_system =
			    (stat.file_attributes & (NTFS_FILE_HIDDEN | NTFS_FILE_SYSTEM)) ==
			    (NTFS_FILE_HIDDEN | NTFS_FILE_SYSTEM);
			if (stat.security_id != 0) {
				validation->has_security_ids = true;
			}
		}
		list_size = 0;
		result = ntfs_attribute_list_read(owner, &list, &list_size);
		if (result == NTFS_NOT_FOUND) {
			result = NTFS_OK;
		} else if (result == NTFS_OK && validation->records[i].base == 0) {
			result = ntfs_validation_check_list(validation, owner, list, list_size, name);
		}
		if (result != NTFS_OK) {
			break;
		}
		if (validation->records[i].base == 0) {
			record = owner->record;
		} else {
			result = ntfs_record_read(validation->volume, i, &record);
		}
		if (result != NTFS_OK) {
			break;
		}
		header = (const void *)record;
		position = ntfs_u16(header->attrs_offset);
		while ((result = ntfs_attr_at(record, ntfs_u32(header->used), &position,
			    &attribute_view)) == NTFS_OK) {
			validation->report->attribute_type = attribute_view.type;
			validation->report->related_reference = owner_reference;
			if (ntfs_validation_charge(validation, attribute_view.length) != NTFS_OK) {
				result = validation->failure;
				break;
			}
			lowest = 0;
			if (attribute_view.disk->nonresident) {
				extent = (const void *)(attribute_view.bytes +
				    sizeof(struct ntfs_disk_attr));
				lowest = ntfs_u64(extent->lowest);
			}
			if (validation->records[i].base != 0 || lowest != 0 ||
			    (list != NULL && attribute_view.type != NTFS_ATTR_LIST)) {
				result = ntfs_validation_listed_extent(validation, list, list_size,
				    validation->records[i].reference, &attribute_view, lowest);
				if (result != NTFS_OK) {
					break;
				}
			}
			validation->report->attributes++;
			if (attribute_view.type == NTFS_ATTR_FILENAME) {
				result = ntfs_validation_remember_filename(
				    validation, owner_reference, &attribute_view, name);
			} else if (lowest == 0) {
				for (unit = 0; unit < attribute_view.disk->name_length; unit++) {
					name[unit] = ntfs_u16(attribute_view.bytes +
					    ntfs_u16(attribute_view.disk->name_offset) +
					    unit * NTFS_UTF16_UNIT_BYTES);
				}
				result = ntfs_bad_clusters_open(owner, attribute_view.type, name,
				    attribute_view.disk->name_length, &stream);
				if (result == NTFS_NOT_FOUND) {
					result = ntfs_attribute_open(owner, attribute_view.type,
					    name, attribute_view.disk->name_length, &stream);
				}
				if (result == NTFS_OK) {
					if (!stream->resident) {
						result = ntfs_validation_remember_stream(validation,
						    stream, owner_reference, attribute_view.type);
					}
				}
				ntfs_stream_close(stream);
				stream = NULL;
			}
			if (result != NTFS_OK) {
				break;
			}
		}
		if (result == NTFS_END) {
			result = NTFS_OK;
		}
		if (record != owner->record) {
			ntfs_free(validation->volume, record, validation->volume->info.record_size);
		}
		record = NULL;
		ntfs_free(validation->volume, list, list_size);
		list = NULL;
		ntfs_node_close(owner);
		owner = NULL;
		if (result != NTFS_OK) {
			break;
		}
	}
	if (owner != NULL && record != owner->record) {
		ntfs_free(validation->volume, record, validation->volume->info.record_size);
	}
	ntfs_free(validation->volume, list, list_size);
	ntfs_node_close(owner);
	return result;
}
