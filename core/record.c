/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"

enum ntfs_result
ntfs_fixup(void *buffer, size_t size, const char *magic)
{
	uint8_t *bytes = buffer;
	const struct ntfs_disk_mst *mst_header = buffer;
	size_t offset, count, i, tail;
	uint16_t sequence;

	if (size < sizeof(*mst_header) || size % NTFS_MST_STRIDE != 0 ||
	    !ntfs_equal(mst_header->magic, magic, sizeof(mst_header->magic))) {
		return NTFS_CORRUPT;
	}
	offset = ntfs_u16(mst_header->usa_offset);
	count = ntfs_u16(mst_header->usa_count);
	if (count != size / NTFS_MST_STRIDE + 1 || offset < sizeof(*mst_header) ||
	    offset % NTFS_MST_WORD_BYTES != 0 ||
	    !ntfs_bounds(
		offset, count * NTFS_MST_WORD_BYTES, NTFS_MST_STRIDE - NTFS_MST_WORD_BYTES)) {
		return NTFS_CORRUPT;
	}
	sequence = ntfs_u16(bytes + offset);
	if (sequence == 0 || sequence == UINT16_MAX) {
		return NTFS_CORRUPT;
	}
	/* Validate all tails before changing any byte, so failure is atomic. */
	for (i = 1; i < count; i++) {
		tail = i * NTFS_MST_STRIDE - NTFS_MST_WORD_BYTES;
		if (ntfs_u16(bytes + tail) != sequence) {
			return NTFS_CORRUPT;
		}
	}
	for (i = 1; i < count; i++) {
		tail = i * NTFS_MST_STRIDE - NTFS_MST_WORD_BYTES;
		ntfs_copy(
		    bytes + tail, bytes + offset + i * NTFS_MST_WORD_BYTES, NTFS_MST_WORD_BYTES);
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_attr_at(
    const uint8_t *record, size_t size, uint32_t *position, struct ntfs_attr_view *attribute_view)
{
	const struct ntfs_disk_attr *disk_attribute;
	const struct ntfs_disk_resident *resident_header;
	const struct ntfs_disk_nonresident *nonresident_header;
	size_t minimum, name_end, value_offset;

	if (!ntfs_bounds(*position, sizeof(uint32_t), size)) {
		return NTFS_CORRUPT;
	}
	if (ntfs_u32(record + *position) == NTFS_ATTR_END) {
		return NTFS_END;
	}
	if (*position % NTFS_WIRE_ALIGNMENT != 0 ||
	    !ntfs_bounds(*position, sizeof(*disk_attribute), size)) {
		return NTFS_CORRUPT;
	}
	disk_attribute = (const void *)(record + *position);
	attribute_view->disk = disk_attribute;
	attribute_view->bytes = (const void *)disk_attribute;
	attribute_view->length = ntfs_u32(disk_attribute->length);
	attribute_view->type = ntfs_u32(disk_attribute->type);
	attribute_view->flags = ntfs_u16(disk_attribute->flags);
	attribute_view->instance = ntfs_u16(disk_attribute->instance);
	if (disk_attribute->nonresident > 1 || attribute_view->type == 0 ||
	    attribute_view->length % NTFS_WIRE_ALIGNMENT != 0 ||
	    !ntfs_bounds(*position, attribute_view->length, size)) {
		return NTFS_CORRUPT;
	}
	minimum = sizeof(*disk_attribute) +
	    (disk_attribute->nonresident ? sizeof(*nonresident_header) : sizeof(*resident_header));
	if (disk_attribute->nonresident &&
	    (attribute_view->flags & (NTFS_ATTR_COMPRESSED | NTFS_ATTR_SPARSE)) != 0) {
		minimum += sizeof(struct ntfs_disk_compressed_tail);
	}
	if (attribute_view->length < minimum) {
		return NTFS_CORRUPT;
	}
	name_end = minimum;
	if (disk_attribute->name_length != 0) {
		name_end = ntfs_u16(disk_attribute->name_offset);
		if (name_end < minimum || name_end % NTFS_UTF16_UNIT_BYTES != 0 ||
		    !ntfs_bounds(name_end,
			(size_t)disk_attribute->name_length * NTFS_UTF16_UNIT_BYTES,
			attribute_view->length)) {
			return NTFS_CORRUPT;
		}
		name_end += (size_t)disk_attribute->name_length * NTFS_UTF16_UNIT_BYTES;
	}
	if (disk_attribute->nonresident) {
		nonresident_header =
		    (const void *)(attribute_view->bytes + sizeof(*disk_attribute));
		value_offset = ntfs_u16(nonresident_header->mapping_offset);
		if (value_offset < name_end || value_offset >= attribute_view->length) {
			return NTFS_CORRUPT;
		}
	} else {
		resident_header = (const void *)(attribute_view->bytes + sizeof(*disk_attribute));
		value_offset = ntfs_u16(resident_header->offset);
		if (value_offset < name_end ||
		    !ntfs_bounds(
			value_offset, ntfs_u32(resident_header->length), attribute_view->length)) {
			return NTFS_CORRUPT;
		}
	}
	*position += attribute_view->length;
	return NTFS_OK;
}

enum ntfs_result
ntfs_record_decode(void *buffer, size_t size, bool require_active)
{
	struct ntfs_disk_record *record_header = buffer;
	struct ntfs_attr_view attribute_view;
	enum ntfs_result result;
	uint32_t position, used;
	uint16_t flags;

	result = ntfs_fixup(buffer, size, "FILE");
	if (result != NTFS_OK || size < sizeof(*record_header)) {
		return NTFS_CORRUPT;
	}
	used = ntfs_u32(record_header->used);
	position = ntfs_u16(record_header->attrs_offset);
	flags = ntfs_u16(record_header->flags);
	if (ntfs_u32(record_header->allocated) != size || used > size ||
	    position < sizeof(*record_header) || position % NTFS_WIRE_ALIGNMENT != 0 ||
	    (require_active && (flags & NTFS_RECORD_IN_USE) == 0) ||
	    (flags &
		~(NTFS_RECORD_IN_USE | NTFS_RECORD_DIRECTORY | NTFS_RECORD_UNINTERPRETED |
		    NTFS_RECORD_VIEW_INDEX)) != 0 ||
	    ntfs_u16(record_header->sequence) == 0 ||
	    ntfs_u16(record_header->mst.usa_offset) < sizeof(*record_header) ||
	    ntfs_u16(record_header->mst.usa_offset) +
		    (size_t)ntfs_u16(record_header->mst.usa_count) * NTFS_MST_WORD_BYTES >
		position) {
		return NTFS_CORRUPT;
	}
	do {
		result = ntfs_attr_at(buffer, used, &position, &attribute_view);
	} while (result == NTFS_OK);
	return result == NTFS_END ? NTFS_OK : result;
}

enum ntfs_result
ntfs_record_validate(void *buffer, size_t size)
{
	return ntfs_record_decode(buffer, size, true);
}

enum ntfs_result
ntfs_attr_find(const uint8_t *record, size_t size, uint32_t type, const uint16_t *name,
    size_t length, uint16_t instance, struct ntfs_attr_view *out)
{
	const struct ntfs_disk_record *record_header = (const void *)record;
	struct ntfs_attr_view attribute_view;
	enum ntfs_result result;
	uint32_t position;
	size_t i;
	bool match, found = false;

	(void)size;
	position = ntfs_u16(record_header->attrs_offset);
	while ((result = ntfs_attr_at(record, ntfs_u32(record_header->used), &position,
		    &attribute_view)) == NTFS_OK) {
		if (attribute_view.type != type || attribute_view.disk->name_length != length ||
		    (instance != UINT16_MAX && attribute_view.instance != instance)) {
			continue;
		}
		match = true;
		for (i = 0; i < length; i++) {
			if (ntfs_u16(attribute_view.bytes +
				ntfs_u16(attribute_view.disk->name_offset) +
				i * NTFS_UTF16_UNIT_BYTES) != name[i]) {
				match = false;
				break;
			}
		}
		if (match) {
			if (found) {
				return NTFS_CORRUPT;
			}
			*out = attribute_view;
			found = true;
		}
	}
	if (result != NTFS_END) {
		return result;
	}
	return found ? NTFS_OK : NTFS_NOT_FOUND;
}

enum ntfs_result
ntfs_attr_value(const struct ntfs_attr_view *attribute_view, const uint8_t **data, size_t *size)
{
	const struct ntfs_disk_resident *resident_header;

	if (attribute_view->disk->nonresident) {
		return NTFS_UNSUPPORTED;
	}
	resident_header = (const void *)(attribute_view->bytes + sizeof(struct ntfs_disk_attr));
	*data = attribute_view->bytes + ntfs_u16(resident_header->offset);
	*size = ntfs_u32(resident_header->length);
	return NTFS_OK;
}

enum ntfs_result
ntfs_record_read(struct ntfs_volume *volume, uint64_t number, uint8_t **out)
{
	uint8_t *record;
	uint32_t i, victim = 0;
	uint64_t offset, oldest = UINT64_MAX;
	enum ntfs_result result;

	*out = NULL;
	if (number > NTFS_REFERENCE_RECORD_MASK || number > UINT64_MAX / volume->info.record_size) {
		return NTFS_CORRUPT;
	}
	offset = number * volume->info.record_size;
	if (!ntfs_bounds(offset, volume->info.record_size, volume->mft->size)) {
		return NTFS_CORRUPT;
	}
	result = ntfs_work(volume, volume->info.record_size);
	if (result != NTFS_OK) {
		return result;
	}
	record = ntfs_alloc(volume, volume->info.record_size);
	if (record == NULL) {
		return NTFS_NO_MEMORY;
	}
	for (i = 0; volume->cache != NULL && i < volume->limits.record_cache_entries; i++) {
		if (volume->cache[i].bytes != NULL && volume->cache[i].number == number) {
			ntfs_copy(record, volume->cache[i].bytes, volume->info.record_size);
			volume->cache[i].stamp = ++volume->clock;
			volume->stats.record_cache_hits++;
			*out = record;
			return NTFS_OK;
		}
		if (volume->cache[i].stamp < oldest) {
			oldest = volume->cache[i].stamp;
			victim = i;
		}
	}
	volume->stats.record_cache_misses++;
	result = ntfs_stream_exact(volume->mft, offset, record, volume->info.record_size);
	if (result == NTFS_OK) {
		result = ntfs_record_decode(record, volume->info.record_size, false);
		if (result == NTFS_OK &&
		    (ntfs_u16(((const struct ntfs_disk_record *)(const void *)record)->flags) &
			NTFS_RECORD_IN_USE) == 0) {
			/* Valid retired records cannot publish a node or enter its cache.
			 * Torn or malformed free headers still retain their decoding error. */
			result = NTFS_NOT_FOUND;
		}
	}
	if (result != NTFS_OK) {
		ntfs_free(volume, record, volume->info.record_size);
		return result;
	}
	if (volume->cache != NULL) {
		if (volume->cache[victim].bytes == NULL) {
			volume->cache[victim].bytes =
			    ntfs_alloc_optional(volume, volume->info.record_size);
		}
		if (volume->cache[victim].bytes != NULL) {
			ntfs_copy(volume->cache[victim].bytes, record, volume->info.record_size);
			volume->cache[victim].number = number;
			volume->cache[victim].stamp = ++volume->clock;
		}
	}
	*out = record;
	return NTFS_OK;
}
