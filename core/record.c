/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"

enum ntfs_result
ntfs_fixup(void *buffer, size_t size, const char *magic)
{
	uint8_t *bytes = buffer;
	const struct ntfs_disk_mst *m = buffer;
	size_t offset, count, i, tail;
	uint16_t sequence;

	if (size < sizeof(*m) || size % NTFS_MST_STRIDE != 0 ||
	    !ntfs_equal(m->magic, magic, sizeof(m->magic))) {
		return NTFS_CORRUPT;
	}
	offset = ntfs_u16(m->usa_offset);
	count = ntfs_u16(m->usa_count);
	if (count != size / NTFS_MST_STRIDE + 1 || offset < sizeof(*m) ||
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
ntfs_attr_at(const uint8_t *record, size_t size, uint32_t *position, struct ntfs_attr_view *a)
{
	const struct ntfs_disk_attr *d;
	const struct ntfs_disk_resident *r;
	const struct ntfs_disk_nonresident *n;
	size_t minimum, name_end, value_offset;

	if (!ntfs_bounds(*position, sizeof(uint32_t), size)) {
		return NTFS_CORRUPT;
	}
	if (ntfs_u32(record + *position) == NTFS_ATTR_END) {
		return NTFS_END;
	}
	if (*position % NTFS_WIRE_ALIGNMENT != 0 || !ntfs_bounds(*position, sizeof(*d), size)) {
		return NTFS_CORRUPT;
	}
	d = (const void *)(record + *position);
	a->disk = d;
	a->bytes = (const void *)d;
	a->length = ntfs_u32(d->length);
	a->type = ntfs_u32(d->type);
	a->flags = ntfs_u16(d->flags);
	a->instance = ntfs_u16(d->instance);
	if (d->nonresident > 1 || a->type == 0 || a->length % NTFS_WIRE_ALIGNMENT != 0 ||
	    !ntfs_bounds(*position, a->length, size)) {
		return NTFS_CORRUPT;
	}
	minimum = sizeof(*d) + (d->nonresident ? sizeof(*n) : sizeof(*r));
	if (d->nonresident && (a->flags & (NTFS_ATTR_COMPRESSED | NTFS_ATTR_SPARSE)) != 0) {
		minimum += sizeof(struct ntfs_disk_compressed_tail);
	}
	if (a->length < minimum) {
		return NTFS_CORRUPT;
	}
	name_end = minimum;
	if (d->name_length != 0) {
		name_end = ntfs_u16(d->name_offset);
		if (name_end < minimum || name_end % NTFS_UTF16_UNIT_BYTES != 0 ||
		    !ntfs_bounds(
			name_end, (size_t)d->name_length * NTFS_UTF16_UNIT_BYTES, a->length)) {
			return NTFS_CORRUPT;
		}
		name_end += (size_t)d->name_length * NTFS_UTF16_UNIT_BYTES;
	}
	if (d->nonresident) {
		n = (const void *)(a->bytes + sizeof(*d));
		value_offset = ntfs_u16(n->mapping_offset);
		if (value_offset < name_end || value_offset >= a->length) {
			return NTFS_CORRUPT;
		}
	} else {
		r = (const void *)(a->bytes + sizeof(*d));
		value_offset = ntfs_u16(r->offset);
		if (value_offset < name_end ||
		    !ntfs_bounds(value_offset, ntfs_u32(r->length), a->length)) {
			return NTFS_CORRUPT;
		}
	}
	*position += a->length;
	return NTFS_OK;
}

enum ntfs_result
ntfs_record_decode(void *buffer, size_t size, bool require_active)
{
	struct ntfs_disk_record *r = buffer;
	struct ntfs_attr_view a;
	enum ntfs_result result;
	uint32_t position, used;
	uint16_t flags;

	result = ntfs_fixup(buffer, size, "FILE");
	if (result != NTFS_OK || size < sizeof(*r)) {
		return NTFS_CORRUPT;
	}
	used = ntfs_u32(r->used);
	position = ntfs_u16(r->attrs_offset);
	flags = ntfs_u16(r->flags);
	if (ntfs_u32(r->allocated) != size || used > size || position < sizeof(*r) ||
	    position % NTFS_WIRE_ALIGNMENT != 0 ||
	    (require_active && (flags & NTFS_RECORD_IN_USE) == 0) ||
	    (flags &
		~(NTFS_RECORD_IN_USE | NTFS_RECORD_DIRECTORY | NTFS_RECORD_UNINTERPRETED |
		    NTFS_RECORD_VIEW_INDEX)) != 0 ||
	    ntfs_u16(r->sequence) == 0 || ntfs_u16(r->mst.usa_offset) < sizeof(*r) ||
	    ntfs_u16(r->mst.usa_offset) + (size_t)ntfs_u16(r->mst.usa_count) * NTFS_MST_WORD_BYTES >
		position) {
		return NTFS_CORRUPT;
	}
	do {
		result = ntfs_attr_at(buffer, used, &position, &a);
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
	const struct ntfs_disk_record *r = (const void *)record;
	struct ntfs_attr_view a;
	enum ntfs_result result;
	uint32_t position;
	size_t i;
	bool match, found = false;

	(void)size;
	position = ntfs_u16(r->attrs_offset);
	while ((result = ntfs_attr_at(record, ntfs_u32(r->used), &position, &a)) == NTFS_OK) {
		if (a.type != type || a.disk->name_length != length ||
		    (instance != UINT16_MAX && a.instance != instance)) {
			continue;
		}
		match = true;
		for (i = 0; i < length; i++) {
			if (ntfs_u16(a.bytes + ntfs_u16(a.disk->name_offset) +
				i * NTFS_UTF16_UNIT_BYTES) != name[i]) {
				match = false;
				break;
			}
		}
		if (match) {
			if (found) {
				return NTFS_CORRUPT;
			}
			*out = a;
			found = true;
		}
	}
	if (result != NTFS_END) {
		return result;
	}
	return found ? NTFS_OK : NTFS_NOT_FOUND;
}

enum ntfs_result
ntfs_attr_value(const struct ntfs_attr_view *a, const uint8_t **data, size_t *size)
{
	const struct ntfs_disk_resident *r;

	if (a->disk->nonresident) {
		return NTFS_UNSUPPORTED;
	}
	r = (const void *)(a->bytes + sizeof(struct ntfs_disk_attr));
	*data = a->bytes + ntfs_u16(r->offset);
	*size = ntfs_u32(r->length);
	return NTFS_OK;
}

enum ntfs_result
ntfs_record_read(struct ntfs_volume *v, uint64_t number, uint8_t **out)
{
	uint8_t *record;
	uint32_t i, victim = 0;
	uint64_t offset, oldest = UINT64_MAX;
	enum ntfs_result result;

	*out = NULL;
	if (number > NTFS_REFERENCE_RECORD_MASK || number > UINT64_MAX / v->info.record_size) {
		return NTFS_CORRUPT;
	}
	offset = number * v->info.record_size;
	if (!ntfs_bounds(offset, v->info.record_size, v->mft->size)) {
		return NTFS_CORRUPT;
	}
	result = ntfs_work(v, v->info.record_size);
	if (result != NTFS_OK) {
		return result;
	}
	record = ntfs_alloc(v, v->info.record_size);
	if (record == NULL) {
		return NTFS_NO_MEMORY;
	}
	for (i = 0; v->cache != NULL && i < v->limits.record_cache_entries; i++) {
		if (v->cache[i].bytes != NULL && v->cache[i].number == number) {
			ntfs_copy(record, v->cache[i].bytes, v->info.record_size);
			v->cache[i].stamp = ++v->clock;
			v->stats.record_cache_hits++;
			*out = record;
			return NTFS_OK;
		}
		if (v->cache[i].stamp < oldest) {
			oldest = v->cache[i].stamp;
			victim = i;
		}
	}
	v->stats.record_cache_misses++;
	result = ntfs_stream_exact(v->mft, offset, record, v->info.record_size);
	if (result == NTFS_OK) {
		result = ntfs_record_decode(record, v->info.record_size, false);
		if (result == NTFS_OK &&
		    (ntfs_u16(((const struct ntfs_disk_record *)(const void *)record)->flags) &
			NTFS_RECORD_IN_USE) == 0) {
			/* Valid retired records cannot publish a node or enter its cache.
			 * Torn or malformed free headers still retain their decoding error. */
			result = NTFS_NOT_FOUND;
		}
	}
	if (result != NTFS_OK) {
		ntfs_free(v, record, v->info.record_size);
		return result;
	}
	if (v->cache != NULL) {
		if (v->cache[victim].bytes == NULL) {
			v->cache[victim].bytes = ntfs_alloc_optional(v, v->info.record_size);
		}
		if (v->cache[victim].bytes != NULL) {
			ntfs_copy(v->cache[victim].bytes, record, v->info.record_size);
			v->cache[victim].number = number;
			v->cache[victim].stamp = ++v->clock;
		}
	}
	*out = record;
	return NTFS_OK;
}
