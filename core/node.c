/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"

enum ntfs_result
ntfs_node_by_number(struct ntfs_volume *v, uint64_t number, struct ntfs_node **out)
{
	struct ntfs_node *node;
	const struct ntfs_disk_record *header;
	enum ntfs_result result;

	*out = NULL;
	if (v->children == UINT32_MAX) {
		return NTFS_RANGE;
	}
	node = ntfs_alloc(v, sizeof(*node));
	if (node == NULL) {
		return NTFS_NO_MEMORY;
	}
	node->volume = v;
	result = ntfs_record_read(v, number, &node->record);
	if (result != NTFS_OK) {
		ntfs_free(v, node, sizeof(*node));
		return result;
	}
	header = (const void *)node->record;
	if (ntfs_u64(header->base_reference) != 0) {
		ntfs_free(v, node->record, v->info.record_size);
		ntfs_free(v, node, sizeof(*node));
		return NTFS_CORRUPT;
	}
	node->reference =
	    number | (uint64_t)ntfs_u16(header->sequence) << NTFS_REFERENCE_SEQUENCE_SHIFT;
	v->children++;
	*out = node;
	return NTFS_OK;
}

enum ntfs_result
ntfs_node_open(struct ntfs_volume *v, uint64_t reference, struct ntfs_node **out)
{
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	*out = NULL;
	if (v == NULL || reference >> NTFS_REFERENCE_SEQUENCE_SHIFT == 0) {
		return NTFS_INVALID;
	}
	result = ntfs_node_by_number(v, reference & NTFS_REFERENCE_RECORD_MASK, out);
	if (result == NTFS_OK && (*out)->reference != reference) {
		ntfs_node_close(*out);
		*out = NULL;
		return NTFS_STALE;
	}
	return result;
}

enum ntfs_result
ntfs_root(struct ntfs_volume *v, struct ntfs_node **out)
{
	if (v == NULL || out == NULL) {
		return NTFS_INVALID;
	}
	return ntfs_node_by_number(v, NTFS_ROOT_RECORD, out);
}

void
ntfs_node_close(struct ntfs_node *node)
{
	struct ntfs_volume *v;

	if (node == NULL) {
		return;
	}
	v = node->volume;
	v->children--;
	ntfs_free(v, node->record, v->info.record_size);
	ntfs_free(v, node, sizeof(*node));
}

enum ntfs_result
ntfs_node_metadata(struct ntfs_node *node, struct ntfs_stat *st)
{
	const struct ntfs_disk_record *r;
	const struct ntfs_disk_standard *si;
	const struct ntfs_disk_standard_extension *extended;
	struct ntfs_attr_view a;
	struct ntfs_stream *reparse = NULL;
	const uint8_t *value;
	size_t length;
	enum ntfs_result result;

	if (node == NULL || st == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(st, sizeof(*st));
	r = (const void *)node->record;
	st->reference = node->reference;
	st->links = ntfs_u16(r->links);
	st->directory = (ntfs_u16(r->flags) & NTFS_RECORD_DIRECTORY) != 0;
	result = ntfs_attr_find(node->record, node->volume->info.record_size, NTFS_ATTR_STANDARD,
	    NULL, 0, UINT16_MAX, &a);
	if (result != NTFS_OK) {
		return result == NTFS_NOT_FOUND ? NTFS_CORRUPT : result;
	}
	result = ntfs_attr_value(&a, &value, &length);
	if (result != NTFS_OK || a.flags != 0 || length < sizeof(*si) ||
	    (length > sizeof(*si) && length < sizeof(*si) + sizeof(*extended))) {
		return NTFS_CORRUPT;
	}
	si = (const void *)value;
	st->file_attributes = ntfs_u32(si->attributes);
	st->reparse = (st->file_attributes & NTFS_FILE_REPARSE) != 0;
	ntfs_decode_time(ntfs_u64(si->created), &st->created);
	ntfs_decode_time(ntfs_u64(si->modified), &st->modified);
	ntfs_decode_time(ntfs_u64(si->changed), &st->changed);
	ntfs_decode_time(ntfs_u64(si->accessed), &st->accessed);
	if (length >= sizeof(*si) + sizeof(*extended)) {
		extended = (const void *)(value + sizeof(*si));
		st->security_id = ntfs_u32(extended->security_id);
	}
	if (!st->reparse) {
		/* A cleared standard-information flag cannot turn filter-owned data
		 * into an ordinary file. This also searches attribute-list extensions. */
		result = ntfs_attribute_open(node, NTFS_ATTRIBUTE_REPARSE_POINT, NULL, 0, &reparse);
		ntfs_stream_close(reparse);
		if (result != NTFS_NOT_FOUND) {
			return result == NTFS_OK ? NTFS_CORRUPT : result;
		}
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_node_stat(struct ntfs_node *node, struct ntfs_stat *st)
{
	struct ntfs_stream *s = NULL;
	enum ntfs_result result;

	result = ntfs_node_metadata(node, st);
	if (result != NTFS_OK) {
		return result;
	}
	if (st->directory || st->reparse) {
		return NTFS_OK;
	}
	result = ntfs_attribute_open(node, NTFS_ATTRIBUTE_DATA, NULL, 0, &s);
	if (result != NTFS_OK) {
		return result;
	}
	st->size = s->size;
	st->allocated_size = s->physical_size;
	ntfs_stream_close(s);
	return NTFS_OK;
}
