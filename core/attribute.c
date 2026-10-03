/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"

static enum ntfs_result
validate_stream(struct ntfs_stream *s)
{
	uint64_t required, mapped = 0;
	uint32_t i, cluster = s->volume->info.cluster_size;
	enum ntfs_result result;

	if (s->resident) {
		return NTFS_OK;
	}
	required = s->size / cluster + (s->size % cluster != 0);
	if (s->clusters < required || s->clusters > (uint64_t)INT64_MAX / cluster) {
		return NTFS_CORRUPT;
	}
	result = ntfs_work(s->volume, s->run_count);
	if (result != NTFS_OK) {
		return result;
	}
	for (i = 0; i < s->run_count; i++) {
		if (s->runs[i].lcn != NTFS_HOLE) {
			mapped += s->runs[i].length;
		}
	}
	if ((s->flags & (NTFS_ATTR_COMPRESSION_MASK | NTFS_ATTR_SPARSE)) == 0 &&
	    mapped * cluster != s->allocated) {
		return NTFS_CORRUPT;
	}
	if ((s->flags & (NTFS_ATTR_COMPRESSION_MASK | NTFS_ATTR_SPARSE)) != 0 &&
	    mapped * cluster != s->physical_size) {
		return NTFS_CORRUPT;
	}
	s->physical_size = mapped * cluster;
	return NTFS_OK;
}

enum ntfs_result
ntfs_listed_attribute(const uint8_t *record, uint32_t type, const uint16_t *name,
    size_t name_length, uint16_t instance, uint64_t lowest, struct ntfs_attr_view *out)
{
	const struct ntfs_disk_record *header = (const void *)record;
	const struct ntfs_disk_nonresident *extent;
	struct ntfs_attr_view attr;
	uint32_t position = ntfs_u16(header->attrs_offset);
	size_t i;
	bool match, found = false;
	enum ntfs_result result;

	while (
	    (result = ntfs_attr_at(record, ntfs_u32(header->used), &position, &attr)) == NTFS_OK) {
		if (attr.type != type || attr.disk->name_length != name_length ||
		    (lowest == 0 && attr.instance != instance)) {
			continue;
		}
		if (attr.disk->nonresident) {
			extent = (const void *)(attr.bytes + sizeof(struct ntfs_disk_attr));
			if (ntfs_u64(extent->lowest) != lowest) {
				continue;
			}
		} else if (lowest != 0) {
			continue;
		}
		match = true;
		for (i = 0; i < name_length; i++) {
			if (name[i] !=
			    ntfs_u16(attr.bytes + ntfs_u16(attr.disk->name_offset) +
				i * NTFS_UTF16_UNIT_BYTES)) {
				match = false;
				break;
			}
		}
		if (match) {
			if (found) {
				return NTFS_CORRUPT;
			}
			*out = attr;
			found = true;
		}
	}
	if (result != NTFS_END) {
		return result;
	}
	return found ? NTFS_OK : NTFS_CORRUPT;
}

enum ntfs_result
ntfs_attribute_list_read(struct ntfs_node *node, uint8_t **out, size_t *out_size)
{
	struct ntfs_volume *v = node->volume;
	struct ntfs_stream *list = NULL;
	uint8_t *bytes = NULL;
	size_t size = 0;
	enum ntfs_result result;

	*out = NULL;
	*out_size = 0;
	result = ntfs_attribute_open(node, NTFS_ATTR_LIST, NULL, 0, &list);
	if (result != NTFS_OK) {
		return result;
	}
	if (list->flags != 0 || list->initialized != list->size) {
		result = NTFS_CORRUPT;
		goto finish;
	}
	if (list->size == 0 || list->size > v->limits.max_attribute_list) {
		result = NTFS_RANGE;
		goto finish;
	}
	size = (size_t)list->size;
	bytes = ntfs_alloc(v, size);
	if (bytes == NULL) {
		result = NTFS_NO_MEMORY;
		goto finish;
	}
	result = ntfs_stream_exact(list, 0, bytes, size);
finish:
	ntfs_stream_close(list);
	if (result != NTFS_OK) {
		ntfs_free(v, bytes, size);
		return result;
	}
	*out = bytes;
	*out_size = size;
	return NTFS_OK;
}

enum ntfs_result
ntfs_list_entry_at(
    const uint8_t *bytes, size_t size, size_t *offset, const struct ntfs_disk_attr_list **out)
{
	const struct ntfs_disk_attr_list *entry;
	size_t length;

	*out = NULL;
	if (*offset == size) {
		return NTFS_END;
	}
	if (!ntfs_bounds(*offset, sizeof(*entry), size)) {
		return NTFS_CORRUPT;
	}
	entry = (const void *)(bytes + *offset);
	length = ntfs_u16(entry->length);
	if (length < sizeof(*entry) || length % NTFS_WIRE_ALIGNMENT != 0 ||
	    !ntfs_bounds(*offset, length, size) ||
	    (entry->name_length != 0 &&
		(entry->name_offset < sizeof(*entry) ||
		    entry->name_offset % NTFS_UTF16_UNIT_BYTES != 0 ||
		    !ntfs_bounds(entry->name_offset,
			(size_t)entry->name_length * NTFS_UTF16_UNIT_BYTES, length))) ||
	    ntfs_u32(entry->type) == NTFS_ATTR_LIST) {
		return NTFS_CORRUPT;
	}
	*offset += length;
	*out = entry;
	return NTFS_OK;
}

enum ntfs_result
ntfs_attribute_type_present(struct ntfs_node *node, uint32_t type, bool *out)
{
	struct ntfs_volume *v = node->volume;
	const struct ntfs_disk_record *header = (const void *)node->record;
	const struct ntfs_disk_attr_list *entry;
	struct ntfs_attr_view attr;
	uint8_t *bytes = NULL;
	uint32_t position = ntfs_u16(header->attrs_offset);
	size_t size = 0, offset = 0;
	enum ntfs_result result;

	*out = false;
	result = ntfs_work(v, v->info.record_size);
	if (result != NTFS_OK) {
		return result;
	}
	while ((result = ntfs_attr_at(node->record, ntfs_u32(header->used), &position, &attr)) ==
	    NTFS_OK) {
		if (attr.type == type) {
			*out = true;
			return NTFS_OK;
		}
	}
	if (result != NTFS_END) {
		return result;
	}
	result = ntfs_attribute_list_read(node, &bytes, &size);
	if (result == NTFS_NOT_FOUND) {
		return NTFS_OK;
	}
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_work(v, size);
	if (result != NTFS_OK) {
		ntfs_free(v, bytes, size);
		return result;
	}
	while ((result = ntfs_list_entry_at(bytes, size, &offset, &entry)) == NTFS_OK) {
		if (ntfs_u32(entry->type) == type) {
			*out = true;
			break;
		}
	}
	ntfs_free(v, bytes, size);
	return result == NTFS_END ? NTFS_OK : result;
}

static enum ntfs_result
attribute_open(struct ntfs_node *node, uint32_t type, const uint16_t *name, size_t name_length,
    bool bootstrap, bool metadata_only, struct ntfs_stream **out)
{
	struct ntfs_volume *v = node->volume;
	struct ntfs_attr_view a, list_attr;
	struct ntfs_stream *stream = NULL;
	const struct ntfs_disk_attr_list *entry;
	const struct ntfs_disk_record *record_header;
	const struct ntfs_disk_nonresident *nonresident;
	uint8_t *bytes = NULL, *record = NULL;
	uint64_t reference, lowest;
	size_t list_size = 0, offset = 0, i;
	bool match;
	enum ntfs_result result;

	*out = NULL;
	if (name_length > NTFS_NAME_MAX || (name_length != 0 && name == NULL)) {
		return NTFS_INVALID;
	}
	/* The base performs at most the list-presence and requested-attribute scans. */
	result = ntfs_work(v, (uint64_t)v->info.record_size * 2);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_attr_find(
	    node->record, v->info.record_size, NTFS_ATTR_LIST, NULL, 0, UINT16_MAX, &list_attr);
	if (result == NTFS_NOT_FOUND || type == NTFS_ATTR_LIST) {
		result = ntfs_attr_find(
		    node->record, v->info.record_size, type, name, name_length, UINT16_MAX, &a);
		if (result == NTFS_OK) {
			result = metadata_only ? ntfs_stream_metadata_from_attr(v, &a, &stream)
					       : ntfs_stream_from_attr(v, &a, &stream);
		}
		if (result == NTFS_OK) {
			result = validate_stream(stream);
		}
		goto finish;
	}
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_attribute_list_read(node, &bytes, &list_size);
	if (result != NTFS_OK) {
		goto finish;
	}
	while ((result = ntfs_list_entry_at(bytes, list_size, &offset, &entry)) == NTFS_OK) {
		result = ntfs_work(v, ntfs_u16(entry->length));
		if (result != NTFS_OK) {
			goto finish;
		}
		if (ntfs_u32(entry->type) != type || entry->name_length != name_length) {
			continue;
		}
		match = true;
		for (i = 0; i < name_length; i++) {
			if (name[i] !=
			    ntfs_u16((const uint8_t *)entry + entry->name_offset +
				i * NTFS_UTF16_UNIT_BYTES)) {
				match = false;
				break;
			}
		}
		if (!match) {
			continue;
		}
		reference = ntfs_u64(entry->reference);
		lowest = ntfs_u64(entry->lowest);
		if (ntfs_u16(entry->instance) == UINT16_MAX ||
		    reference >> NTFS_REFERENCE_SEQUENCE_SHIFT == 0) {
			result = NTFS_CORRUPT;
			goto finish;
		}
		if (stream != NULL &&
		    (stream->resident || lowest != stream->clusters || lowest == 0)) {
			result = NTFS_CORRUPT;
			goto finish;
		}
		if (bootstrap && stream == NULL && reference != node->reference) {
			result = NTFS_CORRUPT;
			goto finish;
		}
		if (reference == node->reference) {
			record = node->record;
		} else {
			/* The next MFT extent record must be reachable through the
			 * prefix already decoded. Never guess its physical address
			 * or recurse through an unvalidated mapping. */
			if (bootstrap) {
				v->mft = stream;
			}
			result =
			    ntfs_record_read(v, reference & NTFS_REFERENCE_RECORD_MASK, &record);
			if (bootstrap) {
				v->mft = NULL;
			}
			if (result != NTFS_OK) {
				goto finish;
			}
			record_header = (const void *)record;
			if (ntfs_u16(record_header->sequence) !=
				reference >> NTFS_REFERENCE_SEQUENCE_SHIFT ||
			    ntfs_u64(record_header->base_reference) != node->reference) {
				result = NTFS_STALE;
				goto finish;
			}
		}
		result = ntfs_work(v, v->info.record_size);
		if (result == NTFS_OK) {
			result = ntfs_listed_attribute(
			    record, type, name, name_length, ntfs_u16(entry->instance), lowest, &a);
		}
		if (result == NTFS_NOT_FOUND) {
			result = NTFS_CORRUPT;
		}
		if (result != NTFS_OK) {
			goto finish;
		}
		if (a.disk->nonresident) {
			nonresident = (const void *)(a.bytes + sizeof(struct ntfs_disk_attr));
			if (ntfs_u64(nonresident->lowest) != lowest) {
				result = NTFS_CORRUPT;
				goto finish;
			}
		} else if (lowest != 0) {
			result = NTFS_CORRUPT;
			goto finish;
		}
		if (stream == NULL) {
			result = metadata_only ? ntfs_stream_metadata_from_attr(v, &a, &stream)
					       : ntfs_stream_from_attr(v, &a, &stream);
		} else {
			result = ntfs_stream_append(stream, &a);
		}
		if (result == NTFS_OK && bootstrap &&
		    (stream->resident || stream->flags != 0 || stream->run_count == 0 ||
			stream->runs[0].lcn != v->mft_lcn || stream->initialized != stream->size ||
			stream->size % v->info.record_size != 0)) {
			result = NTFS_CORRUPT;
		}
		if (record != node->record) {
			ntfs_free(v, record, v->info.record_size);
		}
		record = NULL;
		if (result != NTFS_OK) {
			goto finish;
		}
	}
	if (result == NTFS_END) {
		result = stream == NULL ? NTFS_NOT_FOUND : validate_stream(stream);
	}
finish:
	if (record != node->record) {
		ntfs_free(v, record, v->info.record_size);
	}
	ntfs_free(v, bytes, list_size);
	if (result != NTFS_OK) {
		ntfs_stream_close(stream);
		return result;
	}
	*out = stream;
	return NTFS_OK;
}

enum ntfs_result
ntfs_attribute_open(struct ntfs_node *node, uint32_t type, const uint16_t *name, size_t name_length,
    struct ntfs_stream **out)
{
	return attribute_open(node, type, name, name_length, false, false, out);
}

enum ntfs_result
ntfs_attribute_sizes(struct ntfs_node *node, uint64_t *size, uint64_t *allocated)
{
	struct ntfs_stream *description = NULL;
	enum ntfs_result result;

	result = attribute_open(node, NTFS_ATTRIBUTE_DATA, NULL, 0, false, true, &description);
	if (result == NTFS_OK) {
		*size = description->size;
		*allocated = description->physical_size;
	}
	ntfs_stream_close(description);
	return result;
}

enum ntfs_result
ntfs_attribute_metadata_open(struct ntfs_node *node, uint32_t type, const uint16_t *name,
    size_t name_length, struct ntfs_stream **out)
{
	return attribute_open(node, type, name, name_length, false, true, out);
}

enum ntfs_result
ntfs_mft_open(struct ntfs_volume *v, uint8_t *record, struct ntfs_stream **out)
{
	const struct ntfs_disk_record *header = (const void *)record;
	struct ntfs_node node = {0};
	enum ntfs_result result;

	*out = NULL;
	if (v->mft != NULL || ntfs_u64(header->base_reference) != 0 ||
	    (ntfs_u16(header->flags) & NTFS_RECORD_DIRECTORY) != 0) {
		return NTFS_CORRUPT;
	}
	node.volume = v;
	node.reference = (uint64_t)ntfs_u16(header->sequence) << NTFS_REFERENCE_SEQUENCE_SHIFT;
	node.record = record;
	result = attribute_open(&node, NTFS_ATTRIBUTE_DATA, NULL, 0, true, false, out);
	return result == NTFS_NOT_FOUND ? NTFS_CORRUPT : result;
}

enum ntfs_result
ntfs_stream_open_impl(
    struct ntfs_node *node, const uint16_t *name, size_t length, struct ntfs_stream **out)
{
	struct ntfs_stat st;
	size_t i;
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	*out = NULL;
	if (node == NULL || length > NTFS_NAME_MAX || (length != 0 && name == NULL)) {
		return NTFS_INVALID;
	}
	for (i = 0; i < length; i++) {
		if (name[i] == 0 || name[i] == '/' || name[i] == '\\' || name[i] == ':') {
			return NTFS_INVALID;
		}
	}
	if (node->volume->children == UINT32_MAX) {
		return NTFS_RANGE;
	}
	/* Stream compression/encryption state is independent. Opening one named
	 * stream must not decode or require support for the unnamed stream. */
	result = ntfs_node_metadata(node, &st);
	if (result != NTFS_OK) {
		return result;
	}
	if (st.reparse) {
		result = ntfs_wof_open(node, name, length, out);
	} else if (st.directory && length == 0) {
		return NTFS_IS_DIRECTORY;
	} else {
		result = ntfs_attribute_open(node, NTFS_ATTRIBUTE_DATA, name, length, out);
	}
	if (result == NTFS_OK) {
		(*out)->external = true;
		node->volume->children++;
	}
	return result;
}
