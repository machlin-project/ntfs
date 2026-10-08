/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"

enum attribute_description { ATTRIBUTE_READABLE, ATTRIBUTE_METADATA, ATTRIBUTE_BAD_CLUSTERS };

static enum ntfs_result
ntfs_attribute_describe(struct ntfs_node *node, const struct ntfs_attr_view *attribute_view,
    enum attribute_description description, struct ntfs_stream **out)
{
	switch (description) {
	case ATTRIBUTE_BAD_CLUSTERS:
		return ntfs_bad_clusters_from_attr(node, attribute_view, out);
	case ATTRIBUTE_METADATA:
		return ntfs_stream_metadata_from_attr(node->volume, attribute_view, out);
	case ATTRIBUTE_READABLE:
		return ntfs_stream_from_attr(node->volume, attribute_view, out);
	}
	return NTFS_INVALID;
}

static enum ntfs_result
ntfs_attribute_validate_stream(struct ntfs_stream *stream)
{
	uint64_t required, mapped = 0;
	uint32_t i, cluster = stream->volume->info.cluster_size;
	enum ntfs_result result;

	if (stream->resident) {
		return NTFS_OK;
	}
	required = stream->size / cluster + (stream->size % cluster != 0);
	if (stream->clusters < required || stream->clusters > (uint64_t)INT64_MAX / cluster) {
		return NTFS_CORRUPT;
	}
	result = ntfs_work(stream->volume, stream->run_count);
	if (result != NTFS_OK) {
		return result;
	}
	for (i = 0; i < stream->run_count; i++) {
		if (stream->runs[i].lcn != NTFS_HOLE) {
			mapped += stream->runs[i].length;
		}
	}
	if ((stream->flags & (NTFS_ATTR_COMPRESSION_MASK | NTFS_ATTR_SPARSE)) == 0 &&
	    mapped * cluster != stream->allocated) {
		return NTFS_CORRUPT;
	}
	if ((stream->flags & (NTFS_ATTR_COMPRESSION_MASK | NTFS_ATTR_SPARSE)) != 0 &&
	    mapped * cluster != stream->physical_size) {
		return NTFS_CORRUPT;
	}
	stream->physical_size = mapped * cluster;
	return NTFS_OK;
}

enum ntfs_result
ntfs_listed_attribute(const uint8_t *record, uint32_t type, const uint16_t *name,
    size_t name_length, uint16_t instance, uint64_t lowest, struct ntfs_attr_view *out)
{
	const struct ntfs_disk_record *header = (const void *)record;
	const struct ntfs_disk_nonresident *extent;
	struct ntfs_attr_view attribute_view;
	uint32_t position = ntfs_u16(header->attrs_offset);
	size_t i;
	bool match, found = false;
	enum ntfs_result result;

	while ((result = ntfs_attr_at(
		    record, ntfs_u32(header->used), &position, &attribute_view)) == NTFS_OK) {
		if (attribute_view.type != type ||
		    attribute_view.disk->name_length != name_length ||
		    (lowest == 0 && attribute_view.instance != instance)) {
			continue;
		}
		if (attribute_view.disk->nonresident) {
			extent =
			    (const void *)(attribute_view.bytes + sizeof(struct ntfs_disk_attr));
			if (ntfs_u64(extent->lowest) != lowest) {
				continue;
			}
		} else if (lowest != 0) {
			continue;
		}
		match = true;
		for (i = 0; i < name_length; i++) {
			if (name[i] !=
			    ntfs_u16(attribute_view.bytes +
				ntfs_u16(attribute_view.disk->name_offset) +
				i * NTFS_UTF16_UNIT_BYTES)) {
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
	return found ? NTFS_OK : NTFS_CORRUPT;
}

enum ntfs_result
ntfs_attribute_list_read(struct ntfs_node *node, uint8_t **out, size_t *out_size)
{
	struct ntfs_volume *volume = node->volume;
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
	if (list->size == 0 || list->size > volume->limits.max_attribute_list) {
		result = NTFS_RANGE;
		goto finish;
	}
	size = (size_t)list->size;
	bytes = ntfs_alloc(volume, size);
	if (bytes == NULL) {
		result = NTFS_NO_MEMORY;
		goto finish;
	}
	result = ntfs_stream_exact(list, 0, bytes, size);
finish:
	ntfs_stream_close(list);
	if (result != NTFS_OK) {
		ntfs_free(volume, bytes, size);
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
	struct ntfs_volume *volume = node->volume;
	const struct ntfs_disk_record *header = (const void *)node->record;
	const struct ntfs_disk_attr_list *entry;
	struct ntfs_attr_view attribute_view;
	uint8_t *bytes = NULL;
	uint32_t position = ntfs_u16(header->attrs_offset);
	size_t size = 0, offset = 0;
	enum ntfs_result result;

	*out = false;
	result = ntfs_work(volume, volume->info.record_size);
	if (result != NTFS_OK) {
		return result;
	}
	while ((result = ntfs_attr_at(
		    node->record, ntfs_u32(header->used), &position, &attribute_view)) == NTFS_OK) {
		if (attribute_view.type == type) {
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
	result = ntfs_work(volume, size);
	if (result != NTFS_OK) {
		ntfs_free(volume, bytes, size);
		return result;
	}
	while ((result = ntfs_list_entry_at(bytes, size, &offset, &entry)) == NTFS_OK) {
		if (ntfs_u32(entry->type) == type) {
			*out = true;
			break;
		}
	}
	ntfs_free(volume, bytes, size);
	return result == NTFS_END ? NTFS_OK : result;
}

static enum ntfs_result
ntfs_attribute_acquire(struct ntfs_node *node, uint32_t type, const uint16_t *name,
    size_t name_length, bool bootstrap, enum attribute_description description,
    struct ntfs_stream **out)
{
	struct ntfs_volume *volume = node->volume;
	struct ntfs_attr_view attribute_view, list_attr;
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
	result = ntfs_work(volume, (uint64_t)volume->info.record_size * 2);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_attr_find(node->record, volume->info.record_size, NTFS_ATTR_LIST, NULL, 0,
	    UINT16_MAX, &list_attr);
	if (result == NTFS_NOT_FOUND || type == NTFS_ATTR_LIST) {
		result = ntfs_attr_find(node->record, volume->info.record_size, type, name,
		    name_length, UINT16_MAX, &attribute_view);
		if (result == NTFS_OK) {
			result =
			    ntfs_attribute_describe(node, &attribute_view, description, &stream);
		}
		if (result == NTFS_OK) {
			result = description == ATTRIBUTE_BAD_CLUSTERS
			    ? ntfs_bad_clusters_validate(stream)
			    : ntfs_attribute_validate_stream(stream);
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
		result = ntfs_work(volume, ntfs_u16(entry->length));
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
				volume->mft = stream;
			}
			result = ntfs_record_read(
			    volume, reference & NTFS_REFERENCE_RECORD_MASK, &record);
			if (bootstrap) {
				volume->mft = NULL;
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
		result = ntfs_work(volume, volume->info.record_size);
		if (result == NTFS_OK) {
			result = ntfs_listed_attribute(record, type, name, name_length,
			    ntfs_u16(entry->instance), lowest, &attribute_view);
		}
		if (result == NTFS_NOT_FOUND) {
			result = NTFS_CORRUPT;
		}
		if (result != NTFS_OK) {
			goto finish;
		}
		if (attribute_view.disk->nonresident) {
			nonresident =
			    (const void *)(attribute_view.bytes + sizeof(struct ntfs_disk_attr));
			if (ntfs_u64(nonresident->lowest) != lowest) {
				result = NTFS_CORRUPT;
				goto finish;
			}
		} else if (lowest != 0) {
			result = NTFS_CORRUPT;
			goto finish;
		}
		if (stream == NULL) {
			result =
			    ntfs_attribute_describe(node, &attribute_view, description, &stream);
		} else {
			result = description == ATTRIBUTE_BAD_CLUSTERS
			    ? ntfs_bad_clusters_append(stream, &attribute_view)
			    : ntfs_stream_append(stream, &attribute_view);
		}
		if (result == NTFS_OK && bootstrap &&
		    (stream->resident || stream->flags != 0 || stream->run_count == 0 ||
			stream->runs[0].lcn != volume->mft_lcn ||
			stream->initialized != stream->size ||
			stream->size % volume->info.record_size != 0)) {
			result = NTFS_CORRUPT;
		}
		if (record != node->record) {
			ntfs_free(volume, record, volume->info.record_size);
		}
		record = NULL;
		if (result != NTFS_OK) {
			goto finish;
		}
	}
	if (result == NTFS_END) {
		result = stream == NULL ? NTFS_NOT_FOUND
					: (description == ATTRIBUTE_BAD_CLUSTERS
						  ? ntfs_bad_clusters_validate(stream)
						  : ntfs_attribute_validate_stream(stream));
	}
finish:
	if (record != node->record) {
		ntfs_free(volume, record, volume->info.record_size);
	}
	ntfs_free(volume, bytes, list_size);
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
	return ntfs_attribute_acquire(
	    node, type, name, name_length, false, ATTRIBUTE_READABLE, out);
}

static bool
ntfs_attribute_bad_clusters_key(
    const struct ntfs_node *node, uint32_t type, const uint16_t *name, size_t name_length)
{
	static const uint16_t bad_name[] = {'$', 'B', 'a', 'd'};
	size_t i;

	if ((node->reference & NTFS_REFERENCE_RECORD_MASK) != NTFS_BAD_CLUSTERS_RECORD ||
	    type != NTFS_ATTRIBUTE_DATA || name_length != sizeof(bad_name) / sizeof(bad_name[0])) {
		return false;
	}
	for (i = 0; i < name_length; i++) {
		if (name[i] != bad_name[i]) {
			return false;
		}
	}
	return true;
}

enum ntfs_result
ntfs_bad_clusters_open(struct ntfs_node *node, uint32_t type, const uint16_t *name,
    size_t name_length, struct ntfs_stream **out)
{
	enum ntfs_result result;

	*out = NULL;
	if (!ntfs_attribute_bad_clusters_key(node, type, name, name_length)) {
		return NTFS_NOT_FOUND;
	}
	result = ntfs_operation_enter(node->volume);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_attribute_acquire(
	    node, type, name, name_length, false, ATTRIBUTE_BAD_CLUSTERS, out);
	ntfs_operation_leave(node->volume);
	/* A selected malformed descriptor must not fall back to ordinary content. */
	return result == NTFS_NOT_FOUND ? NTFS_CORRUPT : result;
}

enum ntfs_result
ntfs_attribute_sizes(struct ntfs_node *node, uint64_t *size, uint64_t *allocated)
{
	struct ntfs_stream *description = NULL;
	enum ntfs_result result;

	result = ntfs_attribute_acquire(
	    node, NTFS_ATTRIBUTE_DATA, NULL, 0, false, ATTRIBUTE_METADATA, &description);
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
	return ntfs_attribute_acquire(
	    node, type, name, name_length, false, ATTRIBUTE_METADATA, out);
}

enum ntfs_result
ntfs_mft_open(struct ntfs_volume *volume, uint8_t *record, struct ntfs_stream **out)
{
	const struct ntfs_disk_record *header = (const void *)record;
	struct ntfs_node node = {0};
	enum ntfs_result result;

	*out = NULL;
	if (volume->mft != NULL || ntfs_u64(header->base_reference) != 0 ||
	    (ntfs_u16(header->flags) & NTFS_RECORD_DIRECTORY) != 0) {
		return NTFS_CORRUPT;
	}
	node.volume = volume;
	node.reference = (uint64_t)ntfs_u16(header->sequence) << NTFS_REFERENCE_SEQUENCE_SHIFT;
	node.record = record;
	result = ntfs_attribute_acquire(
	    &node, NTFS_ATTRIBUTE_DATA, NULL, 0, true, ATTRIBUTE_READABLE, out);
	return result == NTFS_NOT_FOUND ? NTFS_CORRUPT : result;
}

enum ntfs_result
ntfs_stream_open_impl(
    struct ntfs_node *node, const uint16_t *name, size_t length, struct ntfs_stream **out)
{
	struct ntfs_stat stat;
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
	result = ntfs_node_metadata(node, &stat);
	if (result != NTFS_OK) {
		return result;
	}
	if (ntfs_attribute_bad_clusters_key(node, NTFS_ATTRIBUTE_DATA, name, length)) {
		return NTFS_UNSUPPORTED;
	}
	if (stat.reparse) {
		result = ntfs_wof_open(node, name, length, out);
	} else if (stat.directory && length == 0) {
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
