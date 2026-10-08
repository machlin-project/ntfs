/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_mutation_internal.h"

enum ntfs_result
ntfs_mutation_stream(struct ntfs_write_mutation_plan *plan, struct ntfs_mutation_record *record,
    uint32_t type, const uint16_t *name, size_t count, struct ntfs_stream **out)
{
	struct ntfs_attr_view attribute;
	struct ntfs_mutation_stream_entry *entry;
	size_t index;
	enum ntfs_result result;

	*out = NULL;
	if (count > NTFS_WRITE_MUTATION_TARGET_NAME_UNITS || (count != 0 && name == NULL)) {
		return NTFS_INVALID;
	}
	for (index = 0; index < NTFS_MUTATION_STREAM_CACHE_ENTRIES; index++) {
		entry = &plan->streams[index];
		if (entry->stream != NULL && entry->record == record &&
		    entry->revision == record->revision && entry->type == type &&
		    entry->name_count == count &&
		    ntfs_equal(entry->name, name, count * sizeof(*name))) {
			entry->stream->shared_references++;
			*out = entry->stream;
			return NTFS_OK;
		}
	}
	result = ntfs_attr_find(
	    record->bytes, sizeof(record->bytes), type, name, count, UINT16_MAX, &attribute);
	if (result == NTFS_OK) {
		result = ntfs_stream_from_attr(plan->volume, &attribute, out);
	}
	if (result == NTFS_OK && ((*out)->flags != 0 || (*out)->compression_unit != 0)) {
		ntfs_stream_close(*out);
		*out = NULL;
		result = NTFS_UNSUPPORTED;
	}
	if (result == NTFS_OK) {
		entry = &plan->streams[plan->stream_cursor];
		ntfs_stream_close(entry->stream);
		*entry = (struct ntfs_mutation_stream_entry){.record = record,
		    .stream = *out,
		    .revision = record->revision,
		    .type = type,
		    .name_count = count};
		ntfs_copy(entry->name, name, count * sizeof(*name));
		(*out)->shared_references++;
		plan->stream_cursor =
		    (plan->stream_cursor + 1) % NTFS_MUTATION_STREAM_CACHE_ENTRIES;
	}
	return result;
}

enum ntfs_result
ntfs_mutation_stream_read(struct ntfs_write_mutation_plan *plan, const struct ntfs_stream *stream,
    uint64_t offset, void *buffer, size_t bytes)
{
	const struct ntfs_run *run;
	uint64_t vcn, physical, available;
	size_t take;
	enum ntfs_result result;

	if (!ntfs_bounds(offset, bytes, stream->size)) {
		return NTFS_RANGE;
	}
	if (bytes == 0) {
		return NTFS_OK;
	}
	if (stream->resident) {
		ntfs_copy(buffer, stream->value + offset, bytes);
		return NTFS_OK;
	}
	while (bytes != 0) {
		if (offset >= stream->initialized) {
			ntfs_zero(buffer, bytes);
			return NTFS_OK;
		}
		vcn = offset / NTFS_WRITE_CLUSTER_BYTES;
		run = ntfs_run_find(stream, vcn);
		if (run == NULL || run->lcn == NTFS_HOLE) {
			return NTFS_CORRUPT;
		}
		physical = (run->lcn + vcn - run->vcn) * NTFS_WRITE_CLUSTER_BYTES +
		    offset % NTFS_WRITE_CLUSTER_BYTES;
		available = (run->length - (vcn - run->vcn)) * NTFS_WRITE_CLUSTER_BYTES -
		    offset % NTFS_WRITE_CLUSTER_BYTES;
		if (available > stream->initialized - offset) {
			available = stream->initialized - offset;
		}
		take = available < bytes ? (size_t)available : bytes;
		result = ntfs_mutation_read(plan, physical, buffer, take);
		if (result != NTFS_OK) {
			return result;
		}
		bytes -= take;
		offset += take;
		buffer = (uint8_t *)buffer + take;
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_mutation_stream_write(struct ntfs_write_mutation_plan *plan,
    const struct ntfs_mutation_record *record, uint32_t type, const uint16_t *name, size_t count,
    const struct ntfs_stream *stream, uint64_t offset, const void *buffer, size_t bytes,
    enum ntfs_write_mutation_region_kind kind)
{
	const struct ntfs_run *run;
	struct ntfs_write_mutation_target target = {0};
	uint64_t vcn, physical, available;
	size_t take;
	enum ntfs_result result;

	if (record == NULL || count > NTFS_WRITE_MUTATION_TARGET_NAME_UNITS ||
	    (name == NULL && count != 0) || stream->resident ||
	    !ntfs_bounds(offset, bytes, stream->allocated)) {
		return NTFS_RANGE;
	}
	target.reference = record->reference;
	target.attribute_type = type;
	target.name_count = count;
	ntfs_copy(target.name, name, count * NTFS_UTF16_UNIT_BYTES);
	while (bytes != 0) {
		vcn = offset / NTFS_WRITE_CLUSTER_BYTES;
		run = ntfs_run_find(stream, vcn);
		if (run == NULL || run->lcn == NTFS_HOLE) {
			return NTFS_CORRUPT;
		}
		physical = (run->lcn + vcn - run->vcn) * NTFS_WRITE_CLUSTER_BYTES +
		    offset % NTFS_WRITE_CLUSTER_BYTES;
		available = (run->length - (vcn - run->vcn)) * NTFS_WRITE_CLUSTER_BYTES -
		    offset % NTFS_WRITE_CLUSTER_BYTES;
		take = available < bytes ? (size_t)available : bytes;
		target.logical_offset = offset;
		result = ntfs_mutation_write(plan, physical, buffer, take, kind, &target);
		if (result != NTFS_OK) {
			return result;
		}
		bytes -= take;
		offset += take;
		buffer = (const uint8_t *)buffer + take;
	}
	return NTFS_OK;
}
