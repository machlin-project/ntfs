/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_mutation_internal.h"

enum ntfs_result
ntfs_mutation_stream(struct ntfs_write_mutation_plan *plan, struct ntfs_mutation_record *record,
    uint32_t type, const uint16_t *name, size_t count, struct ntfs_stream **out)
{
	struct ntfs_attr_view attribute;
	enum ntfs_result result;

	*out = NULL;
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
