/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_mutation_internal.h"

static enum ntfs_result
mutation_attribute_position(struct ntfs_mutation_record *record, uint32_t type,
    const uint16_t *name, size_t count, struct ntfs_attr_view *out, uint16_t *instance)
{
	struct ntfs_disk_record *header = (void *)record->bytes;
	struct ntfs_attr_view attribute;
	uint32_t position, start;
	size_t index, common;
	int order;
	enum ntfs_result result;

	result = ntfs_attr_find(
	    record->bytes, sizeof(record->bytes), type, name, count, UINT16_MAX, out);
	if (result == NTFS_OK) {
		*instance = out->instance;
		return NTFS_OK;
	}
	if (result != NTFS_NOT_FOUND) {
		return result;
	}
	position = ntfs_u16(header->attrs_offset);
	for (;;) {
		start = position;
		result = ntfs_attr_at(record->bytes, ntfs_u32(header->used), &position, &attribute);
		if (result == NTFS_END) {
			break;
		}
		if (result != NTFS_OK) {
			return result;
		}
		order = attribute.type < type ? -1 : attribute.type > type ? 1 : 0;
		if (order == 0) {
			common = count < attribute.disk->name_length ? count
								     : attribute.disk->name_length;
			for (index = 0; index < common; index++) {
				uint16_t unit;

				unit = ntfs_u16(attribute.bytes +
				    ntfs_u16(attribute.disk->name_offset) +
				    index * NTFS_UTF16_UNIT_BYTES);
				if (unit != name[index]) {
					order = unit < name[index] ? -1 : 1;
					break;
				}
			}
			if (order == 0) {
				order = attribute.disk->name_length < count ? -1 : 1;
			}
		}
		if (order > 0) {
			break;
		}
	}
	ntfs_zero(out, sizeof(*out));
	out->bytes = record->bytes + start;
	*instance = ntfs_u16(header->next_instance);
	if (*instance == UINT16_MAX) {
		return NTFS_RANGE;
	}
	return NTFS_OK;
}

static void
mutation_attribute_header(uint8_t *buffer, uint32_t type, const uint16_t *name, size_t count,
    size_t name_offset, size_t bytes, uint16_t instance, bool nonresident)
{
	struct ntfs_disk_attr *header = (void *)buffer;
	size_t index;

	ntfs_put_u32(header->type, type);
	ntfs_put_u32(header->length, (uint32_t)bytes);
	header->nonresident = nonresident;
	header->name_length = (uint8_t)count;
	ntfs_put_u16(header->name_offset, count == 0 ? 0 : (uint16_t)name_offset);
	ntfs_put_u16(header->instance, instance);
	for (index = 0; index < count; index++) {
		ntfs_put_u16(buffer + name_offset + index * NTFS_UTF16_UNIT_BYTES, name[index]);
	}
}

enum ntfs_result
ntfs_mutation_resident(struct ntfs_write_mutation_plan *plan, struct ntfs_mutation_record *record,
    uint32_t type, const uint16_t *name, size_t count, const void *value, size_t bytes,
    uint16_t flags)
{
	struct ntfs_attr_view old;
	struct ntfs_disk_resident *resident;
	struct ntfs_disk_record *header = (void *)record->bytes;
	uint8_t *buffer;
	size_t name_offset, offset, length;
	uint16_t instance;
	enum ntfs_result result;

	name_offset = sizeof(struct ntfs_disk_attr) + sizeof(*resident);
	offset = ntfs_mutation_align_bytes(name_offset + count * NTFS_UTF16_UNIT_BYTES);
	if (count > NTFS_NAME_MAX || bytes > NTFS_WRITE_RECORD_BYTES ||
	    offset > NTFS_WRITE_RECORD_BYTES - bytes || flags != 0) {
		return NTFS_NO_SPACE;
	}
	length = ntfs_mutation_align_bytes(offset + bytes);
	result = mutation_attribute_position(record, type, name, count, &old, &instance);
	if (result != NTFS_OK) {
		return result;
	}
	buffer = ntfs_mutation_allocate(plan, length);
	if (buffer == NULL) {
		return NTFS_NO_MEMORY;
	}
	mutation_attribute_header(buffer, type, name, count, name_offset, length, instance, false);
	resident = (void *)(buffer + sizeof(struct ntfs_disk_attr));
	ntfs_put_u32(resident->length, (uint32_t)bytes);
	ntfs_put_u16(resident->offset, (uint16_t)offset);
	resident->indexed = type == NTFS_ATTR_FILENAME;
	ntfs_copy(buffer + offset, value, bytes);
	result = ntfs_mutation_record_replace(plan, record, &old, buffer, length);
	if (result == NTFS_OK && old.length == 0) {
		ntfs_put_u16(header->next_instance, (uint16_t)(instance + 1u));
	}
	ntfs_mutation_release(plan, buffer, length);
	return result;
}

static unsigned
mutation_run_unsigned_width(uint64_t value)
{
	unsigned width = 1;

	while (width < sizeof(value) && value >> (width * NTFS_BITS_PER_BYTE) != 0) {
		width++;
	}
	return width;
}

static unsigned
mutation_run_signed_width(uint64_t value)
{
	unsigned width;
	uint64_t high;
	bool negative = (value >> (sizeof(value) * NTFS_BITS_PER_BYTE - 1u)) != 0;

	for (width = 1; width < sizeof(value); width++) {
		high = value >> (width * NTFS_BITS_PER_BYTE - 1u);
		if ((!negative && high == 0) ||
		    (negative && high == UINT64_MAX >> (width * NTFS_BITS_PER_BYTE - 1u))) {
			return width;
		}
	}
	return sizeof(value);
}

enum ntfs_result
ntfs_mutation_nonresident(struct ntfs_write_mutation_plan *plan,
    struct ntfs_mutation_record *record, uint32_t type, const uint16_t *name, size_t count,
    const struct ntfs_run *runs, size_t run_count, uint64_t size, uint64_t initialized,
    uint16_t flags)
{
	struct ntfs_attr_view old;
	struct ntfs_disk_nonresident *nonresident;
	struct ntfs_disk_record *header = (void *)record->bytes;
	uint8_t *buffer;
	uint64_t previous = 0, delta, clusters = 0;
	size_t name_offset, offset, position, index, byte, length;
	unsigned count_width, offset_width;
	uint16_t instance;
	enum ntfs_result result;

	if (count > NTFS_NAME_MAX || run_count > NTFS_MUTATION_MAX_RUNS || initialized > size ||
	    size > INT64_MAX || flags != 0) {
		return NTFS_RANGE;
	}
	result = mutation_attribute_position(record, type, name, count, &old, &instance);
	if (result != NTFS_OK) {
		return result;
	}
	buffer = ntfs_mutation_allocate(plan, NTFS_WRITE_RECORD_BYTES);
	if (buffer == NULL) {
		return NTFS_NO_MEMORY;
	}
	name_offset = sizeof(struct ntfs_disk_attr) + sizeof(*nonresident);
	offset = ntfs_mutation_align_bytes(name_offset + count * NTFS_UTF16_UNIT_BYTES);
	position = offset;
	result = NTFS_OK;
	for (index = 0; index < run_count; index++) {
		if (runs[index].vcn != clusters || runs[index].length == 0 ||
		    runs[index].lcn == NTFS_HOLE ||
		    runs[index].length > plan->info.cluster_count - clusters ||
		    !ntfs_bounds(runs[index].lcn, runs[index].length, plan->info.cluster_count)) {
			result = NTFS_CORRUPT;
			break;
		}
		delta = runs[index].lcn >= previous ? runs[index].lcn - previous
						    : UINT64_C(0) - (previous - runs[index].lcn);
		count_width = mutation_run_unsigned_width(runs[index].length);
		offset_width = mutation_run_signed_width(delta);
		if (position + 1u + count_width + offset_width >= NTFS_WRITE_RECORD_BYTES) {
			result = NTFS_RANGE;
			break;
		}
		buffer[position++] =
		    (uint8_t)(count_width | offset_width << NTFS_RUN_OFFSET_WIDTH_SHIFT);
		for (byte = 0; byte < count_width; byte++) {
			buffer[position++] =
			    (uint8_t)(runs[index].length >> (byte * NTFS_BITS_PER_BYTE));
		}
		for (byte = 0; byte < offset_width; byte++) {
			buffer[position++] = (uint8_t)(delta >> (byte * NTFS_BITS_PER_BYTE));
		}
		clusters += runs[index].length;
		previous = runs[index].lcn;
	}
	length = ntfs_mutation_align_bytes(position + 1u);
	if (result == NTFS_OK &&
	    (clusters > (uint64_t)INT64_MAX / NTFS_WRITE_CLUSTER_BYTES ||
		size > clusters * NTFS_WRITE_CLUSTER_BYTES)) {
		result = NTFS_CORRUPT;
	}
	if (result == NTFS_OK) {
		mutation_attribute_header(
		    buffer, type, name, count, name_offset, length, instance, true);
		nonresident = (void *)(buffer + sizeof(struct ntfs_disk_attr));
		ntfs_put_u64(nonresident->highest, clusters == 0 ? UINT64_MAX : clusters - 1u);
		ntfs_put_u16(nonresident->mapping_offset, (uint16_t)offset);
		ntfs_put_u64(nonresident->allocated, clusters * NTFS_WRITE_CLUSTER_BYTES);
		ntfs_put_u64(nonresident->size, size);
		ntfs_put_u64(nonresident->initialized, initialized);
		result = ntfs_mutation_record_replace(plan, record, &old, buffer, length);
		if (result == NTFS_OK && old.length == 0) {
			ntfs_put_u16(header->next_instance, (uint16_t)(instance + 1u));
		}
	}
	ntfs_mutation_release(plan, buffer, NTFS_WRITE_RECORD_BYTES);
	return result;
}

enum ntfs_result
ntfs_mutation_attribute_remove(struct ntfs_write_mutation_plan *plan,
    struct ntfs_mutation_record *record, uint32_t type, const uint16_t *name, size_t count)
{
	struct ntfs_attr_view attribute;
	enum ntfs_result result;

	result = ntfs_attr_find(
	    record->bytes, sizeof(record->bytes), type, name, count, UINT16_MAX, &attribute);
	if (result == NTFS_NOT_FOUND) {
		return NTFS_OK;
	}
	return result == NTFS_OK ? ntfs_mutation_record_replace(plan, record, &attribute, NULL, 0)
				 : result;
}
