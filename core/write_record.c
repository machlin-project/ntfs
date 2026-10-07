/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_mutation_internal.h"

static size_t
aligned(size_t bytes)
{
	return (bytes + NTFS_WIRE_ALIGNMENT - 1u) & ~(size_t)(NTFS_WIRE_ALIGNMENT - 1u);
}

static enum ntfs_result
record_physical(struct ntfs_write_mutation_plan *plan, uint64_t number, uint64_t *out)
{
	const struct ntfs_run *run;
	uint64_t offset, vcn, lcn;

	if (number > (uint64_t)INT64_MAX / NTFS_WRITE_RECORD_BYTES) {
		return NTFS_RANGE;
	}
	offset = number * NTFS_WRITE_RECORD_BYTES;
	if (!ntfs_bounds(offset, NTFS_WRITE_RECORD_BYTES, plan->mft->initialized)) {
		return NTFS_NOT_FOUND;
	}
	vcn = offset / NTFS_WRITE_CLUSTER_BYTES;
	run = ntfs_run_find(plan->mft, vcn);
	if (run == NULL || run->lcn == NTFS_HOLE) {
		return NTFS_CORRUPT;
	}
	lcn = run->lcn + vcn - run->vcn;
	if (lcn >= plan->info.cluster_count) {
		return NTFS_CORRUPT;
	}
	*out = lcn * NTFS_WRITE_CLUSTER_BYTES + offset % NTFS_WRITE_CLUSTER_BYTES;
	return NTFS_OK;
}

static void
empty_record(struct ntfs_mutation_record *record, uint16_t sequence)
{
	struct ntfs_disk_record *header = (void *)record->bytes;
	struct ntfs_disk_record_extension *extension;
	size_t usa, attributes;

	ntfs_zero(record->bytes, sizeof(record->bytes));
	ntfs_copy(header->mst.magic, "FILE", sizeof(header->mst.magic));
	usa = sizeof(*header) + sizeof(*extension);
	attributes =
	    aligned(usa + (NTFS_WRITE_RECORD_BYTES / NTFS_MST_STRIDE + 1) * NTFS_MST_WORD_BYTES);
	ntfs_put_u16(header->mst.usa_offset, (uint16_t)usa);
	ntfs_put_u16(header->mst.usa_count, NTFS_WRITE_RECORD_BYTES / NTFS_MST_STRIDE + 1);
	ntfs_put_u16(header->sequence, sequence);
	ntfs_put_u16(header->attrs_offset, (uint16_t)attributes);
	ntfs_put_u32(header->allocated, NTFS_WRITE_RECORD_BYTES);
	ntfs_put_u32(header->used, (uint32_t)(attributes + NTFS_WIRE_ALIGNMENT));
	ntfs_put_u32(record->bytes + attributes, NTFS_ATTR_END);
	extension = (void *)(record->bytes + sizeof(*header));
	ntfs_put_u32(extension->record_number, (uint32_t)record->number);
	ntfs_put_u16(record->bytes + usa, 1);
}

enum ntfs_result
ntfs_mutation_record_get(struct ntfs_write_mutation_plan *plan, uint64_t reference,
    bool number_only, struct ntfs_mutation_record **out)
{
	struct ntfs_mutation_record *record, **records;
	struct ntfs_disk_record *header;
	uint64_t number = number_only ? reference : reference & NTFS_REFERENCE_RECORD_MASK;
	size_t index, capacity;
	enum ntfs_result result;
	bool free_slot;

	*out = NULL;
	for (index = 0; index < plan->record_count; index++) {
		record = plan->records[index];
		if (record->number == number) {
			goto checked;
		}
	}
	if (number > UINT32_MAX || plan->record_count == NTFS_MUTATION_MAX_RECORDS) {
		return NTFS_RANGE;
	}
	if (plan->record_count == plan->record_capacity) {
		capacity = plan->record_capacity == 0 ? NTFS_MUTATION_INITIAL_RECORDS
						      : plan->record_capacity * NTFS_VECTOR_GROWTH;
		records = ntfs_mutation_allocate(plan, capacity * sizeof(*records));
		if (records == NULL) {
			return NTFS_NO_MEMORY;
		}
		ntfs_copy(records, plan->records, plan->record_count * sizeof(*records));
		ntfs_mutation_release(
		    plan, plan->records, plan->record_capacity * sizeof(*records));
		plan->records = records;
		plan->record_capacity = capacity;
	}
	record = ntfs_mutation_allocate(plan, sizeof(*record));
	if (record == NULL) {
		return NTFS_NO_MEMORY;
	}
	record->number = number;
	result = record_physical(plan, number, &record->physical);
	if (result == NTFS_OK) {
		result = ntfs_mutation_read(
		    plan, record->physical, record->bytes, sizeof(record->bytes));
	}
	if (result != NTFS_OK) {
		ntfs_mutation_release(plan, record, sizeof(*record));
		return result;
	}
	free_slot = number >= NTFS_FIRST_USER_RECORD && plan->mft_bitmap.after != NULL &&
	    !ntfs_mutation_bit(plan->mft_bitmap.after, plan->mft_bitmap.bytes, number);
	header = (void *)record->bytes;
	if (number * NTFS_WRITE_RECORD_BYTES >= plan->volume->mft->initialized) {
		empty_record(record, 1);
		record->changed = true;
	} else if (free_slot) {
		if (!ntfs_equal(header->mst.magic, "FILE", sizeof(header->mst.magic))) {
			empty_record(record, 1);
		} else {
			result = ntfs_record_decode(record->bytes, sizeof(record->bytes), false);
			if (result != NTFS_OK ||
			    (ntfs_u16(header->flags) & NTFS_RECORD_IN_USE) != 0) {
				ntfs_mutation_release(plan, record, sizeof(*record));
				return result == NTFS_OK ? NTFS_CORRUPT : result;
			}
		}
	} else {
		result = ntfs_record_validate(record->bytes, sizeof(record->bytes));
		if (result != NTFS_OK) {
			ntfs_mutation_release(plan, record, sizeof(*record));
			return result;
		}
	}
	record->reference =
	    number | (uint64_t)ntfs_u16(header->sequence) << NTFS_REFERENCE_SEQUENCE_SHIFT;
	plan->records[plan->record_count++] = record;

checked:
	header = (void *)record->bytes;
	if (!number_only && (ntfs_u16(header->flags) & NTFS_RECORD_IN_USE) == 0) {
		return NTFS_NOT_FOUND;
	}
	if (!number_only && record->reference != reference) {
		return NTFS_STALE;
	}
	*out = record;
	return NTFS_OK;
}

enum ntfs_result
ntfs_mutation_record_admit(struct ntfs_mutation_record *record, bool directory, bool parent)
{
	const struct ntfs_disk_record *header = (const void *)record->bytes;
	const struct ntfs_disk_standard *standard;
	struct ntfs_attr_view attribute;
	const uint8_t *value;
	size_t bytes;
	uint16_t flags;
	uint32_t attributes;
	enum ntfs_result result;

	flags = ntfs_u16(header->flags);
	if (((flags & NTFS_RECORD_DIRECTORY) != 0) != directory) {
		return directory ? NTFS_NOT_DIRECTORY : NTFS_IS_DIRECTORY;
	}
	if ((record->number < NTFS_FIRST_USER_RECORD &&
		!(parent && record->number == NTFS_ROOT_RECORD)) ||
	    flags != (NTFS_RECORD_IN_USE | (directory ? NTFS_RECORD_DIRECTORY : 0)) ||
	    ntfs_u64(header->base_reference) != 0 ||
	    ntfs_u16(header->mst.usa_offset) !=
		sizeof(*header) + sizeof(struct ntfs_disk_record_extension)) {
		return NTFS_UNSUPPORTED;
	}
	result = ntfs_attr_find(
	    record->bytes, sizeof(record->bytes), NTFS_ATTR_LIST, NULL, 0, UINT16_MAX, &attribute);
	if (result != NTFS_NOT_FOUND) {
		return result == NTFS_OK ? NTFS_UNSUPPORTED : result;
	}
	result = ntfs_attr_find(record->bytes, sizeof(record->bytes), NTFS_ATTRIBUTE_REPARSE_POINT,
	    NULL, 0, UINT16_MAX, &attribute);
	if (result != NTFS_NOT_FOUND) {
		return result == NTFS_OK ? NTFS_CORRUPT : result;
	}
	result = ntfs_attr_find(record->bytes, sizeof(record->bytes), NTFS_ATTR_STANDARD, NULL, 0,
	    UINT16_MAX, &attribute);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_attr_value(&attribute, &value, &bytes);
	if (result != NTFS_OK) {
		return result;
	}
	if (attribute.flags != 0 || bytes != NTFS_WRITE_STANDARD_BYTES) {
		return NTFS_UNSUPPORTED;
	}
	standard = (const void *)value;
	attributes = ntfs_u32(standard->attributes);
	if ((attributes &
		(NTFS_FILE_READ_ONLY | NTFS_FILE_REPARSE | NTFS_FILE_COMPRESSED |
		    NTFS_FILE_ENCRYPTED | NTFS_FILE_SPARSE)) != 0 ||
	    ((attributes & NTFS_FILE_SYSTEM) != 0 && record->number != NTFS_ROOT_RECORD)) {
		return NTFS_UNSUPPORTED;
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_mutation_record_replace(struct ntfs_write_mutation_plan *plan,
    struct ntfs_mutation_record *record, const struct ntfs_attr_view *old, const void *value,
    size_t bytes)
{
	struct ntfs_disk_record *header = (void *)record->bytes;
	size_t offset, previous, used, tail, index, next_used;

	used = ntfs_u32(header->used);
	offset = (size_t)(old->bytes - record->bytes);
	previous = old->length;
	if (bytes > NTFS_WRITE_RECORD_BYTES || bytes % NTFS_WIRE_ALIGNMENT != 0 ||
	    offset < ntfs_u16(header->attrs_offset) || !ntfs_bounds(offset, previous, used) ||
	    used > NTFS_WRITE_RECORD_BYTES || bytes > NTFS_WRITE_RECORD_BYTES - (used - previous)) {
		return NTFS_NO_SPACE;
	}
	if (previous == bytes && ntfs_equal(old->bytes, value, bytes)) {
		return NTFS_OK;
	}
	ntfs_copy(plan->scratch, value, bytes);
	tail = used - offset - previous;
	next_used = used - previous + bytes;
	if (bytes > previous) {
		for (index = tail; index != 0; index--) {
			record->bytes[offset + bytes + index - 1] =
			    record->bytes[offset + previous + index - 1];
		}
	} else {
		for (index = 0; index < tail; index++) {
			record->bytes[offset + bytes + index] =
			    record->bytes[offset + previous + index];
		}
		ntfs_zero(record->bytes + next_used, used - next_used);
	}
	ntfs_copy(record->bytes + offset, plan->scratch, bytes);
	ntfs_put_u32(header->used, (uint32_t)next_used);
	record->changed = true;
	return NTFS_OK;
}

static enum ntfs_result
attribute_position(struct ntfs_mutation_record *record, uint32_t type, const uint16_t *name,
    size_t count, struct ntfs_attr_view *out, uint16_t *instance)
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
attribute_header(uint8_t *buffer, uint32_t type, const uint16_t *name, size_t count,
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
	offset = aligned(name_offset + count * NTFS_UTF16_UNIT_BYTES);
	if (count > NTFS_NAME_MAX || bytes > NTFS_WRITE_RECORD_BYTES ||
	    offset > NTFS_WRITE_RECORD_BYTES - bytes || flags != 0) {
		return NTFS_NO_SPACE;
	}
	length = aligned(offset + bytes);
	result = attribute_position(record, type, name, count, &old, &instance);
	if (result != NTFS_OK) {
		return result;
	}
	buffer = ntfs_mutation_allocate(plan, length);
	if (buffer == NULL) {
		return NTFS_NO_MEMORY;
	}
	attribute_header(buffer, type, name, count, name_offset, length, instance, false);
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
unsigned_width(uint64_t value)
{
	unsigned width = 1;

	while (width < sizeof(value) && value >> (width * NTFS_BITS_PER_BYTE) != 0) {
		width++;
	}
	return width;
}

static unsigned
signed_width(uint64_t value)
{
	unsigned width;
	uint64_t high;
	bool negative = (value >> (NTFS_LFS_LSN_BITS - 1u)) != 0;

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
	result = attribute_position(record, type, name, count, &old, &instance);
	if (result != NTFS_OK) {
		return result;
	}
	buffer = ntfs_mutation_allocate(plan, NTFS_WRITE_RECORD_BYTES);
	if (buffer == NULL) {
		return NTFS_NO_MEMORY;
	}
	name_offset = sizeof(struct ntfs_disk_attr) + sizeof(*nonresident);
	offset = aligned(name_offset + count * NTFS_UTF16_UNIT_BYTES);
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
		count_width = unsigned_width(runs[index].length);
		offset_width = signed_width(delta);
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
	length = aligned(position + 1u);
	if (result == NTFS_OK &&
	    (clusters > (uint64_t)INT64_MAX / NTFS_WRITE_CLUSTER_BYTES ||
		size > clusters * NTFS_WRITE_CLUSTER_BYTES)) {
		result = NTFS_CORRUPT;
	}
	if (result == NTFS_OK) {
		attribute_header(buffer, type, name, count, name_offset, length, instance, true);
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

enum ntfs_result
ntfs_mutation_touch(struct ntfs_mutation_record *record, uint64_t filetime, bool archive)
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
	ntfs_put_u64(standard->modified, filetime);
	ntfs_put_u64(standard->changed, filetime);
	if (archive) {
		ntfs_put_u32(
		    standard->attributes, ntfs_u32(standard->attributes) | NTFS_FILE_ARCHIVE);
	}
	record->changed = true;
	return NTFS_OK;
}
