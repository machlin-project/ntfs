/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_mutation_internal.h"

static uint16_t *
mutation_record_slot(const struct ntfs_write_mutation_plan *plan, uint64_t number)
{
	uint16_t *slots = ntfs_mutation_vector_slots(plan->records, plan->record_capacity);
	size_t position = ntfs_mutation_hash(number, plan->record_capacity);
	size_t mask = plan->record_capacity * NTFS_MUTATION_LOOKUP_SLOTS_PER_ENTRY - 1u;

	/* The vector is bounded and the table never exceeds half occupancy. */
	while (slots[position] != 0 && plan->records[slots[position] - 1u]->number != number) {
		position = (position + 1u) & mask;
	}
	return &slots[position];
}

static enum ntfs_result
mutation_record_physical(struct ntfs_write_mutation_plan *plan, uint64_t number, uint64_t *out)
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
mutation_record_initialize_empty(struct ntfs_mutation_record *record, uint16_t sequence)
{
	struct ntfs_disk_record *header = (void *)record->bytes;
	struct ntfs_disk_record_extension *extension;
	size_t usa, attributes;

	ntfs_zero(record->bytes, sizeof(record->bytes));
	ntfs_copy(header->mst.magic, "FILE", sizeof(header->mst.magic));
	usa = sizeof(*header) + sizeof(*extension);
	attributes = ntfs_mutation_align_bytes(
	    usa + (NTFS_WRITE_RECORD_BYTES / NTFS_MST_STRIDE + 1) * NTFS_MST_WORD_BYTES);
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
	uint16_t slot;
	enum ntfs_result result;
	bool free_slot;

	*out = NULL;
	if (plan->record_capacity != 0) {
		slot = *mutation_record_slot(plan, number);
		if (slot != 0) {
			record = plan->records[slot - 1u];
			goto checked;
		}
	}
	if (number > UINT32_MAX || plan->record_count == NTFS_MUTATION_MAX_RECORDS) {
		return NTFS_RANGE;
	}
	if (plan->record_count == plan->record_capacity) {
		capacity = plan->record_capacity == 0 ? NTFS_MUTATION_INITIAL_RECORDS
						      : plan->record_capacity * NTFS_VECTOR_GROWTH;
		records = ntfs_mutation_allocate(plan, ntfs_mutation_vector_bytes(capacity));
		if (records == NULL) {
			return NTFS_NO_MEMORY;
		}
		ntfs_copy(records, plan->records, plan->record_count * sizeof(*records));
		ntfs_mutation_release(
		    plan, plan->records, ntfs_mutation_vector_bytes(plan->record_capacity));
		plan->records = records;
		plan->record_capacity = capacity;
		for (index = 0; index < plan->record_count; index++) {
			*mutation_record_slot(plan, plan->records[index]->number) =
			    (uint16_t)(index + 1u);
		}
	}
	record = ntfs_mutation_allocate(plan, sizeof(*record));
	if (record == NULL) {
		return NTFS_NO_MEMORY;
	}
	record->number = number;
	result = mutation_record_physical(plan, number, &record->physical);
	if (result == NTFS_OK) {
		result = ntfs_mutation_read(
		    plan, record->physical, record->bytes, sizeof(record->bytes));
	}
	if (result != NTFS_OK) {
		ntfs_mutation_release(plan, record, sizeof(*record));
		return result;
	}
	free_slot = false;
	if (number >= NTFS_FIRST_USER_RECORD && plan->mft_bitmap.bytes != 0) {
		result =
		    ntfs_mutation_bitmap_test(plan, &plan->mft_bitmap, number, false, &free_slot);
		if (result != NTFS_OK) {
			ntfs_mutation_release(plan, record, sizeof(*record));
			return result;
		}
		free_slot = !free_slot;
	}
	header = (void *)record->bytes;
	if (number * NTFS_WRITE_RECORD_BYTES >= plan->volume->mft->initialized) {
		mutation_record_initialize_empty(record, 1);
		record->changed = true;
	} else if (free_slot) {
		if (!ntfs_equal(header->mst.magic, "FILE", sizeof(header->mst.magic))) {
			mutation_record_initialize_empty(record, 1);
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
	*mutation_record_slot(plan, number) = (uint16_t)plan->record_count;

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
