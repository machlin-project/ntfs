/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "pointer_range.h"
#include "write_bitmap.h"

enum { BITMAP_CLUSTER_BITS = NTFS_WRITE_CLUSTER_BYTES * NTFS_BITS_PER_BYTE };

struct ntfs_write_bitmap_step {
	struct ntfs_logfile_buffer view;
	uint8_t payload[NTFS_WRITE_BITMAP_PAYLOAD_BYTES];
};

struct ntfs_write_bitmap_program {
	void *context;
	void (*release)(void *, void *, size_t);
	size_t bytes, count;
	struct ntfs_write_bitmap_step step[];
};

static enum ntfs_result
bitmap_admit_output(const struct ntfs_environment *source,
    const struct ntfs_write_mutation_region *region, struct ntfs_write_bitmap_program **out)
{
	if (!ntfs_pointer_range_valid(out, sizeof(*out)) ||
	    (source != NULL &&
		!ntfs_pointer_ranges_separate(source, sizeof(*source), out, sizeof(*out))) ||
	    (region != NULL &&
		!ntfs_pointer_ranges_separate(region, sizeof(*region), out, sizeof(*out)))) {
		return NTFS_INVALID;
	}
	if (region != NULL &&
	    (!ntfs_pointer_ranges_separate(region->before, region->bytes, out, sizeof(*out)) ||
		!ntfs_pointer_ranges_separate(region->after, region->bytes, out, sizeof(*out)))) {
		return NTFS_INVALID;
	}
	*out = NULL;
	return NTFS_OK;
}

static enum ntfs_result
bitmap_admit_region(const struct ntfs_environment *source,
    const struct ntfs_write_mutation_region *region, uint16_t key)
{
	const struct ntfs_write_mutation_target *target;
	size_t index;

	if (source == NULL || region == NULL || source->api_version != NTFS_API_VERSION ||
	    source->allocate == NULL || source->release == NULL) {
		return NTFS_INVALID;
	}
	target = &region->target;
	if (region->bytes != NTFS_WRITE_CLUSTER_BYTES ||
	    region->kind != NTFS_WRITE_MUTATION_BITMAP || target->mirror ||
	    (target->attribute_type != NTFS_ATTRIBUTE_DATA &&
		target->attribute_type != NTFS_ATTR_BITMAP)) {
		return NTFS_UNSUPPORTED;
	}
	if ((target->reference >> NTFS_REFERENCE_SEQUENCE_SHIFT) == 0 ||
	    target->name_count > NTFS_WRITE_MUTATION_TARGET_NAME_UNITS ||
	    region->physical % NTFS_WRITE_CLUSTER_BYTES != 0 ||
	    target->logical_offset % NTFS_WRITE_CLUSTER_BYTES != 0 ||
	    region->physical > (uint64_t)INT64_MAX - NTFS_WRITE_CLUSTER_BYTES ||
	    target->logical_offset > (uint64_t)INT64_MAX - NTFS_WRITE_CLUSTER_BYTES ||
	    key < sizeof(struct ntfs_disk_log_table) ||
	    (key - sizeof(struct ntfs_disk_log_table)) %
		    sizeof(struct ntfs_disk_log_open_attribute) !=
		0 ||
	    (source->size_bytes != 0 &&
		!ntfs_bounds(region->physical, region->bytes, source->size_bytes))) {
		return NTFS_INVALID;
	}
	for (index = 0; index < NTFS_WRITE_MUTATION_TARGET_NAME_UNITS; index++) {
		if ((index < target->name_count) == (target->name[index] == 0)) {
			return NTFS_INVALID;
		}
	}
	if (target->attribute_type == NTFS_ATTRIBUTE_DATA &&
	    ((target->reference & NTFS_REFERENCE_RECORD_MASK) != NTFS_BITMAP_RECORD ||
		target->name_count != 0)) {
		return NTFS_UNSUPPORTED;
	}
	return NTFS_OK;
}

static bool
bitmap_bit(const uint8_t *bitmap, size_t index)
{
	return (bitmap[index / NTFS_BITS_PER_BYTE] & (1u << (index % NTFS_BITS_PER_BYTE))) != 0;
}

static bool
bitmap_next_range(const struct ntfs_write_mutation_region *region, size_t *position,
    uint32_t *first, uint32_t *count, bool *set)
{
	size_t begin;
	bool state;

	while (*position < BITMAP_CLUSTER_BITS &&
	    bitmap_bit(region->before, *position) == bitmap_bit(region->after, *position)) {
		(*position)++;
	}
	if (*position == BITMAP_CLUSTER_BITS) {
		return false;
	}
	begin = *position;
	state = bitmap_bit(region->after, begin);
	do {
		(*position)++;
	} while (*position < BITMAP_CLUSTER_BITS && bitmap_bit(region->after, *position) == state &&
	    bitmap_bit(region->before, *position) != state);
	*first = (uint32_t)begin;
	*count = (uint32_t)(*position - begin);
	*set = state;
	return true;
}

static enum ntfs_result
bitmap_encode(const struct ntfs_write_mutation_region *region, uint16_t key, uint32_t first,
    uint32_t count, bool set, struct ntfs_write_bitmap_step *step)
{
	struct ntfs_disk_log_bitmap_range range;
	struct ntfs_logfile_update_input update = {0};
	uint8_t lcn[sizeof(uint64_t)];
	enum ntfs_result result;

	ntfs_put_u32(range.first, first);
	ntfs_put_u32(range.bits, count);
	ntfs_put_u64(lcn, region->physical / NTFS_WRITE_CLUSTER_BYTES);
	update.target_attribute = key;
	update.target_vcn = region->target.logical_offset / NTFS_WRITE_CLUSTER_BYTES;
	update.redo_operation = set ? NTFS_LOG_OP_SET_BITMAP_BITS : NTFS_LOG_OP_CLEAR_BITMAP_BITS;
	update.undo_operation = set ? NTFS_LOG_OP_CLEAR_BITMAP_BITS : NTFS_LOG_OP_SET_BITMAP_BITS;
	update.redo = (struct ntfs_logfile_buffer){&range, sizeof(range)};
	update.undo = update.redo;
	update.lcns = (struct ntfs_logfile_buffer){lcn, sizeof(lcn)};
	result = ntfs_logfile_update_encode(&update, step->payload, sizeof(step->payload));
	if (result == NTFS_OK) {
		step->view = (struct ntfs_logfile_buffer){step->payload, sizeof(step->payload)};
	}
	return result;
}

enum ntfs_result
ntfs_write_bitmap_program_prepare(const struct ntfs_environment *source,
    const struct ntfs_write_mutation_region *region, uint16_t key,
    struct ntfs_write_bitmap_program **out)
{
	struct ntfs_write_bitmap_program *program;
	size_t position = 0, count = 0, bytes, index = 0;
	uint32_t first, bits;
	bool set;
	enum ntfs_result result;

	result = bitmap_admit_output(source, region, out);
	if (result == NTFS_OK) {
		result = bitmap_admit_region(source, region, key);
	}
	if (result != NTFS_OK) {
		return result;
	}
	while (bitmap_next_range(region, &position, &first, &bits, &set)) {
		if (count == NTFS_WRITE_BITMAP_MAX_RANGES) {
			return NTFS_RANGE;
		}
		count++;
	}
	if (count > (SIZE_MAX - sizeof(*program)) / sizeof(*program->step)) {
		return NTFS_RANGE;
	}
	bytes = sizeof(*program) + count * sizeof(*program->step);
	program = source->allocate(source->context, bytes);
	if (program == NULL) {
		return NTFS_NO_MEMORY;
	}
	ntfs_zero(program, bytes);
	program->context = source->context;
	program->release = source->release;
	program->bytes = bytes;
	program->count = count;
	position = 0;
	while (bitmap_next_range(region, &position, &first, &bits, &set)) {
		/* Borrowed source bytes remain immutable throughout preparation. */
		if (index == count) {
			result = NTFS_CORRUPT;
			break;
		}
		result = bitmap_encode(region, key, first, bits, set, &program->step[index]);
		if (result != NTFS_OK) {
			break;
		}
		index++;
	}
	if (result == NTFS_OK && index != count) {
		result = NTFS_CORRUPT;
	}
	if (result != NTFS_OK) {
		ntfs_write_bitmap_program_close(program);
		return result;
	}
	*out = program;
	return NTFS_OK;
}

size_t
ntfs_write_bitmap_program_count(const struct ntfs_write_bitmap_program *program)
{
	return program == NULL ? 0 : program->count;
}

const struct ntfs_logfile_buffer *
ntfs_write_bitmap_program_get(const struct ntfs_write_bitmap_program *program, size_t index)
{
	return program == NULL || index >= program->count ? NULL : &program->step[index].view;
}

void
ntfs_write_bitmap_program_close(struct ntfs_write_bitmap_program *program)
{
	if (program != NULL) {
		program->release(program->context, program, program->bytes);
	}
}

enum ntfs_result
ntfs_write_bitmap_apply(
    const void *payload, size_t bytes, bool undo, void *bitmap, size_t bitmap_bytes)
{
	struct ntfs_logfile_update update;
	const struct ntfs_disk_log_bitmap_range *range;
	uint8_t *output = bitmap;
	uint32_t first, count;
	size_t index, end;
	uint16_t inverse;
	bool set;
	enum ntfs_result result;

	if (bitmap_bytes != NTFS_WRITE_CLUSTER_BYTES ||
	    !ntfs_pointer_range_valid(bitmap, bitmap_bytes) ||
	    !ntfs_pointer_ranges_separate(payload, bytes, bitmap, bitmap_bytes)) {
		return NTFS_INVALID;
	}
	result = ntfs_logfile_update_decode(payload, bytes, &update);
	if (result != NTFS_OK) {
		return result;
	}
	if (update.redo_operation != NTFS_LOG_OP_SET_BITMAP_BITS &&
	    update.redo_operation != NTFS_LOG_OP_CLEAR_BITMAP_BITS) {
		return NTFS_UNSUPPORTED;
	}
	inverse = update.redo_operation == NTFS_LOG_OP_SET_BITMAP_BITS
	    ? NTFS_LOG_OP_CLEAR_BITMAP_BITS
	    : NTFS_LOG_OP_SET_BITMAP_BITS;
	if (update.undo_operation != inverse || update.lcn_count != 1 ||
	    update.record_offset != 0 || update.attribute_offset != 0 ||
	    update.cluster_index != 0 || update.attribute_flags != 0 ||
	    update.target_attribute == 0) {
		return NTFS_UNSUPPORTED;
	}
	if (update.redo.length != sizeof(*range) || update.undo.length != sizeof(*range) ||
	    !ntfs_equal((const uint8_t *)payload + update.redo.offset,
		(const uint8_t *)payload + update.undo.offset, sizeof(*range))) {
		return NTFS_CORRUPT;
	}
	range = (const void *)((const uint8_t *)payload + update.redo.offset);
	first = ntfs_u32(range->first);
	count = ntfs_u32(range->bits);
	if (first >= BITMAP_CLUSTER_BITS || count == 0 || count > BITMAP_CLUSTER_BITS - first) {
		return NTFS_CORRUPT;
	}
	end = (size_t)first + count;
	set = (update.redo_operation == NTFS_LOG_OP_SET_BITMAP_BITS) != undo;
	for (index = first; index < end; index++) {
		if (set) {
			output[index / NTFS_BITS_PER_BYTE] |=
			    (uint8_t)(1u << (index % NTFS_BITS_PER_BYTE));
		} else {
			output[index / NTFS_BITS_PER_BYTE] &=
			    (uint8_t)~(1u << (index % NTFS_BITS_PER_BYTE));
		}
	}
	return NTFS_OK;
}
