/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "pointer_range.h"
#include "write_retirement.h"

enum {
	RETIREMENT_PAYLOAD_CAPACITY =
	    sizeof(struct ntfs_disk_log_update_storage) + NTFS_WRITE_RECORD_BYTES,
	RETIREMENT_USA_OFFSET =
	    sizeof(struct ntfs_disk_record) + sizeof(struct ntfs_disk_record_extension),
	RETIREMENT_USA_COUNT = NTFS_WRITE_RECORD_BYTES / NTFS_MST_STRIDE + 1
};

struct retirement_step {
	struct ntfs_write_retirement_update view;
	uint8_t payload[RETIREMENT_PAYLOAD_CAPACITY];
};

struct ntfs_write_retirement_program {
	void *context;
	void (*release)(void *, void *, size_t);
	size_t bytes, count;
	struct retirement_step step[];
};

struct retirement_workspace {
	uint8_t before[NTFS_WRITE_CLUSTER_BYTES], after[NTFS_WRITE_CLUSTER_BYTES];
	uint8_t expected[NTFS_WRITE_RECORD_BYTES];
	bool retire[NTFS_WRITE_RETIREMENT_RECORDS];
};

static uint16_t
retired_sequence(uint16_t sequence)
{
	sequence = (uint16_t)(sequence + 1u);
	return sequence == 0 ? 1 : sequence;
}

static bool
modern_geometry(const struct ntfs_disk_record *header)
{
	size_t first = ntfs_u16(header->attrs_offset), used = ntfs_u32(header->used);

	return ntfs_equal(header->mst.magic, "FILE", sizeof(header->mst.magic)) &&
	    ntfs_u16(header->mst.usa_offset) == RETIREMENT_USA_OFFSET &&
	    ntfs_u16(header->mst.usa_count) == RETIREMENT_USA_COUNT &&
	    first >= RETIREMENT_USA_OFFSET + RETIREMENT_USA_COUNT * NTFS_MST_WORD_BYTES &&
	    first % NTFS_WIRE_ALIGNMENT == 0 && used % NTFS_WIRE_ALIGNMENT == 0 &&
	    ntfs_bounds(first, NTFS_WIRE_ALIGNMENT, used) && used <= NTFS_WRITE_RECORD_BYTES &&
	    ntfs_u32(header->allocated) == NTFS_WRITE_RECORD_BYTES &&
	    ntfs_u64(header->base_reference) == 0 && ntfs_u16(header->sequence) != 0;
}

static bool
record_number(const void *record, uint64_t logical)
{
	const struct ntfs_disk_record_extension *extension;
	uint64_t number = logical / NTFS_WRITE_RECORD_BYTES;

	extension = (const void *)((const uint8_t *)record + sizeof(struct ntfs_disk_record));
	return number <= UINT32_MAX && ntfs_u32(extension->record_number) == number;
}

static enum ntfs_result
admit_output(const struct ntfs_environment *source, const struct ntfs_write_mutation_region *region,
    struct ntfs_write_retirement_program **out)
{
	if (!ntfs_pointer_range_valid(out, sizeof(*out)) ||
	    (source != NULL &&
		!ntfs_pointer_ranges_separate(source, sizeof(*source), out, sizeof(*out))) ||
	    (region != NULL &&
		!ntfs_pointer_ranges_separate(region, sizeof(*region), out, sizeof(*out))) ||
	    (region != NULL &&
		(!ntfs_pointer_ranges_separate(region->before, region->bytes, out, sizeof(*out)) ||
		    !ntfs_pointer_ranges_separate(
			region->after, region->bytes, out, sizeof(*out))))) {
		return NTFS_INVALID;
	}
	*out = NULL;
	return NTFS_OK;
}

static enum ntfs_result
admit_region(const struct ntfs_environment *source, const struct ntfs_write_mutation_region *region,
    uint16_t key)
{
	const struct ntfs_write_mutation_target *target;
	size_t index;

	if (source == NULL || region == NULL || source->api_version != NTFS_API_VERSION ||
	    source->allocate == NULL || source->release == NULL) {
		return NTFS_INVALID;
	}
	target = &region->target;
	if (region->kind != NTFS_WRITE_MUTATION_FILE || region->bytes != NTFS_WRITE_CLUSTER_BYTES ||
	    target->mirror || target->attribute_type != NTFS_ATTRIBUTE_DATA ||
	    (target->reference & NTFS_REFERENCE_RECORD_MASK) != NTFS_MFT_RECORD ||
	    target->name_count != 0) {
		return NTFS_UNSUPPORTED;
	}
	if (target->reference >> NTFS_REFERENCE_SEQUENCE_SHIFT == 0 ||
	    region->physical % NTFS_WRITE_CLUSTER_BYTES != 0 ||
	    target->logical_offset % NTFS_WRITE_CLUSTER_BYTES != 0 ||
	    !ntfs_bounds(region->physical, region->bytes, INT64_MAX) ||
	    !ntfs_bounds(target->logical_offset, region->bytes, INT64_MAX) ||
	    (source->size_bytes != 0 &&
		!ntfs_bounds(region->physical, region->bytes, source->size_bytes)) ||
	    key < sizeof(struct ntfs_disk_log_table) ||
	    (key - sizeof(struct ntfs_disk_log_table)) %
		    sizeof(struct ntfs_disk_log_open_attribute) !=
		0) {
		return NTFS_INVALID;
	}
	for (index = 0; index < NTFS_WRITE_MUTATION_TARGET_NAME_UNITS; index++) {
		if (target->name[index] != 0) {
			return NTFS_INVALID;
		}
	}
	return NTFS_OK;
}

static void
publication_fields(void *expected, const void *after)
{
	struct ntfs_disk_record *header = expected;
	const struct ntfs_disk_record *next = after;

	ntfs_copy(header->lsn, next->lsn, sizeof(header->lsn));
	ntfs_copy((uint8_t *)expected + RETIREMENT_USA_OFFSET,
	    (const uint8_t *)after + RETIREMENT_USA_OFFSET,
	    RETIREMENT_USA_COUNT * NTFS_MST_WORD_BYTES);
}

static enum ntfs_result
admit_records(const struct ntfs_write_mutation_region *region, struct retirement_workspace *work,
    size_t *count)
{
	const struct ntfs_disk_record *before, *after;
	struct ntfs_disk_record *expected;
	uint64_t logical;
	size_t index, offset;
	uint16_t flags;
	enum ntfs_result result;

	ntfs_zero(work, sizeof(*work));
	ntfs_copy(work->before, region->before, region->bytes);
	ntfs_copy(work->after, region->after, region->bytes);
	*count = 0;
	for (index = 0; index < NTFS_WRITE_RETIREMENT_RECORDS; index++) {
		offset = index * NTFS_WRITE_RECORD_BYTES;
		if (ntfs_equal(
			work->before + offset, work->after + offset, NTFS_WRITE_RECORD_BYTES)) {
			continue;
		}
		result = ntfs_record_decode(work->before + offset, NTFS_WRITE_RECORD_BYTES, false);
		if (result == NTFS_OK) {
			result = ntfs_record_decode(
			    work->after + offset, NTFS_WRITE_RECORD_BYTES, false);
		}
		if (result != NTFS_OK) {
			return result;
		}
		before = (const void *)(work->before + offset);
		after = (const void *)(work->after + offset);
		if (!modern_geometry(before) || !modern_geometry(after)) {
			return NTFS_UNSUPPORTED;
		}
		logical = region->target.logical_offset + offset;
		if (!record_number(before, logical) || !record_number(after, logical)) {
			return NTFS_CORRUPT;
		}
		ntfs_copy(work->expected, before, NTFS_WRITE_RECORD_BYTES);
		publication_fields(work->expected, after);
		if (ntfs_equal(work->expected, after, NTFS_WRITE_RECORD_BYTES)) {
			continue;
		}
		flags = ntfs_u16(before->flags);
		if ((logical / NTFS_WRITE_RECORD_BYTES) < NTFS_FIRST_USER_RECORD ||
		    (flags != NTFS_RECORD_IN_USE &&
			flags != (NTFS_RECORD_IN_USE | NTFS_RECORD_DIRECTORY)) ||
		    ntfs_u16(after->flags) != 0 || ntfs_u16(before->links) == 0 ||
		    ntfs_u16(after->sequence) != retired_sequence(ntfs_u16(before->sequence))) {
			return NTFS_UNSUPPORTED;
		}
		expected = (void *)work->expected;
		ntfs_put_u16(expected->sequence, ntfs_u16(after->sequence));
		ntfs_put_u16(expected->flags, 0);
		if (!ntfs_equal(work->expected, after, NTFS_WRITE_RECORD_BYTES)) {
			return NTFS_UNSUPPORTED;
		}
		work->retire[index] = true;
		*count += 2;
	}
	return NTFS_OK;
}

static enum ntfs_result
encode(const struct ntfs_write_mutation_region *region, uint16_t key, size_t slot,
    const void *before, bool snapshot, struct retirement_step *step)
{
	const struct ntfs_disk_record *header = before;
	struct ntfs_disk_log_update_storage *stored = (void *)step->payload;
	struct ntfs_logfile_update_input update = {0};
	uint8_t lcn[sizeof(uint64_t)];
	uint32_t bytes;
	enum ntfs_result result;

	ntfs_put_u64(lcn, region->physical / NTFS_WRITE_CLUSTER_BYTES);
	update.target_attribute = key;
	update.attribute_flags = NTFS_WRITE_MFT_TARGET_FLAG;
	update.target_vcn = region->target.logical_offset / NTFS_WRITE_CLUSTER_BYTES;
	update.cluster_index = (uint16_t)(slot * NTFS_WRITE_RECORD_BYTES / NTFS_WRITE_SECTOR_BYTES);
	update.lcns = (struct ntfs_logfile_buffer){lcn, sizeof(lcn)};
	if (snapshot) {
		update.redo_operation = NTFS_LOG_OP_INITIALIZE_FILE_RECORD;
		update.undo_operation = NTFS_LOG_OP_NOOP;
		update.redo = (struct ntfs_logfile_buffer){before, ntfs_u32(header->used)};
		step->view.record_flags = NTFS_LOGFILE_RECORD_ADDING;
	} else {
		update.redo_operation = NTFS_LOG_OP_DEALLOCATE_FILE_RECORD;
		update.undo_operation = NTFS_LOG_OP_INITIALIZE_FILE_RECORD;
		update.undo =
		    (struct ntfs_logfile_buffer){before, NTFS_WRITE_RETIREMENT_PREFIX_BYTES};
		step->view.record_flags = NTFS_LOGFILE_RECORD_DELETING;
	}
	result = ntfs_logfile_update_measure(&update, &bytes);
	if (result == NTFS_OK) {
		result = ntfs_logfile_update_encode(&update, step->payload, sizeof(step->payload));
	}
	if (result != NTFS_OK) {
		return result;
	}
	if (update.redo.bytes == 0) {
		ntfs_put_u16(stored->header.redo_offset, sizeof(*stored));
	}
	if (update.undo.bytes == 0) {
		ntfs_put_u16(stored->header.undo_offset, (uint16_t)bytes);
	}
	step->view.payload = (struct ntfs_logfile_buffer){step->payload, bytes};
	return NTFS_OK;
}

enum ntfs_result
ntfs_write_retirement_program_prepare(const struct ntfs_environment *source,
    const struct ntfs_write_mutation_region *region, uint16_t key,
    struct ntfs_write_retirement_program **out)
{
	struct ntfs_write_retirement_program *program = NULL;
	struct retirement_workspace *work;
	struct ntfs_environment allocator;
	size_t count, bytes, index, ordinal = 0;
	enum ntfs_result result;

	result = admit_output(source, region, out);
	if (result == NTFS_OK) {
		result = admit_region(source, region, key);
	}
	if (result != NTFS_OK) {
		return result;
	}
	allocator = *source;
	work = allocator.allocate(allocator.context, sizeof(*work));
	if (work == NULL) {
		return NTFS_NO_MEMORY;
	}
	result = admit_records(region, work, &count);
	if (result == NTFS_OK) {
		bytes = sizeof(*program) + count * sizeof(*program->step);
		program = allocator.allocate(allocator.context, bytes);
		if (program == NULL) {
			result = NTFS_NO_MEMORY;
		} else {
			ntfs_zero(program, bytes);
			program->context = allocator.context;
			program->release = allocator.release;
			program->bytes = bytes;
			program->count = count;
		}
	}
	for (index = 0; result == NTFS_OK && index < NTFS_WRITE_RETIREMENT_RECORDS; index++) {
		if (!work->retire[index]) {
			continue;
		}
		result = encode(region, key, index, work->before + index * NTFS_WRITE_RECORD_BYTES,
		    true, &program->step[ordinal++]);
		if (result == NTFS_OK) {
			result = encode(region, key, index,
			    work->before + index * NTFS_WRITE_RECORD_BYTES, false,
			    &program->step[ordinal++]);
		}
	}
	allocator.release(allocator.context, work, sizeof(*work));
	if (result != NTFS_OK) {
		ntfs_write_retirement_program_close(program);
		return result;
	}
	*out = program;
	return NTFS_OK;
}

size_t
ntfs_write_retirement_program_count(const struct ntfs_write_retirement_program *program)
{
	return program == NULL ? 0 : program->count;
}

const struct ntfs_write_retirement_update *
ntfs_write_retirement_program_get(const struct ntfs_write_retirement_program *program, size_t index)
{
	return program == NULL || index >= program->count ? NULL : &program->step[index].view;
}

void
ntfs_write_retirement_program_close(struct ntfs_write_retirement_program *program)
{
	if (program != NULL) {
		program->release(program->context, program, program->bytes);
	}
}

static enum ntfs_result
admit_restored(const void *memory)
{
	const struct ntfs_disk_record *header = memory;
	struct ntfs_attr_view attribute;
	uint32_t position;
	enum ntfs_result result;

	if (!modern_geometry(header)) {
		return NTFS_CORRUPT;
	}
	position = ntfs_u16(header->attrs_offset);
	do {
		result = ntfs_attr_at(memory, ntfs_u32(header->used), &position, &attribute);
	} while (result == NTFS_OK);
	return result == NTFS_END ? NTFS_OK : result;
}

enum ntfs_result
ntfs_write_retirement_apply(
    const void *payload, size_t bytes, bool undo, uint64_t lsn, void *memory, size_t record_bytes)
{
	struct ntfs_logfile_update update;
	const struct ntfs_disk_record *before;
	struct ntfs_disk_record *header = memory;
	uint64_t logical;
	uint16_t sequence, next_sequence, flags;
	enum ntfs_result result;

	if (lsn == 0 || record_bytes != NTFS_WRITE_RECORD_BYTES ||
	    !ntfs_pointer_range_valid(memory, record_bytes) ||
	    !ntfs_pointer_ranges_separate(payload, bytes, memory, record_bytes)) {
		return NTFS_INVALID;
	}
	result = ntfs_logfile_update_decode(payload, bytes, &update);
	if (result != NTFS_OK) {
		return result;
	}
	if (update.redo_operation != NTFS_LOG_OP_DEALLOCATE_FILE_RECORD ||
	    update.undo_operation != NTFS_LOG_OP_INITIALIZE_FILE_RECORD || update.lcn_count != 1 ||
	    update.record_offset != 0 || update.attribute_offset != 0 ||
	    update.attribute_flags != NTFS_WRITE_MFT_TARGET_FLAG ||
	    update.target_attribute < sizeof(struct ntfs_disk_log_table) ||
	    (update.target_attribute - sizeof(struct ntfs_disk_log_table)) %
		    sizeof(struct ntfs_disk_log_open_attribute) !=
		0 ||
	    (size_t)update.cluster_index * NTFS_WRITE_SECTOR_BYTES % NTFS_WRITE_RECORD_BYTES != 0 ||
	    (size_t)update.cluster_index * NTFS_WRITE_SECTOR_BYTES + NTFS_WRITE_RECORD_BYTES >
		NTFS_WRITE_CLUSTER_BYTES) {
		return NTFS_UNSUPPORTED;
	}
	if (update.redo.length != 0 || update.undo.length != NTFS_WRITE_RETIREMENT_PREFIX_BYTES ||
	    update.target_vcn > (uint64_t)INT64_MAX / NTFS_WRITE_CLUSTER_BYTES ||
	    ntfs_u64((const uint8_t *)payload + update.lcns.offset) >
		(uint64_t)INT64_MAX / NTFS_WRITE_CLUSTER_BYTES) {
		return NTFS_CORRUPT;
	}
	before = (const void *)((const uint8_t *)payload + update.undo.offset);
	sequence = ntfs_u16(before->sequence);
	next_sequence = retired_sequence(sequence);
	flags = ntfs_u16(before->flags);
	if (!ntfs_equal(before->mst.magic, "FILE", sizeof(before->mst.magic)) || sequence == 0 ||
	    ntfs_u16(before->mst.usa_offset) != RETIREMENT_USA_OFFSET ||
	    ntfs_u16(before->mst.usa_count) != RETIREMENT_USA_COUNT ||
	    (flags != NTFS_RECORD_IN_USE &&
		flags != (NTFS_RECORD_IN_USE | NTFS_RECORD_DIRECTORY)) ||
	    ntfs_u16(before->links) == 0) {
		return NTFS_CORRUPT;
	}
	result = admit_restored(memory);
	if (result != NTFS_OK) {
		return result;
	}
	logical = update.target_vcn * NTFS_WRITE_CLUSTER_BYTES +
	    (uint64_t)update.cluster_index * NTFS_WRITE_SECTOR_BYTES;
	if (!record_number(memory, logical) ||
	    ntfs_u16(header->attrs_offset) != ntfs_u16(before->attrs_offset) ||
	    ntfs_u16(header->links) != ntfs_u16(before->links) ||
	    !((ntfs_u16(header->sequence) == sequence && ntfs_u16(header->flags) == flags) ||
		(ntfs_u16(header->sequence) == next_sequence && ntfs_u16(header->flags) == 0))) {
		return NTFS_STALE;
	}
	if (undo) {
		ntfs_copy(memory, before, NTFS_WRITE_RETIREMENT_PREFIX_BYTES);
	} else {
		ntfs_put_u16(header->sequence, next_sequence);
		ntfs_put_u16(header->flags, 0);
	}
	ntfs_put_u64(header->lsn, lsn);
	return NTFS_OK;
}
