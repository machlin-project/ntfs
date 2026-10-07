/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "pointer_range.h"
#include "write_program_internal.h"
#include "write_bitmap.h"
#include "write_retirement.h"
#include "write_mutation_internal.h"
#include <ntfs/record.h>

enum {
	PROGRAM_OAT_STRIDE = sizeof(struct ntfs_disk_log_open_attribute),
	PROGRAM_MAX_TARGETS = (UINT16_MAX - NTFS_WRITE_MFT_KEY) / PROGRAM_OAT_STRIDE + 1,
	PROGRAM_INDEX_TARGET_FLAG = 8,
	PROGRAM_FILE_SLOTS = NTFS_WRITE_CLUSTER_BYTES / NTFS_WRITE_RECORD_BYTES,
	PROGRAM_INITIAL_UPDATES = 16,
	PROGRAM_FILE_USA_COUNT = NTFS_WRITE_RECORD_BYTES / NTFS_MST_STRIDE + 1,
	PROGRAM_PAYLOAD_BYTES =
	    sizeof(struct ntfs_disk_log_update_storage) + 2 * NTFS_WRITE_CLUSTER_BYTES
};

struct program_workspace {
	uint8_t before[NTFS_WRITE_CLUSTER_BYTES], after[NTFS_WRITE_CLUSTER_BYTES];
	uint8_t payload[PROGRAM_PAYLOAD_BYTES];
};

static void *
program_allocate(struct ntfs_write_program *program, size_t bytes)
{
	void *memory;

	if (bytes == 0 || bytes > NTFS_DEFAULT_MAX_LIVE_BYTES - program->live) {
		return NULL;
	}
	memory = program->environment.allocate(program->environment.context, bytes);
	if (memory != NULL) {
		program->live += bytes;
		ntfs_zero(memory, bytes);
	}
	return memory;
}

static void
program_release(struct ntfs_write_program *program, void *memory, size_t bytes)
{
	if (memory != NULL) {
		program->environment.release(program->environment.context, memory, bytes);
		program->live -= bytes;
	}
}

void
ntfs_write_program_close(struct ntfs_write_program *program)
{
	struct ntfs_environment environment;
	size_t index;

	if (program == NULL) {
		return;
	}
	environment = program->environment;
	for (index = 0; index < program->count; index++) {
		program_release(program, (void *)program->update[index].payload.data,
		    program->update[index].payload.bytes);
	}
	program_release(program, program->update, program->capacity * sizeof(*program->update));
	program_release(program, program->target, program->regions * sizeof(*program->target));
	program_release(program, program->region, program->regions * sizeof(*program->region));
	environment.release(environment.context, program, sizeof(*program));
}

static bool
program_targets_equal(
    const struct ntfs_write_mutation_target *a, const struct ntfs_write_mutation_target *b)
{
	return a->reference == b->reference && a->attribute_type == b->attribute_type &&
	    a->name_count == b->name_count && ntfs_equal(a->name, b->name, sizeof(a->name));
}

static enum ntfs_result
program_target_bind(struct ntfs_write_program *program, struct program_region *region)
{
	const struct ntfs_write_mutation_target *identity = &region->view.target;
	struct program_target *entry;
	size_t index;
	uint64_t number;

	region->target = SIZE_MAX;
	if (region->view.kind == NTFS_WRITE_MUTATION_DATA || identity->mirror) {
		return NTFS_OK;
	}
	number = identity->reference & NTFS_REFERENCE_RECORD_MASK;
	if (identity->reference >> NTFS_REFERENCE_SEQUENCE_SHIFT == 0 ||
	    identity->name_count > NTFS_WRITE_MUTATION_TARGET_NAME_UNITS) {
		return NTFS_CORRUPT;
	}
	if ((region->view.kind == NTFS_WRITE_MUTATION_FILE &&
		(number != NTFS_MFT_RECORD || identity->attribute_type != NTFS_ATTRIBUTE_DATA ||
		    identity->name_count != 0)) ||
	    (region->view.kind == NTFS_WRITE_MUTATION_INDEX &&
		(identity->attribute_type != NTFS_ATTR_INDEX_ALLOCATION ||
		    identity->name_count != NTFS_WRITE_MUTATION_TARGET_NAME_UNITS))) {
		return NTFS_UNSUPPORTED;
	}
	for (index = 0; index < program->targets; index++) {
		if (program_targets_equal(identity, &program->target[index].identity)) {
			region->target = index;
			return NTFS_OK;
		}
	}
	if (program->targets == PROGRAM_MAX_TARGETS) {
		return NTFS_RANGE;
	}
	index = program->targets++;
	entry = &program->target[index];
	entry->identity = *identity;
	entry->identity.logical_offset = 0;
	entry->key = (uint16_t)(NTFS_WRITE_MFT_KEY + index * PROGRAM_OAT_STRIDE);
	entry->flags = region->view.kind == NTFS_WRITE_MUTATION_FILE ? NTFS_WRITE_MFT_TARGET_FLAG
	    : region->view.kind == NTFS_WRITE_MUTATION_INDEX	     ? PROGRAM_INDEX_TARGET_FLAG
								     : 0;
	region->target = index;
	return NTFS_OK;
}

static enum ntfs_result
program_update_append(struct ntfs_write_program *program, size_t region, uint16_t flags,
    const void *payload, size_t bytes)
{
	struct ntfs_write_program_update *entries, *entry;
	void *copy;
	size_t capacity;

	if (program->count + program->targets + 1 >= NTFS_WRITE_BATCH_MAX_PACKETS || bytes == 0 ||
	    bytes > PROGRAM_PAYLOAD_BYTES) {
		return NTFS_RANGE;
	}
	if (program->count == program->capacity) {
		capacity = program->capacity == 0 ? PROGRAM_INITIAL_UPDATES
						  : program->capacity * NTFS_VECTOR_GROWTH;
		if (capacity > NTFS_WRITE_BATCH_MAX_PACKETS) {
			capacity = NTFS_WRITE_BATCH_MAX_PACKETS;
		}
		entries = program_allocate(program, capacity * sizeof(*entries));
		if (entries == NULL) {
			return NTFS_NO_MEMORY;
		}
		ntfs_copy(entries, program->update, program->count * sizeof(*entries));
		program_release(program, program->update, program->capacity * sizeof(*entries));
		program->update = entries;
		program->capacity = capacity;
	}
	copy = program_allocate(program, bytes);
	if (copy == NULL) {
		return NTFS_NO_MEMORY;
	}
	ntfs_copy(copy, payload, bytes);
	entry = &program->update[program->count++];
	entry->payload = (struct ntfs_logfile_buffer){copy, bytes};
	entry->region = region;
	entry->record_flags = flags;
	return NTFS_OK;
}

static enum ntfs_result
program_update_encode(struct ntfs_write_program *program, struct program_workspace *work,
    size_t region, uint16_t flags, const struct ntfs_logfile_update_input *input)
{
	uint32_t bytes;
	enum ntfs_result result;

	result = ntfs_write_payload_encode(input, work->payload, sizeof(work->payload), &bytes);
	if (result == NTFS_OK) {
		result = program_update_append(program, region, flags, work->payload, bytes);
	}
	return result;
}

static bool
program_file_bytes_equal(const uint8_t *before, const uint8_t *after)
{
	const struct ntfs_disk_record *header = (const void *)before;
	size_t first = ntfs_u16(header->mst.usa_offset);
	size_t end = first + ntfs_u16(header->mst.usa_count) * sizeof(uint16_t);
	size_t lsn_end = offsetof(struct ntfs_disk_record, lsn) + sizeof(header->lsn);

	return first >= lsn_end && end <= NTFS_WRITE_RECORD_BYTES &&
	    ntfs_equal(before, after, offsetof(struct ntfs_disk_record, lsn)) &&
	    ntfs_equal(before + lsn_end, after + lsn_end, first - lsn_end) &&
	    ntfs_equal(before + end, after + end, NTFS_WRITE_RECORD_BYTES - end);
}

static enum ntfs_result
logical_file(const void *record)
{
	const struct ntfs_disk_record *header = record;
	struct ntfs_attr_view attribute;
	uint32_t position = ntfs_u16(header->attrs_offset), used = ntfs_u32(header->used);
	enum ntfs_result result;

	if (!ntfs_equal(header->mst.magic, "FILE", sizeof(header->mst.magic)) ||
	    ntfs_u16(header->mst.usa_offset) !=
		sizeof(*header) + sizeof(struct ntfs_disk_record_extension) ||
	    ntfs_u16(header->mst.usa_count) != PROGRAM_FILE_USA_COUNT ||
	    position <
		ntfs_u16(header->mst.usa_offset) + PROGRAM_FILE_USA_COUNT * sizeof(uint16_t) ||
	    position % NTFS_WIRE_ALIGNMENT != 0 || !ntfs_bounds(position, sizeof(uint32_t), used) ||
	    used > NTFS_WRITE_RECORD_BYTES ||
	    ntfs_u32(header->allocated) != NTFS_WRITE_RECORD_BYTES ||
	    ntfs_u16(header->sequence) == 0 || ntfs_u64(header->base_reference) != 0 ||
	    (ntfs_u16(header->flags) & ~(NTFS_RECORD_IN_USE | NTFS_RECORD_DIRECTORY)) != 0) {
		return NTFS_CORRUPT;
	}
	do {
		result = ntfs_attr_at(record, used, &position, &attribute);
	} while (result == NTFS_OK);
	return result == NTFS_END ? NTFS_OK : result;
}

static enum ntfs_result
program_file_compile(
    struct ntfs_write_program *program, struct program_workspace *work, size_t ordinal, size_t slot)
{
	const struct program_region *region = &program->region[ordinal];
	struct ntfs_logfile_update_input input = {0};
	const struct ntfs_disk_record *before, *after;
	uint8_t lcn[sizeof(uint64_t)], empty[sizeof(struct ntfs_disk_mst)] = {0};
	uint8_t *old = work->before + slot * NTFS_WRITE_RECORD_BYTES;
	uint8_t *new = work->after + slot * NTFS_WRITE_RECORD_BYTES;
	uint64_t number;
	bool predecessor;
	enum ntfs_result result;

	if (ntfs_equal(region->before + slot * NTFS_WRITE_RECORD_BYTES,
		region->after + slot * NTFS_WRITE_RECORD_BYTES, NTFS_WRITE_RECORD_BYTES)) {
		return NTFS_OK;
	}
	ntfs_copy(new, region->after + slot * NTFS_WRITE_RECORD_BYTES, NTFS_WRITE_RECORD_BYTES);
	result = ntfs_record_decode(new, NTFS_WRITE_RECORD_BYTES, false);
	if (result == NTFS_OK) {
		result = logical_file(new);
	}
	if (result != NTFS_OK) {
		return result;
	}
	number = region->view.target.logical_offset / NTFS_WRITE_RECORD_BYTES + slot;
	after = (const void *)new;
	if (number > UINT32_MAX ||
	    ntfs_u16(after->mst.usa_offset) !=
		sizeof(*after) + sizeof(struct ntfs_disk_record_extension) ||
	    ntfs_u16(after->mst.usa_count) != PROGRAM_FILE_USA_COUNT ||
	    ntfs_u64(after->base_reference) != 0 ||
	    ntfs_u32(((const struct ntfs_disk_record_extension *)(new + sizeof(*after)))
		    ->record_number) != number) {
		return NTFS_UNSUPPORTED;
	}
	ntfs_copy(old, region->before + slot * NTFS_WRITE_RECORD_BYTES, NTFS_WRITE_RECORD_BYTES);
	predecessor = (region->view.predecessor.file_slots & (1u << slot)) != 0;
	if (predecessor) {
		result = ntfs_record_decode(old, NTFS_WRITE_RECORD_BYTES, false);
		if (result == NTFS_OK) {
			result = logical_file(old);
		}
		if (result != NTFS_OK) {
			return result;
		}
		if (program_file_bytes_equal(old, new)) {
			return NTFS_OK;
		}
	}
	before = (const void *)old;
	ntfs_put_u64(lcn, region->view.physical / NTFS_WRITE_CLUSTER_BYTES);
	input.target_attribute = program->target[region->target].key;
	input.target_vcn = region->view.target.logical_offset / NTFS_WRITE_CLUSTER_BYTES;
	input.cluster_index = (uint16_t)(slot * NTFS_WRITE_RECORD_BYTES / NTFS_MST_STRIDE);
	input.attribute_flags = NTFS_WRITE_MFT_TARGET_FLAG;
	input.lcns = (struct ntfs_logfile_buffer){lcn, sizeof(lcn)};
	if (predecessor) {
		/* Initialize is already used as a native full before-snapshot. Its
		 * complete inverse is an experimental composition, requiring Windows
		 * replay/undo acceptance before this program may reach the product. */
		input.redo_operation = NTFS_LOG_OP_INITIALIZE_FILE_RECORD;
		input.undo_operation = NTFS_LOG_OP_INITIALIZE_FILE_RECORD;
		input.redo = input.undo =
		    (struct ntfs_logfile_buffer){old, NTFS_WRITE_RECORD_BYTES};
		result = program_update_encode(
		    program, work, ordinal, NTFS_LOGFILE_RECORD_ADDING, &input);
		if (result != NTFS_OK) {
			return result;
		}
	}
	if (predecessor && (ntfs_u16(before->flags) & NTFS_RECORD_IN_USE) != 0 &&
	    ntfs_u16(after->flags) == 0) {
		struct ntfs_disk_record *expected = (void *)work->payload;
		uint16_t generation = (uint16_t)(ntfs_u16(before->sequence) + 1u);

		ntfs_copy(work->payload, old, NTFS_WRITE_RECORD_BYTES);
		ntfs_put_u16(expected->sequence, generation == 0 ? 1 : generation);
		ntfs_put_u16(expected->flags, 0);
		if (!program_file_bytes_equal(work->payload, new)) {
			return NTFS_UNSUPPORTED;
		}
		input.redo_operation = NTFS_LOG_OP_DEALLOCATE_FILE_RECORD;
		input.undo_operation = NTFS_LOG_OP_INITIALIZE_FILE_RECORD;
		input.redo = (struct ntfs_logfile_buffer){0};
		input.undo = (struct ntfs_logfile_buffer){old, NTFS_WRITE_RETIREMENT_PREFIX_BYTES};
		return program_update_encode(
		    program, work, ordinal, NTFS_LOGFILE_RECORD_DELETING, &input);
	}
	if (!predecessor) {
		/* Retain the new-slot inverse before initialization, so every complete
		 * journal prefix contains the undo needed by its redo. Unowned bytes
		 * are not an old FILE: use an empty MST prefix. */
		input.redo_operation = NTFS_LOG_OP_NOOP;
		input.undo_operation = NTFS_LOG_OP_DEALLOCATE_FILE_RECORD;
		input.redo = (struct ntfs_logfile_buffer){0};
		input.undo = (struct ntfs_logfile_buffer){empty, sizeof(empty)};
		result = program_update_encode(
		    program, work, ordinal, NTFS_LOGFILE_RECORD_DELETING, &input);
		if (result != NTFS_OK) {
			return result;
		}
	}
	input.redo_operation = NTFS_LOG_OP_INITIALIZE_FILE_RECORD;
	input.undo_operation = NTFS_LOG_OP_NOOP;
	input.redo = (struct ntfs_logfile_buffer){new, NTFS_WRITE_RECORD_BYTES};
	input.undo = (struct ntfs_logfile_buffer){0};
	return program_update_encode(program, work, ordinal, NTFS_LOGFILE_RECORD_ADDING, &input);
}

static enum ntfs_result
program_region_compile(
    struct ntfs_write_program *program, struct program_workspace *work, size_t ordinal)
{
	const struct program_region *region = &program->region[ordinal];
	struct ntfs_write_bitmap_program *bitmap = NULL;
	const struct ntfs_logfile_buffer *payload;
	struct ntfs_logfile_update_input input = {0};
	uint8_t lcn[sizeof(uint64_t)];
	size_t index;
	enum ntfs_result result = NTFS_OK;

	if (region->target == SIZE_MAX) {
		return NTFS_OK;
	}
	if (region->view.kind == NTFS_WRITE_MUTATION_BITMAP) {
		result = ntfs_write_bitmap_program_prepare(&program->environment, &region->view,
		    program->target[region->target].key, &bitmap);
		for (index = 0;
		    result == NTFS_OK && index < ntfs_write_bitmap_program_count(bitmap); index++) {
			payload = ntfs_write_bitmap_program_get(bitmap, index);
			result = program_update_append(
			    program, ordinal, 0, payload->data, payload->bytes);
		}
		ntfs_write_bitmap_program_close(bitmap);
		return result;
	}
	if (region->view.kind == NTFS_WRITE_MUTATION_FILE) {
		for (index = 0; result == NTFS_OK && index < PROGRAM_FILE_SLOTS; index++) {
			result = program_file_compile(program, work, ordinal, index);
		}
		return result;
	}
	if (region->view.kind != NTFS_WRITE_MUTATION_INDEX) {
		return NTFS_UNSUPPORTED;
	}
	ntfs_copy(work->after, region->after, NTFS_WRITE_CLUSTER_BYTES);
	result = ntfs_fixup(work->after, NTFS_WRITE_CLUSTER_BYTES, "INDX");
	if (result != NTFS_OK) {
		return result;
	}
	ntfs_copy(work->before, region->before, NTFS_WRITE_CLUSTER_BYTES);
	if (region->view.predecessor.index_allocated) {
		result = ntfs_fixup(work->before, NTFS_WRITE_CLUSTER_BYTES, "INDX");
		if (result != NTFS_OK) {
			return result;
		}
		input.undo_operation = NTFS_LOG_OP_UPDATE_NONRESIDENT_VALUE;
		input.undo = (struct ntfs_logfile_buffer){work->before, NTFS_WRITE_CLUSTER_BYTES};
	}
	ntfs_put_u64(lcn, region->view.physical / NTFS_WRITE_CLUSTER_BYTES);
	input.redo_operation = NTFS_LOG_OP_UPDATE_NONRESIDENT_VALUE;
	input.target_attribute = program->target[region->target].key;
	input.target_vcn = region->view.target.logical_offset / NTFS_WRITE_CLUSTER_BYTES;
	input.attribute_flags = PROGRAM_INDEX_TARGET_FLAG;
	input.lcns = (struct ntfs_logfile_buffer){lcn, sizeof(lcn)};
	input.redo = (struct ntfs_logfile_buffer){work->after, NTFS_WRITE_CLUSTER_BYTES};
	return program_update_encode(
	    program, work, ordinal, input.undo.bytes == 0 ? NTFS_LOGFILE_RECORD_ADDING : 0, &input);
}

enum ntfs_result
ntfs_write_program_prepare(const struct ntfs_environment *source,
    const struct ntfs_write_mutation_plan *plan, struct ntfs_write_program **out)
{
	struct ntfs_write_program *program;
	struct program_workspace *work = NULL;
	struct ntfs_write_mutation_region region;
	size_t count, index, selected, pass;
	uint64_t logical;
	enum ntfs_result result;

	if (!ntfs_pointer_range_valid(out, sizeof(*out)) ||
	    (source != NULL &&
		!ntfs_pointer_ranges_separate(source, sizeof(*source), out, sizeof(*out))) ||
	    (plan != NULL &&
		!ntfs_pointer_ranges_separate(plan, sizeof(*plan), out, sizeof(*out)))) {
		return NTFS_INVALID;
	}
	if (source == NULL || plan == NULL) {
		*out = NULL;
		return NTFS_INVALID;
	}
	count = ntfs_write_mutation_plan_count(plan);
	for (index = 0; index < count; index++) {
		result = ntfs_write_mutation_plan_region(plan, index, &region);
		if (result != NTFS_OK ||
		    !ntfs_pointer_ranges_separate(region.before, region.bytes, out, sizeof(*out)) ||
		    !ntfs_pointer_ranges_separate(region.after, region.bytes, out, sizeof(*out))) {
			return NTFS_INVALID;
		}
	}
	*out = NULL;
	if (source->api_version != NTFS_API_VERSION || source->allocate == NULL ||
	    source->release == NULL || count == 0 || count > NTFS_WRITE_BATCH_MAX_PACKETS ||
	    count > SIZE_MAX / sizeof(*program->region)) {
		return NTFS_INVALID;
	}
	program = source->allocate(source->context, sizeof(*program));
	if (program == NULL) {
		return NTFS_NO_MEMORY;
	}
	ntfs_zero(program, sizeof(*program));
	program->environment = *source;
	program->live = sizeof(*program);
	program->regions = count;
	program->region = program_allocate(program, count * sizeof(*program->region));
	program->target = program_allocate(program, count * sizeof(*program->target));
	work = program_allocate(program, sizeof(*work));
	if (program->region == NULL || program->target == NULL || work == NULL) {
		result = NTFS_NO_MEMORY;
		goto done;
	}
	for (index = 0; index < count; index++) {
		result = ntfs_write_mutation_plan_region(plan, index, &region);
		if (result != NTFS_OK || region.bytes != NTFS_WRITE_CLUSTER_BYTES ||
		    region.physical % NTFS_WRITE_CLUSTER_BYTES != 0 ||
		    region.target.logical_offset % NTFS_WRITE_CLUSTER_BYTES != 0 ||
		    !ntfs_bounds(region.physical, region.bytes, source->size_bytes)) {
			result = NTFS_CORRUPT;
			goto done;
		}
		program->region[index].view = region;
		ntfs_copy(program->region[index].before, region.before, region.bytes);
		ntfs_copy(program->region[index].after, region.after, region.bytes);
		program->region[index].view.before = program->region[index].before;
		program->region[index].view.after = program->region[index].after;
		result = program_target_bind(program, &program->region[index]);
		if (result != NTFS_OK) {
			goto done;
		}
	}
	/* Bootstrap MFT mapping changes precede later FILE slots and any index
	 * stream opened through those slots. OAT ordinals retain their own keys. */
	logical = 0;
	for (pass = 0; pass < count; pass++) {
		selected = count;
		for (index = 0; index < count; index++) {
			if (program->region[index].view.kind == NTFS_WRITE_MUTATION_FILE &&
			    program->region[index].target != SIZE_MAX &&
			    program->region[index].view.target.logical_offset >= logical &&
			    (selected == count ||
				program->region[index].view.target.logical_offset <
				    program->region[selected].view.target.logical_offset)) {
				selected = index;
			}
		}
		if (selected == count) {
			break;
		}
		result = program_region_compile(program, work, selected);
		if (result != NTFS_OK) {
			goto done;
		}
		logical = program->region[selected].view.target.logical_offset;
		if (logical > UINT64_MAX - NTFS_WRITE_CLUSTER_BYTES) {
			result = NTFS_RANGE;
			goto done;
		}
		logical += NTFS_WRITE_CLUSTER_BYTES;
	}
	for (pass = 0; pass < 2; pass++) {
		for (index = 0; index < count; index++) {
			if (program->region[index].view.kind !=
			    (pass == 0 ? NTFS_WRITE_MUTATION_INDEX : NTFS_WRITE_MUTATION_BITMAP)) {
				continue;
			}
			result = program_region_compile(program, work, index);
			if (result != NTFS_OK) {
				goto done;
			}
		}
	}
	result = program->count == 0 ? NTFS_UNSUPPORTED : NTFS_OK;
done:
	program_release(program, work, sizeof(*work));
	if (result != NTFS_OK) {
		ntfs_write_program_close(program);
		return result;
	}
	*out = program;
	return NTFS_OK;
}

size_t
ntfs_write_program_count(const struct ntfs_write_program *program)
{
	return program == NULL ? 0 : program->count;
}

size_t
ntfs_write_program_regions(const struct ntfs_write_program *program)
{
	return program == NULL ? 0 : program->regions;
}

const struct ntfs_write_program_update *
ntfs_write_program_get(const struct ntfs_write_program *program, size_t index)
{
	return program == NULL || index >= program->count ? NULL : &program->update[index];
}

bool
ntfs_write_program_output_separate(
    const struct ntfs_write_program *program, const void *out, size_t bytes)
{
	size_t index;

	if (program == NULL || !ntfs_pointer_range_valid(out, bytes) ||
	    !ntfs_pointer_ranges_separate(program, sizeof(*program), out, bytes) ||
	    !ntfs_pointer_ranges_separate(
		program->region, program->regions * sizeof(*program->region), out, bytes) ||
	    !ntfs_pointer_ranges_separate(
		program->target, program->regions * sizeof(*program->target), out, bytes) ||
	    !ntfs_pointer_ranges_separate(
		program->update, program->capacity * sizeof(*program->update), out, bytes)) {
		return false;
	}
	for (index = 0; index < program->count; index++) {
		if (!ntfs_pointer_ranges_separate(program->update[index].payload.data,
			program->update[index].payload.bytes, out, bytes)) {
			return false;
		}
	}
	return true;
}

enum ntfs_result
ntfs_write_program_region(
    const struct ntfs_write_program *program, size_t index, struct ntfs_write_mutation_region *out)
{
	if (program == NULL || !ntfs_write_program_output_separate(program, out, sizeof(*out))) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (index >= program->regions) {
		return NTFS_END;
	}
	*out = program->region[index].view;
	return NTFS_OK;
}

enum ntfs_result
ntfs_write_program_apply(const struct ntfs_write_program *program, size_t index, bool undo,
    uint64_t lsn, void *cluster, size_t bytes)
{
	const struct ntfs_write_program_update *step;
	const struct program_region *region;
	struct ntfs_logfile_update update;
	struct ntfs_logfile_span span;
	struct ntfs_disk_record *header;
	const struct ntfs_disk_record *image;
	uint16_t operation, generation;
	uint8_t *record, *value = cluster;
	const uint8_t *payload;
	size_t offset;
	enum ntfs_result result;

	if (program == NULL || !ntfs_write_program_output_separate(program, cluster, bytes)) {
		return NTFS_INVALID;
	}
	if (index >= program->count || bytes != NTFS_WRITE_CLUSTER_BYTES || lsn == 0) {
		return NTFS_INVALID;
	}
	step = &program->update[index];
	region = &program->region[step->region];
	payload = step->payload.data;
	result = ntfs_logfile_update_decode(payload, step->payload.bytes, &update);
	if (result != NTFS_OK) {
		return result;
	}
	if (region->view.kind == NTFS_WRITE_MUTATION_BITMAP) {
		return ntfs_write_bitmap_apply(payload, step->payload.bytes, undo, cluster, bytes);
	}
	operation = undo ? update.undo_operation : update.redo_operation;
	span = undo ? update.undo : update.redo;
	if (operation == NTFS_LOG_OP_NOOP) {
		return NTFS_OK;
	}
	if (region->view.kind == NTFS_WRITE_MUTATION_INDEX) {
		if (operation != NTFS_LOG_OP_UPDATE_NONRESIDENT_VALUE ||
		    span.length != NTFS_WRITE_CLUSTER_BYTES) {
			return NTFS_UNSUPPORTED;
		}
		ntfs_copy(value, payload + span.offset, span.length);
		ntfs_put_u64(value + offsetof(struct ntfs_disk_index_block, lsn), lsn);
		return NTFS_OK;
	}
	offset = (size_t)update.cluster_index * NTFS_MST_STRIDE;
	if (region->view.kind != NTFS_WRITE_MUTATION_FILE ||
	    offset % NTFS_WRITE_RECORD_BYTES != 0 ||
	    !ntfs_bounds(offset, NTFS_WRITE_RECORD_BYTES, bytes)) {
		return NTFS_CORRUPT;
	}
	record = value + offset;
	if (update.redo_operation == NTFS_LOG_OP_DEALLOCATE_FILE_RECORD) {
		return ntfs_write_retirement_apply(
		    payload, step->payload.bytes, undo, lsn, record, NTFS_WRITE_RECORD_BYTES);
	}
	if (operation == NTFS_LOG_OP_INITIALIZE_FILE_RECORD) {
		if (span.length != NTFS_WRITE_RECORD_BYTES) {
			return NTFS_UNSUPPORTED;
		}
		result = logical_file(payload + span.offset);
		if (result != NTFS_OK) {
			return result;
		}
		ntfs_copy(record, payload + span.offset, span.length);
		ntfs_put_u64(((struct ntfs_disk_record *)record)->lsn, lsn);
		return NTFS_OK;
	}
	if (operation != NTFS_LOG_OP_DEALLOCATE_FILE_RECORD ||
	    update.redo_operation != NTFS_LOG_OP_NOOP ||
	    span.length != sizeof(struct ntfs_disk_mst)) {
		return NTFS_UNSUPPORTED;
	}
	/* A retained inverse can precede any initialization redo. Its exact
	 * unpublished predecessor already has no FILE object to retire. */
	if (ntfs_equal(record, region->before + offset, NTFS_WRITE_RECORD_BYTES)) {
		return NTFS_OK;
	}
	header = (void *)record;
	image = (const void *)(region->after + offset);
	generation = ntfs_u16(image->sequence);
	if (generation == UINT16_MAX) {
		generation = 1;
	} else {
		generation++;
	}
	/* A new-slot inverse consumes the unpublished generation once; repeated
	 * private compensation is idempotent under the owning LSN contract. */
	if (ntfs_u16(header->sequence) != ntfs_u16(image->sequence) &&
	    ntfs_u16(header->sequence) != generation) {
		return NTFS_STALE;
	}
	ntfs_put_u16(header->sequence, generation);
	ntfs_put_u16(header->flags, 0);
	ntfs_copy(&header->mst, payload + span.offset, span.length);
	ntfs_put_u64(header->lsn, lsn);
	return NTFS_OK;
}
