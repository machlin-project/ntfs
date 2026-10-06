/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_mutation_internal.h"
#include <ntfs/record.h>

const uint16_t ntfs_mutation_index_name[4] = {'$', 'I', '3', '0'};

static bool
separate(const void *a, size_t a_bytes, const void *b, size_t b_bytes)
{
	uintptr_t left = (uintptr_t)a, right = (uintptr_t)b;

	return (a != NULL || a_bytes == 0) && (b != NULL || b_bytes == 0) &&
	    a_bytes <= UINTPTR_MAX - left && b_bytes <= UINTPTR_MAX - right &&
	    (a_bytes == 0 || b_bytes == 0 || left + a_bytes <= right || right + b_bytes <= left);
}

enum ntfs_result
ntfs_mutation_work(struct ntfs_write_mutation_plan *plan, uint64_t count)
{
	if (count > NTFS_DEFAULT_OPERATION_WORK - plan->work) {
		return NTFS_RANGE;
	}
	plan->work += count;
	return plan->volume == NULL ? NTFS_OK : ntfs_work(plan->volume, count);
}

void *
ntfs_mutation_allocate(struct ntfs_write_mutation_plan *plan, size_t bytes)
{
	void *memory;

	if (bytes == 0 || bytes > NTFS_DEFAULT_MAX_LIVE_BYTES - plan->live_bytes ||
	    plan->allocation_calls == NTFS_DEFAULT_OPERATION_ALLOCATION_CALLS ||
	    bytes > NTFS_DEFAULT_OPERATION_ALLOCATION_BYTES - plan->allocation_bytes) {
		return NULL;
	}
	plan->allocation_calls++;
	plan->allocation_bytes += bytes;
	memory = plan->source.allocate(plan->source.context, bytes);
	if (memory != NULL) {
		plan->live_bytes += bytes;
		ntfs_zero(memory, bytes);
	}
	return memory;
}

void
ntfs_mutation_release(struct ntfs_write_mutation_plan *plan, void *memory, size_t bytes)
{
	if (memory != NULL) {
		plan->live_bytes -= bytes;
		plan->source.release(plan->source.context, memory, bytes);
	}
}

static void *
view_allocate(void *context, size_t bytes)
{
	return ntfs_mutation_allocate(context, bytes);
}

static void
view_release(void *context, void *memory, size_t bytes)
{
	ntfs_mutation_release(context, memory, bytes);
}

static enum ntfs_result
source_read(void *context, uint64_t offset, void *memory, size_t bytes)
{
	struct ntfs_write_mutation_plan *plan = context;

	if (bytes == 0) {
		return NTFS_OK;
	}
	if (!ntfs_bounds(offset, bytes, plan->source.size_bytes) ||
	    plan->read_calls == NTFS_DEFAULT_OPERATION_READ_CALLS ||
	    bytes > NTFS_DEFAULT_OPERATION_READ_BYTES - plan->read_bytes) {
		return NTFS_RANGE;
	}
	plan->read_calls++;
	plan->read_bytes += bytes;
	return plan->source.read(plan->source.context, offset, memory, bytes);
}

enum ntfs_result
ntfs_mutation_read(
    struct ntfs_write_mutation_plan *plan, uint64_t offset, void *memory, size_t bytes)
{
	const struct ntfs_mutation_patch *patch;
	uint64_t first, end;
	size_t index;
	enum ntfs_result result;

	if (!ntfs_bounds(offset, bytes, plan->source.size_bytes)) {
		return NTFS_RANGE;
	}
	result = ntfs_mutation_work(plan, plan->patch_count);
	if (result == NTFS_OK) {
		result = source_read(plan, offset, memory, bytes);
	}
	if (result != NTFS_OK) {
		return result;
	}
	for (index = 0; index < plan->patch_count; index++) {
		patch = plan->patches[index];
		first = offset > patch->physical ? offset : patch->physical;
		end = offset + bytes < patch->physical + NTFS_WRITE_CLUSTER_BYTES
		    ? offset + bytes
		    : patch->physical + NTFS_WRITE_CLUSTER_BYTES;
		if (first < end) {
			ntfs_copy((uint8_t *)memory + first - offset,
			    patch->after + first - patch->physical, (size_t)(end - first));
		}
	}
	return NTFS_OK;
}

static enum ntfs_result
view_read(void *context, uint64_t offset, void *memory, size_t bytes)
{
	return ntfs_mutation_read(context, offset, memory, bytes);
}

enum ntfs_result
ntfs_mutation_patch(struct ntfs_write_mutation_plan *plan, uint64_t physical,
    enum ntfs_write_mutation_region_kind kind, struct ntfs_mutation_patch **out)
{
	struct ntfs_mutation_patch **pointers, *patch;
	size_t index, capacity;
	enum ntfs_result result;

	*out = NULL;
	if (plan->sealed || physical % NTFS_WRITE_CLUSTER_BYTES != 0 ||
	    !ntfs_bounds(physical, NTFS_WRITE_CLUSTER_BYTES, plan->info.size_bytes)) {
		return NTFS_RANGE;
	}
	for (index = 0; index < plan->patch_count; index++) {
		patch = plan->patches[index];
		if (patch->physical == physical) {
			if (kind != patch->kind) {
				return NTFS_CORRUPT;
			}
			*out = patch;
			return NTFS_OK;
		}
	}
	if (plan->patch_count == NTFS_MUTATION_MAX_REGIONS) {
		return NTFS_RANGE;
	}
	if (plan->patch_count == plan->patch_capacity) {
		capacity = plan->patch_capacity == 0 ? NTFS_MUTATION_INITIAL_REGIONS
						     : plan->patch_capacity * NTFS_VECTOR_GROWTH;
		pointers = ntfs_mutation_allocate(plan, capacity * sizeof(*pointers));
		if (pointers == NULL) {
			return NTFS_NO_MEMORY;
		}
		ntfs_copy(pointers, plan->patches, plan->patch_count * sizeof(*pointers));
		ntfs_mutation_release(
		    plan, plan->patches, plan->patch_capacity * sizeof(*pointers));
		plan->patches = pointers;
		plan->patch_capacity = capacity;
	}
	patch = ntfs_mutation_allocate(plan, sizeof(*patch));
	if (patch == NULL) {
		return NTFS_NO_MEMORY;
	}
	result = source_read(plan, physical, patch->before, sizeof(patch->before));
	if (result != NTFS_OK) {
		ntfs_mutation_release(plan, patch, sizeof(*patch));
		return result;
	}
	ntfs_copy(patch->after, patch->before, sizeof(patch->after));
	patch->physical = physical;
	patch->kind = kind;
	plan->patches[plan->patch_count++] = patch;
	*out = patch;
	return NTFS_OK;
}

static bool
same_target(
    const struct ntfs_write_mutation_target *left, const struct ntfs_write_mutation_target *right)
{
	return left->reference == right->reference &&
	    left->logical_offset == right->logical_offset &&
	    left->attribute_type == right->attribute_type &&
	    left->name_count == right->name_count && left->mirror == right->mirror &&
	    ntfs_equal(left->name, right->name, sizeof(left->name));
}

static enum ntfs_result
file_predecessors(struct ntfs_write_mutation_plan *plan, struct ntfs_mutation_patch *patch,
    const struct ntfs_write_mutation_target *target)
{
	const struct ntfs_stream *original = plan->volume->mft;
	const struct ntfs_run *run;
	uint64_t logical, vcn, physical;
	size_t slot, offset;

	for (slot = 0; slot < NTFS_WRITE_CLUSTER_BYTES / NTFS_WRITE_RECORD_BYTES; slot++) {
		offset = slot * NTFS_WRITE_RECORD_BYTES;
		logical = target->logical_offset + offset;
		if (!ntfs_bounds(logical, NTFS_WRITE_RECORD_BYTES, original->initialized)) {
			continue;
		}
		if (target->mirror) {
			if (logical >= NTFS_MFT_MIRROR_REQUIRED_RECORDS * NTFS_WRITE_RECORD_BYTES) {
				return NTFS_CORRUPT;
			}
			physical = plan->volume->mirror_lcn * NTFS_WRITE_CLUSTER_BYTES + logical;
		} else {
			vcn = logical / NTFS_WRITE_CLUSTER_BYTES;
			run = ntfs_run_find(original, vcn);
			if (run == NULL || run->lcn == NTFS_HOLE) {
				return NTFS_CORRUPT;
			}
			physical = (run->lcn + vcn - run->vcn) * NTFS_WRITE_CLUSTER_BYTES +
			    logical % NTFS_WRITE_CLUSTER_BYTES;
		}
		if (physical != patch->physical + offset) {
			return NTFS_CORRUPT;
		}
		if (ntfs_equal(patch->before + offset, "FILE",
			sizeof(((struct ntfs_disk_mst *)0)->magic))) {
			patch->predecessor.file_slots |= (uint8_t)(1u << slot);
		}
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_mutation_write(struct ntfs_write_mutation_plan *plan, uint64_t physical, const void *memory,
    size_t bytes, enum ntfs_write_mutation_region_kind kind,
    const struct ntfs_write_mutation_target *target)
{
	struct ntfs_mutation_patch *patch;
	struct ntfs_write_mutation_target current;
	size_t offset, take;
	enum ntfs_result result;

	if (target == NULL || target->reference >> NTFS_REFERENCE_SEQUENCE_SHIFT == 0 ||
	    target->name_count > NTFS_WRITE_MUTATION_TARGET_NAME_UNITS ||
	    target->logical_offset % NTFS_WRITE_CLUSTER_BYTES !=
		physical % NTFS_WRITE_CLUSTER_BYTES ||
	    !ntfs_bounds(target->logical_offset, bytes, INT64_MAX) ||
	    !ntfs_bounds(physical, bytes, plan->info.size_bytes)) {
		return NTFS_RANGE;
	}
	current = *target;
	while (bytes != 0) {
		offset = (size_t)(physical % NTFS_WRITE_CLUSTER_BYTES);
		take = bytes < NTFS_WRITE_CLUSTER_BYTES - offset
		    ? bytes
		    : NTFS_WRITE_CLUSTER_BYTES - offset;
		result = ntfs_mutation_patch(plan, physical - offset, kind, &patch);
		if (result != NTFS_OK) {
			return result;
		}
		current.logical_offset -= offset;
		if (patch->bound && !same_target(&patch->target, &current)) {
			return NTFS_CORRUPT;
		}
		if (!patch->bound && kind == NTFS_WRITE_MUTATION_FILE) {
			result = file_predecessors(plan, patch, &current);
			if (result != NTFS_OK) {
				return result;
			}
		}
		patch->target = current;
		patch->bound = true;
		ntfs_copy(patch->after + offset, memory, take);
		current.logical_offset += offset + take;
		physical += take;
		memory = (const uint8_t *)memory + take;
		bytes -= take;
	}
	return NTFS_OK;
}

static bool
valid_name(const struct ntfs_write_name *name)
{
	size_t index;
	uint16_t unit;

	if (name->units == NULL || name->count == 0 || name->count > NTFS_NAME_MAX ||
	    name->parent_reference >> NTFS_REFERENCE_SEQUENCE_SHIFT == 0 ||
	    name->count * NTFS_UTF16_UNIT_BYTES > UINTPTR_MAX - (uintptr_t)name->units) {
		return false;
	}
	for (index = 0; index < name->count; index++) {
		unit = name->units[index];
		if (unit == 0 || unit == '/' || unit == '\\' || unit == ':') {
			return false;
		}
	}
	return !(name->units[0] == '.' &&
	    (name->count == 1 || (name->count == 2 && name->units[1] == '.')));
}

static bool
valid_request(const struct ntfs_write_mutation_request *request)
{
	if (request->filetime > INT64_MAX || request->kind > NTFS_WRITE_RENAME ||
	    request->kind < NTFS_WRITE_CREATE_FILE) {
		return false;
	}
	switch (request->kind) {
	case NTFS_WRITE_RESIZE_FILE:
		return request->reference >> NTFS_REFERENCE_SEQUENCE_SHIFT != 0 &&
		    request->size <= INT64_MAX;
	case NTFS_WRITE_GROWING_RANGE:
		return request->reference >> NTFS_REFERENCE_SEQUENCE_SHIFT != 0 &&
		    (request->data != NULL || request->bytes == 0) &&
		    request->bytes <= NTFS_OVERWRITE_MAX_BYTES && request->offset <= INT64_MAX &&
		    request->bytes <= (uint64_t)INT64_MAX - request->offset &&
		    request->bytes <= UINTPTR_MAX - (uintptr_t)request->data;
	case NTFS_WRITE_RENAME:
		return valid_name(&request->source) && valid_name(&request->destination);
	case NTFS_WRITE_CREATE_FILE:
	case NTFS_WRITE_CREATE_DIRECTORY:
	case NTFS_WRITE_REMOVE_FILE:
	case NTFS_WRITE_REMOVE_DIRECTORY:
		return valid_name(&request->source);
	}
	return false;
}

static enum ntfs_result
initialize(struct ntfs_write_mutation_plan *plan)
{
	struct ntfs_environment reader;
	struct ntfs_limits limits;
	struct ntfs_mutation_record *mft;
	enum ntfs_result result;

	reader = (struct ntfs_environment){NTFS_API_VERSION, plan, plan->source.size_bytes,
	    source_read, view_allocate, view_release};
	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	result = ntfs_mount(&reader, &limits, &plan->volume);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_operation_enter(plan->volume);
	if (result != NTFS_OK) {
		return result;
	}
	plan->operation_active = true;
	ntfs_get_info(plan->volume, &plan->info);
	if (plan->info.sector_size != NTFS_WRITE_SECTOR_BYTES ||
	    plan->info.cluster_size != NTFS_WRITE_CLUSTER_BYTES ||
	    plan->info.record_size != NTFS_WRITE_RECORD_BYTES ||
	    plan->info.index_size != NTFS_WRITE_CLUSTER_BYTES ||
	    plan->info.major_version != NTFS_VOLUME_MAJOR_VERSION ||
	    plan->info.minor_version != NTFS_VOLUME_MAX_MINOR_VERSION) {
		return NTFS_UNSUPPORTED;
	}
	plan->scratch = ntfs_mutation_allocate(plan, NTFS_WRITE_CLUSTER_BYTES);
	plan->protected_record = ntfs_mutation_allocate(plan, NTFS_WRITE_CLUSTER_BYTES);
	plan->guard = ntfs_mutation_allocate(plan, sizeof(*plan->guard));
	if (plan->scratch == NULL || plan->protected_record == NULL || plan->guard == NULL) {
		return NTFS_NO_MEMORY;
	}
	/* The original MFT map owns initial record acquisition. A separate decoded
	 * map subsequently follows complete private record-zero replacements. */
	plan->mft = plan->volume->mft;
	result = ntfs_mutation_record_get(plan, NTFS_MFT_RECORD, true, &mft);
	plan->mft = NULL;
	if (result == NTFS_OK) {
		result = ntfs_mutation_stream(plan, mft, NTFS_ATTRIBUTE_DATA, NULL, 0, &plan->mft);
	}
	if (result == NTFS_OK) {
		result = ntfs_mutation_bitmap_open(
		    plan, &plan->allocation, NTFS_BITMAP_RECORD, NTFS_ATTRIBUTE_DATA);
	}
	if (result == NTFS_OK) {
		result = ntfs_mutation_bitmap_open(
		    plan, &plan->mft_bitmap, NTFS_MFT_RECORD, NTFS_ATTR_BITMAP);
	}
	return result;
}

static enum ntfs_result
seal(struct ntfs_write_mutation_plan *plan)
{
	struct ntfs_mutation_record *record;
	struct ntfs_mutation_record *mft;
	struct ntfs_mutation_patch *patch;
	struct ntfs_write_mutation_target target = {0};
	const uint8_t *before;
	uint64_t physical;
	size_t index, kept = 0, offset;
	enum ntfs_result result;

	result = ntfs_mutation_bitmap_flush(plan, &plan->mft_bitmap);
	if (result == NTFS_OK) {
		result = ntfs_mutation_bitmap_flush(plan, &plan->allocation);
	}
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_mutation_record_get(plan, NTFS_MFT_RECORD, true, &mft);
	if (result != NTFS_OK) {
		return result;
	}
	target.reference = mft->reference;
	target.attribute_type = NTFS_ATTRIBUTE_DATA;
	for (index = 0; index < plan->record_count; index++) {
		record = plan->records[index];
		if (!record->changed) {
			continue;
		}
		physical = record->physical & ~(uint64_t)(NTFS_WRITE_CLUSTER_BYTES - 1u);
		offset = (size_t)(record->physical - physical);
		target.logical_offset = record->number * NTFS_WRITE_RECORD_BYTES;
		target.mirror = false;
		result = ntfs_mutation_patch(plan, physical, NTFS_WRITE_MUTATION_FILE, &patch);
		if (result != NTFS_OK) {
			return result;
		}
		before = patch->before + offset;
		result = ntfs_record_protect(record->bytes, NTFS_WRITE_RECORD_BYTES,
		    plan->protected_record, NTFS_WRITE_CLUSTER_BYTES);
		if (result == NTFS_OK) {
			result = ntfs_write_guard_frame(
			    before, NTFS_WRITE_RECORD_BYTES, plan->protected_record, plan->guard);
		}
		if (result == NTFS_OK) {
			result = ntfs_mutation_write(plan, record->physical, plan->protected_record,
			    NTFS_WRITE_RECORD_BYTES, NTFS_WRITE_MUTATION_FILE, &target);
		}
		if (result == NTFS_OK && record->number < NTFS_MFT_MIRROR_REQUIRED_RECORDS) {
			physical = plan->volume->mirror_lcn * NTFS_WRITE_CLUSTER_BYTES +
			    record->number * NTFS_WRITE_RECORD_BYTES;
			target.mirror = true;
			result = ntfs_mutation_patch(
			    plan, physical - offset, NTFS_WRITE_MUTATION_FILE, &patch);
			if (result == NTFS_OK) {
				result = ntfs_write_guard_frame(patch->before + offset,
				    NTFS_WRITE_RECORD_BYTES, plan->protected_record, plan->guard);
			}
			if (result == NTFS_OK) {
				result = ntfs_mutation_write(plan, physical, plan->protected_record,
				    NTFS_WRITE_RECORD_BYTES, NTFS_WRITE_MUTATION_FILE, &target);
			}
		}
		if (result != NTFS_OK) {
			return result;
		}
	}
	for (index = 0; index < plan->patch_count; index++) {
		if (!plan->patches[index]->bound &&
		    !ntfs_equal(plan->patches[index]->before, plan->patches[index]->after,
			NTFS_WRITE_CLUSTER_BYTES)) {
			return NTFS_CORRUPT;
		}
	}
	for (index = 0; index < plan->patch_count; index++) {
		patch = plan->patches[index];
		if (ntfs_equal(patch->before, patch->after, NTFS_WRITE_CLUSTER_BYTES)) {
			ntfs_mutation_release(plan, patch, sizeof(*patch));
		} else {
			plan->patches[kept++] = patch;
		}
	}
	plan->patch_count = kept;
	plan->sealed = true;
	return NTFS_OK;
}

enum ntfs_result
ntfs_write_mutation_prepare(const struct ntfs_environment *source,
    const struct ntfs_write_mutation_request *request, struct ntfs_write_mutation_plan **out)
{
	struct ntfs_write_mutation_plan *plan;
	struct ntfs_mutation_record *record;
	enum ntfs_result result;

	if (out == NULL || sizeof(*out) > UINTPTR_MAX - (uintptr_t)out ||
	    (source != NULL && !separate(source, sizeof(*source), out, sizeof(*out))) ||
	    (request != NULL && !separate(request, sizeof(*request), out, sizeof(*out)))) {
		return NTFS_INVALID;
	}
	if (source == NULL || request == NULL || source->api_version != NTFS_API_VERSION ||
	    source->allocate == NULL || source->release == NULL || source->read == NULL ||
	    !valid_request(request)) {
		*out = NULL;
		return NTFS_INVALID;
	}
	/* Admit every borrowed range before clearing output. Caller mistakes cannot
	 * overwrite the request, name, payload or source capability being inspected. */
	if ((request->kind != NTFS_WRITE_RESIZE_FILE && request->kind != NTFS_WRITE_GROWING_RANGE &&
		!separate(request->source.units, request->source.count * NTFS_UTF16_UNIT_BYTES, out,
		    sizeof(*out))) ||
	    (request->kind == NTFS_WRITE_RENAME &&
		!separate(request->destination.units,
		    request->destination.count * NTFS_UTF16_UNIT_BYTES, out, sizeof(*out))) ||
	    (request->kind == NTFS_WRITE_GROWING_RANGE &&
		!separate(request->data, request->bytes, out, sizeof(*out)))) {
		return NTFS_INVALID;
	}
	*out = NULL;
	plan = source->allocate(source->context, sizeof(*plan));
	if (plan == NULL) {
		return NTFS_NO_MEMORY;
	}
	ntfs_zero(plan, sizeof(*plan));
	plan->source = *source;
	plan->live_bytes = sizeof(*plan);
	plan->filetime = request->filetime;
	result = initialize(plan);
	if (result == NTFS_OK &&
	    (request->kind == NTFS_WRITE_RESIZE_FILE ||
		request->kind == NTFS_WRITE_GROWING_RANGE)) {
		result = ntfs_mutation_record_get(plan, request->reference, false, &record);
		if (result == NTFS_OK) {
			result = ntfs_mutation_record_admit(record, false, false);
		}
		if (result == NTFS_OK) {
			plan->reference = record->reference;
			if (request->kind != NTFS_WRITE_GROWING_RANGE || request->bytes != 0) {
				result = ntfs_mutation_resize(plan, record, request->size,
				    request->offset, request->data, request->bytes);
			}
		}
	} else if (result == NTFS_OK) {
		result = ntfs_mutation_namespace(plan, request);
	}
	if (result == NTFS_OK) {
		result = seal(plan);
	}
	if (plan->operation_active) {
		ntfs_operation_leave(plan->volume);
		plan->operation_active = false;
	}
	if (result != NTFS_OK) {
		ntfs_write_mutation_plan_close(plan);
		return result;
	}
	*out = plan;
	return NTFS_OK;
}

static bool
plan_output_separate(const struct ntfs_write_mutation_plan *plan, const void *out, size_t bytes)
{
	size_t index;

	if (!separate(plan, sizeof(*plan), out, bytes) ||
	    !separate(plan->patches, plan->patch_capacity * sizeof(*plan->patches), out, bytes) ||
	    !separate(plan->records, plan->record_capacity * sizeof(*plan->records), out, bytes) ||
	    !separate(plan->scratch, NTFS_WRITE_CLUSTER_BYTES, out, bytes) ||
	    !separate(plan->protected_record, NTFS_WRITE_CLUSTER_BYTES, out, bytes) ||
	    !separate(plan->guard, sizeof(*plan->guard), out, bytes)) {
		return false;
	}
	for (index = 0; index < plan->patch_count; index++) {
		if (!separate(plan->patches[index], sizeof(*plan->patches[index]), out, bytes)) {
			return false;
		}
	}
	for (index = 0; index < plan->record_count; index++) {
		if (!separate(plan->records[index], sizeof(*plan->records[index]), out, bytes)) {
			return false;
		}
	}
	return true;
}

enum ntfs_result
ntfs_write_mutation_plan_view(
    const struct ntfs_write_mutation_plan *plan, struct ntfs_environment *out)
{
	if (plan == NULL || !plan->sealed || out == NULL) {
		return NTFS_INVALID;
	}
	if (!plan_output_separate(plan, out, sizeof(*out))) {
		return NTFS_INVALID;
	}
	*out = (struct ntfs_environment){NTFS_API_VERSION, (void *)plan, plan->source.size_bytes,
	    view_read, view_allocate, view_release};
	return NTFS_OK;
}

size_t
ntfs_write_mutation_plan_count(const struct ntfs_write_mutation_plan *plan)
{
	return plan == NULL || !plan->sealed ? 0 : plan->patch_count;
}

uint64_t
ntfs_write_mutation_plan_reference(const struct ntfs_write_mutation_plan *plan)
{
	return plan == NULL || !plan->sealed ? 0 : plan->reference;
}

enum ntfs_result
ntfs_write_mutation_plan_region(const struct ntfs_write_mutation_plan *plan, size_t index,
    struct ntfs_write_mutation_region *out)
{
	const struct ntfs_mutation_patch *patch;

	if (plan == NULL || !plan->sealed || out == NULL) {
		return NTFS_INVALID;
	}
	if (!plan_output_separate(plan, out, sizeof(*out))) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (index >= plan->patch_count) {
		return NTFS_END;
	}
	patch = plan->patches[index];
	*out = (struct ntfs_write_mutation_region){.physical = patch->physical,
	    .before = patch->before,
	    .after = patch->after,
	    .bytes = NTFS_WRITE_CLUSTER_BYTES,
	    .kind = patch->kind,
	    .target = patch->target,
	    .predecessor = patch->predecessor};
	return NTFS_OK;
}

static void
close_bitmap(struct ntfs_write_mutation_plan *plan, struct ntfs_mutation_bitmap *bitmap)
{
	ntfs_stream_close(bitmap->stream);
	ntfs_mutation_release(plan, bitmap->before, bitmap->bytes);
	ntfs_mutation_release(plan, bitmap->after, bitmap->bytes);
}

void
ntfs_write_mutation_plan_close(struct ntfs_write_mutation_plan *plan)
{
	struct ntfs_environment source;
	size_t index;

	if (plan == NULL) {
		return;
	}
	source = plan->source;
	if (plan->operation_active) {
		ntfs_operation_leave(plan->volume);
		plan->operation_active = false;
	}
	close_bitmap(plan, &plan->allocation);
	close_bitmap(plan, &plan->mft_bitmap);
	if (plan->mft != NULL && plan->volume != NULL && plan->mft != plan->volume->mft) {
		ntfs_stream_close(plan->mft);
	}
	for (index = 0; index < plan->record_count; index++) {
		ntfs_mutation_release(plan, plan->records[index], sizeof(*plan->records[index]));
	}
	for (index = 0; index < plan->patch_count; index++) {
		ntfs_mutation_release(plan, plan->patches[index], sizeof(*plan->patches[index]));
	}
	ntfs_mutation_release(plan, plan->records, plan->record_capacity * sizeof(*plan->records));
	ntfs_mutation_release(plan, plan->patches, plan->patch_capacity * sizeof(*plan->patches));
	ntfs_mutation_release(plan, plan->scratch, NTFS_WRITE_CLUSTER_BYTES);
	ntfs_mutation_release(plan, plan->protected_record, NTFS_WRITE_CLUSTER_BYTES);
	ntfs_mutation_release(plan, plan->guard, sizeof(*plan->guard));
	if (plan->volume != NULL) {
		(void)ntfs_unmount(plan->volume);
	}
	source.release(source.context, plan, sizeof(*plan));
}
