/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "validate_internal.h"

static enum ntfs_result ntfs_validation_sift(struct ntfs_validation_context *validation,
    uint8_t *bytes, size_t stride, uint32_t root, uint32_t count,
    int (*compare)(struct ntfs_validation_context *, const void *, const void *));

void
ntfs_validation_default_limits(struct ntfs_validation_limits *limits)
{
	if (limits != NULL) {
		*limits = (struct ntfs_validation_limits){VALIDATION_DEFAULT_RECORDS,
		    VALIDATION_DEFAULT_RUNS, VALIDATION_DEFAULT_LINKS, VALIDATION_DEFAULT_MEMORY,
		    VALIDATION_DEFAULT_READ_CALLS, VALIDATION_DEFAULT_READ_BYTES,
		    VALIDATION_DEFAULT_WORK};
	}
}

enum ntfs_result
ntfs_validation_limit_failure(
    struct ntfs_validation_context *validation, enum ntfs_validation_limit limit)
{
	if (validation->failure == NTFS_OK) {
		validation->failure = NTFS_RANGE;
		validation->report->exhausted = limit;
	}
	return validation->failure;
}

enum ntfs_result
ntfs_validation_charge(struct ntfs_validation_context *validation, uint64_t units)
{
	if (validation->failure != NTFS_OK) {
		return validation->failure;
	}
	if (units > validation->limits.max_work_units - validation->report->work_units) {
		return ntfs_validation_limit_failure(validation, NTFS_VALIDATION_LIMIT_WORK);
	}
	validation->report->work_units += units;
	return NTFS_OK;
}

void *
ntfs_validation_allocate(void *context, size_t size)
{
	struct ntfs_validation_context *validation = context;
	void *memory;

	if (ntfs_validation_charge(validation, 1) != NTFS_OK) {
		return NULL;
	}
	if (size > validation->limits.max_memory_bytes - validation->memory) {
		ntfs_validation_limit_failure(validation, NTFS_VALIDATION_LIMIT_MEMORY);
		return NULL;
	}
	validation->report->allocation_calls++;
	memory = validation->source.allocate(validation->source.context, size);
	if (memory != NULL) {
		validation->memory += size;
		if (validation->memory > validation->report->peak_memory_bytes) {
			validation->report->peak_memory_bytes = validation->memory;
		}
	}
	return memory;
}

void
ntfs_validation_release(void *context, void *memory, size_t size)
{
	struct ntfs_validation_context *validation = context;

	if (memory != NULL) {
		validation->source.release(validation->source.context, memory, size);
		validation->memory -= size;
	}
}

enum ntfs_result
ntfs_validation_read(void *context, uint64_t offset, void *bytes, size_t size)
{
	struct ntfs_validation_context *validation = context;

	if (validation->failure != NTFS_OK) {
		return validation->failure;
	}
	if (validation->report->read_calls == validation->limits.max_read_calls) {
		return ntfs_validation_limit_failure(validation, NTFS_VALIDATION_LIMIT_READ_CALLS);
	}
	if (size > validation->limits.max_read_bytes - validation->report->read_bytes) {
		return ntfs_validation_limit_failure(validation, NTFS_VALIDATION_LIMIT_READ_BYTES);
	}
	if (ntfs_validation_charge(validation, size) != NTFS_OK) {
		return validation->failure;
	}
	validation->report->read_calls++;
	validation->report->read_bytes += size;
	return validation->source.read(validation->source.context, offset, bytes, size);
}

enum ntfs_result
ntfs_validation_grow(struct ntfs_validation_context *validation, void **buffer, uint32_t *capacity,
    uint32_t needed, size_t element_size, uint32_t maximum, enum ntfs_validation_limit limit)
{
	void *replacement;
	uint32_t next;

	if (needed > maximum) {
		return ntfs_validation_limit_failure(validation, limit);
	}
	if (needed <= *capacity) {
		return NTFS_OK;
	}
	next = *capacity == 0 ? VALIDATION_VECTOR_START : *capacity;
	while (next < needed && next < maximum) {
		next = next > maximum / VALIDATION_VECTOR_GROWTH ? maximum
								 : next * VALIDATION_VECTOR_GROWTH;
	}
	if (next > maximum) {
		next = maximum;
	}
	if (element_size > SIZE_MAX / next) {
		return ntfs_validation_limit_failure(validation, NTFS_VALIDATION_LIMIT_MEMORY);
	}
	replacement = ntfs_validation_allocate(validation, (size_t)next * element_size);
	if (replacement == NULL) {
		return validation->failure != NTFS_OK ? validation->failure : NTFS_NO_MEMORY;
	}
	ntfs_zero(replacement, (size_t)next * element_size);
	ntfs_copy(replacement, *buffer, (size_t)*capacity * element_size);
	ntfs_validation_release(validation, *buffer, (size_t)*capacity * element_size);
	*buffer = replacement;
	*capacity = next;
	return NTFS_OK;
}

static enum ntfs_result
ntfs_validation_sift(struct ntfs_validation_context *validation, uint8_t *bytes, size_t stride,
    uint32_t root, uint32_t count,
    int (*compare)(struct ntfs_validation_context *, const void *, const void *))
{
	union {
		struct ntfs_validation_run run;
		struct ntfs_validation_link link;
	} temporary;

	uint32_t child;
	int comparison;

	while (root < count / VALIDATION_VECTOR_GROWTH) {
		if (ntfs_validation_charge(validation, 1) != NTFS_OK) {
			return validation->failure;
		}
		child = root * VALIDATION_VECTOR_GROWTH + 1;
		if (child + 1 < count) {
			comparison = compare(validation, bytes + (size_t)child * stride,
			    bytes + (size_t)(child + 1) * stride);
			if (validation->failure != NTFS_OK) {
				return validation->failure;
			}
			if (comparison < 0) {
				child++;
			}
		}
		comparison = compare(
		    validation, bytes + (size_t)root * stride, bytes + (size_t)child * stride);
		if (validation->failure != NTFS_OK) {
			return validation->failure;
		}
		if (comparison >= 0) {
			break;
		}
		ntfs_copy(&temporary, bytes + (size_t)root * stride, stride);
		ntfs_copy(bytes + (size_t)root * stride, bytes + (size_t)child * stride, stride);
		ntfs_copy(bytes + (size_t)child * stride, &temporary, stride);
		root = child;
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_validation_sort(struct ntfs_validation_context *validation, void *storage, size_t stride,
    uint32_t count, int (*compare)(struct ntfs_validation_context *, const void *, const void *))
{
	union {
		struct ntfs_validation_run run;
		struct ntfs_validation_link link;
	} temporary;

	uint8_t *bytes = storage;
	uint32_t i;
	enum ntfs_result result;

	for (i = count / VALIDATION_VECTOR_GROWTH; i != 0; i--) {
		result = ntfs_validation_sift(validation, bytes, stride, i - 1, count, compare);
		if (result != NTFS_OK) {
			return result;
		}
	}
	for (i = count; i > 1; i--) {
		ntfs_copy(&temporary, bytes, stride);
		ntfs_copy(bytes, bytes + (size_t)(i - 1) * stride, stride);
		ntfs_copy(bytes + (size_t)(i - 1) * stride, &temporary, stride);
		result = ntfs_validation_sift(validation, bytes, stride, 0, i - 1, compare);
		if (result != NTFS_OK) {
			return result;
		}
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_validate(const struct ntfs_environment *environment, const struct ntfs_limits *core_limits,
    const struct ntfs_validation_limits *limits, struct ntfs_validation_report *report)
{
	struct ntfs_validation_context validation = {0};
	struct ntfs_environment bounded;
	enum ntfs_result result;

	if (report == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(report, sizeof(*report));
	report->result = NTFS_INVALID;
	if (environment == NULL || environment->api_version != NTFS_API_VERSION ||
	    environment->allocate == NULL || environment->release == NULL ||
	    environment->read == NULL) {
		return NTFS_INVALID;
	}
	validation.source = *environment;
	validation.report = report;
	ntfs_validation_default_limits(&validation.limits);
	if (limits != NULL) {
		validation.limits = *limits;
	}
	if (validation.limits.max_records == 0 ||
	    validation.limits.max_records > VALIDATION_DEFAULT_RECORDS ||
	    validation.limits.max_runs == 0 ||
	    validation.limits.max_runs > VALIDATION_DEFAULT_RUNS ||
	    validation.limits.max_links == 0 ||
	    validation.limits.max_links > VALIDATION_DEFAULT_LINKS ||
	    validation.limits.max_memory_bytes == 0 || validation.limits.max_read_calls == 0 ||
	    validation.limits.max_read_bytes == 0 || validation.limits.max_work_units == 0) {
		return NTFS_INVALID;
	}
	bounded = (struct ntfs_environment){NTFS_API_VERSION, &validation, environment->size_bytes,
	    ntfs_validation_read, ntfs_validation_allocate, ntfs_validation_release};
	report->stage = NTFS_VALIDATION_MOUNT;
	result = ntfs_mount(&bounded, core_limits, &validation.volume);
	if (result == NTFS_OK) {
		result = ntfs_validation_scan_records(&validation);
	}
	if (result == NTFS_OK) {
		result = ntfs_validation_scan_attributes(&validation);
	}
	if (result == NTFS_OK) {
		result = ntfs_validation_scan_mirror(&validation);
	}
	if (result == NTFS_OK) {
		result = ntfs_validation_scan_boot(&validation);
	}
	if (result == NTFS_OK) {
		result = ntfs_validation_scan_namespace(&validation);
	}
	if (result == NTFS_OK) {
		result = ntfs_validation_scan_allocation(&validation);
	}
	if (result == NTFS_OK) {
		result = ntfs_validation_scan_security(&validation);
	}
	ntfs_validation_release(&validation, validation.names,
	    (size_t)validation.name_capacity * sizeof(*validation.names));
	ntfs_validation_release(&validation, validation.links,
	    (size_t)validation.link_capacity * sizeof(*validation.links));
	ntfs_validation_release(&validation, validation.runs,
	    (size_t)validation.run_capacity * sizeof(*validation.runs));
	ntfs_validation_release(&validation, validation.records,
	    (size_t)report->record_slots * sizeof(*validation.records));
	if (validation.volume != NULL) {
		enum ntfs_result cleanup = ntfs_unmount(validation.volume);

		if (cleanup != NTFS_OK) {
			result = cleanup;
		}
	}
	if (validation.memory != 0) {
		result = NTFS_CORRUPT;
	}
	if (validation.failure != NTFS_OK) {
		result = validation.failure;
	}
	report->result = result;
	if (result == NTFS_OK) {
		report->stage = NTFS_VALIDATION_FINISHED;
		report->complete = true;
		report->reference = 0;
		report->record_number = 0;
		report->related_reference = 0;
		report->attribute_type = 0;
		report->cluster = 0;
	}
	return result;
}
