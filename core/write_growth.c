/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_mutation_internal.h"

static enum ntfs_result
zero_range(struct ntfs_write_mutation_plan *plan, const struct ntfs_mutation_record *record,
    const struct ntfs_stream *stream, uint64_t offset, uint64_t bytes)
{
	size_t take;
	enum ntfs_result result;

	ntfs_zero(plan->scratch, NTFS_WRITE_CLUSTER_BYTES);
	while (bytes != 0) {
		take = bytes < NTFS_WRITE_CLUSTER_BYTES ? (size_t)bytes : NTFS_WRITE_CLUSTER_BYTES;
		result = ntfs_mutation_stream_write(plan, record, NTFS_ATTRIBUTE_DATA, NULL, 0,
		    stream, offset, plan->scratch, take, NTFS_WRITE_MUTATION_DATA);
		if (result != NTFS_OK) {
			return result;
		}
		offset += take;
		bytes -= take;
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_mutation_resize(struct ntfs_write_mutation_plan *plan, struct ntfs_mutation_record *record,
    uint64_t size, uint64_t offset, const void *data, size_t bytes)
{
	struct ntfs_stream *before = NULL, *after = NULL;
	struct ntfs_run *runs = NULL;
	uint8_t *value = NULL;
	uint64_t wanted, initialized, old_initialized, clusters, allocated;
	size_t count = 0, copy;
	enum ntfs_result result;

	result = ntfs_mutation_stream(plan, record, NTFS_ATTRIBUTE_DATA, NULL, 0, &before);
	if (result != NTFS_OK) {
		return result;
	}
	wanted = bytes != 0 ? before->size : size;
	if (bytes != 0 && wanted < offset + bytes) {
		wanted = offset + bytes;
	}
	if (bytes == 0 && wanted == before->size) {
		result = NTFS_OK;
		goto done;
	}
	initialized = before->initialized < wanted ? before->initialized : wanted;
	old_initialized = initialized;
	if (bytes != 0 && initialized < offset + bytes) {
		initialized = offset + bytes;
	}
	/* A resident attempt needs only one record-sized private value. A failed
	 * fit is followed by complete mapping preparation, never an in-place resize. */
	if (wanted <= NTFS_WRITE_RECORD_BYTES) {
		value = ntfs_mutation_allocate(plan, (size_t)(wanted == 0 ? 1 : wanted));
		if (value == NULL) {
			result = NTFS_NO_MEMORY;
			goto done;
		}
		copy = (size_t)(before->size < wanted ? before->size : wanted);
		result = ntfs_mutation_stream_read(plan, before, 0, value, copy);
		if (result != NTFS_OK) {
			goto done;
		}
		if (bytes != 0) {
			ntfs_copy(value + offset, data, bytes);
		}
		result = ntfs_mutation_resident(
		    plan, record, NTFS_ATTRIBUTE_DATA, NULL, 0, value, (size_t)wanted, 0);
		if (result == NTFS_OK) {
			result = ntfs_mutation_free_runs(plan, before, 0);
			allocated = 0;
			goto metadata;
		}
		if (result != NTFS_NO_SPACE) {
			goto done;
		}
	}
	clusters = wanted / NTFS_WRITE_CLUSTER_BYTES + (wanted % NTFS_WRITE_CLUSTER_BYTES != 0);
	if (wanted > before->size && !before->resident && clusters < before->clusters) {
		clusters = before->clusters;
	}
	result = ntfs_mutation_resize_runs(plan, before, clusters, &runs, &count);
	if (result == NTFS_OK) {
		result = ntfs_mutation_nonresident(plan, record, NTFS_ATTRIBUTE_DATA, NULL, 0, runs,
		    count, wanted, initialized, 0);
	}
	if (result == NTFS_OK) {
		result = ntfs_mutation_stream(plan, record, NTFS_ATTRIBUTE_DATA, NULL, 0, &after);
	}
	if (result != NTFS_OK) {
		goto done;
	}
	allocated = after->allocated;
	if (before->resident && old_initialized != 0) {
		/* The resident contents must survive storage conversion before the new
		 * initialized length exposes them. Other newly allocated bytes stay
		 * behind VDL until the zero-gap and payload preparations below. */
		result = zero_range(plan, record, after, 0, NTFS_WRITE_CLUSTER_BYTES);
		if (result == NTFS_OK) {
			result = ntfs_mutation_stream_write(plan, record, NTFS_ATTRIBUTE_DATA, NULL,
			    0, after, 0, before->value, (size_t)old_initialized,
			    NTFS_WRITE_MUTATION_DATA);
		}
	}
	if (result == NTFS_OK && bytes != 0 && offset > old_initialized) {
		result = zero_range(plan, record, after, old_initialized, offset - old_initialized);
	}
	if (result == NTFS_OK && bytes != 0) {
		result = ntfs_mutation_stream_write(plan, record, NTFS_ATTRIBUTE_DATA, NULL, 0,
		    after, offset, data, bytes, NTFS_WRITE_MUTATION_DATA);
	}

metadata:
	if (result == NTFS_OK) {
		result = ntfs_mutation_touch(record, plan->filetime, true);
	}
	if (result == NTFS_OK) {
		result = ntfs_mutation_filename_sizes(plan, record, wanted, allocated);
	}

done:
	ntfs_mutation_release(plan, value, (size_t)(wanted == 0 ? 1 : wanted));
	ntfs_mutation_release(plan, runs, NTFS_MUTATION_MAX_RUNS * sizeof(*runs));
	ntfs_stream_close(after);
	ntfs_stream_close(before);
	return result;
}
