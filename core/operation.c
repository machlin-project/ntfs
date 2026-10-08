/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"

void
ntfs_operation_default_limits(struct ntfs_operation_limits *limits)
{
	limits->read_calls = NTFS_DEFAULT_OPERATION_READ_CALLS;
	limits->read_bytes = NTFS_DEFAULT_OPERATION_READ_BYTES;
	limits->allocation_calls = NTFS_DEFAULT_OPERATION_ALLOCATION_CALLS;
	limits->allocation_bytes = NTFS_DEFAULT_OPERATION_ALLOCATION_BYTES;
	limits->work = NTFS_DEFAULT_OPERATION_WORK;
}

bool
ntfs_operation_limits_valid(const struct ntfs_operation_limits *limits)
{
	return limits->read_calls != 0 && limits->read_bytes != 0 &&
	    limits->allocation_calls != 0 && limits->allocation_bytes != 0 && limits->work != 0;
}

static enum ntfs_result
operation_limit_result(enum ntfs_operation_limit limit)
{
	if (limit == NTFS_OPERATION_LIMIT_NONE) {
		return NTFS_OK;
	}
	return limit == NTFS_OPERATION_LIMIT_ALLOCATION_CALLS ||
		limit == NTFS_OPERATION_LIMIT_ALLOCATION_BYTES ||
		limit == NTFS_OPERATION_LIMIT_LIVE_BYTES
	    ? NTFS_NO_MEMORY
	    : NTFS_RANGE;
}

static enum ntfs_result
operation_exhausted(const struct ntfs_volume *volume)
{
	const struct ntfs_operation *operation = volume->operation;

	/* Required refusal latches every active ancestor, and begin rejects an
	 * exhausted parent. The head therefore carries the whole stack's result.
	 * Admission still preflights every ancestor before committing any credit. */
	return operation == NULL ? NTFS_OK : operation_limit_result(operation->usage.exhausted);
}

enum ntfs_result
ntfs_operation_check(const struct ntfs_volume *volume)
{
	return volume == NULL ? NTFS_INVALID : operation_exhausted(volume);
}

enum ntfs_result
ntfs_operation_result(const struct ntfs_operation *operation)
{
	return operation == NULL ? NTFS_INVALID
				 : operation_limit_result(operation->usage.exhausted);
}

static enum ntfs_result
operation_refuse(struct ntfs_volume *volume, enum ntfs_operation_limit limit, bool optional)
{
	struct ntfs_operation *operation;

	if (!optional) {
		for (operation = volume->operation; operation != NULL;
		    operation = operation->_previous) {
			if (operation->usage.exhausted == NTFS_OPERATION_LIMIT_NONE) {
				operation->usage.exhausted = limit;
			}
		}
	}
	return operation_limit_result(limit);
}

void
ntfs_get_operation_limits(const struct ntfs_volume *volume, struct ntfs_operation_limits *out)
{
	if (out != NULL) {
		ntfs_zero(out, sizeof(*out));
		if (volume != NULL) {
			*out = volume->limits.operation;
		}
	}
}

void
ntfs_get_operation_usage(const struct ntfs_volume *volume, struct ntfs_operation_usage *out)
{
	if (out != NULL) {
		ntfs_zero(out, sizeof(*out));
		if (volume != NULL) {
			*out = volume->last_operation;
		}
	}
}

enum ntfs_result
ntfs_operation_begin(struct ntfs_volume *volume, const struct ntfs_operation_limits *limits,
    struct ntfs_operation *operation)
{
	struct ntfs_operation_limits selected;
	enum ntfs_result result;

	if (volume == NULL || operation == NULL) {
		return NTFS_INVALID;
	}
	if (operation->_active || volume->operation_calls != 0 ||
	    volume->operation_scopes == NTFS_OPERATION_MAX_DEPTH) {
		return NTFS_BUSY;
	}
	selected = limits == NULL ? volume->limits.operation : *limits;
	if (!ntfs_operation_limits_valid(&selected) ||
	    selected.read_calls > volume->limits.operation.read_calls ||
	    selected.read_bytes > volume->limits.operation.read_bytes ||
	    selected.allocation_calls > volume->limits.operation.allocation_calls ||
	    selected.allocation_bytes > volume->limits.operation.allocation_bytes ||
	    selected.work > volume->limits.operation.work) {
		return NTFS_INVALID;
	}
	result = operation_exhausted(volume);
	if (result != NTFS_OK) {
		return result;
	}
	/* All other fields are assigned below; only usage requires clearing. */
	ntfs_zero(&operation->usage, sizeof(operation->usage));
	operation->limits = selected;
	operation->usage.peak_live_bytes = volume->live_bytes;
	operation->_volume = volume;
	operation->_previous = volume->operation;
	operation->_active = true;
	volume->operation = operation;
	volume->operation_scopes++;
	return NTFS_OK;
}

enum ntfs_result
ntfs_operation_end(struct ntfs_operation *operation, struct ntfs_operation_usage *usage)
{
	struct ntfs_volume *volume;

	if (operation == NULL || !operation->_active) {
		return NTFS_INVALID;
	}
	volume = operation->_volume;
	if (volume != NULL) {
		if (volume->operation != operation || volume->operation_calls != 0) {
			return NTFS_BUSY;
		}
		volume->last_operation = operation->usage;
		volume->operation = operation->_previous;
		volume->operation_scopes--;
	}
	if (usage != NULL) {
		*usage = operation->usage;
	}
	operation->_volume = NULL;
	operation->_previous = NULL;
	operation->_active = false;
	return NTFS_OK;
}

enum ntfs_result
ntfs_operation_enter(struct ntfs_volume *volume)
{
	enum ntfs_result result;

	if (volume == NULL) {
		return NTFS_INVALID;
	}
	if (volume->operation_calls == NTFS_OPERATION_MAX_DEPTH) {
		return NTFS_BUSY;
	}
	if (volume->operation == NULL) {
		result = ntfs_operation_begin(volume, NULL, &volume->implicit_operation);
		if (result != NTFS_OK) {
			return result;
		}
	}
	result = operation_exhausted(volume);
	if (result != NTFS_OK) {
		return result;
	}
	volume->operation_calls++;
	return NTFS_OK;
}

void
ntfs_operation_leave(struct ntfs_volume *volume)
{
	volume->operation_calls--;
	if (volume->operation_calls == 0 && volume->operation == &volume->implicit_operation) {
		(void)ntfs_operation_end(&volume->implicit_operation, NULL);
	}
}

void
ntfs_operation_detach(struct ntfs_volume *volume)
{
	struct ntfs_operation *operation, *previous;

	for (operation = volume->operation; operation != NULL; operation = previous) {
		previous = operation->_previous;
		operation->_volume = NULL;
		operation->_previous = NULL;
	}
	volume->operation = NULL;
	volume->operation_scopes = 0;
}

enum ntfs_result
ntfs_operation_read(struct ntfs_volume *volume, size_t size)
{
	struct ntfs_operation *operation;
	enum ntfs_result result;

	result = operation_exhausted(volume);
	if (result != NTFS_OK) {
		return result;
	}
	/* Check every dimension/ancestor before committing any callback credit. */
	for (operation = volume->operation; operation != NULL; operation = operation->_previous) {
		if (operation->usage.read_calls == operation->limits.read_calls) {
			return operation_refuse(volume, NTFS_OPERATION_LIMIT_READ_CALLS, false);
		}
		if (size > operation->limits.read_bytes - operation->usage.read_bytes) {
			return operation_refuse(volume, NTFS_OPERATION_LIMIT_READ_BYTES, false);
		}
	}
	for (operation = volume->operation; operation != NULL; operation = operation->_previous) {
		operation->usage.read_calls++;
		operation->usage.read_bytes += size;
	}
	return NTFS_OK;
}

bool
ntfs_operation_allocate(struct ntfs_volume *volume, size_t size, bool optional)
{
	struct ntfs_operation *operation;

	if (operation_exhausted(volume) != NTFS_OK) {
		return false;
	}
	if (size > volume->limits.max_live_bytes - volume->live_bytes) {
		(void)operation_refuse(volume, NTFS_OPERATION_LIMIT_LIVE_BYTES, optional);
		return false;
	}
	for (operation = volume->operation; operation != NULL; operation = operation->_previous) {
		if (operation->usage.allocation_calls == operation->limits.allocation_calls) {
			(void)operation_refuse(
			    volume, NTFS_OPERATION_LIMIT_ALLOCATION_CALLS, optional);
			return false;
		}
		if (size > operation->limits.allocation_bytes - operation->usage.allocation_bytes) {
			(void)operation_refuse(
			    volume, NTFS_OPERATION_LIMIT_ALLOCATION_BYTES, optional);
			return false;
		}
	}
	for (operation = volume->operation; operation != NULL; operation = operation->_previous) {
		operation->usage.allocation_calls++;
		operation->usage.allocation_bytes += size;
	}
	return true;
}

void
ntfs_operation_allocated(struct ntfs_volume *volume, size_t size)
{
	struct ntfs_operation *operation;

	volume->live_bytes += size;
	for (operation = volume->operation; operation != NULL; operation = operation->_previous) {
		if (volume->live_bytes > operation->usage.peak_live_bytes) {
			operation->usage.peak_live_bytes = volume->live_bytes;
		}
	}
}

enum ntfs_result
ntfs_work(struct ntfs_volume *volume, uint64_t count)
{
	struct ntfs_operation *operation;
	enum ntfs_result result;

	result = operation_exhausted(volume);
	if (result != NTFS_OK) {
		return result;
	}
	for (operation = volume->operation; operation != NULL; operation = operation->_previous) {
		if (count > operation->limits.work - operation->usage.work) {
			return operation_refuse(volume, NTFS_OPERATION_LIMIT_WORK, false);
		}
	}
	for (operation = volume->operation; operation != NULL; operation = operation->_previous) {
		operation->usage.work += count;
	}
	return NTFS_OK;
}
