/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { TEST_CHARGE_BYTES = 8 };

static bool
same_usage(const struct ntfs_operation_usage *left, const struct ntfs_operation_usage *right)
{
	return left->read_calls == right->read_calls && left->read_bytes == right->read_bytes &&
	    left->allocation_calls == right->allocation_calls &&
	    left->allocation_bytes == right->allocation_bytes && left->work == right->work &&
	    left->peak_live_bytes == right->peak_live_bytes && left->exhausted == right->exhausted;
}

static enum ntfs_result
charge(struct ntfs_volume *volume, enum ntfs_operation_limit dimension, bool optional)
{
	switch (dimension) {
	case NTFS_OPERATION_LIMIT_READ_CALLS:
	case NTFS_OPERATION_LIMIT_READ_BYTES:
		return ntfs_operation_read(volume, TEST_CHARGE_BYTES);
	case NTFS_OPERATION_LIMIT_ALLOCATION_CALLS:
	case NTFS_OPERATION_LIMIT_ALLOCATION_BYTES:
		return ntfs_operation_allocate(volume, TEST_CHARGE_BYTES, optional)
		    ? NTFS_OK
		    : NTFS_NO_MEMORY;
	case NTFS_OPERATION_LIMIT_WORK:
		return ntfs_work(volume, TEST_CHARGE_BYTES);
	default:
		assert(false);
		return NTFS_INVALID;
	}
}

static void
one_charge_limit(struct ntfs_operation_limits *limits, enum ntfs_operation_limit dimension)
{
	switch (dimension) {
	case NTFS_OPERATION_LIMIT_READ_CALLS:
		limits->read_calls = 1;
		break;
	case NTFS_OPERATION_LIMIT_READ_BYTES:
		limits->read_bytes = TEST_CHARGE_BYTES;
		break;
	case NTFS_OPERATION_LIMIT_ALLOCATION_CALLS:
		limits->allocation_calls = 1;
		break;
	case NTFS_OPERATION_LIMIT_ALLOCATION_BYTES:
		limits->allocation_bytes = TEST_CHARGE_BYTES;
		break;
	case NTFS_OPERATION_LIMIT_WORK:
		limits->work = TEST_CHARGE_BYTES;
		break;
	default:
		assert(false);
	}
}

static void
all_ancestors(void)
{
	static const enum ntfs_operation_limit dimensions[] = {NTFS_OPERATION_LIMIT_READ_CALLS,
	    NTFS_OPERATION_LIMIT_READ_BYTES, NTFS_OPERATION_LIMIT_ALLOCATION_CALLS,
	    NTFS_OPERATION_LIMIT_ALLOCATION_BYTES, NTFS_OPERATION_LIMIT_WORK};
	struct ntfs_volume *volume = calloc(1, sizeof(*volume));
	struct ntfs_operation *scopes = calloc(NTFS_OPERATION_MAX_DEPTH, sizeof(*scopes));
	struct ntfs_operation_usage expected = {0};
	struct ntfs_operation_limits limits;
	enum ntfs_operation_limit dimension;
	enum ntfs_result refused;
	size_t index, denied, depth;
	bool allocation;

	assert(volume != NULL && scopes != NULL);
	ntfs_default_limits(&volume->limits);
	for (index = 0; index < sizeof(dimensions) / sizeof(dimensions[0]); index++) {
		dimension = dimensions[index];
		allocation = dimension == NTFS_OPERATION_LIMIT_ALLOCATION_CALLS ||
		    dimension == NTFS_OPERATION_LIMIT_ALLOCATION_BYTES;
		refused = allocation ? NTFS_NO_MEMORY : NTFS_RANGE;
		memset(&expected, 0, sizeof(expected));
		if (allocation) {
			expected.allocation_calls = 1;
			expected.allocation_bytes = TEST_CHARGE_BYTES;
		} else if (dimension == NTFS_OPERATION_LIMIT_WORK) {
			expected.work = TEST_CHARGE_BYTES;
		} else {
			expected.read_calls = 1;
			expected.read_bytes = TEST_CHARGE_BYTES;
		}
		for (denied = 0; denied < NTFS_OPERATION_MAX_DEPTH; denied++) {
			expected.exhausted = NTFS_OPERATION_LIMIT_NONE;
			for (depth = 0; depth < NTFS_OPERATION_MAX_DEPTH; depth++) {
				limits = volume->limits.operation;
				if (depth == denied) {
					one_charge_limit(&limits, dimension);
				}
				assert(ntfs_operation_begin(volume, &limits, &scopes[depth]) ==
				    NTFS_OK);
			}
			assert(charge(volume, dimension, false) == NTFS_OK);
			if (allocation) {
				/* Optional refusal must neither charge a nearer child nor latch
				 * any ancestor. The owner remains admissible afterward. */
				assert(charge(volume, dimension, true) == NTFS_NO_MEMORY);
				for (depth = 0; depth < NTFS_OPERATION_MAX_DEPTH; depth++) {
					assert(same_usage(&scopes[depth].usage, &expected));
				}
				assert(ntfs_operation_check(volume) == NTFS_OK);
			}
			assert(charge(volume, dimension, false) == refused);
			expected.exhausted = dimension;
			for (depth = 0; depth < NTFS_OPERATION_MAX_DEPTH; depth++) {
				assert(same_usage(&scopes[depth].usage, &expected));
			}
			for (depth = NTFS_OPERATION_MAX_DEPTH; depth != 0; depth--) {
				assert(ntfs_operation_check(volume) == refused);
				assert(ntfs_operation_end(&scopes[depth - 1], NULL) == NTFS_OK);
			}
			assert(ntfs_operation_check(volume) == NTFS_OK);
		}
	}
	free(scopes);
	free(volume);
}

static void
saturated_accounting(void)
{
	struct ntfs_volume *volume = calloc(1, sizeof(*volume));
	struct ntfs_operation scope = {0};
	struct ntfs_operation_usage before;

	assert(volume != NULL);
	ntfs_default_limits(&volume->limits);
	volume->limits.operation.work = UINT64_MAX;
	assert(ntfs_operation_begin(volume, NULL, &scope) == NTFS_OK);
	assert(ntfs_work(volume, UINT64_MAX) == NTFS_OK);
	assert(ntfs_work(volume, 1) == NTFS_RANGE);
	assert(
	    scope.usage.work == UINT64_MAX && scope.usage.exhausted == NTFS_OPERATION_LIMIT_WORK);
	assert(ntfs_operation_end(&scope, NULL) == NTFS_OK);

	/* The aggregate owner may be nearly full before this operation starts.
	 * Optional admission refusal preserves every operation field and live byte. */
	volume->limits.max_live_bytes = UINT64_MAX;
	volume->live_bytes = UINT64_MAX - TEST_CHARGE_BYTES;
	assert(ntfs_operation_begin(volume, NULL, &scope) == NTFS_OK);
	assert(ntfs_operation_allocate(volume, TEST_CHARGE_BYTES, false));
	ntfs_operation_allocated(volume, TEST_CHARGE_BYTES);
	assert(volume->live_bytes == UINT64_MAX && scope.usage.peak_live_bytes == UINT64_MAX);
	before = scope.usage;
	assert(!ntfs_operation_allocate(volume, 1, true));
	assert(same_usage(&scope.usage, &before));
	assert(!ntfs_operation_allocate(volume, 1, false));
	assert(scope.usage.exhausted == NTFS_OPERATION_LIMIT_LIVE_BYTES &&
	    scope.usage.allocation_calls == 1 &&
	    scope.usage.allocation_bytes == TEST_CHARGE_BYTES && volume->live_bytes == UINT64_MAX);
	assert(ntfs_operation_end(&scope, NULL) == NTFS_OK);
	free(volume);
}

int
main(void)
{
	all_ancestors();
	saturated_accounting();
	puts("PASS: all 32 denying ancestors across five dimensions; optional refusals, "
	     "unchanged credits, sticky unwind and saturated work/live-byte accounting");
	return 0;
}
