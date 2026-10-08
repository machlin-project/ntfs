/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_sparse.h"
#include "fuzz_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_CLUSTER_BYTES = 512,
	TEST_LOGICAL_CLUSTERS = 5,
	TEST_PHYSICAL_CLUSTERS = 16,
	TEST_PATTERNS = 243,
	TEST_ENDPOINTS = TEST_LOGICAL_CLUSTERS * 3 + 1,
	TEST_PATTERN_MULTIPLIER = 37,
	TEST_PATTERN_BIAS = 19
};

static size_t checked;

static void
expand(const struct ntfs_run *runs, size_t count, uint64_t *map, size_t clusters)
{
	size_t index;
	uint64_t offset, next = 0;

	for (index = 0; index < count; index++) {
		assert(runs[index].vcn == next && runs[index].length != 0);
		assert(runs[index].length <= clusters - next);
		for (offset = 0; offset < runs[index].length; offset++) {
			map[next++] = runs[index].lcn == NTFS_HOLE ? NTFS_HOLE : runs[index].lcn + offset;
		}
	}
	assert(next == clusters);
}

static void
check_interval(const uint64_t *original, const struct ntfs_run *runs, size_t count,
    uint64_t first, uint64_t bytes, const uint8_t *physical, uint8_t *after_physical)
{
	struct fuzz_device device = {0};
	struct ntfs_environment env = fuzz_environment(&device);
	struct ntfs_write_sparse_input input = {runs, count, TEST_CLUSTER_BYTES,
	    TEST_PHYSICAL_CLUSTERS, TEST_LOGICAL_CLUSTERS, first, bytes};
	struct ntfs_write_sparse_plan *plan = NULL;
	const struct ntfs_write_sparse_view *view;
	uint64_t after[TEST_LOGICAL_CLUSTERS];
	bool retired[TEST_PHYSICAL_CLUSTERS] = {0};
	uint64_t position, cluster, lcn, run_offset, physical_byte;
	size_t index;
	uint8_t old_byte, new_byte;

	assert(ntfs_write_sparse_prepare(&env, &input, &plan) == NTFS_OK);
	assert(device.allocations == 1 && device.reads == 0);
	view = ntfs_write_sparse_plan_view(plan);
	assert(view != NULL && view->before_count == count);
	assert(memcmp(view->before, runs, count * sizeof(*runs)) == 0);
	assert(view->after_count <= count + 2 && view->retired_count <= count);
	assert(view->zero_count <= NTFS_WRITE_SPARSE_MAX_ZERO_SPANS);
	if (bytes == 0) {
		assert(view->after_count == count && view->retired_count == 0 && view->zero_count == 0);
		assert(memcmp(view->after, runs, count * sizeof(*runs)) == 0);
	}
	expand(view->after, view->after_count, after, TEST_LOGICAL_CLUSTERS);
	for (cluster = 0; cluster < TEST_LOGICAL_CLUSTERS; cluster++) {
		bool full = first <= cluster * TEST_CLUSTER_BYTES &&
		    first + bytes >= (cluster + 1) * TEST_CLUSTER_BYTES;

		assert(after[cluster] == (full ? NTFS_HOLE : original[cluster]));
	}
	for (index = 0; index < view->retired_count; index++) {
		const struct ntfs_run *run = &view->retired[index];

		assert(run->lcn != NTFS_HOLE && run->length != 0);
		for (run_offset = 0; run_offset < run->length; run_offset++) {
			lcn = run->lcn + run_offset;
			assert(lcn < TEST_PHYSICAL_CLUSTERS && !retired[lcn]);
			assert(run->vcn + run_offset < TEST_LOGICAL_CLUSTERS);
			assert(original[run->vcn + run_offset] == lcn);
			retired[lcn] = true;
		}
	}
	for (cluster = 0; cluster < TEST_LOGICAL_CLUSTERS; cluster++) {
		if (original[cluster] != NTFS_HOLE) {
			assert(retired[original[cluster]] == (after[cluster] == NTFS_HOLE));
		}
	}
	memcpy(after_physical, physical, TEST_PHYSICAL_CLUSTERS * TEST_CLUSTER_BYTES);
	for (index = 0; index < view->zero_count; index++) {
		const struct ntfs_write_sparse_zero *zero = &view->zero[index];

		assert(zero->bytes != 0 && zero->physical / TEST_CLUSTER_BYTES < TEST_PHYSICAL_CLUSTERS);
		assert(zero->bytes <= TEST_CLUSTER_BYTES - zero->physical % TEST_CLUSTER_BYTES);
		assert(!retired[zero->physical / TEST_CLUSTER_BYTES]);
		memset(after_physical + zero->physical, 0, (size_t)zero->bytes);
	}
	/* Independent byte oracle: read the two dense maps, then apply the user
	 * interval to the old logical content rather than repeating run splitting. */
	for (position = 0; position < TEST_LOGICAL_CLUSTERS * TEST_CLUSTER_BYTES; position++) {
		cluster = position / TEST_CLUSTER_BYTES;
		physical_byte = position % TEST_CLUSTER_BYTES;
		old_byte = original[cluster] == NTFS_HOLE
		    ? 0
		    : physical[original[cluster] * TEST_CLUSTER_BYTES + physical_byte];
		new_byte = after[cluster] == NTFS_HOLE
		    ? 0
		    : after_physical[after[cluster] * TEST_CLUSTER_BYTES + physical_byte];
		assert(new_byte == (position >= first && position - first < bytes ? 0 : old_byte));
	}
	ntfs_write_sparse_plan_close(plan);
	assert(device.memory == 0 && device.reads == 0);
	checked++;
}

static void
patterns(void)
{
	uint64_t map[TEST_LOGICAL_CLUSTERS], endpoints[TEST_ENDPOINTS];
	struct ntfs_run runs[TEST_LOGICAL_CLUSTERS];
	uint8_t *physical, *after;
	size_t pattern, value, cluster, index, first, last, count;

	physical = malloc(TEST_PHYSICAL_CLUSTERS * TEST_CLUSTER_BYTES);
	after = malloc(TEST_PHYSICAL_CLUSTERS * TEST_CLUSTER_BYTES);
	assert(physical != NULL && after != NULL);
	for (index = 0; index < TEST_PHYSICAL_CLUSTERS * TEST_CLUSTER_BYTES; index++) {
		physical[index] = (uint8_t)(index * TEST_PATTERN_MULTIPLIER + TEST_PATTERN_BIAS);
	}
	count = 0;
	for (cluster = 0; cluster < TEST_LOGICAL_CLUSTERS; cluster++) {
		endpoints[count++] = cluster * TEST_CLUSTER_BYTES;
		endpoints[count++] = cluster * TEST_CLUSTER_BYTES + 1;
		endpoints[count++] = (cluster + 1) * TEST_CLUSTER_BYTES - 1;
	}
	endpoints[count++] = TEST_LOGICAL_CLUSTERS * TEST_CLUSTER_BYTES;
	assert(count == TEST_ENDPOINTS);
	for (pattern = 0; pattern < TEST_PATTERNS; pattern++) {
		value = pattern;
		for (cluster = 0; cluster < TEST_LOGICAL_CLUSTERS; cluster++) {
			map[cluster] = value % 3 == 0 ? NTFS_HOLE : cluster * 2 + value % 3 - 1;
			runs[cluster] = (struct ntfs_run){cluster, 1, map[cluster]};
			value /= 3;
		}
		for (first = 0; first < count; first++) {
			for (last = first; last < count; last++) {
				check_interval(map, runs, TEST_LOGICAL_CLUSTERS, endpoints[first],
				    endpoints[last] - endpoints[first], physical, after);
			}
		}
	}
	/* A single physical extent must split into the full three-run result. */
	for (cluster = 0; cluster < TEST_LOGICAL_CLUSTERS; cluster++) {
		map[cluster] = cluster;
	}
	runs[0] = (struct ntfs_run){0, TEST_LOGICAL_CLUSTERS, 0};
	for (first = 0; first < count; first++) {
		for (last = first; last < count; last++) {
			check_interval(map, runs, 1, endpoints[first], endpoints[last] - endpoints[first],
			    physical, after);
		}
	}
	free(after);
	free(physical);
}

static void
ownership_and_limits(void)
{
	struct fuzz_device device = {0};
	struct ntfs_environment env = fuzz_environment(&device), saved_env;
	struct ntfs_run runs[2] = {{0, 1, 3}, {1, 1, 5}}, saved_runs[2];
	struct ntfs_write_sparse_input input = {runs, 2, TEST_CLUSTER_BYTES, 16, 2, 1, 700};
	struct ntfs_write_sparse_input invalid, saved_input;
	struct ntfs_write_sparse_plan *plan = NULL;
	const struct ntfs_write_sparse_view *view;
	size_t index, allocations;
	enum ntfs_result expected;

	env.read = NULL;
	memcpy(saved_runs, runs, sizeof(runs));
	assert(ntfs_write_sparse_prepare(&env, &input, &plan) == NTFS_OK);
	view = ntfs_write_sparse_plan_view(plan);
	assert(view->zero_count == 2 && view->retired_count == 0);
	assert(view->zero[0].physical == 3 * TEST_CLUSTER_BYTES + 1 && view->zero[0].bytes == 511);
	assert(view->zero[1].physical == 5 * TEST_CLUSTER_BYTES && view->zero[1].bytes == 189);
	memset(runs, 0, sizeof(runs));
	assert(memcmp(view->before, saved_runs, sizeof(runs)) == 0);
	ntfs_write_sparse_plan_close(plan);
	memcpy(runs, saved_runs, sizeof(runs));
	device.fail_allocation = device.allocations + 1;
	plan = (void *)(uintptr_t)1;
	assert(ntfs_write_sparse_prepare(&env, &input, &plan) == NTFS_NO_MEMORY && plan == NULL);
	device.fail_allocation = 0;
	allocations = device.allocations;
	for (index = 0; index < 9; index++) {
		invalid = input;
		expected = NTFS_CORRUPT;
		if (index == 0) {
			runs[1].lcn = runs[0].lcn;
		} else if (index == 1) {
			runs[1].vcn++;
		} else if (index == 2) {
			runs[1].length = 0;
		} else if (index == 3) {
			runs[1].lcn = input.volume_clusters;
		} else if (index == 4) {
			invalid.count = 1;
		} else if (index == 5) {
			invalid.logical_clusters = UINT64_MAX;
			expected = NTFS_RANGE;
		} else if (index == 6) {
			invalid.offset = UINT64_MAX;
			expected = NTFS_RANGE;
		} else if (index == 7) {
			invalid.cluster_bytes++;
			expected = NTFS_UNSUPPORTED;
		} else {
			invalid.volume_clusters = UINT64_MAX;
			expected = NTFS_RANGE;
		}
		plan = (void *)(uintptr_t)1;
		assert(ntfs_write_sparse_prepare(&env, &invalid, &plan) == expected && plan == NULL);
		assert(device.allocations == allocations && device.memory == 0 && device.reads == 0);
		memcpy(runs, saved_runs, sizeof(runs));
	}
	invalid = input;
	invalid.count = SIZE_MAX;
	plan = (void *)(uintptr_t)1;
	assert(ntfs_write_sparse_prepare(&env, &invalid, &plan) == NTFS_RANGE);
	assert(plan == (void *)(uintptr_t)1);
	saved_input = input;
	assert(ntfs_write_sparse_prepare(&env, &input, (void *)&input) == NTFS_INVALID);
	assert(memcmp(&input, &saved_input, sizeof(input)) == 0);
	saved_env = env;
	assert(ntfs_write_sparse_prepare(&env, &input, (void *)&env) == NTFS_INVALID);
	assert(memcmp(&env, &saved_env, sizeof(env)) == 0);
	assert(ntfs_write_sparse_prepare(&env, &input, (void *)runs) == NTFS_INVALID);
	assert(memcmp(runs, saved_runs, sizeof(runs)) == 0);
	assert(ntfs_write_sparse_plan_view(NULL) == NULL);
	ntfs_write_sparse_plan_close(NULL);
}

static void
wide_boundaries(void)
{
	struct fuzz_device device = {0};
	struct ntfs_environment env = fuzz_environment(&device);
	struct ntfs_write_sparse_input input = {0};
	struct ntfs_write_sparse_plan *plan = NULL;
	const struct ntfs_write_sparse_view *view;
	struct ntfs_run *runs;
	size_t index;
	uint64_t volume;
	uint32_t cluster;

	runs = calloc(NTFS_WRITE_SPARSE_MAX_RUNS, sizeof(*runs));
	assert(runs != NULL);
	for (index = 0; index < NTFS_WRITE_SPARSE_MAX_RUNS; index++) {
		runs[index] = (struct ntfs_run){index, 1, index % 2 == 0 ? index : NTFS_HOLE};
	}
	input = (struct ntfs_write_sparse_input){runs, NTFS_WRITE_SPARSE_MAX_RUNS,
	    TEST_CLUSTER_BYTES, NTFS_WRITE_SPARSE_MAX_RUNS, NTFS_WRITE_SPARSE_MAX_RUNS,
	    0, NTFS_WRITE_SPARSE_MAX_RUNS * TEST_CLUSTER_BYTES};
	assert(ntfs_write_sparse_prepare(&env, &input, &plan) == NTFS_OK);
	view = ntfs_write_sparse_plan_view(plan);
	assert(view->after_count == 1 && view->after[0].lcn == NTFS_HOLE);
	assert(view->retired_count == NTFS_WRITE_SPARSE_MAX_RUNS / 2 && view->zero_count == 0);
	ntfs_write_sparse_plan_close(plan);
	for (cluster = TEST_CLUSTER_BYTES; cluster <= NTFS_MAX_CLUSTER_BYTES; cluster *= 2) {
		volume = (uint64_t)INT64_MAX / cluster;
		runs[0] = (struct ntfs_run){0, 2, volume - 2};
		input = (struct ntfs_write_sparse_input){runs, 1, cluster, volume, 2, 1, cluster};
		assert(ntfs_write_sparse_prepare(&env, &input, &plan) == NTFS_OK);
		view = ntfs_write_sparse_plan_view(plan);
		assert(view->zero_count == 2 && view->retired_count == 0);
		assert(view->zero[0].physical == (volume - 2) * cluster + 1);
		assert(view->zero[0].bytes == cluster - 1 && view->zero[1].bytes == 1);
		ntfs_write_sparse_plan_close(plan);
	}
	input = (struct ntfs_write_sparse_input){NULL, 0, TEST_CLUSTER_BYTES, 1, 0, 0, 0};
	assert(ntfs_write_sparse_prepare(&env, &input, &plan) == NTFS_OK);
	view = ntfs_write_sparse_plan_view(plan);
	assert(view->before_count == 0 && view->after_count == 0 && view->retired_count == 0 &&
	    view->zero_count == 0);
	ntfs_write_sparse_plan_close(plan);
	assert(device.memory == 0 && device.reads == 0);
	free(runs);
}

int
main(void)
{
	patterns();
	ownership_and_limits();
	wide_boundaries();
	printf("private sparse zero/punch: %zu independent map/content/retirement cases; "
	       "partial clusters, original ownership, faults, aliases, geometry and limits passed\n",
	    checked);
	return 0;
}
