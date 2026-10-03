/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/ntfs.h>
#include "fuzz_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_PATH_BYTES = 4096,
	TEST_DATA_BYTES = 8 * 1024 * 1024,
	TEST_SECTOR_BYTES = 512,
	TEST_IMAGE_BYTES = TEST_DATA_BYTES + TEST_SECTOR_BYTES,
	TEST_RECORD = 24,
	TEST_DIRECTORY_RECORD = 48,
	TEST_SEQUENCE = 7,
	TEST_CLUSTER_BYTES = 4096,
	TEST_DATA_FIRST_LCN = 128,
	TEST_DATA_LAST_LCN = 130,
	/* Retained nodes put operation live storage above mount's transient
	 * UpCase-loading peak, so the live quota targets inventory scratch. */
	TEST_LIVE_PREFIX_NODES = 256,
	TEST_PARTIAL_DIVISOR = 2
};

struct link_device {
	struct fuzz_device device;
	bool partial;
};

struct link_case {
	const char *name;
	uint32_t record;
	struct ntfs_link_counts counts;
	enum ntfs_result result;
};

static const struct link_case cases[] = {{"single", TEST_RECORD, {1, 1, 0}, NTFS_OK},
    {"hardlinks", TEST_RECORD, {2, 2, 0}, NTFS_OK}, {"dos", TEST_RECORD, {2, 1, 1}, NTFS_OK},
    {"dos-hardlinks", TEST_RECORD, {4, 2, 2}, NTFS_OK},
    {"dos-nested-hardlinks", TEST_RECORD, {4, 2, 2}, NTFS_OK},
    {"combined-name", TEST_RECORD, {1, 1, 0}, NTFS_OK},
    {"dos-directory", TEST_DIRECTORY_RECORD, {2, 1, 1}, NTFS_OK},
    {"listed", TEST_RECORD, {1, 1, 0}, NTFS_OK},
    {"extension-filename", TEST_RECORD, {1, 1, 0}, NTFS_OK},
    {"listed-four", TEST_RECORD, {4, 2, 2}, NTFS_OK},
    {"listed-shuffled", TEST_RECORD, {4, 2, 2}, NTFS_OK},
    {"listed-nonresident", TEST_RECORD, {4, 2, 2}, NTFS_OK},
    {"listed-large", TEST_RECORD, {32, 16, 16}, NTFS_OK},
    {"duplicate-instance", TEST_RECORD, {0}, NTFS_CORRUPT},
    {"list-duplicate-physical", TEST_RECORD, {0}, NTFS_CORRUPT},
    {"list-unlisted-base", TEST_RECORD, {0}, NTFS_CORRUPT},
    {"list-unlisted-extension", TEST_RECORD, {0}, NTFS_CORRUPT},
    {"list-stale", TEST_RECORD, {0}, NTFS_STALE}, {"list-owner", TEST_RECORD, {0}, NTFS_STALE}};

static void
expect_counts(const struct ntfs_link_counts *actual, const struct ntfs_link_counts *expected)
{
	assert(actual->physical_names == expected->physical_names);
	assert(actual->primary_names == expected->primary_names);
	assert(actual->dos_aliases == expected->dos_aliases);
}

static enum ntfs_result
metadata_read(void *context, uint64_t offset, void *buffer, size_t size)
{
	struct link_device *device = context;
	uint64_t first = (uint64_t)TEST_DATA_FIRST_LCN * TEST_CLUSTER_BYTES;
	uint64_t end = (uint64_t)(TEST_DATA_LAST_LCN + 1) * TEST_CLUSTER_BYTES;

	assert(size == 0 || offset >= end || (offset < first && size <= first - offset));
	if (device->partial && device->device.reads + 1 == device->device.fail_read) {
		assert(offset <= device->device.size && size <= device->device.size - offset);
		memcpy(buffer, device->device.data + offset, size / TEST_PARTIAL_DIVISOR);
	}
	return fuzz_read(&device->device, offset, buffer, size);
}

static uint8_t *
load_image(const char *directory, const char *name)
{
	char path[TEST_PATH_BYTES];
	uint8_t *bytes;
	FILE *file;
	int length;

	length = snprintf(path, sizeof(path), "%s/links-%s.img", directory, name);
	assert(length > 0 && (size_t)length < sizeof(path));
	file = fopen(path, "rb");
	assert(file != NULL);
	bytes = malloc(TEST_IMAGE_BYTES);
	assert(bytes != NULL);
	assert(fread(bytes, 1, TEST_IMAGE_BYTES, file) == TEST_IMAGE_BYTES);
	assert(fgetc(file) == EOF && !ferror(file));
	assert(fclose(file) == 0);
	return bytes;
}

static struct ntfs_operation_usage
exercise(const uint8_t *bytes, const struct link_case *test, size_t failed_allocation,
    size_t failed_read, bool partial, const struct ntfs_operation_limits *operation_limits,
    uint64_t live, enum ntfs_operation_limit exhausted)
{
	struct link_device device = {
	    .device = {.data = bytes, .size = TEST_IMAGE_BYTES}, .partial = partial};
	struct ntfs_environment environment = fuzz_environment(&device.device);
	struct ntfs_limits limits;
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *node = NULL;
	struct ntfs_node *retained[TEST_LIVE_PREFIX_NODES] = {0};
	struct ntfs_link_counts counts, zero = {0};
	struct ntfs_operation scope = {0}, outer = {0}, inner = {0};
	struct ntfs_operation_limits warm_limits;
	struct ntfs_operation_usage usage, hot;
	uint64_t reference =
	    (uint64_t)TEST_SEQUENCE << NTFS_REFERENCE_SEQUENCE_SHIFT | test->record;
	size_t allocations, reads, memory, index;
	enum ntfs_result result;

	environment.context = &device;
	environment.read = metadata_read;
	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	if (live != 0) {
		limits.max_live_bytes = live;
	}
	assert(ntfs_mount(&environment, &limits, &volume) == NTFS_OK);
	assert(ntfs_node_open(volume, reference, &node) == NTFS_OK);
	if (strcmp(test->name, "listed-large") == 0) {
		for (index = 0; index < TEST_LIVE_PREFIX_NODES; index++) {
			assert(ntfs_node_open(volume, reference, &retained[index]) == NTFS_OK);
		}
	}
	memset(&counts, -1, sizeof(counts));
	assert(ntfs_node_link_counts(NULL, &counts) == NTFS_INVALID);
	expect_counts(&counts, &zero);
	assert(ntfs_node_link_counts(node, NULL) == NTFS_INVALID);
	allocations = device.device.allocations;
	reads = device.device.reads;
	memory = device.device.memory;
	device.device.fail_allocation =
	    failed_allocation != 0 ? allocations + failed_allocation : 0;
	device.device.fail_read = failed_read != 0 ? reads + failed_read : 0;
	assert(ntfs_operation_begin(volume, operation_limits, &scope) == NTFS_OK);
	memset(&counts, -1, sizeof(counts));
	result = ntfs_node_link_counts(node, &counts);
	if (exhausted != NTFS_OPERATION_LIMIT_NONE) {
		assert(result ==
		    (exhausted == NTFS_OPERATION_LIMIT_ALLOCATION_CALLS ||
				exhausted == NTFS_OPERATION_LIMIT_ALLOCATION_BYTES ||
				exhausted == NTFS_OPERATION_LIMIT_LIVE_BYTES
			    ? NTFS_NO_MEMORY
			    : NTFS_RANGE));
		expect_counts(&counts, &zero);
		assert(ntfs_operation_result(&scope) == result);
		allocations = device.device.allocations;
		reads = device.device.reads;
		assert(ntfs_node_link_counts(node, &counts) == result);
		assert(device.device.allocations == allocations && device.device.reads == reads);
		expect_counts(&counts, &zero);
	} else if (failed_allocation != 0 || failed_read != 0) {
		assert(result == (failed_allocation != 0 ? NTFS_NO_MEMORY : NTFS_IO));
		expect_counts(&counts, &zero);
		assert(device.device.memory == memory);
		device.device.fail_allocation = 0;
		device.device.fail_read = 0;
		result = ntfs_node_link_counts(node, &counts);
		assert(result == NTFS_OK);
		expect_counts(&counts, &test->counts);
	} else {
		assert(result == test->result);
		expect_counts(&counts, &test->counts);
	}
	assert(device.device.memory == memory);
	assert(ntfs_operation_end(&scope, &usage) == NTFS_OK);
	assert(usage.exhausted == exhausted);
	if (exhausted != NTFS_OPERATION_LIMIT_NONE) {
		if (live == 0) {
			assert(ntfs_node_link_counts(node, &counts) == NTFS_OK);
			expect_counts(&counts, &test->counts);
		}
	} else if (test->result == NTFS_OK) {
		allocations = device.device.allocations;
		reads = device.device.reads;
		device.device.fail_allocation = allocations + 1;
		device.device.fail_read = reads + 1;
		assert(ntfs_node_link_counts(node, &counts) == NTFS_OK);
		expect_counts(&counts, &test->counts);
		ntfs_get_operation_usage(volume, &hot);
		assert(
		    hot.work == sizeof(counts) && hot.allocation_calls == 0 && hot.read_calls == 0);
		assert(device.device.allocations == allocations && device.device.reads == reads);
		ntfs_operation_default_limits(&warm_limits);
		warm_limits.work = sizeof(counts);
		assert(ntfs_operation_begin(volume, &warm_limits, &outer) == NTFS_OK);
		assert(ntfs_node_link_counts(node, &counts) == NTFS_OK);
		assert(ntfs_operation_end(&outer, &hot) == NTFS_OK);
		assert(hot.work == sizeof(counts));
		warm_limits.work--;
		assert(ntfs_operation_begin(volume, &warm_limits, &outer) == NTFS_OK);
		assert(ntfs_operation_begin(volume, NULL, &inner) == NTFS_OK);
		memset(&counts, -1, sizeof(counts));
		assert(ntfs_node_link_counts(node, &counts) == NTFS_RANGE);
		expect_counts(&counts, &zero);
		assert(ntfs_operation_result(&outer) == NTFS_RANGE);
		assert(ntfs_operation_result(&inner) == NTFS_RANGE);
		assert(ntfs_operation_end(&inner, &hot) == NTFS_OK);
		assert(ntfs_operation_end(&outer, &hot) == NTFS_OK);
		assert(hot.exhausted == NTFS_OPERATION_LIMIT_WORK);
		assert(device.device.allocations == allocations && device.device.reads == reads);
		assert(ntfs_node_link_counts(node, &counts) == NTFS_OK);
		expect_counts(&counts, &test->counts);
	}
	for (index = 0; index < TEST_LIVE_PREFIX_NODES; index++) {
		ntfs_node_close(retained[index]);
	}
	ntfs_node_close(node);
	assert(ntfs_unmount(volume) == NTFS_OK && device.device.memory == 0);
	return usage;
}

static uint64_t *
ceiling(struct ntfs_operation_limits *limits, enum ntfs_operation_limit dimension)
{
	switch (dimension) {
	case NTFS_OPERATION_LIMIT_READ_CALLS:
		return &limits->read_calls;
	case NTFS_OPERATION_LIMIT_READ_BYTES:
		return &limits->read_bytes;
	case NTFS_OPERATION_LIMIT_ALLOCATION_CALLS:
		return &limits->allocation_calls;
	case NTFS_OPERATION_LIMIT_ALLOCATION_BYTES:
		return &limits->allocation_bytes;
	case NTFS_OPERATION_LIMIT_WORK:
		return &limits->work;
	default:
		abort();
	}
}

static uint64_t
observed(const struct ntfs_operation_usage *usage, enum ntfs_operation_limit dimension)
{
	switch (dimension) {
	case NTFS_OPERATION_LIMIT_READ_CALLS:
		return usage->read_calls;
	case NTFS_OPERATION_LIMIT_READ_BYTES:
		return usage->read_bytes;
	case NTFS_OPERATION_LIMIT_ALLOCATION_CALLS:
		return usage->allocation_calls;
	case NTFS_OPERATION_LIMIT_ALLOCATION_BYTES:
		return usage->allocation_bytes;
	case NTFS_OPERATION_LIMIT_WORK:
		return usage->work;
	default:
		abort();
	}
}

int
main(int argc, char **argv)
{
	const char *fault_profiles[] = {
	    "dos-hardlinks", "listed-four", "listed-nonresident", "listed-large"};
	struct ntfs_operation_usage baseline;
	struct ntfs_operation_limits limits;
	const struct link_case *test;
	uint8_t *bytes, *original;
	size_t index, profile, failed, allocations = 0, reads = 0, boundaries = 0;
	enum ntfs_operation_limit dimension;

	assert(argc == 2);
	for (index = 0; index < sizeof(cases) / sizeof(*cases); index++) {
		test = &cases[index];
		bytes = load_image(argv[1], test->name);
		original = malloc(TEST_IMAGE_BYTES);
		assert(original != NULL);
		memcpy(original, bytes, TEST_IMAGE_BYTES);
		baseline = exercise(bytes, test, 0, 0, false, NULL, 0, NTFS_OPERATION_LIMIT_NONE);
		for (profile = 0; profile < sizeof(fault_profiles) / sizeof(*fault_profiles);
		    profile++) {
			if (strcmp(test->name, fault_profiles[profile]) != 0) {
				continue;
			}
			for (failed = 1; failed <= baseline.allocation_calls; failed++) {
				(void)exercise(bytes, test, failed, 0, false, NULL, 0,
				    NTFS_OPERATION_LIMIT_NONE);
				allocations++;
			}
			for (failed = 1; failed <= baseline.read_calls; failed++) {
				(void)exercise(bytes, test, 0, failed, false, NULL, 0,
				    NTFS_OPERATION_LIMIT_NONE);
				(void)exercise(bytes, test, 0, failed, true, NULL, 0,
				    NTFS_OPERATION_LIMIT_NONE);
				reads += TEST_PARTIAL_DIVISOR;
			}
			printf("link inventory %s: %llu allocations, %llu reads, %llu work units\n",
			    test->name, (unsigned long long)baseline.allocation_calls,
			    (unsigned long long)baseline.read_calls,
			    (unsigned long long)baseline.work);
			if (strcmp(test->name, "listed-large") != 0) {
				continue;
			}
			for (dimension = NTFS_OPERATION_LIMIT_READ_CALLS;
			    dimension <= NTFS_OPERATION_LIMIT_WORK; dimension++) {
				ntfs_operation_default_limits(&limits);
				*ceiling(&limits, dimension) = observed(&baseline, dimension);
				assert(*ceiling(&limits, dimension) > 1);
				(void)exercise(bytes, test, 0, 0, false, &limits, 0,
				    NTFS_OPERATION_LIMIT_NONE);
				(*ceiling(&limits, dimension))--;
				(void)exercise(bytes, test, 0, 0, false, &limits, 0, dimension);
				boundaries += TEST_PARTIAL_DIVISOR;
			}
			(void)exercise(bytes, test, 0, 0, false, NULL, baseline.peak_live_bytes,
			    NTFS_OPERATION_LIMIT_NONE);
			(void)exercise(bytes, test, 0, 0, false, NULL, baseline.peak_live_bytes - 1,
			    NTFS_OPERATION_LIMIT_LIVE_BYTES);
			boundaries += TEST_PARTIAL_DIVISOR;
		}
		assert(memcmp(bytes, original, TEST_IMAGE_BYTES) == 0);
		free(original);
		free(bytes);
	}
	printf(
	    "PASS: complete physical/primary/DOS counts, immutable cache, %zu allocation and "
	    "%zu partial/full read faults, %zu cold operation boundaries and hot ancestor guards\n",
	    allocations, reads, boundaries);
	return 0;
}
