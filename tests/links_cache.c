/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/ntfs.h>
#include "fixture.h"
#include "fuzz_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_CACHE_PATH_BYTES = 4096,
	TEST_CACHE_FILE_RECORD = 24,
	TEST_CACHE_FILE_SEQUENCE = 7,
	TEST_CACHE_LARGE_NAMES = 2000,
	TEST_CACHE_SMALL_NAMES = 12,
	TEST_CACHE_DOS_ALIASES = 1,
	TEST_CACHE_SINGLE_SLOT = 1,
	TEST_CACHE_ROOT_NAMES = 1,
	TEST_CACHE_PARTIAL_DIVISOR = 2
};

#define TEST_CACHE_FILE_REFERENCE                                                                  \
	((uint64_t)TEST_CACHE_FILE_SEQUENCE << NTFS_REFERENCE_SEQUENCE_SHIFT |                     \
	    TEST_CACHE_FILE_RECORD)

static uint8_t *
load_image(const char *directory, const char *name)
{
	char path[TEST_CACHE_PATH_BYTES];
	FILE *file;
	uint8_t *bytes;
	int length;

	length = snprintf(path, sizeof(path), "%s/%s", directory, name);
	assert(length > 0 && (size_t)length < sizeof(path));
	file = fopen(path, "rb");
	assert(file != NULL);
	bytes = malloc(TEST_IMAGE_BYTES);
	assert(bytes != NULL && fread(bytes, 1, TEST_IMAGE_BYTES, file) == TEST_IMAGE_BYTES);
	assert(fgetc(file) == EOF && !ferror(file) && fclose(file) == 0);
	return bytes;
}

static enum ntfs_result
partial_read(void *context, uint64_t offset, void *buffer, size_t size)
{
	struct fuzz_device *device = context;

	if (device->fail_read != 0 && device->reads + 1 == device->fail_read) {
		assert(offset <= device->size && size <= device->size - offset);
		memcpy(buffer, device->data + offset, size / TEST_CACHE_PARTIAL_DIVISOR);
	}
	return fuzz_read(context, offset, buffer, size);
}

static struct ntfs_volume *
mount_image(struct fuzz_device *device, uint32_t entries)
{
	struct ntfs_environment environment = fuzz_environment(device);
	struct ntfs_limits limits;
	struct ntfs_volume *volume = NULL;

	environment.read = partial_read;
	ntfs_default_limits(&limits);
	limits.record_cache_entries = entries;
	assert(ntfs_mount(&environment, &limits, &volume) == NTFS_OK);
	return volume;
}

static struct ntfs_node *
open_file(struct ntfs_volume *volume, struct fuzz_device *device)
{
	struct ntfs_node *node = NULL;

	device->reads = 0;
	device->allocations = 0;
	assert(ntfs_node_open(volume, TEST_CACHE_FILE_REFERENCE, &node) == NTFS_OK);
	return node;
}

static struct ntfs_operation_usage
inventory(struct ntfs_node *node, struct ntfs_volume *volume, struct fuzz_device *device,
    enum ntfs_result expected, uint16_t primary, uint16_t dos)
{
	struct ntfs_operation operation = {0};
	struct ntfs_operation_usage usage;
	struct ntfs_link_counts counts, zero = {0};

	device->reads = 0;
	device->allocations = 0;
	memset(&counts, -1, sizeof(counts));
	assert(ntfs_operation_begin(volume, NULL, &operation) == NTFS_OK);
	assert(ntfs_node_link_counts(node, &counts) == expected);
	assert(ntfs_operation_end(&operation, &usage) == NTFS_OK);
	if (expected == NTFS_OK) {
		assert(counts.physical_names == primary + dos && counts.primary_names == primary &&
		    counts.dos_aliases == dos);
	} else {
		assert(memcmp(&counts, &zero, sizeof(counts)) == 0);
	}
	assert(usage.read_calls == device->reads && usage.allocation_calls == device->allocations);
	return usage;
}

static void
cache_reuse(const uint8_t *bytes, uint32_t entries)
{
	struct fuzz_device device = {.data = bytes, .size = TEST_IMAGE_BYTES};
	struct ntfs_volume *volume = mount_image(&device, entries);
	struct ntfs_node *file = open_file(volume, &device), *root = NULL, *stale = NULL;
	struct ntfs_operation_usage cold, reopened;
	struct ntfs_operation_limits limits;
	struct ntfs_operation outer = {0}, inner = {0};
	struct ntfs_link_counts counts, zero = {0};
	uint64_t stale_reference =
	    TEST_CACHE_FILE_REFERENCE + (UINT64_C(1) << NTFS_REFERENCE_SEQUENCE_SHIFT);

	cold = inventory(file, volume, &device, NTFS_OK, TEST_CACHE_LARGE_NAMES, 0);
	assert(cold.read_calls != 0 && cold.allocation_calls != 0);
	ntfs_node_close(file);
	assert(ntfs_node_open(volume, stale_reference, &stale) == NTFS_STALE && stale == NULL);
	assert(ntfs_root(volume, &root) == NTFS_OK);
	ntfs_node_close(root);
	/* The intervening root read replaces a single raw record slot. Counts have
	 * their own reference and remain valid independently of raw replacement. */
	file = open_file(volume, &device);
	reopened = inventory(file, volume, &device, NTFS_OK, TEST_CACHE_LARGE_NAMES, 0);
	if (entries == 0) {
		assert(reopened.read_calls != 0 && reopened.allocation_calls != 0);
	} else {
		assert(reopened.read_calls == 0 && reopened.allocation_calls == 0 &&
		    reopened.work < cold.work);
	}
	ntfs_node_close(file);
	if (entries != 0) {
		file = open_file(volume, &device);
		ntfs_operation_default_limits(&limits);
		assert(reopened.work > 1);
		limits.work = reopened.work - 1;
		memset(&counts, -1, sizeof(counts));
		assert(ntfs_operation_begin(volume, &limits, &outer) == NTFS_OK);
		assert(ntfs_operation_begin(volume, NULL, &inner) == NTFS_OK);
		assert(ntfs_node_link_counts(file, &counts) == NTFS_RANGE);
		assert(memcmp(&counts, &zero, sizeof(counts)) == 0);
		assert(ntfs_operation_end(&inner, NULL) == NTFS_OK);
		assert(ntfs_operation_end(&outer, &cold) == NTFS_OK &&
		    cold.exhausted == NTFS_OPERATION_LIMIT_WORK);
		limits.work = reopened.work;
		assert(ntfs_operation_begin(volume, &limits, &outer) == NTFS_OK);
		device.fail_allocation = 1;
		device.fail_read = 1;
		cold = inventory(file, volume, &device, NTFS_OK, TEST_CACHE_LARGE_NAMES, 0);
		assert(cold.read_calls == 0 && cold.allocation_calls == 0);
		assert(ntfs_operation_end(&outer, &cold) == NTFS_OK && cold.work == limits.work &&
		    cold.exhausted == NTFS_OPERATION_LIMIT_NONE);
		device.fail_allocation = 0;
		device.fail_read = 0;
		ntfs_node_close(file);
	}
	assert(ntfs_root(volume, &root) == NTFS_OK);
	(void)inventory(root, volume, &device, NTFS_OK, TEST_CACHE_ROOT_NAMES, 0);
	ntfs_node_close(root);
	file = open_file(volume, &device);
	reopened = inventory(file, volume, &device, NTFS_OK, TEST_CACHE_LARGE_NAMES, 0);
	assert((reopened.read_calls != 0) == (entries <= TEST_CACHE_SINGLE_SLOT));
	ntfs_node_close(file);
	assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
}

static void
failed_inventory(const uint8_t *bytes, bool read_error)
{
	struct fuzz_device device = {.data = bytes, .size = TEST_IMAGE_BYTES};
	struct ntfs_volume *volume = mount_image(&device, TEST_CACHE_SINGLE_SLOT);
	struct ntfs_node *file = open_file(volume, &device);
	struct ntfs_operation_usage usage;

	device.fail_read = read_error ? 1 : 0;
	device.fail_allocation = read_error ? 0 : 1;
	(void)inventory(file, volume, &device, read_error ? NTFS_IO : NTFS_NO_MEMORY, 0, 0);
	device.fail_read = 0;
	device.fail_allocation = 0;
	ntfs_node_close(file);
	file = open_file(volume, &device);
	usage = inventory(file, volume, &device, NTFS_OK, TEST_CACHE_LARGE_NAMES, 0);
	assert(usage.read_calls != 0 && usage.allocation_calls != 0);
	ntfs_node_close(file);
	assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
}

static void
corrupt_inventory(const uint8_t *bytes)
{
	struct fuzz_device device = {.data = bytes, .size = TEST_IMAGE_BYTES};
	struct ntfs_volume *volume = mount_image(&device, TEST_CACHE_SINGLE_SLOT);
	struct ntfs_node *file = open_file(volume, &device);
	struct ntfs_operation_usage first, repeated;

	first = inventory(file, volume, &device, NTFS_CORRUPT, 0, 0);
	assert(first.work > TEST_MFT_RECORD_BYTES);
	ntfs_node_close(file);
	file = open_file(volume, &device);
	repeated = inventory(file, volume, &device, NTFS_CORRUPT, 0, 0);
	assert(repeated.work == first.work);
	ntfs_node_close(file);
	assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
}

static void
owner_isolation(const uint8_t *large, const uint8_t *small)
{
	struct fuzz_device devices[] = {
	    {.data = large, .size = TEST_IMAGE_BYTES}, {.data = small, .size = TEST_IMAGE_BYTES}};
	const uint16_t expected[] = {TEST_CACHE_LARGE_NAMES, TEST_CACHE_SMALL_NAMES};
	struct ntfs_volume *volumes[sizeof(devices) / sizeof(*devices)];
	struct ntfs_node *node;
	struct ntfs_operation_usage usage;
	size_t index;

	for (index = 0; index < sizeof(devices) / sizeof(*devices); index++) {
		volumes[index] = mount_image(&devices[index], TEST_CACHE_SINGLE_SLOT);
		node = open_file(volumes[index], &devices[index]);
		usage =
		    inventory(node, volumes[index], &devices[index], NTFS_OK, expected[index], 0);
		assert(usage.read_calls != 0 && usage.allocation_calls != 0);
		ntfs_node_close(node);
	}
	for (index = 0; index < sizeof(devices) / sizeof(*devices); index++) {
		node = open_file(volumes[index], &devices[index]);
		usage =
		    inventory(node, volumes[index], &devices[index], NTFS_OK, expected[index], 0);
		assert(usage.read_calls == 0 && usage.allocation_calls == 0);
		ntfs_node_close(node);
		assert(ntfs_unmount(volumes[index]) == NTFS_OK && devices[index].memory == 0);
	}
}

static void
dos_inventory(const uint8_t *bytes, uint32_t entries)
{
	struct fuzz_device device = {.data = bytes, .size = TEST_IMAGE_BYTES};
	struct ntfs_volume *volume = mount_image(&device, entries);
	struct ntfs_node *file = open_file(volume, &device);
	struct ntfs_operation_usage usage;

	usage = inventory(
	    file, volume, &device, NTFS_OK, TEST_CACHE_SMALL_NAMES, TEST_CACHE_DOS_ALIASES);
	assert(usage.read_calls != 0 && usage.allocation_calls != 0);
	ntfs_node_close(file);
	file = open_file(volume, &device);
	usage = inventory(
	    file, volume, &device, NTFS_OK, TEST_CACHE_SMALL_NAMES, TEST_CACHE_DOS_ALIASES);
	assert((usage.read_calls != 0) == (entries == 0));
	assert((usage.allocation_calls != 0) == (entries == 0));
	ntfs_node_close(file);
	assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
}

static void
cold_work_admission(const uint8_t *bytes)
{
	const bool refused[] = {false, true};
	struct fuzz_device device = {.data = bytes, .size = TEST_IMAGE_BYTES};
	struct ntfs_volume *volume = mount_image(&device, NTFS_DEFAULT_RECORD_CACHE_ENTRIES);
	struct ntfs_node *file = open_file(volume, &device);
	struct ntfs_operation_usage cold, usage;
	struct ntfs_operation_limits limits;
	struct ntfs_operation scope = {0};
	size_t index;

	cold = inventory(file, volume, &device, NTFS_OK, TEST_CACHE_LARGE_NAMES, 0);
	assert(cold.work > 1);
	ntfs_node_close(file);
	assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
	for (index = 0; index < sizeof(refused) / sizeof(*refused); index++) {
		volume = mount_image(&device, NTFS_DEFAULT_RECORD_CACHE_ENTRIES);
		file = open_file(volume, &device);
		ntfs_operation_default_limits(&limits);
		limits.work = cold.work - (refused[index] ? 1 : 0);
		assert(ntfs_operation_begin(volume, &limits, &scope) == NTFS_OK);
		(void)inventory(file, volume, &device, refused[index] ? NTFS_RANGE : NTFS_OK,
		    TEST_CACHE_LARGE_NAMES, 0);
		assert(ntfs_operation_end(&scope, &usage) == NTFS_OK);
		assert(usage.exhausted ==
		    (refused[index] ? NTFS_OPERATION_LIMIT_WORK : NTFS_OPERATION_LIMIT_NONE));
		if (!refused[index]) {
			assert(usage.work == limits.work);
		}
		ntfs_node_close(file);
		file = open_file(volume, &device);
		usage = inventory(file, volume, &device, NTFS_OK, TEST_CACHE_LARGE_NAMES, 0);
		/* A quota failure cannot publish a partial inventory. A fresh node must
		 * finish validation, whereas the exact admitted inventory is reusable. */
		assert((usage.read_calls != 0) == refused[index]);
		assert((usage.allocation_calls != 0) == refused[index]);
		ntfs_node_close(file);
		assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
	}
}

int
main(int argc, char **argv)
{
	const uint32_t capacities[] = {
	    0, TEST_CACHE_SINGLE_SLOT, NTFS_DEFAULT_RECORD_CACHE_ENTRIES};
	uint8_t *large, *small, *dos, *corrupt;
	size_t index;

	assert(argc == 2);
	large = load_image(argv[1], "namespace-large.img");
	small = load_image(argv[1], "namespace.img");
	dos = load_image(argv[1], "namespace-hidden.img");
	corrupt = load_image(argv[1], "namespace-invalid.img");
	for (index = 0; index < sizeof(capacities) / sizeof(*capacities); index++) {
		cache_reuse(large, capacities[index]);
		dos_inventory(dos, capacities[index]);
	}
	failed_inventory(large, false);
	failed_inventory(large, true);
	corrupt_inventory(corrupt);
	owner_isolation(large, small);
	cold_work_admission(large);
	free(corrupt);
	free(dos);
	free(small);
	free(large);
	puts("PASS: bounded full-reference filename-count reuse, disabled/single/default capacity, "
	     "raw eviction, sequence/owner isolation, count eviction, zero-allocation/read hits, "
	     "DOS inventory, exact/one-below hot/cold work and ancestor refusal, "
	     "failed/corrupt inventory exclusion, retry and cleanup");
	return 0;
}
