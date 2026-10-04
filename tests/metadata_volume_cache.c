/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/ntfs.h>
#include "fixture.h"
#include "fuzz_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_METADATA_PATH_BYTES = 4096,
	TEST_METADATA_FILE_RECORD = 24,
	TEST_METADATA_FILE_SEQUENCE = 7,
	TEST_METADATA_DIRECTORY_RECORD = 48,
	TEST_METADATA_SINGLE_SLOT = 1,
	TEST_METADATA_LARGE_NAMES = 2000,
	TEST_METADATA_SMALL_NAMES = 12,
	TEST_METADATA_DOS_NAMES = TEST_METADATA_SMALL_NAMES + 1,
	TEST_METADATA_PARTIAL_DIVISOR = 2,
	TEST_METADATA_REPETITIONS = 2,
	TEST_METADATA_MODIFIED_SECONDS = 12,
	TEST_METADATA_MODIFIED_NANOSECONDS = 345678900,
	TEST_METADATA_RESIDENT_BYTES = sizeof("Hello from NTFS.\n") - 1
};

enum {
	TEST_METADATA_FIRST_OBJECT_RECORD = 80,
	TEST_METADATA_FIT_OBJECTS = 32,
	TEST_METADATA_PRESSURE_OBJECTS = 256
};

#define TEST_METADATA_FILE_REFERENCE                                                               \
	((uint64_t)TEST_METADATA_FILE_SEQUENCE << NTFS_REFERENCE_SEQUENCE_SHIFT |                  \
	    TEST_METADATA_FILE_RECORD)
#define TEST_METADATA_DIRECTORY_REFERENCE                                                          \
	((uint64_t)TEST_METADATA_FILE_SEQUENCE << NTFS_REFERENCE_SEQUENCE_SHIFT |                  \
	    TEST_METADATA_DIRECTORY_RECORD)

static uint8_t *
load_image(const char *directory, const char *name)
{
	char path[TEST_METADATA_PATH_BYTES];
	FILE *source;
	uint8_t *bytes;
	int length;

	length = snprintf(path, sizeof(path), "%s/%s", directory, name);
	assert(length > 0 && (size_t)length < sizeof(path));
	source = fopen(path, "rb");
	assert(source != NULL);
	bytes = malloc(TEST_IMAGE_BYTES);
	assert(bytes != NULL && fread(bytes, 1, TEST_IMAGE_BYTES, source) == TEST_IMAGE_BYTES);
	assert(fgetc(source) == EOF && !ferror(source) && fclose(source) == 0);
	return bytes;
}

static enum ntfs_result
partial_read(void *context, uint64_t offset, void *buffer, size_t size)
{
	struct fuzz_device *device = context;

	if (device->fail_read != 0 && device->reads + 1 == device->fail_read) {
		assert(offset <= device->size && size <= device->size - offset);
		memcpy(buffer, device->data + offset, size / TEST_METADATA_PARTIAL_DIVISOR);
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
	assert(ntfs_node_open(volume, TEST_METADATA_FILE_REFERENCE, &node) == NTFS_OK);
	return node;
}

static struct ntfs_operation_usage
metadata(struct ntfs_node *node, struct ntfs_volume *volume, struct fuzz_device *device,
    enum ntfs_result expected, struct ntfs_stat *out)
{
	struct ntfs_operation operation = {0};
	struct ntfs_operation_usage usage;
	struct ntfs_stat zero = {0};

	device->reads = 0;
	device->allocations = 0;
	memset(out, -1, sizeof(*out));
	assert(ntfs_operation_begin(volume, NULL, &operation) == NTFS_OK);
	assert(ntfs_node_metadata(node, out) == expected);
	assert(ntfs_operation_end(&operation, &usage) == NTFS_OK);
	if (expected == NTFS_OK) {
		assert(out->reference != 0 && out->size == 0 && out->allocated_size == 0);
	} else {
		assert(memcmp(out, &zero, sizeof(*out)) == 0);
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
	struct ntfs_operation_usage cold, reopened, usage;
	struct ntfs_operation_limits limits;
	struct ntfs_operation outer = {0}, inner = {0};
	struct ntfs_link_counts counts;
	struct ntfs_stat before, after;
	uint64_t stale_reference =
	    TEST_METADATA_FILE_REFERENCE + (UINT64_C(1) << NTFS_REFERENCE_SEQUENCE_SHIFT);

	cold = metadata(file, volume, &device, NTFS_OK, &before);
	assert(cold.read_calls != 0 && cold.allocation_calls != 0);
	assert(before.reference == TEST_METADATA_FILE_REFERENCE &&
	    before.links == TEST_METADATA_LARGE_NAMES && !before.directory && !before.reparse &&
	    !before.case_sensitive && before.security_id == TEST_SECURITY_ID &&
	    before.created.seconds == 0 && before.created.nanoseconds == 0 &&
	    before.modified.seconds == TEST_METADATA_MODIFIED_SECONDS &&
	    before.modified.nanoseconds == TEST_METADATA_MODIFIED_NANOSECONDS);
	ntfs_node_close(file);
	assert(ntfs_node_open(volume, stale_reference, &stale) == NTFS_STALE && stale == NULL);
	assert(ntfs_root(volume, &root) == NTFS_OK);
	assert(ntfs_node_link_counts(root, &counts) == NTFS_OK);
	ntfs_node_close(root);
	/* Reading and counting root can replace raw/count slots independently of
	 * the successful file metadata. Reopening still checks the base reference. */
	file = open_file(volume, &device);
	reopened = metadata(file, volume, &device, NTFS_OK, &after);
	assert(memcmp(&before, &after, sizeof(before)) == 0);
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
		assert(ntfs_operation_begin(volume, &limits, &outer) == NTFS_OK);
		assert(ntfs_operation_begin(volume, NULL, &inner) == NTFS_OK);
		(void)metadata(file, volume, &device, NTFS_RANGE, &after);
		assert(ntfs_operation_end(&inner, NULL) == NTFS_OK);
		assert(ntfs_operation_end(&outer, &usage) == NTFS_OK &&
		    usage.exhausted == NTFS_OPERATION_LIMIT_WORK);
		limits.work = reopened.work;
		assert(ntfs_operation_begin(volume, &limits, &outer) == NTFS_OK);
		device.fail_allocation = 1;
		device.fail_read = 1;
		usage = metadata(file, volume, &device, NTFS_OK, &after);
		assert(usage.read_calls == 0 && usage.allocation_calls == 0 &&
		    memcmp(&before, &after, sizeof(before)) == 0);
		assert(ntfs_operation_end(&outer, &usage) == NTFS_OK && usage.work == limits.work &&
		    usage.exhausted == NTFS_OPERATION_LIMIT_NONE);
		device.fail_allocation = 0;
		device.fail_read = 0;
		ntfs_node_close(file);
	}
	assert(ntfs_root(volume, &root) == NTFS_OK);
	(void)metadata(root, volume, &device, NTFS_OK, &after);
	ntfs_node_close(root);
	file = open_file(volume, &device);
	usage = metadata(file, volume, &device, NTFS_OK, &after);
	assert(memcmp(&before, &after, sizeof(before)) == 0);
	assert((usage.read_calls != 0) == (entries <= TEST_METADATA_SINGLE_SLOT));
	ntfs_node_close(file);
	assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
}

static void
owner_isolation(const uint8_t *large, const uint8_t *small, const uint8_t *dos)
{
	struct fuzz_device devices[] = {{.data = large, .size = TEST_IMAGE_BYTES},
	    {.data = small, .size = TEST_IMAGE_BYTES}, {.data = dos, .size = TEST_IMAGE_BYTES}};
	const uint16_t expected[] = {
	    TEST_METADATA_LARGE_NAMES, TEST_METADATA_SMALL_NAMES, TEST_METADATA_DOS_NAMES};
	struct ntfs_volume *volumes[sizeof(devices) / sizeof(*devices)];
	struct ntfs_stat before[sizeof(devices) / sizeof(*devices)], after;
	struct ntfs_node *node;
	struct ntfs_operation_usage usage;
	size_t index;

	for (index = 0; index < sizeof(devices) / sizeof(*devices); index++) {
		volumes[index] = mount_image(&devices[index], TEST_METADATA_SINGLE_SLOT);
		node = open_file(volumes[index], &devices[index]);
		(void)metadata(node, volumes[index], &devices[index], NTFS_OK, &before[index]);
		assert(before[index].links == expected[index]);
		ntfs_node_close(node);
	}
	for (index = 0; index < sizeof(devices) / sizeof(*devices); index++) {
		node = open_file(volumes[index], &devices[index]);
		usage = metadata(node, volumes[index], &devices[index], NTFS_OK, &after);
		assert(usage.read_calls == 0 && usage.allocation_calls == 0 &&
		    memcmp(&before[index], &after, sizeof(after)) == 0);
		ntfs_node_close(node);
		assert(ntfs_unmount(volumes[index]) == NTFS_OK && devices[index].memory == 0);
	}
}

static void
cold_admission(const uint8_t *bytes)
{
	const bool refused[] = {false, true};
	struct fuzz_device device = {.data = bytes, .size = TEST_IMAGE_BYTES};
	struct ntfs_volume *volume = mount_image(&device, NTFS_DEFAULT_RECORD_CACHE_ENTRIES);
	struct ntfs_node *file = open_file(volume, &device);
	struct ntfs_operation_usage cold, hot, usage;
	struct ntfs_operation_limits limits;
	struct ntfs_operation scope = {0};
	struct ntfs_stat stat;
	size_t index;

	cold = metadata(file, volume, &device, NTFS_OK, &stat);
	ntfs_node_close(file);
	file = open_file(volume, &device);
	hot = metadata(file, volume, &device, NTFS_OK, &stat);
	assert(cold.work > hot.work && hot.work > 1);
	ntfs_node_close(file);
	assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
	for (index = 0; index < sizeof(refused) / sizeof(*refused); index++) {
		volume = mount_image(&device, NTFS_DEFAULT_RECORD_CACHE_ENTRIES);
		file = open_file(volume, &device);
		ntfs_operation_default_limits(&limits);
		limits.work = cold.work - (refused[index] ? 1 : 0);
		assert(ntfs_operation_begin(volume, &limits, &scope) == NTFS_OK);
		(void)metadata(file, volume, &device, refused[index] ? NTFS_RANGE : NTFS_OK, &stat);
		assert(ntfs_operation_end(&scope, &usage) == NTFS_OK &&
		    usage.exhausted ==
			(refused[index] ? NTFS_OPERATION_LIMIT_WORK : NTFS_OPERATION_LIMIT_NONE));
		if (!refused[index]) {
			assert(usage.work == limits.work);
		}
		ntfs_node_close(file);
		file = open_file(volume, &device);
		usage = metadata(file, volume, &device, NTFS_OK, &stat);
		assert((usage.read_calls != 0) == refused[index]);
		assert((usage.allocation_calls != 0) == refused[index]);
		ntfs_node_close(file);
		assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
	}
	/* A miss with only hit-sized work must refuse publication before cold I/O. */
	volume = mount_image(&device, NTFS_DEFAULT_RECORD_CACHE_ENTRIES);
	file = open_file(volume, &device);
	limits.work = hot.work;
	assert(ntfs_operation_begin(volume, &limits, &scope) == NTFS_OK);
	usage = metadata(file, volume, &device, NTFS_RANGE, &stat);
	assert(usage.read_calls == 0 && usage.allocation_calls == 0);
	assert(ntfs_operation_end(&scope, NULL) == NTFS_OK);
	ntfs_node_close(file);
	file = open_file(volume, &device);
	usage = metadata(file, volume, &device, NTFS_OK, &stat);
	assert(usage.read_calls != 0 && usage.allocation_calls != 0);
	ntfs_node_close(file);
	assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
}

static void
failure_sweep(const uint8_t *bytes)
{
	struct fuzz_device device = {.data = bytes, .size = TEST_IMAGE_BYTES};
	struct ntfs_volume *volume = mount_image(&device, TEST_METADATA_SINGLE_SLOT);
	struct ntfs_node *file = open_file(volume, &device);
	struct ntfs_operation_usage cold, usage;
	struct ntfs_stat stat;
	size_t position;
	bool read_error;

	cold = metadata(file, volume, &device, NTFS_OK, &stat);
	assert(cold.allocation_calls != 0 && cold.read_calls != 0);
	ntfs_node_close(file);
	assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
	read_error = false;
	do {
		for (position = 1;
		    position <= (read_error ? cold.read_calls : cold.allocation_calls);
		    position++) {
			volume = mount_image(&device, TEST_METADATA_SINGLE_SLOT);
			file = open_file(volume, &device);
			device.fail_read = read_error ? position : 0;
			device.fail_allocation = read_error ? 0 : position;
			(void)metadata(
			    file, volume, &device, read_error ? NTFS_IO : NTFS_NO_MEMORY, &stat);
			device.fail_read = 0;
			device.fail_allocation = 0;
			ntfs_node_close(file);
			file = open_file(volume, &device);
			usage = metadata(file, volume, &device, NTFS_OK, &stat);
			assert(usage.read_calls != 0 && usage.allocation_calls != 0);
			ntfs_node_close(file);
			file = open_file(volume, &device);
			usage = metadata(file, volume, &device, NTFS_OK, &stat);
			assert(usage.read_calls == 0 && usage.allocation_calls == 0);
			ntfs_node_close(file);
			assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
		}
		read_error = !read_error;
	} while (read_error);
	printf("PASS: metadata publication excludes %llu allocation and %llu partial-read faults\n",
	    (unsigned long long)cold.allocation_calls, (unsigned long long)cold.read_calls);
}

static void
repeated_refusal(const uint8_t *bytes, uint64_t reference, enum ntfs_result result)
{
	struct fuzz_device device = {.data = bytes, .size = TEST_IMAGE_BYTES};
	struct ntfs_volume *volume = mount_image(&device, TEST_METADATA_SINGLE_SLOT);
	struct ntfs_node *node;
	struct ntfs_operation_usage first = {0}, repeated;
	struct ntfs_stat stat;
	size_t index;

	for (index = 0; index < TEST_METADATA_REPETITIONS; index++) {
		assert(ntfs_node_open(volume, reference, &node) == NTFS_OK);
		repeated = metadata(node, volume, &device, result, &stat);
		if (index == 0) {
			first = repeated;
		} else {
			assert(repeated.work == first.work &&
			    repeated.allocation_calls == first.allocation_calls &&
			    repeated.read_calls == first.read_calls);
		}
		ntfs_node_close(node);
	}
	assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
}

static void
size_validation(const uint8_t *bytes, enum ntfs_result expected)
{
	struct fuzz_device device = {.data = bytes, .size = TEST_IMAGE_BYTES};
	struct ntfs_volume *volume = mount_image(&device, TEST_METADATA_SINGLE_SLOT);
	struct ntfs_node *file;
	struct ntfs_operation_usage usage;
	struct ntfs_stat before, after, stat, zero = {0};
	size_t index, allocations;

	for (index = 0; index < TEST_METADATA_REPETITIONS; index++) {
		file = open_file(volume, &device);
		usage = metadata(file, volume, &device, NTFS_OK, &after);
		if (index == 0) {
			before = after;
		} else {
			assert(usage.read_calls == 0 && usage.allocation_calls == 0 &&
			    memcmp(&before, &after, sizeof(before)) == 0);
		}
		allocations = device.allocations;
		memset(&stat, -1, sizeof(stat));
		assert(ntfs_node_stat(file, &stat) == expected);
		assert(device.allocations > allocations);
		if (expected != NTFS_OK) {
			assert(memcmp(&stat, &zero, sizeof(stat)) == 0);
		} else {
			assert(
			    stat.size == TEST_METADATA_RESIDENT_BYTES && stat.allocated_size == 0);
		}
		/* Stat may populate output sizes, but never the base-metadata memo. */
		(void)metadata(file, volume, &device, NTFS_OK, &after);
		assert(memcmp(&before, &after, sizeof(before)) == 0);
		ntfs_node_close(file);
	}
	assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
}

static struct ntfs_node *
open_object(struct ntfs_volume *volume, uint32_t ordinal, uint64_t *reference)
{
	struct ntfs_node *node = NULL;

	*reference = (uint64_t)TEST_METADATA_FILE_SEQUENCE << NTFS_REFERENCE_SEQUENCE_SHIFT |
	    (TEST_METADATA_FIRST_OBJECT_RECORD + ordinal);
	assert(ntfs_node_open(volume, *reference, &node) == NTFS_OK);
	return node;
}

static void
independent_objects(const uint8_t *bytes, uint32_t count)
{
	struct fuzz_device device = {.data = bytes, .size = TEST_IMAGE_BYTES};
	struct ntfs_volume *volume = mount_image(&device, NTFS_DEFAULT_RECORD_CACHE_ENTRIES);
	struct ntfs_node *node;
	struct ntfs_operation_usage cold = {0}, usage;
	struct ntfs_stat stat;
	uint64_t reference;
	uint32_t ordinal, scan;

	for (scan = 0; scan < TEST_METADATA_REPETITIONS; scan++) {
		for (ordinal = 0; ordinal < count; ordinal++) {
			node = open_object(volume, ordinal, &reference);
			usage = metadata(node, volume, &device, NTFS_OK, &stat);
			assert(stat.reference == reference && stat.links == 1 && !stat.directory &&
			    !stat.reparse && stat.security_id == TEST_SECURITY_ID);
			if (scan == 0) {
				cold = usage;
			} else if (count == TEST_METADATA_FIT_OBJECTS) {
				assert(usage.work < cold.work);
			} else {
				assert(usage.work == cold.work);
			}
			ntfs_node_close(node);
		}
	}
	assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
}

static void
failed_collision(const uint8_t *bytes, uint32_t entries)
{
	struct fuzz_device device = {.data = bytes, .size = TEST_IMAGE_BYTES};
	struct ntfs_volume *volume = mount_image(&device, entries);
	struct ntfs_node *node;
	struct ntfs_operation_usage cold, hot, usage;
	struct ntfs_stat before, after;
	uint64_t reference;

	node = open_object(volume, 0, &reference);
	cold = metadata(node, volume, &device, NTFS_OK, &before);
	ntfs_node_close(node);
	node = open_object(volume, 0, &reference);
	hot = metadata(node, volume, &device, NTFS_OK, &after);
	assert(hot.work < cold.work && memcmp(&before, &after, sizeof(before)) == 0);
	ntfs_node_close(node);
	node = open_object(volume, NTFS_DEFAULT_RECORD_CACHE_ENTRIES, &reference);
	(void)metadata(node, volume, &device, NTFS_CORRUPT, &after);
	ntfs_node_close(node);
	/* A colliding failure must retain the previously checked owner's payload. */
	node = open_object(volume, 0, &reference);
	usage = metadata(node, volume, &device, NTFS_OK, &after);
	assert(usage.work == hot.work && memcmp(&before, &after, sizeof(before)) == 0);
	ntfs_node_close(node);
	assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
}

int
main(int argc, char **argv)
{
	const uint32_t capacities[] = {
	    0, TEST_METADATA_SINGLE_SLOT, NTFS_DEFAULT_RECORD_CACHE_ENTRIES};
	const char *hidden[] = {"reparse-unflagged.img", "reparse-unflagged-extension.img",
	    "reparse-unlisted-base.img", "reparse-named-unflagged.img",
	    "reparse-named-listed-unflagged.img"};
	uint8_t *large, *small, *dos, *bytes;
	size_t index;

	assert(argc == 4);
	large = load_image(argv[1], "namespace-large.img");
	small = load_image(argv[1], "namespace.img");
	dos = load_image(argv[1], "namespace-hidden.img");
	for (index = 0; index < sizeof(capacities) / sizeof(*capacities); index++) {
		cache_reuse(large, capacities[index]);
	}
	owner_isolation(large, small, dos);
	cold_admission(large);
	failure_sweep(large);
	for (index = 0; index < sizeof(hidden) / sizeof(*hidden); index++) {
		bytes = load_image(argv[2], hidden[index]);
		repeated_refusal(bytes, TEST_METADATA_FILE_REFERENCE, NTFS_CORRUPT);
		free(bytes);
	}
	bytes = load_image(argv[2], "case-unknown-child.img");
	repeated_refusal(bytes, TEST_METADATA_DIRECTORY_REFERENCE, NTFS_UNSUPPORTED);
	free(bytes);
	bytes = load_image(argv[2], "stat-bad-vdl.img");
	size_validation(bytes, NTFS_CORRUPT);
	free(bytes);
	size_validation(small, NTFS_OK);
	bytes = load_image(argv[3], "metadata-objects-fit.img");
	independent_objects(bytes, TEST_METADATA_FIT_OBJECTS);
	free(bytes);
	bytes = load_image(argv[3], "metadata-objects-pressure.img");
	independent_objects(bytes, TEST_METADATA_PRESSURE_OBJECTS);
	free(bytes);
	bytes = load_image(argv[3], "metadata-objects-rejected.img");
	failed_collision(bytes, TEST_METADATA_SINGLE_SLOT);
	failed_collision(bytes, NTFS_DEFAULT_RECORD_CACHE_ENTRIES);
	free(bytes);
	free(dos);
	free(small);
	free(large);
	puts("PASS: bounded checked metadata reuse across temporary nodes, disabled/single/default "
	     "capacity, independent raw/count eviction, sequence/owner/DOS isolation, exact "
	     "hot/cold "
	     "work and ancestor admission, corruption/unsupported/fault exclusion, separate size "
	     "validation and complete cleanup");
	return 0;
}
