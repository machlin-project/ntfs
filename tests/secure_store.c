/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/security.h>
#include "fuzz_device.h"
#include "fixture.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_STORE_ENTRIES = 4,
	TEST_SENTINEL = 0xa5,
	TEST_SDS_LCN = 160,
	TEST_SII_LCN = 232,
	TEST_SDS_BLOCK_BYTES = 256 * 1024,
	TEST_SDS_GAP_OFFSET = TEST_SECTOR_BYTES,
	TEST_FREE_SLOT = 2
};

struct store_device {
	struct fuzz_device device;
	uint64_t read_bytes, allocation_bytes, forbidden_first, forbidden_end;
	bool full_failure;
};

static void *
allocate(void *context, size_t size)
{
	struct store_device *device = context;

	device->allocation_bytes += size;
	return fuzz_allocate(&device->device, size);
}

static void
release(void *context, void *bytes, size_t size)
{
	struct store_device *device = context;

	fuzz_release(&device->device, bytes, size);
}

static enum ntfs_result
read_bytes(void *context, uint64_t offset, void *bytes, size_t size)
{
	struct store_device *device = context;
	struct fuzz_device *source = &device->device;
	size_t partial;

	device->read_bytes += size;
	if (device->forbidden_end != 0) {
		assert(offset + size <= device->forbidden_first || offset >= device->forbidden_end);
	}
	if (source->fail_read != 0 && source->reads + 1 == source->fail_read) {
		assert(offset <= source->size && size <= source->size - offset);
		partial = device->full_failure ? size : size / 2;
		memcpy(bytes, source->data + offset, partial);
	}
	return fuzz_read(source, offset, bytes, size);
}

static uint8_t *
load(const char *directory, const char *name, size_t *size)
{
	char *path;
	FILE *source;
	long length;
	uint8_t *bytes;
	size_t capacity = strlen(directory) + sizeof("/") + strlen(name);

	path = malloc(capacity);
	assert(path != NULL && snprintf(path, capacity, "%s/%s", directory, name) > 0);
	source = fopen(path, "rb");
	free(path);
	assert(source != NULL && fseek(source, 0, SEEK_END) == 0);
	length = ftell(source);
	assert(length > 0 && length <= TEST_IMAGE_BYTES && fseek(source, 0, SEEK_SET) == 0);
	bytes = malloc((size_t)length);
	assert(bytes != NULL && fread(bytes, 1, (size_t)length, source) == (size_t)length);
	assert(fclose(source) == 0);
	*size = (size_t)length;
	return bytes;
}

static void
reset(struct store_device *device)
{
	device->device.reads = 0;
	device->device.allocations = 0;
	device->device.fail_read = 0;
	device->device.fail_allocation = 0;
	device->read_bytes = 0;
	device->allocation_bytes = 0;
}

static struct ntfs_volume *
mount_device(struct store_device *device, uint64_t live)
{
	struct ntfs_environment environment = {
	    NTFS_API_VERSION, device, device->device.size, read_bytes, allocate, release};
	struct ntfs_limits limits;
	struct ntfs_volume *volume = NULL;

	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	if (live != 0) {
		limits.max_live_bytes = live;
	}
	assert(ntfs_mount(&environment, &limits, &volume) == NTFS_OK);
	reset(device);
	return volume;
}

static enum ntfs_result
validate(struct store_device *device, struct ntfs_volume *volume,
    const struct ntfs_operation_limits *limits, struct ntfs_security_store_report *report,
    struct ntfs_operation_usage *usage)
{
	struct ntfs_operation operation = {0};
	size_t memory = device->device.memory;
	enum ntfs_result result;

	assert(ntfs_operation_begin(volume, limits, &operation) == NTFS_OK);
	memset(report, TEST_SENTINEL, sizeof(*report));
	result = ntfs_security_store_validate(volume, NULL, report);
	assert(ntfs_operation_end(&operation, usage) == NTFS_OK);
	assert(report->result == result && report->complete == (result == NTFS_OK));
	assert(device->device.memory == memory);
	assert(
	    usage->read_calls == device->device.reads && usage->read_bytes == device->read_bytes);
	assert(usage->allocation_calls == device->device.allocations &&
	    usage->allocation_bytes == device->allocation_bytes);
	return result;
}

static void
set_limit(struct ntfs_operation_limits *limits, enum ntfs_operation_limit dimension,
    const struct ntfs_operation_usage *usage, bool below)
{
	switch (dimension) {
	case NTFS_OPERATION_LIMIT_READ_CALLS:
		limits->read_calls = usage->read_calls - below;
		break;
	case NTFS_OPERATION_LIMIT_READ_BYTES:
		limits->read_bytes = usage->read_bytes - below;
		break;
	case NTFS_OPERATION_LIMIT_ALLOCATION_CALLS:
		limits->allocation_calls = usage->allocation_calls - below;
		break;
	case NTFS_OPERATION_LIMIT_ALLOCATION_BYTES:
		limits->allocation_bytes = usage->allocation_bytes - below;
		break;
	case NTFS_OPERATION_LIMIT_WORK:
		limits->work = usage->work - below;
		break;
	default:
		assert(false);
	}
}

static void
exercise(
    const char *directory, const char *name, bool live_boundary, size_t *allocations, size_t *reads)
{
	struct store_device device = {0};
	struct ntfs_volume *volume;
	struct ntfs_security *sibling = NULL;
	struct ntfs_security_store_report report;
	struct ntfs_operation_usage baseline, usage;
	struct ntfs_operation_limits limits;
	uint8_t *image, *original;
	size_t size, index, memory;
	enum ntfs_operation_limit dimension;
	enum ntfs_result result;
	bool full;

	image = load(directory, name, &size);
	original = malloc(size);
	assert(original != NULL);
	memcpy(original, image, size);
	device.device.data = image;
	device.device.size = size;
	volume = mount_device(&device, 0);
	assert(ntfs_security_resolve(volume, TEST_SECURITY_ID, &sibling) == NTFS_OK);
	reset(&device);
	assert(validate(&device, volume, NULL, &report, &baseline) == NTFS_OK);
	memory = device.device.memory;
	*allocations += baseline.allocation_calls;
	*reads += baseline.read_calls;
	for (index = 1; index <= baseline.allocation_calls; index++) {
		reset(&device);
		device.device.fail_allocation = index;
		assert(validate(&device, volume, NULL, &report, &usage) == NTFS_NO_MEMORY);
		assert(device.device.memory == memory && ntfs_security_size(sibling) > 0);
		reset(&device);
		assert(validate(&device, volume, NULL, &report, &usage) == NTFS_OK);
	}
	for (full = false;; full = true) {
		device.full_failure = full;
		for (index = 1; index <= baseline.read_calls; index++) {
			reset(&device);
			device.device.fail_read = index;
			assert(validate(&device, volume, NULL, &report, &usage) == NTFS_IO);
			reset(&device);
			assert(validate(&device, volume, NULL, &report, &usage) == NTFS_OK);
		}
		if (full) {
			break;
		}
	}
	for (dimension = NTFS_OPERATION_LIMIT_READ_CALLS; dimension <= NTFS_OPERATION_LIMIT_WORK;
	    dimension++) {
		ntfs_operation_default_limits(&limits);
		set_limit(&limits, dimension, &baseline, false);
		reset(&device);
		assert(validate(&device, volume, &limits, &report, &usage) == NTFS_OK);
		ntfs_operation_default_limits(&limits);
		set_limit(&limits, dimension, &baseline, true);
		reset(&device);
		result = validate(&device, volume, &limits, &report, &usage);
		assert(result == NTFS_RANGE || result == NTFS_NO_MEMORY);
		assert(usage.exhausted == dimension);
	}
	ntfs_security_close(sibling);
	assert(ntfs_unmount(volume) == NTFS_OK && device.device.memory == 0);
	/* Repeat the same owner/sibling geometry at the measured aggregate cap. */
	for (index = 0; live_boundary && index < 2; index++) {
		reset(&device);
		volume = mount_device(&device, baseline.peak_live_bytes - index);
		assert(ntfs_security_resolve(volume, TEST_SECURITY_ID, &sibling) == NTFS_OK);
		reset(&device);
		result = validate(&device, volume, NULL, &report, &usage);
		assert(result == (index == 0 ? NTFS_OK : NTFS_NO_MEMORY));
		assert(usage.exhausted ==
		    (index == 0 ? NTFS_OPERATION_LIMIT_NONE : NTFS_OPERATION_LIMIT_LIVE_BYTES));
		ntfs_security_close(sibling);
		assert(ntfs_unmount(volume) == NTFS_OK && device.device.memory == 0);
	}
	assert(memcmp(image, original, size) == 0);
	free(original);
	free(image);
}

static void
contracts(const char *directory)
{
	struct store_device device = {0};
	struct ntfs_volume *volume;
	struct ntfs_security_store_limits limits;
	struct ntfs_security_store_report report, zero = {0};
	uint8_t *image;
	size_t size;

	ntfs_security_store_default_limits(NULL);
	ntfs_security_store_default_limits(&limits);
	assert(limits.max_descriptors == NTFS_SECURITY_STORE_DEFAULT_DESCRIPTORS);
	image = load(directory, "secure-store-leaf.img", &size);
	device.device.data = image;
	device.device.size = size;
	volume = mount_device(&device, 0);
	zero.result = NTFS_INVALID;
	assert(ntfs_security_store_validate(volume, NULL, NULL) == NTFS_INVALID);
	assert(ntfs_security_store_validate(NULL, NULL, &report) == NTFS_INVALID);
	assert(memcmp(&report, &zero, sizeof(report)) == 0);
	limits.max_descriptors = 0;
	assert(ntfs_security_store_validate(volume, &limits, &report) == NTFS_INVALID);
	assert(memcmp(&report, &zero, sizeof(report)) == 0);
	limits.max_descriptors = NTFS_SECURITY_STORE_MAX_DESCRIPTORS + 1;
	assert(ntfs_security_store_validate(volume, &limits, &report) == NTFS_INVALID);
	assert(device.device.reads == 0 && device.device.allocations == 0);
	limits.max_descriptors = TEST_STORE_ENTRIES;
	assert(ntfs_security_store_validate(volume, &limits, &report) == NTFS_OK);
	limits.max_descriptors--;
	assert(ntfs_security_store_validate(volume, &limits, &report) == NTFS_RANGE);
	assert(report.descriptor_limit && report.sii_entries == limits.max_descriptors &&
	    !report.complete);
	assert(report.descriptors == 0 && report.stage == NTFS_SECURITY_STORE_SII);
	device.forbidden_first = (uint64_t)TEST_SDS_LCN * TEST_CLUSTER_BYTES + TEST_SDS_GAP_OFFSET;
	device.forbidden_end = (uint64_t)TEST_SDS_LCN * TEST_CLUSTER_BYTES + TEST_SDS_BLOCK_BYTES;
	assert(ntfs_security_store_validate(volume, NULL, &report) == NTFS_OK);
	assert(ntfs_unmount(volume) == NTFS_OK && device.device.memory == 0);
	free(image);
	image = load(directory, "secure-store-free-garbage.img", &size);
	device.device.data = image;
	device.device.size = size;
	device.forbidden_end = 0;
	volume = mount_device(&device, 0);
	device.forbidden_first = (uint64_t)(TEST_SII_LCN + TEST_FREE_SLOT) * TEST_CLUSTER_BYTES;
	device.forbidden_end = device.forbidden_first + TEST_CLUSTER_BYTES;
	assert(ntfs_security_store_validate(volume, NULL, &report) == NTFS_OK);
	assert(ntfs_unmount(volume) == NTFS_OK && device.device.memory == 0);
	free(image);
}

int
main(int argc, char **argv)
{
	static const char *const images[] = {"secure-store-leaf.img", "secure-store-tree-512.img",
	    "secure-store-tree-8192.img", "secure-store-catalog.img", "secure-store-listed.img",
	    "secure-store-maximum.img"};
	size_t index, allocations = 0, reads = 0;

	assert(argc == 2);
	contracts(argv[1]);
	for (index = 0; index < sizeof(images) / sizeof(images[0]); index++) {
		exercise(argv[1], images[index], index == sizeof(images) / sizeof(images[0]) - 1,
		    &allocations, &reads);
	}
	printf("PASS: %zu store allocation faults, %zu partial/full read fault positions, caps, "
	       "five operation dimensions and live storage\n",
	    allocations, reads);
	return 0;
}
