/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_metadata.h"
#include "fuzz_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { TEST_NAME_BYTES = 128, TEST_PATH_BYTES = 4096, TEST_PARTIAL_DIVISOR = 2 };

#define TEST_REFERENCE (UINT64_C(7) << NTFS_REFERENCE_SEQUENCE_SHIFT | UINT64_C(25))
#define TEST_TIME UINT64_C(134357146906613431)
#define TEST_LSN UINT64_C(500)

static bool full_failed_read;

static uint8_t *
load(const char *directory, const char *name, const char *suffix, size_t *bytes)
{
	char *path = malloc(TEST_PATH_BYTES);
	uint8_t *data;
	FILE *file;
	long length;
	int result;

	assert(path != NULL);
	result = snprintf(path, TEST_PATH_BYTES, "%s/%s.%s", directory, name, suffix);
	assert(result > 0 && result < TEST_PATH_BYTES);
	file = fopen(path, "rb");
	free(path);
	assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
	length = ftell(file);
	assert(length > 0 && fseek(file, 0, SEEK_SET) == 0);
	*bytes = (size_t)length;
	data = malloc(*bytes);
	assert(data != NULL && fread(data, 1, *bytes, file) == *bytes);
	assert(fgetc(file) == EOF && !ferror(file) && fclose(file) == 0);
	return data;
}

static enum ntfs_result
partial_read(void *context, uint64_t offset, void *buffer, size_t bytes)
{
	struct fuzz_device *device = context;

	if (device->fail_read != 0 && device->reads + 1 == device->fail_read) {
		assert(ntfs_bounds(offset, bytes, device->size));
		memcpy(buffer, device->data + offset,
		    full_failed_read ? bytes : bytes / TEST_PARTIAL_DIVISOR);
	}
	return fuzz_read(context, offset, buffer, bytes);
}

static struct ntfs_volume *
mount(struct fuzz_device *device)
{
	struct ntfs_environment environment = fuzz_environment(device);
	struct ntfs_limits limits;
	struct ntfs_volume *volume = NULL;

	environment.read = partial_read;
	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	device->reads = 0;
	device->allocations = 0;
	assert(ntfs_mount(&environment, &limits, &volume) == NTFS_OK);
	return volume;
}

static struct ntfs_node *
open_node(struct ntfs_volume *volume, struct fuzz_device *device, uint64_t reference)
{
	struct ntfs_node *node = NULL;

	assert(ntfs_node_open(volume, reference, &node) == NTFS_OK);
	device->reads = 0;
	device->allocations = 0;
	return node;
}

static void
zero_output(const struct ntfs_write_file_plan *plan)
{
	const uint8_t *bytes = (const void *)plan;
	size_t index;

	for (index = 0; index < sizeof(*plan); index++) {
		assert(bytes[index] == 0);
	}
}

static void
oracle(const char *directory, const char *name, const struct ntfs_write_file_plan *plan)
{
	const char *suffixes[] = {"before", "after", "protected"};
	const uint8_t *actual[] = {plan->before, plan->after, plan->protected_after};
	uint8_t *expected;
	size_t bytes, index;

	for (index = 0; index < sizeof(suffixes) / sizeof(*suffixes); index++) {
		expected = load(directory, name, suffixes[index], &bytes);
		assert(bytes == NTFS_WRITE_RECORD_BYTES);
		assert(memcmp(actual[index], expected, bytes) == 0);
		free(expected);
	}
}

static void
vectors(const char *directory)
{
	struct ntfs_write_file_plan *plan = malloc(sizeof(*plan));
	struct ntfs_volume *volume;
	struct ntfs_node *node;
	struct fuzz_device device = {0};
	char *path = malloc(TEST_PATH_BYTES);
	char name[TEST_NAME_BYTES];
	FILE *rows;
	uint8_t *data, *original;
	unsigned long long reference, time, lsn, mft, vcn, lcn, physical;
	unsigned cluster, record, attribute, change, snapshot, count = 0;
	size_t bytes;
	int code, parsed;

	assert(plan != NULL && path != NULL);
	parsed = snprintf(path, TEST_PATH_BYTES, "%s/cases.rows", directory);
	assert(parsed > 0 && parsed < TEST_PATH_BYTES);
	rows = fopen(path, "rb");
	assert(rows != NULL);
	while ((parsed = fscanf(rows, "%127s %d %llu %llu %llu %llu %llu %llu %llu %u %u %u %u %u",
		    name, &code, &reference, &time, &lsn, &mft, &vcn, &lcn, &physical, &cluster,
		    &record, &attribute, &change, &snapshot)) != EOF) {
		assert(parsed == 14);
		data = load(directory, name, "img", &bytes);
		original = malloc(bytes);
		assert(original != NULL);
		memcpy(original, data, bytes);
		device.data = data;
		device.size = bytes;
		volume = mount(&device);
		node = open_node(volume, &device, reference);
		memset(plan, -1, sizeof(*plan));
		assert(code >= NTFS_OK && code <= NTFS_BUSY);
		assert(
		    ntfs_write_prepare_metadata(node, time, lsn, plan) == (enum ntfs_result)code);
		if (code == NTFS_OK) {
			assert(plan->reference == reference && plan->mft_reference == mft &&
			    plan->target_vcn == vcn && plan->target_lcn == lcn &&
			    plan->cluster_physical == physical && plan->cluster_index == cluster &&
			    plan->record_offset == record && plan->attribute_offset == attribute &&
			    plan->change_bytes == change && plan->snapshot_bytes == snapshot);
			assert(memcmp(plan->before, node->record, NTFS_WRITE_RECORD_BYTES) == 0);
		} else {
			zero_output(plan);
		}
		ntfs_node_close(node);
		assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
		if (code == NTFS_OK) {
			oracle(directory, name, plan);
		}
		assert(memcmp(data, original, bytes) == 0);
		free(original);
		free(data);
		count++;
	}
	assert(!ferror(rows) && fclose(rows) == 0 && count != 0);
	printf("PASS: %u independent complete FILE/address/admission profiles\n", count);
	free(path);
	free(plan);
}

#define TEST_RESIDENT_REFERENCE (UINT64_C(7) << NTFS_REFERENCE_SEQUENCE_SHIFT | UINT64_C(24))
static const uint8_t resident_payload[] = "MACHLIN_RESIDENT";

enum { TEST_RESIDENT_OFFSET = 5 };

static enum ntfs_result
metadata_prepare(struct ntfs_node *node, uint64_t filetime, uint64_t lsn,
    struct ntfs_write_file_plan *plan, bool resident)
{
	if (resident) {
		return ntfs_write_prepare_resident_metadata(node, filetime, lsn,
		    TEST_RESIDENT_OFFSET, resident_payload, sizeof(resident_payload) - 1, plan);
	}
	return ntfs_write_prepare_metadata(node, filetime, lsn, plan);
}

static void
resident_vectors(const char *directory)
{
	struct ntfs_write_file_plan *plan = malloc(sizeof(*plan));
	struct ntfs_volume *volume;
	struct ntfs_node *node;
	struct fuzz_device device = {0};
	char *path = malloc(TEST_PATH_BYTES);
	char name[TEST_NAME_BYTES];
	FILE *rows;
	uint8_t *data, *original, *payload;
	unsigned long long reference, time, lsn, offset;
	unsigned requested, record, attribute, count = 0;
	size_t bytes, payload_bytes;
	int code, parsed;

	assert(plan != NULL && path != NULL);
	parsed = snprintf(path, TEST_PATH_BYTES, "%s/cases.rows", directory);
	assert(parsed > 0 && parsed < TEST_PATH_BYTES);
	rows = fopen(path, "rb");
	assert(rows != NULL);
	while ((parsed = fscanf(rows, "%127s %d %llu %llu %llu %llu %u %u %u", name, &code,
		    &reference, &time, &lsn, &offset, &requested, &record, &attribute)) != EOF) {
		assert(parsed == 9);
		data = load(directory, name, "img", &bytes);
		payload = load(directory, name, "payload", &payload_bytes);
		assert(payload_bytes == requested);
		original = malloc(bytes);
		assert(original != NULL);
		memcpy(original, data, bytes);
		device.data = data;
		device.size = bytes;
		volume = mount(&device);
		node = open_node(volume, &device, reference);
		memset(plan, -1, sizeof(*plan));
		assert(ntfs_write_prepare_resident_metadata(node, time, lsn, offset, payload,
			   requested, plan) == (enum ntfs_result)code);
		if (code == NTFS_OK) {
			assert(plan->reference == reference && plan->resident_bytes == requested &&
			    plan->resident_record_offset == record &&
			    plan->resident_attribute_offset == attribute);
			assert(memcmp(plan->before, node->record, NTFS_WRITE_RECORD_BYTES) == 0);
		} else {
			zero_output(plan);
		}
		ntfs_node_close(node);
		assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
		if (code == NTFS_OK) {
			oracle(directory, name, plan);
		}
		assert(memcmp(data, original, bytes) == 0);
		free(payload);
		free(original);
		free(data);
		count++;
	}
	assert(!ferror(rows) && fclose(rows) == 0 && count != 0);
	printf("PASS: %u independent resident FILE/data/USA/admission profiles\n", count);
	free(path);
	free(plan);
}

static void
faults(const char *directory, bool resident)
{
	struct ntfs_write_file_plan *plan = malloc(sizeof(*plan));
	struct ntfs_volume *volume;
	struct ntfs_node *node;
	struct fuzz_device device = {0};
	uint8_t *data, *original;
	size_t bytes, allocations, reads, position;
	unsigned mode;

	assert(plan != NULL);
	data = load(directory, "ordinary", "img", &bytes);
	original = malloc(bytes);
	assert(original != NULL);
	memcpy(original, data, bytes);
	device.data = data;
	device.size = bytes;
	volume = mount(&device);
	node = open_node(volume, &device, (resident ? TEST_RESIDENT_REFERENCE : TEST_REFERENCE));
	assert(metadata_prepare(node, TEST_TIME, TEST_LSN, plan, resident) == NTFS_OK);
	allocations = device.allocations;
	reads = device.reads;
	assert(allocations != 0 && reads != 0);
	ntfs_node_close(node);
	assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
	for (mode = 0; mode < 3; mode++) {
		full_failed_read = mode == 2;
		for (position = 1; position <= (mode == 0 ? allocations : reads); position++) {
			volume = mount(&device);
			node = open_node(
			    volume, &device, (resident ? TEST_RESIDENT_REFERENCE : TEST_REFERENCE));
			device.fail_allocation = mode == 0 ? position : 0;
			device.fail_read = mode == 0 ? 0 : position;
			memset(plan, -1, sizeof(*plan));
			assert(metadata_prepare(node, TEST_TIME, TEST_LSN, plan, resident) ==
			    (mode == 0 ? NTFS_NO_MEMORY : NTFS_IO));
			zero_output(plan);
			device.fail_allocation = 0;
			device.fail_read = 0;
			device.reads = 0;
			assert(
			    metadata_prepare(node, TEST_TIME, TEST_LSN, plan, resident) == NTFS_OK);
			oracle(directory, "ordinary", plan);
			ntfs_node_close(node);
			assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
		}
	}
	assert(memcmp(data, original, bytes) == 0);
	printf("PASS: %zu allocation and %zu partial/full read faults, zero outputs and retry\n",
	    allocations, reads);
	free(original);
	free(data);
	free(plan);
}

static void
preflight(const char *directory, bool resident)
{
	struct ntfs_write_file_plan *plan = malloc(sizeof(*plan));
	struct fuzz_device device = {0};
	struct ntfs_volume *volume;
	struct ntfs_node *node;
	struct ntfs_operation scope = {0};
	struct ntfs_operation_limits limits;
	struct ntfs_info info;
	uint8_t *data;
	size_t bytes, reads, allocations;
	unsigned profile;

	assert(plan != NULL);
	data = load(directory, "ordinary", "img", &bytes);
	device.data = data;
	device.size = bytes;
	volume = mount(&device);
	node = open_node(volume, &device, (resident ? TEST_RESIDENT_REFERENCE : TEST_REFERENCE));
	reads = device.reads;
	allocations = device.allocations;
	assert(metadata_prepare(NULL, TEST_TIME, TEST_LSN, plan, resident) == NTFS_INVALID);
	assert(metadata_prepare(node, TEST_TIME, TEST_LSN, NULL, resident) == NTFS_INVALID);
	assert(metadata_prepare(node, TEST_TIME, TEST_LSN, (void *)node->record, resident) ==
	    NTFS_INVALID);
	assert(metadata_prepare(node, TEST_TIME, TEST_LSN, (void *)node, resident) == NTFS_INVALID);
	assert(
	    metadata_prepare(node, TEST_TIME, TEST_LSN, (void *)volume, resident) == NTFS_INVALID);
	assert(device.reads == reads && device.allocations == allocations);
	if (resident) {
		assert(ntfs_write_prepare_resident_metadata(node, TEST_TIME, TEST_LSN,
			   TEST_RESIDENT_OFFSET, NULL, sizeof(resident_payload) - 1,
			   plan) == NTFS_INVALID);
		assert(ntfs_write_prepare_resident_metadata(node, TEST_TIME, TEST_LSN,
			   TEST_RESIDENT_OFFSET, resident_payload, 0, plan) == NTFS_INVALID);
		assert(ntfs_write_prepare_resident_metadata(node, TEST_TIME, TEST_LSN,
			   TEST_RESIDENT_OFFSET, plan, sizeof(resident_payload) - 1,
			   plan) == NTFS_INVALID);
		assert(device.reads == reads && device.allocations == allocations);
	}
	info = volume->info;
	for (profile = 0; profile < 5; profile++) {
		volume->info = info;
		switch (profile) {
		case 0:
			volume->info.sector_size *= 2;
			break;
		case 1:
			volume->info.cluster_size *= 2;
			break;
		case 2:
			volume->info.record_size /= 2;
			break;
		case 3:
			volume->info.major_version++;
			break;
		default:
			volume->info.minor_version--;
			break;
		}
		memset(plan, -1, sizeof(*plan));
		assert(metadata_prepare(node, TEST_TIME, TEST_LSN, plan, resident) ==
		    NTFS_UNSUPPORTED);
		zero_output(plan);
		assert(device.reads == reads && device.allocations == allocations);
	}
	volume->info = info;
	ntfs_operation_default_limits(&limits);
	limits.work = 1;
	assert(ntfs_operation_begin(volume, &limits, &scope) == NTFS_OK);
	memset(plan, -1, sizeof(*plan));
	assert(metadata_prepare(node, TEST_TIME, TEST_LSN, plan, resident) == NTFS_RANGE);
	zero_output(plan);
	assert(ntfs_operation_end(&scope, NULL) == NTFS_OK);
	device.reads = 0;
	assert(metadata_prepare(node, TEST_TIME, TEST_LSN, plan, resident) == NTFS_OK);
	oracle(directory, "ordinary", plan);
	ntfs_node_close(node);
	assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
	free(data);
	free(plan);
	puts("PASS: pointer/geometry preflight and compound work admission");
}

int
main(int argc, char **argv)
{
	assert(argc == 2 || argc == 3);
	vectors(argv[1]);
	faults(argv[1], false);
	preflight(argv[1], false);
	if (argc == 3) {
		resident_vectors(argv[2]);
		faults(argv[2], true);
		preflight(argv[2], true);
	}
	return 0;
}
