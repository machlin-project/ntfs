/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/validate.h>
#include "fuzz_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_IMAGE_BYTES = 8 * 1024 * 1024,
	TEST_RECORDS = 64,
	TEST_BASE_RECORDS = 9,
	TEST_PRIMARY_NAMES = 8,
	TEST_CLAIMED_CLUSTERS = 53,
	TEST_PHYSICAL_RUNS = 7,
	TEST_STREAMS = 6,
	TEST_RECORD_CAP = 1048576,
	TEST_RUN_CAP = 1048576,
	TEST_LINK_CAP = 1048576,
	TEST_BUDGET_KINDS = 7,
	TEST_CLUSTER_BYTES = 4096,
	TEST_BAD_CLUSTER = 160
};

static void
load_image(const char *directory, const char *name, struct fuzz_device *device)
{
	char *path;
	FILE *source;
	long size;
	size_t length = strlen(directory) + sizeof("/") + strlen(name);

	path = malloc(length);
	assert(path != NULL);
	assert(snprintf(path, length, "%s/%s", directory, name) > 0);
	source = fopen(path, "rb");
	free(path);
	assert(source != NULL && fseek(source, 0, SEEK_END) == 0);
	size = ftell(source);
	assert(size > 0 && size <= TEST_IMAGE_BYTES && fseek(source, 0, SEEK_SET) == 0);
	device->data = malloc((size_t)size);
	assert(device->data != NULL);
	device->size = (size_t)size;
	assert(fread((void *)device->data, 1, device->size, source) == device->size);
	assert(fclose(source) == 0);
}

static enum ntfs_result
validate(struct fuzz_device *device, const struct ntfs_validation_limits *limits,
    struct ntfs_validation_report *report, uint32_t cache)
{
	struct ntfs_environment environment = fuzz_environment(device);
	struct ntfs_limits core_limits;
	enum ntfs_result result;

	device->reads = 0;
	device->allocations = 0;
	ntfs_default_limits(&core_limits);
	core_limits.record_cache_entries = cache;
	memset(report, 0xff, sizeof(*report));
	result = ntfs_validate(&environment, &core_limits, limits, report);
	assert(result == report->result && device->memory == 0);
	assert(
	    device->reads == report->read_calls && device->allocations == report->allocation_calls);
	assert(report->complete == (result == NTFS_OK));
	if (limits != NULL) {
		assert(report->read_calls <= limits->max_read_calls);
		assert(report->read_bytes <= limits->max_read_bytes);
		assert(report->work_units <= limits->max_work_units);
		assert(report->peak_memory_bytes <= limits->max_memory_bytes);
	}
	return result;
}

static void
check_success(struct fuzz_device *device, bool extension)
{
	struct ntfs_validation_report report;
	unsigned cache;

	for (cache = 0; cache < 2; cache++) {
		assert(validate(device, NULL, &report, cache) == NTFS_OK);
		assert(report.stage == NTFS_VALIDATION_FINISHED &&
		    report.exhausted == NTFS_VALIDATION_LIMIT_NONE);
		assert(
		    report.reference == 0 && report.related_reference == 0 && report.cluster == 0);
		assert(
		    report.record_slots == TEST_RECORDS && report.records_scanned == TEST_RECORDS);
		assert(report.base_records == TEST_BASE_RECORDS &&
		    report.extension_records == (extension ? 1 : 0));
		assert(report.filename_attributes == TEST_PRIMARY_NAMES &&
		    report.index_entries == TEST_PRIMARY_NAMES);
		assert(report.directories == 1 && report.deferred_dos_link_counts == 0);
		assert(
		    report.physical_runs == TEST_PHYSICAL_RUNS && report.streams == TEST_STREAMS);
		assert(report.claimed_clusters == TEST_CLAIMED_CLUSTERS &&
		    report.allocated_clusters == TEST_CLAIMED_CLUSTERS);
		assert(report.unclaimed_clusters == 0);
	}
}

static void
check_faults(struct fuzz_device *device)
{
	struct ntfs_validation_report baseline, report;
	uint8_t *original;
	size_t i;

	original = malloc(device->size);
	assert(original != NULL);
	memcpy(original, device->data, device->size);
	assert(validate(device, NULL, &baseline, 0) == NTFS_OK);
	for (i = 1; i <= baseline.allocation_calls; i++) {
		device->fail_allocation = i;
		assert(validate(device, NULL, &report, 0) == NTFS_NO_MEMORY);
		assert(report.exhausted == NTFS_VALIDATION_LIMIT_NONE && !report.complete);
		assert(report.stage != NTFS_VALIDATION_FINISHED);
		device->fail_allocation = 0;
		assert(validate(device, NULL, &report, 0) == NTFS_OK);
		assert(memcmp(original, device->data, device->size) == 0);
	}
	for (i = 1; i <= baseline.read_calls; i++) {
		device->fail_read = i;
		assert(validate(device, NULL, &report, 0) == NTFS_IO);
		assert(report.exhausted == NTFS_VALIDATION_LIMIT_NONE && !report.complete);
		assert(report.stage != NTFS_VALIDATION_FINISHED);
		device->fail_read = 0;
		assert(validate(device, NULL, &report, 0) == NTFS_OK);
		assert(memcmp(original, device->data, device->size) == 0);
	}
	printf("validation faults: %zu allocations, %zu reads\n", (size_t)baseline.allocation_calls,
	    (size_t)baseline.read_calls);
	free(original);
}

static void
check_budgets(struct fuzz_device *device)
{
	struct ntfs_validation_limits limits;
	struct ntfs_validation_report baseline, report;
	enum ntfs_validation_limit expected;
	unsigned i;

	assert(validate(device, NULL, &baseline, 0) == NTFS_OK);
	for (i = 0; i < TEST_BUDGET_KINDS; i++) {
		ntfs_validation_default_limits(&limits);
		expected = (enum ntfs_validation_limit)(NTFS_VALIDATION_LIMIT_MEMORY + i);
		switch (expected) {
		case NTFS_VALIDATION_LIMIT_MEMORY:
			limits.max_memory_bytes = baseline.peak_memory_bytes - 1;
			break;
		case NTFS_VALIDATION_LIMIT_READ_CALLS:
			limits.max_read_calls = baseline.read_calls - 1;
			break;
		case NTFS_VALIDATION_LIMIT_READ_BYTES:
			limits.max_read_bytes = baseline.read_bytes - 1;
			break;
		case NTFS_VALIDATION_LIMIT_WORK:
			limits.max_work_units = baseline.work_units - 1;
			break;
		case NTFS_VALIDATION_LIMIT_RECORDS:
			limits.max_records = TEST_RECORDS - 1;
			break;
		case NTFS_VALIDATION_LIMIT_RUNS:
			limits.max_runs = TEST_PHYSICAL_RUNS - 1;
			break;
		case NTFS_VALIDATION_LIMIT_LINKS:
			limits.max_links = 2 * TEST_PRIMARY_NAMES - 1;
			break;
		default:
			assert(false);
		}
		assert(validate(device, &limits, &report, 0) == NTFS_RANGE);
		assert(report.exhausted == expected && !report.complete);
		assert(validate(device, NULL, &report, 0) == NTFS_OK);
	}
	ntfs_validation_default_limits(&limits);
	limits.max_records = TEST_RECORDS;
	limits.max_runs = TEST_PHYSICAL_RUNS;
	limits.max_links = 2 * TEST_PRIMARY_NAMES;
	assert(validate(device, &limits, &report, 0) == NTFS_OK);
	ntfs_validation_default_limits(&limits);
	limits.max_memory_bytes = baseline.peak_memory_bytes;
	limits.max_read_calls = baseline.read_calls;
	limits.max_read_bytes = baseline.read_bytes;
	limits.max_work_units = baseline.work_units;
	assert(validate(device, &limits, &report, 0) == NTFS_OK);
	ntfs_validation_default_limits(&limits);
	limits.max_memory_bytes = 1;
	assert(validate(device, &limits, &report, 0) == NTFS_RANGE);
	assert(report.exhausted == NTFS_VALIDATION_LIMIT_MEMORY &&
	    report.stage == NTFS_VALIDATION_MOUNT);
	ntfs_validation_default_limits(&limits);
	limits.max_work_units = 1;
	assert(validate(device, &limits, &report, 0) == NTFS_RANGE);
	assert(report.exhausted == NTFS_VALIDATION_LIMIT_WORK &&
	    report.stage == NTFS_VALIDATION_MOUNT);
}

static void
check_invalid(struct fuzz_device *device)
{
	struct ntfs_environment environment = fuzz_environment(device), invalid;
	struct ntfs_validation_report report;
	struct ntfs_validation_limits limits;
	unsigned i;

	assert(ntfs_validate(&environment, NULL, NULL, NULL) == NTFS_INVALID);
	assert(ntfs_validate(NULL, NULL, NULL, &report) == NTFS_INVALID);
	assert(!report.complete && report.stage == NTFS_VALIDATION_SETUP);
	for (i = 0; i < 4; i++) {
		invalid = environment;
		switch (i) {
		case 0:
			invalid.api_version++;
			break;
		case 1:
			invalid.read = NULL;
			break;
		case 2:
			invalid.allocate = NULL;
			break;
		default:
			invalid.release = NULL;
		}
		assert(ntfs_validate(&invalid, NULL, NULL, &report) == NTFS_INVALID &&
		    !report.complete);
	}
	for (i = 0; i < TEST_BUDGET_KINDS + 3; i++) {
		ntfs_validation_default_limits(&limits);
		switch (i) {
		case 0:
			limits.max_records = 0;
			break;
		case 1:
			limits.max_runs = 0;
			break;
		case 2:
			limits.max_links = 0;
			break;
		case 3:
			limits.max_memory_bytes = 0;
			break;
		case 4:
			limits.max_read_calls = 0;
			break;
		case 5:
			limits.max_read_bytes = 0;
			break;
		case 6:
			limits.max_work_units = 0;
			break;
		case 7:
			limits.max_records = TEST_RECORD_CAP + 1;
			break;
		case 8:
			limits.max_runs = TEST_RUN_CAP + 1;
			break;
		default:
			limits.max_links = TEST_LINK_CAP + 1;
		}
		assert(validate(device, &limits, &report, 0) == NTFS_INVALID);
		assert(report.stage == NTFS_VALIDATION_SETUP &&
		    report.exhausted == NTFS_VALIDATION_LIMIT_NONE);
		assert(report.read_calls == 0 && report.allocation_calls == 0);
	}
}

static enum ntfs_result
reject_bad_cluster_read(void *context, uint64_t offset, void *bytes, size_t size)
{
	uint64_t bad_first = (uint64_t)TEST_BAD_CLUSTER * TEST_CLUSTER_BYTES;
	uint64_t bad_end = bad_first + TEST_CLUSTER_BYTES;

	assert(offset >= bad_end || (offset <= bad_first && size <= bad_first - offset));
	return fuzz_read(context, offset, bytes, size);
}

static void
check_bad_cluster(struct fuzz_device *device)
{
	struct ntfs_environment environment = fuzz_environment(device);
	struct ntfs_validation_report report;

	environment.read = reject_bad_cluster_read;
	assert(ntfs_validate(&environment, NULL, NULL, &report) == NTFS_OK);
	assert(report.complete && report.claimed_clusters == TEST_CLAIMED_CLUSTERS + 1);
	assert(device->memory == 0);
}

static void
check_private_owner(struct fuzz_device *device)
{
	struct ntfs_environment environment = fuzz_environment(device);
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *root = NULL;
	struct ntfs_stat before, after;
	struct ntfs_validation_report report;
	size_t memory, reads;

	device->reads = 0;
	device->allocations = 0;
	assert(ntfs_mount(&environment, NULL, &volume) == NTFS_OK);
	assert(ntfs_root(volume, &root) == NTFS_OK && ntfs_node_stat(root, &before) == NTFS_OK);
	memory = device->memory;
	assert(memory != 0);
	assert(ntfs_validate(&environment, NULL, NULL, &report) == NTFS_OK);
	assert(device->memory == memory && report.complete);
	reads = device->reads;
	assert(ntfs_node_stat(root, &after) == NTFS_OK && device->reads == reads);
	assert(
	    before.reference == after.reference && before.case_sensitive == after.case_sensitive);
	assert(ntfs_unmount(volume) == NTFS_BUSY);
	ntfs_node_close(root);
	assert(ntfs_unmount(volume) == NTFS_OK && device->memory == 0);
}

int
main(int argc, char **argv)
{
	const char *images[] = {"validation-standard.img", "validation-listed.img",
	    "validation-extension-filename.img", "validation-bad-clusters-owned.img"};
	struct fuzz_device device;
	size_t i;

	assert(argc == 2);
	ntfs_validation_default_limits(NULL);
	for (i = 0; i < sizeof(images) / sizeof(images[0]); i++) {
		device = (struct fuzz_device){0};
		load_image(argv[1], images[i], &device);
		if (i + 1 == sizeof(images) / sizeof(images[0])) {
			check_bad_cluster(&device);
		} else {
			check_success(&device, i != 0);
		}
		check_faults(&device);
		if (i == 0) {
			check_budgets(&device);
			check_invalid(&device);
			check_private_owner(&device);
		}
		free((void *)device.data);
	}
	return 0;
}
