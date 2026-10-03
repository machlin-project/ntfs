/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/validate.h>
#include "fuzz_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_VOLUME_BYTES = 8 * 1024 * 1024,
	TEST_BOOT_MAX_SECTOR_BYTES = 4096,
	TEST_IMAGE_BYTES = TEST_VOLUME_BYTES + TEST_BOOT_MAX_SECTOR_BYTES,
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
	TEST_BAD_CLUSTER = 160,
	TEST_MIRROR_RECORDS = 4,
	TEST_MIRROR_EXTENDED_RECORDS = 64,
	TEST_MIRROR_RECORD = 1,
	TEST_MIRROR_LCN = 32,
	TEST_LOGFILE_RECORD = 2,
	TEST_VOLUME_RECORD = 3,
	TEST_BOOT_RECORD = 7,
	/* Bounded observation storage for the two-owner authored boot profiles. */
	TEST_BOOT_STAGE_CALLS = 32,
	TEST_BOOT_TAIL_LCN = 160,
	TEST_BOOT_IMAGE_NAME_BYTES = sizeof("validation-boot-trailing-resource.img"),
	TEST_DATA_TYPE = 0x80
};

enum test_boot_budget_dimension {
	TEST_BOOT_READ_CALLS,
	TEST_BOOT_READ_BYTES,
	TEST_BOOT_WORK,
	TEST_BOOT_BUDGET_DIMENSIONS
};

enum {
	TEST_INDEX_LCN = 100,
	TEST_INDEX_BITMAP_LCN = 160,
	TEST_INDEX_BITMAP_BYTES = 513,
	TEST_INDEX_BITMAP_READS = 3,
	TEST_INDEX_BITMAP_TYPE = 0xb0,
	TEST_INDEX_IMAGE_NAME_BYTES = 128,
	TEST_INDEX_BUDGET_DIMENSIONS = 3,
	TEST_EMPTY_DIRECTORY = 48,
	TEST_SMALL_INDEX_ORPHAN_LCN = 276,
	TEST_LARGE_INDEX_ORPHAN_LCN = 10,
	TEST_FILE_SECURITY_RECORD = 24,
	TEST_FILE_SECURITY_TYPE = 0x50,
	TEST_FILE_SECURITY_FIRST_LCN = 170,
	TEST_FILE_SECURITY_SECOND_LCN = 178,
	TEST_FILE_SECURITY_LARGE_BYTES = 9001,
	TEST_FILE_SECURITY_MAX_BYTES = 1024 * 1024,
	TEST_FILE_SECURITY_RECORD_BYTES = 1024,
	TEST_FILE_SECURITY_PAYLOAD_READS = 2,
	TEST_FILE_SECURITY_BUDGET_DIMENSIONS = 3
};

struct index_reads {
	struct fuzz_device *device;
	struct ntfs_validation_report *report;
	uint64_t forbidden_first, forbidden_end;
	uint64_t calls[TEST_INDEX_BITMAP_READS], bytes_before[TEST_INDEX_BITMAP_READS];
	uint64_t work_before[TEST_INDEX_BITMAP_READS];
	size_t count;
	uint64_t bitmap_bytes;
	bool full_failure;
};

static void *
index_allocate(void *context, size_t size)
{
	struct index_reads *reads = context;

	return fuzz_allocate(reads->device, size);
}

static void
index_release(void *context, void *bytes, size_t size)
{
	struct index_reads *reads = context;

	fuzz_release(reads->device, bytes, size);
}

static enum ntfs_result
index_read(void *context, uint64_t offset, void *bytes, size_t size)
{
	struct index_reads *reads = context;
	struct fuzz_device *device = reads->device;
	struct ntfs_validation_report *report = reads->report;
	size_t partial, index;

	assert(offset <= device->size && size <= device->size - offset);
	if (reads->forbidden_end != 0) {
		assert(offset + size <= reads->forbidden_first || offset >= reads->forbidden_end);
	}
	if (report->stage == NTFS_VALIDATION_INDEX_ALLOCATION) {
		index = reads->count++;
		assert(index < TEST_INDEX_BITMAP_READS);
		reads->bitmap_bytes += size;
		reads->calls[index] = report->read_calls;
		reads->bytes_before[index] = report->read_bytes - size;
		reads->work_before[index] = report->work_units - size;
	}
	if (device->fail_read != 0 && device->reads + 1 == device->fail_read) {
		partial = reads->full_failure ? size : size / 2;
		memcpy(bytes, device->data + offset, partial);
	}
	return fuzz_read(device, offset, bytes, size);
}

static enum ntfs_result
validate_index(struct index_reads *reads, const struct ntfs_validation_limits *limits)
{
	struct fuzz_device *device = reads->device;
	struct ntfs_environment environment = {
	    NTFS_API_VERSION, reads, device->size, index_read, index_allocate, index_release};
	struct ntfs_limits core_limits;
	enum ntfs_result result;

	device->reads = 0;
	device->allocations = 0;
	reads->count = 0;
	reads->bitmap_bytes = 0;
	ntfs_default_limits(&core_limits);
	core_limits.record_cache_entries = 0;
	result = ntfs_validate(&environment, &core_limits, limits, reads->report);
	assert(result == reads->report->result && device->memory == 0);
	assert(device->reads == reads->report->read_calls &&
	    device->allocations == reads->report->allocation_calls);
	return result;
}

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

struct boot_observation {
	uint64_t call, bytes_before, work_before;
	uint64_t offset;
	size_t size;
};

struct boot_reads {
	struct fuzz_device *device;
	struct ntfs_validation_report *report;
	struct boot_observation observations[TEST_BOOT_STAGE_CALLS];
	uint64_t allocations[TEST_BOOT_STAGE_CALLS];
	size_t count, allocation_count, primary_reads, replica_reads;
	size_t sector;
	uint64_t forbidden_first, forbidden_end;
	bool full_failure;
};

static void *
boot_allocate(void *context, size_t size)
{
	struct boot_reads *reads = context;

	if (reads->report->stage == NTFS_VALIDATION_BOOT) {
		assert(reads->allocation_count < TEST_BOOT_STAGE_CALLS);
		reads->allocations[reads->allocation_count++] = reads->report->allocation_calls;
	}
	return fuzz_allocate(reads->device, size);
}

static void
boot_release(void *context, void *bytes, size_t size)
{
	struct boot_reads *reads = context;

	fuzz_release(reads->device, bytes, size);
}

static enum ntfs_result
boot_read(void *context, uint64_t offset, void *bytes, size_t size)
{
	struct boot_reads *reads = context;
	struct fuzz_device *device = reads->device;
	struct ntfs_validation_report *report = reads->report;
	size_t partial;

	assert(offset <= device->size && size <= device->size - offset);
	if (reads->forbidden_end != 0) {
		assert(offset + size <= reads->forbidden_first || offset >= reads->forbidden_end);
	}
	if (report->stage == NTFS_VALIDATION_BOOT) {
		assert(reads->count < TEST_BOOT_STAGE_CALLS);
		reads->observations[reads->count++] = (struct boot_observation){report->read_calls,
		    report->read_bytes - size, report->work_units - size, offset, size};
		if (offset == 0) {
			assert(size == reads->sector);
			reads->primary_reads++;
		} else if (offset == TEST_VOLUME_BYTES) {
			assert(size == reads->sector);
			reads->replica_reads++;
		}
	}
	if (device->fail_read != 0 && device->reads + 1 == device->fail_read) {
		partial = reads->full_failure ? size : size / 2;
		memcpy(bytes, device->data + offset, partial);
	}
	return fuzz_read(device, offset, bytes, size);
}

static enum ntfs_result
validate_boot(struct boot_reads *reads, const struct ntfs_validation_limits *limits)
{
	struct fuzz_device *device = reads->device;
	struct ntfs_environment environment = {
	    NTFS_API_VERSION, reads, device->size, boot_read, boot_allocate, boot_release};
	struct ntfs_limits core_limits;
	enum ntfs_result result;

	device->reads = 0;
	device->allocations = 0;
	reads->count = 0;
	reads->allocation_count = 0;
	reads->primary_reads = 0;
	reads->replica_reads = 0;
	ntfs_default_limits(&core_limits);
	core_limits.record_cache_entries = 0;
	result = ntfs_validate(&environment, &core_limits, limits, reads->report);
	assert(device->memory == 0 && result == reads->report->result);
	assert(device->reads == reads->report->read_calls &&
	    device->allocations == reads->report->allocation_calls);
	return result;
}

static void
check_boot(const char *directory)
{
	const struct {
		const char *name;
		size_t sector;
		bool fragmented, trailing;
	} profiles[] = {{"sector-512", 512, false, false}, {"sector-1024", 1024, false, false},
	    {"sector-2048", 2048, false, false}, {"sector-4096", 4096, false, false},
	    {"fragmented", 512, true, false}, {"listed", 512, true, false},
	    {"trailing-resource", 512, false, true}};
	struct fuzz_device device;
	struct ntfs_validation_report baseline, report;
	struct ntfs_validation_limits limits;
	struct boot_reads observed, attempt;
	struct boot_observation last;
	uint8_t *original;
	char image[TEST_BOOT_IMAGE_NAME_BYTES];
	size_t profile, index, mode;
	unsigned dimension;
	enum ntfs_validation_limit refused;

	for (profile = 0; profile < sizeof(profiles) / sizeof(profiles[0]); profile++) {
		device = (struct fuzz_device){0};
		assert(snprintf(image, sizeof(image), "validation-boot-%s.img",
			   profiles[profile].name) > 0);
		load_image(directory, image, &device);
		original = malloc(device.size);
		assert(original != NULL);
		memcpy(original, device.data, device.size);
		observed = (struct boot_reads){
		    .device = &device, .report = &baseline, .sector = profiles[profile].sector};
		if (profiles[profile].fragmented) {
			observed.forbidden_first =
			    (uint64_t)TEST_BOOT_TAIL_LCN * TEST_CLUSTER_BYTES;
			observed.forbidden_end = observed.forbidden_first + TEST_CLUSTER_BYTES;
		} else if (profiles[profile].trailing) {
			observed.forbidden_first = TEST_VOLUME_BYTES + observed.sector;
			observed.forbidden_end = device.size;
		}
		assert(validate_boot(&observed, NULL) == NTFS_OK && baseline.complete);
		assert(observed.primary_reads == 1 && observed.replica_reads == 1);
		assert(observed.count != 0 && observed.allocation_count != 0);
		for (index = 0; index < observed.allocation_count; index++) {
			attempt = observed;
			attempt.report = &report;
			device.fail_allocation = observed.allocations[index];
			assert(validate_boot(&attempt, NULL) == NTFS_NO_MEMORY);
			assert(!report.complete && report.stage == NTFS_VALIDATION_BOOT &&
			    report.exhausted == NTFS_VALIDATION_LIMIT_NONE);
			device.fail_allocation = 0;
			assert(validate_boot(&attempt, NULL) == NTFS_OK);
		}
		for (index = 0; index < observed.count; index++) {
			for (mode = 0; mode < 2; mode++) {
				attempt = observed;
				attempt.report = &report;
				attempt.full_failure = mode != 0;
				device.fail_read = observed.observations[index].call;
				assert(validate_boot(&attempt, NULL) == NTFS_IO);
				assert(!report.complete && report.stage == NTFS_VALIDATION_BOOT &&
				    report.exhausted == NTFS_VALIDATION_LIMIT_NONE);
				device.fail_read = 0;
				assert(validate_boot(&attempt, NULL) == NTFS_OK);
			}
			for (dimension = 0; dimension < TEST_BOOT_BUDGET_DIMENSIONS; dimension++) {
				ntfs_validation_default_limits(&limits);
				switch (dimension) {
				case TEST_BOOT_READ_CALLS:
					limits.max_read_calls =
					    observed.observations[index].call - 1;
					refused = NTFS_VALIDATION_LIMIT_READ_CALLS;
					break;
				case TEST_BOOT_READ_BYTES:
					limits.max_read_bytes =
					    observed.observations[index].bytes_before +
					    observed.observations[index].size - 1;
					refused = NTFS_VALIDATION_LIMIT_READ_BYTES;
					break;
				default:
					limits.max_work_units =
					    observed.observations[index].work_before +
					    observed.observations[index].size - 1;
					refused = NTFS_VALIDATION_LIMIT_WORK;
					break;
				}
				attempt = observed;
				attempt.report = &report;
				assert(validate_boot(&attempt, &limits) == NTFS_RANGE);
				assert(!report.complete && report.stage == NTFS_VALIDATION_BOOT &&
				    report.exhausted == refused);
				assert(attempt.count == index);
				assert(validate_boot(&attempt, NULL) == NTFS_OK);
			}
		}
		last = observed.observations[observed.count - 1];
		assert(last.offset == TEST_VOLUME_BYTES && last.size == observed.sector);
		ntfs_validation_default_limits(&limits);
		limits.max_work_units = last.work_before + last.size + observed.sector - 1;
		attempt = observed;
		attempt.report = &report;
		assert(validate_boot(&attempt, &limits) == NTFS_RANGE);
		assert(report.stage == NTFS_VALIDATION_BOOT &&
		    report.exhausted == NTFS_VALIDATION_LIMIT_WORK && attempt.replica_reads == 1);
		assert(validate_boot(&attempt, NULL) == NTFS_OK);
		assert(memcmp(original, device.data, device.size) == 0);
		printf("boot %s: %zu allocation faults, %zu partial/full read faults, %zu "
		       "pre-callback budgets and comparison precharge; exact retry/cleanup\n",
		    profiles[profile].name, observed.allocation_count, observed.count * 2,
		    observed.count * TEST_BOOT_BUDGET_DIMENSIONS);
		free(original);
		free((void *)device.data);
	}
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
		assert(report.mirror_record_slots == TEST_MIRROR_RECORDS &&
		    report.mirror_records_compared == TEST_MIRROR_RECORDS &&
		    report.mirror_unchecked_records == 0);
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

struct mirror_reads {
	struct fuzz_device *device;
	struct ntfs_validation_report *report;
	uint64_t first, last;
	uint64_t calls_before[TEST_MIRROR_RECORDS], bytes_before[TEST_MIRROR_RECORDS];
	uint64_t work_before[TEST_MIRROR_RECORDS];
	bool seen[TEST_MIRROR_RECORDS], full_failure;
};

static void *
mirror_allocate(void *context, size_t size)
{
	struct mirror_reads *reads = context;

	return fuzz_allocate(reads->device, size);
}

static void
mirror_release(void *context, void *bytes, size_t size)
{
	struct mirror_reads *reads = context;

	fuzz_release(reads->device, bytes, size);
}

static enum ntfs_result
mirror_read(void *context, uint64_t offset, void *bytes, size_t size)
{
	struct mirror_reads *reads = context;
	struct fuzz_device *device = reads->device;
	struct ntfs_validation_report *report = reads->report;
	size_t partial;
	uint64_t completed;

	if (report->stage == NTFS_VALIDATION_MIRROR) {
		if (reads->first == 0) {
			reads->first = report->read_calls;
		}
		reads->last = report->read_calls;
		completed = report->mirror_records_compared;
		if (report->related_reference != 0 && completed < TEST_MIRROR_RECORDS &&
		    !reads->seen[completed]) {
			reads->seen[completed] = true;
			reads->calls_before[completed] = report->read_calls - 1;
			reads->bytes_before[completed] = report->read_bytes - size;
			reads->work_before[completed] = report->work_units - size;
		}
	}
	if (device->fail_read != 0 && device->reads + 1 == device->fail_read) {
		assert(offset <= device->size && size <= device->size - offset);
		partial = reads->full_failure ? size : size / 2;
		memcpy(bytes, device->data + offset, partial);
	}
	return fuzz_read(device, offset, bytes, size);
}

static enum ntfs_result
validate_mirror(struct mirror_reads *reads, const struct ntfs_validation_limits *limits)
{
	struct fuzz_device *device = reads->device;
	struct ntfs_environment environment = {
	    NTFS_API_VERSION, reads, device->size, mirror_read, mirror_allocate, mirror_release};
	struct ntfs_limits core_limits;
	enum ntfs_result result;

	device->reads = 0;
	device->allocations = 0;
	ntfs_default_limits(&core_limits);
	core_limits.record_cache_entries = 0;
	memset(reads->report, 0xff, sizeof(*reads->report));
	result = ntfs_validate(&environment, &core_limits, limits, reads->report);
	assert(device->memory == 0 && reads->report->result == result);
	assert(device->reads == reads->report->read_calls &&
	    device->allocations == reads->report->allocation_calls);
	return result;
}

static void
check_mirror_interruptions(struct fuzz_device *device)
{
	struct ntfs_validation_report baseline, report;
	struct mirror_reads observed = {.device = device, .report = &baseline}, attempt;
	struct ntfs_validation_limits limits;
	uint8_t *original;
	uint64_t call;
	unsigned i, kind, full;

	original = malloc(device->size);
	assert(original != NULL);
	memcpy(original, device->data, device->size);
	assert(validate_mirror(&observed, NULL) == NTFS_OK);
	assert(observed.first != 0 && observed.last >= observed.first);
	for (full = 0; full < 2; full++) {
		for (call = observed.first; call <= observed.last; call++) {
			attempt = (struct mirror_reads){
			    .device = device, .report = &report, .full_failure = full != 0};
			device->fail_read = (size_t)call;
			assert(validate_mirror(&attempt, NULL) == NTFS_IO);
			assert(report.stage == NTFS_VALIDATION_MIRROR && !report.complete &&
			    report.exhausted == NTFS_VALIDATION_LIMIT_NONE);
			assert(report.mirror_records_compared < TEST_MIRROR_RECORDS);
			assert(memcmp(original, device->data, device->size) == 0);
			device->fail_read = 0;
			assert(validate_mirror(&attempt, NULL) == NTFS_OK);
		}
	}
	for (i = 0; i < TEST_MIRROR_RECORDS; i++) {
		assert(observed.seen[i]);
		for (kind = NTFS_VALIDATION_LIMIT_READ_CALLS; kind <= NTFS_VALIDATION_LIMIT_WORK;
		    kind++) {
			ntfs_validation_default_limits(&limits);
			switch (kind) {
			case NTFS_VALIDATION_LIMIT_READ_CALLS:
				limits.max_read_calls = observed.calls_before[i];
				break;
			case NTFS_VALIDATION_LIMIT_READ_BYTES:
				limits.max_read_bytes = observed.bytes_before[i];
				break;
			default:
				limits.max_work_units = observed.work_before[i];
			}
			attempt = (struct mirror_reads){.device = device, .report = &report};
			assert(validate_mirror(&attempt, &limits) == NTFS_RANGE);
			assert(report.stage == NTFS_VALIDATION_MIRROR && report.exhausted == kind &&
			    !report.complete && report.mirror_records_compared == i);
			assert(report.record_number == i);
			assert(report.read_calls <= limits.max_read_calls &&
			    report.read_bytes <= limits.max_read_bytes &&
			    report.work_units <= limits.max_work_units);
			assert(memcmp(original, device->data, device->size) == 0);
		}
	}
	printf("mirror interruption checks: %zu partial/full read faults, %u prefix budgets\n",
	    (size_t)(2 * (observed.last - observed.first + 1)), TEST_MIRROR_RECORDS * 3);
	free(original);
}

static void
check_mirror_cases(const char *directory)
{
	const struct {
		const char *name;
		enum ntfs_result result;
		enum ntfs_validation_stage stage;
		uint64_t slots, compared, subject;
	} failures[] = {{"short", NTFS_CORRUPT, NTFS_VALIDATION_MIRROR, TEST_MIRROR_RECORDS - 1, 0,
			    TEST_MIRROR_RECORD},
	    {"partial-record", NTFS_CORRUPT, NTFS_VALIDATION_MIRROR, TEST_MIRROR_RECORDS - 1, 0,
		TEST_MIRROR_RECORD},
	    {"partial-initialization", NTFS_CORRUPT, NTFS_VALIDATION_MIRROR, TEST_MIRROR_RECORDS, 0,
		TEST_MIRROR_RECORD},
	    {"wrong-anchor", NTFS_CORRUPT, NTFS_VALIDATION_MIRROR, TEST_MIRROR_RECORDS, 0,
		TEST_MIRROR_RECORD},
	    {"missing-data", NTFS_CORRUPT, NTFS_VALIDATION_MIRROR, 0, 0, TEST_MIRROR_RECORD},
	    {"resident-data", NTFS_CORRUPT, NTFS_VALIDATION_MIRROR, 0, 0, TEST_MIRROR_RECORD},
	    {"sparse", NTFS_UNSUPPORTED, NTFS_VALIDATION_MIRROR, TEST_MIRROR_RECORDS, 0,
		TEST_MIRROR_RECORD},
	    {"larger-than-supported", NTFS_UNSUPPORTED, NTFS_VALIDATION_MIRROR,
		TEST_MIRROR_RECORDS + 1, 0, TEST_MIRROR_RECORD},
	    {"encrypted", NTFS_UNSUPPORTED, NTFS_VALIDATION_ATTRIBUTES, 0, 0, TEST_MIRROR_RECORD},
	    {"different-sequence", NTFS_CORRUPT, NTFS_VALIDATION_MIRROR, TEST_MIRROR_RECORDS,
		TEST_MIRROR_RECORD, TEST_MIRROR_RECORD},
	    {"different-lsn", NTFS_CORRUPT, NTFS_VALIDATION_MIRROR, TEST_MIRROR_RECORDS,
		TEST_MIRROR_RECORD, TEST_MIRROR_RECORD},
	    {"different-link-count", NTFS_CORRUPT, NTFS_VALIDATION_MIRROR, TEST_MIRROR_RECORDS,
		TEST_MIRROR_RECORD, TEST_MIRROR_RECORD},
	    {"invalid-used-span", NTFS_CORRUPT, NTFS_VALIDATION_MIRROR, TEST_MIRROR_RECORDS,
		TEST_MIRROR_RECORD, TEST_MIRROR_RECORD},
	    {"inactive-copy", NTFS_CORRUPT, NTFS_VALIDATION_MIRROR, TEST_MIRROR_RECORDS,
		TEST_MIRROR_RECORD, TEST_MIRROR_RECORD},
	    {"directory-owner", NTFS_UNSUPPORTED, NTFS_VALIDATION_MIRROR, 0, 0, TEST_MIRROR_RECORD},
	    {"view-owner", NTFS_UNSUPPORTED, NTFS_VALIDATION_MIRROR, 0, 0, TEST_MIRROR_RECORD},
	    {"uninterpreted-owner", NTFS_UNSUPPORTED, NTFS_VALIDATION_MIRROR, 0, 0,
		TEST_MIRROR_RECORD},
	    {"torn-final-copy", NTFS_CORRUPT, NTFS_VALIDATION_MIRROR, TEST_MIRROR_RECORDS,
		TEST_VOLUME_RECORD, TEST_VOLUME_RECORD},
	    {"different-opaque-free-slot", NTFS_CORRUPT, NTFS_VALIDATION_MIRROR,
		TEST_MIRROR_RECORDS, TEST_LOGFILE_RECORD, TEST_LOGFILE_RECORD},
	    {"different-opaque-free-protection", NTFS_CORRUPT, NTFS_VALIDATION_MIRROR,
		TEST_MIRROR_RECORDS, TEST_LOGFILE_RECORD, TEST_LOGFILE_RECORD},
	    {"bootstrap-difference", NTFS_CORRUPT, NTFS_VALIDATION_MOUNT, 0, 0, 0},
	    {"different-used-protected-tail", NTFS_CORRUPT, NTFS_VALIDATION_MIRROR,
		TEST_MIRROR_RECORDS, TEST_VOLUME_RECORD, TEST_VOLUME_RECORD},
	    {"fragmented-late-difference", NTFS_CORRUPT, NTFS_VALIDATION_MIRROR,
		TEST_MIRROR_RECORDS, TEST_VOLUME_RECORD, TEST_VOLUME_RECORD},
	    {"list-resident-late-difference", NTFS_CORRUPT, NTFS_VALIDATION_MIRROR,
		TEST_MIRROR_RECORDS, TEST_VOLUME_RECORD, TEST_VOLUME_RECORD},
	    {"list-nonresident-late-difference", NTFS_CORRUPT, NTFS_VALIDATION_MIRROR,
		TEST_MIRROR_RECORDS, TEST_VOLUME_RECORD, TEST_VOLUME_RECORD}};

	const char *successes[] = {"independent-protection", "different-slack",
	    "different-slack-tail", "identical-opaque-free-record", "used-protected-tail",
	    "small-clusters", "fragmented", "list-resident", "list-nonresident",
	    "large-cluster-prefix"};
	const char *extended[] = {"extended", "extended-unqualified-tail",
	    "extended-prefix-initialized", "extended-prefix-initialized-unqualified-tail"};
	const char *faults[] = {"fragmented", "list-resident", "list-nonresident", "extended"};
	struct fuzz_device device;
	struct ntfs_validation_report report;
	char image[FILENAME_MAX];
	size_t i;
	unsigned cache;

	for (i = 0; i < sizeof(failures) / sizeof(failures[0]); i++) {
		assert(snprintf(
			   image, sizeof(image), "validation-mirror-%s.img", failures[i].name) > 0);
		device = (struct fuzz_device){0};
		load_image(directory, image, &device);
		for (cache = 0; cache < 2; cache++) {
			assert(validate(&device, NULL, &report, cache) == failures[i].result);
			assert(!report.complete && report.exhausted == NTFS_VALIDATION_LIMIT_NONE);
			assert(report.stage == failures[i].stage &&
			    report.record_number == failures[i].subject);
			assert(report.mirror_record_slots == failures[i].slots &&
			    report.mirror_records_compared == failures[i].compared &&
			    report.mirror_unchecked_records == 0);
			if (report.stage == NTFS_VALIDATION_MIRROR) {
				assert(report.attribute_type == TEST_DATA_TYPE);
			}
		}
		free((void *)device.data);
	}
	for (i = 0; i < sizeof(successes) / sizeof(successes[0]); i++) {
		assert(
		    snprintf(image, sizeof(image), "validation-mirror-%s.img", successes[i]) > 0);
		device = (struct fuzz_device){0};
		load_image(directory, image, &device);
		for (cache = 0; cache < 2; cache++) {
			assert(
			    validate(&device, NULL, &report, cache) == NTFS_OK && report.complete);
			assert(report.mirror_record_slots == TEST_MIRROR_RECORDS &&
			    report.mirror_records_compared == TEST_MIRROR_RECORDS &&
			    report.mirror_unchecked_records == 0);
		}
		free((void *)device.data);
	}
	for (i = 0; i < sizeof(extended) / sizeof(extended[0]); i++) {
		assert(snprintf(image, sizeof(image), "validation-mirror-%s.img", extended[i]) > 0);
		device = (struct fuzz_device){0};
		load_image(directory, image, &device);
		assert(validate(&device, NULL, &report, 0) == NTFS_OK && report.complete);
		assert(report.mirror_record_slots == TEST_MIRROR_EXTENDED_RECORDS &&
		    report.mirror_records_compared == TEST_MIRROR_RECORDS &&
		    report.mirror_unchecked_records ==
			TEST_MIRROR_EXTENDED_RECORDS - TEST_MIRROR_RECORDS);
		free((void *)device.data);
	}
	for (i = 0; i < sizeof(faults) / sizeof(faults[0]); i++) {
		assert(snprintf(image, sizeof(image), "validation-mirror-%s.img", faults[i]) > 0);
		device = (struct fuzz_device){0};
		load_image(directory, image, &device);
		check_faults(&device);
		check_mirror_interruptions(&device);
		free((void *)device.data);
	}
}

static void
check_index_cases(const char *directory)
{
	static const struct {
		const char *name;
		enum ntfs_result result;
		uint64_t cluster, owner;
	} cases[] = {{"free-garbage", NTFS_OK, 0, NTFS_ROOT_RECORD},
	    {"orphan-valid", NTFS_CORRUPT, TEST_INDEX_LCN + 1, NTFS_ROOT_RECORD},
	    {"orphan-garbage", NTFS_CORRUPT, TEST_INDEX_LCN + 1, NTFS_ROOT_RECORD},
	    {"outside-allocation", NTFS_CORRUPT, 0, NTFS_ROOT_RECORD},
	    {"padding-used", NTFS_CORRUPT, 0, NTFS_ROOT_RECORD},
	    {"later-used", NTFS_CORRUPT, 0, NTFS_ROOT_RECORD},
	    {"partial-allocation", NTFS_CORRUPT, 0, NTFS_ROOT_RECORD},
	    {"two-blocks", NTFS_OK, 0, NTFS_ROOT_RECORD},
	    {"fragmented", NTFS_OK, 0, NTFS_ROOT_RECORD},
	    {"orphan-fragmented", NTFS_CORRUPT, TEST_INDEX_BITMAP_LCN, NTFS_ROOT_RECORD},
	    {"resident-paged-bitmap", NTFS_OK, 0, NTFS_ROOT_RECORD},
	    {"nonresident-paged-bitmap", NTFS_OK, 0, NTFS_ROOT_RECORD},
	    {"late-bitmap-used", NTFS_CORRUPT, 0, NTFS_ROOT_RECORD},
	    {"leaf-zero-bitmap", NTFS_OK, 0, TEST_EMPTY_DIRECTORY},
	    {"leaf-used-bitmap", NTFS_CORRUPT, 0, TEST_EMPTY_DIRECTORY},
	    {"leaf-free-storage", NTFS_OK, 0, TEST_EMPTY_DIRECTORY},
	    {"subcluster-two-blocks", NTFS_OK, 0, NTFS_ROOT_RECORD},
	    {"subcluster-orphan", NTFS_CORRUPT, TEST_INDEX_LCN, NTFS_ROOT_RECORD},
	    {"small-cluster-two-blocks", NTFS_OK, 0, NTFS_ROOT_RECORD},
	    {"small-cluster-orphan", NTFS_CORRUPT, TEST_SMALL_INDEX_ORPHAN_LCN, NTFS_ROOT_RECORD},
	    {"large-cluster-two-blocks", NTFS_OK, 0, NTFS_ROOT_RECORD},
	    {"large-cluster-orphan", NTFS_CORRUPT, TEST_LARGE_INDEX_ORPHAN_LCN, NTFS_ROOT_RECORD}};
	struct fuzz_device device;
	struct ntfs_validation_report report;
	struct index_reads reads;
	uint8_t *original;
	char name[TEST_INDEX_IMAGE_NAME_BYTES];
	size_t i;
	unsigned cache;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		assert(snprintf(name, sizeof(name), "validation-index-%s.img", cases[i].name) > 0);
		device = (struct fuzz_device){0};
		load_image(directory, name, &device);
		original = malloc(device.size);
		assert(original != NULL);
		memcpy(original, device.data, device.size);
		for (cache = 0; cache < 2; cache++) {
			assert(validate(&device, NULL, &report, cache) == cases[i].result);
			if (cases[i].result != NTFS_OK) {
				assert(report.stage == NTFS_VALIDATION_INDEX_ALLOCATION &&
				    report.attribute_type == TEST_INDEX_BITMAP_TYPE &&
				    report.cluster == cases[i].cluster &&
				    report.record_number == cases[i].owner);
			} else {
				assert(report.claimed_clusters == report.allocated_clusters &&
				    report.unclaimed_clusters == 0);
			}
			assert(report.exhausted == NTFS_VALIDATION_LIMIT_NONE);
			assert(memcmp(original, device.data, device.size) == 0);
		}
		if (strcmp(cases[i].name, "free-garbage") == 0 ||
		    strcmp(cases[i].name, "leaf-free-storage") == 0) {
			reads = (struct index_reads){.device = &device,
			    .report = &report,
			    .forbidden_first = (TEST_INDEX_LCN + 1) * TEST_CLUSTER_BYTES,
			    .forbidden_end = (TEST_INDEX_LCN + 2) * TEST_CLUSTER_BYTES};
			assert(validate_index(&reads, NULL) == NTFS_OK);
		}
		if (strcmp(cases[i].name, "fragmented") == 0 ||
		    strcmp(cases[i].name, "nonresident-paged-bitmap") == 0) {
			check_faults(&device);
		}
		free(original);
		free((void *)device.data);
	}
	puts("PASS: 22 index bitmap/reachability/storage/geometry verdicts with cache on/off, "
	     "physical failure subjects, unchanged images and no free-block reads");
}

static void
check_index_interruptions(const char *directory)
{
	struct fuzz_device device = {0};
	struct ntfs_validation_report report;
	struct ntfs_validation_limits limits;
	struct index_reads reads = {.device = &device, .report = &report}, observed;
	uint8_t *original;
	size_t i;
	unsigned mode, dimension;

	load_image(directory, "validation-index-nonresident-paged-bitmap.img", &device);
	original = malloc(device.size);
	assert(original != NULL);
	memcpy(original, device.data, device.size);
	assert(validate_index(&reads, NULL) == NTFS_OK && reads.count == TEST_INDEX_BITMAP_READS);
	assert(reads.bitmap_bytes == TEST_INDEX_BITMAP_BYTES);
	observed = reads;
	for (mode = 0; mode < 2; mode++) {
		for (i = 0; i < observed.count; i++) {
			device.fail_read = observed.calls[i];
			reads.full_failure = mode != 0;
			assert(validate_index(&reads, NULL) == NTFS_IO);
			assert(report.stage == NTFS_VALIDATION_INDEX_ALLOCATION &&
			    !report.complete && report.exhausted == NTFS_VALIDATION_LIMIT_NONE &&
			    report.attribute_type == TEST_INDEX_BITMAP_TYPE &&
			    report.record_number == NTFS_ROOT_RECORD);
			device.fail_read = 0;
			assert(validate_index(&reads, NULL) == NTFS_OK);
			assert(memcmp(original, device.data, device.size) == 0);
		}
	}
	for (dimension = 0; dimension < TEST_INDEX_BUDGET_DIMENSIONS; dimension++) {
		for (i = 0; i < observed.count; i++) {
			ntfs_validation_default_limits(&limits);
			if (dimension == 0) {
				limits.max_read_calls = observed.calls[i] - 1;
			} else if (dimension == 1) {
				limits.max_read_bytes = observed.bytes_before[i];
			} else {
				limits.max_work_units = observed.work_before[i];
			}
			assert(validate_index(&reads, &limits) == NTFS_RANGE);
			assert(report.stage == NTFS_VALIDATION_INDEX_ALLOCATION &&
			    !report.complete &&
			    report.exhausted == NTFS_VALIDATION_LIMIT_READ_CALLS + dimension &&
			    device.reads == observed.calls[i] - 1 &&
			    report.work_units <= limits.max_work_units);
			assert(validate_index(&reads, NULL) == NTFS_OK);
			assert(memcmp(original, device.data, device.size) == 0);
		}
	}
	free(original);
	free((void *)device.data);
	puts("PASS: all three bitmap reads, six partial/full failures and nine "
	     "pre-callback budget refusals, fresh retry and exact cleanup");
}

static void
check_security(const char *directory)
{
	struct fuzz_device device = {0};
	struct ntfs_validation_report baseline, report;
	struct ntfs_validation_limits limits;
	enum ntfs_validation_limit dimension;
	unsigned below;

	load_image(directory, "validation-secure-valid.img", &device);
	check_faults(&device);
	assert(validate(&device, NULL, &baseline, 0) == NTFS_OK);
	for (dimension = NTFS_VALIDATION_LIMIT_MEMORY; dimension <= NTFS_VALIDATION_LIMIT_WORK;
	    dimension++) {
		for (below = 0; below < 2; below++) {
			ntfs_validation_default_limits(&limits);
			switch (dimension) {
			case NTFS_VALIDATION_LIMIT_MEMORY:
				limits.max_memory_bytes = baseline.peak_memory_bytes - below;
				break;
			case NTFS_VALIDATION_LIMIT_READ_CALLS:
				limits.max_read_calls = baseline.read_calls - below;
				break;
			case NTFS_VALIDATION_LIMIT_READ_BYTES:
				limits.max_read_bytes = baseline.read_bytes - below;
				break;
			default:
				limits.max_work_units = baseline.work_units - below;
			}
			assert(validate(&device, &limits, &report, 0) ==
			    (below == 0 ? NTFS_OK : NTFS_RANGE));
			assert(report.exhausted ==
			    (below == 0 ? NTFS_VALIDATION_LIMIT_NONE : dimension));
			if (below != 0 && dimension != NTFS_VALIDATION_LIMIT_MEMORY) {
				assert(report.stage == NTFS_VALIDATION_SECURITY);
			}
		}
	}
	free((void *)device.data);
	puts("PASS: complete-volume security fault retry and four exact/one-below diagnostic "
	     "boundaries");
}

struct file_security_reads {
	struct fuzz_device *device;
	struct ntfs_validation_report *report;
	uint64_t first, last, payload_size, payload_bytes, decode_before;
	uint64_t calls_before[TEST_FILE_SECURITY_PAYLOAD_READS];
	uint64_t bytes_before[TEST_FILE_SECURITY_PAYLOAD_READS];
	uint64_t work_before[TEST_FILE_SECURITY_PAYLOAD_READS];
	size_t payload_calls;
	bool full_failure;
};

static void *
file_security_allocate(void *context, size_t size)
{
	struct file_security_reads *reads = context;

	return fuzz_allocate(reads->device, size);
}

static void
file_security_release(void *context, void *bytes, size_t size)
{
	struct file_security_reads *reads = context;

	fuzz_release(reads->device, bytes, size);
}

static enum ntfs_result
file_security_read(void *context, uint64_t offset, void *bytes, size_t size)
{
	struct file_security_reads *reads = context;
	struct fuzz_device *device = reads->device;
	struct ntfs_validation_report *report = reads->report;
	uint64_t first = (uint64_t)TEST_FILE_SECURITY_FIRST_LCN * TEST_CLUSTER_BYTES;
	uint64_t second = (uint64_t)TEST_FILE_SECURITY_SECOND_LCN * TEST_CLUSTER_BYTES;
	size_t index, partial;

	assert(offset <= device->size && size <= device->size - offset);
	if (report->stage == NTFS_VALIDATION_SECURITY) {
		if (reads->first == 0) {
			reads->first = report->read_calls;
		}
		reads->last = report->read_calls;
		if (report->record_number == TEST_FILE_SECURITY_RECORD &&
		    ((offset >= first && offset < first + TEST_CLUSTER_BYTES) ||
			(offset >= second && offset < second + reads->payload_size))) {
			index = reads->payload_calls++;
			assert(index < TEST_FILE_SECURITY_PAYLOAD_READS);
			reads->payload_bytes += size;
			reads->calls_before[index] = report->read_calls - 1;
			reads->bytes_before[index] = report->read_bytes - size;
			reads->work_before[index] = report->work_units - size;
			reads->decode_before = report->work_units;
		}
	}
	if (device->fail_read != 0 && device->reads + 1 == device->fail_read) {
		partial = reads->full_failure ? size : size / 2;
		memcpy(bytes, device->data + offset, partial);
	}
	return fuzz_read(device, offset, bytes, size);
}

static enum ntfs_result
validate_file_security(struct file_security_reads *reads,
    const struct ntfs_validation_limits *limits, const struct ntfs_limits *configured)
{
	struct fuzz_device *device = reads->device;
	struct ntfs_environment environment = {NTFS_API_VERSION, reads, device->size,
	    file_security_read, file_security_allocate, file_security_release};
	struct ntfs_limits defaults;
	enum ntfs_result result;

	ntfs_default_limits(&defaults);
	defaults.record_cache_entries = 0;
	device->allocations = 0;
	device->reads = 0;
	reads->first = 0;
	reads->last = 0;
	reads->payload_calls = 0;
	reads->payload_bytes = 0;
	reads->decode_before = 0;
	result = ntfs_validate(
	    &environment, configured == NULL ? &defaults : configured, limits, reads->report);
	assert(result == reads->report->result && device->memory == 0);
	assert(device->reads == reads->report->read_calls &&
	    device->allocations == reads->report->allocation_calls);
	assert(reads->report->complete == (result == NTFS_OK));
	return result;
}

static void
check_file_security_interruptions(struct fuzz_device *device, uint64_t payload_size)
{
	struct ntfs_validation_report baseline, report;
	struct file_security_reads observed = {
	    .device = device, .report = &baseline, .payload_size = payload_size};
	struct file_security_reads attempt;
	struct ntfs_validation_limits limits;
	struct ntfs_limits core_limits;
	uint8_t *original;
	uint64_t call;
	size_t index;
	unsigned full, dimension;

	original = malloc(device->size);
	assert(original != NULL);
	memcpy(original, device->data, device->size);
	assert(validate_file_security(&observed, NULL, NULL) == NTFS_OK);
	assert(observed.first != 0 && observed.last >= observed.first);
	assert(observed.payload_calls == TEST_FILE_SECURITY_PAYLOAD_READS &&
	    observed.payload_bytes == payload_size);
	for (full = 0; full < 2; full++) {
		for (call = observed.first; call <= observed.last; call++) {
			attempt = (struct file_security_reads){.device = device,
			    .report = &report,
			    .payload_size = payload_size,
			    .full_failure = full != 0};
			device->fail_read = (size_t)call;
			assert(validate_file_security(&attempt, NULL, NULL) == NTFS_IO);
			assert(report.stage == NTFS_VALIDATION_SECURITY && !report.complete &&
			    report.exhausted == NTFS_VALIDATION_LIMIT_NONE &&
			    report.attribute_type == TEST_FILE_SECURITY_TYPE);
			assert(memcmp(original, device->data, device->size) == 0);
			device->fail_read = 0;
			assert(validate_file_security(&attempt, NULL, NULL) == NTFS_OK);
		}
	}
	for (index = 0; index < observed.payload_calls; index++) {
		for (dimension = 0; dimension < TEST_FILE_SECURITY_BUDGET_DIMENSIONS; dimension++) {
			ntfs_validation_default_limits(&limits);
			if (dimension == 0) {
				limits.max_read_calls = observed.calls_before[index];
			} else if (dimension == 1) {
				limits.max_read_bytes = observed.bytes_before[index];
			} else {
				limits.max_work_units = observed.work_before[index];
			}
			attempt = (struct file_security_reads){
			    .device = device, .report = &report, .payload_size = payload_size};
			assert(validate_file_security(&attempt, &limits, NULL) == NTFS_RANGE);
			assert(report.stage == NTFS_VALIDATION_SECURITY &&
			    report.record_number == TEST_FILE_SECURITY_RECORD &&
			    report.attribute_type == TEST_FILE_SECURITY_TYPE &&
			    report.exhausted == NTFS_VALIDATION_LIMIT_READ_CALLS + dimension);
			assert(device->reads == observed.calls_before[index] &&
			    attempt.payload_calls == index &&
			    report.work_units <= limits.max_work_units);
		}
	}
	ntfs_validation_default_limits(&limits);
	limits.max_work_units = observed.decode_before + payload_size - 1;
	attempt = (struct file_security_reads){
	    .device = device, .report = &report, .payload_size = payload_size};
	assert(validate_file_security(&attempt, &limits, NULL) == NTFS_RANGE);
	assert(report.exhausted == NTFS_VALIDATION_LIMIT_WORK &&
	    report.stage == NTFS_VALIDATION_SECURITY &&
	    report.record_number == TEST_FILE_SECURITY_RECORD);
	assert(
	    attempt.payload_bytes == payload_size && report.work_units == observed.decode_before);
	if (payload_size == TEST_FILE_SECURITY_MAX_BYTES) {
		ntfs_default_limits(&core_limits);
		core_limits.record_cache_entries = 0;
		core_limits.operation.read_bytes = payload_size + TEST_FILE_SECURITY_RECORD_BYTES;
		assert(validate_file_security(&attempt, NULL, &core_limits) == NTFS_OK);
		core_limits.operation.read_bytes--;
		assert(validate_file_security(&attempt, NULL, &core_limits) == NTFS_RANGE);
		assert(report.exhausted == NTFS_VALIDATION_LIMIT_NONE &&
		    report.stage == NTFS_VALIDATION_SECURITY &&
		    report.record_number == TEST_FILE_SECURITY_RECORD &&
		    attempt.payload_calls == 1);
	}
	assert(validate_file_security(&attempt, NULL, NULL) == NTFS_OK);
	assert(memcmp(original, device->data, device->size) == 0);
	printf("per-file security interruptions: %zu partial/full read faults, %zu pre-callback "
	       "budgets, parser precharge and retry\n",
	    (size_t)(2 * (observed.last - observed.first + 1)),
	    observed.payload_calls * TEST_FILE_SECURITY_BUDGET_DIMENSIONS);
	free(original);
}

static void
check_file_security(const char *directory)
{
	const struct {
		const char *image;
		uint64_t payload_size;
	} profiles[] = {{"validation-file-security-legacy-standard.img", 0},
	    {"validation-file-security-hardlinks.img", 0},
	    {"validation-file-security-listed-resident.img", 0},
	    {"validation-file-security-fragmented.img", TEST_FILE_SECURITY_LARGE_BYTES},
	    {"validation-file-security-listed-fragmented.img", TEST_FILE_SECURITY_LARGE_BYTES},
	    {"validation-file-security-maximum.img", TEST_FILE_SECURITY_MAX_BYTES}};
	struct fuzz_device device;
	size_t index;

	for (index = 0; index < sizeof(profiles) / sizeof(profiles[0]); index++) {
		device = (struct fuzz_device){0};
		load_image(directory, profiles[index].image, &device);
		check_faults(&device);
		if (profiles[index].payload_size != 0) {
			check_file_security_interruptions(&device, profiles[index].payload_size);
		}
		free((void *)device.data);
	}
	puts("PASS: per-file security storage faults, selected parser and compound core credits");
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
	check_mirror_cases(argv[1]);
	check_boot(argv[1]);
	check_index_cases(argv[1]);
	check_index_interruptions(argv[1]);
	check_security(argv[1]);
	check_file_security(argv[1]);
	return 0;
}
