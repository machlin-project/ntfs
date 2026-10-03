/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include "fuzz_device.h"
#include <ntfs/validate.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_IMAGE_BYTES = 8 * 1024 * 1024,
	TEST_PATH_BYTES = 4096,
	TEST_BAD_RECORD = 8,
	TEST_ORDINARY_RECORD = 24,
	TEST_FIRST_BAD_CLUSTER = 160,
	TEST_SECOND_BAD_CLUSTER = 192,
	TEST_SECOND_BAD_COUNT = 2,
	TEST_CLUSTER_BYTES = 4096,
	TEST_PROBE_BYTES = 32,
	TEST_BUDGET_DIMENSIONS = 5,
	TEST_BUFFER_GUARD = 0xa9
};

static const uint16_t bad_name[] = {'$', 'B', 'a', 'd'};

struct bad_device {
	struct fuzz_device device;
	uint64_t read_bytes, allocation_bytes;
	bool full_failure;
};

static void *
allocate(void *context, size_t size)
{
	struct bad_device *owner = context;

	owner->allocation_bytes += size;
	return fuzz_allocate(&owner->device, size);
}

static void
release(void *context, void *bytes, size_t size)
{
	struct bad_device *owner = context;

	fuzz_release(&owner->device, bytes, size);
}

static enum ntfs_result
read_bytes(void *context, uint64_t offset, void *bytes, size_t size)
{
	struct bad_device *owner = context;
	struct fuzz_device *device = &owner->device;
	uint64_t first = (uint64_t)TEST_FIRST_BAD_CLUSTER * TEST_CLUSTER_BYTES;
	uint64_t second = (uint64_t)TEST_SECOND_BAD_CLUSTER * TEST_CLUSTER_BYTES;
	size_t partial;

	assert(offset <= device->size && size <= device->size - offset);
	assert(offset >= first + TEST_CLUSTER_BYTES || offset + size <= first);
	assert(offset >= second + TEST_SECOND_BAD_COUNT * TEST_CLUSTER_BYTES ||
	    offset + size <= second);
	owner->read_bytes += size;
	if (device->fail_read != 0 && device->reads + 1 == device->fail_read) {
		partial = owner->full_failure ? size : size / 2;
		memcpy(bytes, device->data + offset, partial);
	}
	return fuzz_read(device, offset, bytes, size);
}

static struct ntfs_environment
environment(struct bad_device *owner)
{
	return (struct ntfs_environment){
	    NTFS_API_VERSION, owner, owner->device.size, read_bytes, allocate, release};
}

static void
load_image(const char *directory, const char *name, struct bad_device *owner)
{
	char path[TEST_PATH_BYTES];
	FILE *file;
	long size;
	int length;

	length = snprintf(path, sizeof(path), "%s/%s", directory, name);
	assert(length > 0 && (size_t)length < sizeof(path));
	file = fopen(path, "rb");
	assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
	size = ftell(file);
	assert(size > 0 && size <= TEST_IMAGE_BYTES && fseek(file, 0, SEEK_SET) == 0);
	owner->device.data = malloc((size_t)size);
	assert(owner->device.data != NULL);
	owner->device.size = (size_t)size;
	assert(
	    fread((void *)owner->device.data, 1, owner->device.size, file) == owner->device.size);
	assert(fclose(file) == 0);
}

static enum ntfs_result
open_description(struct ntfs_node *node, struct ntfs_stream **out)
{
	return ntfs_bad_clusters_open(
	    node, NTFS_ATTRIBUTE_DATA, bad_name, sizeof(bad_name) / sizeof(bad_name[0]), out);
}

static void
check_no_content(struct bad_device *owner, struct ntfs_node *node, struct ntfs_stream *stream)
{
	struct ntfs_stream *readable = NULL;
	struct ntfs_stat metadata;
	uint8_t bytes[TEST_PROBE_BYTES], original[TEST_PROBE_BYTES];
	size_t reads, allocations, done;

	assert(stream->metadata_only && !stream->external && !stream->resident);
	assert(ntfs_node_metadata(node, &metadata) == NTFS_OK);
	reads = owner->device.reads;
	allocations = owner->device.allocations;
	owner->device.fail_read = reads + 1;
	owner->device.fail_allocation = allocations + 1;
	memset(bytes, TEST_BUFFER_GUARD, sizeof(bytes));
	memcpy(original, bytes, sizeof(bytes));
	done = SIZE_MAX;
	assert(ntfs_stream_read(stream, (uint64_t)TEST_FIRST_BAD_CLUSTER * TEST_CLUSTER_BYTES,
		   bytes, sizeof(bytes), &done) == NTFS_UNSUPPORTED &&
	    done == 0);
	assert(ntfs_stream_read(stream, stream->size, NULL, 0, &done) == NTFS_UNSUPPORTED &&
	    done == 0);
	assert(ntfs_stream_raw(stream, 0, bytes, sizeof(bytes)) == NTFS_UNSUPPORTED);
	assert(ntfs_stream_exact(stream, 0, bytes, sizeof(bytes)) == NTFS_UNSUPPORTED);
	assert(ntfs_stream_open(node, bad_name, sizeof(bad_name) / sizeof(bad_name[0]),
		   &readable) == NTFS_UNSUPPORTED &&
	    readable == NULL);
	assert(memcmp(bytes, original, sizeof(bytes)) == 0);
	assert(owner->device.reads == reads && owner->device.allocations == allocations);
	owner->device.fail_read = 0;
	owner->device.fail_allocation = 0;
}

static void
check_open_faults(
    struct bad_device *owner, struct ntfs_node *node, const struct ntfs_operation_usage *baseline)
{
	struct ntfs_stream *stream = NULL;
	size_t memory = owner->device.memory, i;
	unsigned full;

	for (i = 1; i <= baseline->allocation_calls; i++) {
		owner->device.fail_allocation = owner->device.allocations + i;
		assert(open_description(node, &stream) == NTFS_NO_MEMORY && stream == NULL);
		assert(owner->device.memory == memory);
		owner->device.fail_allocation = 0;
		assert(open_description(node, &stream) == NTFS_OK);
		ntfs_stream_close(stream);
		stream = NULL;
		assert(owner->device.memory == memory);
	}
	for (full = 0; full < 2; full++) {
		owner->full_failure = full != 0;
		for (i = 1; i <= baseline->read_calls; i++) {
			owner->device.fail_read = owner->device.reads + i;
			assert(open_description(node, &stream) == NTFS_IO && stream == NULL);
			assert(owner->device.memory == memory);
			owner->device.fail_read = 0;
			assert(open_description(node, &stream) == NTFS_OK);
			ntfs_stream_close(stream);
			stream = NULL;
			assert(owner->device.memory == memory);
		}
	}
	printf("bad-cluster open faults: %zu allocations, %zu partial/full reads\n",
	    (size_t)baseline->allocation_calls, (size_t)baseline->read_calls * 2);
}

static void
check_open_budgets(
    struct bad_device *owner, struct ntfs_node *node, const struct ntfs_operation_usage *baseline)
{
	struct ntfs_operation_limits limits;
	struct ntfs_operation_usage usage;
	struct ntfs_operation operation = {0};
	struct ntfs_stream *stream = NULL;
	enum ntfs_operation_limit exhausted;
	enum ntfs_result result, expected;
	uint64_t *credit, required;
	uint64_t read_bytes, allocation_bytes;
	size_t memory = owner->device.memory;
	size_t reads, allocations;
	unsigned dimension, below, checks = 0;

	for (dimension = 0; dimension < TEST_BUDGET_DIMENSIONS; dimension++) {
		for (below = 0; below < 2; below++) {
			ntfs_get_operation_limits(node->volume, &limits);
			switch (dimension) {
			case 0:
				credit = &limits.read_calls;
				required = baseline->read_calls;
				exhausted = NTFS_OPERATION_LIMIT_READ_CALLS;
				break;
			case 1:
				credit = &limits.read_bytes;
				required = baseline->read_bytes;
				exhausted = NTFS_OPERATION_LIMIT_READ_BYTES;
				break;
			case 2:
				credit = &limits.allocation_calls;
				required = baseline->allocation_calls;
				exhausted = NTFS_OPERATION_LIMIT_ALLOCATION_CALLS;
				break;
			case 3:
				credit = &limits.allocation_bytes;
				required = baseline->allocation_bytes;
				exhausted = NTFS_OPERATION_LIMIT_ALLOCATION_BYTES;
				break;
			default:
				credit = &limits.work;
				required = baseline->work;
				exhausted = NTFS_OPERATION_LIMIT_WORK;
				break;
			}
			if (required <= below) {
				continue;
			}
			*credit = required - below;
			reads = owner->device.reads;
			allocations = owner->device.allocations;
			read_bytes = owner->read_bytes;
			allocation_bytes = owner->allocation_bytes;
			assert(ntfs_operation_begin(node->volume, &limits, &operation) == NTFS_OK);
			result = open_description(node, &stream);
			expected = below == 0
			    ? NTFS_OK
			    : (dimension == 2 || dimension == 3 ? NTFS_NO_MEMORY : NTFS_RANGE);
			assert(result == expected && (stream != NULL) == (result == NTFS_OK));
			ntfs_stream_close(stream);
			stream = NULL;
			assert(ntfs_operation_end(&operation, &usage) == NTFS_OK);
			assert(usage.exhausted ==
			    (below == 0 ? NTFS_OPERATION_LIMIT_NONE : exhausted));
			assert(usage.read_calls <= limits.read_calls &&
			    usage.read_bytes <= limits.read_bytes);
			assert(usage.allocation_calls <= limits.allocation_calls &&
			    usage.allocation_bytes <= limits.allocation_bytes &&
			    usage.work <= limits.work);
			assert(usage.read_calls == owner->device.reads - reads &&
			    usage.read_bytes == owner->read_bytes - read_bytes &&
			    usage.allocation_calls == owner->device.allocations - allocations &&
			    usage.allocation_bytes == owner->allocation_bytes - allocation_bytes);
			assert(owner->device.memory == memory);
			checks++;
		}
	}
	printf("bad-cluster operation boundaries: %u exact/one-below checks\n", checks);
}

static enum ntfs_result
run_diagnostic(struct bad_device *owner, const struct ntfs_limits *limits,
    struct ntfs_validation_report *report)
{
	struct ntfs_environment source = environment(owner);
	enum ntfs_result result;

	owner->device.allocations = 0;
	owner->device.reads = 0;
	owner->read_bytes = 0;
	owner->allocation_bytes = 0;
	result = ntfs_validate(&source, limits, NULL, report);
	assert(result == report->result && report->complete == (result == NTFS_OK));
	assert(report->read_calls == owner->device.reads &&
	    report->read_bytes == owner->read_bytes &&
	    report->allocation_calls == owner->device.allocations && owner->device.memory == 0);
	return result;
}

static void
check_diagnostic_faults(struct bad_device *owner)
{
	struct ntfs_limits limits;
	struct ntfs_validation_report baseline, report;
	size_t i;
	unsigned full;

	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	assert(run_diagnostic(owner, &limits, &baseline) == NTFS_OK && baseline.complete);
	assert(owner->device.memory == 0);
	for (i = 1; i <= baseline.allocation_calls; i++) {
		owner->device.fail_allocation = i;
		assert(run_diagnostic(owner, &limits, &report) == NTFS_NO_MEMORY);
		assert(!report.complete && report.exhausted == NTFS_VALIDATION_LIMIT_NONE &&
		    owner->device.memory == 0);
		owner->device.fail_allocation = 0;
		assert(run_diagnostic(owner, &limits, &report) == NTFS_OK && report.complete);
		assert(owner->device.memory == 0);
	}
	for (full = 0; full < 2; full++) {
		owner->full_failure = full != 0;
		for (i = 1; i <= baseline.read_calls; i++) {
			owner->device.fail_read = i;
			assert(run_diagnostic(owner, &limits, &report) == NTFS_IO);
			assert(!report.complete && report.exhausted == NTFS_VALIDATION_LIMIT_NONE &&
			    owner->device.memory == 0);
			owner->device.fail_read = 0;
			assert(
			    run_diagnostic(owner, &limits, &report) == NTFS_OK && report.complete);
			assert(owner->device.memory == 0);
		}
	}
	printf("bad-cluster diagnostic faults: %zu allocations, %zu partial/full reads\n",
	    (size_t)baseline.allocation_calls, (size_t)baseline.read_calls * 2);
}

static void
check_profile(
    const char *directory, const char *name, unsigned physical_clusters, bool faults, bool ordinary)
{
	static const char ordinary_content[] = "ordinary named stream";
	struct bad_device owner = {0};
	struct ntfs_environment source;
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *node = NULL;
	struct ntfs_stream *stream = NULL;
	struct ntfs_operation_usage usage;
	struct ntfs_limits limits;
	uint8_t *original, bytes[sizeof(ordinary_content)];
	size_t done;

	load_image(directory, name, &owner);
	original = malloc(owner.device.size);
	assert(original != NULL);
	memcpy(original, owner.device.data, owner.device.size);
	source = environment(&owner);
	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	assert(ntfs_mount(&source, &limits, &volume) == NTFS_OK);
	assert(ntfs_node_by_number(volume, TEST_BAD_RECORD, &node) == NTFS_OK);
	assert(open_description(node, &stream) == NTFS_OK);
	ntfs_get_operation_usage(volume, &usage);
	assert(stream->clusters == volume->info.cluster_count &&
	    stream->size == volume->info.cluster_count * volume->info.cluster_size &&
	    stream->allocated == stream->size &&
	    stream->physical_size == (uint64_t)physical_clusters * TEST_CLUSTER_BYTES);
	check_no_content(&owner, node, stream);
	ntfs_stream_close(stream);
	stream = NULL;
	if (faults) {
		check_open_faults(&owner, node, &usage);
		check_open_budgets(&owner, node, &usage);
	}
	ntfs_node_close(node);
	node = NULL;
	if (ordinary) {
		assert(ntfs_node_by_number(volume, TEST_ORDINARY_RECORD, &node) == NTFS_OK);
		assert(ntfs_stream_open(node, bad_name, sizeof(bad_name) / sizeof(bad_name[0]),
			   &stream) == NTFS_OK);
		assert(ntfs_stream_read(stream, 0, bytes, sizeof(bytes), &done) == NTFS_OK);
		assert(done == sizeof(ordinary_content) - 1 &&
		    memcmp(bytes, ordinary_content, done) == 0);
		ntfs_stream_close(stream);
		ntfs_node_close(node);
	}
	assert(ntfs_unmount(volume) == NTFS_OK && owner.device.memory == 0);
	if (faults) {
		check_diagnostic_faults(&owner);
	}
	assert(memcmp(original, owner.device.data, owner.device.size) == 0);
	free(original);
	free((void *)owner.device.data);
}

int
main(int argc, char **argv)
{
	assert(argc == 2);
	check_profile(argv[1], "validation-bad-clusters-listed.img", 0, false, false);
	check_profile(argv[1], "validation-bad-chain-split.img", 1, true, false);
	check_profile(
	    argv[1], "validation-bad-chain-multiple.img", 1 + TEST_SECOND_BAD_COUNT, true, false);
	check_profile(argv[1], "validation-bad-chain-first-in-extension.img", 1, true, false);
	check_profile(argv[1], "validation-bad-chain-nonresident-list.img", 1, true, false);
	check_profile(argv[1], "validation-bad-chain-all-holes.img", 0, false, false);
	check_profile(argv[1], "validation-bad-chain-initialized-full.img", 1, false, false);
	check_profile(argv[1], "validation-bad-chain-owner-continuation.img", 1, false, false);
	check_profile(argv[1], "validation-bad-chain-ordinary-name.img", 1, false, true);
	puts("PASS: complete bad-cluster lists, metadata-only guards, fault retry and operation "
	     "credits");
	return 0;
}
