/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/ntfs.h>
#include "fixture.h"
#include "fuzz_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_FILE_RECORD = 24,
	TEST_FRAGMENTED_RECORD = 25,
	TEST_FILE_SEQUENCE = 7,
	TEST_DATA_FIRST_LCN = 128,
	TEST_DATA_LAST_LCN = 130,
	TEST_DATA_EXTENTS = 2,
	TEST_PATH_BYTES = 4096,
	TEST_ADS_READ_BYTES = 64
};

struct stat_case {
	const char *image;
	uint32_t record;
	uint64_t size, allocated;
	enum ntfs_result result, content;
	bool ads;
};

struct stat_work {
	size_t allocations, reads;
};

static const uint16_t notes[] = {'n', 'o', 't', 'e', 's'};
static const uint8_t ads_payload[] = "independent stream payload";

static enum ntfs_result
metadata_read(void *context, uint64_t offset, void *buffer, size_t size)
{
	uint64_t first = (uint64_t)TEST_DATA_FIRST_LCN * TEST_CLUSTER_BYTES;
	uint64_t end = (uint64_t)(TEST_DATA_LAST_LCN + 1) * TEST_CLUSTER_BYTES;

	/* The stat operation and these resident ADS checks may read metadata only. */
	assert(size == 0 || offset >= end || (offset < first && size <= first - offset));
	return fuzz_read(context, offset, buffer, size);
}

static struct stat_work
exercise(struct fuzz_device *device, const struct stat_case *test, size_t failed_allocation,
    size_t failed_read)
{
	struct ntfs_environment env = fuzz_environment(device);
	struct ntfs_limits limits;
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *node = NULL;
	struct ntfs_stream *stream = NULL;
	struct ntfs_stat stat;
	struct stat_work work;
	uint64_t reference =
	    (uint64_t)TEST_FILE_SEQUENCE << NTFS_REFERENCE_SEQUENCE_SHIFT | test->record;
	uint8_t buffer[TEST_ADS_READ_BYTES];
	size_t allocations, reads, completed;
	enum ntfs_result result;

	device->allocations = 0;
	device->reads = 0;
	device->fail_allocation = 0;
	device->fail_read = 0;
	env.read = metadata_read;
	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	assert(ntfs_mount(&env, &limits, &volume) == NTFS_OK);
	assert(ntfs_node_open(volume, reference, &node) == NTFS_OK);
	assert(ntfs_node_stat(NULL, &stat) == NTFS_INVALID);
	assert(ntfs_node_stat(node, NULL) == NTFS_INVALID);
	allocations = device->allocations;
	reads = device->reads;
	device->fail_allocation = failed_allocation != 0 ? allocations + failed_allocation : 0;
	device->fail_read = failed_read != 0 ? reads + failed_read : 0;
	result = ntfs_node_stat(node, &stat);
	work.allocations = device->allocations - allocations;
	work.reads = device->reads - reads;
	if (failed_allocation != 0 || failed_read != 0) {
		assert(result == (failed_allocation != 0 ? NTFS_NO_MEMORY : NTFS_IO));
		assert(stat.size == 0 && stat.allocated_size == 0);
		device->fail_allocation = 0;
		device->fail_read = 0;
		result = ntfs_node_stat(node, &stat);
	}
	assert(result == test->result);
	if (result == NTFS_OK) {
		assert(stat.reference == reference && !stat.directory && !stat.reparse);
		assert(stat.size == test->size && stat.allocated_size == test->allocated);
		assert(ntfs_stream_open(node, NULL, 0, &stream) == test->content);
		if (test->content == NTFS_OK) {
			assert(stream != NULL && ntfs_stream_size(stream) == test->size);
		} else {
			assert(stream == NULL);
		}
		ntfs_stream_close(stream);
		stream = NULL;
		if (test->ads) {
			assert(ntfs_stream_open(node, notes, sizeof(notes) / sizeof(notes[0]),
				   &stream) == NTFS_OK);
			assert(ntfs_stream_read(stream, 0, buffer, sizeof(buffer), &completed) ==
			    NTFS_OK);
			assert(completed == sizeof(ads_payload) - 1 &&
			    memcmp(buffer, ads_payload, completed) == 0);
			ntfs_node_close(node);
			node = NULL;
			assert(ntfs_unmount(volume) == NTFS_BUSY);
			assert(ntfs_stream_read(stream, 0, buffer, sizeof(buffer), &completed) ==
				NTFS_OK &&
			    completed == sizeof(ads_payload) - 1);
			ntfs_stream_close(stream);
		}
	} else {
		assert(stat.size == 0 && stat.allocated_size == 0);
	}
	ntfs_node_close(node);
	assert(ntfs_unmount(volume) == NTFS_OK && device->memory == 0);
	return work;
}

static const struct stat_case cases[] = {{.image = "standard.img",
					     .record = TEST_FILE_RECORD,
					     .size = sizeof("Hello from NTFS.\n") - 1,
					     .result = NTFS_OK,
					     .content = NTFS_OK},
    {.image = "empty-nonresident.img",
	.record = TEST_FILE_RECORD,
	.result = NTFS_OK,
	.content = NTFS_OK},
    {.image = "large-sparse.img",
	.record = TEST_FRAGMENTED_RECORD,
	.size = TEST_LARGE_SPARSE_BYTES,
	.result = NTFS_OK,
	.content = NTFS_OK},
    {.image = "stat-encrypted.img",
	.record = TEST_FILE_RECORD,
	.size = TEST_FRAGMENTED_BYTES,
	.allocated = TEST_CLUSTER_BYTES * TEST_DATA_EXTENTS,
	.result = NTFS_OK,
	.content = NTFS_UNSUPPORTED,
	.ads = true},
    {.image = "stat-format.img",
	.record = TEST_FILE_RECORD,
	.size = TEST_FRAGMENTED_BYTES,
	.allocated = TEST_CLUSTER_BYTES * TEST_DATA_EXTENTS,
	.result = NTFS_OK,
	.content = NTFS_UNSUPPORTED,
	.ads = true},
    {.image = "stat-unit.img",
	.record = TEST_FILE_RECORD,
	.size = TEST_FRAGMENTED_BYTES,
	.allocated = TEST_CLUSTER_BYTES * TEST_DATA_EXTENTS,
	.result = NTFS_OK,
	.content = NTFS_UNSUPPORTED,
	.ads = true},
    {.image = "stat-empty-encrypted.img",
	.record = TEST_FILE_RECORD,
	.result = NTFS_OK,
	.content = NTFS_UNSUPPORTED,
	.ads = true},
    {.image = "stat-listed-encrypted.img",
	.record = TEST_FILE_RECORD,
	.size = TEST_FRAGMENTED_BYTES,
	.allocated = TEST_CLUSTER_BYTES * TEST_DATA_EXTENTS,
	.result = NTFS_OK,
	.content = NTFS_UNSUPPORTED,
	.ads = true},
    {.image = "stat-nonresident-list.img",
	.record = TEST_FILE_RECORD,
	.size = TEST_FRAGMENTED_BYTES,
	.allocated = TEST_CLUSTER_BYTES * TEST_DATA_EXTENTS,
	.result = NTFS_OK,
	.content = NTFS_UNSUPPORTED,
	.ads = true},
    {.image = "stat-bad-vdl.img", .record = TEST_FILE_RECORD, .result = NTFS_CORRUPT},
    {.image = "stat-bad-allocation.img", .record = TEST_FILE_RECORD, .result = NTFS_CORRUPT},
    {.image = "stat-short-mapping.img", .record = TEST_FILE_RECORD, .result = NTFS_CORRUPT},
    {.image = "stat-unknown-flags.img", .record = TEST_FILE_RECORD, .result = NTFS_UNSUPPORTED},
    {.image = "stat-resident-flags.img", .record = TEST_FILE_RECORD, .result = NTFS_CORRUPT},
    {.image = "stat-bad-physical.img", .record = TEST_FILE_RECORD, .result = NTFS_CORRUPT},
    {.image = "stat-stale-extension.img", .record = TEST_FILE_RECORD, .result = NTFS_STALE},
    {.image = "stat-gap.img", .record = TEST_FILE_RECORD, .result = NTFS_CORRUPT},
    {.image = "stat-continuation-flags.img", .record = TEST_FILE_RECORD, .result = NTFS_CORRUPT}};

int
main(int argc, char **argv)
{
	struct fuzz_device device = {0};
	struct stat_work work;
	char path[TEST_PATH_BYTES];
	uint8_t *image, *original;
	FILE *source;
	long length;
	int path_bytes;
	size_t i, fault, allocation_faults = 0, read_faults = 0;

	assert(argc == 2);
	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		path_bytes = snprintf(path, sizeof(path), "%s/%s", argv[1], cases[i].image);
		assert(path_bytes > 0 && (size_t)path_bytes < sizeof(path));
		source = fopen(path, "rb");
		assert(source != NULL && fseek(source, 0, SEEK_END) == 0);
		length = ftell(source);
		assert(length > 0 && length <= TEST_IMAGE_BYTES);
		assert(fseek(source, 0, SEEK_SET) == 0);
		image = malloc((size_t)length);
		original = malloc((size_t)length);
		assert(image != NULL && original != NULL);
		assert(fread(image, 1, (size_t)length, source) == (size_t)length);
		assert(fclose(source) == 0);
		memcpy(original, image, (size_t)length);
		device.data = image;
		device.size = (size_t)length;
		work = exercise(&device, &cases[i], 0, 0);
		if (cases[i].result == NTFS_OK) {
			for (fault = 1; fault <= work.allocations; fault++) {
				exercise(&device, &cases[i], fault, 0);
				allocation_faults++;
			}
			for (fault = 1; fault <= work.reads; fault++) {
				exercise(&device, &cases[i], 0, fault);
				read_faults++;
			}
		}
		assert(memcmp(original, image, (size_t)length) == 0);
		free(original);
		free(image);
	}
	printf("PASS: %zu metadata verdicts, %zu allocation/%zu read faults, retry, independent "
	       "ADS, no default-content I/O and exact cleanup\n",
	    sizeof(cases) / sizeof(cases[0]), allocation_faults, read_faults);
	return 0;
}
