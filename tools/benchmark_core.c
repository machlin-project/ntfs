/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_mutation_internal.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum {
	BENCH_BITS = 1024 * 1024,
	BENCH_REQUEST = 256,
	BENCH_RECORDS = 600,
	BENCH_FILE_RECORD = 24,
	BENCH_FILE_SEQUENCE = 7,
	BENCH_INDEX_BYTES = 1024 * 1024,
	BENCH_READ_CALLS = 4096,
	BENCH_READ_BYTES = 16 * 1024 * 1024
};

struct device {
	uint8_t *data;
	size_t size, live, allocations, reads;
};

static void *
allocate(void *context, size_t size)
{
	struct device *device = context;
	void *bytes = malloc(size);

	device->allocations++;
	if (bytes != NULL) {
		device->live += size;
	}
	return bytes;
}

static void
release(void *context, void *bytes, size_t size)
{
	struct device *device = context;

	assert(bytes != NULL && size <= device->live);
	device->live -= size;
	free(bytes);
}

static enum ntfs_result
read_bytes(void *context, uint64_t offset, void *bytes, size_t size)
{
	struct device *device = context;

	assert(offset <= device->size && size <= device->size - offset);
	device->reads++;
	memcpy(bytes, device->data + offset, size);
	return NTFS_OK;
}

static struct ntfs_environment
environment(struct device *device)
{
	return (struct ntfs_environment){
	    NTFS_API_VERSION, device, device->size, read_bytes, allocate, release};
}

static uint64_t
now(void)
{
	struct timespec value;

	assert(clock_gettime(CLOCK_MONOTONIC, &value) == 0);
	return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}

static void
load(struct device *device, const char *path)
{
	FILE *file = fopen(path, "rb");
	long length;

	assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
	length = ftell(file);
	assert(length > 0 && fseek(file, 0, SEEK_SET) == 0);
	device->size = (size_t)length;
	device->data = malloc(device->size);
	assert(device->data != NULL);
	assert(fread(device->data, 1, device->size, file) == device->size);
	assert(fclose(file) == 0);
}

static uint64_t
bitmap(struct device *device, unsigned iterations, bool fragmented)
{
	struct ntfs_write_mutation_plan *plan = calloc(1, sizeof(*plan));
	struct ntfs_run *runs;
	uint8_t *before = malloc(BENCH_BITS / NTFS_BITS_PER_BYTE);
	uint8_t *after = malloc(BENCH_BITS / NTFS_BITS_PER_BYTE);
	size_t count, index;
	unsigned iteration;
	uint64_t checksum = 0;

	assert(plan != NULL && before != NULL && after != NULL);
	memset(before, UINT8_MAX, BENCH_BITS / NTFS_BITS_PER_BYTE);
	memset(before + (BENCH_BITS - 2 * BENCH_REQUEST) / NTFS_BITS_PER_BYTE,
	    fragmented ? 0xaa : 0, 2 * BENCH_REQUEST / NTFS_BITS_PER_BYTE);
	for (iteration = 0; iteration < iterations; iteration++) {
		memcpy(after, before, BENCH_BITS / NTFS_BITS_PER_BYTE);
		memset(plan, 0, sizeof(*plan));
		plan->source = environment(device);
		plan->info.cluster_count = BENCH_BITS;
		plan->allocation = (struct ntfs_mutation_bitmap){
		    .before = before, .after = after, .bytes = BENCH_BITS / NTFS_BITS_PER_BYTE};
		assert(
		    ntfs_mutation_allocate_runs(plan, 0, BENCH_REQUEST, &runs, &count) == NTFS_OK);
		assert(count == (fragmented ? BENCH_REQUEST : 1));
		for (index = 0; index < count; index++) {
			checksum += runs[index].lcn + runs[index].length;
		}
		ntfs_mutation_release(plan, runs, NTFS_MUTATION_MAX_RUNS * sizeof(*runs));
		assert(plan->live_bytes == 0);
	}
	free(after);
	free(before);
	free(plan);
	return checksum;
}

static uint64_t
history(struct device *device, unsigned iterations, uint64_t first)
{
	struct ntfs_environment env = environment(device);
	struct ntfs_logfile *source = NULL;
	struct ntfs_logfile_limits limits;
	struct ntfs_logfile_page_index_report index;
	struct ntfs_logfile_history_report report;
	uint8_t *workspace = malloc(NTFS_LOGFILE_MAX_RECORD_BYTES);
	unsigned iteration;
	uint64_t checksum = 0;

	assert(workspace != NULL);
	ntfs_logfile_default_limits(&limits);
	limits.max_read_calls = BENCH_READ_CALLS;
	limits.max_read_bytes = BENCH_READ_BYTES;
	assert(ntfs_logfile_open(&env, &limits, NULL, &source) == NTFS_OK);
	assert(ntfs_logfile_prepare_page_index(source, BENCH_INDEX_BYTES, &index) == NTFS_OK);
	device->reads = device->allocations = 0;
	for (iteration = 0; iteration < iterations; iteration++) {
		assert(ntfs_logfile_visit_records(source, first, BENCH_RECORDS, workspace,
			   NTFS_LOGFILE_MAX_RECORD_BYTES, NULL, NULL, &report) == NTFS_OK);
		assert(report.complete && report.visited_records == BENCH_RECORDS);
		checksum += report.visited_records;
	}
	ntfs_logfile_close(source);
	free(workspace);
	return checksum;
}

static uint64_t
wof(struct device *device, unsigned iterations, bool reopen_node)
{
	struct ntfs_environment env = environment(device);
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *node = NULL;
	struct ntfs_stream *stream = NULL;
	const uint64_t reference =
	    (uint64_t)BENCH_FILE_SEQUENCE << NTFS_REFERENCE_SEQUENCE_SHIFT | BENCH_FILE_RECORD;
	unsigned iteration;
	uint64_t checksum = 0;

	assert(ntfs_mount(&env, NULL, &volume) == NTFS_OK);
	assert(ntfs_node_open(volume, reference, &node) == NTFS_OK);
	device->reads = device->allocations = 0;
	for (iteration = 0; iteration < iterations; iteration++) {
		assert(ntfs_stream_open(node, NULL, 0, &stream) == NTFS_OK);
		checksum += ntfs_stream_size(stream);
		ntfs_stream_close(stream);
		if (reopen_node) {
			ntfs_node_close(node);
			assert(ntfs_node_open(volume, reference, &node) == NTFS_OK);
		}
	}
	ntfs_node_close(node);
	assert(ntfs_unmount(volume) == NTFS_OK);
	return checksum;
}

int
main(int argc, char **argv)
{
	struct device device = {0};
	unsigned iterations;
	uint64_t start, elapsed, checksum;

	assert(argc >= 3);
	iterations = (unsigned)strtoul(argv[2], NULL, 10);
	assert(iterations != 0);
	if (argc >= 4) {
		load(&device, argv[3]);
	}
	start = now();
	if (strcmp(argv[1], "bitmap") == 0 || strcmp(argv[1], "fragmented") == 0) {
		checksum = bitmap(&device, iterations, strcmp(argv[1], "fragmented") == 0);
	} else if (strcmp(argv[1], "journal") == 0) {
		assert(argc == 5);
		checksum = history(&device, iterations, strtoull(argv[4], NULL, 10));
	} else {
		assert(
		    argc == 4 && (strcmp(argv[1], "wof") == 0 || strcmp(argv[1], "wof-cold") == 0));
		checksum = wof(&device, iterations, strcmp(argv[1], "wof-cold") == 0);
	}
	elapsed = now() - start;
	assert(device.live == 0);
	printf("{\"ns\":%" PRIu64 ",\"checksum\":%" PRIu64 ",\"reads\":%zu,\"allocations\":%zu}\n",
	    elapsed, checksum, device.reads, device.allocations);
	free(device.data);
	return 0;
}
