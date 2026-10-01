/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/ntfs.h>
#include "image.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum {
	BENCHMARK_LOOKUPS = 1000,
	BENCHMARK_READS = 100,
	BENCHMARK_FILE_LIMIT = 64 * 1048576,
	BENCHMARK_READ_BUFFER_BYTES = 1048576
};

#define NANOSECONDS_PER_SECOND UINT64_C(1000000000)

static uint64_t
now(void)
{
	struct timespec time;

	if (clock_gettime(CLOCK_MONOTONIC, &time) != 0) {
		abort();
	}
	return (uint64_t)time.tv_sec * NANOSECONDS_PER_SECOND + (uint64_t)time.tv_nsec;
}

int
main(int argc, char **argv)
{
	struct ntfs_image image;
	struct ntfs_volume *v = NULL;
	struct ntfs_node *root = NULL, *node = NULL;
	struct ntfs_stream *stream = NULL;
	struct ntfs_io_statistics before, after;
	uint16_t name[NTFS_NAME_MAX];
	uint8_t *buffer = NULL;
	size_t name_length, done;
	uint64_t begin, elapsed = 0, offset, bytes = 0, lookup_ns = 0;
	unsigned iteration;
	enum ntfs_result result;

	if (argc != 3) {
		fprintf(stderr, "usage: ntfs-benchmark IMAGE ROOT_FILE_NAME\n");
		return 2;
	}
	if (ntfs_image_open(argv[1], &image) != 0) {
		return 1;
	}
	result = ntfs_mount(&image.environment, NULL, &v);
	if (result == NTFS_OK) {
		result = ntfs_root(v, &root);
	}
	if (result == NTFS_OK) {
		result =
		    ntfs_utf8_to_utf16(argv[2], strlen(argv[2]), name, NTFS_NAME_MAX, &name_length);
	}
	if (result != NTFS_OK) {
		goto finish;
	}
	begin = now();
	for (iteration = 0; iteration < BENCHMARK_LOOKUPS; iteration++) {
		result = ntfs_lookup(root, name, name_length, &node);
		if (result != NTFS_OK) {
			goto finish;
		}
		ntfs_node_close(node);
		node = NULL;
	}
	lookup_ns = now() - begin;
	result = ntfs_lookup(root, name, name_length, &node);
	if (result == NTFS_OK) {
		result = ntfs_stream_open(node, NULL, 0, &stream);
	}
	if (result != NTFS_OK) {
		goto finish;
	}
	if (ntfs_stream_size(stream) > BENCHMARK_FILE_LIMIT) {
		result = NTFS_RANGE;
		goto finish;
	}
	buffer = malloc(BENCHMARK_READ_BUFFER_BYTES);
	if (buffer == NULL) {
		result = NTFS_NO_MEMORY;
		goto finish;
	}
	ntfs_get_io_statistics(v, &before);
	begin = now();
	for (iteration = 0; iteration < BENCHMARK_READS; iteration++) {
		offset = 0;
		do {
			result = ntfs_stream_read(
			    stream, offset, buffer, BENCHMARK_READ_BUFFER_BYTES, &done);
			if (result != NTFS_OK) {
				goto finish;
			}
			offset += done;
			bytes += done;
		} while (done != 0);
	}
	elapsed = now() - begin;
	ntfs_get_io_statistics(v, &after);
	printf("{\"profile\":\"warm POSIX image, %u full reads and %u lookups\",\"bytes\":%" PRIu64
	       ",\"read_ns\":%" PRIu64 ",\"lookup_ns\":%" PRIu64 ",\"device_calls\":%" PRIu64
	       ",\"device_bytes\":%" PRIu64 ",\"metadata_cache_hits\":%" PRIu64 "}\n",
	    BENCHMARK_READS, BENCHMARK_LOOKUPS, bytes, elapsed, lookup_ns,
	    after.read_calls - before.read_calls, after.read_bytes - before.read_bytes,
	    after.record_cache_hits);
finish:
	free(buffer);
	ntfs_stream_close(stream);
	ntfs_node_close(node);
	ntfs_node_close(root);
	if (ntfs_unmount(v) != NTFS_OK) {
		result = NTFS_BUSY;
	}
	ntfs_image_close(&image);
	if (result != NTFS_OK) {
		fprintf(stderr, "%s\n", ntfs_result_string(result));
		return 1;
	}
	return 0;
}
