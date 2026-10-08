/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/ntfs.h>
#include "fuzz_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_FILE = 24,
	TEST_PEER = 25,
	TEST_SEQUENCE = 7,
	TEST_TABLE_READS = 2,
	TEST_PATH_BYTES = 4096,
	TEST_DATA_BYTES = 16,
	TEST_PEER_BUFFER_BYTES = 1024,
	TEST_PEER_UNIT_BYTES = 4096,
	TEST_PEER_FINAL_BYTES = 777,
	TEST_PEER_ALPHABET_BYTES = 26
};

static struct ntfs_node *
open_node(struct ntfs_volume *volume, unsigned number)
{
	struct ntfs_node *node = NULL;
	struct ntfs_stat stat;
	uint64_t reference = (uint64_t)TEST_SEQUENCE << NTFS_REFERENCE_SEQUENCE_SHIFT | number;

	assert(ntfs_node_open(volume, reference, &node) == NTFS_OK);
	assert(ntfs_node_stat(node, &stat) == NTFS_OK);
	return node;
}

static size_t
open_stream(struct ntfs_volume *volume, struct fuzz_device *device, unsigned number,
    enum ntfs_result expected, size_t *allocations)
{
	struct ntfs_node *node = open_node(volume, number);
	struct ntfs_stream *stream = NULL;
	size_t before = device->reads, allocated = device->allocations;

	assert(ntfs_stream_open(node, NULL, 0, &stream) == expected);
	if (allocations != NULL) {
		*allocations = device->allocations - allocated;
	}
	ntfs_node_close(node);
	ntfs_stream_close(stream);
	return device->reads - before;
}

static void
work_limit(struct ntfs_volume *volume, struct fuzz_device *device, size_t expected_reads)
{
	struct ntfs_node *node = open_node(volume, TEST_FILE);
	struct ntfs_stream *stream = NULL;
	struct ntfs_operation operation = {0};
	struct ntfs_operation_limits limits;
	struct ntfs_operation_usage usage;
	size_t reads;

	/* Measure a successful volume-cache hit on a fresh node, then leave one
	 * work credit short. Refusal must publish no stream and retain its proof. */
	assert(ntfs_stream_open(node, NULL, 0, &stream) == NTFS_OK);
	ntfs_get_operation_usage(volume, &usage);
	assert(usage.work > 1);
	ntfs_stream_close(stream);
	ntfs_node_close(node);
	node = open_node(volume, TEST_FILE);
	ntfs_operation_default_limits(&limits);
	limits.work = usage.work - 1;
	assert(ntfs_operation_begin(volume, &limits, &operation) == NTFS_OK);
	assert(ntfs_stream_open(node, NULL, 0, &stream) == NTFS_RANGE && stream == NULL);
	assert(ntfs_operation_end(&operation, &usage) == NTFS_OK);
	assert(usage.exhausted == NTFS_OPERATION_LIMIT_WORK);
	ntfs_node_close(node);
	reads = open_stream(volume, device, TEST_FILE, NTFS_OK, NULL);
	assert(reads == expected_reads);
}

static void
peer_contents(struct ntfs_volume *volume)
{
	struct ntfs_node *node = open_node(volume, TEST_PEER);
	struct ntfs_stream *stream = NULL;
	struct ntfs_stat stat;
	uint8_t output[TEST_PEER_BUFFER_BYTES];
	uint64_t offset = 0;
	size_t done, index;

	assert(ntfs_node_stat(node, &stat) == NTFS_OK);
	assert(stat.size > TEST_PEER_UNIT_BYTES);
	assert(stat.size % TEST_PEER_UNIT_BYTES == TEST_PEER_FINAL_BYTES);
	assert(ntfs_stream_open(node, NULL, 0, &stream) == NTFS_OK);
	ntfs_node_close(node);
	while (offset < stat.size) {
		assert(ntfs_stream_read(stream, offset, output, sizeof(output), &done) == NTFS_OK);
		assert(done > 0 && done <= sizeof(output) && done <= stat.size - offset);
		for (index = 0; index < done; index++) {
			assert(output[index] == 'A' +
			    ((offset + index) / TEST_PEER_UNIT_BYTES) % TEST_PEER_ALPHABET_BYTES);
		}
		offset += done;
	}
	ntfs_stream_close(stream);
}

static void
exercise(const char *directory, uint32_t entries, bool bad_peer)
{
	struct fuzz_device device = {0};
	struct ntfs_environment environment;
	struct ntfs_limits limits;
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *node;
	struct ntfs_stream *stream = NULL;
	uint8_t *image, output[TEST_DATA_BYTES];
	char path[TEST_PATH_BYTES];
	FILE *file;
	long size;
	size_t cold, warm, allocations, before, fault, retained, done;
	int count;

	count = snprintf(
	    path, sizeof(path), "%s/wof-cache-%s.img", directory, bad_peer ? "bad-peer" : "pair");
	assert(count > 0 && (size_t)count < sizeof(path));
	file = fopen(path, "rb");
	assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
	size = ftell(file);
	assert(size > 0 && fseek(file, 0, SEEK_SET) == 0);
	image = malloc((size_t)size);
	assert(image != NULL && fread(image, 1, (size_t)size, file) == (size_t)size);
	assert(fclose(file) == 0);
	device.data = image;
	device.size = (size_t)size;
	environment = fuzz_environment(&device);
	ntfs_default_limits(&limits);
	limits.record_cache_entries = entries;
	assert(ntfs_mount(&environment, &limits, &volume) == NTFS_OK);
	cold = open_stream(volume, &device, TEST_FILE, NTFS_OK, &allocations);
	warm = open_stream(volume, &device, TEST_FILE, NTFS_OK, NULL);
	assert(cold == warm + (entries == 0 ? 0 : TEST_TABLE_READS));
	assert(
	    open_stream(volume, &device, TEST_PEER, bad_peer ? NTFS_CORRUPT : NTFS_OK, NULL) > 0);
	/* A failed proof cannot evict a successful colliding entry. */
	assert(open_stream(volume, &device, TEST_FILE, NTFS_OK, NULL) ==
	    (!bad_peer && entries == 1 ? cold : warm));
	for (fault = 1; fault <= allocations; fault++) {
		node = open_node(volume, TEST_FILE);
		retained = device.memory;
		device.fail_allocation = device.allocations + fault;
		assert(ntfs_stream_open(node, NULL, 0, &stream) == NTFS_NO_MEMORY);
		assert(stream == NULL && device.memory == retained);
		device.fail_allocation = 0;
		ntfs_node_close(node);
		assert(open_stream(volume, &device, TEST_FILE, NTFS_OK, NULL) == warm);
	}
	work_limit(volume, &device, warm);
	/* A new volume is cold. Refusing final publication cannot seed its memo. */
	assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
	assert(ntfs_mount(&environment, &limits, &volume) == NTFS_OK);
	node = open_node(volume, TEST_FILE);
	device.fail_allocation = device.allocations + allocations;
	assert(ntfs_stream_open(node, NULL, 0, &stream) == NTFS_NO_MEMORY && stream == NULL);
	device.fail_allocation = 0;
	ntfs_node_close(node);
	assert(open_stream(volume, &device, TEST_FILE, NTFS_OK, NULL) == cold);
	node = open_node(volume, TEST_FILE);
	assert(ntfs_stream_open(node, NULL, 0, &stream) == NTFS_OK);
	ntfs_node_close(node);
	before = device.reads;
	device.fail_read = before + 1;
	memset(output, 0, sizeof(output));
	assert(ntfs_stream_read(stream, 0, output, sizeof(output), &done) == NTFS_IO && done == 0);
	device.fail_read = 0;
	assert(ntfs_stream_read(stream, 0, output, sizeof(output), &done) == NTFS_OK);
	assert(done == sizeof(output));
	for (before = 0; before < sizeof(output); before++) {
		assert(output[before] == 'A');
	}
	ntfs_stream_close(stream);
	if (!bad_peer) {
		peer_contents(volume);
	}
	assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
	free(image);
}

int
main(int argc, char **argv)
{
	const uint32_t capacities[] = {0, 1, 64};
	size_t index;

	assert(argc == 2);
	for (index = 0; index < sizeof(capacities) / sizeof(capacities[0]); index++) {
		exercise(argv[1], capacities[index], false);
		exercise(argv[1], capacities[index], true);
	}
	puts("WOF volume proof reuse, eviction, failed publication, remount and stream lifetime "
	     "pass");
	return 0;
}
