/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/logfile.h>
#include "fuzz_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_SOURCE_BYTES = 2 * 1024 * 1024,
	TEST_PATH_BYTES = 1024,
	TEST_SENTINEL = 0xa5,
	TEST_QUERY_FIELDS = 11
};

static uint8_t *
read_file(const char *directory, const char *name, size_t *size)
{
	char path[TEST_PATH_BYTES];
	FILE *file;
	long length;
	uint8_t *bytes;

	assert(snprintf(path, sizeof(path), "%s/%s", directory, name) > 0);
	file = fopen(path, "rb");
	assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
	length = ftell(file);
	assert(length > 0 && length <= TEST_SOURCE_BYTES && fseek(file, 0, SEEK_SET) == 0);
	bytes = malloc((size_t)length);
	assert(bytes != NULL && fread(bytes, 1, (size_t)length, file) == (size_t)length);
	assert(fclose(file) == 0);
	*size = (size_t)length;
	return bytes;
}

int
main(int argc, char **argv)
{
	struct fuzz_device device = {0};
	struct ntfs_environment environment;
	struct ntfs_logfile *source = NULL;
	struct ntfs_logfile_client active, raw, expected, zero = {0};
	FILE *queries;
	char path[TEST_PATH_BYTES], name[TEST_PATH_BYTES], opened[TEST_PATH_BYTES] = {0};
	uint8_t *bytes = NULL, *backup = NULL;
	size_t size = 0, reads, allocations, memory, count = 0, sources = 0;
	unsigned index, sequence, code, has_raw, previous, following, stored_sequence, length, unit;
	unsigned long long oldest, restart;
	uint16_t i;
	enum ntfs_result result;

	assert(argc == 2 && snprintf(path, sizeof(path), "%s/queries.tsv", argv[1]) > 0);
	queries = fopen(path, "r");
	assert(queries != NULL);
	while (fscanf(queries, "%1023s %u %u %u %u %llu %llu %u %u %u %u", name, &index, &sequence,
		   &code, &has_raw, &oldest, &restart, &previous, &following, &stored_sequence,
		   &length) == TEST_QUERY_FIELDS) {
		assert(index <= UINT16_MAX && sequence <= UINT16_MAX && previous <= UINT16_MAX &&
		    following <= UINT16_MAX && stored_sequence <= UINT16_MAX &&
		    length <= NTFS_LOGFILE_CLIENT_NAME_UNITS);
		expected = (struct ntfs_logfile_client){.oldest_lsn = oldest,
		    .restart_lsn = restart,
		    .previous = (uint16_t)previous,
		    .next = (uint16_t)following,
		    .sequence = (uint16_t)stored_sequence,
		    .name_length = (uint16_t)length};
		for (i = 0; i < length; i++) {
			assert(fscanf(queries, "%u", &unit) == 1 && unit <= UINT16_MAX);
			expected.name[i] = (uint16_t)unit;
		}
		if (strcmp(name, opened) != 0) {
			ntfs_logfile_close(source);
			assert(device.memory == 0);
			if (bytes != NULL) {
				assert(memcmp(bytes, backup, size) == 0);
			}
			free(backup);
			free(bytes);
			bytes = read_file(argv[1], name, &size);
			backup = malloc(size);
			assert(backup != NULL);
			memcpy(backup, bytes, size);
			device = (struct fuzz_device){.data = bytes, .size = size};
			environment = fuzz_environment(&device);
			assert(ntfs_logfile_open(&environment, NULL, NULL, &source) == NTFS_OK);
			assert(snprintf(opened, sizeof(opened), "%s", name) > 0);
			sources++;
		}
		reads = device.reads;
		allocations = device.allocations;
		memory = device.memory;
		device.fail_read = reads + 1;
		device.fail_allocation = allocations + 1;
		memset(&active, TEST_SENTINEL, sizeof(active));
		memset(&raw, TEST_SENTINEL, sizeof(raw));
		result = ntfs_logfile_get_active_client(
		    source, (uint16_t)index, (uint16_t)sequence, &active);
		assert(result == (enum ntfs_result)code);
		assert(memcmp(&active, code == NTFS_OK ? &expected : &zero, sizeof(active)) == 0);
		assert(ntfs_logfile_get_client(source, (uint16_t)index, &raw) ==
		    (has_raw ? NTFS_OK : NTFS_END));
		assert(memcmp(&raw, has_raw ? &expected : &zero, sizeof(raw)) == 0);
		assert(device.reads == reads && device.allocations == allocations &&
		    device.memory == memory);
		device.fail_read = 0;
		device.fail_allocation = 0;
		count++;
	}
	assert(feof(queries) && fclose(queries) == 0 && count != 0);
	memset(&active, TEST_SENTINEL, sizeof(active));
	assert(ntfs_logfile_get_active_client(NULL, 0, 0, &active) == NTFS_INVALID &&
	    memcmp(&active, &zero, sizeof(active)) == 0);
	reads = device.reads;
	allocations = device.allocations;
	assert(ntfs_logfile_get_active_client(source, 0, 0, NULL) == NTFS_INVALID &&
	    device.reads == reads && device.allocations == allocations);
	ntfs_logfile_close(source);
	assert(device.memory == 0 && memcmp(bytes, backup, size) == 0);
	free(backup);
	free(bytes);
	printf("PASS: %zu active client pair queries across %zu snapshots, exact free/active "
	       "metadata, sequence boundaries, lossless names and no cached I/O/allocation; "
	       "no current-history/recovery acceptance\n",
	    count, sources);
	return 0;
}
