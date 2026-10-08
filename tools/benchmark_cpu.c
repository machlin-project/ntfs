/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include <ntfs/wof.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum { MAX_BYTES = 65536, INPUT_LIMIT = MAX_BYTES * 2, UNALIGNED = 3 };

static uint64_t
now(void)
{
	struct timespec time;

	assert(clock_gettime(CLOCK_MONOTONIC, &time) == 0);
	return (uint64_t)time.tv_sec * UINT64_C(1000000000) + (uint64_t)time.tv_nsec;
}

static uint8_t *
load(const char *path, size_t *size)
{
	FILE *file;
	long length;
	uint8_t *data;

	file = fopen(path, "rb");
	assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
	length = ftell(file);
	assert(length > 0 && length <= INPUT_LIMIT && fseek(file, 0, SEEK_SET) == 0);
	*size = (size_t)length;
	data = malloc(*size + UNALIGNED);
	assert(data != NULL && fread(data + UNALIGNED, 1, *size, file) == *size);
	assert(fclose(file) == 0);
	return data;
}

static enum ntfs_result
decode(const char *codec, const void *input, size_t size, void *output, size_t expected,
    void *workspace, size_t workspace_size, size_t *written)
{
	if (strcmp(codec, "lznt1") == 0) {
		return ntfs_lznt1_decode(input, size, output, expected, written);
	}
	if (strcmp(codec, "xpress") == 0) {
		return ntfs_xpress_huffman_decode(
		    input, size, output, expected, workspace, workspace_size, written);
	}
	assert(strcmp(codec, "lzx") == 0);
	return ntfs_lzx_decode(input, size, output, expected, workspace, workspace_size, written);
}

int
main(int argc, char **argv)
{
	uint8_t *input, *expected, *output, *workspace, *destination;
	size_t input_size, size, workspace_size, written, index, iterations;
	uint64_t start, elapsed, checksum = 0;
	bool matched = true, codec;

	assert(argc == 5);
	iterations = (size_t)strtoull(argv[4], NULL, 10);
	assert(iterations > 0);
	codec = strcmp(argv[1], "lznt1") == 0 || strcmp(argv[1], "xpress") == 0 ||
	    strcmp(argv[1], "lzx") == 0;
	workspace_size = ntfs_lzx_workspace_size();
	if (workspace_size < ntfs_xpress_workspace_size()) {
		workspace_size = ntfs_xpress_workspace_size();
	}
	workspace = malloc(workspace_size);
	assert(workspace != NULL);
	if (codec) {
		input = load(argv[2], &input_size);
		expected = load(argv[3], &size);
	} else {
		size = (size_t)strtoull(argv[2], NULL, 10);
		assert(size > 0 && size <= MAX_BYTES);
		input_size = size;
		input = malloc(size + UNALIGNED);
		expected = malloc(size + UNALIGNED);
		assert(input != NULL && expected != NULL);
		for (index = 0; index < size; index++) {
			input[index + UNALIGNED] = (uint8_t)(index * 37u + index / 11u);
		}
		memcpy(expected + UNALIGNED, input + UNALIGNED, size);
		if (strcmp(argv[1], "zero") == 0) {
			memset(expected + UNALIGNED, 0, size);
		}
	}
	output = malloc(size + UNALIGNED);
	assert(output != NULL);
	destination = output + UNALIGNED;
	memcpy(destination, expected + UNALIGNED, size);
	if (codec) {
		assert(decode(argv[1], input + UNALIGNED, input_size, destination, size, workspace,
			   workspace_size, &written) == NTFS_OK &&
		    written == size);
		assert(memcmp(destination, expected + UNALIGNED, size) == 0);
	}
	start = now();
	for (index = 0; index < iterations; index++) {
		if (codec) {
			assert(decode(argv[1], input + UNALIGNED, input_size, destination, size,
				   workspace, workspace_size, &written) == NTFS_OK &&
			    written == size);
		} else if (strcmp(argv[1], "copy") == 0) {
			ntfs_copy(destination, input + UNALIGNED, size);
		} else if (strcmp(argv[1], "zero") == 0) {
			ntfs_zero(destination, size);
		} else {
			assert(strcmp(argv[1], "equal") == 0);
			matched &= ntfs_equal(destination, input + UNALIGNED, size);
		}
	}
	elapsed = now() - start;
	assert(matched && memcmp(destination, expected + UNALIGNED, size) == 0);
	for (index = 0; index < size; index++) {
		checksum = checksum * 31u + destination[index];
	}
	printf("{\"bytes\":%zu,\"iterations\":%zu,\"ns\":%llu,\"checksum\":\"%016llx\"}\n", size,
	    iterations, (unsigned long long)elapsed, (unsigned long long)checksum);
	free(output);
	free(expected);
	free(input);
	free(workspace);
	return 0;
}
