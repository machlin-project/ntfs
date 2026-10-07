/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "image_fault.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_FRAME_BYTES = 4096,
	TEST_IMAGE_SLOTS = 8,
	TEST_WRITE_MULTIPLIER = 29,
	TEST_BYTE_MULTIPLIER = 7,
	TEST_PATTERN_FIRST = 11,
	TEST_BYTE_VALUES = 256
};

static size_t
number(const char *text)
{
	char *end;
	unsigned long long value;

	errno = 0;
	value = strtoull(text, &end, 10);
	assert(errno == 0 && end != text && *end == '\0' && text[0] != '-' && value <= SIZE_MAX);
	return (size_t)value;
}

int
main(int argc, char **argv)
{
	struct ntfs_image_fault *fault;
	uint8_t *frame;
	size_t capacity, frame_bytes, writes, index, byte;
	bool bounded;
	int error;
	enum ntfs_result result;

	assert(argc == 10);
	bounded = strcmp(argv[1], "bounded") == 0;
	assert(bounded || strcmp(argv[1], "default") == 0);
	capacity = number(argv[3]);
	frame_bytes = number(argv[4]);
	writes = number(argv[5]);
	fault = calloc(1, sizeof(*fault));
	frame = malloc(TEST_FRAME_BYTES);
	assert(fault != NULL && frame != NULL);
	if (bounded) {
		error = ntfs_image_fault_open_bounded(argv[2], number(argv[6]), number(argv[7]),
		    number(argv[8]), capacity, frame_bytes, fault);
	} else {
		assert(
		    capacity == NTFS_IMAGE_FAULT_EVENTS && frame_bytes == NTFS_OVERWRITE_MAX_BYTES);
		error = ntfs_image_fault_open(
		    argv[2], number(argv[6]), number(argv[7]), number(argv[8]), fault);
	}
	if (error != 0) {
		printf("{\"open_error\":%d}\n", error);
		free(frame);
		free(fault);
		return 2;
	}
	result = fault->environment.claim(fault);
	fault->enabled = true;
	if (result == NTFS_OK) {
		result = fault->environment.persist(fault);
	}
	for (index = 0; result == NTFS_OK && index < writes; index++) {
		size_t completed;

		for (byte = 0; byte < TEST_FRAME_BYTES; byte++) {
			frame[byte] =
			    (uint8_t)((index * TEST_WRITE_MULTIPLIER + byte * TEST_BYTE_MULTIPLIER +
					  TEST_PATTERN_FIRST) %
				TEST_BYTE_VALUES);
		}
		result =
		    fault->environment.write(fault, index % TEST_IMAGE_SLOTS * TEST_FRAME_BYTES,
			frame, TEST_FRAME_BYTES, &completed);
		if (result == NTFS_OK) {
			assert(completed == TEST_FRAME_BYTES);
			result = fault->environment.persist(fault);
		}
	}
	assert(ntfs_image_fault_dump(fault, argv[9]) == 0);
	printf("{\"result\":%u,\"triggered\":%s,\"uncertain\":%s}\n", result,
	    fault->triggered ? "true" : "false", fault->image.uncertain ? "true" : "false");
	ntfs_image_fault_close(fault);
	free(frame);
	free(fault);
	return result == NTFS_OK ? 0 : 1;
}
