/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <limits.h>
#include <stdlib.h>
#include <string.h>

enum { TEST_ARGUMENT_COUNT = 2, TEST_ALLOCATION_BYTES = 8 };

/* Deliberate faults belong only to disposable sanitizer-contract subprocesses.
 * Volatile accesses keep their runtime instrumentation from being optimized out. */
int
main(int argc, char **argv)
{
	volatile int value = INT_MAX;
	volatile size_t position = TEST_ALLOCATION_BYTES;
	volatile unsigned char *storage;

	if (argc != TEST_ARGUMENT_COUNT) {
		return EXIT_FAILURE;
	}
	if (strcmp(argv[1], "undefined") == 0) {
		value += 1;
		return EXIT_SUCCESS;
	}
	if (strcmp(argv[1], "address") == 0) {
		storage = malloc(TEST_ALLOCATION_BYTES);
		if (storage == NULL) {
			return EXIT_FAILURE;
		}
		storage[position] = 0;
		free((void *)storage);
		return EXIT_SUCCESS;
	}
	return strcmp(argv[1], "clean") == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
