/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

enum { ALIGNMENTS = 32, SMALL_LIMIT = 257, GUARD = 0xa5, LARGE_BYTES = 65536 };

static void
reference_copy(uint8_t *output, const uint8_t *input, size_t size)
{
	size_t index;

	for (index = 0; index < size; index++) {
		output[index] = input[index];
	}
}

static void
spans(void)
{
	uint8_t *left, *right, *expected;
	size_t source, target, length, index, total = LARGE_BYTES + ALIGNMENTS * 2;

	left = malloc(total);
	right = malloc(total);
	expected = malloc(total);
	assert(left != NULL && right != NULL && expected != NULL);
	for (index = 0; index < total; index++) {
		left[index] = (uint8_t)(index * 37u + index / 11u);
	}
	for (source = 0; source < ALIGNMENTS; source++) {
		for (target = 0; target < ALIGNMENTS; target++) {
			for (length = 0; length <= SMALL_LIMIT; length++) {
				memset(right, GUARD, SMALL_LIMIT + ALIGNMENTS);
				memcpy(expected, right, SMALL_LIMIT + ALIGNMENTS);
				memcpy(expected + target, left + source, length);
				ntfs_copy(right + target, left + source, length);
				assert(memcmp(right, expected, SMALL_LIMIT + ALIGNMENTS) == 0);
				assert(ntfs_equal(right + target, left + source, length));
			}
		}
		for (length = 0; length <= LARGE_BYTES;
		    length += length < SMALL_LIMIT ? 1 : SMALL_LIMIT) {
			memset(right, GUARD, total);
			memcpy(expected, right, total);
			memset(expected + source, 0, length);
			ntfs_zero(right + source, length);
			assert(memcmp(right, expected, total) == 0);
		}
		memcpy(right, left, total);
		for (index = source; index < source + SMALL_LIMIT; index++) {
			right[index] ^= 1;
			assert(!ntfs_equal(left + source, right + source, SMALL_LIMIT));
			right[index] ^= 1;
		}
	}
	free(expected);
	free(right);
	free(left);
}

static void
overlap(void)
{
	uint8_t *actual, *expected;
	size_t source, target, size, index, total = LARGE_BYTES + ALIGNMENTS * 2;

	actual = malloc(total);
	expected = malloc(total);
	assert(actual != NULL && expected != NULL);
	for (source = 0; source < ALIGNMENTS; source++) {
		for (target = 0; target < ALIGNMENTS; target++) {
			for (size = 0; size <= SMALL_LIMIT; size++) {
				for (index = 0; index < SMALL_LIMIT + ALIGNMENTS; index++) {
					expected[index] = (uint8_t)(index * 37u);
				}
				memcpy(actual, expected, SMALL_LIMIT + ALIGNMENTS);
				reference_copy(expected + target, expected + source, size);
				ntfs_copy(actual + target, actual + source, size);
				assert(memcmp(actual, expected, SMALL_LIMIT + ALIGNMENTS) == 0);
			}
		}
	}
	for (source = 1; source <= ALIGNMENTS; source++) {
		for (size = 0; size <= LARGE_BYTES; size += size < SMALL_LIMIT ? 1 : SMALL_LIMIT) {
			memset(actual, GUARD, total);
			for (index = 0; index < source; index++) {
				actual[index] = (uint8_t)(index * 37u);
			}
			memcpy(expected, actual, total);
			reference_copy(expected + source, expected, size);
			ntfs_lz_copy(actual + source, source, size);
			assert(memcmp(actual, expected, total) == 0);
		}
	}
	free(expected);
	free(actual);
}

static void
search(void)
{
	uint8_t bytes[SMALL_LIMIT + ALIGNMENTS];
	size_t alignment, position;
	unsigned value;

	for (value = 0; value <= UINT8_MAX; value++) {
		memset(bytes, (uint8_t)(value + 1), sizeof(bytes));
		for (alignment = 0; alignment < ALIGNMENTS; alignment++) {
			assert(ntfs_find_byte(bytes + alignment, SMALL_LIMIT, (uint8_t)value) ==
			    SMALL_LIMIT);
			for (position = 0; position < SMALL_LIMIT; position++) {
				bytes[alignment + position] = (uint8_t)value;
				assert(ntfs_find_byte(bytes + alignment, SMALL_LIMIT,
					   (uint8_t)value) == position);
				bytes[alignment + position] = (uint8_t)(value + 1);
			}
		}
	}
}

static void
page_ends(void)
{
	uint8_t *left, *right, *a, *b;
	size_t page = (size_t)sysconf(_SC_PAGESIZE), size, distance, index;

	assert(page > SMALL_LIMIT);
	left = mmap(NULL, page * 3, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
	right = mmap(NULL, page * 3, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
	assert(left != MAP_FAILED && right != MAP_FAILED);
	assert(mprotect(left + page, page, PROT_READ | PROT_WRITE) == 0);
	assert(mprotect(right + page, page, PROT_READ | PROT_WRITE) == 0);
	for (size = 0; size <= page; size++) {
		a = left + 2 * page - size;
		b = right + 2 * page - size;
		memset(a, GUARD, size);
		ntfs_copy(b, a, size);
		assert(ntfs_equal(a, b, size));
		assert(ntfs_find_byte(a, size, 0) == size);
		ntfs_zero(b, size);
		for (index = 0; index < size; index++) {
			assert(b[index] == 0);
		}
	}
	for (distance = 1; distance <= ALIGNMENTS; distance++) {
		for (size = 0; size <= SMALL_LIMIT; size++) {
			a = left + 2 * page - size;
			memset(a - distance, GUARD, distance);
			ntfs_lz_copy(a, distance, size);
			for (index = 0; index < size; index++) {
				assert(a[index] == GUARD);
			}
		}
	}
	assert(munmap(left, page * 3) == 0 && munmap(right, page * 3) == 0);
}

int
main(void)
{
	ntfs_copy(NULL, NULL, 0);
	ntfs_zero(NULL, 0);
	assert(ntfs_equal(NULL, NULL, 0));
	assert(ntfs_find_byte(NULL, 0, 0) == 0);
	spans();
	overlap();
	search();
	page_ends();
	puts("PASS: byte oracles, all alignments, forward overlap, LZ periods and protected page "
	     "ends");
	return 0;
}
