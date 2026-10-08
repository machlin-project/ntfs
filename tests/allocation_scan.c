/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_mutation_internal.h"
#include "fuzz_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_BITS_PER_BYTE = 8,
	TEST_ALIGNMENTS = 16,
	TEST_SMALL_BITS = 257,
	TEST_FRAGMENT_BITS = 16385,
	TEST_SENTINEL = 0x5a,
	TEST_START_VCN = 7
};

static enum ntfs_result
model(const uint8_t *before, uint8_t *after, size_t bits, uint64_t vcn, uint64_t wanted,
    struct ntfs_run *runs, size_t *count)
{
	size_t bit;
	struct ntfs_run *last;

	*count = 0;
	if (wanted > bits || vcn > UINT64_MAX - wanted) {
		return NTFS_NO_SPACE;
	}
	for (bit = 0; bit < bits && wanted != 0; bit++) {
		if (((before[bit / TEST_BITS_PER_BYTE] | after[bit / TEST_BITS_PER_BYTE]) &
			(1u << (bit % TEST_BITS_PER_BYTE))) != 0) {
			continue;
		}
		last = *count == 0 ? NULL : &runs[*count - 1];
		if (last != NULL && last->lcn + last->length == bit) {
			last->length++;
		} else {
			if (*count == NTFS_MUTATION_MAX_RUNS) {
				*count = 0;
				return NTFS_RANGE;
			}
			runs[(*count)++] = (struct ntfs_run){vcn, 1, bit};
		}
		after[bit / TEST_BITS_PER_BYTE] |= (uint8_t)(1u << (bit % TEST_BITS_PER_BYTE));
		vcn++;
		wanted--;
	}
	if (wanted != 0) {
		*count = 0;
		return NTFS_NO_SPACE;
	}
	return NTFS_OK;
}

static void
check(size_t bits, size_t alignment, unsigned pattern, uint64_t wanted)
{
	struct fuzz_device device = {0};
	struct ntfs_write_mutation_plan *plan;
	struct ntfs_run *runs = NULL, *expected;
	uint8_t *first, *second, *oracle, *before, *after;
	size_t bytes = (bits + TEST_BITS_PER_BYTE - 1) / TEST_BITS_PER_BYTE;
	size_t index, count, expected_count;
	uint32_t random = UINT32_C(0x57ab42d1);
	enum ntfs_result result;

	plan = calloc(1, sizeof(*plan));
	first = malloc(bytes + alignment + 1);
	second = malloc(bytes + alignment + 1);
	oracle = malloc(bytes + 1);
	expected = malloc(NTFS_MUTATION_MAX_RUNS * sizeof(*expected));
	assert(plan && first && second && oracle && expected);
	before = first + alignment;
	after = second + alignment;
	for (index = 0; index < bytes; index++) {
		random = random * UINT32_C(1664525) + UINT32_C(1013904223);
		before[index] = pattern == 0 ? 0
		    : pattern == 1	     ? UINT8_MAX
		    : pattern == 2	     ? UINT8_C(0xaa)
					     : (uint8_t)(random >> 24);
		after[index] = pattern < 3 ? 0 : (uint8_t)random;
	}
	before[bytes] = after[bytes] = TEST_SENTINEL;
	memcpy(oracle, after, bytes + 1);
	plan->source = fuzz_environment(&device);
	plan->info.cluster_count = bits;
	plan->allocation =
	    (struct ntfs_mutation_bitmap){.before = before, .after = after, .bytes = bytes};
	result = model(before, oracle, bits, TEST_START_VCN, wanted, expected, &expected_count);
	assert(ntfs_mutation_allocate_runs(plan, TEST_START_VCN, wanted, &runs, &count) == result);
	assert(count == expected_count && memcmp(after, oracle, bytes + 1) == 0);
	assert(before[bytes] == TEST_SENTINEL);
	if (result == NTFS_OK) {
		assert(runs != NULL && memcmp(runs, expected, count * sizeof(*runs)) == 0);
		ntfs_mutation_release(plan, runs, NTFS_MUTATION_MAX_RUNS * sizeof(*runs));
	} else {
		assert(runs == NULL);
	}
	assert(device.memory == 0 && plan->live_bytes == 0);
	free(expected);
	free(oracle);
	free(second);
	free(first);
	free(plan);
}

int
main(void)
{
	size_t bits, alignment;
	unsigned pattern;

	for (alignment = 0; alignment < TEST_ALIGNMENTS; alignment++) {
		for (bits = 0; bits <= TEST_SMALL_BITS; bits++) {
			for (pattern = 0; pattern < 4; pattern++) {
				check(bits, alignment, pattern, bits / 3);
				check(bits, alignment, pattern, bits);
			}
		}
	}
	check(TEST_FRAGMENT_BITS, 1, 2, NTFS_MUTATION_MAX_RUNS + 1);
	check(TEST_FRAGMENT_BITS, 7, 0, TEST_FRAGMENT_BITS + 1);
	puts("allocation first-fit model, original/private union, tails and run cap pass");
	return 0;
}
