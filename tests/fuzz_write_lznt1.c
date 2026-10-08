/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_lznt1.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { FUZZ_GUARD_BYTES = 32, FUZZ_GUARD = 0xa5, FUZZ_SMOKE_CASES = 512,
	FUZZ_SMOKE_BYTES = 65536 };

static void
check_guard(const uint8_t *bytes, size_t count)
{
	size_t index;

	for (index = 0; index < count; index++) {
		assert(bytes[index] == FUZZ_GUARD);
	}
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t *scratch, *output, *second, *decoded;
	size_t workspace, bound = SIZE_MAX, required = SIZE_MAX, written = SIZE_MAX,
	       done = SIZE_MAX, capacity, alignment;
	enum ntfs_result result;

	if (size > NTFS_WRITE_LZNT1_MAX_BYTES) {
		assert(ntfs_write_lznt1_bound(size, &bound) == NTFS_RANGE && bound == SIZE_MAX);
		return 0;
	}
	assert(ntfs_write_lznt1_bound(size, &bound) == NTFS_OK);
	workspace = ntfs_write_lznt1_workspace_size();
	alignment = size == 0 ? 0 : data[0] % FUZZ_GUARD_BYTES;
	scratch = malloc(workspace + alignment);
	output = malloc(bound + FUZZ_GUARD_BYTES);
	second = malloc(bound + FUZZ_GUARD_BYTES);
	decoded = malloc(size + alignment);
	assert(scratch && output && second && (decoded || size + alignment == 0));
	assert(ntfs_write_lznt1_measure(data, size, scratch + alignment, workspace,
	    &required) == NTFS_OK && required <= bound);
	memset(output, FUZZ_GUARD, bound + FUZZ_GUARD_BYTES);
	capacity = required != 0 && (data[0] & 1u) != 0 ? required - 1 : required;
	result = ntfs_write_lznt1_encode(data, size, scratch + alignment, workspace,
	    output, capacity, &written);
	if (capacity < required) {
		assert(result == NTFS_RANGE && written == SIZE_MAX);
		check_guard(output, bound + FUZZ_GUARD_BYTES);
		result = ntfs_write_lznt1_encode(data, size, scratch + alignment, workspace,
		    output, required, &written);
	}
	assert(result == NTFS_OK && written == required);
	check_guard(output + written, bound + FUZZ_GUARD_BYTES - written);
	assert(ntfs_write_lznt1_encode(data, size, scratch + alignment, workspace,
	    second, bound, &done) == NTFS_OK && done == written);
	assert(memcmp(output, second, written) == 0);
	assert(ntfs_lznt1_decode(output, written, size == 0 ? NULL : decoded + alignment,
	    size, &done) == NTFS_OK && done == size);
	if (size != 0) {
		assert(memcmp(data, decoded + alignment, size) == 0);
	}
	free(decoded);
	free(second);
	free(output);
	free(scratch);
	return 0;
}

#ifdef NTFS_FUZZ_STANDALONE
int
main(void)
{
	uint8_t *input;
	uint32_t state = UINT32_C(0x4c5a4e54);
	size_t index, run, size;

	input = malloc(FUZZ_SMOKE_BYTES);
	assert(input);
	memset(input, 0, FUZZ_SMOKE_BYTES);
	for (run = 0; run < FUZZ_SMOKE_CASES; run++) {
		size = run < 32 ? run : (run * 257) % FUZZ_SMOKE_BYTES;
		for (index = 0; index < size; index++) {
			state ^= state << 13;
			state ^= state >> 17;
			state ^= state << 5;
			input[index] = run % 3 == 0 ? (uint8_t)state
						  : (uint8_t)(index % (run % 29 + 1));
		}
		(void)LLVMFuzzerTestOneInput(input, size);
	}
	free(input);
	puts("PASS: 512 deterministic LZNT1 encoder fuzz smoke inputs");
	return 0;
}
#endif
