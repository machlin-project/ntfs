/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include <ntfs/wof.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	FUZZ_METADATA,
	FUZZ_TABLE,
	FUZZ_XPRESS,
	FUZZ_KINDS,
	FUZZ_CHUNK_BUDGET = 4096,
	FUZZ_INPUT_BYTES = 2 * NTFS_XPRESS_MAX_BLOCK,
	FUZZ_SCRATCH_BYTES = 2048,
	FUZZ_GUARD_BYTES = sizeof(max_align_t),
	FUZZ_GUARD_VALUE = 0xa5,
	FUZZ_MUTATIONS = 512
};

/* Independent test envelope, not NTFS wire metadata. */
struct fuzz_wof_header {
	uint8_t kind, algorithm[sizeof(uint32_t)];
	uint8_t logical[sizeof(uint64_t)], stored[sizeof(uint64_t)], expected[sizeof(uint32_t)];
};

union fuzz_scratch {
	max_align_t alignment;
	uint8_t bytes[FUZZ_SCRATCH_BYTES + 2 * FUZZ_GUARD_BYTES];
};

static union fuzz_scratch scratch[2];
static uint8_t output[2][NTFS_XPRESS_MAX_BLOCK + 2 * FUZZ_GUARD_BYTES];

static void
check_guards(const uint8_t *bytes, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++) {
		assert(bytes[i] == FUZZ_GUARD_VALUE);
	}
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const struct fuzz_wof_header *header = (const void *)data;
	struct ntfs_wof_info first_info, second_info, zero_info = {0};
	struct ntfs_wof_layout first_layout, second_layout, zero_layout = {0};
	struct ntfs_wof_span span, zero_span = {0};
	const uint8_t *payload;
	size_t payload_size, expected, workspace_size, done[2], i;
	enum ntfs_result result, repeat;

	if (size < sizeof(*header) || size > FUZZ_INPUT_BYTES) {
		return 0;
	}
	payload = data + sizeof(*header);
	payload_size = size - sizeof(*header);
	switch (header->kind % FUZZ_KINDS) {
	case FUZZ_METADATA:
		result = ntfs_wof_decode(payload, payload_size, &first_info);
		repeat = ntfs_wof_decode(payload, payload_size, &second_info);
		assert(
		    result == repeat && memcmp(&first_info, &second_info, sizeof(first_info)) == 0);
		if (result != NTFS_OK) {
			assert(memcmp(&first_info, &zero_info, sizeof(first_info)) == 0);
		}
		break;
	case FUZZ_TABLE:
		result =
		    ntfs_wof_layout_init(ntfs_u32(header->algorithm), ntfs_u64(header->logical),
			ntfs_u64(header->stored), FUZZ_CHUNK_BUDGET, &first_layout);
		repeat =
		    ntfs_wof_layout_init(ntfs_u32(header->algorithm), ntfs_u64(header->logical),
			ntfs_u64(header->stored), FUZZ_CHUNK_BUDGET, &second_layout);
		assert(result == repeat &&
		    memcmp(&first_layout, &second_layout, sizeof(first_layout)) == 0);
		if (result != NTFS_OK) {
			assert(memcmp(&first_layout, &zero_layout, sizeof(first_layout)) == 0);
			break;
		}
		result = ntfs_wof_table_validate(&first_layout, payload, payload_size);
		assert(result == ntfs_wof_table_validate(&second_layout, payload, payload_size));
		if (payload_size >= 2 * sizeof(uint64_t)) {
			result = ntfs_wof_chunk_span(&first_layout, ntfs_u32(header->expected),
			    ntfs_u64(payload), ntfs_u64(payload + sizeof(uint64_t)), &span);
			if (result != NTFS_OK) {
				assert(memcmp(&span, &zero_span, sizeof(span)) == 0);
			}
		}
		break;
	case FUZZ_XPRESS:
		expected = ntfs_u32(header->expected) % (NTFS_XPRESS_MAX_BLOCK + 1u);
		workspace_size = ntfs_xpress_workspace_size();
		assert(workspace_size <= FUZZ_SCRATCH_BYTES);
		for (i = 0; i < 2; i++) {
			memset(output[i], FUZZ_GUARD_VALUE, expected + 2 * FUZZ_GUARD_BYTES);
			memset(scratch[i].bytes, FUZZ_GUARD_VALUE, sizeof(scratch[i].bytes));
		}
		result =
		    ntfs_xpress_huffman_decode(payload, payload_size, output[0] + FUZZ_GUARD_BYTES,
			expected, scratch[0].bytes + FUZZ_GUARD_BYTES, workspace_size, &done[0]);
		repeat =
		    ntfs_xpress_huffman_decode(payload, payload_size, output[1] + FUZZ_GUARD_BYTES,
			expected, scratch[1].bytes + FUZZ_GUARD_BYTES, workspace_size, &done[1]);
		assert(result == repeat && done[0] == done[1]);
		assert(done[0] == (result == NTFS_OK ? expected : 0));
		assert(memcmp(output[0], output[1], expected + 2 * FUZZ_GUARD_BYTES) == 0);
		for (i = 0; i < 2; i++) {
			check_guards(output[i], FUZZ_GUARD_BYTES);
			check_guards(output[i] + FUZZ_GUARD_BYTES + expected, FUZZ_GUARD_BYTES);
			check_guards(scratch[i].bytes, FUZZ_GUARD_BYTES);
			check_guards(
			    scratch[i].bytes + FUZZ_GUARD_BYTES + workspace_size, FUZZ_GUARD_BYTES);
		}
		break;
	}
	return 0;
}

#ifdef NTFS_FUZZ_STANDALONE
int
main(int argc, char **argv)
{
	FILE *file;
	uint8_t *bytes, saved;
	long length;
	size_t i, position;

	assert(argc == 2);
	file = fopen(argv[1], "rb");
	assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
	length = ftell(file);
	assert(length > 0 && (size_t)length <= FUZZ_INPUT_BYTES);
	assert(fseek(file, 0, SEEK_SET) == 0);
	bytes = malloc((size_t)length);
	assert(bytes != NULL && fread(bytes, 1, (size_t)length, file) == (size_t)length);
	assert(fclose(file) == 0);
	LLVMFuzzerTestOneInput(bytes, (size_t)length);
	for (i = 0; i < FUZZ_MUTATIONS; i++) {
		position = i % (size_t)length;
		saved = bytes[position];
		bytes[position] ^= (uint8_t)(1u << (i % NTFS_BITS_PER_BYTE));
		LLVMFuzzerTestOneInput(bytes, (size_t)length);
		bytes[position] = saved;
	}
	free(bytes);
	puts("PASS: bounded WOF/XPRESS mutations, deterministic errors, output/scratch guards");
	return 0;
}
#endif
