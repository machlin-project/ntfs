/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_lznt1.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { GUARD = 0xa5, ALIGNMENTS = 32, PATTERNS = 7, CHUNK_BYTES = 4096 };

size_t reference_write_lznt1_workspace_size(void);
enum ntfs_result reference_write_lznt1_bound(size_t, size_t *);
enum ntfs_result reference_write_lznt1_measure(const void *, size_t, void *, size_t, size_t *);
enum ntfs_result reference_write_lznt1_encode(
    const void *, size_t, void *, size_t, void *, size_t, size_t *);

static size_t
check(const uint8_t *data, size_t bytes, size_t alignment)
{
	uint8_t *input, *scratch, *reference_scratch, *output, *reference_output;
	size_t workspace, reference_workspace, bound = SIZE_MAX, reference_bound = SIZE_MAX,
					       required = SIZE_MAX, reference_required = SIZE_MAX,
					       written, reference_written, capacities[8], count = 0,
					       index, offset, capacity;
	enum ntfs_result result, reference_result;

	workspace = ntfs_write_lznt1_workspace_size();
	reference_workspace = reference_write_lznt1_workspace_size();
	assert(workspace == reference_workspace);
	assert(ntfs_write_lznt1_bound(bytes, &bound) == NTFS_OK);
	assert(reference_write_lznt1_bound(bytes, &reference_bound) == NTFS_OK &&
	    bound == reference_bound);
	input = malloc(bytes + alignment + 1);
	scratch = malloc(workspace + alignment + 1);
	reference_scratch = malloc(reference_workspace + alignment + 1);
	assert(input && scratch && reference_scratch);
	memset(input, GUARD, bytes + alignment + 1);
	memcpy(input + alignment + 1, data, bytes);
	memset(scratch, GUARD, workspace + alignment + 1);
	memset(reference_scratch, GUARD, reference_workspace + alignment + 1);
	assert(ntfs_write_lznt1_measure(input + alignment + 1, bytes, scratch + alignment + 1,
		   workspace, &required) == NTFS_OK);
	assert(reference_write_lznt1_measure(input + alignment + 1, bytes,
		   reference_scratch + alignment + 1, reference_workspace,
		   &reference_required) == NTFS_OK);
	assert(required == reference_required && required <= bound);
	capacities[count++] = 0;
	capacities[count++] = 1;
	if (required != 0) {
		capacities[count++] = required - 1;
	}
	capacities[count++] = required;
	capacities[count++] = required + 1;
	if (bound != 0) {
		capacities[count++] = bound - 1;
	}
	capacities[count++] = bound;
	capacities[count++] = bound + 1;
	for (index = 0; index < count; index++) {
		capacity = capacities[index];
		output = malloc(capacity + alignment + 1);
		reference_output = malloc(capacity + alignment + 1);
		assert(output && reference_output);
		memset(output, GUARD, capacity + alignment + 1);
		memset(reference_output, GUARD, capacity + alignment + 1);
		written = SIZE_MAX;
		reference_written = SIZE_MAX;
		result = ntfs_write_lznt1_encode(input + alignment + 1, bytes,
		    scratch + alignment + 1, workspace, output + alignment + 1, capacity, &written);
		reference_result = reference_write_lznt1_encode(input + alignment + 1, bytes,
		    reference_scratch + alignment + 1, reference_workspace,
		    reference_output + alignment + 1, capacity, &reference_written);
		assert(result == reference_result && written == reference_written);
		assert(result == (capacity < required ? NTFS_RANGE : NTFS_OK));
		assert(written == (capacity < required ? SIZE_MAX : required));
		assert(memcmp(output, reference_output, capacity + alignment + 1) == 0);
		for (offset = 0; offset <= alignment; offset++) {
			assert(output[offset] == GUARD && scratch[offset] == GUARD &&
			    input[offset] == GUARD);
		}
		for (offset = result == NTFS_OK ? written : 0; offset < capacity; offset++) {
			assert(output[alignment + 1 + offset] == GUARD);
		}
		free(reference_output);
		free(output);
	}
	assert(memcmp(input + alignment + 1, data, bytes) == 0);
	free(reference_scratch);
	free(scratch);
	free(input);
	return count;
}

int
main(void)
{
	static const size_t sizes[] = {0, 1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 18, 31, 32, 33, 34, 63,
	    64, 65, 66, 127, 128, 129, 130, 255, 256, 257, 258, 511, 512, 513, 514, 1023, 1024,
	    1025, 1026, 2047, 2048, 2049, 2050, 4093, 4094, 4095, 4096, 4097, 8191, 8192, 8193,
	    65536, NTFS_WRITE_LZNT1_MAX_BYTES};
	uint8_t *data;
	uint32_t random = UINT32_C(0x4c5a4e54);
	size_t kind, index, check_index, checks = 0, position;

	data = malloc(NTFS_WRITE_LZNT1_MAX_BYTES);
	assert(data);
	for (kind = 0; kind < PATTERNS; kind++) {
		for (index = 0; index < NTFS_WRITE_LZNT1_MAX_BYTES; index++) {
			random ^= random << 13;
			random ^= random >> 17;
			random ^= random << 5;
			switch (kind) {
			case 0:
				data[index] = 0;
				break;
			case 1:
				data[index] = (uint8_t)(index % 3);
				break;
			case 2:
				data[index] = (uint8_t)(index % 31);
				break;
			case 3:
				data[index] = (uint8_t)random;
				break;
			case 4:
				data[index] =
				    index % 257 < 193 ? (uint8_t)(index % 7) : (uint8_t)random;
				break;
			case 5:
				data[index] = (index / CHUNK_BYTES) % 2 ? (uint8_t)random : 'Q';
				break;
			default:
				data[index] = (uint8_t)(index / 3);
				break;
			}
		}
		for (index = 0; index < sizeof(sizes) / sizeof(*sizes); index++) {
			checks += check(data, sizes[index], index % ALIGNMENTS);
		}
	}
	/* Matches that finish immediately before/at/after each width transition,
	 * followed by further references and independent chunk dictionary resets. */
	for (position = 16; position <= 2048; position *= 2) {
		for (check_index = position - 1; check_index <= position + 1; check_index++) {
			memset(data, 'A', CHUNK_BYTES * 2);
			data[check_index] = 'B';
			data[CHUNK_BYTES + check_index] = 'C';
			checks += check(data, CHUNK_BYTES * 2, check_index % ALIGNMENTS);
		}
	}
	free(data);
	printf("PASS: %zu frozen/current LZNT1 encode capacity checks, identical bytes and failure "
	       "publication\n",
	    checks);
	return 0;
}
