/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/ntfs.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Independent wire vectors: the table records each length/displacement split
 * transition. Do not derive these expected splits from the decoder algorithm. */
enum {
	BYTE_BITS = 8,
	CHUNK_BYTES = 4096,
	CHUNK_SIGNATURE = 0x3000,
	CHUNK_COMPRESSED = 0x8000,
	TOKEN_INITIAL_SHIFT = 12,
	TOKEN_MIN_LENGTH = 3,
	SEED_BYTES = 3,
	MATCH_COUNT = 2,
	FIRST_MATCH_BIT = SEED_BYTES,
	SECOND_MATCH_BIT = SEED_BYTES + 1
};

static void
store_u16(uint8_t *out, uint16_t value)
{
	out[0] = (uint8_t)value;
	out[1] = (uint8_t)(value >> BYTE_BITS);
}

static void
token_boundaries(void)
{
	static const struct {
		uint16_t position;
		unsigned shift;
	} cases[] = {{16, 12}, {17, 11}, {32, 11}, {33, 10}, {64, 10}, {65, 9}, {128, 9}, {129, 8},
	    {256, 8}, {257, 7}, {512, 7}, {513, 6}, {1024, 6}, {1025, 5}, {2048, 5}, {2049, 4},
	    {4093, 4}};

	struct encoded_chunk {
		uint8_t header[sizeof(uint16_t)], flags, literals[SEED_BYTES];
		uint8_t tokens[MATCH_COUNT][sizeof(uint16_t)];
		uint8_t terminator[sizeof(uint16_t)];
	} input = {0};

	uint8_t output[CHUNK_BYTES];
	size_t i, j, length, done;
	uint16_t first, second;

	memcpy(input.literals, "Ab7", sizeof(input.literals));
	input.flags = (1u << FIRST_MATCH_BIT) | (1u << SECOND_MATCH_BIT);
	store_u16(input.header,
	    CHUNK_SIGNATURE | CHUNK_COMPRESSED |
		(sizeof(input.flags) + sizeof(input.literals) + sizeof(input.tokens) - 1));
	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		length = cases[i].position + TOKEN_MIN_LENGTH;
		first = ((SEED_BYTES - 1) << TOKEN_INITIAL_SHIFT) |
		    (cases[i].position - SEED_BYTES - TOKEN_MIN_LENGTH);
		second = (uint16_t)((cases[i].position - 1) << cases[i].shift);
		store_u16(input.tokens[0], first);
		store_u16(input.tokens[1], second);
		memset(output, 0, sizeof(output));
		assert(ntfs_lznt1_decode(&input, sizeof(input), output, length, &done) == NTFS_OK &&
		    done == length);
		for (j = 0; j < cases[i].position; j++) {
			assert(output[j] == input.literals[j % SEED_BYTES]);
		}
		assert(memcmp(output + cases[i].position, input.literals, sizeof(input.literals)) ==
		    0);
		assert(ntfs_lznt1_decode(&input, sizeof(input), output, length - 1, &done) ==
			NTFS_RANGE &&
		    done == 0);
		assert(ntfs_lznt1_decode(&input, sizeof(input), NULL, 0, &done) == NTFS_RANGE &&
		    done == 0);
	}
}

static void
chunk_boundaries(void)
{
	struct raw_chunk {
		uint8_t header[sizeof(uint16_t)], data[CHUNK_BYTES];
	} input[2];

	uint8_t output[sizeof(input[0].data) * 2];
	size_t size, done;

	memset(input, 'R', sizeof(input));
	store_u16(input[0].header, CHUNK_SIGNATURE | (sizeof(input[0].data) - 1));
	store_u16(input[1].header, CHUNK_SIGNATURE);
	size = sizeof(input[0]) + sizeof(input[1].header) + 1;
	assert(ntfs_lznt1_decode(input, size, output, sizeof(output), &done) == NTFS_OK &&
	    done == CHUNK_BYTES + 1);
	assert(memcmp(output, input[0].data, CHUNK_BYTES) == 0 && output[CHUNK_BYTES] == 'R');
	assert(
	    ntfs_lznt1_decode(input, size, output, CHUNK_BYTES, &done) == NTFS_RANGE && done == 0);
	assert(ntfs_lznt1_decode(input, sizeof(input[0]) - 1, output, sizeof(output), &done) ==
		NTFS_CORRUPT &&
	    done == 0);
	/* A short chunk is legal only at the end of the decoded sequence. */
	store_u16(input[0].header, CHUNK_SIGNATURE);
	store_u16(input[0].data + 1, CHUNK_SIGNATURE);
	size = sizeof(input[0].header) + 1 + sizeof(input[1].header) + 1;
	assert(ntfs_lznt1_decode(input, size, output, sizeof(output), &done) == NTFS_CORRUPT);
	assert(ntfs_lznt1_decode(
		   input, sizeof(input[0].header) + 1, output, sizeof(output), &done) == NTFS_OK &&
	    done == 1);
}

int
main(void)
{
	token_boundaries();
	chunk_boundaries();
	puts("PASS: LZNT1 token split boundaries, chunk framing and output capacity");
	return 0;
}
