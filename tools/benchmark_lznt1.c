/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_lznt1.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum {
	UNALIGNED = 3,
	CHUNK_BYTES = 4096,
	HEADER_BYTES = 2,
	GUARD_BYTES = 32,
	GUARD = 0xa5,
	SIGNATURE_MASK = 0x7000,
	SIGNATURE = 0x3000,
	COMPRESSED = 0x8000,
	WORD_HIGH_MULTIPLIER = 256,
	FLAG_BITS = 8,
	MIN_MATCH = 3
};

static uint64_t
now(clockid_t clock)
{
	struct timespec time;

	assert(clock_gettime(clock, &time) == 0);
	return (uint64_t)time.tv_sec * UINT64_C(1000000000) + (uint64_t)time.tv_nsec;
}

/* Independent wire inspection: original bytes, explicit position intervals and
 * division/remainder establish expected tokens without invoking our decoder. */
static void
inspect(const uint8_t *packed, size_t count, const uint8_t *original, size_t bytes)
{
	static const unsigned widths[] = {12, 11, 10, 9, 8, 7, 6, 5, 4};
	static const unsigned ends[] = {16, 32, 64, 128, 256, 512, 1024, 2048, 4096};
	size_t offset = 0, position = 0, end, base, body, index, length, distance;
	unsigned header, flags, bit, width, token;

	while (offset < count) {
		assert(count - offset >= HEADER_BYTES);
		header = packed[offset] + WORD_HIGH_MULTIPLIER * packed[offset + 1];
		offset += HEADER_BYTES;
		assert((header & SIGNATURE_MASK) == SIGNATURE);
		body = header % CHUNK_BYTES + 1;
		assert(body <= count - offset);
		end = offset + body;
		base = position;
		if ((header & COMPRESSED) == 0) {
			assert(body <= bytes - position);
			assert(memcmp(packed + offset, original + position, body) == 0);
			offset = end;
			position += body;
		} else {
			while (offset < end) {
				flags = packed[offset++];
				for (bit = 0; bit < FLAG_BITS && offset < end; bit++) {
					if ((flags & (1u << bit)) == 0) {
						assert(position < bytes &&
						    packed[offset] == original[position]);
						offset++;
						position++;
						continue;
					}
					assert(end - offset >= HEADER_BYTES && position > base);
					token = packed[offset] +
					    WORD_HIGH_MULTIPLIER * packed[offset + 1];
					offset += HEADER_BYTES;
					for (width = 0; position - base > ends[width]; width++) {
						assert(
						    width + 1 < sizeof(widths) / sizeof(*widths));
					}
					length = token % (1u << widths[width]) + MIN_MATCH;
					distance = token / (1u << widths[width]) + 1;
					assert(distance <= position - base &&
					    length <= bytes - position);
					assert(length <= CHUNK_BYTES - (position - base));
					for (index = 0; index < length; index++) {
						assert(original[position + index] ==
						    original[position - distance + index]);
					}
					position += length;
				}
			}
			assert(body < position - base);
		}
		assert(position - base <= CHUNK_BYTES);
		assert(offset == count || position - base == CHUNK_BYTES);
	}
	assert(position == bytes);
}

int
main(int argc, char **argv)
{
	FILE *file;
	long input_length;
	uint8_t *input, *workspace, *output;
	size_t bytes, bound, required, written, workspace_bytes, capacity, index, iterations;
	uint64_t wall_start, cpu_start, wall, cpu, checksum = 0;
	bool measure;

	assert(argc == 4);
	measure = strcmp(argv[1], "measure") == 0;
	assert(measure || strcmp(argv[1], "exact") == 0 || strcmp(argv[1], "bound") == 0);
	iterations = (size_t)strtoull(argv[3], NULL, 10);
	assert(iterations > 0);
	file = fopen(argv[2], "rb");
	assert(file && fseek(file, 0, SEEK_END) == 0);
	input_length = ftell(file);
	assert(input_length >= 0 && input_length <= NTFS_WRITE_LZNT1_MAX_BYTES);
	assert(fseek(file, 0, SEEK_SET) == 0);
	bytes = (size_t)input_length;
	input = malloc(bytes + UNALIGNED);
	assert(input && fread(input + UNALIGNED, 1, bytes, file) == bytes);
	assert(fclose(file) == 0);
	assert(ntfs_write_lznt1_bound(bytes, &bound) == NTFS_OK);
	workspace_bytes = ntfs_write_lznt1_workspace_size();
	workspace = malloc(workspace_bytes + UNALIGNED);
	output = malloc(bound + UNALIGNED + GUARD_BYTES);
	assert(workspace && output);
	memset(output, GUARD, bound + UNALIGNED + GUARD_BYTES);
	assert(ntfs_write_lznt1_measure(input + UNALIGNED, bytes, workspace + UNALIGNED,
		   workspace_bytes, &required) == NTFS_OK);
	capacity = strcmp(argv[1], "bound") == 0 ? bound : required;
	assert(ntfs_write_lznt1_encode(input + UNALIGNED, bytes, workspace + UNALIGNED,
		   workspace_bytes, output + UNALIGNED, capacity, &written) == NTFS_OK &&
	    written == required);
	inspect(output + UNALIGNED, written, input + UNALIGNED, bytes);
	wall_start = now(CLOCK_MONOTONIC);
	cpu_start = now(CLOCK_PROCESS_CPUTIME_ID);
	for (index = 0; index < iterations; index++) {
		if (measure) {
			assert(ntfs_write_lznt1_measure(input + UNALIGNED, bytes,
				   workspace + UNALIGNED, workspace_bytes, &written) == NTFS_OK &&
			    written == required);
		} else {
			assert(ntfs_write_lznt1_encode(input + UNALIGNED, bytes,
				   workspace + UNALIGNED, workspace_bytes, output + UNALIGNED,
				   capacity, &written) == NTFS_OK &&
			    written == required);
		}
	}
	cpu = now(CLOCK_PROCESS_CPUTIME_ID) - cpu_start;
	wall = now(CLOCK_MONOTONIC) - wall_start;
	inspect(output + UNALIGNED, written, input + UNALIGNED, bytes);
	for (index = 0; index < UNALIGNED; index++) {
		assert(output[index] == GUARD);
	}
	for (index = UNALIGNED + written; index < bound + UNALIGNED + GUARD_BYTES; index++) {
		assert(output[index] == GUARD);
	}
	for (index = 0; index < written; index++) {
		checksum = checksum * 31u + output[UNALIGNED + index];
	}
	printf(
	    "{\"bytes\":%zu,\"encodedBytes\":%zu,\"capacity\":%zu,\"workspaceBytes\":%zu,"
	    "\"coreAllocations\":0,\"coreIoCalls\":0,\"iterations\":%zu,\"ns\":%llu,\"cpuNs\":%llu,"
	    "\"checksum\":\"%016llx\"}\n",
	    bytes, written, capacity, workspace_bytes, iterations, (unsigned long long)wall,
	    (unsigned long long)cpu, (unsigned long long)checksum);
	free(output);
	free(workspace);
	free(input);
	return 0;
}
