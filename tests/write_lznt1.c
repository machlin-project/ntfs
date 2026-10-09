/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_lznt1.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_CHUNK_BYTES = 4096,
	TEST_HEADER_BYTES = 2,
	TEST_GUARD_BYTES = 32,
	TEST_SENTINEL = 0xa5,
	TEST_LENGTH_MASK = 0x0fff,
	TEST_SIGNATURE_MASK = 0x7000,
	TEST_SIGNATURE = 0x3000,
	TEST_COMPRESSED = 0x8000,
	TEST_MIN_MATCH = 3,
	TEST_FLAG_BITS = 8,
	TEST_ALIGNMENTS = 16,
	TEST_PATTERN_COUNT = 7
};

struct wire_stats {
	size_t raw_chunks, compressed_chunks, matches, overlaps, maximum_distance;
	unsigned widths;
	bool requested_position;
};

/* Original hand-authored packets. None uses private wire layouts or stores. */
static const uint8_t literal_golden[] = {0x02, 0x30, 'C', 'A', 'T'};
static const uint8_t run_golden[] = {0x03, 0xb0, 0x02, 'A', 0xfc, 0x0f};
static const uint8_t pair_golden[] = {0x04, 0xb0, 0x04, 'A', 'B', 0x05, 0x10};
static const uint8_t triple_golden[] = {0x05, 0xb0, 0x08, 'A', 'B', 'C', 0x06, 0x20};
static const uint8_t tie_golden[] = {0x03, 0x30, 'A', 'A', 'A', 'A'};

static void
empty_admission(void)
{
	union {
		size_t alignment;
		uint8_t bytes[64];
	} storage;
	uint8_t original[sizeof(storage)];
	size_t written = SIZE_MAX;
	void *wrapped = (void *)(uintptr_t)(UINTPTR_MAX - sizeof(size_t) + 1);

	memset(&storage, TEST_SENTINEL, sizeof(storage));
	memcpy(original, &storage, sizeof(storage));
	assert(ntfs_write_lznt1_encode(NULL, 0, NULL, 1, NULL, 0, &written) == NTFS_INVALID);
	assert(ntfs_write_lznt1_encode(NULL, 0, NULL, 0, NULL, 1, &written) == NTFS_INVALID);
	assert(ntfs_write_lznt1_encode(NULL, 0, NULL, 0, NULL, 0, NULL) == NTFS_INVALID);
	assert(ntfs_write_lznt1_encode(NULL, 0, wrapped, sizeof(size_t), NULL, 0, &written) == NTFS_INVALID);
	assert(ntfs_write_lznt1_encode(NULL, 0, NULL, 0, wrapped, sizeof(size_t), &written) == NTFS_INVALID);
	assert(ntfs_write_lznt1_encode(NULL, 0, NULL, 0, NULL, 0, wrapped) == NTFS_INVALID);
	assert(ntfs_write_lznt1_encode(NULL, 0, storage.bytes, sizeof(storage), storage.bytes,
	    1, &written) == NTFS_INVALID);
	assert(ntfs_write_lznt1_encode(NULL, 0, storage.bytes, sizeof(storage), NULL,
	    0, &storage.alignment) == NTFS_INVALID);
	assert(ntfs_write_lznt1_encode(NULL, 0, NULL, 0, storage.bytes,
	    sizeof(storage), &storage.alignment) == NTFS_INVALID);
	assert(written == SIZE_MAX && memcmp(original, &storage, sizeof(storage)) == 0);
	/* Empty input still admits short nonzero workspace and disjoint output.
	 * Neither declared buffer may be touched, even though capacity is unused. */
	assert(ntfs_write_lznt1_encode(NULL, 0, storage.bytes, 1, storage.bytes + 1,
	    sizeof(storage) - 1, &written) == NTFS_OK && written == 0);
	assert(memcmp(original, &storage, sizeof(storage)) == 0);
}

static void
sentinel(const uint8_t *bytes, size_t count)
{
	size_t index;

	for (index = 0; index < count; index++) {
		assert(bytes[index] == TEST_SENTINEL);
	}
}

static uint16_t
wire_word(const uint8_t *bytes)
{
	return (uint16_t)((unsigned)bytes[0] + (unsigned)bytes[1] * 256u);
}

/* This independent wire walk validates against original plaintext directly.
 * Widths use an explicit range table, not the core's shifting algorithm; every
 * matched byte must equal the earlier original byte it references. */
static struct wire_stats
inspect(const uint8_t *packed, size_t packed_bytes, const uint8_t *original, size_t original_bytes,
    size_t requested_position)
{
	static const size_t highest_position[] = {16, 32, 64, 128, 256, 512, 1024, 2048, 4096};
	static const unsigned length_bits[] = {12, 11, 10, 9, 8, 7, 6, 5, 4};
	struct wire_stats stats = {0};
	size_t cursor = 0, plain = 0, base, end, body, width, length, distance, index;
	uint16_t header, token;
	unsigned flags, bit, bits;

	while (cursor < packed_bytes) {
		assert(packed_bytes - cursor >= TEST_HEADER_BYTES);
		header = wire_word(packed + cursor);
		cursor += TEST_HEADER_BYTES;
		assert((header & TEST_SIGNATURE_MASK) == TEST_SIGNATURE);
		body = (header & TEST_LENGTH_MASK) + 1u;
		assert(body <= TEST_CHUNK_BYTES && body <= packed_bytes - cursor);
		end = cursor + body;
		base = plain;
		if ((header & TEST_COMPRESSED) == 0) {
			assert(body <= original_bytes - plain);
			assert(memcmp(packed + cursor, original + plain, body) == 0);
			plain += body;
			cursor = end;
			stats.raw_chunks++;
		} else {
			stats.compressed_chunks++;
			while (cursor < end) {
				flags = packed[cursor++];
				for (bit = 0; bit < TEST_FLAG_BITS && cursor < end; bit++) {
					if ((flags & (1u << bit)) == 0) {
						assert(plain < original_bytes);
						assert(packed[cursor++] == original[plain++]);
					} else {
						assert(end - cursor >= TEST_HEADER_BYTES &&
						    plain > base);
						token = wire_word(packed + cursor);
						cursor += TEST_HEADER_BYTES;
						for (width = 0;
						    plain - base > highest_position[width];
						    width++) {
							assert(width + 1 < sizeof(length_bits) /
								sizeof(*length_bits));
						}
						bits = length_bits[width];
						length = token % (1u << bits) + TEST_MIN_MATCH;
						distance = token / (1u << bits) + 1u;
						assert(distance <= plain - base &&
						    length <= original_bytes - plain);
						assert(length <= TEST_CHUNK_BYTES - (plain - base));
						stats.widths |= 1u << width;
						stats.matches++;
						stats.overlaps += length > distance;
						if (distance > stats.maximum_distance) {
							stats.maximum_distance = distance;
						}
						if (plain - base == requested_position) {
							stats.requested_position = true;
						}
						for (index = 0; index < length; index++) {
							assert(original[plain + index] ==
							    original[plain - distance + index]);
						}
						plain += length;
					}
				}
			}
			assert(body < plain - base);
		}
		assert(plain - base <= TEST_CHUNK_BYTES);
		assert(cursor == packed_bytes || plain - base == TEST_CHUNK_BYTES);
	}
	assert(plain == original_bytes);
	return stats;
}

static struct wire_stats
check(const uint8_t *input, size_t bytes, const uint8_t *golden, size_t golden_bytes,
    size_t alignment, size_t requested_position, const char *corpus, size_t case_id)
{
	struct wire_stats stats;
	uint8_t *source, *workspace, *output, *decoded, *again;
	size_t workspace_bytes, bound = SIZE_MAX, required = SIZE_MAX, written = SIZE_MAX,
				done = SIZE_MAX, capacity, original_written;
	char path[1024];
	FILE *file;
	int count;

	assert(ntfs_write_lznt1_bound(bytes, &bound) == NTFS_OK);
	assert(bound ==
	    bytes + ((bytes + TEST_CHUNK_BYTES - 1) / TEST_CHUNK_BYTES) * TEST_HEADER_BYTES);
	workspace_bytes = ntfs_write_lznt1_workspace_size();
	source = malloc(alignment + bytes + TEST_GUARD_BYTES);
	workspace = malloc(alignment + workspace_bytes + TEST_GUARD_BYTES);
	output = malloc(alignment + bound + TEST_GUARD_BYTES);
	decoded = malloc(alignment + bytes + TEST_GUARD_BYTES);
	again = malloc(bound + TEST_GUARD_BYTES);
	assert(source && workspace && output && decoded && again);
	memset(source, TEST_SENTINEL, alignment + bytes + TEST_GUARD_BYTES);
	memcpy(source + alignment, input, bytes);
	memset(workspace, TEST_SENTINEL, alignment + workspace_bytes + TEST_GUARD_BYTES);
	assert(ntfs_write_lznt1_measure(source + alignment, bytes, workspace + alignment,
		   workspace_bytes, &required) == NTFS_OK);
	assert(required <= bound);
	/* Every short capacity for the small goldens, plus zero and one-short for
	 * larger/multi-chunk inputs. No partial first chunk may escape on error. */
	for (capacity = 0; capacity < required;
	    capacity = required < 32 ? capacity + 1 : (capacity == 0 ? required - 1 : required)) {
		memset(output, TEST_SENTINEL, alignment + bound + TEST_GUARD_BYTES);
		original_written = written;
		assert(ntfs_write_lznt1_encode(source + alignment, bytes, workspace + alignment,
			   workspace_bytes, output + alignment, capacity, &written) == NTFS_RANGE);
		assert(written == original_written);
		sentinel(output, alignment + bound + TEST_GUARD_BYTES);
	}
	memset(output, TEST_SENTINEL, alignment + bound + TEST_GUARD_BYTES);
	assert(ntfs_write_lznt1_encode(source + alignment, bytes, workspace + alignment,
		   workspace_bytes, output + alignment, required, &written) == NTFS_OK);
	assert(written == required);
	if (golden != NULL) {
		assert(written == golden_bytes && memcmp(output + alignment, golden, written) == 0);
	}
	sentinel(output, alignment);
	sentinel(output + alignment + written, bound + TEST_GUARD_BYTES - written);
	sentinel(workspace, alignment);
	sentinel(workspace + alignment + workspace_bytes, TEST_GUARD_BYTES);
	assert(memcmp(source + alignment, input, bytes) == 0);
	sentinel(source, alignment);
	sentinel(source + alignment + bytes, TEST_GUARD_BYTES);
	stats = inspect(output + alignment, written, input, bytes, requested_position);
	memset(decoded, TEST_SENTINEL, alignment + bytes + TEST_GUARD_BYTES);
	assert(ntfs_lznt1_decode(output + alignment, written, decoded + alignment, bytes, &done) ==
		NTFS_OK &&
	    done == bytes);
	assert(memcmp(decoded + alignment, input, bytes) == 0);
	sentinel(decoded, alignment);
	sentinel(decoded + alignment + bytes, TEST_GUARD_BYTES);
	memset(workspace, 0x5a, alignment + workspace_bytes + TEST_GUARD_BYTES);
	assert(ntfs_write_lznt1_encode(source + alignment, bytes, workspace + alignment,
		   workspace_bytes, again, bound, &done) == NTFS_OK &&
	    done == written);
	assert(memcmp(again, output + alignment, written) == 0);
	if (corpus != NULL && bytes != 0) {
		count = snprintf(path, sizeof(path), "%s/case-%04zu.data", corpus, case_id);
		assert(count > 0 && (size_t)count < sizeof(path));
		file = fopen(path, "wbx");
		assert(file && fwrite(input, 1, bytes, file) == bytes && fclose(file) == 0);
		count = snprintf(path, sizeof(path), "%s/case-%04zu.packed", corpus, case_id);
		assert(count > 0 && (size_t)count < sizeof(path));
		file = fopen(path, "wbx");
		assert(file && fwrite(output + alignment, 1, written, file) == written &&
		    fclose(file) == 0);
	}
	free(again);
	free(decoded);
	free(output);
	free(workspace);
	free(source);
	return stats;
}

static void
pattern(uint8_t *bytes, size_t count, unsigned kind)
{
	uint32_t state = UINT32_C(0x4e544653);
	size_t index;
	uint8_t random;

	for (index = 0; index < count; index++) {
		state ^= state << 13;
		state ^= state >> 17;
		state ^= state << 5;
		random = (uint8_t)state;
		switch (kind) {
		case 0:
			bytes[index] = 0;
			break;
		case 1:
			bytes[index] = (uint8_t)index;
			break;
		case 2:
			bytes[index] = (uint8_t)(index % 17);
			break;
		case 3:
			bytes[index] = random;
			break;
		case 4:
			bytes[index] = index % 257 < 193 ? (uint8_t)(index % 7) : random;
			break;
		case 5:
			bytes[index] = (index / TEST_CHUNK_BYTES) % 2 ? random : 'Q';
			break;
		default:
			bytes[index] = (uint8_t)((index / 3) % 256);
			break;
		}
	}
}

static void
exact_allocation_ends(void)
{
	static const size_t lengths[] = {1, 2, 3, 8, 17, 257, 4095, 4096, 4097, 65536};
	uint8_t *input, *output, *workspace, *decoded;
	size_t index, alignment, required, written, workspace_bytes;

	workspace_bytes = ntfs_write_lznt1_workspace_size();
	for (index = 0; index < sizeof(lengths) / sizeof(*lengths); index++) {
		for (alignment = 0; alignment < TEST_ALIGNMENTS; alignment++) {
			input = malloc(alignment + lengths[index]);
			workspace = malloc(alignment + workspace_bytes);
			decoded = malloc(alignment + lengths[index]);
			assert(input && workspace && decoded);
			pattern(input + alignment, lengths[index],
			    (unsigned)(index % TEST_PATTERN_COUNT));
			assert(ntfs_write_lznt1_measure(input + alignment, lengths[index],
				   workspace + alignment, workspace_bytes, &required) == NTFS_OK);
			output = malloc(alignment + required);
			assert(output);
			assert(ntfs_write_lznt1_encode(input + alignment, lengths[index],
				   workspace + alignment, workspace_bytes, output + alignment,
				   required, &written) == NTFS_OK &&
			    written == required);
			assert(ntfs_lznt1_decode(output + alignment, written, decoded + alignment,
				   lengths[index], &written) == NTFS_OK &&
			    written == lengths[index]);
			assert(memcmp(input + alignment, decoded + alignment, written) == 0);
			free(output);
			free(decoded);
			free(workspace);
			free(input);
		}
	}
}

static void
admission(void)
{
	uint8_t input[64], output[128], *workspace, *shared, *bad = (void *)(UINTPTR_MAX - 7);
	size_t workspace_bytes, written = SIZE_MAX, bound = SIZE_MAX, capacity, saved;

	workspace_bytes = ntfs_write_lznt1_workspace_size();
	workspace = malloc(workspace_bytes + TEST_GUARD_BYTES);
	shared = malloc(workspace_bytes + sizeof(size_t) + sizeof(output));
	assert(workspace && shared);
	memset(input, 'A', sizeof(input));
	memset(output, TEST_SENTINEL, sizeof(output));
	memset(workspace, TEST_SENTINEL, workspace_bytes + TEST_GUARD_BYTES);
	assert(ntfs_write_lznt1_bound(NTFS_WRITE_LZNT1_MAX_BYTES + 1u, &bound) == NTFS_RANGE);
	assert(ntfs_write_lznt1_bound(SIZE_MAX, &bound) == NTFS_RANGE && bound == SIZE_MAX);
	assert(ntfs_write_lznt1_bound(1, NULL) == NTFS_INVALID);
	assert(ntfs_write_lznt1_measure(NULL, 0, NULL, 0, &written) == NTFS_OK && written == 0);
	assert(ntfs_write_lznt1_encode(NULL, 0, NULL, 0, NULL, 0, &written) == NTFS_OK &&
	    written == 0);
	written = SIZE_MAX;
	for (capacity = 0; capacity < workspace_bytes; capacity++) {
		assert(ntfs_write_lznt1_encode(input, sizeof(input), workspace, capacity, output,
			   sizeof(output), &written) == NTFS_RANGE);
	}
	sentinel(workspace, workspace_bytes + TEST_GUARD_BYTES);
	assert(ntfs_write_lznt1_encode(NULL, 1, workspace, workspace_bytes, output, sizeof(output),
		   &written) == NTFS_INVALID);
	assert(ntfs_write_lznt1_encode(input, sizeof(input), NULL, workspace_bytes, output,
		   sizeof(output), &written) == NTFS_INVALID);
	assert(ntfs_write_lznt1_encode(input, sizeof(input), workspace, workspace_bytes, NULL,
		   sizeof(output), &written) == NTFS_INVALID);
	assert(ntfs_write_lznt1_encode(input, sizeof(input), workspace, workspace_bytes, output,
		   sizeof(output), NULL) == NTFS_INVALID);
	assert(ntfs_write_lznt1_encode(bad, 16, workspace, workspace_bytes, output, sizeof(output),
		   &written) == NTFS_INVALID);
	assert(ntfs_write_lznt1_encode(input, sizeof(input), bad, workspace_bytes, output,
		   sizeof(output), &written) == NTFS_INVALID);
	assert(ntfs_write_lznt1_encode(input, sizeof(input), workspace, workspace_bytes, bad, 16,
		   &written) == NTFS_INVALID);
	assert(ntfs_write_lznt1_encode(input, NTFS_WRITE_LZNT1_MAX_BYTES + 1u, workspace,
		   workspace_bytes, output, sizeof(output), &written) == NTFS_RANGE);
	assert(ntfs_write_lznt1_encode(input, sizeof(input), workspace, workspace_bytes, input,
		   sizeof(input), &written) == NTFS_INVALID);
	assert(ntfs_write_lznt1_encode(input, sizeof(input), input, workspace_bytes, output,
		   sizeof(output), &written) == NTFS_INVALID);
	assert(ntfs_write_lznt1_encode(input, sizeof(input), workspace, workspace_bytes,
		   workspace + workspace_bytes - 1, sizeof(output), &written) == NTFS_INVALID);
	assert(ntfs_write_lznt1_measure(input, sizeof(input), workspace, workspace_bytes,
		   (size_t *)workspace) == NTFS_INVALID);
	assert(ntfs_write_lznt1_measure(input, sizeof(input), workspace, workspace_bytes,
		   (size_t *)input) == NTFS_INVALID);
	assert(ntfs_write_lznt1_encode(input, sizeof(input), workspace, workspace_bytes, &written,
		   sizeof(written), &written) == NTFS_INVALID);
	assert(written == SIZE_MAX);
	sentinel(output, sizeof(output));
	sentinel(workspace, workspace_bytes + TEST_GUARD_BYTES);
	/* Touching endpoints are disjoint; the full declared capacity matters,
	 * including unused output tail that would otherwise alias input. */
	memset(shared, 'A', workspace_bytes + sizeof(size_t) + sizeof(output));
	assert(ntfs_write_lznt1_encode(shared + workspace_bytes, sizeof(size_t), shared,
		   workspace_bytes, shared + workspace_bytes + sizeof(size_t), sizeof(output),
		   &written) == NTFS_OK);
	saved = written;
	assert(ntfs_write_lznt1_encode(input, sizeof(input), workspace, workspace_bytes, input,
		   sizeof(input) + sizeof(output), &written) == NTFS_INVALID);
	assert(written == saved);
	free(shared);
	free(workspace);
}

static void
malformed_goldens(void)
{
	static const uint8_t packets[][8] = {
	    {0x03, 0xb0, 0x02, 'A', 0xfd, 0x0f}, /* Expands beyond the chunk. */
	    {0x02, 0xb0, 0x01, 0x00, 0x00},	 /* Reference before any literal. */
	    {0x02, 0xb0, 0x02, 'A', 0x00},	 /* Truncated match word. */
	    {0x00, 0x20, 'A'},			 /* Incorrect signature. */
	    {0x00, 0x30, 'A', 0x00, 0x30, 'B'}	 /* Short interior chunk. */
	};
	static const size_t lengths[] = {6, 5, 5, 3, 6};
	uint8_t *output;
	size_t index, written;

	output = malloc(TEST_CHUNK_BYTES + TEST_GUARD_BYTES);
	assert(output);
	for (index = 0; index < sizeof(lengths) / sizeof(*lengths); index++) {
		memset(output, TEST_SENTINEL, TEST_CHUNK_BYTES + TEST_GUARD_BYTES);
		written = SIZE_MAX;
		assert(ntfs_lznt1_decode(packets[index], lengths[index], output, TEST_CHUNK_BYTES,
			   &written) == NTFS_CORRUPT &&
		    written == 0);
		sentinel(output + TEST_CHUNK_BYTES, TEST_GUARD_BYTES);
	}
	written = SIZE_MAX;
	assert(ntfs_lznt1_decode(run_golden, sizeof(run_golden), output, TEST_CHUNK_BYTES - 1,
		   &written) == NTFS_RANGE &&
	    written == 0);
	free(output);
}

int
main(int argc, char **argv)
{
	static const size_t lengths[] = {1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 255, 256, 257,
	    2048, 2049, 4095, 4096, 4097, 8191, 8192, 8193, 65536, NTFS_WRITE_LZNT1_MAX_BYTES};
	static const size_t transitions[] = {
	    16, 17, 32, 33, 64, 65, 128, 129, 256, 257, 512, 513, 1024, 1025, 2048, 2049};
	struct wire_stats stats;
	uint8_t *input;
	size_t index, kind, alignment, count = 0;
	unsigned widths = 0;
	const char *corpus = argc == 2 ? argv[1] : NULL;

	assert(argc <= 2);
	input = malloc(NTFS_WRITE_LZNT1_MAX_BYTES);
	assert(input);
	admission();
	empty_admission();
	malformed_goldens();
	exact_allocation_ends();
	for (alignment = 0; alignment < TEST_ALIGNMENTS; alignment++) {
		(void)check((const uint8_t *)"CAT", 3, literal_golden, sizeof(literal_golden),
		    alignment, SIZE_MAX, corpus, count++);
		memset(input, 'A', TEST_CHUNK_BYTES);
		stats = check(input, TEST_CHUNK_BYTES, run_golden, sizeof(run_golden), alignment,
		    SIZE_MAX, corpus, count++);
		assert(stats.compressed_chunks == 1 && stats.overlaps == 1);
		(void)check((const uint8_t *)"ABABABABAB", 10, pair_golden, sizeof(pair_golden),
		    alignment, SIZE_MAX, corpus, count++);
		(void)check((const uint8_t *)"ABCABCABCABC", 12, triple_golden,
		    sizeof(triple_golden), alignment, SIZE_MAX, corpus, count++);
		(void)check((const uint8_t *)"AAAA", 4, tie_golden, sizeof(tie_golden), alignment,
		    SIZE_MAX, corpus, count++);
	}
	for (kind = 0; kind < TEST_PATTERN_COUNT; kind++) {
		pattern(input, NTFS_WRITE_LZNT1_MAX_BYTES, (unsigned)kind);
		for (index = 0; index < sizeof(lengths) / sizeof(*lengths); index++) {
			stats = check(input, lengths[index], NULL, 0, index % TEST_ALIGNMENTS,
			    SIZE_MAX, corpus, count++);
			widths |= stats.widths;
			if (kind == 3 && lengths[index] >= TEST_CHUNK_BYTES) {
				assert(stats.raw_chunks != 0);
			}
			if (kind == 5 && lengths[index] >= TEST_CHUNK_BYTES * 2) {
				assert(stats.raw_chunks != 0 && stats.compressed_chunks != 0);
			}
		}
	}
	for (index = 0; index < sizeof(transitions) / sizeof(*transitions); index++) {
		pattern(input, TEST_CHUNK_BYTES, 3);
		memset(
		    input + transitions[index] - 1, 'A', TEST_CHUNK_BYTES - transitions[index] + 1);
		stats = check(input, TEST_CHUNK_BYTES, NULL, 0, index % TEST_ALIGNMENTS,
		    transitions[index], corpus, count++);
		assert(stats.requested_position);
		widths |= stats.widths;
	}
	/* Far words retain an early unique triple across long compressed runs.
	 * The final case reaches the furthest displacement that leaves three bytes. */
	for (index = 0; index < sizeof(transitions) / sizeof(*transitions); index++) {
		memset(input, 0xef, TEST_CHUNK_BYTES);
		memcpy(input, "ABC", TEST_MIN_MATCH);
		memcpy(input + transitions[index], "ABC", TEST_MIN_MATCH);
		stats = check(input, TEST_CHUNK_BYTES, NULL, 0, index % TEST_ALIGNMENTS,
		    transitions[index], corpus, count++);
		assert(stats.maximum_distance >= transitions[index]);
	}
	memset(input, 0xef, TEST_CHUNK_BYTES);
	memcpy(input, "ABC", TEST_MIN_MATCH);
	memcpy(input + TEST_CHUNK_BYTES - TEST_MIN_MATCH, "ABC", TEST_MIN_MATCH);
	stats = check(input, TEST_CHUNK_BYTES, NULL, 0, 0, SIZE_MAX, corpus, count++);
	assert(stats.maximum_distance == TEST_CHUNK_BYTES - TEST_MIN_MATCH);
	assert(widths == 0x1ff);
	free(input);
	printf("PASS: %zu original LZNT1 encodes, literal goldens, nine widths, guards and "
	       "admission\n",
	    count);
	return 0;
}
