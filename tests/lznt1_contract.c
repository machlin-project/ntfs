/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/ntfs.h>
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { PATH_BYTES = 1024, NAME_BYTES = 128, CODEC_BYTES = 16, GUARD = 0xa5,
	ALIGNMENTS = 32, LITERAL_GROUP = 8, CHUNK_BYTES = 4096, HEADER_BYTES = 2,
	HEADER_SIGNATURE = 0x3000, HEADER_COMPRESSED = 0x8000 };

#ifdef NTFS_LZNT1_REFERENCE
enum ntfs_result reference_lznt1_decode(const void *, size_t, void *, size_t, size_t *);
#endif

static uint8_t *
load(const char *directory, const char *name, const char *suffix, size_t *size)
{
	char path[PATH_BYTES];
	FILE *file;
	long length;
	uint8_t *bytes;
	int result;

	result = snprintf(path, sizeof(path), "%s/%s%s", directory, name, suffix);
	assert(result > 0 && (size_t)result < sizeof(path));
	file = fopen(path, "rb");
	assert(file && fseek(file, 0, SEEK_END) == 0);
	length = ftell(file);
	assert(length > 0 && fseek(file, 0, SEEK_SET) == 0);
	*size = (size_t)length;
	bytes = malloc(*size);
	assert(bytes && fread(bytes, 1, *size, file) == *size);
	assert(fclose(file) == 0);
	return bytes;
}

static void
check(const uint8_t *packed, size_t bytes, size_t capacity, size_t alignment,
    const uint8_t *expected, size_t expected_bytes, bool require_success)
{
	uint8_t *input, *output;
	size_t written = SIZE_MAX, index;
	enum ntfs_result result;
#ifdef NTFS_LZNT1_REFERENCE
	uint8_t *reference_output;
	size_t reference_written = SIZE_MAX;
	enum ntfs_result reference_result;
#endif

	/* Allocation ends coincide with declared ends, including zero capacity. */
	input = malloc(bytes + alignment + 1);
	output = malloc(capacity + alignment + 1);
	assert(input && output);
	memset(input, GUARD, bytes + alignment + 1);
	memset(output, GUARD, capacity + alignment + 1);
	memcpy(input + alignment + 1, packed, bytes);
	result = ntfs_lznt1_decode(input + alignment + 1, bytes, output + alignment + 1,
	    capacity, &written);
	assert(result == NTFS_OK || result == NTFS_CORRUPT || result == NTFS_RANGE);
	assert(result == NTFS_OK ? written <= capacity : written == 0);
	if (require_success) {
		assert(result == NTFS_OK && written == expected_bytes);
		assert(memcmp(output + alignment + 1, expected, expected_bytes) == 0);
		for (index = written; index < capacity; index++) {
			assert(output[alignment + 1 + index] == GUARD);
		}
	}
#ifdef NTFS_LZNT1_REFERENCE
	reference_output = malloc(capacity + alignment + 1);
	assert(reference_output);
	memset(reference_output, GUARD, capacity + alignment + 1);
	reference_result = reference_lznt1_decode(input + alignment + 1, bytes,
	    reference_output + alignment + 1, capacity, &reference_written);
	assert(result == reference_result && written == reference_written);
	assert(memcmp(output, reference_output, capacity + alignment + 1) == 0);
	free(reference_output);
#endif
	for (index = 0; index <= alignment; index++) {
		assert(input[index] == GUARD && output[index] == GUARD);
	}
	assert(memcmp(input + alignment + 1, packed, bytes) == 0);
	free(output);
	free(input);
}

#ifdef NTFS_LZNT1_REFERENCE
static void
overlap_contract(const uint8_t *packed, size_t bytes, size_t capacity)
{
	uint8_t *shared, *reference_shared;
	size_t total, origin = ALIGNMENTS * 2, written, reference_written, shift;
	enum ntfs_result result, reference_result;

	total = bytes + capacity + ALIGNMENTS * 4;
	shared = malloc(total);
	reference_shared = malloc(total);
	assert(shared && reference_shared);
	for (shift = 0; shift <= ALIGNMENTS * 2; shift++) {
		memset(shared, GUARD, total);
		memcpy(shared + origin, packed, bytes);
		memcpy(reference_shared, shared, total);
		written = SIZE_MAX;
		reference_written = SIZE_MAX;
		result = ntfs_lznt1_decode(shared + origin, bytes,
		    shared + origin - ALIGNMENTS + shift, capacity, &written);
		reference_result = reference_lznt1_decode(reference_shared + origin, bytes,
		    reference_shared + origin - ALIGNMENTS + shift, capacity, &reference_written);
		assert(result == reference_result && written == reference_written);
		assert(memcmp(shared, reference_shared, total) == 0);
	}
	free(reference_shared);
	free(shared);
}
#endif

static void
literal_contract(void)
{
	uint8_t packed[2 + (LITERAL_GROUP + 1) * 3], expected[LITERAL_GROUP * 3], output[32];
	size_t bytes, count, index, offset, capacity, written, copied;
	unsigned header;
	enum ntfs_result result;

	for (count = 1; count <= sizeof(expected); count++) {
		for (index = 0; index < count; index++) {
			expected[index] = (uint8_t)('A' + index);
		}
		offset = HEADER_BYTES;
		for (index = 0; index < count; index++) {
			if (index % LITERAL_GROUP == 0) {
				packed[offset++] = 0;
			}
			packed[offset++] = expected[index];
		}
		bytes = offset;
		header = HEADER_SIGNATURE | HEADER_COMPRESSED | (unsigned)(bytes - HEADER_BYTES - 1);
		packed[0] = (uint8_t)header;
		packed[1] = (uint8_t)(header >> CHAR_BIT);
		for (capacity = 0; capacity <= count + 1; capacity++) {
			memset(output, GUARD, sizeof(output));
			written = SIZE_MAX;
			result = ntfs_lznt1_decode(packed, bytes, output, capacity, &written);
			assert(result == (capacity < count ? NTFS_RANGE : NTFS_OK));
			assert(written == (capacity < count ? 0 : count));
			copied = capacity < count ? capacity : count;
			assert(memcmp(output, expected, copied) == 0);
			for (index = copied; index < sizeof(output); index++) {
				assert(output[index] == GUARD);
			}
		}
		/* Ignored flag bits after the final element cannot introduce a match. */
		if (count % LITERAL_GROUP != 0) {
			packed[HEADER_BYTES + (count / LITERAL_GROUP) * (LITERAL_GROUP + 1)] =
			    (uint8_t)(UINT8_MAX << (count % LITERAL_GROUP));
			check(packed, bytes, count, count % ALIGNMENTS, expected, count, true);
		}
	}
}

static void
flag_combinations(void)
{
	enum { PREFIX_BYTES = 8, TOKENS = 8, MATCH_BYTES = 3, TAIL_BYTES = 8,
		PACKED_BYTES = HEADER_BYTES + 1 + PREFIX_BYTES + 1 + TOKENS * 2 + 1 + TAIL_BYTES,
		PLAIN_BYTES = PREFIX_BYTES + TOKENS * MATCH_BYTES + TAIL_BYTES };
	uint8_t packed[PACKED_BYTES], expected[PLAIN_BYTES];
	size_t offset, plain, index, capacity;
	unsigned flags, header;

	for (flags = 0; flags <= UINT8_MAX; flags++) {
		offset = HEADER_BYTES;
		plain = 0;
		packed[offset++] = 0;
		for (index = 0; index < PREFIX_BYTES; index++) {
			packed[offset++] = (uint8_t)('a' + index);
			expected[plain++] = (uint8_t)('a' + index);
		}
		packed[offset++] = (uint8_t)flags;
		for (index = 0; index < TOKENS; index++) {
			if ((flags & (1u << index)) != 0) {
				packed[offset++] = 0;
				packed[offset++] = 0;
				memset(expected + plain, expected[plain - 1], MATCH_BYTES);
				plain += MATCH_BYTES;
			} else {
				packed[offset++] = (uint8_t)('A' + index);
				expected[plain++] = (uint8_t)('A' + index);
			}
		}
		packed[offset++] = 0;
		for (index = 0; index < TAIL_BYTES; index++) {
			packed[offset++] = (uint8_t)('0' + index);
			expected[plain++] = (uint8_t)('0' + index);
		}
		header = HEADER_SIGNATURE | HEADER_COMPRESSED | (unsigned)(offset - HEADER_BYTES - 1);
		packed[0] = (uint8_t)header;
		packed[1] = (uint8_t)(header >> CHAR_BIT);
		for (capacity = 0; capacity <= plain + 1; capacity++) {
			check(packed, offset, capacity, flags % ALIGNMENTS,
			    expected, plain, capacity >= plain);
		}
	}
}

static void
chunk_end_publication(void)
{
	enum { MATCH_BYTES = 4085, PREFIX_BYTES = MATCH_BYTES + 1, FIRST_LITERALS = 6,
		FINAL_LITERALS = 8, BODY_BYTES = 1 + 1 + 2 + FIRST_LITERALS + 1 + FINAL_LITERALS };
	uint8_t packed[HEADER_BYTES + BODY_BYTES], *output, *expected;
	size_t index, capacity, written, copied;
	unsigned header, token;
	enum ntfs_result result;

	header = HEADER_SIGNATURE | HEADER_COMPRESSED | (BODY_BYTES - 1);
	packed[0] = (uint8_t)header;
	packed[1] = (uint8_t)(header >> CHAR_BIT);
	packed[HEADER_BYTES] = 2;
	packed[HEADER_BYTES + 1] = 'A';
	token = MATCH_BYTES - 3;
	packed[HEADER_BYTES + 2] = (uint8_t)token;
	packed[HEADER_BYTES + 3] = (uint8_t)(token >> CHAR_BIT);
	for (index = 0; index < FIRST_LITERALS; index++) {
		packed[HEADER_BYTES + 4 + index] = (uint8_t)('B' + index);
	}
	packed[HEADER_BYTES + 4 + FIRST_LITERALS] = 0;
	for (index = 0; index < FINAL_LITERALS; index++) {
		packed[HEADER_BYTES + 5 + FIRST_LITERALS + index] = (uint8_t)('H' + index);
	}
	output = malloc(CHUNK_BYTES + 2);
	expected = malloc(CHUNK_BYTES);
	assert(output && expected);
	memset(expected, 'A', PREFIX_BYTES);
	for (index = PREFIX_BYTES; index < CHUNK_BYTES; index++) {
		expected[index] = (uint8_t)('B' + index - PREFIX_BYTES);
	}
	for (capacity = PREFIX_BYTES - 2; capacity <= CHUNK_BYTES + 1; capacity++) {
		memset(output, GUARD, CHUNK_BYTES + 2);
		written = SIZE_MAX;
		result = ntfs_lznt1_decode(packed, sizeof(packed), output, capacity, &written);
		assert(result == (capacity < CHUNK_BYTES ? NTFS_RANGE : NTFS_CORRUPT));
		assert(written == 0);
		copied = capacity < PREFIX_BYTES ? 1 : (capacity < CHUNK_BYTES ? capacity : CHUNK_BYTES);
		assert(memcmp(output, expected, copied) == 0);
		for (index = copied; index < CHUNK_BYTES + 2; index++) {
			assert(output[index] == GUARD);
		}
		check(packed, sizeof(packed), capacity, capacity % ALIGNMENTS, NULL, 0, false);
	}
	free(expected);
	free(output);
}

static size_t
multi_chunk_contract(const uint8_t *packed, size_t bytes, const uint8_t *expected)
{
	static const size_t capacities[] = {CHUNK_BYTES - 1, CHUNK_BYTES, CHUNK_BYTES + 1,
	    CHUNK_BYTES * 2 - 1, CHUNK_BYTES * 2, CHUNK_BYTES * 2 + 1};
	uint8_t *input, *plain;
	size_t index, checks = 0;

	input = malloc(bytes * 2 + HEADER_BYTES);
	plain = malloc(CHUNK_BYTES * 2);
	assert(input && plain);
	memcpy(input, packed, bytes);
	memcpy(input + bytes, packed, bytes);
	memcpy(plain, expected, CHUNK_BYTES);
	memcpy(plain + CHUNK_BYTES, expected, CHUNK_BYTES);
	for (index = 0; index < sizeof(capacities) / sizeof(*capacities); index++) {
		check(input, bytes * 2, capacities[index], index, plain, CHUNK_BYTES * 2,
		    capacities[index] >= CHUNK_BYTES * 2);
		checks++;
	}
	/* Every truncation in a second chunk retains its full first-chunk bytes
	 * on failure. A cut exactly between chunks is a valid shorter stream. */
	for (index = 0; index < bytes; index++) {
		check(input, bytes + index, CHUNK_BYTES * 2, index % ALIGNMENTS,
		    plain, CHUNK_BYTES, index == 0);
		checks++;
	}
	memset(input + bytes * 2, 0, HEADER_BYTES);
	check(input, bytes * 2 + HEADER_BYTES, CHUNK_BYTES * 2, 0,
	    plain, CHUNK_BYTES * 2, true);
	/* Corrupt only the second signature, after a fully published first chunk. */
	input[bytes + 1] ^= (uint8_t)(1u << 4);
	check(input, bytes * 2, CHUNK_BYTES * 2, 1, NULL, 0, false);
	checks += 2;
	free(plain);
	free(input);
	return checks;
}

int
main(int argc, char **argv)
{
	char path[PATH_BYTES], codec[CODEC_BYTES], name[NAME_BYTES];
	FILE *manifest;
	uint8_t *packed, *expected;
	size_t bytes, expected_bytes, index, alignment, count = 0, checks = 0;
	int length;

	assert(argc == 2);
	literal_contract();
	chunk_end_publication();
	flag_combinations();
	length = snprintf(path, sizeof(path), "%s/cases.txt", argv[1]);
	assert(length > 0 && (size_t)length < sizeof(path));
	manifest = fopen(path, "r");
	assert(manifest);
	while (fscanf(manifest, "%15s %127s", codec, name) == 2) {
		if (strcmp(codec, "lznt1") != 0) {
			continue;
		}
		packed = load(argv[1], name, ".packed", &bytes);
		expected = load(argv[1], name, ".data", &expected_bytes);
		if (expected_bytes == CHUNK_BYTES) {
			checks += multi_chunk_contract(packed, bytes, expected);
		}
#ifdef NTFS_LZNT1_REFERENCE
		overlap_contract(packed, bytes, expected_bytes);
		checks += ALIGNMENTS * 2 + 1;
#endif
		for (alignment = 0; alignment < ALIGNMENTS; alignment++) {
			check(packed, bytes, expected_bytes, alignment, expected, expected_bytes, true);
			check(packed, bytes, expected_bytes + 1, alignment, expected, expected_bytes, true);
			checks += 2;
		}
		for (index = 0; index < bytes; index++) {
			check(packed, index, expected_bytes, index % ALIGNMENTS, NULL, 0, false);
			packed[index] ^= (uint8_t)(1u << (index % CHAR_BIT));
			check(packed, bytes, expected_bytes, index % ALIGNMENTS, NULL, 0, false);
			packed[index] ^= (uint8_t)(1u << (index % CHAR_BIT));
			checks += 2;
		}
		for (index = 0; index < expected_bytes; index++) {
			check(packed, bytes, index, index % ALIGNMENTS, NULL, 0, false);
			checks++;
		}
		free(expected);
		free(packed);
		count++;
	}
	assert(feof(manifest) && fclose(manifest) == 0 && count > 0);
	printf("PASS: %zu LZNT1 packets, %zu exact-end/alignment/truncation/mutation/capacity checks", count, checks);
#ifdef NTFS_LZNT1_REFERENCE
	printf(" with identical reference status, length and complete partial output");
#endif
	puts("; independent 256-flag, literal-group and chunk-end failure/publication oracles");
	return 0;
}
