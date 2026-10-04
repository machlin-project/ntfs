/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include <ntfs/record.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_PATH_BYTES = 4096,
	TEST_NAME_BYTES = 96,
	TEST_SCAN_FORMAT_BYTES = 32,
	TEST_CASE_COLUMNS = 3,
	TEST_GUARD_BYTES = 1,
	TEST_GUARD = 0xa5,
	TEST_TORN_MASK = 1
};

static uint8_t *
read_bytes(const char *directory, const char *name, const char *suffix, size_t *size)
{
	char path[TEST_PATH_BYTES];
	FILE *file;
	uint8_t *bytes;
	long length;
	int written;

	written = snprintf(path, sizeof(path), "%s/%s%s", directory, name, suffix);
	assert(written > 0 && (size_t)written < sizeof(path));
	file = fopen(path, "rb");
	assert(file != NULL);
	assert(fseek(file, 0, SEEK_END) == 0);
	length = ftell(file);
	assert(length >= 0 && fseek(file, 0, SEEK_SET) == 0);
	*size = (size_t)length;
	bytes = malloc(*size + 2 * TEST_GUARD_BYTES);
	assert(bytes != NULL);
	bytes[0] = TEST_GUARD;
	bytes[*size + TEST_GUARD_BYTES] = TEST_GUARD;
	assert(fread(bytes + TEST_GUARD_BYTES, 1, *size, file) == *size);
	assert(fclose(file) == 0);
	return bytes;
}

static void
guards(const uint8_t *bytes, size_t size)
{
	assert(bytes[0] == TEST_GUARD);
	assert(bytes[size + TEST_GUARD_BYTES] == TEST_GUARD);
}

static size_t
check_case(const char *directory, const char *name, unsigned expected_code, size_t capacity)
{
	const struct ntfs_disk_mst *header;
	uint8_t *input, *unchanged, *encoded, *expected, *torn;
	size_t size, output_bytes, expected_size, offset, count, index, tail, torn_checks = 0;
	enum ntfs_result result;

	input = read_bytes(directory, name, ".input", &size);
	output_bytes = capacity > size ? capacity : size;
	unchanged = malloc(size + 2 * TEST_GUARD_BYTES);
	encoded = malloc(output_bytes + 2 * TEST_GUARD_BYTES);
	assert(unchanged != NULL && encoded != NULL);
	memcpy(unchanged, input, size + 2 * TEST_GUARD_BYTES);
	memset(encoded, TEST_GUARD, output_bytes + 2 * TEST_GUARD_BYTES);
	result = ntfs_record_protect(
	    input + TEST_GUARD_BYTES, size, encoded + TEST_GUARD_BYTES, capacity);
	if ((unsigned)result != expected_code) {
		fprintf(stderr, "%s: expected %u, got %u\n", name, expected_code, (unsigned)result);
		abort();
	}
	assert(memcmp(input, unchanged, size + 2 * TEST_GUARD_BYTES) == 0);
	guards(encoded, output_bytes);
	for (index = size; index < output_bytes; index++) {
		assert(encoded[index + TEST_GUARD_BYTES] == TEST_GUARD);
	}
	if (result == NTFS_OK) {
		expected = read_bytes(directory, name, ".expected", &expected_size);
		assert(expected_size == size);
		assert(memcmp(encoded + TEST_GUARD_BYTES, expected + TEST_GUARD_BYTES, size) == 0);
		header = (const void *)(input + TEST_GUARD_BYTES);
		offset = ntfs_u16(header->usa_offset);
		count = ntfs_u16(header->usa_count);
		torn = malloc(size);
		assert(torn != NULL);
		for (index = 1; index < count; index++) {
			tail = index * NTFS_MST_STRIDE - NTFS_MST_WORD_BYTES;
			memcpy(torn, expected + TEST_GUARD_BYTES, size);
			torn[tail] ^= TEST_TORN_MASK;
			memcpy(encoded + TEST_GUARD_BYTES, torn, size);
			assert(ntfs_fixup(encoded + TEST_GUARD_BYTES, size,
				   (const char *)header->magic) == NTFS_CORRUPT);
			assert(memcmp(encoded + TEST_GUARD_BYTES, torn, size) == 0);
			torn_checks++;
		}
		memcpy(encoded + TEST_GUARD_BYTES, expected + TEST_GUARD_BYTES, size);
		assert(ntfs_fixup(encoded + TEST_GUARD_BYTES, size, (const char *)header->magic) ==
		    NTFS_OK);
		for (index = 0; index < size; index++) {
			if (index < offset || index >= offset + count * NTFS_MST_WORD_BYTES) {
				assert(encoded[index + TEST_GUARD_BYTES] ==
				    input[index + TEST_GUARD_BYTES]);
			}
		}
		guards(encoded, output_bytes);
		free(torn);
		free(expected);
	} else {
		for (index = 0; index < output_bytes + 2 * TEST_GUARD_BYTES; index++) {
			assert(encoded[index] == TEST_GUARD);
		}
	}
	free(encoded);
	free(unchanged);
	free(input);
	return torn_checks;
}

static void
check_endian_writes(void)
{
	const uint64_t values[] = {0, UINT64_MAX, UINT64_C(0xefcdab8967452301)};
	const uint8_t expected[][sizeof(uint64_t)] = {{0, 0, 0, 0, 0, 0, 0, 0},
	    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	    {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}};
	const size_t widths[] = {sizeof(uint16_t), sizeof(uint32_t), sizeof(uint64_t)};
	uint8_t output[sizeof(uint64_t) + 2 * TEST_GUARD_BYTES];
	size_t value_index, width_index, width, index;

	for (value_index = 0; value_index < sizeof(values) / sizeof(values[0]); value_index++) {
		for (width_index = 0; width_index < sizeof(widths) / sizeof(widths[0]);
		    width_index++) {
			width = widths[width_index];
			memset(output, TEST_GUARD, sizeof(output));
			if (width == sizeof(uint16_t)) {
				ntfs_put_u16(
				    output + TEST_GUARD_BYTES, (uint16_t)values[value_index]);
			} else if (width == sizeof(uint32_t)) {
				ntfs_put_u32(
				    output + TEST_GUARD_BYTES, (uint32_t)values[value_index]);
			} else {
				ntfs_put_u64(output + TEST_GUARD_BYTES, values[value_index]);
			}
			assert(
			    memcmp(output + TEST_GUARD_BYTES, expected[value_index], width) == 0);
			assert(output[0] == TEST_GUARD);
			for (index = width + TEST_GUARD_BYTES; index < sizeof(output); index++) {
				assert(output[index] == TEST_GUARD);
			}
		}
	}
}

static void
check_arguments(const char *directory)
{
	uint8_t *input, *unchanged, *output;
	size_t size, index;

	input = read_bytes(directory, "file-512-1", ".input", &size);
	unchanged = malloc(size + 2 * TEST_GUARD_BYTES);
	output = malloc(size);
	assert(unchanged != NULL && output != NULL);
	memcpy(unchanged, input, size + 2 * TEST_GUARD_BYTES);
	memset(output, TEST_GUARD, size);
	assert(ntfs_record_protect(NULL, size, output, size) == NTFS_INVALID);
	assert(ntfs_record_protect(input + TEST_GUARD_BYTES, size, NULL, size) == NTFS_INVALID);
	assert(ntfs_record_protect(
		   input + TEST_GUARD_BYTES, size, input + TEST_GUARD_BYTES, size) == NTFS_INVALID);
	assert(ntfs_record_protect(input + TEST_GUARD_BYTES, size, input + 2 * TEST_GUARD_BYTES,
		   size) == NTFS_INVALID);
	assert(ntfs_record_protect(input + 2 * TEST_GUARD_BYTES, size, input + TEST_GUARD_BYTES,
		   size) == NTFS_INVALID);
	assert(memcmp(input, unchanged, size + 2 * TEST_GUARD_BYTES) == 0);
	for (index = 0; index < size; index++) {
		assert(output[index] == TEST_GUARD);
	}
	free(output);
	free(unchanged);
	free(input);
}

int
main(int argc, char **argv)
{
	char path[TEST_PATH_BYTES], name[TEST_NAME_BYTES], format[TEST_SCAN_FORMAT_BYTES];
	FILE *cases;
	size_t capacity, case_count = 0, torn_checks = 0;
	unsigned code;
	int written, scanned;

	assert(argc == 2);
	written = snprintf(path, sizeof(path), "%s/cases.tsv", argv[1]);
	assert(written > 0 && (size_t)written < sizeof(path));
	cases = fopen(path, "r");
	assert(cases != NULL);
	written = snprintf(format, sizeof(format), "%%%zus %%u %%zu", sizeof(name) - 1);
	assert(written > 0 && (size_t)written < sizeof(format));
	while ((scanned = fscanf(cases, format, name, &code, &capacity)) == TEST_CASE_COLUMNS) {
		torn_checks += check_case(argv[1], name, code, capacity);
		case_count++;
	}
	assert(scanned == EOF && feof(cases) && fclose(cases) == 0);
	check_arguments(argv[1]);
	check_endian_writes();
	printf("PASS: %zu independent protected-byte vectors, %zu sector-tail corruptions, "
	       "sequence wrap, unaligned buffers, exact/extra capacity, unchanged failures and "
	       "input\n",
	    case_count, torn_checks);
	return 0;
}
