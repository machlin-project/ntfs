/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_reparse.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_COMMON_BYTES = 8,
	TEST_SYMLINK_BYTES = 12,
	TEST_JUNCTION_BYTES = 8,
	TEST_TERMINATORS = 2,
	TEST_OUTPUT_BYTES = 128,
	TEST_SENTINEL = 0xa5
};

static const uint16_t relative[] = {'.', '.', '\\', 't', 'a', 'r', 'g', 'e', 't'};
static const uint16_t absolute[] = {'\\', '?', '?', '\\', 'C', ':', '\\', 'f', 'o', 'o'};
static const uint16_t display[] = {'t', 'a', 'r', 'g', 'e', 't'};
static const uint16_t junction_display[] = {'C', ':', '\\', 'f', 'o', 'o'};

/* Independent literal wire packets from the documented REPARSE_DATA_BUFFER.
 * These do not use the implementation's disk layouts or endian helpers. */
static const uint8_t relative_golden[] = {0x0c, 0x00, 0x00, 0xa0, 0x2e, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x12, 0x00, 0x14, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00,
    '.', 0, '.', 0, '\\', 0, 't', 0, 'a', 0, 'r', 0, 'g', 0, 'e', 0, 't', 0, 0, 0,
    't', 0, 'a', 0, 'r', 0, 'g', 0, 'e', 0, 't', 0, 0, 0};
static const uint8_t junction_golden[] = {0x03, 0x00, 0x00, 0xa0, 0x2c, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x14, 0x00, 0x16, 0x00, 0x0c, 0x00, '\\', 0, '?', 0, '?', 0, '\\', 0,
    'C', 0, ':', 0, '\\', 0, 'f', 0, 'o', 0, 'o', 0, 0, 0,
    'C', 0, ':', 0, '\\', 0, 'f', 0, 'o', 0, 'o', 0, 0, 0};
static const uint8_t unicode_golden[] = {0x0c, 0x00, 0x00, 0xa0, 0x18, 0, 0, 0,
    0, 0, 8, 0, 10, 0, 0, 0, 1, 0, 0, 0,
    0xa9, 0x03, 0x00, 0xd8, 0x3d, 0xd8, 0x00, 0xde, 0, 0, 0, 0};

static void
unchanged(const uint8_t *bytes, size_t length)
{
	size_t index;

	for (index = 0; index < length; index++) {
		assert(bytes[index] == TEST_SENTINEL);
	}
}

static void
golden(const struct ntfs_write_reparse_input *input, const uint8_t *expected, size_t bytes)
{
	struct ntfs_write_reparse_input saved = *input;
	struct ntfs_reparse_info decoded;
	uint8_t output[TEST_OUTPUT_BYTES];
	size_t written = SIZE_MAX, required = SIZE_MAX, capacity;

	assert(ntfs_write_reparse_size(input, &required) == NTFS_OK && required == bytes);
	for (capacity = 0; capacity < bytes; capacity++) {
		memset(output, TEST_SENTINEL, sizeof(output));
		assert(ntfs_write_reparse_encode(input, output, capacity, &written) == NTFS_RANGE);
		assert(written == SIZE_MAX);
		unchanged(output, sizeof(output));
	}
	assert(ntfs_write_reparse_encode(input, output, sizeof(output), &written) == NTFS_OK);
	assert(written == bytes && memcmp(output, expected, bytes) == 0);
	unchanged(output + bytes, sizeof(output) - bytes);
	assert(memcmp(input, &saved, sizeof(saved)) == 0);
	assert(ntfs_reparse_decode(output, written, &decoded) == NTFS_OK);
	assert(decoded.kind == input->kind && decoded.flags == input->flags);
	assert(decoded.substitute_length == input->substitute_units &&
	    decoded.print_length == input->display_units);
}

static void
boundaries(void)
{
	uint16_t *name;
	uint8_t *output;
	struct ntfs_write_reparse_input input = {0};
	struct ntfs_reparse_info decoded;
	size_t kind, units, index, required, written;

	name = malloc(NTFS_REPARSE_MAX_BYTES);
	output = malloc(NTFS_REPARSE_MAX_BYTES + 1);
	assert(name != NULL && output != NULL);
	for (index = 0; index < NTFS_REPARSE_MAX_BYTES / sizeof(*name); index++) {
		name[index] = 0x4142;
	}
	for (kind = 0; kind != 2; kind++) {
		input.kind = kind == 0 ? NTFS_REPARSE_SYMLINK : NTFS_REPARSE_MOUNT_POINT;
		units = (NTFS_REPARSE_MAX_BYTES - TEST_COMMON_BYTES -
			    (kind == 0 ? TEST_SYMLINK_BYTES : TEST_JUNCTION_BYTES)) /
			    sizeof(*name) -
		    TEST_TERMINATORS;
		input.substitute = name;
		input.substitute_units = units;
		input.display = NULL;
		input.display_units = 0;
		required = written = SIZE_MAX;
		memset(output, TEST_SENTINEL, NTFS_REPARSE_MAX_BYTES + 1);
		assert(ntfs_write_reparse_size(&input, &required) == NTFS_OK);
		assert(required == NTFS_REPARSE_MAX_BYTES);
		assert(ntfs_write_reparse_encode(
			   &input, output, NTFS_REPARSE_MAX_BYTES, &written) == NTFS_OK);
		assert(written == required && output[NTFS_REPARSE_MAX_BYTES] == TEST_SENTINEL);
		assert(ntfs_reparse_decode(output, written, &decoded) == NTFS_OK);
		assert(decoded.substitute_length == units && decoded.print_length == 0);
		input.substitute_units++;
		required = written = SIZE_MAX;
		memset(output, TEST_SENTINEL, NTFS_REPARSE_MAX_BYTES + 1);
		assert(ntfs_write_reparse_size(&input, &required) == NTFS_RANGE);
		assert(required == SIZE_MAX);
		assert(ntfs_write_reparse_encode(
			   &input, output, NTFS_REPARSE_MAX_BYTES, &written) == NTFS_RANGE);
		assert(written == SIZE_MAX);
		unchanged(output, NTFS_REPARSE_MAX_BYTES + 1);
		/* Split the exact maximum between both overlapping immutable inputs. */
		input.substitute_units = 1;
		input.display = name;
		input.display_units = units - 1;
		assert(ntfs_write_reparse_encode(
			   &input, output, NTFS_REPARSE_MAX_BYTES, &written) == NTFS_OK);
		assert(written == NTFS_REPARSE_MAX_BYTES);
		assert(ntfs_reparse_decode(output, written, &decoded) == NTFS_OK);
		assert(decoded.substitute_length == 1 && decoded.print_length == units - 1);
	}
	free(output);
	free(name);
}

static void
refusals(void)
{
	struct ntfs_write_reparse_input input = {NTFS_REPARSE_SYMLINK,
	    NTFS_REPARSE_SYMLINK_RELATIVE, relative, display,
	    sizeof(relative) / sizeof(*relative), sizeof(display) / sizeof(*display)};
	struct ntfs_write_reparse_input invalid, saved;
	uint8_t output[TEST_OUTPUT_BYTES];
	uint16_t embedded_nul[] = {'x', 0, 'y'};
	uint16_t alias[TEST_OUTPUT_BYTES];
	size_t written, index;
	enum ntfs_result expected;

	for (index = 0; index != 12; index++) {
		invalid = input;
		expected = NTFS_INVALID;
		switch (index) {
		case 0:
			invalid.kind = NTFS_REPARSE_WOF;
			expected = NTFS_UNSUPPORTED;
			break;
		case 1:
			invalid.kind = NTFS_REPARSE_UNKNOWN;
			expected = NTFS_UNSUPPORTED;
			break;
		case 2:
			invalid.flags = 2;
			expected = NTFS_UNSUPPORTED;
			break;
		case 3:
			invalid.kind = NTFS_REPARSE_MOUNT_POINT;
			expected = NTFS_UNSUPPORTED;
			break;
		case 4:
			invalid.substitute_units = 0;
			break;
		case 5:
			invalid.substitute = NULL;
			break;
		case 6:
			invalid.display = NULL;
			break;
		case 7:
			invalid.substitute = embedded_nul;
			invalid.substitute_units = sizeof(embedded_nul) / sizeof(*embedded_nul);
			break;
		case 8:
			invalid.display = embedded_nul;
			invalid.display_units = sizeof(embedded_nul) / sizeof(*embedded_nul);
			break;
		case 9:
			invalid.substitute_units = SIZE_MAX;
			expected = NTFS_RANGE;
			break;
		case 10:
			invalid.display_units = SIZE_MAX;
			expected = NTFS_RANGE;
			break;
		case 11:
			invalid.substitute = (const void *)UINTPTR_MAX;
			break;
		}
		saved = invalid;
		written = SIZE_MAX;
		memset(output, TEST_SENTINEL, sizeof(output));
		assert(ntfs_write_reparse_size(&invalid, &written) == expected);
		assert(written == SIZE_MAX);
		assert(ntfs_write_reparse_encode(&invalid, output, sizeof(output), &written) ==
		    expected);
		assert(written == SIZE_MAX && memcmp(&invalid, &saved, sizeof(saved)) == 0);
		unchanged(output, sizeof(output));
	}
	memset(alias, TEST_SENTINEL, sizeof(alias));
	input.substitute = alias;
	assert(ntfs_write_reparse_encode(&input, alias, sizeof(alias), &written) == NTFS_INVALID);
	unchanged((const void *)alias, sizeof(alias));
	input.substitute = relative;
	input.display = alias;
	assert(ntfs_write_reparse_encode(&input, alias, sizeof(alias), &written) == NTFS_INVALID);
	unchanged((const void *)alias, sizeof(alias));
	input.display = display;
	saved = input;
	assert(ntfs_write_reparse_size(&input, &input.substitute_units) == NTFS_INVALID);
	assert(memcmp(&input, &saved, sizeof(saved)) == 0);
	assert(ntfs_write_reparse_encode(&input, &input, sizeof(input), &written) == NTFS_INVALID);
	assert(memcmp(&input, &saved, sizeof(saved)) == 0);
	assert(ntfs_write_reparse_encode(&input, output, sizeof(output), (void *)output) ==
	    NTFS_INVALID);
	unchanged(output, sizeof(output));
	assert(ntfs_write_reparse_size(NULL, &written) == NTFS_INVALID);
	assert(ntfs_write_reparse_size(&input, NULL) == NTFS_INVALID);
	assert(ntfs_write_reparse_encode(&input, NULL, sizeof(output), &written) == NTFS_INVALID);
	assert(ntfs_write_reparse_encode(&input, output, SIZE_MAX, &written) == NTFS_INVALID);
	assert(ntfs_write_reparse_encode(&input, output, sizeof(output), NULL) == NTFS_INVALID);
	assert(ntfs_write_reparse_size((const void *)UINTPTR_MAX, &written) == NTFS_INVALID);
	unchanged(output, sizeof(output));
}

int
main(void)
{
	static const uint16_t unicode[] = {0x03a9, 0xd800, 0xd83d, 0xde00};
	struct ntfs_write_reparse_input input = {NTFS_REPARSE_SYMLINK,
	    NTFS_REPARSE_SYMLINK_RELATIVE, relative, display,
	    sizeof(relative) / sizeof(*relative), sizeof(display) / sizeof(*display)};

	golden(&input, relative_golden, sizeof(relative_golden));
	input = (struct ntfs_write_reparse_input){NTFS_REPARSE_MOUNT_POINT, 0, absolute,
	    junction_display, sizeof(absolute) / sizeof(*absolute),
	    sizeof(junction_display) / sizeof(*junction_display)};
	golden(&input, junction_golden, sizeof(junction_golden));
	input = (struct ntfs_write_reparse_input){NTFS_REPARSE_SYMLINK,
	    NTFS_REPARSE_SYMLINK_RELATIVE, unicode, NULL, sizeof(unicode) / sizeof(*unicode), 0};
	golden(&input, unicode_golden, sizeof(unicode_golden));
	boundaries();
	refusals();
	puts("private reparse encoding: literal packets, exact UTF-16, terminators, maximum sizes, "
	     "aliases, refusals and unchanged failed outputs passed");
	return 0;
}
