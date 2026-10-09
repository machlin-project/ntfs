/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "usn.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { TEST_ALIGNMENT = 8, TEST_OUTPUT_BYTES = 256, TEST_SENTINEL = 0xa5 };

/* Original literal wire goldens. These independent field declarations do not
 * use core disk structures, wire helpers or an encoder to author expectations. */
struct fixture_v2 {
	uint8_t length[4], major[2], minor[2], file[8], parent[8], usn[8], time[8];
	uint8_t reason[4], source[4], security[4], attributes[4], name_length[2], name_offset[2];
	uint8_t name[8], padding[4];
};

struct fixture_v3 {
	uint8_t length[4], major[2], minor[2], file[16], parent[16], usn[8], time[8];
	uint8_t reason[4], source[4], security[4], attributes[4], name_length[2], name_offset[2];
	uint8_t name[6], padding[6];
};

_Static_assert(offsetof(struct fixture_v2, name) == 60, "independent V2 prefix");
_Static_assert(offsetof(struct fixture_v3, name) == 76, "independent V3 prefix");
_Static_assert(sizeof(struct fixture_v2) == 72, "independent V2 complete record");
_Static_assert(sizeof(struct fixture_v3) == 88, "independent V3 complete record");

static const struct fixture_v2 golden_v2 = {.length = {0x48, 0, 0, 0},
    .major = {2, 0},
    .minor = {0, 0},
    .file = {8, 7, 6, 5, 4, 3, 2, 1},
    .parent = {0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11},
    .usn = {0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21},
    .time = {0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31},
    .reason = {3, 0x81, 0, 0x81},
    .source = {9, 0, 0, 0x80},
    .security = {0x88, 0x77, 0x66, 0x55},
    .attributes = {0xef, 0xcd, 0xab, 0x89},
    .name_length = {8, 0},
    .name_offset = {0x3c, 0},
    .name = {'A', 0, 0xa9, 3, 0, 0xd8, 0, 0},
    .padding = {0, 0, 0, 0}};

static const struct fixture_v3 golden_v3 = {.length = {0x58, 0, 0, 0},
    .major = {3, 0},
    .minor = {0, 0},
    .file = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    .parent = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
	0xfe, 0xff},
    .usn = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
    .time = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
    .reason = {0xff, 0xff, 0xff, 0xff},
    .source = {0, 0, 0, 0},
    .security = {0, 0, 0, 0},
    .attributes = {0, 0, 0, 0},
    .name_length = {6, 0},
    .name_offset = {0x4c, 0},
    .name = {'x', 0, 'y', 0, 'z', 0},
    .padding = {0, 0, 0, 0, 0, 0}};

static struct ntfs_usn_record
description(unsigned version)
{
	struct ntfs_usn_record input;

	memset(&input, 0, sizeof(input));
	input.major_version = (uint16_t)version;
	if (version == 2) {
		memcpy(input.file_id, golden_v2.file, sizeof(golden_v2.file));
		memcpy(input.parent_id, golden_v2.parent, sizeof(golden_v2.parent));
		input.usn = UINT64_C(0x2122232425262728);
		input.timestamp = UINT64_C(0x3132333435363738);
		input.reason = UINT32_C(0x81008103);
		input.source_info = UINT32_C(0x80000009);
		input.security_id = UINT32_C(0x55667788);
		input.file_attributes = UINT32_C(0x89abcdef);
		input.filename = golden_v2.name;
		input.filename_bytes = sizeof(golden_v2.name);
	} else {
		memcpy(input.file_id, golden_v3.file, sizeof(golden_v3.file));
		memcpy(input.parent_id, golden_v3.parent, sizeof(golden_v3.parent));
		input.usn = INT64_MAX;
		input.timestamp = UINT64_MAX;
		input.reason = UINT32_MAX;
		input.filename = golden_v3.name;
		input.filename_bytes = sizeof(golden_v3.name);
	}
	return input;
}

static void
sentinel(const void *input, size_t bytes)
{
	const uint8_t *data = input;
	size_t index;

	for (index = 0; index < bytes; index++) {
		assert(data[index] == TEST_SENTINEL);
	}
}

static void
equal_values(const struct ntfs_usn_record *left, const struct ntfs_usn_record *right)
{
	assert(left->major_version == right->major_version);
	assert(left->minor_version == right->minor_version);
	assert(memcmp(left->file_id, right->file_id, sizeof(left->file_id)) == 0);
	assert(memcmp(left->parent_id, right->parent_id, sizeof(left->parent_id)) == 0);
	assert(left->usn == right->usn && left->timestamp == right->timestamp);
	assert(left->reason == right->reason && left->source_info == right->source_info);
	assert(left->security_id == right->security_id);
	assert(left->file_attributes == right->file_attributes);
	assert(left->filename_bytes == right->filename_bytes);
	assert(memcmp(left->filename, right->filename, left->filename_bytes) == 0);
}

static void
golden(unsigned version, const void *wire, size_t bytes, size_t prefix)
{
	struct ntfs_usn_record input = description(version), saved = input;
	struct ntfs_usn_view decoded;
	uint8_t output[TEST_OUTPUT_BYTES];
	size_t capacity, offset, written, required, length;

	required = SIZE_MAX;
	assert(ntfs_usn_record_size(&input, &required) == NTFS_OK && required == bytes);
	for (capacity = 0; capacity < bytes; capacity++) {
		written = SIZE_MAX;
		memset(output, TEST_SENTINEL, sizeof(output));
		assert(ntfs_usn_record_encode(&input, output, capacity, &written) == NTFS_RANGE);
		assert(written == SIZE_MAX);
		sentinel(output, sizeof(output));
	}
	for (offset = 0; offset < TEST_ALIGNMENT; offset++) {
		memset(output, TEST_SENTINEL, sizeof(output));
		written = SIZE_MAX;
		assert(ntfs_usn_record_encode(&input, output + offset, bytes, &written) == NTFS_OK);
		assert(written == bytes && memcmp(output + offset, wire, bytes) == 0);
		sentinel(output, offset);
		sentinel(output + offset + bytes, sizeof(output) - offset - bytes);
		for (length = 0; length < bytes; length++) {
			memset(&decoded, TEST_SENTINEL, sizeof(decoded));
			assert(ntfs_usn_record_decode(output + offset, length, &decoded) ==
			    NTFS_CORRUPT);
			sentinel(&decoded, sizeof(decoded));
		}
		assert(ntfs_usn_record_decode(output + offset, bytes, &decoded) == NTFS_OK);
		equal_values(&input, &decoded.record);
		assert(decoded.record_bytes == bytes && decoded.filename_offset == prefix);
		assert(decoded.record.filename == output + offset + prefix);
		assert(ntfs_usn_record_decode(output + offset, sizeof(output) - offset, &decoded) ==
		    NTFS_OK);
		assert(decoded.record_bytes == bytes);
	}
	assert(memcmp(&input, &saved, sizeof(input)) == 0);
}

static void
put_word(uint8_t *field, uint16_t value)
{
	field[0] = (uint8_t)value;
	field[1] = (uint8_t)(value / 256);
}

static void
put_dword(uint8_t *field, uint32_t value)
{
	size_t index;

	for (index = 0; index < sizeof(value); index++) {
		field[index] = (uint8_t)value;
		value /= 256;
	}
}

static void
malformed(void)
{
	struct fixture_v2 wire;
	struct fixture_v3 wide;
	struct ntfs_usn_view out;
	enum ntfs_result expected;
	size_t index;

	for (index = 0; index != 17; index++) {
		wire = golden_v2;
		expected = NTFS_CORRUPT;
		switch (index) {
		case 0:
			put_dword(wire.length, 0);
			break;
		case 1:
			put_dword(wire.length, sizeof(wire.length));
			break;
		case 2:
			put_dword(wire.length, TEST_ALIGNMENT);
			break;
		case 3:
			put_dword(wire.length, sizeof(wire) - 1);
			break;
		case 4:
			put_dword(wire.length, sizeof(wire) + TEST_ALIGNMENT);
			break;
		case 5:
			put_dword(wire.length, UINT32_MAX);
			break;
		case 6:
			put_word(wire.name_offset, offsetof(struct fixture_v2, name) - 2);
			break;
		case 7:
			put_word(wire.name_offset, sizeof(wire));
			break;
		case 8:
			put_word(wire.name_offset, UINT16_MAX - 1);
			break;
		case 9:
			put_word(wire.name_offset, offsetof(struct fixture_v2, name) + 1);
			break;
		case 10:
			put_word(wire.name_length, sizeof(wire.name) - 1);
			break;
		case 11:
			put_word(wire.name_length, UINT16_MAX - 1);
			break;
		case 12:
			wire.usn[sizeof(wire.usn) - 1] = 0x80;
			break;
		case 13:
			put_word(wire.major, 1);
			expected = NTFS_UNSUPPORTED;
			break;
		case 14:
			put_word(wire.major, 4);
			expected = NTFS_UNSUPPORTED;
			break;
		case 15:
			put_word(wire.minor, 1);
			expected = NTFS_UNSUPPORTED;
			break;
		case 16:
			put_word(wire.major, UINT16_MAX);
			expected = NTFS_UNSUPPORTED;
			break;
		}
		memset(&out, TEST_SENTINEL, sizeof(out));
		assert(ntfs_usn_record_decode(&wire, sizeof(wire), &out) == expected);
		sentinel(&out, sizeof(out));
	}
	for (index = 0; index != 7; index++) {
		wide = golden_v3;
		expected = NTFS_CORRUPT;
		switch (index) {
		case 0:
			put_dword(wide.length, sizeof(golden_v2));
			break;
		case 1:
			put_word(wide.name_offset, offsetof(struct fixture_v2, name));
			break;
		case 2:
			put_word(wide.name_offset, offsetof(struct fixture_v3, name) + 1);
			break;
		case 3:
			put_word(wide.name_length, sizeof(wide.name) - 1);
			break;
		case 4:
			put_word(wide.name_offset, sizeof(wide));
			break;
		case 5:
			wide.usn[sizeof(wide.usn) - 1] = 0x80;
			break;
		case 6:
			put_word(wide.minor, UINT16_MAX);
			expected = NTFS_UNSUPPORTED;
			break;
		}
		memset(&out, TEST_SENTINEL, sizeof(out));
		assert(ntfs_usn_record_decode(&wide, sizeof(wide), &out) == expected);
		sentinel(&out, sizeof(out));
	}
}

static void
offset_and_sequence(void)
{
	uint8_t bytes[TEST_OUTPUT_BYTES], output[TEST_OUTPUT_BYTES];
	struct fixture_v2 *first = (void *)bytes;
	struct ntfs_usn_view decoded;
	size_t name_offset = offsetof(struct fixture_v2, name) + TEST_ALIGNMENT, written;

	memset(bytes, TEST_SENTINEL, sizeof(bytes));
	memcpy(bytes, &golden_v2, offsetof(struct fixture_v2, name));
	put_dword(first->length, sizeof(golden_v2) + TEST_ALIGNMENT);
	put_word(first->name_offset, (uint16_t)name_offset);
	memcpy(bytes + name_offset, golden_v2.name, sizeof(golden_v2.name));
	assert(ntfs_usn_record_decode(bytes, sizeof(bytes), &decoded) == NTFS_OK);
	assert(decoded.filename_offset == name_offset);
	assert(decoded.record.filename == bytes + name_offset);
	assert(
	    ntfs_usn_record_encode(&decoded.record, output, sizeof(output), &written) == NTFS_OK);
	assert(written == sizeof(golden_v2) && memcmp(output, &golden_v2, written) == 0);
	/* Records use their own length; following V3 cannot be mistaken for padding. */
	memcpy(bytes, &golden_v2, sizeof(golden_v2));
	memcpy(bytes + sizeof(golden_v2), &golden_v3, sizeof(golden_v3));
	assert(ntfs_usn_record_decode(bytes, sizeof(bytes), &decoded) == NTFS_OK);
	assert(decoded.record_bytes == sizeof(golden_v2));
	assert(ntfs_usn_record_decode(bytes + decoded.record_bytes,
		   sizeof(bytes) - decoded.record_bytes, &decoded) == NTFS_OK);
	assert(decoded.record.major_version == 3 && decoded.record_bytes == sizeof(golden_v3));
}

static void
maximum_names(void)
{
	struct ntfs_usn_record input;
	struct ntfs_usn_view decoded;
	uint8_t *name, *output;
	size_t bytes = UINT16_MAX - 1, capacity = UINT16_MAX + sizeof(golden_v3);
	size_t version, index, required, written, prefix, expected;

	name = malloc(bytes);
	output = malloc(capacity);
	assert(name != NULL && output != NULL);
	for (index = 0; index < bytes; index++) {
		name[index] = (uint8_t)index;
	}
	for (version = 2; version <= 3; version++) {
		input = description((unsigned)version);
		input.filename = name;
		input.filename_bytes = bytes;
		prefix = version == 2 ? offsetof(struct fixture_v2, name)
				      : offsetof(struct fixture_v3, name);
		expected =
		    ((prefix + bytes + TEST_ALIGNMENT - 1) / TEST_ALIGNMENT) * TEST_ALIGNMENT;
		assert(ntfs_usn_record_size(&input, &required) == NTFS_OK && required == expected);
		memset(output, TEST_SENTINEL, capacity);
		assert(ntfs_usn_record_encode(&input, output, required, &written) == NTFS_OK);
		assert(written == expected && memcmp(output + prefix, name, bytes) == 0);
		for (index = prefix + bytes; index < written; index++) {
			assert(output[index] == 0);
		}
		sentinel(output + written, capacity - written);
		assert(ntfs_usn_record_decode(output, written, &decoded) == NTFS_OK);
		equal_values(&input, &decoded.record);
		input.filename = NULL;
		input.filename_bytes = 0;
		assert(ntfs_usn_record_encode(&input, output, capacity, &written) == NTFS_OK);
		assert(
		    written == ((prefix + TEST_ALIGNMENT - 1) / TEST_ALIGNMENT) * TEST_ALIGNMENT);
		assert(ntfs_usn_record_decode(output, written, &decoded) == NTFS_OK);
		assert(decoded.record.filename_bytes == 0);
	}
	/* Largest even WORD offset, with the name ending exactly at RecordLength. */
	memcpy(output, &golden_v2, offsetof(struct fixture_v2, name));
	put_dword(((struct fixture_v2 *)(void *)output)->length, UINT16_MAX + 1u);
	put_word(((struct fixture_v2 *)(void *)output)->name_offset, UINT16_MAX - 1);
	put_word(((struct fixture_v2 *)(void *)output)->name_length, sizeof(uint16_t));
	assert(ntfs_usn_record_decode(output, UINT16_MAX + 1u, &decoded) == NTFS_OK);
	assert(decoded.record.filename == output + UINT16_MAX - 1);
	assert(decoded.record.filename_bytes == sizeof(uint16_t));
	free(output);
	free(name);
}

static void
input_errors(void)
{
	struct ntfs_usn_record input, saved;
	struct ntfs_usn_view decoded;
	uint8_t output[TEST_OUTPUT_BYTES];
	size_t index, written, required;
	enum ntfs_result expected;

	for (index = 0; index != 11; index++) {
		input = description(2);
		expected = NTFS_INVALID;
		switch (index) {
		case 0:
			input.major_version = 4;
			expected = NTFS_UNSUPPORTED;
			break;
		case 1:
			input.minor_version = 1;
			expected = NTFS_UNSUPPORTED;
			break;
		case 2:
			input.filename_bytes = UINT16_MAX;
			break;
		case 3:
			input.filename_bytes = (size_t)UINT16_MAX + 1;
			expected = NTFS_RANGE;
			break;
		case 4:
			input.filename_bytes = SIZE_MAX;
			expected = NTFS_RANGE;
			break;
		case 5:
			input.filename = NULL;
			break;
		case 6:
			input.filename = (const void *)UINTPTR_MAX;
			break;
		case 7:
			input.file_id[sizeof(golden_v2.file)] = 1;
			break;
		case 8:
			input.parent_id[sizeof(golden_v2.parent)] = 1;
			break;
		case 9:
			input.usn = (uint64_t)INT64_MAX + 1;
			expected = NTFS_RANGE;
			break;
		case 10:
			input.usn = UINT64_MAX;
			expected = NTFS_RANGE;
			break;
		}
		saved = input;
		written = required = SIZE_MAX;
		memset(output, TEST_SENTINEL, sizeof(output));
		assert(ntfs_usn_record_size(&input, &required) == expected);
		assert(
		    ntfs_usn_record_encode(&input, output, sizeof(output), &written) == expected);
		assert(required == SIZE_MAX && written == SIZE_MAX);
		assert(memcmp(&input, &saved, sizeof(input)) == 0);
		sentinel(output, sizeof(output));
	}
	input = description(2);
	written = SIZE_MAX;
	assert(ntfs_usn_record_size(NULL, &written) == NTFS_INVALID);
	assert(ntfs_usn_record_size((const void *)UINTPTR_MAX, &written) == NTFS_INVALID);
	assert(ntfs_usn_record_size(&input, NULL) == NTFS_INVALID);
	assert(ntfs_usn_record_size(&input, (void *)UINTPTR_MAX) == NTFS_INVALID);
	assert(ntfs_usn_record_encode(&input, NULL, 0, &written) == NTFS_INVALID);
	assert(ntfs_usn_record_encode(&input, output, SIZE_MAX, &written) == NTFS_INVALID);
	assert(ntfs_usn_record_encode(&input, output, sizeof(output), NULL) == NTFS_INVALID);
	assert(ntfs_usn_record_encode(NULL, output, sizeof(output), &written) == NTFS_INVALID);
	assert(ntfs_usn_record_encode(
		   (const void *)UINTPTR_MAX, output, sizeof(output), &written) == NTFS_INVALID);
	assert(written == SIZE_MAX);
	sentinel(output, sizeof(output));
	memset(&decoded, TEST_SENTINEL, sizeof(decoded));
	assert(ntfs_usn_record_decode(NULL, 0, &decoded) == NTFS_INVALID);
	assert(ntfs_usn_record_decode((const void *)UINTPTR_MAX, sizeof(golden_v2), &decoded) ==
	    NTFS_INVALID);
	assert(ntfs_usn_record_decode(&golden_v2, SIZE_MAX, &decoded) == NTFS_INVALID);
	assert(ntfs_usn_record_decode(&golden_v2, sizeof(golden_v2), NULL) == NTFS_INVALID);
	assert(ntfs_usn_record_decode(&golden_v2, sizeof(golden_v2), (void *)UINTPTR_MAX) ==
	    NTFS_INVALID);
	sentinel(&decoded, sizeof(decoded));
}

static void
aliases(void)
{
	union {
		uint8_t bytes[TEST_OUTPUT_BYTES];
		size_t size;
		struct ntfs_usn_view view;
	} storage;
	struct ntfs_usn_record input = description(2), saved;
	uint8_t output[TEST_OUTPUT_BYTES];
	size_t written = SIZE_MAX;

	memset(&storage, TEST_SENTINEL, sizeof(storage));
	saved = input;
	assert(ntfs_usn_record_size(&input, &input.filename_bytes) == NTFS_INVALID);
	assert(ntfs_usn_record_encode(&input, &input, sizeof(input), &written) == NTFS_INVALID);
	assert(ntfs_usn_record_encode(&input, storage.bytes, sizeof(storage.bytes),
		   &input.filename_bytes) == NTFS_INVALID);
	assert(memcmp(&input, &saved, sizeof(input)) == 0);
	assert(ntfs_usn_record_encode(
		   &input, storage.bytes, sizeof(storage.bytes), &storage.size) == NTFS_INVALID);
	sentinel(&storage, sizeof(storage));
	input.filename = storage.bytes;
	saved = input;
	assert(ntfs_usn_record_size(&input, &storage.size) == NTFS_INVALID);
	assert(ntfs_usn_record_encode(&input, storage.bytes, sizeof(storage.bytes), &written) ==
	    NTFS_INVALID);
	memset(output, TEST_SENTINEL, sizeof(output));
	assert(
	    ntfs_usn_record_encode(&input, output, sizeof(output), &storage.size) == NTFS_INVALID);
	sentinel(output, sizeof(output));
	assert(memcmp(&input, &saved, sizeof(input)) == 0);
	sentinel(&storage, sizeof(storage));
	assert(written == SIZE_MAX);
	memcpy(storage.bytes, &golden_v2, sizeof(golden_v2));
	assert(ntfs_usn_record_decode(storage.bytes, sizeof(storage.bytes), &storage.view) ==
	    NTFS_INVALID);
	assert(ntfs_usn_record_decode(storage.bytes, sizeof(storage.bytes),
		   (void *)(storage.bytes + TEST_ALIGNMENT)) == NTFS_INVALID);
	assert(memcmp(storage.bytes, &golden_v2, sizeof(golden_v2)) == 0);
	sentinel(storage.bytes + sizeof(golden_v2), sizeof(storage.bytes) - sizeof(golden_v2));
}

static void
reason_union(void)
{
	union {
		uint32_t aligned;
		uint8_t bytes[sizeof(uint32_t) + 1];
	} unaligned;

	uint32_t flags[] = {0x00000100, 0x80000000, 0x00000002, 0x00000002, 0x01000000};
	uint32_t saved[sizeof(flags) / sizeof(*flags)], bits[32], out;
	uint32_t *maximum;
	size_t index;

	memcpy(saved, flags, sizeof(flags));
	out = TEST_SENTINEL;
	assert(ntfs_usn_reason_union(flags, sizeof(flags) / sizeof(*flags), &out) == NTFS_OK);
	assert(out == UINT32_C(0x81000102));
	assert(memcmp(flags, saved, sizeof(flags)) == 0);
	assert(ntfs_usn_reason_union(NULL, 0, &out) == NTFS_OK && out == 0);
	for (index = 0; index < sizeof(bits) / sizeof(*bits); index++) {
		bits[index] = UINT32_C(1) << index;
		assert(ntfs_usn_reason_union(&bits[index], 1, &out) == NTFS_OK);
		assert(out == bits[index]);
	}
	assert(ntfs_usn_reason_union(bits, sizeof(bits) / sizeof(*bits), &out) == NTFS_OK);
	assert(out == UINT32_MAX);
	maximum = malloc(NTFS_USN_MAX_REASON_INPUTS * sizeof(*maximum));
	assert(maximum != NULL);
	for (index = 0; index < NTFS_USN_MAX_REASON_INPUTS; index++) {
		maximum[index] = UINT32_C(0x01000000);
	}
	maximum[0] = UINT32_C(0x80000000);
	maximum[NTFS_USN_MAX_REASON_INPUTS - 1] = UINT32_C(0x00000200);
	assert(ntfs_usn_reason_union(maximum, NTFS_USN_MAX_REASON_INPUTS, &out) == NTFS_OK);
	assert(out == UINT32_C(0x81000200));
	free(maximum);
	out = TEST_SENTINEL;
	assert(ntfs_usn_reason_union(flags, NTFS_USN_MAX_REASON_INPUTS + 1, &out) == NTFS_RANGE);
	assert(ntfs_usn_reason_union(flags, SIZE_MAX, &out) == NTFS_RANGE);
	assert(ntfs_usn_reason_union(NULL, 1, &out) == NTFS_INVALID);
	assert(ntfs_usn_reason_union((const void *)UINTPTR_MAX, 1, &out) == NTFS_INVALID);
	assert(ntfs_usn_reason_union(flags, sizeof(flags) / sizeof(*flags), &flags[1]) ==
	    NTFS_INVALID);
	assert(ntfs_usn_reason_union(flags, 1, NULL) == NTFS_INVALID);
	assert(ntfs_usn_reason_union(flags, 1, (void *)UINTPTR_MAX) == NTFS_INVALID);
	memset(&unaligned, TEST_SENTINEL, sizeof(unaligned));
	assert(ntfs_usn_reason_union((const void *)(unaligned.bytes + 1), 1, &out) == NTFS_INVALID);
	assert(ntfs_usn_reason_union(flags, 1, (void *)(unaligned.bytes + 1)) == NTFS_INVALID);
	sentinel(&unaligned, sizeof(unaligned));
	assert(out == TEST_SENTINEL && memcmp(flags, saved, sizeof(flags)) == 0);
}

int
main(void)
{
	golden(2, &golden_v2, sizeof(golden_v2), offsetof(struct fixture_v2, name));
	golden(3, &golden_v3, sizeof(golden_v3), offsetof(struct fixture_v3, name));
	malformed();
	offset_and_sequence();
	maximum_names();
	input_errors();
	aliases();
	reason_union();
	puts("USN V2/V3: independent wire goldens, byte bounds, alignment, UTF-16 spans, "
	     "versions, aliases, unchanged errors and explicit reason union passed");
	return 0;
}
