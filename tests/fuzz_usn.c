/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "usn.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	FUZZ_USN_MAX_BYTES = 128 * 1024,
	FUZZ_GUARD_BYTES = 16,
	FUZZ_GUARD = 0xa5,
	FUZZ_ALIGNMENT = 8,
	FUZZ_BITS_PER_BYTE = 8
};

/* Independent test layout; no core wire declaration or endian helper authors
 * the standalone inputs or calculates the expected canonical name position. */
struct fuzz_usn_fields {
	uint8_t usn[8], time[8], reason[4], source[4], security[4], attributes[4];
	uint8_t name_bytes[2], name_offset[2];
};

struct fuzz_usn_v2 {
	uint8_t length[4], major[2], minor[2], file[8], parent[8];
	struct fuzz_usn_fields fields;
};

struct fuzz_usn_v3 {
	uint8_t length[4], major[2], minor[2], file[16], parent[16];
	struct fuzz_usn_fields fields;
};

static void
guard(const void *input, size_t count)
{
	const uint8_t *bytes = input;
	size_t index;

	for (index = 0; index < count; index++) {
		assert(bytes[index] == FUZZ_GUARD);
	}
}

static uint64_t
little(const uint8_t *bytes, size_t count)
{
	uint64_t value = 0;
	size_t index;

	assert(count <= sizeof(value));
	for (index = count; index != 0; index--) {
		value = value * 256 + bytes[index - 1];
	}
	return value;
}

static void
verify_wire_values(const uint8_t *bytes, const struct ntfs_usn_view *view)
{
	const struct fuzz_usn_fields *fields;
	const uint8_t *file, *parent;
	size_t prefix, id_bytes, index;

	if (view->record.major_version == 2) {
		const struct fuzz_usn_v2 *wire = (const void *)bytes;

		prefix = sizeof(*wire);
		fields = &wire->fields;
		file = wire->file;
		parent = wire->parent;
		id_bytes = sizeof(wire->file);
		assert(view->record_bytes == little(wire->length, sizeof(wire->length)));
		assert(view->record.major_version == little(wire->major, sizeof(wire->major)));
		assert(view->record.minor_version == little(wire->minor, sizeof(wire->minor)));
	} else {
		const struct fuzz_usn_v3 *wire = (const void *)bytes;

		assert(view->record.major_version == 3);
		prefix = sizeof(*wire);
		fields = &wire->fields;
		file = wire->file;
		parent = wire->parent;
		id_bytes = sizeof(wire->file);
		assert(view->record_bytes == little(wire->length, sizeof(wire->length)));
		assert(view->record.major_version == little(wire->major, sizeof(wire->major)));
		assert(view->record.minor_version == little(wire->minor, sizeof(wire->minor)));
	}
	assert(view->filename_offset >= prefix);
	assert(memcmp(view->record.file_id, file, id_bytes) == 0);
	assert(memcmp(view->record.parent_id, parent, id_bytes) == 0);
	for (index = id_bytes; index < sizeof(view->record.file_id); index++) {
		assert(view->record.file_id[index] == 0 && view->record.parent_id[index] == 0);
	}
	assert(view->record.usn == little(fields->usn, sizeof(fields->usn)));
	assert(view->record.timestamp == little(fields->time, sizeof(fields->time)));
	assert(view->record.reason == little(fields->reason, sizeof(fields->reason)));
	assert(view->record.source_info == little(fields->source, sizeof(fields->source)));
	assert(view->record.security_id == little(fields->security, sizeof(fields->security)));
	assert(
	    view->record.file_attributes == little(fields->attributes, sizeof(fields->attributes)));
	assert(view->filename_offset == little(fields->name_offset, sizeof(fields->name_offset)));
	assert(
	    view->record.filename_bytes == little(fields->name_bytes, sizeof(fields->name_bytes)));
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct ntfs_usn_view first, second, canonical, expected_view;
	uint8_t *copy, *output, *again;
	uint32_t reasons[2], combined;
	size_t alignment, required = SIZE_MAX, written = SIZE_MAX, done = SIZE_MAX;
	size_t prefix, expected, capacity, index;
	enum ntfs_result result, repeated;

	if (size > FUZZ_USN_MAX_BYTES) {
		return 0;
	}
	alignment = size == 0 ? 0 : data[0] % FUZZ_ALIGNMENT;
	copy = malloc(size + FUZZ_GUARD_BYTES);
	assert(copy != NULL);
	memset(copy, FUZZ_GUARD, size + FUZZ_GUARD_BYTES);
	if (size != 0) {
		memcpy(copy + alignment, data, size);
	}
	memset(&first, FUZZ_GUARD, sizeof(first));
	memset(&second, FUZZ_GUARD, sizeof(second));
	result = ntfs_usn_record_decode(copy + alignment, size, &first);
	repeated = ntfs_usn_record_decode(copy + alignment, size, &second);
	assert(result == repeated);
	assert(memcmp(&first, &second, sizeof(first)) == 0);
	if (result != NTFS_OK) {
		guard(&first, sizeof(first));
	} else {
		assert(first.record_bytes <= size && first.record_bytes % FUZZ_ALIGNMENT == 0);
		assert(first.record.minor_version == 0 && first.record.usn <= INT64_MAX);
		assert(first.filename_offset % sizeof(uint16_t) == 0);
		assert(first.record.filename_bytes % sizeof(uint16_t) == 0);
		assert(first.filename_offset <= first.record_bytes);
		assert(first.record.filename_bytes <= first.record_bytes - first.filename_offset);
		assert(first.record.filename == copy + alignment + first.filename_offset);
		verify_wire_values(copy + alignment, &first);
		prefix = first.record.major_version == 2 ? sizeof(struct fuzz_usn_v2)
							 : sizeof(struct fuzz_usn_v3);
		expected =
		    ((prefix + first.record.filename_bytes + FUZZ_ALIGNMENT - 1) / FUZZ_ALIGNMENT) *
		    FUZZ_ALIGNMENT;
		assert(ntfs_usn_record_size(&first.record, &required) == NTFS_OK);
		assert(required == expected && required <= first.record_bytes);
		output = malloc(required + FUZZ_GUARD_BYTES);
		again = malloc(required);
		assert(output != NULL && again != NULL);
		memset(output, FUZZ_GUARD, required + FUZZ_GUARD_BYTES);
		capacity = size % required;
		assert(ntfs_usn_record_encode(
			   &first.record, output + alignment, capacity, &written) == NTFS_RANGE);
		assert(written == SIZE_MAX);
		guard(output, required + FUZZ_GUARD_BYTES);
		assert(ntfs_usn_record_encode(
			   &first.record, output + alignment, required, &written) == NTFS_OK);
		assert(written == required);
		expected_view = first;
		expected_view.record_bytes = (uint32_t)required;
		expected_view.filename_offset = (uint16_t)prefix;
		verify_wire_values(output + alignment, &expected_view);
		guard(output, alignment);
		guard(output + alignment + written, FUZZ_GUARD_BYTES - alignment);
		assert(memcmp(output + alignment + prefix, first.record.filename,
			   first.record.filename_bytes) == 0);
		for (index = prefix + first.record.filename_bytes; index < required; index++) {
			assert(output[alignment + index] == 0);
		}
		assert(ntfs_usn_record_decode(output + alignment, written, &canonical) == NTFS_OK);
		assert(canonical.filename_offset == prefix);
		verify_wire_values(output + alignment, &canonical);
		assert(
		    ntfs_usn_record_encode(&canonical.record, again, required, &done) == NTFS_OK);
		assert(done == required && memcmp(output + alignment, again, required) == 0);
		reasons[0] = first.record.reason;
		reasons[1] = ~first.record.reason;
		assert(ntfs_usn_reason_union(
			   reasons, sizeof(reasons) / sizeof(*reasons), &combined) == NTFS_OK);
		assert(combined == UINT32_MAX);
		free(again);
		free(output);
	}
	if (size != 0) {
		assert(memcmp(copy + alignment, data, size) == 0);
	}
	guard(copy, alignment);
	guard(copy + alignment + size, FUZZ_GUARD_BYTES - alignment);
	free(copy);
	return 0;
}

#ifdef NTFS_FUZZ_STANDALONE
int
main(void)
{
	static const struct {
		struct fuzz_usn_v2 prefix;
		uint8_t name[2], padding[2];
	} v2 = {.prefix = {.length = {64},
		    .major = {2},
		    .fields = {.reason = {1}, .name_bytes = {2}, .name_offset = {60}}},
	    .name = {'A', 0}};

	static const struct {
		struct fuzz_usn_v3 prefix;
		uint8_t name[4];
	} v3 = {.prefix = {.length = {80},
		    .major = {3},
		    .fields = {.reason = {0, 0, 0, 0x80}, .name_bytes = {4}, .name_offset = {76}}},
	    .name = {0, 0xd8, 0, 0}};

	uint8_t bytes[sizeof(v3)], saved;
	size_t version, length, index, bit;

	for (version = 2; version <= 3; version++) {
		length = version == 2 ? sizeof(v2) : sizeof(v3);
		memcpy(bytes, version == 2 ? (const void *)&v2 : (const void *)&v3, length);
		(void)LLVMFuzzerTestOneInput(bytes, length);
		for (index = 0; index < length; index++) {
			(void)LLVMFuzzerTestOneInput(bytes, index);
			saved = bytes[index];
			for (bit = 0; bit < FUZZ_BITS_PER_BYTE; bit++) {
				bytes[index] = saved ^ (uint8_t)(1u << bit);
				(void)LLVMFuzzerTestOneInput(bytes, length);
			}
			bytes[index] = saved;
		}
	}
	puts("PASS: USN V2/V3 truncation and single-bit fuzz smoke inputs, independent fields, "
	     "canonical encoding and unchanged failures");
	return 0;
}
#endif
