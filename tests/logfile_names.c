/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/logfile_tables.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_WHOLE,
	TEST_ENTRY,
	TEST_PATH_BYTES = 1024,
	TEST_NAME_BYTES = 128,
	TEST_GUARD_BYTES = 32,
	TEST_UNALIGNED_OFFSET = 1,
	TEST_SENTINEL = 0xa5,
	TEST_VALUES = 5
};

union decoded {
	struct ntfs_logfile_attribute_name entry;
	struct ntfs_logfile_attribute_names names;
};

static void
filled(const uint8_t *bytes, size_t size)
{
	size_t index;

	for (index = 0; index < size; index++) {
		assert(bytes[index] == TEST_SENTINEL);
	}
}

static enum ntfs_result
decode(unsigned kind, const void *bytes, size_t size, union decoded *out)
{
	size_t used = kind == TEST_WHOLE ? sizeof(out->names) : sizeof(out->entry);
	enum ntfs_result result;

	memset(out, TEST_SENTINEL, sizeof(*out));
	result = kind == TEST_WHOLE ? ntfs_logfile_attribute_names_decode(bytes, size, &out->names)
				    : ntfs_logfile_attribute_name_decode(bytes, size, &out->entry);
	memset((uint8_t *)out + used, 0, sizeof(*out) - used);
	return result;
}

int
main(int argc, char **argv)
{
	union decoded out, repeated, zero = {0};
	struct ntfs_logfile_attribute_name entry;
	FILE *cases, *file;
	char path[TEST_PATH_BYTES], name[TEST_NAME_BYTES], scan[TEST_NAME_BYTES];
	uint8_t *guarded, *original, *bytes;
	uint32_t golden[TEST_VALUES], observed[TEST_VALUES];
	size_t prefix = TEST_GUARD_BYTES + TEST_UNALIGNED_OFFSET;
	size_t capacity =
	    NTFS_LOGFILE_MAX_RECORD_BYTES + TEST_GUARD_BYTES * 2 + TEST_UNALIGNED_OFFSET;
	size_t size = 0, index, offset, entries, count = 0;
	long length;
	unsigned kind, code;
	enum ntfs_result result;

	assert(argc == 2 && snprintf(path, sizeof(path), "%s/cases.tsv", argv[1]) > 0);
	assert(snprintf(scan, sizeof(scan), "%%%zus %%u %%u", sizeof(name) - 1) > 0);
	cases = fopen(path, "r");
	assert(cases != NULL);
	guarded = malloc(capacity);
	original = malloc(capacity);
	assert(guarded != NULL && original != NULL);
	bytes = guarded + prefix;
	while (fscanf(cases, scan, name, &kind, &code) == 3) {
		assert(kind == TEST_WHOLE || kind == TEST_ENTRY);
		assert(snprintf(path, sizeof(path), "%s/%s.input", argv[1], name) > 0);
		file = fopen(path, "rb");
		assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
		length = ftell(file);
		assert(length > 0 && length <= NTFS_LOGFILE_MAX_RECORD_BYTES);
		size = (size_t)length;
		memset(guarded, TEST_SENTINEL, capacity);
		assert(fseek(file, 0, SEEK_SET) == 0 && fread(bytes, 1, size, file) == size);
		assert(fclose(file) == 0);
		memcpy(original, guarded, capacity);
		assert(snprintf(path, sizeof(path), "%s/%s.expected", argv[1], name) > 0);
		file = fopen(path, "r");
		assert(file != NULL);
		for (index = 0; index < TEST_VALUES; index++) {
			assert(fscanf(file, "%u", &golden[index]) == 1);
		}
		assert(fclose(file) == 0);
		result = decode(kind, bytes, size, &out);
		if (result != (enum ntfs_result)code) {
			fprintf(
			    stderr, "%s: expected %u, observed %u\n", name, code, (unsigned)result);
		}
		assert(result == (enum ntfs_result)code);
		assert(decode(kind, bytes, size, &repeated) == result);
		assert(memcmp(&out, &repeated, sizeof(out)) == 0);
		memset(observed, 0, sizeof(observed));
		if (result == NTFS_OK && kind == TEST_ENTRY) {
			observed[0] = out.entry.target_attribute;
			observed[1] = out.entry.name_units;
			observed[2] = out.entry.bytes;
			observed[3] = out.entry.name.offset;
			observed[4] = out.entry.name.length;
		} else if (result == NTFS_OK) {
			observed[0] = out.names.entry_count;
			observed[1] = out.names.entries.offset;
			observed[2] = out.names.entries.length;
			offset = out.names.entries.offset;
			for (entries = 0; entries < out.names.entry_count; entries++) {
				assert(ntfs_logfile_attribute_name_decode(
					   bytes + offset, size - offset, &entry) == NTFS_OK);
				assert(entry.name.length ==
				    (uint32_t)entry.name_units * sizeof(uint16_t));
				offset += entry.bytes;
			}
			assert(offset == out.names.entries.length);
			assert(ntfs_logfile_attribute_name_decode(
				   bytes + offset, size - offset, &entry) == NTFS_END);
		} else {
			assert(memcmp(&out, &zero, sizeof(out)) == 0);
		}
		assert(memcmp(golden, observed, sizeof(golden)) == 0);
		assert(memcmp(guarded, original, capacity) == 0);
		filled(guarded, prefix);
		filled(bytes + size, capacity - prefix - size);
		count++;
	}
	assert(feof(cases) && count != 0 && fclose(cases) == 0);
	for (kind = TEST_WHOLE; kind <= TEST_ENTRY; kind++) {
		assert(decode(kind, NULL, 0, &out) == NTFS_INVALID);
		assert(memcmp(&out, &zero, sizeof(out)) == 0);
		assert(decode(kind, bytes, 0, &out) == NTFS_CORRUPT);
		assert(memcmp(&out, &zero, sizeof(out)) == 0);
		assert(decode(kind, bytes, NTFS_LOGFILE_MAX_RECORD_BYTES + 1u, &out) == NTFS_RANGE);
		assert(memcmp(&out, &zero, sizeof(out)) == 0);
	}
	assert(ntfs_logfile_attribute_name_decode(bytes, size, NULL) == NTFS_INVALID);
	assert(ntfs_logfile_attribute_names_decode(bytes, size, NULL) == NTFS_INVALID);
	free(original);
	free(guarded);
	printf("PASS: %zu original byte-counted name packets, unaligned lossless spans, exact "
	       "terminators, bounded complete traversal and unchanged inputs\n",
	    count);
	return 0;
}
