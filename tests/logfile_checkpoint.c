/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/logfile.h>
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_PATH_BYTES = 1024,
	TEST_NAME_BYTES = 128,
	TEST_LINE_BYTES = 2048,
	TEST_EXPECTED_FIELDS = 14,
	TEST_GUARD_BYTES = 32,
	TEST_GUARD_BYTE = 0xa5,
	TEST_PACKET_CAP = 1024 * 1024
};

struct guarded_output {
	uint8_t before[TEST_GUARD_BYTES];
	struct ntfs_logfile_client_restart value;
	uint8_t after[TEST_GUARD_BYTES];
};

static void
poison(const uint8_t *bytes, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++) {
		assert(bytes[i] == TEST_GUARD_BYTE);
	}
}

int
main(int argc, char **argv)
{
	char path[TEST_PATH_BYTES], name[TEST_NAME_BYTES], line[TEST_LINE_BYTES];
	char *fields_text;
	FILE *cases, *packet;
	struct ntfs_logfile_client_restart expected, zero = {0};
	struct guarded_output output;
	uint8_t *original, *allocation, *input;
	long fileBytes;
	size_t size, shift, leading, name_bytes, verdicts = 0;
	unsigned code;
	int written, fields;

	assert(argc == 2);
	written = snprintf(path, sizeof(path), "%s/cases.tsv", argv[1]);
	assert(written > 0 && (size_t)written < sizeof(path));
	cases = fopen(path, "r");
	assert(cases != NULL);
	while (fgets(line, sizeof(line), cases) != NULL) {
		fields_text = strchr(line, '\t');
		assert(fields_text != NULL);
		name_bytes = (size_t)(fields_text - line);
		assert(name_bytes > 0 && name_bytes < sizeof(name));
		memcpy(name, line, name_bytes);
		name[name_bytes] = '\0';
		memset(&expected, 0, sizeof(expected));
		fields = sscanf(fields_text + 1,
		    "%u %" SCNu32 " %" SCNu32 " %" SCNu64 " %" SCNu64 " %" SCNu32 " %" SCNu64
		    " %" SCNu32 " %" SCNu64 " %" SCNu32 " %" SCNu64 " %" SCNu32 " %" SCNu32
		    " %" SCNu32,
		    &code, &expected.major, &expected.minor, &expected.analysis_lsn,
		    &expected.open_attributes.lsn, &expected.open_attributes.bytes,
		    &expected.attribute_names.lsn, &expected.attribute_names.bytes,
		    &expected.dirty_pages.lsn, &expected.dirty_pages.bytes,
		    &expected.transactions.lsn, &expected.transactions.bytes,
		    &expected.extension.offset, &expected.extension.length);
		assert(fields == TEST_EXPECTED_FIELDS);
		written = snprintf(path, sizeof(path), "%s/%s", argv[1], name);
		assert(written > 0 && (size_t)written < sizeof(path));
		packet = fopen(path, "rb");
		assert(packet != NULL && fseek(packet, 0, SEEK_END) == 0);
		fileBytes = ftell(packet);
		assert(fileBytes >= 0 && fileBytes <= TEST_PACKET_CAP + 1);
		size = (size_t)fileBytes;
		original = malloc(size == 0 ? 1 : size);
		allocation = malloc(size + 2 * TEST_GUARD_BYTES + 1);
		assert(original != NULL && allocation != NULL && fseek(packet, 0, SEEK_SET) == 0);
		assert(fread(original, 1, size, packet) == size && fclose(packet) == 0);
		for (shift = 0; shift <= 1; shift++) {
			leading = TEST_GUARD_BYTES + shift;
			input = allocation + leading;
			memset(allocation, TEST_GUARD_BYTE, size + 2 * TEST_GUARD_BYTES + 1);
			memcpy(input, original, size);
			memset(&output, TEST_GUARD_BYTE, sizeof(output));
			assert((unsigned)ntfs_logfile_client_restart_decode(
				   input, size, &output.value) == code);
			assert(memcmp(&output.value, &expected, sizeof(expected)) == 0);
			assert(memcmp(input, original, size) == 0);
			poison(allocation, leading);
			poison(input + size, TEST_GUARD_BYTES);
			poison(output.before, sizeof(output.before));
			poison(output.after, sizeof(output.after));
		}
		free(allocation);
		free(original);
		verdicts++;
	}
	assert(feof(cases) && fclose(cases) == 0);
	memset(&output, TEST_GUARD_BYTE, sizeof(output));
	assert(ntfs_logfile_client_restart_decode(NULL, 0, &output.value) == NTFS_INVALID);
	assert(memcmp(&output.value, &zero, sizeof(zero)) == 0);
	poison(output.before, sizeof(output.before));
	poison(output.after, sizeof(output.after));
	assert(ntfs_logfile_client_restart_decode(&zero, sizeof(zero), NULL) == NTFS_INVALID);
	printf("PASS: %zu NTFS client restart-prefix verdicts, aligned/unaligned input, "
	       "raw boundary fields, opaque tails, truncations, guards and immutable bytes\n",
	    verdicts);
	return 0;
}
