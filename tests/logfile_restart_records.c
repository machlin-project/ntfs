/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/logfile.h>
#include "fuzz_device.h"
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
	TEST_INPUT_BYTES = 2 * 1024 * 1024,
	TEST_GUARD_BYTES = 32,
	TEST_GUARD_BYTE = 0xa5
};

struct guarded_restart {
	uint8_t before[TEST_GUARD_BYTES];
	struct ntfs_logfile_client_restart value;
	uint8_t after[TEST_GUARD_BYTES];
};

static void
guard(const uint8_t *bytes, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++) {
		assert(bytes[i] == TEST_GUARD_BYTE);
	}
}

static void
filename(char **text, char *out, size_t capacity)
{
	char *end = strchr(*text, '\t');
	size_t size;

	assert(end != NULL);
	size = (size_t)(end - *text);
	assert(size > 0 && size < capacity);
	memcpy(out, *text, size);
	out[size] = '\0';
	*text = end + 1;
}

static uint8_t *
read_file(const char *directory, const char *name, size_t *size)
{
	char path[TEST_PATH_BYTES];
	FILE *file;
	long length;
	uint8_t *bytes;
	int written;

	written = snprintf(path, sizeof(path), "%s/%s", directory, name);
	assert(written > 0 && (size_t)written < sizeof(path));
	file = fopen(path, "rb");
	assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
	length = ftell(file);
	assert(length >= 0 && length <= TEST_INPUT_BYTES && fseek(file, 0, SEEK_SET) == 0);
	*size = (size_t)length;
	bytes = malloc(*size == 0 ? 1 : *size);
	assert(bytes != NULL && fread(bytes, 1, *size, file) == *size && fclose(file) == 0);
	return bytes;
}

int
main(int argc, char **argv)
{
	char path[TEST_PATH_BYTES], source_name[TEST_NAME_BYTES], record_name[TEST_NAME_BYTES];
	char line[TEST_LINE_BYTES], *fields_text;
	FILE *cases;
	struct ntfs_logfile *source;
	struct ntfs_environment environment;
	struct fuzz_device device;
	struct ntfs_logfile_client_restart expected, zero = {0};
	struct guarded_restart output;
	uint8_t *journal, *backup, *record, *allocation, *input;
	size_t source_bytes, record_bytes, reads, allocations, memory, shift, leading, verdicts = 0;
	unsigned code;
	int written, fields;

	assert(argc == 2);
	written = snprintf(path, sizeof(path), "%s/cases.tsv", argv[1]);
	assert(written > 0 && (size_t)written < sizeof(path));
	cases = fopen(path, "r");
	assert(cases != NULL);
	while (fgets(line, sizeof(line), cases) != NULL) {
		fields_text = line;
		filename(&fields_text, source_name, sizeof(source_name));
		filename(&fields_text, record_name, sizeof(record_name));
		memset(&expected, 0, sizeof(expected));
		fields = sscanf(fields_text,
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
		journal = read_file(argv[1], source_name, &source_bytes);
		backup = malloc(source_bytes);
		assert(backup != NULL);
		memcpy(backup, journal, source_bytes);
		device = (struct fuzz_device){.data = journal, .size = source_bytes};
		environment = fuzz_environment(&device);
		assert(ntfs_logfile_open(&environment, NULL, NULL, &source) == NTFS_OK);
		record = read_file(argv[1], record_name, &record_bytes);
		allocation = malloc(record_bytes + 2 * TEST_GUARD_BYTES + 1);
		assert(allocation != NULL);
		reads = device.reads;
		allocations = device.allocations;
		memory = device.memory;
		device.fail_read = reads + 1;
		device.fail_allocation = allocations + 1;
		for (shift = 0; shift <= 1; shift++) {
			leading = TEST_GUARD_BYTES + shift;
			memset(
			    allocation, TEST_GUARD_BYTE, record_bytes + 2 * TEST_GUARD_BYTES + 1);
			input = allocation + leading;
			memcpy(input, record, record_bytes);
			memset(&output, TEST_GUARD_BYTE, sizeof(output));
			assert((unsigned)ntfs_logfile_decode_client_restart_record(
				   source, input, record_bytes, &output.value) == code);
			assert(memcmp(&output.value, &expected, sizeof(expected)) == 0);
			assert(memcmp(input, record, record_bytes) == 0);
			guard(allocation, leading);
			guard(input + record_bytes, TEST_GUARD_BYTES);
			guard(output.before, sizeof(output.before));
			guard(output.after, sizeof(output.after));
			assert(device.reads == reads && device.allocations == allocations &&
			    device.memory == memory && memcmp(journal, backup, source_bytes) == 0);
		}
		memset(&output, TEST_GUARD_BYTE, sizeof(output));
		assert(ntfs_logfile_decode_client_restart_record(source, NULL, 0, &output.value) ==
			NTFS_INVALID &&
		    memcmp(&output.value, &zero, sizeof(zero)) == 0);
		assert(ntfs_logfile_decode_client_restart_record(
			   NULL, record, record_bytes, &output.value) == NTFS_INVALID &&
		    memcmp(&output.value, &zero, sizeof(zero)) == 0);
		assert(ntfs_logfile_decode_client_restart_record(
			   source, record, record_bytes, NULL) == NTFS_INVALID);
		guard(output.before, sizeof(output.before));
		guard(output.after, sizeof(output.after));
		assert(device.reads == reads && device.allocations == allocations &&
		    device.memory == memory);
		ntfs_logfile_close(source);
		assert(device.memory == 0 && memcmp(journal, backup, source_bytes) == 0);
		free(allocation);
		free(record);
		free(backup);
		free(journal);
		verdicts++;
	}
	assert(feof(cases) && fclose(cases) == 0 && verdicts != 0);
	printf("PASS: %zu selected-client restart-record verdicts, aligned/unaligned exact bytes, "
	       "cached type/identity/name/LSN gates, zero outputs/guards and no I/O/allocation; "
	       "no current-history/recovery acceptance\n",
	    verdicts);
	return 0;
}
