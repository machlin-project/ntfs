/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/checkpoint.h>
#include "fuzz_device.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_PATH_BYTES = 1024,
	TEST_NAME_BYTES = 128,
	TEST_SCAN_BYTES = 128,
	TEST_COLUMNS = 6,
	TEST_FIELDS = 16,
	/* Logical sources include the original three-MiB historical journals. */
	TEST_INPUT_BYTES = 4 * 1024 * 1024,
	TEST_GUARD_BYTES = 32,
	TEST_GUARD_BYTE = 0xa5,
	TEST_UNALIGNED_BYTES = 1
};

struct guarded_table {
	uint8_t before[TEST_GUARD_BYTES];
	struct ntfs_logfile_checkpoint_table value;
	uint8_t after[TEST_GUARD_BYTES];
};

static void
guard(const uint8_t *bytes, size_t size)
{
	size_t index;

	for (index = 0; index < size; index++) {
		assert(bytes[index] == TEST_GUARD_BYTE);
	}
}

static uint8_t *
read_file(const char *directory, const char *name, const char *suffix, size_t *size)
{
	char path[TEST_PATH_BYTES];
	FILE *file;
	uint8_t *bytes;
	long length;
	int written;

	written = snprintf(path, sizeof(path), "%s/%s%s", directory, name, suffix);
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

static void
values(const struct ntfs_logfile_checkpoint_table *table, uint64_t *out)
{
	const uint64_t fields[] = {table->kind, table->client_major, table->client_minor,
	    table->checkpoint_lsn, table->table_lsn, table->body.offset, table->body.length,
	    table->table.entry_bytes, table->table.entry_count, table->table.allocated_count,
	    table->table.free_goal, table->table.first_free, table->table.last_free,
	    table->kind == NTFS_LOGFILE_CHECKPOINT_ATTRIBUTE_NAMES ? table->names.entries.offset
								   : table->table.entries.offset,
	    table->kind == NTFS_LOGFILE_CHECKPOINT_ATTRIBUTE_NAMES ? table->names.entries.length
								   : table->table.entries.length,
	    table->names.entry_count};

	_Static_assert(
	    sizeof(fields) == TEST_FIELDS * sizeof(*fields), "checkpoint numeric oracle");
	memcpy(out, fields, sizeof(fields));
}

int
main(int argc, char **argv)
{
	char path[TEST_PATH_BYTES], name[TEST_NAME_BYTES], source_name[TEST_NAME_BYTES];
	char checkpoint_name[TEST_NAME_BYTES], table_name[TEST_NAME_BYTES], scan[TEST_SCAN_BYTES];
	struct guarded_table output, repeated;
	struct ntfs_logfile_checkpoint_table zero = {0};
	struct ntfs_logfile *source;
	struct ntfs_environment environment;
	struct fuzz_device device;
	FILE *cases, *expected_file;
	uint8_t *journal, *unchanged, *checkpoint, *table, *guarded_checkpoint, *guarded_input;
	uint64_t expected[TEST_FIELDS], observed[TEST_FIELDS];
	size_t source_bytes, checkpoint_bytes, table_bytes, reads, allocations, memory;
	size_t shift, prefix, index, count = 0;
	unsigned kind, code;
	int written;
	enum ntfs_result result;

	assert(argc == 2);
	written = snprintf(path, sizeof(path), "%s/cases.tsv", argv[1]);
	assert(written > 0 && (size_t)written < sizeof(path));
	written =
	    snprintf(scan, sizeof(scan), "%%%zus %%%zus %%%zus %%%zus %%u %%u", sizeof(name) - 1,
		sizeof(source_name) - 1, sizeof(checkpoint_name) - 1, sizeof(table_name) - 1);
	assert(written > 0 && (size_t)written < sizeof(scan));
	cases = fopen(path, "r");
	assert(cases != NULL);
	while (fscanf(cases, scan, name, source_name, checkpoint_name, table_name, &kind, &code) ==
	    TEST_COLUMNS) {
		journal = read_file(argv[1], source_name, "", &source_bytes);
		unchanged = malloc(source_bytes);
		assert(unchanged != NULL);
		memcpy(unchanged, journal, source_bytes);
		device = (struct fuzz_device){.data = journal, .size = source_bytes};
		environment = fuzz_environment(&device);
		assert(ntfs_logfile_open(&environment, NULL, NULL, &source) == NTFS_OK);
		checkpoint = read_file(argv[1], checkpoint_name, "", &checkpoint_bytes);
		table = read_file(argv[1], table_name, "", &table_bytes);
		guarded_checkpoint =
		    malloc(checkpoint_bytes + 2 * TEST_GUARD_BYTES + TEST_UNALIGNED_BYTES);
		guarded_input = malloc(table_bytes + 2 * TEST_GUARD_BYTES + TEST_UNALIGNED_BYTES);
		assert(guarded_checkpoint != NULL && guarded_input != NULL);
		written = snprintf(path, sizeof(path), "%s/%s.expected", argv[1], name);
		assert(written > 0 && (size_t)written < sizeof(path));
		expected_file = fopen(path, "r");
		assert(expected_file != NULL);
		for (index = 0; index < TEST_FIELDS; index++) {
			assert(fscanf(expected_file, "%" SCNu64, &expected[index]) == 1);
		}
		assert(fscanf(expected_file, "%" SCNu64, &observed[0]) == EOF &&
		    fclose(expected_file) == 0);
		reads = device.reads;
		allocations = device.allocations;
		memory = device.memory;
		device.fail_read = reads + 1;
		device.fail_allocation = allocations + 1;
		for (shift = 0; shift <= TEST_UNALIGNED_BYTES; shift++) {
			prefix = TEST_GUARD_BYTES + shift;
			memset(guarded_checkpoint, TEST_GUARD_BYTE,
			    checkpoint_bytes + 2 * TEST_GUARD_BYTES + TEST_UNALIGNED_BYTES);
			memset(guarded_input, TEST_GUARD_BYTE,
			    table_bytes + 2 * TEST_GUARD_BYTES + TEST_UNALIGNED_BYTES);
			memcpy(guarded_checkpoint + prefix, checkpoint, checkpoint_bytes);
			memcpy(guarded_input + prefix, table, table_bytes);
			memset(&output, TEST_GUARD_BYTE, sizeof(output));
			memset(&repeated, TEST_GUARD_BYTE, sizeof(repeated));
			result = ntfs_logfile_checkpoint_table_decode(source,
			    (enum ntfs_logfile_checkpoint_kind)kind, guarded_checkpoint + prefix,
			    checkpoint_bytes, guarded_input + prefix, table_bytes, &output.value);
			assert(ntfs_logfile_checkpoint_table_decode(source,
				   (enum ntfs_logfile_checkpoint_kind)kind,
				   guarded_checkpoint + prefix, checkpoint_bytes,
				   guarded_input + prefix, table_bytes, &repeated.value) == result);
			values(&output.value, observed);
			if ((unsigned)result != code ||
			    memcmp(expected, observed, sizeof(expected)) != 0) {
				fprintf(stderr, "%s: expected %u, observed %u\n", name, code,
				    (unsigned)result);
			}
			assert((unsigned)result == code &&
			    memcmp(expected, observed, sizeof(expected)) == 0);
			assert(memcmp(&output.value, &repeated.value, sizeof(output.value)) == 0);
			if (result != NTFS_OK) {
				assert(memcmp(&output.value, &zero, sizeof(zero)) == 0);
			} else {
				assert(output.value.body.offset <= table_bytes &&
				    output.value.body.length <=
					table_bytes - output.value.body.offset);
			}
			assert(
			    memcmp(guarded_checkpoint + prefix, checkpoint, checkpoint_bytes) == 0);
			assert(memcmp(guarded_input + prefix, table, table_bytes) == 0);
			guard(guarded_checkpoint, prefix);
			guard(guarded_checkpoint + prefix + checkpoint_bytes, TEST_GUARD_BYTES);
			guard(guarded_input, prefix);
			guard(guarded_input + prefix + table_bytes, TEST_GUARD_BYTES);
			guard(output.before, sizeof(output.before));
			guard(output.after, sizeof(output.after));
			guard(repeated.before, sizeof(repeated.before));
			guard(repeated.after, sizeof(repeated.after));
			assert(device.reads == reads && device.allocations == allocations &&
			    device.memory == memory);
		}
		if (code == NTFS_OK || code == NTFS_NOT_FOUND) {
			result = ntfs_logfile_checkpoint_table_decode(source,
			    (enum ntfs_logfile_checkpoint_kind)kind, checkpoint, checkpoint_bytes,
			    NULL, TEST_INPUT_BYTES, &output.value);
			assert(result == (code == NTFS_OK ? NTFS_INVALID : NTFS_NOT_FOUND));
			assert(memcmp(&output.value, &zero, sizeof(zero)) == 0);
		}
		assert(ntfs_logfile_checkpoint_table_decode(NULL,
			   NTFS_LOGFILE_CHECKPOINT_OPEN_ATTRIBUTES, checkpoint, checkpoint_bytes,
			   table, table_bytes, &output.value) == NTFS_INVALID);
		assert(memcmp(&output.value, &zero, sizeof(zero)) == 0);
		assert(ntfs_logfile_checkpoint_table_decode(source,
			   (enum ntfs_logfile_checkpoint_kind) - 1, checkpoint, checkpoint_bytes,
			   table, table_bytes, &output.value) == NTFS_INVALID);
		assert(memcmp(&output.value, &zero, sizeof(zero)) == 0);
		assert(ntfs_logfile_checkpoint_table_decode(source,
			   NTFS_LOGFILE_CHECKPOINT_OPEN_ATTRIBUTES, NULL, 0, table, table_bytes,
			   &output.value) == NTFS_INVALID);
		assert(memcmp(&output.value, &zero, sizeof(zero)) == 0);
		assert(ntfs_logfile_checkpoint_table_decode(source,
			   (enum ntfs_logfile_checkpoint_kind)kind, checkpoint, checkpoint_bytes,
			   table, table_bytes, NULL) == NTFS_INVALID);
		assert(device.reads == reads && device.allocations == allocations &&
		    device.memory == memory);
		ntfs_logfile_close(source);
		assert(device.memory == 0 && memcmp(journal, unchanged, source_bytes) == 0);
		free(guarded_input);
		free(guarded_checkpoint);
		free(table);
		free(checkpoint);
		free(unchanged);
		free(journal);
		count++;
	}
	assert(feof(cases) && fclose(cases) == 0 && count != 0);
	printf("PASS: %zu selected checkpoint dump bindings, complete allocated/free framing, "
	       "aligned/unaligned immutable inputs, exact borrowed spans, guarded zero outputs and "
	       "no I/O/allocation; "
	       "no current history or recovery qualification\n",
	    count);
	return 0;
}
