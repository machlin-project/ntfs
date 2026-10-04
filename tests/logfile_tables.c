/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/logfile_tables.h>
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_PATH_BYTES = 4096,
	TEST_NAME_BYTES = 96,
	TEST_SCAN_FORMAT_BYTES = 64,
	TEST_CASE_COLUMNS = 5,
	TEST_SUMMARY_VALUES = 12,
	TEST_GUARD_BYTES = 1,
	TEST_GUARD = 0xa5
};

enum test_kind { TABLE_KIND = 0, OPEN_KIND = 1, DIRTY_KIND = 2, TRANSACTION_KIND = 3 };

static FILE *
open_case(const char *directory, const char *name, const char *suffix)
{
	char path[TEST_PATH_BYTES];
	FILE *file;
	int written;

	written = snprintf(path, sizeof(path), "%s/%s%s", directory, name, suffix);
	assert(written > 0 && (size_t)written < sizeof(path));
	file = fopen(path, "rb");
	assert(file != NULL);
	return file;
}

static void
zero_bytes(const void *bytes, size_t size)
{
	const uint8_t *value = bytes;
	size_t index;

	for (index = 0; index < size; index++) {
		assert(value[index] == 0);
	}
}

static void
table_values(const struct ntfs_logfile_restart_table *table, uint64_t *values)
{
	const uint64_t decoded[] = {table->entry_bytes, table->entry_count, table->allocated_count,
	    table->free_goal, table->first_free, table->last_free, table->entries.offset,
	    table->entries.length};

	memcpy(values, decoded, sizeof(decoded));
}

static void
open_values(const struct ntfs_logfile_open_attribute *attribute, uint64_t *values)
{
	const uint64_t decoded[] = {attribute->reference, attribute->open_lsn,
	    attribute->attribute_type, attribute->index_buffer_bytes,
	    attribute->legacy_attribute_offset, attribute->dirty_pages_known,
	    attribute->dirty_pages};

	memcpy(values, decoded, sizeof(decoded));
}

static void
dirty_values(const struct ntfs_logfile_dirty_page *page, uint64_t *values)
{
	const uint64_t decoded[] = {page->vcn, page->oldest_lsn, page->target_attribute,
	    page->transfer_bytes, page->lcn_count, page->lcns.offset, page->lcns.length,
	    page->unused.offset, page->unused.length};

	memcpy(values, decoded, sizeof(decoded));
}

static void
transaction_values(const struct ntfs_logfile_transaction *transaction, uint64_t *values)
{
	const uint64_t decoded[] = {transaction->first_lsn, transaction->previous_lsn,
	    transaction->undo_next_lsn, transaction->undo_records, transaction->undo_bytes,
	    transaction->state};

	memcpy(values, decoded, sizeof(decoded));
}

static enum ntfs_result
decode(
    unsigned kind, const void *input, size_t size, unsigned major, unsigned minor, uint64_t *values)
{
	union {
		struct ntfs_logfile_restart_table table;
		struct ntfs_logfile_open_attribute attribute;
		struct ntfs_logfile_dirty_page page;
		struct ntfs_logfile_transaction transaction;
	} output;
	enum ntfs_result result;

	memset(&output, TEST_GUARD, sizeof(output));
	memset(values, 0, TEST_SUMMARY_VALUES * sizeof(*values));
	switch (kind) {
	case TABLE_KIND:
		result = ntfs_logfile_restart_table_decode(input, size, &output.table);
		if (result != NTFS_OK) {
			zero_bytes(&output.table, sizeof(output.table));
		}
		table_values(&output.table, values);
		return result;
	case OPEN_KIND:
		result = ntfs_logfile_open_attribute_decode(
		    input, size, major, minor, &output.attribute);
		if (result != NTFS_OK) {
			zero_bytes(&output.attribute, sizeof(output.attribute));
		}
		open_values(&output.attribute, values);
		return result;
	case DIRTY_KIND:
		result = ntfs_logfile_dirty_page_decode(input, size, major, minor, &output.page);
		if (result != NTFS_OK) {
			zero_bytes(&output.page, sizeof(output.page));
		}
		dirty_values(&output.page, values);
		return result;
	case TRANSACTION_KIND:
		result = ntfs_logfile_transaction_decode(input, size, &output.transaction);
		if (result != NTFS_OK) {
			zero_bytes(&output.transaction, sizeof(output.transaction));
		}
		transaction_values(&output.transaction, values);
		return result;
	default:
		abort();
	}
}

static void
check_case(const char *directory, const char *name, unsigned kind, unsigned major, unsigned minor,
    unsigned code)
{
	FILE *input_file, *expected_file;
	uint8_t *input, *unchanged;
	uint64_t expected[TEST_SUMMARY_VALUES], actual[TEST_SUMMARY_VALUES];
	size_t size, index;
	long length;
	enum ntfs_result result;

	input_file = open_case(directory, name, ".input");
	assert(fseek(input_file, 0, SEEK_END) == 0);
	length = ftell(input_file);
	assert(length >= 0 && fseek(input_file, 0, SEEK_SET) == 0);
	size = (size_t)length;
	input = malloc(size + 2 * TEST_GUARD_BYTES);
	unchanged = malloc(size + 2 * TEST_GUARD_BYTES);
	assert(input != NULL && unchanged != NULL);
	memset(input, TEST_GUARD, size + 2 * TEST_GUARD_BYTES);
	assert(fread(input + TEST_GUARD_BYTES, 1, size, input_file) == size);
	assert(fclose(input_file) == 0);
	memcpy(unchanged, input, size + 2 * TEST_GUARD_BYTES);
	expected_file = open_case(directory, name, ".expected");
	for (index = 0; index < TEST_SUMMARY_VALUES; index++) {
		assert(fscanf(expected_file, "%" SCNu64, &expected[index]) == 1);
	}
	assert(fscanf(expected_file, "%" SCNu64, &actual[0]) == EOF);
	assert(feof(expected_file) && fclose(expected_file) == 0);
	result = decode(kind, input + TEST_GUARD_BYTES, size, major, minor, actual);
	if ((unsigned)result != code || memcmp(expected, actual, sizeof(expected)) != 0) {
		fprintf(
		    stderr, "%s: expected result %u, actual %u\n", name, code, (unsigned)result);
		for (index = 0; index < TEST_SUMMARY_VALUES; index++) {
			fprintf(stderr, "  field %zu: expected %" PRIu64 ", actual %" PRIu64 "\n",
			    index, expected[index], actual[index]);
		}
		abort();
	}
	assert(memcmp(input, unchanged, size + 2 * TEST_GUARD_BYTES) == 0);
	free(unchanged);
	free(input);
}

static void
check_arguments(void)
{
	uint64_t values[TEST_SUMMARY_VALUES];
	unsigned kind;

	for (kind = TABLE_KIND; kind <= TRANSACTION_KIND; kind++) {
		assert(decode(kind, NULL, 0, 0, 0, values) == NTFS_INVALID);
		zero_bytes(values, sizeof(values));
	}
	assert(ntfs_logfile_restart_table_decode(NULL, 0, NULL) == NTFS_INVALID);
	assert(ntfs_logfile_open_attribute_decode(NULL, 0, 0, 0, NULL) == NTFS_INVALID);
	assert(ntfs_logfile_dirty_page_decode(NULL, 0, 0, 0, NULL) == NTFS_INVALID);
	assert(ntfs_logfile_transaction_decode(NULL, 0, NULL) == NTFS_INVALID);
}

int
main(int argc, char **argv)
{
	char name[TEST_NAME_BYTES], format[TEST_SCAN_FORMAT_BYTES];
	FILE *cases;
	size_t case_count = 0;
	unsigned kind, major, minor, code;
	int written, scanned;

	assert(argc == 2);
	cases = open_case(argv[1], "cases", ".tsv");
	written = snprintf(format, sizeof(format), "%%%zus %%u %%u %%u %%u", sizeof(name) - 1);
	assert(written > 0 && (size_t)written < sizeof(format));
	while ((scanned = fscanf(cases, format, name, &kind, &major, &minor, &code)) ==
	    TEST_CASE_COLUMNS) {
		check_case(argv[1], name, kind, major, minor, code);
		case_count++;
	}
	assert(scanned == EOF && feof(cases) && fclose(cases) == 0);
	check_arguments();
	printf("PASS: %zu independent native checkpoint vectors, complete free topology, "
	       "maximum entry count, client versions, stale free payloads and unchanged inputs\n",
	    case_count);
	return 0;
}
