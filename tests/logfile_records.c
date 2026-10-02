/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/logfile.h>
#include "fuzz_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_SOURCE_BYTES = 4 * 1024 * 1024,
	TEST_PATH_BYTES = 1024,
	TEST_GUARD_BYTES = 32,
	TEST_SENTINEL = 0xa5,
	TEST_PARTIAL_BYTE = 0x71,
	TEST_PARTIAL_DENOMINATOR = 2,
	TEST_CLIENT_SEQUENCE = 7,
	TEST_TRANSACTION = 24,
	TEST_CREDITS_EXACT = 0,
	TEST_CREDITS_SHORT_CALLS,
	TEST_CREDITS_SHORT_BYTES,
	TEST_CREDIT_CASES
};

static uint8_t *
read_file(const char *directory, const char *name, size_t *size)
{
	char path[TEST_PATH_BYTES];
	FILE *file;
	long length;
	uint8_t *bytes;

	assert(snprintf(path, sizeof(path), "%s/%s", directory, name) > 0);
	file = fopen(path, "rb");
	assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
	length = ftell(file);
	assert(length > 0 && length <= TEST_SOURCE_BYTES && fseek(file, 0, SEEK_SET) == 0);
	bytes = malloc((size_t)length);
	assert(bytes != NULL && fread(bytes, 1, (size_t)length, file) == (size_t)length);
	assert(fclose(file) == 0);
	*size = (size_t)length;
	return bytes;
}

static enum ntfs_result
partial_read(void *context, uint64_t offset, void *bytes, size_t size)
{
	enum ntfs_result result = fuzz_read(context, offset, bytes, size);

	if (result == NTFS_IO) {
		memset(bytes, TEST_PARTIAL_BYTE, size / TEST_PARTIAL_DENOMINATOR);
	}
	return result;
}

static void
filled(const void *data, size_t size, unsigned value)
{
	const uint8_t *bytes = data;
	size_t i;

	for (i = 0; i < size; i++) {
		assert(bytes[i] == value);
	}
}

static void
check_output(const uint8_t *guarded, const uint8_t *expected, size_t size)
{
	filled(guarded, TEST_GUARD_BYTES, TEST_SENTINEL);
	assert(memcmp(guarded + TEST_GUARD_BYTES, expected, size) == 0);
	filled(guarded + TEST_GUARD_BYTES + size,
	    NTFS_LOGFILE_MAX_RECORD_BYTES - size + TEST_GUARD_BYTES, TEST_SENTINEL);
}

static void
check_credits(const uint8_t *bytes, size_t size, uint64_t lsn, uint32_t pages, uint32_t page_bytes,
    uint8_t *guarded, const uint8_t *expected, size_t record_bytes)
{
	struct fuzz_device device;
	struct ntfs_environment environment;
	struct ntfs_logfile_limits limits;
	struct ntfs_logfile *source;
	struct ntfs_logfile_record_view view, zero = {0};
	size_t memory, reads;
	unsigned i;

	for (i = TEST_CREDITS_EXACT; i < TEST_CREDIT_CASES; i++) {
		device = (struct fuzz_device){.data = bytes, .size = size};
		environment = fuzz_environment(&device);
		ntfs_logfile_default_limits(&limits);
		limits.max_read_calls = pages - (i == TEST_CREDITS_SHORT_CALLS);
		limits.max_read_bytes =
		    (uint64_t)pages * page_bytes - (i == TEST_CREDITS_SHORT_BYTES);
		assert(ntfs_logfile_open(&environment, &limits, NULL, &source) == NTFS_OK);
		memory = device.memory;
		reads = device.reads;
		memset(
		    guarded, TEST_SENTINEL, NTFS_LOGFILE_MAX_RECORD_BYTES + TEST_GUARD_BYTES * 2);
		if (i == TEST_CREDITS_EXACT) {
			assert(ntfs_logfile_read_circular_record(source, lsn,
				   guarded + TEST_GUARD_BYTES, NTFS_LOGFILE_MAX_RECORD_BYTES,
				   &view) == NTFS_OK);
			assert(view.read_calls == limits.max_read_calls &&
			    view.read_bytes == limits.max_read_bytes);
			check_output(guarded, expected, record_bytes);
		} else {
			assert(ntfs_logfile_read_circular_record(source, lsn,
				   guarded + TEST_GUARD_BYTES, NTFS_LOGFILE_MAX_RECORD_BYTES,
				   &view) == NTFS_RANGE);
			assert(memcmp(&view, &zero, sizeof(view)) == 0 &&
			    device.reads - reads == pages - 1);
			filled(guarded, NTFS_LOGFILE_MAX_RECORD_BYTES + TEST_GUARD_BYTES * 2,
			    TEST_SENTINEL);
		}
		assert(device.memory == memory);
		ntfs_logfile_close(source);
		assert(device.memory == 0);
	}
}

static void
check_record_cap(const uint8_t *bytes, size_t size, uint64_t lsn, uint32_t pages,
    uint32_t page_bytes, uint8_t *guarded, const uint8_t *expected, size_t record_bytes)
{
	struct fuzz_device device = {.data = bytes, .size = size};
	struct ntfs_environment environment = fuzz_environment(&device);
	struct ntfs_logfile_limits limits;
	struct ntfs_logfile *source;
	struct ntfs_logfile_record_view view, zero = {0};
	size_t memory;

	assert(record_bytes == NTFS_LOGFILE_MAX_RECORD_BYTES);
	ntfs_logfile_default_limits(&limits);
	limits.max_read_calls = pages;
	limits.max_read_bytes = (uint64_t)pages * page_bytes;
	assert(ntfs_logfile_open(&environment, &limits, NULL, &source) == NTFS_OK);
	memory = device.memory;
	memset(guarded, TEST_SENTINEL, NTFS_LOGFILE_MAX_RECORD_BYTES + TEST_GUARD_BYTES * 2);
	assert(ntfs_logfile_read_circular_record(source, lsn, guarded + TEST_GUARD_BYTES,
		   NTFS_LOGFILE_MAX_RECORD_BYTES - 1, &view) == NTFS_RANGE);
	assert(memcmp(&view, &zero, sizeof(view)) == 0 && device.memory == memory);
	filled(guarded, NTFS_LOGFILE_MAX_RECORD_BYTES + TEST_GUARD_BYTES * 2, TEST_SENTINEL);
	assert(ntfs_logfile_read_circular_record(source, lsn, guarded + TEST_GUARD_BYTES,
		   NTFS_LOGFILE_MAX_RECORD_BYTES, &view) == NTFS_OK);
	assert(view.bytes == record_bytes && view.pages_read == pages &&
	    view.read_calls == limits.max_read_calls && view.read_bytes == limits.max_read_bytes &&
	    device.memory == memory);
	check_output(guarded, expected, record_bytes);
	ntfs_logfile_close(source);
	assert(device.memory == 0);
}

int
main(int argc, char **argv)
{
	struct fuzz_device device;
	struct ntfs_environment environment;
	struct ntfs_logfile *source;
	struct ntfs_logfile_record_view view, saved, zero = {0};
	struct ntfs_logfile_restart restart;
	FILE *cases;
	char path[TEST_PATH_BYTES], name[TEST_PATH_BYTES], filename[TEST_PATH_BYTES];
	uint8_t *bytes, *expected, *backup, *guarded;
	size_t size, expected_bytes, memory, reads, i, count = 0, read_faults = 0,
						       allocation_faults = 0;
	unsigned code, record_bytes, header_bytes, pages, page_bytes, wrapped;
	unsigned long long lsn, first_page, last_page;
	enum ntfs_result result;

	assert(argc == 2 && snprintf(path, sizeof(path), "%s/cases.tsv", argv[1]) > 0);
	cases = fopen(path, "r");
	assert(cases != NULL);
	guarded = malloc(NTFS_LOGFILE_MAX_RECORD_BYTES + TEST_GUARD_BYTES * 2);
	assert(guarded != NULL);
	while (fscanf(cases, "%1023s %u %llu %u %u %u %u %llu %llu %u", name, &code, &lsn,
		   &record_bytes, &header_bytes, &pages, &page_bytes, &first_page, &last_page,
		   &wrapped) == 10) {
		bytes = read_file(argv[1], name, &size);
		backup = malloc(size);
		assert(backup != NULL);
		memcpy(backup, bytes, size);
		assert(snprintf(filename, sizeof(filename), "%s.record", name) > 0);
		expected = read_file(argv[1], filename, &expected_bytes);
		assert(expected_bytes == record_bytes);
		device = (struct fuzz_device){.data = bytes, .size = size};
		environment = fuzz_environment(&device);
		environment.read = partial_read;
		assert(ntfs_logfile_open(&environment, NULL, NULL, &source) == NTFS_OK);
		memory = device.memory;
		memset(
		    guarded, TEST_SENTINEL, NTFS_LOGFILE_MAX_RECORD_BYTES + TEST_GUARD_BYTES * 2);
		memset(&view, TEST_SENTINEL, sizeof(view));
		result = ntfs_logfile_read_circular_record(
		    source, lsn, guarded + TEST_GUARD_BYTES, NTFS_LOGFILE_MAX_RECORD_BYTES, &view);
		if (result != (enum ntfs_result)code) {
			fprintf(stderr, "%s: record returned %s, expected %s\n", name,
			    ntfs_result_string(result), ntfs_result_string((enum ntfs_result)code));
		}
		assert(result == (enum ntfs_result)code && device.memory == memory);
		if (code == NTFS_OK) {
			assert(view.bytes == record_bytes && view.pages_read == pages &&
			    view.first_page_offset == first_page &&
			    view.last_page_offset == last_page && view.wrapped == (wrapped != 0) &&
			    view.read_calls == pages &&
			    view.read_bytes == (uint64_t)pages * page_bytes);
			assert(view.record.lsn == lsn && view.record.previous_lsn == 0 &&
			    view.record.undo_next_lsn == 0 && view.record.client_index == 0 &&
			    view.record.client_sequence == TEST_CLIENT_SEQUENCE &&
			    view.record.transaction == TEST_TRANSACTION &&
			    view.record.type == NTFS_LOGFILE_RECORD_UPDATE &&
			    view.record.data.offset == header_bytes &&
			    view.record.data.length == record_bytes - header_bytes);
			check_output(guarded, expected, record_bytes);
			saved = view;
			memset(guarded, TEST_SENTINEL,
			    NTFS_LOGFILE_MAX_RECORD_BYTES + TEST_GUARD_BYTES * 2);
			assert(
			    ntfs_logfile_read_circular_record(source, lsn,
				guarded + TEST_GUARD_BYTES, record_bytes - 1, &view) == NTFS_RANGE);
			assert(memcmp(&view, &zero, sizeof(view)) == 0 && device.memory == memory);
			filled(guarded, NTFS_LOGFILE_MAX_RECORD_BYTES + TEST_GUARD_BYTES * 2,
			    TEST_SENTINEL);
			device.fail_allocation = device.allocations + 1;
			assert(ntfs_logfile_read_circular_record(source, lsn,
				   guarded + TEST_GUARD_BYTES, NTFS_LOGFILE_MAX_RECORD_BYTES,
				   &view) == NTFS_NO_MEMORY);
			assert(memcmp(&view, &zero, sizeof(view)) == 0 && device.memory == memory);
			filled(guarded, NTFS_LOGFILE_MAX_RECORD_BYTES + TEST_GUARD_BYTES * 2,
			    TEST_SENTINEL);
			device.fail_allocation = 0;
			allocation_faults++;
			for (i = 1; i <= pages; i++) {
				device.fail_read = device.reads + i;
				assert(ntfs_logfile_read_circular_record(source, lsn,
					   guarded + TEST_GUARD_BYTES,
					   NTFS_LOGFILE_MAX_RECORD_BYTES, &view) == NTFS_IO);
				assert(memcmp(&view, &zero, sizeof(view)) == 0 &&
				    device.memory == memory);
				filled(guarded,
				    NTFS_LOGFILE_MAX_RECORD_BYTES + TEST_GUARD_BYTES * 2,
				    TEST_SENTINEL);
				device.fail_read = 0;
				reads = device.reads;
				assert(ntfs_logfile_get_restart(source, &restart) == NTFS_OK &&
				    device.reads == reads);
				assert(ntfs_logfile_read_circular_record(source, lsn,
					   guarded + TEST_GUARD_BYTES,
					   NTFS_LOGFILE_MAX_RECORD_BYTES, &view) == NTFS_OK);
				assert(memcmp(&view, &saved, sizeof(view)) == 0 &&
				    device.memory == memory);
				check_output(guarded, expected, record_bytes);
				memset(guarded, TEST_SENTINEL,
				    NTFS_LOGFILE_MAX_RECORD_BYTES + TEST_GUARD_BYTES * 2);
				read_faults++;
			}
		} else {
			assert(memcmp(&view, &zero, sizeof(view)) == 0);
			filled(guarded, NTFS_LOGFILE_MAX_RECORD_BYTES + TEST_GUARD_BYTES * 2,
			    TEST_SENTINEL);
		}
		ntfs_logfile_close(source);
		assert(device.memory == 0 && memcmp(bytes, backup, size) == 0);
		if (strcmp(name, "credits.journal") == 0) {
			check_credits(
			    bytes, size, lsn, pages, page_bytes, guarded, expected, expected_bytes);
		} else if (strcmp(name, "at-record-cap.journal") == 0) {
			check_record_cap(
			    bytes, size, lsn, pages, page_bytes, guarded, expected, expected_bytes);
		}
		free(expected);
		free(backup);
		free(bytes);
		count++;
	}
	assert(feof(cases) && fclose(cases) == 0 && count > 0);
	memset(guarded, TEST_SENTINEL, NTFS_LOGFILE_MAX_RECORD_BYTES + TEST_GUARD_BYTES * 2);
	assert(ntfs_logfile_read_circular_record(
		   NULL, 0, guarded, NTFS_LOGFILE_MAX_RECORD_BYTES, &view) == NTFS_INVALID &&
	    memcmp(&view, &zero, sizeof(view)) == 0);
	filled(guarded, NTFS_LOGFILE_MAX_RECORD_BYTES + TEST_GUARD_BYTES * 2, TEST_SENTINEL);
	free(guarded);
	printf(
	    "PASS: %zu physical record verdicts, %zu allocation/%zu partial read faults, "
	    "exact wrap/extended/1-MiB cap bytes and shared credits; no current-history/recovery "
	    "acceptance\n",
	    count, allocation_faults, read_faults);
	return 0;
}
