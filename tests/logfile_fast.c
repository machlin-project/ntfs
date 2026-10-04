/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/logfile.h>
#include "fuzz_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_PATH_BYTES = 1024,
	TEST_NAME_BYTES = 128,
	TEST_SOURCE_MAX_BYTES = 1024 * 1024,
	TEST_GUARD_BYTES = 32,
	TEST_BYTE_ALIGNMENT_OFFSET = 1,
	TEST_SENTINEL = 0xa5,
	TEST_PARTIAL_BYTE = 0x71,
	TEST_PARTIAL_DENOMINATOR = 2,
	TEST_TEMPORARY_ALLOCATIONS = 2,
	TEST_ROUTE_METADATA_BYTES = 2 * 1024,
	TEST_PAGE_BYTES = 4096,
	TEST_READ_CALLS = 2 * NTFS_LOGFILE_FAST_COPY_PAGES + 1,
	TEST_READ_BYTES = TEST_READ_CALLS * TEST_PAGE_BYTES,
	TEST_RESTART_PAGES = 2,
	TEST_SELECTED_COPY_READ = NTFS_LOGFILE_FAST_COPY_PAGES + 2,
	TEST_HEADER_CHANGES = 7,
	TEST_FIELDS = 12,
	TEST_CREDITS_EXACT = 0,
	TEST_CREDITS_SHORT_CALLS,
	TEST_CREDITS_SHORT_BYTES,
	TEST_CREDITS_CASES
};

struct test_device {
	struct fuzz_device device;
	enum ntfs_result failure;
	size_t peak_memory;
	const uint8_t *replacement;
	size_t replacement_bytes, replacement_read;
};

static enum ntfs_result
read_source(void *context, uint64_t offset, void *bytes, size_t size)
{
	struct test_device *test = context;
	enum ntfs_result result;

	result = fuzz_read(&test->device, offset, bytes, size);
	if (result != NTFS_OK) {
		memset(bytes, TEST_PARTIAL_BYTE, size / TEST_PARTIAL_DENOMINATOR);
		return test->failure;
	}
	if (test->device.reads == test->replacement_read && test->replacement != NULL) {
		assert(offset == (uint64_t)TEST_RESTART_PAGES * TEST_PAGE_BYTES &&
		    size == test->replacement_bytes);
		memcpy(bytes, test->replacement, size);
	}
	return NTFS_OK;
}

static void *
allocate(void *context, size_t size)
{
	struct test_device *test = context;
	void *bytes;

	bytes = fuzz_allocate(&test->device, size);
	if (test->device.memory > test->peak_memory) {
		test->peak_memory = test->device.memory;
	}
	return bytes;
}

static void
release(void *context, void *bytes, size_t size)
{
	struct test_device *test = context;

	fuzz_release(&test->device, bytes, size);
}

static struct ntfs_environment
environment(struct test_device *test)
{
	return (struct ntfs_environment){
	    NTFS_API_VERSION, test, test->device.size, read_source, allocate, release};
}

static enum ntfs_result
open_source(const struct ntfs_environment *env, struct ntfs_logfile **source)
{
	struct ntfs_logfile_limits limits;

	ntfs_logfile_default_limits(&limits);
	limits.max_read_calls = TEST_READ_CALLS;
	limits.max_read_bytes = TEST_READ_BYTES;
	return ntfs_logfile_open(env, &limits, NULL, source);
}

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
	assert(length > 0 && length <= TEST_SOURCE_MAX_BYTES && fseek(file, 0, SEEK_SET) == 0);
	bytes = malloc((size_t)length);
	assert(bytes != NULL && fread(bytes, 1, (size_t)length, file) == (size_t)length);
	assert(fclose(file) == 0);
	*size = (size_t)length;
	return bytes;
}

static void
filled(const void *data, size_t size, unsigned value)
{
	const uint8_t *bytes = data;
	size_t index;

	for (index = 0; index < size; index++) {
		assert(bytes[index] == value);
	}
}

static void
output_bytes(const uint8_t *guarded, const uint8_t *expected, size_t size)
{
	size_t prefix = TEST_GUARD_BYTES + TEST_BYTE_ALIGNMENT_OFFSET;

	filled(guarded, prefix, TEST_SENTINEL);
	assert(memcmp(guarded + prefix, expected, size) == 0);
	filled(guarded + prefix + size, NTFS_LOGFILE_MAX_RECORD_BYTES - size + TEST_GUARD_BYTES,
	    TEST_SENTINEL);
}

static void
check_faults(struct ntfs_logfile *source, struct test_device *test, uint64_t lsn,
    uint32_t expected_reads, uint8_t *guarded, size_t guarded_bytes, const uint8_t *expected,
    size_t record_bytes)
{
	static const enum ntfs_result failures[] = {
	    NTFS_IO, NTFS_CORRUPT, NTFS_UNSUPPORTED, NTFS_RANGE, NTFS_STALE};
	struct ntfs_logfile_record_view view, zero = {0};
	size_t memory = test->device.memory, reads, retry_reads, index, kind;
	uint8_t *bytes = guarded + TEST_GUARD_BYTES + TEST_BYTE_ALIGNMENT_OFFSET;
	enum ntfs_result result;

	for (kind = 0; kind < sizeof(failures) / sizeof(failures[0]); kind++) {
		for (index = 1; index <= expected_reads; index++) {
			/* Each independent operation has its own callback read budget. */
			test->device.reads = 0;
			reads = test->device.reads;
			test->failure = failures[kind];
			test->device.fail_read = reads + index;
			memset(guarded, TEST_SENTINEL, guarded_bytes);
			assert(ntfs_logfile_read_fast_record(source, lsn, bytes,
				   NTFS_LOGFILE_MAX_RECORD_BYTES, &view) == failures[kind]);
			assert(
			    test->device.reads - reads == index && test->device.memory == memory);
			assert(memcmp(&view, &zero, sizeof(view)) == 0);
			filled(guarded, guarded_bytes, TEST_SENTINEL);
			test->device.fail_read = 0;
			test->failure = NTFS_IO;
			test->device.reads = 0;
			retry_reads = test->device.reads;
			result = ntfs_logfile_read_fast_record(
			    source, lsn, bytes, NTFS_LOGFILE_MAX_RECORD_BYTES, &view);
			if (result != NTFS_OK) {
				fprintf(stderr,
				    "Retry failed: lsn=%llu fault=%u read=%zu result=%u "
				    "retry_reads=%zu cumulative_reads=%zu device_budget=%u\n",
				    (unsigned long long)lsn, (unsigned)failures[kind], index,
				    (unsigned)result, test->device.reads - retry_reads,
				    test->device.reads, FUZZ_READ_BUDGET);
			}
			assert(result == NTFS_OK);
			assert(test->device.memory == memory);
			output_bytes(guarded, expected, record_bytes);
		}
	}
	for (index = 1; index <= TEST_TEMPORARY_ALLOCATIONS; index++) {
		test->device.reads = 0;
		test->device.fail_allocation = test->device.allocations + index;
		memset(guarded, TEST_SENTINEL, guarded_bytes);
		assert(ntfs_logfile_read_fast_record(source, lsn, bytes,
			   NTFS_LOGFILE_MAX_RECORD_BYTES, &view) == NTFS_NO_MEMORY);
		assert(test->device.memory == memory && memcmp(&view, &zero, sizeof(view)) == 0);
		filled(guarded, guarded_bytes, TEST_SENTINEL);
		test->device.fail_allocation = 0;
		test->device.reads = 0;
		assert(ntfs_logfile_read_fast_record(
			   source, lsn, bytes, NTFS_LOGFILE_MAX_RECORD_BYTES, &view) == NTFS_OK);
		assert(test->device.memory == memory);
		output_bytes(guarded, expected, record_bytes);
	}
}

static void
check_header_stability(const char *directory, struct ntfs_logfile *source, struct test_device *test,
    uint64_t lsn, uint8_t *guarded, size_t guarded_bytes, const uint8_t *expected,
    size_t record_bytes)
{
	struct ntfs_logfile_record_view view, zero = {0};
	char path[TEST_PATH_BYTES], name[TEST_NAME_BYTES], scan[TEST_NAME_BYTES];
	FILE *changes;
	uint8_t *replacement, *bytes = guarded + TEST_GUARD_BYTES + TEST_BYTE_ALIGNMENT_OFFSET;
	size_t size, count = 0, memory = test->device.memory;

	assert(snprintf(path, sizeof(path), "%s/changed.tsv", directory) > 0);
	assert(snprintf(scan, sizeof(scan), "%%%zus", sizeof(name) - 1) > 0);
	changes = fopen(path, "r");
	assert(changes != NULL);
	while (fscanf(changes, scan, name) == 1) {
		replacement = read_file(directory, name, &size);
		assert(size == TEST_PAGE_BYTES);
		test->device.reads = 0;
		test->replacement = replacement;
		test->replacement_bytes = size;
		test->replacement_read = TEST_SELECTED_COPY_READ;
		memset(guarded, TEST_SENTINEL, guarded_bytes);
		assert(ntfs_logfile_read_fast_record(
			   source, lsn, bytes, NTFS_LOGFILE_MAX_RECORD_BYTES, &view) == NTFS_STALE);
		assert(
		    test->device.reads == TEST_SELECTED_COPY_READ && test->device.memory == memory);
		assert(memcmp(&view, &zero, sizeof(view)) == 0);
		filled(guarded, guarded_bytes, TEST_SENTINEL);
		test->replacement = NULL;
		test->replacement_read = 0;
		test->device.reads = 0;
		assert(ntfs_logfile_read_fast_record(
			   source, lsn, bytes, NTFS_LOGFILE_MAX_RECORD_BYTES, &view) == NTFS_OK);
		assert(test->device.memory == memory);
		output_bytes(guarded, expected, record_bytes);
		free(replacement);
		count++;
	}
	assert(feof(changes) && fclose(changes) == 0 && count == TEST_HEADER_CHANGES);
}

static void
check_arguments(struct ntfs_logfile *source, struct test_device *test, uint64_t lsn,
    uint16_t header_bytes, size_t record_bytes, uint8_t *guarded, size_t guarded_bytes)
{
	struct ntfs_logfile_record_view view, zero = {0};
	uint8_t *bytes = guarded + TEST_GUARD_BYTES + TEST_BYTE_ALIGNMENT_OFFSET;
	size_t reads, allocations, memory = test->device.memory;

	memset(guarded, TEST_SENTINEL, guarded_bytes);
	assert(ntfs_logfile_read_fast_record(source, lsn, bytes, record_bytes - 1, &view) ==
	    NTFS_RANGE);
	assert(memcmp(&view, &zero, sizeof(view)) == 0 && test->device.memory == memory);
	filled(guarded, guarded_bytes, TEST_SENTINEL);
	reads = test->device.reads;
	allocations = test->device.allocations;
	assert(ntfs_logfile_read_fast_record(source, lsn, bytes, header_bytes - 1, &view) ==
	    NTFS_RANGE);
	assert(memcmp(&view, &zero, sizeof(view)) == 0);
	assert(
	    ntfs_logfile_read_fast_record(NULL, lsn, bytes, record_bytes, &view) == NTFS_INVALID);
	assert(memcmp(&view, &zero, sizeof(view)) == 0);
	assert(
	    ntfs_logfile_read_fast_record(source, lsn, NULL, record_bytes, &view) == NTFS_INVALID);
	assert(memcmp(&view, &zero, sizeof(view)) == 0);
	assert(
	    ntfs_logfile_read_fast_record(source, lsn, bytes, record_bytes, NULL) == NTFS_INVALID);
	assert(test->device.reads == reads && test->device.allocations == allocations &&
	    test->device.memory == memory);
	filled(guarded, guarded_bytes, TEST_SENTINEL);
}

static void
check_credits(const uint8_t *data, size_t size, uint64_t lsn, uint32_t calls, uint32_t page_bytes,
    uint8_t *guarded, size_t guarded_bytes, const uint8_t *expected, size_t record_bytes)
{
	struct test_device test;
	struct ntfs_environment env;
	struct ntfs_logfile_limits limits;
	struct ntfs_logfile *source;
	struct ntfs_logfile_record_view view, zero = {0};
	size_t kind, reads, memory;
	uint8_t *bytes = guarded + TEST_GUARD_BYTES + TEST_BYTE_ALIGNMENT_OFFSET;

	for (kind = TEST_CREDITS_EXACT; kind < TEST_CREDITS_CASES; kind++) {
		test = (struct test_device){
		    .device = {.data = data, .size = size}, .failure = NTFS_IO};
		env = environment(&test);
		ntfs_logfile_default_limits(&limits);
		limits.max_read_calls = calls - (kind == TEST_CREDITS_SHORT_CALLS);
		limits.max_read_bytes =
		    (uint64_t)calls * page_bytes - (kind == TEST_CREDITS_SHORT_BYTES);
		assert(ntfs_logfile_open(&env, &limits, NULL, &source) == NTFS_OK);
		reads = test.device.reads;
		memory = test.device.memory;
		memset(guarded, TEST_SENTINEL, guarded_bytes);
		if (kind == TEST_CREDITS_EXACT) {
			assert(ntfs_logfile_read_fast_record(source, lsn, bytes,
				   NTFS_LOGFILE_MAX_RECORD_BYTES, &view) == NTFS_OK);
			assert(view.read_calls == calls &&
			    view.read_bytes == (uint64_t)calls * page_bytes);
			output_bytes(guarded, expected, record_bytes);
		} else {
			assert(ntfs_logfile_read_fast_record(source, lsn, bytes,
				   NTFS_LOGFILE_MAX_RECORD_BYTES, &view) == NTFS_RANGE);
			if (limits.max_read_calls <= NTFS_LOGFILE_FAST_COPY_PAGES ||
			    limits.max_read_bytes <
				(uint64_t)(NTFS_LOGFILE_FAST_COPY_PAGES + 1) * page_bytes) {
				assert(test.device.reads == reads);
			} else {
				assert(test.device.reads - reads == calls - 1);
			}
			assert(memcmp(&view, &zero, sizeof(view)) == 0);
			filled(guarded, guarded_bytes, TEST_SENTINEL);
		}
		assert(test.device.memory == memory);
		ntfs_logfile_close(source);
		assert(test.device.memory == 0);
	}
}

static void
check_default_credits(
    const uint8_t *data, size_t size, uint64_t lsn, uint8_t *guarded, size_t guarded_bytes)
{
	struct test_device test = {.device = {.data = data, .size = size}, .failure = NTFS_IO};
	struct ntfs_environment env = environment(&test);
	struct ntfs_logfile_record_view view, zero = {0};
	struct ntfs_logfile *source;
	size_t reads, allocations, memory;
	uint8_t *bytes = guarded + TEST_GUARD_BYTES + TEST_BYTE_ALIGNMENT_OFFSET;

	assert(ntfs_logfile_open(&env, NULL, NULL, &source) == NTFS_OK);
	reads = test.device.reads;
	allocations = test.device.allocations;
	memory = test.device.memory;
	memset(guarded, TEST_SENTINEL, guarded_bytes);
	assert(ntfs_logfile_read_fast_record(
		   source, lsn, bytes, NTFS_LOGFILE_MAX_RECORD_BYTES, &view) == NTFS_RANGE);
	assert(test.device.reads == reads && test.device.allocations == allocations &&
	    test.device.memory == memory && memcmp(&view, &zero, sizeof(view)) == 0);
	filled(guarded, guarded_bytes, TEST_SENTINEL);
	ntfs_logfile_close(source);
	assert(test.device.memory == 0);
}

int
main(int argc, char **argv)
{
	struct test_device test;
	struct ntfs_environment env;
	struct ntfs_logfile *source;
	struct ntfs_logfile_record_view view, saved, zero = {0};
	struct ntfs_logfile_restart before, after;
	struct ntfs_logfile_client client_before, client_after;
	FILE *cases;
	char path[TEST_PATH_BYTES], name[TEST_NAME_BYTES], scan[TEST_NAME_BYTES];
	uint8_t *data, *expected, *backup, *guarded;
	size_t size, expected_bytes, memory, reads, count = 0;
	size_t guarded_bytes =
	    NTFS_LOGFILE_MAX_RECORD_BYTES + TEST_GUARD_BYTES * 2 + TEST_BYTE_ALIGNMENT_OFFSET;
	unsigned code, record_bytes, pages, copies, calls, page_bytes, wrapped, faults;
	unsigned long long lsn, first, last;
	enum ntfs_result result;

	assert(argc == 2 && snprintf(path, sizeof(path), "%s/cases.tsv", argv[1]) > 0);
	assert(
	    snprintf(scan, sizeof(scan), "%%%zus %%u %%llu %%u %%u %%u %%u %%u %%llu %%llu %%u %%u",
		sizeof(name) - 1) > 0);
	cases = fopen(path, "r");
	assert(cases != NULL);
	guarded = malloc(guarded_bytes);
	assert(guarded != NULL);
	while (fscanf(cases, scan, name, &code, &lsn, &record_bytes, &pages, &copies, &calls,
		   &page_bytes, &first, &last, &wrapped, &faults) == TEST_FIELDS) {
		data = read_file(argv[1], name, &size);
		backup = malloc(size);
		assert(backup != NULL);
		memcpy(backup, data, size);
		assert(snprintf(path, sizeof(path), "%s.record", name) > 0);
		expected = read_file(argv[1], path, &expected_bytes);
		assert(expected_bytes == record_bytes);
		test = (struct test_device){
		    .device = {.data = data, .size = size}, .failure = NTFS_IO};
		env = environment(&test);
		assert(open_source(&env, &source) == NTFS_OK);
		assert(ntfs_logfile_get_restart(source, &before) == NTFS_OK);
		assert(ntfs_logfile_get_client(source, 0, &client_before) == NTFS_OK);
		memory = test.device.memory;
		reads = test.device.reads;
		test.peak_memory = memory;
		memset(guarded, TEST_SENTINEL, guarded_bytes);
		memset(&view, TEST_SENTINEL, sizeof(view));
		result = ntfs_logfile_read_fast_record(source, lsn,
		    guarded + TEST_GUARD_BYTES + TEST_BYTE_ALIGNMENT_OFFSET,
		    NTFS_LOGFILE_MAX_RECORD_BYTES, &view);
		assert(result == (enum ntfs_result)code && test.device.reads - reads == calls);
		assert(test.device.memory == memory);
		if (result == NTFS_OK) {
			assert(view.record.lsn == lsn && view.bytes == record_bytes &&
			    view.pages_read == pages);
			assert(view.first_page_offset == first && view.last_page_offset == last);
			assert(view.copy_pages_read == copies && view.read_calls == calls);
			assert(view.read_bytes == (uint64_t)calls * page_bytes &&
			    view.wrapped == (wrapped != 0));
			assert(test.peak_memory <=
			    memory + TEST_ROUTE_METADATA_BYTES + page_bytes + record_bytes);
			output_bytes(guarded, expected, record_bytes);
			saved = view;
			assert(ntfs_logfile_read_fast_record(source, lsn,
				   guarded + TEST_GUARD_BYTES + TEST_BYTE_ALIGNMENT_OFFSET,
				   NTFS_LOGFILE_MAX_RECORD_BYTES, &view) == NTFS_OK);
			assert(memcmp(&view, &saved, sizeof(view)) == 0);
			if (faults) {
				check_faults(source, &test, lsn, calls, guarded, guarded_bytes,
				    expected, record_bytes);
				check_default_credits(data, size, lsn, guarded, guarded_bytes);
			}
			if (strcmp(name, "reload-header-stability.journal") == 0) {
				check_header_stability(argv[1], source, &test, lsn, guarded,
				    guarded_bytes, expected, record_bytes);
			}
			check_arguments(source, &test, lsn, before.record_header_bytes,
			    record_bytes, guarded, guarded_bytes);
			if (pages > 1 || faults || calls == TEST_READ_CALLS) {
				check_credits(data, size, lsn, calls, page_bytes, guarded,
				    guarded_bytes, expected, record_bytes);
			}
		} else {
			assert(memcmp(&view, &zero, sizeof(view)) == 0);
			filled(guarded, guarded_bytes, TEST_SENTINEL);
		}
		assert(ntfs_logfile_get_restart(source, &after) == NTFS_OK &&
		    memcmp(&before, &after, sizeof(before)) == 0);
		assert(ntfs_logfile_get_client(source, 0, &client_after) == NTFS_OK &&
		    memcmp(&client_before, &client_after, sizeof(client_before)) == 0);
		assert(memcmp(data, backup, size) == 0 && test.device.memory == memory);
		ntfs_logfile_close(source);
		assert(test.device.memory == 0);
		free(backup);
		free(expected);
		free(data);
		count++;
	}
	assert(feof(cases) && count != 0 && fclose(cases) == 0);
	free(guarded);
	printf("PASS: %zu original fast-copy records, exact bytes, backend result preservation, "
	       "allocation/read faults, retry, credits and immutable restart snapshots\n",
	    count);
	return 0;
}
