/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/logfile.h>
#include "fuzz_device.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_NAME_CHARACTERS 127
#define TEST_STRINGIFY_VALUE(value) #value
#define TEST_STRINGIFY(value) TEST_STRINGIFY_VALUE(value)
#define TEST_NAME_FORMAT "%" TEST_STRINGIFY(TEST_NAME_CHARACTERS) "s"

enum {
	TEST_PATH_BYTES = 1024,
	TEST_NAME_BYTES = TEST_NAME_CHARACTERS + 1,
	TEST_MAX_SOURCE_BYTES = 4 * 1024 * 1024,
	TEST_INDEX_BYTES = 1024 * 1024,
	TEST_READ_BYTES = 16 * 1024 * 1024,
	TEST_READ_CALLS = 4096,
	TEST_RECORDS = 4096,
	TEST_GUARD_BYTES = 32,
	TEST_SENTINEL = 0xa5,
	TEST_PARTIAL_FILL = 0x71,
	TEST_PARTIAL_DIVISOR = 2,
	TEST_CASE_FIELDS = 9,
	TEST_PACKET_FIELDS = 7,
	TEST_PREFIX_PAIR_READS = 2
};

struct test_device {
	struct fuzz_device device;
	enum ntfs_result failure;
	bool full_failure;
};

struct test_case {
	char name[TEST_NAME_BYTES];
	uint64_t first;
	uint32_t code, records, page_bytes, reads, endpoint, tail, wrapped;
};

struct test_visitor {
	const char *directory;
	const struct test_case *test;
	uint32_t calls, stop_at;
	enum ntfs_result stop_result;
	FILE *rows;
};

static FILE *
open_file(const char *directory, const char *name, const char *suffix)
{
	char path[TEST_PATH_BYTES];
	int length;
	FILE *file;

	length = snprintf(path, sizeof(path), "%s/%s%s", directory, name, suffix);
	assert(length > 0 && (size_t)length < sizeof(path));
	file = fopen(path, "rb");
	assert(file != NULL);
	return file;
}

static uint8_t *
file_bytes(const char *directory, const char *name, size_t *size)
{
	FILE *file;
	long length;
	uint8_t *bytes;

	file = open_file(directory, name, "");
	assert(fseek(file, 0, SEEK_END) == 0);
	length = ftell(file);
	assert(length > 0 && length <= TEST_MAX_SOURCE_BYTES && fseek(file, 0, SEEK_SET) == 0);
	bytes = malloc((size_t)length);
	assert(bytes != NULL && fread(bytes, 1, (size_t)length, file) == (size_t)length);
	assert(fclose(file) == 0);
	*size = (size_t)length;
	return bytes;
}

static enum ntfs_result
read_source(void *context, uint64_t offset, void *bytes, size_t size)
{
	struct test_device *test = context;
	enum ntfs_result result;

	result = fuzz_read(&test->device, offset, bytes, size);
	if (result != NTFS_OK) {
		if (test->full_failure) {
			assert(offset <= test->device.size && size <= test->device.size - offset);
			memcpy(bytes, test->device.data + (size_t)offset, size);
		} else {
			memset(bytes, TEST_PARTIAL_FILL, size / TEST_PARTIAL_DIVISOR);
		}
		return test->failure;
	}
	return NTFS_OK;
}

static void *
allocate_source(void *context, size_t size)
{
	struct test_device *test = context;

	return fuzz_allocate(&test->device, size);
}

static void
release_source(void *context, void *bytes, size_t size)
{
	struct test_device *test = context;

	fuzz_release(&test->device, bytes, size);
}

static struct ntfs_environment
environment(struct test_device *device)
{
	return (struct ntfs_environment){NTFS_API_VERSION, device, device->device.size, read_source,
	    allocate_source, release_source};
}

static enum ntfs_result
visit_record(void *context, const struct ntfs_logfile_record_view *view, const void *bytes)
{
	struct test_visitor *visitor = context;
	uint64_t lsn, first, last;
	uint32_t size, pages, copies, wrapped;
	char name[TEST_NAME_BYTES];
	uint8_t *expected;
	size_t expected_bytes;
	int length;

	assert(visitor->calls < visitor->test->records);
	assert(
	    fscanf(visitor->rows,
		"%" SCNu64 " %" SCNu32 " %" SCNu64 " %" SCNu64 " %" SCNu32 " %" SCNu32 " %" SCNu32,
		&lsn, &size, &first, &last, &pages, &copies, &wrapped) == TEST_PACKET_FIELDS);
	length =
	    snprintf(name, sizeof(name), "%s.packet-%" PRIu32, visitor->test->name, visitor->calls);
	assert(length > 0 && (size_t)length < sizeof(name));
	expected = file_bytes(visitor->directory, name, &expected_bytes);
	assert(expected_bytes == size && view->bytes == size && memcmp(bytes, expected, size) == 0);
	assert(view->record.lsn == lsn && view->first_page_offset == first &&
	    view->last_page_offset == last);
	assert(view->pages_read == pages && view->copy_pages_read == copies &&
	    view->wrapped == (wrapped != 0));
	assert(view->read_calls == pages &&
	    view->read_bytes == (uint64_t)pages * visitor->test->page_bytes);
	free(expected);
	visitor->calls++;
	return visitor->calls == visitor->stop_at ? visitor->stop_result : NTFS_OK;
}

static void
reset_visitor(struct test_visitor *visitor)
{
	visitor->calls = 0;
	assert(fseek(visitor->rows, 0, SEEK_SET) == 0);
}

static void
guarded(const uint8_t *allocation)
{
	size_t i;

	for (i = 0; i < TEST_GUARD_BYTES; i++) {
		assert(allocation[i] == TEST_SENTINEL);
		assert(allocation[TEST_GUARD_BYTES + NTFS_LOGFILE_MAX_RECORD_BYTES + i] ==
		    TEST_SENTINEL);
	}
}

static void
check_case(const char *directory, const struct test_case *test)
{
	struct test_device device = {0};
	struct ntfs_environment env;
	struct ntfs_logfile_limits limits;
	struct ntfs_logfile *source = NULL;
	struct ntfs_logfile_page_index_report preparation;
	struct ntfs_logfile_history_report report;
	struct test_visitor visitor = {.directory = directory, .test = test};

	const enum ntfs_result failures[] = {NTFS_IO, NTFS_CORRUPT, NTFS_NOT_FOUND, NTFS_RANGE};

	uint8_t *raw, *allocation, *workspace;
	size_t size, retained, before, fault, mode, status, stop, base_allocations;
	bool faults;
	enum ntfs_result result;

	raw = file_bytes(directory, test->name, &size);
	device.device.data = raw;
	device.device.size = size;
	env = environment(&device);
	ntfs_logfile_default_limits(&limits);
	limits.max_read_calls = TEST_READ_CALLS;
	limits.max_read_bytes = TEST_READ_BYTES;
	assert(ntfs_logfile_open(&env, &limits, NULL, &source) == NTFS_OK);
	allocation = malloc(NTFS_LOGFILE_MAX_RECORD_BYTES + 2 * TEST_GUARD_BYTES);
	assert(allocation != NULL);
	memset(allocation, TEST_SENTINEL, NTFS_LOGFILE_MAX_RECORD_BYTES + 2 * TEST_GUARD_BYTES);
	workspace = allocation + TEST_GUARD_BYTES;
	before = device.device.reads;
	assert(ntfs_logfile_visit_records(source, test->first, TEST_RECORDS, workspace,
		   NTFS_LOGFILE_MAX_RECORD_BYTES, NULL, NULL, &report) == NTFS_NOT_FOUND);
	assert(device.device.reads == before && !report.complete);
	assert(ntfs_logfile_prepare_page_index(source, TEST_INDEX_BYTES, &preparation) == NTFS_OK);
	retained = device.device.memory;
	visitor.rows = open_file(directory, test->name, ".packets.rows");
	before = device.device.reads;
	result = ntfs_logfile_visit_records(source, test->first, TEST_RECORDS, workspace,
	    NTFS_LOGFILE_MAX_RECORD_BYTES, visit_record, &visitor, &report);
	if (result != (enum ntfs_result)test->code) {
		fprintf(stderr, "%s: got %d expected %u\n", test->name, (int)result, test->code);
	}
	assert(result == (enum ntfs_result)test->code);
	assert(visitor.calls == test->records && report.examined_records == test->records &&
	    report.visited_records == test->records && report.read_calls == test->reads);
	assert(device.device.reads - before == test->reads &&
	    report.read_bytes == (uint64_t)test->reads * test->page_bytes);
	assert(report.endpoint_verified == (test->endpoint != 0) &&
	    report.tail_verified == (test->tail != 0));
	assert(report.complete == (result == NTFS_OK) && report.wrapped == (test->wrapped != 0));
	assert(device.device.memory == retained);
	guarded(allocation);
	/* Every physical read and record allocation in these distinct successful
	 * windows is failed in turn. Backend statuses survive full/partial buffers,
	 * no failing packet reaches the visitor, and the same owner can retry. */
	faults = strcmp(test->name, "legacy-adjacent-header-48.journal") == 0 ||
	    strcmp(test->name, "legacy-three-page-record.journal") == 0 ||
	    strcmp(test->name, "fast-unfinished-copy.journal") == 0;
	if (faults) {
		before = device.device.reads;
		memset(&report, TEST_SENTINEL, sizeof(report));
		assert(ntfs_logfile_visit_records(source, test->first, 0, workspace,
			   NTFS_LOGFILE_MAX_RECORD_BYTES, NULL, NULL, &report) == NTFS_INVALID);
		assert(report.first_lsn == 0 && report.read_calls == 0 && !report.complete);
		assert(ntfs_logfile_visit_records(source, test->first, TEST_RECORDS, NULL,
			   NTFS_LOGFILE_MAX_RECORD_BYTES, NULL, NULL, &report) == NTFS_INVALID);
		assert(ntfs_logfile_visit_records(source, test->first, TEST_RECORDS, workspace, 0,
			   NULL, NULL, &report) == NTFS_RANGE);
		assert(device.device.reads == before && report.first_lsn == 0 &&
		    report.read_calls == 0);
		for (mode = 0; mode < 2; mode++) {
			device.full_failure = mode != 0;
			for (status = 0; status < sizeof(failures) / sizeof(failures[0]);
			    status++) {
				device.failure = failures[status];
				for (fault = 1; fault <= test->reads; fault++) {
					reset_visitor(&visitor);
					before = device.device.reads;
					device.device.fail_read = before + fault;
					assert(ntfs_logfile_visit_records(source, test->first,
						   TEST_RECORDS, workspace,
						   NTFS_LOGFILE_MAX_RECORD_BYTES, visit_record,
						   &visitor, &report) == failures[status]);
					assert(report.read_calls == fault && !report.complete &&
					    device.device.memory == retained);
					assert(visitor.calls == report.visited_records);
					device.device.fail_read = 0;
					reset_visitor(&visitor);
					assert(ntfs_logfile_visit_records(source, test->first,
						   TEST_RECORDS, workspace,
						   NTFS_LOGFILE_MAX_RECORD_BYTES, visit_record,
						   &visitor, &report) == NTFS_OK);
					assert(visitor.calls == test->records && report.complete &&
					    device.device.memory == retained);
					guarded(allocation);
				}
			}
		}
		for (fault = 1; fault <= test->records; fault++) {
			reset_visitor(&visitor);
			base_allocations = device.device.allocations;
			device.device.fail_allocation = base_allocations + fault;
			assert(ntfs_logfile_visit_records(source, test->first, TEST_RECORDS,
				   workspace, NTFS_LOGFILE_MAX_RECORD_BYTES, visit_record, &visitor,
				   &report) == NTFS_NO_MEMORY);
			assert(visitor.calls == fault - 1 && report.visited_records == fault - 1 &&
			    !report.complete);
			assert(device.device.memory == retained);
			device.device.fail_allocation = 0;
			reset_visitor(&visitor);
			assert(ntfs_logfile_visit_records(source, test->first, TEST_RECORDS,
				   workspace, NTFS_LOGFILE_MAX_RECORD_BYTES, visit_record, &visitor,
				   &report) == NTFS_OK);
			assert(device.device.memory == retained);
		}
		for (stop = 1; stop <= test->records; stop++) {
			reset_visitor(&visitor);
			visitor.stop_at = (uint32_t)stop;
			visitor.stop_result = NTFS_END;
			assert(ntfs_logfile_visit_records(source, test->first, TEST_RECORDS,
				   workspace, NTFS_LOGFILE_MAX_RECORD_BYTES, visit_record, &visitor,
				   &report) == NTFS_END);
			assert(visitor.calls == stop && report.examined_records == stop &&
			    report.visited_records == stop - 1);
			assert(!report.complete && device.device.memory == retained);
		}
		visitor.stop_at = 0;
		reset_visitor(&visitor);
		assert(ntfs_logfile_visit_records(source, test->first, 1, workspace,
			   NTFS_LOGFILE_MAX_RECORD_BYTES, visit_record, &visitor,
			   &report) == NTFS_RANGE);
		assert(visitor.calls == 1 && report.visited_records == 1 && !report.complete);
	}
	assert(fclose(visitor.rows) == 0);
	ntfs_logfile_clear_page_index(source);
	before = device.device.reads;
	assert(ntfs_logfile_visit_records(source, test->first, TEST_RECORDS, workspace,
		   NTFS_LOGFILE_MAX_RECORD_BYTES, NULL, NULL, &report) == NTFS_NOT_FOUND);
	assert(before == device.device.reads);
	ntfs_logfile_close(source);
	assert(device.device.memory == 0);
	free(allocation);
	free(raw);
}

static void
shared_credits(const char *directory)
{
	struct test_device device = {0};
	struct ntfs_environment env;
	struct ntfs_logfile_limits limits;
	struct ntfs_logfile *source = NULL;
	struct ntfs_logfile_restart restart;
	struct ntfs_logfile_page_index_report preparation;
	struct ntfs_logfile_history_report report;
	uint8_t *raw, *workspace;
	size_t size, before, mode;
	uint32_t maximum;

	raw = file_bytes(directory, "fast-shared-operation-credits.journal", &size);
	device.device.data = raw;
	device.device.size = size;
	env = environment(&device);
	ntfs_logfile_default_limits(&limits);
	limits.max_read_calls = TEST_READ_CALLS;
	limits.max_read_bytes = TEST_READ_BYTES;
	assert(ntfs_logfile_open(&env, &limits, NULL, &source) == NTFS_OK);
	assert(ntfs_logfile_get_restart(source, &restart) == NTFS_OK);
	ntfs_logfile_close(source);
	assert(device.device.memory == 0);
	maximum =
	    (uint32_t)((restart.usable_bytes - restart.circular_offset) / restart.log_page_bytes) +
	    NTFS_LOGFILE_FAST_COPY_PAGES + TEST_PREFIX_PAIR_READS * NTFS_LOGFILE_FAST_COPY_PAGES;
	assert(maximum < TEST_RECORDS);
	workspace = malloc(NTFS_LOGFILE_MAX_RECORD_BYTES);
	assert(workspace != NULL);
	for (mode = 0; mode < 2; mode++) {
		limits.max_read_calls = mode == 0 ? maximum : TEST_READ_CALLS;
		limits.max_read_bytes =
		    mode == 0 ? TEST_READ_BYTES : (uint64_t)maximum * restart.log_page_bytes;
		assert(ntfs_logfile_open(&env, &limits, NULL, &source) == NTFS_OK);
		assert(ntfs_logfile_prepare_page_index(source, TEST_INDEX_BYTES, &preparation) ==
		    NTFS_OK);
		before = device.device.reads;
		assert(
		    ntfs_logfile_visit_records(source, restart.current_lsn, TEST_RECORDS, workspace,
			NTFS_LOGFILE_MAX_RECORD_BYTES, NULL, NULL, &report) == NTFS_RANGE);
		assert(report.read_calls == maximum &&
		    report.read_bytes == (uint64_t)maximum * restart.log_page_bytes &&
		    report.visited_records == maximum && !report.complete &&
		    !report.endpoint_verified);
		assert(device.device.reads - before == maximum);
		ntfs_logfile_close(source);
		assert(device.device.memory == 0);
	}
	free(workspace);
	free(raw);
}

int
main(int argc, char **argv)
{
	struct test_case test;
	struct ntfs_logfile_history_report report, zero = {0};
	FILE *cases;
	uint32_t count = 0;
	int fields;

	assert(argc == 2);
	memset(&report, TEST_SENTINEL, sizeof(report));
	assert(ntfs_logfile_visit_records(NULL, 0, TEST_RECORDS, NULL, 0, NULL, NULL, &report) ==
	    NTFS_INVALID);
	assert(memcmp(&report, &zero, sizeof(report)) == 0);
	assert(ntfs_logfile_visit_records(NULL, 0, TEST_RECORDS, NULL, 0, NULL, NULL, NULL) ==
	    NTFS_INVALID);
	cases = open_file(argv[1], "cases.tsv", "");
	while ((fields = fscanf(cases,
		    TEST_NAME_FORMAT " %" SCNu32 " %" SCNu64 " %" SCNu32 " %" SCNu32 " %" SCNu32
				     " %" SCNu32 " %" SCNu32 " %" SCNu32,
		    test.name, &test.code, &test.first, &test.records, &test.page_bytes,
		    &test.reads, &test.endpoint, &test.tail, &test.wrapped)) != EOF) {
		assert(fields == TEST_CASE_FIELDS);
		check_case(argv[1], &test);
		count++;
	}
	assert(fclose(cases) == 0 && count != 0);
	shared_credits(argv[1]);
	printf("PASS: %" PRIu32 " selected windows, exact packets, shared credits and retryable "
	       "read/allocation/visitor failures\n",
	    count);
	return 0;
}
