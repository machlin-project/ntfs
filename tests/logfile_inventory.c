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

enum {
	TEST_PATH_BYTES = 1024,
	TEST_NAME_BYTES = TEST_NAME_CHARACTERS + 1,
	TEST_SOURCE_MAX_BYTES = 4 * 1024 * 1024,
	TEST_RESTART_PAGES = 2,
	TEST_PARTIAL_BYTE = 0x71,
	TEST_PARTIAL_DENOMINATOR = 2,
	TEST_FAILED_TRANSFERS = 2,
	TEST_CASE_FIELDS = 11,
	TEST_ROW_FIELDS = 11,
	TEST_CREDITS_EXACT = 0,
	TEST_CREDITS_SHORT_CALLS,
	TEST_CREDITS_SHORT_BYTES,
	TEST_CREDITS_DEFAULT,
	TEST_CREDIT_CASES
};

struct test_device {
	struct fuzz_device device;
	enum ntfs_result failure;
	bool full_failure;
};

struct test_visitor {
	FILE *rows;
	uint64_t first_offset;
	uint32_t page_bytes, seen, fail_at;
	enum ntfs_result failure;
};

struct test_case {
	char name[TEST_NAME_BYTES];
	uint32_t page_bytes, pages, decoded, missing, corrupt, invalid, unsupported, faults;
	uint64_t max_epoch, max_completed;
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
source_bytes(const char *directory, const char *name, size_t *size)
{
	FILE *file;
	long length;
	uint8_t *bytes;

	file = open_file(directory, name, "");
	assert(fseek(file, 0, SEEK_END) == 0);
	length = ftell(file);
	assert(length > 0 && length <= TEST_SOURCE_MAX_BYTES && fseek(file, 0, SEEK_SET) == 0);
	bytes = malloc((size_t)length);
	assert(bytes != NULL && fread(bytes, 1, (size_t)length, file) == (size_t)length);
	assert(fclose(file) == 0);
	*size = (size_t)length;
	return bytes;
}

static enum ntfs_result
source_read(void *context, uint64_t offset, void *bytes, size_t size)
{
	struct test_device *test = context;
	enum ntfs_result result;

	result = fuzz_read(&test->device, offset, bytes, size);
	if (result != NTFS_OK) {
		if (test->full_failure) {
			assert(offset <= test->device.size && size <= test->device.size - offset);
			memcpy(bytes, test->device.data + (size_t)offset, size);
		} else {
			memset(bytes, TEST_PARTIAL_BYTE, size / TEST_PARTIAL_DENOMINATOR);
		}
		return test->failure;
	}
	return NTFS_OK;
}

static void *
source_allocate(void *context, size_t size)
{
	struct test_device *test = context;

	return fuzz_allocate(&test->device, size);
}

static void
source_release(void *context, void *bytes, size_t size)
{
	struct test_device *test = context;

	fuzz_release(&test->device, bytes, size);
}

static enum ntfs_result
visit(void *context, const struct ntfs_logfile_page_observation *actual)
{
	struct test_visitor *test = context;
	struct ntfs_logfile_page_observation expected = {0};
	unsigned storage, code, target_code;
	int fields;

	assert(actual->offset == test->first_offset + (uint64_t)test->seen * test->page_bytes);
	if (test->rows != NULL) {
		fields = fscanf(test->rows,
		    "%" SCNu64 " %u %u %u %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu32
		    " %hu %hu %hu",
		    &expected.offset, &storage, &code, &target_code, &expected.target_offset,
		    &expected.page.copy_value, &expected.page.last_end_lsn, &expected.page.flags,
		    &expected.page.page_count, &expected.page.page_position,
		    &expected.page.next_record_offset);
		assert(fields == TEST_ROW_FIELDS);
		assert(actual->offset == expected.offset && (unsigned)actual->storage == storage &&
		    (unsigned)actual->result == code &&
		    (unsigned)actual->target_result == target_code &&
		    actual->target_offset == expected.target_offset);
		assert(actual->page.copy_value == expected.page.copy_value &&
		    actual->page.last_end_lsn == expected.page.last_end_lsn &&
		    actual->page.flags == expected.page.flags &&
		    actual->page.page_count == expected.page.page_count &&
		    actual->page.page_position == expected.page.page_position &&
		    actual->page.next_record_offset == expected.page.next_record_offset);
	}
	test->seen++;
	return test->seen == test->fail_at ? test->failure : NTFS_OK;
}

static void
summary(const struct test_case *test, const struct ntfs_logfile_inventory *out,
    const struct ntfs_logfile_restart *restart)
{
	assert(out->complete && out->total_pages == test->pages &&
	    out->examined_pages == test->pages && out->visited_pages == test->pages);
	assert(out->decoded_pages == test->decoded && out->missing_pages == test->missing &&
	    out->corrupt_pages == test->corrupt && out->invalid_targets == test->invalid &&
	    out->unsupported_targets == test->unsupported);
	assert(out->read_calls == test->pages &&
	    out->read_bytes == (uint64_t)test->pages * test->page_bytes &&
	    out->next_offset == restart->usable_bytes &&
	    out->max_observed_epoch_lsn == test->max_epoch &&
	    out->max_observed_end_lsn == test->max_completed);
}

static void
faults(struct ntfs_logfile *source, struct test_device *device, const struct test_case *test,
    const struct ntfs_logfile_restart *restart)
{
	static const enum ntfs_result failures[] = {NTFS_IO, NTFS_CORRUPT, NTFS_UNSUPPORTED,
	    NTFS_NOT_FOUND, NTFS_RANGE, NTFS_STALE, NTFS_END};
	struct ntfs_logfile_inventory out;
	struct test_visitor visitor;
	size_t kind, memory, allocations;
	uint32_t index, transfer;

	memory = device->device.memory;
	allocations = device->device.allocations;
	for (kind = 0; kind < sizeof(failures) / sizeof(failures[0]); kind++) {
		device->failure = failures[kind];
		for (transfer = 0; transfer < TEST_FAILED_TRANSFERS; transfer++) {
			device->full_failure = transfer != 0;
			for (index = 1; index <= test->pages; index++) {
				device->device.reads = 0;
				device->device.fail_read = index;
				visitor = (struct test_visitor){
				    .first_offset =
					(uint64_t)TEST_RESTART_PAGES * restart->system_page_bytes,
				    .page_bytes = test->page_bytes};
				assert(ntfs_logfile_visit_pages(source, visit, &visitor, &out) ==
				    failures[kind]);
				assert(!out.complete && out.read_calls == index &&
				    out.read_bytes == (uint64_t)index * test->page_bytes &&
				    out.examined_pages == index - 1 &&
				    out.visited_pages == index - 1 && visitor.seen == index - 1 &&
				    out.next_offset ==
					visitor.first_offset +
					    (uint64_t)(index - 1) * test->page_bytes);
				assert(out.decoded_pages + out.missing_pages + out.corrupt_pages ==
				    out.examined_pages);
				device->device.reads = 0;
				device->device.fail_read = 0;
				assert(
				    ntfs_logfile_visit_pages(source, NULL, NULL, &out) == NTFS_OK);
				summary(test, &out, restart);
				assert(device->device.memory == memory &&
				    device->device.allocations == allocations);
			}
		}
		device->full_failure = false;
		for (index = 1; index <= test->pages; index++) {
			device->device.reads = 0;
			visitor =
			    (struct test_visitor){.first_offset = (uint64_t)TEST_RESTART_PAGES *
				    restart->system_page_bytes,
				.page_bytes = test->page_bytes,
				.fail_at = index,
				.failure = failures[kind]};
			assert(ntfs_logfile_visit_pages(source, visit, &visitor, &out) ==
			    failures[kind]);
			assert(!out.complete && out.read_calls == index &&
			    out.examined_pages == index && out.visited_pages == index - 1 &&
			    visitor.seen == index &&
			    out.next_offset ==
				visitor.first_offset + (uint64_t)(index - 1) * test->page_bytes);
			assert(device->device.memory == memory &&
			    device->device.allocations == allocations);
		}
		device->device.reads = 0;
		assert(ntfs_logfile_visit_pages(source, NULL, NULL, &out) == NTFS_OK);
		summary(test, &out, restart);
	}
}

static void
credits(const struct ntfs_environment *environment, struct test_device *device,
    const struct test_case *test)
{
	struct ntfs_logfile *source;
	struct ntfs_logfile_limits limits;
	struct ntfs_logfile_inventory out;
	struct ntfs_logfile_restart restart;
	struct test_visitor visitor;
	size_t reads, allocations;
	unsigned kind;

	for (kind = TEST_CREDITS_EXACT; kind < TEST_CREDIT_CASES; kind++) {
		ntfs_logfile_default_limits(&limits);
		if (kind != TEST_CREDITS_DEFAULT) {
			limits.max_read_calls = test->pages - (kind == TEST_CREDITS_SHORT_CALLS);
			limits.max_read_bytes = (uint64_t)test->pages * test->page_bytes -
			    (kind == TEST_CREDITS_SHORT_BYTES);
		}
		device->device.reads = 0;
		device->device.fail_allocation = 0;
		assert(ntfs_logfile_open(environment, &limits, NULL, &source) == NTFS_OK);
		assert(ntfs_logfile_get_restart(source, &restart) == NTFS_OK);
		reads = device->device.reads;
		allocations = device->device.allocations;
		visitor = (struct test_visitor){
		    .first_offset = (uint64_t)TEST_RESTART_PAGES * restart.system_page_bytes,
		    .page_bytes = test->page_bytes};
		assert(ntfs_logfile_visit_pages(source, visit, &visitor, &out) ==
		    (kind == TEST_CREDITS_EXACT ? NTFS_OK : NTFS_RANGE));
		if (kind == TEST_CREDITS_EXACT) {
			summary(test, &out, &restart);
		} else {
			assert(out.total_pages == test->pages && !out.complete &&
			    out.examined_pages == 0 && out.visited_pages == 0 &&
			    out.read_calls == 0 && out.read_bytes == 0 && visitor.seen == 0 &&
			    device->device.reads == reads &&
			    out.next_offset == visitor.first_offset);
		}
		assert(device->device.allocations == allocations);
		ntfs_logfile_close(source);
		assert(device->device.memory == 0);
	}
}

static void
check(const char *directory, const struct test_case *test)
{
	struct ntfs_logfile *source;
	struct ntfs_environment environment;
	struct ntfs_logfile_limits limits;
	struct ntfs_logfile_inventory out, zero = {0};
	struct ntfs_logfile_restart before, after;
	struct test_device device = {0};
	struct test_visitor visitor;
	uint8_t *bytes, *saved;
	size_t size, allocations, memory;

	bytes = source_bytes(directory, test->name, &size);
	saved = malloc(size);
	assert(saved != NULL);
	memcpy(saved, bytes, size);
	device.device = (struct fuzz_device){.data = bytes, .size = size};
	device.failure = NTFS_IO;
	environment = (struct ntfs_environment){
	    NTFS_API_VERSION, &device, size, source_read, source_allocate, source_release};
	ntfs_logfile_default_limits(&limits);
	limits.max_read_calls = test->pages;
	limits.max_read_bytes = (uint64_t)test->pages * test->page_bytes;
	assert(ntfs_logfile_open(&environment, &limits, NULL, &source) == NTFS_OK);
	assert(ntfs_logfile_get_restart(source, &before) == NTFS_OK);
	allocations = device.device.allocations;
	memory = device.device.memory;
	device.device.fail_allocation = allocations + 1;
	device.device.reads = 0;
	visitor = (struct test_visitor){.rows = open_file(directory, test->name, ".rows"),
	    .first_offset = (uint64_t)TEST_RESTART_PAGES * before.system_page_bytes,
	    .page_bytes = test->page_bytes};
	assert(ntfs_logfile_visit_pages(source, visit, &visitor, &out) == NTFS_OK);
	summary(test, &out, &before);
	assert(visitor.seen == test->pages);
	assert(fscanf(visitor.rows, " %*c") == EOF && fclose(visitor.rows) == 0);
	assert(device.device.memory == memory && device.device.allocations == allocations);
	if (test->faults != 0) {
		faults(source, &device, test, &before);
	}
	assert(ntfs_logfile_get_restart(source, &after) == NTFS_OK);
	assert(memcmp(&before, &after, sizeof(before)) == 0 && memcmp(bytes, saved, size) == 0);
	device.device.reads = 0;
	memset(&out, TEST_PARTIAL_BYTE, sizeof(out));
	assert(ntfs_logfile_visit_pages(NULL, NULL, NULL, &out) == NTFS_INVALID);
	assert(memcmp(&out, &zero, sizeof(out)) == 0);
	assert(ntfs_logfile_visit_pages(source, visit, &visitor, NULL) == NTFS_INVALID);
	assert(device.device.reads == 0 && device.device.allocations == allocations);
	ntfs_logfile_close(source);
	assert(device.device.memory == 0);
	if (test->faults != 0) {
		credits(&environment, &device, test);
	}
	assert(memcmp(bytes, saved, size) == 0);
	free(saved);
	free(bytes);
}

static void
virtual_maximum(const char *directory)
{
	struct ntfs_logfile *source;
	struct ntfs_environment environment;
	struct ntfs_logfile_inventory out;
	struct ntfs_logfile_restart restart;
	struct test_device device = {0};
	uint8_t *bytes;
	size_t size, reads, allocations;

	bytes = source_bytes(directory, "maximum-file-prefix.bin", &size);
	device.device = (struct fuzz_device){.data = bytes, .size = size};
	device.failure = NTFS_IO;
	environment = (struct ntfs_environment){NTFS_API_VERSION, &device,
	    NTFS_LOGFILE_MAX_FILE_BYTES, source_read, source_allocate, source_release};
	assert(ntfs_logfile_open(&environment, NULL, NULL, &source) == NTFS_OK);
	assert(ntfs_logfile_get_restart(source, &restart) == NTFS_OK);
	reads = device.device.reads;
	allocations = device.device.allocations;
	assert(ntfs_logfile_visit_pages(source, NULL, NULL, &out) == NTFS_RANGE);
	assert(out.total_pages ==
		(restart.usable_bytes - (uint64_t)TEST_RESTART_PAGES * restart.system_page_bytes) /
		    restart.log_page_bytes &&
	    !out.complete && out.read_calls == 0 && out.read_bytes == 0 &&
	    out.examined_pages == 0 && out.visited_pages == 0 && device.device.reads == reads &&
	    device.device.allocations == allocations);
	ntfs_logfile_close(source);
	assert(device.device.memory == 0);
	free(bytes);
}

int
main(int argc, char **argv)
{
	struct test_case test;
	FILE *cases;
	unsigned count = 0;
	int fields;

	assert(argc == 2);
	cases = open_file(argv[1], "cases.txt", "");
	for (;;) {
		fields = fscanf(cases,
		    "%" TEST_STRINGIFY(TEST_NAME_CHARACTERS) "s %" SCNu32 " %" SCNu32 " %" SCNu32
							     " %" SCNu32 " %" SCNu32 " %" SCNu32
							     " %" SCNu32 " %" SCNu64 " %" SCNu64
							     " %" SCNu32,
		    test.name, &test.page_bytes, &test.pages, &test.decoded, &test.missing,
		    &test.corrupt, &test.invalid, &test.unsupported, &test.max_epoch,
		    &test.max_completed, &test.faults);
		if (fields == EOF) {
			break;
		}
		assert(fields == TEST_CASE_FIELDS);
		check(argv[1], &test);
		count++;
	}
	assert(fclose(cases) == 0 && count != 0);
	virtual_maximum(argv[1]);
	printf(
	    "PASS: %u complete ordered physical inventories, faults, visitor stops and credits\n",
	    count);
	return 0;
}
