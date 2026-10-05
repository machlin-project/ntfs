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
	TEST_PAGE_BYTES = 4096,
	TEST_INDEX_BYTES = 1024 * 1024,
	TEST_READ_BYTES = 16 * 1024 * 1024,
	TEST_RECORDS = 2,
	TEST_CASE_FIELDS = 8,
	TEST_PARTIAL_BYTE = 0x71
};

struct test_device {
	struct fuzz_device device;
	bool partial;
};

struct test_case {
	char name[TEST_NAME_BYTES];
	uint32_t code, qualified, maximum_reads, faults;
	uint64_t first, alias, home;
};

struct packet_comparison {
	const char *directory, *name;
	uint32_t count;
};

static FILE *
open_input(const char *directory, const char *name)
{
	char path[TEST_PATH_BYTES];
	int length;
	FILE *input;

	length = snprintf(path, sizeof(path), "%s/%s", directory, name);
	assert(length > 0 && (size_t)length < sizeof(path));
	input = fopen(path, "rb");
	assert(input != NULL);
	return input;
}

static uint8_t *
load_input(const char *directory, const char *name, size_t *size)
{
	FILE *input = open_input(directory, name);
	long bytes;
	uint8_t *data;

	assert(fseek(input, 0, SEEK_END) == 0);
	bytes = ftell(input);
	assert(bytes > 0 && (unsigned long)bytes <= TEST_INDEX_BYTES);
	assert(fseek(input, 0, SEEK_SET) == 0);
	*size = (size_t)bytes;
	data = malloc(*size);
	assert(data != NULL);
	assert(fread(data, 1, *size, input) == *size);
	assert(fclose(input) == 0);
	return data;
}

static enum ntfs_result
read_input(void *context, uint64_t offset, void *buffer, size_t size)
{
	struct test_device *device = context;
	enum ntfs_result result;

	result = fuzz_read(&device->device, offset, buffer, size);
	if (result != NTFS_OK && device->partial) {
		memset(buffer, TEST_PARTIAL_BYTE, size / 2);
	}
	return result;
}

static enum ntfs_result
compare_packet(void *context, const struct ntfs_logfile_record_view *view, const void *bytes)
{
	struct packet_comparison *comparison = context;
	char name[TEST_PATH_BYTES];
	size_t size;
	uint8_t *expected;
	int length;

	assert(comparison->count < TEST_RECORDS);
	length = snprintf(name, sizeof(name), "%s.packet-%u", comparison->name, comparison->count);
	assert(length > 0 && (size_t)length < sizeof(name));
	expected = load_input(comparison->directory, name, &size);
	assert(size == view->bytes && memcmp(expected, bytes, size) == 0);
	free(expected);
	comparison->count++;
	return NTFS_OK;
}

static void
check_case(const char *directory, const struct test_case *test)
{
	struct test_device device = {0};
	struct ntfs_environment environment;
	struct ntfs_logfile_limits limits;
	struct ntfs_logfile_report opened;
	struct ntfs_logfile_page_index_report report, absent;
	struct ntfs_logfile_indexed_page indexed;
	struct ntfs_logfile_history_report history;
	struct ntfs_logfile *source;
	struct packet_comparison comparison = {directory, test->name, 0};
	uint8_t workspace[TEST_PAGE_BYTES];
	uint8_t *bytes;
	size_t size, memory, baseline_reads, index_reads, fault, mode;
	enum ntfs_result result;

	bytes = load_input(directory, test->name, &size);
	device.device.data = bytes;
	device.device.size = size;
	environment = fuzz_environment(&device.device);
	environment.context = &device;
	environment.read = read_input;
	ntfs_logfile_default_limits(&limits);
	limits.max_read_calls = FUZZ_READ_BUDGET;
	limits.max_read_bytes = TEST_READ_BYTES;
	assert(ntfs_logfile_open(&environment, &limits, &opened, &source) == NTFS_OK);
	memory = device.device.memory;
	baseline_reads = device.device.reads;
	assert(ntfs_logfile_prepare_page_index(source, TEST_INDEX_BYTES, &report) == NTFS_OK);
	assert(report.published && report.inventory.complete);
	assert(ntfs_logfile_get_indexed_page(source, test->alias, &indexed) == NTFS_OK);
	assert(indexed.retained_fast_copy == (test->qualified != 0));
	index_reads = device.device.reads - baseline_reads;
	result = ntfs_logfile_visit_records(source, test->first, TEST_RECORDS, workspace,
	    sizeof(workspace), compare_packet, &comparison, &history);
	assert(result == (enum ntfs_result)test->code);
	assert(history.complete == (test->code == NTFS_OK));
	if (test->code == NTFS_OK) {
		assert(comparison.count == TEST_RECORDS && history.endpoint_verified);
	} else {
		assert(comparison.count == 0);
	}
	ntfs_logfile_clear_page_index(source);
	assert(device.device.memory == memory);
	if (test->faults) {
		for (mode = 0; mode < 2; mode++) {
			for (fault = 1; fault <= index_reads; fault++) {
				device.device.reads = 0;
				device.partial = mode != 0;
				device.device.fail_read = device.device.reads + fault;
				assert(ntfs_logfile_prepare_page_index(
					   source, TEST_INDEX_BYTES, &report) == NTFS_IO);
				assert(!report.published && device.device.memory == memory);
				assert(ntfs_logfile_get_page_index_report(source, &absent) ==
				    NTFS_NOT_FOUND);
				device.device.fail_read = 0;
				assert(ntfs_logfile_prepare_page_index(
					   source, TEST_INDEX_BYTES, &report) == NTFS_OK);
				ntfs_logfile_clear_page_index(source);
			}
		}
		device.device.fail_allocation = device.device.allocations + 1;
		assert(ntfs_logfile_prepare_page_index(source, TEST_INDEX_BYTES, &report) ==
		    NTFS_NO_MEMORY);
		assert(!report.published && device.device.memory == memory);
		device.device.fail_allocation = 0;
	}
	device.device.reads = 0;
	ntfs_logfile_close(source);
	assert(device.device.memory == 0);
	if (test->faults) {
		for (mode = 0; mode < 2; mode++) {
			device.device.reads = 0;
			limits.max_read_calls = test->maximum_reads - 1;
			limits.max_read_bytes = TEST_READ_BYTES;
			if (mode != 0) {
				limits.max_read_calls = test->maximum_reads;
				limits.max_read_bytes =
				    (uint64_t)test->maximum_reads * TEST_PAGE_BYTES - 1;
			}
			assert(
			    ntfs_logfile_open(&environment, &limits, &opened, &source) == NTFS_OK);
			assert(ntfs_logfile_prepare_page_index(source, TEST_INDEX_BYTES, &report) ==
			    NTFS_RANGE);
			assert(!report.published && report.inventory.complete);
			assert(report.read_calls == report.inventory.read_calls);
			ntfs_logfile_close(source);
			assert(device.device.memory == 0);
		}
	}
	free(bytes);
}

int
main(int argc, char **argv)
{
	struct test_case test;
	FILE *rows;
	uint32_t count = 0;
	int fields;

	assert(argc == 2);
	rows = open_input(argv[1], "cases.rows");
	while ((fields = fscanf(rows,
		    "%127s %" SCNu32 " %" SCNu32 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu32
		    " %" SCNu32,
		    test.name, &test.code, &test.qualified, &test.first, &test.alias, &test.home,
		    &test.maximum_reads, &test.faults)) != EOF) {
		assert(fields == TEST_CASE_FIELDS);
		check_case(argv[1], &test);
		count++;
	}
	assert(fclose(rows) == 0 && count != 0);
	printf(
	    "PASS: %u retained restart-copy profiles, exact packets, faults and credits\n", count);
	return 0;
}
