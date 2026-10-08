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
	TEST_NAME_BYTES = TEST_NAME_CHARACTERS + 1,
	TEST_PATH_BYTES = 1024,
	TEST_SOURCE_BYTES = 4 * 1024 * 1024,
	TEST_INDEX_BYTES = 1024 * 1024,
	TEST_READ_CALLS = 8192,
	TEST_READ_BYTES = 64 * 1024 * 1024,
	TEST_LINK_BYTES = NTFS_LOGFILE_TRANSACTION_MAX_RECORDS * 2 * sizeof(uint64_t),
	TEST_LINK_ITEM_BYTES = 2 * sizeof(uint64_t),
	TEST_GUARD_BYTES = 32,
	TEST_SENTINEL = 0xa5,
	TEST_PARTIAL_BYTE = 0x71,
	TEST_PARTIAL_DIVISOR = 2,
	TEST_UNALIGNED_SHIFT = 1,
	TEST_COLUMNS = 21,
	TEST_PACKET_COLUMNS = 4,
	/* The dense author's 1-MiB/512-byte geometry needs fewer than 3072
	 * preparation reads, but its 4096-record walk needs one per packet. */
	TEST_DENSE_PAGE_BYTES = 512,
	TEST_DENSE_OWNER_CALLS = 3072,
	TEST_DENSE_OWNER_READ_BYTES = TEST_DENSE_OWNER_CALLS * TEST_DENSE_PAGE_BYTES
};

enum {
	TEST_ZERO_RECORDS,
	TEST_ZERO_CALLS,
	TEST_ZERO_BYTES,
	TEST_EXCESS_RECORDS,
	TEST_NULL_SOURCE,
	TEST_NULL_REPORT,
	TEST_NULL_RECORD_WORKSPACE,
	TEST_NULL_LINK_WORKSPACE,
	TEST_NULL_VISITOR,
	TEST_ADMISSION_CASES
};

struct test_device {
	struct fuzz_device device;
	enum ntfs_result failure;
	bool full_failure;
};

struct test_case {
	char name[TEST_NAME_BYTES];
	uint64_t root;
	uint32_t index, sequence, transaction, code, max_records;
	struct ntfs_logfile_transaction_report expected;
};

struct visitor_context {
	FILE *rows;
	const uint8_t *packets;
	size_t packet_bytes, position, calls, stop;
	uint32_t reads;
	uint64_t last_page;
	enum ntfs_result stop_result;
	struct ntfs_logfile_transaction_limits *alter_limits;
};

struct guarded_report {
	uint8_t before[TEST_GUARD_BYTES];
	struct ntfs_logfile_transaction_report value;
	uint8_t after[TEST_GUARD_BYTES];
};

static FILE *
open_file(const char *directory, const char *name, const char *suffix)
{
	char path[TEST_PATH_BYTES];
	FILE *file;
	int length;

	length = snprintf(path, sizeof(path), "%s/%s%s", directory, name, suffix);
	assert(length > 0 && (size_t)length < sizeof(path));
	file = fopen(path, "rb");
	assert(file != NULL);
	return file;
}

static uint8_t *
read_file(const char *directory, const char *name, const char *suffix, size_t *size)
{
	FILE *file;
	uint8_t *bytes;
	long length;

	file = open_file(directory, name, suffix);
	assert(fseek(file, 0, SEEK_END) == 0);
	length = ftell(file);
	assert(length >= 0 && length <= TEST_SOURCE_BYTES && fseek(file, 0, SEEK_SET) == 0);
	*size = (size_t)length;
	bytes = malloc(*size == 0 ? 1 : *size);
	assert(bytes != NULL && fread(bytes, 1, *size, file) == *size && fclose(file) == 0);
	return bytes;
}

static void
guard(const uint8_t *bytes, size_t size)
{
	size_t index;

	for (index = 0; index < size; index++) {
		assert(bytes[index] == TEST_SENTINEL);
	}
}

static enum ntfs_result
read_source(void *context, uint64_t offset, void *bytes, size_t size)
{
	struct test_device *test = context;
	struct fuzz_device *device = &test->device;

	device->reads++;
	assert(offset <= device->size && size <= device->size - offset);
	if (device->reads == device->fail_read) {
		if (test->full_failure) {
			memcpy(bytes, device->data + (size_t)offset, size);
		} else {
			memset(bytes, TEST_PARTIAL_BYTE, size / TEST_PARTIAL_DIVISOR);
		}
		return test->failure;
	}
	memcpy(bytes, device->data + (size_t)offset, size);
	return NTFS_OK;
}

static void *
allocate_source(void *context, size_t bytes)
{
	struct test_device *test = context;

	return fuzz_allocate(&test->device, bytes);
}

static void
release_source(void *context, void *bytes, size_t size)
{
	struct test_device *test = context;

	fuzz_release(&test->device, bytes, size);
}

static void
reset_visitor(struct visitor_context *context)
{
	assert(fseek(context->rows, 0, SEEK_SET) == 0);
	context->position = 0;
	context->calls = 0;
	context->reads = 0;
	context->last_page = UINT64_MAX;
	context->stop = 0;
	context->alter_limits = NULL;
}

static enum ntfs_result
visit(void *opaque, const struct ntfs_logfile_record_view *view, const void *bytes)
{
	struct visitor_context *context = opaque;
	uint64_t lsn;
	uint32_t length, pages, copies;

	assert(fscanf(context->rows, "%" SCNu64 " %" SCNu32 " %" SCNu32 " %" SCNu32, &lsn, &length,
		   &pages, &copies) == TEST_PACKET_COLUMNS);
	assert(view->record.lsn == lsn && view->bytes == length && view->pages_read == pages &&
	    view->copy_pages_read == copies);
	assert(context->position <= context->packet_bytes &&
	    length <= context->packet_bytes - context->position);
	assert(memcmp(bytes, context->packets + context->position, length) == 0);
	context->position += length;
	context->reads += pages - (view->first_page_offset == context->last_page);
	context->last_page = view->last_page_offset;
	assert(view->read_calls == context->reads);
	context->calls++;
	if (context->alter_limits != NULL) {
		*context->alter_limits = (struct ntfs_logfile_transaction_limits){0};
		context->alter_limits = NULL;
	}
	return context->calls == context->stop ? context->stop_result : NTFS_OK;
}

static void
admission(const struct test_case *test, struct ntfs_logfile *source, struct test_device *device,
    void *records, void *links, struct visitor_context *context, struct guarded_report *report)
{
	struct ntfs_logfile_transaction_limits limits;
	struct ntfs_logfile_transaction_report empty = {0};
	enum ntfs_result result, expected;
	size_t mode, reads, allocations;

	for (mode = 0; mode < TEST_ADMISSION_CASES; mode++) {
		reset_visitor(context);
		limits = (struct ntfs_logfile_transaction_limits){
		    NTFS_LOGFILE_TRANSACTION_MAX_RECORDS, TEST_READ_CALLS, TEST_READ_BYTES};
		if (mode == TEST_ZERO_RECORDS) {
			limits.max_records = 0;
		} else if (mode == TEST_ZERO_CALLS) {
			limits.max_read_calls = 0;
		} else if (mode == TEST_ZERO_BYTES) {
			limits.max_read_bytes = 0;
		} else if (mode == TEST_EXCESS_RECORDS) {
			limits.max_records++;
		}
		reads = device->device.reads;
		allocations = device->device.allocations;
		expected = mode == TEST_EXCESS_RECORDS ? NTFS_RANGE : NTFS_INVALID;
		memset(&report->value, TEST_SENTINEL, sizeof(report->value));
		result = ntfs_logfile_visit_transaction(mode == TEST_NULL_SOURCE ? NULL : source,
		    (uint16_t)test->index, (uint16_t)test->sequence, test->transaction, test->root,
		    &limits, mode == TEST_NULL_RECORD_WORKSPACE ? NULL : records,
		    NTFS_LOGFILE_MAX_RECORD_BYTES, mode == TEST_NULL_LINK_WORKSPACE ? NULL : links,
		    TEST_LINK_BYTES, mode == TEST_NULL_VISITOR ? NULL : visit, context,
		    mode == TEST_NULL_REPORT ? NULL : &report->value);
		assert(result == expected && context->calls == 0 && device->device.reads == reads &&
		    device->device.allocations == allocations);
		if (mode == TEST_NULL_REPORT) {
			guard((const void *)&report->value, sizeof(report->value));
		} else {
			assert(memcmp(&report->value, &empty, sizeof(empty)) == 0);
		}
	}
}

static void
equal_report(const struct ntfs_logfile_transaction_report *a,
    const struct ntfs_logfile_transaction_report *b)
{
	assert(a->root_lsn == b->root_lsn && a->last_lsn == b->last_lsn &&
	    a->next_lsn == b->next_lsn && a->control_lsn == b->control_lsn &&
	    a->record_bytes == b->record_bytes && a->read_bytes == b->read_bytes &&
	    a->transaction == b->transaction && a->read_calls == b->read_calls &&
	    a->examined_records == b->examined_records &&
	    a->visited_records == b->visited_records && a->copy_pages_read == b->copy_pages_read &&
	    a->undo_references == b->undo_references &&
	    a->control_operation == b->control_operation && a->complete == b->complete);
}

static void
exercise(const char *directory, const struct test_case *test)
{
	static const enum ntfs_result failures[] = {
	    NTFS_IO, NTFS_RANGE, NTFS_NOT_FOUND, NTFS_CORRUPT};
	struct test_device device = {0};
	struct ntfs_environment environment;
	struct ntfs_logfile_limits owner_limits;
	struct ntfs_logfile_page_index_report preparation;
	struct ntfs_logfile_restart restart;
	struct ntfs_logfile *source = NULL;
	struct ntfs_logfile_transaction_limits limits;
	struct guarded_report report;
	struct visitor_context context = {0};
	uint8_t *input, *unchanged, *record_guard, *link_guard, *records, *links;
	size_t source_bytes, packet_bytes, before_reads, before_allocations, retained;
	size_t shift, item, mode, failure, record, prefix_reads, completed, read_faults = 0;
	size_t record_capacity, staging_capacity = 0, growths = 0;
	uint64_t lsn;
	uint32_t bytes, pages, copies;
	enum ntfs_result result;
	bool sweep;

	input = read_file(directory, test->name, "", &source_bytes);
	unchanged = malloc(source_bytes);
	record_guard =
	    malloc(NTFS_LOGFILE_MAX_RECORD_BYTES + 2 * TEST_GUARD_BYTES + TEST_UNALIGNED_SHIFT);
	link_guard = malloc(TEST_LINK_BYTES + 2 * TEST_GUARD_BYTES + TEST_UNALIGNED_SHIFT);
	assert(unchanged != NULL && record_guard != NULL && link_guard != NULL);
	memcpy(unchanged, input, source_bytes);
	context.packets = read_file(directory, test->name, ".packets", &packet_bytes);
	context.packet_bytes = packet_bytes;
	context.rows = open_file(directory, test->name, ".records.tsv");
	device.device.data = input;
	device.device.size = source_bytes;
	environment = fuzz_environment(&device.device);
	environment.context = &device;
	environment.read = read_source;
	environment.allocate = allocate_source;
	environment.release = release_source;
	ntfs_logfile_default_limits(&owner_limits);
	owner_limits.max_read_calls = TEST_READ_CALLS;
	owner_limits.max_read_bytes = TEST_READ_BYTES;
	assert(ntfs_logfile_open(&environment, &owner_limits, NULL, &source) == NTFS_OK);
	assert(ntfs_logfile_prepare_page_index(source, TEST_INDEX_BYTES, &preparation) == NTFS_OK);
	retained = device.device.memory;
	limits = (struct ntfs_logfile_transaction_limits){
	    test->max_records, TEST_READ_CALLS, TEST_READ_BYTES};
	for (shift = 0; shift <= TEST_UNALIGNED_SHIFT; shift++) {
		memset(record_guard, TEST_SENTINEL,
		    NTFS_LOGFILE_MAX_RECORD_BYTES + 2 * TEST_GUARD_BYTES + TEST_UNALIGNED_SHIFT);
		memset(link_guard, TEST_SENTINEL,
		    TEST_LINK_BYTES + 2 * TEST_GUARD_BYTES + TEST_UNALIGNED_SHIFT);
		memset(&report, TEST_SENTINEL, sizeof(report));
		records = record_guard + TEST_GUARD_BYTES + shift;
		links = link_guard + TEST_GUARD_BYTES + shift;
		reset_visitor(&context);
		before_reads = device.device.reads;
		result = ntfs_logfile_visit_transaction(source, (uint16_t)test->index,
		    (uint16_t)test->sequence, test->transaction, test->root, &limits, records,
		    NTFS_LOGFILE_MAX_RECORD_BYTES, links, TEST_LINK_BYTES, visit, &context,
		    &report.value);
		if (result != (enum ntfs_result)test->code) {
			fprintf(stderr, "%s: got %d, expected %u\n", test->name, (int)result,
			    test->code);
		}
		assert(result == (enum ntfs_result)test->code);
		equal_report(&report.value, &test->expected);
		assert(context.calls == test->expected.visited_records);
		assert(context.position == packet_bytes);
		assert(device.device.reads - before_reads == report.value.read_calls);
		assert(device.device.memory == retained);
		guard(report.before, sizeof(report.before));
		guard(report.after, sizeof(report.after));
		guard(record_guard, TEST_GUARD_BYTES + shift);
		guard(records + NTFS_LOGFILE_MAX_RECORD_BYTES, TEST_GUARD_BYTES);
		guard(link_guard, TEST_GUARD_BYTES + shift);
		guard(links + TEST_LINK_BYTES, TEST_GUARD_BYTES);
		guard(links + context.calls * TEST_LINK_ITEM_BYTES,
		    TEST_LINK_BYTES - context.calls * TEST_LINK_ITEM_BYTES);
	}
	sweep = test->code == NTFS_OK &&
	    (strcmp(test->name, "legacy-markers-extended-0.journal") == 0 ||
		strcmp(test->name, "fast-copy-31.journal") == 0 ||
		strcmp(test->name, "legacy-spanning-root.journal") == 0 ||
		strcmp(test->name, "legacy-wrapped-root.journal") == 0 ||
		strcmp(test->name, "legacy-exact-record-cap.journal") == 0);
	if (sweep) {
		admission(test, source, &device, records, links, &context, &report);
		assert(ntfs_logfile_get_restart(source, &restart) == NTFS_OK);
		reset_visitor(&context);
		before_reads = device.device.reads;
		before_allocations = device.device.allocations;
		result = ntfs_logfile_visit_transaction(source, (uint16_t)test->index,
		    (uint16_t)test->sequence, test->transaction, test->root, &limits, records,
		    restart.record_header_bytes - 1u, links, TEST_LINK_BYTES, visit, &context,
		    &report.value);
		assert(result == NTFS_RANGE && !report.value.complete &&
		    report.value.read_calls == 0 && report.value.examined_records == 0 &&
		    report.value.visited_records == 0 && context.calls == 0 &&
		    device.device.reads == before_reads &&
		    device.device.allocations == before_allocations);
		record_capacity = 0;
		for (record = 0; record < test->expected.visited_records; record++) {
			assert(fscanf(context.rows, "%" SCNu64 " %" SCNu32 " %" SCNu32 " %" SCNu32,
				   &lsn, &bytes, &pages, &copies) == TEST_PACKET_COLUMNS);
			if (bytes > record_capacity) {
				record_capacity = bytes;
			}
		}
		reset_visitor(&context);
		result = ntfs_logfile_visit_transaction(source, (uint16_t)test->index,
		    (uint16_t)test->sequence, test->transaction, test->root, &limits, records,
		    record_capacity, links, TEST_LINK_BYTES, visit, &context, &report.value);
		assert(result == NTFS_OK);
		equal_report(&report.value, &test->expected);
		for (item = 1; item <= test->expected.read_calls; item++) {
			for (mode = 0; mode < 2; mode++) {
				for (failure = 0; failure < sizeof(failures) / sizeof(failures[0]);
				    failure++) {
					reset_visitor(&context);
					before_reads = device.device.reads;
					device.device.fail_read = before_reads + item;
					device.failure = failures[failure];
					device.full_failure = mode != 0;
					result = ntfs_logfile_visit_transaction(source,
					    (uint16_t)test->index, (uint16_t)test->sequence,
					    test->transaction, test->root, &limits, records,
					    NTFS_LOGFILE_MAX_RECORD_BYTES, links, TEST_LINK_BYTES,
					    visit, &context, &report.value);
					assert(
					    result == failures[failure] && !report.value.complete);
					assert(report.value.read_calls == item &&
					    device.device.reads - before_reads == item);
					assert(report.value.examined_records == context.calls &&
					    report.value.visited_records == context.calls);
					assert(report.value.record_bytes == context.position &&
					    device.device.memory == retained);
					device.device.fail_read = 0;
					read_faults++;
				}
			}
		}
		prefix_reads = 0;
		reset_visitor(&context);
		for (record = 0; record < test->expected.visited_records; record++) {
			assert(fscanf(context.rows, "%" SCNu64 " %" SCNu32 " %" SCNu32 " %" SCNu32,
				   &lsn, &bytes, &pages, &copies) == TEST_PACKET_COLUMNS);
			if (bytes > staging_capacity) {
				staging_capacity = bytes;
				growths++;
				reset_visitor(&context);
				before_reads = device.device.reads;
				before_allocations = device.device.allocations;
				device.device.fail_allocation = before_allocations + growths;
				result =
				    ntfs_logfile_visit_transaction(source, (uint16_t)test->index,
					(uint16_t)test->sequence, test->transaction, test->root,
					&limits, records, NTFS_LOGFILE_MAX_RECORD_BYTES, links,
					TEST_LINK_BYTES, visit, &context, &report.value);
				assert(result == NTFS_NO_MEMORY && !report.value.complete &&
				    context.calls == record);
				assert(report.value.read_calls == prefix_reads + 1 &&
				    report.value.visited_records == record);
				assert(device.device.memory == retained);
				device.device.fail_allocation = 0;
				assert(fscanf(context.rows,
					   "%" SCNu64 " %" SCNu32 " %" SCNu32 " %" SCNu32, &lsn,
					   &bytes, &pages, &copies) == TEST_PACKET_COLUMNS);
			}
			prefix_reads += pages;
		}
		for (item = 1; item <= test->expected.visited_records; item++) {
			reset_visitor(&context);
			context.stop = item;
			context.stop_result = NTFS_END;
			result = ntfs_logfile_visit_transaction(source, (uint16_t)test->index,
			    (uint16_t)test->sequence, test->transaction, test->root, &limits,
			    records, NTFS_LOGFILE_MAX_RECORD_BYTES, links, TEST_LINK_BYTES, visit,
			    &context, &report.value);
			assert(
			    result == NTFS_END && !report.value.complete && context.calls == item);
			assert(report.value.examined_records == item &&
			    report.value.visited_records == item - 1);
		}
		reset_visitor(&context);
		limits.max_records = test->expected.visited_records;
		limits.max_read_calls = test->expected.read_calls;
		limits.max_read_bytes = test->expected.read_bytes;
		result = ntfs_logfile_visit_transaction(source, (uint16_t)test->index,
		    (uint16_t)test->sequence, test->transaction, test->root, &limits, records,
		    NTFS_LOGFILE_MAX_RECORD_BYTES, links,
		    (size_t)limits.max_records * TEST_LINK_ITEM_BYTES, visit, &context,
		    &report.value);
		assert(result == NTFS_OK);
		equal_report(&report.value, &test->expected);
		for (mode = 0; mode < 3; mode++) {
			reset_visitor(&context);
			before_reads = device.device.reads;
			if (mode == 0) {
				limits.max_read_calls--;
			} else if (mode == 1) {
				limits.max_read_calls++;
				limits.max_read_bytes--;
			} else {
				limits.max_read_bytes++;
			}
			result = ntfs_logfile_visit_transaction(source, (uint16_t)test->index,
			    (uint16_t)test->sequence, test->transaction, test->root, &limits,
			    records, NTFS_LOGFILE_MAX_RECORD_BYTES, links,
			    (size_t)limits.max_records * TEST_LINK_ITEM_BYTES - (mode == 2), visit,
			    &context, &report.value);
			assert(result == NTFS_RANGE && !report.value.complete);
			assert(device.device.reads - before_reads == report.value.read_calls);
			if (mode == 2) {
				assert(report.value.read_calls == 0 && context.calls == 0);
			}
		}
		reset_visitor(&context);
		result = ntfs_logfile_visit_transaction(source, (uint16_t)test->index,
		    (uint16_t)test->sequence, test->transaction, test->root, NULL, records,
		    NTFS_LOGFILE_MAX_RECORD_BYTES, links, TEST_LINK_BYTES, visit, &context,
		    &report.value);
		assert(result == NTFS_OK);
		equal_report(&report.value, &test->expected);
		reset_visitor(&context);
		context.alter_limits = &limits;
		result = ntfs_logfile_visit_transaction(source, (uint16_t)test->index,
		    (uint16_t)test->sequence, test->transaction, test->root, &limits, records,
		    NTFS_LOGFILE_MAX_RECORD_BYTES, links, TEST_LINK_BYTES, visit, &context,
		    &report.value);
		assert(result == NTFS_OK && limits.max_records == 0 && limits.max_read_calls == 0 &&
		    limits.max_read_bytes == 0);
		equal_report(&report.value, &test->expected);
		limits = (struct ntfs_logfile_transaction_limits){
		    test->max_records, TEST_READ_CALLS, TEST_READ_BYTES};
		ntfs_logfile_clear_page_index(source);
		reset_visitor(&context);
		before_reads = device.device.reads;
		before_allocations = device.device.allocations;
		result = ntfs_logfile_visit_transaction(source, (uint16_t)test->index,
		    (uint16_t)test->sequence, test->transaction, test->root, &limits, records,
		    NTFS_LOGFILE_MAX_RECORD_BYTES, links, TEST_LINK_BYTES, visit, &context,
		    &report.value);
		assert(result == NTFS_NOT_FOUND && !report.value.complete && context.calls == 0 &&
		    report.value.read_calls == 0 && device.device.reads == before_reads &&
		    device.device.allocations == before_allocations);
	}
	completed = context.calls;
	assert(memcmp(input, unchanged, source_bytes) == 0);
	ntfs_logfile_close(source);
	assert(device.device.memory == 0);
	if (strcmp(test->name, "dense-records-4096.journal") == 0) {
		for (mode = 0; mode < 2; mode++) {
			owner_limits.max_read_calls =
			    mode == 0 ? TEST_DENSE_OWNER_CALLS : TEST_READ_CALLS;
			owner_limits.max_read_bytes =
			    mode == 0 ? TEST_READ_BYTES : TEST_DENSE_OWNER_READ_BYTES;
			device.device.reads = 0;
			assert(ntfs_logfile_open(&environment, &owner_limits, NULL, &source) ==
			    NTFS_OK);
			assert(ntfs_logfile_prepare_page_index(
				   source, TEST_INDEX_BYTES, &preparation) == NTFS_OK);
			retained = device.device.memory;
			limits = (struct ntfs_logfile_transaction_limits){
			    NTFS_LOGFILE_TRANSACTION_MAX_RECORDS, TEST_READ_CALLS, TEST_READ_BYTES};
			reset_visitor(&context);
			before_reads = device.device.reads;
			result = ntfs_logfile_visit_transaction(source, (uint16_t)test->index,
			    (uint16_t)test->sequence, test->transaction, test->root, &limits,
			    records, NTFS_LOGFILE_MAX_RECORD_BYTES, links, TEST_LINK_BYTES, visit,
			    &context, &report.value);
			assert(result == NTFS_OK && report.value.complete);
			assert(report.value.visited_records == test->expected.visited_records &&
			    report.value.read_calls == test->expected.read_calls &&
			    report.value.read_bytes == test->expected.read_bytes &&
			    device.device.reads - before_reads == test->expected.read_calls &&
			    device.device.memory == retained);
			ntfs_logfile_close(source);
			assert(device.device.memory == 0);
		}
	}
	assert(memcmp(input, unchanged, source_bytes) == 0);
	guard(report.before, sizeof(report.before));
	guard(report.after, sizeof(report.after));
	guard(record_guard, TEST_GUARD_BYTES + TEST_UNALIGNED_SHIFT);
	guard(records + NTFS_LOGFILE_MAX_RECORD_BYTES, TEST_GUARD_BYTES);
	guard(link_guard, TEST_GUARD_BYTES + TEST_UNALIGNED_SHIFT);
	guard(links + TEST_LINK_BYTES, TEST_GUARD_BYTES);
	assert(fclose(context.rows) == 0);
	free((void *)context.packets);
	free(link_guard);
	free(record_guard);
	free(unchanged);
	free(input);
	printf(
	    "PASS: %s; %zu fault reads; %zu final callbacks\n", test->name, read_faults, completed);
}

int
main(int argc, char **argv)
{
	struct test_case test;
	FILE *cases;
	unsigned operation, complete;
	int fields;
	size_t count = 0;

	assert(argc == 2);
	cases = open_file(argv[1], "cases.tsv", "");
	for (;;) {
		memset(&test, 0, sizeof(test));
		fields = fscanf(cases,
		    TEST_NAME_FORMAT " %" SCNu32 " %" SCNu32 " %" SCNu32 " %" SCNu32 " %" SCNu64
				     " %" SCNu32 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64
				     " %" SCNu64 " %" SCNu64 " %" SCNu32 " %" SCNu32 " %" SCNu32
				     " %" SCNu32 " %" SCNu32 " %" SCNu32 " %u %u",
		    test.name, &test.index, &test.sequence, &test.code, &test.max_records,
		    &test.root, &test.transaction, &test.expected.root_lsn, &test.expected.last_lsn,
		    &test.expected.next_lsn, &test.expected.control_lsn,
		    &test.expected.record_bytes, &test.expected.read_bytes,
		    &test.expected.transaction, &test.expected.read_calls,
		    &test.expected.examined_records, &test.expected.visited_records,
		    &test.expected.copy_pages_read, &test.expected.undo_references, &operation,
		    &complete);
		if (fields == EOF) {
			break;
		}
		assert(fields == TEST_COLUMNS && test.index <= UINT16_MAX &&
		    test.sequence <= UINT16_MAX && operation <= UINT16_MAX);
		test.expected.control_operation = (uint16_t)operation;
		test.expected.complete = complete != 0;
		exercise(argv[1], &test);
		count++;
	}
	assert(fclose(cases) == 0 && count != 0);
	printf("PASS: %zu original transaction-chain profiles\n", count);
	return 0;
}
