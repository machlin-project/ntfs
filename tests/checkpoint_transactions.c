/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/checkpoint.h>
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
	TEST_CLIENT_SEQUENCE = 7,
	TEST_INDEX_BYTES = 1024 * 1024,
	TEST_READ_CALLS = 16384,
	TEST_READ_BYTES = 64 * 1024 * 1024,
	TEST_LINK_BYTES = NTFS_LOGFILE_TRANSACTION_MAX_RECORDS * 2 * sizeof(uint64_t),
	TEST_GUARD_BYTES = 32,
	TEST_SENTINEL = 0xa5,
	TEST_PARTIAL_BYTE = 0x71,
	TEST_CAPTURE_VALUES = 8,
	TEST_REPORT_VALUES = 12,
	TEST_VIEW_VALUES = 21,
	TEST_CASE_VALUES = 4,
	TEST_SOURCE_CEILING_CALLS = 3072,
	TEST_DENSE_PAGE_BYTES = 512
};

struct test_device {
	struct fuzz_device device;
	enum ntfs_result failure;
	bool full_failure;
};

struct visitor_context {
	FILE *rows;
	size_t calls, stop;
	enum ntfs_result stop_result;
	struct ntfs_logfile_checkpoint_transaction_limits *alter_limits;
	struct ntfs_logfile_checkpoint_transaction_workspace *alter_workspace;
};

struct guarded_report {
	uint8_t before[TEST_GUARD_BYTES];
	struct ntfs_logfile_checkpoint_transaction_report value;
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
	assert(length >= 0 && length <= TEST_READ_BYTES && fseek(file, 0, SEEK_SET) == 0);
	*size = (size_t)length;
	bytes = malloc(*size == 0 ? 1 : *size);
	assert(bytes != NULL && fread(bytes, 1, *size, file) == *size && fclose(file) == 0);
	return bytes;
}

static void
guard(const uint8_t *bytes, size_t size)
{
	size_t item;

	for (item = 0; item < size; item++) {
		assert(bytes[item] == TEST_SENTINEL);
	}
}

static void
values(FILE *file, const uint64_t *actual, size_t count)
{
	uint64_t expected;
	size_t item;

	for (item = 0; item < count; item++) {
		assert(fscanf(file, "%" SCNu64, &expected) == 1);
		if (expected != actual[item]) {
			fprintf(stderr, "field %zu: expected %" PRIu64 ", actual %" PRIu64 "\n",
			    item, expected, actual[item]);
		}
		assert(expected == actual[item]);
	}
}

static void
equal_report(FILE *file, const struct ntfs_logfile_checkpoint_transaction_report *report)
{
	const struct ntfs_logfile_checkpoint_capture_report *capture = &report->checkpoint;
	uint64_t checkpoint[TEST_CAPTURE_VALUES] = {capture->checkpoint_lsn, capture->requested_lsn,
	    capture->read_calls, capture->read_bytes, capture->acquired_records,
	    capture->record_bytes, capture->copy_pages_read, capture->complete};
	uint64_t outer[TEST_REPORT_VALUES] = {report->table_lsn, report->allocated_transactions,
	    report->verified_transactions, report->visited_transactions,
	    report->requested_transaction, report->read_calls, report->read_bytes,
	    report->record_bytes, report->examined_records, report->checked_records,
	    report->copy_pages_read, report->complete};

	assert(fseek(file, 0, SEEK_SET) == 0);
	values(file, checkpoint, TEST_CAPTURE_VALUES);
	values(file, outer, TEST_REPORT_VALUES);
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
			memset(bytes, TEST_PARTIAL_BYTE, size / 2);
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
	context->calls = 0;
	context->stop = 0;
	context->alter_limits = NULL;
	context->alter_workspace = NULL;
}

static enum ntfs_result
visit(void *opaque, const struct ntfs_logfile_checkpoint_transaction_view *view)
{
	struct visitor_context *context = opaque;
	const struct ntfs_logfile_transaction *seed = &view->snapshot;
	const struct ntfs_logfile_transaction_report *chain = &view->chain;
	uint64_t actual[TEST_VIEW_VALUES] = {view->key, seed->state, seed->first_lsn,
	    seed->previous_lsn, seed->undo_next_lsn, seed->undo_records, seed->undo_bytes,
	    chain->root_lsn, chain->last_lsn, chain->next_lsn, chain->control_lsn,
	    chain->record_bytes, chain->read_bytes, chain->transaction, chain->read_calls,
	    chain->examined_records, chain->visited_records, chain->copy_pages_read,
	    chain->undo_references, chain->control_operation, chain->complete};

	values(context->rows, actual, TEST_VIEW_VALUES);
	context->calls++;
	if (context->alter_limits != NULL) {
		*context->alter_limits = (struct ntfs_logfile_checkpoint_transaction_limits){0};
		context->alter_limits = NULL;
	}
	if (context->alter_workspace != NULL) {
		*context->alter_workspace =
		    (struct ntfs_logfile_checkpoint_transaction_workspace){0};
		context->alter_workspace = NULL;
	}
	return context->calls == context->stop ? context->stop_result : NTFS_OK;
}

static enum ntfs_result
walk(struct ntfs_logfile *source, const struct ntfs_logfile_checkpoint_transaction_limits *limits,
    const struct ntfs_logfile_checkpoint_transaction_workspace *workspace,
    struct visitor_context *context, struct guarded_report *report)
{
	enum ntfs_result result;

	memset(report, TEST_SENTINEL, sizeof(*report));
	result = ntfs_logfile_visit_checkpoint_transactions(
	    source, 0, TEST_CLIENT_SEQUENCE, limits, workspace, visit, context, &report->value);
	guard(report->before, sizeof(report->before));
	guard(report->after, sizeof(report->after));
	assert(context->calls ==
	    report->value.visited_transactions +
		(size_t)(context->stop != 0 && context->calls == context->stop));
	return result;
}

static void
faults(struct ntfs_logfile *source, struct test_device *device,
    const struct ntfs_logfile_checkpoint_transaction_limits *limits,
    const struct ntfs_logfile_checkpoint_transaction_workspace *workspace,
    struct visitor_context *context, struct guarded_report *report,
    const struct ntfs_logfile_checkpoint_transaction_report *baseline, size_t allocations,
    FILE *expected)
{
	static const enum ntfs_result errors[] = {NTFS_IO, NTFS_NO_MEMORY, NTFS_RANGE, NTFS_STALE};

	size_t item, error, mode, live = device->device.memory;

	for (error = 0; error < sizeof(errors) / sizeof(errors[0]); error++) {
		for (mode = 0; mode < 2; mode++) {
			for (item = 1; item <= baseline->read_calls; item++) {
				reset_visitor(context);
				device->failure = errors[error];
				device->full_failure = mode != 0;
				device->device.fail_read = device->device.reads + item;
				assert(walk(source, limits, workspace, context, report) ==
				    errors[error]);
				assert(!report->value.complete &&
				    report->value.read_calls == item &&
				    device->device.memory == live);
				device->device.fail_read = 0;
				reset_visitor(context);
				assert(walk(source, limits, workspace, context, report) == NTFS_OK);
				equal_report(expected, &report->value);
			}
		}
	}
	for (item = 1; item <= allocations; item++) {
		reset_visitor(context);
		device->device.fail_allocation = device->device.allocations + item;
		assert(walk(source, limits, workspace, context, report) == NTFS_NO_MEMORY);
		assert(!report->value.complete && device->device.memory == live);
		device->device.fail_allocation = 0;
		reset_visitor(context);
		assert(walk(source, limits, workspace, context, report) == NTFS_OK);
		equal_report(expected, &report->value);
	}
	for (item = 1; item <= baseline->visited_transactions; item++) {
		reset_visitor(context);
		context->stop = item;
		context->stop_result = NTFS_BUSY;
		assert(walk(source, limits, workspace, context, report) == NTFS_BUSY);
		assert(!report->value.complete && report->value.verified_transactions == item &&
		    report->value.visited_transactions == item - 1 &&
		    device->device.memory == live);
	}
	reset_visitor(context);
	assert(walk(source, limits, workspace, context, report) == NTFS_OK);
	equal_report(expected, &report->value);
}

static void
boundaries(struct ntfs_logfile *source, struct test_device *device,
    const struct ntfs_logfile_checkpoint_transaction_limits *limits,
    const struct ntfs_logfile_checkpoint_transaction_workspace *workspace,
    struct visitor_context *context, struct guarded_report *report,
    const struct ntfs_logfile_checkpoint_transaction_report *baseline, FILE *expected)
{
	struct ntfs_logfile_checkpoint_transaction_limits credits = *limits;
	struct ntfs_logfile_checkpoint_transaction_workspace buffers = *workspace;
	struct ntfs_logfile_checkpoint_transaction_report zero = {0};
	size_t reads, item;
	enum ntfs_result result;

	credits.max_read_calls = baseline->read_calls;
	credits.max_read_bytes = baseline->read_bytes;
	reset_visitor(context);
	assert(walk(source, &credits, &buffers, context, report) == NTFS_OK);
	equal_report(expected, &report->value);
	for (item = 0; item < 2; item++) {
		credits.max_read_calls = baseline->read_calls - (item == 0);
		credits.max_read_bytes = baseline->read_bytes - (item == 1);
		reset_visitor(context);
		assert(walk(source, &credits, &buffers, context, report) == NTFS_RANGE);
		assert(!report->value.complete &&
		    report->value.read_calls <= credits.max_read_calls &&
		    report->value.read_bytes <= credits.max_read_bytes);
	}
	reads = device->device.reads;
	buffers.link_capacity = limits->max_records * 2 * sizeof(uint64_t) - 1;
	reset_visitor(context);
	assert(walk(source, limits, &buffers, context, report) == NTFS_RANGE);
	assert(device->device.reads == reads && memcmp(&report->value, &zero, sizeof(zero)) == 0);
	for (item = 0; item < 6; item++) {
		credits = *limits;
		if (item == 0) {
			credits.max_transactions = 0;
		} else if (item == 1) {
			credits.max_records = 0;
		} else if (item == 2) {
			credits.max_read_calls = 0;
		} else if (item == 3) {
			credits.max_read_bytes = 0;
		} else if (item == 4) {
			credits.max_transactions = NTFS_LOGFILE_TRANSACTION_MAX_RECORDS + 1;
		} else {
			credits.max_records = NTFS_LOGFILE_TRANSACTION_MAX_RECORDS + 1;
		}
		reset_visitor(context);
		assert(walk(source, &credits, workspace, context, report) ==
		    (item < 4 ? NTFS_INVALID : NTFS_RANGE));
		assert(device->device.reads == reads &&
		    memcmp(&report->value, &zero, sizeof(zero)) == 0);
	}
	for (item = 0; item < 3; item++) {
		buffers = *workspace;
		if (item == 0) {
			buffers.checkpoint_records = NULL;
		} else if (item == 1) {
			buffers.record = NULL;
		} else {
			buffers.links = NULL;
		}
		reset_visitor(context);
		assert(walk(source, limits, &buffers, context, report) == NTFS_INVALID);
		assert(device->device.reads == reads &&
		    memcmp(&report->value, &zero, sizeof(zero)) == 0);
	}
	reset_visitor(context);
	assert(ntfs_logfile_visit_checkpoint_transactions(source, 0, TEST_CLIENT_SEQUENCE + 1,
		   limits, workspace, visit, context, &report->value) == NTFS_STALE);
	assert(device->device.reads == reads && context->calls == 0 &&
	    memcmp(&report->value, &zero, sizeof(zero)) == 0);
	credits = *limits;
	buffers = *workspace;
	reset_visitor(context);
	context->alter_limits = &credits;
	context->alter_workspace = &buffers;
	assert(walk(source, &credits, &buffers, context, report) == NTFS_OK);
	equal_report(expected, &report->value);
	reset_visitor(context);
	assert(walk(source, NULL, workspace, context, report) == NTFS_OK);
	equal_report(expected, &report->value);
	for (item = 0; item < 3; item++) {
		buffers = *workspace;
		if (item == 0) {
			buffers.checkpoint_capacity = baseline->checkpoint.record_bytes - 1;
		} else if (item == 1) {
			buffers.record_capacity = 1;
		} else {
			buffers.link_capacity = 0;
		}
		reset_visitor(context);
		result = walk(source, limits, &buffers, context, report);
		assert(result == NTFS_RANGE && !report->value.complete);
	}
}

static void
source_ceilings(struct test_device *device,
    const struct ntfs_logfile_checkpoint_transaction_limits *limits,
    const struct ntfs_logfile_checkpoint_transaction_workspace *workspace,
    struct visitor_context *context, struct guarded_report *report)
{
	struct ntfs_environment environment = {.api_version = NTFS_API_VERSION,
	    .context = device,
	    .size_bytes = device->device.size,
	    .read = read_source,
	    .allocate = allocate_source,
	    .release = release_source};
	struct ntfs_logfile_limits source_limits;
	struct ntfs_logfile *source;
	struct ntfs_logfile_page_index_report index;
	uint64_t ceiling_bytes = (uint64_t)TEST_SOURCE_CEILING_CALLS * TEST_DENSE_PAGE_BYTES;
	size_t mode, variant;

	for (mode = 0; mode < 2; mode++) {
		ntfs_logfile_default_limits(&source_limits);
		source_limits.max_read_calls =
		    mode == 0 ? TEST_SOURCE_CEILING_CALLS : TEST_READ_CALLS;
		source_limits.max_read_bytes = mode == 0 ? TEST_READ_BYTES : ceiling_bytes;
		assert(ntfs_logfile_open(&environment, &source_limits, NULL, &source) == NTFS_OK);
		assert(
		    ntfs_logfile_prepare_page_index(source, TEST_INDEX_BYTES, &index) == NTFS_OK);
		for (variant = 0; variant < 2; variant++) {
			reset_visitor(context);
			assert(walk(source, variant == 0 ? limits : NULL, workspace, context,
				   report) == NTFS_RANGE);
			assert(!report->value.complete && context->calls == 1 &&
			    report->value.read_calls == TEST_SOURCE_CEILING_CALLS &&
			    report->value.read_bytes == ceiling_bytes);
		}
		ntfs_logfile_close(source);
		assert(device->device.memory == 0);
	}
}

int
main(int argc, char **argv)
{
	char name[TEST_NAME_BYTES];
	uint32_t code, records, transactions;
	struct test_device device = {0};
	struct ntfs_environment environment;
	struct ntfs_logfile_limits source_limits;
	struct ntfs_logfile_checkpoint_transaction_limits limits;
	struct ntfs_logfile_checkpoint_transaction_workspace workspace;
	struct ntfs_logfile_checkpoint_transaction_report baseline;
	struct ntfs_logfile_page_index_report index;
	struct ntfs_logfile *source;
	struct visitor_context context = {0};
	struct guarded_report report;
	FILE *cases, *expected;
	uint8_t *raw, *original, *captured, *checkpoint, *record, *links;
	size_t source_bytes, capture_bytes, allocations, count = 0;
	enum ntfs_result result;

	assert(argc == 2);
	cases = open_file(argv[1], "cases.tsv", "");
	checkpoint = malloc(NTFS_LOGFILE_CHECKPOINT_MAX_BYTES + 2 * TEST_GUARD_BYTES);
	record = malloc(NTFS_LOGFILE_MAX_RECORD_BYTES + 2 * TEST_GUARD_BYTES);
	links = malloc(TEST_LINK_BYTES + 2 * TEST_GUARD_BYTES);
	assert(checkpoint != NULL && record != NULL && links != NULL);
	while (fscanf(cases, TEST_NAME_FORMAT " %" SCNu32 " %" SCNu32 " %" SCNu32, name, &code,
		   &records, &transactions) == TEST_CASE_VALUES) {
		fprintf(stderr, "checkpoint transactions: %s\n", name);
		raw = read_file(argv[1], name, "", &source_bytes);
		original = malloc(source_bytes);
		assert(original != NULL);
		memcpy(original, raw, source_bytes);
		captured = read_file(argv[1], name, ".capture", &capture_bytes);
		expected = open_file(argv[1], name, ".expected");
		context.rows = open_file(argv[1], name, ".views");
		memset(&device, 0, sizeof(device));
		device.device.data = raw;
		device.device.size = source_bytes;
		environment = (struct ntfs_environment){.api_version = NTFS_API_VERSION,
		    .context = &device,
		    .size_bytes = source_bytes,
		    .read = read_source,
		    .allocate = allocate_source,
		    .release = release_source};
		ntfs_logfile_default_limits(&source_limits);
		source_limits.max_read_calls = TEST_READ_CALLS;
		source_limits.max_read_bytes = TEST_READ_BYTES;
		assert(ntfs_logfile_open(&environment, &source_limits, NULL, &source) == NTFS_OK);
		assert(
		    ntfs_logfile_prepare_page_index(source, TEST_INDEX_BYTES, &index) == NTFS_OK);
		limits = (struct ntfs_logfile_checkpoint_transaction_limits){
		    transactions, records, TEST_READ_CALLS, TEST_READ_BYTES};
		workspace = (struct ntfs_logfile_checkpoint_transaction_workspace){
		    checkpoint + TEST_GUARD_BYTES + 1, NULL, record + TEST_GUARD_BYTES + 1,
		    links + TEST_GUARD_BYTES + 1, NTFS_LOGFILE_CHECKPOINT_MAX_BYTES - 1, 0,
		    NTFS_LOGFILE_MAX_RECORD_BYTES - 1, TEST_LINK_BYTES - 1};
		/* Byte alignment is accepted; the declared link policy gets exact storage. */
		workspace.link_capacity = (size_t)records * 2 * sizeof(uint64_t);
		memset(checkpoint, TEST_SENTINEL,
		    NTFS_LOGFILE_CHECKPOINT_MAX_BYTES + 2 * TEST_GUARD_BYTES);
		memset(record, TEST_SENTINEL, NTFS_LOGFILE_MAX_RECORD_BYTES + 2 * TEST_GUARD_BYTES);
		memset(links, TEST_SENTINEL, TEST_LINK_BYTES + 2 * TEST_GUARD_BYTES);
		reset_visitor(&context);
		allocations = device.device.allocations;
		result = walk(source, &limits, &workspace, &context, &report);
		if (result != (enum ntfs_result)code) {
			fprintf(stderr, "expected code %" PRIu32 ", actual %d (%s)\n", code,
			    (int)result, ntfs_result_string(result));
		}
		assert(result == (enum ntfs_result)code);
		equal_report(expected, &report.value);
		assert(report.value.checkpoint.record_bytes == capture_bytes &&
		    memcmp(workspace.checkpoint_records, captured, capture_bytes) == 0);
		baseline = report.value;
		allocations = device.device.allocations - allocations;
		if (code == NTFS_OK && strcmp(name, "client-1-fast-0-extended-0.journal") == 0) {
			faults(source, &device, &limits, &workspace, &context, &report, &baseline,
			    allocations, expected);
			boundaries(source, &device, &limits, &workspace, &context, &report,
			    &baseline, expected);
		}
		guard(checkpoint, TEST_GUARD_BYTES + 1);
		guard(checkpoint + TEST_GUARD_BYTES + 1 + capture_bytes,
		    NTFS_LOGFILE_CHECKPOINT_MAX_BYTES - 1 - capture_bytes + TEST_GUARD_BYTES);
		guard(record, TEST_GUARD_BYTES + 1);
		guard(record + TEST_GUARD_BYTES + NTFS_LOGFILE_MAX_RECORD_BYTES, TEST_GUARD_BYTES);
		guard(links, TEST_GUARD_BYTES + 1);
		guard(links + TEST_GUARD_BYTES + 1 + workspace.link_capacity,
		    TEST_LINK_BYTES + TEST_GUARD_BYTES - 1 - workspace.link_capacity);
		assert(memcmp(raw, original, source_bytes) == 0);
		ntfs_logfile_close(source);
		assert(device.device.memory == 0);
		if (strcmp(name, "aggregate-exact-record-cap.journal") == 0) {
			source_ceilings(&device, &limits, &workspace, &context, &report);
		}
		assert(fclose(expected) == 0 && fclose(context.rows) == 0);
		free(captured);
		free(original);
		free(raw);
		count++;
	}
	assert(feof(cases) && count != 0 && fclose(cases) == 0);
	free(links);
	free(record);
	free(checkpoint);
	printf("PASS: %zu checkpoint transaction profiles; exact seeds/chains, shared ceilings, "
	       "faults and retry\n",
	    count);
	return 0;
}
