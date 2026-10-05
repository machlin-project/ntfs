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
	TEST_SOURCE_MAX_BYTES = 4 * 1024 * 1024,
	TEST_INDEX_MAX_BYTES = 1024 * 1024,
	TEST_READ_BYTES = 16 * 1024 * 1024,
	TEST_SENTINEL = 0xa5,
	TEST_PARTIAL_BYTE = 0x71,
	TEST_PARTIAL_DENOMINATOR = 2,
	TEST_FAILED_TRANSFERS = 2,
	TEST_PREFIX_PAIR_READS = 2,
	TEST_GUARD_BYTES = 32,
	TEST_BYTE_ALIGNMENT_OFFSET = 1,
	TEST_CASE_FIELDS = 15,
	TEST_ROW_FIELDS = 12,
	TEST_RECORD_FIELDS = 10,
	TEST_CHANGE_FIELDS = 3,
	TEST_CREDITS_EXACT = 0,
	TEST_CREDITS_SHORT_CALLS,
	TEST_CREDITS_SHORT_BYTES,
	TEST_CREDITS_DEFAULT,
	TEST_CREDIT_CASES,
	TEST_REPEATED_RECORDS = 2
};

struct test_device {
	struct fuzz_device device;
	enum ntfs_result failure;
	bool full_failure;
	size_t allocation_bytes;
	const uint8_t *replacement;
	size_t replacement_bytes, replacement_read;
	uint64_t replacement_offset;
};

struct test_case {
	char name[TEST_NAME_BYTES];
	uint32_t code, page_bytes, copies, targets, selected, missing, corrupt, unsupported;
	uint32_t conflicts, comparisons, unrouted, unsupported_copies, reads, faults;
};

struct record_case {
	char name[TEST_NAME_BYTES];
	uint64_t lsn, first, last;
	uint32_t code, bytes, pages, copies, page_bytes, wrapped;
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
file_bytes(const char *directory, const char *name, const char *suffix, size_t *size)
{
	FILE *file;
	long length;
	uint8_t *bytes;

	file = open_file(directory, name, suffix);
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
	if (test->replacement != NULL && test->device.reads == test->replacement_read) {
		assert(offset == test->replacement_offset && size == test->replacement_bytes);
		memcpy(bytes, test->replacement, size);
	}
	return NTFS_OK;
}

static void *
source_allocate(void *context, size_t size)
{
	struct test_device *test = context;

	test->allocation_bytes = size;
	return fuzz_allocate(&test->device, size);
}

static void
source_release(void *context, void *bytes, size_t size)
{
	struct test_device *test = context;

	fuzz_release(&test->device, bytes, size);
}

static struct ntfs_environment
environment(struct test_device *device)
{
	return (struct ntfs_environment){NTFS_API_VERSION, device, device->device.size, source_read,
	    source_allocate, source_release};
}

static void
open_source(const struct ntfs_environment *env, struct ntfs_logfile **source)
{
	struct ntfs_logfile_limits limits;

	ntfs_logfile_default_limits(&limits);
	limits.max_read_calls = FUZZ_READ_BUDGET;
	limits.max_read_bytes = TEST_READ_BYTES;
	assert(ntfs_logfile_open(env, &limits, NULL, source) == NTFS_OK);
}

static void
filled(const void *data, size_t size, unsigned byte)
{
	const uint8_t *bytes = data;
	size_t index;

	for (index = 0; index < size; index++) {
		assert(bytes[index] == byte);
	}
}

static void
report(const struct test_case *test, const struct ntfs_logfile_page_index_report *out)
{
	uint32_t pages = test->targets + test->copies;

	assert(out->published && out->required_bytes != 0 &&
	    out->required_bytes == out->retained_bytes && out->indexed_targets == test->targets);
	assert(out->selected_pages == test->selected && out->missing_targets == test->missing &&
	    out->corrupt_targets == test->corrupt &&
	    out->unsupported_targets == test->unsupported &&
	    out->prefix_conflicts == test->conflicts &&
	    out->compared_prefixes == test->comparisons && out->unrouted_copies == test->unrouted &&
	    out->unsupported_copies == test->unsupported_copies);
	assert(out->read_calls == test->reads &&
	    out->read_bytes == (uint64_t)test->reads * test->page_bytes);
	assert(out->inventory.complete && out->inventory.total_pages == pages &&
	    out->inventory.examined_pages == pages && out->inventory.visited_pages == pages &&
	    out->inventory.read_calls == pages &&
	    out->inventory.read_bytes == (uint64_t)pages * test->page_bytes);
}

static void
target_rows(const char *directory, const struct test_case *test, struct ntfs_logfile *source,
    const struct ntfs_logfile_restart *restart)
{
	struct ntfs_logfile_indexed_page actual, expected;
	FILE *rows;
	unsigned code, conflict, storage;
	uint32_t ordinal;
	int fields;

	rows = open_file(directory, test->name, ".index.rows");
	for (ordinal = 0; ordinal < test->targets; ordinal++) {
		memset(&expected, 0, sizeof(expected));
		fields = fscanf(rows,
		    "%" SCNu64 " %" SCNu64 " %u %u %" SCNu64 " %u %" SCNu64 " %" SCNu64 " %" SCNu32
		    " %hu %hu %hu",
		    &expected.target_offset, &expected.epoch_lsn, &code, &conflict,
		    &expected.selected.offset, &storage, &expected.selected.page.copy_value,
		    &expected.selected.page.last_end_lsn, &expected.selected.page.flags,
		    &expected.selected.page.page_count, &expected.selected.page.page_position,
		    &expected.selected.page.next_record_offset);
		assert(fields == TEST_ROW_FIELDS);
		assert(ntfs_logfile_get_indexed_page(source,
			   restart->circular_offset + (uint64_t)ordinal * test->page_bytes,
			   &actual) == NTFS_OK);
		assert(actual.target_offset == expected.target_offset &&
		    actual.epoch_lsn == expected.epoch_lsn && (unsigned)actual.result == code &&
		    actual.prefix_conflict == (conflict != 0) &&
		    actual.selected.offset == expected.selected.offset &&
		    (unsigned)actual.selected.storage == storage);
		assert(actual.selected.page.copy_value == expected.selected.page.copy_value &&
		    actual.selected.page.last_end_lsn == expected.selected.page.last_end_lsn &&
		    actual.selected.page.flags == expected.selected.page.flags &&
		    actual.selected.page.page_count == expected.selected.page.page_count &&
		    actual.selected.page.page_position == expected.selected.page.page_position &&
		    actual.selected.page.next_record_offset ==
			expected.selected.page.next_record_offset);
	}
	assert(fscanf(rows, " %*c") == EOF && fclose(rows) == 0);
}

static void
construction_faults(struct ntfs_logfile *source, struct test_device *device,
    const struct test_case *test, uint64_t required)
{
	static const enum ntfs_result failures[] = {NTFS_IO, NTFS_CORRUPT, NTFS_UNSUPPORTED,
	    NTFS_NOT_FOUND, NTFS_RANGE, NTFS_STALE, NTFS_END};
	struct ntfs_logfile_page_index_report out, cached, zero = {0};
	size_t kind, memory = device->device.memory, allocations;
	uint32_t read, transfer, physical = test->targets + test->copies;

	for (kind = 0; kind < sizeof(failures) / sizeof(failures[0]); kind++) {
		device->failure = failures[kind];
		for (transfer = 0; transfer < TEST_FAILED_TRANSFERS; transfer++) {
			device->full_failure = transfer != 0;
			for (read = 1; read <= test->reads; read++) {
				device->device.reads = 0;
				device->device.fail_read = read;
				allocations = device->device.allocations;
				assert(ntfs_logfile_prepare_page_index(source, required, &out) ==
				    failures[kind]);
				assert(!out.published && out.retained_bytes == 0 &&
				    out.required_bytes == required && out.read_calls == read &&
				    out.read_bytes == (uint64_t)read * test->page_bytes &&
				    out.inventory.complete == (read > physical));
				assert(device->device.reads == read &&
				    device->device.memory == memory &&
				    device->device.allocations == allocations + 1);
				assert(ntfs_logfile_get_page_index_report(source, &cached) ==
				    NTFS_NOT_FOUND);
				assert(memcmp(&cached, &zero, sizeof(cached)) == 0);
				device->device.reads = 0;
				device->device.fail_read = 0;
				assert(ntfs_logfile_prepare_page_index(source, required, &out) ==
				    NTFS_OK);
				report(test, &out);
				assert(device->device.reads == test->reads &&
				    device->device.memory == memory + required);
				ntfs_logfile_clear_page_index(source);
				assert(device->device.memory == memory);
			}
		}
	}
	device->full_failure = false;
	device->failure = NTFS_IO;
}

static void
credits(
    const struct ntfs_environment *env, struct test_device *device, const struct test_case *test)
{
	struct ntfs_logfile *source;
	struct ntfs_logfile_limits limits;
	struct ntfs_logfile_page_index_report out;
	size_t reads, allocations;
	uint32_t maximum = test->targets + test->copies + TEST_PREFIX_PAIR_READS * test->copies;
	unsigned kind;

	for (kind = TEST_CREDITS_EXACT; kind < TEST_CREDIT_CASES; kind++) {
		ntfs_logfile_default_limits(&limits);
		if (kind != TEST_CREDITS_DEFAULT) {
			limits.max_read_calls = maximum - (kind == TEST_CREDITS_SHORT_CALLS);
			limits.max_read_bytes = (uint64_t)maximum * test->page_bytes -
			    (kind == TEST_CREDITS_SHORT_BYTES);
		}
		device->device.reads = 0;
		assert(ntfs_logfile_open(env, &limits, NULL, &source) == NTFS_OK);
		reads = device->device.reads;
		allocations = device->device.allocations;
		assert(ntfs_logfile_prepare_page_index(source, TEST_INDEX_MAX_BYTES, &out) ==
		    (kind == TEST_CREDITS_EXACT ? NTFS_OK : NTFS_RANGE));
		if (kind == TEST_CREDITS_EXACT) {
			report(test, &out);
		} else {
			assert(!out.published && out.required_bytes != 0 &&
			    out.retained_bytes == 0 && out.read_calls == 0 && out.read_bytes == 0 &&
			    device->device.reads == reads &&
			    device->device.allocations == allocations);
		}
		ntfs_logfile_close(source);
		assert(device->device.memory == 0);
	}
}

static void
check_index(const char *directory, const struct test_case *test)
{
	struct ntfs_logfile *source;
	struct ntfs_environment env;
	struct ntfs_logfile_page_index_report out, cached, zero = {0};
	struct ntfs_logfile_restart before, after;
	struct ntfs_logfile_indexed_page page, empty = {0};
	struct test_device device = {0};
	uint8_t *bytes, *saved;
	size_t size, allocations, memory;
	uint64_t required;

	bytes = file_bytes(directory, test->name, "", &size);
	saved = malloc(size);
	assert(saved != NULL);
	memcpy(saved, bytes, size);
	device.device = (struct fuzz_device){.data = bytes, .size = size};
	device.failure = NTFS_IO;
	env = environment(&device);
	open_source(&env, &source);
	assert(ntfs_logfile_get_restart(source, &before) == NTFS_OK);
	device.device.reads = 0;
	allocations = device.device.allocations;
	memory = device.device.memory;
	assert(ntfs_logfile_get_page_index_report(source, &out) == NTFS_NOT_FOUND);
	assert(memcmp(&out, &zero, sizeof(out)) == 0);
	assert(
	    ntfs_logfile_get_indexed_page(source, before.circular_offset, &page) == NTFS_NOT_FOUND);
	assert(memcmp(&page, &empty, sizeof(page)) == 0);
	if (test->code != NTFS_OK) {
		assert(ntfs_logfile_prepare_page_index(source, TEST_INDEX_MAX_BYTES, &out) ==
		    (enum ntfs_result)test->code);
		assert(memcmp(&out, &zero, sizeof(out)) == 0 && device.device.reads == 0 &&
		    device.device.allocations == allocations);
	} else {
		assert(ntfs_logfile_prepare_page_index(source, 1, &out) == NTFS_RANGE);
		required = out.required_bytes;
		assert(required > 1 && required <= TEST_INDEX_MAX_BYTES && !out.published &&
		    out.retained_bytes == 0 && out.read_calls == 0 &&
		    out.indexed_targets == test->targets);
		assert(ntfs_logfile_prepare_page_index(source, required - 1, &out) == NTFS_RANGE);
		assert(out.required_bytes == required && device.device.reads == 0 &&
		    device.device.allocations == allocations && device.device.memory == memory);
		device.device.fail_allocation = allocations + 1;
		assert(ntfs_logfile_prepare_page_index(source, required, &out) == NTFS_NO_MEMORY);
		assert(out.required_bytes == required && !out.published &&
		    out.retained_bytes == 0 && out.read_calls == 0 && device.device.reads == 0 &&
		    device.device.memory == memory && device.device.allocations == allocations + 1);
		device.device.fail_allocation = 0;
		assert(ntfs_logfile_prepare_page_index(source, required, &out) == NTFS_OK);
		report(test, &out);
		assert(device.device.memory == memory + required &&
		    device.allocation_bytes == required &&
		    device.device.allocations == allocations + TEST_FAILED_TRANSFERS &&
		    device.device.reads == test->reads);
		allocations = device.device.allocations;
		assert(ntfs_logfile_get_page_index_report(source, &cached) == NTFS_OK);
		assert(memcmp(&out, &cached, sizeof(out)) == 0);
		target_rows(directory, test, source, &before);
		assert(ntfs_logfile_prepare_page_index(source, required, &out) == NTFS_BUSY);
		assert(memcmp(&out, &zero, sizeof(out)) == 0 &&
		    device.device.reads == test->reads && device.device.allocations == allocations);
		ntfs_logfile_clear_page_index(source);
		assert(device.device.memory == memory);
		if (test->faults != 0) {
			construction_faults(source, &device, test, required);
		}
		device.device.reads = 0;
		assert(ntfs_logfile_prepare_page_index(source, required, &out) == NTFS_OK);
		report(test, &out);
	}
	assert(ntfs_logfile_get_restart(source, &after) == NTFS_OK);
	assert(memcmp(&before, &after, sizeof(before)) == 0 && memcmp(bytes, saved, size) == 0);
	ntfs_logfile_close(source);
	assert(device.device.memory == 0);
	if (test->faults != 0) {
		credits(&env, &device, test);
	}
	assert(memcmp(bytes, saved, size) == 0);
	free(saved);
	free(bytes);
}

static void
record_output(const uint8_t *guarded, const uint8_t *expected, const struct record_case *test,
    const struct ntfs_logfile_record_view *out)
{
	size_t prefix = TEST_GUARD_BYTES + TEST_BYTE_ALIGNMENT_OFFSET;

	filled(guarded, prefix, TEST_SENTINEL);
	assert(memcmp(guarded + prefix, expected, test->bytes) == 0);
	filled(guarded + prefix + test->bytes,
	    NTFS_LOGFILE_MAX_RECORD_BYTES - test->bytes + TEST_GUARD_BYTES, TEST_SENTINEL);
	assert(out->bytes == test->bytes && out->record.lsn == test->lsn &&
	    out->first_page_offset == test->first && out->last_page_offset == test->last &&
	    out->pages_read == test->pages && out->copy_pages_read == test->copies &&
	    out->read_calls == test->pages &&
	    out->read_bytes == (uint64_t)test->pages * test->page_bytes &&
	    out->wrapped == (test->wrapped != 0));
}

static void
record_faults(struct ntfs_logfile *source, struct test_device *device,
    const struct record_case *test, uint8_t *guarded, size_t guarded_bytes, const uint8_t *expected)
{
	static const enum ntfs_result failures[] = {NTFS_IO, NTFS_CORRUPT, NTFS_UNSUPPORTED,
	    NTFS_NOT_FOUND, NTFS_RANGE, NTFS_STALE, NTFS_END};
	struct ntfs_logfile_record_view out, zero = {0};
	uint8_t *bytes = guarded + TEST_GUARD_BYTES + TEST_BYTE_ALIGNMENT_OFFSET;
	size_t memory = device->device.memory, kind;
	uint32_t read, transfer;

	device->device.reads = 0;
	device->device.fail_allocation = device->device.allocations + 1;
	memset(guarded, TEST_SENTINEL, guarded_bytes);
	assert(ntfs_logfile_read_indexed_record(source, test->lsn, bytes,
		   NTFS_LOGFILE_MAX_RECORD_BYTES, &out) == NTFS_NO_MEMORY);
	assert(memcmp(&out, &zero, sizeof(out)) == 0 && device->device.memory == memory);
	filled(guarded, guarded_bytes, TEST_SENTINEL);
	device->device.fail_allocation = 0;
	for (kind = 0; kind < sizeof(failures) / sizeof(failures[0]); kind++) {
		device->failure = failures[kind];
		for (transfer = 0; transfer < TEST_FAILED_TRANSFERS; transfer++) {
			device->full_failure = transfer != 0;
			for (read = 1; read <= test->pages; read++) {
				device->device.reads = 0;
				device->device.fail_read = read;
				memset(guarded, TEST_SENTINEL, guarded_bytes);
				memset(&out, TEST_SENTINEL, sizeof(out));
				assert(ntfs_logfile_read_indexed_record(source, test->lsn, bytes,
					   NTFS_LOGFILE_MAX_RECORD_BYTES, &out) == failures[kind]);
				assert(memcmp(&out, &zero, sizeof(out)) == 0 &&
				    device->device.reads == read &&
				    device->device.memory == memory);
				filled(guarded, guarded_bytes, TEST_SENTINEL);
				device->device.reads = 0;
				device->device.fail_read = 0;
				assert(ntfs_logfile_read_indexed_record(source, test->lsn, bytes,
					   NTFS_LOGFILE_MAX_RECORD_BYTES, &out) == NTFS_OK);
				record_output(guarded, expected, test, &out);
				assert(device->device.memory == memory);
			}
		}
	}
	device->full_failure = false;
	device->failure = NTFS_IO;
	device->device.reads = 0;
	memset(guarded, TEST_SENTINEL, guarded_bytes);
	assert(ntfs_logfile_read_indexed_record(source, test->lsn, bytes, test->bytes - 1, &out) ==
	    NTFS_RANGE);
	assert(memcmp(&out, &zero, sizeof(out)) == 0 && device->device.memory == memory);
	filled(guarded, guarded_bytes, TEST_SENTINEL);
}

static void
check_record(const char *directory, const struct record_case *test)
{
	struct ntfs_logfile *source;
	struct ntfs_environment env;
	struct ntfs_logfile_page_index_report prepared, cached;
	struct ntfs_logfile_record_view out, zero = {0};
	struct test_device device = {0};
	uint8_t *source_bytes, *saved, *expected, *guarded, *bytes;
	size_t size, expected_size, memory, repeat;
	size_t guarded_bytes = NTFS_LOGFILE_MAX_RECORD_BYTES + TEST_BYTE_ALIGNMENT_OFFSET +
	    TEST_FAILED_TRANSFERS * TEST_GUARD_BYTES;
	enum ntfs_result result;

	source_bytes = file_bytes(directory, test->name, "", &size);
	expected = file_bytes(directory, test->name, ".record", &expected_size);
	assert(expected_size == test->bytes);
	saved = malloc(size);
	guarded = malloc(guarded_bytes);
	assert(saved != NULL && guarded != NULL);
	memcpy(saved, source_bytes, size);
	device.device = (struct fuzz_device){.data = source_bytes, .size = size};
	device.failure = NTFS_IO;
	env = environment(&device);
	open_source(&env, &source);
	device.device.reads = 0;
	memset(guarded, TEST_SENTINEL, guarded_bytes);
	memset(&out, TEST_SENTINEL, sizeof(out));
	bytes = guarded + TEST_GUARD_BYTES + TEST_BYTE_ALIGNMENT_OFFSET;
	assert(ntfs_logfile_read_indexed_record(source, test->lsn, bytes,
		   NTFS_LOGFILE_MAX_RECORD_BYTES, &out) == NTFS_NOT_FOUND);
	assert(memcmp(&out, &zero, sizeof(out)) == 0 && device.device.reads == 0);
	filled(guarded, guarded_bytes, TEST_SENTINEL);
	result = ntfs_logfile_prepare_page_index(source, TEST_INDEX_MAX_BYTES, &prepared);
	if (result != NTFS_OK) {
		assert(result == (enum ntfs_result)test->code && !prepared.published &&
		    prepared.retained_bytes == 0);
	} else {
		memory = device.device.memory;
		for (repeat = 0; repeat < TEST_REPEATED_RECORDS; repeat++) {
			device.device.reads = 0;
			memset(guarded, TEST_SENTINEL, guarded_bytes);
			memset(&out, TEST_SENTINEL, sizeof(out));
			bytes = guarded + TEST_GUARD_BYTES + TEST_BYTE_ALIGNMENT_OFFSET;
			assert(ntfs_logfile_read_indexed_record(source, test->lsn, bytes,
				   NTFS_LOGFILE_MAX_RECORD_BYTES,
				   &out) == (enum ntfs_result)test->code);
			if (test->code == NTFS_OK) {
				record_output(guarded, expected, test, &out);
				assert(device.device.reads == test->pages);
			} else {
				assert(memcmp(&out, &zero, sizeof(out)) == 0);
				filled(guarded, guarded_bytes, TEST_SENTINEL);
			}
			assert(device.device.memory == memory);
		}
		if (test->code == NTFS_OK) {
			record_faults(source, &device, test, guarded, guarded_bytes, expected);
		}
		assert(ntfs_logfile_get_page_index_report(source, &cached) == NTFS_OK);
		assert(memcmp(&prepared, &cached, sizeof(prepared)) == 0);
	}
	ntfs_logfile_close(source);
	assert(device.device.memory == 0 && memcmp(source_bytes, saved, size) == 0);
	free(guarded);
	free(saved);
	free(expected);
	free(source_bytes);
}

static void
stability(const char *directory)
{
	struct ntfs_logfile *source;
	struct ntfs_environment env;
	struct ntfs_logfile_page_index_report out, zero = {0};
	struct test_device device = {0};
	uint8_t *bytes, *changed;
	char name[TEST_NAME_BYTES];
	FILE *changes;
	size_t size, changed_size, memory;
	uint64_t offset;
	unsigned read;
	int fields;

	bytes = file_bytes(directory, "all-fast-and-circular-equal.journal", "", &size);
	device.device = (struct fuzz_device){.data = bytes, .size = size};
	device.failure = NTFS_IO;
	env = environment(&device);
	open_source(&env, &source);
	memory = device.device.memory;
	changes = open_file(directory, "changes.tsv", "");
	for (;;) {
		fields = fscanf(changes, TEST_NAME_FORMAT " %" SCNu64 " %u", name, &offset, &read);
		if (fields == EOF) {
			break;
		}
		assert(fields == TEST_CHANGE_FIELDS);
		changed = file_bytes(directory, name, "", &changed_size);
		device.replacement = changed;
		device.replacement_bytes = changed_size;
		device.replacement_offset = offset;
		device.replacement_read = read;
		device.device.reads = 0;
		assert(ntfs_logfile_prepare_page_index(source, TEST_INDEX_MAX_BYTES, &out) ==
		    NTFS_STALE);
		assert(!out.published && out.retained_bytes == 0 && out.read_calls == read &&
		    device.device.reads == read && device.device.memory == memory);
		assert(ntfs_logfile_get_page_index_report(source, &out) == NTFS_NOT_FOUND);
		assert(memcmp(&out, &zero, sizeof(out)) == 0);
		device.replacement = NULL;
		device.device.reads = 0;
		assert(
		    ntfs_logfile_prepare_page_index(source, TEST_INDEX_MAX_BYTES, &out) == NTFS_OK);
		ntfs_logfile_clear_page_index(source);
		assert(device.device.memory == memory);
		free(changed);
	}
	assert(fclose(changes) == 0);
	ntfs_logfile_close(source);
	assert(device.device.memory == 0);
	free(bytes);
}

static void
record_stability(const char *directory)
{
	struct ntfs_logfile *source;
	struct ntfs_environment env;
	struct ntfs_logfile_page_index_report prepared, cached;
	struct ntfs_logfile_restart restart;
	struct ntfs_logfile_indexed_page selected;
	struct ntfs_logfile_record_view out, zero = {0};
	struct test_device device = {0};
	uint8_t *bytes, *changed, *output;
	char name[TEST_NAME_BYTES], path[TEST_PATH_BYTES];
	FILE *changes;
	size_t size, changed_size, memory;
	int fields, length;

	bytes = file_bytes(directory, "fast/reload-header-stability.journal", "", &size);
	output = malloc(NTFS_LOGFILE_MAX_RECORD_BYTES);
	assert(output != NULL);
	device.device = (struct fuzz_device){.data = bytes, .size = size};
	device.failure = NTFS_IO;
	env = environment(&device);
	open_source(&env, &source);
	assert(ntfs_logfile_get_restart(source, &restart) == NTFS_OK);
	device.device.reads = 0;
	assert(ntfs_logfile_prepare_page_index(source, TEST_INDEX_MAX_BYTES, &prepared) == NTFS_OK);
	assert(
	    ntfs_logfile_get_indexed_page(source, restart.circular_offset, &selected) == NTFS_OK);
	memory = device.device.memory;
	changes = open_file(directory, "fast/changed.tsv", "");
	for (;;) {
		fields = fscanf(changes, TEST_NAME_FORMAT, name);
		if (fields == EOF) {
			break;
		}
		assert(fields == 1);
		length = snprintf(path, sizeof(path), "fast/%s", name);
		assert(length > 0 && (size_t)length < sizeof(path));
		changed = file_bytes(directory, path, "", &changed_size);
		device.replacement = changed;
		device.replacement_bytes = changed_size;
		device.replacement_offset = selected.selected.offset;
		device.replacement_read = 1;
		device.device.reads = 0;
		memset(output, TEST_SENTINEL, NTFS_LOGFILE_MAX_RECORD_BYTES);
		assert(ntfs_logfile_read_indexed_record(source, restart.current_lsn, output,
			   NTFS_LOGFILE_MAX_RECORD_BYTES, &out) == NTFS_STALE);
		assert(memcmp(&out, &zero, sizeof(out)) == 0 && device.device.reads == 1 &&
		    device.device.memory == memory);
		filled(output, NTFS_LOGFILE_MAX_RECORD_BYTES, TEST_SENTINEL);
		device.replacement = NULL;
		device.device.reads = 0;
		assert(ntfs_logfile_read_indexed_record(source, restart.current_lsn, output,
			   NTFS_LOGFILE_MAX_RECORD_BYTES, &out) == NTFS_OK);
		assert(device.device.reads == 1 && device.device.memory == memory);
		assert(ntfs_logfile_get_page_index_report(source, &cached) == NTFS_OK);
		assert(memcmp(&prepared, &cached, sizeof(prepared)) == 0);
		free(changed);
	}
	assert(fclose(changes) == 0);
	ntfs_logfile_close(source);
	assert(device.device.memory == 0);
	free(output);
	free(bytes);
}

static void
invalid_and_maximum(const char *directory)
{
	struct ntfs_logfile *source;
	struct ntfs_environment env;
	struct ntfs_logfile_page_index_report out, zero = {0};
	struct ntfs_logfile_indexed_page page, empty = {0};
	struct ntfs_logfile_record_view record, blank = {0};
	struct ntfs_logfile_restart restart;
	struct test_device device = {0};
	uint8_t *bytes, output[TEST_GUARD_BYTES];
	size_t size, reads, allocations;

	bytes = file_bytes(directory, "physical/maximum-file-prefix.bin", "", &size);
	device.device = (struct fuzz_device){.data = bytes, .size = size};
	device.failure = NTFS_IO;
	env = environment(&device);
	env.size_bytes = NTFS_LOGFILE_MAX_FILE_BYTES;
	open_source(&env, &source);
	assert(ntfs_logfile_get_restart(source, &restart) == NTFS_OK);
	reads = device.device.reads;
	allocations = device.device.allocations;
	assert(ntfs_logfile_prepare_page_index(source, TEST_INDEX_MAX_BYTES, &out) == NTFS_RANGE);
	assert(!out.published && out.required_bytes > TEST_INDEX_MAX_BYTES &&
	    out.retained_bytes == 0 && out.read_calls == 0 && out.read_bytes == 0 &&
	    device.device.reads == reads && device.device.allocations == allocations);
	memset(&out, TEST_SENTINEL, sizeof(out));
	assert(ntfs_logfile_prepare_page_index(NULL, TEST_INDEX_MAX_BYTES, &out) == NTFS_INVALID);
	assert(memcmp(&out, &zero, sizeof(out)) == 0);
	assert(ntfs_logfile_prepare_page_index(source, 0, &out) == NTFS_INVALID);
	assert(memcmp(&out, &zero, sizeof(out)) == 0);
	assert(ntfs_logfile_prepare_page_index(source, TEST_INDEX_MAX_BYTES, NULL) == NTFS_INVALID);
	memset(&out, TEST_SENTINEL, sizeof(out));
	assert(ntfs_logfile_get_page_index_report(NULL, &out) == NTFS_INVALID);
	assert(memcmp(&out, &zero, sizeof(out)) == 0);
	assert(ntfs_logfile_get_page_index_report(source, NULL) == NTFS_INVALID);
	memset(&page, TEST_SENTINEL, sizeof(page));
	assert(ntfs_logfile_get_indexed_page(NULL, restart.circular_offset, &page) == NTFS_INVALID);
	assert(memcmp(&page, &empty, sizeof(page)) == 0);
	assert(
	    ntfs_logfile_get_indexed_page(source, restart.circular_offset, NULL) == NTFS_INVALID);
	assert(ntfs_logfile_get_indexed_page(source, 0, &page) == NTFS_INVALID);
	assert(memcmp(&page, &empty, sizeof(page)) == 0);
	assert(ntfs_logfile_get_indexed_page(source, restart.circular_offset + 1, &page) ==
	    NTFS_INVALID);
	assert(memcmp(&page, &empty, sizeof(page)) == 0);
	assert(ntfs_logfile_get_indexed_page(source, restart.usable_bytes, &page) == NTFS_INVALID);
	assert(memcmp(&page, &empty, sizeof(page)) == 0);
	memset(output, TEST_SENTINEL, sizeof(output));
	memset(&record, TEST_SENTINEL, sizeof(record));
	assert(ntfs_logfile_read_indexed_record(
		   NULL, restart.current_lsn, output, sizeof(output), &record) == NTFS_INVALID);
	assert(memcmp(&record, &blank, sizeof(record)) == 0);
	assert(ntfs_logfile_read_indexed_record(
		   source, restart.current_lsn, NULL, sizeof(output), &record) == NTFS_INVALID);
	assert(memcmp(&record, &blank, sizeof(record)) == 0);
	assert(ntfs_logfile_read_indexed_record(
		   source, restart.current_lsn, output, sizeof(output), NULL) == NTFS_INVALID);
	filled(output, sizeof(output), TEST_SENTINEL);
	assert(device.device.reads == reads && device.device.allocations == allocations);
	ntfs_logfile_clear_page_index(NULL);
	ntfs_logfile_close(source);
	assert(device.device.memory == 0);
	free(bytes);
}

int
main(int argc, char **argv)
{
	struct test_case test;
	struct record_case record;
	FILE *cases;
	unsigned count = 0, records = 0;
	int fields;

	assert(argc == 2);
	cases = open_file(argv[1], "cases.tsv", "");
	for (;;) {
		fields = fscanf(cases,
		    TEST_NAME_FORMAT " %" SCNu32 " %" SCNu32 " %" SCNu32 " %" SCNu32 " %" SCNu32
				     " %" SCNu32 " %" SCNu32 " %" SCNu32 " %" SCNu32 " %" SCNu32
				     " %" SCNu32 " %" SCNu32 " %" SCNu32 " %" SCNu32,
		    test.name, &test.code, &test.page_bytes, &test.copies, &test.targets,
		    &test.selected, &test.missing, &test.corrupt, &test.unsupported,
		    &test.conflicts, &test.comparisons, &test.unrouted, &test.unsupported_copies,
		    &test.reads, &test.faults);
		if (fields == EOF) {
			break;
		}
		assert(fields == TEST_CASE_FIELDS);
		check_index(argv[1], &test);
		count++;
	}
	assert(fclose(cases) == 0 && count != 0);
	cases = open_file(argv[1], "records.tsv", "");
	for (;;) {
		fields = fscanf(cases,
		    TEST_NAME_FORMAT " %" SCNu32 " %" SCNu64 " %" SCNu32 " %" SCNu32 " %" SCNu32
				     " %" SCNu32 " %" SCNu64 " %" SCNu64 " %" SCNu32,
		    record.name, &record.code, &record.lsn, &record.bytes, &record.pages,
		    &record.copies, &record.page_bytes, &record.first, &record.last,
		    &record.wrapped);
		if (fields == EOF) {
			break;
		}
		assert(fields == TEST_RECORD_FIELDS);
		check_record(argv[1], &record);
		records++;
	}
	assert(fclose(cases) == 0 && records != 0);
	stability(argv[1]);
	record_stability(argv[1]);
	invalid_and_maximum(argv[1]);
	printf("PASS: %u target-index graphs/%u exact records, atomic faults, credits and "
	       "lifecycle\n",
	    count, records);
	return 0;
}
