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
	TEST_NAME_BYTES = TEST_NAME_CHARACTERS + 1,
	TEST_PATH_BYTES = 1024,
	TEST_SOURCE_BYTES = 4 * 1024 * 1024,
	TEST_INDEX_BYTES = 1024 * 1024,
	TEST_READ_CALLS = 4096,
	TEST_READ_BYTES = 16 * 1024 * 1024,
	TEST_GUARD_BYTES = 32,
	TEST_SENTINEL = 0xa5,
	TEST_PARTIAL_BYTE = 0x71,
	TEST_PARTIAL_DIVISOR = 2,
	TEST_COLUMNS = 18,
	TEST_PACKET_COLUMNS = 4,
	TEST_UNALIGNED_SHIFT = 1,
	TEST_BITS_PER_BYTE = 8
};

struct test_case {
	char name[TEST_NAME_BYTES];
	uint32_t index, sequence, code, mask, major, names, dirty, header, page;
	struct ntfs_logfile_checkpoint_capture_report report;
};

struct test_packet {
	uint64_t lsn;
	uint32_t bytes, pages, copies;
};

struct test_device {
	struct fuzz_device device;
	enum ntfs_result failure;
	bool full_failure;
};

struct guarded_capture {
	uint8_t before[TEST_GUARD_BYTES];
	struct ntfs_logfile_checkpoint_capture value;
	uint8_t after[TEST_GUARD_BYTES];
};

struct guarded_report {
	uint8_t before[TEST_GUARD_BYTES];
	struct ntfs_logfile_checkpoint_capture_report value;
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
	assert(length > 0 && length <= TEST_SOURCE_BYTES && fseek(file, 0, SEEK_SET) == 0);
	*size = (size_t)length;
	bytes = malloc(*size);
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
			assert(offset <= test->device.size && size <= test->device.size - offset);
			memcpy(bytes, test->device.data + (size_t)offset, size);
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
equal_report(const struct ntfs_logfile_checkpoint_capture_report *a,
    const struct ntfs_logfile_checkpoint_capture_report *b)
{
	assert(a->checkpoint_lsn == b->checkpoint_lsn && a->requested_lsn == b->requested_lsn &&
	    a->read_bytes == b->read_bytes && a->read_calls == b->read_calls &&
	    a->acquired_records == b->acquired_records && a->record_bytes == b->record_bytes &&
	    a->copy_pages_read == b->copy_pages_read && a->complete == b->complete);
}

static void
packet_oracle(const char *directory, const struct test_case *test, const uint8_t *bytes,
    const struct ntfs_logfile_checkpoint_capture *capture)
{
	struct ntfs_logfile_span span;
	char suffix[TEST_NAME_BYTES];
	uint8_t *expected;
	size_t length, offset = 0;
	uint32_t ordinal, kind = 0;
	int written;

	assert(capture->client_index == test->index && capture->client_sequence == test->sequence &&
	    capture->client.sequence == test->sequence && capture->restart.major == test->major &&
	    capture->restart.minor == 0 && capture->snapshot.present_mask == test->mask &&
	    capture->snapshot.client_major == test->major && capture->snapshot.client_minor == 0 &&
	    capture->snapshot.checkpoint_lsn == test->report.checkpoint_lsn &&
	    capture->snapshot.named_attributes == test->names &&
	    capture->snapshot.dirty_pages == test->dirty &&
	    capture->bytes == test->report.record_bytes);
	for (ordinal = 0; ordinal < test->report.acquired_records; ordinal++) {
		if (ordinal == 0) {
			span = capture->checkpoint;
		} else {
			while ((test->mask & (1u << kind)) == 0) {
				assert(kind < NTFS_LOGFILE_CHECKPOINT_KINDS);
				assert(capture->dumps[kind].offset == 0 &&
				    capture->dumps[kind].length == 0);
				kind++;
			}
			assert(kind < NTFS_LOGFILE_CHECKPOINT_KINDS);
			span = capture->dumps[kind++];
		}
		written = snprintf(suffix, sizeof(suffix), ".packet-%" PRIu32, ordinal);
		assert(written > 0 && (size_t)written < sizeof(suffix));
		expected = read_file(directory, test->name, suffix, &length);
		assert(span.offset == offset && span.length == length &&
		    memcmp(bytes + offset, expected, length) == 0);
		offset += length;
		free(expected);
	}
	while (kind < NTFS_LOGFILE_CHECKPOINT_KINDS) {
		assert(capture->dumps[kind].offset == 0 && capture->dumps[kind].length == 0);
		kind++;
	}
	assert(offset == capture->bytes);
}

static enum ntfs_result
invoke(struct ntfs_logfile *source, const struct test_case *test,
    const struct ntfs_logfile_checkpoint_capture_limits *limits, uint8_t *records, size_t capacity,
    uint8_t *names, size_t name_capacity, struct guarded_capture *capture,
    struct guarded_report *report)
{
	static const struct ntfs_logfile_checkpoint_capture zero;
	enum ntfs_result result;

	memset(capture, TEST_SENTINEL, sizeof(*capture));
	memset(report, TEST_SENTINEL, sizeof(*report));
	result =
	    ntfs_logfile_capture_checkpoint(source, (uint16_t)test->index, (uint16_t)test->sequence,
		limits, records, capacity, names, name_capacity, &capture->value, &report->value);
	guard(capture->before, sizeof(capture->before));
	guard(capture->after, sizeof(capture->after));
	guard(report->before, sizeof(report->before));
	guard(report->after, sizeof(report->after));
	if (result != NTFS_OK) {
		assert(
		    memcmp(&capture->value, &zero, sizeof(zero)) == 0 && !report->value.complete);
	} else {
		assert(report->value.complete && capture->value.bytes <= capacity);
	}
	return result;
}

static void
failure_oracle(const struct test_case *test, const struct test_packet *packets, uint32_t failure,
    bool attempted, struct ntfs_logfile_checkpoint_capture_report *expected)
{
	uint32_t ordinal, page = 0;

	memset(expected, 0, sizeof(*expected));
	expected->checkpoint_lsn = test->report.checkpoint_lsn;
	expected->read_calls = failure - (attempted ? 0u : 1u);
	expected->read_bytes = (uint64_t)expected->read_calls * test->page;
	for (ordinal = 0; ordinal < test->report.acquired_records; ordinal++) {
		expected->requested_lsn = packets[ordinal].lsn;
		page += packets[ordinal].pages;
		if (page >= failure) {
			break;
		}
		expected->acquired_records++;
		expected->record_bytes += packets[ordinal].bytes;
		expected->copy_pages_read += packets[ordinal].copies;
	}
	assert(ordinal < test->report.acquired_records);
}

static void
faults(const char *directory, const struct test_case *test, struct ntfs_logfile *source,
    struct test_device *device, uint8_t *records, size_t capacity, uint8_t *names)
{
	static const enum ntfs_result failures[] = {
	    NTFS_IO, NTFS_RANGE, NTFS_NOT_FOUND, NTFS_CORRUPT};
	struct test_packet packets[NTFS_LOGFILE_CHECKPOINT_MAX_PACKETS];
	struct ntfs_logfile_checkpoint_capture_report expected;
	struct ntfs_logfile_checkpoint_capture_limits limits;
	struct guarded_capture capture;
	struct guarded_report report;
	FILE *rows;
	size_t baseline_memory, baseline_reads, baseline_allocations, mode;
	uint32_t ordinal, point, full, previous_pages = 0, stage_size = 0, growths = 0;
	enum ntfs_result result;

	rows = open_file(directory, test->name, ".packets.tsv");
	for (ordinal = 0; ordinal < test->report.acquired_records; ordinal++) {
		assert(fscanf(rows, "%" SCNu64 " %" SCNu32 " %" SCNu32 " %" SCNu32,
			   &packets[ordinal].lsn, &packets[ordinal].bytes, &packets[ordinal].pages,
			   &packets[ordinal].copies) == TEST_PACKET_COLUMNS);
	}
	assert(fscanf(rows, "%" SCNu32, &ordinal) == EOF && fclose(rows) == 0);
	baseline_memory = device->device.memory;
	for (mode = 0; mode < sizeof(failures) / sizeof(failures[0]); mode++) {
		for (full = 0; full <= 1; full++) {
			device->failure = failures[mode];
			device->full_failure = full != 0;
			for (point = 1; point <= test->report.read_calls; point++) {
				baseline_reads = device->device.reads;
				device->device.fail_read = baseline_reads + point;
				result = invoke(source, test, NULL, records, capacity, names,
				    NTFS_LOGFILE_CHECKPOINT_NAME_WORKSPACE_BYTES, &capture,
				    &report);
				assert(result == failures[mode] &&
				    device->device.reads - baseline_reads == point &&
				    device->device.memory == baseline_memory);
				failure_oracle(test, packets, point, true, &expected);
				equal_report(&report.value, &expected);
				device->device.fail_read = 0;
			}
		}
	}
	for (ordinal = 0; ordinal < test->report.acquired_records; ordinal++) {
		if (packets[ordinal].bytes <= stage_size) {
			previous_pages += packets[ordinal].pages;
			continue;
		}
		stage_size = packets[ordinal].bytes;
		growths++;
		baseline_reads = device->device.reads;
		baseline_allocations = device->device.allocations;
		device->device.fail_allocation = baseline_allocations + growths;
		result = invoke(source, test, NULL, records, capacity, names,
		    NTFS_LOGFILE_CHECKPOINT_NAME_WORKSPACE_BYTES, &capture, &report);
		assert(result == NTFS_NO_MEMORY &&
		    device->device.allocations - baseline_allocations == growths &&
		    device->device.reads - baseline_reads == previous_pages + 1 &&
		    device->device.memory == baseline_memory);
		failure_oracle(test, packets, previous_pages + 1, true, &expected);
		equal_report(&report.value, &expected);
		previous_pages += packets[ordinal].pages;
		device->device.fail_allocation = 0;
	}
	limits = (struct ntfs_logfile_checkpoint_capture_limits){
	    test->report.read_calls, test->report.read_bytes};
	assert(invoke(source, test, &limits, records, capacity, names,
		   NTFS_LOGFILE_CHECKPOINT_NAME_WORKSPACE_BYTES, &capture, &report) == NTFS_OK);
	equal_report(&report.value, &test->report);
	if (limits.max_read_calls > 1) {
		limits.max_read_calls--;
		baseline_reads = device->device.reads;
		assert(invoke(source, test, &limits, records, capacity, names,
			   NTFS_LOGFILE_CHECKPOINT_NAME_WORKSPACE_BYTES, &capture,
			   &report) == NTFS_RANGE);
		failure_oracle(test, packets, test->report.read_calls, false, &expected);
		equal_report(&report.value, &expected);
		assert(device->device.reads - baseline_reads == limits.max_read_calls);
	}
	limits.max_read_calls = UINT32_MAX;
	limits.max_read_bytes = test->report.read_bytes - 1;
	assert(invoke(source, test, &limits, records, capacity, names,
		   NTFS_LOGFILE_CHECKPOINT_NAME_WORKSPACE_BYTES, &capture, &report) == NTFS_RANGE);
	failure_oracle(test, packets, test->report.read_calls, false, &expected);
	equal_report(&report.value, &expected);
	baseline_reads = device->device.reads;
	limits.max_read_calls = 0;
	assert(
	    invoke(source, test, &limits, records, capacity, names,
		NTFS_LOGFILE_CHECKPOINT_NAME_WORKSPACE_BYTES, &capture, &report) == NTFS_INVALID);
	assert(report.value.read_calls == 0 && device->device.reads == baseline_reads);
	limits = (struct ntfs_logfile_checkpoint_capture_limits){UINT32_MAX, 0};
	assert(
	    invoke(source, test, &limits, records, capacity, names,
		NTFS_LOGFILE_CHECKPOINT_NAME_WORKSPACE_BYTES, &capture, &report) == NTFS_INVALID);
	assert(device->device.reads == baseline_reads && device->device.memory == baseline_memory);
	assert(invoke(source, test, NULL, records, capacity - 1, names,
		   NTFS_LOGFILE_CHECKPOINT_NAME_WORKSPACE_BYTES, &capture, &report) == NTFS_RANGE);
	assert(report.value.acquired_records == test->report.acquired_records - 1);
	if (test->names != 0) {
		assert(invoke(source, test, NULL, records, capacity, names, 0, &capture, &report) ==
		    NTFS_RANGE);
		assert(report.value.acquired_records == test->report.acquired_records);
		assert(invoke(source, test, NULL, records, capacity, NULL,
			   NTFS_LOGFILE_CHECKPOINT_NAME_WORKSPACE_BYTES, &capture,
			   &report) == NTFS_INVALID);
		assert(report.value.acquired_records == test->report.acquired_records);
	}
	assert(invoke(source, test, NULL, records, capacity, names,
		   NTFS_LOGFILE_CHECKPOINT_NAME_WORKSPACE_BYTES, &capture, &report) == NTFS_OK);
	equal_report(&report.value, &test->report);
	packet_oracle(directory, test, records, &capture.value);
	assert(device->device.memory == baseline_memory);
}

int
main(int argc, char **argv)
{
	struct test_case test;
	struct test_device device;
	struct ntfs_environment environment;
	struct ntfs_logfile *source;
	struct ntfs_logfile_limits limits;
	struct ntfs_logfile_page_index_report preparation;
	struct guarded_capture capture, saved;
	struct guarded_report report;
	uint8_t *journal, *unchanged, *records, *names;
	size_t source_bytes, capacity, reads, memory, allocations, shift, prefix, count = 0;
	uint32_t complete;
	FILE *cases;
	enum ntfs_result result;

	assert(argc == 2);
	cases = open_file(argv[1], "cases.tsv", "");
	while (fscanf(cases,
		   TEST_NAME_FORMAT " %" SCNu32 " %" SCNu32 " %" SCNu32 " %" SCNu32 " %" SCNu32
				    " %" SCNu32 " %" SCNu32 " %" SCNu32 " %" SCNu32 " %" SCNu64
				    " %" SCNu64 " %" SCNu64 " %" SCNu32 " %" SCNu32 " %" SCNu32
				    " %" SCNu32 " %" SCNu32,
		   test.name, &test.index, &test.sequence, &test.code, &test.mask, &test.major,
		   &test.names, &test.dirty, &test.header, &test.page, &test.report.checkpoint_lsn,
		   &test.report.requested_lsn, &test.report.read_bytes, &test.report.read_calls,
		   &test.report.acquired_records, &test.report.record_bytes,
		   &test.report.copy_pages_read, &complete) == TEST_COLUMNS) {
		test.report.complete = complete != 0;
		journal = read_file(argv[1], test.name, "", &source_bytes);
		unchanged = malloc(source_bytes);
		assert(unchanged != NULL);
		memcpy(unchanged, journal, source_bytes);
		device = (struct test_device){
		    .device = {.data = journal, .size = source_bytes}, .failure = NTFS_IO};
		environment = (struct ntfs_environment){NTFS_API_VERSION, &device, source_bytes,
		    read_source, allocate_source, release_source};
		ntfs_logfile_default_limits(&limits);
		limits.max_read_calls = TEST_READ_CALLS;
		limits.max_read_bytes = TEST_READ_BYTES;
		assert(ntfs_logfile_open(&environment, &limits, NULL, &source) == NTFS_OK);
		assert(ntfs_logfile_prepare_page_index(source, TEST_INDEX_BYTES, &preparation) ==
		    NTFS_OK);
		capacity = test.report.record_bytes == 0 ? NTFS_LOGFILE_MAX_RECORD_BYTES
							 : test.report.record_bytes;
		records = malloc(capacity + 2 * TEST_GUARD_BYTES + TEST_UNALIGNED_SHIFT);
		names = malloc(NTFS_LOGFILE_CHECKPOINT_NAME_WORKSPACE_BYTES + 2 * TEST_GUARD_BYTES +
		    TEST_UNALIGNED_SHIFT);
		assert(records != NULL && names != NULL);
		for (shift = 0; shift <= TEST_UNALIGNED_SHIFT; shift++) {
			prefix = TEST_GUARD_BYTES + shift;
			memset(records, TEST_SENTINEL,
			    capacity + 2 * TEST_GUARD_BYTES + TEST_UNALIGNED_SHIFT);
			memset(names, TEST_SENTINEL,
			    NTFS_LOGFILE_CHECKPOINT_NAME_WORKSPACE_BYTES + 2 * TEST_GUARD_BYTES +
				TEST_UNALIGNED_SHIFT);
			reads = device.device.reads;
			memory = device.device.memory;
			result =
			    invoke(source, &test, NULL, records + prefix, capacity, names + prefix,
				NTFS_LOGFILE_CHECKPOINT_NAME_WORKSPACE_BYTES, &capture, &report);
			if ((uint32_t)result != test.code) {
				fprintf(stderr, "%s: expected %" PRIu32 ", observed %u\n",
				    test.name, test.code, (unsigned)result);
			}
			assert((uint32_t)result == test.code);
			equal_report(&report.value, &test.report);
			assert(device.device.reads - reads == test.report.read_calls &&
			    device.device.memory == memory);
			if (result == NTFS_OK) {
				packet_oracle(argv[1], &test, records + prefix, &capture.value);
				saved = capture;
			}
			guard(records, prefix);
			guard(records + prefix + test.report.record_bytes,
			    capacity - test.report.record_bytes + TEST_GUARD_BYTES);
			guard(names, prefix);
			guard(names + prefix + NTFS_LOGFILE_CHECKPOINT_NAME_WORKSPACE_BYTES,
			    TEST_GUARD_BYTES);
		}
		prefix = TEST_GUARD_BYTES + TEST_UNALIGNED_SHIFT;
		if (test.code == NTFS_OK &&
		    (strcmp(test.name, "client-0-fast-0-mask-15.journal") == 0 ||
			strcmp(test.name, "checkpoint-fast-copy.journal") == 0 ||
			strcmp(test.name, "wrapped-checkpoint.journal") == 0 ||
			strcmp(test.name, "large-open-table.journal") == 0 ||
			strcmp(test.name, "maximum-checkpoint-record.journal") == 0)) {
			faults(argv[1], &test, source, &device, records + prefix, capacity,
			    names + prefix);
		}
		reads = device.device.reads;
		allocations = device.device.allocations;
		assert(invoke(NULL, &test, NULL, records + prefix, capacity, names + prefix,
			   NTFS_LOGFILE_CHECKPOINT_NAME_WORKSPACE_BYTES, &capture,
			   &report) == NTFS_INVALID);
		assert(invoke(source, &test, NULL, NULL, capacity, names + prefix,
			   NTFS_LOGFILE_CHECKPOINT_NAME_WORKSPACE_BYTES, &capture,
			   &report) == NTFS_INVALID);
		assert(ntfs_logfile_capture_checkpoint(source, (uint16_t)test.index,
			   (uint16_t)test.sequence, NULL, records + prefix, capacity,
			   names + prefix, NTFS_LOGFILE_CHECKPOINT_NAME_WORKSPACE_BYTES, NULL,
			   &report.value) == NTFS_INVALID);
		assert(ntfs_logfile_capture_checkpoint(source, (uint16_t)test.index,
			   (uint16_t)test.sequence, NULL, records + prefix, capacity,
			   names + prefix, NTFS_LOGFILE_CHECKPOINT_NAME_WORKSPACE_BYTES,
			   &capture.value, NULL) == NTFS_INVALID);
		assert(device.device.reads == reads && device.device.allocations == allocations);
		ntfs_logfile_close(source);
		assert(device.device.memory == 0 && device.device.reads == reads &&
		    memcmp(journal, unchanged, source_bytes) == 0);
		if (test.code == NTFS_OK) {
			packet_oracle(argv[1], &test, records + prefix, &saved.value);
		}
		free(names);
		free(records);
		free(unchanged);
		free(journal);
		count++;
	}
	assert(feof(cases) && fclose(cases) == 0 && count != 0);
	printf(
	    "PASS: %zu complete checkpoint acquisitions/refusals, exact owned packets, shared "
	    "credits, "
	    "all read/allocation failures in selected layouts, byte guards, immutable media and "
	    "source-independent snapshot lifetime; native analysis/recovery remain unqualified\n",
	    count);
	return 0;
}
