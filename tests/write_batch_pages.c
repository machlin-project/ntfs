/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_batch_pages.h"
#include <ntfs/record.h>
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_PATH_BYTES = 2048,
	TEST_NAME_BYTES = 128,
	TEST_CODE_BYTES = 32,
	TEST_HEADER_FIELDS = 8,
	TEST_RECORD_FIELDS = 8,
	TEST_PAGE_FIELDS = 2,
	TEST_CLIENT_SEQUENCE = 7,
	TEST_INDEX_BYTES = 4 * 1024 * 1024,
	TEST_READ_CALLS = 16384,
	TEST_READ_BYTES = 128 * 1024 * 1024,
	TEST_RECORD_SENTINEL = 0xa5
};

union allocation_header {
	max_align_t alignment;
	size_t bytes;
};

struct tracker {
	const uint8_t *image;
	size_t image_bytes, live, peak, allocations, releases, reads, fail_at;
};

struct expected_record {
	uint64_t lsn;
	size_t bytes;
	uint8_t *packet, *payload;
};

struct expected_page {
	uint64_t offset;
	size_t packet;
	uint8_t *bytes;
};

struct batch_case {
	char path[TEST_PATH_BYTES];
	struct ntfs_write_batch_pages_input input;
	struct ntfs_write_batch_packet *packets;
	struct expected_record *records;
	struct expected_page *page;
	uint8_t *source;
	size_t source_bytes, pages;
	uint64_t next;
	enum ntfs_result result;
};

struct visitor {
	const struct batch_case *test;
	size_t calls;
};

static FILE *
open_file(const char *directory, const char *name)
{
	char path[TEST_PATH_BYTES];
	int length;
	FILE *file;

	length = snprintf(path, sizeof(path), "%s/%s", directory, name);
	assert(length > 0 && (size_t)length < sizeof(path));
	file = fopen(path, "rb");
	assert(file != NULL);
	return file;
}

static uint8_t *
load(const char *directory, const char *name, size_t *bytes)
{
	FILE *file;
	uint8_t *data;
	long length;

	file = open_file(directory, name);
	assert(fseek(file, 0, SEEK_END) == 0);
	length = ftell(file);
	assert(length >= 0 && (uint64_t)length <= TEST_READ_BYTES);
	assert(fseek(file, 0, SEEK_SET) == 0);
	*bytes = (size_t)length;
	data = malloc(*bytes == 0 ? 1 : *bytes);
	assert(data != NULL && fread(data, 1, *bytes, file) == *bytes);
	assert(fgetc(file) == EOF && !ferror(file) && fclose(file) == 0);
	return data;
}

static enum ntfs_result
result_code(const char *name)
{
	if (strcmp(name, "success") == 0) {
		return NTFS_OK;
	}
	if (strcmp(name, "no-space") == 0) {
		return NTFS_NO_SPACE;
	}
	if (strcmp(name, "range") == 0) {
		return NTFS_RANGE;
	}
	assert(strcmp(name, "unsupported") == 0);
	return NTFS_UNSUPPORTED;
}

static void
read_case(const char *directory, const char *name, struct batch_case *test)
{
	struct ntfs_write_batch_packet *packet;
	struct expected_record *record;
	char code[TEST_CODE_BYTES], file_name[TEST_NAME_BYTES], trailing[2];
	uint8_t *restart, *scratch;
	uint64_t file_bytes;
	uint32_t type, flags;
	int64_t previous, undo;
	FILE *rows;
	size_t index, bytes;
	int length;

	memset(test, 0, sizeof(*test));
	length = snprintf(test->path, sizeof(test->path), "%s/%s", directory, name);
	assert(length > 0 && (size_t)length < sizeof(test->path));
	rows = open_file(test->path, "case.rows");
	assert(
	    fscanf(rows, "%" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %zu %zu %31s %" SCNu64,
		&test->input.floor_lsn, &test->input.tail_lsn, &test->input.next_lsn, &file_bytes,
		&test->input.packets, &test->pages, code, &test->next) == TEST_HEADER_FIELDS);
	assert(test->input.packets > 0 && test->input.packets <= NTFS_WRITE_BATCH_MAX_PACKETS);
	test->result = result_code(code);
	restart = load(test->path, "restart.input", &bytes);
	assert(bytes == NTFS_WRITE_CLUSTER_BYTES);
	scratch = malloc(bytes);
	assert(scratch != NULL);
	assert(ntfs_logfile_restart_decode(
		   restart, bytes, file_bytes, scratch, bytes, &test->input.restart) == NTFS_OK);
	free(scratch);
	free(restart);
	test->source = load(test->path, "source.log", &test->source_bytes);
	assert(test->source_bytes == file_bytes);
	test->packets = calloc(test->input.packets, sizeof(*test->packets));
	test->records = calloc(test->input.packets, sizeof(*test->records));
	test->page = calloc(test->pages, sizeof(*test->page));
	assert(test->packets != NULL && test->records != NULL && test->page != NULL);
	test->input.packet = test->packets;
	for (index = 0; index < test->input.packets; index++) {
		packet = &test->packets[index];
		record = &test->records[index];
		assert(fscanf(rows,
			   "%" SCNu64 " %zu %" SCNu32 " %" SCNu32 " %" SCNd64 " %" SCNd64
			   " %" SCNu64 " %" SCNu64,
			   &record->lsn, &record->bytes, &type, &flags, &previous, &undo,
			   &packet->record.previous_lsn,
			   &packet->record.undo_next_lsn) == TEST_RECORD_FIELDS);
		assert(flags <= UINT16_MAX);
		packet->record.type = type;
		packet->record.flags = (uint16_t)flags;
		packet->record.client_sequence = TEST_CLIENT_SEQUENCE;
		packet->record.transaction = NTFS_WRITE_TRANSACTION_KEY;
		packet->record.data.offset = sizeof(struct ntfs_disk_log_record);
		packet->record.data.length =
		    (uint32_t)(record->bytes - sizeof(struct ntfs_disk_log_record));
		packet->previous = previous < 0 ? SIZE_MAX : (size_t)previous;
		packet->undo_next = undo < 0 ? SIZE_MAX : (size_t)undo;
		length = snprintf(file_name, sizeof(file_name), "payload-%zu.input", index);
		assert(length > 0 && (size_t)length < sizeof(file_name));
		record->payload = load(test->path, file_name, &bytes);
		assert(bytes == packet->record.data.length);
		packet->payload = (struct ntfs_logfile_buffer){record->payload, bytes};
		length = snprintf(file_name, sizeof(file_name), "packet-%zu.expected", index);
		assert(length > 0 && (size_t)length < sizeof(file_name));
		record->packet = load(test->path, file_name, &bytes);
		assert(bytes == record->bytes);
	}
	for (index = 0; index < test->pages; index++) {
		assert(fscanf(rows, "%" SCNu64 " %zu", &test->page[index].offset,
			   &test->page[index].packet) == TEST_PAGE_FIELDS);
		length = snprintf(file_name, sizeof(file_name), "page-%zu.expected", index);
		assert(length > 0 && (size_t)length < sizeof(file_name));
		test->page[index].bytes = load(test->path, file_name, &bytes);
		assert(bytes == NTFS_WRITE_CLUSTER_BYTES);
	}
	assert(fscanf(rows, "%1s", trailing) == EOF && fclose(rows) == 0);
}

static void
close_case(struct batch_case *test)
{
	size_t index;

	for (index = 0; index < test->input.packets; index++) {
		free(test->records[index].packet);
		free(test->records[index].payload);
	}
	for (index = 0; index < test->pages; index++) {
		free(test->page[index].bytes);
	}
	free(test->page);
	free(test->records);
	free(test->packets);
	free(test->source);
	memset(test, 0, sizeof(*test));
}

static void *
allocate(void *context, size_t bytes)
{
	struct tracker *tracker = context;
	union allocation_header *header;

	assert(bytes > 0);
	tracker->allocations++;
	if (tracker->allocations == tracker->fail_at ||
	    bytes > NTFS_DEFAULT_MAX_LIVE_BYTES - tracker->live) {
		return NULL;
	}
	header = malloc(sizeof(*header) + bytes);
	assert(header != NULL);
	header->bytes = bytes;
	tracker->live += bytes;
	if (tracker->live > tracker->peak) {
		tracker->peak = tracker->live;
	}
	return header + 1;
}

static void
release(void *context, void *memory, size_t bytes)
{
	struct tracker *tracker = context;
	union allocation_header *header = (union allocation_header *)memory - 1;

	assert(memory != NULL && header->bytes == bytes && bytes <= tracker->live);
	tracker->live -= bytes;
	tracker->releases++;
	memset(memory, TEST_RECORD_SENTINEL, bytes);
	free(header);
}

static enum ntfs_result
read_source(void *context, uint64_t offset, void *memory, size_t bytes)
{
	struct tracker *tracker = context;

	tracker->reads++;
	assert(offset <= tracker->image_bytes && bytes <= tracker->image_bytes - offset);
	memcpy(memory, tracker->image + (size_t)offset, bytes);
	return NTFS_OK;
}

static struct ntfs_environment
environment(struct tracker *tracker)
{
	return (struct ntfs_environment){
	    NTFS_API_VERSION, tracker, tracker->image_bytes, read_source, allocate, release};
}

static void
compare_plan(const struct batch_case *test, const struct ntfs_write_batch_pages *plan)
{
	const struct ntfs_write_batch_page *page;
	const struct ntfs_disk_log_page *header;
	size_t index;

	assert(plan != NULL && ntfs_write_batch_pages_count(plan) == test->pages);
	assert(ntfs_write_batch_pages_next_lsn(plan) == test->next);
	for (index = 0; index < test->input.packets; index++) {
		assert(ntfs_write_batch_pages_lsn(plan, index) == test->records[index].lsn);
	}
	for (index = 0; index < test->pages; index++) {
		page = ntfs_write_batch_pages_get(plan, index);
		assert(page != NULL && page->packet < test->input.packets);
		header = (const void *)page->protected_bytes;
		/* Native spanning reads require the page LSN to cover this packet. */
		assert(ntfs_u64(header->copy_value) >= test->records[page->packet].lsn);
		assert(page != NULL && page->offset == test->page[index].offset &&
		    page->packet == test->page[index].packet &&
		    memcmp(page->protected_bytes, test->page[index].bytes,
			sizeof(page->protected_bytes)) == 0);
	}
	assert(ntfs_write_batch_pages_get(plan, test->pages) == NULL);
	assert(ntfs_write_batch_pages_lsn(plan, test->input.packets) == 0);
}

static enum ntfs_result
visit(void *context, const struct ntfs_logfile_record_view *view, const void *bytes)
{
	struct visitor *visitor = context;
	const struct expected_record *record;

	assert(visitor->calls < visitor->test->input.packets);
	record = &visitor->test->records[visitor->calls];
	assert(view->record.lsn == record->lsn && view->bytes == record->bytes &&
	    view->copy_pages_read == 0 && memcmp(bytes, record->packet, record->bytes) == 0);
	visitor->calls++;
	return NTFS_OK;
}

static void
walk(const struct batch_case *test, uint8_t *image, enum ntfs_result expected)
{
	struct tracker tracker = {.image = image, .image_bytes = test->source_bytes};
	struct ntfs_environment reader = environment(&tracker);
	struct ntfs_logfile *source = NULL;
	struct ntfs_logfile_report discovery;
	struct ntfs_logfile_page_index_report index;
	struct ntfs_logfile_history_report history;
	struct ntfs_logfile_limits limits;
	struct visitor visitor = {.test = test};
	uint8_t *packet;

	packet = malloc(NTFS_WRITE_BATCH_MAX_PACKET_BYTES);
	assert(packet != NULL);
	memset(packet, TEST_RECORD_SENTINEL, NTFS_WRITE_BATCH_MAX_PACKET_BYTES);
	ntfs_logfile_default_limits(&limits);
	limits.max_read_calls = TEST_READ_CALLS;
	limits.max_read_bytes = TEST_READ_BYTES;
	assert(ntfs_logfile_open(&reader, &limits, &discovery, &source) == NTFS_OK);
	assert(ntfs_logfile_prepare_page_index(source, TEST_INDEX_BYTES, &index) == NTFS_OK);
	assert(
	    ntfs_logfile_visit_records(source, test->records[0].lsn, (uint32_t)test->input.packets,
		packet, NTFS_WRITE_BATCH_MAX_PACKET_BYTES, visit, &visitor, &history) == expected);
	if (expected == NTFS_OK) {
		assert(history.complete && history.endpoint_verified &&
		    history.visited_records == test->input.packets &&
		    visitor.calls == test->input.packets &&
		    history.completed_end_lsn == test->records[test->input.packets - 1].lsn &&
		    history.next_lsn == test->next);
	} else {
		assert(!history.complete && visitor.calls == 0 && history.visited_records == 0);
	}
	ntfs_logfile_close(source);
	assert(tracker.live == 0);
	free(packet);
}

static void
roundtrip(const struct batch_case *test, const struct ntfs_write_batch_pages *plan)
{
	const struct ntfs_write_batch_page *page;
	struct ntfs_disk_log_page *header;
	struct ntfs_disk_log_record *record;
	uint8_t *image;
	size_t index;

	image = malloc(test->source_bytes);
	assert(image != NULL);
	memcpy(image, test->source, test->source_bytes);
	for (index = 0; index < test->pages; index++) {
		page = ntfs_write_batch_pages_get(plan, index);
		assert(page->offset <= test->source_bytes &&
		    sizeof(page->protected_bytes) <= test->source_bytes - page->offset);
		/* Every authored retained page, including old continuations, stays intact. */
		assert(
		    memcmp(image + (size_t)page->offset, "RCRD", sizeof(header->mst.magic)) != 0);
		memcpy(image + (size_t)page->offset, page->protected_bytes,
		    sizeof(page->protected_bytes));
	}
	walk(test, image, NTFS_OK);
	if (strcmp(strrchr(test->path, '/') + 1, "continuation") == 0) {
		page = ntfs_write_batch_pages_get(plan, 0);
		header = (void *)(image + (size_t)page->offset);
		ntfs_put_u16(header->next_record_offset, 0);
		walk(test, image, NTFS_CORRUPT);
		memcpy(header, page->protected_bytes, sizeof(page->protected_bytes));
		record = (void *)((uint8_t *)header + NTFS_WRITE_LOG_DATA_OFFSET);
		ntfs_put_u16(record->flags, 0);
		walk(test, image, NTFS_CORRUPT);
	}
	free(image);
}

static void
packet_copy_checks(const struct batch_case *test, const struct ntfs_write_batch_pages *plan)
{
	const struct ntfs_write_batch_page *page;
	uint8_t *packet, *snapshot, *protected_bytes;
	size_t index, bytes, actual, tail;

	packet = malloc(NTFS_WRITE_BATCH_MAX_PACKET_BYTES);
	snapshot = malloc(NTFS_WRITE_CLUSTER_BYTES);
	assert(packet != NULL && snapshot != NULL);
	for (index = 0; index < test->input.packets; index++) {
		assert(ntfs_write_batch_pages_packet_copy(plan, index, packet,
			   NTFS_WRITE_BATCH_MAX_PACKET_BYTES, &actual) == NTFS_OK);
		assert(actual == test->records[index].bytes &&
		    memcmp(packet, test->records[index].packet, actual) == 0);
	}
	page = ntfs_write_batch_pages_get(plan, test->pages - 1);
	assert(page != NULL);
	protected_bytes = (void *)page->protected_bytes;
	memcpy(snapshot, protected_bytes, NTFS_WRITE_CLUSTER_BYTES);
	bytes = test->records[page->packet].bytes;
	memset(packet, TEST_RECORD_SENTINEL, NTFS_WRITE_BATCH_MAX_PACKET_BYTES);
	actual = SIZE_MAX;
	assert(ntfs_write_batch_pages_packet_copy(plan, page->packet, protected_bytes,
		   NTFS_WRITE_CLUSTER_BYTES, &actual) == NTFS_INVALID);
	assert(
	    actual == SIZE_MAX && memcmp(snapshot, protected_bytes, NTFS_WRITE_CLUSTER_BYTES) == 0);
	assert(ntfs_write_batch_pages_packet_copy(plan, page->packet, packet,
		   NTFS_WRITE_BATCH_MAX_PACKET_BYTES, (void *)protected_bytes) == NTFS_INVALID);
	assert(memcmp(snapshot, protected_bytes, NTFS_WRITE_CLUSTER_BYTES) == 0);
	assert(ntfs_write_batch_pages_packet_copy(plan, page->packet, packet,
		   NTFS_WRITE_BATCH_MAX_PACKET_BYTES, (void *)packet) == NTFS_INVALID);
	assert(ntfs_write_batch_pages_packet_copy(plan, page->packet, NULL,
		   NTFS_WRITE_BATCH_MAX_PACKET_BYTES, &actual) == NTFS_INVALID);
	assert(actual == SIZE_MAX);
	assert(ntfs_write_batch_pages_packet_copy(plan, page->packet, packet, bytes - 1, &actual) ==
		NTFS_RANGE &&
	    actual == 0);
	for (tail = NTFS_MST_STRIDE - sizeof(uint16_t); tail < NTFS_WRITE_CLUSTER_BYTES;
	    tail += NTFS_MST_STRIDE) {
		protected_bytes[tail] ^= 1;
		actual = SIZE_MAX;
		assert(ntfs_write_batch_pages_packet_copy(plan, page->packet, packet,
			   NTFS_WRITE_BATCH_MAX_PACKET_BYTES, &actual) == NTFS_CORRUPT);
		assert(actual == 0);
		protected_bytes[tail] ^= 1;
	}
	actual = SIZE_MAX;
	assert(ntfs_write_batch_pages_packet_copy(plan, test->input.packets, packet,
		   NTFS_WRITE_BATCH_MAX_PACKET_BYTES, &actual) == NTFS_END &&
	    actual == 0);
	for (index = 0; index < NTFS_WRITE_BATCH_MAX_PACKET_BYTES; index++) {
		assert(packet[index] == TEST_RECORD_SENTINEL);
	}
	assert(memcmp(snapshot, protected_bytes, NTFS_WRITE_CLUSTER_BYTES) == 0);
	assert(ntfs_write_batch_pages_packet_copy(plan, page->packet, packet,
		   NTFS_WRITE_BATCH_MAX_PACKET_BYTES, &actual) == NTFS_OK);
	assert(actual == bytes && memcmp(packet, test->records[page->packet].packet, bytes) == 0);
	free(snapshot);
	free(packet);
}

static void
faults_and_lifetime(struct batch_case *test)
{
	struct ntfs_write_batch_pages *plan = NULL;
	struct tracker tracker = {.image = test->source, .image_bytes = test->source_bytes};
	struct ntfs_environment source = environment(&tracker);
	struct ntfs_write_batch_pages_input input_snapshot = test->input;
	struct ntfs_write_batch_packet *descriptors;
	size_t attempts, failure, index;

	descriptors = malloc(test->input.packets * sizeof(*descriptors));
	assert(descriptors != NULL);
	memcpy(descriptors, test->packets, test->input.packets * sizeof(*descriptors));
	assert(ntfs_write_batch_pages_prepare(&source, &test->input, &plan) == NTFS_OK);
	assert(tracker.reads == 0 && tracker.live > 0);
	attempts = tracker.allocations;
	assert(attempts > 0 && attempts <= NTFS_DEFAULT_OPERATION_ALLOCATION_CALLS &&
	    tracker.peak <= NTFS_DEFAULT_MAX_LIVE_BYTES);
	compare_plan(test, plan);
	roundtrip(test, plan);
	packet_copy_checks(test, plan);
	for (index = 0; index < test->input.packets; index++) {
		memset(test->records[index].payload, TEST_RECORD_SENTINEL,
		    test->packets[index].payload.bytes);
	}
	memset(test->packets, 0, test->input.packets * sizeof(*test->packets));
	memset(&test->input.restart, 0, sizeof(test->input.restart));
	compare_plan(test, plan);
	test->input = input_snapshot;
	memcpy(test->packets, descriptors, test->input.packets * sizeof(*descriptors));
	for (index = 0; index < test->input.packets; index++) {
		memcpy(test->records[index].payload,
		    test->records[index].packet + sizeof(struct ntfs_disk_log_record),
		    test->packets[index].payload.bytes);
	}
	ntfs_write_batch_pages_close(plan);
	assert(tracker.live == 0);
	for (failure = 1; failure <= attempts; failure++) {
		tracker = (struct tracker){
		    .image = test->source, .image_bytes = test->source_bytes, .fail_at = failure};
		assert(
		    ntfs_write_batch_pages_prepare(&source, &test->input, &plan) == NTFS_NO_MEMORY);
		assert(plan == NULL && tracker.live == 0 && tracker.reads == 0);
		assert(memcmp(&test->input, &input_snapshot, sizeof(input_snapshot)) == 0);
		assert(memcmp(test->packets, descriptors,
			   test->input.packets * sizeof(*descriptors)) == 0);
		tracker.fail_at = 0;
		assert(ntfs_write_batch_pages_prepare(&source, &test->input, &plan) == NTFS_OK);
		compare_plan(test, plan);
		ntfs_write_batch_pages_close(plan);
		assert(tracker.live == 0 && tracker.reads == 0);
	}
	free(descriptors);
}

static void
refused(const struct ntfs_environment *source, const struct ntfs_write_batch_pages_input *input,
    enum ntfs_result expected)
{
	struct ntfs_write_batch_pages *plan = (void *)(uintptr_t)1;
	struct tracker *tracker = source->context;
	size_t calls = tracker->allocations;

	assert(ntfs_write_batch_pages_prepare(source, input, &plan) == expected);
	assert(plan == NULL && tracker->live == 0 && tracker->reads == 0 &&
	    tracker->allocations == calls);
}

static void
bad_pointer(const struct ntfs_environment *source, const struct ntfs_write_batch_pages_input *input)
{
	struct ntfs_write_batch_pages *plan = (void *)(uintptr_t)1;
	struct tracker *tracker = source->context;
	size_t calls = tracker->allocations;

	assert(ntfs_write_batch_pages_prepare(source, input, &plan) == NTFS_INVALID);
	assert(plan == (void *)(uintptr_t)1 && tracker->live == 0 && tracker->reads == 0 &&
	    tracker->allocations == calls);
}

static void
bad_inputs(struct batch_case *test)
{
	struct ntfs_write_batch_pages_input input;
	struct ntfs_write_batch_packet packet, pair[2];
	struct ntfs_write_batch_pages *plan = NULL;
	struct tracker tracker = {.image = test->source, .image_bytes = test->source_bytes};
	struct ntfs_environment source = environment(&tracker), changed;
	uint64_t epoch_step;
	uint8_t snapshot[sizeof(input)];

	assert(test->input.packets == 1);
	input = test->input;
	packet = test->packets[0];
	input.packet = &packet;
	assert(ntfs_write_batch_pages_prepare(&source, &input, NULL) == NTFS_INVALID);
	refused(&source, NULL, NTFS_INVALID);
	assert(ntfs_write_batch_pages_prepare(NULL, &input, &plan) == NTFS_INVALID && plan == NULL);
	changed = source;
	changed.api_version++;
	refused(&changed, &input, NTFS_INVALID);
	changed = source;
	changed.allocate = NULL;
	refused(&changed, &input, NTFS_INVALID);
	changed = source;
	changed.release = NULL;
	refused(&changed, &input, NTFS_INVALID);
	memcpy(snapshot, &input, sizeof(input));
	assert(ntfs_write_batch_pages_prepare(&source, &input, (void *)&input.next_lsn) ==
	    NTFS_INVALID);
	assert(memcmp(snapshot, &input, sizeof(input)) == 0);
	assert(ntfs_write_batch_pages_prepare(&source, &input, (void *)&packet.record) ==
	    NTFS_INVALID);
	assert(memcmp(&packet, &test->packets[0], sizeof(packet)) == 0);
	assert(ntfs_write_batch_pages_prepare(&source, &input, (void *)packet.payload.data) ==
	    NTFS_INVALID);
	assert(memcmp(packet.payload.data,
		   test->records[0].packet + sizeof(struct ntfs_disk_log_record),
		   packet.payload.bytes) == 0);
	assert(ntfs_write_batch_pages_prepare(&source, &input, (void *)&source) == NTFS_INVALID);
	assert(ntfs_write_batch_pages_prepare(
		   &source, &input, (void *)(UINTPTR_MAX - sizeof(void *) + 1)) == NTFS_INVALID);
	bad_pointer(&source, (void *)(UINTPTR_MAX - sizeof(input) + 1));
	input.packet = (void *)(UINTPTR_MAX - sizeof(packet) + 1);
	bad_pointer(&source, &input);
	input.packet = &packet;
	input.packets = 0;
	refused(&source, &input, NTFS_INVALID);
	input.packets = NTFS_WRITE_BATCH_MAX_PACKETS + 1;
	input.packet = test->packets;
	refused(&source, &input, NTFS_RANGE);
	input.packet = &packet;
	input.packets = 1;
	packet.payload.data = NULL;
	bad_pointer(&source, &input);
	packet.payload.data = (void *)(UINTPTR_MAX - packet.payload.bytes + 1);
	bad_pointer(&source, &input);
	packet = test->packets[0];
	packet.payload.bytes = NTFS_WRITE_BATCH_MAX_PACKET_BYTES;
	packet.record.data.length = (uint32_t)packet.payload.bytes;
	refused(&source, &input, NTFS_RANGE);
	packet = test->packets[0];
	packet.record.lsn = input.tail_lsn;
	refused(&source, &input, NTFS_INVALID);
	packet = test->packets[0];
	packet.record.flags = NTFS_LOGFILE_RECORD_MULTI_PAGE;
	refused(&source, &input, NTFS_INVALID);
	packet.record.flags = UINT16_MAX;
	refused(&source, &input, NTFS_UNSUPPORTED);
	packet = test->packets[0];
	packet.record.data.offset += NTFS_WIRE_ALIGNMENT;
	refused(&source, &input, NTFS_UNSUPPORTED);
	packet = test->packets[0];
	packet.record.data.length++;
	refused(&source, &input, NTFS_INVALID);
	packet = test->packets[0];
	packet.record.type = 0;
	refused(&source, &input, NTFS_UNSUPPORTED);
	packet = test->packets[0];
	packet.record.client_index = input.restart.client_count;
	refused(&source, &input, NTFS_INVALID);
	packet = test->packets[0];
	packet.previous = 0;
	refused(&source, &input, NTFS_INVALID);
	packet.previous = SIZE_MAX;
	packet.undo_next = 1;
	refused(&source, &input, NTFS_INVALID);
	packet = test->packets[0];
	packet.record.previous_lsn = input.next_lsn;
	refused(&source, &input, NTFS_INVALID);
	packet.record.previous_lsn = input.floor_lsn - 1;
	refused(&source, &input, NTFS_INVALID);
	packet = test->packets[0];
	pair[0] = packet;
	pair[1] = packet;
	pair[1].previous = 0;
	pair[1].record.client_sequence++;
	input.packet = pair;
	input.packets = 2;
	refused(&source, &input, NTFS_INVALID);
	pair[1].record.client_sequence--;
	pair[1].record.previous_lsn = input.tail_lsn;
	refused(&source, &input, NTFS_INVALID);
	pair[1].record.previous_lsn = 0;
	pair[1].record.transaction++;
	refused(&source, &input, NTFS_INVALID);
	input = test->input;
	input.next_lsn = input.tail_lsn;
	refused(&source, &input, NTFS_INVALID);
	input = test->input;
	input.floor_lsn = input.next_lsn;
	refused(&source, &input, NTFS_INVALID);
	input = test->input;
	input.next_lsn -=
	    (NTFS_WRITE_LOG_DATA_OFFSET + test->records[0].bytes) >> NTFS_LFS_LSN_OFFSET_SHIFT;
	refused(&source, &input, NTFS_CORRUPT);
	input = test->input;
	epoch_step = UINT64_C(1) << (NTFS_LFS_LSN_BITS - input.restart.sequence_bits);
	input.next_lsn += 2 * epoch_step;
	refused(&source, &input, NTFS_STALE);
	input = test->input;
	input.next_lsn = input.floor_lsn + epoch_step + 1;
	refused(&source, &input, NTFS_NO_SPACE);
	input = test->input;
	input.restart.major = NTFS_LFS_MAJOR_FAST;
	refused(&source, &input, NTFS_UNSUPPORTED);
	input = test->input;
	input.restart.page_data_offset += NTFS_WIRE_ALIGNMENT;
	refused(&source, &input, NTFS_UNSUPPORTED);
	input = test->input;
	input.restart.record_header_bytes += NTFS_WIRE_ALIGNMENT;
	refused(&source, &input, NTFS_UNSUPPORTED);
	input = test->input;
	input.restart.sequence_bits = 0;
	refused(&source, &input, NTFS_INVALID);
	changed = source;
	changed.read = NULL;
	assert(ntfs_write_batch_pages_prepare(&changed, &test->input, &plan) == NTFS_OK);
	compare_plan(test, plan);
	ntfs_write_batch_pages_close(plan);
	assert(tracker.live == 0 && tracker.reads == 0);
}

static void
page_policy(struct batch_case *test, const struct batch_case *spanning)
{
	struct ntfs_write_batch_pages_input input = test->input;
	struct ntfs_write_batch_packet *packets;
	struct tracker tracker = {.image = test->source, .image_bytes = test->source_bytes};
	struct ntfs_environment source = environment(&tracker);
	size_t index;

	assert(test->input.packets == NTFS_WRITE_BATCH_MAX_PACKETS && spanning->input.packets == 1);
	packets = malloc(input.packets * sizeof(*packets));
	assert(packets != NULL);
	for (index = 0; index < input.packets; index++) {
		packets[index] = spanning->packets[0];
	}
	input.packet = packets;
	refused(&source, &input, NTFS_RANGE);
	free(packets);
}

int
main(int argc, char **argv)
{
	struct batch_case *test, *spanning;
	struct ntfs_write_batch_pages *plan = NULL;
	struct tracker tracker;
	struct ntfs_environment source;
	char name[TEST_NAME_BYTES];
	FILE *rows;
	size_t cases = 0, pages = 0, successes = 0;

	assert(argc == 2);
	test = calloc(1, sizeof(*test));
	spanning = calloc(1, sizeof(*spanning));
	assert(test != NULL && spanning != NULL);
	read_case(argv[1], "one-byte-continuation", spanning);
	rows = open_file(argv[1], "cases.rows");
	assert(ntfs_write_batch_pages_count(NULL) == 0 &&
	    ntfs_write_batch_pages_get(NULL, 0) == NULL &&
	    ntfs_write_batch_pages_lsn(NULL, 0) == 0 && ntfs_write_batch_pages_next_lsn(NULL) == 0);
	ntfs_write_batch_pages_close(NULL);
	while (fscanf(rows, "%127s", name) == 1) {
		read_case(argv[1], name, test);
		tracker =
		    (struct tracker){.image = test->source, .image_bytes = test->source_bytes};
		source = environment(&tracker);
		assert(
		    ntfs_write_batch_pages_prepare(&source, &test->input, &plan) == test->result);
		assert(tracker.reads == 0);
		if (test->result == NTFS_OK) {
			compare_plan(test, plan);
			ntfs_write_batch_pages_close(plan);
			assert(tracker.live == 0);
			faults_and_lifetime(test);
			if (strcmp(name, "one") == 0) {
				bad_inputs(test);
			}
			if (strcmp(name, "maximum-transfers") == 0) {
				page_policy(test, spanning);
			}
			successes++;
			pages += test->pages;
		} else {
			assert(plan == NULL && tracker.live == 0 && tracker.allocations == 0);
		}
		close_case(test);
		cases++;
	}
	assert(ferror(rows) == 0 && fclose(rows) == 0 && cases > 0);
	close_case(spanning);
	free(spanning);
	free(test);
	printf("PASS %zu LFS placement profiles, %zu complete projections, %zu exact pages\n",
	    cases, successes, pages);
	return 0;
}
