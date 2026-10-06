/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_internal.h"
#include "fuzz_device.h"
#include "image_fault.h"
#include "../adapters/posix/overwrite_image.h"
#include <ntfs/validate.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_PATH_BYTES = 4096,
	TEST_DATA_SPANS = 2,
	TEST_WRITES = NTFS_WRITE_EXECUTE_FRAMES + 1 + TEST_DATA_SPANS,
	TEST_BARRIERS = NTFS_WRITE_EXECUTE_FRAMES + 2,
	TEST_CAPTURE_EVENTS = 2 * (3 * NTFS_WRITE_HISTORY_TRANSACTIONS + 6),
	TEST_COMMIT_COPY_WRITE = NTFS_LFS_RESTART_PAGES + 2 + TEST_DATA_SPANS + 1,
	TEST_FILE_HOME_WRITE = TEST_COMMIT_COPY_WRITE + 2,
	TEST_PARTIAL_DIVISOR = 2
};

#define TEST_REFERENCE (UINT64_C(7) << NTFS_REFERENCE_SEQUENCE_SHIFT | UINT64_C(25))
#define TEST_FILETIME UINT64_C(134357146906613431)

struct event {
	uint64_t physical;
	size_t bytes;
	bool barrier;
};

struct device {
	struct fuzz_device reader;
	uint8_t *visible, *durable;
	size_t writes, barriers, fail_write, fail_barrier, failed_bytes, events;
	bool claimed, full_failed_read, malformed_transfer, owned_writer;
	struct event event[TEST_CAPTURE_EVENTS];
};

union owned_allocation {
	max_align_t alignment;
	size_t bytes;
};

struct test_case {
	struct device device;
	struct ntfs_overwrite_environment backend;
	struct ntfs_write_transaction_workspace *transaction;
	struct ntfs_write_execution_workspace *execution;
	struct ntfs_write_recovery_workspace *recovery;
	struct ntfs_write_data_span data[TEST_DATA_SPANS];
	struct ntfs_validation_report *validation;
	struct ntfs_write_history_workspace *history_work;
	struct ntfs_write_history *history;
	uint8_t *source, *expected;
	size_t bytes;
};

static void *
aligned(size_t bytes)
{
	void *buffer = NULL;

	assert(posix_memalign(&buffer, NTFS_WRITE_CLUSTER_BYTES, bytes) == 0 && buffer != NULL);
	memset(buffer, 0, bytes);
	return buffer;
}

static uint8_t *
load(const char *directory, const char *name, size_t *bytes)
{
	char *path = malloc(TEST_PATH_BYTES);
	uint8_t *buffer;
	FILE *file;
	long length;
	int result;

	assert(path != NULL);
	result = snprintf(path, TEST_PATH_BYTES, "%s/%s", directory, name);
	assert(result > 0 && result < TEST_PATH_BYTES);
	file = fopen(path, "rb");
	free(path);
	assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
	length = ftell(file);
	assert(length > 0 && fseek(file, 0, SEEK_SET) == 0);
	*bytes = (size_t)length;
	buffer = aligned(*bytes);
	assert(fread(buffer, 1, *bytes, file) == *bytes);
	assert(fgetc(file) == EOF && !ferror(file) && fclose(file) == 0);
	return buffer;
}

static enum ntfs_result
read_image(void *context, uint64_t physical, void *buffer, size_t bytes)
{
	struct device *device = context;

	assert(device->claimed);
	if (device->reader.fail_read != 0 && device->reader.reads + 1 == device->reader.fail_read) {
		assert(ntfs_bounds(physical, bytes, device->reader.size));
		memcpy(buffer, device->visible + physical,
		    device->full_failed_read ? bytes : bytes / TEST_PARTIAL_DIVISOR);
	}
	return fuzz_read(context, physical, buffer, bytes);
}

static void *
allocate_image(void *context, size_t bytes)
{
	struct device *device = context;
	union owned_allocation *buffer;

	if (!device->owned_writer) {
		return fuzz_allocate(context, bytes);
	}
	device->reader.allocations++;
	if (device->reader.allocations == device->reader.fail_allocation ||
	    bytes > NTFS_DEFAULT_MAX_LIVE_BYTES - device->reader.memory) {
		return NULL;
	}
	buffer = malloc(sizeof(*buffer) + bytes);
	if (buffer != NULL) {
		buffer->bytes = bytes;
		device->reader.memory += bytes;
		return buffer + 1;
	}
	return NULL;
}

static void
release_image(void *context, void *memory, size_t bytes)
{
	struct device *device = context;
	union owned_allocation *buffer = (union owned_allocation *)memory - 1;

	if (!device->owned_writer) {
		fuzz_release(context, memory, bytes);
		return;
	}
	assert(buffer->bytes == bytes && bytes <= device->reader.memory);
	device->reader.memory -= bytes;
	free(buffer);
}

static enum ntfs_result
claim(void *context)
{
	struct device *device = context;

	assert(!device->claimed);
	device->claimed = true;
	return NTFS_OK;
}

static void
unclaim(void *context)
{
	struct device *device = context;

	assert(device->claimed && (device->owned_writer || device->reader.memory == 0));
	device->claimed = false;
}

static enum ntfs_result
write_image(void *context, uint64_t physical, const void *image, size_t bytes, size_t *actual)
{
	struct device *device = context;
	size_t changed;

	assert(device->claimed && (device->owned_writer || device->reader.memory == 0));
	assert(ntfs_bounds(physical, bytes, device->reader.size));
	assert(physical % NTFS_WRITE_SECTOR_BYTES == 0 && bytes % NTFS_WRITE_SECTOR_BYTES == 0 &&
	    (uintptr_t)image % NTFS_WRITE_SECTOR_BYTES == 0);
	assert(device->events < TEST_CAPTURE_EVENTS);
	device->event[device->events++] = (struct event){physical, bytes, false};
	device->writes++;
	if (device->writes == device->fail_write) {
		changed = device->failed_bytes < bytes ? device->failed_bytes : bytes;
		/* An attempted failed transfer may persist an arbitrary requested prefix. */
		memcpy(device->visible + physical, image, changed);
		memcpy(device->durable + physical, image, changed);
		*actual = device->malformed_transfer ? bytes + 1 : changed;
		return NTFS_IO;
	}
	memcpy(device->visible + physical, image, bytes);
	*actual = bytes;
	return NTFS_OK;
}

static enum ntfs_result
persist_image(void *context)
{
	struct device *device = context;

	assert(device->claimed && (device->owned_writer || device->reader.memory == 0) &&
	    device->events < TEST_CAPTURE_EVENTS);
	device->event[device->events++] = (struct event){0, 0, true};
	device->barriers++;
	/* The failure case retains all preceding writes: failure cannot prove loss. */
	memcpy(device->durable, device->visible, device->reader.size);
	return device->barriers == device->fail_barrier ? NTFS_IO : NTFS_OK;
}

static struct ntfs_volume *
mount(struct test_case *test)
{
	struct ntfs_volume *volume = NULL;
	struct ntfs_limits limits;

	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	test->device.reader.reads = 0;
	test->device.reader.allocations = 0;
	assert(ntfs_mount(&test->backend.reader, &limits, &volume) == NTFS_OK);
	return volume;
}

static void
reset(struct test_case *test)
{
	struct device *device = &test->device;

	assert(device->reader.memory == 0 && device->claimed);
	memcpy(device->visible, test->source, test->bytes);
	memcpy(device->durable, test->source, test->bytes);
	device->reader.reads = 0;
	device->reader.allocations = 0;
	device->reader.fail_read = 0;
	device->writes = 0;
	device->barriers = 0;
	device->events = 0;
	device->fail_write = 0;
	device->fail_barrier = 0;
	device->failed_bytes = 0;
	device->malformed_transfer = false;
	test->transaction->execution.data = test->data;
	test->transaction->execution.spans = TEST_DATA_SPANS;
}

static void
initialize(struct test_case *test, const char *directory)
{
	struct ntfs_volume *volume;
	struct ntfs_node *node = NULL;
	struct ntfs_write_replay_plan *overlay = calloc(1, sizeof(*overlay));
	char *path = malloc(TEST_PATH_BYTES), name[TEST_PATH_BYTES];
	FILE *rows;
	unsigned long long physical, bytes;
	size_t index, expected_bytes, data_bytes;
	int result;

	assert(overlay != NULL && path != NULL);
	test->transaction = calloc(1, sizeof(*test->transaction));
	test->execution = aligned(sizeof(*test->execution));
	test->recovery = aligned(sizeof(*test->recovery));
	test->validation = calloc(1, sizeof(*test->validation));
	test->history_work = calloc(1, sizeof(*test->history_work));
	test->history = calloc(1, sizeof(*test->history));
	assert(test->transaction != NULL && test->validation != NULL &&
	    test->history_work != NULL && test->history != NULL);
	test->source = load(directory, "source.img", &test->bytes);
	test->expected = load(directory, "execute-final.img", &expected_bytes);
	assert(expected_bytes == test->bytes);
	test->device.visible = malloc(test->bytes);
	test->device.durable = malloc(test->bytes);
	assert(test->device.visible != NULL && test->device.durable != NULL);
	test->device.reader.data = test->device.visible;
	test->device.reader.size = test->bytes;
	test->backend.reader = fuzz_environment(&test->device.reader);
	test->backend.reader.read = read_image;
	test->backend.reader.allocate = allocate_image;
	test->backend.reader.release = release_image;
	test->backend.api_version = NTFS_OVERWRITE_API_VERSION;
	test->backend.alignment = NTFS_WRITE_SECTOR_BYTES;
	test->backend.claim = claim;
	test->backend.unclaim = unclaim;
	test->backend.write = write_image;
	test->backend.persist = persist_image;
	assert(claim(&test->device) == NTFS_OK);
	reset(test);
	assert(ntfs_validate(&test->backend.reader, NULL, NULL, test->validation) == NTFS_OK);
	volume = mount(test);
	assert(ntfs_node_open(volume, TEST_REFERENCE, &node) == NTFS_OK);
	assert(ntfs_write_prepare_transaction(node, TEST_FILETIME, test->transaction) == NTFS_OK);
	assert(test->transaction->history.transactions == 0);
	ntfs_node_close(node);
	assert(ntfs_unmount(volume) == NTFS_OK && test->device.reader.memory == 0);
	memcpy(&overlay->file, &test->transaction->file, sizeof(overlay->file));
	assert(ntfs_write_validate_overlay(&test->backend.reader, overlay, test->validation) ==
	    NTFS_OK);
	free(overlay);
	result = snprintf(path, TEST_PATH_BYTES, "%s/execute-data.rows", directory);
	assert(result > 0 && result < TEST_PATH_BYTES);
	rows = fopen(path, "rb");
	assert(rows != NULL);
	for (index = 0; index < TEST_DATA_SPANS; index++) {
		assert(fscanf(rows, "%llu %llu", &physical, &bytes) == 2);
		result = snprintf(name, sizeof(name), "execute-data-%zu.expected", index);
		assert(result > 0 && (size_t)result < sizeof(name));
		test->data[index].image = load(directory, name, &data_bytes);
		assert(data_bytes == bytes);
		test->data[index].physical = physical;
		test->data[index].bytes = data_bytes;
	}
	assert(fscanf(rows, "%llu", &physical) == EOF && !ferror(rows) && fclose(rows) == 0);
	free(path);
	reset(test);
}

static void
prepare(struct test_case *test)
{
	test->device.reader.reads = 0;
	assert(ntfs_write_execute_prepare(
		   &test->backend, &test->transaction->execution, test->execution) == NTFS_OK);
	assert(test->device.reader.reads == NTFS_WRITE_EXECUTE_LOG_LOCATIONS + 1);
	assert(test->device.reader.memory == 0 && test->device.writes == 0 &&
	    test->device.barriers == 0);
}

static void
success(struct test_case *test)
{
	const struct ntfs_write_execution_input *input = &test->transaction->execution;
	struct ntfs_write_execution_report report;
	uint64_t physical[TEST_WRITES] = {input->physical[NTFS_WRITE_EXECUTE_RESTART_FIRST],
	    input->physical[NTFS_WRITE_EXECUTE_RESTART_SECOND],
	    input->physical[NTFS_WRITE_EXECUTE_PREPARE_COPY],
	    input->physical[NTFS_WRITE_EXECUTE_PREPARE_HOME], test->data[0].physical,
	    test->data[1].physical, input->physical[NTFS_WRITE_EXECUTE_COMMIT_COPY],
	    input->physical[NTFS_WRITE_EXECUTE_COMMIT_HOME], input->file->cluster_physical,
	    input->physical[NTFS_WRITE_EXECUTE_RESTART_FIRST],
	    input->physical[NTFS_WRITE_EXECUTE_RESTART_SECOND]};
	size_t index, write = 0, barriers = 0, reads, allocations;
	bool poisoned = false;

	prepare(test);
	reads = test->device.reader.reads;
	allocations = test->device.reader.allocations;
	assert(ntfs_write_execute(test->execution, &poisoned, &report) == NTFS_OK);
	assert(!poisoned && !report.poisoned && report.completed && report.commit_persisted &&
	    report.data_persisted && report.durable_stage == NTFS_WRITE_EXECUTION_CLEAN_SECOND);
	assert(report.writes == TEST_WRITES && report.barriers == TEST_BARRIERS &&
	    report.data_bytes == test->data[0].bytes + test->data[1].bytes &&
	    report.physical_bytes ==
		report.data_bytes + (TEST_WRITES - TEST_DATA_SPANS) * NTFS_WRITE_CLUSTER_BYTES);
	assert(
	    test->device.reader.reads == reads && test->device.reader.allocations == allocations);
	assert(memcmp(test->device.visible, test->expected, test->bytes) == 0 &&
	    memcmp(test->device.durable, test->expected, test->bytes) == 0);
	for (index = 0; index < test->device.events; index++) {
		if (test->device.event[index].barrier) {
			barriers++;
			assert(index != 0 && !test->device.event[index - 1].barrier);
		} else {
			assert(write < TEST_WRITES &&
			    test->device.event[index].physical == physical[write]);
			if (write != 5) {
				assert(index == 0 || test->device.event[index - 1].barrier);
			}
			write++;
		}
	}
	assert(write == TEST_WRITES && barriers == TEST_BARRIERS);
	assert(ntfs_write_execute(test->execution, &poisoned, &report) == NTFS_INVALID);
	assert(test->device.writes == TEST_WRITES && test->device.barriers == TEST_BARRIERS);
}

static void
clear_io(struct test_case *test)
{
	struct device *device = &test->device;

	assert(device->reader.memory == 0);
	device->writes = 0;
	device->barriers = 0;
	device->events = 0;
	device->fail_write = 0;
	device->fail_barrier = 0;
	device->reader.fail_read = 0;
	device->reader.fail_allocation = 0;
	device->malformed_transfer = false;
	device->full_failed_read = false;
}

static void
recover_current(struct test_case *test)
{
	struct ntfs_write_recovery_report report;
	struct ntfs_volume *volume;
	struct ntfs_node *node = NULL;
	struct ntfs_disk_record *header;
	const struct ntfs_write_file_plan *file = &test->transaction->file;
	uint8_t *before = malloc(test->bytes), *preserved = malloc(test->bytes);
	uint8_t *wanted = malloc(NTFS_WRITE_RECORD_BYTES);
	uint64_t physical[] = {test->transaction->execution.physical[0],
	    test->transaction->execution.physical[1], test->transaction->execution.physical[2],
	    test->transaction->execution.physical[3], test->transaction->execution.physical[5]};
	uint64_t home = file->cluster_physical + file->cluster_index * NTFS_WRITE_SECTOR_BYTES;
	size_t index, reads, allocations, first, end, used;
	bool committed, poisoned = false;
	enum ntfs_result result;

	assert(before != NULL && preserved != NULL && wanted != NULL);
	clear_io(test);
	memcpy(before, test->device.visible, test->bytes);
	volume = mount(test);
	result = ntfs_write_recover_prepare(volume, &test->backend, test->recovery);
	if (result != NTFS_OK) {
		fprintf(stderr, "recovery prepare result=%u\n", result);
	}
	assert(result == NTFS_OK);
	committed = test->recovery->history.transactions != 0 &&
	    test->recovery->history.transaction[0].committed;
	assert(ntfs_unmount(volume) == NTFS_OK && test->device.reader.memory == 0);
	reads = test->device.reader.reads;
	allocations = test->device.reader.allocations;
	assert(ntfs_write_recover_execute(test->recovery, &poisoned, &report) == NTFS_OK);
	assert(report.completed && report.homes_persisted && !report.poisoned && !poisoned);
	assert(
	    test->device.reader.reads == reads && test->device.reader.allocations == allocations);
	assert(memcmp(test->device.visible, test->device.durable, test->bytes) == 0);
	memcpy(preserved, test->device.visible, test->bytes);
	for (index = 0; index < sizeof(physical) / sizeof(physical[0]); index++) {
		memcpy(preserved + physical[index], before + physical[index],
		    NTFS_WRITE_CLUSTER_BYTES);
	}
	memcpy(preserved + home, before + home, NTFS_WRITE_RECORD_BYTES);
	assert(memcmp(preserved, before, test->bytes) == 0);
	clear_io(test);
	volume = mount(test);
	assert(ntfs_validate(&test->backend.reader, NULL, NULL, test->validation) == NTFS_OK);
	assert(ntfs_write_history_capture(volume, test->history_work, test->history) == NTFS_OK);
	assert(test->history->selected.flags == NTFS_LOGFILE_RESTART_CLEAN);
	assert(ntfs_write_history_settled(volume, test->history) == NTFS_OK);
	assert(ntfs_node_open(volume, TEST_REFERENCE, &node) == NTFS_OK);
	memcpy(wanted, (committed ? test->expected : test->source) + home, NTFS_WRITE_RECORD_BYTES);
	assert(ntfs_fixup(wanted, NTFS_WRITE_RECORD_BYTES, "FILE") == NTFS_OK);
	header = (void *)wanted;
	if (test->history->transactions != 0) {
		assert(test->history->transactions == 1 &&
		    (test->history->transaction[0].committed ||
			test->history->transaction[0].compensated));
		assert(test->history->transaction[0].committed == committed);
		ntfs_put_u64(header->lsn,
		    committed ? test->history->transaction[0].update_lsn
			      : test->history->transaction[0].compensation_lsn);
	}
	first = ntfs_u16(header->mst.usa_offset);
	end = first + (size_t)ntfs_u16(header->mst.usa_count) * sizeof(uint16_t);
	used = ntfs_u32(header->used);
	assert(end <= used && used <= NTFS_WRITE_RECORD_BYTES);
	assert(memcmp(node->record, wanted, first) == 0 &&
	    memcmp(node->record + end, wanted + end, used - end) == 0);
	ntfs_node_close(node);
	assert(ntfs_write_recover_prepare(volume, &test->backend, test->recovery) == NTFS_OK);
	assert(ntfs_unmount(volume) == NTFS_OK && test->device.reader.memory == 0);
	assert(!test->recovery->mutation && !test->recovery->close_transaction);
	memcpy(before, test->device.visible, test->bytes);
	assert(ntfs_write_recover_execute(test->recovery, &poisoned, &report) == NTFS_OK);
	assert(report.completed && report.writes == 0 && report.barriers == 1);
	assert(memcmp(before, test->device.visible, test->bytes) == 0);
	assert(ntfs_write_recover_execute(test->recovery, &poisoned, &report) == NTFS_INVALID);
	free(before);
	free(preserved);
	free(wanted);
}

static void
reconstruction(struct test_case *test, size_t fail_write, size_t failed_bytes, size_t fail_barrier)
{
	struct ntfs_volume *volume;
	enum ntfs_result result;

	/* Reopen from durable bytes, then execute recovery after the read epoch closes. */
	memcpy(test->device.visible, test->device.durable, test->bytes);
	volume = mount(test);
	result = ntfs_write_history_capture(volume, test->history_work, test->history);
	if (result != NTFS_OK) {
		fprintf(stderr, "history result=%u write=%zu bytes=%zu barrier=%zu\n", result,
		    fail_write, failed_bytes, fail_barrier);
	}
	assert(result == NTFS_OK);
	if (test->history->pending) {
		assert(test->history->transactions == 1);
		assert(
		    ntfs_write_validate_overlays(&test->backend.reader, test->history->transaction,
			test->history->transactions, test->validation) == NTFS_OK);
	} else {
		assert(test->history->transactions == 0);
		assert(
		    ntfs_validate(&test->backend.reader, NULL, NULL, test->validation) == NTFS_OK);
	}
	assert(ntfs_unmount(volume) == NTFS_OK && test->device.reader.memory == 0);
	recover_current(test);
}

static void
failure(struct test_case *test, size_t fail_write, size_t failed_bytes, size_t fail_barrier,
    bool malformed)
{
	struct ntfs_write_execution_report report;
	size_t writes, barriers, reads, allocations;
	bool poisoned = false;

	reset(test);
	prepare(test);
	test->device.fail_write = fail_write;
	test->device.fail_barrier = fail_barrier;
	test->device.failed_bytes = failed_bytes;
	test->device.malformed_transfer = malformed;
	reads = test->device.reader.reads;
	allocations = test->device.reader.allocations;
	assert(ntfs_write_execute(test->execution, &poisoned, &report) == NTFS_IO);
	assert(poisoned && report.poisoned && !report.completed);
	assert(report.writes == test->device.writes && report.barriers == test->device.barriers);
	assert(
	    test->device.reader.reads == reads && test->device.reader.allocations == allocations);
	writes = test->device.writes;
	barriers = test->device.barriers;
	assert(
	    ntfs_write_execute(test->execution, &poisoned, &report) == NTFS_IO && report.poisoned);
	assert(test->device.writes == writes && test->device.barriers == barriers);
	reconstruction(test, fail_write, failed_bytes, fail_barrier);
}

static void
recovery_unknown_lsn(struct test_case *test)
{
	const uint64_t unrelated[] = {0, UINT64_MAX};
	struct ntfs_write_execution_report written;
	struct ntfs_write_recovery_report report;
	struct ntfs_write_transaction_workspace *transaction = calloc(1, sizeof(*transaction));
	struct ntfs_volume *volume;
	struct ntfs_node *node = NULL;
	struct ntfs_disk_record *header;
	uint8_t *power = malloc(test->bytes);
	size_t index, offset;
	bool poisoned = false;

	assert(power != NULL && transaction != NULL);
	reset(test);
	offset = (size_t)test->transaction->file.cluster_physical +
	    (size_t)test->transaction->file.cluster_index * NTFS_WRITE_SECTOR_BYTES;
	/* The ordinary fixture has a valid zero before-LSN. Give this separate
	 * checked transaction a nonzero preceding LSN, so zero is unrelated. */
	assert(test->transaction->history.origin.current_lsn != 0);
	header = (void *)(test->device.visible + offset);
	ntfs_put_u64(header->lsn, test->transaction->history.origin.current_lsn);
	memcpy(test->device.durable, test->device.visible, test->bytes);
	volume = mount(test);
	assert(ntfs_node_open(volume, TEST_REFERENCE, &node) == NTFS_OK);
	assert(ntfs_write_prepare_transaction(node, TEST_FILETIME, transaction) == NTFS_OK);
	ntfs_node_close(node);
	assert(ntfs_unmount(volume) == NTFS_OK && test->device.reader.memory == 0);
	transaction->execution.data = test->data;
	transaction->execution.spans = TEST_DATA_SPANS;
	assert(ntfs_write_execute_prepare(
		   &test->backend, &transaction->execution, test->execution) == NTFS_OK);
	test->device.fail_write = TEST_FILE_HOME_WRITE;
	test->device.failed_bytes = NTFS_WRITE_SECTOR_BYTES;
	assert(ntfs_write_execute(test->execution, &poisoned, &written) == NTFS_IO && poisoned);
	memcpy(power, test->device.durable, test->bytes);
	for (index = 0; index < sizeof(unrelated) / sizeof(unrelated[0]); index++) {
		memcpy(test->device.visible, power, test->bytes);
		header = (void *)(test->device.visible + offset);
		/* An absent compensation LSN cannot authorize an unrelated torn home.
		 * The complete logged snapshot does not grant authority over that state. */
		ntfs_put_u64(header->lsn, unrelated[index]);
		memcpy(test->device.durable, test->device.visible, test->bytes);
		clear_io(test);
		volume = mount(test);
		assert(ntfs_write_recover_prepare(volume, &test->backend, test->recovery) ==
		    NTFS_STALE);
		assert(ntfs_unmount(volume) == NTFS_OK && test->device.reader.memory == 0);
		poisoned = false;
		assert(
		    ntfs_write_recover_execute(test->recovery, &poisoned, &report) == NTFS_INVALID);
		assert(!poisoned && test->device.writes == 0 && test->device.barriers == 0);
		assert(memcmp(test->device.visible, test->device.durable, test->bytes) == 0);
	}
	free(power);
	free(transaction);
}

static void
recovery_interruptions(struct test_case *test, size_t writer_ordinal, size_t prefix)
{
	struct ntfs_write_execution_report written;
	struct ntfs_write_recovery_report report;
	struct ntfs_volume *volume;
	uint8_t *power = malloc(test->bytes);
	size_t writes, ordinal, sector, mode, reads, allocations, count = 0;
	bool poisoned = false;

	assert(power != NULL);
	reset(test);
	prepare(test);
	test->device.fail_write = writer_ordinal;
	test->device.failed_bytes = prefix;
	assert(ntfs_write_execute(test->execution, &poisoned, &written) == NTFS_IO && poisoned);
	memcpy(power, test->device.durable, test->bytes);
	memcpy(test->device.visible, power, test->bytes);
	clear_io(test);
	volume = mount(test);
	assert(ntfs_write_recover_prepare(volume, &test->backend, test->recovery) == NTFS_OK);
	writes = 2 * NTFS_LFS_RESTART_PAGES + 1 + (test->recovery->close_transaction ? 2 : 0);
	assert(test->recovery->homes == 1 && test->recovery->home_changed[0]);
	assert(ntfs_unmount(volume) == NTFS_OK && test->device.reader.memory == 0);
	for (mode = 0; mode < 2; mode++) {
		for (ordinal = 1; ordinal <= writes; ordinal++) {
			for (sector = 0; sector <=
			    (mode == 0 ? NTFS_WRITE_CLUSTER_BYTES / NTFS_WRITE_SECTOR_BYTES : 0);
			    sector++) {
				memcpy(test->device.visible, power, test->bytes);
				memcpy(test->device.durable, power, test->bytes);
				clear_io(test);
				volume = mount(test);
				assert(ntfs_write_recover_prepare(
					   volume, &test->backend, test->recovery) == NTFS_OK);
				assert(ntfs_unmount(volume) == NTFS_OK &&
				    test->device.reader.memory == 0);
				reads = test->device.reader.reads;
				allocations = test->device.reader.allocations;
				test->device.fail_write = mode == 0 ? ordinal : 0;
				test->device.fail_barrier = mode == 0 ? 0 : ordinal;
				test->device.failed_bytes = sector * NTFS_WRITE_SECTOR_BYTES;
				poisoned = false;
				assert(ntfs_write_recover_execute(
					   test->recovery, &poisoned, &report) == NTFS_IO);
				assert(poisoned && report.poisoned && !report.completed);
				assert(test->device.reader.reads == reads &&
				    test->device.reader.allocations == allocations);
				reads = test->device.writes;
				allocations = test->device.barriers;
				assert(ntfs_write_recover_execute(
					   test->recovery, &poisoned, &report) == NTFS_IO);
				assert(test->device.writes == reads &&
				    test->device.barriers == allocations);
				memcpy(test->device.visible, test->device.durable, test->bytes);
				recover_current(test);
				count++;
			}
		}
	}
	free(power);
	printf("recovery: %zu interrupted write/barrier profiles recovered again; original writer "
	       "step=%zu\n",
	    count, writer_ordinal);
}

static void
faults(struct test_case *test)
{
	size_t ordinal, sector, count = 0;

	for (ordinal = 1; ordinal <= TEST_WRITES; ordinal++) {
		for (sector = 0; sector <= NTFS_WRITE_CLUSTER_BYTES / NTFS_WRITE_SECTOR_BYTES;
		    sector++) {
			failure(test, ordinal, sector * NTFS_WRITE_SECTOR_BYTES, 0, false);
			count++;
		}
	}
	for (ordinal = 1; ordinal <= TEST_BARRIERS; ordinal++) {
		failure(test, 0, 0, ordinal, false);
		count++;
	}
	failure(test, 1, NTFS_WRITE_CLUSTER_BYTES, 0, true);
	count++;
	printf("write execution: %zu uncertain-transfer/barrier/power-loss profiles with executed "
	       "recovery\n",
	    count);
}

static void
refusals(struct test_case *test)
{
	struct ntfs_write_execution_input input = test->transaction->execution;
	struct ntfs_write_execution_report report;
	struct ntfs_write_data_span data = test->data[0];
	size_t ordinal, mode, writes, barriers;
	uint64_t physical;
	bool poisoned = false;

	reset(test);
	assert(ntfs_write_execute_prepare(&test->backend, &input, (void *)&input) == NTFS_INVALID);
	physical = input.physical[NTFS_WRITE_EXECUTE_PREPARE_HOME];
	input.physical[NTFS_WRITE_EXECUTE_PREPARE_HOME]++;
	assert(ntfs_write_execute_prepare(&test->backend, &input, test->execution) == NTFS_INVALID);
	input.physical[NTFS_WRITE_EXECUTE_PREPARE_HOME] = input.file->cluster_physical;
	assert(ntfs_write_execute_prepare(&test->backend, &input, test->execution) == NTFS_INVALID);
	input.physical[NTFS_WRITE_EXECUTE_PREPARE_HOME] = physical;
	input.data = &data;
	input.spans = 1;
	data.physical = input.physical[NTFS_WRITE_EXECUTE_PREPARE_HOME];
	assert(ntfs_write_execute_prepare(&test->backend, &input, test->execution) == NTFS_INVALID);
	data = test->data[0];
	data.image = NULL;
	assert(ntfs_write_execute_prepare(&test->backend, &input, test->execution) == NTFS_INVALID);
	input = test->transaction->execution;
	for (mode = 0; mode < 2; mode++) {
		for (ordinal = 1; ordinal <= NTFS_WRITE_EXECUTE_LOG_LOCATIONS + 1; ordinal++) {
			test->device.reader.reads = 0;
			test->device.reader.fail_read = ordinal;
			test->device.full_failed_read = mode != 0;
			assert(ntfs_write_execute_prepare(
				   &test->backend, &input, test->execution) == NTFS_IO);
			assert(!test->execution->prepared && test->device.writes == 0 &&
			    test->device.barriers == 0 &&
			    memcmp(test->source, test->device.visible, test->bytes) == 0);
		}
	}
	test->device.reader.fail_read = 0;
	prepare(test);
	writes = test->device.writes;
	barriers = test->device.barriers;
	assert(ntfs_write_execute(test->execution, &poisoned, (void *)test->data[0].image) ==
	    NTFS_INVALID);
	assert(test->device.writes == writes && test->device.barriers == barriers &&
	    memcmp(test->data[0].image, test->expected + test->data[0].physical,
		test->data[0].bytes) == 0);
	poisoned = true;
	assert(
	    ntfs_write_execute(test->execution, &poisoned, &report) == NTFS_IO && report.poisoned);
	assert(test->device.writes == writes && test->device.barriers == barriers);
}

static void
close_case(struct test_case *test)
{
	size_t index;

	unclaim(&test->device);
	for (index = 0; index < TEST_DATA_SPANS; index++) {
		free((void *)test->data[index].image);
	}
	free(test->device.visible);
	free(test->device.durable);
	free(test->source);
	free(test->expected);
	free(test->transaction);
	free(test->execution);
	free(test->recovery);
	free(test->validation);
	free(test->history_work);
	free(test->history);
}

static void
owned_ranges(struct test_case *test, const char *directory)
{
	struct ntfs_overwrite *owner = NULL;
	struct ntfs_overwrite_admission *admission = calloc(1, sizeof(*admission));
	struct ntfs_write_range_report report;
	struct ntfs_write_recovery_report recovered;
	struct ntfs_volume *volume;
	uint8_t *payload, *expected;
	char *path = malloc(TEST_PATH_BYTES);
	FILE *rows;
	unsigned long long offset, requested;
	size_t bytes, expected_bytes, memory, ordinal;
	int result;

	assert(admission != NULL && path != NULL);
	payload = load(directory, "execute-payload.input", &bytes);
	expected = load(directory, "execute-followup-final.img", &expected_bytes);
	assert(expected_bytes == test->bytes);
	result = snprintf(path, TEST_PATH_BYTES, "%s/execute-range.rows", directory);
	assert(result > 0 && result < TEST_PATH_BYTES);
	rows = fopen(path, "rb");
	assert(rows != NULL && fscanf(rows, "%llu %llu", &offset, &requested) == 2 &&
	    requested == bytes);
	assert(fscanf(rows, "%llu", &requested) == EOF && !ferror(rows) && fclose(rows) == 0);
	reset(test);
	unclaim(&test->device);
	test->device.owned_writer = true;
	result = ntfs_overwrite_open(&test->backend, admission, &owner);
	if (result != NTFS_OK) {
		fprintf(stderr, "owned open result=%u\n", result);
	}
	assert(result == NTFS_OK);
	assert(admission->claimed && admission->quiescent && admission->persistence_succeeded);
	memory = test->device.reader.memory;
	test->device.events = 0;
	test->device.barriers = 0;
	for (ordinal = 1; ordinal <= 7; ordinal++) {
		test->device.reader.fail_allocation = test->device.reader.allocations + ordinal;
		assert(ntfs_write_existing_range(owner, TEST_REFERENCE, offset, payload, bytes,
			   TEST_FILETIME, &report) == NTFS_NO_MEMORY);
		assert(!report.execution.poisoned && report.execution.writes == 0 &&
		    report.execution.barriers == 0 && test->device.reader.memory == memory &&
		    memcmp(test->source, test->device.visible, test->bytes) == 0);
	}
	test->device.reader.fail_allocation = 0;
	assert(ntfs_write_existing_range(owner, TEST_REFERENCE, offset, payload, bytes,
		   TEST_FILETIME, &report) == NTFS_OK);
	assert(report.completed_bytes == bytes && report.requested_bytes == bytes &&
	    report.execution.completed && report.execution.commit_persisted &&
	    !report.execution.poisoned && test->device.reader.memory == memory);
	assert(memcmp(test->device.visible, test->expected, test->bytes) == 0 &&
	    memcmp(test->device.durable, test->expected, test->bytes) == 0);
	test->device.events = 0;
	test->device.writes = 0;
	test->device.barriers = 0;
	assert(ntfs_write_existing_range(owner, TEST_REFERENCE, offset, payload, bytes,
		   TEST_FILETIME + UINT64_C(230000000), &report) == NTFS_OK);
	assert(report.completed_bytes == bytes && report.execution.completed &&
	    test->device.reader.memory == memory &&
	    memcmp(test->device.visible, expected, test->bytes) == 0 &&
	    memcmp(test->device.durable, expected, test->bytes) == 0);
	ntfs_overwrite_close(owner);
	assert(test->device.reader.memory == 0 && !test->device.claimed);
	clear_io(test);
	owner = NULL;
	assert(ntfs_overwrite_open(&test->backend, admission, &owner) == NTFS_UNSUPPORTED &&
	    owner == NULL && !test->device.claimed && test->device.reader.memory == 0 &&
	    test->device.writes == 0);
	assert(ntfs_write_owner_open(&test->backend, admission, &recovered, &owner) == NTFS_OK);
	assert(recovered.completed && recovered.homes_persisted && recovered.writes == 0 &&
	    recovered.barriers == 1 && admission->quiescent && admission->persistence_succeeded &&
	    memcmp(test->device.visible, expected, test->bytes) == 0);
	ntfs_overwrite_close(owner);
	assert(test->device.reader.memory == 0 && !test->device.claimed);
	test->device.owned_writer = false;
	assert(claim(&test->device) == NTFS_OK);
	volume = mount(test);
	assert(ntfs_write_history_capture(volume, test->history_work, test->history) == NTFS_OK &&
	    test->history->transactions == 2 &&
	    ntfs_write_history_settled(volume, test->history) == NTFS_OK);
	assert(ntfs_unmount(volume) == NTFS_OK && test->device.reader.memory == 0);
	free(payload);
	free(expected);
	free(path);
	free(admission);
	puts("write owner: complete independent images after two appends; reservation "
	     "refusal/retry passed");
}

static uint64_t
number(const char *value, int base)
{
	char *end;
	unsigned long long parsed;

	errno = 0;
	parsed = strtoull(value, &end, base);
	assert(errno == 0 && end != value && *end == '\0' && value[0] != '-');
	return parsed;
}

struct image_fault_configuration {
	size_t write, prefix, barrier;
	const char *trace_directory;
};

static struct ntfs_image_fault *
image_fault_prepare(const char *path, const struct image_fault_configuration *configuration)
{
	struct ntfs_image_fault *fault = calloc(1, sizeof(*fault));
	int opened;

	assert(fault != NULL);
	opened = ntfs_image_fault_open(
	    path, configuration->write, configuration->prefix, configuration->barrier, fault);
	assert(opened == 0);
	return fault;
}

static void
image_fault_finish(struct ntfs_image_fault *fault, const char *directory)
{
	assert(ntfs_image_fault_dump(fault, directory) == 0);
	ntfs_image_fault_close(fault);
	free(fault);
}

static int
image_recover(const char *path, const struct image_fault_configuration *configuration)
{
	struct ntfs_overwrite_image image;
	struct ntfs_image_fault *fault = NULL;
	const struct ntfs_overwrite_environment *environment;
	struct ntfs_overwrite *owner = NULL;
	struct ntfs_overwrite_admission *admission = calloc(1, sizeof(*admission));
	struct ntfs_write_recovery_report report;
	int opened;
	enum ntfs_result result;

	assert(admission != NULL);
	if (configuration != NULL) {
		fault = image_fault_prepare(path, configuration);
		fault->enabled = true;
		environment = &fault->environment;
		opened = 0;
	} else {
		opened = ntfs_overwrite_image_open(path, &image);
		environment = &image.environment;
	}
	if (opened != 0) {
		fprintf(stderr, "Private recovery image open failed: %d\n", opened);
		free(admission);
		return 2;
	}
	result = ntfs_write_owner_open(environment, admission, &report, &owner);
	printf("{\"result\":%u,\"claimed\":%s,\"quiescent\":%s,\"initial_persistence\":%s,"
	       "\"writes\":%u,\"barriers\":%u,\"physical_bytes\":%llu,\"durable_stage\":%u,"
	       "\"reconstructed_files\":%u,\"compensation_persisted\":%s,\"homes_persisted\":%s,"
	       "\"completed\":%s,\"poisoned\":%s}\n",
	    result, admission->claimed ? "true" : "false", admission->quiescent ? "true" : "false",
	    admission->persistence_succeeded ? "true" : "false", report.writes, report.barriers,
	    (unsigned long long)report.physical_bytes, report.durable_stage,
	    report.reconstructed_files, report.compensation_persisted ? "true" : "false",
	    report.homes_persisted ? "true" : "false", report.completed ? "true" : "false",
	    report.poisoned ? "true" : "false");
	ntfs_overwrite_close(owner);
	if (fault != NULL) {
		image_fault_finish(fault, configuration->trace_directory);
	} else {
		ntfs_overwrite_image_close(&image);
	}
	free(admission);
	return result == NTFS_OK ? 0 : 1;
}

static int
image_range(const char *path, uint64_t reference, uint64_t offset, const char *payload_path,
    uint64_t filetime, bool retained_owner, const struct image_fault_configuration *configuration)
{
	struct ntfs_overwrite_image image;
	struct ntfs_image_fault *fault = NULL;
	const struct ntfs_overwrite_environment *environment;
	struct ntfs_overwrite *owner = NULL;
	struct ntfs_overwrite_admission *admission = calloc(1, sizeof(*admission));
	struct ntfs_write_range_report report = {0};
	struct ntfs_write_recovery_report recovered;
	FILE *file;
	uint8_t *payload;
	long length;
	int opened;
	enum ntfs_result result;

	assert(admission != NULL);
	file = fopen(payload_path, "rb");
	assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
	length = ftell(file);
	assert(length > 0 && length <= NTFS_OVERWRITE_MAX_BYTES && fseek(file, 0, SEEK_SET) == 0);
	payload = malloc((size_t)length);
	assert(payload != NULL && fread(payload, 1, (size_t)length, file) == (size_t)length);
	assert(fgetc(file) == EOF && !ferror(file) && fclose(file) == 0);
	if (configuration != NULL) {
		fault = image_fault_prepare(path, configuration);
		environment = &fault->environment;
		opened = 0;
	} else {
		opened = ntfs_overwrite_image_open(path, &image);
		environment = &image.environment;
	}
	assert(opened == 0);
	result = retained_owner ? ntfs_write_owner_open(environment, admission, &recovered, &owner)
				: ntfs_overwrite_open(environment, admission, &owner);
	if (result == NTFS_OK) {
		if (fault != NULL) {
			fault->enabled = true;
		}
		result = ntfs_write_existing_range(
		    owner, reference, offset, payload, (size_t)length, filetime, &report);
	}
	printf("{\"scope\":\"private-native-image-transaction-experiment\",\"result\":%u,"
	       "\"claimed\":%s,\"initially_quiet\":%s,\"initial_persistence\":%s,"
	       "\"requested_bytes\":%llu,\"completed_bytes\":%llu,\"writes\":%u,"
	       "\"barriers\":%u,\"physical_bytes\":%llu,\"durable_stage\":%u,"
	       "\"commit_persisted\":%s,\"completed\":%s,\"poisoned\":%s}\n",
	    result, admission->claimed ? "true" : "false", admission->quiescent ? "true" : "false",
	    admission->persistence_succeeded ? "true" : "false",
	    (unsigned long long)report.requested_bytes, (unsigned long long)report.completed_bytes,
	    report.execution.writes, report.execution.barriers,
	    (unsigned long long)report.execution.physical_bytes, report.execution.durable_stage,
	    report.execution.commit_persisted ? "true" : "false",
	    report.execution.completed ? "true" : "false",
	    report.execution.poisoned ? "true" : "false");
	ntfs_overwrite_close(owner);
	if (fault != NULL) {
		image_fault_finish(fault, configuration->trace_directory);
	} else {
		ntfs_overwrite_image_close(&image);
	}
	free(payload);
	free(admission);
	return result == NTFS_OK ? 0 : 1;
}

int
main(int argc, char **argv)
{
	struct test_case *test = calloc(1, sizeof(*test));
	struct image_fault_configuration configuration;

	assert(test != NULL);
	if (argc == 3 && strcmp(argv[1], "--recover") == 0) {
		free(test);
		return image_recover(argv[2], NULL);
	}
	if (argc == 7 && (strcmp(argv[1], "--image") == 0 || strcmp(argv[1], "--append") == 0)) {
		free(test);
		return image_range(argv[2], number(argv[3], 16), number(argv[4], 10), argv[5],
		    number(argv[6], 10), strcmp(argv[1], "--append") == 0, NULL);
	}
	if (argc == 11 && strcmp(argv[1], "--interrupt-image") == 0) {
		configuration.write = (size_t)number(argv[7], 10);
		configuration.prefix = (size_t)number(argv[8], 10);
		configuration.barrier = (size_t)number(argv[9], 10);
		configuration.trace_directory = argv[10];
		free(test);
		return image_range(argv[2], number(argv[3], 16), number(argv[4], 10), argv[5],
		    number(argv[6], 10), false, &configuration);
	}
	if (argc == 7 && strcmp(argv[1], "--interrupt-recover") == 0) {
		configuration.write = (size_t)number(argv[3], 10);
		configuration.prefix = (size_t)number(argv[4], 10);
		configuration.barrier = (size_t)number(argv[5], 10);
		configuration.trace_directory = argv[6];
		free(test);
		return image_recover(argv[2], &configuration);
	}
	assert(argc == 2);
	initialize(test, argv[1]);
	success(test);
	faults(test);
	recovery_interruptions(test, TEST_COMMIT_COPY_WRITE, 0);
	recovery_interruptions(test, TEST_FILE_HOME_WRITE, NTFS_WRITE_SECTOR_BYTES);
	recovery_unknown_lsn(test);
	refusals(test);
	owned_ranges(test, argv[1]);
	close_case(test);
	free(test);
	puts("write execution: complete independent image, ordering, poison, executed recovery "
	     "and repeated recovery passed");
	return 0;
}
