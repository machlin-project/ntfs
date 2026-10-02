/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/logfile.h>
#include "fuzz_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_SOURCE_BYTES = 2 * 1024 * 1024,
	TEST_PATH_BYTES = 1024,
	TEST_GUARD_BYTES = 32,
	TEST_SENTINEL = 0xa5,
	TEST_PARTIAL_READ = 0x71,
	TEST_PARTIAL_DENOMINATOR = 2,
	TEST_LOGICAL_MIN_PAGE = 512,
	TEST_RESTART_PAGE_COUNT = 2,
	TEST_LFS_MAJOR_FAST = 2
};

static enum ntfs_result injected_read_result = NTFS_IO;

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
	assert(length > 0 && length <= TEST_SOURCE_BYTES && fseek(file, 0, SEEK_SET) == 0);
	bytes = malloc((size_t)length);
	assert(bytes != NULL && fread(bytes, 1, (size_t)length, file) == (size_t)length);
	assert(fclose(file) == 0);
	*size = (size_t)length;
	return bytes;
}

static enum ntfs_result
partial_read(void *context, uint64_t offset, void *bytes, size_t size)
{
	enum ntfs_result result = fuzz_read(context, offset, bytes, size);

	if (result == NTFS_IO) {
		memset(bytes, TEST_PARTIAL_READ, size / TEST_PARTIAL_DENOMINATOR);
		return injected_read_result;
	}
	return result;
}

static void
filled(const void *data, size_t size, unsigned value)
{
	const uint8_t *bytes = data;
	size_t i;

	for (i = 0; i < size; i++) {
		assert(bytes[i] == value);
	}
}

static void
check_page(struct ntfs_logfile *source, struct fuzz_device *device,
    const struct ntfs_logfile_restart *restart, const char *directory, const char *name, bool tail,
    enum ntfs_result expected_result)
{
	struct ntfs_logfile_page_view view, zero = {0};
	char filename[TEST_PATH_BYTES];
	uint8_t *guarded, *expected;
	size_t size, before_reads;
	uint64_t offset = tail ? (uint64_t)TEST_RESTART_PAGE_COUNT * restart->system_page_bytes
			       : restart->circular_offset;
	enum ntfs_logfile_storage storage = !tail   ? NTFS_LOGFILE_CIRCULAR
	    : restart->major == TEST_LFS_MAJOR_FAST ? NTFS_LOGFILE_FAST_STORAGE
						    : NTFS_LOGFILE_LEGACY_TAIL;

	assert(snprintf(filename, sizeof(filename), "%s.%s", name, tail ? "tail" : "page") > 0);
	expected = read_file(directory, filename, &size);
	assert(size == restart->log_page_bytes);
	guarded = malloc(size + TEST_GUARD_BYTES * 2);
	assert(guarded != NULL);
	memset(guarded, TEST_SENTINEL, size + TEST_GUARD_BYTES * 2);
	before_reads = device->reads;
	memset(&view, TEST_SENTINEL, sizeof(view));
	assert(ntfs_logfile_read_page(
		   source, offset, guarded + TEST_GUARD_BYTES, size - 1, &view) == NTFS_RANGE);
	assert(memcmp(&view, &zero, sizeof(view)) == 0 && device->reads == before_reads);
	assert(ntfs_logfile_read_page(
		   source, offset + 1, guarded + TEST_GUARD_BYTES, size, &view) == NTFS_INVALID);
	assert(memcmp(&view, &zero, sizeof(view)) == 0 && device->reads == before_reads);
	assert(ntfs_logfile_read_page(source, 0, guarded + TEST_GUARD_BYTES, size, &view) ==
	    NTFS_INVALID);
	assert(memcmp(&view, &zero, sizeof(view)) == 0 && device->reads == before_reads);
	assert(ntfs_logfile_read_page(source, restart->usable_bytes, guarded + TEST_GUARD_BYTES,
		   size, &view) == NTFS_INVALID);
	assert(memcmp(&view, &zero, sizeof(view)) == 0 && device->reads == before_reads);
	filled(guarded, size + TEST_GUARD_BYTES * 2, TEST_SENTINEL);
	device->fail_read = device->reads + 1;
	assert(ntfs_logfile_read_page(source, offset, guarded + TEST_GUARD_BYTES, size, &view) ==
	    NTFS_IO);
	assert(memcmp(&view, &zero, sizeof(view)) == 0);
	filled(guarded, size + TEST_GUARD_BYTES * 2, TEST_SENTINEL);
	device->fail_read = 0;
	assert(ntfs_logfile_read_page(source, offset, guarded + TEST_GUARD_BYTES, size, &view) ==
	    expected_result);
	if (expected_result == NTFS_OK) {
		assert(view.offset == offset && view.storage == storage);
		assert(memcmp(guarded + TEST_GUARD_BYTES, expected, size) == 0);
	} else {
		assert(memcmp(&view, &zero, sizeof(view)) == 0);
		filled(guarded + TEST_GUARD_BYTES, size, TEST_SENTINEL);
	}
	filled(guarded, TEST_GUARD_BYTES, TEST_SENTINEL);
	filled(guarded + TEST_GUARD_BYTES + size, TEST_GUARD_BYTES, TEST_SENTINEL);
	free(guarded);
	free(expected);
}

static void
check_faults(const uint8_t *bytes, size_t size, size_t allocations, size_t reads)
{
	struct fuzz_device device;
	struct ntfs_environment environment;
	struct ntfs_logfile_report report;
	struct ntfs_logfile *source;
	size_t i;

	for (i = 1; i <= allocations; i++) {
		device = (struct fuzz_device){.data = bytes, .size = size, .fail_allocation = i};
		environment = fuzz_environment(&device);
		assert(ntfs_logfile_open(&environment, NULL, &report, &source) == NTFS_NO_MEMORY);
		assert(source == NULL && device.memory == 0 && device.reads == 0 &&
		    !report.scan_complete && report.selected_probe == NTFS_LOGFILE_NO_PROBE);
	}
	for (i = 1; i <= reads; i++) {
		device = (struct fuzz_device){.data = bytes, .size = size, .fail_read = i};
		environment = fuzz_environment(&device);
		environment.read = partial_read;
		assert(ntfs_logfile_open(&environment, NULL, &report, &source) == NTFS_IO);
		assert(source == NULL && device.memory == 0 && report.read_calls == i &&
		    !report.scan_complete && report.selected_probe == NTFS_LOGFILE_NO_PROBE);
		device.fail_read = 0;
		assert(ntfs_logfile_open(&environment, NULL, &report, &source) == NTFS_OK);
		ntfs_logfile_close(source);
		assert(device.memory == 0);
	}
}

static void
check_limits(
    const uint8_t *bytes, size_t size, uint32_t reads, uint64_t read_bytes, uint32_t page_bytes)
{
	struct fuzz_device device = {.data = bytes, .size = size};
	struct ntfs_environment environment = fuzz_environment(&device);
	struct ntfs_logfile_limits limits;
	struct ntfs_logfile_report report;
	struct ntfs_logfile *source;

	ntfs_logfile_default_limits(&limits);
	limits.max_page_bytes = page_bytes;
	limits.max_read_calls = reads;
	limits.max_read_bytes = read_bytes;
	assert(ntfs_logfile_open(&environment, &limits, &report, &source) == NTFS_OK);
	assert(report.read_calls == reads && report.read_bytes == read_bytes);
	ntfs_logfile_close(source);
	limits.max_read_calls--;
	assert(ntfs_logfile_open(&environment, &limits, &report, &source) == NTFS_RANGE);
	assert(source == NULL && report.read_calls == limits.max_read_calls && device.memory == 0);
	limits.max_read_calls++;
	limits.max_read_bytes--;
	assert(ntfs_logfile_open(&environment, &limits, &report, &source) == NTFS_RANGE);
	assert(source == NULL && report.read_bytes <= limits.max_read_bytes && device.memory == 0);
	limits.max_read_bytes++;
	limits.max_page_bytes = TEST_LOGICAL_MIN_PAGE - 1;
	assert(ntfs_logfile_open(&environment, &limits, &report, &source) == NTFS_INVALID);
	limits.max_page_bytes = NTFS_LOGFILE_MAX_PAGE_BYTES * 2;
	assert(ntfs_logfile_open(&environment, &limits, &report, &source) == NTFS_INVALID);
	assert(source == NULL && device.memory == 0);
}

static void
check_backend_errors(const uint8_t *bytes, size_t size)
{
	const enum ntfs_result errors[] = {
	    NTFS_CORRUPT, NTFS_NOT_FOUND, NTFS_UNSUPPORTED, NTFS_RANGE, NTFS_INVALID, NTFS_IO};
	struct fuzz_device device;
	struct ntfs_environment environment;
	struct ntfs_logfile_report report;
	struct ntfs_logfile *source;
	size_t i;

	for (i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
		/* The first complete restart is valid before the second prefix fails. */
		device = (struct fuzz_device){
		    .data = bytes, .size = size, .fail_read = TEST_RESTART_PAGE_COUNT + 1};
		environment = fuzz_environment(&device);
		environment.read = partial_read;
		injected_read_result = errors[i];
		assert(ntfs_logfile_open(&environment, NULL, &report, &source) == errors[i]);
		assert(source == NULL && device.memory == 0 && !report.scan_complete &&
		    report.selected_probe == NTFS_LOGFILE_NO_PROBE &&
		    report.selection == NTFS_LOGFILE_UNSELECTED);
	}
	injected_read_result = NTFS_IO;
}

int
main(int argc, char **argv)
{
	struct fuzz_device device;
	struct ntfs_environment environment;
	struct ntfs_logfile_report report;
	struct ntfs_logfile_restart restart, zero_restart = {0};
	struct ntfs_logfile_client client, zero_client = {0};
	struct ntfs_logfile *source;
	struct ntfs_logfile_limits limits;
	FILE *cases;
	char path[TEST_PATH_BYTES], name[TEST_PATH_BYTES];
	uint8_t *bytes, *backup;
	size_t size, allocations, before_reads, count = 0;
	unsigned code, selection, system, log, reads, page_code;
	unsigned long long selected_offset, current_lsn, read_bytes;
	uint16_t index;

	assert(argc == 2 && snprintf(path, sizeof(path), "%s/cases.tsv", argv[1]) > 0);
	cases = fopen(path, "r");
	assert(cases != NULL);
	while (fscanf(cases, "%1023s %u %u %llu %llu %u %u %u %llu %u", name, &code, &selection,
		   &selected_offset, &current_lsn, &system, &log, &reads, &read_bytes,
		   &page_code) == 10) {
		bytes = read_file(argv[1], name, &size);
		backup = malloc(size);
		assert(backup != NULL);
		memcpy(backup, bytes, size);
		device = (struct fuzz_device){.data = bytes, .size = size};
		environment = fuzz_environment(&device);
		environment.read = partial_read;
		assert(ntfs_logfile_open(&environment, NULL, &report, &source) ==
		    (enum ntfs_result)code);
		assert(report.scan_complete && report.probe_count == NTFS_LOGFILE_RESTART_PROBES &&
		    report.selection == (enum ntfs_logfile_selection)selection &&
		    report.read_calls == reads && report.read_bytes == read_bytes);
		if (code == NTFS_OK) {
			assert(source != NULL && report.selected_probe < report.probe_count &&
			    report.probes[report.selected_probe].offset == selected_offset);
			assert(ntfs_logfile_get_restart(source, &restart) == NTFS_OK);
			assert(restart.current_lsn == current_lsn &&
			    restart.system_page_bytes == system && restart.log_page_bytes == log);
			allocations = device.allocations;
			before_reads = device.reads;
			device.fail_read = before_reads + 1;
			device.fail_allocation = allocations + 1;
			for (index = 0; index < restart.client_count; index++) {
				assert(ntfs_logfile_get_client(source, index, &client) == NTFS_OK);
			}
			assert(ntfs_logfile_get_client(source, restart.client_count, &client) ==
			    NTFS_END);
			assert(memcmp(&client, &zero_client, sizeof(client)) == 0 &&
			    device.allocations == allocations && device.reads == before_reads);
			device.fail_read = 0;
			device.fail_allocation = 0;
			check_page(source, &device, &restart, argv[1], name, false,
			    (enum ntfs_result)page_code);
			check_page(source, &device, &restart, argv[1], name, true, NTFS_OK);
			ntfs_logfile_close(source);
			if (strcmp(name, "equal.journal") == 0) {
				check_faults(bytes, size, allocations, before_reads);
				check_limits(bytes, size, reads, read_bytes, system);
				check_backend_errors(bytes, size);
			}
			if (strcmp(name, "larger-record-page.journal") == 0) {
				ntfs_logfile_default_limits(&limits);
				limits.max_page_bytes = system;
				assert(log > system &&
				    ntfs_logfile_open(&environment, &limits, &report, &source) ==
					NTFS_RANGE &&
				    source == NULL);
			}
		} else {
			assert(source == NULL && report.selected_probe == NTFS_LOGFILE_NO_PROBE);
		}
		assert(device.memory == 0 && memcmp(bytes, backup, size) == 0);
		free(backup);
		free(bytes);
		count++;
	}
	assert(feof(cases) && fclose(cases) == 0 && count > 0);
	assert(ntfs_logfile_get_restart(NULL, &restart) == NTFS_INVALID &&
	    memcmp(&restart, &zero_restart, sizeof(restart)) == 0);
	assert(ntfs_logfile_get_client(NULL, 0, &client) == NTFS_INVALID &&
	    memcmp(&client, &zero_client, sizeof(client)) == 0);
	ntfs_logfile_close(NULL);
	ntfs_logfile_default_limits(NULL);
	puts("PASS: bounded journal sources, copy conflicts, exact pages, allocation/read faults, "
	     "partial-read isolation and budgets; no recovery acceptance");
	printf("PASS: %zu independent journal source verdicts\n", count);
	return 0;
}
