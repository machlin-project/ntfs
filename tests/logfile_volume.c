/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/logfile.h>
#include "fuzz_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_IMAGE_BYTES = 8 * 1024 * 1024,
	TEST_PATH_BYTES = 1024,
	TEST_GUARD_BYTES = 32,
	TEST_SENTINEL = 0xa5,
	TEST_PARTIAL_READ = 0x71,
	TEST_PARTIAL_DENOMINATOR = 2,
	TEST_LOGICAL_MIN_PAGE = 512,
	TEST_RESTART_PAGE_COUNT = 2,
	TEST_LFS_MAJOR_FAST = 2
};

struct source_expectation {
	unsigned code, selection, system, log, reads, page_code;
	unsigned long long selected_offset, current_lsn, read_bytes;
};

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
	assert(length > 0 && length <= TEST_IMAGE_BYTES && fseek(file, 0, SEEK_SET) == 0);
	bytes = malloc((size_t)length);
	assert(bytes != NULL && fread(bytes, 1, (size_t)length, file) == (size_t)length);
	assert(fclose(file) == 0);
	*size = (size_t)length;
	return bytes;
}

static struct source_expectation
source_expectation(const char *directory, const char *name)
{
	struct source_expectation expected;
	char path[TEST_PATH_BYTES], candidate[TEST_PATH_BYTES];
	FILE *file;
	bool found = false;

	assert(snprintf(path, sizeof(path), "%s/cases.tsv", directory) > 0);
	file = fopen(path, "r");
	assert(file != NULL);
	while (fscanf(file, "%1023s %u %u %llu %llu %u %u %u %llu %u", candidate, &expected.code,
		   &expected.selection, &expected.selected_offset, &expected.current_lsn,
		   &expected.system, &expected.log, &expected.reads, &expected.read_bytes,
		   &expected.page_code) == 10) {
		if (strcmp(candidate, name) == 0) {
			found = true;
			break;
		}
	}
	assert(fclose(file) == 0 && found);
	return expected;
}

static enum ntfs_result
partial_read(void *context, uint64_t offset, void *bytes, size_t size)
{
	enum ntfs_result result = fuzz_read(context, offset, bytes, size);

	if (result == NTFS_IO) {
		memset(bytes, TEST_PARTIAL_READ, size / TEST_PARTIAL_DENOMINATOR);
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

static struct ntfs_volume *
mount_volume(struct fuzz_device *device)
{
	struct ntfs_environment environment = fuzz_environment(device);
	struct ntfs_limits limits;
	struct ntfs_volume *volume;

	environment.read = partial_read;
	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	assert(ntfs_mount(&environment, &limits, &volume) == NTFS_OK);
	return volume;
}

static void
check_page(struct ntfs_logfile *source, struct fuzz_device *device,
    const struct ntfs_logfile_restart *restart, const char *directory, const char *name, bool tail)
{
	struct ntfs_logfile_page_view view, zero = {0};
	char filename[TEST_PATH_BYTES];
	uint8_t *guarded, *expected;
	size_t size, reads;
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
	memset(&view, TEST_SENTINEL, sizeof(view));
	reads = device->reads;
	assert(ntfs_logfile_read_page(
		   source, offset, guarded + TEST_GUARD_BYTES, size - 1, &view) == NTFS_RANGE);
	assert(memcmp(&view, &zero, sizeof(view)) == 0 && device->reads == reads);
	filled(guarded, size + TEST_GUARD_BYTES * 2, TEST_SENTINEL);
	device->fail_read = device->reads + 1;
	assert(ntfs_logfile_read_page(source, offset, guarded + TEST_GUARD_BYTES, size, &view) ==
	    NTFS_IO);
	assert(memcmp(&view, &zero, sizeof(view)) == 0);
	filled(guarded, size + TEST_GUARD_BYTES * 2, TEST_SENTINEL);
	device->fail_read = 0;
	assert(ntfs_logfile_read_page(source, offset, guarded + TEST_GUARD_BYTES, size, &view) ==
	    NTFS_OK);
	assert(view.offset == offset && view.storage == storage);
	assert(memcmp(guarded + TEST_GUARD_BYTES, expected, size) == 0);
	filled(guarded, TEST_GUARD_BYTES, TEST_SENTINEL);
	filled(guarded + TEST_GUARD_BYTES + size, TEST_GUARD_BYTES, TEST_SENTINEL);
	free(guarded);
	free(expected);
}

static void
check_record(struct ntfs_logfile *source, struct fuzz_device *device,
    const struct ntfs_logfile_restart *restart, const char *directory, const char *name)
{
	struct ntfs_logfile_record_view view, zero = {0};
	char filename[TEST_PATH_BYTES];
	uint8_t *guarded, *expected;
	size_t size, memory = device->memory;

	assert(snprintf(filename, sizeof(filename), "%s.record", name) > 0);
	expected = read_file(directory, filename, &size);
	guarded = malloc(size + TEST_GUARD_BYTES * 2);
	assert(guarded != NULL);
	memset(guarded, TEST_SENTINEL, size + TEST_GUARD_BYTES * 2);
	device->fail_read = device->reads + 1;
	assert(ntfs_logfile_read_circular_record(source, restart->current_lsn,
		   guarded + TEST_GUARD_BYTES, size, &view) == NTFS_IO);
	assert(memcmp(&view, &zero, sizeof(view)) == 0 && device->memory == memory);
	filled(guarded, size + TEST_GUARD_BYTES * 2, TEST_SENTINEL);
	device->fail_read = 0;
	device->fail_allocation = device->allocations + 1;
	assert(ntfs_logfile_read_circular_record(source, restart->current_lsn,
		   guarded + TEST_GUARD_BYTES, size, &view) == NTFS_NO_MEMORY);
	assert(memcmp(&view, &zero, sizeof(view)) == 0 && device->memory == memory);
	filled(guarded, size + TEST_GUARD_BYTES * 2, TEST_SENTINEL);
	device->fail_allocation = 0;
	assert(ntfs_logfile_read_circular_record(source, restart->current_lsn,
		   guarded + TEST_GUARD_BYTES, size, &view) == NTFS_OK);
	assert(view.bytes == size && view.pages_read == 1 && view.read_calls == 1 &&
	    view.read_bytes == restart->log_page_bytes && view.record.lsn == restart->current_lsn &&
	    device->memory == memory);
	assert(memcmp(guarded + TEST_GUARD_BYTES, expected, size) == 0);
	filled(guarded, TEST_GUARD_BYTES, TEST_SENTINEL);
	filled(guarded + TEST_GUARD_BYTES + size, TEST_GUARD_BYTES, TEST_SENTINEL);
	free(guarded);
	free(expected);
}

static void
check_faults(const uint8_t *bytes, size_t size, const char *name, size_t *allocation_faults,
    size_t *read_faults)
{
	struct fuzz_device device = {.data = bytes, .size = size};
	struct ntfs_volume *volume = mount_volume(&device);
	struct ntfs_logfile *source;
	struct ntfs_logfile_report report;
	size_t memory = device.memory, allocations = device.allocations, reads = device.reads;
	size_t i;

	assert(ntfs_logfile_open_volume(volume, NULL, &report, &source) == NTFS_OK);
	allocations = device.allocations - allocations;
	reads = device.reads - reads;
	ntfs_logfile_close(source);
	assert(device.memory == memory && ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
	for (i = 1; i <= allocations; i++) {
		device = (struct fuzz_device){.data = bytes, .size = size};
		volume = mount_volume(&device);
		memory = device.memory;
		device.fail_allocation = device.allocations + i;
		assert(ntfs_logfile_open_volume(volume, NULL, &report, &source) == NTFS_NO_MEMORY);
		assert(source == NULL && device.memory == memory &&
		    report.selected_probe == NTFS_LOGFILE_NO_PROBE && !report.scan_complete);
		device.fail_allocation = 0;
		assert(ntfs_logfile_open_volume(volume, NULL, NULL, &source) == NTFS_OK);
		ntfs_logfile_close(source);
		assert(device.memory == memory && ntfs_unmount(volume) == NTFS_OK &&
		    device.memory == 0);
	}
	for (i = 1; i <= reads; i++) {
		device = (struct fuzz_device){.data = bytes, .size = size};
		volume = mount_volume(&device);
		memory = device.memory;
		device.fail_read = device.reads + i;
		assert(ntfs_logfile_open_volume(volume, NULL, &report, &source) == NTFS_IO);
		assert(source == NULL && device.memory == memory &&
		    report.selected_probe == NTFS_LOGFILE_NO_PROBE && !report.scan_complete);
		device.fail_read = 0;
		assert(ntfs_logfile_open_volume(volume, NULL, &report, &source) == NTFS_OK);
		ntfs_logfile_close(source);
		assert(device.memory == memory && ntfs_unmount(volume) == NTFS_OK &&
		    device.memory == 0);
	}
	*allocation_faults += allocations;
	*read_faults += reads;
	printf("PASS: %s: %zu binding allocation and %zu physical read faults with retry\n", name,
	    allocations, reads);
}

static void
check_limits(struct ntfs_volume *volume, struct fuzz_device *device,
    const struct source_expectation *expected)
{
	struct ntfs_logfile_limits limits;
	struct ntfs_logfile_report report, empty = {0};
	struct ntfs_logfile *source, *other;
	size_t memory = device->memory, reads = device->reads, allocations = device->allocations;

	empty.selected_probe = NTFS_LOGFILE_NO_PROBE;
	ntfs_logfile_default_limits(&limits);
	limits.max_page_bytes = TEST_LOGICAL_MIN_PAGE - 1;
	assert(ntfs_logfile_open_volume(volume, &limits, &report, &source) == NTFS_INVALID);
	assert(source == NULL && memcmp(&report, &empty, sizeof(report)) == 0);
	assert(ntfs_logfile_open_volume(NULL, NULL, &report, &source) == NTFS_INVALID);
	assert(source == NULL && memcmp(&report, &empty, sizeof(report)) == 0);
	assert(ntfs_logfile_open_volume(volume, NULL, &report, NULL) == NTFS_INVALID);
	assert(memcmp(&report, &empty, sizeof(report)) == 0 && device->reads == reads &&
	    device->allocations == allocations && device->memory == memory);
	ntfs_logfile_default_limits(&limits);
	limits.max_page_bytes = expected->system;
	limits.max_read_calls = expected->reads;
	limits.max_read_bytes = expected->read_bytes;
	assert(ntfs_logfile_open_volume(volume, &limits, &report, &source) == NTFS_OK);
	assert(report.read_calls == limits.max_read_calls &&
	    report.read_bytes == limits.max_read_bytes);
	assert(ntfs_logfile_open_volume(volume, &limits, NULL, &other) == NTFS_OK);
	ntfs_logfile_close(source);
	assert(ntfs_unmount(volume) == NTFS_BUSY);
	ntfs_logfile_close(other);
	assert(device->memory == memory);
	limits.max_read_calls--;
	assert(ntfs_logfile_open_volume(volume, &limits, &report, &source) == NTFS_RANGE &&
	    source == NULL && report.read_calls == limits.max_read_calls &&
	    device->memory == memory);
	limits.max_read_calls++;
	limits.max_read_bytes--;
	assert(ntfs_logfile_open_volume(volume, &limits, &report, &source) == NTFS_RANGE &&
	    source == NULL && report.read_bytes <= limits.max_read_bytes &&
	    device->memory == memory);
}

int
main(int argc, char **argv)
{
	struct fuzz_device device;
	struct ntfs_volume *volume;
	struct ntfs_logfile *source;
	struct ntfs_logfile_report report, empty = {0};
	struct ntfs_logfile_restart restart;
	struct ntfs_logfile_client client, active_client, zero_client = {0};
	struct source_expectation expected;
	FILE *cases;
	char path[TEST_PATH_BYTES], name[TEST_PATH_BYTES], source_name[TEST_PATH_BYTES];
	uint8_t *bytes, *backup;
	size_t size, memory, reads, allocations, count = 0, allocation_faults = 0, read_faults = 0;
	unsigned code;
	uint16_t index;
	enum ntfs_result result;

	assert(argc == 3 && snprintf(path, sizeof(path), "%s/cases.tsv", argv[1]) > 0);
	empty.selected_probe = NTFS_LOGFILE_NO_PROBE;
	cases = fopen(path, "r");
	assert(cases != NULL);
	while (fscanf(cases, "%1023s %u %1023s", name, &code, source_name) == 3) {
		bytes = read_file(argv[1], name, &size);
		backup = malloc(size);
		assert(backup != NULL);
		memcpy(backup, bytes, size);
		device = (struct fuzz_device){.data = bytes, .size = size};
		volume = mount_volume(&device);
		memory = device.memory;
		result = ntfs_logfile_open_volume(volume, NULL, &report, &source);
		if (result != (enum ntfs_result)code) {
			fprintf(stderr, "%s: binding returned %s, expected %s\n", name,
			    ntfs_result_string(result), ntfs_result_string((enum ntfs_result)code));
		}
		assert(result == (enum ntfs_result)code);
		if (code == NTFS_OK) {
			expected = source_expectation(argv[2], source_name);
			assert(source != NULL && ntfs_unmount(volume) == NTFS_BUSY &&
			    report.scan_complete && report.selected_probe < report.probe_count &&
			    report.selection == (enum ntfs_logfile_selection)expected.selection &&
			    report.probes[report.selected_probe].offset ==
				expected.selected_offset &&
			    report.read_calls == expected.reads &&
			    report.read_bytes == expected.read_bytes);
			reads = device.reads;
			allocations = device.allocations;
			device.fail_read = reads + 1;
			device.fail_allocation = allocations + 1;
			assert(ntfs_logfile_get_restart(source, &restart) == NTFS_OK &&
			    restart.current_lsn == expected.current_lsn &&
			    restart.system_page_bytes == expected.system &&
			    restart.log_page_bytes == expected.log);
			for (index = 0; index < restart.client_count; index++) {
				assert(ntfs_logfile_get_client(source, index, &client) == NTFS_OK);
				assert(ntfs_logfile_get_active_client(source, index,
					   client.sequence, &active_client) == NTFS_OK &&
				    memcmp(&active_client, &client, sizeof(client)) == 0);
				assert(ntfs_logfile_get_active_client(source, index,
					   (uint16_t)(client.sequence + 1u),
					   &active_client) == NTFS_STALE &&
				    memcmp(&active_client, &zero_client, sizeof(active_client)) ==
					0);
			}
			assert(ntfs_logfile_get_client(source, restart.client_count, &client) ==
			    NTFS_END);
			assert(memcmp(&client, &zero_client, sizeof(client)) == 0 &&
			    device.reads == reads && device.allocations == allocations);
			device.fail_read = 0;
			device.fail_allocation = 0;
			check_page(source, &device, &restart, argv[2], source_name, false);
			check_page(source, &device, &restart, argv[2], source_name, true);
			check_record(source, &device, &restart, argv[2], source_name);
			ntfs_logfile_close(source);
			if (strcmp(name, "contiguous.img") == 0) {
				check_limits(volume, &device, &expected);
			}
		} else {
			assert(source == NULL && report.selected_probe == NTFS_LOGFILE_NO_PROBE);
			if (strcmp(name, "conflicting-copies.img") == 0) {
				assert(report.scan_complete &&
				    report.selection == NTFS_LOGFILE_CONFLICT);
			} else {
				assert(memcmp(&report, &empty, sizeof(report)) == 0);
			}
		}
		assert(device.memory == memory && ntfs_unmount(volume) == NTFS_OK &&
		    device.memory == 0 && memcmp(bytes, backup, size) == 0);
		if (strcmp(name, "contiguous.img") == 0 || strcmp(name, "fragmented.img") == 0 ||
		    strcmp(name, "listed.img") == 0 || strcmp(name, "nonresident-list.img") == 0 ||
		    strcmp(name, "maximum-page.img") == 0) {
			check_faults(bytes, size, name, &allocation_faults, &read_faults);
		}
		assert(memcmp(bytes, backup, size) == 0);
		free(backup);
		free(bytes);
		count++;
	}
	assert(feof(cases) && fclose(cases) == 0 && count > 0);
	printf("PASS: %zu independent volume journal verdicts, %zu allocation/%zu physical read "
	       "binding faults, exact fragmented pages/records and counted unmount lifetime; "
	       "no recovery acceptance\n",
	    count, allocation_faults, read_faults);
	return 0;
}
