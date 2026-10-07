/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_history.h"
#include "write_overlay.h"
#include "fuzz_device.h"
#include <ntfs/validate.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { TEST_PATH_BYTES = 4096, TEST_NAME_BYTES = 128, TEST_PARTIAL_DIVISOR = 2 };

struct history_case {
	struct ntfs_write_history_workspace work;
	struct ntfs_write_history history;
};

static bool full_failed_read;

static uint8_t *
load(const char *directory, const char *name, size_t *bytes)
{
	char *path = malloc(TEST_PATH_BYTES);
	uint8_t *data;
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
	data = malloc(*bytes);
	assert(data != NULL && fread(data, 1, *bytes, file) == *bytes);
	assert(fgetc(file) == EOF && !ferror(file) && fclose(file) == 0);
	return data;
}

static enum ntfs_result
partial_read(void *context, uint64_t offset, void *buffer, size_t bytes)
{
	struct fuzz_device *device = context;

	if (device->fail_read != 0 && device->reads + 1 == device->fail_read) {
		assert(ntfs_bounds(offset, bytes, device->size));
		memcpy(buffer, device->data + offset,
		    full_failed_read ? bytes : bytes / TEST_PARTIAL_DIVISOR);
	}
	return fuzz_read(context, offset, buffer, bytes);
}

static struct ntfs_volume *
mount(struct fuzz_device *device)
{
	struct ntfs_environment environment = fuzz_environment(device);
	struct ntfs_limits limits;
	struct ntfs_volume *volume = NULL;

	environment.read = partial_read;
	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	device->reads = 0;
	device->allocations = 0;
	assert(ntfs_mount(&environment, &limits, &volume) == NTFS_OK);
	device->reads = 0;
	device->allocations = 0;
	return volume;
}

static void
zero_output(const struct ntfs_write_history *history)
{
	const uint8_t *bytes = (const void *)history;
	size_t index;

	for (index = 0; index < sizeof(*history); index++) {
		assert(bytes[index] == 0);
	}
}

static void
golden(const char *directory, const char *name, const void *actual, size_t length)
{
	uint8_t *expected;
	size_t bytes;

	expected = load(directory, name, &bytes);
	assert(bytes == length && memcmp(expected, actual, length) == 0);
	free(expected);
}

static void
oracle(const char *directory, const struct ntfs_write_history *history)
{
	const struct ntfs_write_file_plan *file = &history->replay.file;
	const char *packets[] = {"bootstrap.input", "checkpoint.input", "open.packet",
	    "snapshot.packet", "update.packet", "commit.packet"};
	size_t index,
	    count = history->count < sizeof(packets) / sizeof(*packets)
	    ? history->count
	    : sizeof(packets) / sizeof(*packets);

	for (index = 0; index < count; index++) {
		golden(directory, packets[index], history->packet[index], history->bytes[index]);
	}
	if (history->pending) {
		if (history->transactions == 1) {
			golden(directory, "before.expected", file->before, sizeof(file->before));
			golden(directory,
			    history->replay.committed ? "after.expected" : "before.expected",
			    file->after, sizeof(file->after));
			golden(directory,
			    history->replay.committed ? "protected.expected"
						      : "undo-protected.expected",
			    file->protected_after, sizeof(file->protected_after));
		} else {
			assert(history->transactions == 2);
			for (index = 0; index < history->count - count; index++) {
				golden(directory,
				    index == 0	     ? "followup-open.packet"
					: index == 1 ? "followup-snapshot.packet"
					: index == 2 ? "followup-update.packet"
						     : "followup-commit.packet",
				    history->packet[count + index], history->bytes[count + index]);
			}
			golden(directory, "followup-before.expected", file->before,
			    sizeof(file->before));
			golden(directory,
			    history->replay.committed ? "followup-after.expected"
						      : "followup-before.expected",
			    file->after, sizeof(file->after));
			golden(directory,
			    history->replay.committed ? "followup-protected.expected"
						      : "followup-undo-protected.expected",
			    file->protected_after, sizeof(file->protected_after));
		}
	}
}

static void
vectors(const char *directory, const char *goldens)
{
	struct history_case *test = calloc(1, sizeof(*test));
	struct ntfs_validation_report *validation = malloc(sizeof(*validation));
	struct fuzz_device device = {0};
	struct ntfs_environment environment;
	struct ntfs_limits limits;
	struct ntfs_volume *volume;
	struct ntfs_logfile *strict_source;
	struct ntfs_logfile_report strict_report;
	uint8_t *data, *original;
	char *path = malloc(TEST_PATH_BYTES), name[TEST_NAME_BYTES], file_name[TEST_NAME_BYTES];
	FILE *rows;
	unsigned count, pending, committed, checkpoint, profiles = 0;
	unsigned long long log_first, home;
	size_t bytes;
	int result, parsed;
	enum ntfs_result actual;

	assert(test != NULL && validation != NULL && path != NULL);
	parsed = snprintf(path, TEST_PATH_BYTES, "%s/cases.rows", directory);
	assert(parsed > 0 && parsed < TEST_PATH_BYTES);
	rows = fopen(path, "rb");
	assert(rows != NULL);
	while ((parsed = fscanf(rows, "%127s %d %u %u %u %u %llu %llu", name, &result, &count,
		    &pending, &committed, &checkpoint, &log_first, &home)) != EOF) {
		assert(parsed == 8);
		parsed = snprintf(file_name, sizeof(file_name), "%s.img", name);
		assert(parsed > 0 && (size_t)parsed < sizeof(file_name));
		data = load(directory, file_name, &bytes);
		original = malloc(bytes);
		assert(original != NULL);
		memcpy(original, data, bytes);
		device.data = data;
		device.size = bytes;
		volume = mount(&device);
		if (strncmp(name, "mixed-", strlen("mixed-")) == 0) {
			strict_source = NULL;
			assert(ntfs_logfile_open_volume(volume, NULL, &strict_report,
				   &strict_source) == NTFS_UNSUPPORTED);
			assert(strict_source == NULL &&
			    strict_report.selection == NTFS_LOGFILE_CONFLICT);
		}
		memset(&test->history, -1, sizeof(test->history));
		actual = ntfs_write_history_capture(volume, &test->work, &test->history);
		if (actual != (enum ntfs_result)result) {
			fprintf(stderr,
			    "%s: expected %d, got %d; checkpoint %u records, history %u/%u, "
			    "endpoint %llu tail %llu\n",
			    name, result, actual, test->work.checkpoint.acquired_records,
			    test->work.history.visited_records, test->work.history.examined_records,
			    (unsigned long long)test->work.history.candidate_end_lsn,
			    (unsigned long long)test->work.history.tail_lsn);
		}
		assert(actual == (enum ntfs_result)result);
		assert(volume->children == 0);
		assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
		if (result == NTFS_OK) {
			if (strncmp(name, "mixed-", strlen("mixed-")) == 0) {
				assert(test->work.discovery.selection == NTFS_LOGFILE_CONFLICT &&
				    test->history.selected.flags == 0 &&
				    !test->history.selected.clean_hint);
			}
			assert(test->history.count == count &&
			    test->history.pending == (pending != 0) &&
			    test->history.replay.committed == (committed != 0) &&
			    test->history.checkpoint_observed == (checkpoint != 0) &&
			    test->history.history.visited_records == count &&
			    test->history.history.complete && test->history.history.tail_lsn == 0);
			if (strcmp(name, "clean-published") != 0) {
				oracle(goldens, &test->history);
			}
			if (pending) {
				assert(test->history.replay.file.cluster_physical +
					test->history.replay.file.cluster_index *
					    NTFS_WRITE_SECTOR_BYTES ==
				    home);
				environment = fuzz_environment(&device);
				ntfs_default_limits(&limits);
				limits.record_cache_entries = 0;
				device.reads = 0;
				if (strstr(name, "torn") != NULL) {
					assert(ntfs_validate(&environment, &limits, NULL,
						   validation) == NTFS_CORRUPT);
				}
				device.reads = 0;
				assert(ntfs_write_validate_overlay(&environment,
					   &test->history.replay, validation) == NTFS_OK);
				assert(validation->unclaimed_clusters == 0 && device.memory == 0);
				assert(ntfs_write_validate_overlays(&environment,
					   test->history.transaction, test->history.transactions,
					   validation) == NTFS_OK);
				assert(validation->unclaimed_clusters == 0 && device.memory == 0);
			}
		} else {
			zero_output(&test->history);
		}
		assert(memcmp(data, original, bytes) == 0);
		free(original);
		free(data);
		profiles++;
	}
	assert(!ferror(rows) && fclose(rows) == 0 && profiles != 0);
	printf("PASS: %u complete history/refusal profiles; exact source-close packet/FILE "
	       "oracles and fresh whole-volume recovery overlays\n",
	    profiles);
	free(path);
	free(validation);
	free(test);
}

static void
overlay_refusal(const char *directory)
{
	struct history_case *test = calloc(1, sizeof(*test));
	struct ntfs_validation_report *report = malloc(sizeof(*report));
	struct fuzz_device device = {0};
	struct ntfs_environment environment;
	struct ntfs_volume *volume;
	uint8_t *data, *original;
	size_t bytes, reads;

	assert(test != NULL && report != NULL);
	data = load(directory, "overlay-free-data-allocation.img", &bytes);
	original = malloc(bytes);
	assert(original != NULL);
	memcpy(original, data, bytes);
	device.data = data;
	device.size = bytes;
	volume = mount(&device);
	assert(ntfs_write_history_capture(volume, &test->work, &test->history) == NTFS_OK);
	assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
	environment = fuzz_environment(&device);
	device.reads = 0;
	assert(ntfs_write_validate_overlay(&environment, &test->history.replay, report) ==
	    NTFS_CORRUPT);
	assert(device.memory == 0);
	reads = device.reads;
	test->history.replay.file.cluster_index++;
	assert(ntfs_write_validate_overlay(&environment, &test->history.replay, report) ==
	    NTFS_CORRUPT);
	assert(device.reads == reads && device.memory == 0);
	assert(memcmp(data, original, bytes) == 0);
	puts("PASS: reconstructed FILE cannot hide separate allocation damage; address refusal "
	     "before I/O");
	free(original);
	free(data);
	free(report);
	free(test);
}

static void
faults(const char *directory)
{
	struct history_case *test = calloc(1, sizeof(*test));
	struct fuzz_device device = {0};
	struct ntfs_volume *volume;
	uint8_t *data, *original;
	size_t bytes, reads, allocations, position, memory;
	unsigned mode;

	assert(test != NULL);
	data = load(directory, "committed-torn-home.img", &bytes);
	original = malloc(bytes);
	assert(original != NULL);
	memcpy(original, data, bytes);
	device.data = data;
	device.size = bytes;
	volume = mount(&device);
	assert(ntfs_write_history_capture(volume, &test->work, &test->history) == NTFS_OK);
	reads = device.reads;
	allocations = device.allocations;
	assert(reads != 0 && allocations != 0);
	assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
	for (mode = 0; mode < 3; mode++) {
		full_failed_read = mode == 2;
		for (position = 1; position <= (mode == 0 ? allocations : reads); position++) {
			volume = mount(&device);
			memory = device.memory;
			device.fail_allocation = mode == 0 ? position : 0;
			device.fail_read = mode == 0 ? 0 : position;
			memset(&test->history, -1, sizeof(test->history));
			assert(ntfs_write_history_capture(volume, &test->work, &test->history) ==
			    (mode == 0 ? NTFS_NO_MEMORY : NTFS_IO));
			zero_output(&test->history);
			assert(device.memory == memory && volume->children == 0);
			device.fail_allocation = 0;
			device.fail_read = 0;
			device.reads = 0;
			assert(ntfs_write_history_capture(volume, &test->work, &test->history) ==
			    NTFS_OK);
			assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
		}
	}
	assert(memcmp(data, original, bytes) == 0);
	printf("PASS: %zu acquisition allocation and %zu partial/full read faults; zero output, "
	       "source/child cleanup and complete retry\n",
	    allocations, reads);
	free(original);
	free(data);
	free(test);
}

int
main(int argc, char **argv)
{
	assert(argc == 3);
	vectors(argv[1], argv[2]);
	overlay_refusal(argv[1]);
	faults(argv[1]);
	return 0;
}
