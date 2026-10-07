/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_batch_recover.h"
#include "write_batch_history.h"
#include "write_history.h"
#include "write_batch_execute.h"
#include "write_program.h"
#include "fuzz_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_PATH_BYTES = 4096,
	TEST_NAME_BYTES = 128,
	TEST_REFUSED = -1,
	TEST_EMPTY_CHECKPOINT_PAGES = 1
};

#define TEST_FILETIME UINT64_C(134357146906613431)

static enum ntfs_result
space_read(void *context, uint64_t offset, void *bytes, size_t count)
{
	struct fuzz_device *device = context;

	assert(ntfs_bounds(offset, count, device->size));
	device->reads++;
	if (device->reads == device->fail_read) {
		return NTFS_IO;
	}
	memcpy(bytes, device->data + offset, count);
	return NTFS_OK;
}

static enum ntfs_result
write_refuse(void *context, uint64_t offset, const void *bytes, size_t count, size_t *actual)
{
	(void)context;
	(void)offset;
	(void)bytes;
	(void)count;
	(void)actual;
	assert(false);
	return NTFS_INVALID;
}

static enum ntfs_result
persist_refuse(void *context)
{
	(void)context;
	assert(false);
	return NTFS_INVALID;
}

static uint8_t *
load(const char *directory, const char *name, size_t *bytes)
{
	char path[TEST_PATH_BYTES];
	uint8_t *data;
	FILE *file;
	long length;
	int count;

	count = snprintf(path, sizeof(path), "%s/%s", directory, name);
	assert(count > 0 && (size_t)count < sizeof(path));
	file = fopen(path, "rb");
	assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
	length = ftell(file);
	assert(length > 0 && fseek(file, 0, SEEK_SET) == 0);
	*bytes = (size_t)length;
	data = malloc(*bytes);
	assert(data != NULL && fread(data, 1, *bytes, file) == *bytes);
	assert(fgetc(file) == EOF && !ferror(file) && fclose(file) == 0);
	return data;
}

static void
qualified_owner_refuses(struct fuzz_device *device)
{
	struct ntfs_write_history *history = malloc(sizeof(*history));
	struct ntfs_write_history_workspace *work = malloc(sizeof(*work));
	struct ntfs_environment reader = fuzz_environment(device);
	struct ntfs_volume *volume = NULL;
	struct ntfs_limits limits;

	assert(history != NULL && work != NULL);
	device->reads = device->allocations = 0;
	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	assert(ntfs_mount(&reader, &limits, &volume) == NTFS_OK);
	assert(ntfs_write_history_capture(volume, work, history) == NTFS_UNSUPPORTED);
	assert(volume->children == 0 && ntfs_unmount(volume) == NTFS_OK && device->memory == 0);
	free(work);
	free(history);
}

static void
space_profiles(const char *directory)
{
	static const uint16_t name_units[] = {'c', 'h', 'e', 'c', 'k', 'p', 'o', 'i', 'n', 't'};
	struct ntfs_write_mutation_request request = {.kind = NTFS_WRITE_CREATE_FILE,
	    .filetime = TEST_FILETIME,
	    .source = {0, name_units, sizeof(name_units) / sizeof(*name_units)}};
	struct ntfs_overwrite_environment backend = {0};
	struct ntfs_write_batch_history history;
	struct ntfs_write_batch_pages_input window = {0};
	struct ntfs_write_mutation_plan *plan;
	struct ntfs_write_program *program;
	struct ntfs_volume *volume;
	struct ntfs_node *root;
	struct ntfs_stat metadata;
	struct ntfs_write_batch_pages *pages;
	struct ntfs_write_batch_execution *execution;
	struct ntfs_logfile_update update;
	const struct ntfs_write_program_update *step;
	struct fuzz_device device = {0};
	uint8_t *data, *before;
	char path[TEST_PATH_BYTES], name[TEST_NAME_BYTES], image[TEST_NAME_BYTES];
	FILE *rows;
	size_t bytes, index, forward, undo, required, lcn_bytes, profiles = 0, refused = 0,
								 accepted = 0;
	unsigned free_pages, opens;
	int parsed;
	enum ntfs_result result, expected;

	parsed = snprintf(path, sizeof(path), "%s/space.rows", directory);
	assert(parsed > 0 && (size_t)parsed < sizeof(path));
	rows = fopen(path, "rb");
	assert(rows != NULL);
	while ((parsed = fscanf(rows, "%127s %u %u", name, &free_pages, &opens)) != EOF) {
		assert(parsed == 3 && opens != 0);
		parsed = snprintf(image, sizeof(image), "%s.img", name);
		assert(parsed > 0 && (size_t)parsed < sizeof(image));
		data = load(directory, image, &bytes);
		before = malloc(bytes);
		assert(before != NULL);
		memcpy(before, data, bytes);
		device = (struct fuzz_device){.data = data, .size = bytes};
		backend.reader = fuzz_environment(&device);
		backend.reader.read = space_read;
		backend.api_version = NTFS_OVERWRITE_API_VERSION;
		backend.alignment = NTFS_WRITE_SECTOR_BYTES;
		backend.write = write_refuse;
		backend.persist = persist_refuse;
		plan = NULL;
		program = NULL;
		pages = NULL;
		execution = NULL;
		volume = NULL;
		root = NULL;
		assert(ntfs_mount(&backend.reader, NULL, &volume) == NTFS_OK);
		assert(ntfs_root(volume, &root) == NTFS_OK &&
		    ntfs_node_stat(root, &metadata) == NTFS_OK);
		request.source.parent_reference = metadata.reference;
		ntfs_node_close(root);
		assert(ntfs_unmount(volume) == NTFS_OK);
		result = ntfs_write_mutation_prepare(&backend.reader, &request, &plan);
		if (result != NTFS_OK) {
			fprintf(stderr, "%s: mutation preparation: %s\n", name,
			    ntfs_result_string(result));
		}
		assert(result == NTFS_OK);
		assert(ntfs_write_program_prepare(&backend.reader, plan, &program) == NTFS_OK);
		ntfs_write_mutation_plan_close(plan);
		result = ntfs_write_batch_history_prepare(&backend.reader, &history);
		if (result != NTFS_OK) {
			fprintf(stderr, "%s: retained history preparation: %s\n", name,
			    ntfs_result_string(result));
		}
		assert(result == NTFS_OK);
		window.restart = history.origin;
		window.floor_lsn = history.client.oldest_lsn;
		window.tail_lsn = history.history.completed_end_lsn;
		window.next_lsn = history.history.next_lsn;
		result = ntfs_write_program_pages_prepare(
		    &backend.reader, program, &history.client, &window, &pages);
		if (result == NTFS_NO_SPACE) {
			ntfs_write_program_close(program);
			assert(device.memory == 0 && memcmp(data, before, bytes) == 0);
			free(before);
			free(data);
			continue;
		}
		assert(result == NTFS_OK && pages != NULL);
		forward = ntfs_write_batch_pages_count(pages);
		undo = 0;
		for (index = 0; index < ntfs_write_program_count(program); index++) {
			step = ntfs_write_program_get(program, index);
			assert(step != NULL &&
			    ntfs_logfile_update_decode(
				step->payload.data, step->payload.bytes, &update) == NTFS_OK);
			/* Each independently measured inverse starts in a fresh data page.
			 * The terminal Forget replaces the forward Forget; one additional
			 * page remains for the subsequent empty checkpoint in either state. */
			lcn_bytes = update.lcns.length > sizeof(uint64_t) ? update.lcns.length
									  : sizeof(uint64_t);
			undo += (sizeof(struct ntfs_disk_log_record) +
				    sizeof(struct ntfs_disk_log_update) + lcn_bytes +
				    update.undo.length + NTFS_WRITE_CLUSTER_BYTES -
				    NTFS_WRITE_LOG_DATA_OFFSET - 1u) /
			    (NTFS_WRITE_CLUSTER_BYTES - NTFS_WRITE_LOG_DATA_OFFSET);
		}
		required = forward + undo + TEST_EMPTY_CHECKPOINT_PAGES;
		expected = free_pages < required ? NTFS_NO_SPACE : NTFS_OK;
		ntfs_write_batch_pages_close(pages);
		result = ntfs_write_batch_execute_prepare(&backend, program, &execution);
		if (result != expected) {
			fprintf(stderr,
			    "%s: free %u pages, forward %zu, inverses %zu, checkpoint 1; "
			    "expected %s, actual %s\n",
			    name, free_pages, forward, undo, ntfs_result_string(expected),
			    ntfs_result_string(result));
		}
		assert(result == expected);
		if (expected == NTFS_NO_SPACE) {
			assert(execution == NULL);
			refused++;
		} else {
			assert(execution != NULL);
			accepted++;
		}
		ntfs_write_batch_execution_close(execution);
		ntfs_write_program_close(program);
		assert(device.memory == 0 && memcmp(data, before, bytes) == 0);
		free(before);
		free(data);
		profiles++;
	}
	assert(fclose(rows) == 0 && refused != 0 && accepted != 0);
	printf("PASS: %zu complete recovery/checkpoint space profiles, %zu refused and "
	       "%zu admitted before writes\n",
	    profiles, refused, accepted);
}

static void
origin_profiles(const char *directory)
{
	struct ntfs_write_batch_recovery *owner;
	struct ntfs_write_batch_history history;
	struct ntfs_overwrite_environment backend = {0};
	struct fuzz_device device = {0};
	uint8_t *data, *before;
	char path[TEST_PATH_BYTES], name[TEST_NAME_BYTES], image[TEST_NAME_BYTES];
	FILE *rows;
	size_t bytes, profiles = 0, accepted = 0, refused = 0;
	unsigned publications;
	unsigned long long analysis_lsn, checkpoint_lsn;
	int expected, expected_history, parsed;
	enum ntfs_result result;

	parsed = snprintf(path, sizeof(path), "%s/cases.rows", directory);
	assert(parsed > 0 && (size_t)parsed < sizeof(path));
	rows = fopen(path, "rb");
	assert(rows != NULL);
	while ((parsed = fscanf(rows, "%127s %d %u %llu %llu %d", name, &expected, &publications,
		    &analysis_lsn, &checkpoint_lsn, &expected_history)) != EOF) {
		assert(parsed == 6);
		parsed = snprintf(image, sizeof(image), "%s.img", name);
		assert(parsed > 0 && (size_t)parsed < sizeof(image));
		data = load(directory, image, &bytes);
		before = malloc(bytes);
		assert(before != NULL);
		memcpy(before, data, bytes);
		device = (struct fuzz_device){.data = data, .size = bytes};
		backend.reader = fuzz_environment(&device);
		backend.api_version = NTFS_OVERWRITE_API_VERSION;
		backend.alignment = NTFS_WRITE_SECTOR_BYTES;
		backend.write = write_refuse;
		backend.persist = persist_refuse;
		owner = NULL;
		result = ntfs_write_batch_recover_prepare(&backend, &owner);
		if ((expected == TEST_REFUSED && result == NTFS_OK) ||
		    (expected != TEST_REFUSED && result != (enum ntfs_result)expected)) {
			fprintf(stderr, "%s: expected %d, actual %s (%d)\n", name, expected,
			    ntfs_result_string(result), result);
		}
		if (expected == TEST_REFUSED) {
			assert(result != NTFS_OK && owner == NULL);
			refused++;
		} else {
			assert(result == (enum ntfs_result)expected && owner != NULL);
			assert(ntfs_write_batch_recovery_count(owner) == publications);
			accepted++;
		}
		ntfs_write_batch_recovery_close(owner);
		assert(device.memory == 0 && memcmp(data, before, bytes) == 0);
		if (expected != TEST_REFUSED) {
			device.reads = device.allocations = 0;
			memset(&history, -1, sizeof(history));
			result = ntfs_write_batch_history_prepare(&backend.reader, &history);
			assert(result == (enum ntfs_result)expected_history);
			if (result == NTFS_OK) {
				assert(history.client.oldest_lsn == analysis_lsn &&
				    history.client.restart_lsn == checkpoint_lsn &&
				    history.selected.current_lsn == checkpoint_lsn &&
				    history.history.completed_end_lsn == checkpoint_lsn &&
				    history.history.visited_records == 2 &&
				    history.history.complete && history.history.endpoint_verified &&
				    history.history.tail_lsn == 0);
				qualified_owner_refuses(&device);
			}
			assert(device.memory == 0 && memcmp(data, before, bytes) == 0);
		}
		free(before);
		free(data);
		profiles++;
	}
	assert(fclose(rows) == 0 && accepted == 8 && refused != 0);
	printf("PASS: %zu independent checkpoint origins (%zu accepted, %zu refused), "
	       "unchanged media and zero write/persistence callbacks\n",
	    profiles, accepted, refused);
}

int
main(int argc, char **argv)
{
	assert(argc == 2 || argc == 3);
	if (argc == 3) {
		assert(strcmp(argv[2], "space") == 0);
		space_profiles(argv[1]);
	} else {
		origin_profiles(argv[1]);
	}
	return 0;
}
