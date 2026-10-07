/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_checkpoint.h"
#include "write_batch_history.h"
#include "write_batch_recover.h"
#include "fuzz_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_PATH_BYTES = 4096,
	TEST_NAME_BYTES = 128,
	TEST_PUBLICATIONS = 8,
	TEST_BARRIERS = TEST_PUBLICATIONS + 1
};

static const enum ntfs_write_checkpoint_stage publication_stages[TEST_PUBLICATIONS] = {
    NTFS_WRITE_CHECKPOINT_OLD_FIRST, NTFS_WRITE_CHECKPOINT_OLD_SECOND, NTFS_WRITE_CHECKPOINT_COPY,
    NTFS_WRITE_CHECKPOINT_HOME, NTFS_WRITE_CHECKPOINT_ADVANCED_FIRST,
    NTFS_WRITE_CHECKPOINT_ADVANCED_SECOND, NTFS_WRITE_CHECKPOINT_CLEAN_FIRST,
    NTFS_WRITE_CHECKPOINT_CLEAN_SECOND};

struct checkpoint_device {
	struct fuzz_device fuzz;
	uint8_t *image;
	size_t writes, barriers;
	bool executing;
};

static enum ntfs_result
checkpoint_read(void *context, uint64_t physical, void *memory, size_t bytes)
{
	struct checkpoint_device *device = context;

	assert(!device->executing && ntfs_bounds(physical, bytes, device->fuzz.size));
	device->fuzz.reads++;
	if (device->fuzz.reads == device->fuzz.fail_read) {
		return NTFS_IO;
	}
	memcpy(memory, device->image + physical, bytes);
	return NTFS_OK;
}

static enum ntfs_result
checkpoint_write(void *context, uint64_t physical, const void *memory, size_t bytes, size_t *actual)
{
	struct checkpoint_device *device = context;

	assert(device->executing && device->barriers == device->writes + 1 &&
	    bytes == NTFS_WRITE_CLUSTER_BYTES && ntfs_bounds(physical, bytes, device->fuzz.size));
	device->writes++;
	memcpy(device->image + physical, memory, bytes);
	*actual = bytes;
	return NTFS_OK;
}

static enum ntfs_result
checkpoint_persist(void *context)
{
	struct checkpoint_device *device = context;

	assert(device->executing && device->barriers == device->writes);
	device->barriers++;
	return NTFS_OK;
}

static uint8_t *
load(const char *directory, const char *name, size_t *bytes)
{
	char path[TEST_PATH_BYTES];
	FILE *file;
	uint8_t *data;
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
preparation_faults(struct checkpoint_device *device,
    const struct ntfs_overwrite_environment *backend, struct ntfs_write_checkpoint *baseline,
    const uint8_t *source, size_t bytes)
{
	struct ntfs_write_checkpoint *owner;
	const struct ntfs_write_checkpoint_publication *publication;
	uint8_t *expected;
	size_t reads = device->fuzz.reads, allocations = device->fuzz.allocations;
	size_t mode, failure, index, limit, refused = 0, redundant_reads = 0;
	enum ntfs_result result;

	expected = malloc(TEST_PUBLICATIONS * NTFS_WRITE_CLUSTER_BYTES);
	assert(expected != NULL);
	for (index = 0; index < TEST_PUBLICATIONS; index++) {
		publication = ntfs_write_checkpoint_get(baseline, index);
		memcpy(expected + index * NTFS_WRITE_CLUSTER_BYTES, publication->image,
		    NTFS_WRITE_CLUSTER_BYTES);
	}
	ntfs_write_checkpoint_close(baseline);
	assert(device->fuzz.memory == 0);
	for (mode = 0; mode < 2; mode++) {
		limit = mode == 0 ? allocations : reads;
		for (failure = 1; failure <= limit; failure++) {
			device->fuzz.reads = device->fuzz.allocations = 0;
			device->fuzz.fail_allocation = mode == 0 ? failure : 0;
			device->fuzz.fail_read = mode == 1 ? failure : 0;
			owner = NULL;
			result = ntfs_write_checkpoint_prepare(backend, &owner);
			if (result != NTFS_OK) {
				assert(owner == NULL &&
				    result == (mode == 0 ? NTFS_NO_MEMORY : NTFS_IO));
				refused++;
			} else {
				assert(mode == 1 && owner != NULL);
				redundant_reads++;
				for (index = 0; index < TEST_PUBLICATIONS; index++) {
					publication = ntfs_write_checkpoint_get(owner, index);
					assert(
					    memcmp(expected + index * NTFS_WRITE_CLUSTER_BYTES,
						publication->image, NTFS_WRITE_CLUSTER_BYTES) == 0);
				}
			}
			ntfs_write_checkpoint_close(owner);
			assert(device->fuzz.memory == 0 && device->writes == 0 &&
			    device->barriers == 0 && memcmp(device->image, source, bytes) == 0);
			device->fuzz.reads = device->fuzz.allocations = 0;
			device->fuzz.fail_read = device->fuzz.fail_allocation = 0;
			owner = NULL;
			assert(ntfs_write_checkpoint_prepare(backend, &owner) == NTFS_OK);
			for (index = 0; index < TEST_PUBLICATIONS; index++) {
				publication = ntfs_write_checkpoint_get(owner, index);
				assert(memcmp(expected + index * NTFS_WRITE_CLUSTER_BYTES,
					   publication->image, NTFS_WRITE_CLUSTER_BYTES) == 0);
			}
			ntfs_write_checkpoint_close(owner);
			assert(
			    device->fuzz.memory == 0 && memcmp(device->image, source, bytes) == 0);
		}
	}
	printf("PASS: checkpoint prepare faults: %zu allocations/%zu reads, %zu refusals/%zu "
	       "redundant reads, exact retry and unchanged media\n",
	    allocations, reads, refused, redundant_reads);
	free(expected);
}

static void
refusal_profiles(const char *directory)
{
	struct checkpoint_device device = {0};
	struct ntfs_overwrite_environment backend = {0};
	struct ntfs_write_checkpoint *checkpoint;
	struct ntfs_write_batch_recovery *recovery;
	char path[TEST_PATH_BYTES], name[TEST_NAME_BYTES], operation[TEST_NAME_BYTES];
	uint8_t *source;
	size_t bytes, profiles = 0;
	FILE *rows;
	int length, parsed;
	enum ntfs_result result;

	length = snprintf(path, sizeof(path), "%s/refusals", directory);
	assert(length > 0 && (size_t)length < sizeof(path));
	rows = NULL;
	length = snprintf(name, sizeof(name), "cases.rows");
	assert(length > 0 && (size_t)length < sizeof(name));
	{
		char rows_path[TEST_PATH_BYTES];

		length = snprintf(rows_path, sizeof(rows_path), "%s/%s", path, name);
		assert(length > 0 && (size_t)length < sizeof(rows_path));
		rows = fopen(rows_path, "rb");
	}
	assert(rows != NULL);
	while ((parsed = fscanf(rows, "%127s %127s", name, operation)) != EOF) {
		char image_name[TEST_NAME_BYTES];

		assert(parsed == 2);
		length = snprintf(image_name, sizeof(image_name), "%s.img", name);
		assert(length > 0 && (size_t)length < sizeof(image_name));
		source = load(path, image_name, &bytes);
		device = (struct checkpoint_device){0};
		device.image = malloc(bytes);
		assert(device.image != NULL);
		memcpy(device.image, source, bytes);
		device.fuzz = (struct fuzz_device){.data = device.image, .size = bytes};
		backend.reader = fuzz_environment(&device.fuzz);
		backend.reader.read = checkpoint_read;
		backend.api_version = NTFS_OVERWRITE_API_VERSION;
		backend.alignment = NTFS_WRITE_SECTOR_BYTES;
		backend.write = checkpoint_write;
		backend.persist = checkpoint_persist;
		checkpoint = NULL;
		recovery = NULL;
		if (strcmp(operation, "checkpoint") == 0) {
			result = ntfs_write_checkpoint_prepare(&backend, &checkpoint);
		} else {
			assert(strcmp(operation, "recovery") == 0);
			result = ntfs_write_batch_recover_prepare(&backend, &recovery);
		}
		if (result == NTFS_OK) {
			fprintf(stderr, "%s: unproved %s was accepted\n", name, operation);
		}
		assert(result != NTFS_OK && result != NTFS_IO && result != NTFS_NO_MEMORY &&
		    checkpoint == NULL && recovery == NULL && device.fuzz.memory == 0 &&
		    device.writes == 0 && device.barriers == 0 &&
		    memcmp(device.image, source, bytes) == 0);
		free(device.image);
		free(source);
		profiles++;
	}
	assert(fclose(rows) == 0 && profiles != 0);
	printf("PASS: %zu independently authored checkpoint/recovery ownership refusals, "
	       "unchanged media and no write/persistence callbacks\n",
	    profiles);
}

static void
check_case(const char *directory, const char *name, uint32_t alignment, bool faults)
{
	struct checkpoint_device device = {0};
	struct ntfs_overwrite_environment backend = {0};
	struct ntfs_write_checkpoint *owner = NULL;
	const struct ntfs_write_checkpoint_publication *publication;
	struct ntfs_write_checkpoint_report report;
	struct ntfs_write_batch_history history;
	struct ntfs_write_batch_recovery *recovery = NULL;
	char path[TEST_PATH_BYTES], rows_path[TEST_PATH_BYTES], file_name[TEST_NAME_BYTES];
	uint8_t *source, *expected;
	uint64_t physical, log_first, log_bytes, old_floor, old_restart, floor, checkpoint;
	unsigned wrapped;
	unsigned long long fields[6];
	size_t bytes, expected_bytes, index, reads, allocations;
	FILE *rows;
	bool poisoned = false;
	int count;
	enum ntfs_result result;

	count = snprintf(path, sizeof(path), "%s/%s", directory, name);
	assert(count > 0 && (size_t)count < sizeof(path));
	count = snprintf(rows_path, sizeof(rows_path), "%s/case.rows", path);
	assert(count > 0 && (size_t)count < sizeof(rows_path));
	rows = fopen(rows_path, "rb");
	assert(rows != NULL &&
	    fscanf(rows, "%llu %llu %llu %llu %llu %llu %u", &fields[0], &fields[1], &fields[2],
		&fields[3], &fields[4], &fields[5], &wrapped) == 7);
	log_first = fields[0];
	log_bytes = fields[1];
	old_floor = fields[2];
	old_restart = fields[3];
	floor = fields[4];
	checkpoint = fields[5];
	assert(log_first != 0 && log_bytes != 0 && old_floor < old_restart && old_restart < floor &&
	    floor < checkpoint && wrapped <= 1);
	source = load(path, "source.img", &bytes);
	device.image = malloc(bytes);
	assert(device.image != NULL);
	memcpy(device.image, source, bytes);
	device.fuzz.data = device.image;
	device.fuzz.size = bytes;
	backend.reader = fuzz_environment(&device.fuzz);
	backend.reader.read = checkpoint_read;
	backend.api_version = NTFS_OVERWRITE_API_VERSION;
	backend.alignment = alignment;
	backend.write = checkpoint_write;
	backend.persist = checkpoint_persist;
	result = ntfs_write_batch_history_prepare(&backend.reader, &history);
	if (result != NTFS_OK) {
		fprintf(stderr, "%s/%u: independently authored settled history: %s\n", name,
		    alignment, ntfs_result_string(result));
	}
	assert(result == NTFS_OK && history.client.oldest_lsn == old_floor &&
	    history.client.restart_lsn == old_restart &&
	    history.history.completed_end_lsn == floor && device.fuzz.memory == 0);
	device.fuzz.reads = device.fuzz.allocations = 0;
	result = ntfs_write_checkpoint_prepare(&backend, &owner);
	if (result != NTFS_OK) {
		fprintf(stderr, "%s/%u: checkpoint preparation: %s\n", name, alignment,
		    ntfs_result_string(result));
	}
	assert(result == NTFS_OK && owner != NULL);
	if (faults) {
		preparation_faults(&device, &backend, owner, source, bytes);
		device.fuzz.reads = device.fuzz.allocations = 0;
		owner = NULL;
		assert(ntfs_write_checkpoint_prepare(&backend, &owner) == NTFS_OK);
	}
	assert(
	    device.writes == 0 && device.barriers == 0 && memcmp(device.image, source, bytes) == 0);
	assert(ntfs_write_checkpoint_count(owner) == TEST_PUBLICATIONS);
	for (index = 0; index < TEST_PUBLICATIONS; index++) {
		assert(fscanf(rows, "%llu", &fields[0]) == 1);
		physical = fields[0];
		publication = ntfs_write_checkpoint_get(owner, index);
		assert(publication != NULL && publication->physical == physical &&
		    publication->stage == publication_stages[index] &&
		    (uintptr_t)publication->image % alignment == 0);
		count = snprintf(file_name, sizeof(file_name), "publication-%zu.expected", index);
		assert(count > 0 && (size_t)count < sizeof(file_name));
		expected = load(path, file_name, &expected_bytes);
		assert(expected_bytes == NTFS_WRITE_CLUSTER_BYTES &&
		    memcmp(expected, publication->image, expected_bytes) == 0);
		free(expected);
	}
	assert(fgetc(rows) == '\n' && fgetc(rows) == EOF && fclose(rows) == 0);
	assert(ntfs_write_checkpoint_get(owner, TEST_PUBLICATIONS) == NULL);
	publication = ntfs_write_checkpoint_get(owner, 0);
	assert(ntfs_write_checkpoint_execute(owner, &poisoned,
		   (struct ntfs_write_checkpoint_report *)(void *)publication->image) ==
		NTFS_INVALID &&
	    ntfs_write_checkpoint_execute(owner, (bool *)(void *)publication->image, &report) ==
		NTFS_INVALID &&
	    ntfs_write_checkpoint_execute(owner, (bool *)(void *)&report, &report) == NTFS_INVALID);
	assert(device.writes == 0 && device.barriers == 0);
	reads = device.fuzz.reads;
	allocations = device.fuzz.allocations;
	device.executing = true;
	assert(ntfs_write_checkpoint_execute(owner, &poisoned, &report) == NTFS_OK);
	assert(!poisoned && !report.poisoned && report.completed && report.homes_persisted &&
	    report.checkpoint_persisted && report.writes == TEST_PUBLICATIONS &&
	    report.barriers == TEST_BARRIERS &&
	    report.physical_bytes == TEST_PUBLICATIONS * NTFS_WRITE_CLUSTER_BYTES &&
	    report.durable_stage == NTFS_WRITE_CHECKPOINT_CLEAN_SECOND);
	assert(device.writes == TEST_PUBLICATIONS && device.barriers == TEST_BARRIERS &&
	    device.fuzz.reads == reads && device.fuzz.allocations == allocations);
	assert(ntfs_write_checkpoint_execute(owner, &poisoned, &report) == NTFS_INVALID);
	ntfs_write_checkpoint_close(owner);
	assert(device.fuzz.memory == 0);
	device.executing = false;
	expected = load(path, "postimage.expected", &expected_bytes);
	assert(expected_bytes == bytes && memcmp(expected, device.image, bytes) == 0);
	device.fuzz.reads = device.fuzz.allocations = 0;
	assert(ntfs_write_batch_recover_prepare(&backend, &recovery) == NTFS_OK &&
	    ntfs_write_batch_recovery_count(recovery) == 0);
	ntfs_write_batch_recovery_close(recovery);
	assert(ntfs_write_batch_history_prepare(&backend.reader, &history) == NTFS_OK &&
	    history.client.oldest_lsn == floor && history.client.restart_lsn == checkpoint &&
	    history.history.completed_end_lsn == checkpoint &&
	    history.history.visited_records == 2);
	owner = NULL;
	assert(ntfs_write_checkpoint_prepare(&backend, &owner) == NTFS_BUSY && owner == NULL);
	assert(device.fuzz.memory == 0 && memcmp(expected, device.image, bytes) == 0);
	free(expected);
	free(device.image);
	free(source);
}

int
main(int argc, char **argv)
{
	char path[TEST_PATH_BYTES], name[TEST_NAME_BYTES];
	FILE *rows;
	size_t cases = 0;
	int count, parsed;
	bool faults = false;

	assert(argc == 2 || argc == 3);
	if (argc == 3 && strcmp(argv[2], "refusals") == 0) {
		refusal_profiles(argv[1]);
		return 0;
	}
	if (argc == 3) {
		assert(strcmp(argv[2], "prepare-faults") == 0);
		faults = true;
	}
	count = snprintf(path, sizeof(path), "%s/cases.rows", argv[1]);
	assert(count > 0 && (size_t)count < sizeof(path));
	rows = fopen(path, "rb");
	assert(rows != NULL);
	while ((parsed = fscanf(rows, "%127s", name)) != EOF) {
		assert(parsed == 1);
		check_case(argv[1], name, NTFS_WRITE_SECTOR_BYTES, faults);
		if (!faults) {
			check_case(argv[1], name, NTFS_WRITE_CLUSTER_BYTES, false);
		}
		cases++;
	}
	assert(fclose(rows) == 0 && cases == 4);
	printf("PASS: %zu exact settled checkpoint cases at two alignments, with no execution "
	       "reads/allocations and zero-rewrite fresh recovery\n",
	    cases);
	return 0;
}
