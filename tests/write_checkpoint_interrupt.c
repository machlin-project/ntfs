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

static const size_t transfer_cuts[] = {0, 1, NTFS_MST_STRIDE / 2, NTFS_MST_STRIDE,
    2 * NTFS_MST_STRIDE, 3 * NTFS_MST_STRIDE, 4 * NTFS_MST_STRIDE, 5 * NTFS_MST_STRIDE,
    6 * NTFS_MST_STRIDE, 7 * NTFS_MST_STRIDE, NTFS_WRITE_CLUSTER_BYTES - 1,
    NTFS_WRITE_CLUSTER_BYTES};

struct checkpoint_device {
	struct fuzz_device fuzz;
	uint8_t *image, *durable;
	size_t writes, barriers, fail_write, fail_barrier, cut;
	bool executing, checkpoint, suffix, failed_barrier_persisted;
};

struct checkpoint_case {
	char name[TEST_NAME_BYTES];
	uint8_t *source;
	size_t bytes;
	uint64_t log_first, log_bytes, old_floor, old_checkpoint, floor, checkpoint;
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
	size_t count, offset;

	assert(device->executing && bytes == NTFS_WRITE_CLUSTER_BYTES &&
	    ntfs_bounds(physical, bytes, device->fuzz.size));
	if (device->checkpoint) {
		assert(device->barriers == device->writes + 1);
	}
	device->writes++;
	count = device->writes == device->fail_write ? device->cut : bytes;
	assert(count <= bytes);
	offset = device->suffix ? bytes - count : 0;
	memcpy(device->image + physical + offset, (const uint8_t *)memory + offset, count);
	*actual = count;
	return device->writes == device->fail_write ? NTFS_IO : NTFS_OK;
}

static enum ntfs_result
checkpoint_persist(void *context)
{
	struct checkpoint_device *device = context;

	assert(device->executing);
	if (device->checkpoint) {
		assert(device->barriers == device->writes);
	}
	device->barriers++;
	if (device->barriers != device->fail_barrier || device->failed_barrier_persisted) {
		memcpy(device->durable, device->image, device->fuzz.size);
	}
	return device->barriers == device->fail_barrier ? NTFS_IO : NTFS_OK;
}

static struct ntfs_overwrite_environment
backend_for(struct checkpoint_device *device)
{
	struct ntfs_overwrite_environment backend = {0};

	backend.reader = fuzz_environment(&device->fuzz);
	backend.reader.read = checkpoint_read;
	backend.api_version = NTFS_OVERWRITE_API_VERSION;
	backend.alignment = NTFS_WRITE_SECTOR_BYTES;
	backend.write = checkpoint_write;
	backend.persist = checkpoint_persist;
	return backend;
}

static void
device_reset(struct checkpoint_device *device, const uint8_t *source, size_t bytes)
{
	uint8_t *image = device->image, *durable = device->durable;

	assert(device->fuzz.memory == 0);
	*device = (struct checkpoint_device){.image = image, .durable = durable};
	device->fuzz = (struct fuzz_device){.data = image, .size = bytes};
	memcpy(image, source, bytes);
	memcpy(durable, source, bytes);
}

static uint8_t *
load(const char *path, size_t *bytes)
{
	FILE *file;
	uint8_t *data;
	long length;

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
case_load(const char *directory, const char *name, struct checkpoint_case *test)
{
	char path[TEST_PATH_BYTES];
	unsigned long long fields[6];
	unsigned wrapped;
	FILE *rows;
	int count;

	memset(test, 0, sizeof(*test));
	count = snprintf(test->name, sizeof(test->name), "%s", name);
	assert(count > 0 && (size_t)count < sizeof(test->name));
	count = snprintf(path, sizeof(path), "%s/%s/case.rows", directory, name);
	assert(count > 0 && (size_t)count < sizeof(path));
	rows = fopen(path, "rb");
	assert(rows != NULL &&
	    fscanf(rows, "%llu %llu %llu %llu %llu %llu %u", &fields[0], &fields[1], &fields[2],
		&fields[3], &fields[4], &fields[5], &wrapped) == 7);
	assert(fclose(rows) == 0 && wrapped <= 1);
	test->log_first = fields[0];
	test->log_bytes = fields[1];
	test->old_floor = fields[2];
	test->old_checkpoint = fields[3];
	test->floor = fields[4];
	test->checkpoint = fields[5];
	count = snprintf(path, sizeof(path), "%s/%s/source.img", directory, name);
	assert(count > 0 && (size_t)count < sizeof(path));
	test->source = load(path, &test->bytes);
	assert(ntfs_bounds(test->log_first, test->log_bytes, test->bytes));
}

static void
recovery_prepare_check(struct checkpoint_device *device, const struct checkpoint_case *test,
    const char *phase, struct ntfs_write_batch_recovery **out)
{
	struct ntfs_overwrite_environment backend = backend_for(device);
	enum ntfs_result result;

	device->executing = false;
	device->checkpoint = false;
	device->writes = device->barriers = device->fail_write = device->fail_barrier = 0;
	device->fuzz.reads = device->fuzz.allocations = 0;
	result = ntfs_write_batch_recover_prepare(&backend, out);
	if (result != NTFS_OK) {
		fprintf(
		    stderr, "%s: %s recovery: %s\n", test->name, phase, ntfs_result_string(result));
	}
	assert(result == NTFS_OK && *out != NULL && device->writes == 0 && device->barriers == 0);
}

static void
recover_and_check(
    struct checkpoint_device *device, const struct checkpoint_case *test, const char *phase)
{
	struct ntfs_write_batch_recovery *owner = NULL;
	struct ntfs_write_recovery_report report;
	struct ntfs_write_batch_history history;
	struct ntfs_overwrite_environment backend;
	size_t reads, allocations, end;
	bool poisoned = false;

	recovery_prepare_check(device, test, phase, &owner);
	reads = device->fuzz.reads;
	allocations = device->fuzz.allocations;
	device->executing = true;
	assert(ntfs_write_batch_recover_execute(owner, &poisoned, &report) == NTFS_OK &&
	    report.completed && report.homes_persisted && !poisoned && !report.poisoned);
	assert(device->fuzz.reads == reads && device->fuzz.allocations == allocations);
	ntfs_write_batch_recovery_close(owner);
	assert(device->fuzz.memory == 0);
	device->executing = false;
	end = (size_t)(test->log_first + test->log_bytes);
	assert(memcmp(device->image, test->source, (size_t)test->log_first) == 0 &&
	    memcmp(device->image + end, test->source + end, test->bytes - end) == 0);
	backend = backend_for(device);
	assert(ntfs_write_batch_history_prepare(&backend.reader, &history) == NTFS_OK &&
	    history.history.complete && history.history.endpoint_verified &&
	    history.history.tail_lsn == 0 && history.selected.flags == NTFS_LOGFILE_RESTART_CLEAN);
	assert((history.client.oldest_lsn == test->old_floor &&
		   history.client.restart_lsn == test->old_checkpoint) ||
	    (history.client.oldest_lsn == test->floor &&
		history.client.restart_lsn == test->checkpoint));
	owner = NULL;
	assert(ntfs_write_batch_recover_prepare(&backend, &owner) == NTFS_OK &&
	    ntfs_write_batch_recovery_count(owner) == 0);
	ntfs_write_batch_recovery_close(owner);
	assert(device->fuzz.memory == 0);
}

static size_t
recovery_interruptions(struct checkpoint_device *device, const struct checkpoint_case *test)
{
	struct ntfs_write_batch_recovery *owner = NULL;
	struct ntfs_write_recovery_report report;
	uint8_t *source;
	size_t publications, index, cut, direction, delivered, crash, states = 0;
	bool poisoned;
	char phase[TEST_NAME_BYTES];
	int length;

	source = malloc(test->bytes);
	assert(source != NULL);
	memcpy(source, device->image, test->bytes);
	recovery_prepare_check(device, test, "publication inventory", &owner);
	publications = ntfs_write_batch_recovery_count(owner);
	assert(publications != 0);
	ntfs_write_batch_recovery_close(owner);
	for (index = 1; index <= publications; index++) {
		for (direction = 0; direction < 2; direction++) {
			for (cut = 0; cut < sizeof(transfer_cuts) / sizeof(*transfer_cuts); cut++) {
				device_reset(device, source, test->bytes);
				owner = NULL;
				recovery_prepare_check(
				    device, test, "recovery interruption preparation", &owner);
				device->executing = true;
				device->fail_write = index;
				device->cut = transfer_cuts[cut];
				device->suffix = direction != 0;
				poisoned = false;
				assert(ntfs_write_batch_recover_execute(
					   owner, &poisoned, &report) == NTFS_IO &&
				    poisoned && report.poisoned && !report.completed &&
				    report.writes == index);
				assert(ntfs_write_batch_recover_execute(
					   owner, &poisoned, &report) == NTFS_IO);
				ntfs_write_batch_recovery_close(owner);
				assert(device->fuzz.memory == 0);
				length = snprintf(phase, sizeof(phase),
				    "interrupted recovery write %zu, %zu-byte %s", index,
				    transfer_cuts[cut], direction == 0 ? "prefix" : "suffix");
				assert(length > 0 && (size_t)length < sizeof(phase));
				recover_and_check(device, test, phase);
				states++;
			}
		}
	}
	/* The settled-home barrier is part of pending-checkpoint recovery too.
	 * Model both successful delivery and lost delivery of a failed barrier,
	 * then reopen either durable media or the still-visible volatile image. */
	for (index = 1; index <= publications + 1; index++) {
		for (delivered = 0; delivered < 2; delivered++) {
			for (crash = 0; crash < 2; crash++) {
				device_reset(device, source, test->bytes);
				owner = NULL;
				recovery_prepare_check(
				    device, test, "recovery barrier preparation", &owner);
				device->executing = true;
				device->fail_barrier = index;
				device->failed_barrier_persisted = delivered != 0;
				poisoned = false;
				assert(ntfs_write_batch_recover_execute(
					   owner, &poisoned, &report) == NTFS_IO &&
				    poisoned && report.poisoned && !report.completed &&
				    report.writes == index - 1 && report.barriers == index);
				ntfs_write_batch_recovery_close(owner);
				assert(device->fuzz.memory == 0);
				if (crash == 0) {
					memcpy(device->image, device->durable, test->bytes);
				}
				length = snprintf(phase, sizeof(phase),
				    "interrupted recovery barrier %zu, delivered %zu, visible %zu",
				    index, delivered, crash);
				assert(length > 0 && (size_t)length < sizeof(phase));
				recover_and_check(device, test, phase);
				states++;
			}
		}
	}
	free(source);
	return states;
}

static size_t
recovery_preparation_faults(struct checkpoint_device *device, const struct checkpoint_case *test)
{
	struct ntfs_write_batch_recovery *owner = NULL;
	struct ntfs_overwrite_environment backend = backend_for(device);
	const struct ntfs_write_batch_recovery_publication *publication;
	uint8_t *source, *expected;
	size_t reads, allocations, publications, mode, failure, limit, index, states = 0;
	enum ntfs_result result;

	source = malloc(test->bytes);
	assert(source != NULL);
	memcpy(source, device->image, test->bytes);
	recovery_prepare_check(device, test, "preparation fault inventory", &owner);
	reads = device->fuzz.reads;
	allocations = device->fuzz.allocations;
	publications = ntfs_write_batch_recovery_count(owner);
	assert(publications != 0);
	expected = malloc(publications * NTFS_WRITE_CLUSTER_BYTES);
	assert(expected != NULL);
	for (index = 0; index < publications; index++) {
		publication = ntfs_write_batch_recovery_get(owner, index);
		memcpy(expected + index * NTFS_WRITE_CLUSTER_BYTES, publication->image,
		    NTFS_WRITE_CLUSTER_BYTES);
	}
	ntfs_write_batch_recovery_close(owner);
	assert(device->fuzz.memory == 0);
	for (mode = 0; mode < 2; mode++) {
		limit = mode == 0 ? allocations : reads;
		for (failure = 1; failure <= limit; failure++) {
			device_reset(device, source, test->bytes);
			device->fuzz.fail_allocation = mode == 0 ? failure : 0;
			device->fuzz.fail_read = mode == 1 ? failure : 0;
			owner = NULL;
			result = ntfs_write_batch_recover_prepare(&backend, &owner);
			if (result != (mode == 0 ? NTFS_NO_MEMORY : NTFS_IO)) {
				fprintf(stderr, "%s: recovery prepare %s fault %zu: %s\n",
				    test->name, mode == 0 ? "allocation" : "read", failure,
				    ntfs_result_string(result));
			}
			assert(result == (mode == 0 ? NTFS_NO_MEMORY : NTFS_IO) && owner == NULL &&
			    device->fuzz.memory == 0 && device->writes == 0 &&
			    device->barriers == 0 &&
			    memcmp(device->image, source, test->bytes) == 0);
			device->fuzz.fail_allocation = device->fuzz.fail_read = 0;
			owner = NULL;
			recovery_prepare_check(device, test, "exact preparation retry", &owner);
			assert(ntfs_write_batch_recovery_count(owner) == publications);
			for (index = 0; index < publications; index++) {
				publication = ntfs_write_batch_recovery_get(owner, index);
				assert(memcmp(expected + index * NTFS_WRITE_CLUSTER_BYTES,
					   publication->image, NTFS_WRITE_CLUSTER_BYTES) == 0);
			}
			ntfs_write_batch_recovery_close(owner);
			assert(device->fuzz.memory == 0 &&
			    memcmp(device->image, source, test->bytes) == 0);
			states++;
		}
	}
	printf("PASS: %s recovery preparation: %zu allocations/%zu reads, unchanged "
	       "media, exact retry and no publication callbacks\n",
	    test->name, allocations, reads);
	free(expected);
	free(source);
	return states;
}

static size_t
checkpoint_interruptions(
    const struct checkpoint_case *test, bool repeated_recovery, bool preparation_faults)
{
	struct checkpoint_device device = {0};
	struct ntfs_overwrite_environment backend;
	struct ntfs_write_checkpoint *owner;
	struct ntfs_write_checkpoint_report report;
	size_t publication, cut, direction, delivered, crash, reads, allocations, states = 0;
	char phase[TEST_NAME_BYTES];
	bool poisoned;
	int length;

	device.image = malloc(test->bytes);
	device.durable = malloc(test->bytes);
	assert(device.image != NULL && device.durable != NULL);
	for (publication = 1; publication <= TEST_PUBLICATIONS; publication++) {
		for (direction = 0; direction < 2; direction++) {
			for (cut = 0; cut < sizeof(transfer_cuts) / sizeof(*transfer_cuts); cut++) {
				if ((repeated_recovery || preparation_faults) &&
				    (direction != 0 ||
					!((publication == 3 || publication == 5) &&
					    transfer_cuts[cut] == NTFS_WRITE_CLUSTER_BYTES))) {
					continue;
				}
				device_reset(&device, test->source, test->bytes);
				backend = backend_for(&device);
				owner = NULL;
				assert(ntfs_write_checkpoint_prepare(&backend, &owner) == NTFS_OK &&
				    ntfs_write_checkpoint_count(owner) == TEST_PUBLICATIONS &&
				    device.writes == 0 && device.barriers == 0);
				device.checkpoint = device.executing = true;
				device.fail_write = publication;
				device.cut = transfer_cuts[cut];
				device.suffix = direction != 0;
				reads = device.fuzz.reads;
				allocations = device.fuzz.allocations;
				poisoned = false;
				assert(ntfs_write_checkpoint_execute(owner, &poisoned, &report) ==
					NTFS_IO &&
				    poisoned && report.poisoned && !report.completed &&
				    report.homes_persisted && report.writes == publication &&
				    report.barriers == publication &&
				    report.physical_bytes ==
					(publication - 1) * NTFS_WRITE_CLUSTER_BYTES +
					    transfer_cuts[cut] &&
				    report.checkpoint_persisted == (publication > 4));
				assert(device.fuzz.reads == reads &&
				    device.fuzz.allocations == allocations);
				assert(ntfs_write_checkpoint_execute(owner, &poisoned, &report) ==
				    NTFS_IO);
				ntfs_write_checkpoint_close(owner);
				assert(device.fuzz.memory == 0);
				length = snprintf(phase, sizeof(phase),
				    "checkpoint write %zu, %zu-byte %s", publication,
				    transfer_cuts[cut], direction == 0 ? "prefix" : "suffix");
				assert(length > 0 && (size_t)length < sizeof(phase));
				if (preparation_faults) {
					states += recovery_preparation_faults(&device, test);
				} else if (repeated_recovery) {
					states += recovery_interruptions(&device, test);
				} else {
					recover_and_check(&device, test, phase);
					states++;
				}
			}
		}
	}
	for (publication = 1;
	    !repeated_recovery && !preparation_faults && publication <= TEST_BARRIERS;
	    publication++) {
		for (delivered = 0; delivered < 2; delivered++) {
			for (crash = 0; crash < 2; crash++) {
				device_reset(&device, test->source, test->bytes);
				backend = backend_for(&device);
				owner = NULL;
				assert(ntfs_write_checkpoint_prepare(&backend, &owner) == NTFS_OK);
				device.executing = device.checkpoint = true;
				device.fail_barrier = publication;
				device.failed_barrier_persisted = delivered != 0;
				poisoned = false;
				assert(ntfs_write_checkpoint_execute(owner, &poisoned, &report) ==
					NTFS_IO &&
				    poisoned && report.poisoned && !report.completed &&
				    report.writes == publication - 1 &&
				    report.barriers == publication &&
				    report.homes_persisted == (publication > 1) &&
				    report.checkpoint_persisted == (publication > 5));
				ntfs_write_checkpoint_close(owner);
				assert(device.fuzz.memory == 0);
				if (crash == 0) {
					memcpy(device.image, device.durable, test->bytes);
				}
				length = snprintf(phase, sizeof(phase),
				    "checkpoint barrier %zu, delivered %zu, visible %zu",
				    publication, delivered, crash);
				assert(length > 0 && (size_t)length < sizeof(phase));
				recover_and_check(&device, test, phase);
				states++;
			}
		}
	}
	free(device.durable);
	free(device.image);
	return states;
}

int
main(int argc, char **argv)
{
	struct checkpoint_case test;
	char path[TEST_PATH_BYTES], name[TEST_NAME_BYTES];
	FILE *rows;
	size_t cases = 0, states = 0;
	bool repeated_recovery, preparation_faults;
	int count, parsed;

	assert(argc == 2 || argc == 3);
	repeated_recovery = argc == 3 && strcmp(argv[2], "recovery") == 0;
	preparation_faults = argc == 3 && strcmp(argv[2], "prepare-faults") == 0;
	assert(argc == 2 || repeated_recovery || preparation_faults);
	count = snprintf(path, sizeof(path), "%s/cases.rows", argv[1]);
	assert(count > 0 && (size_t)count < sizeof(path));
	rows = fopen(path, "rb");
	assert(rows != NULL);
	while ((parsed = fscanf(rows, "%127s", name)) != EOF) {
		assert(parsed == 1);
		case_load(argv[1], name, &test);
		states += checkpoint_interruptions(&test, repeated_recovery, preparation_faults);
		free(test.source);
		cases++;
	}
	assert(fclose(rows) == 0 && cases == 4 && states != 0);
	printf(
	    "PASS: %zu %s states across %zu settled linear/wrapped families, unchanged user bytes "
	    "and zero-rewrite fresh recovery\n",
	    states,
	    preparation_faults	    ? "checkpoint recovery preparation fault"
		: repeated_recovery ? "interrupted checkpoint recovery"
				    : "checkpoint transfer/persistence interruption",
	    cases);
	return 0;
}
