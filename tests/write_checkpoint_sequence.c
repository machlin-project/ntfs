/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_checkpoint.h"
#include "write_batch_history.h"
#include "write_batch_recover.h"
#include "write_batch_execute.h"
#include "../adapters/posix/overwrite_image.h"
#include "fuzz_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum {
	TEST_PATH_BYTES = 4096,
	TEST_CYCLES = 128,
	TEST_STEPS = 5,
	TEST_DATA_BYTES = 8193,
	TEST_DATA_OFFSET = 257,
	TEST_SHRINK_BYTES = 19,
	TEST_PATTERN_MULTIPLIER = 37,
	TEST_PATTERN_BIAS = 11
};

#define TEST_FILETIME UINT64_C(134357146906613431)

static const uint16_t file_name[] = {'r', 'i', 'n', 'g', '-', 'f', 'i', 'l', 'e'};
static const uint16_t renamed_name[] = {'r', 'i', 'n', 'g', '-', 'n', 'e', 'w'};

struct sequence_case {
	struct fuzz_device fuzz;
	struct ntfs_overwrite_image image;
	struct ntfs_overwrite_environment backend;
	uint8_t *bytes, *before, *owned, *data;
	char path[TEST_PATH_BYTES];
	uint64_t parent, reference, previous_reference, log_first, log_bytes;
	size_t writes, barriers, packets, checkpoints, operations, wraps;
	bool executing, posix;
};

static enum ntfs_result
sequence_read(void *context, uint64_t physical, void *memory, size_t bytes)
{
	struct sequence_case *test = context;

	assert(!test->executing && ntfs_bounds(physical, bytes, test->fuzz.size));
	test->fuzz.reads++;
	memcpy(memory, test->bytes + physical, bytes);
	return NTFS_OK;
}

static enum ntfs_result
sequence_write(void *context, uint64_t physical, const void *memory, size_t bytes, size_t *actual)
{
	struct sequence_case *test = context;

	assert(test->executing && bytes == NTFS_WRITE_CLUSTER_BYTES &&
	    ntfs_bounds(physical, bytes, test->fuzz.size) &&
	    test->owned[physical / NTFS_WRITE_CLUSTER_BYTES]);
	memcpy(test->bytes + physical, memory, bytes);
	*actual = bytes;
	test->writes++;
	return NTFS_OK;
}

static enum ntfs_result
sequence_persist(void *context)
{
	struct sequence_case *test = context;

	assert(test->executing);
	test->barriers++;
	return NTFS_OK;
}

static void
load_file(const char *path, uint8_t *bytes, size_t count)
{
	FILE *file = fopen(path, "rb");

	assert(file != NULL && fread(bytes, 1, count, file) == count && fgetc(file) == EOF &&
	    fclose(file) == 0);
}

static void
backend_begin(struct sequence_case *test)
{
	assert(test->fuzz.memory == 0 && !test->executing);
	if (test->posix) {
		assert(ntfs_overwrite_image_open(test->path, &test->image) == 0 &&
		    test->image.environment.claim(test->image.environment.reader.context) ==
			NTFS_OK);
		test->backend = test->image.environment;
	}
}

static void
backend_end(struct sequence_case *test)
{
	assert(!test->executing);
	if (test->posix) {
		ntfs_overwrite_image_close(&test->image);
		load_file(test->path, test->bytes, test->fuzz.size);
	}
	assert(test->fuzz.memory == 0);
}

static struct ntfs_environment
snapshot_reader(struct sequence_case *test)
{
	struct ntfs_environment reader = fuzz_environment(&test->fuzz);

	reader.read = sequence_read;
	return reader;
}

static void
unchanged_unowned(struct sequence_case *test)
{
	uint64_t physical;
	size_t bytes;

	for (physical = 0; physical < test->fuzz.size; physical += NTFS_WRITE_CLUSTER_BYTES) {
		if (test->owned[physical / NTFS_WRITE_CLUSTER_BYTES]) {
			continue;
		}
		bytes = test->fuzz.size - physical < NTFS_WRITE_CLUSTER_BYTES
		    ? test->fuzz.size - physical
		    : NTFS_WRITE_CLUSTER_BYTES;
		assert(memcmp(test->bytes + physical, test->before + physical, bytes) == 0);
	}
}

static void
prepare_owned_log(struct sequence_case *test)
{
	memset(test->owned, 0,
	    (test->fuzz.size + NTFS_WRITE_CLUSTER_BYTES - 1) / NTFS_WRITE_CLUSTER_BYTES);
	memset(test->owned + test->log_first / NTFS_WRITE_CLUSTER_BYTES, 1,
	    test->log_bytes / NTFS_WRITE_CLUSTER_BYTES);
}

static void
fresh_settled(struct sequence_case *test, struct ntfs_write_batch_history *history)
{
	struct ntfs_write_batch_recovery *recovery = NULL;
	struct ntfs_overwrite_environment backend = {0};

	backend.reader = snapshot_reader(test);
	backend.api_version = NTFS_OVERWRITE_API_VERSION;
	backend.alignment = NTFS_WRITE_SECTOR_BYTES;
	backend.write = sequence_write;
	backend.persist = sequence_persist;
	assert(ntfs_write_batch_recover_prepare(&backend, &recovery) == NTFS_OK &&
	    ntfs_write_batch_recovery_count(recovery) == 0);
	ntfs_write_batch_recovery_close(recovery);
	assert(ntfs_write_batch_history_prepare(&backend.reader, history) == NTFS_OK &&
	    history->selected.flags == NTFS_LOGFILE_RESTART_CLEAN && history->history.complete &&
	    history->history.endpoint_verified && history->history.tail_lsn == 0 &&
	    test->fuzz.memory == 0);
}

static void
check_file(struct sequence_case *test, size_t step)
{
	struct ntfs_environment reader = snapshot_reader(test);
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *root = NULL, *node = NULL, *stale = NULL;
	struct ntfs_stream *stream = NULL;
	struct ntfs_stat metadata;
	uint8_t *expected, *actual;
	size_t size, transferred, index;
	enum ntfs_result result;

	assert(
	    ntfs_mount(&reader, NULL, &volume) == NTFS_OK && ntfs_root(volume, &root) == NTFS_OK);
	result = ntfs_lookup(root, file_name, sizeof(file_name) / sizeof(*file_name), &node);
	if (step < 3) {
		assert(result == NTFS_OK && ntfs_node_stat(node, &metadata) == NTFS_OK &&
		    metadata.reference == test->reference && !metadata.directory &&
		    metadata.links == 1);
	} else {
		assert(result == NTFS_NOT_FOUND && node == NULL);
	}
	if (step == 3) {
		assert(ntfs_lookup(root, renamed_name, sizeof(renamed_name) / sizeof(*renamed_name),
			   &node) == NTFS_OK &&
		    ntfs_node_stat(node, &metadata) == NTFS_OK &&
		    metadata.reference == test->reference && metadata.links == 1);
	} else {
		assert(ntfs_lookup(root, renamed_name, sizeof(renamed_name) / sizeof(*renamed_name),
			   &stale) == NTFS_NOT_FOUND &&
		    stale == NULL);
	}
	if (step < 4) {
		size = step == 0 ? 0
		    : step == 1	 ? TEST_DATA_OFFSET + TEST_DATA_BYTES
				 : TEST_SHRINK_BYTES;
		assert(metadata.size == size &&
		    ntfs_stream_open(node, NULL, 0, &stream) == NTFS_OK &&
		    ntfs_stream_size(stream) == size);
		expected = calloc(1, size + 1);
		actual = malloc(size + 1);
		assert(expected != NULL && actual != NULL);
		if (step == 1) {
			for (index = 0; index < TEST_DATA_BYTES; index++) {
				expected[TEST_DATA_OFFSET + index] =
				    (uint8_t)(index * TEST_PATTERN_MULTIPLIER + TEST_PATTERN_BIAS);
			}
		}
		assert(ntfs_stream_read(stream, 0, actual, size + 1, &transferred) == NTFS_OK &&
		    transferred == size && memcmp(actual, expected, size) == 0);
		free(actual);
		free(expected);
		ntfs_stream_close(stream);
	}
	ntfs_node_close(node);
	if (step == 0 && test->previous_reference != 0) {
		assert(ntfs_node_open(volume, test->previous_reference, &stale) == NTFS_STALE &&
		    stale == NULL);
	}
	ntfs_node_close(root);
	assert(ntfs_unmount(volume) == NTFS_OK && test->fuzz.memory == 0);
}

static void
observe_wrap(struct sequence_case *test, const struct ntfs_write_batch_history *before,
    const struct ntfs_write_batch_history *after)
{
	struct ntfs_logfile_lsn older, newer;

	assert(ntfs_logfile_lsn_decode(
		   &before->origin, before->history.completed_end_lsn, &older) == NTFS_OK &&
	    ntfs_logfile_lsn_decode(&after->origin, after->history.completed_end_lsn, &newer) ==
		NTFS_OK &&
	    newer.sequence >= older.sequence);
	test->wraps += (size_t)(newer.sequence - older.sequence);
}

static void
checkpoint(struct sequence_case *test)
{
	struct ntfs_write_batch_history before, after;
	struct ntfs_write_checkpoint *owner = NULL;
	struct ntfs_write_checkpoint_report report;
	const struct ntfs_write_checkpoint_publication *publication;
	size_t reads, allocations, index, count;
	bool poisoned = false;

	fresh_settled(test, &before);
	memcpy(test->before, test->bytes, test->fuzz.size);
	prepare_owned_log(test);
	backend_begin(test);
	assert(ntfs_write_checkpoint_prepare(&test->backend, &owner) == NTFS_OK);
	count = ntfs_write_checkpoint_count(owner);
	for (index = 0; index < count; index++) {
		publication = ntfs_write_checkpoint_get(owner, index);
		assert(ntfs_bounds(publication->physical - test->log_first,
		    NTFS_WRITE_CLUSTER_BYTES, test->log_bytes));
	}
	reads = test->fuzz.reads;
	allocations = test->fuzz.allocations;
	test->executing = true;
	assert(ntfs_write_checkpoint_execute(owner, &poisoned, &report) == NTFS_OK && !poisoned &&
	    report.completed && report.homes_persisted && report.checkpoint_persisted &&
	    report.writes == count && report.barriers == count + 1 && test->fuzz.reads == reads &&
	    test->fuzz.allocations == allocations);
	test->executing = false;
	ntfs_write_checkpoint_close(owner);
	backend_end(test);
	unchanged_unowned(test);
	fresh_settled(test, &after);
	assert(after.client.oldest_lsn == before.history.completed_end_lsn &&
	    after.client.restart_lsn == after.selected.current_lsn &&
	    after.history.visited_records == 2 &&
	    after.history.completed_end_lsn == after.client.restart_lsn);
	observe_wrap(test, &before, &after);
	test->checkpoints++;
}

static enum ntfs_result
mutate(struct sequence_case *test, const struct ntfs_write_mutation_request *request)
{
	struct ntfs_write_mutation_plan *plan = NULL;
	struct ntfs_write_program *program = NULL;
	struct ntfs_write_batch_execution *execution = NULL;
	struct ntfs_write_execution_report report;
	struct ntfs_write_mutation_region region;
	struct ntfs_write_batch_history before, after;
	const struct ntfs_write_batch_publication *publication;
	uint64_t reference;
	size_t index, count, barriers = 0, reads, allocations;
	bool poisoned = false;
	enum ntfs_result result;

	fresh_settled(test, &before);
	memcpy(test->before, test->bytes, test->fuzz.size);
	prepare_owned_log(test);
	backend_begin(test);
	assert(ntfs_write_mutation_prepare(&test->backend.reader, request, &plan) == NTFS_OK);
	reference = ntfs_write_mutation_plan_reference(plan);
	for (index = 0; index < ntfs_write_mutation_plan_count(plan); index++) {
		assert(ntfs_write_mutation_plan_region(plan, index, &region) == NTFS_OK &&
		    region.bytes == NTFS_WRITE_CLUSTER_BYTES);
		test->owned[region.physical / NTFS_WRITE_CLUSTER_BYTES] = 1;
	}
	assert(ntfs_write_program_prepare(&test->backend.reader, plan, &program) == NTFS_OK);
	ntfs_write_mutation_plan_close(plan);
	result = ntfs_write_batch_execute_prepare(&test->backend, program, &execution);
	ntfs_write_program_close(program);
	if (result != NTFS_OK) {
		assert(result == NTFS_NO_SPACE && execution == NULL);
		backend_end(test);
		assert(memcmp(test->before, test->bytes, test->fuzz.size) == 0);
		return result;
	}
	count = ntfs_write_batch_execution_count(execution);
	for (index = 0; index < count; index++) {
		publication = ntfs_write_batch_execution_get(execution, index);
		assert(test->owned[publication->physical / NTFS_WRITE_CLUSTER_BYTES]);
		barriers += publication->barrier;
	}
	reads = test->fuzz.reads;
	allocations = test->fuzz.allocations;
	test->executing = true;
	assert(ntfs_write_batch_execute(execution, &poisoned, &report) == NTFS_OK && !poisoned &&
	    report.completed && report.commit_persisted && report.writes == count &&
	    report.barriers == barriers && test->fuzz.reads == reads &&
	    test->fuzz.allocations == allocations);
	test->executing = false;
	ntfs_write_batch_execution_close(execution);
	backend_end(test);
	unchanged_unowned(test);
	fresh_settled(test, &after);
	assert(after.client.oldest_lsn == before.client.oldest_lsn &&
	    after.client.restart_lsn == before.client.restart_lsn &&
	    after.history.visited_records > before.history.visited_records);
	test->packets += after.history.visited_records - before.history.visited_records;
	observe_wrap(test, &before, &after);
	if (request->kind == NTFS_WRITE_CREATE_FILE) {
		if (test->previous_reference != 0) {
			uint16_t generation;

			generation =
			    (uint16_t)(test->previous_reference >> NTFS_REFERENCE_SEQUENCE_SHIFT);
			generation = (uint16_t)(generation + 1u);
			assert((reference & NTFS_REFERENCE_RECORD_MASK) ==
				(test->previous_reference & NTFS_REFERENCE_RECORD_MASK) &&
			    reference >> NTFS_REFERENCE_SEQUENCE_SHIFT ==
				(generation == 0 ? 1 : generation));
		}
		test->reference = reference;
	}
	test->operations++;
	return NTFS_OK;
}

static void
sequence(const char *directory, const char *image_name, const char *output, bool posix)
{
	struct sequence_case test = {0};
	struct ntfs_environment reader;
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *root = NULL, *node = NULL;
	struct ntfs_stream *log = NULL;
	struct ntfs_stat metadata;
	struct ntfs_write_mutation_request request = {0};
	struct ntfs_validation_report *validation;
	char path[TEST_PATH_BYTES], temporary[TEST_PATH_BYTES];
	FILE *file;
	long bytes;
	size_t cycle, step, index;
	int length;

	length = snprintf(path, sizeof(path), "%s/%s", directory, image_name);
	assert(length > 0 && (size_t)length < sizeof(path));
	file = fopen(path, "rb");
	assert(file != NULL && fseek(file, 0, SEEK_END) == 0 && (bytes = ftell(file)) > 0 &&
	    fseek(file, 0, SEEK_SET) == 0);
	test.bytes = malloc((size_t)bytes);
	test.before = malloc((size_t)bytes);
	test.owned =
	    calloc(1, ((size_t)bytes + NTFS_WRITE_CLUSTER_BYTES - 1) / NTFS_WRITE_CLUSTER_BYTES);
	test.data = malloc(TEST_DATA_BYTES);
	validation = malloc(sizeof(*validation));
	assert(test.bytes != NULL && test.before != NULL && test.owned != NULL &&
	    test.data != NULL && validation != NULL &&
	    fread(test.bytes, 1, (size_t)bytes, file) == (size_t)bytes && fgetc(file) == EOF &&
	    fclose(file) == 0);
	test.fuzz = (struct fuzz_device){.data = test.bytes, .size = (size_t)bytes};
	test.posix = posix;
	reader = snapshot_reader(&test);
	assert(ntfs_mount(&reader, NULL, &volume) == NTFS_OK &&
	    ntfs_root(volume, &root) == NTFS_OK && ntfs_node_stat(root, &metadata) == NTFS_OK);
	test.parent = metadata.reference;
	ntfs_node_close(root);
	assert(ntfs_node_by_number(volume, NTFS_LOGFILE_RECORD, &node) == NTFS_OK &&
	    ntfs_stream_open(node, NULL, 0, &log) == NTFS_OK && log->run_count == 1 &&
	    log->runs[0].lcn != NTFS_HOLE);
	test.log_first = log->runs[0].lcn * NTFS_WRITE_CLUSTER_BYTES;
	test.log_bytes = log->size;
	ntfs_stream_close(log);
	ntfs_node_close(node);
	assert(ntfs_unmount(volume) == NTFS_OK && test.fuzz.memory == 0);
	test.backend.reader = reader;
	test.backend.api_version = NTFS_OVERWRITE_API_VERSION;
	test.backend.alignment = NTFS_WRITE_SECTOR_BYTES;
	test.backend.write = sequence_write;
	test.backend.persist = sequence_persist;
	if (posix) {
		length =
		    snprintf(temporary, sizeof(temporary), "%s/checkpoint-sequence-XXXXXX", output);
		assert(
		    length > 0 && (size_t)length < sizeof(temporary) && mkdtemp(temporary) != NULL);
		length = snprintf(test.path, sizeof(test.path), "%s/operations.img", temporary);
		assert(length > 0 && (size_t)length < sizeof(test.path));
		file = fopen(test.path, "wbx");
		assert(file != NULL &&
		    fwrite(test.bytes, 1, test.fuzz.size, file) == test.fuzz.size &&
		    fclose(file) == 0);
	}
	for (index = 0; index < TEST_DATA_BYTES; index++) {
		test.data[index] = (uint8_t)(index * TEST_PATTERN_MULTIPLIER + TEST_PATTERN_BIAS);
	}
	for (cycle = 0; cycle < TEST_CYCLES; cycle++) {
		for (step = 0; step < TEST_STEPS; step++) {
			request = (struct ntfs_write_mutation_request){
			    .filetime = TEST_FILETIME + cycle * TEST_STEPS + step,
			    .reference = test.reference,
			    .source = {
				test.parent, file_name, sizeof(file_name) / sizeof(*file_name)}};
			if (step == 0) {
				request.kind = NTFS_WRITE_CREATE_FILE;
			} else if (step == 1) {
				request.kind = NTFS_WRITE_GROWING_RANGE;
				request.offset = TEST_DATA_OFFSET;
				request.data = test.data;
				request.bytes = TEST_DATA_BYTES;
			} else if (step == 2) {
				request.kind = NTFS_WRITE_RESIZE_FILE;
				request.size = TEST_SHRINK_BYTES;
			} else if (step == 3) {
				request.kind = NTFS_WRITE_RENAME;
				request.destination = (struct ntfs_write_name){test.parent,
				    renamed_name, sizeof(renamed_name) / sizeof(*renamed_name)};
			} else {
				request.kind = NTFS_WRITE_REMOVE_FILE;
				request.source.units = renamed_name;
				request.source.count = sizeof(renamed_name) / sizeof(*renamed_name);
			}
			if (mutate(&test, &request) == NTFS_NO_SPACE) {
				checkpoint(&test);
				assert(mutate(&test, &request) == NTFS_OK);
			}
			check_file(&test, step);
			assert(ntfs_validate(&reader, NULL, NULL, validation) == NTFS_OK &&
			    validation->complete && test.fuzz.memory == 0);
		}
		test.previous_reference = test.reference;
		checkpoint(&test);
	}
	assert(test.operations == TEST_CYCLES * TEST_STEPS && test.checkpoints >= TEST_CYCLES &&
	    test.packets > NTFS_WRITE_BATCH_MAX_PACKETS && test.wraps >= 3 &&
	    test.fuzz.memory == 0);
	printf(
	    "PASS: %s %s: %zu operations/%zu packets/%zu checkpoints/%zu ring wraps, "
	    "fresh zero-rewrite recovery, exact names/data/zero gaps/generations and unowned bytes",
	    posix ? "actual POSIX" : "modeled", image_name, test.operations, test.packets,
	    test.checkpoints, test.wraps);
	if (posix) {
		printf("; close/reopened postimage %s", test.path);
	}
	putchar('\n');
	free(validation);
	free(test.data);
	free(test.owned);
	free(test.before);
	free(test.bytes);
}

int
main(int argc, char **argv)
{
	assert(argc == 3 || argc == 4);
	if (argc == 4) {
		assert(strcmp(argv[3], "posix") == 0);
		sequence(argv[1], "source.img", argv[2], true);
	} else {
		sequence(argv[1], "source.img", argv[2], false);
		sequence(argv[1], "large-source.img", argv[2], false);
	}
	return 0;
}
