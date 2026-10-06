/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_bitmap.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { TEST_PATH_BYTES = 2048, TEST_NAME_BYTES = 128, TEST_SENTINEL = 0xa5 };

struct tracker {
	size_t live, allocations, releases, reads, fail;
};

struct test_case {
	struct ntfs_write_mutation_region region;
	uint8_t *before, *after, *goldens;
	size_t count;
	uint16_t key;
	enum ntfs_result result;
};

static void *
allocate(void *context, size_t bytes)
{
	struct tracker *tracker = context;
	void *memory;

	tracker->allocations++;
	if (tracker->allocations == tracker->fail) {
		return NULL;
	}
	memory = malloc(bytes);
	assert(memory != NULL);
	tracker->live += bytes;
	memset(memory, TEST_SENTINEL, bytes);
	return memory;
}

static void
release(void *context, void *memory, size_t bytes)
{
	struct tracker *tracker = context;

	assert(memory != NULL && bytes <= tracker->live);
	tracker->live -= bytes;
	tracker->releases++;
	free(memory);
}

static enum ntfs_result
refuse_read(void *context, uint64_t offset, void *memory, size_t bytes)
{
	struct tracker *tracker = context;

	(void)offset;
	(void)memory;
	(void)bytes;
	tracker->reads++;
	return NTFS_IO;
}

static FILE *
open_file(const char *directory, const char *name)
{
	char path[TEST_PATH_BYTES];
	FILE *file;
	int count;

	count = snprintf(path, sizeof(path), "%s/%s", directory, name);
	assert(count > 0 && (size_t)count < sizeof(path));
	file = fopen(path, "rb");
	assert(file != NULL);
	return file;
}

static uint8_t *
load(const char *directory, const char *name, size_t wanted)
{
	FILE *file;
	uint8_t *data;

	file = open_file(directory, name);
	data = malloc(wanted == 0 ? 1 : wanted);
	assert(data != NULL && fread(data, 1, wanted, file) == wanted);
	assert(fgetc(file) == EOF && !ferror(file) && fclose(file) == 0);
	return data;
}

static void
test_load(const char *directory, struct test_case *test)
{
	FILE *file;
	char code[TEST_NAME_BYTES];
	unsigned key, attribute, names, name[NTFS_WRITE_MUTATION_TARGET_NAME_UNITS];
	uint64_t reference, physical, logical;
	size_t index;

	memset(test, 0, sizeof(*test));
	file = open_file(directory, "expected.txt");
	assert(fscanf(file, "%127s %zu %u %" SCNu64 " %" SCNu64 " %" SCNu64 " %u %u %u %u %u %u",
		   code, &test->count, &key, &reference, &physical, &logical, &attribute, &names,
		   &name[0], &name[1], &name[2], &name[3]) == 12);
	assert(fclose(file) == 0 && key <= UINT16_MAX &&
	    names <= NTFS_WRITE_MUTATION_TARGET_NAME_UNITS);
	test->key = (uint16_t)key;
	test->result = strcmp(code, "success") == 0 ? NTFS_OK : NTFS_RANGE;
	test->before = load(directory, "before.bin", NTFS_WRITE_CLUSTER_BYTES);
	test->after = load(directory, "after.bin", NTFS_WRITE_CLUSTER_BYTES);
	test->goldens =
	    load(directory, "payloads.bin", test->count * NTFS_WRITE_BITMAP_PAYLOAD_BYTES);
	test->region.physical = physical;
	test->region.before = test->before;
	test->region.after = test->after;
	test->region.bytes = NTFS_WRITE_CLUSTER_BYTES;
	test->region.kind = NTFS_WRITE_MUTATION_BITMAP;
	test->region.target.reference = reference;
	test->region.target.logical_offset = logical;
	test->region.target.attribute_type = attribute;
	test->region.target.name_count = names;
	for (index = 0; index < NTFS_WRITE_MUTATION_TARGET_NAME_UNITS; index++) {
		test->region.target.name[index] = (uint16_t)name[index];
	}
}

static void
verify(struct test_case *test, struct ntfs_write_bitmap_program *program)
{
	const struct ntfs_logfile_buffer *payload;
	struct ntfs_logfile_update update;
	uint8_t *image;
	size_t index;

	assert(ntfs_write_bitmap_program_count(program) == test->count);
	assert(ntfs_write_bitmap_program_get(program, test->count) == NULL);
	image = malloc(NTFS_WRITE_CLUSTER_BYTES);
	assert(image != NULL);
	memcpy(image, test->before, NTFS_WRITE_CLUSTER_BYTES);
	for (index = 0; index < test->count; index++) {
		payload = ntfs_write_bitmap_program_get(program, index);
		assert(payload != NULL && payload->bytes == NTFS_WRITE_BITMAP_PAYLOAD_BYTES);
		assert(memcmp(payload->data, test->goldens + index * payload->bytes,
			   payload->bytes) == 0);
		assert(
		    ntfs_logfile_update_decode(payload->data, payload->bytes, &update) == NTFS_OK);
		assert(update.target_attribute == test->key && update.attribute_flags == 0 &&
		    update.target_vcn ==
			test->region.target.logical_offset / NTFS_WRITE_CLUSTER_BYTES);
		assert(ntfs_write_bitmap_apply(payload->data, payload->bytes, false, image,
			   NTFS_WRITE_CLUSTER_BYTES) == NTFS_OK);
	}
	assert(memcmp(image, test->after, NTFS_WRITE_CLUSTER_BYTES) == 0);
	for (index = 0; index < test->count; index++) {
		payload = ntfs_write_bitmap_program_get(program, index);
		assert(ntfs_write_bitmap_apply(payload->data, payload->bytes, false, image,
			   NTFS_WRITE_CLUSTER_BYTES) == NTFS_OK);
	}
	assert(memcmp(image, test->after, NTFS_WRITE_CLUSTER_BYTES) == 0);
	for (index = test->count; index != 0; index--) {
		payload = ntfs_write_bitmap_program_get(program, index - 1);
		assert(ntfs_write_bitmap_apply(payload->data, payload->bytes, true, image,
			   NTFS_WRITE_CLUSTER_BYTES) == NTFS_OK);
	}
	assert(memcmp(image, test->before, NTFS_WRITE_CLUSTER_BYTES) == 0);
	free(image);
}

static void
apply_errors(const struct test_case *test, const struct ntfs_write_bitmap_program *program)
{
	const struct ntfs_logfile_buffer *payload;
	struct ntfs_disk_log_update *header;
	struct ntfs_disk_log_bitmap_range *range;
	uint8_t *bytes, *image;
	size_t index;

	if (test->count == 0) {
		return;
	}
	payload = ntfs_write_bitmap_program_get(program, 0);
	bytes = malloc(payload->bytes);
	image = malloc(NTFS_WRITE_CLUSTER_BYTES);
	assert(bytes != NULL && image != NULL);
	for (index = 0; index < payload->bytes; index++) {
		memcpy(image, test->before, NTFS_WRITE_CLUSTER_BYTES);
		assert(ntfs_write_bitmap_apply(payload->data, index, false, image,
			   NTFS_WRITE_CLUSTER_BYTES) != NTFS_OK);
		assert(memcmp(image, test->before, NTFS_WRITE_CLUSTER_BYTES) == 0);
	}
	memcpy(bytes, payload->data, payload->bytes);
	header = (void *)bytes;
	ntfs_put_u16(header->redo_operation, NTFS_LOG_OP_UPDATE_RESIDENT_VALUE);
	assert(ntfs_write_bitmap_apply(bytes, payload->bytes, false, image,
		   NTFS_WRITE_CLUSTER_BYTES) == NTFS_UNSUPPORTED);
	assert(memcmp(image, test->before, NTFS_WRITE_CLUSTER_BYTES) == 0);
	memcpy(bytes, payload->data, payload->bytes);
	range = (void *)(bytes + ntfs_u16(header->redo_offset));
	ntfs_put_u32(range->bits, 0);
	assert(ntfs_write_bitmap_apply(
		   bytes, payload->bytes, false, image, NTFS_WRITE_CLUSTER_BYTES) == NTFS_CORRUPT);
	assert(memcmp(image, test->before, NTFS_WRITE_CLUSTER_BYTES) == 0);
	memcpy(bytes, payload->data, payload->bytes);
	range = (void *)(bytes + ntfs_u16(header->redo_offset));
	ntfs_put_u32(range->first, NTFS_WRITE_CLUSTER_BYTES * NTFS_BITS_PER_BYTE);
	assert(ntfs_write_bitmap_apply(
		   bytes, payload->bytes, false, image, NTFS_WRITE_CLUSTER_BYTES) == NTFS_CORRUPT);
	assert(memcmp(image, test->before, NTFS_WRITE_CLUSTER_BYTES) == 0);
	memcpy(bytes, payload->data, payload->bytes);
	assert(ntfs_write_bitmap_apply(
		   bytes, payload->bytes, false, bytes, NTFS_WRITE_CLUSTER_BYTES) == NTFS_INVALID);
	assert(memcmp(bytes, payload->data, payload->bytes) == 0);
	free(bytes);
	free(image);
}

static void
run_case(const char *directory, size_t *steps)
{
	struct test_case test;
	struct tracker tracker = {0};
	struct ntfs_environment source = {
	    NTFS_API_VERSION, &tracker, 0, refuse_read, allocate, release};
	struct ntfs_write_bitmap_program *program = NULL, *failed;
	struct ntfs_write_mutation_region invalid;
	size_t allocations, fail;
	enum ntfs_result result;

	test_load(directory, &test);
	result = ntfs_write_bitmap_program_prepare(&source, &test.region, test.key, &program);
	assert(result == test.result && tracker.reads == 0);
	if (result == NTFS_OK) {
		assert(program != NULL);
		verify(&test, program);
		apply_errors(&test, program);
		memset(test.before, TEST_SENTINEL, NTFS_WRITE_CLUSTER_BYTES);
		memset(test.after, TEST_SENTINEL, NTFS_WRITE_CLUSTER_BYTES);
		for (fail = 0; fail < test.count; fail++) {
			const struct ntfs_logfile_buffer *payload;

			payload = ntfs_write_bitmap_program_get(program, fail);
			assert(memcmp(payload->data, test.goldens + fail * payload->bytes,
				   payload->bytes) == 0);
		}
		*steps += test.count;
	}
	allocations = tracker.allocations;
	ntfs_write_bitmap_program_close(program);
	assert(tracker.live == 0);
	free(test.before);
	free(test.after);
	free(test.goldens);
	test_load(directory, &test);
	for (fail = 1; fail <= allocations; fail++) {
		memset(&tracker, 0, sizeof(tracker));
		tracker.fail = fail;
		failed = (void *)(uintptr_t)TEST_SENTINEL;
		assert(ntfs_write_bitmap_program_prepare(
			   &source, &test.region, test.key, &failed) == NTFS_NO_MEMORY);
		assert(failed == NULL && tracker.live == 0 && tracker.reads == 0);
		tracker.fail = 0;
		assert(ntfs_write_bitmap_program_prepare(
			   &source, &test.region, test.key, &failed) == NTFS_OK);
		verify(&test, failed);
		ntfs_write_bitmap_program_close(failed);
		assert(tracker.live == 0);
	}
	invalid = test.region;
	invalid.target.mirror = true;
	failed = (void *)(uintptr_t)TEST_SENTINEL;
	assert(ntfs_write_bitmap_program_prepare(&source, &invalid, test.key, &failed) ==
	    NTFS_UNSUPPORTED);
	assert(failed == NULL && tracker.live == 0);
	invalid = test.region;
	invalid.target.reference &= NTFS_REFERENCE_RECORD_MASK;
	assert(ntfs_write_bitmap_program_prepare(&source, &invalid, test.key, &failed) ==
	    NTFS_INVALID);
	assert(failed == NULL);
	invalid = test.region;
	invalid.target.logical_offset++;
	assert(ntfs_write_bitmap_program_prepare(&source, &invalid, test.key, &failed) ==
	    NTFS_INVALID);
	assert(failed == NULL);
	assert(
	    ntfs_write_bitmap_program_prepare(&source, &test.region, test.key,
		(void *)(test.before + NTFS_WRITE_CLUSTER_BYTES - sizeof(failed))) == NTFS_INVALID);
	invalid = test.region;
	invalid.before = (void *)(UINTPTR_MAX - NTFS_WRITE_CLUSTER_BYTES + 2u);
	failed = (void *)(uintptr_t)TEST_SENTINEL;
	assert(ntfs_write_bitmap_program_prepare(&source, &invalid, test.key, &failed) ==
	    NTFS_INVALID);
	assert(failed == (void *)(uintptr_t)TEST_SENTINEL && tracker.live == 0);
	free(test.before);
	free(test.after);
	free(test.goldens);
}

static void
native_cases(const char *directory, size_t *cases)
{
	FILE *rows, *file;
	char name[TEST_NAME_BYTES], path[TEST_PATH_BYTES];
	uint8_t *payload, *original, *before, *after, *image;
	long bytes;
	int length;

	rows = open_file(directory, "cases.rows");
	while (fscanf(rows, "%127s", name) == 1) {
		length = snprintf(path, sizeof(path), "%s/%s", directory, name);
		assert(length > 0 && (size_t)length < sizeof(path));
		file = open_file(path, "payload.bin");
		assert(fseek(file, 0, SEEK_END) == 0);
		bytes = ftell(file);
		assert(bytes > 0 && bytes <= NTFS_WRITE_BITMAP_PAYLOAD_BYTES);
		assert(fclose(file) == 0);
		payload = load(path, "payload.bin", (size_t)bytes);
		original = load(path, "payload.bin", (size_t)bytes);
		before = load(path, "before.bin", NTFS_WRITE_CLUSTER_BYTES);
		after = load(path, "after.bin", NTFS_WRITE_CLUSTER_BYTES);
		image = malloc(NTFS_WRITE_CLUSTER_BYTES);
		assert(image != NULL);
		memcpy(image, before, NTFS_WRITE_CLUSTER_BYTES);
		assert(ntfs_write_bitmap_apply(payload, (size_t)bytes, false, image,
			   NTFS_WRITE_CLUSTER_BYTES) == NTFS_OK);
		assert(memcmp(image, after, NTFS_WRITE_CLUSTER_BYTES) == 0);
		assert(ntfs_write_bitmap_apply(payload, (size_t)bytes, false, image,
			   NTFS_WRITE_CLUSTER_BYTES) == NTFS_OK);
		assert(memcmp(image, after, NTFS_WRITE_CLUSTER_BYTES) == 0);
		assert(ntfs_write_bitmap_apply(payload, (size_t)bytes, true, image,
			   NTFS_WRITE_CLUSTER_BYTES) == NTFS_OK);
		assert(memcmp(image, before, NTFS_WRITE_CLUSTER_BYTES) == 0);
		assert(memcmp(payload, original, (size_t)bytes) == 0);
		free(payload);
		free(original);
		free(before);
		free(after);
		free(image);
		(*cases)++;
	}
	assert(!ferror(rows) && fclose(rows) == 0);
}

int
main(int argc, char **argv)
{
	FILE *rows;
	char name[TEST_NAME_BYTES], path[TEST_PATH_BYTES];
	size_t cases = 0, steps = 0, native = 0;
	int length;

	assert(argc == 2 || argc == 3);
	rows = open_file(argv[1], "cases.rows");
	while (fscanf(rows, "%127s", name) == 1) {
		length = snprintf(path, sizeof(path), "%s/%s", argv[1], name);
		assert(length > 0 && (size_t)length < sizeof(path));
		run_case(path, &steps);
		cases++;
	}
	assert(!ferror(rows) && fclose(rows) == 0 && cases > 0);
	if (argc == 3) {
		native_cases(argv[2], &native);
	}
	printf("PASS %zu bitmap programs, %zu exact native payloads, redo/undo/idempotence and "
	       "preparation refusals\n",
	    cases, steps);
	printf("PASS %zu original native range payloads applied to private logical bytes; no "
	       "native execution admission\n",
	    native);
	return 0;
}
