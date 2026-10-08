/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_mutation.h"
#include "write_program.h"
#include "write_owner_internal.h"
#include "fuzz_device.h"
#include <ntfs/record.h>
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_PATH_BYTES = 4096,
	TEST_NAME_BYTES = 128,
	TEST_RECORD_BYTES = 1024,
	TEST_PROGRAM_UPDATES = 2
};
#define TEST_CHANGED UINT64_C(134357146906613431)
#define TEST_ACCESSED UINT64_C(134357146900000007)

struct test_device {
	struct fuzz_device device;
	bool partial;
};

static size_t program_allocation_failures;

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

static enum ntfs_result
read_image(void *context, uint64_t offset, void *memory, size_t bytes)
{
	struct test_device *test = context;
	enum ntfs_result result;

	result = fuzz_read(&test->device, offset, memory, bytes);
	if (result != NTFS_OK && test->partial && offset <= test->device.size &&
	    bytes <= test->device.size - offset) {
		memcpy(memory, test->device.data + offset, bytes / 2);
	}
	return result;
}

static struct ntfs_environment
environment(struct test_device *test)
{
	struct ntfs_environment env = fuzz_environment(&test->device);

	/* device is the first member, so allocator callbacks share this address. */
	env.context = test;
	env.read = read_image;
	return env;
}

static void
normalize_record(uint8_t *actual, const uint8_t *expected, bool lsn)
{
	const struct ntfs_disk_record *header = (const void *)expected;
	struct ntfs_disk_record *result = (void *)actual;
	size_t usa = ntfs_u16(header->mst.usa_offset);
	size_t bytes = ntfs_u16(header->mst.usa_count) * NTFS_MST_WORD_BYTES;

	assert(ntfs_bounds(usa, bytes, TEST_RECORD_BYTES));
	assert(memcmp(&result->mst, &header->mst, sizeof(header->mst)) == 0);
	memcpy(actual + usa, expected + usa, bytes);
	if (lsn) {
		memcpy(result->lsn, header->lsn, sizeof(header->lsn));
	}
}

static void
decode_region(const struct ntfs_write_mutation_region *region, const void *source, uint8_t *out)
{
	size_t offset;

	memcpy(out, source, region->bytes);
	for (offset = 0; offset < region->bytes; offset += TEST_RECORD_BYTES) {
		if ((region->predecessor.file_slots & (1u << (offset / TEST_RECORD_BYTES))) != 0) {
			assert(ntfs_record_decode(out + offset, TEST_RECORD_BYTES, false) == NTFS_OK);
		}
	}
}

static void
check_program(const struct ntfs_environment *env, struct ntfs_write_mutation_plan *plan,
    uint64_t physical, const uint8_t *expected)
{
	struct ntfs_write_program *program = NULL;
	struct ntfs_write_program *failed;
	struct ntfs_write_mutation_region region;
	struct test_device *test = env->context;
	uint8_t *logical, *original, *final;
	size_t offset, prefix, index, allocations, reads, retained;
	size_t bytes = NTFS_WRITE_CLUSTER_BYTES;

	allocations = test->device.allocations;
	reads = test->device.reads;
	assert(ntfs_write_program_prepare(env, plan, &program) == NTFS_OK);
	allocations = test->device.allocations - allocations;
	retained = test->device.memory;
	for (index = 1; index <= allocations; index++) {
		test->device.fail_allocation = test->device.allocations + index;
		failed = (void *)(uintptr_t)1;
		assert(ntfs_write_program_prepare(env, plan, &failed) == NTFS_NO_MEMORY);
		assert(failed == NULL && test->device.memory == retained);
		assert(test->device.reads == reads);
		program_allocation_failures++;
	}
	test->device.fail_allocation = 0;
	/* The existing FILE compiler first logs its complete predecessor/inverse,
	 * then publishes the changed FILE. Every complete prefix must be undoable. */
	assert(ntfs_write_program_count(program) == TEST_PROGRAM_UPDATES &&
	    ntfs_write_program_regions(program) == 1);
	ntfs_write_mutation_plan_close(plan);
	assert(ntfs_write_program_region(program, 0, &region) == NTFS_OK);
	assert(region.kind == NTFS_WRITE_MUTATION_FILE && !region.target.mirror);
	assert(region.bytes == bytes && physical >= region.physical);
	offset = (size_t)(physical - region.physical);
	assert(ntfs_bounds(offset, TEST_RECORD_BYTES, bytes));
	logical = malloc(bytes);
	original = malloc(bytes);
	final = malloc(bytes);
	assert(logical != NULL && original != NULL && final != NULL);
	decode_region(&region, region.before, original);
	decode_region(&region, region.after, final);
	normalize_record(final + offset, expected, false);
	assert(memcmp(final + offset, expected, TEST_RECORD_BYTES) == 0);
	for (prefix = 0; prefix <= TEST_PROGRAM_UPDATES; prefix++) {
		memcpy(logical, original, bytes);
		for (index = 0; index < prefix; index++) {
			assert(ntfs_write_program_apply(program, index, false, 100001 + index,
				   logical, bytes) == NTFS_OK);
		}
		normalize_record(logical + offset,
		    (prefix == TEST_PROGRAM_UPDATES ? final : original) + offset, true);
		assert(memcmp(logical, prefix == TEST_PROGRAM_UPDATES ? final : original,
			   bytes) == 0);
		for (index = prefix; index != 0; index--) {
			assert(ntfs_write_program_apply(program, index - 1, true, 100003 + index,
				   logical, bytes) == NTFS_OK);
		}
		normalize_record(logical + offset, original + offset, true);
		assert(memcmp(logical, original, bytes) == 0);
	}
	ntfs_write_program_close(program);
	free(final);
	free(original);
	free(logical);
}

static void
check_case(const uint8_t *image, size_t bytes, uint64_t reference, uint64_t physical,
    unsigned mask, const uint8_t *expected)
{
	struct test_device test = {{.data = image, .size = bytes}, false};
	struct ntfs_environment env = environment(&test), view;
	struct ntfs_write_mutation_request request = {.kind = NTFS_WRITE_SET_TIMES,
	    .reference = reference,
	    .times = {0, INT64_MAX, TEST_CHANGED, TEST_ACCESSED, mask}};
	struct ntfs_write_mutation_request saved = request;
	struct ntfs_write_mutation_plan *plan = NULL;
	struct ntfs_write_mutation_region region;
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *node = NULL;
	struct ntfs_stat stat;
	uint8_t record[TEST_RECORD_BYTES];
	size_t offset;

	assert(ntfs_write_mutation_prepare(&env, &request, &plan) == NTFS_OK);
	assert(memcmp(&request, &saved, sizeof(request)) == 0);
	assert(ntfs_write_mutation_plan_reference(plan) == reference);
	assert(ntfs_write_mutation_plan_count(plan) == (mask == 0 ? 0 : 1));
	assert(ntfs_write_mutation_plan_view(plan, &view) == NTFS_OK);
	assert(view.read(view.context, physical, record, sizeof(record)) == NTFS_OK);
	assert(ntfs_record_decode(record, sizeof(record), false) == NTFS_OK);
	normalize_record(record, expected, false);
	assert(memcmp(record, expected, sizeof(record)) == 0);
	assert(ntfs_mount(&view, NULL, &volume) == NTFS_OK);
	assert(ntfs_node_open(volume, reference, &node) == NTFS_OK);
	assert(ntfs_node_stat(node, &stat) == NTFS_OK && stat.reference == reference);
	ntfs_node_close(node);
	ntfs_unmount(volume);
	if (mask != 0) {
		assert(ntfs_write_mutation_plan_region(plan, 0, &region) == NTFS_OK);
		assert(memcmp(region.before, image + region.physical, region.bytes) == 0);
		offset = (size_t)(physical - region.physical);
		assert(offset + TEST_RECORD_BYTES <= region.bytes);
		assert(memcmp(region.before, region.after, offset) == 0);
		assert(memcmp(region.before + offset + TEST_RECORD_BYTES,
			   region.after + offset + TEST_RECORD_BYTES,
			   region.bytes - offset - TEST_RECORD_BYTES) == 0);
		check_program(&env, plan, physical, expected);
	} else {
		ntfs_write_mutation_plan_close(plan);
	}
	assert(test.device.memory == 0);
}

static void
check_faults(const uint8_t *image, size_t bytes, uint64_t reference)
{
	struct test_device test = {{.data = image, .size = bytes}, false};
	struct ntfs_environment env = environment(&test);
	struct ntfs_write_mutation_request request = {.kind = NTFS_WRITE_SET_TIMES,
	    .reference = reference,
	    .times = {0, INT64_MAX, TEST_CHANGED, TEST_ACCESSED, NTFS_WRITE_TIME_ALL}};
	struct ntfs_write_mutation_plan *plan = NULL;
	enum ntfs_result result;
	size_t allocations, reads, index;
	unsigned partial;

	assert(ntfs_write_mutation_prepare(&env, &request, &plan) == NTFS_OK);
	allocations = test.device.allocations;
	reads = test.device.reads;
	ntfs_write_mutation_plan_close(plan);
	assert(test.device.memory == 0);
	for (index = 1; index <= allocations; index++) {
		test.device.allocations = test.device.reads = 0;
		test.device.fail_allocation = index;
		plan = (void *)(uintptr_t)1;
		result = ntfs_write_mutation_prepare(&env, &request, &plan);
		assert(result == NTFS_NO_MEMORY && plan == NULL && test.device.memory == 0);
	}
	test.device.fail_allocation = 0;
	for (partial = 0; partial != 2; partial++) {
		test.partial = partial != 0;
		for (index = 1; index <= reads; index++) {
			test.device.allocations = test.device.reads = 0;
			test.device.fail_read = index;
			plan = (void *)(uintptr_t)1;
			result = ntfs_write_mutation_prepare(&env, &request, &plan);
			assert(result == NTFS_IO && plan == NULL && test.device.memory == 0);
		}
	}
	test.device.fail_read = 0;
	test.device.reads = 0;
	assert(ntfs_write_mutation_prepare(&env, &request, &plan) == NTFS_OK);
	ntfs_write_mutation_plan_close(plan);
	assert(test.device.memory == 0);
	printf("timestamp preparation: %zu allocation and %zu full/partial read faults\n",
	    allocations, reads * 2);
}

static void
check_admission(const uint8_t *image, size_t bytes, uint64_t reference, uint64_t physical)
{
	struct test_device test = {{.data = image, .size = bytes}, false};
	struct ntfs_environment env = environment(&test);
	struct ntfs_write_mutation_request request = {.kind = NTFS_WRITE_SET_TIMES,
	    .reference = reference,
	    .times = {0, INT64_MAX, TEST_CHANGED, TEST_ACCESSED, NTFS_WRITE_TIME_ALL}};
	struct ntfs_write_mutation_request invalid;
	struct ntfs_write_mutation_request saved;
	struct ntfs_environment saved_env;
	struct ntfs_write_mutation_plan *plan = NULL;
	struct ntfs_write_mutation_execution *execution = (void *)(uintptr_t)1;
	struct ntfs_overwrite owner = {.reader = env, .mutations = true};
	struct ntfs_attr_view attribute;
	const struct ntfs_disk_standard *standard;
	const uint8_t *value;
	uint8_t record[TEST_RECORD_BYTES];
	size_t length, index;
	uint64_t *selected;

	assert(ntfs_write_mutation_execution_prepare(&owner, &request, &execution) ==
	    NTFS_UNSUPPORTED);
	assert(execution == NULL && owner.mutation == NULL);
	assert(test.device.reads == 0 && test.device.allocations == 0);
	saved = request;
	assert(ntfs_write_mutation_prepare(&env, &request, (void *)&request) == NTFS_INVALID);
	assert(memcmp(&request, &saved, sizeof(request)) == 0);
	saved_env = env;
	assert(ntfs_write_mutation_prepare(&env, &request, (void *)&env) == NTFS_INVALID);
	assert(memcmp(&env, &saved_env, sizeof(env)) == 0);
	for (index = 0; index < 6; index++) {
		invalid = request;
		if (index < 4) {
			selected = index == 0 ? &invalid.times.created
					     : index == 1 ? &invalid.times.modified
							  : index == 2 ? &invalid.times.changed
								       : &invalid.times.accessed;
			*selected = (uint64_t)INT64_MAX + 1;
		} else if (index == 4) {
			invalid.times.fields = UINT32_MAX;
		} else {
			invalid.reference &= NTFS_REFERENCE_RECORD_MASK;
		}
		assert(ntfs_write_mutation_prepare(&env, &invalid, &plan) == NTFS_INVALID);
		assert(plan == NULL && test.device.reads == 0 && test.device.allocations == 0);
	}
	invalid = request;
	invalid.times.fields = 0;
	invalid.times.created = invalid.times.modified = invalid.times.changed =
	    invalid.times.accessed = UINT64_MAX;
	assert(ntfs_write_mutation_prepare(&env, &invalid, &plan) == NTFS_OK);
	assert(ntfs_write_mutation_plan_count(plan) == 0);
	ntfs_write_mutation_plan_close(plan);
	invalid.reference ^= UINT64_C(1) << NTFS_REFERENCE_SEQUENCE_SHIFT;
	assert(ntfs_write_mutation_prepare(&env, &invalid, &plan) == NTFS_STALE && plan == NULL);
	memcpy(record, image + physical, sizeof(record));
	assert(ntfs_record_decode(record, sizeof(record), false) == NTFS_OK);
	assert(ntfs_attr_find(record, sizeof(record), NTFS_ATTR_STANDARD, NULL, 0, UINT16_MAX,
		   &attribute) == NTFS_OK);
	assert(ntfs_attr_value(&attribute, &value, &length) == NTFS_OK);
	assert(length == NTFS_WRITE_STANDARD_BYTES);
	standard = (const void *)value;
	request.times = (struct ntfs_write_times){ntfs_u64(standard->created),
	    ntfs_u64(standard->modified), ntfs_u64(standard->changed),
	    ntfs_u64(standard->accessed), NTFS_WRITE_TIME_ALL};
	assert(ntfs_write_mutation_prepare(&env, &request, &plan) == NTFS_OK);
	assert(ntfs_write_mutation_plan_count(plan) == 0);
	ntfs_write_mutation_plan_close(plan);
	assert(test.device.memory == 0);
}

static void
check_unsupported(const char *directory)
{
	char path[TEST_PATH_BYTES], source[TEST_NAME_BYTES];
	FILE *manifest;
	uint8_t *image, *saved;
	size_t bytes, cases = 0;
	uint64_t reference;
	int count;
	struct test_device test;
	struct ntfs_environment env;
	struct ntfs_write_mutation_request request = {.kind = NTFS_WRITE_SET_TIMES,
	    .times = {.changed = TEST_CHANGED, .fields = NTFS_WRITE_TIME_CHANGED}};
	struct ntfs_write_mutation_plan *plan;

	count = snprintf(path, sizeof(path), "%s/refusals.txt", directory);
	assert(count > 0 && (size_t)count < sizeof(path));
	manifest = fopen(path, "r");
	assert(manifest != NULL);
	while (fscanf(manifest, "%127s %" SCNu64, source, &reference) == 2) {
		image = load(directory, source, &bytes);
		saved = malloc(bytes);
		assert(saved != NULL);
		memcpy(saved, image, bytes);
		test = (struct test_device){{.data = image, .size = bytes}, false};
		env = environment(&test);
		request.reference = reference;
		plan = (void *)(uintptr_t)1;
		assert(ntfs_write_mutation_prepare(&env, &request, &plan) == NTFS_UNSUPPORTED);
		assert(plan == NULL && test.device.memory == 0);
		assert(memcmp(saved, image, bytes) == 0);
		free(saved);
		free(image);
		cases++;
	}
	assert(feof(manifest) && !ferror(manifest) && fclose(manifest) == 0);
	assert(cases == 9);
}

int
main(int argc, char **argv)
{
	char path[TEST_PATH_BYTES], source[TEST_NAME_BYTES], expected_name[TEST_NAME_BYTES];
	FILE *manifest;
	uint8_t *image, *saved, *expected;
	size_t bytes, expected_bytes, cases = 0;
	uint64_t reference, physical;
	unsigned fields;
	int count;

	assert(argc == 2);
	count = snprintf(path, sizeof(path), "%s/cases.txt", argv[1]);
	assert(count > 0 && (size_t)count < sizeof(path));
	manifest = fopen(path, "r");
	assert(manifest != NULL);
	while (fscanf(manifest, "%127s %" SCNu64 " %" SCNu64 " %u %127s", source, &reference,
		   &physical, &fields, expected_name) == 5) {
		image = load(argv[1], source, &bytes);
		expected = load(argv[1], expected_name, &expected_bytes);
		assert(expected_bytes == TEST_RECORD_BYTES && physical + expected_bytes <= bytes);
		saved = malloc(bytes);
		assert(saved != NULL);
		memcpy(saved, image, bytes);
		check_case(image, bytes, reference, physical, fields, expected);
		if (fields == NTFS_WRITE_TIME_ALL) {
			check_admission(image, bytes, reference, physical);
			check_faults(image, bytes, reference);
		}
		assert(memcmp(saved, image, bytes) == 0);
		free(saved);
		free(expected);
		free(image);
		cases++;
	}
	assert(feof(manifest) && !ferror(manifest) && fclose(manifest) == 0);
	assert(cases == 48);
	check_unsupported(argv[1]);
	printf("timestamp compiler: %zu allocation failures retain the plan and prior program\n",
	    program_allocation_failures);
	puts("48 independent SI timestamp plans, exact unaffected bytes, owned redo/undo, "
	     "no-ops, stale references, boundaries, aliases, nine unsupported profiles "
	     "and execution refusal passed");
	return 0;
}
