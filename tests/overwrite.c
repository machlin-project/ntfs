/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/overwrite.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_CLUSTER_BYTES = 4096,
	TEST_RECORD_BYTES = 1024,
	TEST_DATA_BYTES = 6000,
	TEST_FIRST_LCN = 128,
	TEST_SECOND_LCN = 130,
	TEST_DATA_RECORD = 25,
	TEST_RESIDENT_RECORD = 24,
	TEST_REFERENCE_SHIFT = 48,
	TEST_FILE_SEQUENCE = 7,
	TEST_PATCH_OFFSET = 3997,
	TEST_PATCH_BYTES = 1023,
	TEST_CASE_NAME_BYTES = 64,
	TEST_PATCH_MULTIPLIER = 19,
	TEST_PATCH_ADDEND = 5,
	TEST_BYTE_MODULUS = 251,
	TEST_MAX_MEMORY = 64 * 1024 * 1024,
	TEST_WRITE_FAILURE_KINDS = 5
};

struct test_device {
	uint8_t *image;
	size_t bytes, memory, allocations, live_allocations, owner_bytes;
	size_t reads, writes, barriers, claims, unclaims;
	size_t fail_allocate, fail_read, fail_write, fail_barrier, failed_allocate_bytes;
	unsigned write_failure_kind;
	bool claimed, fail_claim, full_read_failure;
};

static void *
allocate(void *context, size_t bytes)
{
	struct test_device *device = context;
	void *buffer;

	device->allocations++;
	if (device->fail_allocate == device->allocations ||
	    bytes > TEST_MAX_MEMORY - device->memory) {
		device->failed_allocate_bytes = bytes;
		return NULL;
	}
	buffer = malloc(bytes);
	assert(buffer != NULL);
	device->memory += bytes;
	device->live_allocations++;
	if (device->live_allocations == 1) {
		device->owner_bytes = bytes;
	}
	return buffer;
}

static void
release(void *context, void *buffer, size_t bytes)
{
	struct test_device *device = context;

	assert(device->memory >= bytes && device->live_allocations != 0);
	device->memory -= bytes;
	device->live_allocations--;
	free(buffer);
}

static enum ntfs_result
claim(void *context)
{
	struct test_device *device = context;

	device->claims++;
	if (device->fail_claim || device->claimed) {
		return NTFS_BUSY;
	}
	device->claimed = true;
	return NTFS_OK;
}

static void
unclaim(void *context)
{
	struct test_device *device = context;

	assert(device->claimed);
	device->claimed = false;
	device->unclaims++;
}

static enum ntfs_result
read_image(void *context, uint64_t offset, void *buffer, size_t bytes)
{
	struct test_device *device = context;

	assert(device->claimed && offset <= device->bytes && bytes <= device->bytes - offset);
	device->reads++;
	if (device->fail_read == device->reads) {
		memcpy(
		    buffer, device->image + offset, device->full_read_failure ? bytes : bytes / 2);
		return NTFS_IO;
	}
	memcpy(buffer, device->image + offset, bytes);
	return NTFS_OK;
}

static enum ntfs_result
write_image(void *context, uint64_t offset, const void *buffer, size_t bytes, size_t *actual)
{
	struct test_device *device = context;

	assert(device->claimed && device->live_allocations == 3);
	assert(offset <= device->bytes && bytes <= device->bytes - offset);
	assert(offset % NTFS_OVERWRITE_MIN_ALIGNMENT == 0 &&
	    bytes % NTFS_OVERWRITE_MIN_ALIGNMENT == 0 &&
	    (uintptr_t)buffer % NTFS_OVERWRITE_MIN_ALIGNMENT == 0);
	device->writes++;
	if (device->fail_write == device->writes) {
		if (device->write_failure_kind == 0) {
			*actual = 0;
			return NTFS_IO;
		}
		*actual = device->write_failure_kind == 1 ? bytes / 2 : bytes;
		memcpy(device->image + offset, buffer, *actual);
		if (device->write_failure_kind == 3) {
			*actual = bytes / 2;
			return NTFS_OK;
		}
		if (device->write_failure_kind == 4) {
			*actual = bytes + 1;
			return NTFS_OK;
		}
		return NTFS_IO;
	}
	memcpy(device->image + offset, buffer, bytes);
	*actual = bytes;
	return NTFS_OK;
}

static enum ntfs_result
persist(void *context)
{
	struct test_device *device = context;

	assert(device->claimed && (device->live_allocations == 1 || device->live_allocations == 3));
	device->barriers++;
	return device->fail_barrier == device->barriers ? NTFS_IO : NTFS_OK;
}

static struct ntfs_overwrite_environment
environment(struct test_device *device)
{
	struct ntfs_overwrite_environment value = {
	    {NTFS_API_VERSION, device, device->bytes, read_image, allocate, release},
	    NTFS_OVERWRITE_API_VERSION, NTFS_OVERWRITE_MIN_ALIGNMENT, claim, unclaim, write_image,
	    persist};

	return value;
}

static void
load(const char *directory, const char *name, struct test_device *device)
{
	char *path;
	FILE *input;
	long bytes;
	size_t length = strlen(directory) + strlen(name) + sizeof("/");

	path = malloc(length);
	assert(path != NULL);
	assert(snprintf(path, length, "%s/%s", directory, name) > 0);
	input = fopen(path, "rb");
	assert(input != NULL && fseek(input, 0, SEEK_END) == 0);
	bytes = ftell(input);
	assert(bytes > 0 && fseek(input, 0, SEEK_SET) == 0);
	*device = (struct test_device){.bytes = (size_t)bytes};
	device->image = malloc(device->bytes);
	assert(device->image != NULL);
	assert(fread(device->image, 1, device->bytes, input) == device->bytes);
	assert(fclose(input) == 0);
	free(path);
}

static void
reset(struct test_device *device, const uint8_t *original)
{
	uint8_t *image = device->image;
	size_t bytes = device->bytes;

	assert(device->memory == 0 && !device->claimed && device->live_allocations == 0);
	*device = (struct test_device){.image = image, .bytes = bytes};
	memcpy(image, original, bytes);
}

static struct ntfs_overwrite *
open_owner(struct test_device *device)
{
	struct ntfs_overwrite_environment env = environment(device);
	struct ntfs_overwrite_admission admission;
	struct ntfs_overwrite *owner = NULL;

	assert(ntfs_overwrite_open(&env, &admission, &owner) == NTFS_OK && owner != NULL);
	assert(admission.claimed && admission.validation.complete && admission.quiescent &&
	    admission.persistence_succeeded && device->barriers == 1);
	assert(device->live_allocations == 1 && device->memory == device->owner_bytes);
	return owner;
}

static uint64_t
file_reference(unsigned number)
{
	return ((uint64_t)TEST_FILE_SEQUENCE << TEST_REFERENCE_SHIFT) | number;
}

static void
expected_patch(uint8_t *expected, uint64_t offset, const uint8_t *patch, size_t bytes)
{
	uint64_t physical;
	size_t ordinal;

	for (ordinal = 0; ordinal < bytes; ordinal++) {
		physical = offset + ordinal < TEST_CLUSTER_BYTES
		    ? TEST_FIRST_LCN * TEST_CLUSTER_BYTES + offset + ordinal
		    : TEST_SECOND_LCN * TEST_CLUSTER_BYTES + offset + ordinal - TEST_CLUSTER_BYTES;
		expected[physical] = patch[ordinal];
	}
}

static void
assert_closed(struct test_device *device)
{
	assert(!device->claimed && device->memory == 0 && device->live_allocations == 0 &&
	    device->unclaims == 1);
}

static void
poisoned_owner(struct test_device *device, struct ntfs_overwrite *owner, const uint8_t *patch)
{
	static const uint16_t path[] = {
	    '/', 'f', 'r', 'a', 'g', 'm', 'e', 'n', 't', 'e', 'd', '.', 'b', 'i', 'n'};
	struct ntfs_overwrite_report report;
	uint64_t reference;
	size_t reads = device->reads, writes = device->writes, barriers = device->barriers;

	assert(ntfs_overwrite_range(owner, file_reference(TEST_DATA_RECORD), TEST_PATCH_OFFSET,
		   patch, TEST_PATCH_BYTES, &report) == NTFS_IO &&
	    report.poisoned);
	assert(ntfs_overwrite_resolve(owner, path, sizeof(path) / sizeof(*path), &reference) ==
		NTFS_IO &&
	    reference == 0);
	ntfs_overwrite_close(owner);
	assert(device->reads == reads && device->writes == writes && device->barriers == barriers);
	assert_closed(device);
}

static void
ordinary(const char *directory)
{
	static const uint16_t path[] = {
	    '/', 'f', 'r', 'a', 'g', 'm', 'e', 'n', 't', 'e', 'd', '.', 'b', 'i', 'n'};
	struct test_device device;
	struct ntfs_overwrite *owner;
	struct ntfs_overwrite *second;
	struct ntfs_overwrite_environment env;
	struct ntfs_overwrite_admission admission;
	struct ntfs_overwrite_report report;
	uint8_t patch[TEST_DATA_BYTES], *original, *expected;
	uint64_t reference;
	size_t ordinal, allocation_calls, read_calls, range_reads, range_allocations, writes;
	size_t optional_cache_refusals = 0;
	unsigned failure, physical;
	enum ntfs_result result;

	load(directory, "ordinary.img", &device);
	original = malloc(device.bytes);
	expected = malloc(device.bytes);
	assert(original != NULL && expected != NULL);
	memcpy(original, device.image, device.bytes);
	for (ordinal = 0; ordinal < sizeof(patch); ordinal++) {
		patch[ordinal] = (uint8_t)((ordinal * TEST_PATCH_MULTIPLIER + TEST_PATCH_ADDEND) %
		    TEST_BYTE_MODULUS);
	}
	owner = open_owner(&device);
	allocation_calls = device.allocations;
	read_calls = device.reads;
	env = environment(&device);
	assert(ntfs_overwrite_open(&env, &admission, &second) == NTFS_BUSY && second == NULL);
	assert(device.live_allocations == 1 && device.barriers == 1);
	assert(ntfs_overwrite_resolve(owner, path, sizeof(path) / sizeof(*path), &reference) ==
		NTFS_OK &&
	    reference == file_reference(TEST_DATA_RECORD));
	device.reads = 0;
	device.allocations = 0;
	assert(ntfs_overwrite_range(owner, reference, TEST_PATCH_OFFSET, patch, TEST_PATCH_BYTES,
		   &report) == NTFS_OK);
	range_reads = device.reads;
	range_allocations = device.allocations;
	assert(report.completed_bytes == TEST_PATCH_BYTES && report.writes == 2 &&
	    report.physical_bytes == 3 * NTFS_OVERWRITE_MIN_ALIGNMENT && report.persisted &&
	    !report.poisoned);
	memcpy(expected, original, device.bytes);
	expected_patch(expected, TEST_PATCH_OFFSET, patch, TEST_PATCH_BYTES);
	assert(memcmp(device.image, expected, device.bytes) == 0);
	ntfs_overwrite_close(owner);
	assert_closed(&device);
	for (ordinal = 1; ordinal <= allocation_calls; ordinal++) {
		reset(&device, original);
		device.fail_allocate = ordinal;
		env = environment(&device);
		owner = NULL;
		assert(ntfs_overwrite_open(&env, &admission, &owner) == NTFS_NO_MEMORY);
		assert(owner == NULL && device.memory == 0 && !device.claimed &&
		    device.writes == 0 && device.barriers == 0);
		assert(memcmp(device.image, original, device.bytes) == 0);
	}
	for (failure = 0; failure < 2; failure++) {
		for (ordinal = 1; ordinal <= read_calls; ordinal++) {
			reset(&device, original);
			device.fail_read = ordinal;
			device.full_read_failure = failure != 0;
			env = environment(&device);
			owner = NULL;
			result = ntfs_overwrite_open(&env, &admission, &owner);
			assert(result == NTFS_IO && owner == NULL && device.memory == 0 &&
			    !device.claimed && device.writes == 0 && device.barriers == 0);
			assert(memcmp(device.image, original, device.bytes) == 0);
		}
	}
	for (failure = 0; failure < 2; failure++) {
		for (ordinal = 1; ordinal <= (failure ? range_reads : range_allocations);
		    ordinal++) {
			reset(&device, original);
			owner = open_owner(&device);
			device.reads = 0;
			device.allocations = 0;
			device.fail_read = failure ? ordinal : 0;
			device.fail_allocate = failure ? 0 : ordinal;
			result = ntfs_overwrite_range(owner, file_reference(TEST_DATA_RECORD),
			    TEST_PATCH_OFFSET, patch, TEST_PATCH_BYTES, &report);
			if (!failure && result == NTFS_OK) {
				/* Optional raw-record cache fills can fail without failing the
				 * read operation; exact content and ownership still qualify. */
				assert(device.failed_allocate_bytes == TEST_RECORD_BYTES);
				assert(report.persisted && !report.poisoned && device.writes == 2 &&
				    device.barriers == 2 &&
				    report.completed_bytes == TEST_PATCH_BYTES);
				assert(memcmp(device.image, expected, device.bytes) == 0);
				ntfs_overwrite_close(owner);
				assert_closed(&device);
				optional_cache_refusals++;
				continue;
			}
			if (result != (failure ? NTFS_IO : NTFS_NO_MEMORY)) {
				fprintf(stderr,
				    "range %s fault %zu/%zu: returned %d (%s), writes=%zu "
				    "barriers=%zu\n",
				    failure ? "read" : "allocation", ordinal,
				    failure ? range_reads : range_allocations, result,
				    ntfs_result_string(result), device.writes, device.barriers);
			}
			assert(result == (failure ? NTFS_IO : NTFS_NO_MEMORY) && !report.poisoned &&
			    device.writes == 0 && device.barriers == 1);
			assert(memcmp(device.image, original, device.bytes) == 0);
			assert(device.live_allocations == 1 && device.memory == device.owner_bytes);
			device.fail_read = 0;
			device.fail_allocate = 0;
			assert(ntfs_overwrite_range(owner, file_reference(TEST_DATA_RECORD),
				   TEST_PATCH_OFFSET, patch, TEST_PATCH_BYTES, &report) == NTFS_OK);
			assert(memcmp(device.image, expected, device.bytes) == 0);
			ntfs_overwrite_close(owner);
			assert_closed(&device);
		}
	}
	for (failure = 0; failure < TEST_WRITE_FAILURE_KINDS; failure++) {
		for (physical = 1; physical <= 2; physical++) {
			reset(&device, original);
			owner = open_owner(&device);
			device.fail_write = physical;
			device.write_failure_kind = failure;
			assert(ntfs_overwrite_range(owner, file_reference(TEST_DATA_RECORD),
				   TEST_PATCH_OFFSET, patch, TEST_PATCH_BYTES, &report) == NTFS_IO);
			assert(report.poisoned && !report.persisted &&
			    report.completed_bytes ==
				(physical == 1 ? 0 : TEST_CLUSTER_BYTES - TEST_PATCH_OFFSET));
			assert(device.barriers == 1);
			poisoned_owner(&device, owner, patch);
		}
	}
	reset(&device, original);
	owner = open_owner(&device);
	device.fail_barrier = 2;
	assert(ntfs_overwrite_range(owner, file_reference(TEST_DATA_RECORD), TEST_PATCH_OFFSET,
		   patch, TEST_PATCH_BYTES, &report) == NTFS_IO &&
	    report.poisoned);
	assert(report.completed_bytes == TEST_PATCH_BYTES && !report.persisted);
	poisoned_owner(&device, owner, patch);
	reset(&device, original);
	device.fail_barrier = 1;
	env = environment(&device);
	assert(ntfs_overwrite_open(&env, &admission, &owner) == NTFS_IO && owner == NULL);
	assert(device.writes == 0 && memcmp(device.image, original, device.bytes) == 0);
	assert_closed(&device);
	reset(&device, original);
	device.fail_claim = true;
	env = environment(&device);
	assert(ntfs_overwrite_open(&env, &admission, &owner) == NTFS_BUSY && owner == NULL);
	assert(device.reads == 0 && device.memory == 0 && device.unclaims == 0);
	reset(&device, original);
	owner = open_owner(&device);
	writes = device.writes;
	assert(ntfs_overwrite_range(owner, file_reference(TEST_DATA_RECORD), 0, NULL, 0, &report) ==
		NTFS_OK &&
	    device.writes == writes);
	assert(ntfs_overwrite_range(owner, file_reference(TEST_DATA_RECORD), TEST_DATA_BYTES, patch,
		   1, &report) == NTFS_RANGE &&
	    !report.poisoned);
	assert(ntfs_overwrite_range(owner, file_reference(TEST_RESIDENT_RECORD), 0, patch, 1,
		   &report) == NTFS_UNSUPPORTED &&
	    !report.poisoned);
	assert(ntfs_overwrite_range(owner, file_reference(TEST_DATA_RECORD), UINT64_MAX, patch, 1,
		   &report) == NTFS_RANGE &&
	    !report.poisoned);
	assert(ntfs_overwrite_range(owner, file_reference(TEST_DATA_RECORD), 0, patch,
		   NTFS_OVERWRITE_MAX_BYTES + 1, &report) == NTFS_RANGE &&
	    !report.poisoned);
	assert(device.writes == 0 && device.barriers == 1);
	assert(ntfs_overwrite_range(
		   owner, file_reference(TEST_DATA_RECORD), 0, owner, 1, &report) == NTFS_INVALID);
	assert(ntfs_overwrite_range(owner, file_reference(TEST_DATA_RECORD), 0, &report, 1,
		   &report) == NTFS_INVALID);
	assert(ntfs_overwrite_range(owner, file_reference(TEST_DATA_RECORD), 0, patch,
		   TEST_DATA_BYTES, &report) == NTFS_OK);
	memcpy(expected, original, device.bytes);
	expected_patch(expected, 0, patch, TEST_DATA_BYTES);
	assert(memcmp(device.image, expected, device.bytes) == 0);
	ntfs_overwrite_close(owner);
	assert_closed(&device);
	reset(&device, original);
	env = environment(&device);
	env.alignment = TEST_CLUSTER_BYTES;
	assert(ntfs_overwrite_open(&env, &admission, &owner) == NTFS_OK && owner != NULL);
	assert(ntfs_overwrite_range(owner, file_reference(TEST_DATA_RECORD), TEST_PATCH_OFFSET,
		   patch, TEST_PATCH_BYTES, &report) == NTFS_OK);
	assert(report.physical_bytes == 2 * TEST_CLUSTER_BYTES && report.persisted);
	memcpy(expected, original, device.bytes);
	expected_patch(expected, TEST_PATCH_OFFSET, patch, TEST_PATCH_BYTES);
	assert(memcmp(device.image, expected, device.bytes) == 0);
	ntfs_overwrite_close(owner);
	assert_closed(&device);
	reset(&device, original);
	env = environment(&device);
	env.alignment = 2 * TEST_CLUSTER_BYTES;
	assert(ntfs_overwrite_open(&env, &admission, &owner) == NTFS_UNSUPPORTED && owner == NULL);
	assert(device.writes == 0 && device.barriers == 0);
	assert_closed(&device);
	reset(&device, original);
	env = environment(&device);
	env.alignment = NTFS_OVERWRITE_MIN_ALIGNMENT + 1;
	assert(ntfs_overwrite_open(&env, &admission, &owner) == NTFS_INVALID && owner == NULL);
	assert(device.allocations == 0 && device.claims == 0);
	env = environment(&device);
	env.persist = NULL;
	assert(ntfs_overwrite_open(&env, &admission, &owner) == NTFS_INVALID && owner == NULL);
	assert(device.allocations == 0 && device.claims == 0);
	printf("PASS: exclusive overwrite owner; %zu allocation/%zu partial+full read admission "
	       "faults; %zu allocation/%zu range read faults; write/short/overflow/barrier poison; "
	       "fragmented RMW and complete outside-byte preservation; %zu optional cache "
	       "refusals preserved exact successful writes\n",
	    allocation_calls, read_calls, range_allocations, range_reads, optional_cache_refusals);
	free(expected);
	free(original);
	free(device.image);
}

int
main(int argc, char **argv)
{
	struct test_device device;
	struct ntfs_overwrite_environment env;
	struct ntfs_overwrite_admission admission;
	struct ntfs_overwrite_report report;
	struct ntfs_overwrite *owner = NULL;
	char name[TEST_CASE_NAME_BYTES], *rows_path;
	FILE *rows;
	int code;
	enum ntfs_result result;
	uint8_t byte = 0x83;
	size_t length;

	assert(argc == 2);
	length = strlen(argv[1]) + sizeof("/cases.rows");
	rows_path = malloc(length);
	assert(rows_path != NULL);
	assert(snprintf(rows_path, length, "%s/cases.rows", argv[1]) > 0);
	rows = fopen(rows_path, "r");
	assert(rows != NULL);
	while (fscanf(rows, "%63s %d", name, &code) == 2) {
		load(argv[1], name, &device);
		env = environment(&device);
		result = ntfs_overwrite_open(&env, &admission, &owner);
		if (result != (enum ntfs_result)code) {
			fprintf(stderr,
			    "%s: open returned %d (%s), expected %d, validation %d stage %u\n",
			    name, result, ntfs_result_string(result), code,
			    admission.validation.result, (unsigned)admission.validation.stage);
		}
		assert(result == (enum ntfs_result)code);
		if (code == NTFS_OK) {
			assert(
			    owner != NULL && admission.quiescent && admission.validation.complete);
			if (strcmp(name, "read-only-file.img") == 0) {
				assert(ntfs_overwrite_range(owner, file_reference(TEST_DATA_RECORD),
					   0, &byte, 1, &report) == NTFS_UNSUPPORTED);
			} else if (strcmp(name, "uninitialized-file.img") == 0) {
				assert(ntfs_overwrite_range(owner, file_reference(TEST_DATA_RECORD),
					   0, &byte, 1, &report) == NTFS_RANGE);
			}
			ntfs_overwrite_close(owner);
		} else {
			assert(owner == NULL && device.barriers == 0);
		}
		assert(device.writes == 0);
		assert_closed(&device);
		free(device.image);
	}
	assert(fclose(rows) == 0);
	free(rows_path);
	ordinary(argv[1]);
	return 0;
}
