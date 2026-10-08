/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_mutation_internal.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_KEYS = 257,
	TEST_READ_BYTES = 2 * NTFS_WRITE_CLUSTER_BYTES + 17,
	TEST_PATTERN = 0x5a,
	TEST_RECORDS = 1031,
	TEST_FIRST_RECORD = 24,
	TEST_BITS_PER_BYTE = 8
};

#define TEST_DEVICE_BYTES (UINT64_C(1) << 46)

union allocation {
	max_align_t alignment;
	size_t bytes;
};

struct device {
	size_t live, allocations, reads, fail_allocation, fail_read;
};

static void *
allocate(void *context, size_t bytes)
{
	struct device *device = context;
	union allocation *allocation;

	if (++device->allocations == device->fail_allocation) {
		return NULL;
	}
	allocation = malloc(sizeof(*allocation) + bytes);
	assert(allocation != NULL);
	allocation->bytes = bytes;
	device->live += bytes;
	return allocation + 1;
}

static void
release(void *context, void *memory, size_t bytes)
{
	struct device *device = context;
	union allocation *allocation = (union allocation *)memory - 1;

	assert(allocation->bytes == bytes && device->live >= bytes);
	device->live -= bytes;
	free(allocation);
}

static enum ntfs_result
read_source(void *context, uint64_t offset, void *memory, size_t bytes)
{
	struct device *device = context;

	assert(offset <= TEST_DEVICE_BYTES && bytes <= TEST_DEVICE_BYTES - offset);
	memset(memory, TEST_PATTERN, bytes);
	return ++device->reads == device->fail_read ? NTFS_IO : NTFS_OK;
}

static struct ntfs_write_mutation_plan *
open_plan(struct device *device)
{
	struct ntfs_write_mutation_plan *plan = allocate(device, sizeof(*plan));

	assert(plan != NULL);
	memset(plan, 0, sizeof(*plan));
	plan->source = (struct ntfs_environment){
	    NTFS_API_VERSION, device, TEST_DEVICE_BYTES, read_source, allocate, release};
	plan->info.size_bytes = TEST_DEVICE_BYTES;
	plan->info.cluster_count = TEST_DEVICE_BYTES / NTFS_WRITE_CLUSTER_BYTES;
	return plan;
}

static uint64_t
physical(size_t index, size_t count, unsigned geometry)
{
	uint64_t cluster = (index * (count - 1)) % count;

	if (geometry == 1) {
		cluster *= NTFS_MUTATION_MAX_REGIONS;
	} else if (geometry == 2) {
		cluster |= UINT64_C(1) << 32;
	}
	return cluster * NTFS_WRITE_CLUSTER_BYTES;
}

static void
patches(size_t count, unsigned geometry)
{
	struct device device = {0};
	struct ntfs_write_mutation_plan *plan = open_plan(&device);
	struct ntfs_mutation_patch *patch, *again;
	uint8_t *output = malloc(TEST_READ_BYTES), *expected = malloc(TEST_READ_BYTES);
	size_t index, reads, allocations, offset, size, other, byte;
	uint64_t start, location;

	assert(output != NULL && expected != NULL);
	for (index = 0; index < count; index++) {
		location = physical(index, count, geometry);
		assert(ntfs_mutation_patch(plan, location, NTFS_WRITE_MUTATION_DATA, &patch) ==
		    NTFS_OK);
		assert(plan->patch_count == index + 1 && plan->patches[index] == patch);
		memset(patch->after, (int)(index % UINT8_MAX), NTFS_WRITE_CLUSTER_BYTES);
		assert(patch->before[0] == TEST_PATTERN);
	}
	reads = device.reads;
	allocations = device.allocations;
	for (index = 0; index < count; index++) {
		location = physical(index, count, geometry);
		assert(ntfs_mutation_patch(plan, location, NTFS_WRITE_MUTATION_DATA, &again) ==
		    NTFS_OK);
		assert(again == plan->patches[index]);
		assert(ntfs_mutation_patch(plan, location, NTFS_WRITE_MUTATION_BITMAP, &again) ==
		    NTFS_CORRUPT);
		assert(again == NULL);
	}
	assert(device.reads == reads && device.allocations == allocations);
	for (index = 0; index < count; index += count / 16 + 1) {
		for (offset = 0; offset < 19; offset++) {
			start = physical(index, count, geometry) + offset;
			size = TEST_READ_BYTES - offset;
			memset(expected, TEST_PATTERN, size);
			for (other = 0; other < count; other++) {
				location = physical(other, count, geometry);
				for (byte = 0; byte < size; byte++) {
					if (start + byte >= location &&
					    start + byte - location < NTFS_WRITE_CLUSTER_BYTES) {
						expected[byte] = (uint8_t)(other % UINT8_MAX);
					}
				}
			}
			assert(ntfs_mutation_read(plan, start, output, size) == NTFS_OK);
			assert(memcmp(output, expected, size) == 0);
		}
	}
	device.fail_read = device.reads + 1;
	memset(output, 0, TEST_READ_BYTES);
	assert(ntfs_mutation_read(plan, 0, output, TEST_READ_BYTES) == NTFS_IO);
	for (byte = 0; byte < TEST_READ_BYTES; byte++) {
		assert(output[byte] == TEST_PATTERN);
	}
	device.fail_read = 0;
	plan->sealed = true;
	assert(ntfs_mutation_patch(plan, 0, NTFS_WRITE_MUTATION_DATA, &patch) == NTFS_RANGE);
	for (index = 0; index < ntfs_mutation_vector_bytes(plan->patch_capacity); index++) {
		assert(ntfs_write_mutation_plan_view(
			   plan, (void *)((uint8_t *)plan->patches + index)) == NTFS_INVALID);
		assert(ntfs_write_mutation_plan_region(
			   plan, 0, (void *)((uint8_t *)plan->patches + index)) == NTFS_INVALID);
	}
	ntfs_write_mutation_plan_close(plan);
	assert(device.live == 0);
	free(expected);
	free(output);
}

static void
patch_faults(void)
{
	struct device device;
	struct ntfs_write_mutation_plan *plan;
	struct ntfs_mutation_patch *patch;
	size_t fault, index, mode, allocations, reads;

	for (mode = 0; mode < 2; mode++) {
		for (fault = 1; fault <= (mode == 0 ? 2 : 1); fault++) {
			device = (struct device){0};
			plan = open_plan(&device);
			for (index = 0; index < NTFS_MUTATION_INITIAL_REGIONS; index++) {
				assert(ntfs_mutation_patch(plan, index * NTFS_WRITE_CLUSTER_BYTES,
					   NTFS_WRITE_MUTATION_DATA, &patch) == NTFS_OK);
			}
			device.fail_allocation = mode == 0 ? device.allocations + fault : 0;
			device.fail_read = mode == 1 ? device.reads + fault : 0;
			assert(ntfs_mutation_patch(plan, index * NTFS_WRITE_CLUSTER_BYTES,
				   NTFS_WRITE_MUTATION_DATA,
				   &patch) == (mode == 0 ? NTFS_NO_MEMORY : NTFS_IO));
			assert(patch == NULL && plan->patch_count == NTFS_MUTATION_INITIAL_REGIONS);
			allocations = device.allocations;
			reads = device.reads;
			assert(ntfs_mutation_patch(plan, 0, NTFS_WRITE_MUTATION_DATA, &patch) ==
			    NTFS_OK);
			assert(device.allocations == allocations && device.reads == reads);
			device.fail_allocation = device.fail_read = 0;
			assert(ntfs_mutation_patch(plan, index * NTFS_WRITE_CLUSTER_BYTES,
				   NTFS_WRITE_MUTATION_DATA, &patch) == NTFS_OK);
			ntfs_write_mutation_plan_close(plan);
			assert(device.live == 0);
		}
	}
}

static void
records_and_bitmap(void)
{
	struct device device = {0};
	struct ntfs_write_mutation_plan *plan;
	struct ntfs_volume volume = {0};
	struct ntfs_stream original = {0}, mft = {0};
	struct ntfs_mutation_record *record, *again;
	struct ntfs_run run = {0, TEST_RECORDS, 1};
	uint8_t before[(TEST_RECORDS + TEST_BITS_PER_BYTE - 1) / TEST_BITS_PER_BYTE];
	uint8_t after[sizeof(before)];
	size_t index, wanted, actual, reads, allocations;

	volume.mft = &original;
	mft.runs = &run;
	mft.run_count = 1;
	mft.initialized = (uint64_t)TEST_RECORDS * NTFS_WRITE_RECORD_BYTES;
	for (wanted = TEST_FIRST_RECORD; wanted < TEST_RECORDS; wanted++) {
		plan = open_plan(&device);
		plan->volume = &volume;
		plan->mft = &mft;
		memset(before, UINT8_MAX, sizeof(before));
		memset(after, 0, sizeof(after));
		/* Reserved slots are free. Alternating ownership before the chosen
		 * record verifies that the first-fit search uses the union. */
		for (index = 0; index <= wanted; index++) {
			if (index < TEST_FIRST_RECORD || index == wanted || (index & 1u) != 0) {
				before[index / TEST_BITS_PER_BYTE] &=
				    (uint8_t)~(1u << (index % TEST_BITS_PER_BYTE));
			}
			if (index >= TEST_FIRST_RECORD && index < wanted && (index & 1u) != 0) {
				after[index / TEST_BITS_PER_BYTE] |=
				    (uint8_t)(1u << (index % TEST_BITS_PER_BYTE));
			}
		}
		plan->mft_bitmap = (struct ntfs_mutation_bitmap){
		    .before = before, .after = after, .bytes = sizeof(before)};
		assert(
		    ntfs_mutation_new_record(plan, &record) == NTFS_OK && record->number == wanted);
		for (actual = TEST_FIRST_RECORD; actual < TEST_RECORDS; actual++) {
			assert(
			    ((after[actual / TEST_BITS_PER_BYTE] >> (actual % TEST_BITS_PER_BYTE)) &
				1u) ==
			    (actual == wanted || (actual < wanted && (actual & 1u) != 0)));
		}
		/* Populate in descending order, then resolve by both number and full
		 * reference. No test reaches into the lookup representation. */
		if (wanted == TEST_FIRST_RECORD) {
			for (index = TEST_RECORDS; index-- > TEST_FIRST_RECORD;) {
				assert(
				    ntfs_mutation_record_get(plan, index, true, &again) == NTFS_OK);
			}
			reads = device.reads;
			allocations = device.allocations;
			for (index = TEST_FIRST_RECORD; index < TEST_RECORDS; index++) {
				assert(
				    ntfs_mutation_record_get(plan, index, true, &again) == NTFS_OK);
				assert(again->number == index);
				/* Empty records are not published as live file references. */
				assert(ntfs_mutation_record_get(plan, again->reference, false,
					   &again) == NTFS_NOT_FOUND);
				assert(
				    ntfs_mutation_record_get(plan, index, true, &again) == NTFS_OK);
				ntfs_put_u16(
				    ((struct ntfs_disk_record *)(void *)again->bytes)->flags,
				    NTFS_RECORD_IN_USE);
				assert(ntfs_mutation_record_get(plan,
					   again->reference ^
					       (UINT64_C(1) << NTFS_REFERENCE_SEQUENCE_SHIFT),
					   false, &again) == NTFS_STALE &&
				    again == NULL);
			}
			assert(device.reads == reads && device.allocations == allocations);
		}
		plan->volume = NULL;
		plan->mft = NULL;
		plan->mft_bitmap = (struct ntfs_mutation_bitmap){0};
		ntfs_write_mutation_plan_close(plan);
		assert(device.live == 0);
	}
}

static void
record_faults(void)
{
	struct device device;
	struct ntfs_write_mutation_plan *plan;
	struct ntfs_volume volume = {0};
	struct ntfs_stream original = {0}, mft = {0};
	struct ntfs_run run = {0, TEST_RECORDS, 1};
	struct ntfs_mutation_record *record;
	size_t index, mode, fault, reads, allocations;

	volume.mft = &original;
	mft.runs = &run;
	mft.run_count = 1;
	mft.initialized = (uint64_t)TEST_RECORDS * NTFS_WRITE_RECORD_BYTES;
	for (mode = 0; mode < 2; mode++) {
		for (fault = 1; fault <= (mode == 0 ? 2 : 1); fault++) {
			device = (struct device){0};
			plan = open_plan(&device);
			plan->volume = &volume;
			plan->mft = &mft;
			for (index = 0; index < NTFS_MUTATION_INITIAL_RECORDS; index++) {
				assert(ntfs_mutation_record_get(plan, index, true, &record) ==
				    NTFS_OK);
			}
			device.fail_allocation = mode == 0 ? device.allocations + fault : 0;
			device.fail_read = mode == 1 ? device.reads + fault : 0;
			assert(ntfs_mutation_record_get(plan, index, true, &record) ==
			    (mode == 0 ? NTFS_NO_MEMORY : NTFS_IO));
			assert(
			    record == NULL && plan->record_count == NTFS_MUTATION_INITIAL_RECORDS);
			reads = device.reads;
			allocations = device.allocations;
			assert(ntfs_mutation_record_get(plan, 0, true, &record) == NTFS_OK);
			assert(device.reads == reads && device.allocations == allocations);
			device.fail_allocation = device.fail_read = 0;
			assert(ntfs_mutation_record_get(plan, index, true, &record) == NTFS_OK);
			plan->sealed = true;
			/* Protect the complete private vector allocation, including its
			 * appended lookup slots, from overlapping public outputs. */
			for (index = 0; index < ntfs_mutation_vector_bytes(plan->record_capacity);
			    index++) {
				assert(ntfs_write_mutation_plan_view(
					   plan, (void *)((uint8_t *)plan->records + index)) ==
				    NTFS_INVALID);
				assert(ntfs_write_mutation_plan_region(
					   plan, 0, (void *)((uint8_t *)plan->records + index)) ==
				    NTFS_INVALID);
			}
			plan->volume = NULL;
			plan->mft = NULL;
			ntfs_write_mutation_plan_close(plan);
			assert(device.live == 0);
		}
	}
}

static void
capacity_limits(void)
{
	struct device device = {0};
	struct ntfs_write_mutation_plan *plan = open_plan(&device);
	struct ntfs_volume volume = {0};
	struct ntfs_stream original = {0}, mft = {0};
	struct ntfs_run run = {0, NTFS_MUTATION_MAX_RECORDS + 1, 1};
	struct ntfs_mutation_record *record;
	struct ntfs_mutation_patch *patch;
	size_t index, allocations, reads;

	volume.mft = &original;
	mft.runs = &run;
	mft.run_count = 1;
	mft.initialized = (uint64_t)(NTFS_MUTATION_MAX_RECORDS + 1) * NTFS_WRITE_RECORD_BYTES;
	plan->volume = &volume;
	plan->mft = &mft;
	for (index = 0; index < NTFS_MUTATION_MAX_REGIONS; index++) {
		assert(ntfs_mutation_patch(plan, index * NTFS_WRITE_CLUSTER_BYTES,
			   NTFS_WRITE_MUTATION_DATA, &patch) == NTFS_OK);
	}
	for (index = 0; index < NTFS_MUTATION_MAX_RECORDS; index++) {
		assert(ntfs_mutation_record_get(plan, index, true, &record) == NTFS_OK);
	}
	allocations = device.allocations;
	reads = device.reads;
	assert(ntfs_mutation_patch(plan, NTFS_MUTATION_MAX_REGIONS * NTFS_WRITE_CLUSTER_BYTES,
		   NTFS_WRITE_MUTATION_DATA, &patch) == NTFS_RANGE &&
	    patch == NULL);
	assert(ntfs_mutation_record_get(plan, NTFS_MUTATION_MAX_RECORDS, true, &record) ==
		NTFS_RANGE &&
	    record == NULL);
	for (index = 0; index < NTFS_MUTATION_MAX_REGIONS; index++) {
		assert(ntfs_mutation_patch(plan, index * NTFS_WRITE_CLUSTER_BYTES,
			   NTFS_WRITE_MUTATION_DATA, &patch) == NTFS_OK);
	}
	for (index = 0; index < NTFS_MUTATION_MAX_RECORDS; index++) {
		assert(ntfs_mutation_record_get(plan, index, true, &record) == NTFS_OK);
	}
	assert(device.allocations == allocations && device.reads == reads);
	plan->volume = NULL;
	plan->mft = NULL;
	ntfs_write_mutation_plan_close(plan);
	assert(device.live == 0);
}

int
main(void)
{
	unsigned geometry;

	for (geometry = 0; geometry < 3; geometry++) {
		patches(TEST_KEYS, geometry);
	}
	patch_faults();
	record_faults();
	records_and_bitmap();
	capacity_limits();
	puts("mutation lookup/overlay order, sparse keys, retry and MFT first-fit contracts pass");
	return 0;
}
