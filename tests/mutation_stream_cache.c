/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_mutation_internal.h"
#include "fuzz_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void
initialize_record(struct ntfs_mutation_record *record)
{
	struct ntfs_disk_record *header = (void *)record->bytes;
	size_t first = ntfs_mutation_align_bytes(sizeof(*header));

	ntfs_put_u16(header->attrs_offset, (uint16_t)first);
	ntfs_put_u32(header->allocated, sizeof(record->bytes));
	ntfs_put_u32(header->used, (uint32_t)(first + NTFS_WIRE_ALIGNMENT));
	ntfs_put_u32(record->bytes + first, NTFS_ATTR_END);
}

static void
empty_resident_read(void)
{
	struct ntfs_stream stream = {.resident = true};

	/* An empty resident stream legitimately owns no value allocation. Even a
	 * zero pointer offset is undefined C; zero-byte admission must not form it. */
	assert(ntfs_mutation_stream_read(NULL, &stream, 0, NULL, 0) == NTFS_OK);
	assert(ntfs_mutation_stream_read(NULL, &stream, 1, NULL, 0) == NTFS_RANGE);
	assert(ntfs_mutation_stream_read(NULL, &stream, 0, NULL, 1) == NTFS_RANGE);
	stream.resident = false;
	assert(ntfs_mutation_stream_read(NULL, &stream, 0, NULL, 0) == NTFS_OK);
}

int
main(void)
{
	struct fuzz_device device = {0};
	struct ntfs_volume volume = {0};
	struct ntfs_write_mutation_plan *plan;
	struct ntfs_mutation_record *records;
	struct ntfs_stream *old, *same, *next, *held, *resident;
	struct ntfs_run run = {0, 1, 5};
	size_t index, calls, live;
	uint8_t value = 0x37;

	empty_resident_read();
	volume.env = fuzz_environment(&device);
	ntfs_default_limits(&volume.limits);
	volume.info.cluster_size = NTFS_WRITE_CLUSTER_BYTES;
	volume.info.cluster_count = 64;
	plan = calloc(1, sizeof(*plan));
	records = calloc(NTFS_MUTATION_STREAM_CACHE_ENTRIES + 1, sizeof(*records));
	assert(plan != NULL && records != NULL);
	plan->source = volume.env;
	plan->volume = &volume;
	plan->info = volume.info;
	plan->scratch = ntfs_mutation_allocate(plan, NTFS_WRITE_CLUSTER_BYTES);
	assert(plan->scratch != NULL);
	for (index = 0; index <= NTFS_MUTATION_STREAM_CACHE_ENTRIES; index++) {
		initialize_record(&records[index]);
	}
	assert(ntfs_mutation_resident(
		   plan, &records[0], NTFS_ATTRIBUTE_DATA, NULL, 0, &value, 1, 0) == NTFS_OK);
	assert(
	    ntfs_mutation_stream(plan, &records[0], NTFS_ATTRIBUTE_DATA, NULL, 0, &old) == NTFS_OK);
	calls = device.allocations;
	for (index = 0; index < 1000; index++) {
		assert(ntfs_mutation_stream(
			   plan, &records[0], NTFS_ATTRIBUTE_DATA, NULL, 0, &same) == NTFS_OK);
		assert(same == old && same->value[0] == value);
		ntfs_stream_close(same);
	}
	assert(device.allocations == calls);
	value++;
	assert(ntfs_mutation_resident(
		   plan, &records[0], NTFS_ATTRIBUTE_DATA, NULL, 0, &value, 1, 0) == NTFS_OK);
	device.fail_allocation = device.allocations + 1;
	assert(ntfs_mutation_stream(plan, &records[0], NTFS_ATTRIBUTE_DATA, NULL, 0, &same) ==
		NTFS_NO_MEMORY &&
	    same == NULL);
	device.fail_allocation = 0;
	assert(ntfs_mutation_stream(plan, &records[0], NTFS_ATTRIBUTE_DATA, NULL, 0, &same) ==
	    NTFS_OK);
	assert(same != old && same->value[0] == value && old->value[0] == value - 1);
	resident = same;
	assert(ntfs_mutation_nonresident(plan, &records[0], NTFS_ATTRIBUTE_DATA, NULL, 0, &run, 1,
		   NTFS_WRITE_CLUSTER_BYTES, NTFS_WRITE_CLUSTER_BYTES, 0) == NTFS_OK);
	assert(ntfs_mutation_stream(plan, &records[0], NTFS_ATTRIBUTE_DATA, NULL, 0, &next) ==
	    NTFS_OK);
	assert(!next->resident && next->runs[0].lcn == run.lcn);
	run.lcn++;
	assert(ntfs_mutation_nonresident(plan, &records[0], NTFS_ATTRIBUTE_DATA, NULL, 0, &run, 1,
		   NTFS_WRITE_CLUSTER_BYTES, NTFS_WRITE_CLUSTER_BYTES, 0) == NTFS_OK);
	assert(ntfs_mutation_stream(plan, &records[0], NTFS_ATTRIBUTE_DATA, NULL, 0, &held) ==
	    NTFS_OK);
	assert(held != next && held->runs[0].lcn == run.lcn && next->runs[0].lcn == run.lcn - 1);
	assert(ntfs_mutation_attribute_remove(plan, &records[0], NTFS_ATTRIBUTE_DATA, NULL, 0) ==
	    NTFS_OK);
	assert(ntfs_mutation_stream(plan, &records[0], NTFS_ATTRIBUTE_DATA, NULL, 0, &same) ==
	    NTFS_NOT_FOUND);
	/* Retained snapshots survive cache eviction and record reuse. */
	for (index = 1; index <= NTFS_MUTATION_STREAM_CACHE_ENTRIES; index++) {
		assert(ntfs_mutation_resident(plan, &records[index], NTFS_ATTRIBUTE_DATA, NULL, 0,
			   &value, 1, 0) == NTFS_OK);
		assert(ntfs_mutation_stream(
			   plan, &records[index], NTFS_ATTRIBUTE_DATA, NULL, 0, &same) == NTFS_OK);
		ntfs_stream_close(same);
	}
	assert(old->value[0] == value - 1 && next->runs[0].lcn == run.lcn - 1 &&
	    held->runs[0].lcn == run.lcn);
	ntfs_stream_close(old);
	ntfs_stream_close(next);
	ntfs_stream_close(held);
	ntfs_stream_close(resident);
	for (index = 0; index < NTFS_MUTATION_STREAM_CACHE_ENTRIES; index++) {
		ntfs_stream_close(plan->streams[index].stream);
	}
	live = plan->live_bytes;
	assert(live == NTFS_WRITE_CLUSTER_BYTES);
	ntfs_mutation_release(plan, plan->scratch, NTFS_WRITE_CLUSTER_BYTES);
	assert(device.memory == 0);
	free(records);
	free(plan);
	puts("private stream reuse, revision invalidation, immutable borrowers, mapping changes "
	     "and faults passed");
	return 0;
}
