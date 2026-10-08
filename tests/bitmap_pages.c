/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_mutation_internal.h"
#include "fuzz_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { TEST_PAGE_BYTES = 4096, TEST_PAGE_BITS = TEST_PAGE_BYTES * 8, TEST_START_VCN = 7 };

struct fixture {
	struct fuzz_device device;
	struct ntfs_volume volume;
	struct ntfs_stream stream;
	struct ntfs_run run;
	struct ntfs_write_mutation_plan *plan;
	uint8_t *source;
	size_t bytes;
};

static enum ntfs_result
partial_read(void *context, uint64_t offset, void *bytes, size_t size)
{
	struct fixture *f = context;

	/* A failing exact callback may have overwritten its entire destination. */
	memset(bytes, 0xa5, size);
	if (offset < f->bytes) {
		return fuzz_read(context, offset, bytes, size);
	}
	if (++f->device.reads > FUZZ_READ_BUDGET || f->device.reads == f->device.fail_read ||
	    !ntfs_bounds(offset, size, f->device.size)) {
		return NTFS_IO;
	}
	memset(bytes, 0, size);
	return NTFS_OK;
}

static void
open_fixture(struct fixture *f, size_t bytes)
{
	memset(f, 0, sizeof(*f));
	f->bytes = bytes;
	f->source = malloc(bytes);
	assert(f->source != NULL);
	memset(f->source, UINT8_MAX, bytes);
	f->device.data = f->source;
	f->device.size = bytes;
	f->volume.env = fuzz_environment(&f->device);
	f->volume.env.read = partial_read;
	ntfs_default_limits(&f->volume.limits);
	f->volume.info.cluster_size = NTFS_WRITE_CLUSTER_BYTES;
	f->volume.info.size_bytes = bytes;
	f->volume.info.cluster_count =
	    (bytes + NTFS_WRITE_CLUSTER_BYTES - 1) / NTFS_WRITE_CLUSTER_BYTES;
	f->run = (struct ntfs_run){0, f->volume.info.cluster_count, 0};
	f->stream = (struct ntfs_stream){.volume = &f->volume,
	    .size = bytes,
	    .initialized = bytes,
	    .allocated = bytes,
	    .runs = &f->run,
	    .run_count = 1};
	f->plan = fuzz_allocate(&f->device, sizeof(*f->plan));
	assert(f->plan != NULL);
	memset(f->plan, 0, sizeof(*f->plan));
	f->plan->source = f->volume.env;
	f->plan->info.size_bytes = bytes;
	f->plan->info.cluster_count = bytes * NTFS_BITS_PER_BYTE - 3;
	f->plan->allocation = (struct ntfs_mutation_bitmap){
	    .stream = &f->stream, .bytes = bytes, .original_bytes = bytes};
}

static void
close_fixture(struct fixture *f)
{
	f->plan->allocation.stream = NULL;
	f->plan->mft_bitmap.stream = NULL;
	f->plan->volume = NULL;
	f->plan->mft = NULL;
	ntfs_write_mutation_plan_close(f->plan);
	assert(f->device.memory == 0);
	free(f->source);
}

static void
check_bytes(struct fixture *f, const uint8_t *after)
{
	struct ntfs_mutation_bitmap_view view;
	size_t offset;

	for (offset = 0; offset < f->bytes; offset += view.bytes) {
		assert(ntfs_mutation_bitmap_view(
			   f->plan, &f->plan->allocation, offset, false, &view) == NTFS_OK);
		assert(view.bytes != 0 && view.bytes <= f->bytes - offset);
		assert(memcmp(view.before, f->source + offset, view.bytes) == 0);
		assert(memcmp(view.after, after + offset, view.bytes) == 0);
	}
}

static void
scan_cases(void)
{
	struct fixture f;
	struct ntfs_stream retired = {0};
	struct ntfs_run retirement, *runs;
	uint8_t *expected;
	uint64_t first, bit, missing, end, available;
	size_t size, variant, count, index;
	enum ntfs_result result;

	for (size = TEST_PAGE_BYTES + 1; size <= 3 * TEST_PAGE_BYTES + 1; size += TEST_PAGE_BYTES) {
		for (variant = 0; variant < 4; variant++) {
			open_fixture(&f, size);
			expected = malloc(size);
			assert(expected != NULL);
			first = TEST_PAGE_BITS - 11;
			end = f.plan->info.cluster_count;
			missing = variant == 0 ? end : first + variant * 5;
			if (missing < end) {
				ntfs_mutation_set_bit(f.source, missing, false);
			}
			memcpy(expected, f.source, size);
			for (bit = first; bit < missing; bit++) {
				ntfs_mutation_set_bit(expected, bit, false);
			}
			retirement = (struct ntfs_run){0, end - first, first};
			retired.runs = &retirement;
			retired.run_count = 1;
			retired.clusters = retirement.length;
			result = missing == end ? NTFS_OK : NTFS_CORRUPT;
			assert(ntfs_mutation_free_runs(f.plan, &retired, 0) == result);
			check_bytes(&f, expected);
			/* Privately freed original ownership must never be allocated again. */
			assert(ntfs_mutation_allocate_runs(f.plan, TEST_START_VCN, 1, &runs,
				   &count) == (missing == end ? NTFS_NO_SPACE : NTFS_OK));
			if (missing < end) {
				assert(count == 1 && runs[0].vcn == TEST_START_VCN &&
				    runs[0].lcn == missing && runs[0].length == 1);
				ntfs_mutation_set_bit(expected, missing, true);
				ntfs_mutation_release(
				    f.plan, runs, NTFS_MUTATION_MAX_RUNS * sizeof(*runs));
			} else {
				assert(runs == NULL && count == 0);
			}
			check_bytes(&f, expected);
			free(expected);
			close_fixture(&f);
		}
		open_fixture(&f, size);
		expected = malloc(size);
		assert(expected != NULL);
		first = TEST_PAGE_BITS - 11;
		for (bit = first; bit < f.plan->info.cluster_count; bit++) {
			ntfs_mutation_set_bit(f.source, bit, false);
		}
		memcpy(expected, f.source, size);
		available = f.plan->info.cluster_count - first;
		for (bit = first; bit < f.plan->info.cluster_count; bit++) {
			ntfs_mutation_set_bit(expected, bit, true);
		}
		assert(ntfs_mutation_allocate_runs(
			   f.plan, TEST_START_VCN, available, &runs, &count) == NTFS_OK);
		assert(count == 1 && runs[0].lcn == first && runs[0].length == available);
		check_bytes(&f, expected);
		ntfs_mutation_release(f.plan, runs, NTFS_MUTATION_MAX_RUNS * sizeof(*runs));
		/* Exact trailing bits must retain their original padding value. */
		for (index = (size_t)f.plan->info.cluster_count; index < size * NTFS_BITS_PER_BYTE;
		    index++) {
			assert(ntfs_mutation_bit(expected, size, index));
		}
		free(expected);
		close_fixture(&f);
	}
}

static void
snapshot_and_faults(void)
{
	struct fixture f;
	struct ntfs_mutation_bitmap_view view;
	struct ntfs_mutation_patch *patch;
	size_t fault, allocations;
	bool bit;

	open_fixture(&f, TEST_PAGE_BYTES * 2 + 1);
	f.source[0] = 0x12;
	f.source[TEST_PAGE_BYTES] = 0x34;
	assert(ntfs_mutation_bitmap_view(f.plan, &f.plan->allocation, 0, false, &view) == NTFS_OK);
	assert(view.before[0] == 0x12 && view.before == view.after);
	f.device.fail_read = f.device.reads + 1;
	assert(ntfs_mutation_bitmap_view(
		   f.plan, &f.plan->allocation, TEST_PAGE_BYTES, false, &view) == NTFS_IO);
	f.device.fail_read = 0;
	assert(ntfs_mutation_bitmap_view(f.plan, &f.plan->allocation, 0, false, &view) == NTFS_OK);
	assert(view.before[0] == 0x12 && f.device.reads == 3);
	assert(ntfs_mutation_patch(f.plan, 0, NTFS_WRITE_MUTATION_BITMAP, &patch) == NTFS_OK);
	memset(patch->after, 0x99, sizeof(patch->after));
	assert(ntfs_mutation_bitmap_view(
		   f.plan, &f.plan->allocation, TEST_PAGE_BYTES, false, &view) == NTFS_OK);
	assert(ntfs_mutation_bitmap_view(f.plan, &f.plan->allocation, 0, true, &view) == NTFS_OK);
	assert(view.before[0] == 0x12 && view.after[0] == 0x12);
	view.after[0] = 0;
	assert(ntfs_mutation_bitmap_test(f.plan, &f.plan->allocation, 1, true, &bit) == NTFS_OK &&
	    bit);
	assert(ntfs_mutation_bitmap_test(f.plan, &f.plan->allocation, 1, false, &bit) == NTFS_OK &&
	    !bit);
	view.after[0] = 0x12;
	assert(ntfs_mutation_bitmap_flush(f.plan, &f.plan->allocation) == NTFS_OK);
	close_fixture(&f);
	/* Every allocation needed to acquire the first writable page may fail.
	 * A retry must retain source bytes and balance every allocation. */
	open_fixture(&f, TEST_PAGE_BYTES + 1);
	allocations = f.device.allocations;
	assert(ntfs_mutation_bitmap_view(f.plan, &f.plan->allocation, 0, true, &view) == NTFS_OK);
	allocations = f.device.allocations - allocations;
	close_fixture(&f);
	for (fault = 1; fault <= allocations; fault++) {
		open_fixture(&f, TEST_PAGE_BYTES + 1);
		f.device.fail_allocation = f.device.allocations + fault;
		assert(ntfs_mutation_bitmap_view(f.plan, &f.plan->allocation, 0, true, &view) ==
		    NTFS_NO_MEMORY);
		f.device.fail_allocation = 0;
		assert(ntfs_mutation_bitmap_view(f.plan, &f.plan->allocation, 0, true, &view) ==
		    NTFS_OK);
		assert(view.before != view.after && view.before[0] == UINT8_MAX &&
		    view.after[0] == UINT8_MAX);
		close_fixture(&f);
	}
}

static void
allocation_failures(void)
{
	struct fixture f;
	struct ntfs_run *runs;
	uint8_t *expected;
	size_t count, bit, mode, fault, counts[2], start[2];
	bool allocated;

	open_fixture(&f, 3 * TEST_PAGE_BYTES + 1);
	memset(f.source + TEST_PAGE_BYTES, 0xaa, f.bytes - TEST_PAGE_BYTES);
	expected = malloc(f.bytes);
	assert(expected != NULL);
	memcpy(expected, f.source, f.bytes);
	for (bit = 0; bit < NTFS_MUTATION_MAX_RUNS; bit++) {
		ntfs_mutation_set_bit(expected, TEST_PAGE_BITS + bit * 2, true);
	}
	assert(ntfs_mutation_allocate_runs(f.plan, 0, NTFS_MUTATION_MAX_RUNS + 1, &runs, &count) ==
	    NTFS_RANGE);
	assert(runs == NULL && count == 0);
	check_bytes(&f, expected);
	free(expected);
	close_fixture(&f);
	open_fixture(&f, 2 * TEST_PAGE_BYTES + 1);
	for (bit = 0; bit < 3; bit++) {
		ntfs_mutation_set_bit(f.source, bit * TEST_PAGE_BITS, false);
	}
	expected = malloc(f.bytes);
	assert(expected != NULL);
	memset(expected, UINT8_MAX, f.bytes);
	assert(ntfs_mutation_allocate_runs(f.plan, 0, 4, &runs, &count) == NTFS_NO_SPACE);
	assert(runs == NULL && count == 0);
	check_bytes(&f, expected);
	free(expected);
	close_fixture(&f);
	/* Sweep every read and allocation, including faults after a prior page has
	 * changed. An error publishes no run vector and never changes source bytes. */
	open_fixture(&f, 2 * TEST_PAGE_BYTES + 1);
	f.source[0] = f.source[TEST_PAGE_BYTES] = f.source[2 * TEST_PAGE_BYTES] = 0;
	start[0] = f.device.allocations;
	start[1] = f.device.reads;
	assert(ntfs_mutation_allocate_runs(f.plan, 0, 17, &runs, &count) == NTFS_OK);
	counts[0] = f.device.allocations - start[0];
	counts[1] = f.device.reads - start[1];
	ntfs_mutation_release(f.plan, runs, NTFS_MUTATION_MAX_RUNS * sizeof(*runs));
	close_fixture(&f);
	for (mode = 0; mode < 2; mode++) {
		for (fault = 1; fault <= counts[mode]; fault++) {
			open_fixture(&f, 2 * TEST_PAGE_BYTES + 1);
			f.source[0] = f.source[TEST_PAGE_BYTES] = f.source[2 * TEST_PAGE_BYTES] = 0;
			if (mode == 0) {
				f.device.fail_allocation = f.device.allocations + fault;
			} else {
				f.device.fail_read = f.device.reads + fault;
			}
			assert(ntfs_mutation_allocate_runs(f.plan, 0, 17, &runs, &count) ==
			    (mode == 0 ? NTFS_NO_MEMORY : NTFS_IO));
			assert(runs == NULL && count == 0);
			f.device.fail_allocation = f.device.fail_read = 0;
			for (bit = 0; bit < 3; bit++) {
				assert(f.source[bit * TEST_PAGE_BYTES] == 0);
				assert(ntfs_mutation_bitmap_test(f.plan, &f.plan->allocation,
					   bit * TEST_PAGE_BITS, true, &allocated) == NTFS_OK &&
				    !allocated);
			}
			close_fixture(&f);
		}
	}
}

static void
growth_cases(void)
{
	struct fixture f;
	struct ntfs_mutation_bitmap *bitmap;
	struct ntfs_mutation_bitmap_view view;
	size_t fault, index;
	bool bit;

	for (fault = 0; fault <= 2; fault++) {
		open_fixture(&f, TEST_PAGE_BYTES);
		bitmap = &f.plan->allocation;
		bitmap->before = ntfs_mutation_allocate(f.plan, bitmap->bytes);
		bitmap->after = ntfs_mutation_allocate(f.plan, bitmap->bytes);
		assert(bitmap->before != NULL && bitmap->after != NULL);
		memcpy(bitmap->before, f.source, bitmap->bytes);
		memcpy(bitmap->after, f.source, bitmap->bytes);
		bitmap->after[0] = 0;
		if (fault != 0) {
			f.device.fail_allocation = f.device.allocations + fault;
			assert(ntfs_mutation_bitmap_grow(f.plan, bitmap, 2 * TEST_PAGE_BYTES + 1) ==
			    NTFS_NO_MEMORY);
			assert(bitmap->bytes == TEST_PAGE_BYTES && bitmap->before[0] == UINT8_MAX &&
			    bitmap->after[0] == 0);
			f.device.fail_allocation = 0;
		}
		assert(
		    ntfs_mutation_bitmap_grow(f.plan, bitmap, 2 * TEST_PAGE_BYTES + 1) == NTFS_OK);
		assert(ntfs_mutation_bitmap_view(f.plan, bitmap, 0, false, &view) == NTFS_OK);
		assert(view.before[0] == UINT8_MAX && view.after[0] == 0);
		assert(ntfs_mutation_bitmap_view(f.plan, bitmap, TEST_PAGE_BYTES, true, &view) ==
		    NTFS_OK);
		for (index = 0; index < view.bytes; index++) {
			assert(view.before[index] == 0 && view.after[index] == 0);
		}
		view.after[0] = 1;
		assert(ntfs_mutation_bitmap_test(f.plan, bitmap, TEST_PAGE_BITS, true, &bit) ==
			NTFS_OK &&
		    !bit);
		assert(ntfs_mutation_bitmap_test(f.plan, bitmap, TEST_PAGE_BITS, false, &bit) ==
			NTFS_OK &&
		    bit);
		f.device.fail_allocation = f.device.allocations + 1;
		assert(ntfs_mutation_bitmap_grow(f.plan, bitmap, 4 * TEST_PAGE_BYTES) ==
		    NTFS_NO_MEMORY);
		assert(bitmap->bytes == 2 * TEST_PAGE_BYTES + 1);
		f.device.fail_allocation = 0;
		assert(ntfs_mutation_bitmap_grow(f.plan, bitmap, 4 * TEST_PAGE_BYTES) == NTFS_OK);
		assert(ntfs_mutation_bitmap_test(f.plan, bitmap, TEST_PAGE_BITS, false, &bit) ==
			NTFS_OK &&
		    bit);
		assert(ntfs_mutation_bitmap_test(f.plan, bitmap, 4 * TEST_PAGE_BITS, false, &bit) ==
			NTFS_OK &&
		    !bit);
		assert(ntfs_mutation_bitmap_grow(
			   f.plan, bitmap, NTFS_MUTATION_MAX_BITMAP_BYTES + 1) == NTFS_RANGE);
		close_fixture(&f);
	}
}

static void
open_mft_fixture(struct fixture *f, struct ntfs_stream *mft, struct ntfs_stream *original,
    struct ntfs_run *mapping)
{
	size_t bit;

	open_fixture(f, TEST_PAGE_BYTES + 1);
	f->device.size = (TEST_PAGE_BITS + 4u) * NTFS_WRITE_CLUSTER_BYTES;
	f->volume.env.size_bytes = f->device.size;
	f->volume.info.size_bytes = f->device.size;
	f->volume.info.cluster_count = f->device.size / NTFS_WRITE_CLUSTER_BYTES;
	f->volume.mft = original;
	f->plan->source.size_bytes = f->device.size;
	f->plan->info = f->volume.info;
	f->plan->volume = &f->volume;
	f->plan->mft = mft;
	f->plan->mft_bitmap = f->plan->allocation;
	f->plan->allocation = (struct ntfs_mutation_bitmap){0};
	*mapping = (struct ntfs_run){0, TEST_PAGE_BITS, 1};
	*mft = (struct ntfs_stream){.initialized = (TEST_PAGE_BITS + 3u) * NTFS_WRITE_RECORD_BYTES,
	    .runs = mapping,
	    .run_count = 1};
	for (bit = 0; bit < NTFS_MUTATION_FIRST_ALLOCATABLE_RECORD; bit++) {
		ntfs_mutation_set_bit(f->source, bit, false);
	}
	ntfs_mutation_set_bit(f->source, TEST_PAGE_BITS - 1, false);
	ntfs_mutation_set_bit(f->source, TEST_PAGE_BITS, false);
	ntfs_mutation_set_bit(f->source, TEST_PAGE_BITS + 2, false);
	/* Clear padding beyond initialized MFT records: the scanner must ignore it. */
	for (bit = TEST_PAGE_BITS + 3; bit < f->bytes * NTFS_BITS_PER_BYTE; bit++) {
		ntfs_mutation_set_bit(f->source, bit, false);
	}
}

static void
mft_cases(void)
{
	static const uint64_t wanted[] = {TEST_PAGE_BITS - 1, TEST_PAGE_BITS, TEST_PAGE_BITS + 2};
	struct fixture f;
	struct ntfs_stream mft, original = {0};
	struct ntfs_run mapping;
	struct ntfs_mutation_record *record;
	size_t mode, fault, index, counts[2], start[2];
	bool allocated;

	open_mft_fixture(&f, &mft, &original, &mapping);
	assert(ntfs_mutation_bitmap_set(f.plan, &f.plan->mft_bitmap,
		   NTFS_MUTATION_FIRST_ALLOCATABLE_RECORD, false) == NTFS_OK);
	for (index = 0; index < sizeof(wanted) / sizeof(*wanted); index++) {
		assert(ntfs_mutation_new_record(f.plan, &record) == NTFS_OK);
		assert(record->number == wanted[index]);
	}
	close_fixture(&f);
	open_mft_fixture(&f, &mft, &original, &mapping);
	start[0] = f.device.allocations;
	start[1] = f.device.reads;
	assert(ntfs_mutation_new_record(f.plan, &record) == NTFS_OK);
	counts[0] = f.device.allocations - start[0];
	counts[1] = f.device.reads - start[1];
	close_fixture(&f);
	for (mode = 0; mode < 2; mode++) {
		for (fault = 1; fault <= counts[mode]; fault++) {
			open_mft_fixture(&f, &mft, &original, &mapping);
			if (mode == 0) {
				f.device.fail_allocation = f.device.allocations + fault;
			} else {
				f.device.fail_read = f.device.reads + fault;
			}
			assert(ntfs_mutation_new_record(f.plan, &record) ==
			    (mode == 0 ? NTFS_NO_MEMORY : NTFS_IO));
			assert(record == NULL);
			f.device.fail_allocation = f.device.fail_read = 0;
			assert(ntfs_mutation_bitmap_test(f.plan, &f.plan->mft_bitmap, wanted[0],
				   false, &allocated) == NTFS_OK &&
			    !allocated);
			assert(ntfs_mutation_new_record(f.plan, &record) == NTFS_OK &&
			    record->number == wanted[0]);
			close_fixture(&f);
		}
	}
}

int
main(void)
{
	scan_cases();
	snapshot_and_faults();
	allocation_failures();
	growth_cases();
	mft_cases();
	puts("paged bitmap first-fit/free models, ownership, exact tails, immutable reads, faults "
	     "and growth pass");
	return 0;
}
