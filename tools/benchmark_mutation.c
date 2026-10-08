/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_mutation_internal.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum {
	BENCH_BITS = 1024 * 1024,
	BENCH_KEYS = 1024,
	BENCH_READ_BYTES = 64,
	BENCH_FILE_BYTES = 1024 * 1024
};

#define BENCH_FILETIME UINT64_C(134357146906613431)
#define BENCH_VIRTUAL_BYTES (UINT64_C(1) << 34)

struct seed_region {
	struct seed_region *next;
	uint64_t physical;
	uint8_t bytes[NTFS_WRITE_CLUSTER_BYTES];
};

struct device {
	uint8_t *data;
	struct seed_region *seed;
	uint64_t size, read_bytes, allocation_bytes;
	size_t backing_bytes, live, peak, allocations, reads, maximum_live;
};

static void *
allocate(void *context, size_t size)
{
	struct device *device = context;
	void *bytes = malloc(size);

	assert(bytes != NULL);
	device->allocations++;
	device->allocation_bytes += size;
	device->live += size;
	if (device->live > device->peak) {
		device->peak = device->live;
	}
	assert(device->maximum_live == 0 || device->peak <= device->maximum_live);
	return bytes;
}

static void
release(void *context, void *bytes, size_t size)
{
	struct device *device = context;

	assert(bytes != NULL && size <= device->live);
	device->live -= size;
	free(bytes);
}

static enum ntfs_result
read_bytes(void *context, uint64_t offset, void *bytes, size_t size)
{
	struct device *device = context;
	const struct seed_region *region;
	uint64_t first, end;
	size_t take;

	assert(offset <= device->size && size <= device->size - offset);
	device->reads++;
	device->read_bytes += size;
	memset(bytes, 0, size);
	if (device->data != NULL && offset < device->backing_bytes) {
		take = device->backing_bytes - (size_t)offset;
		if (take > size) {
			take = size;
		}
		memcpy(bytes, device->data + offset, take);
	}
	for (region = device->seed; region != NULL; region = region->next) {
		first = offset > region->physical ? offset : region->physical;
		end = offset + size < region->physical + sizeof(region->bytes)
		    ? offset + size
		    : region->physical + sizeof(region->bytes);
		if (first < end) {
			memcpy((uint8_t *)bytes + (size_t)(first - offset),
			    region->bytes + (size_t)(first - region->physical),
			    (size_t)(end - first));
		}
	}
	return NTFS_OK;
}

static struct ntfs_environment
environment(struct device *device)
{
	return (struct ntfs_environment){
	    NTFS_API_VERSION, device, device->size, read_bytes, allocate, release};
}

static void
reset_counts(struct device *device)
{
	device->peak = device->live;
	device->reads = device->allocations = 0;
	device->read_bytes = device->allocation_bytes = 0;
}

static uint64_t
now(void)
{
	struct timespec value;

	assert(clock_gettime(CLOCK_MONOTONIC, &value) == 0);
	return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}

static struct ntfs_write_mutation_plan *
open_plan(struct device *device)
{
	struct ntfs_write_mutation_plan *plan = allocate(device, sizeof(*plan));

	memset(plan, 0, sizeof(*plan));
	plan->source = environment(device);
	plan->info.size_bytes = device->size;
	plan->info.cluster_count = device->size / NTFS_WRITE_CLUSTER_BYTES;
	return plan;
}

static uint64_t
lookup(struct device *device, const char *mode, unsigned iterations, uint64_t *elapsed)
{
	struct ntfs_write_mutation_plan *plan = open_plan(device);
	struct ntfs_mutation_patch *patch;
	struct ntfs_mutation_record *record;
	struct ntfs_volume volume = {0};
	struct ntfs_stream original = {0}, mft = {0};
	struct ntfs_run run = {0, BENCH_BITS, 1};
	uint8_t output[BENCH_READ_BYTES];
	uint64_t start, checksum = 0;
	size_t index, key, count = strcmp(mode, "patch-small") == 0 ? 8 : BENCH_KEYS;
	unsigned iteration;
	bool records = strcmp(mode, "record") == 0, reads = strcmp(mode, "overlay") == 0;

	volume.mft = &original;
	mft.runs = &run;
	mft.run_count = 1;
	mft.initialized = (uint64_t)BENCH_BITS * NTFS_WRITE_RECORD_BYTES;
	plan->volume = &volume;
	plan->mft = &mft;
	for (index = 0; index < count; index++) {
		key = index * (count - 1) % count;
		if (records) {
			assert(ntfs_mutation_record_get(plan, key, true, &record) == NTFS_OK);
		} else {
			assert(ntfs_mutation_patch(plan, key * NTFS_WRITE_CLUSTER_BYTES,
				   NTFS_WRITE_MUTATION_DATA, &patch) == NTFS_OK);
			patch->after[0] = (uint8_t)(key % UINT8_MAX);
		}
	}
	reset_counts(device);
	start = now();
	for (iteration = 0; iteration < iterations; iteration++) {
		for (key = 0; key < count; key++) {
			if (records) {
				assert(
				    ntfs_mutation_record_get(plan, key, true, &record) == NTFS_OK);
				checksum += record->number;
			} else if (reads) {
				assert(ntfs_mutation_read(plan, key * NTFS_WRITE_CLUSTER_BYTES,
					   output, sizeof(output)) == NTFS_OK);
				checksum += output[0];
			} else {
				assert(ntfs_mutation_patch(plan, key * NTFS_WRITE_CLUSTER_BYTES,
					   NTFS_WRITE_MUTATION_DATA, &patch) == NTFS_OK);
				checksum += patch->after[0];
			}
		}
	}
	*elapsed = now() - start;
	plan->volume = NULL;
	plan->mft = NULL;
	ntfs_write_mutation_plan_close(plan);
	return checksum;
}

static uint64_t
bitmap(struct device *device, bool freeing, unsigned iterations, uint64_t *elapsed)
{
	struct ntfs_write_mutation_plan *plan = open_plan(device);
	struct ntfs_mutation_record *record;
	struct ntfs_volume volume = {0};
	struct ntfs_stream original = {0}, mft = {0}, stream = {0};
	struct ntfs_run run = {0, BENCH_BITS, 0};
	uint8_t *before = malloc(BENCH_BITS / NTFS_BITS_PER_BYTE);
	uint8_t *after = malloc(BENCH_BITS / NTFS_BITS_PER_BYTE);
	uint64_t start, checksum = 0;
	unsigned iteration;

	assert(before != NULL && after != NULL);
	memset(before, UINT8_MAX, BENCH_BITS / NTFS_BITS_PER_BYTE);
	volume.mft = &original;
	mft.runs = &run;
	mft.run_count = 1;
	mft.initialized = (uint64_t)BENCH_BITS * NTFS_WRITE_RECORD_BYTES;
	stream.runs = &run;
	stream.run_count = 1;
	stream.clusters = BENCH_BITS;
	plan->volume = &volume;
	plan->mft = &mft;
	if (freeing) {
		plan->allocation = (struct ntfs_mutation_bitmap){
		    .before = before, .after = after, .bytes = BENCH_BITS / NTFS_BITS_PER_BYTE};
	} else {
		ntfs_mutation_set_bit(before, BENCH_BITS - 1, false);
		plan->mft_bitmap = (struct ntfs_mutation_bitmap){
		    .before = before, .after = after, .bytes = BENCH_BITS / NTFS_BITS_PER_BYTE};
	}
	reset_counts(device);
	start = now();
	for (iteration = 0; iteration < iterations; iteration++) {
		memcpy(after, before, BENCH_BITS / NTFS_BITS_PER_BYTE);
		if (freeing) {
			assert(ntfs_mutation_free_runs(plan, &stream, 0) == NTFS_OK);
			checksum += after[BENCH_BITS / NTFS_BITS_PER_BYTE - 1];
		} else {
			assert(ntfs_mutation_new_record(plan, &record) == NTFS_OK);
			assert(record->number == BENCH_BITS - 1);
			checksum += record->number;
		}
	}
	*elapsed = now() - start;
	if (freeing) {
		for (iteration = 0; iteration < BENCH_BITS / NTFS_BITS_PER_BYTE; iteration++) {
			assert(after[iteration] == 0);
		}
	}
	plan->volume = NULL;
	plan->mft = NULL;
	plan->allocation = plan->mft_bitmap = (struct ntfs_mutation_bitmap){0};
	ntfs_write_mutation_plan_close(plan);
	free(after);
	free(before);
	return checksum;
}

static uint64_t
apply_seed(struct device *device, const struct ntfs_write_mutation_request *request)
{
	struct ntfs_environment env = environment(device);
	struct ntfs_write_mutation_plan *plan = NULL;
	struct ntfs_write_mutation_region region;
	struct seed_region *seed;
	size_t index;
	uint64_t reference;

	assert(ntfs_write_mutation_prepare(&env, request, &plan) == NTFS_OK);
	reference = ntfs_write_mutation_plan_reference(plan);
	for (index = 0; index < ntfs_write_mutation_plan_count(plan); index++) {
		assert(ntfs_write_mutation_plan_region(plan, index, &region) == NTFS_OK);
		if (ntfs_bounds(region.physical, region.bytes, device->backing_bytes)) {
			memcpy(device->data + region.physical, region.after, region.bytes);
			continue;
		}
		assert(region.bytes == NTFS_WRITE_CLUSTER_BYTES);
		for (seed = device->seed; seed != NULL; seed = seed->next) {
			if (seed->physical == region.physical) {
				break;
			}
		}
		if (seed == NULL) {
			seed = malloc(sizeof(*seed));
			assert(seed != NULL);
			seed->physical = region.physical;
			seed->next = device->seed;
			device->seed = seed;
		}
		memcpy(seed->bytes, region.after, region.bytes);
	}
	ntfs_write_mutation_plan_close(plan);
	return reference;
}

static uint64_t
mutation(struct device *device, const char *mode, unsigned iterations, uint64_t *elapsed)
{
	static const uint16_t name[] = {'b', 'e', 'n', 'c', 'h'};
	struct ntfs_environment env = environment(device);
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *root = NULL;
	struct ntfs_stat metadata;
	struct ntfs_write_mutation_request request = {
	    .kind = NTFS_WRITE_CREATE_FILE, .filetime = BENCH_FILETIME};
	struct ntfs_write_mutation_plan *plan = NULL;
	struct ntfs_write_mutation_region region;
	uint64_t start, checksum = 0, reference;
	uint8_t *payload = NULL;
	size_t index, byte;
	unsigned iteration;

	assert(ntfs_mount(&env, NULL, &volume) == NTFS_OK);
	assert(ntfs_root(volume, &root) == NTFS_OK);
	assert(ntfs_node_stat(root, &metadata) == NTFS_OK);
	request.source =
	    (struct ntfs_write_name){metadata.reference, name, sizeof(name) / sizeof(*name)};
	ntfs_node_close(root);
	assert(ntfs_unmount(volume) == NTFS_OK);
	if (strcmp(mode, "create") != 0) {
		reference = apply_seed(device, &request);
		request.kind = NTFS_WRITE_RESIZE_FILE;
		request.reference = reference;
		request.size = BENCH_FILE_BYTES;
		assert(apply_seed(device, &request) == reference);
		request.size = strcmp(mode, "grow") == 0 ? 2 * BENCH_FILE_BYTES : BENCH_READ_BYTES;
		if (strcmp(mode, "unlink") == 0) {
			request.kind = NTFS_WRITE_REMOVE_FILE;
		} else if (strcmp(mode, "grow-write") == 0) {
			payload = malloc(BENCH_FILE_BYTES);
			assert(payload != NULL);
			memset(payload, 0xa5, BENCH_FILE_BYTES);
			request.kind = NTFS_WRITE_GROWING_RANGE;
			request.offset = BENCH_FILE_BYTES;
			request.bytes = BENCH_FILE_BYTES;
			request.data = payload;
		}
	}
	reset_counts(device);
	start = now();
	for (iteration = 0; iteration < iterations; iteration++) {
		ntfs_write_mutation_plan_close(plan);
		assert(ntfs_write_mutation_prepare(&env, &request, &plan) == NTFS_OK);
		checksum +=
		    ntfs_write_mutation_plan_reference(plan) + ntfs_write_mutation_plan_count(plan);
	}
	*elapsed = now() - start;
	/* Hash all final regions outside timing. Repeated preparations leave the
	 * same seed image untouched; this measures planning, not durable execution. */
	for (index = 0; index < ntfs_write_mutation_plan_count(plan); index++) {
		assert(ntfs_write_mutation_plan_region(plan, index, &region) == NTFS_OK);
		checksum = checksum * UINT64_C(1099511628211) ^ region.physical;
		for (byte = 0; byte < region.bytes; byte++) {
			checksum = checksum * UINT64_C(1099511628211) ^ region.after[byte];
		}
	}
	ntfs_write_mutation_plan_close(plan);
	free(payload);
	return checksum;
}

int
main(int argc, char **argv)
{
	struct device device = {.size = BENCH_VIRTUAL_BYTES};
	struct seed_region *seed;
	FILE *file;
	const struct ntfs_disk_boot *boot;
	long length;
	unsigned iterations;
	uint64_t checksum, elapsed;

	assert(argc == 3 || argc == 4 || argc == 5);
	iterations = (unsigned)strtoul(argv[2], NULL, 10);
	assert(iterations != 0);
	if (argc >= 4) {
		file = fopen(argv[3], "rb");
		assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
		length = ftell(file);
		assert(length > 0 && fseek(file, 0, SEEK_SET) == 0);
		device.backing_bytes = (size_t)length;
		device.data = malloc((size_t)length);
		assert(device.data != NULL &&
		    fread(device.data, 1, (size_t)length, file) == (size_t)length);
		assert(fclose(file) == 0);
		assert(device.backing_bytes >= sizeof(*boot));
		boot = (const void *)device.data;
		device.size = ntfs_u64(boot->sectors) * ntfs_u16(boot->sector_size);
		if (device.size < device.backing_bytes) {
			device.size = device.backing_bytes;
		}
		if (argc == 5) {
			device.maximum_live = (size_t)strtoull(argv[4], NULL, 10);
		}
		checksum = mutation(&device, argv[1], iterations, &elapsed);
	} else if (strcmp(argv[1], "free") == 0 || strcmp(argv[1], "mft") == 0) {
		checksum = bitmap(&device, strcmp(argv[1], "free") == 0, iterations, &elapsed);
	} else {
		checksum = lookup(&device, argv[1], iterations, &elapsed);
	}
	assert(device.live == 0);
	printf("{\"case\":\"%s\",\"ns\":%" PRIu64 ",\"checksum\":%" PRIu64
	       ",\"reads\":%zu,\"read_bytes\":%" PRIu64 ",\"allocations\":%zu,"
	       "\"allocation_bytes\":%" PRIu64 ",\"peak_live_bytes\":%zu}\n",
	    argv[1], elapsed, checksum, device.reads, device.read_bytes, device.allocations,
	    device.allocation_bytes, device.peak);
	free(device.data);
	while (device.seed != NULL) {
		seed = device.seed;
		device.seed = seed->next;
		free(seed);
	}
	return 0;
}
