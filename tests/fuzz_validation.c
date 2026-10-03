/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/validate.h>
#include "fuzz_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	VALIDATION_FUZZ_RECORDS = 128,
	VALIDATION_FUZZ_RUNS = 256,
	VALIDATION_FUZZ_LINKS = 256,
	VALIDATION_FUZZ_MEMORY = 2 * 1024 * 1024,
	VALIDATION_FUZZ_READS = 256,
	VALIDATION_FUZZ_READ_BYTES = 2 * 1024 * 1024,
	VALIDATION_FUZZ_WORK = 8 * 1024 * 1024,
	VALIDATION_FUZZ_LIST_BYTES = 64 * 1024,
	VALIDATION_FUZZ_DIRECTORY_NODES = 128,
	VALIDATION_FUZZ_REPETITIONS = 2,
	VALIDATION_FUZZ_MUTATIONS = 256,
	VALIDATION_FUZZ_MUTATION_BYTES = 512 * 1024,
	VALIDATION_FUZZ_BOOT_MAX_SECTOR_BYTES = 4096,
	VALIDATION_FUZZ_IMAGE_BYTES = 8 * 1024 * 1024 + VALIDATION_FUZZ_BOOT_MAX_SECTOR_BYTES,
	VALIDATION_FUZZ_BYTE_BITS = 8
};

/* Numerical Recipes LCG for reproducible standalone smoke mutations. */
#define VALIDATION_RANDOM_SEED UINT32_C(0x1a6fced9)
#define VALIDATION_RANDOM_MULTIPLIER UINT32_C(1664525)
#define VALIDATION_RANDOM_INCREMENT UINT32_C(1013904223)

int
LLVMFuzzerTestOneInput(const uint8_t *bytes, size_t size)
{
	struct fuzz_device device = {.data = bytes, .size = size};
	struct ntfs_environment environment = fuzz_environment(&device);
	struct ntfs_limits core_limits;
	struct ntfs_validation_limits limits = {VALIDATION_FUZZ_RECORDS, VALIDATION_FUZZ_RUNS,
	    VALIDATION_FUZZ_LINKS, VALIDATION_FUZZ_MEMORY, VALIDATION_FUZZ_READS,
	    VALIDATION_FUZZ_READ_BYTES, VALIDATION_FUZZ_WORK};
	struct ntfs_validation_report report, previous = {0};
	enum ntfs_result result;
	unsigned i;

	ntfs_default_limits(&core_limits);
	core_limits.max_runs = VALIDATION_FUZZ_RUNS;
	core_limits.max_attribute_list = VALIDATION_FUZZ_LIST_BYTES;
	core_limits.record_cache_entries = 0;
	core_limits.max_directory_nodes = VALIDATION_FUZZ_DIRECTORY_NODES;
	for (i = 0; i < VALIDATION_FUZZ_REPETITIONS; i++) {
		device.reads = 0;
		device.allocations = 0;
		result = ntfs_validate(&environment, &core_limits, &limits, &report);
		assert(result == report.result && report.complete == (result == NTFS_OK));
		assert((report.stage == NTFS_VALIDATION_FINISHED) == report.complete);
		assert(device.memory == 0 && device.reads == report.read_calls);
		assert(device.allocations == report.allocation_calls);
		assert(report.read_calls <= limits.max_read_calls &&
		    report.read_bytes <= limits.max_read_bytes);
		assert(report.work_units <= limits.max_work_units &&
		    report.peak_memory_bytes <= limits.max_memory_bytes);
		if (report.complete) {
			assert(report.exhausted == NTFS_VALIDATION_LIMIT_NONE);
			assert(report.allocated_clusters == report.claimed_clusters &&
			    report.unclaimed_clusters == 0);
			assert(report.record_slots == report.records_scanned &&
			    report.deferred_dos_link_counts == 0);
		}
		if (i != 0) {
			assert(memcmp(&previous, &report, sizeof(report)) == 0);
		}
		previous = report;
	}
	return 0;
}

#ifdef NTFS_FUZZ_STANDALONE
int
main(int argc, char **argv)
{
	FILE *source;
	uint8_t *bytes, saved;
	long size;
	size_t i, offset;
	uint32_t random = VALIDATION_RANDOM_SEED;

	assert(argc == 2);
	source = fopen(argv[1], "rb");
	assert(source != NULL && fseek(source, 0, SEEK_END) == 0);
	size = ftell(source);
	assert(size > 0 && size <= VALIDATION_FUZZ_IMAGE_BYTES && fseek(source, 0, SEEK_SET) == 0);
	bytes = malloc((size_t)size);
	assert(bytes != NULL);
	assert(fread(bytes, 1, (size_t)size, source) == (size_t)size && fclose(source) == 0);
	LLVMFuzzerTestOneInput(bytes, (size_t)size);
	for (i = 0; i < VALIDATION_FUZZ_MUTATIONS; i++) {
		random = random * VALIDATION_RANDOM_MULTIPLIER + VALIDATION_RANDOM_INCREMENT;
		offset = random %
		    ((size_t)size < VALIDATION_FUZZ_MUTATION_BYTES
			    ? (size_t)size
			    : VALIDATION_FUZZ_MUTATION_BYTES);
		saved = bytes[offset];
		bytes[offset] ^= (uint8_t)(1u << (i % VALIDATION_FUZZ_BYTE_BITS));
		LLVMFuzzerTestOneInput(bytes, (size_t)size);
		bytes[offset] = saved;
	}
	free(bytes);
	printf("PASS: %u deterministic diagnostic mutations and repeatable bounded reports\n",
	    VALIDATION_FUZZ_MUTATIONS);
	return 0;
}
#endif
