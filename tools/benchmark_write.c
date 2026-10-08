/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
/* Share the counted immutable image backend with the mutation microbenchmarks. */
#define main ntfs_mutation_benchmark_entry
#include "benchmark_mutation.c"
#undef main
#include "write_batch_execute.h"
#include <ntfs/validate.h>

enum { BENCH_DIRECTORY_NAME_UNITS = 200 };

static enum ntfs_result
no_write(void *context, uint64_t offset, const void *bytes, size_t length, size_t *out)
{
	(void)context;
	(void)offset;
	(void)bytes;
	(void)length;
	(void)out;
	assert(false);
	return NTFS_IO;
}

static enum ntfs_result
no_persist(void *context)
{
	(void)context;
	assert(false);
	return NTFS_IO;
}

static uint64_t
semantic_digest(struct ntfs_write_mutation_plan *plan)
{
	struct ntfs_environment view;
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *root = NULL;
	struct ntfs_directory *directory = NULL;
	struct ntfs_dirent entry;
	struct ntfs_validation_report *validation;
	enum ntfs_result result;
	uint64_t digest = 0;
	size_t unit;

	validation = malloc(sizeof(*validation));
	assert(validation != NULL);
	assert(ntfs_write_mutation_plan_view(plan, &view) == NTFS_OK);
	assert(ntfs_validate(&view, NULL, NULL, validation) == NTFS_OK);
	free(validation);
	assert(ntfs_mount(&view, NULL, &volume) == NTFS_OK);
	assert(ntfs_root(volume, &root) == NTFS_OK);
	assert(ntfs_directory_open(root, &directory) == NTFS_OK);
	while ((result = ntfs_directory_next(directory, &entry)) == NTFS_OK) {
		digest = digest * UINT64_C(1099511628211) ^ entry.reference;
		digest = digest * UINT64_C(1099511628211) ^ entry.parent_reference;
		digest = digest * UINT64_C(1099511628211) ^ entry.size;
		for (unit = 0; unit < entry.name_length; unit++) {
			digest = digest * UINT64_C(1099511628211) ^ entry.name[unit];
		}
	}
	assert(result == NTFS_END);
	ntfs_directory_close(directory);
	ntfs_node_close(root);
	assert(ntfs_unmount(volume) == NTFS_OK);
	return digest;
}

int
main(int argc, char **argv)
{
	struct device device = {0}, metrics;
	struct ntfs_environment env;
	struct ntfs_overwrite_environment backend = {0};
	struct ntfs_write_mutation_plan *plan = NULL;
	struct ntfs_write_program *program = NULL;
	struct ntfs_write_batch_execution *execution = NULL;
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *root = NULL;
	struct ntfs_stat metadata;
	struct ntfs_mutation_record *record;
	struct ntfs_stream *stream;
	struct ntfs_write_mutation_request request = {
	    .kind = NTFS_WRITE_CREATE_FILE, .filetime = BENCH_FILETIME};
	uint16_t name[BENCH_DIRECTORY_NAME_UNITS];
	FILE *file;
	long length;
	uint64_t start, elapsed, checksum;
	size_t index, unit, count, regions = 0, updates = 0, publications = 0;
	bool seed, planning, compiling, streams;

	assert(argc == 4 || argc == 5);
	seed = strcmp(argv[1], "seed") == 0;
	planning = strcmp(argv[1], "plan") == 0;
	compiling = strcmp(argv[1], "program") == 0;
	streams = strcmp(argv[1], "stream") == 0;
	assert(seed || planning || compiling || streams || strcmp(argv[1], "execution") == 0);
	count = (size_t)strtoull(argv[2], NULL, 10);
	assert(count > 0);
	file = fopen(argv[3], "rb");
	assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
	length = ftell(file);
	assert(length > 0 && fseek(file, 0, SEEK_SET) == 0);
	device.size = device.backing_bytes = (size_t)length;
	device.data = malloc(device.backing_bytes);
	assert(device.data != NULL &&
	    fread(device.data, 1, device.backing_bytes, file) == device.backing_bytes &&
	    fclose(file) == 0);
	env = environment(&device);
	backend.reader = env;
	backend.api_version = NTFS_OVERWRITE_API_VERSION;
	backend.alignment = NTFS_WRITE_SECTOR_BYTES;
	backend.write = no_write;
	backend.persist = no_persist;
	assert(ntfs_mount(&env, NULL, &volume) == NTFS_OK);
	assert(ntfs_root(volume, &root) == NTFS_OK && ntfs_node_stat(root, &metadata) == NTFS_OK);
	ntfs_node_close(root);
	assert(ntfs_unmount(volume) == NTFS_OK);
	for (unit = 0; unit < BENCH_DIRECTORY_NAME_UNITS; unit++) {
		name[unit] = 'n';
	}
	request.source =
	    (struct ntfs_write_name){metadata.reference, name, BENCH_DIRECTORY_NAME_UNITS};
	if (seed) {
		assert(argc == 5 && count <= UINT16_MAX);
		for (index = 0; index < count; index++) {
			for (unit = 0; unit < sizeof(uint16_t) * 2; unit++) {
				name[unit] = (uint16_t)('a' +
				    ((index >> ((sizeof(uint16_t) * 2 - unit - 1) * 4)) & 15));
			}
			(void)apply_seed(&device, &request);
		}
		assert(device.seed == NULL && device.live == 0);
		file = fopen(argv[4], "wb");
		assert(file != NULL &&
		    fwrite(device.data, 1, device.backing_bytes, file) == device.backing_bytes &&
		    fclose(file) == 0);
		printf("{\"seeded\":%zu}\n", count);
		free(device.data);
		return 0;
	}
	name[0] = 'z';
	if (!planning) {
		assert(ntfs_write_mutation_prepare(&env, &request, &plan) == NTFS_OK);
	}
	if (!planning && !compiling && !streams) {
		assert(ntfs_write_program_prepare(&env, plan, &program) == NTFS_OK);
	}
	if (streams) {
		assert(ntfs_mutation_record_get(plan, NTFS_MFT_RECORD, true, &record) == NTFS_OK);
	}
	reset_counts(&device);
	start = now();
	for (index = 0; index < count; index++) {
		if (planning) {
			ntfs_write_mutation_plan_close(plan);
			assert(ntfs_write_mutation_prepare(&env, &request, &plan) == NTFS_OK);
		} else if (compiling) {
			ntfs_write_program_close(program);
			assert(ntfs_write_program_prepare(&env, plan, &program) == NTFS_OK);
		} else if (streams) {
			assert(ntfs_mutation_stream(
				   plan, record, NTFS_ATTRIBUTE_DATA, NULL, 0, &stream) == NTFS_OK);
			assert(stream->run_count != 0);
			ntfs_stream_close(stream);
		} else {
			ntfs_write_batch_execution_close(execution);
			assert(ntfs_write_batch_execute_prepare(&backend, program, &execution) ==
			    NTFS_OK);
		}
	}
	elapsed = now() - start;
	metrics = device;
	regions = ntfs_write_mutation_plan_count(plan);
	updates = ntfs_write_program_count(program);
	publications = ntfs_write_batch_execution_count(execution);
	checksum = semantic_digest(plan);
	ntfs_write_batch_execution_close(execution);
	ntfs_write_program_close(program);
	ntfs_write_mutation_plan_close(plan);
	assert(device.live == 0);
	printf("{\"case\":\"%s\",\"iterations\":%zu,\"ns\":%" PRIu64 ",\"checksum\":%" PRIu64
	       ",\"reads\":%zu,\"read_bytes\":%" PRIu64
	       ",\"allocations\":%zu,\"allocation_bytes\":%" PRIu64
	       ",\"peak_live_bytes\":%zu,\"regions\":%zu,\"updates\":%zu,\"publications\":%zu}\n",
	    argv[1], count, elapsed, checksum, metrics.reads, metrics.read_bytes,
	    metrics.allocations, metrics.allocation_bytes, metrics.peak, regions, updates,
	    publications);
	free(device.data);
	return 0;
}
