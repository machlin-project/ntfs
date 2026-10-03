/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/ntfs.h>
#include <ntfs/security.h>
#include <ntfs/logfile.h>
#include "fuzz_device.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

enum {
	FUZZ_MAX_RUNS = 1024,
	FUZZ_MAX_ATTRIBUTE_LIST = 65536,
	FUZZ_CACHE_ENTRIES = 4,
	FUZZ_MAX_DIRECTORY_NODES = 128,
	FUZZ_READ_BUFFER_BYTES = 1024,
	FUZZ_REPARSE_NAME_UNITS = 128,
	FUZZ_DIRECTORY_ENTRIES = 64,
	FUZZ_STREAM_NAMES = 32,
	FUZZ_JOURNAL_CLIENTS = 32,
	FUZZ_JOURNAL_PAGE_POSITIONS = 2,
	FUZZ_JOURNAL_GUARD_BYTES = 16,
	FUZZ_RESTART_PAGE_COUNT = 2,
	FUZZ_CONTENT_POSITIONS = 3,
	FUZZ_MUTATIONS = 2000,
	FUZZ_MUTATION_REGION = 512 * 1024,
	FUZZ_BITS_PER_BYTE = 8,
	FUZZ_COPY_GUARD = 0xa6
};

struct operation_credit_seed {
	uint8_t dimension, credit;
};

/* Fixed Numerical Recipes LCG parameters make smoke mutations reproducible. */
#define FUZZ_RANDOM_SEED UINT32_C(0x85a7f12d)
#define FUZZ_RANDOM_MULTIPLIER UINT32_C(1664525)
#define FUZZ_RANDOM_INCREMENT UINT32_C(1013904223)

static void
fuzz_journal(struct ntfs_volume *volume, struct fuzz_device *device)
{
	struct ntfs_logfile *source = NULL;
	struct ntfs_logfile_restart restart;
	struct ntfs_logfile_client client;
	struct ntfs_logfile_page_view view, zero = {0};
	uint8_t *guarded;
	uint64_t offset;
	size_t i, j, bytes;
	enum ntfs_result result;

	if (ntfs_logfile_open_volume(volume, NULL, NULL, &source) != NTFS_OK) {
		assert(source == NULL);
		return;
	}
	assert(ntfs_unmount(volume) == NTFS_BUSY);
	assert(ntfs_logfile_get_restart(source, &restart) == NTFS_OK);
	for (i = 0; i < restart.client_count && i < FUZZ_JOURNAL_CLIENTS; i++) {
		assert(ntfs_logfile_get_client(source, (uint16_t)i, &client) == NTFS_OK);
	}
	bytes = restart.log_page_bytes + FUZZ_JOURNAL_GUARD_BYTES * 2;
	guarded = fuzz_allocate(device, bytes);
	if (guarded != NULL) {
		for (i = 0; i < FUZZ_JOURNAL_PAGE_POSITIONS; i++) {
			offset = i == 0
			    ? restart.circular_offset
			    : (uint64_t)FUZZ_RESTART_PAGE_COUNT * restart.system_page_bytes;
			memset(guarded, FUZZ_COPY_GUARD, bytes);
			result = ntfs_logfile_read_page(source, offset,
			    guarded + FUZZ_JOURNAL_GUARD_BYTES, restart.log_page_bytes, &view);
			if (result == NTFS_OK) {
				assert(view.offset == offset);
			} else {
				assert(memcmp(&view, &zero, sizeof(view)) == 0);
			}
			for (j = 0; j < bytes; j++) {
				if (result != NTFS_OK || j < FUZZ_JOURNAL_GUARD_BYTES ||
				    j >= bytes - FUZZ_JOURNAL_GUARD_BYTES) {
					assert(guarded[j] == FUZZ_COPY_GUARD);
				}
			}
		}
		fuzz_release(device, guarded, bytes);
	}
	ntfs_logfile_close(source);
}

static void
fuzz_budgeted(
    struct ntfs_volume *volume, struct fuzz_device *device, const uint8_t *data, size_t size)
{
	struct operation_credit_seed seed;
	struct ntfs_operation_limits limits;
	struct ntfs_operation operation = {0};
	struct ntfs_operation_usage usage;
	struct ntfs_node *root = NULL, *node = NULL;
	struct ntfs_directory *directory = NULL;
	struct ntfs_stream *stream = NULL;
	struct ntfs_stat stat;
	struct ntfs_dirent entry;
	uint8_t buffer[FUZZ_READ_BUFFER_BYTES];
	uint64_t credit;
	size_t i, done, reads = device->reads, allocations = device->allocations;
	enum ntfs_operation_limit dimension;

	if (size < sizeof(seed)) {
		return;
	}
	/* An additional budgeted walk retains the existing unrestricted parser walk.
	 * The unused image tail supplies fuzz policy bytes, never NTFS field offsets. */
	memcpy(&seed, data + size - sizeof(seed), sizeof(seed));
	dimension = NTFS_OPERATION_LIMIT_READ_CALLS +
	    seed.dimension % (NTFS_OPERATION_LIMIT_WORK - NTFS_OPERATION_LIMIT_READ_CALLS + 1);
	credit = (uint64_t)seed.credit + 1;
	ntfs_get_operation_limits(volume, &limits);
	switch (dimension) {
	case NTFS_OPERATION_LIMIT_READ_CALLS:
		limits.read_calls = credit;
		break;
	case NTFS_OPERATION_LIMIT_READ_BYTES:
		limits.read_bytes = credit * FUZZ_READ_BUFFER_BYTES;
		break;
	case NTFS_OPERATION_LIMIT_ALLOCATION_CALLS:
		limits.allocation_calls = credit;
		break;
	case NTFS_OPERATION_LIMIT_ALLOCATION_BYTES:
		limits.allocation_bytes = credit * FUZZ_READ_BUFFER_BYTES;
		break;
	case NTFS_OPERATION_LIMIT_WORK:
		limits.work = credit * FUZZ_READ_BUFFER_BYTES;
		break;
	default:
		assert(false);
	}
	assert(ntfs_operation_begin(volume, &limits, &operation) == NTFS_OK);
	if (ntfs_root(volume, &root) == NTFS_OK &&
	    ntfs_directory_open(root, &directory) == NTFS_OK) {
		for (i = 0;
		    i < FUZZ_DIRECTORY_ENTRIES && ntfs_directory_next(directory, &entry) == NTFS_OK;
		    i++) {
			if (ntfs_node_open(volume, entry.reference, &node) == NTFS_OK) {
				(void)ntfs_node_stat(node, &stat);
				if (ntfs_stream_open(node, NULL, 0, &stream) == NTFS_OK) {
					(void)ntfs_stream_read(
					    stream, 0, buffer, sizeof(buffer), &done);
					ntfs_stream_close(stream);
					stream = NULL;
				}
				ntfs_node_close(node);
				node = NULL;
			}
		}
	}
	ntfs_directory_close(directory);
	ntfs_node_close(root);
	assert(ntfs_operation_end(&operation, &usage) == NTFS_OK);
	assert(usage.read_calls == device->reads - reads &&
	    usage.allocation_calls == device->allocations - allocations);
	assert(usage.read_calls <= limits.read_calls && usage.read_bytes <= limits.read_bytes &&
	    usage.allocation_calls <= limits.allocation_calls &&
	    usage.allocation_bytes <= limits.allocation_bytes && usage.work <= limits.work);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct fuzz_device d = {.data = data, .size = size};
	struct ntfs_environment env = fuzz_environment(&d);
	struct ntfs_limits limits;
	struct ntfs_volume *v = NULL;
	struct ntfs_node *root = NULL, *node = NULL;
	struct ntfs_directory *directory = NULL;
	struct ntfs_stream *stream = NULL;
	struct ntfs_reparse *reparse = NULL;
	struct ntfs_stream_catalog *catalog = NULL;
	struct ntfs_security *security = NULL;
	struct ntfs_stream_name stream_name;
	struct ntfs_reparse_info reparse_info;
	struct ntfs_reparse_info copied_reparse_info;
	struct ntfs_dirent entry;
	uint8_t buffer[FUZZ_READ_BUFFER_BYTES];
	uint16_t reparse_name[FUZZ_REPARSE_NAME_UNITS];
	size_t i, j, count, required;
	uint64_t stream_size, offset;
	enum ntfs_result result;

	(void)ntfs_reparse_decode(data, size, &reparse_info);
	ntfs_default_limits(&limits);
	limits.max_runs = FUZZ_MAX_RUNS;
	limits.max_attribute_list = FUZZ_MAX_ATTRIBUTE_LIST;
	limits.record_cache_entries = FUZZ_CACHE_ENTRIES;
	limits.max_directory_nodes = FUZZ_MAX_DIRECTORY_NODES;
	if (ntfs_mount(&env, &limits, &v) == NTFS_OK) {
		fuzz_journal(v, &d);
	}
	if (v != NULL && ntfs_root(v, &root) == NTFS_OK &&
	    ntfs_directory_open(root, &directory) == NTFS_OK) {
		for (i = 0;
		    i < FUZZ_DIRECTORY_ENTRIES && ntfs_directory_next(directory, &entry) == NTFS_OK;
		    i++) {
			if (ntfs_node_open(v, entry.reference, &node) == NTFS_OK) {
				if (ntfs_security_open(node, &security) == NTFS_OK) {
					(void)ntfs_security_copy(
					    security, buffer, sizeof(buffer), &count);
					ntfs_security_close(security);
					security = NULL;
				}
				if (ntfs_stream_catalog_open(node, FUZZ_STREAM_NAMES, &catalog) ==
				    NTFS_OK) {
					for (j = 0; j < ntfs_stream_catalog_count(catalog); j++) {
						if (ntfs_stream_catalog_entry(catalog, (uint32_t)j,
							&stream_name) == NTFS_OK &&
						    stream_name.length != 0 &&
						    ntfs_stream_open(node, stream_name.units,
							stream_name.length, &stream) == NTFS_OK) {
							(void)ntfs_stream_read(stream, 0, buffer,
							    sizeof(buffer), &count);
							ntfs_stream_close(stream);
							stream = NULL;
						}
					}
					ntfs_stream_catalog_close(catalog);
					catalog = NULL;
				}
				if (ntfs_reparse_open(node, &reparse) == NTFS_OK) {
					ntfs_reparse_get_info(reparse, &reparse_info);
					assert(ntfs_reparse_bytes(reparse, NULL, 0, &required) ==
						NTFS_RANGE &&
					    required != 0);
					memset(buffer, FUZZ_COPY_GUARD, sizeof(buffer));
					result = ntfs_reparse_bytes(
					    reparse, buffer, sizeof(buffer) - 1, &count);
					assert(count == required);
					if (result == NTFS_OK) {
						assert(ntfs_reparse_decode(buffer, count,
							   &copied_reparse_info) == NTFS_OK &&
						    memcmp(&reparse_info, &copied_reparse_info,
							sizeof(reparse_info)) == 0);
					} else {
						assert(result == NTFS_RANGE);
					}
					for (j = result == NTFS_OK ? count : 0; j < sizeof(buffer);
					    j++) {
						assert(buffer[j] == FUZZ_COPY_GUARD);
					}
					(void)ntfs_reparse_name(reparse,
					    NTFS_REPARSE_SUBSTITUTE_NAME, reparse_name,
					    FUZZ_REPARSE_NAME_UNITS, &count);
					(void)ntfs_reparse_name(reparse, NTFS_REPARSE_PRINT_NAME,
					    reparse_name, FUZZ_REPARSE_NAME_UNITS, &count);
					ntfs_reparse_close(reparse);
					reparse = NULL;
				}
				if (ntfs_stream_open(node, NULL, 0, &stream) == NTFS_OK) {
					stream_size = ntfs_stream_size(stream);
					for (j = 0; j < FUZZ_CONTENT_POSITIONS; j++) {
						offset = j == 0 ? 0 : stream_size / 2;
						if (j == FUZZ_CONTENT_POSITIONS - 1) {
							offset = stream_size > sizeof(buffer)
							    ? stream_size - sizeof(buffer)
							    : 0;
						}
						(void)ntfs_stream_read(
						    stream, offset, buffer, sizeof(buffer), &count);
					}
					ntfs_stream_close(stream);
					stream = NULL;
				}
				ntfs_node_close(node);
				node = NULL;
			}
		}
	}
	ntfs_directory_close(directory);
	ntfs_node_close(root);
	if (v != NULL) {
		fuzz_budgeted(v, &d, data, size);
	}
	assert(ntfs_unmount(v) == NTFS_OK && d.memory == 0);
	return 0;
}
#ifdef NTFS_FUZZ_STANDALONE
int
main(int argc, char **argv)
{
	FILE *file;
	uint8_t *data, old;
	long bytes;
	size_t i, offset;
	uint32_t random = FUZZ_RANDOM_SEED;

	assert(argc == 2);
	file = fopen(argv[1], "rb");
	assert(file != NULL);
	assert(fseek(file, 0, SEEK_END) == 0);
	bytes = ftell(file);
	assert(bytes > 0);
	rewind(file);
	data = malloc((size_t)bytes);
	assert(data != NULL);
	assert(fread(data, 1, (size_t)bytes, file) == (size_t)bytes);
	fclose(file);
	LLVMFuzzerTestOneInput(data, (size_t)bytes);
	for (i = 0; i < FUZZ_MUTATIONS; i++) {
		random = random * FUZZ_RANDOM_MULTIPLIER + FUZZ_RANDOM_INCREMENT;
		offset = random %
		    ((size_t)bytes < FUZZ_MUTATION_REGION ? (size_t)bytes : FUZZ_MUTATION_REGION);
		old = data[offset];
		data[offset] ^= (uint8_t)(1u << (i % FUZZ_BITS_PER_BYTE));
		LLVMFuzzerTestOneInput(data, (size_t)bytes);
		data[offset] = old;
	}
	free(data);
	printf("PASS: %u deterministic image mutations with bounded memory/I/O\n", FUZZ_MUTATIONS);
	return 0;
}
#endif
