/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/ntfs.h>
#include <ntfs/security.h>
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
	FUZZ_MUTATIONS = 2000,
	FUZZ_MUTATION_REGION = 512 * 1024,
	FUZZ_BITS_PER_BYTE = 8
};

/* Fixed Numerical Recipes LCG parameters make smoke mutations reproducible. */
#define FUZZ_RANDOM_SEED UINT32_C(0x85a7f12d)
#define FUZZ_RANDOM_MULTIPLIER UINT32_C(1664525)
#define FUZZ_RANDOM_INCREMENT UINT32_C(1013904223)

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct fuzz_device d = {.data = data, .size = size};
	struct ntfs_environment env = fuzz_environment(&d);
	struct ntfs_limits limits = {
	    FUZZ_MAX_RUNS, FUZZ_MAX_ATTRIBUTE_LIST, FUZZ_CACHE_ENTRIES, FUZZ_MAX_DIRECTORY_NODES};
	struct ntfs_volume *v = NULL;
	struct ntfs_node *root = NULL, *node = NULL;
	struct ntfs_directory *directory = NULL;
	struct ntfs_stream *stream = NULL;
	struct ntfs_reparse *reparse = NULL;
	struct ntfs_stream_catalog *catalog = NULL;
	struct ntfs_security *security = NULL;
	struct ntfs_stream_name stream_name;
	struct ntfs_reparse_info reparse_info;
	struct ntfs_dirent entry;
	uint8_t buffer[FUZZ_READ_BUFFER_BYTES];
	uint16_t reparse_name[FUZZ_REPARSE_NAME_UNITS];
	size_t i, j, count;

	(void)ntfs_reparse_decode(data, size, &reparse_info);
	if (ntfs_mount(&env, &limits, &v) == NTFS_OK && ntfs_root(v, &root) == NTFS_OK &&
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
					(void)ntfs_reparse_name(reparse,
					    NTFS_REPARSE_SUBSTITUTE_NAME, reparse_name,
					    FUZZ_REPARSE_NAME_UNITS, &count);
					(void)ntfs_reparse_name(reparse, NTFS_REPARSE_PRINT_NAME,
					    reparse_name, FUZZ_REPARSE_NAME_UNITS, &count);
					ntfs_reparse_close(reparse);
					reparse = NULL;
				}
				if (ntfs_stream_open(node, NULL, 0, &stream) == NTFS_OK) {
					(void)ntfs_stream_read(
					    stream, 0, buffer, sizeof(buffer), &count);
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
