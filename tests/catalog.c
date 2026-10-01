/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/ntfs.h>
#include "fuzz_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_IMAGE_LIMIT = 8 * 1024 * 1024,
	TEST_FILE_RECORD = 24,
	TEST_STREAMED_RECORD = 30,
	TEST_EXTENDED_RECORD = 27,
	TEST_FILE_SEQUENCE = 7,
	TEST_SYSTEM_SEQUENCE = 1,
	TEST_CATALOG_LIMIT = 8,
	TEST_LONG_NAME_PREFIX = 0xd800
};

struct catalog_case {
	const char *image;
	uint32_t record, sequence;
	const uint16_t *names[TEST_CATALOG_LIMIT];
	uint16_t lengths[TEST_CATALOG_LIMIT];
	uint32_t count, maximum;
	enum ntfs_result result;
	bool long_name, encrypted;
};

static const uint16_t notes[] = {'n', 'o', 't', 'e', 's'};
static const uint16_t upper_notes[] = {'N', 'O', 'T', 'E', 'S'};
static const uint16_t data_name[] = {'$', 'D', 'A', 'T', 'A'};
static const uint16_t omega[] = {0x03a9};
static const uint16_t unpaired[] = {TEST_LONG_NAME_PREFIX};

static enum ntfs_result
exercise(struct fuzz_device *device, const struct catalog_case *test, size_t fail_allocation,
    size_t fail_read, size_t *allocations, size_t *reads)
{
	struct ntfs_environment env = fuzz_environment(device);
	struct ntfs_limits limits;
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *node = NULL;
	struct ntfs_stream_catalog *catalog = NULL;
	struct ntfs_stream *stream = NULL;
	struct ntfs_stream_name name, zero = {0};
	uint64_t reference =
	    test->record | (uint64_t)test->sequence << NTFS_REFERENCE_SEQUENCE_SHIFT;
	size_t before_allocations, before_reads, i, j;
	enum ntfs_result result;

	device->allocations = 0;
	device->reads = 0;
	device->fail_allocation = 0;
	device->fail_read = 0;
	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	assert(ntfs_mount(&env, &limits, &volume) == NTFS_OK);
	assert(ntfs_node_open(volume, reference, &node) == NTFS_OK);
	before_allocations = device->allocations;
	before_reads = device->reads;
	device->fail_allocation = fail_allocation != 0 ? before_allocations + fail_allocation : 0;
	device->fail_read = fail_read != 0 ? before_reads + fail_read : 0;
	result = ntfs_stream_catalog_open(
	    node, test->maximum != 0 ? test->maximum : TEST_CATALOG_LIMIT, &catalog);
	*allocations = device->allocations - before_allocations;
	*reads = device->reads - before_reads;
	device->fail_allocation = 0;
	device->fail_read = 0;
	if (result == NTFS_OK) {
		assert(catalog != NULL && ntfs_stream_catalog_count(catalog) == test->count);
		if (test->encrypted) {
			assert(ntfs_stream_open(node, NULL, 0, &stream) == NTFS_UNSUPPORTED &&
			    stream == NULL);
		}
		if (test->long_name) {
			assert(
			    ntfs_stream_catalog_entry(catalog, test->count - 1, &name) == NTFS_OK);
			assert(ntfs_stream_open(node, name.units, name.length, &stream) == NTFS_OK);
			assert(ntfs_stream_size(stream) == strlen("catalog payload"));
			ntfs_stream_close(stream);
		}
		ntfs_node_close(node);
		node = NULL;
		assert(ntfs_unmount(volume) == NTFS_BUSY);
		before_reads = device->reads;
		before_allocations = device->allocations;
		device->fail_read = before_reads + 1;
		device->fail_allocation = before_allocations + 1;
		for (i = 0; i < test->count; i++) {
			assert(ntfs_stream_catalog_entry(catalog, (uint32_t)i, &name) == NTFS_OK);
			if (test->long_name && i == test->count - 1) {
				assert(name.length == NTFS_NAME_MAX);
				assert(name.units[0] == TEST_LONG_NAME_PREFIX);
				for (j = 1; j < name.length; j++) {
					assert(name.units[j] == 'x');
				}
			} else {
				assert(name.length == test->lengths[i]);
				if (name.length != 0) {
					assert(memcmp(name.units, test->names[i],
						   name.length * sizeof(name.units[0])) == 0);
				}
			}
		}
		memset(&name, 0xff, sizeof(name));
		assert(ntfs_stream_catalog_entry(catalog, test->count, &name) == NTFS_END);
		assert(memcmp(&name, &zero, sizeof(name)) == 0);
		assert(ntfs_stream_catalog_entry(catalog, UINT32_MAX, &name) == NTFS_END);
		assert(device->reads == before_reads && device->allocations == before_allocations);
	} else {
		assert(catalog == NULL);
	}
	ntfs_node_close(node);
	ntfs_stream_catalog_close(catalog);
	assert(ntfs_unmount(volume) == NTFS_OK && device->memory == 0);
	return result;
}

static void
load_image(const char *directory, const char *name, struct fuzz_device *device)
{
	char *path;
	FILE *source;
	long size;
	size_t length = strlen(directory) + sizeof("/") + strlen(name);

	path = malloc(length);
	assert(path != NULL);
	assert(snprintf(path, length, "%s/%s", directory, name) > 0);
	source = fopen(path, "rb");
	free(path);
	assert(source != NULL && fseek(source, 0, SEEK_END) == 0);
	size = ftell(source);
	assert(size > 0 && size <= TEST_IMAGE_LIMIT && fseek(source, 0, SEEK_SET) == 0);
	device->data = malloc((size_t)size);
	assert(device->data != NULL);
	assert(fread((void *)device->data, 1, (size_t)size, source) == (size_t)size);
	assert(fclose(source) == 0);
	device->size = (size_t)size;
}

int
main(int argc, char **argv)
{
	const struct catalog_case cases[] = {{.image = "standard.img",
						 .record = TEST_FILE_RECORD,
						 .sequence = TEST_FILE_SEQUENCE,
						 .count = 1},
	    {.image = "standard.img",
		.record = TEST_STREAMED_RECORD,
		.sequence = TEST_FILE_SEQUENCE,
		.names = {NULL, notes},
		.lengths = {0, sizeof(notes) / sizeof(notes[0])},
		.count = 2},
	    {.image = "standard.img",
		.record = TEST_EXTENDED_RECORD,
		.sequence = TEST_FILE_SEQUENCE,
		.count = 1},
	    {.image = "standard.img", .record = NTFS_ROOT_RECORD, .sequence = TEST_SYSTEM_SEQUENCE},
	    {.image = "directory-ads.img",
		.record = NTFS_ROOT_RECORD,
		.sequence = TEST_SYSTEM_SEQUENCE,
		.names = {notes},
		.lengths = {sizeof(notes) / sizeof(notes[0])},
		.count = 1},
	    {.image = "independent-ads.img",
		.record = TEST_FILE_RECORD,
		.sequence = TEST_FILE_SEQUENCE,
		.names = {NULL, notes},
		.lengths = {0, sizeof(notes) / sizeof(notes[0])},
		.count = 2,
		.encrypted = true},
	    {.image = "catalog-long-unpaired.img",
		.record = TEST_FILE_RECORD,
		.sequence = TEST_FILE_SEQUENCE,
		.count = 2,
		.long_name = true},
	    {.image = "catalog-listed.img",
		.record = TEST_FILE_RECORD,
		.sequence = TEST_FILE_SEQUENCE,
		.names = {NULL, data_name, upper_notes, notes, omega, unpaired},
		.lengths = {0, sizeof(data_name) / sizeof(data_name[0]),
		    sizeof(upper_notes) / sizeof(upper_notes[0]), sizeof(notes) / sizeof(notes[0]),
		    sizeof(omega) / sizeof(omega[0]), sizeof(unpaired) / sizeof(unpaired[0])},
		.count = 6},
	    {.image = "catalog-listed.img",
		.record = TEST_FILE_RECORD,
		.sequence = TEST_FILE_SEQUENCE,
		.maximum = 1,
		.result = NTFS_RANGE},
	    {.image = "catalog-duplicate.img",
		.record = TEST_FILE_RECORD,
		.sequence = TEST_FILE_SEQUENCE,
		.result = NTFS_CORRUPT},
	    {.image = "catalog-unlisted-base.img",
		.record = TEST_FILE_RECORD,
		.sequence = TEST_FILE_SEQUENCE,
		.result = NTFS_CORRUPT},
	    {.image = "catalog-stale.img",
		.record = TEST_FILE_RECORD,
		.sequence = TEST_FILE_SEQUENCE,
		.result = NTFS_STALE},
	    {.image = "catalog-wrong-base.img",
		.record = TEST_FILE_RECORD,
		.sequence = TEST_FILE_SEQUENCE,
		.result = NTFS_STALE},
	    {.image = "catalog-instance.img",
		.record = TEST_FILE_RECORD,
		.sequence = TEST_FILE_SEQUENCE,
		.result = NTFS_CORRUPT}};
	struct fuzz_device device = {0};
	struct ntfs_stream_catalog *invalid = NULL;
	struct ntfs_stream_name name;
	size_t i, fault, allocations, reads, ignored_allocations, ignored_reads;
	size_t allocation_faults = 0, read_faults = 0;
	enum ntfs_result result;

	assert(argc == 2);
	assert(ntfs_stream_catalog_open(NULL, TEST_CATALOG_LIMIT, &invalid) == NTFS_INVALID &&
	    invalid == NULL);
	assert(ntfs_stream_catalog_open(NULL, TEST_CATALOG_LIMIT, NULL) == NTFS_INVALID);
	assert(ntfs_stream_catalog_entry(NULL, 0, &name) == NTFS_INVALID);
	assert(ntfs_stream_catalog_entry(NULL, 0, NULL) == NTFS_INVALID);
	assert(ntfs_stream_catalog_count(NULL) == 0);
	ntfs_stream_catalog_close(NULL);
	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		load_image(argv[1], cases[i].image, &device);
		result = exercise(&device, &cases[i], 0, 0, &allocations, &reads);
		if (result != cases[i].result) {
			fprintf(stderr, "%s: %s\n", cases[i].image, ntfs_result_string(result));
			return 1;
		}
		if (result == NTFS_OK) {
			for (fault = 1; fault <= allocations; fault++) {
				assert(exercise(&device, &cases[i], fault, 0, &ignored_allocations,
					   &ignored_reads) == NTFS_NO_MEMORY);
			}
			for (fault = 1; fault <= reads; fault++) {
				assert(exercise(&device, &cases[i], 0, fault, &ignored_allocations,
					   &ignored_reads) == NTFS_IO);
			}
			allocation_faults += allocations;
			read_faults += reads;
		}
		free((void *)device.data);
	}
	printf("PASS: %zu stream inventories, exact UTF-16 sorting, unsupported/default/directory "
	       "streams, independent snapshot lifetime; %zu allocation and %zu I/O faults\n",
	    sizeof(cases) / sizeof(cases[0]), allocation_faults, read_faults);
	return 0;
}
