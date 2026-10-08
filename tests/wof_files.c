/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/wof.h>
#include "fixture.h"
#include "fuzz_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	FILE_RECORD = 24,
	FILE_SEQUENCE = 7,
	PATH_BYTES = 4096,
	GUARD_BYTES = 16,
	GUARD_VALUE = 0xa5,
	CROSS_PREFIX_BYTES = 7,
	CROSS_TAIL_BYTES = 19,
	RANGE_BYTES = NTFS_WOF_UNIT_32K + CROSS_TAIL_BYTES,
	READ_STRIDE = 773,
	PAGE_BYTES = 4096,
	PAGE_ENTRIES = PAGE_BYTES / sizeof(uint32_t),
	PAGE_BACKING_CLUSTERS = 73,
	LZX_PAGE_BACKING_CLUSTERS = 70
};

enum { REQUIRED_DECODE_ALLOCATION = 1, OPTIONAL_OUTPUT_ALLOCATION };

enum { FAULT_STAT, FAULT_OPEN, FAULT_READ, FAULT_PHASES };

struct test_case {
	const char *name;
	enum ntfs_result stat, open, read;
	uint32_t algorithm, clusters;
	bool ads;
};

static const struct test_case cases[] = {
    {"4k", NTFS_OK, NTFS_OK, NTFS_OK, NTFS_WOF_XPRESS_4K, 2, true},
    {"8k", NTFS_OK, NTFS_OK, NTFS_OK, NTFS_WOF_XPRESS_8K, 3, true},
    {"16k", NTFS_OK, NTFS_OK, NTFS_OK, NTFS_WOF_XPRESS_16K, 5, true},
    {"resident", NTFS_OK, NTFS_OK, NTFS_OK, NTFS_WOF_XPRESS_4K, 0, true},
    {"empty", NTFS_OK, NTFS_OK, NTFS_OK, NTFS_WOF_XPRESS_4K, 0, true},
    {"exact", NTFS_OK, NTFS_OK, NTFS_OK, NTFS_WOF_XPRESS_4K, 2, true},
    {"vdl-full", NTFS_OK, NTFS_OK, NTFS_OK, NTFS_WOF_XPRESS_4K, 2, true},
    {"pages", NTFS_OK, NTFS_OK, NTFS_OK, NTFS_WOF_XPRESS_4K, PAGE_BACKING_CLUSTERS, true},
    {"listed", NTFS_OK, NTFS_OK, NTFS_OK, NTFS_WOF_XPRESS_4K, 3, true},
    {"nonresident-list", NTFS_OK, NTFS_OK, NTFS_OK, NTFS_WOF_XPRESS_4K, 3, true},
    {"lzx", NTFS_OK, NTFS_OK, NTFS_OK, NTFS_WOF_LZX_32K, 17, true},
    {"lzx-packed", NTFS_OK, NTFS_OK, NTFS_OK, NTFS_WOF_LZX_32K, 9, true},
    {"lzx-resident", NTFS_OK, NTFS_OK, NTFS_OK, NTFS_WOF_LZX_32K, 0, true},
    {"lzx-empty", NTFS_OK, NTFS_OK, NTFS_OK, NTFS_WOF_LZX_32K, 0, true},
    {"lzx-exact", NTFS_OK, NTFS_OK, NTFS_OK, NTFS_WOF_LZX_32K, 9, true},
    {"lzx-listed", NTFS_OK, NTFS_OK, NTFS_OK, NTFS_WOF_LZX_32K, 10, true},
    {"lzx-pages", NTFS_OK, NTFS_OK, NTFS_OK, NTFS_WOF_LZX_32K, LZX_PAGE_BACKING_CLUSTERS, true},
    {"lzx-call", NTFS_OK, NTFS_OK, NTFS_OK, NTFS_WOF_LZX_32K, 9, true},
    {"lzx-codec", NTFS_OK, NTFS_OK, NTFS_CORRUPT, NTFS_WOF_LZX_32K, 9, true},
    {"lzx-late-codec", NTFS_OK, NTFS_OK, NTFS_CORRUPT, NTFS_WOF_LZX_32K, 1, true},
    {"codec", NTFS_OK, NTFS_OK, NTFS_CORRUPT, NTFS_WOF_XPRESS_4K, 2, true},
    {"duplicate", NTFS_OK, NTFS_CORRUPT, NTFS_CORRUPT, NTFS_WOF_XPRESS_4K, 2, true},
    {"descending", NTFS_OK, NTFS_CORRUPT, NTFS_CORRUPT, NTFS_WOF_XPRESS_4K, 2, true},
    {"out-of-range", NTFS_OK, NTFS_CORRUPT, NTFS_CORRUPT, NTFS_WOF_XPRESS_4K, 2, true},
    {"final-span", NTFS_OK, NTFS_CORRUPT, NTFS_CORRUPT, NTFS_WOF_XPRESS_4K, 2, true},
    {"placeholder-resident", NTFS_CORRUPT, NTFS_CORRUPT, NTFS_CORRUPT, 0, 0, true},
    {"placeholder-physical", NTFS_CORRUPT, NTFS_CORRUPT, NTFS_CORRUPT, 0, 0, true},
    {"placeholder-encoding", NTFS_CORRUPT, NTFS_CORRUPT, NTFS_CORRUPT, 0, 0, true},
    {"backing-vdl", NTFS_CORRUPT, NTFS_CORRUPT, NTFS_CORRUPT, 0, 0, true},
    {"backing-flags", NTFS_UNSUPPORTED, NTFS_UNSUPPORTED, NTFS_UNSUPPORTED, 0, 0, true},
    {"backing-efs", NTFS_OK, NTFS_UNSUPPORTED, NTFS_UNSUPPORTED, 0, 2, true},
    {"missing-backing", NTFS_CORRUPT, NTFS_CORRUPT, NTFS_CORRUPT, 0, 0, true},
    {"cleared-reparse", NTFS_CORRUPT, NTFS_CORRUPT, NTFS_CORRUPT, 0, 0, false},
    {"work-limit", NTFS_RANGE, NTFS_RANGE, NTFS_RANGE, 0, 0, true},
    {"unknown-provider", NTFS_OK, NTFS_UNSUPPORTED, NTFS_UNSUPPORTED, 0, 0, false},
    {"directory", NTFS_CORRUPT, NTFS_CORRUPT, NTFS_CORRUPT, 0, 0, false},
    {"stale", NTFS_STALE, NTFS_STALE, NTFS_STALE, 0, 0, false}};

struct work {
	size_t allocations, reads;
};

static uint8_t *
load(const char *directory, const char *name, const char *suffix, size_t *size)
{
	char path[PATH_BYTES];
	FILE *file;
	long length;
	uint8_t *bytes;
	int result;

	result = snprintf(path, sizeof(path), "%s/wof-file-%s.%s", directory, name, suffix);
	assert(result > 0 && (size_t)result < sizeof(path));
	file = fopen(path, "rb");
	assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
	length = ftell(file);
	assert(length >= 0 && fseek(file, 0, SEEK_SET) == 0);
	*size = (size_t)length;
	bytes = malloc(*size + 1);
	assert(bytes != NULL && fread(bytes, 1, *size, file) == *size);
	assert(fclose(file) == 0);
	return bytes;
}

static void
guards(const uint8_t *bytes, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++) {
		assert(bytes[i] == GUARD_VALUE);
	}
}

static struct work
exercise(struct fuzz_device *device, const struct test_case *test, const uint8_t *original,
    size_t size, unsigned phase, size_t failed_allocation, size_t failed_read)
{
	static const uint16_t notes[] = {'n', 'o', 't', 'e', 's'};
	static const uint16_t backing[] = {
	    'W', 'o', 'f', 'C', 'o', 'm', 'p', 'r', 'e', 's', 's', 'e', 'd', 'D', 'a', 't', 'a'};
	static const char ads[] = "independent WOF notes";
	struct ntfs_environment environment = fuzz_environment(device);
	struct ntfs_limits limits;
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *node = NULL;
	struct ntfs_stream *stream = NULL, *named = NULL;
	struct ntfs_stat stat;
	struct work work = {0};
	uint64_t reference = (uint64_t)FILE_SEQUENCE << NTFS_REFERENCE_SEQUENCE_SHIFT | FILE_RECORD;
	uint64_t offset = 0;
	size_t length = size < RANGE_BYTES ? size : RANGE_BYTES, done, allocations, reads, i;
	size_t expected_prefix;
	uint32_t unit;
	uint8_t *output;
	enum ntfs_result result, expected_error;

	device->reads = 0;
	device->allocations = 0;
	device->fail_allocation = 0;
	device->fail_read = 0;
	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	assert(ntfs_mount(&environment, &limits, &volume) == NTFS_OK);
	assert(ntfs_node_open(volume, reference, &node) == NTFS_OK);
	if (phase == FAULT_STAT) {
		allocations = device->allocations;
		reads = device->reads;
		device->fail_allocation =
		    failed_allocation == 0 ? 0 : allocations + failed_allocation;
		device->fail_read = failed_read == 0 ? 0 : reads + failed_read;
	}
	result = ntfs_node_stat(node, &stat);
	if (phase == FAULT_STAT) {
		work = (struct work){device->allocations - allocations, device->reads - reads};
		if (failed_allocation != 0 || failed_read != 0) {
			expected_error = failed_allocation != 0 ? NTFS_NO_MEMORY : NTFS_IO;
			assert(
			    result == expected_error && stat.size == 0 && stat.allocated_size == 0);
			device->fail_allocation = 0;
			device->fail_read = 0;
			result = ntfs_node_stat(node, &stat);
		}
	}
	assert(result == test->stat);
	if (result == NTFS_OK && strcmp(test->name, "unknown-provider") != 0) {
		assert(stat.size == size &&
		    stat.allocated_size == (uint64_t)test->clusters * TEST_CLUSTER_BYTES);
		assert(stat.reparse && !stat.directory);
	}
	if (phase == FAULT_OPEN) {
		allocations = device->allocations;
		reads = device->reads;
		device->fail_allocation =
		    failed_allocation == 0 ? 0 : allocations + failed_allocation;
		device->fail_read = failed_read == 0 ? 0 : reads + failed_read;
	}
	result = ntfs_stream_open(node, NULL, 0, &stream);
	if (phase == FAULT_OPEN) {
		work = (struct work){device->allocations - allocations, device->reads - reads};
		if (failed_allocation != 0 || failed_read != 0) {
			expected_error = failed_allocation != 0 ? NTFS_NO_MEMORY : NTFS_IO;
			assert(result == expected_error && stream == NULL);
			device->fail_allocation = 0;
			device->fail_read = 0;
			result = ntfs_stream_open(node, NULL, 0, &stream);
		}
	}
	assert(result == test->open);
	if (test->ads) {
		assert(ntfs_stream_open(node, notes, sizeof(notes) / sizeof(notes[0]), &named) ==
		    NTFS_OK);
		output = malloc(sizeof(ads));
		assert(output != NULL);
		assert(ntfs_stream_read(named, 0, output, sizeof(ads), &done) == NTFS_OK &&
		    done == sizeof(ads) - 1);
		assert(memcmp(output, ads, done) == 0);
		free(output);
		ntfs_stream_close(named);
		named = NULL;
		assert(ntfs_wof_is_backing_stream(backing, sizeof(backing) / sizeof(backing[0])));
		assert(ntfs_stream_open(node, backing, sizeof(backing) / sizeof(backing[0]),
			   &named) == NTFS_UNSUPPORTED &&
		    named == NULL);
	}
	ntfs_node_close(node);
	node = NULL;
	if (stream != NULL) {
		assert(ntfs_unmount(volume) == NTFS_BUSY && ntfs_stream_size(stream) == size);
		if (strcmp(test->name, "pages") == 0 || strcmp(test->name, "lzx-pages") == 0) {
			unit = test->algorithm == NTFS_WOF_LZX_32K ? NTFS_WOF_UNIT_32K
								   : NTFS_WOF_UNIT_4K;
			offset = (uint64_t)(PAGE_ENTRIES - 1) * unit - CROSS_PREFIX_BYTES;
			length = unit + CROSS_TAIL_BYTES;
		}
		output = malloc(length + 2 * GUARD_BYTES);
		assert(output != NULL);
		memset(output, GUARD_VALUE, length + 2 * GUARD_BYTES);
		if (phase == FAULT_READ) {
			allocations = device->allocations;
			reads = device->reads;
			device->fail_allocation =
			    failed_allocation == 0 ? 0 : allocations + failed_allocation;
			device->fail_read = failed_read == 0 ? 0 : reads + failed_read;
		}
		result = ntfs_stream_read(stream, offset, output + GUARD_BYTES, length, &done);
		if (phase == FAULT_READ) {
			work =
			    (struct work){device->allocations - allocations, device->reads - reads};
			if (failed_allocation == OPTIONAL_OUTPUT_ALLOCATION) {
				/* A refused extra output must preserve complete successful data. */
				assert(result == NTFS_OK && done == length &&
				    device->allocations ==
					allocations + OPTIONAL_OUTPUT_ALLOCATION);
				assert(memcmp(output + GUARD_BYTES, original + (size_t)offset,
					   done) == 0);
				device->fail_allocation = 0;
			} else if (failed_allocation != 0 || failed_read != 0) {
				expected_error = failed_allocation != 0 ? NTFS_NO_MEMORY : NTFS_IO;
				assert(result == expected_error && done <= length);
				assert(memcmp(output + GUARD_BYTES, original + (size_t)offset,
					   done) == 0);
				guards(output + GUARD_BYTES + done, length - done);
				device->fail_allocation = 0;
				device->fail_read = 0;
				result = ntfs_stream_read(
				    stream, offset, output + GUARD_BYTES, length, &done);
			}
		}
		assert(result == test->read);
		if (result == NTFS_OK) {
			assert(done == length &&
			    memcmp(output + GUARD_BYTES, original + (size_t)offset, length) == 0);
			reads = device->reads;
			assert(ntfs_stream_read(stream, offset + length, output + GUARD_BYTES, 0,
				   &done) == NTFS_OK &&
			    done == 0);
			assert(device->reads == reads);
			if (length != 0) {
				assert(ntfs_stream_read(stream, offset + length - 1,
					   output + GUARD_BYTES, 1, &done) == NTFS_OK &&
				    done == 1);
				assert(
				    output[GUARD_BYTES] == original[(size_t)offset + length - 1] &&
				    device->reads == reads);
			}
		} else {
			expected_prefix =
			    strcmp(test->name, "lzx-late-codec") == 0 ? NTFS_WOF_UNIT_32K : 0;
			assert(done == expected_prefix);
			assert(memcmp(output + GUARD_BYTES, original, done) == 0);
			guards(output + GUARD_BYTES + done, length - done);
			if (expected_prefix != 0) {
				/* Failed decoding of the next unit preserves the prior output. */
				reads = device->reads;
				assert(ntfs_stream_read(stream, offset, output + GUARD_BYTES,
					   expected_prefix, &done) == NTFS_OK &&
				    done == expected_prefix && device->reads == reads);
				assert(memcmp(output + GUARD_BYTES, original, done) == 0);
			}
			/* The failed private block must remain invalid on the next fill. */
			assert(ntfs_stream_read(stream, offset, output + GUARD_BYTES, length,
				   &done) == test->read &&
			    done == expected_prefix);
			guards(output + GUARD_BYTES + done, length - done);
		}
		guards(output, GUARD_BYTES);
		guards(output + GUARD_BYTES + length, GUARD_BYTES);
		free(output);
		if (result == NTFS_OK && failed_allocation == 0 && failed_read == 0) {
			output = malloc(READ_STRIDE + GUARD_BYTES);
			assert(output != NULL);
			for (i = 0; i < size; i += done) {
				memset(output, GUARD_VALUE, READ_STRIDE + GUARD_BYTES);
				assert(ntfs_stream_read(stream, i, output, READ_STRIDE, &done) ==
				    NTFS_OK);
				assert(done == (size - i < READ_STRIDE ? size - i : READ_STRIDE));
				assert(memcmp(output, original + i, done) == 0);
				guards(output + done, READ_STRIDE + GUARD_BYTES - done);
			}
			assert(ntfs_stream_read(stream, UINT64_MAX, output, READ_STRIDE, &done) ==
				NTFS_OK &&
			    done == 0);
			free(output);
		}
		ntfs_stream_close(stream);
	}
	assert(ntfs_unmount(volume) == NTFS_OK && device->memory == 0);
	return work;
}

static void
reopen_case(const char *directory, const char *name)
{
	struct fuzz_device device = {0};
	struct ntfs_environment environment;
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *node = NULL;
	struct ntfs_stream *stream = NULL;
	struct ntfs_stat stat;
	uint8_t *image, *original, output[GUARD_BYTES];
	uint64_t reference = (uint64_t)FILE_SEQUENCE << NTFS_REFERENCE_SEQUENCE_SHIFT | FILE_RECORD;
	size_t image_size, size, reads, allocations, cold_reads, warm_reads, warm_allocations;
	size_t retained, done, mode, fault;

	image = load(directory, name, "img", &image_size);
	original = load(directory, name, "data", &size);
	device.data = image;
	device.size = image_size;
	environment = fuzz_environment(&device);
	assert(ntfs_mount(&environment, NULL, &volume) == NTFS_OK);
	assert(ntfs_node_open(volume, reference, &node) == NTFS_OK);
	assert(ntfs_node_stat(node, &stat) == NTFS_OK && stat.size == size);
	reads = device.reads;
	assert(ntfs_stream_open(node, NULL, 0, &stream) == NTFS_OK);
	cold_reads = device.reads - reads;
	ntfs_stream_close(stream);
	stream = NULL;
	reads = device.reads;
	allocations = device.allocations;
	assert(ntfs_stream_open(node, NULL, 0, &stream) == NTFS_OK);
	warm_reads = device.reads - reads;
	warm_allocations = device.allocations - allocations;
	/* The authored tables occupy two pages. Required provider/mapping checks
	 * still execute; only the already validated table walk disappears. */
	assert(cold_reads == warm_reads + 2);
	ntfs_stream_close(stream);
	stream = NULL;
	retained = device.memory;
	for (mode = 0; mode < 2; mode++) {
		for (fault = 1; fault <= (mode == 0 ? warm_allocations : warm_reads); fault++) {
			device.fail_allocation = mode == 0 ? device.allocations + fault : 0;
			device.fail_read = mode == 1 ? device.reads + fault : 0;
			assert(ntfs_stream_open(node, NULL, 0, &stream) ==
			    (mode == 0 ? NTFS_NO_MEMORY : NTFS_IO));
			assert(stream == NULL && device.memory == retained);
			device.fail_allocation = device.fail_read = 0;
			reads = device.reads;
			assert(ntfs_stream_open(node, NULL, 0, &stream) == NTFS_OK);
			assert(device.reads - reads == warm_reads);
			ntfs_stream_close(stream);
			stream = NULL;
		}
	}
	/* A fresh node never inherits a previous node's validation marker. Refuse
	 * the final stream allocation, after validation, then require a cold retry. */
	ntfs_node_close(node);
	assert(ntfs_node_open(volume, reference, &node) == NTFS_OK);
	assert(ntfs_node_stat(node, &stat) == NTFS_OK);
	device.fail_allocation = device.allocations + warm_allocations;
	assert(ntfs_stream_open(node, NULL, 0, &stream) == NTFS_NO_MEMORY && stream == NULL);
	device.fail_allocation = 0;
	reads = device.reads;
	assert(ntfs_stream_open(node, NULL, 0, &stream) == NTFS_OK);
	assert(device.reads - reads == cold_reads);
	ntfs_stream_close(stream);
	assert(ntfs_stream_open(node, NULL, 0, &stream) == NTFS_OK);
	ntfs_node_close(node);
	device.fail_read = device.reads + 1;
	memset(output, GUARD_VALUE, sizeof(output));
	assert(ntfs_stream_read(stream, size - sizeof(output), output, sizeof(output), &done) ==
	    NTFS_IO);
	assert(done == 0);
	guards(output, sizeof(output));
	device.fail_read = 0;
	assert(ntfs_stream_read(stream, size - sizeof(output), output, sizeof(output), &done) ==
	    NTFS_OK);
	assert(done == sizeof(output) && memcmp(output, original + size - done, done) == 0);
	ntfs_stream_close(stream);
	assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
	free(original);
	free(image);
}

int
main(int argc, char **argv)
{
	struct fuzz_device device = {0};
	struct work work;
	uint8_t *image, *saved, *original;
	size_t image_size, original_size, i, fault, allocations = 0, reads = 0;
	unsigned phase;

	assert(argc == 2);
	reopen_case(argv[1], "pages");
	reopen_case(argv[1], "lzx-pages");
	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		image = load(argv[1], cases[i].name, "img", &image_size);
		saved = malloc(image_size);
		assert(saved != NULL);
		memcpy(saved, image, image_size);
		original = load(argv[1], cases[i].name, "data", &original_size);
		device.data = image;
		device.size = image_size;
		for (phase = FAULT_STAT; phase < FAULT_PHASES; phase++) {
			work = exercise(&device, &cases[i], original, original_size, phase, 0, 0);
			if (cases[i].stat != NTFS_OK || cases[i].open != NTFS_OK ||
			    cases[i].read != NTFS_OK) {
				continue;
			}
			for (fault = 1; fault <= work.allocations; fault++) {
				exercise(
				    &device, &cases[i], original, original_size, phase, fault, 0);
				allocations++;
			}
			for (fault = 1; fault <= work.reads; fault++) {
				exercise(
				    &device, &cases[i], original, original_size, phase, 0, fault);
				reads++;
			}
		}
		assert(memcmp(saved, image, image_size) == 0);
		free(original);
		free(saved);
		free(image);
	}
	printf("PASS: %zu WOF file verdicts, %zu allocation/%zu read faults, byte oracles, "
	       "page/cache retry, independent lifetime/ADS and cleanup\n",
	    sizeof(cases) / sizeof(cases[0]), allocations, reads);
	return 0;
}
