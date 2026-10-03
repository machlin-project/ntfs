/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/ntfs.h>
#include "image.h"
#include "fixture.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { MIXED_PACKED_UNIT, MIXED_RAW_UNIT, MIXED_HOLE_UNIT, MIXED_FINAL_UNIT };

struct tracked_image {
	struct ntfs_image image;
	size_t reads, fail_read;
};

static enum ntfs_result
tracked_read(void *context, uint64_t offset, void *buffer, size_t size)
{
	struct tracked_image *tracked = context;
	struct ntfs_environment *env = &tracked->image.environment;

	if (++tracked->reads == tracked->fail_read) {
		return NTFS_IO;
	}
	return env->read(env->context, offset, buffer, size);
}

static void *
tracked_allocate(void *context, size_t size)
{
	struct tracked_image *tracked = context;
	struct ntfs_environment *env = &tracked->image.environment;

	return env->allocate(env->context, size);
}

static void
tracked_release(void *context, void *buffer, size_t size)
{
	struct tracked_image *tracked = context;
	struct ntfs_environment *env = &tracked->image.environment;

	env->release(env->context, buffer, size);
}

static struct ntfs_stream *
open_stream(struct ntfs_volume *volume, const char *filename)
{
	struct ntfs_node *root, *node;
	struct ntfs_stream *stream, *invalid = NULL;
	uint16_t name[NTFS_NAME_MAX];
	const uint16_t forbidden[] = {0, '/', '\\', ':'};
	size_t length, i;

	assert(ntfs_root(volume, &root) == NTFS_OK);
	assert(ntfs_utf8_to_utf16(filename, strlen(filename), name, NTFS_NAME_MAX, &length) ==
	    NTFS_OK);
	assert(ntfs_lookup(root, name, length, &node) == NTFS_OK);
	ntfs_node_close(root);
	for (i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); i++) {
		assert(ntfs_stream_open(node, &forbidden[i], 1, &invalid) == NTFS_INVALID);
		assert(invalid == NULL);
	}
	assert(ntfs_stream_open(node, NULL, 1, &invalid) == NTFS_INVALID && invalid == NULL);
	assert(ntfs_stream_open(node, NULL, 0, &stream) == NTFS_OK);
	ntfs_node_close(node);
	assert(ntfs_unmount(volume) == NTFS_BUSY);
	return stream;
}

static uint8_t
pattern_byte(size_t position)
{
	return (uint8_t)(position * TEST_PATTERN_MULTIPLIER + TEST_PATTERN_ADDEND);
}

static void
check_mixed(struct ntfs_stream *stream, size_t offset, size_t length)
{
	uint8_t *bytes, expected;
	size_t done, i, position, unit;

	bytes = malloc(length);
	assert(bytes != NULL);
	assert(ntfs_stream_read(stream, offset, bytes, length, &done) == NTFS_OK && done == length);
	for (i = 0; i < done; i++) {
		position = offset + i;
		unit = position / TEST_COMPRESSION_UNIT_BYTES;
		expected = pattern_byte(position % TEST_COMPRESSION_UNIT_BYTES);
		if (unit == MIXED_PACKED_UNIT && position >= TEST_CLUSTER_BYTES) {
			expected = 'Z';
		} else if (unit == MIXED_HOLE_UNIT) {
			expected = 0;
		}
		assert(bytes[i] == expected);
	}
	free(bytes);
}

static void
mixed_tests(struct ntfs_volume *volume, struct tracked_image *tracked)
{
	struct ntfs_stream *stream;
	uint8_t byte;
	size_t reads, done;
	const size_t unit = TEST_COMPRESSION_UNIT_BYTES;
	const size_t total = unit * MIXED_FINAL_UNIT + TEST_FRAGMENTED_BYTES;

	stream = open_stream(volume, "compressed.bin");
	assert(ntfs_stream_size(stream) == total);
	check_mixed(stream, 0, unit);
	reads = tracked->reads;
	check_mixed(stream, TEST_CLUSTER_BYTES - 1, TEST_READ_WINDOW_BYTES);
	assert(tracked->reads == reads);
	tracked->fail_read = reads + 1;
	assert(ntfs_stream_read(stream, unit, &byte, sizeof(byte), &done) == NTFS_IO && done == 0);
	tracked->fail_read = 0;
	reads = tracked->reads;
	check_mixed(stream, 0, unit);
	assert(tracked->reads == reads);
	check_mixed(stream, unit, unit);
	assert(tracked->reads > reads);
	check_mixed(stream, unit - 1, unit + 2);
	reads = tracked->reads;
	check_mixed(stream, unit * MIXED_HOLE_UNIT, unit);
	assert(tracked->reads == reads);
	check_mixed(stream, unit * MIXED_FINAL_UNIT - 1, TEST_FRAGMENTED_BYTES + 1);
	check_mixed(stream, total - 1, 1);
	assert(ntfs_stream_read(stream, total, &byte, sizeof(byte), &done) == NTFS_OK && done == 0);
	check_mixed(stream, 0, total);
	ntfs_stream_close(stream);
}

static void
zero_tests(struct ntfs_volume *volume, struct tracked_image *tracked, bool sparse)
{
	struct ntfs_stream *stream;
	uint8_t buffer[TEST_READ_WINDOW_BYTES];
	uint64_t offset, size;
	size_t reads, done, i;

	stream = open_stream(volume, sparse ? "fragmented.bin" : "tail.bin");
	size = ntfs_stream_size(stream);
	assert(size == (sparse ? TEST_LARGE_SPARSE_BYTES : TEST_CLUSTER_BYTES * 2));
	reads = tracked->reads;
	/* Read across the 32-bit offset boundary, or wholly beyond valid data. */
	offset = sparse ? (uint64_t)UINT32_MAX - sizeof(buffer) / 2 : TEST_INITIALIZED_BYTES;
	memset(buffer, 'X', sizeof(buffer));
	assert(ntfs_stream_read(stream, offset, buffer, sizeof(buffer), &done) == NTFS_OK &&
	    done == sizeof(buffer));
	for (i = 0; i < done; i++) {
		assert(buffer[i] == 0);
	}
	assert(tracked->reads == reads);
	assert(ntfs_stream_read(stream, size - 1, buffer, sizeof(buffer), &done) == NTFS_OK &&
	    done == 1 && buffer[0] == 0);
	assert(ntfs_stream_read(stream, UINT64_MAX, buffer, sizeof(buffer), &done) == NTFS_OK &&
	    done == 0);
	assert(tracked->reads == reads);
	if (!sparse) {
		assert(ntfs_stream_read(stream, TEST_INITIALIZED_BYTES - 1, buffer, sizeof(buffer),
			   &done) == NTFS_OK &&
		    done == sizeof(buffer));
		assert(buffer[0] == 'I');
		for (i = 1; i < done; i++) {
			assert(buffer[i] == 0);
		}
	}
	ntfs_stream_close(stream);
}

int
main(int argc, char **argv)
{
	const char *const files[] = {"mixed-compression.img", "large-sparse.img", "standard.img"};
	struct tracked_image tracked;
	struct ntfs_environment env;
	struct ntfs_volume *volume;
	char *path;
	size_t i, length;

	assert(argc == 2);
	for (i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
		memset(&tracked, 0, sizeof(tracked));
		length = strlen(argv[1]) + sizeof("/") + strlen(files[i]);
		path = malloc(length);
		assert(path != NULL);
		assert(snprintf(path, length, "%s/%s", argv[1], files[i]) > 0);
		assert(ntfs_image_open(path, &tracked.image) == 0);
		free(path);
		env = tracked.image.environment;
		env.context = &tracked;
		env.read = tracked_read;
		env.allocate = tracked_allocate;
		env.release = tracked_release;
		assert(ntfs_mount(&env, NULL, &volume) == NTFS_OK);
		if (i == 0) {
			mixed_tests(volume, &tracked);
		} else {
			zero_tests(volume, &tracked, i == 1);
		}
		assert(ntfs_unmount(volume) == NTFS_OK);
		ntfs_image_close(&tracked.image);
	}
	puts(
	    "PASS: mixed compression, cache retry, sparse offsets, VDL, stream names and lifetime");
	return 0;
}
