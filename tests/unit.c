/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct memory_device {
	uint8_t *bytes;
	size_t size, allocation_calls, read_calls, fail_allocation, fail_read, live, live_bytes;
};

union allocation_header {
	max_align_t alignment;
	size_t size;
};

static void *
allocate(void *context, size_t size)
{
	struct memory_device *m = context;
	union allocation_header *header;

	m->allocation_calls++;
	if (m->fail_allocation == m->allocation_calls) {
		return NULL;
	}
	header = malloc(sizeof(*header) + size);
	assert(header != NULL);
	header->size = size;
	m->live++;
	m->live_bytes += size;
	return header + 1;
}

static void
release(void *context, void *allocation, size_t size)
{
	struct memory_device *m = context;
	union allocation_header *header = (union allocation_header *)allocation - 1;

	assert(m->live != 0 && header->size == size);
	m->live--;
	m->live_bytes -= size;
	free(header);
}

static enum ntfs_result
read_bytes(void *context, uint64_t offset, void *buffer, size_t size)
{
	struct memory_device *m = context;

	m->read_calls++;
	if (m->read_calls == m->fail_read) {
		return NTFS_IO;
	}
	assert(offset <= m->size && size <= m->size - offset);
	memcpy(buffer, m->bytes + offset, size);
	return NTFS_OK;
}

static enum ntfs_result
exercise(struct memory_device *m)
{
	struct ntfs_environment env = {NTFS_API_VERSION, m, m->size, read_bytes, allocate, release};
	struct ntfs_volume *v = NULL;
	struct ntfs_node *root = NULL, *file = NULL, *looked = NULL;
	struct ntfs_directory *d = NULL;
	struct ntfs_stream *stream = NULL;
	struct ntfs_dirent entry;
	struct ntfs_stat st;
	uint8_t buffer[513];
	size_t done, count = 0;
	uint64_t size, free_clusters;
	enum ntfs_result result;

	result = ntfs_mount(&env, NULL, &v);
	if (result != NTFS_OK) {
		goto finish;
	}
	result = ntfs_count_free_clusters(v, &free_clusters);
	if (result != NTFS_OK) {
		goto finish;
	}
	assert(free_clusters == 2048 - 160);
	result = ntfs_root(v, &root);
	if (result != NTFS_OK) {
		goto finish;
	}
	assert(ntfs_unmount(v) == NTFS_BUSY);
	result = ntfs_directory_open(root, &d);
	if (result != NTFS_OK) {
		goto finish;
	}
	while ((result = ntfs_directory_next(d, &entry)) == NTFS_OK) {
		count++;
		result = ntfs_node_open(v, entry.reference, &file);
		if (result != NTFS_OK) {
			break;
		}
		result = ntfs_node_stat(file, &st);
		if (result != NTFS_OK) {
			break;
		}
		assert(st.size == entry.size && st.links == 1 && st.security_id == 256);
		result = ntfs_lookup(root, entry.name, entry.name_length, &looked);
		if (result != NTFS_OK) {
			break;
		}
		ntfs_node_close(looked);
		looked = NULL;
		result = ntfs_stream_open(file, NULL, 0, &stream);
		if (result != NTFS_OK) {
			break;
		}
		ntfs_node_close(file);
		file = NULL;
		size = ntfs_stream_size(stream);
		result = ntfs_stream_read(stream, 0, buffer, sizeof(buffer), &done);
		if (result != NTFS_OK) {
			break;
		}
		assert(done == (size < sizeof(buffer) ? size : sizeof(buffer)));
		result = ntfs_stream_read(stream, size - 1, buffer, sizeof(buffer), &done);
		if (result != NTFS_OK) {
			break;
		}
		assert(done == 1);
		result = ntfs_stream_read(stream, UINT64_MAX, buffer, sizeof(buffer), &done);
		assert(result == NTFS_OK && done == 0);
		ntfs_stream_close(stream);
		stream = NULL;
	}
	if (result == NTFS_END) {
		assert(count == 9 && ntfs_directory_next(d, &entry) == NTFS_END);
		result = NTFS_OK;
	}
finish:
	ntfs_stream_close(stream);
	ntfs_node_close(looked);
	ntfs_node_close(file);
	ntfs_directory_close(d);
	ntfs_node_close(root);
	assert(ntfs_unmount(v) == NTFS_OK);
	assert(m->live == 0 && m->live_bytes == 0);
	return result;
}

static void
primitive_tests(void)
{
	uint16_t utf16[16];
	char utf8[32];
	const char sample[] = "A\xce\xa9\xf0\x9f\x98\x80";
	const uint8_t compressed[] = {3, 0xb0, 2, 'Z', 0xfc, 0x0f, 0, 0};
	uint8_t output[4096], corrupt[8], *record, *original;
	size_t size, units, i;
	struct ntfs_time time;

	assert(ntfs_utf8_to_utf16(sample, sizeof(sample) - 1, utf16, 16, &units) == NTFS_OK &&
	    units == 4);
	assert(ntfs_utf16_to_utf8(utf16, units, utf8, sizeof(utf8), &size) == NTFS_OK &&
	    size == sizeof(sample) - 1);
	assert(memcmp(sample, utf8, size) == 0);
	assert(ntfs_utf8_to_utf16("\xc0\x80", 2, utf16, 16, &units) == NTFS_INVALID);
	assert(ntfs_utf8_to_utf16("\xed\xa0\x80", 3, utf16, 16, &units) == NTFS_INVALID);
	assert(ntfs_utf8_to_utf16("\xf4\x90\x80\x80", 4, utf16, 16, &units) == NTFS_INVALID);
	assert(ntfs_utf8_to_utf16(sample, sizeof(sample) - 1, utf16, 1, &units) == NTFS_RANGE);
	utf16[0] = 0xd800;
	assert(ntfs_utf16_to_utf8(utf16, 1, utf8, sizeof(utf8), &size) == NTFS_INVALID);
	ntfs_decode_time(NTFS_TIME_EPOCH - 1, &time);
	assert(time.seconds == -1 && time.nanoseconds == 999999900);
	ntfs_decode_time(NTFS_TIME_EPOCH + NTFS_TIME_TICKS + 3, &time);
	assert(time.seconds == 1 && time.nanoseconds == 300);
	assert(ntfs_lznt1_decode(compressed, sizeof(compressed), output, sizeof(output), &size) ==
		NTFS_OK &&
	    size == sizeof(output));
	for (i = 0; i < size; i++) {
		assert(output[i] == 'Z');
	}
	memcpy(corrupt, compressed, sizeof(corrupt));
	corrupt[2] = 1;
	assert(ntfs_lznt1_decode(corrupt, sizeof(corrupt), output, sizeof(output), &size) ==
	    NTFS_CORRUPT);
	assert(ntfs_lznt1_decode(compressed, 3, output, sizeof(output), &size) == NTFS_CORRUPT);
	assert(ntfs_bounds(UINT64_MAX, 0, UINT64_MAX));
	assert(!ntfs_bounds(UINT64_MAX, 1, UINT64_MAX));
	record = calloc(1, 1024);
	original = malloc(1024);
	assert(record != NULL && original != NULL);
	memcpy(record, "FILE", 4);
	record[offsetof(struct ntfs_disk_mst, usa_offset)] = 48;
	record[offsetof(struct ntfs_disk_mst, usa_count)] = 3;
	record[48] = 1;
	record[510] = 1;
	memcpy(original, record, 1024);
	assert(ntfs_fixup(record, 1024, "FILE") == NTFS_CORRUPT &&
	    memcmp(original, record, 1024) == 0);
	free(original);
	free(record);
}

int
main(int argc, char **argv)
{
	struct memory_device m = {0};
	FILE *file;
	long size;
	size_t allocations, reads, i;
	enum ntfs_result result;

	assert(argc == 2);
	primitive_tests();
	file = fopen(argv[1], "rb");
	assert(file != NULL);
	assert(fseek(file, 0, SEEK_END) == 0);
	size = ftell(file);
	assert(size > 0);
	rewind(file);
	m.size = (size_t)size;
	m.bytes = malloc(m.size);
	assert(m.bytes != NULL);
	assert(fread(m.bytes, 1, m.size, file) == m.size);
	fclose(file);
	result = exercise(&m);
	if (result != NTFS_OK) {
		fprintf(stderr, "baseline: %s\n", ntfs_result_string(result));
		return 1;
	}
	allocations = m.allocation_calls;
	reads = m.read_calls;
	for (i = 1; i <= allocations; i++) {
		m.allocation_calls = 0;
		m.read_calls = 0;
		m.fail_allocation = i;
		result = exercise(&m);
		assert(result == NTFS_OK || result == NTFS_NO_MEMORY);
	}
	m.fail_allocation = 0;
	for (i = 1; i <= reads; i++) {
		m.allocation_calls = 0;
		m.read_calls = 0;
		m.fail_read = i;
		result = exercise(&m);
		assert(result == NTFS_IO);
	}
	free(m.bytes);
	printf("PASS: primitive and lifecycle contracts; %zu allocation and %zu I/O failure "
	       "positions\n",
	    allocations, reads);
	return 0;
}
