/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include "fixture.h"
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
	const char *const missing[] = {"!missing", "hello.txt.more", "zzzz-missing"};
	uint16_t name[NTFS_NAME_MAX];
	uint8_t buffer[TEST_READ_WINDOW_BYTES];
	size_t done, count = 0, i, name_length;
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
	assert(free_clusters == TEST_IMAGE_BYTES / TEST_CLUSTER_BYTES - TEST_ALLOCATED_CLUSTERS);
	result = ntfs_root(v, &root);
	if (result != NTFS_OK) {
		goto finish;
	}
	assert(ntfs_unmount(v) == NTFS_BUSY);
	for (i = 0; i < sizeof(missing) / sizeof(missing[0]); i++) {
		result = ntfs_utf8_to_utf16(
		    missing[i], strlen(missing[i]), name, NTFS_NAME_MAX, &name_length);
		assert(result == NTFS_OK);
		result = ntfs_lookup(root, name, name_length, &looked);
		if (result != NTFS_NOT_FOUND) {
			assert(result != NTFS_OK);
			goto finish;
		}
		assert(looked == NULL);
	}
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
		assert(
		    st.size == entry.size && st.links == 1 && st.security_id == TEST_SECURITY_ID);
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
		assert(count == TEST_FILE_COUNT && ntfs_directory_next(d, &entry) == NTFS_END);
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
store_u16(void *destination, uint16_t value)
{
	uint8_t *bytes = destination;

	bytes[0] = (uint8_t)value;
	bytes[1] = (uint8_t)(value >> NTFS_BITS_PER_BYTE);
}

static void
primitive_tests(void)
{
	enum {
		SAMPLE_UTF16_UNITS = 4,
		UNPAIRED_HIGH_SURROGATE = 0xd800,
		SUBSECOND_TICKS = 3,
		FIXUP_SEQUENCE = 1,
		LITERAL_TOKEN_MASK = 1u << 1,
		INVALID_INITIAL_MATCH_MASK = 1u << 0
	};

	uint16_t utf16[NTFS_NAME_MAX];
	char utf8[NTFS_UTF8_NAME_MAX];
	const char sample[] = "A\xce\xa9\xf0\x9f\x98\x80";
	const char overlong[] = "\xc0\x80", surrogate[] = "\xed\xa0\x80";
	const char out_of_range[] = "\xf4\x90\x80\x80";

	struct repeated_chunk {
		uint8_t header[sizeof(uint16_t)], flags, literal;
		uint8_t token[sizeof(uint16_t)], terminator[sizeof(uint16_t)];
	} compressed = {0}, corrupt;

	uint8_t output[NTFS_LZNT1_CHUNK], *record, *original;
	struct ntfs_disk_record *header;
	size_t size, units, i;
	struct ntfs_time time;

	assert(ntfs_utf8_to_utf16(sample, sizeof(sample) - 1, utf16, NTFS_NAME_MAX, &units) ==
		NTFS_OK &&
	    units == SAMPLE_UTF16_UNITS);
	assert(ntfs_utf16_to_utf8(utf16, units, utf8, sizeof(utf8), &size) == NTFS_OK &&
	    size == sizeof(sample) - 1);
	assert(memcmp(sample, utf8, size) == 0);
	assert(ntfs_utf8_to_utf16(overlong, sizeof(overlong) - 1, utf16, NTFS_NAME_MAX, &units) ==
	    NTFS_INVALID);
	assert(ntfs_utf8_to_utf16(surrogate, sizeof(surrogate) - 1, utf16, NTFS_NAME_MAX, &units) ==
	    NTFS_INVALID);
	assert(ntfs_utf8_to_utf16(out_of_range, sizeof(out_of_range) - 1, utf16, NTFS_NAME_MAX,
		   &units) == NTFS_INVALID);
	assert(ntfs_utf8_to_utf16(sample, sizeof(sample) - 1, utf16, 1, &units) == NTFS_RANGE);
	utf16[0] = UNPAIRED_HIGH_SURROGATE;
	assert(ntfs_utf16_to_utf8(utf16, 1, utf8, sizeof(utf8), &size) == NTFS_INVALID);
	ntfs_decode_time(NTFS_TIME_EPOCH - 1, &time);
	assert(time.seconds == -1 &&
	    time.nanoseconds == (NTFS_TIME_TICKS - 1) * NTFS_TIME_NANOSECONDS_PER_TICK);
	ntfs_decode_time(NTFS_TIME_EPOCH + NTFS_TIME_TICKS + SUBSECOND_TICKS, &time);
	assert(time.seconds == 1 &&
	    time.nanoseconds == SUBSECOND_TICKS * NTFS_TIME_NANOSECONDS_PER_TICK);
	store_u16(compressed.header,
	    NTFS_LZNT1_SIGNATURE | NTFS_LZNT1_COMPRESSED |
		(sizeof(compressed.flags) + sizeof(compressed.literal) + sizeof(compressed.token) -
		    1));
	compressed.flags = LITERAL_TOKEN_MASK;
	compressed.literal = 'Z';
	store_u16(
	    compressed.token, NTFS_LZNT1_CHUNK - sizeof(compressed.literal) - NTFS_LZNT1_MIN_MATCH);
	assert(ntfs_lznt1_decode(&compressed, sizeof(compressed), output, sizeof(output), &size) ==
		NTFS_OK &&
	    size == sizeof(output));
	for (i = 0; i < size; i++) {
		assert(output[i] == 'Z');
	}
	corrupt = compressed;
	corrupt.flags = INVALID_INITIAL_MATCH_MASK;
	assert(ntfs_lznt1_decode(&corrupt, sizeof(corrupt), output, sizeof(output), &size) ==
	    NTFS_CORRUPT);
	assert(ntfs_lznt1_decode(&compressed, offsetof(struct repeated_chunk, token), output,
		   sizeof(output), &size) == NTFS_CORRUPT);
	assert(ntfs_bounds(UINT64_MAX, 0, UINT64_MAX));
	assert(!ntfs_bounds(UINT64_MAX, 1, UINT64_MAX));
	record = calloc(1, TEST_MFT_RECORD_BYTES);
	original = malloc(TEST_MFT_RECORD_BYTES);
	assert(record != NULL && original != NULL);
	header = (void *)record;
	memcpy(header->mst.magic, "FILE", sizeof(header->mst.magic));
	store_u16(header->mst.usa_offset, sizeof(*header));
	store_u16(header->mst.usa_count, TEST_MFT_RECORD_BYTES / NTFS_MST_STRIDE + 1);
	store_u16(record + sizeof(*header), FIXUP_SEQUENCE);
	store_u16(record + NTFS_MST_STRIDE - NTFS_MST_WORD_BYTES, FIXUP_SEQUENCE);
	memcpy(original, record, TEST_MFT_RECORD_BYTES);
	assert(ntfs_fixup(record, TEST_MFT_RECORD_BYTES, "FILE") == NTFS_CORRUPT &&
	    memcmp(original, record, TEST_MFT_RECORD_BYTES) == 0);
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
