/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/ntfs.h>
#include "image.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_BITS_PER_BYTE = 8,
	TEST_CLOUD_VARIANTS = 16,
	TEST_CLOUD_VARIANT_SHIFT = 12,
	TEST_RESERVED_TAG_MAX = 2,
	TEST_INVALID_NAME_SELECTOR = 2,
	TEST_LONG_NAME_UNITS = 3000,
	TEST_NAME_CAPACITY = 64,
	TEST_HELLO_RECORD = 24,
	TEST_FILE_SEQUENCE = 7,
	TEST_UNPAIRED_HIGH_SURROGATE = 0xd800,
	TEST_RESERVED_FIELD = 0xabcd,
	TEST_NAME_FILL = 0x5a5a
};

#define TEST_UNKNOWN_TAG UINT32_C(0x80001234)
#define TEST_THIRD_PARTY_TAG UINT32_C(0x00001234)
#define TEST_RESERVED_TAG_BITS UINT32_C(0x01230000)
#define TEST_INVALID_DIRECTORY_TAG UINT32_C(0xb000000c)
#define TEST_FUTURE_SYMLINK_FLAG UINT32_C(0x00000002)

/* Independent MS-FSCC wire authors; no parser-private structures are used. */
struct test_common {
	uint8_t tag[sizeof(uint32_t)], length[sizeof(uint16_t)], reserved[sizeof(uint16_t)];
};

struct test_names {
	uint8_t substitute_offset[sizeof(uint16_t)], substitute_length[sizeof(uint16_t)];
	uint8_t print_offset[sizeof(uint16_t)], print_length[sizeof(uint16_t)];
};

struct test_paths {
	uint8_t substitute[2 * sizeof(uint16_t)], substitute_terminator[sizeof(uint16_t)];
	uint8_t display[sizeof(uint16_t)], display_terminator[sizeof(uint16_t)];
};

struct test_symlink {
	struct test_common common;
	struct test_names names;
	uint8_t flags[sizeof(uint32_t)];
	struct test_paths path;
};

struct test_mount_point {
	struct test_common common;
	struct test_names names;
	struct test_paths path;
};

struct test_guid_packet {
	struct test_common common;
	uint8_t guid_data1[sizeof(uint32_t)], guid_data2[sizeof(uint16_t)];
	uint8_t guid_data3[sizeof(uint16_t)], guid_data4[sizeof(uint64_t)];
	uint8_t payload[sizeof(uint16_t)];
};

struct tracked_device {
	struct ntfs_image image;
	size_t allocations, reads, fail_allocation, fail_read, live, live_bytes;
};

union tracked_allocation {
	max_align_t alignment;
	size_t size;
};

struct image_case {
	const char *filename;
	enum ntfs_result result;
	enum ntfs_reparse_kind kind;
	uint32_t tag;
	const uint16_t *substitute, *display;
	size_t substitute_length, display_length;
	uint32_t flags;
	bool directory, unflagged;
};

static const uint16_t relative_name[] = u"..\\\u03a9-target.txt";
static const uint16_t absolute_name[] = u"\\??\\C:\\folder\\target.txt";
static const uint16_t display_name[] = u"C:\\folder\\target.txt";
static const uint16_t unpaired_name[] = {TEST_UNPAIRED_HIGH_SURROGATE, 'x'};

#define UNITS(array) (sizeof(array) / sizeof((array)[0]) - 1)

static void
store(void *destination, uint64_t value, size_t size)
{
	uint8_t *bytes = destination;
	size_t i;

	for (i = 0; i < size; i++) {
		bytes[i] = (uint8_t)value;
		value >>= TEST_BITS_PER_BYTE;
	}
}

static void
check_decode(const void *buffer, size_t size, enum ntfs_result expected)
{
	struct ntfs_reparse_info info, zero = {0};
	enum ntfs_result result;

	memset(&info, TEST_NAME_FILL & UINT8_MAX, sizeof(info));
	result = ntfs_reparse_decode(buffer, size, &info);
	assert(result == expected);
	if (result != NTFS_OK) {
		assert(memcmp(&info, &zero, sizeof(info)) == 0);
	}
}

static void
decoder_tests(void)
{
	struct test_symlink valid = {0}, changed;
	struct test_mount_point junction = {0};
	struct test_common opaque = {0};
	struct test_guid_packet guid = {0};
	struct ntfs_reparse_info info;
	uint8_t *maximum;
	size_t i;
	uint32_t tag;

	store(valid.common.tag, NTFS_REPARSE_TAG_SYMLINK, sizeof(valid.common.tag));
	store(
	    valid.common.length, sizeof(valid) - sizeof(valid.common), sizeof(valid.common.length));
	store(valid.common.reserved, TEST_RESERVED_FIELD, sizeof(valid.common.reserved));
	store(valid.names.substitute_length, sizeof(valid.path.substitute),
	    sizeof(valid.names.substitute_length));
	store(valid.names.print_offset, offsetof(struct test_paths, display),
	    sizeof(valid.names.print_offset));
	store(
	    valid.names.print_length, sizeof(valid.path.display), sizeof(valid.names.print_length));
	store(valid.flags, NTFS_REPARSE_SYMLINK_RELATIVE, sizeof(valid.flags));
	store(valid.path.substitute, 'x', sizeof(uint16_t));
	store(valid.path.substitute + sizeof(uint16_t), 'y', sizeof(uint16_t));
	store(valid.path.display, 'z', sizeof(uint16_t));
	assert(ntfs_reparse_decode(&valid, sizeof(valid), &info) == NTFS_OK);
	assert(info.kind == NTFS_REPARSE_SYMLINK && info.tag == NTFS_REPARSE_TAG_SYMLINK &&
	    info.flags == NTFS_REPARSE_SYMLINK_RELATIVE &&
	    info.substitute_length == sizeof(valid.path.substitute) / sizeof(uint16_t) &&
	    info.print_length == sizeof(valid.path.display) / sizeof(uint16_t));
	for (i = 0; i < sizeof(valid); i++) {
		check_decode(&valid, i, NTFS_CORRUPT);
	}
	check_decode(NULL, sizeof(valid), NTFS_INVALID);
	assert(ntfs_reparse_decode(&valid, sizeof(valid), NULL) == NTFS_INVALID);

	changed = valid;
	store(changed.common.tag, NTFS_REPARSE_TAG_SYMLINK | TEST_RESERVED_TAG_BITS,
	    sizeof(changed.common.tag));
	assert(ntfs_reparse_decode(&changed, sizeof(changed), &info) == NTFS_OK &&
	    info.kind == NTFS_REPARSE_SYMLINK &&
	    info.tag == (NTFS_REPARSE_TAG_SYMLINK | TEST_RESERVED_TAG_BITS));
	changed = valid;
	store(changed.flags, 0, sizeof(changed.flags));
	check_decode(&changed, sizeof(changed), NTFS_OK);
	store(changed.flags, TEST_FUTURE_SYMLINK_FLAG, sizeof(changed.flags));
	check_decode(&changed, sizeof(changed), NTFS_UNSUPPORTED);
	changed = valid;
	store(changed.names.substitute_offset, 1, sizeof(changed.names.substitute_offset));
	check_decode(&changed, sizeof(changed), NTFS_CORRUPT);
	store(changed.names.substitute_offset, UINT16_MAX, sizeof(changed.names.substitute_offset));
	check_decode(&changed, sizeof(changed), NTFS_CORRUPT);
	changed = valid;
	store(changed.names.substitute_length, sizeof(uint16_t) - 1,
	    sizeof(changed.names.substitute_length));
	check_decode(&changed, sizeof(changed), NTFS_CORRUPT);
	store(changed.names.substitute_length, 0, sizeof(changed.names.substitute_length));
	check_decode(&changed, sizeof(changed), NTFS_CORRUPT);
	changed = valid;
	store(changed.names.print_offset, sizeof(changed.path), sizeof(changed.names.print_offset));
	check_decode(&changed, sizeof(changed), NTFS_CORRUPT);
	store(changed.names.print_length, 0, sizeof(changed.names.print_length));
	check_decode(&changed, sizeof(changed), NTFS_OK);
	changed = valid;
	store(changed.names.print_length, UINT16_MAX, sizeof(changed.names.print_length));
	check_decode(&changed, sizeof(changed), NTFS_CORRUPT);
	changed = valid;
	store(changed.names.print_offset, 1, sizeof(changed.names.print_offset));
	check_decode(&changed, sizeof(changed), NTFS_CORRUPT);
	changed = valid;
	/* Names may share the same bytes; ordering and terminators are optional. */
	store(changed.names.print_offset, 0, sizeof(changed.names.print_offset));
	store(changed.names.print_length, sizeof(changed.path.substitute),
	    sizeof(changed.names.print_length));
	check_decode(&changed, sizeof(changed), NTFS_OK);
	store(changed.common.length,
	    offsetof(struct test_symlink, path) + sizeof(changed.path.substitute) -
		sizeof(changed.common),
	    sizeof(changed.common.length));
	check_decode(&changed,
	    offsetof(struct test_symlink, path) + sizeof(changed.path.substitute), NTFS_OK);
	changed = valid;
	store(changed.path.substitute, 0, sizeof(uint16_t));
	check_decode(&changed, sizeof(changed), NTFS_CORRUPT);
	changed = valid;
	store(changed.path.display, 0, sizeof(uint16_t));
	check_decode(&changed, sizeof(changed), NTFS_CORRUPT);
	changed = valid;
	store(changed.path.substitute, TEST_UNPAIRED_HIGH_SURROGATE, sizeof(uint16_t));
	check_decode(&changed, sizeof(changed), NTFS_OK);
	changed = valid;
	store(changed.common.length, sizeof(changed) - sizeof(changed.common) - 1,
	    sizeof(changed.common.length));
	check_decode(&changed, sizeof(changed) - 1, NTFS_CORRUPT);
	changed = valid;
	store(changed.common.tag, TEST_INVALID_DIRECTORY_TAG, sizeof(changed.common.tag));
	check_decode(&changed, sizeof(changed), NTFS_CORRUPT);
	for (i = 0; i <= TEST_RESERVED_TAG_MAX; i++) {
		store(opaque.tag, i, sizeof(opaque.tag));
		check_decode(&opaque, sizeof(opaque), NTFS_CORRUPT);
	}
	store(opaque.tag, TEST_THIRD_PARTY_TAG, sizeof(opaque.tag));
	check_decode(&opaque, sizeof(opaque), NTFS_UNSUPPORTED);
	store(guid.common.tag, NTFS_REPARSE_TAG_SYMLINK, sizeof(guid.common.tag));
	store(guid.common.length, sizeof(guid.payload), sizeof(guid.common.length));
	check_decode(&guid, sizeof(guid), NTFS_UNSUPPORTED);
	store(guid.common.tag, TEST_THIRD_PARTY_TAG, sizeof(guid.common.tag));
	check_decode(&guid, sizeof(guid), NTFS_UNSUPPORTED);
	store(opaque.tag, TEST_UNKNOWN_TAG, sizeof(opaque.tag));
	assert(ntfs_reparse_decode(&opaque, sizeof(opaque), &info) == NTFS_OK &&
	    info.kind == NTFS_REPARSE_UNKNOWN);
	store(opaque.tag, NTFS_REPARSE_TAG_WOF, sizeof(opaque.tag));
	assert(ntfs_reparse_decode(&opaque, sizeof(opaque), &info) == NTFS_OK &&
	    info.kind == NTFS_REPARSE_WOF);
	for (i = 0; i < TEST_CLOUD_VARIANTS; i++) {
		tag = NTFS_REPARSE_TAG_CLOUD | (uint32_t)i << TEST_CLOUD_VARIANT_SHIFT;
		store(opaque.tag, tag, sizeof(opaque.tag));
		assert(ntfs_reparse_decode(&opaque, sizeof(opaque), &info) == NTFS_OK &&
		    info.kind == NTFS_REPARSE_CLOUD && info.tag == tag);
	}
	junction.common = valid.common;
	junction.names = valid.names;
	junction.path = valid.path;
	store(junction.common.tag, NTFS_REPARSE_TAG_MOUNT_POINT, sizeof(junction.common.tag));
	store(junction.common.length, sizeof(junction) - sizeof(junction.common),
	    sizeof(junction.common.length));
	assert(ntfs_reparse_decode(&junction, sizeof(junction), &info) == NTFS_OK &&
	    info.kind == NTFS_REPARSE_MOUNT_POINT && info.flags == 0);
	maximum = calloc(1, NTFS_REPARSE_MAX_BYTES + 1);
	assert(maximum != NULL);
	memcpy(maximum, &opaque, sizeof(opaque));
	store(((struct test_common *)maximum)->length, NTFS_REPARSE_MAX_BYTES - sizeof(opaque),
	    sizeof(opaque.length));
	check_decode(maximum, NTFS_REPARSE_MAX_BYTES, NTFS_OK);
	check_decode(maximum, NTFS_REPARSE_MAX_BYTES + 1, NTFS_CORRUPT);
	free(maximum);
}

static void *
allocate(void *context, size_t size)
{
	struct tracked_device *device = context;
	union tracked_allocation *header;

	if (++device->allocations == device->fail_allocation) {
		return NULL;
	}
	header = malloc(sizeof(*header) + size);
	assert(header != NULL);
	header->size = size;
	device->live++;
	device->live_bytes += size;
	return header + 1;
}

static void
release(void *context, void *memory, size_t size)
{
	struct tracked_device *device = context;
	union tracked_allocation *header = (union tracked_allocation *)memory - 1;

	assert(device->live != 0 && device->live_bytes >= size && header->size == size);
	device->live--;
	device->live_bytes -= size;
	free(header);
}

static enum ntfs_result
read_bytes(void *context, uint64_t offset, void *memory, size_t size)
{
	struct tracked_device *device = context;
	struct ntfs_environment *env = &device->image.environment;

	if (++device->reads == device->fail_read) {
		return NTFS_IO;
	}
	return env->read(env->context, offset, memory, size);
}

static void
check_names(struct ntfs_reparse *reparse, const struct image_case *test)
{
	uint16_t buffer[TEST_NAME_CAPACITY];
	const uint16_t *expected;
	size_t length, count, i;
	enum ntfs_reparse_name_type which;
	enum ntfs_result result;

	for (which = NTFS_REPARSE_SUBSTITUTE_NAME; which <= NTFS_REPARSE_PRINT_NAME; which++) {
		count = which == NTFS_REPARSE_SUBSTITUTE_NAME ? test->substitute_length
							      : test->display_length;
		expected = which == NTFS_REPARSE_SUBSTITUTE_NAME ? test->substitute : test->display;
		for (i = 0; i < sizeof(buffer) / sizeof(buffer[0]); i++) {
			buffer[i] = TEST_NAME_FILL;
		}
		result = ntfs_reparse_name(reparse, which, NULL, 0, &length);
		assert(length == count && result == (count == 0 ? NTFS_OK : NTFS_RANGE));
		if (count != 0 && count <= TEST_NAME_CAPACITY) {
			assert(ntfs_reparse_name(reparse, which, buffer, count - 1, &length) ==
				NTFS_RANGE &&
			    length == count);
			for (i = 0; i < TEST_NAME_CAPACITY; i++) {
				assert(buffer[i] == TEST_NAME_FILL);
			}
		}
		if (count > TEST_NAME_CAPACITY) {
			assert(ntfs_reparse_name(reparse, which, buffer, TEST_NAME_CAPACITY,
				   &length) == NTFS_RANGE);
		} else {
			assert(ntfs_reparse_name(
				   reparse, which, buffer, TEST_NAME_CAPACITY, &length) == NTFS_OK);
			assert(
			    count == 0 || memcmp(buffer, expected, count * sizeof(buffer[0])) == 0);
		}
		for (i = count <= TEST_NAME_CAPACITY ? count : 0; i < TEST_NAME_CAPACITY; i++) {
			assert(buffer[i] == TEST_NAME_FILL);
		}
	}
	assert(ntfs_reparse_name(reparse, NTFS_REPARSE_SUBSTITUTE_NAME, NULL, 1, &length) ==
	    NTFS_INVALID);
	assert(ntfs_reparse_name(reparse, TEST_INVALID_NAME_SELECTOR, buffer, TEST_NAME_CAPACITY,
		   &length) == NTFS_INVALID &&
	    length == 0);
	assert(ntfs_reparse_name(reparse, NTFS_REPARSE_SUBSTITUTE_NAME, buffer, TEST_NAME_CAPACITY,
		   NULL) == NTFS_INVALID);
}

static enum ntfs_result
exercise(struct tracked_device *device, const struct image_case *test, size_t fail_allocation,
    size_t fail_read, size_t *allocations, size_t *reads)
{
	struct ntfs_environment env = {NTFS_API_VERSION, device,
	    device->image.environment.size_bytes, read_bytes, allocate, release};
	struct ntfs_volume *volume;
	struct ntfs_node *node;
	struct ntfs_reparse *reparse = NULL;
	struct ntfs_reparse_info info;
	struct ntfs_stream *stream = NULL;
	struct ntfs_directory *directory = NULL;
	uint16_t *name;
	size_t length, i;
	enum ntfs_result result;
	uint64_t reference =
	    TEST_HELLO_RECORD | (uint64_t)TEST_FILE_SEQUENCE << NTFS_REFERENCE_SEQUENCE_SHIFT;

	device->fail_allocation = 0;
	device->fail_read = 0;
	assert(ntfs_mount(&env, NULL, &volume) == NTFS_OK);
	assert(ntfs_node_open(volume, reference, &node) == NTFS_OK);
	device->allocations = 0;
	device->reads = 0;
	device->fail_allocation = fail_allocation;
	device->fail_read = fail_read;
	result = ntfs_reparse_open(node, &reparse);
	*allocations = device->allocations;
	*reads = device->reads;
	device->fail_allocation = 0;
	device->fail_read = 0;
	if (result == NTFS_OK) {
		assert(reparse != NULL);
		ntfs_reparse_get_info(reparse, &info);
		assert(
		    info.kind == test->kind && info.tag == test->tag && info.flags == test->flags);
		assert(info.substitute_length == test->substitute_length &&
		    info.print_length == test->display_length);
		if (info.kind == NTFS_REPARSE_SYMLINK || info.kind == NTFS_REPARSE_MOUNT_POINT) {
			check_names(reparse, test);
			if (test->substitute_length == TEST_LONG_NAME_UNITS) {
				name = malloc(info.substitute_length * sizeof(*name));
				assert(name != NULL);
				assert(ntfs_reparse_name(reparse, NTFS_REPARSE_SUBSTITUTE_NAME,
					   name, info.substitute_length, &length) == NTFS_OK);
				for (i = 0; i < length; i++) {
					assert(name[i] == 'R');
				}
				free(name);
			}
		} else {
			assert(ntfs_reparse_name(reparse, NTFS_REPARSE_SUBSTITUTE_NAME, NULL, 0,
				   &length) == NTFS_UNSUPPORTED &&
			    length == 0);
		}
	} else {
		assert(reparse == NULL);
	}
	if (test->result != NTFS_NOT_FOUND) {
		assert(ntfs_stream_open(node, NULL, 0, &stream) ==
		    (test->unflagged ? NTFS_CORRUPT : NTFS_UNSUPPORTED));
		assert(stream == NULL);
	}
	if (test->directory) {
		assert(ntfs_directory_open(node, &directory) == NTFS_UNSUPPORTED);
		assert(directory == NULL);
	}
	ntfs_node_close(node);
	if (reparse != NULL) {
		assert(ntfs_unmount(volume) == NTFS_BUSY);
		if (test->kind == NTFS_REPARSE_SYMLINK || test->kind == NTFS_REPARSE_MOUNT_POINT) {
			check_names(reparse, test);
		}
	}
	ntfs_reparse_close(reparse);
	assert(ntfs_unmount(volume) == NTFS_OK);
	assert(device->live == 0 && device->live_bytes == 0);
	return result;
}

int
main(int argc, char **argv)
{
	const struct image_case tests[] = {{.filename = "standard.img", .result = NTFS_NOT_FOUND},
	    {"reparse-relative.img", NTFS_OK, NTFS_REPARSE_SYMLINK, NTFS_REPARSE_TAG_SYMLINK,
		relative_name, relative_name, UNITS(relative_name), UNITS(relative_name),
		NTFS_REPARSE_SYMLINK_RELATIVE, false, false},
	    {"reparse-absolute.img", NTFS_OK, NTFS_REPARSE_SYMLINK, NTFS_REPARSE_TAG_SYMLINK,
		absolute_name, display_name, UNITS(absolute_name), UNITS(display_name), 0, false,
		false},
	    {"reparse-junction.img", NTFS_OK, NTFS_REPARSE_MOUNT_POINT,
		NTFS_REPARSE_TAG_MOUNT_POINT, absolute_name, display_name, UNITS(absolute_name),
		UNITS(display_name), 0, true, false},
	    {"reparse-unpaired.img", NTFS_OK, NTFS_REPARSE_SYMLINK, NTFS_REPARSE_TAG_SYMLINK,
		unpaired_name, NULL, sizeof(unpaired_name) / sizeof(unpaired_name[0]), 0,
		NTFS_REPARSE_SYMLINK_RELATIVE, false, false},
	    {"reparse-nonresident.img", NTFS_OK, NTFS_REPARSE_SYMLINK, NTFS_REPARSE_TAG_SYMLINK,
		NULL, NULL, TEST_LONG_NAME_UNITS, 0, NTFS_REPARSE_SYMLINK_RELATIVE, false, false},
	    {"reparse-listed.img", NTFS_OK, NTFS_REPARSE_SYMLINK, NTFS_REPARSE_TAG_SYMLINK, NULL,
		NULL, TEST_LONG_NAME_UNITS, 0, NTFS_REPARSE_SYMLINK_RELATIVE, false, false},
	    {"reparse-resident-extension.img", NTFS_OK, NTFS_REPARSE_SYMLINK,
		NTFS_REPARSE_TAG_SYMLINK, relative_name, relative_name, UNITS(relative_name),
		UNITS(relative_name), NTFS_REPARSE_SYMLINK_RELATIVE, false, false},
	    {.filename = "reparse-wof.img",
		.result = NTFS_OK,
		.kind = NTFS_REPARSE_WOF,
		.tag = NTFS_REPARSE_TAG_WOF},
	    {.filename = "reparse-cloud.img",
		.result = NTFS_OK,
		.kind = NTFS_REPARSE_CLOUD,
		.tag = NTFS_REPARSE_TAG_CLOUD},
	    {.filename = "reparse-unknown.img",
		.result = NTFS_OK,
		.kind = NTFS_REPARSE_UNKNOWN,
		.tag = TEST_UNKNOWN_TAG},
	    {.filename = "reparse-third-party.img", .result = NTFS_UNSUPPORTED},
	    {.filename = "reparse-missing.img", .result = NTFS_CORRUPT},
	    {.filename = "reparse-duplicate.img", .result = NTFS_CORRUPT},
	    {.filename = "reparse-short.img", .result = NTFS_CORRUPT},
	    {.filename = "reparse-length.img", .result = NTFS_CORRUPT},
	    {.filename = "reparse-junction-file.img", .result = NTFS_CORRUPT},
	    {.filename = "reparse-uninitialized.img", .result = NTFS_CORRUPT},
	    {.filename = "reparse-sparse.img", .result = NTFS_CORRUPT},
	    {.filename = "reparse-oversized.img", .result = NTFS_CORRUPT},
	    {.filename = "reparse-unflagged.img", .result = NTFS_CORRUPT, .unflagged = true},
	    {.filename = "reparse-unflagged-extension.img",
		.result = NTFS_CORRUPT,
		.unflagged = true},
	    {.filename = "reparse-unlisted-base.img", .result = NTFS_CORRUPT, .unflagged = true},
	    {.filename = "reparse-named-unflagged.img", .result = NTFS_CORRUPT, .unflagged = true},
	    {.filename = "reparse-named-listed-unflagged.img",
		.result = NTFS_CORRUPT,
		.unflagged = true},
	    {"reparse-directory.img", NTFS_OK, NTFS_REPARSE_MOUNT_POINT,
		NTFS_REPARSE_TAG_MOUNT_POINT, absolute_name, display_name, UNITS(absolute_name),
		UNITS(display_name), 0, true, false}};
	struct tracked_device device = {0};
	struct ntfs_reparse *invalid = NULL;
	char *path;
	size_t i, fault, allocations, reads, ignored_allocations, ignored_reads, length;
	size_t total_allocations = 0, total_reads = 0;
	enum ntfs_result result;

	assert(argc == 2);
	decoder_tests();
	assert(ntfs_reparse_open(NULL, &invalid) == NTFS_INVALID && invalid == NULL);
	assert(ntfs_reparse_open(NULL, NULL) == NTFS_INVALID);
	ntfs_reparse_close(NULL);
	assert(ntfs_reparse_name(NULL, NTFS_REPARSE_PRINT_NAME, NULL, 0, &length) == NTFS_INVALID);
	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		length = strlen(argv[1]) + sizeof("/") + strlen(tests[i].filename);
		path = malloc(length);
		assert(path != NULL);
		assert(snprintf(path, length, "%s/%s", argv[1], tests[i].filename) > 0);
		assert(ntfs_image_open(path, &device.image) == 0);
		free(path);
		result = exercise(&device, &tests[i], 0, 0, &allocations, &reads);
		if (result != tests[i].result) {
			fprintf(stderr, "%s: %s\n", tests[i].filename, ntfs_result_string(result));
			return 1;
		}
		if (result == NTFS_OK) {
			for (fault = 1; fault <= allocations; fault++) {
				result = exercise(&device, &tests[i], fault, 0,
				    &ignored_allocations, &ignored_reads);
				assert(result == NTFS_OK || result == NTFS_NO_MEMORY);
			}
			for (fault = 1; fault <= reads; fault++) {
				assert(exercise(&device, &tests[i], 0, fault, &ignored_allocations,
					   &ignored_reads) == NTFS_IO);
			}
			total_allocations += allocations;
			total_reads += reads;
		}
		ntfs_image_close(&device.image);
	}
	printf("PASS: reparse decoder boundaries, %zu image contracts, independent lifetime, "
	       "fail-closed data/directory access; %zu allocation and %zu I/O failure positions\n",
	    sizeof(tests) / sizeof(tests[0]), total_allocations, total_reads);
	return 0;
}
