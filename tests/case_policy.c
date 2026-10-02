/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/ntfs.h>
#include "fuzz_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_IMAGE_LIMIT = 8 * 1024 * 1024,
	TEST_FILE_SEQUENCE = 7,
	TEST_SENSITIVE_DIRECTORY = 48,
	TEST_INSENSITIVE_DIRECTORY = 49,
	TEST_UPPER_A = 50,
	TEST_UPPER_FOO = 51,
	TEST_LOWER_FOO = 52,
	TEST_UPPER_Z = 53,
	TEST_LOWER_A = 54,
	TEST_UPPER_OMEGA = 56,
	TEST_LOWER_OMEGA = 57
};

struct expected_name {
	const uint16_t *units;
	size_t length;
	uint32_t record;
	const char *payload;
};

enum expected_name_index {
	NAME_UPPER_A,
	NAME_LOWER_A,
	NAME_UPPER_FOO,
	NAME_LOWER_FOO,
	NAME_UPPER_Z,
	NAME_UPPER_OMEGA,
	NAME_LOWER_OMEGA,
	NAME_COUNT
};

static const uint16_t upper_a[] = {'A', '.', 't', 'x', 't'};
static const uint16_t lower_a[] = {'a', '.', 't', 'x', 't'};
static const uint16_t upper_foo[] = {'F', 'o', 'o', '.', 't', 'x', 't'};
static const uint16_t lower_foo[] = {'f', 'o', 'o', '.', 't', 'x', 't'};
static const uint16_t mixed_foo[] = {'F', 'O', 'O', '.', 't', 'x', 't'};
static const uint16_t upper_z[] = {'Z', '.', 't', 'x', 't'};
static const uint16_t lower_z[] = {'z', '.', 't', 'x', 't'};
static const uint16_t upper_omega[] = {0x03a9, 'm', 'e', 'g', 'a'};
static const uint16_t lower_omega[] = {0x03c9, 'm', 'e', 'g', 'a'};
static const uint16_t mixed_omega[] = {0x03a9, 'M', 'E', 'G', 'A'};
static const uint16_t sensitive_name[] = {'S', 'e', 'n', 's', 'i', 't', 'i', 'v', 'e'};
static const uint16_t insensitive_name[] = {'I', 'n', 's', 'e', 'n', 's', 'i', 't', 'i', 'v', 'e'};
static const uint16_t upper_sensitive[] = {'S', 'E', 'N', 'S', 'I', 'T', 'I', 'V', 'E'};

#define UNITS(name) name, sizeof(name) / sizeof(name[0])
#define EXPECTED(name, record, payload) {UNITS(name), record, payload}

static const struct expected_name names[NAME_COUNT] = {
    [NAME_UPPER_A] = EXPECTED(upper_a, TEST_UPPER_A, "case-file/A.txt"),
    [NAME_LOWER_A] = EXPECTED(lower_a, TEST_LOWER_A, "case-file/a.txt"),
    [NAME_UPPER_FOO] = EXPECTED(upper_foo, TEST_UPPER_FOO, "case-file/Foo.txt"),
    [NAME_LOWER_FOO] = EXPECTED(lower_foo, TEST_LOWER_FOO, "case-file/foo.txt"),
    [NAME_UPPER_Z] = EXPECTED(upper_z, TEST_UPPER_Z, "case-file/Z.txt"),
    [NAME_UPPER_OMEGA] = EXPECTED(upper_omega, TEST_UPPER_OMEGA, "case-file/\xce\xa9mega"),
    [NAME_LOWER_OMEGA] = EXPECTED(lower_omega, TEST_LOWER_OMEGA, "case-file/\xcf\x89mega")};

static uint64_t
reference(uint32_t record)
{
	return (uint64_t)TEST_FILE_SEQUENCE << NTFS_REFERENCE_SEQUENCE_SHIFT | record;
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
	device->size = (size_t)size;
	assert(fread((void *)device->data, 1, device->size, source) == device->size);
	assert(fclose(source) == 0);
}

static struct ntfs_volume *
mount_image(struct fuzz_device *device, uint32_t cache_entries)
{
	struct ntfs_environment environment = fuzz_environment(device);
	struct ntfs_limits limits;
	struct ntfs_volume *volume = NULL;

	device->reads = 0;
	device->allocations = 0;
	device->fail_read = 0;
	device->fail_allocation = 0;
	ntfs_default_limits(&limits);
	limits.record_cache_entries = cache_entries;
	assert(ntfs_mount(&environment, &limits, &volume) == NTFS_OK);
	return volume;
}

static void
check_lookup(struct ntfs_node *parent, const uint16_t *name, size_t length,
    enum ntfs_result expected, const struct expected_name *target)
{
	struct ntfs_node *node = NULL;
	struct ntfs_stream *stream = NULL;
	struct ntfs_dirent entry, zero = {0};
	struct ntfs_stat stat;
	uint8_t bytes[sizeof("case-file/") + NTFS_NAME_MAX];
	size_t completed, payload_size;

	memset(&entry, 0xff, sizeof(entry));
	assert(ntfs_lookup_entry(parent, name, length, &node, &entry) == expected);
	if (expected != NTFS_OK) {
		assert(node == NULL && memcmp(&entry, &zero, sizeof(entry)) == 0);
		return;
	}
	assert(target != NULL && node != NULL);
	assert(entry.reference == reference(target->record) && entry.name_length == target->length);
	assert(memcmp(entry.name, target->units, target->length * sizeof(entry.name[0])) == 0);
	assert(ntfs_node_stat(node, &stat) == NTFS_OK && !stat.directory && !stat.case_sensitive);
	assert(ntfs_stream_open(node, NULL, 0, &stream) == NTFS_OK);
	payload_size = strlen(target->payload);
	assert(ntfs_stream_read(stream, 0, bytes, sizeof(bytes), &completed) == NTFS_OK);
	assert(completed == payload_size && memcmp(bytes, target->payload, completed) == 0);
	ntfs_stream_close(stream);
	ntfs_node_close(node);
}

static void
check_root(struct fuzz_device *device, bool sensitive, bool full_names, uint32_t cache_entries)
{
	const struct expected_name *unique_names[] = {&names[NAME_UPPER_FOO], &names[NAME_UPPER_Z]};
	struct ntfs_volume *volume = mount_image(device, cache_entries);
	struct ntfs_node *root = NULL;
	struct ntfs_directory *directory = NULL;
	struct ntfs_stat stat;
	struct ntfs_dirent entry;
	size_t i, reads, allocations, expected_count = sizeof(names) / sizeof(names[0]);

	assert(ntfs_root(volume, &root) == NTFS_OK);
	assert(ntfs_node_stat(root, &stat) == NTFS_OK && stat.directory &&
	    stat.case_sensitive == sensitive);
	reads = device->reads;
	allocations = device->allocations;
	assert(ntfs_node_stat(root, &stat) == NTFS_OK && stat.case_sensitive == sensitive);
	assert(device->reads == reads && device->allocations == allocations);
	if (full_names) {
		for (i = 0; i < expected_count; i++) {
			check_lookup(root, names[i].units, names[i].length, NTFS_OK, &names[i]);
		}
		check_lookup(root, UNITS(mixed_foo), NTFS_NOT_FOUND, NULL);
		check_lookup(root, UNITS(lower_z), NTFS_NOT_FOUND, NULL);
		check_lookup(root, UNITS(mixed_omega), NTFS_NOT_FOUND, NULL);
	} else {
		check_lookup(root, UNITS(mixed_foo), NTFS_OK, &names[NAME_UPPER_FOO]);
		check_lookup(root, UNITS(lower_foo), NTFS_OK, &names[NAME_UPPER_FOO]);
		check_lookup(root, UNITS(lower_z), NTFS_OK, &names[NAME_UPPER_Z]);
		expected_count = sizeof(unique_names) / sizeof(unique_names[0]);
	}
	assert(ntfs_directory_open(root, &directory) == NTFS_OK);
	ntfs_node_close(root);
	assert(ntfs_unmount(volume) == NTFS_BUSY);
	for (i = 0; i < expected_count; i++) {
		const struct expected_name *expected = full_names ? &names[i] : unique_names[i];

		assert(ntfs_directory_next(directory, &entry) == NTFS_OK);
		assert(entry.reference == reference(expected->record) &&
		    entry.name_length == expected->length);
		assert(memcmp(entry.name, expected->units,
			   expected->length * sizeof(entry.name[0])) == 0);
	}
	assert(ntfs_directory_next(directory, &entry) == NTFS_END);
	ntfs_directory_close(directory);
	assert(ntfs_unmount(volume) == NTFS_OK && device->memory == 0);
}

static void
check_mixed(struct fuzz_device *device, bool root_sensitive, bool unknown_child)
{
	struct ntfs_volume *volume = mount_image(device, 0);
	struct ntfs_node *root = NULL, *sensitive = NULL, *insensitive = NULL, *upper = NULL;
	struct ntfs_stat stat;
	enum ntfs_result result;

	assert(ntfs_root(volume, &root) == NTFS_OK);
	assert(ntfs_node_stat(root, &stat) == NTFS_OK && stat.case_sensitive == root_sensitive);
	assert(ntfs_lookup(root, UNITS(sensitive_name), &sensitive) == NTFS_OK);
	assert(ntfs_lookup(root, UNITS(insensitive_name), &insensitive) == NTFS_OK);
	result = ntfs_lookup(root, UNITS(upper_sensitive), &upper);
	assert(result == (root_sensitive ? NTFS_NOT_FOUND : NTFS_OK));
	ntfs_node_close(upper);
	if (unknown_child) {
		assert(ntfs_node_stat(sensitive, &stat) == NTFS_UNSUPPORTED);
		check_lookup(sensitive, UNITS(upper_foo), NTFS_UNSUPPORTED, NULL);
		assert(ntfs_node_stat(sensitive, &stat) == NTFS_UNSUPPORTED);
	} else {
		assert(ntfs_node_stat(sensitive, &stat) == NTFS_OK && stat.case_sensitive);
		assert(stat.reference == reference(TEST_SENSITIVE_DIRECTORY));
		check_lookup(sensitive, UNITS(upper_foo), NTFS_OK, &names[NAME_UPPER_FOO]);
		check_lookup(sensitive, UNITS(lower_foo), NTFS_OK, &names[NAME_LOWER_FOO]);
		check_lookup(sensitive, UNITS(mixed_foo), NTFS_NOT_FOUND, NULL);
	}
	assert(ntfs_node_stat(insensitive, &stat) == NTFS_OK && !stat.case_sensitive);
	assert(stat.reference == reference(TEST_INSENSITIVE_DIRECTORY));
	check_lookup(insensitive, UNITS(upper_foo), NTFS_OK, &names[NAME_UPPER_FOO]);
	check_lookup(insensitive, UNITS(lower_foo), NTFS_OK, &names[NAME_UPPER_FOO]);
	check_lookup(insensitive, UNITS(mixed_foo), NTFS_OK, &names[NAME_UPPER_FOO]);
	ntfs_node_close(insensitive);
	ntfs_node_close(sensitive);
	ntfs_node_close(root);
	assert(ntfs_unmount(volume) == NTFS_OK && device->memory == 0);
}

static void
check_rejection(struct fuzz_device *device, enum ntfs_result expected, bool mount_failure)
{
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *root = NULL;
	struct ntfs_environment environment = fuzz_environment(device);

	if (mount_failure) {
		assert(ntfs_mount(&environment, NULL, &volume) == expected && volume == NULL);
	} else {
		volume = mount_image(device, 0);
		assert(ntfs_root(volume, &root) == NTFS_OK);
		check_lookup(root, UNITS(upper_foo), expected, NULL);
		ntfs_node_close(root);
		assert(ntfs_unmount(volume) == NTFS_OK);
	}
	assert(device->memory == 0);
}

static enum ntfs_result
fault_lookup(struct fuzz_device *device, size_t fail_allocation, size_t fail_read,
    size_t *allocations, size_t *reads)
{
	struct ntfs_volume *volume = mount_image(device, 0);
	struct ntfs_node *root = NULL, *node = NULL;
	struct ntfs_dirent entry, zero = {0};
	size_t before_reads, before_allocations;
	enum ntfs_result result;

	assert(ntfs_root(volume, &root) == NTFS_OK);
	before_reads = device->reads;
	before_allocations = device->allocations;
	device->fail_read = fail_read == 0 ? 0 : before_reads + fail_read;
	device->fail_allocation = fail_allocation == 0 ? 0 : before_allocations + fail_allocation;
	memset(&entry, 0xff, sizeof(entry));
	result = ntfs_lookup_entry(root, UNITS(upper_foo), &node, &entry);
	*reads = device->reads - before_reads;
	*allocations = device->allocations - before_allocations;
	device->fail_read = 0;
	device->fail_allocation = 0;
	if (result == NTFS_OK) {
		assert(node != NULL && entry.reference == reference(TEST_UPPER_FOO));
		ntfs_node_close(node);
	} else {
		assert(node == NULL && memcmp(&entry, &zero, sizeof(entry)) == 0);
		check_lookup(root, UNITS(upper_foo), NTFS_OK, &names[NAME_UPPER_FOO]);
		check_lookup(root, UNITS(lower_foo), NTFS_OK, &names[NAME_LOWER_FOO]);
	}
	ntfs_node_close(root);
	assert(ntfs_unmount(volume) == NTFS_OK && device->memory == 0);
	return result;
}

int
main(int argc, char **argv)
{
	const char *sensitive[] = {"case-resident.img", "case-external.img", "case-nested.img",
	    "case-listed.img", "case-common.img", "case-storage-sensitive.img"};
	const char *insensitive[] = {
	    "case-insensitive.img", "case-storage-insensitive.img", "case-legacy-version.img"};
	const char *fault_images[] = {"case-external.img", "case-listed.img", "case-nested.img"};
	const char *rejected[] = {"case-insensitive-collision.img", "case-wrong-parent.img",
	    "case-wrong-order.img", "case-stale.img", "case-unknown-root.img"};

	const enum ntfs_result errors[] = {
	    NTFS_UNSUPPORTED, NTFS_CORRUPT, NTFS_CORRUPT, NTFS_STALE, NTFS_UNSUPPORTED};
	struct fuzz_device device = {0};
	size_t i, j, allocations, reads, observed_allocations, observed_reads;
	size_t allocation_failures = 0, read_failures = 0;

	assert(argc == 2);
	for (i = 0; i < sizeof(sensitive) / sizeof(sensitive[0]); i++) {
		load_image(argv[1], sensitive[i], &device);
		check_root(&device, true, true, 0);
		check_root(&device, true, true, NTFS_DEFAULT_RECORD_CACHE_ENTRIES);
		free((void *)device.data);
	}
	for (i = 0; i < sizeof(insensitive) / sizeof(insensitive[0]); i++) {
		load_image(argv[1], insensitive[i], &device);
		check_root(&device, false, false, 0);
		free((void *)device.data);
	}
	load_image(argv[1], "case-mixed.img", &device);
	check_mixed(&device, false, false);
	free((void *)device.data);
	load_image(argv[1], "case-mixed-sensitive-root.img", &device);
	check_mixed(&device, true, false);
	free((void *)device.data);
	load_image(argv[1], "case-unknown-child.img", &device);
	check_mixed(&device, false, true);
	free((void *)device.data);
	for (i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
		load_image(argv[1], rejected[i], &device);
		check_rejection(
		    &device, errors[i], i == sizeof(rejected) / sizeof(rejected[0]) - 1);
		free((void *)device.data);
	}
	for (i = 0; i < sizeof(fault_images) / sizeof(fault_images[0]); i++) {
		load_image(argv[1], fault_images[i], &device);
		assert(fault_lookup(&device, 0, 0, &allocations, &reads) == NTFS_OK);
		for (j = 1; j <= allocations; j++) {
			assert(fault_lookup(&device, j, 0, &observed_allocations,
				   &observed_reads) == NTFS_NO_MEMORY);
			allocation_failures++;
		}
		for (j = 1; j <= reads; j++) {
			assert(fault_lookup(&device, 0, j, &observed_allocations,
				   &observed_reads) == NTFS_IO);
			read_failures++;
		}
		free((void *)device.data);
	}
	printf("PASS: 17 case-policy images, exact UTF-16/tree collation, mixed parents, "
	       "legacy/unknown flags, %zu allocation/%zu I/O faults and retry\n",
	    allocation_failures, read_failures);
	return 0;
}
