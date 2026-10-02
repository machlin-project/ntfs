/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/security.h>
#include "fuzz_device.h"
#include "fixture.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_FILE_RECORD = 24,
	TEST_FILE_SEQUENCE = 7,
	TEST_DESCRIPTOR_LIMIT = 256 * 1024,
	TEST_SDS_HEADER_BYTES = 20,
	TEST_LOCAL_SYSTEM_RID = 18,
	TEST_BUILTIN_USERS_RID = 545,
	TEST_NT_AUTHORITY = 5,
	TEST_CAPACITY_SENTINEL = 0xa5,
	TEST_LARGE_DESCRIPTOR_BYTES = 9001
};

struct secure_case {
	const char *image;
	uint32_t id, node_budget;
	enum ntfs_result result;
	enum ntfs_acl_state dacl;
	bool direct, large, maximum, encrypted, inline_storage, different_owner;
};

static uint8_t *
read_file(const char *directory, const char *name, size_t maximum, size_t *size)
{
	char *path;
	FILE *source;
	long length;
	uint8_t *bytes;
	size_t capacity = strlen(directory) + sizeof("/") + strlen(name);

	path = malloc(capacity);
	assert(path != NULL && snprintf(path, capacity, "%s/%s", directory, name) > 0);
	source = fopen(path, "rb");
	free(path);
	assert(source != NULL && fseek(source, 0, SEEK_END) == 0);
	length = ftell(source);
	assert(length > 0 && (size_t)length <= maximum && fseek(source, 0, SEEK_SET) == 0);
	bytes = malloc((size_t)length);
	assert(bytes != NULL && fread(bytes, 1, (size_t)length, source) == (size_t)length);
	assert(fclose(source) == 0);
	*size = (size_t)length;
	return bytes;
}

static void
verify_snapshot(struct fuzz_device *device, struct ntfs_security *snapshot,
    const struct secure_case *test, const char *directory)
{
	struct ntfs_security_info info, decoded;
	uint8_t *bytes, *expected;
	char expected_name[sizeof("secure-expected/same-hash-4294967295.bin")];
	size_t required, size, i, before_reads = device->reads,
				  before_allocations = device->allocations;
	uint32_t id = test->id != 0 ? test->id : TEST_SECURITY_ID;

	assert(ntfs_security_id(snapshot) == (test->inline_storage ? 0 : id));
	ntfs_security_get_info(snapshot, &info);
	assert(info.dacl.state == test->dacl && info.sacl.state == NTFS_ACL_ABSENT);
	if (info.dacl.state == NTFS_ACL_PRESENT) {
		assert(info.owner.authority == TEST_NT_AUTHORITY && info.owner.count == 1 &&
		    info.owner.subauthorities[0] == TEST_LOCAL_SYSTEM_RID + test->different_owner);
		assert(info.group.authority == TEST_NT_AUTHORITY && info.group.count == 2 &&
		    info.group.subauthorities[1] == TEST_BUILTIN_USERS_RID);
		assert(info.dacl.entries == 1 && !info.dacl.opaque_aces);
	}
	assert(ntfs_security_copy(snapshot, NULL, 0, &required) == NTFS_OK);
	assert(required == ntfs_security_size(snapshot) && required > 0);
	if (test->maximum) {
		assert(required == TEST_DESCRIPTOR_LIMIT - TEST_SDS_HEADER_BYTES);
		strcpy(expected_name, "secure-expected/maximum.bin");
	} else if (test->large) {
		assert(required == TEST_LARGE_DESCRIPTOR_BYTES);
		strcpy(expected_name, "secure-expected/large.bin");
	} else if (strcmp(test->image, "secure-same-hash.img") == 0) {
		assert(snprintf(expected_name, sizeof(expected_name),
			   "secure-expected/same-hash-%u.bin", id) > 0);
	} else {
		/* The maximum-ID image intentionally reuses ID 256's bytes. */
		if (strcmp(test->image, "secure-maximum-id.img") == 0) {
			id = TEST_SECURITY_ID;
		}
		assert(snprintf(
			   expected_name, sizeof(expected_name), "secure-expected/%u.bin", id) > 0);
	}
	expected = read_file(directory, expected_name, TEST_DESCRIPTOR_LIMIT, &size);
	assert(size == required);
	bytes = malloc(required);
	assert(bytes != NULL);
	memset(bytes, TEST_CAPACITY_SENTINEL, required);
	device->fail_read = before_reads + 1;
	device->fail_allocation = before_allocations + 1;
	assert(ntfs_security_copy(snapshot, bytes, required - 1, &size) == NTFS_RANGE &&
	    size == required);
	for (i = 0; i < required; i++) {
		assert(bytes[i] == TEST_CAPACITY_SENTINEL);
	}
	assert(ntfs_security_copy(snapshot, bytes, required, &size) == NTFS_OK && size == required);
	assert(memcmp(bytes, expected, size) == 0);
	assert(ntfs_security_decode(bytes, size, &decoded) == NTFS_OK);
	assert(memcmp(&info, &decoded, sizeof(info)) == 0);
	ntfs_security_get_info(snapshot, &decoded);
	assert(memcmp(&info, &decoded, sizeof(info)) == 0);
	assert(ntfs_security_copy(snapshot, NULL, 1, &size) == NTFS_INVALID && size == 0);
	assert(ntfs_security_copy(snapshot, bytes, required, NULL) == NTFS_INVALID);
	assert(device->reads == before_reads && device->allocations == before_allocations);
	device->fail_read = 0;
	device->fail_allocation = 0;
	free(bytes);
	free(expected);
}

static enum ntfs_result
exercise(struct fuzz_device *device, const struct secure_case *test, const char *directory,
    size_t fail_allocation, size_t fail_read, size_t *allocations, size_t *reads)
{
	struct ntfs_environment env = fuzz_environment(device);
	struct ntfs_limits limits;
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *node = NULL;
	struct ntfs_security *snapshot = NULL;
	struct ntfs_stream *stream = NULL;
	size_t before_allocations, before_reads, before_memory;
	enum ntfs_result result;

	device->allocations = 0;
	device->reads = 0;
	device->fail_allocation = 0;
	device->fail_read = 0;
	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	if (test->node_budget != 0) {
		limits.max_directory_nodes = test->node_budget;
	}
	assert(ntfs_mount(&env, &limits, &volume) == NTFS_OK);
	assert(ntfs_node_open(volume,
		   TEST_FILE_RECORD | (uint64_t)TEST_FILE_SEQUENCE << NTFS_REFERENCE_SEQUENCE_SHIFT,
		   &node) == NTFS_OK);
	before_allocations = device->allocations;
	before_reads = device->reads;
	before_memory = device->memory;
	device->fail_allocation = fail_allocation != 0 ? before_allocations + fail_allocation : 0;
	device->fail_read = fail_read != 0 ? before_reads + fail_read : 0;
	result = test->direct ? ntfs_security_resolve(volume, test->id, &snapshot)
			      : ntfs_security_open(node, &snapshot);
	*allocations = device->allocations - before_allocations;
	*reads = device->reads - before_reads;
	device->fail_allocation = 0;
	device->fail_read = 0;
	if (result == NTFS_OK) {
		assert(snapshot != NULL);
		if (test->encrypted) {
			assert(ntfs_stream_open(node, NULL, 0, &stream) == NTFS_UNSUPPORTED &&
			    stream == NULL);
		}
	} else {
		assert(snapshot == NULL && device->memory == before_memory);
		if (fail_allocation != 0 || fail_read != 0) {
			assert((test->direct ? ntfs_security_resolve(volume, test->id, &snapshot)
					     : ntfs_security_open(node, &snapshot)) == NTFS_OK);
		}
	}
	ntfs_node_close(node);
	if (snapshot != NULL) {
		assert(ntfs_unmount(volume) == NTFS_BUSY);
		verify_snapshot(device, snapshot, test, directory);
	}
	ntfs_security_close(snapshot);
	assert(ntfs_unmount(volume) == NTFS_OK && device->memory == 0);
	return result;
}

int
main(int argc, char **argv)
{
	const struct secure_case cases[] = {
	    {.image = "secure-resident.img", .dacl = NTFS_ACL_PRESENT},
	    {.image = "secure-resident.img",
		.direct = true,
		.id = TEST_SECURITY_ID + 1,
		.dacl = NTFS_ACL_ABSENT},
	    {.image = "secure-resident.img",
		.direct = true,
		.id = TEST_SECURITY_ID + 2,
		.dacl = NTFS_ACL_NULL},
	    {.image = "secure-resident.img",
		.direct = true,
		.id = TEST_SECURITY_ID + 3,
		.dacl = NTFS_ACL_EMPTY},
	    {.image = "secure-resident.img",
		.direct = true,
		.id = TEST_SECURITY_ID - 1,
		.result = NTFS_NOT_FOUND},
	    {.image = "secure-resident.img", .direct = true, .id = 0, .result = NTFS_INVALID},
	    {.image = "secure-listed.img", .dacl = NTFS_ACL_PRESENT},
	    {.image = "secure-stale.img", .result = NTFS_STALE},
	    {.image = "secure-wrong-base.img", .result = NTFS_STALE},
	    {.image = "secure-maximum-id.img", .id = UINT32_MAX, .dacl = NTFS_ACL_PRESENT},
	    {.image = "secure-large.img", .dacl = NTFS_ACL_PRESENT, .large = true},
	    {.image = "secure-maximum-descriptor.img", .dacl = NTFS_ACL_PRESENT, .maximum = true},
	    {.image = "secure-second-pair.img", .dacl = NTFS_ACL_PRESENT},
	    {.image = "secure-same-hash.img",
		.direct = true,
		.id = TEST_SECURITY_ID,
		.dacl = NTFS_ACL_PRESENT},
	    {.image = "secure-same-hash.img",
		.direct = true,
		.id = TEST_SECURITY_ID + 1,
		.dacl = NTFS_ACL_PRESENT,
		.different_owner = true},
	    {.image = "secure-zero-id.img", .result = NTFS_CORRUPT},
	    {.image = "secure-inline.img", .inline_storage = true, .dacl = NTFS_ACL_PRESENT},
	    {.image = "secure-inline-legacy.img", .inline_storage = true, .dacl = NTFS_ACL_PRESENT},
	    {.image = "secure-inline-null.img",
		.inline_storage = true,
		.id = TEST_SECURITY_ID + 2,
		.dacl = NTFS_ACL_NULL},
	    {.image = "secure-inline-empty.img",
		.inline_storage = true,
		.id = TEST_SECURITY_ID + 3,
		.dacl = NTFS_ACL_EMPTY},
	    {.image = "secure-inline-listed.img", .inline_storage = true, .dacl = NTFS_ACL_PRESENT},
	    {.image = "secure-inline-missing.img", .result = NTFS_CORRUPT},
	    {.image = "secure-inline-zero.img", .result = NTFS_CORRUPT},
	    {.image = "secure-inline-short.img", .result = NTFS_CORRUPT},
	    {.image = "secure-inline-duplicate.img", .result = NTFS_CORRUPT},
	    {.image = "secure-inline-nonresident.img",
		.inline_storage = true,
		.dacl = NTFS_ACL_PRESENT},
	    {.image = "secure-inline-fragmented.img",
		.inline_storage = true,
		.dacl = NTFS_ACL_PRESENT,
		.large = true},
	    {.image = "secure-inline-uninitialized.img", .result = NTFS_CORRUPT},
	    {.image = "secure-inline-oversized.img", .result = NTFS_RANGE},
	    {.image = "secure-id-no-fallback.img", .result = NTFS_CORRUPT},
	    {.image = "secure-missing-id.img", .result = NTFS_CORRUPT},
	    {.image = "secure-unknown-record-flag.img", .result = NTFS_CORRUPT},
	    {.image = "secure-encrypted-file.img", .dacl = NTFS_ACL_PRESENT, .encrypted = true},
	    {.image = "secure-reparse-file.img", .dacl = NTFS_ACL_PRESENT},
	    {.image = "secure-uninitialized.img", .result = NTFS_CORRUPT},
	    {.image = "secure-hash.img", .result = NTFS_CORRUPT},
	    {.image = "secure-duplicate-header.img", .result = NTFS_CORRUPT},
	    {.image = "secure-duplicate-body.img", .result = NTFS_CORRUPT},
	    {.image = "secure-descriptor.img", .result = NTFS_CORRUPT},
	    {.image = "secure-alignment.img", .result = NTFS_CORRUPT},
	    {.image = "secure-secondary-offset.img", .result = NTFS_CORRUPT},
	    {.image = "secure-overflow.img", .result = NTFS_CORRUPT},
	    {.image = "secure-cross-block.img", .result = NTFS_CORRUPT},
	    {.image = "secure-short-length.img", .result = NTFS_CORRUPT},
	    {.image = "secure-large-length.img", .result = NTFS_CORRUPT},
	    {.image = "secure-header-id.img", .result = NTFS_CORRUPT},
	    {.image = "secure-header-hash.img", .result = NTFS_CORRUPT},
	    {.image = "secure-sdh-missing.img", .result = NTFS_CORRUPT},
	    {.image = "secure-sdh-mismatch.img", .result = NTFS_CORRUPT},
	    {.image = "secure-sii-order.img", .result = NTFS_CORRUPT},
	    {.image = "secure-sii-duplicate.img", .result = NTFS_CORRUPT},
	    {.image = "secure-sii-data-overlap.img", .result = NTFS_CORRUPT},
	    {.image = "secure-sii-key-size.img", .result = NTFS_CORRUPT},
	    {.image = "secure-sii-flags.img", .result = NTFS_CORRUPT},
	    {.image = "secure-sii-no-terminal.img", .result = NTFS_CORRUPT},
	    {.image = "secure-sii-terminal-data.img", .result = NTFS_CORRUPT},
	    {.image = "secure-sii-missing-allocation.img", .result = NTFS_CORRUPT},
	    {.image = "secure-sii-collation.img", .result = NTFS_UNSUPPORTED},
	    {.image = "secure-sii-block-size.img", .result = NTFS_CORRUPT},
	    {.image = "secure-tree.img", .dacl = NTFS_ACL_PRESENT},
	    {.image = "secure-tree.img",
		.direct = true,
		.id = TEST_SECURITY_ID + 2,
		.dacl = NTFS_ACL_NULL},
	    {.image = "secure-tree.img",
		.direct = true,
		.id = TEST_SECURITY_ID + 3,
		.dacl = NTFS_ACL_EMPTY},
	    {.image = "secure-tree-bounds.img", .result = NTFS_CORRUPT},
	    {.image = "secure-tree-lower.img",
		.direct = true,
		.id = TEST_SECURITY_ID + 3,
		.result = NTFS_CORRUPT},
	    {.image = "secure-tree-usa.img", .result = NTFS_CORRUPT},
	    {.image = "secure-tree-free.img", .result = NTFS_CORRUPT},
	    {.image = "secure-tree-short-bitmap.img", .result = NTFS_CORRUPT},
	    {.image = "secure-tree-torn.img", .result = NTFS_CORRUPT},
	    {.image = "secure-tree-vcn.img", .result = NTFS_CORRUPT},
	    {.image = "secure-tree-overflow.img", .result = NTFS_CORRUPT},
	    {.image = "secure-depth-valid.img", .dacl = NTFS_ACL_PRESENT},
	    {.image = "secure-depth-valid.img", .node_budget = 1, .result = NTFS_RANGE},
	    {.image = "secure-depth-limit.img", .result = NTFS_RANGE},
	    {.image = "secure-cycle.img", .result = NTFS_CORRUPT}};
	struct fuzz_device device = {0};
	struct ntfs_security *invalid = NULL;
	struct ntfs_security_info info, zero = {0};
	size_t i, fault, allocations, reads, ignored_allocations, ignored_reads, size;
	size_t allocation_faults = 0, read_faults = 0;
	enum ntfs_result result;

	assert(argc == 2);
	assert(ntfs_security_open(NULL, &invalid) == NTFS_INVALID && invalid == NULL);
	assert(ntfs_security_open(NULL, NULL) == NTFS_INVALID);
	assert(ntfs_security_resolve(NULL, TEST_SECURITY_ID, &invalid) == NTFS_INVALID &&
	    invalid == NULL);
	assert(ntfs_security_resolve(NULL, TEST_SECURITY_ID, NULL) == NTFS_INVALID);
	assert(ntfs_security_copy(NULL, NULL, 0, &size) == NTFS_INVALID && size == 0);
	assert(ntfs_security_id(NULL) == 0 && ntfs_security_size(NULL) == 0);
	memset(&info, 0xff, sizeof(info));
	ntfs_security_get_info(NULL, &info);
	assert(memcmp(&info, &zero, sizeof(info)) == 0);
	ntfs_security_get_info(NULL, NULL);
	ntfs_security_close(NULL);
	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		device.data = read_file(argv[1], cases[i].image, TEST_IMAGE_BYTES, &device.size);
		result = exercise(&device, &cases[i], argv[1], 0, 0, &allocations, &reads);
		if (result != cases[i].result) {
			fprintf(stderr, "%s: expected %s, received %s\n", cases[i].image,
			    ntfs_result_string(cases[i].result), ntfs_result_string(result));
			return 1;
		}
		if (result == NTFS_OK) {
			for (fault = 1; fault <= allocations; fault++) {
				assert(exercise(&device, &cases[i], argv[1], fault, 0,
					   &ignored_allocations, &ignored_reads) == NTFS_NO_MEMORY);
			}
			for (fault = 1; fault <= reads; fault++) {
				assert(exercise(&device, &cases[i], argv[1], 0, fault,
					   &ignored_allocations, &ignored_reads) == NTFS_IO);
			}
			allocation_faults += allocations;
			read_faults += reads;
		}
		free((void *)device.data);
	}
	printf("PASS: %zu Secure contracts, %zu allocation/%zu I/O failures with retry and exact "
	       "release\n",
	    sizeof(cases) / sizeof(cases[0]), allocation_faults, read_faults);
	return 0;
}
