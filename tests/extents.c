/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/ntfs.h>
#include "fixture.h"
#include "fuzz_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	FILE_SEQUENCE = 7,
	FILE_RECORD = 25,
	LOGICAL_CLUSTERS = 1024,
	PATH_BYTES = 4096,
	IMAGE_BYTES = 16 * 1024 * 1024,
	ORIGINAL_BYTES = LOGICAL_CLUSTERS * TEST_CLUSTER_BYTES,
	WINDOW_BYTES = 257,
	GUARD_BYTES = 16,
	GUARD_VALUE = 0xa5,
	CALLBACK_LIMIT = 64 * 1024,
	FAULT_SPAN_CLUSTERS = 3,
	FAULT_EXTRA_BYTES = 17,
	FAULT_BYTES = FAULT_SPAN_CLUSTERS * TEST_CLUSTER_BYTES + FAULT_EXTRA_BYTES,
	RANDOM_READS = 512,
	READ_CONTEXTS = 2,
	READ_FAILURE_MODES = 2,
	COMPOUND_READS = 2,
	FULL_WINDOW_BYTES = 32 * 1024
};

#define RANDOM_MULTIPLIER UINT32_C(1664525)
#define RANDOM_INCREMENT UINT32_C(1013904223)
#define RANDOM_SEED UINT32_C(0x71e4d2b9)

struct profile {
	const char *name;
	uint32_t runs;
};

enum budget_dimension { READ_CALL_CREDIT, READ_BYTE_CREDIT, WORK_CREDIT, BUDGET_DIMENSIONS };

static const struct profile profiles[] = {{"contiguous", 1}, {"runs-16", 16}, {"runs-256", 256},
    {"runs-1024", LOGICAL_CLUSTERS}, {"sparse-1024", LOGICAL_CLUSTERS},
    {"uninitialized-1024", LOGICAL_CLUSTERS}};

struct device {
	struct fuzz_device tracked;
	bool partial;
};

struct session {
	struct device device;
	struct ntfs_volume *volume;
	struct ntfs_stream *streams[READ_CONTEXTS];
	const uint8_t *original;
};

static size_t fault_cases, budget_cases, byte_checks;

static uint8_t *
load(const char *directory, const char *name, const char *suffix, size_t expected)
{
	char path[PATH_BYTES];
	FILE *file;
	uint8_t *bytes;
	int count;

	count = snprintf(path, sizeof(path), "%s/%s.%s", directory, name, suffix);
	assert(count > 0 && (size_t)count < sizeof(path));
	file = fopen(path, "rb");
	assert(file != NULL);
	bytes = malloc(expected);
	assert(bytes != NULL);
	assert(fread(bytes, 1, expected, file) == expected && fgetc(file) == EOF);
	assert(fclose(file) == 0);
	return bytes;
}

static enum ntfs_result
read_bytes(void *context, uint64_t offset, void *bytes, size_t length)
{
	struct device *device = context;
	struct fuzz_device *tracked = &device->tracked;

	tracked->reads++;
	if (tracked->reads > CALLBACK_LIMIT || offset > tracked->size ||
	    length > tracked->size - offset) {
		return NTFS_IO;
	}
	if (tracked->reads == tracked->fail_read) {
		if (device->partial) {
			memcpy(bytes, tracked->data + offset, length / 2);
		}
		return NTFS_IO;
	}
	memcpy(bytes, tracked->data + offset, length);
	return NTFS_OK;
}

static void
open_session(struct session *session, const uint8_t *image, const uint8_t *original)
{
	struct ntfs_environment environment;
	struct ntfs_limits limits;
	struct ntfs_node *node;
	uint64_t reference = (uint64_t)FILE_SEQUENCE << NTFS_REFERENCE_SEQUENCE_SHIFT | FILE_RECORD;
	size_t i;

	memset(session, 0, sizeof(*session));
	session->device.tracked.data = image;
	session->device.tracked.size = IMAGE_BYTES;
	session->original = original;
	environment = (struct ntfs_environment){NTFS_API_VERSION, &session->device, IMAGE_BYTES,
	    read_bytes, fuzz_allocate, fuzz_release};
	/* tracked is the first member, so the shared allocator receives its owner. */
	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	assert(ntfs_mount(&environment, &limits, &session->volume) == NTFS_OK);
	assert(ntfs_node_open(session->volume, reference, &node) == NTFS_OK);
	for (i = 0; i < READ_CONTEXTS; i++) {
		assert(ntfs_stream_open(node, NULL, 0, &session->streams[i]) == NTFS_OK);
		assert(ntfs_stream_size(session->streams[i]) == ORIGINAL_BYTES);
	}
	ntfs_node_close(node);
	assert(ntfs_unmount(session->volume) == NTFS_BUSY);
}

static void
close_session(struct session *session)
{
	size_t i;

	for (i = 0; i < READ_CONTEXTS; i++) {
		ntfs_stream_close(session->streams[i]);
	}
	assert(ntfs_unmount(session->volume) == NTFS_OK);
	assert(session->device.tracked.memory == 0);
}

static void
check_read(struct session *session, size_t context, uint64_t offset, size_t length,
    enum ntfs_result expected)
{
	uint8_t *buffer;
	size_t done, delivered, i;

	buffer = malloc(length + 2 * GUARD_BYTES);
	assert(buffer != NULL);
	memset(buffer, GUARD_VALUE, length + 2 * GUARD_BYTES);
	assert(ntfs_stream_read(session->streams[context], offset, buffer + GUARD_BYTES, length,
		   &done) == expected);
	delivered = offset < ORIGINAL_BYTES
	    ? (ORIGINAL_BYTES - offset < length ? (size_t)(ORIGINAL_BYTES - offset) : length)
	    : 0;
	if (expected == NTFS_OK) {
		assert(done == delivered);
		if (done != 0) {
			assert(memcmp(buffer + GUARD_BYTES, session->original + (size_t)offset,
				   done) == 0);
		}
		for (i = GUARD_BYTES + done; i < length + GUARD_BYTES; i++) {
			assert(buffer[i] == GUARD_VALUE);
		}
		byte_checks++;
	} else {
		assert(done == 0);
	}
	for (i = 0; i < GUARD_BYTES; i++) {
		assert(buffer[i] == GUARD_VALUE && buffer[GUARD_BYTES + length + i] == GUARD_VALUE);
	}
	free(buffer);
}

static void
contents(struct session *session, const struct profile *profile)
{
	uint64_t run_bytes = (uint64_t)ORIGINAL_BYTES / profile->runs;
	uint64_t start, offset;
	uint32_t random = RANDOM_SEED;
	size_t i, allocations, memory;

	allocations = session->device.tracked.allocations;
	memory = session->device.tracked.memory;
	/* Forbid any read-path allocation while exercising all independently stored runs. */
	session->device.tracked.fail_allocation = allocations + 1;
	for (i = 0; i < profile->runs; i++) {
		start = i * run_bytes;
		check_read(session, 0, start, WINDOW_BYTES, NTFS_OK);
		check_read(session, 0, start + 1, WINDOW_BYTES, NTFS_OK);
		check_read(session, 0, start + run_bytes - 1, WINDOW_BYTES, NTFS_OK);
		check_read(
		    session, 1, ORIGINAL_BYTES - start - WINDOW_BYTES, WINDOW_BYTES, NTFS_OK);
	}
	for (i = 0; i < RANDOM_READS; i++) {
		random = random * RANDOM_MULTIPLIER + RANDOM_INCREMENT;
		offset = random % (ORIGINAL_BYTES - WINDOW_BYTES + 1);
		check_read(session, i % READ_CONTEXTS, offset, WINDOW_BYTES, NTFS_OK);
	}
	for (offset = 0; offset < ORIGINAL_BYTES; offset += FULL_WINDOW_BYTES) {
		check_read(session, 0, offset, FULL_WINDOW_BYTES, NTFS_OK);
	}
	check_read(session, 0, ORIGINAL_BYTES - 1, WINDOW_BYTES, NTFS_OK);
	check_read(session, 0, ORIGINAL_BYTES, WINDOW_BYTES, NTFS_OK);
	check_read(session, 0, UINT64_MAX, WINDOW_BYTES, NTFS_OK);
	check_read(session, 0, 0, 0, NTFS_OK);
	assert(session->device.tracked.allocations == allocations &&
	    session->device.tracked.memory == memory);
	session->device.tracked.fail_allocation = 0;
}

static void
read_faults(struct session *session)
{
	size_t calls, before, memory, allocation, position, partial;
	const uint64_t offset = TEST_CLUSTER_BYTES - 1;

	before = session->device.tracked.reads;
	check_read(session, 0, offset, FAULT_BYTES, NTFS_OK);
	calls = session->device.tracked.reads - before;
	assert(calls != 0);
	memory = session->device.tracked.memory;
	allocation = session->device.tracked.allocations;
	for (partial = 0; partial < READ_FAILURE_MODES; partial++) {
		session->device.partial = partial != 0;
		for (position = 1; position <= calls; position++) {
			session->device.tracked.fail_read =
			    session->device.tracked.reads + position;
			check_read(session, 0, offset, FAULT_BYTES, NTFS_IO);
			session->device.tracked.fail_read = 0;
			check_read(session, 0, offset, FAULT_BYTES, NTFS_OK);
			check_read(session, 0, 0, WINDOW_BYTES, NTFS_OK);
			assert(session->device.tracked.memory == memory &&
			    session->device.tracked.allocations == allocation);
			fault_cases++;
		}
	}
	session->device.partial = false;
}

static void
budgets(struct session *session)
{
	struct ntfs_operation scope = {0};
	struct ntfs_operation_limits limits;
	struct ntfs_operation_usage required, usage;
	uint64_t *credit;
	size_t dimension, exact, i, reads, allocations;
	const uint64_t offset = TEST_CLUSTER_BYTES - 1;

	assert(ntfs_operation_begin(session->volume, NULL, &scope) == NTFS_OK);
	for (i = 0; i < COMPOUND_READS; i++) {
		check_read(session, 0, offset, FAULT_BYTES, NTFS_OK);
	}
	assert(ntfs_operation_end(&scope, &required) == NTFS_OK);
	assert(required.read_calls >= COMPOUND_READS && required.allocation_calls == 0);
	for (dimension = 0; dimension < BUDGET_DIMENSIONS; dimension++) {
		for (exact = 0; exact < COMPOUND_READS; exact++) {
			ntfs_get_operation_limits(session->volume, &limits);
			if (dimension == READ_CALL_CREDIT) {
				credit = &limits.read_calls;
				*credit = required.read_calls;
			} else if (dimension == READ_BYTE_CREDIT) {
				credit = &limits.read_bytes;
				*credit = required.read_bytes;
			} else {
				credit = &limits.work;
				*credit = required.work;
			}
			*credit -= exact == 0;
			reads = session->device.tracked.reads;
			allocations = session->device.tracked.allocations;
			assert(ntfs_operation_begin(session->volume, &limits, &scope) == NTFS_OK);
			check_read(session, 0, offset, FAULT_BYTES, NTFS_OK);
			check_read(
			    session, 0, offset, FAULT_BYTES, exact == 0 ? NTFS_RANGE : NTFS_OK);
			if (exact == 0) {
				assert(ntfs_operation_result(&scope) == NTFS_RANGE);
				check_read(session, 0, 0, 1, NTFS_RANGE);
			}
			assert(ntfs_operation_end(&scope, &usage) == NTFS_OK);
			assert(usage.read_calls == session->device.tracked.reads - reads &&
			    session->device.tracked.allocations == allocations);
			assert(usage.exhausted ==
			    (exact != 0 ? NTFS_OPERATION_LIMIT_NONE
				    : dimension == READ_CALL_CREDIT
				    ? NTFS_OPERATION_LIMIT_READ_CALLS
				    : dimension == READ_BYTE_CREDIT
				    ? NTFS_OPERATION_LIMIT_READ_BYTES
				    : NTFS_OPERATION_LIMIT_WORK));
			check_read(session, 0, offset, FAULT_BYTES, NTFS_OK);
			budget_cases++;
		}
	}
}

int
main(int argc, char **argv)
{
	struct session session;
	uint8_t *image, *original, *unchanged;
	size_t i;

	assert(argc == 2);
	unchanged = malloc(IMAGE_BYTES);
	assert(unchanged != NULL);
	for (i = 0; i < sizeof(profiles) / sizeof(profiles[0]); i++) {
		image = load(argv[1], profiles[i].name, "img", IMAGE_BYTES);
		original = load(argv[1], profiles[i].name, "data", ORIGINAL_BYTES);
		memcpy(unchanged, image, IMAGE_BYTES);
		open_session(&session, image, original);
		contents(&session, &profiles[i]);
		read_faults(&session);
		budgets(&session);
		close_session(&session);
		assert(memcmp(unchanged, image, IMAGE_BYTES) == 0);
		free(original);
		free(image);
	}
	free(unchanged);
	printf("PASS: extent reads, independent contexts, unchanged images, %zu byte checks, "
	       "%zu partial/full read faults and %zu exact/one-below compound budgets\n",
	    byte_checks, fault_cases, budget_cases);
	return 0;
}
