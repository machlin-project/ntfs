/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/wof.h>
#include "fixture.h"
#include "fuzz_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	FILE_SEQUENCE = 7,
	COMPRESSED_FILE_RECORD = 26,
	WOF_FILE_RECORD = 24,
	PATH_BYTES = 4096,
	GUARD_BYTES = 16,
	GUARD_VALUE = 0xa5,
	CHECK_BYTES = TEST_READ_WINDOW_BYTES,
	ALTERNATING_READS = 32,
	CACHE_WORKING_UNITS = 2,
	MIXED_FINAL_UNIT = 3,
	WOF_PARTIAL_UNIT = 2,
	CROSS_PREFIX_BYTES = 7,
	WOF_TABLE_PAGE_ENTRIES = TEST_CLUSTER_BYTES / sizeof(uint32_t)
};

enum refusal { ALLOCATOR_REFUSAL, CALL_CREDIT_REFUSAL, BYTE_CREDIT_REFUSAL, LIVE_REFUSAL };

struct profile {
	const char *image, *original;
	uint32_t record, unit, replacement;
};

static const struct profile profiles[] = {
    {"mixed-compression.img", "expected/mixed-compression.bin", COMPRESSED_FILE_RECORD,
	TEST_COMPRESSION_UNIT_BYTES, MIXED_FINAL_UNIT},
    {"wof-file-4k.img", "wof-file-4k.data", WOF_FILE_RECORD, NTFS_WOF_UNIT_4K, WOF_PARTIAL_UNIT},
    {"wof-file-8k.img", "wof-file-8k.data", WOF_FILE_RECORD, NTFS_WOF_UNIT_8K, WOF_PARTIAL_UNIT},
    {"wof-file-16k.img", "wof-file-16k.data", WOF_FILE_RECORD, NTFS_WOF_UNIT_16K, WOF_PARTIAL_UNIT},
    {"wof-file-lzx-packed.img", "wof-file-lzx-packed.data", WOF_FILE_RECORD, NTFS_WOF_UNIT_32K,
	WOF_PARTIAL_UNIT},
    {"wof-file-pages.img", "wof-file-pages.data", WOF_FILE_RECORD, NTFS_WOF_UNIT_4K,
	WOF_TABLE_PAGE_ENTRIES}};

struct test_device {
	struct fuzz_device device;
	uint64_t allocation_bytes, read_bytes;
	size_t peak;
	bool partial;
};

struct session {
	struct test_device device;
	struct ntfs_volume *volume;
	struct ntfs_stream *stream;
	const struct profile *profile;
	const uint8_t *original;
	size_t original_size;
};

static void *
allocate(void *context, size_t size)
{
	struct test_device *device = context;
	void *bytes;

	device->allocation_bytes += size;
	bytes = fuzz_allocate(&device->device, size);
	if (device->device.memory > device->peak) {
		device->peak = device->device.memory;
	}
	return bytes;
}

static void
release(void *context, void *bytes, size_t size)
{
	struct test_device *device = context;

	fuzz_release(&device->device, bytes, size);
}

static enum ntfs_result
read_bytes(void *context, uint64_t offset, void *bytes, size_t size)
{
	struct test_device *device = context;

	device->read_bytes += size;
	if (device->partial && device->device.reads + 1 == device->device.fail_read) {
		assert(offset <= device->device.size && size <= device->device.size - offset);
		memcpy(bytes, device->device.data + (size_t)offset, size / 2);
	}
	return fuzz_read(&device->device, offset, bytes, size);
}

static uint8_t *
load(const char *directory, const char *name, size_t *size)
{
	char path[PATH_BYTES];
	FILE *file;
	long length;
	uint8_t *bytes;
	int count;

	count = snprintf(path, sizeof(path), "%s/%s", directory, name);
	assert(count > 0 && (size_t)count < sizeof(path));
	file = fopen(path, "rb");
	assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
	length = ftell(file);
	assert(length > 0 && fseek(file, 0, SEEK_SET) == 0);
	*size = (size_t)length;
	bytes = malloc(*size);
	assert(bytes != NULL && fread(bytes, 1, *size, file) == *size);
	assert(fclose(file) == 0);
	return bytes;
}

static void
open_session(struct session *session, const struct profile *profile, const uint8_t *image,
    size_t image_size, const uint8_t *original, size_t original_size, uint64_t live)
{
	struct ntfs_environment environment;
	struct ntfs_limits limits;
	struct ntfs_node *node = NULL;
	uint64_t reference =
	    (uint64_t)FILE_SEQUENCE << NTFS_REFERENCE_SEQUENCE_SHIFT | profile->record;

	memset(session, 0, sizeof(*session));
	session->device.device.data = image;
	session->device.device.size = image_size;
	session->profile = profile;
	session->original = original;
	session->original_size = original_size;
	environment = (struct ntfs_environment){
	    NTFS_API_VERSION, &session->device, image_size, read_bytes, allocate, release};
	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	if (live != 0) {
		limits.max_live_bytes = live;
	}
	assert(ntfs_mount(&environment, &limits, &session->volume) == NTFS_OK);
	assert(ntfs_node_open(session->volume, reference, &node) == NTFS_OK);
	assert(ntfs_stream_open(node, NULL, 0, &session->stream) == NTFS_OK);
	ntfs_node_close(node);
	assert(ntfs_stream_size(session->stream) == original_size);
	assert(ntfs_unmount(session->volume) == NTFS_BUSY);
}

static void
close_session(struct session *session)
{
	ntfs_stream_close(session->stream);
	assert(ntfs_unmount(session->volume) == NTFS_OK && session->device.device.memory == 0);
}

static void
check_read(struct session *session, struct ntfs_stream *stream, uint64_t offset,
    enum ntfs_result expected_result)
{
	uint8_t buffer[CHECK_BYTES + 2 * GUARD_BYTES];
	size_t done, expected, i;

	memset(buffer, GUARD_VALUE, sizeof(buffer));
	assert(ntfs_stream_read(stream, offset, buffer + GUARD_BYTES, CHECK_BYTES, &done) ==
	    expected_result);
	expected = offset < session->original_size
	    ? (session->original_size - offset < CHECK_BYTES
		      ? (size_t)(session->original_size - offset)
		      : CHECK_BYTES)
	    : 0;
	if (expected_result == NTFS_OK) {
		assert(done == expected);
		if (done != 0) {
			assert(memcmp(buffer + GUARD_BYTES, session->original + (size_t)offset,
				   done) == 0);
		}
	} else {
		assert(done == 0);
	}
	for (i = 0; i < GUARD_BYTES; i++) {
		assert(buffer[i] == GUARD_VALUE);
	}
	for (i = GUARD_BYTES + done; i < sizeof(buffer); i++) {
		assert(buffer[i] == GUARD_VALUE);
	}
}

static void
read_unit(struct session *session, uint32_t unit, enum ntfs_result result)
{
	check_read(session, session->stream, (uint64_t)unit * session->profile->unit, result);
}

static void
warm_pair(struct session *session)
{
	read_unit(session, 0, NTFS_OK);
	read_unit(session, 1, NTFS_OK);
	read_unit(session, 0, NTFS_OK);
}

static void
cache_contents(struct session *session)
{
	struct ntfs_node *node;
	struct ntfs_stream *independent;
	struct ntfs_operation_usage usage;
	uint64_t reference =
	    (uint64_t)FILE_SEQUENCE << NTFS_REFERENCE_SEQUENCE_SHIFT | session->profile->record;
	size_t memory, allocations, reads, i;

	read_unit(session, 0, NTFS_OK);
	memory = session->device.device.memory;
	allocations = session->device.device.allocations;
	read_unit(session, 1, NTFS_OK);
	assert(session->device.device.memory == memory + session->profile->unit &&
	    session->device.device.allocations == allocations + 1);
	ntfs_get_operation_usage(session->volume, &usage);
	assert(usage.allocation_calls == 1 && usage.allocation_bytes == session->profile->unit &&
	    usage.exhausted == NTFS_OPERATION_LIMIT_NONE);
	reads = session->device.device.reads;
	allocations = session->device.device.allocations;
	for (i = 0; i < ALTERNATING_READS; i++) {
		read_unit(session, (uint32_t)(i % CACHE_WORKING_UNITS), NTFS_OK);
		ntfs_get_operation_usage(session->volume, &usage);
		assert(usage.read_calls == 0 && usage.allocation_calls == 0 &&
		    usage.work == CHECK_BYTES);
	}
	check_read(session, session->stream, session->profile->unit - CROSS_PREFIX_BYTES, NTFS_OK);
	assert(session->device.device.reads == reads &&
	    session->device.device.allocations == allocations);
	read_unit(session, 0, NTFS_OK);
	read_unit(session, session->profile->replacement, NTFS_OK);
	reads = session->device.device.reads;
	read_unit(session, 0, NTFS_OK);
	assert(session->device.device.reads == reads);
	read_unit(session, 1, NTFS_OK);
	assert(session->device.device.reads > reads);
	check_read(session, session->stream, session->original_size - 1, NTFS_OK);
	check_read(session, session->stream, session->original_size, NTFS_OK);
	check_read(session, session->stream, UINT64_MAX, NTFS_OK);
	assert(ntfs_node_open(session->volume, reference, &node) == NTFS_OK);
	assert(ntfs_stream_open(node, NULL, 0, &independent) == NTFS_OK);
	ntfs_node_close(node);
	reads = session->device.device.reads;
	check_read(session, independent, 0, NTFS_OK);
	assert(session->device.device.reads > reads);
	ntfs_stream_close(independent);
}

static void
fallback(const struct profile *profile, const uint8_t *image, size_t image_size,
    const uint8_t *original, size_t original_size, enum refusal refusal, uint64_t one_unit_live,
    uint64_t required_bytes)
{
	struct session session;
	struct ntfs_operation parent = {0}, child = {0};
	struct ntfs_operation_limits limits;
	struct ntfs_operation_usage parent_usage, child_usage;
	size_t allocations, memory, reads, i;

	open_session(&session, profile, image, image_size, original, original_size,
	    refusal == LIVE_REFUSAL ? one_unit_live : 0);
	if (refusal == CALL_CREDIT_REFUSAL || refusal == BYTE_CREDIT_REFUSAL) {
		ntfs_get_operation_limits(session.volume, &limits);
		if (refusal == CALL_CREDIT_REFUSAL) {
			limits.allocation_calls = 1;
		} else {
			limits.allocation_bytes = required_bytes;
		}
		assert(ntfs_operation_begin(session.volume, &limits, &parent) == NTFS_OK);
		assert(ntfs_operation_begin(session.volume, NULL, &child) == NTFS_OK);
	}
	read_unit(&session, 0, NTFS_OK);
	allocations = session.device.device.allocations;
	memory = session.device.device.memory;
	if (refusal == ALLOCATOR_REFUSAL) {
		session.device.device.fail_allocation = allocations + 1;
	}
	read_unit(&session, 1, NTFS_OK);
	assert(session.device.device.memory == memory);
	assert(session.device.device.allocations == allocations + (refusal == ALLOCATOR_REFUSAL));
	session.device.device.fail_allocation = 0;
	allocations = session.device.device.allocations;
	for (i = 0; i < ALTERNATING_READS; i++) {
		reads = session.device.device.reads;
		read_unit(&session, (uint32_t)(i % CACHE_WORKING_UNITS), NTFS_OK);
		assert(session.device.device.reads > reads);
	}
	assert(session.device.device.allocations == allocations &&
	    session.device.device.memory == memory);
	if (parent._active) {
		assert(ntfs_operation_result(&parent) == NTFS_OK &&
		    ntfs_operation_result(&child) == NTFS_OK);
		assert(ntfs_operation_end(&child, &child_usage) == NTFS_OK);
		assert(ntfs_operation_end(&parent, &parent_usage) == NTFS_OK);
		assert(memcmp(&parent_usage, &child_usage, sizeof(parent_usage)) == 0);
		assert(parent_usage.exhausted == NTFS_OPERATION_LIMIT_NONE &&
		    parent_usage.allocation_calls == 1 &&
		    parent_usage.allocation_bytes == required_bytes);
	}
	close_session(&session);
}

static void
required_failure(const struct profile *profile, const uint8_t *image, size_t image_size,
    const uint8_t *original, size_t original_size)
{
	struct session session;
	struct ntfs_operation_usage usage;
	size_t memory, reads;

	open_session(&session, profile, image, image_size, original, original_size, 0);
	memory = session.device.device.memory;
	reads = session.device.device.reads;
	session.device.device.fail_allocation = session.device.device.allocations + 1;
	read_unit(&session, 0, NTFS_NO_MEMORY);
	assert(session.device.device.memory == memory && session.device.device.reads == reads);
	ntfs_get_operation_usage(session.volume, &usage);
	assert(usage.allocation_calls == 1 && usage.exhausted == NTFS_OPERATION_LIMIT_NONE);
	session.device.device.fail_allocation = 0;
	read_unit(&session, 0, NTFS_OK);
	assert(session.device.device.reads > reads);
	close_session(&session);
}

static void
fallback_replacement_failure(const struct profile *profile, const uint8_t *image, size_t image_size,
    const uint8_t *original, size_t original_size)
{
	struct session session;
	size_t reads, allocations, memory;

	open_session(&session, profile, image, image_size, original, original_size, 0);
	read_unit(&session, 0, NTFS_OK);
	allocations = session.device.device.allocations;
	memory = session.device.device.memory;
	session.device.device.fail_allocation = allocations + 1;
	session.device.device.fail_read = session.device.device.reads + 1;
	session.device.partial = true;
	read_unit(&session, 1, NTFS_IO);
	assert(session.device.device.allocations == allocations + 1 &&
	    session.device.device.memory == memory);
	session.device.device.fail_allocation = 0;
	session.device.device.fail_read = 0;
	reads = session.device.device.reads;
	/* The single-buffer fallback invalidates the replaced output even when
	 * its first bytes happen to match the other unit's payload. */
	check_read(&session, session.stream, profile->unit / 2, NTFS_OK);
	assert(session.device.device.reads > reads);
	reads = session.device.device.reads;
	check_read(&session, session.stream, profile->unit / 2, NTFS_OK);
	assert(session.device.device.reads == reads);
	read_unit(&session, 1, NTFS_OK);
	assert(session.device.device.allocations == allocations + 1 &&
	    session.device.device.memory == memory);
	close_session(&session);
}

static void
replacement_failure(const struct profile *profile, const uint8_t *image, size_t image_size,
    const uint8_t *original, size_t original_size, size_t fault, bool partial,
    const struct ntfs_operation_limits *limits, enum ntfs_operation_limit exhausted)
{
	struct session session;
	struct ntfs_operation scope = {0};
	struct ntfs_operation_usage usage;
	size_t reads, allocations;

	open_session(&session, profile, image, image_size, original, original_size, 0);
	warm_pair(&session);
	allocations = session.device.device.allocations;
	if (limits != NULL) {
		assert(ntfs_operation_begin(session.volume, limits, &scope) == NTFS_OK);
	}
	session.device.device.fail_read = fault == 0 ? 0 : session.device.device.reads + fault;
	session.device.partial = partial;
	read_unit(&session, profile->replacement, fault != 0 ? NTFS_IO : NTFS_RANGE);
	if (limits != NULL) {
		assert(ntfs_operation_result(&scope) == NTFS_RANGE);
		assert(ntfs_operation_end(&scope, &usage) == NTFS_OK);
		assert(usage.exhausted == exhausted);
	}
	session.device.device.fail_read = 0;
	reads = session.device.device.reads;
	read_unit(&session, 0, NTFS_OK);
	assert(session.device.device.reads == reads);
	read_unit(&session, profile->replacement, NTFS_OK);
	assert(session.device.device.reads > reads);
	reads = session.device.device.reads;
	read_unit(&session, 0, NTFS_OK);
	read_unit(&session, profile->replacement, NTFS_OK);
	assert(session.device.device.reads == reads);
	read_unit(&session, 1, NTFS_OK);
	assert(session.device.device.reads > reads &&
	    session.device.device.allocations == allocations);
	close_session(&session);
}

int
main(int argc, char **argv)
{
	struct session session;
	struct ntfs_operation_usage required, replacement;
	struct ntfs_operation_limits limits;
	const struct profile *profile;
	uint8_t *image, *original, *saved;
	size_t image_size, original_size, one_unit_live, i, fault, faults = 0;
	unsigned refusal, partial;

	assert(argc == 2);
	for (i = 0; i < sizeof(profiles) / sizeof(profiles[0]); i++) {
		profile = &profiles[i];
		image = load(argv[1], profile->image, &image_size);
		original = load(argv[1], profile->original, &original_size);
		saved = malloc(image_size);
		assert(saved != NULL);
		memcpy(saved, image, image_size);
		open_session(&session, profile, image, image_size, original, original_size, 0);
		read_unit(&session, 0, NTFS_OK);
		ntfs_get_operation_usage(session.volume, &required);
		assert(required.allocation_calls == 1 && required.allocation_bytes > profile->unit);
		one_unit_live = session.device.device.memory;
		assert(session.device.peak <= one_unit_live);
		read_unit(&session, 1, NTFS_OK);
		read_unit(&session, 0, NTFS_OK);
		read_unit(&session, profile->replacement, NTFS_OK);
		ntfs_get_operation_usage(session.volume, &replacement);
		assert(replacement.read_calls > 0 && replacement.read_bytes > 1 &&
		    replacement.work > CHECK_BYTES);
		close_session(&session);
		open_session(&session, profile, image, image_size, original, original_size, 0);
		cache_contents(&session);
		close_session(&session);
		required_failure(profile, image, image_size, original, original_size);
		fallback_replacement_failure(profile, image, image_size, original, original_size);
		for (refusal = ALLOCATOR_REFUSAL; refusal <= LIVE_REFUSAL; refusal++) {
			fallback(profile, image, image_size, original, original_size, refusal,
			    one_unit_live, required.allocation_bytes);
		}
		for (fault = 1; fault <= replacement.read_calls; fault++) {
			for (partial = 0; partial <= 1; partial++) {
				replacement_failure(profile, image, image_size, original,
				    original_size, fault, partial != 0, NULL,
				    NTFS_OPERATION_LIMIT_NONE);
				faults++;
			}
		}
		ntfs_operation_default_limits(&limits);
		limits.read_bytes = replacement.read_bytes - 1;
		replacement_failure(profile, image, image_size, original, original_size, 0, false,
		    &limits, NTFS_OPERATION_LIMIT_READ_BYTES);
		ntfs_operation_default_limits(&limits);
		limits.work = replacement.work - 1;
		replacement_failure(profile, image, image_size, original, original_size, 0, false,
		    &limits, NTFS_OPERATION_LIMIT_WORK);
		assert(memcmp(saved, image, image_size) == 0);
		free(saved);
		free(original);
		free(image);
	}
	printf("PASS: %zu compression-cache profiles, %zu partial/full replacement faults; "
	       "independent bytes, two-unit reuse, eviction, required/optional failures, "
	       "nested credits, live caps, retry and exact cleanup\n",
	    sizeof(profiles) / sizeof(profiles[0]), faults);
	return 0;
}
