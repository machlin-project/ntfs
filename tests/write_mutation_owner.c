/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_mutation.h"
#include "write_owner.h"
#include "write_batch_history.h"
#include <ntfs/validate.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_PATH_BYTES = 4096,
	TEST_WRITE_BYTES = 8193,
	TEST_GAP_BYTES = 257,
	TEST_SHRINK_BYTES = 19,
	TEST_RING_CYCLES = 48,
	TEST_HISTORY_PADDING_FILES = 48,
	TEST_HISTORY_CYCLES = 100,
	TEST_HISTORY_NAME_UNITS = 3,
	TEST_NAME_ALPHABET = 26,
	TEST_HISTORY_REOPEN_INTERVAL = 8,
	TEST_HISTORY_JOURNAL_BYTES = 4 * 1024 * 1024,
	TEST_HISTORY_MIN_FREE_PAGES = 64,
	TEST_FIRST_ORDINARY_RECORD = 24
};

#define TEST_TIME UINT64_C(134357146906613431)
#define TEST_CREATED_TIME UINT64_C(116444735991234567)
#define TEST_MODIFIED_TIME UINT64_C(116444736000000001)

union test_allocation {
	max_align_t alignment;
	size_t bytes;
};

struct test_device {
	uint8_t *visible, *durable;
	size_t bytes, live, allocations, reads, writes, barriers, claims, unclaims;
	size_t fail_allocation, fail_read, fail_write, fail_barrier;
	bool claimed, executing;
};

static void *
allocate(void *context, size_t bytes)
{
	struct test_device *device = context;
	union test_allocation *memory;

	assert(!device->executing && bytes != 0);
	device->allocations++;
	if (device->allocations == device->fail_allocation) {
		return NULL;
	}
	memory = malloc(sizeof(*memory) + bytes);
	assert(memory != NULL);
	memory->bytes = bytes;
	device->live += bytes;
	return memory + 1;
}

static void
release(void *context, void *pointer, size_t bytes)
{
	struct test_device *device = context;
	union test_allocation *memory = (union test_allocation *)pointer - 1;

	assert(memory->bytes == bytes && device->live >= bytes);
	device->live -= bytes;
	free(memory);
}

static enum ntfs_result
read_image(void *context, uint64_t first, void *output, size_t bytes)
{
	struct test_device *device = context;

	assert(!device->executing && first <= device->bytes && bytes <= device->bytes - first);
	device->reads++;
	if (device->reads == device->fail_read) {
		memcpy(output, device->visible + first, bytes / 2);
		return NTFS_IO;
	}
	memcpy(output, device->visible + first, bytes);
	return NTFS_OK;
}

static enum ntfs_result
claim(void *context)
{
	struct test_device *device = context;

	device->claims++;
	if (device->claimed) {
		return NTFS_BUSY;
	}
	device->claimed = true;
	return NTFS_OK;
}

static void
unclaim(void *context)
{
	struct test_device *device = context;

	assert(device->claimed);
	device->claimed = false;
	device->unclaims++;
}

static enum ntfs_result
write_image(void *context, uint64_t first, const void *input, size_t bytes, size_t *actual)
{
	struct test_device *device = context;

	assert(device->claimed && bytes == NTFS_WRITE_CLUSTER_BYTES);
	/* Fresh recovery may publish its first prepared journal copy before the
	 * first barrier. Reads/allocations stop at the first transfer in either route. */
	device->executing = true;
	assert(first <= device->bytes && bytes <= device->bytes - first);
	assert(first % NTFS_WRITE_SECTOR_BYTES == 0 &&
	    (uintptr_t)input % NTFS_WRITE_SECTOR_BYTES == 0);
	device->writes++;
	if (device->writes == device->fail_write) {
		memcpy(device->visible + first, input, NTFS_WRITE_SECTOR_BYTES);
		*actual = NTFS_WRITE_SECTOR_BYTES;
		return NTFS_IO;
	}
	memcpy(device->visible + first, input, bytes);
	*actual = bytes;
	return NTFS_OK;
}

static enum ntfs_result
persist(void *context)
{
	struct test_device *device = context;

	assert(device->claimed);
	device->executing = true;
	device->barriers++;
	if (device->barriers == device->fail_barrier) {
		return NTFS_IO;
	}
	memcpy(device->durable, device->visible, device->bytes);
	return NTFS_OK;
}

static struct ntfs_overwrite_environment
environment(struct test_device *device)
{
	return (struct ntfs_overwrite_environment){
	    {NTFS_API_VERSION, device, device->bytes, read_image, allocate, release},
	    NTFS_OVERWRITE_API_VERSION, NTFS_WRITE_SECTOR_BYTES, claim, unclaim, write_image,
	    persist};
}

static void
begin(struct test_device *device)
{
	device->executing = false;
	device->allocations = device->reads = device->writes = device->barriers = 0;
	device->fail_allocation = device->fail_read = device->fail_write = device->fail_barrier = 0;
}

static uint64_t
root_reference(struct test_device *device)
{
	struct ntfs_environment reader = environment(device).reader;
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *root = NULL;
	struct ntfs_stat metadata;

	assert(ntfs_mount(&reader, NULL, &volume) == NTFS_OK);
	assert(ntfs_root(volume, &root) == NTFS_OK && ntfs_node_stat(root, &metadata) == NTFS_OK);
	ntfs_node_close(root);
	assert(ntfs_unmount(volume) == NTFS_OK);
	return metadata.reference;
}

static void
check_file(struct test_device *device, uint64_t reference, const uint8_t *wanted, size_t bytes)
{
	struct ntfs_environment reader = environment(device).reader;
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *node = NULL;
	struct ntfs_stream *stream = NULL;
	struct ntfs_stat metadata;
	uint8_t *actual;
	size_t copied;

	device->executing = false;
	actual = malloc(bytes == 0 ? 1 : bytes);
	assert(actual != NULL && ntfs_mount(&reader, NULL, &volume) == NTFS_OK);
	assert(ntfs_node_open(volume, reference, &node) == NTFS_OK);
	assert(ntfs_node_stat(node, &metadata) == NTFS_OK && metadata.size == bytes);
	assert(ntfs_stream_open(node, NULL, 0, &stream) == NTFS_OK);
	assert(ntfs_stream_read(stream, 0, actual, bytes, &copied) == NTFS_OK && copied == bytes);
	assert(memcmp(actual, wanted, bytes) == 0);
	ntfs_stream_close(stream);
	ntfs_node_close(node);
	assert(ntfs_unmount(volume) == NTFS_OK);
	assert(memcmp(device->visible, device->durable, device->bytes) == 0);
	free(actual);
}

static void
checkpoint_preparation_failures(struct test_device *device, struct ntfs_overwrite *owner,
    const struct ntfs_write_mutation_request *request, bool *checked)
{
	struct ntfs_write_mutation_execution *prepared = NULL;
	uint8_t *before;
	size_t allocations, reads, live;

	if (*checked) {
		return;
	}
	begin(device);
	live = device->live;
	assert(ntfs_write_mutation_execution_prepare(owner, request, &prepared) == NTFS_OK);
	allocations = device->allocations;
	reads = device->reads;
	*checked = ntfs_write_mutation_execution_preview(prepared)->checkpoint_required;
	ntfs_write_mutation_execution_close(prepared);
	if (!*checked) {
		return;
	}
	before = malloc(device->bytes);
	assert(before != NULL);
	memcpy(before, device->visible, device->bytes);
	begin(device);
	device->fail_read = reads;
	assert(ntfs_write_mutation_execution_prepare(owner, request, &prepared) == NTFS_IO &&
	    prepared == NULL);
	assert(device->reads == reads && device->writes == 0 && device->barriers == 0 &&
	    device->live == live && memcmp(before, device->visible, device->bytes) == 0);
	begin(device);
	device->fail_allocation = allocations;
	assert(ntfs_write_mutation_execution_prepare(owner, request, &prepared) == NTFS_NO_MEMORY &&
	    prepared == NULL);
	assert(device->allocations == allocations && device->writes == 0 && device->barriers == 0 &&
	    device->live == live && memcmp(before, device->visible, device->bytes) == 0);
	free(before);
	puts("PASS: checkpoint plus mutation last-read/allocation refusal before either "
	     "publication");
}

static void
partial_write_reopen(struct test_device *device)
{
	static const uint16_t name[] = {'i', 'n', 't', 'e', 'r', 'r', 'u', 'p', 't', 'e', 'd'};
	static const uint16_t path[] = {'/', 'i', 'n', 't', 'e', 'r', 'r', 'u', 'p', 't', 'e', 'd'};
	struct ntfs_overwrite_environment backend = environment(device);
	struct ntfs_overwrite_admission *admission;
	struct ntfs_write_recovery_report recovered;
	struct ntfs_write_mutation_report report;
	struct ntfs_write_name source;
	struct ntfs_overwrite *owner = NULL;
	uint64_t reference;

	admission = malloc(sizeof(*admission));
	assert(admission != NULL);
	source =
	    (struct ntfs_write_name){root_reference(device), name, sizeof(name) / sizeof(*name)};
	begin(device);
	assert(ntfs_write_mutation_owner_open(&backend, admission, &recovered, &owner) == NTFS_OK);
	begin(device);
	device->fail_write = 1;
	assert(ntfs_write_create_file(owner, &source, TEST_TIME, &report) == NTFS_IO &&
	    report.initial_persistence_succeeded && report.execution.poisoned &&
	    device->writes == 1 && device->barriers == 1);
	/* Model a cut retaining that one complete sector, without a retry by the
	 * failed owner or any knowledge of its discarded mutation plan. */
	memcpy(device->durable, device->visible, device->bytes);
	begin(device);
	assert(ntfs_write_create_file(owner, &source, TEST_TIME, &report) == NTFS_IO &&
	    device->allocations == 0 && device->reads == 0 && device->writes == 0 &&
	    device->barriers == 0);
	ntfs_overwrite_close(owner);
	assert(device->live == 0 && !device->claimed);
	begin(device);
	assert(ntfs_write_mutation_owner_open(&backend, admission, &recovered, &owner) == NTFS_OK &&
	    recovered.completed && admission->validation.complete);
	begin(device);
	assert(ntfs_overwrite_resolve(owner, path, sizeof(path) / sizeof(*path), &reference) ==
	    NTFS_NOT_FOUND);
	ntfs_overwrite_close(owner);
	assert(device->live == 0 && !device->claimed);
	free(admission);
	puts("PASS: sector-partial writer poison and fresh image-only recovery admission");
}

static void
prepared_contract(struct test_device *device)
{
	static uint16_t name[] = {'p', 'r', 'e', 'p', 'a', 'r', 'e', 'd'};
	static const uint16_t root_path[] = {'/'};
	struct ntfs_overwrite_environment backend = environment(device);
	struct ntfs_overwrite_admission *admission;
	struct ntfs_write_recovery_report recovered;
	struct ntfs_write_mutation_report report;
	struct ntfs_write_mutation_execution *prepared = NULL, *other = NULL;
	const struct ntfs_write_mutation_preview *preview;
	struct ntfs_write_mutation_request request = {0};
	struct ntfs_write_mutation_request alias;
	struct ntfs_overwrite *owner = NULL;
	uint8_t *before, *payload, *wanted;
	uint64_t reference, ignored;
	size_t live, allocations, reads, index, unclaims;
	enum ntfs_result result;

	admission = malloc(sizeof(*admission));
	before = malloc(device->bytes);
	payload = malloc(TEST_WRITE_BYTES);
	wanted = calloc(1, TEST_GAP_BYTES + TEST_WRITE_BYTES);
	assert(admission != NULL && before != NULL && payload != NULL && wanted != NULL);
	request.kind = NTFS_WRITE_CREATE_FILE;
	request.source =
	    (struct ntfs_write_name){root_reference(device), name, sizeof(name) / sizeof(*name)};
	request.filetime = TEST_TIME;
	begin(device);
	assert(ntfs_write_mutation_owner_open(&backend, admission, &recovered, &owner) == NTFS_OK);
	live = device->live;
	memcpy(before, device->visible, device->bytes);
	alias = request;
	alias.source.units = (const uint16_t *)&prepared;
	alias.source.count = 1;
	begin(device);
	assert(ntfs_write_mutation_execution_prepare(owner, &alias, &prepared) == NTFS_INVALID &&
	    prepared == NULL && device->reads == 0 && device->allocations == 0);
	begin(device);
	assert(ntfs_write_mutation_execution_prepare(owner, &request, &prepared) == NTFS_OK);
	allocations = device->allocations;
	reads = device->reads;
	preview = ntfs_write_mutation_execution_preview(prepared);
	assert(preview != NULL && preview->item_exists && preview->item.stat.size == 0 &&
	    preview->item.links.primary_names == 1 && preview->source_directory_present &&
	    preview->source_directory.stat.reference == request.source.parent_reference);
	assert(device->writes == 0 && device->barriers == 0 &&
	    memcmp(before, device->visible, device->bytes) == 0);
	assert(ntfs_write_mutation_execution_prepare(owner, &request, &other) == NTFS_BUSY &&
	    other == NULL && device->allocations == allocations && device->reads == reads);
	assert(ntfs_overwrite_resolve(owner, root_path, 1, &ignored) == NTFS_BUSY && ignored == 0);
	ntfs_write_mutation_execution_close(prepared);
	prepared = NULL;
	assert(device->live == live && device->writes == 0 && device->barriers == 0);
	for (index = 0; index < 4; index++) {
		begin(device);
		if (index < 2) {
			device->fail_allocation = index == 0 ? 1 : allocations;
		} else {
			device->fail_read = index == 2 ? 1 : reads;
		}
		result = ntfs_write_mutation_execution_prepare(owner, &request, &prepared);
		assert(result == (index < 2 ? NTFS_NO_MEMORY : NTFS_IO) && prepared == NULL);
		assert(device->live == live && device->writes == 0 && device->barriers == 0 &&
		    memcmp(before, device->visible, device->bytes) == 0);
	}
	begin(device);
	assert(ntfs_write_mutation_execution_prepare(owner, &request, &prepared) == NTFS_OK);
	reference = ntfs_write_mutation_execution_preview(prepared)->item.stat.reference;
	/* The prepared owner must not borrow request/name storage. */
	memset(name, 0, sizeof(name));
	memset(&request, 0, sizeof(request));
	assert(ntfs_write_mutation_execution_execute(prepared, &report) == NTFS_OK &&
	    report.reference == reference && report.execution.completed);
	assert(ntfs_write_mutation_execution_execute(prepared, &report) == NTFS_STALE);
	ntfs_write_mutation_execution_close(prepared);
	prepared = NULL;
	assert(device->live == live);
	check_file(device, reference, wanted, 0);
	for (index = 0; index < TEST_WRITE_BYTES; index++) {
		payload[index] = (uint8_t)(index * 23u + 7u);
	}
	memcpy(wanted + TEST_GAP_BYTES, payload, TEST_WRITE_BYTES);
	request.kind = NTFS_WRITE_GROWING_RANGE;
	request.reference = reference;
	request.offset = TEST_GAP_BYTES;
	request.data = payload;
	request.bytes = TEST_WRITE_BYTES;
	request.filetime = TEST_TIME;
	begin(device);
	assert(ntfs_write_mutation_execution_prepare(owner, &request, &prepared) == NTFS_OK);
	preview = ntfs_write_mutation_execution_preview(prepared);
	assert(preview->item.stat.size == TEST_GAP_BYTES + TEST_WRITE_BYTES &&
	    preview->requested_bytes == TEST_WRITE_BYTES && preview->item_exists);
	memset(payload, 0, TEST_WRITE_BYTES);
	assert(ntfs_write_mutation_execution_execute(prepared, &report) == NTFS_OK &&
	    report.completed_bytes == TEST_WRITE_BYTES);
	ntfs_write_mutation_execution_close(prepared);
	prepared = NULL;
	check_file(device, reference, wanted, TEST_GAP_BYTES + TEST_WRITE_BYTES);
	begin(device);
	request.kind = NTFS_WRITE_RESIZE_FILE;
	request.size = TEST_SHRINK_BYTES;
	request.data = NULL;
	request.bytes = 0;
	assert(ntfs_write_mutation_execution_prepare(owner, &request, &prepared) == NTFS_OK);
	memcpy(before, device->visible, device->bytes);
	unclaims = device->unclaims;
	ntfs_overwrite_close(owner);
	assert(device->claimed && device->unclaims == unclaims);
	assert(ntfs_write_mutation_execution_execute(prepared, &report) == NTFS_STALE &&
	    device->writes == 0 && device->barriers == 0);
	ntfs_write_mutation_execution_close(prepared);
	assert(!device->claimed && device->live == 0 && device->unclaims == unclaims + 1 &&
	    memcmp(before, device->visible, device->bytes) == 0);
	free(wanted);
	free(payload);
	free(before);
	free(admission);
	puts("PASS: complete pre-write metadata, abandoned preparation, fallible preparation "
	     "atomicity, borrowed-input independence, one-shot execution and deferred claim "
	     "release");
}

static void
creation_times(struct test_device *device)
{
	static const uint32_t fields[] = {NTFS_WRITE_CREATION_ALL_TIMES,
	    NTFS_WRITE_CREATION_CREATED, NTFS_WRITE_CREATION_MODIFIED, NTFS_WRITE_CREATION_CHANGED,
	    NTFS_WRITE_CREATION_ACCESSED, 0};
	static const struct ntfs_time expected[] = {
	    {-1, 123456700}, {0, 100}, {1791241090, 661343100}, {-11644473600, 0}};
	static const struct ntfs_time default_time = {1791241090, 661343100};
	static const uint64_t ticks[] = {TEST_CREATED_TIME, TEST_MODIFIED_TIME, TEST_TIME, 0};
	static const uint32_t time_fields[] = {NTFS_WRITE_CREATION_CREATED,
	    NTFS_WRITE_CREATION_MODIFIED, NTFS_WRITE_CREATION_CHANGED,
	    NTFS_WRITE_CREATION_ACCESSED};
	static const size_t filename_fields[] = {offsetof(struct ntfs_disk_filename, created),
	    offsetof(struct ntfs_disk_filename, modified),
	    offsetof(struct ntfs_disk_filename, changed),
	    offsetof(struct ntfs_disk_filename, accessed)};
	struct ntfs_overwrite_environment backend = environment(device);
	struct ntfs_overwrite_admission *admission;
	struct ntfs_write_recovery_report recovered;
	struct ntfs_write_mutation_execution *prepared = NULL;
	struct ntfs_write_mutation_report report;
	struct ntfs_write_mutation_request request = {0}, invalid;
	struct ntfs_overwrite *owner = NULL;
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *node = NULL;
	struct ntfs_attr_view attribute;
	const struct ntfs_write_mutation_preview *preview;
	const struct ntfs_time *wanted;
	struct ntfs_time actual[4];
	struct ntfs_stat metadata;
	uint16_t name[] = {'t', 'i', 'm', 'e', '-', 'a'};
	const uint8_t *value;
	uint8_t *before;
	uint64_t reference;
	size_t bytes, kind, profile, index, live;

	admission = malloc(sizeof(*admission));
	before = malloc(device->bytes);
	assert(admission != NULL && before != NULL);
	request.source =
	    (struct ntfs_write_name){root_reference(device), name, sizeof(name) / sizeof(*name)};
	request.filetime = TEST_TIME;
	request.creation_times = (struct ntfs_write_creation_times){
	    TEST_CREATED_TIME, TEST_MODIFIED_TIME, TEST_TIME, 0, NTFS_WRITE_CREATION_ALL_TIMES};
	begin(device);
	assert(ntfs_write_mutation_owner_open(&backend, admission, &recovered, &owner) == NTFS_OK);
	live = device->live;
	memcpy(before, device->visible, device->bytes);
	for (index = 0; index < sizeof(time_fields) / sizeof(*time_fields) + 2; index++) {
		invalid = request;
		if (index == 0) {
			invalid.creation_times.created = (uint64_t)INT64_MAX + 1;
		} else if (index == 1) {
			invalid.creation_times.modified = (uint64_t)INT64_MAX + 1;
		} else if (index == 2) {
			invalid.creation_times.changed = (uint64_t)INT64_MAX + 1;
		} else if (index == 3) {
			invalid.creation_times.accessed = (uint64_t)INT64_MAX + 1;
		} else if (index == 4) {
			invalid.creation_times.fields = NTFS_WRITE_CREATION_ALL_TIMES << 1;
		} else {
			invalid.kind = NTFS_WRITE_REMOVE_FILE;
		}
		begin(device);
		assert(ntfs_write_mutation_execution_prepare(owner, &invalid, &prepared) ==
			NTFS_INVALID &&
		    prepared == NULL && device->reads == 0 && device->allocations == 0 &&
		    device->writes == 0 && device->barriers == 0 && device->live == live &&
		    memcmp(before, device->visible, device->bytes) == 0);
	}
	for (kind = 0; kind < 2; kind++) {
		request.kind = kind == 0 ? NTFS_WRITE_CREATE_FILE : NTFS_WRITE_CREATE_DIRECTORY;
		for (profile = 0; profile < sizeof(fields) / sizeof(*fields); profile++) {
			name[sizeof(name) / sizeof(*name) - 1]++;
			request.creation_times.fields = fields[profile];
			begin(device);
			assert(ntfs_write_mutation_execution_prepare(owner, &request, &prepared) ==
			    NTFS_OK);
			preview = ntfs_write_mutation_execution_preview(prepared);
			reference = preview->item.stat.reference;
			actual[0] = preview->item.stat.created;
			actual[1] = preview->item.stat.modified;
			actual[2] = preview->item.stat.changed;
			actual[3] = preview->item.stat.accessed;
			for (index = 0; index < sizeof(time_fields) / sizeof(*time_fields);
			    index++) {
				wanted = (fields[profile] & time_fields[index]) != 0
				    ? &expected[index]
				    : &default_time;
				assert(actual[index].seconds == wanted->seconds &&
				    actual[index].nanoseconds == wanted->nanoseconds);
			}
			assert(device->writes == 0 && device->barriers == 0);
			assert(
			    ntfs_write_mutation_execution_execute(prepared, &report) == NTFS_OK &&
			    report.reference == reference);
			ntfs_write_mutation_execution_close(prepared);
			prepared = NULL;
			device->executing = false;
			assert(ntfs_mount(&backend.reader, NULL, &volume) == NTFS_OK &&
			    ntfs_node_open(volume, reference, &node) == NTFS_OK);
			assert(ntfs_node_stat(node, &metadata) == NTFS_OK);
			actual[0] = metadata.created;
			actual[1] = metadata.modified;
			actual[2] = metadata.changed;
			actual[3] = metadata.accessed;
			for (index = 0; index < sizeof(time_fields) / sizeof(*time_fields);
			    index++) {
				wanted = (fields[profile] & time_fields[index]) != 0
				    ? &expected[index]
				    : &default_time;
				assert(actual[index].seconds == wanted->seconds &&
				    actual[index].nanoseconds == wanted->nanoseconds);
			}
			assert(ntfs_attr_find(node->record, NTFS_WRITE_RECORD_BYTES,
				   NTFS_ATTR_FILENAME, NULL, 0, UINT16_MAX, &attribute) == NTFS_OK);
			assert(ntfs_attr_value(&attribute, &value, &bytes) == NTFS_OK &&
			    bytes >= sizeof(struct ntfs_disk_filename));
			for (index = 0; index < sizeof(time_fields) / sizeof(*time_fields);
			    index++) {
				assert(ntfs_u64(value + filename_fields[index]) ==
				    ((fields[profile] & time_fields[index]) != 0 ? ticks[index]
										 : TEST_TIME));
			}
			ntfs_node_close(node);
			node = NULL;
			assert(ntfs_unmount(volume) == NTFS_OK);
			volume = NULL;
			assert(device->live == live &&
			    memcmp(device->visible, device->durable, device->bytes) == 0);
		}
	}
	ntfs_overwrite_close(owner);
	assert(!device->claimed && device->live == 0);
	free(before);
	free(admission);
	puts("PASS: independent creation times, partial/default fields, exact filename caches and "
	     "pre-I/O invalid-request refusal");
}

static void
history_padding_name(size_t index, uint16_t *name)
{
	name[0] = 'p';
	name[1] = (uint16_t)('a' + index / TEST_NAME_ALPHABET);
	name[2] = (uint16_t)('a' + index % TEST_NAME_ALPHABET);
}

static void
history_padding_check(struct test_device *device, uint64_t parent, const uint64_t *references)
{
	struct ntfs_environment reader = environment(device).reader;
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *directory = NULL, *node = NULL;
	struct ntfs_stat metadata;
	uint16_t name[TEST_HISTORY_NAME_UNITS];
	size_t index;

	assert(ntfs_mount(&reader, NULL, &volume) == NTFS_OK);
	assert(ntfs_node_open(volume, parent, &directory) == NTFS_OK);
	for (index = 0; index < TEST_HISTORY_PADDING_FILES; index++) {
		history_padding_name(index, name);
		assert(ntfs_lookup(directory, name, TEST_HISTORY_NAME_UNITS, &node) == NTFS_OK);
		assert(ntfs_node_stat(node, &metadata) == NTFS_OK);
		assert(metadata.reference == references[index] && metadata.size == 0 &&
		    metadata.links == 1 && !metadata.directory);
		ntfs_node_close(node);
		node = NULL;
	}
	ntfs_node_close(directory);
	assert(ntfs_unmount(volume) == NTFS_OK);
}

static void
history_budget(struct test_device *device)
{
	static const uint16_t units[] = {'r', 'e', 'u', 's', 'e'};
	struct ntfs_overwrite_environment backend = environment(device);
	struct ntfs_overwrite_admission *admission;
	struct ntfs_validation_report *validation;
	struct ntfs_write_recovery_report recovered;
	struct ntfs_write_mutation_report report;
	struct ntfs_write_mutation_request request = {0};
	struct ntfs_write_mutation_plan *plan = NULL;
	struct ntfs_write_mutation_region region;
	struct ntfs_write_mutation_execution *prepared = NULL;
	struct ntfs_write_batch_history history;
	struct ntfs_logfile_lsn floor, next;
	struct ntfs_overwrite *owner = NULL;
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *node = NULL;
	uint64_t references[TEST_HISTORY_PADDING_FILES], parent, previous = 0, reference;
	uint16_t name[TEST_HISTORY_NAME_UNITS];
	uint8_t *before;
	size_t index, part, operation, checkpoints = 0, live;
	bool checkpoint_faults = false;
	enum ntfs_result result;

	admission = malloc(sizeof(*admission));
	validation = malloc(sizeof(*validation));
	before = malloc(device->bytes);
	assert(admission != NULL && validation != NULL && before != NULL);
	parent = root_reference(device);
	request.kind = NTFS_WRITE_CREATE_FILE;
	request.filetime = TEST_TIME;
	request.source = (struct ntfs_write_name){parent, name, TEST_HISTORY_NAME_UNITS};
	/* Prepare an immutable larger predecessor without adding test transactions.
	 * The retained-history exercise below uses only actual owning executions. */
	for (index = 0; index < TEST_HISTORY_PADDING_FILES; index++) {
		history_padding_name(index, name);
		assert(ntfs_write_mutation_prepare(&backend.reader, &request, &plan) == NTFS_OK);
		references[index] = ntfs_write_mutation_plan_reference(plan);
		for (part = 0; part < ntfs_write_mutation_plan_count(plan); part++) {
			assert(ntfs_write_mutation_plan_region(plan, part, &region) == NTFS_OK);
			memcpy(device->visible + region.physical, region.after, region.bytes);
		}
		ntfs_write_mutation_plan_close(plan);
		plan = NULL;
	}
	memcpy(device->durable, device->visible, device->bytes);
	assert(device->live == 0 &&
	    ntfs_validate(&backend.reader, NULL, NULL, validation) == NTFS_OK &&
	    validation->complete && validation->base_records >= TEST_HISTORY_PADDING_FILES);
	history_padding_check(device, parent, references);
	begin(device);
	assert(ntfs_write_mutation_owner_open(&backend, admission, &recovered, &owner) == NTFS_OK);
	assert(recovered.completed && recovered.writes == 0);
	live = device->live;
	request.source = (struct ntfs_write_name){parent, units, sizeof(units) / sizeof(*units)};
	for (index = 0; index < TEST_HISTORY_CYCLES; index++) {
		for (operation = 0; operation < 2; operation++) {
			request.kind =
			    operation == 0 ? NTFS_WRITE_CREATE_FILE : NTFS_WRITE_REMOVE_FILE;
			begin(device);
			memcpy(before, device->visible, device->bytes);
			result = ntfs_write_mutation_execution_prepare(owner, &request, &prepared);
			if (result != NTFS_OK) {
				fprintf(stderr, "history cycle %zu operation %zu: %s\n", index,
				    operation, ntfs_result_string(result));
			}
			assert(result == NTFS_OK && prepared != NULL);
			assert(device->writes == 0 && device->barriers == 0 &&
			    memcmp(before, device->visible, device->bytes) == 0);
			if (ntfs_write_mutation_execution_preview(prepared)->checkpoint_required &&
			    !checkpoint_faults) {
				ntfs_write_mutation_execution_close(prepared);
				prepared = NULL;
				assert(ntfs_write_batch_history_prepare(
					   &backend.reader, &history) == NTFS_OK);
				assert(history.origin.file_bytes == TEST_HISTORY_JOURNAL_BYTES);
				assert(ntfs_logfile_lsn_decode(&history.origin,
					   history.client.oldest_lsn, &floor) == NTFS_OK &&
				    ntfs_logfile_lsn_decode(&history.origin,
					history.history.next_lsn, &next) == NTFS_OK);
				/* The first checkpoint must reserve recovery resources while the
				 * physical ring still has ample ordinary/undo/checkpoint space. */
				assert(next.sequence == floor.sequence &&
				    next.page_offset >= floor.page_offset &&
				    history.origin.file_bytes - next.page_offset +
					    floor.page_offset >
					TEST_HISTORY_MIN_FREE_PAGES * NTFS_WRITE_CLUSTER_BYTES);
				checkpoint_preparation_failures(
				    device, owner, &request, &checkpoint_faults);
				assert(checkpoint_faults);
				begin(device);
				assert(ntfs_write_mutation_execution_prepare(
					   owner, &request, &prepared) == NTFS_OK);
			}
			reference =
			    ntfs_write_mutation_execution_preview(prepared)->item.stat.reference;
			assert(ntfs_write_mutation_execution_execute(prepared, &report) == NTFS_OK);
			checkpoints += report.checkpointed;
			ntfs_write_mutation_execution_close(prepared);
			prepared = NULL;
			assert(report.execution.completed && device->live == live &&
			    memcmp(device->visible, device->durable, device->bytes) == 0);
			if (operation == 0) {
				begin(device);
				check_file(device, reference, before, 0);
				if (previous != 0) {
					assert(
					    ntfs_mount(&backend.reader, NULL, &volume) == NTFS_OK);
					result = ntfs_node_open(volume, previous, &node);
					assert(result == NTFS_STALE && node == NULL);
					assert(ntfs_unmount(volume) == NTFS_OK);
					volume = NULL;
				}
				previous = reference;
			}
		}
		if ((index + 1) % TEST_HISTORY_REOPEN_INTERVAL == 0) {
			ntfs_overwrite_close(owner);
			owner = NULL;
			assert(device->live == 0 && !device->claimed);
			begin(device);
			memcpy(before, device->visible, device->bytes);
			assert(ntfs_write_mutation_owner_open(
				   &backend, admission, &recovered, &owner) == NTFS_OK);
			assert(recovered.completed && recovered.writes == 0 &&
			    memcmp(before, device->visible, device->bytes) == 0);
			begin(device);
			history_padding_check(device, parent, references);
		}
	}
	assert(checkpoints > 1 && checkpoint_faults);
	ntfs_overwrite_close(owner);
	assert(device->live == 0 && !device->claimed);
	begin(device);
	assert(ntfs_validate(&backend.reader, NULL, NULL, validation) == NTFS_OK &&
	    validation->complete);
	history_padding_check(device, parent, references);
	free(before);
	free(validation);
	free(admission);
	printf("PASS: %u retained-history create/remove cycles, %zu resource checkpoints, "
	       "zero-rewrite fresh owners, unchanged padding identities, stale generations "
	       "and pre-transfer checkpoint faults\n",
	    TEST_HISTORY_CYCLES, checkpoints);
}

static void
sequence(struct test_device *device)
{
	static const uint16_t directory_units[] = {'o', 'w', 'n', 'e', 'r', '-', 'd', 'i', 'r'};
	static const uint16_t source_units[] = {'o', 'w', 'n', 'e', 'r', '-', 'f', 'i', 'l', 'e'};
	static const uint16_t destination_units[] = {
	    'o', 'w', 'n', 'e', 'r', '-', 'm', 'o', 'v', 'e', 'd'};
	struct ntfs_overwrite_environment backend = environment(device);
	struct ntfs_overwrite_admission *admission;
	struct ntfs_write_recovery_report recovered;
	struct ntfs_write_mutation_report report;
	struct ntfs_overwrite *owner = NULL, *other = NULL;
	struct ntfs_write_name directory, source, destination;
	struct ntfs_write_mutation_request request = {0};
	uint8_t *payload, *wanted, *before;
	uint64_t file, parent, previous;
	size_t index, checkpoints = 0, live, unclaims = device->unclaims;
	enum ntfs_result previous_result;
	bool checkpoint_faults = false;

	admission = malloc(sizeof(*admission));
	payload = malloc(TEST_WRITE_BYTES);
	wanted = calloc(1, TEST_GAP_BYTES + TEST_WRITE_BYTES);
	before = malloc(device->bytes);
	assert(admission != NULL && payload != NULL && wanted != NULL && before != NULL);
	for (index = 0; index < TEST_WRITE_BYTES; index++) {
		payload[index] = (uint8_t)(index * 37u + 11u);
	}
	memcpy(wanted + TEST_GAP_BYTES, payload, TEST_WRITE_BYTES);
	directory = (struct ntfs_write_name){root_reference(device), directory_units,
	    sizeof(directory_units) / sizeof(*directory_units)};
	begin(device);
	assert(ntfs_write_mutation_owner_open(&backend, admission, &recovered, &owner) == NTFS_OK);
	assert(owner != NULL && admission->claimed && admission->quiescent &&
	    admission->validation.complete && recovered.completed);
	live = device->live;
	begin(device);
	assert(
	    ntfs_write_mutation_owner_open(&backend, admission, &recovered, &other) == NTFS_BUSY);
	assert(
	    other == NULL && device->live == live && device->writes == 0 && device->barriers == 0);
	assert(ntfs_write_create_directory(owner, &directory, TEST_TIME, &report) == NTFS_OK);
	parent = report.reference;
	assert((parent & NTFS_REFERENCE_RECORD_MASK) >= TEST_FIRST_ORDINARY_RECORD);
	source = (struct ntfs_write_name){
	    parent, source_units, sizeof(source_units) / sizeof(*source_units)};
	destination = (struct ntfs_write_name){directory.parent_reference, destination_units,
	    sizeof(destination_units) / sizeof(*destination_units)};
	begin(device);
	assert(ntfs_write_create_file(owner, &source, TEST_TIME, &report) == NTFS_OK);
	file = report.reference;
	assert(report.execution.completed && report.initial_persistence_succeeded &&
	    device->live == live);
	begin(device);
	assert(ntfs_write_growing_range(owner, file, TEST_GAP_BYTES, payload, TEST_WRITE_BYTES,
		   TEST_TIME, &report) == NTFS_OK &&
	    report.completed_bytes == TEST_WRITE_BYTES);
	check_file(device, file, wanted, TEST_GAP_BYTES + TEST_WRITE_BYTES);
	begin(device);
	assert(
	    ntfs_write_resize_file(owner, file, TEST_SHRINK_BYTES, TEST_TIME, &report) == NTFS_OK);
	check_file(device, file, wanted, TEST_SHRINK_BYTES);
	memset(wanted, 0, TEST_GAP_BYTES + TEST_WRITE_BYTES);
	begin(device);
	assert(ntfs_write_resize_file(
		   owner, file, TEST_GAP_BYTES + TEST_WRITE_BYTES, TEST_TIME, &report) == NTFS_OK);
	check_file(device, file, wanted, TEST_GAP_BYTES + TEST_WRITE_BYTES);
	begin(device);
	memcpy(before, device->visible, device->bytes);
	assert(
	    ntfs_write_remove_directory(owner, &directory, TEST_TIME, &report) == NTFS_NOT_EMPTY);
	assert(device->writes == 0 && device->barriers == 0 &&
	    memcmp(before, device->visible, device->bytes) == 0);
	assert(
	    ntfs_write_rename(owner, &source, &destination, false, TEST_TIME, &report) == NTFS_OK);
	assert(report.reference == file);
	begin(device);
	assert(ntfs_write_remove_directory(owner, &directory, TEST_TIME, &report) == NTFS_OK);
	previous = file;
	request.source = destination;
	request.filetime = TEST_TIME;
	for (index = 0; index < TEST_RING_CYCLES; index++) {
		request.kind = NTFS_WRITE_REMOVE_FILE;
		checkpoint_preparation_failures(device, owner, &request, &checkpoint_faults);
		begin(device);
		assert(ntfs_write_remove_file(owner, &destination, TEST_TIME, &report) == NTFS_OK);
		checkpoints += report.checkpointed;
		request.kind = NTFS_WRITE_CREATE_FILE;
		checkpoint_preparation_failures(device, owner, &request, &checkpoint_faults);
		begin(device);
		assert(ntfs_write_create_file(owner, &destination, TEST_TIME, &report) == NTFS_OK);
		checkpoints += report.checkpointed;
		file = report.reference;
		previous_result =
		    (file & NTFS_REFERENCE_RECORD_MASK) == (previous & NTFS_REFERENCE_RECORD_MASK)
		    ? NTFS_STALE
		    : NTFS_NOT_FOUND;
		assert((file & NTFS_REFERENCE_RECORD_MASK) >= TEST_FIRST_ORDINARY_RECORD &&
		    file != previous);
		begin(device);
		memcpy(before, device->visible, device->bytes);
		assert(ntfs_write_resize_file(owner, previous, TEST_SHRINK_BYTES, TEST_TIME,
			   &report) == previous_result);
		assert(device->writes == 0 && device->barriers == 0 &&
		    memcmp(before, device->visible, device->bytes) == 0);
		previous = file;
	}
	assert(checkpoints >= 3 && device->live == live && checkpoint_faults);
	begin(device);
	device->fail_barrier = 1;
	memcpy(before, device->visible, device->bytes);
	assert(ntfs_write_growing_range(
		   owner, file, 0, payload, TEST_WRITE_BYTES, TEST_TIME, &report) == NTFS_IO);
	assert(report.execution.poisoned && device->writes == 0 &&
	    memcmp(before, device->visible, device->bytes) == 0);
	begin(device);
	assert(
	    ntfs_write_resize_file(owner, file, TEST_SHRINK_BYTES, TEST_TIME, &report) == NTFS_IO);
	assert(report.execution.poisoned && device->reads == 0 && device->allocations == 0 &&
	    device->writes == 0 && device->barriers == 0);
	ntfs_overwrite_close(owner);
	assert(!device->claimed && device->live == 0 && device->unclaims == unclaims + 1);
	free(before);
	free(wanted);
	free(payload);
	free(admission);
	printf("PASS: exclusive general owner; all mutation kinds, durable gap/shrink/regrow, "
	       "stale generation, nonempty refusal, %zu automatic checkpoints, initial-barrier "
	       "poison\n",
	    checkpoints);
}

int
main(int argc, char **argv)
{
	struct test_device device = {0};
	uint8_t *original;
	char path[TEST_PATH_BYTES];
	FILE *source;
	long bytes;
	int count;

	assert(argc == 2 || (argc == 3 && strcmp(argv[2], "history-budget") == 0));
	count = snprintf(
	    path, sizeof(path), "%s/%s", argv[1], argc == 3 ? "history-source.img" : "source.img");
	assert(count > 0 && (size_t)count < sizeof(path));
	source = fopen(path, "rb");
	assert(source != NULL && fseek(source, 0, SEEK_END) == 0);
	bytes = ftell(source);
	assert(bytes > 0 && fseek(source, 0, SEEK_SET) == 0);
	device.bytes = (size_t)bytes;
	device.visible = malloc(device.bytes);
	device.durable = malloc(device.bytes);
	assert(device.visible != NULL && device.durable != NULL);
	assert(
	    fread(device.visible, 1, device.bytes, source) == device.bytes && fclose(source) == 0);
	memcpy(device.durable, device.visible, device.bytes);
	original = malloc(device.bytes);
	assert(original != NULL);
	memcpy(original, device.visible, device.bytes);
	if (argc == 3) {
		history_budget(&device);
		free(original);
		free(device.durable);
		free(device.visible);
		return 0;
	}
	creation_times(&device);
	begin(&device);
	memcpy(device.visible, original, device.bytes);
	memcpy(device.durable, original, device.bytes);
	sequence(&device);
	begin(&device);
	memcpy(device.visible, original, device.bytes);
	memcpy(device.durable, original, device.bytes);
	prepared_contract(&device);
	begin(&device);
	memcpy(device.visible, original, device.bytes);
	memcpy(device.durable, original, device.bytes);
	partial_write_reopen(&device);
	free(original);
	free(device.durable);
	free(device.visible);
	return 0;
}
