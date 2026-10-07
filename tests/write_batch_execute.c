/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_batch_execute.h"
#include "../adapters/posix/overwrite_image.h"
#include <ntfs/record.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum {
	TEST_PATH_BYTES = 4096,
	TEST_GROW_BYTES = 65537,
	TEST_WRITE_OFFSET = 257,
	TEST_PATTERN = 0xb3,
	TEST_FAULT_MODES = 6,
	TEST_SHRINK_BYTES = 19,
	TEST_PRESSURE_LIMIT = 128,
	TEST_SEED_NAME_UNITS = 255,
	TEST_ALPHABET_LETTERS = 26,
	TEST_JOURNAL_READ_CALLS = 8192,
	TEST_JOURNAL_READ_BYTES = 16 * 1024 * 1024,
	TEST_INDEX_TARGET_FLAG = 8,
	TEST_FILE_SLOTS = NTFS_WRITE_CLUSTER_BYTES / NTFS_WRITE_RECORD_BYTES
};

#define TEST_TIME UINT64_C(134357146906613431)
#define TEST_FILE (UINT64_C(7) << NTFS_REFERENCE_SEQUENCE_SHIFT | UINT64_C(25))
#define TEST_RESIDENT_FILE (UINT64_C(7) << NTFS_REFERENCE_SEQUENCE_SHIFT | UINT64_C(24))

enum test_profile {
	TEST_DEFAULT,
	TEST_SHRINK,
	TEST_RESIDENT_GROWTH,
	TEST_EMPTY_DIRECTORY,
	TEST_MFT_GROWTH,
	TEST_PAGE_ALIGNMENT
};

union allocation {
	max_align_t alignment;
	size_t bytes;
};

struct device {
	uint8_t *visible, *durable;
	size_t bytes, live, allocations, reads, writes, barriers;
	uint32_t alignment;
	size_t fail_allocation, fail_read, fail_write, fail_barrier, failure_bytes;
	const struct ntfs_write_batch_execution *expected;
	bool executing, overreport, short_success, persist_on_failure;
};

struct test_case {
	struct device device;
	struct ntfs_overwrite_environment backend;
	struct ntfs_write_mutation_plan *plan;
	struct ntfs_write_program *program;
	uint8_t *before, *after;
	uint8_t *expected_file;
	uint64_t file_reference;
	size_t expected_file_bytes;
	struct ntfs_write_mutation_region *region;
	size_t regions;
};

struct journal_step {
	uint8_t *payload;
	size_t bytes, region;
	uint16_t flags;
};

struct journal_oracle {
	struct ntfs_logfile_restart restart;
	struct ntfs_logfile_client client;
	struct ntfs_logfile_history_report original;
	struct journal_step *step;
	struct ntfs_write_mutation_target *target;
	struct ntfs_write_mutation_region *region;
	uint64_t *home_lsn;
	uint64_t first_lsn, previous_lsn, transaction_lsn;
	size_t regions, targets, steps, records, observed;
};

static void *
allocate(void *context, size_t bytes)
{
	struct device *device = context;
	union allocation *memory;

	assert(!device->executing && bytes != 0);
	device->allocations++;
	if (device->allocations == device->fail_allocation ||
	    bytes > NTFS_DEFAULT_MAX_LIVE_BYTES - device->live) {
		return NULL;
	}
	memory = calloc(1, sizeof(*memory) + bytes);
	assert(memory != NULL);
	memory->bytes = bytes;
	device->live += bytes;
	return memory + 1;
}

static void
release(void *context, void *pointer, size_t bytes)
{
	struct device *device = context;
	union allocation *memory;

	assert(pointer != NULL);
	memory = (union allocation *)pointer - 1;
	assert(memory->bytes == bytes && device->live >= bytes);
	device->live -= bytes;
	free(memory);
}

static enum ntfs_result
read_image(void *context, uint64_t physical, void *out, size_t bytes)
{
	struct device *device = context;

	assert(!device->executing && ntfs_bounds(physical, bytes, device->bytes));
	device->reads++;
	if (device->reads == device->fail_read) {
		memcpy(out, device->visible + physical, bytes / 2);
		return NTFS_IO;
	}
	memcpy(out, device->visible + physical, bytes);
	return NTFS_OK;
}

static enum ntfs_result
write_image(void *context, uint64_t physical, const void *data, size_t bytes, size_t *actual)
{
	struct device *device = context;
	const struct ntfs_write_batch_publication *expected;
	size_t count;

	assert(device->executing && bytes == NTFS_WRITE_CLUSTER_BYTES &&
	    physical % device->alignment == 0 && (uintptr_t)data % device->alignment == 0 &&
	    ntfs_bounds(physical, bytes, device->bytes));
	expected = ntfs_write_batch_execution_get(device->expected, device->writes);
	assert(expected != NULL && expected->physical == physical &&
	    memcmp(expected->image, data, bytes) == 0);
	device->writes++;
	if (device->writes == device->fail_write) {
		count = device->failure_bytes;
		assert(count <= bytes);
		memcpy(device->visible + physical, data, count);
		*actual = device->overreport ? bytes + 1 : count;
		return device->overreport || device->short_success ? NTFS_OK : NTFS_IO;
	}
	memcpy(device->visible + physical, data, bytes);
	*actual = bytes;
	return NTFS_OK;
}

static enum ntfs_result
persist_image(void *context)
{
	struct device *device = context;

	assert(device->executing);
	device->barriers++;
	if (device->barriers == device->fail_barrier) {
		if (device->persist_on_failure) {
			memcpy(device->durable, device->visible, device->bytes);
		}
		return NTFS_IO;
	}
	memcpy(device->durable, device->visible, device->bytes);
	return NTFS_OK;
}

static void
validate(struct test_case *test)
{
	struct ntfs_validation_report *report;

	report = calloc(1, sizeof(*report));
	assert(report != NULL);
	assert(ntfs_validate(&test->backend.reader, NULL, NULL, report) == NTFS_OK &&
	    report->complete);
	free(report);
}

static void
seed_source(struct test_case *test, struct ntfs_write_mutation_plan *plan)
{
	struct ntfs_write_mutation_region region;
	size_t index;

	/* Construct a test predecessor privately. The original quiet journal is
	 * retained; this does not exercise consecutive physical transactions. */
	for (index = 0; index < ntfs_write_mutation_plan_count(plan); index++) {
		assert(ntfs_write_mutation_plan_region(plan, index, &region) == NTFS_OK);
		memcpy(test->device.visible + region.physical, region.after, region.bytes);
	}
	memcpy(test->device.durable, test->device.visible, test->device.bytes);
	ntfs_write_mutation_plan_close(plan);
}

static struct ntfs_write_mutation_plan *
growth_predecessor(struct test_case *test, uint64_t parent)
{
	struct ntfs_write_mutation_plan *plan = NULL;
	struct ntfs_write_mutation_request request = {0};
	struct ntfs_volume *volume = NULL;
	struct ntfs_environment projected;
	uint16_t name[TEST_SEED_NAME_UNITS];
	uint64_t original_initialized;
	size_t index, unit;
	bool initialized_growth;

	assert(ntfs_mount(&test->backend.reader, NULL, &volume) == NTFS_OK);
	original_initialized = volume->mft->initialized;
	assert(ntfs_unmount(volume) == NTFS_OK);
	volume = NULL;
	request.kind = NTFS_WRITE_CREATE_FILE;
	request.filetime = TEST_TIME;
	request.source = (struct ntfs_write_name){parent, name, TEST_SEED_NAME_UNITS};
	for (index = 0; index < TEST_PRESSURE_LIMIT; index++) {
		for (unit = 0; unit < TEST_SEED_NAME_UNITS; unit++) {
			name[unit] = 'n';
		}
		/* Long independent names force index growth as well as new FILEs. */
		name[0] = 'a' + (uint16_t)(index / TEST_ALPHABET_LETTERS);
		name[1] = 'a' + (uint16_t)(index % TEST_ALPHABET_LETTERS);
		assert(
		    ntfs_write_mutation_prepare(&test->backend.reader, &request, &plan) == NTFS_OK);
		assert(ntfs_write_mutation_plan_view(plan, &projected) == NTFS_OK);
		assert(ntfs_mount(&projected, NULL, &volume) == NTFS_OK);
		initialized_growth = volume->mft->initialized > original_initialized;
		assert(ntfs_unmount(volume) == NTFS_OK);
		volume = NULL;
		if (initialized_growth) {
			validate(test);
			printf("PASS: prepared MFT initialization growth after %zu predecessor "
			       "files\n",
			    index);
			return plan;
		}
		seed_source(test, plan);
		plan = NULL;
	}
	assert(false);
	return NULL;
}

static struct test_case *
prepare_profile(const char *directory, const char *image, enum ntfs_write_mutation_kind kind,
    enum test_profile profile)
{
	struct test_case *test;
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *root = NULL;
	struct ntfs_node *file_node = NULL;
	struct ntfs_stream *file_stream = NULL;
	struct ntfs_stat metadata;
	struct ntfs_write_mutation_request request = {0};
	struct ntfs_environment projected;
	struct ntfs_validation_report *validation;
	struct ntfs_write_mutation_plan *seed = NULL;
	uint16_t name[] = {'b', 'a', 't', 'c', 'h', '-', 'f', 'i', 'l', 'e'};
	uint16_t original[] = {
	    'f', 'r', 'a', 'g', 'm', 'e', 'n', 't', 'e', 'd', '.', 'b', 'i', 'n'};
	uint8_t *payload;
	uint8_t *original_file = NULL;
	char *path;
	FILE *file;
	long bytes;
	size_t index, original_bytes, actual, copied;
	int count;

	test = calloc(1, sizeof(*test));
	path = malloc(TEST_PATH_BYTES);
	assert(test != NULL && path != NULL);
	count = snprintf(path, TEST_PATH_BYTES, "%s/%s", directory, image);
	assert(count > 0 && count < TEST_PATH_BYTES);
	file = fopen(path, "rb");
	free(path);
	assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
	bytes = ftell(file);
	assert(bytes > 0 && fseek(file, 0, SEEK_SET) == 0);
	test->device.bytes = (size_t)bytes;
	test->device.visible = malloc((size_t)bytes);
	test->device.durable = malloc((size_t)bytes);
	test->before = malloc((size_t)bytes);
	test->after = malloc((size_t)bytes);
	assert(test->device.visible != NULL && test->device.durable != NULL &&
	    test->before != NULL && test->after != NULL);
	assert(fread(test->before, 1, (size_t)bytes, file) == (size_t)bytes && fclose(file) == 0);
	memcpy(test->device.visible, test->before, (size_t)bytes);
	memcpy(test->device.durable, test->before, (size_t)bytes);
	memcpy(test->after, test->before, (size_t)bytes);
	test->backend =
	    (struct ntfs_overwrite_environment){.reader = {NTFS_API_VERSION, &test->device,
						    (size_t)bytes, read_image, allocate, release},
		.api_version = NTFS_OVERWRITE_API_VERSION,
		.alignment = NTFS_WRITE_SECTOR_BYTES,
		.write = write_image,
		.persist = persist_image};
	test->device.alignment =
	    profile == TEST_PAGE_ALIGNMENT ? NTFS_WRITE_CLUSTER_BYTES : NTFS_WRITE_SECTOR_BYTES;
	test->backend.alignment = test->device.alignment;
	assert(ntfs_mount(&test->backend.reader, NULL, &volume) == NTFS_OK);
	assert(ntfs_root(volume, &root) == NTFS_OK && ntfs_node_stat(root, &metadata) == NTFS_OK);
	request.kind = kind;
	request.filetime = TEST_TIME;
	request.source =
	    (struct ntfs_write_name){metadata.reference, name, sizeof(name) / sizeof(name[0])};
	request.destination = request.source;
	if (kind == NTFS_WRITE_REMOVE_FILE || kind == NTFS_WRITE_RENAME) {
		request.source.units = original;
		request.source.count = sizeof(original) / sizeof(original[0]);
	}
	request.reference = TEST_FILE;
	request.size = TEST_GROW_BYTES;
	payload = malloc(TEST_GROW_BYTES);
	assert(payload != NULL);
	memset(payload, TEST_PATTERN, TEST_GROW_BYTES);
	request.offset = TEST_WRITE_OFFSET;
	if (kind == NTFS_WRITE_GROWING_RANGE) {
		request.data = payload;
		request.bytes = TEST_GROW_BYTES;
	}
	ntfs_node_close(root);
	assert(ntfs_unmount(volume) == NTFS_OK);
	if (profile == TEST_SHRINK) {
		request.size = TEST_SHRINK_BYTES;
	} else if (profile == TEST_RESIDENT_GROWTH) {
		request.reference = TEST_RESIDENT_FILE;
	} else if (profile == TEST_EMPTY_DIRECTORY) {
		request.kind = NTFS_WRITE_CREATE_DIRECTORY;
		assert(
		    ntfs_write_mutation_prepare(&test->backend.reader, &request, &seed) == NTFS_OK);
		seed_source(test, seed);
		request.kind = kind;
	} else if (profile == TEST_MFT_GROWTH) {
		test->plan = growth_predecessor(test, metadata.reference);
	}
	memcpy(test->before, test->device.visible, test->device.bytes);
	memcpy(test->after, test->before, test->device.bytes);
	if (kind == NTFS_WRITE_RESIZE_FILE || kind == NTFS_WRITE_GROWING_RANGE) {
		assert(ntfs_mount(&test->backend.reader, NULL, &volume) == NTFS_OK);
		assert(ntfs_node_open(volume, request.reference, &file_node) == NTFS_OK);
		assert(ntfs_stream_open(file_node, NULL, 0, &file_stream) == NTFS_OK);
		original_bytes = (size_t)ntfs_stream_size(file_stream);
		original_file = malloc(original_bytes == 0 ? 1 : original_bytes);
		assert(original_file != NULL);
		assert(ntfs_stream_read(file_stream, 0, original_file, original_bytes, &actual) ==
			NTFS_OK &&
		    actual == original_bytes);
		test->file_reference = request.reference;
		test->expected_file_bytes = kind == NTFS_WRITE_RESIZE_FILE ? (size_t)request.size
		    : original_bytes > request.offset + request.bytes
		    ? original_bytes
		    : (size_t)(request.offset + request.bytes);
		test->expected_file =
		    calloc(test->expected_file_bytes == 0 ? 1 : test->expected_file_bytes, 1);
		assert(test->expected_file != NULL);
		copied = original_bytes < test->expected_file_bytes ? original_bytes
								    : test->expected_file_bytes;
		memcpy(test->expected_file, original_file, copied);
		if (kind == NTFS_WRITE_GROWING_RANGE) {
			memcpy(test->expected_file + request.offset, payload, request.bytes);
		}
		ntfs_stream_close(file_stream);
		ntfs_node_close(file_node);
		assert(ntfs_unmount(volume) == NTFS_OK);
		free(original_file);
	}
	if (test->plan == NULL) {
		assert(ntfs_write_mutation_prepare(&test->backend.reader, &request, &test->plan) ==
		    NTFS_OK);
	}
	free(payload);
	assert(ntfs_write_mutation_plan_view(test->plan, &projected) == NTFS_OK);
	validation = calloc(1, sizeof(*validation));
	assert(validation != NULL && ntfs_validate(&projected, NULL, NULL, validation) == NTFS_OK &&
	    validation->complete);
	free(validation);
	test->regions = ntfs_write_mutation_plan_count(test->plan);
	test->region = calloc(test->regions, sizeof(*test->region));
	assert(test->region != NULL);
	for (index = 0; index < test->regions; index++) {
		assert(ntfs_write_mutation_plan_region(test->plan, index, &test->region[index]) ==
		    NTFS_OK);
		memcpy(test->after + test->region[index].physical, test->region[index].after,
		    test->region[index].bytes);
	}
	assert(ntfs_write_program_prepare(&test->backend.reader, test->plan, &test->program) ==
	    NTFS_OK);
	return test;
}

static struct test_case *
prepare(const char *directory, const char *image, enum ntfs_write_mutation_kind kind)
{
	return prepare_profile(directory, image, kind, TEST_DEFAULT);
}

static void
finish(struct test_case *test)
{
	ntfs_write_program_close(test->program);
	ntfs_write_mutation_plan_close(test->plan);
	assert(test->device.live == 0);
	free(test->region);
	free(test->expected_file);
	free(test->after);
	free(test->before);
	free(test->device.durable);
	free(test->device.visible);
	free(test);
}

static void
requested_file_check(struct test_case *test)
{
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *node = NULL;
	struct ntfs_stream *stream = NULL;
	uint8_t *actual;
	size_t bytes;

	if (test->expected_file == NULL) {
		return;
	}
	actual = malloc(test->expected_file_bytes == 0 ? 1 : test->expected_file_bytes);
	assert(actual != NULL);
	assert(ntfs_mount(&test->backend.reader, NULL, &volume) == NTFS_OK);
	assert(ntfs_node_open(volume, test->file_reference, &node) == NTFS_OK);
	assert(ntfs_stream_open(node, NULL, 0, &stream) == NTFS_OK &&
	    ntfs_stream_size(stream) == test->expected_file_bytes);
	assert(ntfs_stream_read(stream, 0, actual, test->expected_file_bytes, &bytes) == NTFS_OK &&
	    bytes == test->expected_file_bytes && memcmp(actual, test->expected_file, bytes) == 0);
	ntfs_stream_close(stream);
	ntfs_node_close(node);
	assert(ntfs_unmount(volume) == NTFS_OK);
	free(actual);
}

static enum ntfs_result
execute(struct test_case *test, struct ntfs_write_batch_execution *owner, bool *poisoned,
    struct ntfs_write_execution_report *report)
{
	size_t allocations = test->device.allocations, reads = test->device.reads;
	enum ntfs_result result;

	test->device.expected = owner;
	test->device.executing = true;
	result = ntfs_write_batch_execute(owner, poisoned, report);
	test->device.executing = false;
	assert(test->device.allocations == allocations && test->device.reads == reads);
	return result;
}

static struct ntfs_logfile *
journal_open(struct test_case *test, struct ntfs_volume **volume)
{
	struct ntfs_logfile *log = NULL;
	struct ntfs_logfile_limits limits;
	struct ntfs_logfile_page_index_report report;

	assert(ntfs_mount(&test->backend.reader, NULL, volume) == NTFS_OK);
	ntfs_logfile_default_limits(&limits);
	limits.max_read_calls = TEST_JOURNAL_READ_CALLS;
	limits.max_read_bytes = TEST_JOURNAL_READ_BYTES;
	assert(ntfs_logfile_open_volume(*volume, &limits, NULL, &log) == NTFS_OK);
	assert(
	    ntfs_logfile_prepare_page_index(log, NTFS_DEFAULT_MAX_LIVE_BYTES, &report) == NTFS_OK);
	return log;
}

static bool
same_target(
    const struct ntfs_write_mutation_target *left, const struct ntfs_write_mutation_target *right)
{
	return left->reference == right->reference &&
	    left->attribute_type == right->attribute_type &&
	    left->name_count == right->name_count &&
	    memcmp(left->name, right->name, sizeof(left->name)) == 0;
}

static struct journal_oracle *
journal_capture(struct test_case *test)
{
	struct journal_oracle *oracle;
	struct ntfs_logfile *log;
	struct ntfs_volume *volume = NULL;
	struct ntfs_logfile_lsn successor;
	struct ntfs_write_mutation_region region;
	const struct ntfs_write_program_update *step;
	uint8_t *workspace;
	uint64_t page, sequence;
	size_t index, other;

	oracle = calloc(1, sizeof(*oracle));
	workspace = malloc(NTFS_WRITE_BATCH_MAX_PACKET_BYTES);
	assert(oracle != NULL && workspace != NULL);
	oracle->steps = ntfs_write_program_count(test->program);
	oracle->regions = test->regions;
	oracle->region = test->region;
	oracle->step = calloc(oracle->steps, sizeof(*oracle->step));
	oracle->target = calloc(oracle->regions, sizeof(*oracle->target));
	oracle->home_lsn = calloc(oracle->regions * TEST_FILE_SLOTS, sizeof(*oracle->home_lsn));
	assert(oracle->step != NULL && oracle->target != NULL && oracle->home_lsn != NULL);
	for (index = 0; index < oracle->steps; index++) {
		step = ntfs_write_program_get(test->program, index);
		assert(step != NULL);
		oracle->step[index].bytes = step->payload.bytes;
		oracle->step[index].region = step->region;
		oracle->step[index].flags = step->record_flags;
		oracle->step[index].payload = malloc(step->payload.bytes);
		assert(oracle->step[index].payload != NULL);
		memcpy(oracle->step[index].payload, step->payload.data, step->payload.bytes);
	}
	for (index = 0; index < oracle->regions; index++) {
		assert(ntfs_write_program_region(test->program, index, &region) == NTFS_OK);
		if (region.kind == NTFS_WRITE_MUTATION_DATA || region.target.mirror) {
			continue;
		}
		for (other = 0; other < oracle->targets; other++) {
			if (same_target(&region.target, &oracle->target[other])) {
				break;
			}
		}
		if (other == oracle->targets) {
			oracle->target[oracle->targets++] = region.target;
		}
	}
	log = journal_open(test, &volume);
	assert(ntfs_logfile_get_restart(log, &oracle->restart) == NTFS_OK);
	assert(ntfs_logfile_get_client(log, 0, &oracle->client) == NTFS_OK);
	assert(ntfs_logfile_visit_records(log, oracle->client.oldest_lsn,
		   NTFS_WRITE_BATCH_MAX_PACKETS, workspace, NTFS_WRITE_BATCH_MAX_PACKET_BYTES, NULL,
		   NULL, &oracle->original) == NTFS_OK);
	assert(oracle->original.complete && oracle->original.endpoint_verified &&
	    oracle->original.tail_lsn == 0);
	assert(ntfs_logfile_lsn_decode(&oracle->restart, oracle->original.next_lsn, &successor) ==
	    NTFS_OK);
	page = successor.page_offset;
	sequence = successor.sequence;
	if (successor.record_offset != oracle->restart.page_data_offset) {
		page += oracle->restart.log_page_bytes;
		if (page == oracle->restart.file_bytes) {
			page = oracle->restart.circular_offset;
			sequence++;
		}
	}
	oracle->first_lsn = (sequence << (NTFS_LFS_LSN_BITS - oracle->restart.sequence_bits)) |
	    ((page + oracle->restart.page_data_offset) >> NTFS_LFS_LSN_OFFSET_SHIFT);
	oracle->previous_lsn = oracle->original.completed_end_lsn;
	ntfs_logfile_close(log);
	assert(ntfs_unmount(volume) == NTFS_OK);
	free(workspace);
	return oracle;
}

static enum ntfs_result
journal_visit(void *context, const struct ntfs_logfile_record_view *view, const void *bytes)
{
	struct journal_oracle *oracle = context;
	const struct ntfs_logfile_record *record = &view->record;
	const uint8_t *payload = (const uint8_t *)bytes + record->data.offset;
	const struct ntfs_disk_log_open_attribute *entry;
	const struct ntfs_write_mutation_target *target;
	const struct journal_step *step;
	struct ntfs_logfile_update update;
	size_t index = oracle->records, unit, slot;
	uint16_t flags;

	oracle->observed++;
	if (record->lsn <= oracle->original.completed_end_lsn) {
		return NTFS_OK;
	}
	assert(record->type == NTFS_LOGFILE_RECORD_UPDATE && record->client_index == 0 &&
	    record->client_sequence == oracle->client.sequence);
	assert(index != 0 || record->lsn == oracle->first_lsn);
	assert(ntfs_logfile_update_decode(payload, record->data.length, &update) == NTFS_OK);
	if (index < oracle->targets) {
		target = &oracle->target[index];
		flags = target->name_count == 0 ? NTFS_LOGFILE_RECORD_ADDING : 0;
		assert(record->transaction == NTFS_WRITE_MFT_KEY && record->previous_lsn == 0 &&
		    record->undo_next_lsn == 0 && record->flags == flags);
		assert(update.redo_operation == NTFS_LOG_OP_OPEN_NONRESIDENT_ATTRIBUTE &&
		    update.undo_operation == NTFS_LOG_OP_NOOP &&
		    update.target_attribute == NTFS_WRITE_MFT_KEY + index * sizeof(*entry) &&
		    update.attribute_flags ==
			(target->attribute_type == NTFS_ATTR_INDEX_ALLOCATION
				? TEST_INDEX_TARGET_FLAG
				: target->attribute_type == NTFS_ATTRIBUTE_DATA &&
				    (target->reference & NTFS_REFERENCE_RECORD_MASK) ==
					NTFS_MFT_RECORD
				? NTFS_WRITE_MFT_TARGET_FLAG
				: 0) &&
		    update.redo.length == sizeof(*entry) &&
		    update.undo.length == target->name_count * sizeof(uint16_t));
		entry = (const void *)(payload + update.redo.offset);
		assert(ntfs_u32(entry->allocated) == NTFS_LOG_TABLE_ALLOCATED &&
		    ntfs_u32(entry->attribute_type) == target->attribute_type &&
		    ntfs_u64(entry->reference) == target->reference &&
		    ntfs_u64(entry->open_lsn) == oracle->previous_lsn &&
		    ntfs_u32(entry->index_buffer_bytes) ==
			(target->attribute_type == NTFS_ATTR_INDEX_ALLOCATION
				? NTFS_WRITE_CLUSTER_BYTES
				: 0));
		for (unit = 0; unit < target->name_count; unit++) {
			assert(ntfs_u16(payload + update.undo.offset + unit * sizeof(uint16_t)) ==
			    target->name[unit]);
		}
	} else if (index - oracle->targets < oracle->steps) {
		step = &oracle->step[index - oracle->targets];
		assert(record->transaction == NTFS_WRITE_TRANSACTION_KEY &&
		    record->previous_lsn == oracle->transaction_lsn &&
		    record->undo_next_lsn == oracle->transaction_lsn &&
		    (record->flags & ~NTFS_LOGFILE_RECORD_MULTI_PAGE) == step->flags &&
		    record->data.length == step->bytes &&
		    memcmp(payload, step->payload, step->bytes) == 0);
		if (update.redo_operation != NTFS_LOG_OP_NOOP) {
			slot = (size_t)update.cluster_index * NTFS_MST_STRIDE /
			    NTFS_WRITE_RECORD_BYTES;
			if (oracle->region[step->region].kind == NTFS_WRITE_MUTATION_FILE) {
				assert(slot < TEST_FILE_SLOTS);
				oracle->home_lsn[step->region * TEST_FILE_SLOTS + slot] =
				    record->lsn;
			} else if (oracle->region[step->region].kind == NTFS_WRITE_MUTATION_INDEX) {
				oracle->home_lsn[step->region * TEST_FILE_SLOTS] = record->lsn;
			}
		}
		oracle->transaction_lsn = record->lsn;
	} else {
		assert(index == oracle->targets + oracle->steps &&
		    record->transaction == NTFS_WRITE_TRANSACTION_KEY &&
		    record->previous_lsn == oracle->transaction_lsn && record->undo_next_lsn == 0 &&
		    record->flags == NTFS_LOGFILE_RECORD_DELETING &&
		    update.redo_operation == NTFS_LOG_OP_FORGET_TRANSACTION &&
		    update.undo_operation == NTFS_LOG_OP_COMPENSATION &&
		    update.target_attribute == 0 && update.lcn_count == 0 &&
		    update.redo.length == 0 && update.undo.length == 0);
	}
	oracle->records++;
	oracle->previous_lsn = record->lsn;
	return NTFS_OK;
}

static void
journal_check(struct test_case *test, struct journal_oracle *oracle)
{
	struct ntfs_volume *volume = NULL;
	struct ntfs_logfile *log;
	struct ntfs_logfile_restart restart;
	struct ntfs_logfile_client client;
	struct ntfs_logfile_history_report report;
	const struct ntfs_write_mutation_region *region, *primary;
	uint8_t *workspace;
	uint64_t expected_lsn;
	size_t index, slot, other;

	workspace = malloc(NTFS_WRITE_BATCH_MAX_PACKET_BYTES);
	assert(workspace != NULL);
	log = journal_open(test, &volume);
	assert(ntfs_logfile_get_restart(log, &restart) == NTFS_OK &&
	    restart.flags == NTFS_LOGFILE_RESTART_CLEAN &&
	    restart.current_lsn == oracle->restart.current_lsn);
	assert(ntfs_logfile_get_client(log, 0, &client) == NTFS_OK &&
	    memcmp(&client, &oracle->client, sizeof(client)) == 0);
	assert(ntfs_logfile_visit_records(log, client.oldest_lsn, NTFS_WRITE_BATCH_MAX_PACKETS,
		   workspace, NTFS_WRITE_BATCH_MAX_PACKET_BYTES, journal_visit, oracle,
		   &report) == NTFS_OK);
	assert(report.complete && report.endpoint_verified && report.tail_lsn == 0 &&
	    report.completed_end_lsn == oracle->previous_lsn &&
	    oracle->records == oracle->targets + oracle->steps + 1 &&
	    oracle->observed == oracle->records + oracle->original.visited_records);
	ntfs_logfile_close(log);
	assert(ntfs_unmount(volume) == NTFS_OK);
	for (index = 0; index < oracle->regions; index++) {
		region = &oracle->region[index];
		other = index;
		if (region->target.mirror) {
			for (other = 0; other < oracle->regions; other++) {
				primary = &oracle->region[other];
				if (!primary->target.mirror &&
				    primary->kind == NTFS_WRITE_MUTATION_FILE &&
				    same_target(&primary->target, &region->target) &&
				    primary->target.logical_offset ==
					region->target.logical_offset) {
					break;
				}
			}
			assert(other < oracle->regions);
		}
		for (slot = 0; slot < TEST_FILE_SLOTS; slot++) {
			expected_lsn = oracle->home_lsn[other * TEST_FILE_SLOTS + slot];
			if (expected_lsn != 0) {
				assert(ntfs_u64(test->device.visible + region->physical +
					   slot * NTFS_WRITE_RECORD_BYTES +
					   offsetof(struct ntfs_disk_record, lsn)) == expected_lsn);
			}
		}
	}
	for (index = 0; index < oracle->steps; index++) {
		free(oracle->step[index].payload);
	}
	free(oracle->home_lsn);
	free(oracle->target);
	free(oracle->step);
	free(oracle);
	free(workspace);
}

static void
frame_guard(const uint8_t *before, const uint8_t *after, size_t bytes, const char *magic)
{
	const struct ntfs_disk_mst *header = (const void *)after;
	const struct ntfs_disk_mst *old_header = (const void *)before;
	uint8_t *mixed;
	uint16_t marker, old_offset;
	size_t prefix, sector;

	mixed = malloc(bytes);
	assert(mixed != NULL);
	memcpy(mixed, after, bytes);
	assert(ntfs_fixup(mixed, bytes, magic) == NTFS_OK);
	marker = ntfs_u16(after + ntfs_u16(header->usa_offset));
	old_offset = ntfs_u16(old_header->usa_offset);
	if (old_offset >= sizeof(*old_header) && old_offset % sizeof(uint16_t) == 0 &&
	    ntfs_bounds(old_offset, sizeof(uint16_t), bytes)) {
		assert(marker != ntfs_u16(before + old_offset));
	}
	for (sector = NTFS_MST_STRIDE; sector <= bytes; sector += NTFS_MST_STRIDE) {
		assert(marker != ntfs_u16(before + sector - sizeof(uint16_t)));
	}
	for (prefix = NTFS_MST_STRIDE; prefix < bytes; prefix += NTFS_MST_STRIDE) {
		memcpy(mixed, before, prefix);
		memcpy(mixed + prefix, after + prefix, bytes - prefix);
		assert(ntfs_fixup(mixed, bytes, magic) != NTFS_OK);
		memcpy(mixed, after, prefix);
		memcpy(mixed + prefix, before + prefix, bytes - prefix);
		assert(ntfs_fixup(mixed, bytes, magic) != NTFS_OK);
	}
	free(mixed);
}

static void
restart_publication(struct test_case *test, const struct ntfs_write_batch_publication *step,
    const struct journal_oracle *oracle)
{
	struct ntfs_logfile_restart before, after;
	struct ntfs_disk_log_restart_area *area;
	const struct ntfs_disk_mst *mst;
	uint8_t *old, *image;
	size_t first, bytes;

	old = malloc(NTFS_WRITE_CLUSTER_BYTES);
	image = malloc(NTFS_WRITE_CLUSTER_BYTES);
	assert(old != NULL && image != NULL);
	assert(ntfs_logfile_restart_decode(test->before + step->physical, NTFS_WRITE_CLUSTER_BYTES,
		   oracle->restart.file_bytes, old, NTFS_WRITE_CLUSTER_BYTES, &before) == NTFS_OK);
	assert(ntfs_logfile_restart_decode(step->image, NTFS_WRITE_CLUSTER_BYTES,
		   oracle->restart.file_bytes, image, NTFS_WRITE_CLUSTER_BYTES, &after) == NTFS_OK);
	assert(after.current_lsn == before.current_lsn);
	mst = (const void *)old;
	first = ntfs_u16(mst->usa_offset);
	bytes = ntfs_u16(mst->usa_count) * sizeof(uint16_t);
	memcpy(image + first, old + first, bytes);
	area = (void *)(old + before.area.offset);
	ntfs_put_u16(area->flags,
	    step->stage == NTFS_WRITE_EXECUTION_DIRTY_FIRST ||
		    step->stage == NTFS_WRITE_EXECUTION_DIRTY_SECOND
		? 0
		: NTFS_LOGFILE_RESTART_CLEAN);
	assert(memcmp(image, old, NTFS_WRITE_CLUSTER_BYTES) == 0);
	free(image);
	free(old);
}

static void
publication_guards(struct test_case *test, const struct ntfs_write_batch_publication *step,
    const uint8_t *preceding)
{
	const struct ntfs_write_mutation_region *region;
	size_t index, slot, offset;

	if (step->stage == NTFS_WRITE_EXECUTION_DATA) {
		return;
	}
	if (step->stage == NTFS_WRITE_EXECUTION_METADATA_HOME) {
		for (index = 0; index < test->regions; index++) {
			region = &test->region[index];
			if (region->physical != step->physical) {
				continue;
			}
			if (region->kind == NTFS_WRITE_MUTATION_FILE) {
				for (slot = 0; slot < TEST_FILE_SLOTS; slot++) {
					offset = slot * NTFS_WRITE_RECORD_BYTES;
					if (memcmp(preceding + offset, step->image + offset,
						NTFS_WRITE_RECORD_BYTES) != 0) {
						frame_guard(preceding + offset,
						    step->image + offset, NTFS_WRITE_RECORD_BYTES,
						    "FILE");
					}
				}
			} else if (region->kind == NTFS_WRITE_MUTATION_INDEX) {
				frame_guard(
				    preceding, step->image, NTFS_WRITE_CLUSTER_BYTES, "INDX");
			} else {
				assert(region->kind == NTFS_WRITE_MUTATION_BITMAP);
			}
			return;
		}
		assert(false);
	}
	frame_guard(preceding, step->image, NTFS_WRITE_CLUSTER_BYTES,
	    step->stage == NTFS_WRITE_EXECUTION_DIRTY_FIRST ||
		    step->stage == NTFS_WRITE_EXECUTION_DIRTY_SECOND ||
		    step->stage == NTFS_WRITE_EXECUTION_CLEAN_FIRST ||
		    step->stage == NTFS_WRITE_EXECUTION_CLEAN_SECOND
		? "RSTR"
		: "RCRD");
}

static void
same_metadata(const struct ntfs_write_mutation_region *region, const uint8_t *before,
    const uint8_t *expected, const uint8_t *actual)
{
	uint8_t *left, *right;
	const struct ntfs_disk_mst *mst;
	size_t offset, span, first, bytes;

	left = malloc(region->bytes);
	right = malloc(region->bytes);
	assert(left != NULL && right != NULL);
	memcpy(left, expected, region->bytes);
	memcpy(right, actual, region->bytes);
	span = region->kind == NTFS_WRITE_MUTATION_FILE ? NTFS_WRITE_RECORD_BYTES : region->bytes;
	if (region->kind == NTFS_WRITE_MUTATION_FILE || region->kind == NTFS_WRITE_MUTATION_INDEX) {
		for (offset = 0; offset < region->bytes; offset += span) {
			if (memcmp(before + offset, expected + offset, span) == 0) {
				assert(memcmp(left + offset, right + offset, span) == 0);
				continue;
			}
			mst = (const void *)(left + offset);
			if (memcmp(mst->magic, "FILE", sizeof(mst->magic)) != 0 &&
			    memcmp(mst->magic, "INDX", sizeof(mst->magic)) != 0) {
				assert(memcmp(left + offset, right + offset, span) == 0);
				continue;
			}
			assert(
			    ntfs_fixup(left + offset, span, (const char *)mst->magic) == NTFS_OK);
			assert(
			    ntfs_fixup(right + offset, span, (const char *)mst->magic) == NTFS_OK);
			first = ntfs_u16(mst->usa_offset);
			bytes = ntfs_u16(mst->usa_count) * sizeof(uint16_t);
			memcpy(right + offset + first, left + offset + first, bytes);
			memcpy(right + offset + offsetof(struct ntfs_disk_record, lsn),
			    left + offset + offsetof(struct ntfs_disk_record, lsn),
			    sizeof(((struct ntfs_disk_record *)0)->lsn));
		}
	}
	assert(memcmp(left, right, region->bytes) == 0);
	free(right);
	free(left);
}

static void
complete(const char *directory, const char *image, enum ntfs_write_mutation_kind kind,
    enum test_profile profile)
{
	struct test_case *test;
	struct ntfs_write_batch_execution *owner = NULL;
	struct ntfs_write_execution_report report;
	struct journal_oracle *oracle;
	const struct ntfs_write_batch_publication *publication;
	uint8_t *expected;
	size_t index, publications, barriers = 0, data_regions = 0;
	enum ntfs_result result;
	bool poisoned = false, data = false, committed = false;

	test = prepare_profile(directory, image, kind, profile);
	oracle = journal_capture(test);
	for (index = 0; index < test->regions; index++) {
		data_regions += test->region[index].kind == NTFS_WRITE_MUTATION_DATA;
	}
	result = ntfs_write_batch_execute_prepare(&test->backend, test->program, &owner);
	if (result != NTFS_OK) {
		fprintf(stderr,
		    "Physical preparation refused kind %u/profile %u on %s: %s; %zu regions/%zu "
		    "updates, %llu journal bytes\n",
		    kind, profile, image, ntfs_result_string(result), test->regions,
		    ntfs_write_program_count(test->program),
		    (unsigned long long)oracle->restart.file_bytes);
	}
	assert(result == NTFS_OK);
	assert(owner != NULL && test->device.writes == 0 && test->device.barriers == 0);
	/* Publication bytes survive both original preparation owners. */
	ntfs_write_program_close(test->program);
	ntfs_write_mutation_plan_close(test->plan);
	test->program = NULL;
	test->plan = NULL;
	publications = ntfs_write_batch_execution_count(owner);
	expected = malloc(test->device.bytes);
	assert(expected != NULL);
	memcpy(expected, test->before, test->device.bytes);
	for (index = 0; index < publications; index++) {
		publication = ntfs_write_batch_execution_get(owner, index);
		assert(publication != NULL);
		if (publication->stage == NTFS_WRITE_EXECUTION_DATA) {
			assert(!committed);
			data = true;
		}
		if (publication->stage == NTFS_WRITE_EXECUTION_COMMIT_COPY) {
			committed = true;
		}
		if (publication->stage == NTFS_WRITE_EXECUTION_METADATA_HOME) {
			assert(committed);
		}
		barriers += publication->barrier;
		publication_guards(test, publication, expected + publication->physical);
		if (publication->stage == NTFS_WRITE_EXECUTION_DIRTY_FIRST ||
		    publication->stage == NTFS_WRITE_EXECUTION_DIRTY_SECOND ||
		    publication->stage == NTFS_WRITE_EXECUTION_CLEAN_FIRST ||
		    publication->stage == NTFS_WRITE_EXECUTION_CLEAN_SECOND) {
			restart_publication(test, publication, oracle);
		}
		memcpy(
		    expected + publication->physical, publication->image, NTFS_WRITE_CLUSTER_BYTES);
	}
	assert(committed && data == (data_regions != 0));
	assert(ntfs_write_batch_execution_get(owner, publications) == NULL);
	assert(execute(test, owner, &poisoned, &report) == NTFS_OK && !poisoned &&
	    report.completed && report.commit_persisted && report.data_persisted == data);
	assert(report.writes == publications && report.barriers == barriers &&
	    report.physical_bytes == publications * NTFS_WRITE_CLUSTER_BYTES);
	assert(memcmp(expected, test->device.visible, test->device.bytes) == 0 &&
	    memcmp(expected, test->device.durable, test->device.bytes) == 0);
	for (index = 0; index < test->regions; index++) {
		same_metadata(&test->region[index], test->before + test->region[index].physical,
		    test->after + test->region[index].physical,
		    test->device.visible + test->region[index].physical);
	}
	validate(test);
	journal_check(test, oracle);
	requested_file_check(test);
	assert(execute(test, owner, &poisoned, &report) == NTFS_INVALID);
	ntfs_write_batch_execution_close(owner);
	free(expected);
	printf("PASS: physical kind %u/profile %u on %s; %zu publications/%zu barriers\n", kind,
	    profile, image, publications, barriers);
	finish(test);
}

static void
fault_report(const struct ntfs_write_batch_execution *owner,
    const struct ntfs_write_execution_report *actual, size_t write_fault, size_t barrier_fault,
    size_t partial, bool overreport)
{
	struct ntfs_write_execution_report expected = {0};
	const struct ntfs_write_batch_publication *step;
	size_t index;

	for (index = 0; index < ntfs_write_batch_execution_count(owner); index++) {
		step = ntfs_write_batch_execution_get(owner, index);
		expected.writes++;
		if (expected.writes == write_fault) {
			expected.physical_bytes += overreport ? 0 : partial;
			break;
		}
		expected.physical_bytes += NTFS_WRITE_CLUSTER_BYTES;
		if (step->stage == NTFS_WRITE_EXECUTION_DATA) {
			expected.data_bytes += NTFS_WRITE_CLUSTER_BYTES;
		}
		if (step->barrier) {
			expected.barriers++;
			if (expected.barriers == barrier_fault) {
				break;
			}
			expected.durable_stage = step->stage;
			expected.data_persisted |= step->stage == NTFS_WRITE_EXECUTION_DATA;
			expected.commit_persisted |=
			    step->stage == NTFS_WRITE_EXECUTION_COMMIT_COPY;
		}
	}
	assert(actual->writes == expected.writes && actual->barriers == expected.barriers &&
	    actual->physical_bytes == expected.physical_bytes &&
	    actual->data_bytes == expected.data_bytes &&
	    actual->durable_stage == expected.durable_stage &&
	    actual->data_persisted == expected.data_persisted &&
	    actual->commit_persisted == expected.commit_persisted && actual->poisoned &&
	    !actual->completed);
}

static void
admission(const char *directory)
{
	static const uint32_t alignments[] = {0, NTFS_WRITE_SECTOR_BYTES / 2,
	    NTFS_WRITE_CLUSTER_BYTES * 2, NTFS_WRITE_SECTOR_BYTES + 1};
	struct test_case *test;
	struct ntfs_overwrite_environment backend, saved;
	struct ntfs_write_batch_execution *owner = NULL;
	struct ntfs_write_execution_report report, prior_report;
	const struct ntfs_write_program_update *update;
	const struct ntfs_write_batch_publication *step;
	uint8_t *snapshot;
	size_t baseline, allocations, reads, index, data_region;
	bool poisoned = false;

	test = prepare(directory, "source.img", NTFS_WRITE_GROWING_RANGE);
	baseline = test->device.live;
	allocations = test->device.allocations;
	reads = test->device.reads;
	backend = saved = test->backend;
	assert(ntfs_write_batch_execute_prepare(
		   &backend, test->program, (void *)&backend.reader.size_bytes) == NTFS_INVALID);
	assert(memcmp(&backend, &saved, sizeof(backend)) == 0);
	update = ntfs_write_program_get(test->program, 0);
	assert(update != NULL && update->payload.bytes >= sizeof(owner));
	snapshot = malloc(update->payload.bytes);
	assert(snapshot != NULL);
	memcpy(snapshot, update->payload.data, update->payload.bytes);
	assert(ntfs_write_batch_execute_prepare(
		   &backend, test->program, (void *)update->payload.data) == NTFS_INVALID);
	assert(memcmp(snapshot, update->payload.data, update->payload.bytes) == 0);
	free(snapshot);
	for (index = 0; index < sizeof(alignments) / sizeof(alignments[0]); index++) {
		backend.alignment = alignments[index];
		owner = (void *)(uintptr_t)1;
		assert(ntfs_write_batch_execute_prepare(&backend, test->program, &owner) ==
			NTFS_INVALID &&
		    owner == NULL);
	}
	backend = saved;
	backend.persist = NULL;
	owner = (void *)(uintptr_t)1;
	assert(ntfs_write_batch_execute_prepare(&backend, test->program, &owner) == NTFS_INVALID &&
	    owner == NULL);
	assert(test->device.allocations == allocations && test->device.reads == reads &&
	    test->device.live == baseline);
	for (data_region = 0; data_region < test->regions; data_region++) {
		if (test->region[data_region].kind == NTFS_WRITE_MUTATION_DATA) {
			break;
		}
	}
	assert(data_region < test->regions);
	test->device.visible[test->region[data_region].physical] ^= TEST_PATTERN;
	owner = (void *)(uintptr_t)1;
	assert(ntfs_write_batch_execute_prepare(&saved, test->program, &owner) == NTFS_STALE &&
	    owner == NULL && test->device.live == baseline);
	assert(test->device.writes == 0 && test->device.barriers == 0);
	assert(test->device.visible[test->region[data_region].physical] ==
	    (uint8_t)(test->before[test->region[data_region].physical] ^ TEST_PATTERN));
	memcpy(test->device.visible, test->before, test->device.bytes);
	assert(ntfs_write_batch_execute_prepare(&saved, test->program, &owner) == NTFS_OK);
	step = ntfs_write_batch_execution_get(owner, 0);
	assert(step != NULL);
	snapshot = malloc(NTFS_WRITE_CLUSTER_BYTES);
	assert(snapshot != NULL);
	memcpy(snapshot, step->image, NTFS_WRITE_CLUSTER_BYTES);
	memset(&report, TEST_PATTERN, sizeof(report));
	prior_report = report;
	assert(execute(test, owner, (void *)step->image, &report) == NTFS_INVALID);
	assert(memcmp(&report, &prior_report, sizeof(report)) == 0 &&
	    memcmp(snapshot, step->image, NTFS_WRITE_CLUSTER_BYTES) == 0);
	assert(execute(test, owner, &poisoned, (void *)step->image) == NTFS_INVALID && !poisoned);
	assert(memcmp(snapshot, step->image, NTFS_WRITE_CLUSTER_BYTES) == 0);
	assert(execute(test, owner, &poisoned, &report) == NTFS_OK);
	ntfs_write_batch_execution_close(owner);
	free(snapshot);
	finish(test);
	puts("PASS: admission aliases, invalid backend, exact stale-before refusal and retry");
}

static void
journal_capacity(const char *directory)
{
	struct test_case *test;
	struct ntfs_write_batch_execution *owner = NULL;
	size_t baseline;

	test = prepare_profile(directory, "source.img", NTFS_WRITE_CREATE_FILE, TEST_MFT_GROWTH);
	baseline = test->device.live;
	assert(ntfs_write_batch_execute_prepare(&test->backend, test->program, &owner) ==
		NTFS_NO_SPACE &&
	    owner == NULL && test->device.live == baseline && test->device.writes == 0 &&
	    test->device.barriers == 0);
	assert(memcmp(test->before, test->device.visible, test->device.bytes) == 0 &&
	    memcmp(test->before, test->device.durable, test->device.bytes) == 0);
	assert(ntfs_write_batch_execute_prepare(&test->backend, test->program, &owner) ==
		NTFS_NO_SPACE &&
	    owner == NULL && test->device.live == baseline);
	finish(test);
	puts("PASS: complete MFT/index growth refuses insufficient retained journal capacity "
	     "before I/O");
}

static void
posix_case(const char *directory, const char *output, unsigned ordinal, const char *source,
    enum ntfs_write_mutation_kind kind, enum test_profile profile)
{
	struct test_case *test;
	struct ntfs_overwrite_image image;
	struct ntfs_write_batch_execution *owner = NULL;
	struct ntfs_write_execution_report report;
	struct journal_oracle *oracle;
	const struct ntfs_write_batch_publication *step;
	uint8_t *expected;
	char *path;
	FILE *file;
	size_t index, barriers = 0, publications;
	int count;
	bool poisoned = false;

	test = prepare_profile(directory, source, kind, profile);
	oracle = journal_capture(test);
	path = malloc(TEST_PATH_BYTES);
	expected = malloc(test->device.bytes);
	assert(path != NULL && expected != NULL);
	count = snprintf(path, TEST_PATH_BYTES, "%s/operation-%u.img", output, ordinal);
	assert(count > 0 && count < TEST_PATH_BYTES);
	file = fopen(path, "wbx");
	assert(file != NULL &&
	    fwrite(test->before, 1, test->device.bytes, file) == test->device.bytes &&
	    fclose(file) == 0);
	assert(ntfs_overwrite_image_open(path, &image) == 0);
	assert(image.environment.claim(image.environment.reader.context) == NTFS_OK);
	assert(
	    ntfs_write_batch_execute_prepare(&image.environment, test->program, &owner) == NTFS_OK);
	ntfs_write_program_close(test->program);
	ntfs_write_mutation_plan_close(test->plan);
	test->program = NULL;
	test->plan = NULL;
	memcpy(expected, test->before, test->device.bytes);
	publications = ntfs_write_batch_execution_count(owner);
	for (index = 0; index < publications; index++) {
		step = ntfs_write_batch_execution_get(owner, index);
		barriers += step->barrier;
		memcpy(expected + step->physical, step->image, NTFS_WRITE_CLUSTER_BYTES);
	}
	assert(ntfs_write_batch_execute(owner, &poisoned, &report) == NTFS_OK && !poisoned &&
	    report.completed && report.commit_persisted && report.writes == publications &&
	    report.barriers == barriers);
	ntfs_write_batch_execution_close(owner);
	ntfs_overwrite_image_close(&image);
	/* Reopen the exact ordinary backing file after its writer closes. */
	file = fopen(path, "rb");
	assert(file != NULL &&
	    fread(test->device.visible, 1, test->device.bytes, file) == test->device.bytes &&
	    fgetc(file) == EOF && fclose(file) == 0);
	assert(memcmp(expected, test->device.visible, test->device.bytes) == 0);
	for (index = 0; index < test->regions; index++) {
		same_metadata(&test->region[index], test->before + test->region[index].physical,
		    test->after + test->region[index].physical,
		    test->device.visible + test->region[index].physical);
	}
	validate(test);
	journal_check(test, oracle);
	requested_file_check(test);
	printf("PASS: actual regular-image transfers/persistence and fresh reopen: %s (%zu "
	       "writes/%zu barriers)\n",
	    path, publications, barriers);
	free(expected);
	free(path);
	finish(test);
}

static void
posix_images(const char *directory, const char *output)
{
	char *path;
	int count;

	path = malloc(TEST_PATH_BYTES);
	assert(path != NULL);
	count = snprintf(path, TEST_PATH_BYTES, "%s/write-batch-posix-XXXXXX", output);
	assert(count > 0 && count < TEST_PATH_BYTES && mkdtemp(path) != NULL);
	posix_case(directory, path, 0, "source.img", NTFS_WRITE_CREATE_FILE, TEST_DEFAULT);
	posix_case(directory, path, 1, "source.img", NTFS_WRITE_GROWING_RANGE, TEST_DEFAULT);
	posix_case(directory, path, 2, "large-source.img", NTFS_WRITE_CREATE_FILE, TEST_MFT_GROWTH);
	free(path);
}

static void
faults(const char *directory, enum ntfs_write_mutation_kind kind)
{
	struct test_case *test;
	struct ntfs_write_batch_execution *owner = NULL;
	struct ntfs_write_execution_report report;
	size_t writes, barriers, index, mode, baseline, allocations, reads, fault;
	bool poisoned;

	test = prepare(directory, "source.img", kind);
	baseline = test->device.live;
	test->device.allocations = test->device.reads = 0;
	assert(ntfs_write_batch_execute_prepare(&test->backend, test->program, &owner) == NTFS_OK);
	allocations = test->device.allocations;
	reads = test->device.reads;
	writes = ntfs_write_batch_execution_count(owner);
	barriers = 0;
	for (index = 0; index < writes; index++) {
		barriers += ntfs_write_batch_execution_get(owner, index)->barrier;
	}
	ntfs_write_batch_execution_close(owner);
	assert(test->device.live == baseline);
	for (mode = 0; mode < 2; mode++) {
		for (fault = 1; fault <= (mode == 0 ? allocations : reads); fault++) {
			test->device.allocations = test->device.reads = 0;
			test->device.fail_allocation = mode == 0 ? fault : 0;
			test->device.fail_read = mode == 1 ? fault : 0;
			owner = (void *)(uintptr_t)1;
			assert(ntfs_write_batch_execute_prepare(&test->backend, test->program,
				   &owner) == (mode == 0 ? NTFS_NO_MEMORY : NTFS_IO));
			assert(owner == NULL && test->device.live == baseline &&
			    test->device.writes == 0 && test->device.barriers == 0);
			assert(memcmp(test->before, test->device.visible, test->device.bytes) == 0);
			test->device.fail_allocation = test->device.fail_read = 0;
			assert(ntfs_write_batch_execute_prepare(
				   &test->backend, test->program, &owner) == NTFS_OK);
			assert(ntfs_write_batch_execution_count(owner) == writes);
			ntfs_write_batch_execution_close(owner);
		}
	}
	for (index = 1; index <= writes; index++) {
		for (mode = 0; mode < TEST_FAULT_MODES; mode++) {
			memcpy(test->device.visible, test->before, test->device.bytes);
			memcpy(test->device.durable, test->before, test->device.bytes);
			test->device.writes = test->device.barriers = 0;
			test->device.fail_write = index;
			test->device.failure_bytes = mode == 0 ? 0
			    : mode == 1			       ? NTFS_WRITE_SECTOR_BYTES
			    : mode == 2			       ? NTFS_WRITE_CLUSTER_BYTES / 2
							       : NTFS_WRITE_CLUSTER_BYTES;
			test->device.overreport = mode == TEST_FAULT_MODES - 2;
			test->device.short_success = mode == TEST_FAULT_MODES - 1;
			if (test->device.short_success) {
				test->device.failure_bytes = NTFS_WRITE_SECTOR_BYTES;
			}
			assert(ntfs_write_batch_execute_prepare(
				   &test->backend, test->program, &owner) == NTFS_OK);
			poisoned = false;
			assert(execute(test, owner, &poisoned, &report) == NTFS_IO && poisoned &&
			    report.poisoned && !report.completed && report.writes == index);
			fault_report(owner, &report, index, 0, test->device.failure_bytes,
			    test->device.overreport);
			assert(execute(test, owner, &poisoned, &report) == NTFS_IO &&
			    report.poisoned && test->device.writes == index);
			ntfs_write_batch_execution_close(owner);
			assert(test->device.live == baseline);
		}
	}
	test->device.fail_write = 0;
	test->device.overreport = false;
	test->device.short_success = false;
	for (index = 1; index <= barriers; index++) {
		for (mode = 0; mode < 2; mode++) {
			memcpy(test->device.visible, test->before, test->device.bytes);
			memcpy(test->device.durable, test->before, test->device.bytes);
			test->device.writes = test->device.barriers = 0;
			test->device.fail_barrier = index;
			test->device.persist_on_failure = mode != 0;
			assert(ntfs_write_batch_execute_prepare(
				   &test->backend, test->program, &owner) == NTFS_OK);
			poisoned = false;
			assert(execute(test, owner, &poisoned, &report) == NTFS_IO && poisoned &&
			    report.poisoned && !report.completed && report.barriers == index);
			fault_report(owner, &report, 0, index, 0, false);
			assert(execute(test, owner, &poisoned, &report) == NTFS_IO &&
			    report.poisoned && test->device.barriers == index);
			ntfs_write_batch_execution_close(owner);
			assert(test->device.live == baseline);
		}
	}
	printf("PASS: %zu allocation and %zu read failures with retry; %zu write and %zu "
	       "barrier interruption states, sticky poison and no execution reads/allocations\n",
	    allocations, reads, writes * TEST_FAULT_MODES, barriers * 2);
	finish(test);
}

int
main(int argc, char **argv)
{
	assert(argc == 3);
	complete(argv[1], "source.img", NTFS_WRITE_CREATE_FILE, TEST_DEFAULT);
	complete(argv[1], "source.img", NTFS_WRITE_CREATE_DIRECTORY, TEST_DEFAULT);
	complete(argv[1], "source.img", NTFS_WRITE_RESIZE_FILE, TEST_DEFAULT);
	complete(argv[1], "source.img", NTFS_WRITE_GROWING_RANGE, TEST_DEFAULT);
	complete(argv[1], "source.img", NTFS_WRITE_REMOVE_FILE, TEST_DEFAULT);
	complete(argv[1], "source.img", NTFS_WRITE_RENAME, TEST_DEFAULT);
	complete(argv[1], "source.img", NTFS_WRITE_RESIZE_FILE, TEST_SHRINK);
	complete(argv[1], "source.img", NTFS_WRITE_RESIZE_FILE, TEST_RESIDENT_GROWTH);
	complete(argv[1], "source.img", NTFS_WRITE_REMOVE_DIRECTORY, TEST_EMPTY_DIRECTORY);
	complete(argv[1], "large-source.img", NTFS_WRITE_CREATE_FILE, TEST_MFT_GROWTH);
	complete(argv[1], "unused-index-torn.img", NTFS_WRITE_CREATE_FILE, TEST_DEFAULT);
	complete(argv[1], "unused-index-stale.img", NTFS_WRITE_CREATE_FILE, TEST_DEFAULT);
	complete(argv[1], "unused-index-unused-slot.img", NTFS_WRITE_CREATE_FILE, TEST_DEFAULT);
	complete(argv[1], "large-unused-file-stale.img", NTFS_WRITE_CREATE_FILE, TEST_MFT_GROWTH);
	complete(argv[1], "large-unused-file-torn.img", NTFS_WRITE_CREATE_FILE, TEST_MFT_GROWTH);
	complete(
	    argv[1], "large-unused-mft-tail-stale.img", NTFS_WRITE_CREATE_FILE, TEST_MFT_GROWTH);
	complete(
	    argv[1], "large-unused-mft-tail-torn.img", NTFS_WRITE_CREATE_FILE, TEST_MFT_GROWTH);
	complete(argv[1], "source.img", NTFS_WRITE_GROWING_RANGE, TEST_PAGE_ALIGNMENT);
	admission(argv[1]);
	journal_capacity(argv[1]);
	faults(argv[1], NTFS_WRITE_CREATE_FILE);
	faults(argv[1], NTFS_WRITE_GROWING_RANGE);
	posix_images(argv[1], argv[2]);
	puts("PASS: complete physical operation preparation, retained roots, aligned "
	     "publications and durable metadata equivalence; native recovery/admission open");
	return 0;
}
