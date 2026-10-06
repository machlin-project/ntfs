/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_retirement.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { TEST_PATH_BYTES = 2048, TEST_NAME_BYTES = 128, TEST_PATTERN = 0xa5 };

#define TEST_REDO_LSN UINT64_C(11003)
#define TEST_UNDO_LSN UINT64_C(12007)

struct tracker {
	size_t live, calls, releases, reads, fail;
};

struct fixture {
	struct ntfs_write_mutation_region region;
	uint8_t *before, *after;
	size_t count, length[NTFS_WRITE_RETIREMENT_MAX_UPDATES];
	uint16_t key, flags[NTFS_WRITE_RETIREMENT_MAX_UPDATES];
	enum ntfs_result result;
	uint8_t *payload[NTFS_WRITE_RETIREMENT_MAX_UPDATES];
};

static void *
allocate(void *context, size_t bytes)
{
	struct tracker *tracker = context;
	void *memory;

	tracker->calls++;
	if (tracker->calls == tracker->fail) {
		return NULL;
	}
	memory = malloc(bytes);
	assert(memory != NULL);
	memset(memory, TEST_PATTERN, bytes);
	tracker->live += bytes;
	return memory;
}

static void
release(void *context, void *memory, size_t bytes)
{
	struct tracker *tracker = context;

	assert(memory != NULL && tracker->live >= bytes);
	tracker->live -= bytes;
	tracker->releases++;
	free(memory);
}

static enum ntfs_result
refuse_read(void *context, uint64_t offset, void *memory, size_t bytes)
{
	struct tracker *tracker = context;

	(void)offset;
	(void)memory;
	(void)bytes;
	tracker->reads++;
	return NTFS_IO;
}

static FILE *
open_file(const char *directory, const char *name)
{
	char *path;
	FILE *file;
	int length;

	path = malloc(TEST_PATH_BYTES);
	assert(path != NULL);
	length = snprintf(path, TEST_PATH_BYTES, "%s/%s", directory, name);
	assert(length > 0 && length < TEST_PATH_BYTES);
	file = fopen(path, "rb");
	free(path);
	assert(file != NULL);
	return file;
}

static uint8_t *
load(const char *directory, const char *name, size_t *bytes)
{
	FILE *file;
	uint8_t *memory;
	long length;

	file = open_file(directory, name);
	assert(fseek(file, 0, SEEK_END) == 0);
	length = ftell(file);
	assert(length >= 0 && fseek(file, 0, SEEK_SET) == 0);
	*bytes = (size_t)length;
	memory = malloc(*bytes == 0 ? 1 : *bytes);
	assert(memory != NULL && fread(memory, 1, *bytes, file) == *bytes);
	assert(fgetc(file) == EOF && !ferror(file) && fclose(file) == 0);
	return memory;
}

static void
fixture_load(const char *directory, struct fixture *fixture)
{
	FILE *file;
	char code[TEST_NAME_BYTES], name[TEST_NAME_BYTES];
	uint64_t reference, physical, logical;
	size_t index, bytes;
	unsigned key, flags;

	memset(fixture, 0, sizeof(*fixture));
	file = open_file(directory, "expected.txt");
	assert(fscanf(file, "%127s %zu %u %" SCNu64 " %" SCNu64 " %" SCNu64, code, &fixture->count,
		   &key, &reference, &physical, &logical) == 6);
	assert(key <= UINT16_MAX && fixture->count <= NTFS_WRITE_RETIREMENT_MAX_UPDATES);
	fixture->key = (uint16_t)key;
	fixture->result = strcmp(code, "success") == 0 ? NTFS_OK
	    : strcmp(code, "corrupt") == 0	       ? NTFS_CORRUPT
						       : NTFS_UNSUPPORTED;
	for (index = 0; index < fixture->count; index++) {
		assert(fscanf(file, "%zu %u", &fixture->length[index], &flags) == 2);
		assert(flags <= UINT16_MAX);
		fixture->flags[index] = (uint16_t)flags;
		assert(snprintf(name, sizeof(name), "step-%zu.payload", index) > 0);
		fixture->payload[index] = load(directory, name, &bytes);
		assert(bytes == fixture->length[index]);
	}
	assert(fclose(file) == 0);
	fixture->before = load(directory, "before.bin", &bytes);
	assert(bytes == NTFS_WRITE_CLUSTER_BYTES);
	fixture->after = load(directory, "after.bin", &bytes);
	assert(bytes == NTFS_WRITE_CLUSTER_BYTES);
	fixture->region = (struct ntfs_write_mutation_region){.physical = physical,
	    .before = fixture->before,
	    .after = fixture->after,
	    .bytes = NTFS_WRITE_CLUSTER_BYTES,
	    .kind = NTFS_WRITE_MUTATION_FILE,
	    .target = {.reference = reference,
		.logical_offset = logical,
		.attribute_type = NTFS_ATTRIBUTE_DATA}};
}

static void
fixture_close(struct fixture *fixture)
{
	size_t index;

	for (index = 0; index < fixture->count; index++) {
		free(fixture->payload[index]);
	}
	free(fixture->before);
	free(fixture->after);
}

static void
verify_payloads(const struct fixture *fixture, const struct ntfs_write_retirement_program *program)
{
	const struct ntfs_write_retirement_update *step;
	size_t index;

	assert(ntfs_write_retirement_program_count(program) == fixture->count);
	assert(ntfs_write_retirement_program_get(program, fixture->count) == NULL);
	for (index = 0; index < fixture->count; index++) {
		step = ntfs_write_retirement_program_get(program, index);
		assert(step != NULL && step->record_flags == fixture->flags[index]);
		assert(step->payload.bytes == fixture->length[index]);
		assert(
		    memcmp(step->payload.data, fixture->payload[index], step->payload.bytes) == 0);
	}
}

static void
verify_effects(const char *directory, const struct ntfs_write_retirement_program *program)
{
	const struct ntfs_write_retirement_update *step;
	struct ntfs_logfile_update update;
	char name[TEST_NAME_BYTES];
	uint8_t *image, *redo, *undo;
	size_t index, slot, bytes;

	for (index = 1; index < ntfs_write_retirement_program_count(program); index += 2) {
		step = ntfs_write_retirement_program_get(program, index);
		assert(ntfs_logfile_update_decode(
			   step->payload.data, step->payload.bytes, &update) == NTFS_OK);
		slot = (size_t)update.cluster_index * NTFS_WRITE_SECTOR_BYTES /
		    NTFS_WRITE_RECORD_BYTES;
		assert(snprintf(name, sizeof(name), "slot-%zu.before", slot) > 0);
		image = load(directory, name, &bytes);
		assert(bytes == NTFS_WRITE_RECORD_BYTES);
		assert(snprintf(name, sizeof(name), "slot-%zu.redo", slot) > 0);
		redo = load(directory, name, &bytes);
		assert(bytes == NTFS_WRITE_RECORD_BYTES);
		assert(snprintf(name, sizeof(name), "slot-%zu.undo", slot) > 0);
		undo = load(directory, name, &bytes);
		assert(bytes == NTFS_WRITE_RECORD_BYTES);
		assert(ntfs_write_retirement_apply(step->payload.data, step->payload.bytes, false,
			   TEST_REDO_LSN, image, bytes) == NTFS_OK);
		assert(memcmp(image, redo, bytes) == 0);
		assert(ntfs_write_retirement_apply(step->payload.data, step->payload.bytes, false,
			   TEST_REDO_LSN, image, bytes) == NTFS_OK);
		assert(memcmp(image, redo, bytes) == 0);
		assert(ntfs_write_retirement_apply(step->payload.data, step->payload.bytes, true,
			   TEST_UNDO_LSN, image, bytes) == NTFS_OK);
		assert(memcmp(image, undo, bytes) == 0);
		assert(ntfs_write_retirement_apply(step->payload.data, step->payload.bytes, true,
			   TEST_UNDO_LSN, image, bytes) == NTFS_OK);
		assert(memcmp(image, undo, bytes) == 0);
		free(image);
		free(redo);
		free(undo);
	}
}

static void
one_case(const char *directory)
{
	struct fixture *fixture;
	struct tracker tracker = {0};
	struct ntfs_environment source;
	struct ntfs_write_retirement_program *program;
	size_t allocations, fault;
	enum ntfs_result result;

	fixture = calloc(1, sizeof(*fixture));
	assert(fixture != NULL);
	fixture_load(directory, fixture);
	source = (struct ntfs_environment){
	    NTFS_API_VERSION, &tracker, 0, refuse_read, allocate, release};
	program = (void *)(uintptr_t)1;
	result = ntfs_write_retirement_program_prepare(
	    &source, &fixture->region, fixture->key, &program);
	if (result != fixture->result) {
		fprintf(stderr, "%s: expected %d, got %d\n", directory, fixture->result, result);
	}
	assert(result == fixture->result && tracker.reads == 0);
	allocations = tracker.calls;
	if (result == NTFS_OK) {
		verify_payloads(fixture, program);
		verify_effects(directory, program);
		ntfs_write_retirement_program_close(program);
		assert(tracker.live == 0);
		for (fault = 1; fault <= allocations; fault++) {
			tracker.calls = 0;
			tracker.fail = fault;
			program = (void *)(uintptr_t)1;
			assert(ntfs_write_retirement_program_prepare(&source, &fixture->region,
				   fixture->key, &program) == NTFS_NO_MEMORY);
			assert(program == NULL && tracker.live == 0 && tracker.reads == 0);
			tracker.fail = 0;
			assert(ntfs_write_retirement_program_prepare(
				   &source, &fixture->region, fixture->key, &program) == NTFS_OK);
			verify_payloads(fixture, program);
			ntfs_write_retirement_program_close(program);
			assert(tracker.live == 0);
		}
		assert(ntfs_write_retirement_program_prepare(
			   &source, &fixture->region, fixture->key, &program) == NTFS_OK);
		memset(fixture->before, TEST_PATTERN, fixture->region.bytes);
		memset(fixture->after, TEST_PATTERN, fixture->region.bytes);
		memset(&fixture->region, 0, sizeof(fixture->region));
		verify_payloads(fixture, program);
		ntfs_write_retirement_program_close(program);
	} else {
		assert(program == NULL);
	}
	assert(tracker.live == 0 && tracker.reads == 0);
	fixture_close(fixture);
	free(fixture);
}

static void
rejected_apply(const char *directory)
{
	struct ntfs_disk_log_update_storage *stored;
	struct ntfs_disk_record *header;
	uint8_t *payload, *original, *image, *backup, *prefix;
	size_t bytes, record_bytes, length, variant;
	enum ntfs_result result;

	payload = load(directory, "step-1.payload", &bytes);
	original = malloc(bytes);
	assert(original != NULL);
	memcpy(original, payload, bytes);
	image = load(directory, "slot-0.before", &record_bytes);
	backup = malloc(record_bytes);
	assert(backup != NULL && record_bytes == NTFS_WRITE_RECORD_BYTES);
	memcpy(backup, image, record_bytes);
	for (length = 0; length < bytes; length++) {
		assert(ntfs_write_retirement_apply(
			   payload, length, false, TEST_REDO_LSN, image, record_bytes) != NTFS_OK);
		assert(memcmp(image, backup, record_bytes) == 0);
	}
	for (variant = 0; variant < 13; variant++) {
		memcpy(payload, original, bytes);
		stored = (void *)payload;
		header = (void *)image;
		prefix = payload + ntfs_u16(stored->header.undo_offset);
		if (variant == 0) {
			ntfs_put_u16(
			    stored->header.redo_operation, NTFS_LOG_OP_UPDATE_RESIDENT_VALUE);
		} else if (variant == 1) {
			ntfs_put_u16(stored->header.undo_operation, NTFS_LOG_OP_NOOP);
		} else if (variant == 2) {
			ntfs_put_u16(stored->header.redo_bytes, 1);
		} else if (variant == 3) {
			ntfs_put_u16(
			    stored->header.undo_bytes, NTFS_WRITE_RETIREMENT_PREFIX_BYTES - 1);
		} else if (variant == 4) {
			ntfs_put_u16(stored->header.cluster_index, 1);
		} else if (variant == 5) {
			ntfs_put_u16(stored->header.record_offset, 1);
		} else if (variant == 6) {
			ntfs_put_u16(stored->header.attribute_flags, 0);
		} else if (variant == 7) {
			prefix[offsetof(struct ntfs_disk_record, mst.magic)] ^= 1;
		} else if (variant == 8) {
			ntfs_put_u16(prefix + offsetof(struct ntfs_disk_record, sequence), 0);
		} else if (variant == 9) {
			ntfs_put_u16(header->sequence, 49);
		} else if (variant == 10) {
			ntfs_put_u16(header->links, 19);
		} else if (variant == 11) {
			ntfs_put_u16(header->attrs_offset, 0);
		} else {
			ntfs_put_u32(header->allocated, 0);
		}
		memcpy(backup, image, record_bytes);
		result = ntfs_write_retirement_apply(
		    payload, bytes, false, TEST_REDO_LSN, image, record_bytes);
		assert(result != NTFS_OK && memcmp(image, backup, record_bytes) == 0);
		result = ntfs_write_retirement_apply(
		    payload, bytes, true, TEST_UNDO_LSN, image, record_bytes);
		assert(result != NTFS_OK && memcmp(image, backup, record_bytes) == 0);
		/* Restore the complete independently authored active predecessor. */
		free(image);
		image = load(directory, "slot-0.before", &record_bytes);
	}
	memcpy(payload, original, bytes);
	memcpy(backup, image, record_bytes);
	assert(ntfs_write_retirement_apply(payload, bytes, false, 0, image, record_bytes) ==
	    NTFS_INVALID);
	assert(memcmp(image, backup, record_bytes) == 0);
	assert(ntfs_write_retirement_apply(
		   payload, bytes, false, TEST_REDO_LSN, payload, record_bytes) == NTFS_INVALID);
	assert(memcmp(payload, original, bytes) == 0);
	free(payload);
	free(original);
	free(image);
	free(backup);
}

static void
rejected_program(const char *directory)
{
	struct fixture *fixture;
	struct tracker tracker = {0};
	struct ntfs_environment source, source_before;
	struct ntfs_write_mutation_region region, region_before;
	struct ntfs_write_retirement_program *program;
	uint8_t *before, *after;
	size_t variant, calls;
	enum ntfs_result result;

	fixture = calloc(1, sizeof(*fixture));
	assert(fixture != NULL);
	fixture_load(directory, fixture);
	source = (struct ntfs_environment){
	    NTFS_API_VERSION, &tracker, 0, refuse_read, allocate, release};
	source_before = source;
	region = fixture->region;
	region_before = region;
	before = malloc(region.bytes);
	after = malloc(region.bytes);
	assert(before != NULL && after != NULL);
	memcpy(before, region.before, region.bytes);
	memcpy(after, region.after, region.bytes);
	assert(ntfs_write_retirement_program_prepare(
		   &source, &region, fixture->key, (void *)&source) == NTFS_INVALID);
	assert(memcmp(&source, &source_before, sizeof(source)) == 0);
	assert(ntfs_write_retirement_program_prepare(
		   &source, &region, fixture->key, (void *)&region) == NTFS_INVALID);
	assert(memcmp(&region, &region_before, sizeof(region)) == 0);
	assert(ntfs_write_retirement_program_prepare(
		   &source, &region, fixture->key, (void *)fixture->before) == NTFS_INVALID);
	assert(ntfs_write_retirement_program_prepare(
		   &source, &region, fixture->key, (void *)fixture->after) == NTFS_INVALID);
	assert(memcmp(before, region.before, region.bytes) == 0 &&
	    memcmp(after, region.after, region.bytes) == 0);
	region.before = (void *)(UINTPTR_MAX - 3);
	program = (void *)(uintptr_t)1;
	assert(ntfs_write_retirement_program_prepare(&source, &region, fixture->key, &program) ==
	    NTFS_INVALID);
	assert(program == (void *)(uintptr_t)1);
	region = region_before;
	assert(ntfs_write_retirement_program_prepare(&source, &region, fixture->key,
		   (void *)(UINTPTR_MAX - sizeof(program) + 1)) == NTFS_INVALID);
	assert(ntfs_write_retirement_program_prepare(&source, &region, fixture->key, NULL) ==
	    NTFS_INVALID);
	assert(tracker.calls == 0);
	for (variant = 0; variant < 11; variant++) {
		source = source_before;
		region = region_before;
		if (variant == 0) {
			source.api_version = 0;
		} else if (variant == 1) {
			source.allocate = NULL;
		} else if (variant == 2) {
			region.physical++;
		} else if (variant == 3) {
			region.target.logical_offset++;
		} else if (variant == 4) {
			region.target.reference = 0;
		} else if (variant == 5) {
			region.target.mirror = true;
		} else if (variant == 6) {
			region.target.attribute_type = NTFS_ATTR_BITMAP;
		} else if (variant == 7) {
			region.target.name[0] = 'x';
		} else if (variant == 8) {
			region.bytes--;
		} else if (variant == 9) {
			source.size_bytes = region.physical;
		} else {
			fixture->key++;
		}
		calls = tracker.calls;
		program = (void *)(uintptr_t)1;
		result =
		    ntfs_write_retirement_program_prepare(&source, &region, fixture->key, &program);
		assert((result == NTFS_INVALID || result == NTFS_UNSUPPORTED) && program == NULL);
		assert(tracker.calls == calls && tracker.reads == 0 && tracker.live == 0);
	}
	assert(memcmp(before, fixture->before, NTFS_WRITE_CLUSTER_BYTES) == 0 &&
	    memcmp(after, fixture->after, NTFS_WRITE_CLUSTER_BYTES) == 0);
	free(before);
	free(after);
	fixture_close(fixture);
	free(fixture);
	assert(ntfs_write_retirement_program_count(NULL) == 0);
	assert(ntfs_write_retirement_program_get(NULL, 0) == NULL);
	ntfs_write_retirement_program_close(NULL);
}

static void
native_inputs(const char *root)
{
	struct ntfs_logfile_record record;
	const struct ntfs_disk_record *header;
	FILE *list;
	char name[TEST_NAME_BYTES], *directory;
	uint8_t *packet, *image, *home, *before;
	size_t bytes, image_bytes, expected_bytes, cases = 0;
	uint64_t previous_lsn;

	directory = malloc(TEST_PATH_BYTES);
	assert(directory != NULL);
	list = open_file(root, "cases.list");
	while (fscanf(list, "%127s", name) == 1) {
		assert(snprintf(directory, TEST_PATH_BYTES, "%s/%s", root, name) > 0);
		packet = load(directory, "packet.original.bin", &bytes);
		image = load(directory, "before.constructed.bin", &image_bytes);
		home = load(directory, "home.restored.bin", &expected_bytes);
		before = load(directory, "before.constructed.bin", &expected_bytes);
		assert(image_bytes == expected_bytes && image_bytes == NTFS_WRITE_RECORD_BYTES);
		assert(ntfs_logfile_record_decode(
			   packet, bytes, sizeof(struct ntfs_disk_log_record), &record) == NTFS_OK);
		assert(record.data.offset + record.data.length == bytes);
		header = (const void *)before;
		previous_lsn = ntfs_u64(header->lsn);
		assert(previous_lsn != 0);
		assert(ntfs_write_retirement_apply(packet + record.data.offset, record.data.length,
			   false, record.lsn, image, image_bytes) == NTFS_OK);
		assert(memcmp(image, home, image_bytes) == 0);
		assert(ntfs_write_retirement_apply(packet + record.data.offset, record.data.length,
			   true, previous_lsn, image, image_bytes) == NTFS_OK);
		assert(memcmp(image, before, image_bytes) == 0);
		free(packet);
		free(image);
		free(home);
		free(before);
		cases++;
	}
	assert(!ferror(list) && fclose(list) == 0 && cases > 0);
	free(directory);
	printf("PASS: %zu original Deallocate/Initialize payloads reproduce exact matched FILE "
	       "headers and private inverse effects\n",
	    cases);
}

int
main(int argc, char **argv)
{
	FILE *list;
	char name[TEST_NAME_BYTES], *directory;
	size_t cases = 0;

	assert(argc == 2 || argc == 3);
	directory = malloc(TEST_PATH_BYTES);
	assert(directory != NULL);
	list = open_file(argv[1], "cases.list");
	while (fscanf(list, "%127s", name) == 1) {
		assert(snprintf(directory, TEST_PATH_BYTES, "%s/%s", argv[1], name) > 0);
		one_case(directory);
		cases++;
	}
	assert(!ferror(list) && fclose(list) == 0);
	assert(snprintf(directory, TEST_PATH_BYTES, "%s/slot-0", argv[1]) > 0);
	rejected_apply(directory);
	rejected_program(directory);
	free(directory);
	if (argc == 3) {
		native_inputs(argv[2]);
	}
	printf("PASS: %zu FILE retirement programs, exact payloads, whole private redo/undo, "
	       "lifetime, allocation faults and unchanged failures\n",
	    cases);
	return 0;
}
