/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_mutation_internal.h"
#include "write_batch_execute.h"
#include "write_batch_recover.h"
#include "../adapters/posix/overwrite_image.h"
#include <ntfs/record.h>
#include <ntfs/validate.h>
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum { TEST_PATH_BYTES = 4096, TEST_LABEL_BYTES = 128 };

union allocation {
	max_align_t alignment;
	size_t bytes;
};

struct device {
	uint8_t *image, *durable;
	size_t bytes, live, reads, allocations, writes, barriers;
	bool executing;
};

struct hardlink_case {
	struct device device;
	struct ntfs_overwrite_environment backend;
	struct ntfs_write_mutation_region *region;
	struct ntfs_write_batch_publication *publication;
	uint8_t *before, *after, *committed, *frames, *journal, *golden;
	uint64_t target_physical;
	size_t regions, publications, commit, cases;
	char label[TEST_LABEL_BYTES], output[TEST_PATH_BYTES];
};

static void *
allocate(void *context, size_t bytes)
{
	struct device *device = context;
	union allocation *memory;

	assert(!device->executing && bytes != 0);
	device->allocations++;
	if (bytes > NTFS_DEFAULT_MAX_LIVE_BYTES - device->live) {
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
	union allocation *memory = (union allocation *)pointer - 1;

	assert(pointer != NULL && memory->bytes == bytes && device->live >= bytes);
	device->live -= bytes;
	free(memory);
}

static enum ntfs_result
read_image(void *context, uint64_t physical, void *out, size_t bytes)
{
	struct device *device = context;

	assert(!device->executing && ntfs_bounds(physical, bytes, device->bytes));
	device->reads++;
	memcpy(out, device->image + physical, bytes);
	return NTFS_OK;
}

static enum ntfs_result
write_image(void *context, uint64_t physical, const void *data, size_t bytes, size_t *actual)
{
	struct device *device = context;

	assert(device->executing && bytes == NTFS_WRITE_CLUSTER_BYTES &&
	    physical % NTFS_WRITE_SECTOR_BYTES == 0 &&
	    (uintptr_t)data % NTFS_WRITE_SECTOR_BYTES == 0 &&
	    ntfs_bounds(physical, bytes, device->bytes));
	device->writes++;
	memcpy(device->image + physical, data, bytes);
	*actual = bytes;
	return NTFS_OK;
}

static enum ntfs_result
persist_image(void *context)
{
	struct device *device = context;

	assert(device->executing);
	device->barriers++;
	memcpy(device->durable, device->image, device->bytes);
	return NTFS_OK;
}

static uint8_t *
load(const char *directory, const char *name, size_t *bytes)
{
	char path[TEST_PATH_BYTES];
	uint8_t *data;
	FILE *file;
	long length;
	int count;

	count = snprintf(path, sizeof(path), "%s/%s", directory, name);
	assert(count > 0 && (size_t)count < sizeof(path));
	file = fopen(path, "rb");
	assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
	length = ftell(file);
	assert(length > 0 && fseek(file, 0, SEEK_SET) == 0);
	*bytes = (size_t)length;
	data = malloc(*bytes);
	assert(data != NULL && fread(data, 1, *bytes, file) == *bytes);
	assert(fgetc(file) == EOF && !ferror(file) && fclose(file) == 0);
	return data;
}

static void
save(const char *path, const uint8_t *bytes, size_t count)
{
	FILE *file = fopen(path, "wbx");

	assert(file != NULL && fwrite(bytes, 1, count, file) == count && fclose(file) == 0);
}

static void
validate(struct hardlink_case *test)
{
	struct ntfs_validation_report *report = calloc(1, sizeof(*report));

	assert(report != NULL);
	assert(ntfs_validate(&test->backend.reader, NULL, NULL, report) == NTFS_OK &&
	    report->complete);
	free(report);
	assert(test->device.live == 0);
}

static void
mark_journal(struct hardlink_case *test)
{
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *node = NULL;
	struct ntfs_stream *stream = NULL;
	size_t index;
	uint64_t first, bytes;

	assert(ntfs_mount(&test->backend.reader, NULL, &volume) == NTFS_OK);
	assert(ntfs_node_by_number(volume, NTFS_LOGFILE_RECORD, &node) == NTFS_OK);
	assert(ntfs_stream_open(node, NULL, 0, &stream) == NTFS_OK);
	for (index = 0; index < stream->run_count; index++) {
		assert(stream->runs[index].lcn != NTFS_HOLE);
		first = stream->runs[index].lcn * NTFS_WRITE_CLUSTER_BYTES;
		bytes = stream->runs[index].length * NTFS_WRITE_CLUSTER_BYTES;
		assert(ntfs_bounds(first, bytes, test->device.bytes));
		memset(test->journal + first / NTFS_WRITE_CLUSTER_BYTES, 1,
		    (size_t)(bytes / NTFS_WRITE_CLUSTER_BYTES));
	}
	ntfs_stream_close(stream);
	ntfs_node_close(node);
	assert(ntfs_unmount(volume) == NTFS_OK && test->device.live == 0);
}

/* Only the USA storage and journal-derived LSN may differ for a changed owned
 * FILE/INDX object. Unchanged sibling FILE slots remain exact raw-byte matches. */
static void
normalize(uint8_t *actual, const uint8_t *expected, size_t bytes)
{
	const struct ntfs_disk_mst *header = (const void *)expected;
	size_t first = ntfs_u16(header->usa_offset);
	size_t count = ntfs_u16(header->usa_count) * NTFS_MST_WORD_BYTES;

	assert(memcmp(actual, expected, sizeof(*header)) == 0 && ntfs_bounds(first, count, bytes));
	memcpy(actual + first, expected + first, count);
	memcpy(actual + offsetof(struct ntfs_disk_record, lsn),
	    expected + offsetof(struct ntfs_disk_record, lsn),
	    sizeof(((struct ntfs_disk_record *)0)->lsn));
}

static void
endpoint(struct hardlink_case *test, bool committed)
{
	const struct ntfs_write_mutation_region *region;
	const uint8_t *expected = committed ? test->after : test->before;
	uint8_t *left = malloc(test->device.bytes), *right = malloc(test->device.bytes);
	uint8_t target[NTFS_WRITE_RECORD_BYTES];
	size_t index, offset, span, physical, bytes;

	assert(left != NULL && right != NULL);
	memcpy(left, expected, test->device.bytes);
	memcpy(right, test->device.image, test->device.bytes);
	if (committed) {
		for (index = 0; index < test->regions; index++) {
			region = &test->region[index];
			if (region->kind != NTFS_WRITE_MUTATION_FILE &&
			    region->kind != NTFS_WRITE_MUTATION_INDEX) {
				continue;
			}
			span = region->kind == NTFS_WRITE_MUTATION_FILE
			    ? NTFS_WRITE_RECORD_BYTES
			    : region->bytes;
			for (offset = 0; offset < region->bytes; offset += span) {
				physical = region->physical + offset;
				if (memcmp(test->before + physical, expected + physical, span) == 0) {
					continue;
				}
				assert(ntfs_fixup(left + physical, span,
					   region->kind == NTFS_WRITE_MUTATION_FILE ? "FILE" : "INDX") ==
				    NTFS_OK);
				assert(ntfs_fixup(right + physical, span,
					   region->kind == NTFS_WRITE_MUTATION_FILE ? "FILE" : "INDX") ==
				    NTFS_OK);
				normalize(right + physical, left + physical, span);
			}
		}
		/* Independent fixture-authored complete target FILE proves preserved
		 * old names, SI, security and ADS, plus the exact new cached name. */
		memcpy(target, test->device.image + test->target_physical, sizeof(target));
		assert(ntfs_record_decode(target, sizeof(target), false) == NTFS_OK);
		normalize(target, test->golden, sizeof(target));
		assert(memcmp(target, test->golden, sizeof(target)) == 0);
	}
	for (physical = 0; physical < test->device.bytes; physical += NTFS_WRITE_CLUSTER_BYTES) {
		bytes = test->device.bytes - physical < NTFS_WRITE_CLUSTER_BYTES
		    ? test->device.bytes - physical
		    : NTFS_WRITE_CLUSTER_BYTES;
		if (test->journal[physical / NTFS_WRITE_CLUSTER_BYTES] == 0) {
			assert(memcmp(left + physical, right + physical, bytes) == 0);
		}
	}
	free(right);
	free(left);
	validate(test);
}

static void
reset(struct hardlink_case *test, const uint8_t *input)
{
	assert(test->device.live == 0 && !test->device.executing);
	memcpy(test->device.image, input, test->device.bytes);
	memcpy(test->device.durable, input, test->device.bytes);
	test->device.writes = test->device.barriers = 0;
}

static void
writer_state(struct hardlink_case *test, size_t complete, size_t partial, bool suffix)
{
	const struct ntfs_write_batch_publication *step;
	size_t index, offset = suffix ? NTFS_WRITE_CLUSTER_BYTES - partial : 0;

	assert(complete <= test->publications && partial < NTFS_WRITE_CLUSTER_BYTES);
	reset(test, test->before);
	for (index = 0; index < complete; index++) {
		step = &test->publication[index];
		memcpy(test->device.image + step->physical, step->image, NTFS_WRITE_CLUSTER_BYTES);
	}
	if (partial != 0) {
		assert(complete < test->publications);
		step = &test->publication[complete];
		memcpy(test->device.image + step->physical + offset, step->image + offset, partial);
	}
	memcpy(test->device.durable, test->device.image, test->device.bytes);
}

static void
recover(struct hardlink_case *test, bool committed, bool quiet)
{
	struct ntfs_write_batch_recovery *owner = NULL;
	struct ntfs_write_recovery_report report;
	const struct ntfs_write_batch_recovery_publication *step;
	uint8_t *expected = malloc(test->device.bytes);
	char path[TEST_PATH_BYTES];
	size_t index, count, reads, allocations;
	int length;
	bool poisoned = false;
	enum ntfs_result result;

	assert(expected != NULL && test->device.live == 0);
	memcpy(expected, test->device.image, test->device.bytes);
	result = ntfs_write_batch_recover_prepare(&test->backend, &owner);
	if (result != NTFS_OK) {
		length = snprintf(path, sizeof(path), "%s/refused-%s-%zu.img", test->output,
		    test->label, test->cases);
		assert(length > 0 && (size_t)length < sizeof(path));
		save(path, expected, test->device.bytes);
		fprintf(stderr, "%s recovery case %zu (%s): %s; retained %s\n", test->label,
		    test->cases, committed ? "committed" : "old", ntfs_result_string(result), path);
	}
	assert(result == NTFS_OK && owner != NULL);
	assert(memcmp(expected, test->device.image, test->device.bytes) == 0);
	count = ntfs_write_batch_recovery_count(owner);
	assert(!quiet || count == 0);
	for (index = 0; index < count; index++) {
		step = ntfs_write_batch_recovery_get(owner, index);
		assert(step != NULL && ntfs_bounds(step->physical, NTFS_WRITE_CLUSTER_BYTES,
				   test->device.bytes));
		memcpy(expected + step->physical, step->image, NTFS_WRITE_CLUSTER_BYTES);
	}
	reads = test->device.reads;
	allocations = test->device.allocations;
	test->device.executing = true;
	assert(ntfs_write_batch_recover_execute(owner, &poisoned, &report) == NTFS_OK &&
	    !poisoned && report.completed && report.homes_persisted && report.writes == count);
	assert(ntfs_write_batch_recover_execute(owner, &poisoned, &report) == NTFS_INVALID);
	test->device.executing = false;
	assert(test->device.reads == reads && test->device.allocations == allocations);
	ntfs_write_batch_recovery_close(owner);
	assert(test->device.live == 0 && memcmp(expected, test->device.image, test->device.bytes) == 0 &&
	    memcmp(expected, test->device.durable, test->device.bytes) == 0);
	free(expected);
	endpoint(test, committed);
}

static void
writer_cuts(struct hardlink_case *test)
{
	size_t complete, partial, direction;
	bool committed;

	/* The entire cut set is determined by captured publications before the
	 * first recovery verdict. Every metadata sector, both commit sides, and
	 * every journal/restart prefix and suffix are included. */
	for (complete = 0; complete <= test->publications; complete++) {
		for (partial = 0; partial < NTFS_WRITE_CLUSTER_BYTES;
		     partial += NTFS_WRITE_SECTOR_BYTES) {
			if (complete == test->publications && partial != 0) {
				break;
			}
			for (direction = 0; direction < (partial == 0 ? 1u : 2u); direction++) {
				committed = complete > test->commit;
				writer_state(test, complete, partial, direction != 0);
				recover(test, committed, false);
				recover(test, committed, true);
				test->cases++;
			}
		}
	}
}

static void
recovery_cuts(struct hardlink_case *test)
{
	struct ntfs_write_batch_recovery *owner = NULL;
	struct ntfs_write_batch_recovery_publication *steps;
	const struct ntfs_write_batch_recovery_publication *step;
	uint8_t *input = malloc(test->device.bytes), *frames;
	size_t committed, count, complete, partial, direction, index, offset;

	assert(input != NULL);
	for (committed = 0; committed < 2; committed++) {
		writer_state(test, test->commit + committed, 0, false);
		memcpy(input, test->device.image, test->device.bytes);
		assert(ntfs_write_batch_recover_prepare(&test->backend, &owner) == NTFS_OK);
		count = ntfs_write_batch_recovery_count(owner);
		assert(count != 0);
		steps = calloc(count, sizeof(*steps));
		frames = malloc(count * NTFS_WRITE_CLUSTER_BYTES);
		assert(steps != NULL && frames != NULL);
		for (index = 0; index < count; index++) {
			step = ntfs_write_batch_recovery_get(owner, index);
			steps[index] = *step;
			memcpy(frames + index * NTFS_WRITE_CLUSTER_BYTES, step->image,
			    NTFS_WRITE_CLUSTER_BYTES);
			steps[index].image = frames + index * NTFS_WRITE_CLUSTER_BYTES;
		}
		ntfs_write_batch_recovery_close(owner);
		for (complete = 0; complete <= count; complete++) {
			for (partial = 0; partial < NTFS_WRITE_CLUSTER_BYTES;
			     partial += NTFS_WRITE_SECTOR_BYTES) {
				if (complete == count && partial != 0) {
					break;
				}
				for (direction = 0; direction < (partial == 0 ? 1u : 2u);
				     direction++) {
					reset(test, input);
					for (index = 0; index < complete; index++) {
						memcpy(test->device.image + steps[index].physical,
						    steps[index].image, NTFS_WRITE_CLUSTER_BYTES);
					}
					if (partial != 0) {
						offset = direction != 0
						    ? NTFS_WRITE_CLUSTER_BYTES - partial
						    : 0;
						memcpy(test->device.image + steps[complete].physical +
							    offset,
						    steps[complete].image + offset, partial);
					}
					memcpy(test->device.durable, test->device.image,
					    test->device.bytes);
					recover(test, committed != 0, false);
					recover(test, committed != 0, true);
					test->cases++;
				}
			}
		}
		free(frames);
		free(steps);
	}
	free(input);
}

static void
regular_images(struct hardlink_case *test)
{
	struct ntfs_overwrite_image image;
	struct ntfs_write_batch_recovery *owner = NULL;
	struct ntfs_write_recovery_report report;
	const struct ntfs_write_batch_recovery_publication *step;
	uint8_t *expected = malloc(test->device.bytes), *actual;
	char path[TEST_PATH_BYTES], name[TEST_LABEL_BYTES];
	size_t committed, pass, count, index, bytes;
	int length;
	bool poisoned;

	assert(expected != NULL);
	for (committed = 0; committed < 2; committed++) {
		writer_state(test, test->commit + committed, 0, false);
		memcpy(expected, test->device.image, test->device.bytes);
		length = snprintf(name, sizeof(name), "%s-%s.img", test->label,
		    committed != 0 ? "committed" : "old");
		assert(length > 0 && (size_t)length < sizeof(name));
		length = snprintf(path, sizeof(path), "%s/%s", test->output, name);
		assert(length > 0 && (size_t)length < sizeof(path));
		save(path, expected, test->device.bytes);
		for (pass = 0; pass < 2; pass++) {
			assert(ntfs_overwrite_image_open(path, &image) == 0);
			assert(image.environment.claim(image.environment.reader.context) == NTFS_OK);
			assert(ntfs_write_batch_recover_prepare(&image.environment, &owner) == NTFS_OK);
			count = ntfs_write_batch_recovery_count(owner);
			assert(pass == 0 ? count != 0 : count == 0);
			for (index = 0; index < count; index++) {
				step = ntfs_write_batch_recovery_get(owner, index);
				memcpy(expected + step->physical, step->image, NTFS_WRITE_CLUSTER_BYTES);
			}
			poisoned = false;
			assert(ntfs_write_batch_recover_execute(owner, &poisoned, &report) == NTFS_OK &&
			    !poisoned && report.completed && report.homes_persisted &&
			    report.writes == count);
			ntfs_write_batch_recovery_close(owner);
			ntfs_overwrite_image_close(&image);
			actual = load(test->output, name, &bytes);
			assert(bytes == test->device.bytes && memcmp(actual, expected, bytes) == 0);
			reset(test, actual);
			free(actual);
			endpoint(test, committed != 0);
		}
	}
	free(expected);
}

static struct hardlink_case *
prepare(const char *directory, const char *output, const char *label, const char *golden,
    uint64_t target_physical, const struct ntfs_write_mutation_request *request)
{
	struct hardlink_case *test = calloc(1, sizeof(*test));
	struct ntfs_write_mutation_plan *plan = NULL;
	struct ntfs_write_program *program = NULL;
	struct ntfs_write_batch_execution *owner = NULL;
	struct ntfs_write_execution_report report;
	const struct ntfs_write_batch_publication *step;
	char name[TEST_LABEL_BYTES];
	size_t bytes, index, allocations, reads;
	int length;
	bool poisoned = false;

	assert(test != NULL && strlen(label) < sizeof(test->label) &&
	    strlen(output) < sizeof(test->output));
	strcpy(test->label, label);
	strcpy(test->output, output);
	length = snprintf(name, sizeof(name), "%s.img", label);
	assert(length > 0 && (size_t)length < sizeof(name));
	test->before = load(directory, name, &test->device.bytes);
	bytes = test->device.bytes;
	assert(bytes % NTFS_WRITE_SECTOR_BYTES == 0);
	test->after = malloc(bytes);
	test->committed = malloc(bytes);
	test->device.image = malloc(bytes);
	test->device.durable = malloc(bytes);
	test->journal = calloc((bytes + NTFS_WRITE_CLUSTER_BYTES - 1) / NTFS_WRITE_CLUSTER_BYTES, 1);
	assert(test->after != NULL && test->committed != NULL && test->device.image != NULL &&
	    test->device.durable != NULL && test->journal != NULL);
	test->golden = load(directory, golden, &bytes);
	assert(bytes == NTFS_WRITE_RECORD_BYTES);
	test->target_physical = target_physical;
	memcpy(test->after, test->before, test->device.bytes);
	memcpy(test->committed, test->before, test->device.bytes);
	reset(test, test->before);
	test->backend = (struct ntfs_overwrite_environment){
	    .reader = {NTFS_API_VERSION, &test->device, test->device.bytes, read_image, allocate,
		release},
	    .api_version = NTFS_OVERWRITE_API_VERSION,
	    .alignment = NTFS_WRITE_SECTOR_BYTES,
	    .write = write_image,
	    .persist = persist_image};
	mark_journal(test);
	validate(test);
	assert(ntfs_write_mutation_prepare(&test->backend.reader, request, &plan) == NTFS_OK);
	test->regions = ntfs_write_mutation_plan_count(plan);
	test->region = calloc(test->regions, sizeof(*test->region));
	assert(test->region != NULL);
	for (index = 0; index < test->regions; index++) {
		assert(ntfs_write_mutation_plan_region(plan, index, &test->region[index]) == NTFS_OK);
		assert(test->region[index].kind != NTFS_WRITE_MUTATION_DATA &&
		    !test->region[index].target.mirror);
		memcpy(test->after + test->region[index].physical, test->region[index].after,
		    test->region[index].bytes);
		/* No borrowed region bytes survive plan close. */
		test->region[index].before = test->before + test->region[index].physical;
		test->region[index].after = test->after + test->region[index].physical;
	}
	assert(ntfs_write_program_prepare(&test->backend.reader, plan, &program) == NTFS_OK);
	ntfs_write_mutation_plan_close(plan);
	assert(ntfs_write_batch_execute_prepare(&test->backend, program, &owner) == NTFS_OK);
	ntfs_write_program_close(program);
	test->publications = ntfs_write_batch_execution_count(owner);
	test->publication = calloc(test->publications, sizeof(*test->publication));
	test->frames = malloc(test->publications * NTFS_WRITE_CLUSTER_BYTES);
	assert(test->publication != NULL && test->frames != NULL);
	for (index = 0; index < test->publications; index++) {
		step = ntfs_write_batch_execution_get(owner, index);
		assert(step != NULL && step->stage != NTFS_WRITE_EXECUTION_DATA);
		test->publication[index] = *step;
		memcpy(test->frames + index * NTFS_WRITE_CLUSTER_BYTES, step->image,
		    NTFS_WRITE_CLUSTER_BYTES);
		test->publication[index].image = test->frames + index * NTFS_WRITE_CLUSTER_BYTES;
		memcpy(test->committed + step->physical, step->image, NTFS_WRITE_CLUSTER_BYTES);
		if (step->stage == NTFS_WRITE_EXECUTION_COMMIT_COPY) {
			test->commit = index;
		}
	}
	assert(test->commit != 0 && test->device.writes == 0 && test->device.barriers == 0 &&
	    memcmp(test->device.image, test->before, test->device.bytes) == 0);
	reads = test->device.reads;
	allocations = test->device.allocations;
	test->device.executing = true;
	assert(ntfs_write_batch_execute(owner, &poisoned, &report) == NTFS_OK && !poisoned &&
	    report.completed && report.commit_persisted && report.writes == test->publications);
	assert(ntfs_write_batch_execute(owner, &poisoned, &report) == NTFS_INVALID);
	test->device.executing = false;
	assert(test->device.reads == reads && test->device.allocations == allocations);
	ntfs_write_batch_execution_close(owner);
	assert(test->device.live == 0 &&
	    memcmp(test->committed, test->device.image, test->device.bytes) == 0 &&
	    memcmp(test->committed, test->device.durable, test->device.bytes) == 0);
	endpoint(test, true);
	recover(test, true, true);
	return test;
}

static void
finish(struct hardlink_case *test)
{
	assert(test->device.live == 0);
	free(test->region);
	free(test->publication);
	free(test->before);
	free(test->after);
	free(test->committed);
	free(test->frames);
	free(test->journal);
	free(test->golden);
	free(test->device.image);
	free(test->device.durable);
	free(test);
}

int
main(int argc, char **argv)
{
	char path[TEST_PATH_BYTES], output[TEST_PATH_BYTES];
	char label[TEST_LABEL_BYTES], golden[TEST_LABEL_BYTES];
	char source[NTFS_NAME_MAX + 1], destination[NTFS_NAME_MAX + 1];
	uint16_t source_units[NTFS_NAME_MAX], destination_units[NTFS_NAME_MAX];
	struct ntfs_write_mutation_request request = {.kind = NTFS_WRITE_CREATE_HARD_LINK};
	struct hardlink_case *test;
	uint64_t physical;
	size_t profiles = 0, cases = 0;
	unsigned code;
	FILE *manifest;
	int count;

	assert(argc == 3);
	count = snprintf(output, sizeof(output), "%s/hardlink-execution-XXXXXX", argv[2]);
	assert(count > 0 && (size_t)count < sizeof(output) && mkdtemp(output) != NULL);
	count = snprintf(path, sizeof(path), "%s/cases.txt", argv[1]);
	assert(count > 0 && (size_t)count < sizeof(path));
	manifest = fopen(path, "r");
	assert(manifest != NULL);
	while (fscanf(manifest,
		   "%127s %u %" SCNu64 " %" SCNu64 " %255s %" SCNu64 " %255s %" SCNu64 " %127s",
		   label, &code, &request.reference, &request.source.parent_reference, source,
		   &request.destination.parent_reference, destination, &physical, golden) == 9) {
		if (strcmp(label, "same-parent") != 0 && strcmp(label, "cross-parent") != 0 &&
		    strcmp(label, "paired-source") != 0 && strcmp(label, "index-split") != 0 &&
		    strcmp(label, "fragmented") != 0) {
			continue;
		}
		assert(code == NTFS_OK);
		assert(ntfs_utf8_to_utf16(source, strlen(source), source_units, NTFS_NAME_MAX,
			   &request.source.count) == NTFS_OK);
		assert(ntfs_utf8_to_utf16(destination, strlen(destination), destination_units,
			   NTFS_NAME_MAX, &request.destination.count) == NTFS_OK);
		request.source.units = source_units;
		request.destination.units = destination_units;
		test = prepare(argv[1], output, label, golden, physical, &request);
		writer_cuts(test);
		if (strcmp(label, "cross-parent") == 0 || strcmp(label, "index-split") == 0) {
			recovery_cuts(test);
		}
		regular_images(test);
		printf("PASS: hard-link %s: %zu publications, %zu writer/recovery cuts, "
		       "full-image endpoints, independent FILE golden, quiet fresh reopen\n",
		    label, test->publications, test->cases);
		cases += test->cases;
		profiles++;
		finish(test);
	}
	assert(feof(manifest) && !ferror(manifest) && fclose(manifest) == 0 && profiles == 5);
	printf("PASS: %zu selected-cache storage profiles, %zu preselected interruption states, "
	       "10 persisted recovery images; artifacts %s; general owner remains refused\n",
	    profiles, cases, output);
	return 0;
}
