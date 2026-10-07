/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_batch_execute.h"
#include "write_metadata.h"
#include "../adapters/posix/overwrite_image.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum { TEST_TRACE_PATH_BYTES = 4096, TEST_ASCII_MAX = 127 };

struct image_case {
	struct ntfs_overwrite_image image;
	struct ntfs_write_mutation_request request;
	struct ntfs_write_execution_report report;
	uint16_t source_name[NTFS_NAME_MAX], destination_name[NTFS_NAME_MAX];
	uint8_t *data;
	char path[TEST_TRACE_PATH_BYTES];
};

static uint64_t
number(const char *text)
{
	char *end;
	unsigned long long value;

	errno = 0;
	value = strtoull(text, &end, 10);
	assert(errno == 0 && end != text && *end == '\0' && text[0] != '-' && value <= UINT64_MAX);
	return (uint64_t)value;
}

/* This private acceptance CLI uses ASCII fixture paths. The core owns lossless
 * UTF-16 names; its Unicode conformance tests remain separate. */
static enum ntfs_result
resolve(
    const struct ntfs_environment *environment, const char *path, size_t bytes, uint64_t *reference)
{
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *node = NULL, *child = NULL;
	struct ntfs_stat status;
	uint16_t name[NTFS_NAME_MAX];
	size_t first, index, count;
	enum ntfs_result result;

	*reference = 0;
	if (bytes == 0 || path[0] != '/' || bytes > NTFS_OVERWRITE_MAX_PATH_UNITS) {
		return NTFS_INVALID;
	}
	result = ntfs_mount(environment, NULL, &volume);
	if (result == NTFS_OK) {
		result = ntfs_root(volume, &node);
	}
	first = 1;
	while (result == NTFS_OK && first < bytes) {
		index = first;
		while (index < bytes && path[index] != '/') {
			index++;
		}
		count = index - first;
		if (count == 0 || count > NTFS_NAME_MAX) {
			result = NTFS_INVALID;
			break;
		}
		for (count = 0; first + count < index; count++) {
			if ((unsigned char)path[first + count] > TEST_ASCII_MAX) {
				result = NTFS_INVALID;
				break;
			}
			name[count] = (unsigned char)path[first + count];
		}
		if (result != NTFS_OK) {
			break;
		}
		result = ntfs_lookup(node, name, count, &child);
		ntfs_node_close(node);
		node = child;
		child = NULL;
		first = index + 1;
	}
	if (result == NTFS_OK) {
		result = ntfs_node_stat(node, &status);
		if (result == NTFS_OK) {
			*reference = status.reference;
		}
	}
	ntfs_node_close(node);
	if (volume != NULL) {
		assert(ntfs_unmount(volume) == NTFS_OK);
	}
	return result;
}

static enum ntfs_result
split_name(const struct ntfs_environment *environment, const char *path, uint16_t *units,
    struct ntfs_write_name *name)
{
	const char *last;
	size_t index, count;
	enum ntfs_result result;

	last = strrchr(path, '/');
	if (last == NULL || last[1] == '\0') {
		return NTFS_INVALID;
	}
	count = strlen(last + 1);
	if (count > NTFS_NAME_MAX) {
		return NTFS_INVALID;
	}
	for (index = 0; index < count; index++) {
		if ((unsigned char)last[1 + index] > TEST_ASCII_MAX) {
			return NTFS_INVALID;
		}
		units[index] = (unsigned char)last[1 + index];
	}
	result = resolve(
	    environment, path, last == path ? 1 : (size_t)(last - path), &name->parent_reference);
	if (result == NTFS_OK) {
		name->units = units;
		name->count = count;
	}
	return result;
}

static void
read_data(struct image_case *test, const char *path)
{
	struct stat status;
	ssize_t actual;
	size_t copied = 0;
	int fd;

	fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	assert(fd >= 0 && fstat(fd, &status) == 0 && S_ISREG(status.st_mode) &&
	    status.st_size > 0 && status.st_size <= NTFS_OVERWRITE_MAX_BYTES);
	test->request.bytes = (size_t)status.st_size;
	test->data = malloc(test->request.bytes);
	assert(test->data != NULL);
	while (copied < test->request.bytes) {
		actual = read(fd, test->data + copied, test->request.bytes - copied);
		if (actual < 0 && errno == EINTR) {
			continue;
		}
		assert(actual > 0);
		copied += (size_t)actual;
	}
	assert(close(fd) == 0);
	test->request.data = test->data;
}

static enum ntfs_result
request(struct image_case *test, int argc, char **argv)
{
	struct ntfs_write_mutation_request *input = &test->request;
	const struct ntfs_environment *environment = &test->image.environment.reader;
	const char *kind = argv[3], *path = argv[4];
	enum ntfs_result result;

	input->filetime = number(argv[5]);
	if (strcmp(kind, "create") == 0 || strcmp(kind, "mkdir") == 0 ||
	    strcmp(kind, "remove") == 0 || strcmp(kind, "rmdir") == 0) {
		assert(argc == 7);
		input->kind = strcmp(kind, "create") == 0 ? NTFS_WRITE_CREATE_FILE
		    : strcmp(kind, "mkdir") == 0	  ? NTFS_WRITE_CREATE_DIRECTORY
		    : strcmp(kind, "remove") == 0	  ? NTFS_WRITE_REMOVE_FILE
							  : NTFS_WRITE_REMOVE_DIRECTORY;
		return split_name(environment, path, test->source_name, &input->source);
	}
	if (strcmp(kind, "rename") == 0) {
		assert(argc == 9 && number(argv[8]) <= 1);
		input->kind = NTFS_WRITE_RENAME;
		input->replace = number(argv[8]) != 0;
		result = split_name(environment, path, test->source_name, &input->source);
		if (result == NTFS_OK) {
			result = split_name(
			    environment, argv[7], test->destination_name, &input->destination);
		}
		return result;
	}
	assert(strcmp(kind, "resize") == 0 || strcmp(kind, "write") == 0);
	result = resolve(environment, path, strlen(path), &input->reference);
	if (result != NTFS_OK) {
		return result;
	}
	if (strcmp(kind, "resize") == 0) {
		assert(argc == 8);
		input->kind = NTFS_WRITE_RESIZE_FILE;
		input->size = number(argv[7]);
	} else {
		assert(argc == 9);
		input->kind = NTFS_WRITE_GROWING_RANGE;
		input->offset = number(argv[7]);
		read_data(test, argv[8]);
	}
	return result;
}

static void
dump(struct image_case *test, const char *directory, const char *kind, size_t index,
    const void *memory, size_t bytes)
{
	FILE *file;
	int count;

	count = snprintf(test->path, sizeof(test->path), "%s/%s-%zu.bin", directory, kind, index);
	assert(count > 0 && (size_t)count < sizeof(test->path));
	file = fopen(test->path, "wx");
	assert(file != NULL && fwrite(memory, 1, bytes, file) == bytes && fclose(file) == 0);
}

static void
describe(struct image_case *test, const char *directory, const struct ntfs_write_program *program,
    const struct ntfs_write_batch_execution *execution)
{
	struct ntfs_write_mutation_region region;
	const struct ntfs_write_batch_publication *publication;
	FILE *file;
	size_t index;
	int count;

	count = snprintf(test->path, sizeof(test->path), "%s/plan.json", directory);
	assert(count > 0 && (size_t)count < sizeof(test->path));
	file = fopen(test->path, "wx");
	assert(file != NULL);
	fprintf(file, "{\"regions\":[");
	for (index = 0; index < ntfs_write_program_regions(program); index++) {
		assert(ntfs_write_program_region(program, index, &region) == NTFS_OK);
		dump(test, directory, "region-before", index, region.before, region.bytes);
		dump(test, directory, "region-after", index, region.after, region.bytes);
		fprintf(file,
		    "%s{\"physical\":%llu,\"bytes\":%zu,\"kind\":%u,"
		    "\"reference\":%llu,\"logical\":%llu,\"attribute_type\":%u,"
		    "\"mirror\":%s,\"file_slots\":%u,\"index_allocated\":%s}",
		    index == 0 ? "" : ",", (unsigned long long)region.physical, region.bytes,
		    region.kind, (unsigned long long)region.target.reference,
		    (unsigned long long)region.target.logical_offset, region.target.attribute_type,
		    region.target.mirror ? "true" : "false", region.predecessor.file_slots,
		    region.predecessor.index_allocated ? "true" : "false");
	}
	fprintf(file, "],\"publications\":[");
	for (index = 0; index < ntfs_write_batch_execution_count(execution); index++) {
		publication = ntfs_write_batch_execution_get(execution, index);
		assert(publication != NULL);
		dump(test, directory, "publication", index, publication->image,
		    NTFS_WRITE_CLUSTER_BYTES);
		fprintf(file, "%s{\"physical\":%llu,\"bytes\":%u,\"stage\":%u,\"barrier\":%s}",
		    index == 0 ? "" : ",", (unsigned long long)publication->physical,
		    NTFS_WRITE_CLUSTER_BYTES, publication->stage,
		    publication->barrier ? "true" : "false");
	}
	fprintf(file, "]}\n");
	assert(fclose(file) == 0);
}

int
main(int argc, char **argv)
{
	struct image_case *test;
	struct ntfs_write_mutation_plan *plan = NULL;
	struct ntfs_write_program *program = NULL;
	struct ntfs_write_batch_execution *execution = NULL;
	const char *stage = "claim";
	uint64_t reference = 0;
	size_t regions = 0, packets = 0, publications = 0;
	bool execute, poisoned = false;
	int opened;
	enum ntfs_result result;

	assert(argc >= 7 && argc <= 9);
	execute = strcmp(argv[1], "execute") == 0;
	assert(execute || strcmp(argv[1], "prepare") == 0);
	test = calloc(1, sizeof(*test));
	assert(test != NULL);
	opened = ntfs_overwrite_image_open(argv[2], &test->image);
	if (opened != 0) {
		fprintf(stderr, "private operation image open failed: %d\n", opened);
		free(test);
		return 2;
	}
	result = test->image.environment.claim(test->image.environment.reader.context);
	if (result == NTFS_OK) {
		stage = "resolve";
		result = request(test, argc, argv);
	}
	if (result == NTFS_OK) {
		stage = "mutation";
		result = ntfs_write_mutation_prepare(
		    &test->image.environment.reader, &test->request, &plan);
	}
	if (result == NTFS_OK) {
		reference = ntfs_write_mutation_plan_reference(plan);
		regions = ntfs_write_mutation_plan_count(plan);
		stage = "program";
		result =
		    ntfs_write_program_prepare(&test->image.environment.reader, plan, &program);
	}
	ntfs_write_mutation_plan_close(plan);
	if (result == NTFS_OK) {
		packets = ntfs_write_program_count(program);
		stage = "execution-prepare";
		result =
		    ntfs_write_batch_execute_prepare(&test->image.environment, program, &execution);
	}
	if (result == NTFS_OK) {
		publications = ntfs_write_batch_execution_count(execution);
		describe(test, argv[6], program, execution);
	}
	ntfs_write_program_close(program);
	if (result == NTFS_OK && execute) {
		stage = "execute";
		result = ntfs_write_batch_execute(execution, &poisoned, &test->report);
	}
	printf("{\"result\":%u,\"stage\":\"%s\",\"execution_requested\":%s,"
	       "\"executed\":%s,\"reference\":%llu,"
	       "\"regions\":%zu,\"updates\":%zu,\"publications\":%zu,\"writes\":%u,"
	       "\"barriers\":%u,\"physical_bytes\":%llu,\"completed\":%s,\"poisoned\":%s}\n",
	    result, stage, execute ? "true" : "false",
	    strcmp(stage, "execute") == 0 ? "true" : "false", (unsigned long long)reference,
	    regions, packets, publications, test->report.writes, test->report.barriers,
	    (unsigned long long)test->report.physical_bytes,
	    test->report.completed ? "true" : "false", poisoned ? "true" : "false");
	ntfs_write_batch_execution_close(execution);
	ntfs_overwrite_image_close(&test->image);
	free(test->data);
	free(test);
	return result == NTFS_OK ? 0 : 1;
}
