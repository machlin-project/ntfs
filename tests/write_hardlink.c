/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_mutation_internal.h"
#include "write_program.h"
#include "write_owner_internal.h"
#include "fuzz_device.h"
#include <ntfs/record.h>
#include <ntfs/validate.h>
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { TEST_PATH_BYTES = 4096, TEST_LABEL_BYTES = 128, TEST_KEYS = 64 };

struct test_device {
	struct fuzz_device device;
	bool partial;
};

struct test_keys {
	struct ntfs_mutation_key keys[TEST_KEYS];
	size_t count;
};

static size_t cases, allocation_faults, read_faults, program_faults, inverse_prefixes;

static uint8_t *
load(const char *directory, const char *name, size_t *bytes)
{
	char path[TEST_PATH_BYTES];
	FILE *file;
	uint8_t *data;
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

static enum ntfs_result
read_image(void *context, uint64_t offset, void *memory, size_t bytes)
{
	struct test_device *test = context;
	enum ntfs_result result = fuzz_read(&test->device, offset, memory, bytes);

	if (result != NTFS_OK && test->partial && offset <= test->device.size &&
	    bytes <= test->device.size - offset) {
		memcpy(memory, test->device.data + offset, bytes / 2);
	}
	return result;
}

static struct ntfs_environment
environment(struct test_device *test)
{
	struct ntfs_environment env = fuzz_environment(&test->device);

	env.context = test;
	env.read = read_image;
	return env;
}

static void
normalize(uint8_t *actual, const uint8_t *expected, size_t bytes, bool lsn)
{
	const struct ntfs_disk_mst *header = (const void *)expected;
	size_t offset = ntfs_u16(header->usa_offset);
	size_t count = ntfs_u16(header->usa_count) * NTFS_MST_WORD_BYTES;

	assert(ntfs_bounds(offset, count, bytes));
	assert(memcmp(actual, expected, sizeof(*header)) == 0);
	memcpy(actual + offset, expected + offset, count);
	if (lsn) {
		memcpy(actual + offsetof(struct ntfs_disk_record, lsn),
		    expected + offsetof(struct ntfs_disk_record, lsn),
		    sizeof(((struct ntfs_disk_record *)0)->lsn));
	}
}

static void
logical(const struct ntfs_write_mutation_region *region, bool before, uint8_t *out)
{
	size_t offset;

	memcpy(out, before ? region->before : region->after, region->bytes);
	if (region->kind == NTFS_WRITE_MUTATION_FILE) {
		for (offset = 0; offset < region->bytes; offset += NTFS_WRITE_RECORD_BYTES) {
			if ((region->predecessor.file_slots &
				(1u << (offset / NTFS_WRITE_RECORD_BYTES))) != 0) {
				assert(ntfs_record_decode(out + offset, NTFS_WRITE_RECORD_BYTES,
					   false) == NTFS_OK);
			}
		}
	} else if (region->kind == NTFS_WRITE_MUTATION_INDEX &&
	    (!before || region->predecessor.index_allocated)) {
		assert(ntfs_fixup(out, region->bytes, "INDX") == NTFS_OK);
	}
}

static void
program_equal(const struct ntfs_write_mutation_region *region, uint8_t *actual, bool before)
{
	uint8_t expected[NTFS_WRITE_CLUSTER_BYTES];
	size_t offset;

	logical(region, before, expected);
	if (region->kind == NTFS_WRITE_MUTATION_FILE) {
		for (offset = 0; offset < region->bytes; offset += NTFS_WRITE_RECORD_BYTES) {
			if ((region->predecessor.file_slots &
				(1u << (offset / NTFS_WRITE_RECORD_BYTES))) != 0) {
				normalize(actual + offset, expected + offset,
				    NTFS_WRITE_RECORD_BYTES, true);
			}
		}
	} else if (region->kind == NTFS_WRITE_MUTATION_INDEX) {
		if (before && !region->predecessor.index_allocated) {
			/* Reclaimed free storage has no predecessor index object. The
			 * inverse still restores its allocation and live-slot bitmaps. */
			return;
		}
		normalize(actual, expected, region->bytes, true);
	}
	assert(memcmp(actual, expected, region->bytes) == 0);
}

static void
check_program(struct test_device *test, const struct ntfs_environment *env,
    struct ntfs_write_mutation_plan *plan)
{
	struct ntfs_write_program *program = NULL, *failed;
	struct ntfs_write_mutation_region region;
	const struct ntfs_write_program_update *step;
	uint8_t *bytes;
	size_t count, regions, index, prefix, allocations, retained, reads;

	allocations = test->device.allocations;
	reads = test->device.reads;
	assert(ntfs_write_program_prepare(env, plan, &program) == NTFS_OK);
	allocations = test->device.allocations - allocations;
	retained = test->device.memory;
	for (index = 1; index <= allocations; index++) {
		test->device.fail_allocation = test->device.allocations + index;
		failed = (void *)(uintptr_t)1;
		assert(ntfs_write_program_prepare(env, plan, &failed) == NTFS_NO_MEMORY);
		assert(failed == NULL && test->device.memory == retained);
		assert(test->device.reads == reads);
		program_faults++;
	}
	test->device.fail_allocation = 0;
	ntfs_write_mutation_plan_close(plan);
	count = ntfs_write_program_count(program);
	regions = ntfs_write_program_regions(program);
	assert(count > 0 && regions > 0);
	bytes = malloc(regions * NTFS_WRITE_CLUSTER_BYTES);
	assert(bytes != NULL);
	for (prefix = 0; prefix <= count; prefix++) {
		for (index = 0; index < regions; index++) {
			assert(ntfs_write_program_region(program, index, &region) == NTFS_OK);
			assert(region.kind != NTFS_WRITE_MUTATION_DATA && !region.target.mirror);
			logical(&region, true, bytes + index * NTFS_WRITE_CLUSTER_BYTES);
		}
		for (index = 0; index < prefix; index++) {
			step = ntfs_write_program_get(program, index);
			assert(ntfs_write_program_apply(program, index, false, 100001 + index,
				   bytes + step->region * NTFS_WRITE_CLUSTER_BYTES,
				   NTFS_WRITE_CLUSTER_BYTES) == NTFS_OK);
		}
		if (prefix == count) {
			for (index = 0; index < regions; index++) {
				assert(
				    ntfs_write_program_region(program, index, &region) == NTFS_OK);
				program_equal(
				    &region, bytes + index * NTFS_WRITE_CLUSTER_BYTES, false);
			}
		}
		for (index = prefix; index != 0; index--) {
			step = ntfs_write_program_get(program, index - 1);
			assert(ntfs_write_program_apply(program, index - 1, true, 200001 + index,
				   bytes + step->region * NTFS_WRITE_CLUSTER_BYTES,
				   NTFS_WRITE_CLUSTER_BYTES) == NTFS_OK);
		}
		for (index = 0; index < regions; index++) {
			assert(ntfs_write_program_region(program, index, &region) == NTFS_OK);
			program_equal(&region, bytes + index * NTFS_WRITE_CLUSTER_BYTES, true);
		}
		inverse_prefixes++;
	}
	free(bytes);
	ntfs_write_program_close(program);
	assert(test->device.memory == 0);
}

/* Independently inventory complete raw I30 key bodies, including cache bytes
 * which the public names-only iterator deliberately does not expose. */
static void
collect_keys(struct ntfs_stream *allocation, const uint8_t *value, size_t length,
    size_t header_offset, unsigned depth, struct test_keys *keys)
{
	const struct ntfs_disk_index_header *header = (const void *)(value + header_offset);
	const struct ntfs_disk_index_entry *entry;
	uint8_t *child;
	uint64_t vcn;
	size_t position, end, key_bytes;
	uint16_t flags, bytes;

	assert(depth < NTFS_DIRECTORY_DEPTH);
	assert(ntfs_bounds(header_offset, sizeof(*header), length));
	position = header_offset + ntfs_u32(header->entries_offset);
	end = header_offset + ntfs_u32(header->used);
	assert(end <= length);
	for (;;) {
		assert(ntfs_bounds(position, sizeof(*entry), end));
		entry = (const void *)(value + position);
		bytes = ntfs_u16(entry->length);
		flags = ntfs_u16(entry->flags);
		key_bytes = ntfs_u16(entry->key_length);
		assert(bytes >= sizeof(*entry) && ntfs_bounds(position, bytes, end));
		if ((flags & NTFS_INDEX_CHILD) != 0) {
			assert(allocation != NULL);
			vcn = ntfs_u64(value + position + bytes - sizeof(vcn));
			child = malloc(NTFS_WRITE_CLUSTER_BYTES);
			assert(child != NULL);
			assert(ntfs_stream_exact(allocation, vcn * NTFS_WRITE_CLUSTER_BYTES, child,
				   NTFS_WRITE_CLUSTER_BYTES) == NTFS_OK);
			assert(ntfs_fixup(child, NTFS_WRITE_CLUSTER_BYTES, "INDX") == NTFS_OK);
			collect_keys(allocation, child, NTFS_WRITE_CLUSTER_BYTES,
			    offsetof(struct ntfs_disk_index_block, header), depth + 1, keys);
			free(child);
		}
		if ((flags & NTFS_INDEX_END) != 0) {
			break;
		}
		assert(keys->count < TEST_KEYS && key_bytes <= NTFS_MUTATION_FILENAME_BYTES);
		keys->keys[keys->count].reference = ntfs_u64(entry->reference);
		keys->keys[keys->count].bytes = (uint16_t)key_bytes;
		memcpy(keys->keys[keys->count].value, value + position + sizeof(*entry), key_bytes);
		keys->count++;
		position += bytes;
	}
}

static void
keys_at(const struct ntfs_environment *env, uint64_t reference, struct test_keys *keys)
{
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *node = NULL;
	struct ntfs_stream *allocation = NULL;
	struct ntfs_attr_view root;
	const uint8_t *value;
	size_t bytes;
	enum ntfs_result result;

	keys->count = 0;
	assert(ntfs_mount(env, NULL, &volume) == NTFS_OK);
	assert(ntfs_node_open(volume, reference, &node) == NTFS_OK);
	assert(ntfs_attr_find(node->record, NTFS_WRITE_RECORD_BYTES, NTFS_ATTR_INDEX_ROOT,
		   ntfs_mutation_index_name, 4, UINT16_MAX, &root) == NTFS_OK);
	assert(ntfs_attr_value(&root, &value, &bytes) == NTFS_OK);
	result = ntfs_attribute_open(
	    node, NTFS_ATTR_INDEX_ALLOCATION, ntfs_mutation_index_name, 4, &allocation);
	assert(result == NTFS_OK || result == NTFS_NOT_FOUND);
	collect_keys(allocation, value, bytes, sizeof(struct ntfs_disk_index_root), 0, keys);
	ntfs_stream_close(allocation);
	ntfs_node_close(node);
	assert(ntfs_unmount(volume) == NTFS_OK);
}

static void
check_keys(const struct ntfs_environment *source, const struct ntfs_environment *view,
    const struct ntfs_write_mutation_request *request, const uint8_t *value, size_t value_bytes)
{
	struct test_keys *old = calloc(1, sizeof(*old)), *current = calloc(1, sizeof(*current));
	size_t index, seen = 0, added = 0;

	assert(old != NULL && current != NULL);
	keys_at(source, request->destination.parent_reference, old);
	keys_at(view, request->destination.parent_reference, current);
	assert(current->count == old->count + 1);
	for (index = 0; index < current->count; index++) {
		if (current->keys[index].reference == request->reference &&
		    current->keys[index].bytes == value_bytes &&
		    memcmp(current->keys[index].value, value, value_bytes) == 0) {
			added++;
		} else {
			assert(seen < old->count);
			assert(memcmp(&current->keys[index], &old->keys[seen],
				   sizeof(old->keys[seen])) == 0);
			seen++;
		}
	}
	assert(added == 1 && seen == old->count);
	if (request->source.parent_reference != request->destination.parent_reference) {
		memset(old, 0, sizeof(*old));
		memset(current, 0, sizeof(*current));
		keys_at(source, request->source.parent_reference, old);
		keys_at(view, request->source.parent_reference, current);
		assert(memcmp(old, current, sizeof(*old)) == 0);
	}
	free(current);
	free(old);
}

static void
check_parent_attributes(
    const struct ntfs_environment *source, const struct ntfs_environment *view, uint64_t reference)
{
	struct ntfs_volume *old_volume = NULL, *new_volume = NULL;
	struct ntfs_node *old_node = NULL, *new_node = NULL;
	struct ntfs_attr_view old, current;
	const struct ntfs_disk_record *header;
	uint16_t name[NTFS_NAME_MAX];
	uint32_t position;
	size_t index;
	enum ntfs_result result;

	assert(ntfs_mount(source, NULL, &old_volume) == NTFS_OK);
	assert(ntfs_mount(view, NULL, &new_volume) == NTFS_OK);
	assert(ntfs_node_open(old_volume, reference, &old_node) == NTFS_OK);
	assert(ntfs_node_open(new_volume, reference, &new_node) == NTFS_OK);
	header = (const void *)old_node->record;
	position = ntfs_u16(header->attrs_offset);
	while ((result = ntfs_attr_at(old_node->record, ntfs_u32(header->used), &position, &old)) ==
	    NTFS_OK) {
		if (old.type == NTFS_ATTR_INDEX_ROOT || old.type == NTFS_ATTR_INDEX_ALLOCATION ||
		    old.type == NTFS_ATTR_BITMAP) {
			continue;
		}
		for (index = 0; index < old.disk->name_length; index++) {
			name[index] = ntfs_u16(old.bytes + ntfs_u16(old.disk->name_offset) +
			    index * NTFS_UTF16_UNIT_BYTES);
		}
		assert(ntfs_attr_find(new_node->record, NTFS_WRITE_RECORD_BYTES, old.type, name,
			   old.disk->name_length, old.instance, &current) == NTFS_OK);
		assert(old.length == current.length &&
		    memcmp(old.bytes, current.bytes, old.length) == 0);
	}
	assert(result == NTFS_END);
	ntfs_node_close(new_node);
	ntfs_node_close(old_node);
	assert(ntfs_unmount(new_volume) == NTFS_OK);
	assert(ntfs_unmount(old_volume) == NTFS_OK);
}

static void
faults(const uint8_t *image, size_t bytes, const struct ntfs_write_mutation_request *request)
{
	struct test_device test = {{.data = image, .size = bytes}, false};
	struct ntfs_environment env = environment(&test);
	struct ntfs_write_mutation_plan *plan = NULL;
	size_t allocations, reads, index;
	unsigned partial;
	enum ntfs_result result;

	assert(ntfs_write_mutation_prepare(&env, request, &plan) == NTFS_OK);
	allocations = test.device.allocations;
	reads = test.device.reads;
	ntfs_write_mutation_plan_close(plan);
	assert(test.device.memory == 0);
	for (index = 1; index <= allocations; index++) {
		test.device.allocations = test.device.reads = 0;
		test.device.fail_allocation = index;
		plan = (void *)(uintptr_t)1;
		result = ntfs_write_mutation_prepare(&env, request, &plan);
		assert(result == NTFS_NO_MEMORY && plan == NULL && test.device.memory == 0);
		allocation_faults++;
	}
	test.device.fail_allocation = 0;
	for (partial = 0; partial < 2; partial++) {
		test.partial = partial != 0;
		for (index = 1; index <= reads; index++) {
			test.device.allocations = test.device.reads = 0;
			test.device.fail_read = index;
			plan = (void *)(uintptr_t)1;
			assert(ntfs_write_mutation_prepare(&env, request, &plan) == NTFS_IO);
			assert(plan == NULL && test.device.memory == 0);
			read_faults++;
		}
	}
	test.device.fail_read = 0;
	test.device.reads = 0;
	assert(ntfs_write_mutation_prepare(&env, request, &plan) == NTFS_OK);
	ntfs_write_mutation_plan_close(plan);
	assert(test.device.memory == 0);
}

static void
check_count_boundaries(void)
{
	static const struct {
		struct ntfs_link_counts counts;
		enum ntfs_result result;
	} vectors[] = {{{1, 1, 0}, NTFS_OK}, {{2, 1, 1}, NTFS_OK}, {{1023, 1023, 0}, NTFS_OK},
	    {{1024, 1023, 1}, NTFS_OK}, {{1024, 1024, 0}, NTFS_TOO_MANY_LINKS},
	    {{1025, 1024, 1}, NTFS_TOO_MANY_LINKS},
	    {{UINT16_MAX, 1023, UINT16_MAX - 1023}, NTFS_TOO_MANY_LINKS},
	    {{UINT16_MAX, UINT16_MAX, 0}, NTFS_TOO_MANY_LINKS}, {{0, 0, 0}, NTFS_CORRUPT},
	    {{1, 0, 1}, NTFS_CORRUPT}, {{1, 1, 1}, NTFS_CORRUPT},
	    {{UINT16_MAX, UINT16_MAX, UINT16_MAX}, NTFS_CORRUPT}};
	struct ntfs_link_counts counts, saved;
	size_t index;

	assert(ntfs_mutation_hardlink_count_admit(NULL) == NTFS_INVALID);
	/* This helper has no environment or callback capability. Native limits are
	 * checked independently from the inline FILE capacity and uint16 overflow. */
	for (index = 0; index < sizeof(vectors) / sizeof(vectors[0]); index++) {
		counts = saved = vectors[index].counts;
		assert(ntfs_mutation_hardlink_count_admit(&counts) == vectors[index].result);
		assert(memcmp(&counts, &saved, sizeof(counts)) == 0);
	}
}

static void
check_admission(const struct ntfs_environment *env, struct test_device *test,
    const struct ntfs_write_mutation_request *request)
{
	struct ntfs_overwrite owner = {.reader = *env, .mutations = true};
	struct ntfs_write_mutation_execution *execution = (void *)(uintptr_t)1;
	struct ntfs_write_mutation_plan *plan = (void *)(uintptr_t)1;
	struct ntfs_write_mutation_request invalid = *request, saved = *request;
	size_t reads = test->device.reads, allocations = test->device.allocations;
	uint16_t source[NTFS_NAME_MAX], destination[NTFS_NAME_MAX];

	assert(
	    ntfs_write_mutation_execution_prepare(&owner, request, &execution) == NTFS_UNSUPPORTED);
	assert(execution == NULL && owner.mutation == NULL);
	invalid.replace = true;
	assert(ntfs_write_mutation_prepare(env, &invalid, &plan) == NTFS_INVALID && plan == NULL);
	assert(ntfs_write_mutation_prepare(env, request, (void *)request) == NTFS_INVALID);
	assert(memcmp(request, &saved, sizeof(saved)) == 0);
	memcpy(source, request->source.units, request->source.count * sizeof(*source));
	memcpy(destination, request->destination.units,
	    request->destination.count * sizeof(*destination));
	assert(ntfs_write_mutation_prepare(env, request, (void *)request->source.units) ==
	    NTFS_INVALID);
	assert(ntfs_write_mutation_prepare(env, request, (void *)request->destination.units) ==
	    NTFS_INVALID);
	assert(memcmp(source, request->source.units, request->source.count * sizeof(*source)) == 0);
	assert(memcmp(destination, request->destination.units,
		   request->destination.count * sizeof(*destination)) == 0);
	assert(test->device.reads == reads && test->device.allocations == allocations);
}

static void
check_case(const char *directory, const char *label, unsigned code,
    const struct ntfs_write_mutation_request *request, uint64_t physical, const char *golden)
{
	char name[TEST_LABEL_BYTES];
	uint8_t *image, *saved, *expected, *filename, *projected, *actual,
	    record[NTFS_WRITE_RECORD_BYTES];
	struct test_device test;
	struct ntfs_environment env, view;
	struct ntfs_write_mutation_plan *plan = (void *)(uintptr_t)1;
	struct ntfs_write_mutation_region region;
	struct ntfs_validation_report validation;
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *node = NULL;
	struct ntfs_link_counts counts;
	size_t bytes, expected_bytes, filename_bytes, index, offset, changed = 0;
	uint64_t number;
	int length;
	enum ntfs_result result;

	length = snprintf(name, sizeof(name), "%s.img", label);
	assert(length > 0 && (size_t)length < sizeof(name));
	image = load(directory, name, &bytes);
	saved = malloc(bytes);
	assert(saved != NULL);
	memcpy(saved, image, bytes);
	test = (struct test_device){{.data = image, .size = bytes}, false};
	env = environment(&test);
	check_admission(&env, &test, request);
	result = ntfs_write_mutation_prepare(&env, request, &plan);
	if (result != (enum ntfs_result)code) {
		fprintf(stderr, "%s: result %s expected %s\n", label, ntfs_result_string(result),
		    ntfs_result_string((enum ntfs_result)code));
	}
	assert(result == (enum ntfs_result)code);
	if (result == NTFS_OK) {
		expected = load(directory, golden, &expected_bytes);
		assert(expected_bytes == sizeof(record));
		length = snprintf(name, sizeof(name), "%s.filename", label);
		assert(length > 0 && (size_t)length < sizeof(name));
		filename = load(directory, name, &filename_bytes);
		assert(ntfs_write_mutation_plan_reference(plan) == request->reference);
		assert(ntfs_write_mutation_plan_view(plan, &view) == NTFS_OK);
		assert(view.read(view.context, physical, record, sizeof(record)) == NTFS_OK);
		assert(ntfs_record_decode(record, sizeof(record), false) == NTFS_OK);
		normalize(record, expected, sizeof(record), false);
		assert(memcmp(record, expected, sizeof(record)) == 0);
		assert(ntfs_mount(&view, NULL, &volume) == NTFS_OK);
		assert(ntfs_node_open(volume, request->reference, &node) == NTFS_OK);
		assert(ntfs_node_link_counts(node, &counts) == NTFS_OK);
		assert(counts.physical_names ==
		    ntfs_u16(((const struct ntfs_disk_record *)(const void *)expected)->links));
		ntfs_node_close(node);
		assert(ntfs_unmount(volume) == NTFS_OK);
		check_keys(&env, &view, request, filename, filename_bytes);
		check_parent_attributes(&env, &view, request->source.parent_reference);
		check_parent_attributes(&env, &view, request->destination.parent_reference);
		assert(ntfs_validate(&view, NULL, NULL, &validation) == NTFS_OK);
		assert(validation.complete);
		projected = malloc(bytes);
		assert(projected != NULL);
		memcpy(projected, image, bytes);
		for (index = 0; index < ntfs_write_mutation_plan_count(plan); index++) {
			assert(ntfs_write_mutation_plan_region(plan, index, &region) == NTFS_OK);
			assert(region.kind != NTFS_WRITE_MUTATION_DATA);
			assert(ntfs_bounds(region.physical, region.bytes, bytes));
			assert(memcmp(region.before, image + region.physical, region.bytes) == 0);
			if (region.kind == NTFS_WRITE_MUTATION_FILE) {
				for (offset = 0; offset < region.bytes;
				    offset += NTFS_WRITE_RECORD_BYTES) {
					number = (region.target.logical_offset + offset) /
					    NTFS_WRITE_RECORD_BYTES;
					if (number !=
						(request->reference & NTFS_REFERENCE_RECORD_MASK) &&
					    number !=
						(request->destination.parent_reference &
						    NTFS_REFERENCE_RECORD_MASK) &&
					    number != NTFS_BITMAP_RECORD) {
						assert(memcmp(region.before + offset,
							   region.after + offset,
							   NTFS_WRITE_RECORD_BYTES) == 0);
					}
				}
			}
			memcpy(projected + region.physical, region.after, region.bytes);
			changed += region.bytes;
		}
		assert(changed > 0);
		actual = malloc(bytes);
		assert(actual != NULL);
		assert(view.read(view.context, 0, actual, bytes) == NTFS_OK);
		assert(memcmp(actual, projected, bytes) == 0);
		free(actual);
		free(projected);
		free(filename);
		free(expected);
		check_program(&test, &env, plan);
		if (strcmp(label, "cross-parent") == 0 || strcmp(label, "index-split") == 0) {
			faults(image, bytes, request);
		}
	} else {
		assert(plan == NULL);
	}
	assert(test.device.memory == 0 && memcmp(image, saved, bytes) == 0);
	free(saved);
	free(image);
	cases++;
}

int
main(int argc, char **argv)
{
	char path[TEST_PATH_BYTES], label[TEST_LABEL_BYTES], golden[TEST_LABEL_BYTES];
	char source[NTFS_NAME_MAX + 1], destination[NTFS_NAME_MAX + 1];
	uint16_t source_units[NTFS_NAME_MAX], destination_units[NTFS_NAME_MAX];
	struct ntfs_write_mutation_request request = {.kind = NTFS_WRITE_CREATE_HARD_LINK};
	uint64_t physical;
	unsigned code;
	FILE *manifest;
	int count;

	assert(argc == 2);
	check_count_boundaries();
	count = snprintf(path, sizeof(path), "%s/cases.txt", argv[1]);
	assert(count > 0 && (size_t)count < sizeof(path));
	manifest = fopen(path, "r");
	assert(manifest != NULL);
	while (fscanf(manifest,
		   "%127s %u %" SCNu64 " %" SCNu64 " %255s %" SCNu64 " %255s %" SCNu64 " %127s",
		   label, &code, &request.reference, &request.source.parent_reference, source,
		   &request.destination.parent_reference, destination, &physical, golden) == 9) {
		assert(ntfs_utf8_to_utf16(source, strlen(source), source_units, NTFS_NAME_MAX,
			   &request.source.count) == NTFS_OK);
		assert(ntfs_utf8_to_utf16(destination, strlen(destination), destination_units,
			   NTFS_NAME_MAX, &request.destination.count) == NTFS_OK);
		request.source.units = source_units;
		request.destination.units = destination_units;
		check_case(argv[1], label, code, &request, physical, golden);
	}
	assert(feof(manifest) && !ferror(manifest) && fclose(manifest) == 0);
	assert(cases == 25);
	printf("hard-link preparation: 13 count boundaries, %zu image cases, "
	       "%zu allocation faults, %zu read faults, "
	       "%zu program allocation faults, %zu inverse prefixes\n",
	    cases, allocation_faults, read_faults, program_faults, inverse_prefixes);
	return 0;
}
