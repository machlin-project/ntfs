/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_directory_internal.h"
#include "fuzz_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Test input, not an NTFS format: little-endian header followed by operations.
 * Keep in sync with scripts/directory_fuzz_seeds.py. Trailing bytes are ignored. */
struct directory_input_header {
	uint8_t initial[2], fail_allocation[2], order, case_sensitive, salt[2];
};

struct directory_input_operation {
	uint8_t kind, length, identifier[2], stamp[4];
};

_Static_assert(sizeof(struct directory_input_header) == 8, "directory input header");
_Static_assert(sizeof(struct directory_input_operation) == 8, "directory input operation");

enum {
	DIRECTORY_KEYS = 768,
	DIRECTORY_PREFIX = 4,
	DIRECTORY_INPUT_BYTES = 32768,
	DIRECTORY_UNICODE_MODE = 2,
	DIRECTORY_LATIN_SMALL_E_ACUTE = 0x00e9,
	DIRECTORY_LATIN_CAPITAL_E_ACUTE = 0x00c9,
	DIRECTORY_GREEK_SMALL_OMEGA = 0x03c9,
	DIRECTORY_GREEK_CAPITAL_OMEGA = 0x03a9,
	DIRECTORY_CJK_MIDDLE = 0x4e2d,
	DIRECTORY_ZERO_WIDTH_JOINER = 0x200d,
	DIRECTORY_OPERATIONS = (DIRECTORY_INPUT_BYTES - sizeof(struct directory_input_header)) /
	    sizeof(struct directory_input_operation)
};

enum {
	DIRECTORY_ADD,
	DIRECTORY_REMOVE,
	DIRECTORY_UPDATE,
	DIRECTORY_RENAME,
	DIRECTORY_LOOKUP,
	DIRECTORY_CLEAR,
	DIRECTORY_KIND_COUNT = DIRECTORY_CLEAR - DIRECTORY_ADD + 1
};

struct model_key {
	bool present;
	uint8_t length;
	uint16_t generation;
	uint16_t suffix;
	uint32_t stamp;
};

struct directory_model {
	struct fuzz_device device;
	struct ntfs_volume volume;
	struct ntfs_write_mutation_plan plan;
	struct ntfs_mutation_record record;
	struct ntfs_mutation_directory directory;
	struct model_key keys[DIRECTORY_KEYS];
	struct ntfs_mutation_key expected_keys[DIRECTORY_KEYS];
	struct ntfs_mutation_index_node *by_vcn[NTFS_MUTATION_MAX_REGIONS];
	bool visited[NTFS_MUTATION_MAX_REGIONS];
	bool unicode;
};

static void
model_key(struct ntfs_mutation_key *key, unsigned identifier, const struct model_key *model)
{
	struct ntfs_disk_filename *name;
	size_t unit;
	uint16_t value;

	memset(key, 0, sizeof(*key));
	key->reference = ((uint64_t)model->generation << NTFS_REFERENCE_SEQUENCE_SHIFT) |
	    (NTFS_FIRST_USER_RECORD + identifier);
	name = (void *)key->value;
	name->length = model->length;
	name->name_namespace = NTFS_NAMESPACE_POSIX;
	ntfs_put_u64(
	    name->parent, (UINT64_C(1) << NTFS_REFERENCE_SEQUENCE_SHIFT) | NTFS_ROOT_RECORD);
	ntfs_put_u64(name->size, model->stamp);
	key->bytes = (uint16_t)(sizeof(*name) + name->length * NTFS_UTF16_UNIT_BYTES);
	/* The fixed prefix sorts by identifier independently of the tree's own
	 * comparator. The suffix makes key length vary across split boundaries. */
	for (unit = 0; unit < name->length; unit++) {
		value = unit < DIRECTORY_PREFIX
		    ? (uint16_t)('A' + ((identifier >> ((DIRECTORY_PREFIX - unit - 1) * 4)) & 15))
		    : model->suffix;
		ntfs_put_u16(key->value + sizeof(*name) + unit * NTFS_UTF16_UNIT_BYTES, value);
	}
}

static void
check_key(struct directory_model *model, const struct ntfs_mutation_key *actual, size_t *next)
{
	const struct ntfs_mutation_key *expected;

	while (*next < DIRECTORY_KEYS && !model->keys[*next].present) {
		(*next)++;
	}
	assert(*next < DIRECTORY_KEYS);
	expected = &model->expected_keys[*next];
	assert(actual->reference == expected->reference && actual->bytes == expected->bytes);
	assert(memcmp(actual->value, expected->value, expected->bytes) == 0);
	(*next)++;
}

static void
walk_tree(struct directory_model *model, struct ntfs_mutation_index_node *node, size_t *next,
    size_t *count, unsigned depth)
{
	const struct ntfs_disk_index_entry *entry;
	struct ntfs_mutation_key actual;
	size_t offset, length, trailer;
	uint64_t vcn;
	uint16_t flags;

	assert(depth < NTFS_DIRECTORY_DEPTH && node != NULL && node->live);
	assert(node->used <= (node == model->directory.tree->root
				     ? NTFS_WRITE_RECORD_BYTES
				     : NTFS_MUTATION_INDEX_CONTENT_BYTES));
	for (offset = 0; offset < node->used; offset += length) {
		assert(node->used - offset >= sizeof(*entry));
		entry = (const void *)(node->entries + offset);
		length = ntfs_u16(entry->length);
		flags = ntfs_u16(entry->flags);
		trailer = node->child ? sizeof(uint64_t) : 0;
		assert(length >= sizeof(*entry) + trailer && length % NTFS_WIRE_ALIGNMENT == 0 &&
		    length <= node->used - offset &&
		    (flags & ~(NTFS_INDEX_CHILD | NTFS_INDEX_END)) == 0);
		assert(((flags & NTFS_INDEX_CHILD) != 0) == node->child);
		if (node->child) {
			vcn = ntfs_u64(node->entries + offset + length - trailer);
			assert(vcn < NTFS_MUTATION_MAX_REGIONS && !model->visited[vcn]);
			model->visited[vcn] = true;
			walk_tree(model, model->by_vcn[vcn], next, count, depth + 1);
		}
		if ((flags & NTFS_INDEX_END) != 0) {
			assert(ntfs_u16(entry->key_length) == 0 && offset + length == node->used);
			return;
		}
		actual.reference = ntfs_u64(entry->reference);
		actual.bytes = ntfs_u16(entry->key_length);
		assert(actual.bytes <= sizeof(actual.value) &&
		    actual.bytes <= length - sizeof(*entry) - trailer);
		memcpy(actual.value, entry + 1, actual.bytes);
		check_key(model, &actual, next);
		(*count)++;
	}
	assert(false);
}

static void
check_model(struct directory_model *model)
{
	struct ntfs_mutation_index_tree *tree = model->directory.tree;
	size_t index, next = 0, count = 0, expected = 0;
	uint64_t vcn;

	memset(model->by_vcn, 0, sizeof(model->by_vcn));
	memset(model->visited, 0, sizeof(model->visited));
	for (index = 0; index < DIRECTORY_KEYS; index++) {
		expected += model->keys[index].present;
	}
	assert(model->directory.count == expected);
	for (index = 0; index < expected; index++) {
		check_key(model, &model->directory.keys[index], &next);
	}
	assert(tree != NULL && tree->count <= NTFS_MUTATION_MAX_REGIONS);
	for (index = 0; index < tree->count; index++) {
		vcn = tree->nodes[index]->vcn;
		assert(vcn < NTFS_MUTATION_MAX_REGIONS && model->by_vcn[vcn] == NULL);
		model->by_vcn[vcn] = tree->nodes[index];
	}
	next = 0;
	walk_tree(model, tree->root, &next, &count, 0);
	assert(count == expected);
	for (index = 0; index < tree->count; index++) {
		assert(model->visited[tree->nodes[index]->vcn] == tree->nodes[index]->live);
	}
	if (expected == 0) {
		assert(!tree->root->child);
	}
}

static enum ntfs_result
operate(struct directory_model *model, unsigned kind, unsigned identifier, uint8_t length,
    uint32_t stamp)
{
	struct model_key *state = &model->keys[identifier], next = *state;
	struct ntfs_mutation_key key;
	struct ntfs_write_name name;
	uint16_t units[NTFS_NAME_MAX];
	size_t position = 0, index;
	enum ntfs_result result;

	/* Each command represents a new bounded operation on the retained private
	 * model. Allocation fault ordinals remain global to the complete input. */
	model->plan.work = 0;
	model->plan.allocation_calls = 0;
	model->plan.allocation_bytes = 0;
	for (index = 0; index < identifier; index++) {
		position += model->keys[index].present;
	}
	if (kind == DIRECTORY_LOOKUP || (kind != DIRECTORY_ADD && !state->present)) {
		next.length = state->present ? state->length : DIRECTORY_PREFIX;
		model_key(&key, identifier, &next);
		for (index = 0; index < next.length; index++) {
			units[index] = ntfs_u16(key.value + sizeof(struct ntfs_disk_filename) +
			    index * NTFS_UTF16_UNIT_BYTES);
		}
		name = (struct ntfs_write_name){.units = units, .count = next.length};
		result =
		    ntfs_mutation_directory_find(&model->plan, &model->directory, &name, &index);
		assert(result == (state->present ? NTFS_OK : NTFS_NOT_FOUND));
		assert(!state->present || index == position);
		if (kind == DIRECTORY_LOOKUP) {
			/* Prefix identifiers stay unique. A case-only alternate query has
			 * an independently known verdict under the selected policy. */
			for (index = 0; index < next.length; index++) {
				if (units[index] >= 'A' && units[index] <= 'Z') {
					units[index] = (uint16_t)(units[index] - 'A' + 'a');
				} else if (units[index] == 'x') {
					units[index] = 'X';
				} else if (units[index] == DIRECTORY_LATIN_SMALL_E_ACUTE) {
					units[index] = DIRECTORY_LATIN_CAPITAL_E_ACUTE;
				} else if (units[index] == DIRECTORY_GREEK_CAPITAL_OMEGA) {
					units[index] = DIRECTORY_GREEK_SMALL_OMEGA;
				}
			}
			result = ntfs_mutation_directory_find(
			    &model->plan, &model->directory, &name, &index);
			assert(result == (state->present && !model->directory.case_sensitive
					     ? NTFS_OK
					     : NTFS_NOT_FOUND));
			assert(result != NTFS_OK || index == position);
		}
		return NTFS_OK;
	}
	if (kind == DIRECTORY_REMOVE || kind == DIRECTORY_RENAME) {
		result = ntfs_mutation_directory_remove(&model->plan, &model->directory, position);
		if (result != NTFS_OK) {
			return result;
		}
		state->present = false;
		if (kind == DIRECTORY_REMOVE) {
			return NTFS_OK;
		}
	}
	if (kind == DIRECTORY_ADD && state->present) {
		model_key(&key, identifier, state);
		result = ntfs_mutation_directory_add(
		    &model->plan, &model->directory, key.reference, key.value, key.bytes);
		assert(result == NTFS_EXISTS);
		return NTFS_OK;
	}
	if (kind != DIRECTORY_UPDATE) {
		const uint16_t suffixes[] = {DIRECTORY_LATIN_SMALL_E_ACUTE,
		    DIRECTORY_GREEK_CAPITAL_OMEGA, DIRECTORY_CJK_MIDDLE, DIRECTORY_ZERO_WIDTH_JOINER};

		next.length =
		    (uint8_t)(DIRECTORY_PREFIX + length % (NTFS_NAME_MAX - DIRECTORY_PREFIX + 1));
		next.suffix = model->unicode
		    ? suffixes[identifier % (sizeof(suffixes) / sizeof(suffixes[0]))]
		    : 'x';
		if (kind == DIRECTORY_ADD) {
			next.generation++;
		}
	}
	next.stamp = stamp;
	next.present = true;
	model_key(&key, identifier, &next);
	result = kind == DIRECTORY_UPDATE
	    ? ntfs_mutation_directory_update(
		  &model->plan, &model->directory, position, key.value, key.bytes)
	    : ntfs_mutation_directory_add(
		  &model->plan, &model->directory, key.reference, key.value, key.bytes);
	if (result == NTFS_OK) {
		*state = next;
		/* Author once from the independent operation model. Every later flat
		 * and wire walk still compares every byte; avoid reauthoring unchanged
		 * long names thousands of times under coverage instrumentation. */
		model->expected_keys[identifier] = key;
	}
	return result;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const struct directory_input_header *input;
	const struct directory_input_operation *operation;
	struct directory_model *model;
	struct ntfs_disk_record *file;
	struct ntfs_disk_index_header *header;
	uint8_t root[sizeof(*header) + sizeof(struct ntfs_disk_index_entry)] = {0};
	size_t index, offset, first, count;
	unsigned identifier, kind, initial, salt;
	enum ntfs_result result;

	if (size < sizeof(*input) || size > DIRECTORY_INPUT_BYTES) {
		return 0;
	}
	input = (const void *)data;
	model = calloc(1, sizeof(*model));
	assert(model != NULL);
	model->device.fail_allocation = ntfs_u16(input->fail_allocation);
	model->volume.env = fuzz_environment(&model->device);
	ntfs_default_limits(&model->volume.limits);
	model->volume.upcase = calloc(1, NTFS_UPCASE_BYTES);
	assert(model->volume.upcase != NULL);
	for (index = 0; index < NTFS_UPCASE_BYTES / NTFS_UTF16_UNIT_BYTES; index++) {
		ntfs_put_u16(model->volume.upcase + index * NTFS_UTF16_UNIT_BYTES,
		    (uint16_t)(index >= 'a' && index <= 'z' ? index - 'a' + 'A' : index));
	}
	ntfs_put_u16(model->volume.upcase + DIRECTORY_LATIN_SMALL_E_ACUTE * NTFS_UTF16_UNIT_BYTES,
	    DIRECTORY_LATIN_CAPITAL_E_ACUTE);
	ntfs_put_u16(model->volume.upcase + DIRECTORY_GREEK_SMALL_OMEGA * NTFS_UTF16_UNIT_BYTES,
	    DIRECTORY_GREEK_CAPITAL_OMEGA);
	model->unicode = (input->case_sensitive & DIRECTORY_UNICODE_MODE) != 0;
	model->plan.source = model->volume.env;
	model->plan.volume = &model->volume;
	model->directory.record = &model->record;
	model->directory.case_sensitive = (input->case_sensitive & 1) != 0;
	file = (void *)model->record.bytes;
	first = ntfs_mutation_align_bytes(sizeof(*file));
	ntfs_put_u32(file->used, (uint32_t)(first + NTFS_WIRE_ALIGNMENT));
	ntfs_put_u16(file->attrs_offset, (uint16_t)first);
	ntfs_put_u32(model->record.bytes + first, NTFS_ATTR_END);
	header = (void *)root;
	ntfs_put_u32(header->entries_offset, sizeof(*header));
	ntfs_put_u32(header->used, sizeof(root));
	ntfs_put_u32(header->allocated, sizeof(root));
	(void)ntfs_mutation_index_encode(root + sizeof(*header), NULL, false, 0);
	result = ntfs_mutation_index_load(
	    &model->plan, &model->directory, NTFS_MUTATION_INDEX_ROOT_VCN, root, sizeof(root));
	initial = ntfs_u16(input->initial) % (DIRECTORY_KEYS + 1);
	salt = ntfs_u16(input->salt);
	for (index = 0; result == NTFS_OK && index < initial; index++) {
		identifier = input->order % 3 == 0 ? (unsigned)index
		    : input->order % 3 == 1	   ? initial - 1 - (unsigned)index
						   : (unsigned)((index * 307u) % DIRECTORY_KEYS);
		result = operate(
		    model, DIRECTORY_ADD, identifier, (uint8_t)(identifier * 97u + salt), salt);
		if (result == NTFS_OK) {
			check_model(model);
		}
	}
	count = (size - sizeof(*input)) / sizeof(*operation);
	assert(count <= DIRECTORY_OPERATIONS);
	for (offset = 0; result == NTFS_OK && offset < count; offset++) {
		operation = (const void *)(data + sizeof(*input) + offset * sizeof(*operation));
		kind = DIRECTORY_ADD + operation->kind % DIRECTORY_KIND_COUNT;
		identifier = ntfs_u16(operation->identifier) % DIRECTORY_KEYS;
		if (kind == DIRECTORY_CLEAR) {
			/* One bounded removal per opcode keeps arbitrary inputs cheap. */
			for (index = 0; index < DIRECTORY_KEYS; index++) {
				identifier = (identifier + 1) % DIRECTORY_KEYS;
				if (model->keys[identifier].present) {
					break;
				}
			}
			kind = DIRECTORY_REMOVE;
		}
		result =
		    operate(model, kind, identifier, operation->length, ntfs_u32(operation->stamp));
		if (result == NTFS_OK) {
			check_model(model);
		}
	}
	/* A failed private plan is abandoned, never continued or published. */
	assert(
	    result == NTFS_OK || (result == NTFS_NO_MEMORY && model->device.fail_allocation != 0));
	ntfs_mutation_directory_close(&model->plan, &model->directory);
	assert(
	    model->device.memory == 0 && model->plan.live_bytes == 0 && model->device.reads == 0);
	free(model->volume.upcase);
	free(model);
	return 0;
}

#ifdef NTFS_FUZZ_STANDALONE
int
main(int argc, char **argv)
{
	uint8_t *data;
	size_t bytes;
	int index;
	FILE *file;

	assert(argc > 1);
	data = malloc(DIRECTORY_INPUT_BYTES + 1);
	assert(data != NULL);
	for (index = 1; index < argc; index++) {
		file = fopen(argv[index], "rb");
		assert(file != NULL);
		bytes = fread(data, 1, DIRECTORY_INPUT_BYTES + 1, file);
		assert(!ferror(file) && bytes <= DIRECTORY_INPUT_BYTES && fclose(file) == 0);
		LLVMFuzzerTestOneInput(data, bytes);
	}
	free(data);
	puts("directory mutation model replay passed");
	return 0;
}
#endif
