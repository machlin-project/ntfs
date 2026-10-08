/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_directory_internal.h"
#include "fuzz_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_KEYS = 701,
	TEST_NAME_PREFIX = 4,
	TEST_FILLER_NAME_UNITS = 88,
	TEST_DONOR_NAME_UNITS = 175,
	TEST_PREDECESSOR_NAME_UNITS = 128,
	TEST_FILLED_NODE_BYTES = NTFS_MUTATION_INDEX_CONTENT_BYTES - 4 * NTFS_WIRE_ALIGNMENT
};

static struct ntfs_mutation_index_node *
child_node(struct ntfs_mutation_index_tree *tree, uint64_t vcn)
{
	size_t index;

	for (index = 0; index < tree->count; index++) {
		if (tree->nodes[index]->vcn == vcn && tree->nodes[index]->live) {
			return tree->nodes[index];
		}
	}
	assert(false);
	return NULL;
}

static void
walk(struct ntfs_mutation_directory *directory, struct ntfs_mutation_index_node *node,
    size_t *ordinal, size_t *nodes, unsigned depth)
{
	const struct ntfs_disk_index_entry *entry;
	const struct ntfs_mutation_key *key;
	size_t position, length;
	uint16_t flags;

	assert(depth < NTFS_DIRECTORY_DEPTH);
	assert(node->used <= (node == directory->tree->root ? NTFS_WRITE_RECORD_BYTES
							    : NTFS_MUTATION_INDEX_CONTENT_BYTES));
	(*nodes)++;
	for (position = 0; position < node->used; position += length) {
		entry = (const void *)(node->entries + position);
		length = ntfs_u16(entry->length);
		flags = ntfs_u16(entry->flags);
		assert(length >= sizeof(*entry) && length % NTFS_WIRE_ALIGNMENT == 0 &&
		    length <= node->used - position);
		assert(((flags & NTFS_INDEX_CHILD) != 0) == node->child);
		if (node->child) {
			walk(directory,
			    child_node(directory->tree,
				ntfs_u64(node->entries + position + length - sizeof(uint64_t))),
			    ordinal, nodes, depth + 1);
		}
		if ((flags & NTFS_INDEX_END) != 0) {
			assert(ntfs_u16(entry->key_length) == 0 && position + length == node->used);
			return;
		}
		assert(*ordinal < directory->count);
		key = &directory->keys[(*ordinal)++];
		assert(ntfs_u64(entry->reference) == key->reference &&
		    ntfs_u16(entry->key_length) == key->bytes);
		assert(memcmp(entry + 1, key->value, key->bytes) == 0);
	}
	assert(false);
}

static void
check_tree(struct ntfs_mutation_directory *directory)
{
	size_t index, ordinal = 0, nodes = 0, live = 1;

	walk(directory, directory->tree->root, &ordinal, &nodes, 0);
	for (index = 0; index < directory->tree->count; index++) {
		live += directory->tree->nodes[index]->live;
	}
	assert(ordinal == directory->count && nodes == live);
}

static void
name_key(struct ntfs_mutation_key *key, unsigned number)
{
	struct ntfs_disk_filename *name = (void *)key->value;
	size_t index;

	memset(key, 0, sizeof(*key));
	key->reference =
	    (UINT64_C(1) << NTFS_REFERENCE_SEQUENCE_SHIFT) | (NTFS_FIRST_USER_RECORD + number);
	name->length =
	    (uint8_t)(TEST_NAME_PREFIX + (number * 97u) % (NTFS_NAME_MAX - TEST_NAME_PREFIX));
	name->name_namespace = NTFS_NAMESPACE_POSIX;
	key->bytes = (uint16_t)(sizeof(*name) + name->length * NTFS_UTF16_UNIT_BYTES);
	for (index = 0; index < name->length; index++) {
		ntfs_put_u16(key->value + sizeof(*name) + index * NTFS_UTF16_UNIT_BYTES,
		    index < TEST_NAME_PREFIX
			? (uint16_t)('A' + ((number >> ((TEST_NAME_PREFIX - index - 1) * 4)) & 15))
			: 'x');
	}
}

static void
load_node(struct ntfs_write_mutation_plan *plan, struct ntfs_mutation_directory *directory,
    uint64_t vcn, const unsigned *keys, const uint64_t *children, size_t count)
{
	uint8_t *buffer;
	struct ntfs_disk_index_header *header;
	size_t index, used;

	buffer = calloc(1, NTFS_WRITE_CLUSTER_BYTES);
	assert(buffer != NULL);
	header = (void *)buffer;
	header->flags = children == NULL ? 0 : NTFS_INDEX_LARGE;
	used = sizeof(*header);
	for (index = 0; index <= count; index++) {
		used += ntfs_mutation_index_encode(buffer + used,
		    index == count ? NULL : &directory->keys[keys[index]], children != NULL,
		    children == NULL ? 0 : children[index]);
	}
	ntfs_put_u32(header->entries_offset, sizeof(*header));
	ntfs_put_u32(header->used, (uint32_t)used);
	ntfs_put_u32(header->allocated, NTFS_WRITE_CLUSTER_BYTES);
	assert(ntfs_mutation_index_load(plan, directory, vcn, buffer, NTFS_WRITE_CLUSTER_BYTES) ==
	    NTFS_OK);
	free(buffer);
}

static void
cascading_delete(struct ntfs_write_mutation_plan *plan, struct ntfs_mutation_record *record)
{
	/* The rightmost leaf holds the predecessor of the outer separator. Its
	 * deletion empties that leaf. A full left sibling rotates a long key into
	 * the inner node, splitting it. The outer node must temporarily hold both
	 * the longer predecessor and the newly promoted key before its own split. */
	static const unsigned numbers[] = {1000, 2000, 3000, 4000, 5000, 6000, 7000, 7100, 7200,
	    7300, 7400, 7500, 7600, 7700, 7800, 7900, 8000, 8100, 8200, 8300, 8700, 8800, 8900,
	    9000};
	static const unsigned outer[] = {0, 1, 2, 3, 4, 5, 6, 23};
	static const unsigned inner[] = {7, 8, 9, 10, 11, 12, 13, 21};
	static const unsigned donor[] = {14, 15, 16, 17, 18, 19, 20}, predecessor[] = {22};
	static const uint64_t outer_children[] = {5, 7, 9, 11, 13, 15, 17, 1, 19};
	static const uint64_t inner_children[] = {21, 22, 23, 24, 25, 26, 27, 2, 3};
	struct ntfs_mutation_directory directory = {.record = record};
	struct ntfs_disk_filename *filename;
	struct ntfs_mutation_key *key;
	uint64_t child = 0;
	size_t index, unit, units;

	directory.count = directory.capacity = sizeof(numbers) / sizeof(numbers[0]);
	directory.keys = ntfs_mutation_allocate(plan, directory.capacity * sizeof(*directory.keys));
	assert(directory.keys != NULL);
	for (index = 0; index < directory.count; index++) {
		key = &directory.keys[index];
		name_key(key, numbers[index]);
		units = index == 6 || index == 13 ? TEST_FILLER_NAME_UNITS
		    : index == 14		  ? TEST_DONOR_NAME_UNITS
		    : index == 21 || index == 23  ? TEST_NAME_PREFIX
		    : index == 22		  ? TEST_PREDECESSOR_NAME_UNITS
						  : NTFS_NAME_MAX;
		filename = (void *)key->value;
		filename->length = (uint8_t)units;
		key->bytes = (uint16_t)(sizeof(*filename) + units * NTFS_UTF16_UNIT_BYTES);
		for (unit = TEST_NAME_PREFIX; unit < units; unit++) {
			ntfs_put_u16(
			    key->value + sizeof(*filename) + unit * NTFS_UTF16_UNIT_BYTES, 'x');
		}
	}
	load_node(plan, &directory, NTFS_MUTATION_INDEX_ROOT_VCN, NULL, &child, 0);
	load_node(plan, &directory, 0, outer, outer_children, sizeof(outer) / sizeof(outer[0]));
	load_node(plan, &directory, 1, inner, inner_children, sizeof(inner) / sizeof(inner[0]));
	load_node(plan, &directory, 2, donor, NULL, sizeof(donor) / sizeof(donor[0]));
	load_node(plan, &directory, 3, predecessor, NULL, 1);
	for (index = 5; index <= 19; index += 2) {
		child = index + 1;
		load_node(plan, &directory, index, NULL, &child, 0);
		load_node(plan, &directory, child, NULL, NULL, 0);
	}
	for (index = 21; index <= 27; index++) {
		load_node(plan, &directory, index, NULL, NULL, 0);
	}
	assert(child_node(directory.tree, 0)->used == TEST_FILLED_NODE_BYTES &&
	    child_node(directory.tree, 1)->used == TEST_FILLED_NODE_BYTES &&
	    child_node(directory.tree, 2)->used == TEST_FILLED_NODE_BYTES);
	check_tree(&directory);
	assert(ntfs_mutation_directory_remove(plan, &directory, directory.count - 1) == NTFS_OK);
	check_tree(&directory);
	ntfs_mutation_directory_close(plan, &directory);
}

static void
exercise(unsigned order)
{
	struct fuzz_device device = {0};
	struct ntfs_volume volume = {0};
	struct ntfs_write_mutation_plan *plan;
	struct ntfs_mutation_record *record;
	struct ntfs_mutation_directory directory = {0};
	struct ntfs_mutation_key key;
	struct ntfs_disk_record *file;
	struct ntfs_disk_index_header header = {0};
	uint8_t root[sizeof(header) + sizeof(struct ntfs_disk_index_entry)];
	uint8_t chain[sizeof(header) + sizeof(struct ntfs_disk_index_entry) + sizeof(uint64_t)];
	size_t index, position, first;
	unsigned number;

	volume.env = fuzz_environment(&device);
	ntfs_default_limits(&volume.limits);
	volume.upcase = calloc(NTFS_UPCASE_BYTES, 1);
	plan = calloc(1, sizeof(*plan));
	record = calloc(1, sizeof(*record));
	assert(volume.upcase != NULL && plan != NULL && record != NULL);
	for (index = 0; index < NTFS_UPCASE_BYTES / NTFS_UTF16_UNIT_BYTES; index++) {
		ntfs_put_u16(volume.upcase + index * NTFS_UTF16_UNIT_BYTES, (uint16_t)index);
	}
	plan->source = volume.env;
	plan->volume = &volume;
	directory.record = record;
	file = (void *)record->bytes;
	first = ntfs_mutation_align_bytes(sizeof(*file));
	ntfs_put_u32(file->used, (uint32_t)(first + NTFS_WIRE_ALIGNMENT));
	ntfs_put_u16(file->attrs_offset, (uint16_t)first);
	ntfs_put_u32(record->bytes + first, NTFS_ATTR_END);
	ntfs_put_u32(header.entries_offset, sizeof(header));
	ntfs_put_u32(header.used, sizeof(root));
	ntfs_put_u32(header.allocated, sizeof(root));
	memcpy(root, &header, sizeof(header));
	(void)ntfs_mutation_index_encode(root + sizeof(header), NULL, false, 0);
	assert(ntfs_mutation_index_load(
		   plan, &directory, NTFS_MUTATION_INDEX_ROOT_VCN, root, sizeof(root)) == NTFS_OK);
	for (index = 0; index < TEST_KEYS; index++) {
		number = order == 0 ? (unsigned)index
		    : order == 1    ? TEST_KEYS - 1 - (unsigned)index
				    : (unsigned)(index * 307u % TEST_KEYS);
		name_key(&key, number);
		assert(ntfs_mutation_directory_add(
			   plan, &directory, key.reference, key.value, key.bytes) == NTFS_OK);
		check_tree(&directory);
	}
	assert(directory.tree->count > 16);
	for (index = 0; index < TEST_KEYS; index += 13) {
		key = directory.keys[index];
		ntfs_put_u64(((struct ntfs_disk_filename *)(void *)key.value)->size, index + 1);
		assert(ntfs_mutation_directory_update(
			   plan, &directory, index, key.value, key.bytes) == NTFS_OK);
		check_tree(&directory);
	}
	for (index = 0; index < TEST_KEYS; index++) {
		position = order == 0 ? 0
		    : order == 1      ? directory.count - 1
				      : (index * 307u) % directory.count;
		assert(ntfs_mutation_directory_remove(plan, &directory, position) == NTFS_OK);
		check_tree(&directory);
	}
	assert(!directory.tree->root->child);
	/* A valid older tree can have empty children at unequal heights. Deleting
	 * its only separator retires the empty chain without changing key order. */
	assert(ntfs_mutation_index_load(plan, &directory, 0, root, sizeof(root)) == NTFS_OK);
	assert(ntfs_mutation_index_load(plan, &directory, 2, root, sizeof(root)) == NTFS_OK);
	header.flags = NTFS_INDEX_LARGE;
	ntfs_put_u32(header.used, sizeof(chain));
	ntfs_put_u32(header.allocated, sizeof(chain));
	memcpy(chain, &header, sizeof(header));
	(void)ntfs_mutation_index_encode(chain + sizeof(header), NULL, true, 2);
	assert(ntfs_mutation_index_load(plan, &directory, 1, chain, sizeof(chain)) == NTFS_OK);
	name_key(&key, 1);
	directory.keys[0] = key;
	directory.count = 1;
	directory.tree->root->child = true;
	first = ntfs_mutation_index_encode(directory.tree->root->entries, &key, true, 0);
	directory.tree->root->used = first +
	    ntfs_mutation_index_encode(directory.tree->root->entries + first, NULL, true, 1);
	check_tree(&directory);
	assert(ntfs_mutation_directory_remove(plan, &directory, 0) == NTFS_OK);
	check_tree(&directory);
	assert(!directory.tree->root->child);
	ntfs_mutation_directory_close(plan, &directory);
	if (order == 0) {
		cascading_delete(plan, record);
	}
	assert(device.memory == 0 && plan->live_bytes == 0);
	free(volume.upcase);
	free(plan);
	free(record);
}

int
main(void)
{
	exercise(0);
	exercise(1);
	exercise(2);
	puts("variable-length directory insertion, internal deletion, split, merge, root "
	     "transitions and metadata updates passed");
	return 0;
}
