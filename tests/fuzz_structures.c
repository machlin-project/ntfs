/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include "fuzz_device.h"
#include <ntfs/security.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum ntfs_fuzz_target {
	NTFS_FUZZ_MAPPING_PAIRS,
	NTFS_FUZZ_ATTRIBUTE_LIST,
	NTFS_FUZZ_INDEX_ROOT,
	NTFS_FUZZ_INDEX_BLOCK,
	NTFS_FUZZ_LZNT1,
	NTFS_FUZZ_REPARSE,
	NTFS_FUZZ_SECURITY
};

#ifndef NTFS_FUZZ_TARGET
#define NTFS_FUZZ_TARGET NTFS_FUZZ_MAPPING_PAIRS
#endif

enum {
	FUZZ_STRUCTURE_INPUT_BYTES = 32768,
	FUZZ_STRUCTURE_RECORD_BYTES = 65536,
	FUZZ_STRUCTURE_CLUSTER_BYTES = 4096,
	FUZZ_STRUCTURE_CLUSTERS = 1024,
	FUZZ_STRUCTURE_INDEX_BYTES = 4096,
	FUZZ_STRUCTURE_MAX_RUNS = 1024,
	FUZZ_STRUCTURE_DIRECTORY_NODES = 128,
	FUZZ_STRUCTURE_ENTRIES = 128,
	FUZZ_STRUCTURE_READ_BYTES = 512,
	FUZZ_DECODED_BYTES = 65536,
	FUZZ_FAULT_POSITIONS = 16,
	FUZZ_DATA_INSTANCE = 1,
	FUZZ_BITMAP_ALLOCATED_BIT = 1,
	FUZZ_STANDALONE_MUTATIONS = 512,
	FUZZ_ATTRIBUTE_ALIGNMENT = 8,
	FUZZ_SEQUENCE = 1
};

static const uint16_t directory_index_name[] = {'$', 'I', '3', '0'};
static const uint8_t listed_data[] = "attribute-list payload";

static void
store_integer(uint8_t *out, uint64_t value, size_t bytes)
{
	size_t i;

	for (i = 0; i < bytes; i++) {
		out[i] = (uint8_t)value;
		value >>= NTFS_BITS_PER_BYTE;
	}
}

static size_t
align_attribute(size_t size)
{
	return (size + FUZZ_ATTRIBUTE_ALIGNMENT - 1) & ~(FUZZ_ATTRIBUTE_ALIGNMENT - 1u);
}

static size_t
add_resident(uint8_t *record, size_t offset, uint32_t type, uint16_t instance, const uint16_t *name,
    size_t name_units, const void *data, size_t data_bytes)
{
	struct ntfs_disk_attr *attr = (void *)(record + offset);
	struct ntfs_disk_resident *resident = (void *)((uint8_t *)attr + sizeof(*attr));
	size_t name_offset = sizeof(*attr) + sizeof(*resident);
	size_t value_offset = align_attribute(name_offset + name_units * NTFS_UTF16_UNIT_BYTES);
	size_t length = align_attribute(value_offset + data_bytes), i;

	assert(ntfs_bounds(offset, length, FUZZ_STRUCTURE_RECORD_BYTES));
	store_integer(attr->type, type, sizeof(attr->type));
	store_integer(attr->length, length, sizeof(attr->length));
	store_integer(attr->instance, instance, sizeof(attr->instance));
	attr->name_length = (uint8_t)name_units;
	store_integer(attr->name_offset, name_offset, sizeof(attr->name_offset));
	store_integer(resident->offset, value_offset, sizeof(resident->offset));
	store_integer(resident->length, data_bytes, sizeof(resident->length));
	for (i = 0; i < name_units; i++) {
		store_integer((uint8_t *)attr + name_offset + i * NTFS_UTF16_UNIT_BYTES, name[i],
		    NTFS_UTF16_UNIT_BYTES);
	}
	memcpy((uint8_t *)attr + value_offset, data, data_bytes);
	return offset + length;
}

static size_t
add_index_allocation(uint8_t *record, size_t offset)
{
	struct ntfs_disk_attr *attr = (void *)(record + offset);
	struct ntfs_disk_nonresident *value = (void *)((uint8_t *)attr + sizeof(*attr));
	size_t name_offset = sizeof(*attr) + sizeof(*value), mapping_offset, length, i;
	const uint8_t mapping[] = {
	    1 | (1 << NTFS_RUN_OFFSET_WIDTH_SHIFT), 1, 0, 0}; /* One cluster at LCN zero. */

	mapping_offset = align_attribute(name_offset + sizeof(directory_index_name));
	length = align_attribute(mapping_offset + sizeof(mapping));
	assert(ntfs_bounds(offset, length, FUZZ_STRUCTURE_RECORD_BYTES));
	store_integer(attr->type, NTFS_ATTR_INDEX_ALLOCATION, sizeof(attr->type));
	store_integer(attr->length, length, sizeof(attr->length));
	attr->nonresident = 1;
	attr->name_length = sizeof(directory_index_name) / sizeof(directory_index_name[0]);
	store_integer(attr->name_offset, name_offset, sizeof(attr->name_offset));
	store_integer(value->mapping_offset, mapping_offset, sizeof(value->mapping_offset));
	store_integer(value->allocated, FUZZ_STRUCTURE_CLUSTER_BYTES, sizeof(value->allocated));
	store_integer(value->size, FUZZ_STRUCTURE_INDEX_BYTES, sizeof(value->size));
	store_integer(value->initialized, FUZZ_STRUCTURE_INDEX_BYTES, sizeof(value->initialized));
	for (i = 0; i < sizeof(directory_index_name) / sizeof(directory_index_name[0]); i++) {
		store_integer((uint8_t *)attr + name_offset + i * NTFS_UTF16_UNIT_BYTES,
		    directory_index_name[i], NTFS_UTF16_UNIT_BYTES);
	}
	memcpy((uint8_t *)attr + mapping_offset, mapping, sizeof(mapping));
	return offset + length;
}

static void
finish_record(uint8_t *record, size_t attrs, size_t end, bool directory)
{
	struct ntfs_disk_record *header = (void *)record;

	memcpy(header->mst.magic, "FILE", sizeof(header->mst.magic));
	store_integer(header->sequence, FUZZ_SEQUENCE, sizeof(header->sequence));
	store_integer(header->links, 1, sizeof(header->links));
	store_integer(header->attrs_offset, attrs, sizeof(header->attrs_offset));
	store_integer(header->flags, NTFS_RECORD_IN_USE | (directory ? NTFS_RECORD_DIRECTORY : 0),
	    sizeof(header->flags));
	store_integer(header->used, end + sizeof(uint32_t), sizeof(header->used));
	store_integer(header->allocated, FUZZ_STRUCTURE_RECORD_BYTES, sizeof(header->allocated));
	store_integer(record + end, NTFS_ATTR_END, sizeof(uint32_t));
}

static void
fuzz_mapping(struct ntfs_volume *volume, const uint8_t *data, size_t size)
{
	struct ntfs_attr_view attribute;
	struct ntfs_stream *stream = NULL;
	uint8_t buffer[FUZZ_STRUCTURE_READ_BYTES];
	uint32_t position = 0;
	size_t count;

	if (ntfs_attr_at(data, size, &position, &attribute) == NTFS_OK &&
	    ntfs_stream_from_attr(volume, &attribute, &stream) == NTFS_OK) {
		(void)ntfs_stream_read(stream, 0, buffer, sizeof(buffer), &count);
		(void)ntfs_stream_read(
		    stream, ntfs_stream_size(stream), buffer, sizeof(buffer), &count);
	}
	ntfs_stream_close(stream);
}

static void
fuzz_list(struct ntfs_volume *volume, const uint8_t *data, size_t size)
{
	struct ntfs_node node = {.volume = volume,
	    .reference =
		((uint64_t)FUZZ_SEQUENCE << NTFS_REFERENCE_SEQUENCE_SHIFT) | NTFS_ROOT_RECORD};
	struct ntfs_stream *stream = NULL;
	size_t attrs = align_attribute(sizeof(struct ntfs_disk_record)), end;

	node.record = ntfs_alloc(volume, FUZZ_STRUCTURE_RECORD_BYTES);
	if (node.record == NULL) {
		return;
	}
	end = add_resident(node.record, attrs, NTFS_ATTR_LIST, 0, NULL, 0, data, size);
	end = add_resident(node.record, end, NTFS_ATTRIBUTE_DATA, FUZZ_DATA_INSTANCE, NULL, 0,
	    listed_data, sizeof(listed_data) - 1);
	finish_record(node.record, attrs, end, false);
	(void)ntfs_attribute_open(&node, NTFS_ATTRIBUTE_DATA, NULL, 0, &stream);
	ntfs_stream_close(stream);
	ntfs_free(volume, node.record, FUZZ_STRUCTURE_RECORD_BYTES);
}

static void
fuzz_index(struct ntfs_volume *volume, const uint8_t *data, size_t size, bool block)
{
	struct child_root {
		struct ntfs_disk_index_root root;
		struct ntfs_disk_index_header header;
		struct ntfs_disk_index_entry entry;
		uint8_t vcn[sizeof(uint64_t)];
	} root = {0};

	struct ntfs_node node = {.volume = volume,
	    .reference =
		((uint64_t)FUZZ_SEQUENCE << NTFS_REFERENCE_SEQUENCE_SHIFT) | NTFS_ROOT_RECORD};
	struct ntfs_disk_standard standard = {0};
	struct ntfs_directory *directory = NULL;
	struct ntfs_dirent entry;
	uint8_t bitmap = FUZZ_BITMAP_ALLOCATED_BIT;
	size_t attrs = align_attribute(sizeof(struct ntfs_disk_record)), end;
	unsigned i;

	node.record = ntfs_alloc(volume, FUZZ_STRUCTURE_RECORD_BYTES);
	volume->upcase = ntfs_alloc(volume, NTFS_UPCASE_BYTES);
	if (node.record == NULL || volume->upcase == NULL) {
		goto finish;
	}
	for (i = 0; i < NTFS_UTF16_CODE_UNITS; i++) {
		store_integer(volume->upcase + (size_t)i * NTFS_UTF16_UNIT_BYTES,
		    i >= 'a' && i <= 'z' ? i - 'a' + 'A' : i, NTFS_UTF16_UNIT_BYTES);
	}
	end = add_resident(
	    node.record, attrs, NTFS_ATTR_STANDARD, 0, NULL, 0, &standard, sizeof(standard));
	if (block) {
		store_integer(root.root.type, NTFS_ATTR_FILENAME, sizeof(root.root.type));
		store_integer(
		    root.root.collation, NTFS_COLLATION_FILENAME, sizeof(root.root.collation));
		store_integer(
		    root.root.block_size, FUZZ_STRUCTURE_INDEX_BYTES, sizeof(root.root.block_size));
		root.root.clusters_per_block = 1;
		store_integer(root.header.entries_offset, sizeof(root.header),
		    sizeof(root.header.entries_offset));
		store_integer(
		    root.header.used, sizeof(root) - sizeof(root.root), sizeof(root.header.used));
		store_integer(root.header.allocated, sizeof(root) - sizeof(root.root),
		    sizeof(root.header.allocated));
		root.header.flags = NTFS_INDEX_LARGE;
		store_integer(root.entry.length, sizeof(root.entry) + sizeof(root.vcn),
		    sizeof(root.entry.length));
		store_integer(
		    root.entry.flags, NTFS_INDEX_CHILD | NTFS_INDEX_END, sizeof(root.entry.flags));
		end = add_resident(node.record, end, NTFS_ATTR_INDEX_ROOT, 1, directory_index_name,
		    sizeof(directory_index_name) / sizeof(directory_index_name[0]), &root,
		    sizeof(root));
		end = add_index_allocation(node.record, end);
		end = add_resident(node.record, end, NTFS_ATTR_BITMAP, 2, directory_index_name,
		    sizeof(directory_index_name) / sizeof(directory_index_name[0]), &bitmap,
		    sizeof(bitmap));
	} else {
		end = add_resident(node.record, end, NTFS_ATTR_INDEX_ROOT, 1, directory_index_name,
		    sizeof(directory_index_name) / sizeof(directory_index_name[0]), data, size);
	}
	finish_record(node.record, attrs, end, true);
	if (ntfs_directory_open(&node, &directory) == NTFS_OK) {
		for (i = 0;
		    i < FUZZ_STRUCTURE_ENTRIES && ntfs_directory_next(directory, &entry) == NTFS_OK;
		    i++) {
			/* The index entry remains lossless even when UTF conversion refuses it. */
			assert(entry.name_length <= NTFS_NAME_MAX);
		}
	}
finish:
	ntfs_directory_close(directory);
	ntfs_free(volume, volume->upcase, NTFS_UPCASE_BYTES);
	volume->upcase = NULL;
	ntfs_free(volume, node.record, FUZZ_STRUCTURE_RECORD_BYTES);
}

static void
exercise(const uint8_t *data, size_t size, size_t fail_allocation, size_t fail_read)
{
	struct fuzz_device device = {
	    .data = data, .size = size, .fail_allocation = fail_allocation, .fail_read = fail_read};
	struct ntfs_volume volume = {0};
	struct ntfs_stream empty_mft = {.volume = &volume, .resident = true};
	struct ntfs_reparse_info reparse;
	struct ntfs_security_info security;
	struct ntfs_ace_info ace;
	uint8_t *decoded;
	size_t produced;

	volume.env = fuzz_environment(&device);
	ntfs_default_limits(&volume.limits);
	volume.limits.max_runs = FUZZ_STRUCTURE_MAX_RUNS;
	volume.limits.max_attribute_list = FUZZ_STRUCTURE_INPUT_BYTES;
	volume.limits.max_directory_nodes = FUZZ_STRUCTURE_DIRECTORY_NODES;
	volume.info.cluster_size = FUZZ_STRUCTURE_CLUSTER_BYTES;
	volume.info.cluster_count = FUZZ_STRUCTURE_CLUSTERS;
	volume.info.sector_size = NTFS_SECTOR_MIN_BYTES;
	volume.info.record_size = FUZZ_STRUCTURE_RECORD_BYTES;
	volume.info.index_size = FUZZ_STRUCTURE_INDEX_BYTES;
	volume.info.size_bytes = (uint64_t)FUZZ_STRUCTURE_CLUSTER_BYTES * FUZZ_STRUCTURE_CLUSTERS;
	volume.mft = &empty_mft;
	switch (NTFS_FUZZ_TARGET) {
	case NTFS_FUZZ_MAPPING_PAIRS:
		fuzz_mapping(&volume, data, size);
		break;
	case NTFS_FUZZ_ATTRIBUTE_LIST:
		fuzz_list(&volume, data, size);
		break;
	case NTFS_FUZZ_INDEX_ROOT:
		fuzz_index(&volume, data, size, false);
		break;
	case NTFS_FUZZ_INDEX_BLOCK:
		fuzz_index(&volume, data, size, true);
		break;
	case NTFS_FUZZ_LZNT1:
		decoded = ntfs_alloc(&volume, FUZZ_DECODED_BYTES);
		if (decoded != NULL) {
			(void)ntfs_lznt1_decode(data, size, decoded, FUZZ_DECODED_BYTES, &produced);
			ntfs_free(&volume, decoded, FUZZ_DECODED_BYTES);
		}
		break;
	case NTFS_FUZZ_REPARSE:
		(void)ntfs_reparse_decode(data, size, &reparse);
		break;
	case NTFS_FUZZ_SECURITY:
		(void)ntfs_security_decode(data, size, &security);
		(void)ntfs_security_ace_decode(data, size, &ace);
		break;
	}
	assert(device.memory == 0 && volume.children == 0);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	size_t fail;

	if (size > (NTFS_FUZZ_TARGET == NTFS_FUZZ_SECURITY ? NTFS_SECURITY_MAX_BYTES
							   : FUZZ_STRUCTURE_INPUT_BYTES)) {
		return 0;
	}
	exercise(data, size, 0, 0);
	if (size != 0) {
		fail = data[size - 1] % FUZZ_FAULT_POSITIONS + 1;
		exercise(data, size, fail, 0);
		exercise(data, size, 0, fail);
	}
	return 0;
}

#ifdef NTFS_FUZZ_STANDALONE
int
main(int argc, char **argv)
{
	FILE *file;
	uint8_t *data, saved;
	long bytes;
	size_t i, position;

	assert(argc == 2);
	file = fopen(argv[1], "rb");
	assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
	bytes = ftell(file);
	assert(bytes > 0 &&
	    (size_t)bytes <= (NTFS_FUZZ_TARGET == NTFS_FUZZ_SECURITY ? NTFS_SECURITY_MAX_BYTES
								     : FUZZ_STRUCTURE_INPUT_BYTES));
	rewind(file);
	data = malloc((size_t)bytes);
	assert(data != NULL && fread(data, 1, (size_t)bytes, file) == (size_t)bytes);
	fclose(file);
	LLVMFuzzerTestOneInput(data, (size_t)bytes);
	for (i = 0; i < FUZZ_STANDALONE_MUTATIONS; i++) {
		position = i % (size_t)bytes;
		saved = data[position];
		data[position] ^= (uint8_t)(1u << (i % NTFS_BITS_PER_BYTE));
		LLVMFuzzerTestOneInput(data, (size_t)bytes);
		data[position] = saved;
	}
	free(data);
	puts("PASS: standalone structure mutations with bounded memory, I/O and injected failures");
	return 0;
}
#endif
