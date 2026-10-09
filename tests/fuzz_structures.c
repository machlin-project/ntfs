/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include "fuzz_device.h"
#include "security_edit.h"
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
	FUZZ_GUARD_BYTE = 0xa6,
	FUZZ_DECODED_BYTES = 65536,
	FUZZ_FAULT_POSITIONS = 16,
	FUZZ_DATA_INSTANCE = 1,
	FUZZ_BITMAP_ALLOCATED_BIT = 1,
	FUZZ_STANDALONE_MUTATIONS = 512,
	FUZZ_ATTRIBUTE_ALIGNMENT = 8,
	FUZZ_SEQUENCE = 1,
	FUZZ_SECURITY_GUARD_BYTES = 16,
	FUZZ_SECURITY_ALIGNMENT = sizeof(uint32_t),
	FUZZ_SECURITY_DACL_BITS = 0x150c,
	FUZZ_SECURITY_AUTHORITY_BYTES = 6
};

static const uint16_t directory_index_name[] = {'$', 'I', '3', '0'};
static const uint8_t listed_data[] = "attribute-list payload";

/* Independent literal donor descriptors retain the existing fuzzer's raw
 * descriptor framing. The fifth donor is the fuzzed descriptor itself. */
static const uint8_t security_absent[] = {
    1, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const uint8_t security_null[] = {
    1, 0, 4, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const uint8_t security_empty[] = {
    1, 0, 4, 0x90, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x14, 0, 0, 0,
    2, 0, 8, 0, 0, 0, 0, 0};
static const uint8_t security_one_ace[] = {
    1, 0, 0x0c, 0x85, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x14, 0, 0, 0,
    2, 0, 0x1c, 0, 1, 0, 0, 0,
    0, 0x13, 0x14, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0};

struct security_fuzz_descriptor {
	uint8_t revision, manager, control[sizeof(uint16_t)];
	uint8_t owner[sizeof(uint32_t)], group[sizeof(uint32_t)];
	uint8_t sacl[sizeof(uint32_t)], dacl[sizeof(uint32_t)];
};

struct security_fuzz_sid {
	uint8_t revision, count, authority[FUZZ_SECURITY_AUTHORITY_BYTES];
};

struct security_fuzz_acl {
	uint8_t revision, reserved1, length[sizeof(uint16_t)];
	uint8_t count[sizeof(uint16_t)], reserved2[sizeof(uint16_t)];
};

static uint32_t
security_fuzz_little(const uint8_t *bytes, size_t count)
{
	uint32_t value = 0;
	size_t index;

	assert(count <= sizeof(value));
	for (index = count; index != 0; index--) {
		value = value * (UINT8_MAX + 1u) + bytes[index - 1];
	}
	return value;
}

static void
security_fuzz_guard(const uint8_t *bytes, size_t count)
{
	size_t index;

	for (index = 0; index < count; index++) {
		assert(bytes[index] == FUZZ_GUARD_BYTE);
	}
}

static void
security_fuzz_component(const uint8_t *source, size_t source_bytes, const uint8_t *output,
    size_t output_bytes, size_t field, bool acl)
{
	const struct security_fuzz_acl *header;
	const struct security_fuzz_sid *sid;
	size_t source_offset, output_offset, length;

	source_offset = security_fuzz_little(source + field, sizeof(uint32_t));
	output_offset = security_fuzz_little(output + field, sizeof(uint32_t));
	if (source_offset == 0) {
		assert(output_offset == 0);
		return;
	}
	assert(source_offset >= sizeof(struct security_fuzz_descriptor));
	assert(output_offset >= sizeof(struct security_fuzz_descriptor));
	assert(source_offset <= source_bytes && output_offset <= output_bytes);
	assert(output_offset % FUZZ_SECURITY_ALIGNMENT == 0);
	if (acl) {
		assert(sizeof(*header) <= source_bytes - source_offset);
		header = (const void *)(source + source_offset);
		length = security_fuzz_little(header->length, sizeof(header->length));
	} else {
		assert(sizeof(*sid) <= source_bytes - source_offset);
		sid = (const void *)(source + source_offset);
		length = sizeof(*sid) + sid->count * sizeof(uint32_t);
	}
	assert(length <= source_bytes - source_offset && length <= output_bytes - output_offset);
	assert(memcmp(source + source_offset, output + output_offset, length) == 0);
}

static void
security_fuzz_oracle(const struct ntfs_security_edit_input *input, const uint8_t *bytes,
    size_t size)
{
	const struct security_fuzz_descriptor *original = input->original;
	const struct security_fuzz_descriptor *donor = input->dacl_source;
	const struct security_fuzz_descriptor *output = (const void *)bytes;
	uint32_t control, old_control, donor_control;

	assert(size >= sizeof(*output));
	assert(output->revision == original->revision && output->manager == original->manager);
	control = security_fuzz_little(output->control, sizeof(output->control));
	old_control = security_fuzz_little(original->control, sizeof(original->control));
	donor_control = security_fuzz_little(donor->control, sizeof(donor->control));
	assert((control & FUZZ_SECURITY_DACL_BITS) == (donor_control & FUZZ_SECURITY_DACL_BITS));
	assert((control & ~FUZZ_SECURITY_DACL_BITS) == (old_control & ~FUZZ_SECURITY_DACL_BITS));
	security_fuzz_component(input->original, input->original_bytes, bytes, size,
	    offsetof(struct security_fuzz_descriptor, owner), false);
	security_fuzz_component(input->original, input->original_bytes, bytes, size,
	    offsetof(struct security_fuzz_descriptor, group), false);
	security_fuzz_component(input->original, input->original_bytes, bytes, size,
	    offsetof(struct security_fuzz_descriptor, sacl), true);
	security_fuzz_component(input->dacl_source, input->dacl_source_bytes, bytes, size,
	    offsetof(struct security_fuzz_descriptor, dacl), true);
}

static void
fuzz_security_edit(const uint8_t *data, size_t size, enum ntfs_result decoded)
{
	const struct {
		const uint8_t *bytes;
		size_t size;
	} donors[] = {{security_absent, sizeof(security_absent)},
	    {security_null, sizeof(security_null)}, {security_empty, sizeof(security_empty)},
	    {security_one_ace, sizeof(security_one_ace)}, {data, size}};
	struct ntfs_security_edit_input input = {data, security_absent, size, sizeof(security_absent)};
	uint8_t refused[sizeof(struct security_fuzz_descriptor) + 2 * FUZZ_SECURITY_GUARD_BYTES];
	uint8_t *copy, *guarded, *output;
	size_t required = SIZE_MAX, written = SIZE_MAX, index, prefix, allocation;

	if (decoded != NTFS_OK) {
		memset(refused, FUZZ_GUARD_BYTE, sizeof(refused));
		assert(ntfs_security_edit_dacl_size(&input, &required) == decoded);
		assert(ntfs_security_edit_dacl_encode(&input, refused + FUZZ_SECURITY_GUARD_BYTES,
		    sizeof(struct security_fuzz_descriptor), &written) == decoded);
		assert(required == SIZE_MAX && written == SIZE_MAX);
		security_fuzz_guard(refused, sizeof(refused));
		return;
	}
	copy = malloc(size);
	assert(copy != NULL);
	memcpy(copy, data, size);
	prefix = FUZZ_SECURITY_GUARD_BYTES + data[size - 1] % FUZZ_SECURITY_ALIGNMENT;
	for (index = 0; index < sizeof(donors) / sizeof(donors[0]); index++) {
		input.dacl_source = donors[index].bytes;
		input.dacl_source_bytes = donors[index].size;
		assert(ntfs_security_edit_dacl_size(&input, &required) == NTFS_OK);
		assert(required >= sizeof(struct security_fuzz_descriptor));
		assert(required <= NTFS_SECURITY_MAX_BYTES);
		allocation = prefix + required + FUZZ_SECURITY_GUARD_BYTES;
		guarded = malloc(allocation);
		assert(guarded != NULL);
		output = guarded + prefix;
		memset(guarded, FUZZ_GUARD_BYTE, allocation);
		written = SIZE_MAX;
		assert(ntfs_security_edit_dacl_encode(&input, output, required - 1, &written) == NTFS_RANGE);
		assert(written == SIZE_MAX);
		security_fuzz_guard(guarded, allocation);
		assert(ntfs_security_edit_dacl_encode(&input, output, required, &written) == NTFS_OK);
		assert(written == required);
		security_fuzz_guard(guarded, prefix);
		security_fuzz_guard(output + required, FUZZ_SECURITY_GUARD_BYTES);
		security_fuzz_oracle(&input, output, written);
		assert(ntfs_security_edit_dacl_encode(&input, output, required + 1, &written) == NTFS_OK);
		assert(written == required);
		security_fuzz_guard(guarded, prefix);
		security_fuzz_guard(output + required, FUZZ_SECURITY_GUARD_BYTES);
		assert(memcmp(data, copy, size) == 0);
		free(guarded);
	}
	free(copy);
}

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
	uint8_t original[FUZZ_STRUCTURE_READ_BYTES];
	uint32_t position = 0;
	uint64_t reads;
	size_t count;

	if (ntfs_attr_at(data, size, &position, &attribute) != NTFS_OK) {
		return;
	}
	if (ntfs_stream_from_attr(volume, &attribute, &stream) == NTFS_OK) {
		(void)ntfs_stream_read(stream, 0, buffer, sizeof(buffer), &count);
		(void)ntfs_stream_read(
		    stream, ntfs_stream_size(stream), buffer, sizeof(buffer), &count);
	}
	ntfs_stream_close(stream);
	stream = NULL;
	reads = volume->stats.read_calls;
	if (ntfs_stream_metadata_from_attr(volume, &attribute, &stream) == NTFS_OK) {
		memset(original, FUZZ_GUARD_BYTE, sizeof(original));
		memcpy(buffer, original, sizeof(buffer));
		count = SIZE_MAX;
		assert(ntfs_stream_read(stream, 0, buffer, sizeof(buffer), &count) ==
			NTFS_UNSUPPORTED &&
		    count == 0);
		assert(ntfs_stream_read(stream, ntfs_stream_size(stream), buffer, sizeof(buffer),
			   &count) == NTFS_UNSUPPORTED &&
		    count == 0);
		assert(ntfs_stream_raw(stream, 0, buffer, sizeof(buffer)) == NTFS_UNSUPPORTED);
		assert(ntfs_stream_exact(stream, 0, buffer, 0) == NTFS_UNSUPPORTED);
		assert(memcmp(buffer, original, sizeof(buffer)) == 0);
	}
	assert(volume->stats.read_calls == reads);
	ntfs_stream_close(stream);
}

static void
fuzz_list(struct ntfs_volume *volume, const uint8_t *data, size_t size)
{
	struct ntfs_node node = {.volume = volume,
	    .reference =
		((uint64_t)FUZZ_SEQUENCE << NTFS_REFERENCE_SEQUENCE_SHIFT) | NTFS_ROOT_RECORD};
	struct ntfs_stream *stream = NULL;
	uint64_t size_bytes, allocated;
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
	(void)ntfs_attribute_sizes(&node, &size_bytes, &allocated);
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
	enum ntfs_result result;

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
		result = ntfs_security_decode(data, size, &security);
		(void)ntfs_security_ace_decode(data, size, &ace);
		(void)ntfs_security_sid_decode(data, size, &security.owner);
		if (fail_allocation == 0 && fail_read == 0) {
			fuzz_security_edit(data, size, result);
		}
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
