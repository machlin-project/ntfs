/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include "fuzz_device.h"
#include <stdlib.h>
#include <string.h>

enum {
	MUTATOR_SCAN_BYTES = 512 * 1024,
	MUTATOR_STRUCTURAL_CHOICES = 4,
	MUTATOR_GENERIC_CHOICE = 0
};

/* Numerical Recipes LCG: deterministic selection from a libFuzzer seed. */
#define MUTATOR_RANDOM_MULTIPLIER UINT32_C(1664525)
#define MUTATOR_RANDOM_INCREMENT UINT32_C(1013904223)

size_t LLVMFuzzerMutate(uint8_t *, size_t, size_t);

static uint32_t
random_next(uint32_t *state)
{
	*state = *state * MUTATOR_RANDOM_MULTIPLIER + MUTATOR_RANDOM_INCREMENT;
	return *state;
}

static void
store_word(uint8_t *bytes, uint16_t value)
{
	bytes[0] = (uint8_t)value;
	bytes[1] = (uint8_t)(value >> NTFS_BITS_PER_BYTE);
}

static size_t
mutate_span(uint8_t *data, size_t size)
{
	size_t changed;

	if (size == 0) {
		return 0;
	}
	changed = LLVMFuzzerMutate(data, size, size);
	if (changed < size) {
		memset(data + changed, 0, size - changed);
	}
	return size;
}

static bool
mutate_attribute(uint8_t *record, size_t size, uint32_t *random)
{
	const struct ntfs_disk_record *header = (const void *)record;
	const struct ntfs_disk_resident *resident;
	const struct ntfs_disk_nonresident *nonresident;
	struct ntfs_attr_view attr;
	uint32_t position = ntfs_u16(header->attrs_offset), count = 0;
	size_t offset, length, selected_offset = 0, selected_length = 0;

	if (ntfs_u32(header->used) > size || position < sizeof(*header)) {
		return false;
	}
	while (ntfs_attr_at(record, ntfs_u32(header->used), &position, &attr) == NTFS_OK) {
		if (attr.disk->nonresident) {
			nonresident = (const void *)(attr.bytes + sizeof(*attr.disk));
			offset = ntfs_u16(nonresident->mapping_offset);
			length = attr.length - offset;
		} else {
			resident = (const void *)(attr.bytes + sizeof(*attr.disk));
			offset = ntfs_u16(resident->offset);
			length = ntfs_u32(resident->length);
		}
		if (length != 0 && random_next(random) % ++count == 0) {
			selected_offset = (size_t)(attr.bytes - record) + offset;
			selected_length = length;
		}
	}
	if (selected_length == 0) {
		return false;
	}
	(void)mutate_span(record + selected_offset, selected_length);
	return true;
}

/* Preserve envelope sizes and MST protection often enough to mutate deep
 * attribute/index values. Generic mutations remain in the same campaign. */
size_t
LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t maximum, unsigned seed)
{
	struct ntfs_disk_mst *mst;
	const struct ntfs_disk_record *record;
	const struct ntfs_disk_index_block *index;
	uint8_t *frame, *copy;
	size_t offset, bytes, end, selected = 0, selected_bytes = 0, candidates = 0;
	size_t usa_offset, usa_count, i, tail, payload_offset, payload_bytes;
	uint16_t sequence;
	uint32_t random = seed;
	struct fuzz_device device = {.data = data, .size = size};
	struct ntfs_environment environment = fuzz_environment(&device);
	struct ntfs_info info;
	bool file = false, selected_file = false, changed;

	if (random_next(&random) % MUTATOR_STRUCTURAL_CHOICES == MUTATOR_GENERIC_CHOICE) {
		return LLVMFuzzerMutate(data, size, maximum);
	}
	if (ntfs_probe(&environment, &info) != NTFS_OK) {
		return LLVMFuzzerMutate(data, size, maximum);
	}
	end = size < MUTATOR_SCAN_BYTES ? size : MUTATOR_SCAN_BYTES;
	for (offset = 0; ntfs_bounds(offset, sizeof(struct ntfs_disk_record), end);
	    offset += NTFS_MST_STRIDE) {
		frame = data + offset;
		file = memcmp(frame, "FILE", sizeof(mst->magic)) == 0;
		if (file) {
			record = (const void *)frame;
			bytes = ntfs_u32(record->allocated);
		} else if (memcmp(frame, "INDX", sizeof(mst->magic)) == 0) {
			bytes = info.index_size;
		} else {
			continue;
		}
		if (bytes < NTFS_MST_STRIDE || bytes > NTFS_MAX_RECORD_BYTES ||
		    bytes % NTFS_MST_STRIDE != 0 || !ntfs_bounds(offset, bytes, size)) {
			continue;
		}
		if (random_next(&random) % ++candidates == 0) {
			selected = offset;
			selected_bytes = bytes;
			selected_file = file;
		}
	}
	if (selected_bytes == 0) {
		return LLVMFuzzerMutate(data, size, maximum);
	}
	frame = data + selected;
	mst = (void *)frame;
	usa_offset = ntfs_u16(mst->usa_offset);
	usa_count = ntfs_u16(mst->usa_count);
	/* Work in private storage: failed validation or selection leaves the
	 * protected input untouched before the generic fallback. */
	copy = malloc(selected_bytes);
	if (copy == NULL) {
		return LLVMFuzzerMutate(data, size, maximum);
	}
	memcpy(copy, frame, selected_bytes);
	changed = false;
	if (ntfs_fixup(copy, selected_bytes, selected_file ? "FILE" : "INDX") == NTFS_OK) {
		sequence = ntfs_u16(copy + usa_offset);
		if (selected_file) {
			changed = mutate_attribute(copy, selected_bytes, &random);
		} else {
			index = (const void *)copy;
			payload_offset = offsetof(struct ntfs_disk_index_block, header) +
			    ntfs_u32(index->header.entries_offset);
			payload_bytes = ntfs_u32(index->header.used);
			if (payload_bytes >= ntfs_u32(index->header.entries_offset)) {
				payload_bytes -= ntfs_u32(index->header.entries_offset);
				if (payload_offset >= sizeof(*index) &&
				    ntfs_bounds(payload_offset, payload_bytes, selected_bytes)) {
					changed =
					    mutate_span(copy + payload_offset, payload_bytes) != 0;
				}
			}
		}
		if (changed) {
			for (i = 1; i < usa_count; i++) {
				tail = i * NTFS_MST_STRIDE - NTFS_MST_WORD_BYTES;
				memcpy(copy + usa_offset + i * NTFS_MST_WORD_BYTES, copy + tail,
				    NTFS_MST_WORD_BYTES);
				store_word(copy + tail, sequence);
			}
			memcpy(frame, copy, selected_bytes);
		}
	}
	free(copy);
	return changed ? size : LLVMFuzzerMutate(data, size, maximum);
}
