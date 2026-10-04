/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include <ntfs/record.h>

enum { NTFS_MST_FIRST_SEQUENCE = 1 };

_Static_assert(
    NTFS_PROTECTED_RECORD_MAX_BYTES == NTFS_MAX_RECORD_BYTES, "private protected-record policy");

static bool
supported_magic(const struct ntfs_disk_mst *header)
{
	return ntfs_equal(header->magic, "FILE", sizeof(header->magic)) ||
	    ntfs_equal(header->magic, "INDX", sizeof(header->magic)) ||
	    ntfs_equal(header->magic, "RSTR", sizeof(header->magic)) ||
	    ntfs_equal(header->magic, "RCRD", sizeof(header->magic));
}

enum ntfs_result
ntfs_record_protect(const void *input, size_t size, void *output, size_t capacity)
{
	const struct ntfs_disk_mst *header = input;
	const uint8_t *original = input;
	uint8_t *encoded = output;
	uintptr_t source_address, output_address;
	size_t offset, count, index, tail;
	uint16_t sequence;

	if (input == NULL || output == NULL) {
		return NTFS_INVALID;
	}
	if (size > NTFS_PROTECTED_RECORD_MAX_BYTES || capacity < size) {
		return NTFS_RANGE;
	}
	if (size < NTFS_MST_STRIDE || size % NTFS_MST_STRIDE != 0) {
		return NTFS_CORRUPT;
	}
	source_address = (uintptr_t)input;
	output_address = (uintptr_t)output;
	if (size > UINTPTR_MAX - source_address || size > UINTPTR_MAX - output_address ||
	    (source_address <= output_address ? output_address - source_address < size
					      : source_address - output_address < size)) {
		return NTFS_INVALID;
	}
	if (!supported_magic(header)) {
		return NTFS_UNSUPPORTED;
	}
	offset = ntfs_u16(header->usa_offset);
	count = ntfs_u16(header->usa_count);
	if (count != size / NTFS_MST_STRIDE + 1 || offset < sizeof(*header) ||
	    offset % NTFS_MST_WORD_BYTES != 0 ||
	    !ntfs_bounds(
		offset, count * NTFS_MST_WORD_BYTES, NTFS_MST_STRIDE - NTFS_MST_WORD_BYTES)) {
		return NTFS_CORRUPT;
	}
	sequence = (uint16_t)(ntfs_u16(original + offset) + 1u);
	if (sequence == 0 || sequence == UINT16_MAX) {
		sequence = NTFS_MST_FIRST_SEQUENCE;
	}
	/* Complete admission precedes publication; the input is a private restored
	 * snapshot, so saved tails come from original bytes, never the old USA. */
	ntfs_copy(encoded, original, size);
	ntfs_put_u16(encoded + offset, sequence);
	for (index = 1; index < count; index++) {
		tail = index * NTFS_MST_STRIDE - NTFS_MST_WORD_BYTES;
		ntfs_copy(encoded + offset + index * NTFS_MST_WORD_BYTES, original + tail,
		    NTFS_MST_WORD_BYTES);
		ntfs_put_u16(encoded + tail, sequence);
	}
	return NTFS_OK;
}
