/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include "pointer_range.h"
#include "write_reparse.h"

enum { REPARSE_NAME_TERMINATORS = 2 };

struct reparse_write_layout {
	size_t prefix, bytes, substitute_bytes, display_bytes;
};

static enum ntfs_result
reparse_write_layout(
    const struct ntfs_write_reparse_input *input, struct reparse_write_layout *layout)
{
	size_t maximum, index;

	if (!ntfs_pointer_range_valid(input, sizeof(*input))) {
		return NTFS_INVALID;
	}
	if (input->kind != NTFS_REPARSE_SYMLINK && input->kind != NTFS_REPARSE_MOUNT_POINT) {
		return NTFS_UNSUPPORTED;
	}
	if ((input->kind == NTFS_REPARSE_SYMLINK &&
		(input->flags & ~NTFS_REPARSE_SYMLINK_RELATIVE) != 0) ||
	    (input->kind == NTFS_REPARSE_MOUNT_POINT && input->flags != 0)) {
		return NTFS_UNSUPPORTED;
	}
	if (input->substitute_units == 0) {
		return NTFS_INVALID;
	}
	layout->prefix = sizeof(struct ntfs_disk_reparse) +
	    (input->kind == NTFS_REPARSE_SYMLINK ? sizeof(struct ntfs_disk_reparse_symlink)
						 : sizeof(struct ntfs_disk_reparse_names));
	maximum = (NTFS_REPARSE_MAX_BYTES - layout->prefix) / NTFS_UTF16_UNIT_BYTES -
	    REPARSE_NAME_TERMINATORS;
	if (input->substitute_units > maximum ||
	    input->display_units > maximum - input->substitute_units) {
		return NTFS_RANGE;
	}
	layout->substitute_bytes = input->substitute_units * NTFS_UTF16_UNIT_BYTES;
	layout->display_bytes = input->display_units * NTFS_UTF16_UNIT_BYTES;
	if (!ntfs_pointer_range_valid(input->substitute, layout->substitute_bytes) ||
	    !ntfs_pointer_range_valid(input->display, layout->display_bytes)) {
		return NTFS_INVALID;
	}
	for (index = 0; index < input->substitute_units; index++) {
		if (input->substitute[index] == 0) {
			return NTFS_INVALID;
		}
	}
	for (index = 0; index < input->display_units; index++) {
		if (input->display[index] == 0) {
			return NTFS_INVALID;
		}
	}
	layout->bytes = layout->prefix + layout->substitute_bytes + layout->display_bytes +
	    REPARSE_NAME_TERMINATORS * NTFS_UTF16_UNIT_BYTES;
	return NTFS_OK;
}

static bool
reparse_write_separate(const struct ntfs_write_reparse_input *input,
    const struct reparse_write_layout *layout, const void *output, size_t bytes)
{
	return ntfs_pointer_ranges_separate(input, sizeof(*input), output, bytes) &&
	    ntfs_pointer_ranges_separate(
		input->substitute, layout->substitute_bytes, output, bytes) &&
	    ntfs_pointer_ranges_separate(input->display, layout->display_bytes, output, bytes);
}

enum ntfs_result
ntfs_write_reparse_size(const struct ntfs_write_reparse_input *input, size_t *out)
{
	struct reparse_write_layout layout;
	enum ntfs_result result;

	if (!ntfs_pointer_range_valid(out, sizeof(*out))) {
		return NTFS_INVALID;
	}
	result = reparse_write_layout(input, &layout);
	if (result != NTFS_OK) {
		return result;
	}
	if (!reparse_write_separate(input, &layout, out, sizeof(*out))) {
		return NTFS_INVALID;
	}
	*out = layout.bytes;
	return NTFS_OK;
}

enum ntfs_result
ntfs_write_reparse_encode(
    const struct ntfs_write_reparse_input *input, void *output, size_t capacity, size_t *written)
{
	struct reparse_write_layout layout;
	struct ntfs_disk_reparse *header;
	struct ntfs_disk_reparse_names *names;
	struct ntfs_disk_reparse_symlink *symlink;
	uint8_t *path;
	size_t index, display_offset;
	enum ntfs_result result;

	if (output == NULL || !ntfs_pointer_range_valid(output, capacity) ||
	    !ntfs_pointer_range_valid(written, sizeof(*written))) {
		return NTFS_INVALID;
	}
	result = reparse_write_layout(input, &layout);
	if (result != NTFS_OK) {
		return result;
	}
	if (!reparse_write_separate(input, &layout, output, capacity) ||
	    !reparse_write_separate(input, &layout, written, sizeof(*written)) ||
	    !ntfs_pointer_ranges_separate(output, capacity, written, sizeof(*written))) {
		return NTFS_INVALID;
	}
	if (capacity < layout.bytes) {
		return NTFS_RANGE;
	}
	/* All bounds, names and aliases are proved before the first changed byte. */
	ntfs_zero(output, layout.bytes);
	header = output;
	ntfs_put_u32(header->tag,
	    input->kind == NTFS_REPARSE_SYMLINK ? NTFS_REPARSE_TAG_SYMLINK
						: NTFS_REPARSE_TAG_MOUNT_POINT);
	ntfs_put_u16(header->length, (uint16_t)(layout.bytes - sizeof(*header)));
	names = (void *)((uint8_t *)output + sizeof(*header));
	display_offset = layout.substitute_bytes + NTFS_UTF16_UNIT_BYTES;
	ntfs_put_u16(names->substitute_length, (uint16_t)layout.substitute_bytes);
	ntfs_put_u16(names->print_offset, (uint16_t)display_offset);
	ntfs_put_u16(names->print_length, (uint16_t)layout.display_bytes);
	if (input->kind == NTFS_REPARSE_SYMLINK) {
		symlink = (void *)names;
		ntfs_put_u32(symlink->flags, input->flags);
	}
	path = (uint8_t *)output + layout.prefix;
	for (index = 0; index < input->substitute_units; index++) {
		ntfs_put_u16(path + index * NTFS_UTF16_UNIT_BYTES, input->substitute[index]);
	}
	for (index = 0; index < input->display_units; index++) {
		ntfs_put_u16(
		    path + display_offset + index * NTFS_UTF16_UNIT_BYTES, input->display[index]);
	}
	*written = layout.bytes;
	return NTFS_OK;
}
