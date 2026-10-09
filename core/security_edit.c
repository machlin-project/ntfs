/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include "pointer_range.h"
#include "security_edit.h"

enum {
	SECURITY_EDIT_ALIGNMENT = sizeof(uint32_t),
	SECURITY_EDIT_DACL_CONTROL = NTFS_SD_DACL_PRESENT | NTFS_SD_DACL_DEFAULTED |
	    NTFS_SD_DACL_AUTO_INHERIT_REQUEST | NTFS_SD_DACL_AUTO_INHERITED | NTFS_SD_DACL_PROTECTED
};

struct security_edit_component {
	const uint8_t *bytes;
	uint32_t length, offset;
};

struct security_edit_layout {
	struct security_edit_component owner, group, sacl, dacl;
	size_t bytes;
	uint16_t control;
};

static enum ntfs_result
security_edit_append(struct security_edit_layout *layout, struct security_edit_component *component,
    const void *input, const struct ntfs_security_span *span)
{
	size_t padding;

	if (span->length == 0) {
		return NTFS_OK;
	}
	padding = (SECURITY_EDIT_ALIGNMENT - layout->bytes % SECURITY_EDIT_ALIGNMENT) %
	    SECURITY_EDIT_ALIGNMENT;
	if (padding > NTFS_SECURITY_MAX_BYTES - layout->bytes ||
	    span->length > NTFS_SECURITY_MAX_BYTES - layout->bytes - padding) {
		return NTFS_RANGE;
	}
	layout->bytes += padding;
	component->bytes = (const uint8_t *)input + span->offset;
	component->length = span->length;
	component->offset = (uint32_t)layout->bytes;
	layout->bytes += span->length;
	return NTFS_OK;
}

static enum ntfs_result
security_edit_prepare(
    const struct ntfs_security_edit_input *input, struct security_edit_layout *layout)
{
	struct ntfs_security_info original, source;
	enum ntfs_result result;

	if (!ntfs_pointer_range_valid(input, sizeof(*input))) {
		return NTFS_INVALID;
	}
	if (input->original_bytes > NTFS_SECURITY_MAX_BYTES ||
	    input->dacl_source_bytes > NTFS_SECURITY_MAX_BYTES) {
		return NTFS_RANGE;
	}
	if (input->original == NULL || input->dacl_source == NULL ||
	    !ntfs_pointer_range_valid(input->original, input->original_bytes) ||
	    !ntfs_pointer_range_valid(input->dacl_source, input->dacl_source_bytes)) {
		return NTFS_INVALID;
	}
	result = ntfs_security_decode(input->original, input->original_bytes, &original);
	if (result == NTFS_OK) {
		result =
		    ntfs_security_decode(input->dacl_source, input->dacl_source_bytes, &source);
	}
	if (result != NTFS_OK) {
		return result;
	}
	ntfs_zero(layout, sizeof(*layout));
	layout->bytes = sizeof(struct ntfs_disk_security_descriptor);
	layout->control = (uint16_t)((original.control & ~SECURITY_EDIT_DACL_CONTROL) |
	    (source.control & SECURITY_EDIT_DACL_CONTROL));
	result =
	    security_edit_append(layout, &layout->owner, input->original, &original.owner_span);
	if (result == NTFS_OK) {
		result = security_edit_append(
		    layout, &layout->group, input->original, &original.group_span);
	}
	if (result == NTFS_OK) {
		result = security_edit_append(
		    layout, &layout->sacl, input->original, &original.sacl.span);
	}
	if (result == NTFS_OK) {
		result = security_edit_append(
		    layout, &layout->dacl, input->dacl_source, &source.dacl.span);
	}
	return result;
}

static bool
security_edit_separate(
    const struct ntfs_security_edit_input *input, const void *output, size_t bytes)
{
	return ntfs_pointer_ranges_separate(input, sizeof(*input), output, bytes) &&
	    ntfs_pointer_ranges_separate(input->original, input->original_bytes, output, bytes) &&
	    ntfs_pointer_ranges_separate(
		input->dacl_source, input->dacl_source_bytes, output, bytes);
}

static void
security_edit_copy(uint8_t *output, const struct security_edit_component *component)
{
	if (component->length != 0) {
		ntfs_copy(output + component->offset, component->bytes, component->length);
	}
}

enum ntfs_result
ntfs_security_edit_dacl_size(const struct ntfs_security_edit_input *input, size_t *out)
{
	struct security_edit_layout layout;
	enum ntfs_result result;

	if (!ntfs_pointer_range_valid(out, sizeof(*out))) {
		return NTFS_INVALID;
	}
	result = security_edit_prepare(input, &layout);
	if (result != NTFS_OK) {
		return result;
	}
	if (!security_edit_separate(input, out, sizeof(*out))) {
		return NTFS_INVALID;
	}
	*out = layout.bytes;
	return NTFS_OK;
}

enum ntfs_result
ntfs_security_edit_dacl_encode(
    const struct ntfs_security_edit_input *input, void *output, size_t capacity, size_t *written)
{
	struct security_edit_layout layout;
	struct ntfs_disk_security_descriptor *header;
	enum ntfs_result result;

	if (output == NULL || !ntfs_pointer_range_valid(output, capacity) ||
	    !ntfs_pointer_range_valid(written, sizeof(*written))) {
		return NTFS_INVALID;
	}
	result = security_edit_prepare(input, &layout);
	if (result != NTFS_OK) {
		return result;
	}
	if (!security_edit_separate(input, output, capacity) ||
	    !security_edit_separate(input, written, sizeof(*written)) ||
	    !ntfs_pointer_ranges_separate(output, capacity, written, sizeof(*written))) {
		return NTFS_INVALID;
	}
	if (capacity < layout.bytes) {
		return NTFS_RANGE;
	}
	/* No fallible operation follows the first write. Preserve the original
	 * fixed header except for the selected control bits and rebuilt offsets. */
	ntfs_zero(output, layout.bytes);
	ntfs_copy(output, input->original, sizeof(*header));
	header = output;
	ntfs_put_u16(header->control, layout.control);
	ntfs_put_u32(header->owner, layout.owner.offset);
	ntfs_put_u32(header->group, layout.group.offset);
	ntfs_put_u32(header->sacl, layout.sacl.offset);
	ntfs_put_u32(header->dacl, layout.dacl.offset);
	security_edit_copy(output, &layout.owner);
	security_edit_copy(output, &layout.group);
	security_edit_copy(output, &layout.sacl);
	security_edit_copy(output, &layout.dacl);
	*written = layout.bytes;
	return NTFS_OK;
}
