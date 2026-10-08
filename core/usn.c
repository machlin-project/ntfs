/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include "pointer_range.h"
#include "usn.h"

struct usn_layout {
	size_t prefix, id_bytes, bytes;
};

static enum ntfs_result
usn_version(uint16_t major, uint16_t minor, struct usn_layout *layout)
{
	if (minor != 0 || (major != NTFS_USN_VERSION_2 && major != NTFS_USN_VERSION_3)) {
		return NTFS_UNSUPPORTED;
	}
	layout->prefix = major == NTFS_USN_VERSION_2 ? sizeof(struct ntfs_disk_usn_v2)
						 : sizeof(struct ntfs_disk_usn_v3);
	layout->id_bytes = major == NTFS_USN_VERSION_2 ? NTFS_USN_V2_FILE_ID_BYTES
						   : NTFS_USN_FILE_ID_BYTES;
	return NTFS_OK;
}

enum ntfs_result
ntfs_usn_record_decode(const void *input, size_t available, struct ntfs_usn_view *out)
{
	const struct ntfs_disk_usn_header *header = input;
	const struct ntfs_disk_usn_tail *tail;
	const uint8_t *bytes = input;
	struct ntfs_usn_view view;
	struct usn_layout layout;
	uint32_t record_bytes;
	uint16_t major, minor, name_bytes, name_offset;
	enum ntfs_result result;

	if (input == NULL || !ntfs_pointer_range_valid(input, available) ||
	    !ntfs_pointer_range_valid(out, sizeof(*out)) ||
	    !ntfs_pointer_ranges_separate(input, available, out, sizeof(*out))) {
		return NTFS_INVALID;
	}
	if (available < sizeof(*header)) {
		return NTFS_CORRUPT;
	}
	record_bytes = ntfs_u32(header->record_length);
	if (record_bytes < sizeof(*header) || record_bytes > available ||
	    record_bytes % NTFS_USN_RECORD_ALIGNMENT != 0) {
		return NTFS_CORRUPT;
	}
	major = ntfs_u16(header->major_version);
	minor = ntfs_u16(header->minor_version);
	result = usn_version(major, minor, &layout);
	if (result != NTFS_OK) {
		return result;
	}
	if (record_bytes < layout.prefix) {
		return NTFS_CORRUPT;
	}
	tail = (const void *)(bytes + layout.prefix - sizeof(*tail));
	name_bytes = ntfs_u16(tail->filename_length);
	name_offset = ntfs_u16(tail->filename_offset);
	if (name_offset < layout.prefix || name_offset > record_bytes ||
	    name_offset % NTFS_UTF16_UNIT_BYTES != 0 ||
	    name_bytes % NTFS_UTF16_UNIT_BYTES != 0 || name_bytes > record_bytes - name_offset ||
	    ntfs_u64(tail->usn) > INT64_MAX) {
		return NTFS_CORRUPT;
	}
	ntfs_zero(&view, sizeof(view));
	view.record.major_version = major;
	view.record.minor_version = minor;
	ntfs_copy(view.record.file_id, bytes + sizeof(*header), layout.id_bytes);
	ntfs_copy(view.record.parent_id, bytes + sizeof(*header) + layout.id_bytes, layout.id_bytes);
	view.record.usn = ntfs_u64(tail->usn);
	view.record.timestamp = ntfs_u64(tail->timestamp);
	view.record.reason = ntfs_u32(tail->reason);
	view.record.source_info = ntfs_u32(tail->source_info);
	view.record.security_id = ntfs_u32(tail->security_id);
	view.record.file_attributes = ntfs_u32(tail->file_attributes);
	view.record.filename = bytes + name_offset;
	view.record.filename_bytes = name_bytes;
	view.record_bytes = record_bytes;
	view.filename_offset = name_offset;
	ntfs_copy(out, &view, sizeof(view));
	return NTFS_OK;
}

static enum ntfs_result
usn_record_layout(const struct ntfs_usn_record *input, struct usn_layout *layout)
{
	size_t index, remainder;
	enum ntfs_result result;

	if (!ntfs_pointer_range_valid(input, sizeof(*input))) {
		return NTFS_INVALID;
	}
	result = usn_version(input->major_version, input->minor_version, layout);
	if (result != NTFS_OK) {
		return result;
	}
	if (input->filename_bytes > UINT16_MAX || input->usn > INT64_MAX) {
		return NTFS_RANGE;
	}
	if (input->filename_bytes % NTFS_UTF16_UNIT_BYTES != 0 ||
	    !ntfs_pointer_range_valid(input->filename, input->filename_bytes)) {
		return NTFS_INVALID;
	}
	for (index = layout->id_bytes; index < NTFS_USN_FILE_ID_BYTES; index++) {
		if (input->file_id[index] != 0 || input->parent_id[index] != 0) {
			return NTFS_INVALID;
		}
	}
	/* The fixed prefix plus a WORD byte count fits size_t and DWORD even on
	 * 32-bit hosts. Rounding adds at most alignment - 1 bytes. */
	layout->bytes = layout->prefix + input->filename_bytes;
	remainder = layout->bytes % NTFS_USN_RECORD_ALIGNMENT;
	if (remainder != 0) {
		layout->bytes += NTFS_USN_RECORD_ALIGNMENT - remainder;
	}
	return NTFS_OK;
}

static bool
usn_record_separate(const struct ntfs_usn_record *input, const void *output, size_t bytes)
{
	return ntfs_pointer_ranges_separate(input, sizeof(*input), output, bytes) &&
	    ntfs_pointer_ranges_separate(input->filename, input->filename_bytes, output, bytes);
}

enum ntfs_result
ntfs_usn_record_size(const struct ntfs_usn_record *input, size_t *out)
{
	struct usn_layout layout;
	enum ntfs_result result;

	if (!ntfs_pointer_range_valid(out, sizeof(*out))) {
		return NTFS_INVALID;
	}
	result = usn_record_layout(input, &layout);
	if (result != NTFS_OK) {
		return result;
	}
	if (!usn_record_separate(input, out, sizeof(*out))) {
		return NTFS_INVALID;
	}
	*out = layout.bytes;
	return NTFS_OK;
}

enum ntfs_result
ntfs_usn_record_encode(
    const struct ntfs_usn_record *input, void *output, size_t capacity, size_t *written)
{
	struct ntfs_disk_usn_header *header = output;
	struct ntfs_disk_usn_tail *tail;
	struct usn_layout layout;
	uint8_t *bytes = output;
	enum ntfs_result result;

	if (output == NULL || !ntfs_pointer_range_valid(output, capacity) ||
	    !ntfs_pointer_range_valid(written, sizeof(*written))) {
		return NTFS_INVALID;
	}
	result = usn_record_layout(input, &layout);
	if (result != NTFS_OK) {
		return result;
	}
	if (!usn_record_separate(input, output, capacity) ||
	    !usn_record_separate(input, written, sizeof(*written)) ||
	    !ntfs_pointer_ranges_separate(output, capacity, written, sizeof(*written))) {
		return NTFS_INVALID;
	}
	if (capacity < layout.bytes) {
		return NTFS_RANGE;
	}
	/* All admission precedes the first changed byte. The borrowed name can
	 * overlap its immutable description, but never either output. */
	ntfs_zero(output, layout.bytes);
	ntfs_put_u32(header->record_length, (uint32_t)layout.bytes);
	ntfs_put_u16(header->major_version, input->major_version);
	ntfs_put_u16(header->minor_version, input->minor_version);
	ntfs_copy(bytes + sizeof(*header), input->file_id, layout.id_bytes);
	ntfs_copy(bytes + sizeof(*header) + layout.id_bytes, input->parent_id, layout.id_bytes);
	tail = (void *)(bytes + layout.prefix - sizeof(*tail));
	ntfs_put_u64(tail->usn, input->usn);
	ntfs_put_u64(tail->timestamp, input->timestamp);
	ntfs_put_u32(tail->reason, input->reason);
	ntfs_put_u32(tail->source_info, input->source_info);
	ntfs_put_u32(tail->security_id, input->security_id);
	ntfs_put_u32(tail->file_attributes, input->file_attributes);
	ntfs_put_u16(tail->filename_length, (uint16_t)input->filename_bytes);
	ntfs_put_u16(tail->filename_offset, (uint16_t)layout.prefix);
	if (input->filename_bytes != 0) {
		ntfs_copy(bytes + layout.prefix, input->filename, input->filename_bytes);
	}
	*written = layout.bytes;
	return NTFS_OK;
}

enum ntfs_result
ntfs_usn_reason_union(const uint32_t *reasons, size_t count, uint32_t *out)
{
	size_t index, bytes;
	uint32_t combined = 0;

	if (!ntfs_pointer_range_valid(out, sizeof(*out)) ||
	    (uintptr_t)out % _Alignof(uint32_t) != 0) {
		return NTFS_INVALID;
	}
	if (count > SIZE_MAX / sizeof(*reasons) || count > NTFS_USN_MAX_REASON_INPUTS) {
		return NTFS_RANGE;
	}
	bytes = count * sizeof(*reasons);
	if (!ntfs_pointer_range_valid(reasons, bytes) ||
	    (count != 0 && (uintptr_t)reasons % _Alignof(uint32_t) != 0) ||
	    !ntfs_pointer_ranges_separate(reasons, bytes, out, sizeof(*out))) {
		return NTFS_INVALID;
	}
	for (index = 0; index < count; index++) {
		combined |= reasons[index];
	}
	*out = combined;
	return NTFS_OK;
}
