/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "pointer_range.h"
#include "internal.h"
#include <ntfs/logfile_encode.h>
#include <ntfs/record.h>

struct update_layout {
	uint32_t bytes;
	uint16_t lcn_count;
	struct ntfs_logfile_span redo, undo;
};

_Static_assert(NTFS_LOGFILE_RECORD_HEADER_BYTES == sizeof(struct ntfs_disk_log_record),
    "encoded LFS common header");

enum ntfs_result
ntfs_logfile_record_encode(const struct ntfs_logfile_record *record, const void *payload,
    size_t payload_bytes, void *output, size_t capacity)
{
	struct ntfs_disk_log_record *header = output;
	size_t bytes;

	if (output == NULL || !ntfs_pointer_range_valid(record, sizeof(*record))) {
		return NTFS_INVALID;
	}
	if (payload_bytes > NTFS_LOGFILE_MAX_RECORD_BYTES - sizeof(*header)) {
		return NTFS_RANGE;
	}
	bytes = sizeof(*header) + payload_bytes;
	if (capacity < bytes) {
		return NTFS_RANGE;
	}
	if (!ntfs_pointer_ranges_separate(record, sizeof(*record), output, bytes) ||
	    !ntfs_pointer_ranges_separate(payload, payload_bytes, output, bytes) ||
	    record->data.length != payload_bytes || record->lsn == 0 ||
	    record->previous_lsn >= record->lsn || record->undo_next_lsn >= record->lsn ||
	    record->client_index == NTFS_LOGFILE_NO_CLIENT ||
	    record->data.offset < sizeof(*header) ||
	    record->data.offset % NTFS_WIRE_ALIGNMENT != 0) {
		return NTFS_INVALID;
	}
	if (record->data.offset != sizeof(*header) ||
	    (record->flags &
		~(NTFS_LOGFILE_RECORD_MULTI_PAGE | NTFS_LOGFILE_RECORD_DELETING |
		    NTFS_LOGFILE_RECORD_ADDING)) != 0 ||
	    (record->type != NTFS_LOGFILE_RECORD_UPDATE &&
		record->type != NTFS_LOGFILE_RECORD_RESTART)) {
		return NTFS_UNSUPPORTED;
	}
	ntfs_zero(header, sizeof(*header));
	ntfs_put_u64(header->lsn, record->lsn);
	ntfs_put_u64(header->previous_lsn, record->previous_lsn);
	ntfs_put_u64(header->undo_next_lsn, record->undo_next_lsn);
	ntfs_put_u32(header->data_bytes, (uint32_t)payload_bytes);
	ntfs_put_u16(header->client_sequence, record->client_sequence);
	ntfs_put_u16(header->client_index, record->client_index);
	ntfs_put_u32(header->type, record->type);
	ntfs_put_u32(header->transaction, record->transaction);
	ntfs_put_u16(header->flags, record->flags);
	ntfs_copy((uint8_t *)output + sizeof(*header), payload, payload_bytes);
	return NTFS_OK;
}

static enum ntfs_result
update_layout(const struct ntfs_logfile_update_input *input, struct update_layout *layout)
{
	size_t prefix, count, bytes, undo_offset;

	if (input->lcns.bytes % sizeof(uint64_t) != 0) {
		return NTFS_INVALID;
	}
	count = input->lcns.bytes / sizeof(uint64_t);
	if (count > UINT16_MAX || input->redo.bytes > UINT16_MAX ||
	    input->undo.bytes > UINT16_MAX) {
		return NTFS_RANGE;
	}
	/* Wire-width admission bounds every following addition below the record cap. */
	prefix = count == 0 ? sizeof(struct ntfs_disk_log_update_storage)
			    : sizeof(struct ntfs_disk_log_update) + input->lcns.bytes;
	bytes = prefix;
	if (input->redo.bytes != 0) {
		if (prefix > UINT16_MAX) {
			return NTFS_RANGE;
		}
		layout->redo.offset = (uint32_t)prefix;
		bytes += input->redo.bytes;
	}
	if (input->undo.bytes != 0) {
		undo_offset =
		    (bytes + NTFS_WIRE_ALIGNMENT - 1) / NTFS_WIRE_ALIGNMENT * NTFS_WIRE_ALIGNMENT;
		if (undo_offset > UINT16_MAX) {
			return NTFS_RANGE;
		}
		layout->undo.offset = (uint32_t)undo_offset;
		bytes = undo_offset + input->undo.bytes;
	}
	if (bytes > NTFS_LOGFILE_MAX_RECORD_BYTES) {
		return NTFS_RANGE;
	}
	layout->lcn_count = (uint16_t)count;
	layout->redo.length = (uint32_t)input->redo.bytes;
	layout->undo.length = (uint32_t)input->undo.bytes;
	layout->bytes = (uint32_t)bytes;
	return NTFS_OK;
}

static bool
update_inputs_separate(
    const struct ntfs_logfile_update_input *input, const void *output, size_t bytes)
{
	return ntfs_pointer_ranges_separate(input, sizeof(*input), output, bytes) &&
	    ntfs_pointer_ranges_separate(input->lcns.data, input->lcns.bytes, output, bytes) &&
	    ntfs_pointer_ranges_separate(input->redo.data, input->redo.bytes, output, bytes) &&
	    ntfs_pointer_ranges_separate(input->undo.data, input->undo.bytes, output, bytes);
}

enum ntfs_result
ntfs_logfile_update_measure(const struct ntfs_logfile_update_input *input, uint32_t *bytes)
{
	struct update_layout layout = {0};
	enum ntfs_result result;

	if (bytes == NULL || !ntfs_pointer_range_valid(input, sizeof(*input))) {
		return NTFS_INVALID;
	}
	result = update_layout(input, &layout);
	if (result != NTFS_OK) {
		return result;
	}
	if (!update_inputs_separate(input, bytes, sizeof(*bytes))) {
		return NTFS_INVALID;
	}
	*bytes = layout.bytes;
	return NTFS_OK;
}

enum ntfs_result
ntfs_logfile_update_encode(
    const struct ntfs_logfile_update_input *input, void *output, size_t capacity)
{
	struct ntfs_disk_log_update *header = output;
	struct update_layout layout = {0};
	uint8_t *encoded = output;
	size_t redo_end;
	enum ntfs_result result;

	if (output == NULL || !ntfs_pointer_range_valid(input, sizeof(*input))) {
		return NTFS_INVALID;
	}
	result = update_layout(input, &layout);
	if (result != NTFS_OK) {
		return result;
	}
	if (capacity < layout.bytes) {
		return NTFS_RANGE;
	}
	if (!update_inputs_separate(input, output, layout.bytes)) {
		return NTFS_INVALID;
	}
	ntfs_zero(header, sizeof(*header));
	ntfs_put_u16(header->redo_operation, input->redo_operation);
	ntfs_put_u16(header->undo_operation, input->undo_operation);
	ntfs_put_u16(header->redo_offset, (uint16_t)layout.redo.offset);
	ntfs_put_u16(header->redo_bytes, (uint16_t)layout.redo.length);
	ntfs_put_u16(header->undo_offset, (uint16_t)layout.undo.offset);
	ntfs_put_u16(header->undo_bytes, (uint16_t)layout.undo.length);
	ntfs_put_u16(header->target_attribute, input->target_attribute);
	ntfs_put_u16(header->lcns, layout.lcn_count);
	ntfs_put_u16(header->record_offset, input->record_offset);
	ntfs_put_u16(header->attribute_offset, input->attribute_offset);
	ntfs_put_u16(header->cluster_index, input->cluster_index);
	ntfs_put_u16(header->attribute_flags, input->attribute_flags);
	ntfs_put_u64(header->target_vcn, input->target_vcn);
	if (layout.lcn_count == 0) {
		ntfs_zero(encoded + sizeof(*header), sizeof(uint64_t));
	} else {
		ntfs_copy(encoded + sizeof(*header), input->lcns.data, input->lcns.bytes);
	}
	if (layout.redo.length != 0) {
		ntfs_copy(encoded + layout.redo.offset, input->redo.data, layout.redo.length);
	}
	if (layout.undo.length != 0) {
		redo_end = layout.redo.length == 0 ? layout.undo.offset
						   : layout.redo.offset + layout.redo.length;
		ntfs_zero(encoded + redo_end, layout.undo.offset - redo_end);
		ntfs_copy(encoded + layout.undo.offset, input->undo.data, layout.undo.length);
	}
	return NTFS_OK;
}

static enum ntfs_result
page_encode(const struct ntfs_logfile_page_input *input, const void *description,
    size_t description_bytes, bool fast, uint32_t file_offset, void *workspace,
    size_t workspace_bytes, void *output, size_t capacity)
{
	struct ntfs_disk_log_page *header = workspace;
	struct ntfs_disk_log_fast_page *fast_header = workspace;
	uint8_t *restored = workspace;
	size_t bytes, data_offset, usa_count, usa_bytes, prefix;
	uint32_t known_flags;

	if (!ntfs_pointer_range_valid(description, description_bytes) || workspace == NULL ||
	    output == NULL) {
		return NTFS_INVALID;
	}
	known_flags = NTFS_LOGFILE_PAGE_RECORD_END | NTFS_LOGFILE_PAGE_CLIENT_RESTART;
	if (fast) {
		if (input->major != NTFS_LFS_MAJOR_FAST || input->minor != NTFS_LFS_MINOR_FAST ||
		    input->bytes != NTFS_LFS_FAST_PAGE_BYTES) {
			return NTFS_UNSUPPORTED;
		}
	} else if (input->major != NTFS_LFS_MAJOR_LEGACY || input->minor != NTFS_LFS_MINOR_LEGACY) {
		return NTFS_UNSUPPORTED;
	}
	if ((input->page.flags & ~known_flags) != 0) {
		return NTFS_UNSUPPORTED;
	}
	bytes = input->bytes;
	data_offset = input->data_offset;
	if (bytes > NTFS_LOGFILE_MAX_PAGE_BYTES || bytes > NTFS_PROTECTED_RECORD_MAX_BYTES ||
	    capacity < bytes || workspace_bytes < bytes) {
		return NTFS_RANGE;
	}
	if (bytes < NTFS_MST_STRIDE || (bytes & (bytes - 1)) != 0) {
		return NTFS_INVALID;
	}
	usa_count = bytes / NTFS_MST_STRIDE + 1;
	usa_bytes = usa_count * NTFS_MST_WORD_BYTES;
	prefix = fast ? sizeof(*fast_header) : sizeof(*header) + usa_bytes;
	if (data_offset < prefix || data_offset % NTFS_WIRE_ALIGNMENT != 0 ||
	    !ntfs_bounds(data_offset, sizeof(struct ntfs_disk_log_record), bytes) ||
	    input->data.bytes != bytes - data_offset ||
	    input->page.page_position > input->page.page_count ||
	    ((input->page.page_position == 0) != (input->page.page_count == 0)) ||
	    (input->page.next_record_offset != 0 &&
		(input->page.next_record_offset < data_offset ||
		    input->page.next_record_offset > bytes ||
		    input->page.next_record_offset % NTFS_WIRE_ALIGNMENT != 0))) {
		return NTFS_INVALID;
	}
	if (!ntfs_pointer_ranges_separate(description, description_bytes, output, bytes) ||
	    !ntfs_pointer_ranges_separate(input->data.data, input->data.bytes, output, bytes) ||
	    !ntfs_pointer_ranges_separate(description, description_bytes, workspace, bytes) ||
	    !ntfs_pointer_ranges_separate(input->data.data, input->data.bytes, workspace, bytes) ||
	    !ntfs_pointer_ranges_separate(workspace, bytes, output, bytes)) {
		return NTFS_INVALID;
	}
	/* These size limits place the canonical USA wholly before the first stride
	 * tail. The protection helper needs no further fallible input admission. */
	ntfs_zero(restored, data_offset);
	ntfs_copy(header->mst.magic, "RCRD", sizeof(header->mst.magic));
	ntfs_put_u16(header->mst.usa_offset, sizeof(*header));
	ntfs_put_u16(header->mst.usa_count, (uint16_t)usa_count);
	ntfs_put_u64(header->copy_value, input->page.copy_value);
	ntfs_put_u32(header->flags, input->page.flags);
	ntfs_put_u16(header->page_count, input->page.page_count);
	ntfs_put_u16(header->page_position, input->page.page_position);
	ntfs_put_u16(header->next_record_offset, input->page.next_record_offset);
	ntfs_put_u64(header->last_end_lsn, input->page.last_end_lsn);
	ntfs_put_u16(restored + sizeof(*header), input->prior_update_sequence);
	if (fast) {
		ntfs_put_u32(fast_header->file_offset, file_offset);
	}
	ntfs_copy(restored + data_offset, input->data.data, input->data.bytes);
	return ntfs_record_protect(workspace, bytes, output, capacity);
}

enum ntfs_result
ntfs_logfile_page_encode(const struct ntfs_logfile_page_input *input, void *workspace,
    size_t workspace_bytes, void *output, size_t capacity)
{
	return page_encode(
	    input, input, sizeof(*input), false, 0, workspace, workspace_bytes, output, capacity);
}

enum ntfs_result
ntfs_logfile_fast_page_encode(const struct ntfs_logfile_fast_page_input *input, void *workspace,
    size_t workspace_bytes, void *output, size_t capacity)
{
	if (!ntfs_pointer_range_valid(input, sizeof(*input))) {
		return NTFS_INVALID;
	}
	return page_encode(&input->common, input, sizeof(*input), true, input->file_offset,
	    workspace, workspace_bytes, output, capacity);
}
