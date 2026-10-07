/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include "logfile_tables_disk.h"
#include "write_payload.h"

enum ntfs_result
ntfs_write_payload_encode(
    const struct ntfs_logfile_update_input *input, void *memory, size_t capacity, uint32_t *bytes)
{
	struct ntfs_disk_log_update_storage *stored = memory;
	enum ntfs_result result;

	result = ntfs_logfile_update_measure(input, bytes);
	if (result == NTFS_OK) {
		result = ntfs_logfile_update_encode(input, memory, capacity);
	}
	if (result != NTFS_OK) {
		return result;
	}
	if (input->redo.bytes == 0) {
		ntfs_put_u16(stored->header.redo_offset, sizeof(*stored));
	}
	if (input->undo.bytes == 0) {
		ntfs_put_u16(stored->header.undo_offset, (uint16_t)*bytes);
	}
	if (input->undo_operation == NTFS_LOG_OP_COMPENSATION && input->redo.bytes != 0) {
		ntfs_put_u16(stored->header.undo_bytes, (uint16_t)input->redo.bytes);
	}
	if (input->lcns.bytes == 0) {
		ntfs_put_u64(stored->first_lcn, UINT64_MAX);
	}
	return NTFS_OK;
}
