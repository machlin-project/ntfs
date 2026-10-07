/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_transaction.h"

static bool
separate(const void *a, size_t a_bytes, const void *b, size_t b_bytes)
{
	uintptr_t left = (uintptr_t)a, right = (uintptr_t)b;

	return a != NULL && b != NULL && a_bytes <= UINTPTR_MAX - left &&
	    b_bytes <= UINTPTR_MAX - right && (left + a_bytes <= right || right + b_bytes <= left);
}

static enum ntfs_result
settled(struct ntfs_volume *volume, const struct ntfs_write_history *history)
{
	const struct ntfs_write_file_plan *file;
	const struct ntfs_disk_record *header;
	struct ntfs_node *node = NULL;
	size_t index, later, first, end, used;
	enum ntfs_result result;

	if (history->checkpoint_observed ||
	    history->transactions > NTFS_WRITE_HISTORY_TRANSACTIONS) {
		return NTFS_UNSUPPORTED;
	}
	for (index = 0; index < history->transactions; index++) {
		file = &history->transaction[index].file;
		if (!history->transaction[index].committed &&
		    !history->transaction[index].compensated) {
			return NTFS_BUSY;
		}
		for (later = index + 1; later < history->transactions; later++) {
			if (file->reference == history->transaction[later].file.reference) {
				break;
			}
		}
		if (later != history->transactions) {
			continue;
		}
		header = (const void *)file->after;
		used = file->snapshot_bytes;
		first = ntfs_u16(header->mst.usa_offset);
		end = first + (size_t)ntfs_u16(header->mst.usa_count) * sizeof(uint16_t);
		if (end > used || used > NTFS_WRITE_RECORD_BYTES) {
			return NTFS_CORRUPT;
		}
		result = ntfs_node_open(volume, file->reference, &node);
		if (result != NTFS_OK) {
			return result;
		}
		/* Only USA storage changes when the complete home is reprotected. */
		result = ntfs_equal(node->record, file->after, first) &&
			ntfs_equal(node->record + end, file->after + end, used - end)
		    ? NTFS_OK
		    : NTFS_BUSY;
		ntfs_node_close(node);
		node = NULL;
		if (result != NTFS_OK) {
			return result;
		}
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_write_history_settled(struct ntfs_volume *volume, const struct ntfs_write_history *history)
{
	enum ntfs_result result;

	if (volume == NULL || history == NULL) {
		return NTFS_INVALID;
	}
	result = ntfs_operation_enter(volume);
	if (result == NTFS_OK) {
		result = settled(volume, history);
		ntfs_operation_leave(volume);
	}
	return result;
}

static enum ntfs_result
prepare(struct ntfs_node *node, uint64_t filetime, uint64_t offset, const void *data,
    size_t resident_bytes, struct ntfs_write_transaction_workspace *out)
{
	struct ntfs_volume *volume = node->volume;
	struct ntfs_node *log_node = NULL;
	struct ntfs_stream *log = NULL;
	struct ntfs_write_journal_input input = {0};
	struct ntfs_write_log_reservation reservation;
	const struct ntfs_run *run;
	const struct ntfs_disk_record *header = (const void *)node->record;
	uint64_t offsets[NTFS_WRITE_EXECUTE_LOG_LOCATIONS], lcn, vcn, tail;
	size_t index, bytes;
	enum ntfs_result result;

	if (volume->info.sector_size != NTFS_WRITE_SECTOR_BYTES ||
	    volume->info.cluster_size != NTFS_WRITE_CLUSTER_BYTES ||
	    volume->info.record_size != NTFS_WRITE_RECORD_BYTES) {
		return NTFS_UNSUPPORTED;
	}
	if (resident_bytes > NTFS_WRITE_RECORD_BYTES) {
		return NTFS_RANGE;
	}
	result = ntfs_write_history_capture(volume, &out->history_work, &out->history);
	if (result == NTFS_OK) {
		result = settled(volume, &out->history);
	}
	if (result != NTFS_OK) {
		return result;
	}
	if (out->history.selected.flags != NTFS_LOGFILE_RESTART_CLEAN ||
	    out->history.transactions == NTFS_WRITE_HISTORY_TRANSACTIONS) {
		return NTFS_UNSUPPORTED;
	}
	tail = out->history.history.completed_end_lsn;
	result = ntfs_write_journal_reserve_resident_tail(&out->history.origin, tail,
	    (uint16_t)ntfs_u32(header->used), (uint16_t)resident_bytes, &reservation);
	if (result == NTFS_OK) {
		if (resident_bytes != 0) {
			result = ntfs_write_prepare_resident_metadata(node, filetime,
			    reservation.resident_lsn, offset, data, resident_bytes, &out->file);
		} else {
			result = ntfs_write_prepare_metadata(
			    node, filetime, reservation.update_lsn, &out->file);
		}
	}
	if (result == NTFS_OK) {
		result = ntfs_node_by_number(volume, NTFS_LOGFILE_RECORD, &log_node);
	}
	if (result == NTFS_OK) {
		result = ntfs_stream_open(log_node, NULL, 0, &log);
	}
	if (result != NTFS_OK) {
		goto done;
	}
	if (log->resident || log->metadata_only || log->flags != 0 || log->compression_unit != 0 ||
	    log->initialized != log->size) {
		result = NTFS_UNSUPPORTED;
		goto done;
	}
	for (index = 0; index < NTFS_LFS_RESTART_PAGES; index++) {
		result = ntfs_stream_read(log, index * NTFS_WRITE_CLUSTER_BYTES,
		    out->restart[index], NTFS_WRITE_CLUSTER_BYTES, &bytes);
		if (result != NTFS_OK || bytes != NTFS_WRITE_CLUSTER_BYTES) {
			result = result == NTFS_OK ? NTFS_IO : result;
			goto done;
		}
		input.restart[index] = out->restart[index];
		out->execution.restart[index] = out->restart[index];
	}
	offsets[NTFS_WRITE_EXECUTE_RESTART_FIRST] = 0;
	offsets[NTFS_WRITE_EXECUTE_RESTART_SECOND] = NTFS_WRITE_CLUSTER_BYTES;
	offsets[NTFS_WRITE_EXECUTE_PREPARE_HOME] = reservation.prepare_offset;
	offsets[NTFS_WRITE_EXECUTE_COMMIT_HOME] = reservation.commit_offset;
	offsets[NTFS_WRITE_EXECUTE_PREPARE_COPY] =
	    NTFS_LFS_RESTART_PAGES * NTFS_WRITE_CLUSTER_BYTES;
	offsets[NTFS_WRITE_EXECUTE_COMMIT_COPY] =
	    (NTFS_LFS_RESTART_PAGES + 1) * NTFS_WRITE_CLUSTER_BYTES;
	for (index = 0; index < NTFS_WRITE_EXECUTE_LOG_LOCATIONS; index++) {
		if (!ntfs_bounds(offsets[index], NTFS_WRITE_CLUSTER_BYTES, log->initialized)) {
			result = NTFS_CORRUPT;
			goto done;
		}
		vcn = offsets[index] / NTFS_WRITE_CLUSTER_BYTES;
		run = ntfs_run_find(log, vcn);
		if (run == NULL || run->lcn == NTFS_HOLE || vcn < run->vcn ||
		    vcn - run->vcn >= run->length || run->lcn > UINT64_MAX - (vcn - run->vcn)) {
			result = NTFS_CORRUPT;
			goto done;
		}
		lcn = run->lcn + vcn - run->vcn;
		if (lcn >= volume->info.cluster_count ||
		    lcn > UINT64_MAX / NTFS_WRITE_CLUSTER_BYTES) {
			result = NTFS_CORRUPT;
			goto done;
		}
		out->execution.physical[index] = lcn * NTFS_WRITE_CLUSTER_BYTES;
	}
	input.file_bytes = log->size;
	input.tail_lsn = tail;
	input.bootstrap = out->history.packet[0];
	input.checkpoint = out->history.packet[1];
	input.file = &out->file;
	result = ntfs_write_journal_encode(&input, &out->journal_work, &out->journal);
	if (result == NTFS_OK) {
		out->execution.file = &out->file;
		out->execution.journal = &out->journal;
	}

done:
	ntfs_stream_close(log);
	ntfs_node_close(log_node);
	return result;
}

enum ntfs_result
ntfs_write_prepare_transaction(
    struct ntfs_node *node, uint64_t filetime, struct ntfs_write_transaction_workspace *out)
{
	enum ntfs_result result;

	if (node == NULL || out == NULL || !separate(node, sizeof(*node), out, sizeof(*out)) ||
	    !separate(node->volume, sizeof(*node->volume), out, sizeof(*out)) ||
	    !separate(node->record, node->volume->info.record_size, out, sizeof(*out))) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	result = ntfs_operation_enter(node->volume);
	if (result == NTFS_OK) {
		result = prepare(node, filetime, 0, NULL, 0, out);
		ntfs_operation_leave(node->volume);
	}
	if (result != NTFS_OK) {
		ntfs_zero(out, sizeof(*out));
	}
	return result;
}

enum ntfs_result
ntfs_write_prepare_resident_transaction(struct ntfs_node *node, uint64_t filetime, uint64_t offset,
    const void *data, size_t bytes, struct ntfs_write_transaction_workspace *out)
{
	enum ntfs_result result;

	if (node == NULL || data == NULL || bytes == 0 || out == NULL ||
	    !separate(node, sizeof(*node), out, sizeof(*out)) ||
	    !separate(node->volume, sizeof(*node->volume), out, sizeof(*out)) ||
	    !separate(node->record, node->volume->info.record_size, out, sizeof(*out)) ||
	    !separate(data, bytes, out, sizeof(*out))) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	result = ntfs_operation_enter(node->volume);
	if (result == NTFS_OK) {
		result = prepare(node, filetime, offset, data, bytes, out);
		ntfs_operation_leave(node->volume);
	}
	if (result != NTFS_OK) {
		ntfs_zero(out, sizeof(*out));
	}
	return result;
}
