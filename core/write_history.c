/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_history.h"
#include <ntfs/recovery.h>

enum { HISTORY_ORIGIN_PACKETS = 2 };

struct history_context {
	struct ntfs_volume *volume;
	struct ntfs_write_history *out;
};

static bool
separate(const void *left, size_t left_bytes, const void *right, size_t right_bytes)
{
	uintptr_t a = (uintptr_t)left, b = (uintptr_t)right;

	return left != NULL && right != NULL && left_bytes <= UINTPTR_MAX - a &&
	    right_bytes <= UINTPTR_MAX - b && (a + left_bytes <= b || b + right_bytes <= a);
}

static enum ntfs_result
retain(void *context, const struct ntfs_logfile_record_view *view, const void *packet)
{
	struct history_context *work = context;
	struct ntfs_write_history *out = work->out;
	enum ntfs_result result;

	if (out->count == NTFS_WRITE_HISTORY_PACKETS ||
	    view->bytes > NTFS_WRITE_HISTORY_PACKET_BYTES) {
		return NTFS_RANGE;
	}
	if (view->record.client_index != 0 ||
	    view->record.client_sequence != out->client.sequence) {
		return NTFS_STALE;
	}
	result = ntfs_work(work->volume, view->bytes);
	if (result != NTFS_OK) {
		return result;
	}
	ntfs_copy(out->packet[out->count], packet, view->bytes);
	out->bytes[out->count] = view->bytes;
	out->count++;
	return NTFS_OK;
}

static enum ntfs_result
bind_checkpoint(
    struct ntfs_write_history_workspace *work, struct ntfs_write_history *out, size_t first)
{
	struct ntfs_logfile_restart origin = out->origin;
	struct ntfs_logfile_client client = out->client;

	origin.current_lsn = work->replay.reservation.checkpoint_lsn;
	client.oldest_lsn = work->replay.reservation.bootstrap_lsn;
	client.restart_lsn = work->replay.reservation.checkpoint_lsn;
	if (!out->replay.committed || out->bytes[first] != NTFS_WRITE_BOOTSTRAP_BYTES ||
	    out->bytes[first + 1] != NTFS_WRITE_CHECKPOINT_BYTES ||
	    !ntfs_equal(out->packet[0] + sizeof(struct ntfs_disk_log_record),
		out->packet[first] + sizeof(struct ntfs_disk_log_record),
		NTFS_WRITE_BOOTSTRAP_BYTES - sizeof(struct ntfs_disk_log_record)) ||
	    out->history.completed_end_lsn != origin.current_lsn) {
		return NTFS_CORRUPT;
	}
	return ntfs_write_quiet_bind(&origin, &client, out->packet[first], out->packet[first + 1]);
}

enum ntfs_result
ntfs_write_history_bind_previous(const struct ntfs_write_replay_plan *plans, size_t count,
    const struct ntfs_write_replay_plan *current)
{
	const struct ntfs_write_file_plan *previous;
	const struct ntfs_disk_record *header = (const void *)current->file.before;
	size_t index, used = current->file.snapshot_bytes;
	size_t first = ntfs_u16(header->mst.usa_offset), end;

	end = first + (size_t)ntfs_u16(header->mst.usa_count) * sizeof(uint16_t);
	if (end > used) {
		return NTFS_CORRUPT;
	}
	for (index = count; index > 0; index--) {
		previous = &plans[index - 1].file;
		if (previous->reference != current->file.reference) {
			continue;
		}
		/* USA storage advances on each home publication. Unused FILE padding
		 * is not part of the snapshot. Every other used byte must follow the
		 * preceding exact transaction on this sequence-bearing reference. */
		return previous->snapshot_bytes == used &&
			ntfs_equal(previous->after, current->file.before, first) &&
			ntfs_equal(previous->after + end, current->file.before + end, used - end)
		    ? NTFS_OK
		    : NTFS_CORRUPT;
	}
	return NTFS_OK;
}

static enum ntfs_result
history_buffer_update(const struct ntfs_logfile_buffer *packet, struct ntfs_logfile_update *update)
{
	struct ntfs_logfile_record record;
	enum ntfs_result result;

	result = ntfs_logfile_record_decode(
	    packet->data, packet->bytes, sizeof(struct ntfs_disk_log_record), &record);
	if (result != NTFS_OK) {
		return result;
	}
	return ntfs_logfile_update_decode(
	    (const uint8_t *)packet->data + record.data.offset, record.data.length, update);
}

enum ntfs_result
ntfs_write_history_prepare_transaction(struct ntfs_volume *volume,
    const struct ntfs_logfile_restart *origin, uint64_t tail_lsn,
    const struct ntfs_logfile_buffer *packet, size_t packets,
    struct ntfs_write_replay_workspace *work, struct ntfs_write_replay_plan *out, size_t *consumed)
{
	struct ntfs_write_replay_input input = {0};
	struct ntfs_logfile_update update;
	size_t index, count;
	enum ntfs_result result;

	if (volume == NULL || origin == NULL || packet == NULL || work == NULL || out == NULL ||
	    consumed == NULL) {
		return NTFS_INVALID;
	}
	if (packets < NTFS_WRITE_REPLAY_COMMIT) {
		return NTFS_UNSUPPORTED;
	}
	input.restart = *origin;
	input.tail_lsn = tail_lsn;
	ntfs_zero(input.packet, sizeof(input.packet));
	ntfs_zero(&input.abort, sizeof(input.abort));
	ntfs_zero(&input.resident, sizeof(input.resident));
	ntfs_zero(&input.resident_compensation, sizeof(input.resident_compensation));
	count = NTFS_WRITE_REPLAY_COMMIT;
	for (index = 0; index < count; index++) {
		input.packet[index] = packet[index];
	}
	index = count;
	if (index < packets) {
		result = history_buffer_update(&packet[index], &update);
		if (result != NTFS_OK) {
			return result;
		}
		if (update.redo_operation == NTFS_LOG_OP_UPDATE_RESIDENT_VALUE &&
		    update.undo_operation == NTFS_LOG_OP_UPDATE_RESIDENT_VALUE) {
			input.resident = packet[index];
			count++;
			index++;
		}
	}
	if (index < packets) {
		result = history_buffer_update(&packet[index], &update);
		if (result != NTFS_OK) {
			return result;
		}
		if (update.redo_operation == NTFS_LOG_OP_UPDATE_RESIDENT_VALUE &&
		    update.undo_operation == NTFS_LOG_OP_COMPENSATION) {
			if (input.resident.bytes != 0) {
				input.resident_compensation = packet[index];
				count++;
				index++;
			}
			if (packets - index < 2) {
				return NTFS_UNSUPPORTED;
			}
			input.abort = packet[index + 1];
			count++;
		}
		input.packet[NTFS_WRITE_REPLAY_COMMIT] = packet[index];
		count++;
	}
	result = ntfs_write_replay_prepare(volume, &input, work, out);
	if (result != NTFS_OK) {
		return result;
	}
	if (out->packets != count) {
		return NTFS_CORRUPT;
	}
	*consumed = count;
	return NTFS_OK;
}

static enum ntfs_result
bind_history(struct ntfs_volume *volume, struct ntfs_write_history_workspace *work,
    struct ntfs_write_history *out)
{
	struct ntfs_write_replay_input input = {0};
	struct ntfs_write_replay_plan *current;
	struct ntfs_logfile_record record;
	struct ntfs_logfile_buffer packet[NTFS_WRITE_REPLAY_MAX_PACKETS];
	size_t index, first, count;
	enum ntfs_result result;

	if (!out->history.complete || !out->history.endpoint_verified ||
	    out->history.tail_lsn != 0 || out->bytes[0] != NTFS_WRITE_BOOTSTRAP_BYTES ||
	    out->bytes[1] != NTFS_WRITE_CHECKPOINT_BYTES ||
	    !ntfs_equal(out->packet[1], work->checkpoint_packet, NTFS_WRITE_CHECKPOINT_BYTES)) {
		return NTFS_UNSUPPORTED;
	}
	result = ntfs_write_quiet_bind(&out->origin, &out->client, out->packet[0], out->packet[1]);
	if (result != NTFS_OK) {
		return result;
	}
	if (out->count == HISTORY_ORIGIN_PACKETS) {
		return out->selected.current_lsn == out->origin.current_lsn &&
			out->history.completed_end_lsn == out->origin.current_lsn &&
			out->selected.last_data_bytes == out->origin.last_data_bytes
		    ? NTFS_OK
		    : NTFS_UNSUPPORTED;
	}
	input.restart = out->origin;
	first = HISTORY_ORIGIN_PACKETS;
	while (first < out->count) {
		if (out->count - first == HISTORY_ORIGIN_PACKETS && out->transactions != 0) {
			result = bind_checkpoint(work, out, first);
			if (result != NTFS_OK) {
				return result;
			}
			out->checkpoint_observed = true;
			break;
		}
		if (out->count - first < NTFS_WRITE_REPLAY_COMMIT) {
			return NTFS_UNSUPPORTED;
		}
		if (out->transactions == NTFS_WRITE_HISTORY_TRANSACTIONS) {
			return NTFS_RANGE;
		}
		count = out->count - first;
		if (count > NTFS_WRITE_REPLAY_MAX_PACKETS) {
			count = NTFS_WRITE_REPLAY_MAX_PACKETS;
		}
		for (index = 0; index < count; index++) {
			packet[index] = (struct ntfs_logfile_buffer){
			    out->packet[first + index], out->bytes[first + index]};
		}
		current = &out->transaction[out->transactions];
		result = ntfs_write_history_prepare_transaction(volume, &input.restart,
		    input.tail_lsn, packet, count, &work->replay, current, &count);
		if (result != NTFS_OK) {
			return result;
		}
		if (current->packets != count) {
			return NTFS_CORRUPT;
		}
		result =
		    ntfs_write_history_bind_previous(out->transaction, out->transactions, current);
		if (result != NTFS_OK) {
			return result;
		}
		out->transactions++;
		ntfs_copy(&out->replay, current, sizeof(out->replay));
		input.tail_lsn = current->end_lsn;
		first += count;
		if (!current->committed && !current->compensated && first != out->count) {
			return NTFS_UNSUPPORTED;
		}
	}
	out->pending = out->transactions != 0;
	if (!out->checkpoint_observed && out->history.completed_end_lsn != input.tail_lsn) {
		return NTFS_CORRUPT;
	}
	/* A later LFS restart endpoint must itself name one of these exact retained
	 * complete packets, with its matching payload length. It is not a ceiling. */
	for (index = 1; index < out->count; index++) {
		result = ntfs_logfile_record_decode(out->packet[index], out->bytes[index],
		    sizeof(struct ntfs_disk_log_record), &record);
		if (result != NTFS_OK) {
			return result;
		}
		if (record.lsn == out->selected.current_lsn) {
			return record.data.length == out->selected.last_data_bytes ? NTFS_OK
										   : NTFS_CORRUPT;
		}
	}
	return NTFS_STALE;
}

static enum ntfs_result
capture(struct ntfs_volume *volume, struct ntfs_write_history_workspace *work,
    struct ntfs_write_history *out)
{
	struct ntfs_logfile *source = NULL;
	struct ntfs_logfile_limits limits;
	struct history_context context = {volume, out};
	enum ntfs_result result;

	ntfs_logfile_default_limits(&limits);
	limits.max_read_calls = NTFS_RECOVERY_DEFAULT_READ_CALLS;
	limits.max_read_bytes = NTFS_RECOVERY_DEFAULT_READ_BYTES;
	result = ntfs_logfile_open_volume_retained_impl(volume, &limits, &work->discovery, &source);
	if (result == NTFS_OK) {
		result = ntfs_logfile_get_restart(source, &out->selected);
	}
	if (result == NTFS_OK) {
		result = ntfs_logfile_get_client(source, 0, &out->client);
	}
	if (result == NTFS_OK) {
		out->origin = out->selected;
		/* This value describes the captured owning checkpoint, rather than
		 * pretending a later physical endpoint was the writer's quiet origin. */
		out->origin.current_lsn = out->client.restart_lsn;
		result = ntfs_logfile_prepare_page_index(
		    source, NTFS_WRITE_HISTORY_INDEX_BYTES, &work->index);
	}
	if (result == NTFS_OK) {
		result = ntfs_logfile_capture_checkpoint(source, 0, out->client.sequence, NULL,
		    work->checkpoint_packet, sizeof(work->checkpoint_packet), NULL, 0,
		    &work->capture, &work->checkpoint);
	}
	if (result == NTFS_OK &&
	    (work->capture.bytes != NTFS_WRITE_CHECKPOINT_BYTES ||
		work->capture.snapshot.present_mask != 0 ||
		work->capture.client.oldest_lsn != work->capture.restart.analysis_lsn)) {
		result = NTFS_UNSUPPORTED;
	}
	if (result == NTFS_OK) {
		out->origin.last_data_bytes =
		    NTFS_WRITE_CHECKPOINT_BYTES - sizeof(struct ntfs_disk_log_record);
		result = ntfs_logfile_visit_records(source, out->client.oldest_lsn,
		    NTFS_WRITE_HISTORY_PACKETS, work->record, sizeof(work->record), retain,
		    &context, &work->history);
		out->history = work->history;
	}
	if (result == NTFS_OK) {
		result = bind_history(volume, work, out);
	}
	ntfs_logfile_close(source);
	return result;
}

enum ntfs_result
ntfs_write_history_capture(struct ntfs_volume *volume, struct ntfs_write_history_workspace *work,
    struct ntfs_write_history *out)
{
	enum ntfs_result result;

	if (volume == NULL || work == NULL || out == NULL ||
	    !separate(volume, sizeof(*volume), out, sizeof(*out)) ||
	    !separate(volume, sizeof(*volume), work, sizeof(*work)) ||
	    !separate(work, sizeof(*work), out, sizeof(*out))) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	result = ntfs_operation_enter(volume);
	if (result == NTFS_OK) {
		result = capture(volume, work, out);
		ntfs_operation_leave(volume);
	}
	if (result != NTFS_OK) {
		ntfs_zero(out, sizeof(*out));
	}
	return result;
}
