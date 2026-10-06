/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_internal.h"
#include <ntfs/record.h>

enum {
	REPLAY_CHANGE_BYTES =
	    NTFS_WRITE_STANDARD_BYTES - offsetof(struct ntfs_disk_standard, modified),
	REPLAY_OPEN_BYTES = sizeof(struct ntfs_disk_log_record) +
	    sizeof(struct ntfs_disk_log_update_storage) +
	    sizeof(struct ntfs_disk_log_open_attribute),
	REPLAY_UPDATE_BYTES = sizeof(struct ntfs_disk_log_record) +
	    sizeof(struct ntfs_disk_log_update_storage) + 2 * REPLAY_CHANGE_BYTES,
	REPLAY_COMPENSATION_BYTES = sizeof(struct ntfs_disk_log_record) +
	    sizeof(struct ntfs_disk_log_update_storage) + REPLAY_CHANGE_BYTES,
	REPLAY_COMMIT_BYTES =
	    sizeof(struct ntfs_disk_log_record) + sizeof(struct ntfs_disk_log_update_storage)
};

static bool
separate(const void *left, size_t left_bytes, const void *right, size_t right_bytes)
{
	uintptr_t a = (uintptr_t)left, b = (uintptr_t)right;

	return (left != NULL || left_bytes == 0) && (right != NULL || right_bytes == 0) &&
	    left_bytes <= UINTPTR_MAX - a && right_bytes <= UINTPTR_MAX - b &&
	    (left_bytes == 0 || right_bytes == 0 || a + left_bytes <= b || b + right_bytes <= a);
}

static const uint8_t *
body(const struct ntfs_write_replay_input *input, const struct ntfs_write_replay_workspace *work,
    size_t index)
{
	return (const uint8_t *)input->packet[index].data + work->record[index].data.offset;
}

static enum ntfs_result
decode_packets(const struct ntfs_write_replay_input *input,
    struct ntfs_write_replay_workspace *work, bool committed)
{
	const struct ntfs_logfile_buffer *packet;
	struct ntfs_logfile_record *record;
	size_t index, count = committed ? NTFS_WRITE_REPLAY_PACKETS : NTFS_WRITE_REPLAY_COMMIT;
	enum ntfs_result result;

	for (index = 0; index < count; index++) {
		packet = &input->packet[index];
		record = &work->record[index];
		result = ntfs_logfile_record_decode(
		    packet->data, packet->bytes, sizeof(struct ntfs_disk_log_record), record);
		if (result != NTFS_OK) {
			return result;
		}
		if (record->type != NTFS_LOGFILE_RECORD_UPDATE || record->client_index != 0 ||
		    (size_t)record->data.offset + record->data.length != packet->bytes ||
		    (index != 0 && record->client_sequence != work->record[0].client_sequence)) {
			return NTFS_UNSUPPORTED;
		}
		result = ntfs_logfile_update_decode(
		    body(input, work, index), record->data.length, &work->update[index]);
		if (result != NTFS_OK) {
			return result;
		}
	}
	return NTFS_OK;
}

static bool
empty_target(const struct ntfs_logfile_update *update)
{
	return update->target_attribute == NTFS_WRITE_MFT_KEY &&
	    update->attribute_flags == NTFS_WRITE_MFT_TARGET_FLAG && update->lcn_count == 0 &&
	    update->record_offset == 0 && update->attribute_offset == 0 &&
	    update->cluster_index == 0 && update->target_vcn == 0;
}

static enum ntfs_result
bind_open(
    const struct ntfs_write_replay_input *input, const struct ntfs_write_replay_workspace *work)
{
	const struct ntfs_logfile_record *record = &work->record[NTFS_WRITE_REPLAY_OPEN];
	const struct ntfs_logfile_update *update = &work->update[NTFS_WRITE_REPLAY_OPEN];
	const uint8_t *payload = body(input, work, NTFS_WRITE_REPLAY_OPEN);
	const struct ntfs_disk_log_open_attribute *entry;

	if (input->packet[NTFS_WRITE_REPLAY_OPEN].bytes != REPLAY_OPEN_BYTES ||
	    record->flags != NTFS_LOGFILE_RECORD_ADDING ||
	    record->transaction != NTFS_WRITE_MFT_KEY || record->previous_lsn != 0 ||
	    record->undo_next_lsn != 0 ||
	    update->redo_operation != NTFS_LOG_OP_OPEN_NONRESIDENT_ATTRIBUTE ||
	    update->undo_operation != NTFS_LOG_OP_NOOP || !empty_target(update) ||
	    update->redo.offset != sizeof(struct ntfs_disk_log_update_storage) ||
	    update->redo.length != sizeof(*entry) || update->undo.offset != record->data.length ||
	    update->undo.length != 0 ||
	    ntfs_u64(payload + sizeof(struct ntfs_disk_log_update)) != UINT64_MAX) {
		return NTFS_UNSUPPORTED;
	}
	entry = (const void *)(payload + update->redo.offset);
	if (ntfs_u32(entry->allocated) != NTFS_LOG_TABLE_ALLOCATED ||
	    ntfs_u32(entry->index_buffer_bytes) != 0 ||
	    ntfs_u32(entry->attribute_type) != NTFS_ATTRIBUTE_DATA || entry->dirty_pages != 0 ||
	    ntfs_u64(entry->name_pointer) != 0 ||
	    ntfs_u64(entry->reference) != (UINT64_C(1) << NTFS_REFERENCE_SEQUENCE_SHIFT) ||
	    ntfs_u64(entry->open_lsn) != input->restart.current_lsn) {
		return NTFS_UNSUPPORTED;
	}
	return NTFS_OK;
}

static enum ntfs_result
bind_snapshot(struct ntfs_volume *volume, const struct ntfs_write_replay_input *input,
    struct ntfs_write_replay_workspace *work, struct ntfs_write_replay_plan *out)
{
	const struct ntfs_logfile_record *record = &work->record[NTFS_WRITE_REPLAY_SNAPSHOT];
	const struct ntfs_logfile_update *update = &work->update[NTFS_WRITE_REPLAY_SNAPSHOT];
	const uint8_t *payload = body(input, work, NTFS_WRITE_REPLAY_SNAPSHOT);
	const struct ntfs_disk_record *header;
	const struct ntfs_disk_record_extension *extension;
	const struct ntfs_run *run;
	struct ntfs_node *mft = NULL;
	uint64_t number, position, vcn, lcn;
	enum ntfs_result result;

	if (record->flags != NTFS_LOGFILE_RECORD_ADDING ||
	    record->transaction != NTFS_WRITE_TRANSACTION_KEY || record->previous_lsn != 0 ||
	    record->undo_next_lsn != 0 ||
	    update->redo_operation != NTFS_LOG_OP_INITIALIZE_FILE_RECORD ||
	    update->undo_operation != NTFS_LOG_OP_NOOP || update->undo.length != 0 ||
	    update->target_attribute != NTFS_WRITE_MFT_KEY ||
	    update->attribute_flags != NTFS_WRITE_MFT_TARGET_FLAG || update->lcn_count != 1 ||
	    update->record_offset != 0 || update->attribute_offset != 0 ||
	    update->redo.offset != sizeof(struct ntfs_disk_log_update_storage) ||
	    update->undo.offset != record->data.length ||
	    update->redo.length < sizeof(*header) + sizeof(*extension) ||
	    update->redo.length > NTFS_WRITE_RECORD_BYTES) {
		return NTFS_UNSUPPORTED;
	}
	ntfs_zero(work->snapshot, sizeof(work->snapshot));
	ntfs_copy(work->snapshot, payload + update->redo.offset, update->redo.length);
	header = (const void *)work->snapshot;
	extension = (const void *)(work->snapshot + sizeof(*header));
	if (ntfs_u32(header->used) != update->redo.length ||
	    update->redo.length % NTFS_WIRE_ALIGNMENT != 0 ||
	    ntfs_u32(header->allocated) != NTFS_WRITE_RECORD_BYTES ||
	    ntfs_u16(header->flags) != NTFS_RECORD_IN_USE || ntfs_u16(header->sequence) == 0 ||
	    ntfs_u64(header->base_reference) != 0 ||
	    ntfs_u16(header->mst.usa_offset) != sizeof(*header) + sizeof(*extension) ||
	    ntfs_u16(header->mst.usa_count) != NTFS_WRITE_RECORD_BYTES / NTFS_MST_STRIDE + 1) {
		return NTFS_UNSUPPORTED;
	}
	result = ntfs_record_protect(
	    work->snapshot, sizeof(work->snapshot), work->checked, sizeof(work->checked));
	if (result == NTFS_OK) {
		result = ntfs_record_validate(work->checked, sizeof(work->checked));
	}
	if (result != NTFS_OK) {
		return result;
	}
	number = ntfs_u32(extension->record_number);
	position = number * (uint64_t)NTFS_WRITE_RECORD_BYTES;
	vcn = position / NTFS_WRITE_CLUSTER_BYTES;
	if (number < NTFS_FIRST_USER_RECORD || update->target_vcn != vcn ||
	    update->cluster_index !=
		position % NTFS_WRITE_CLUSTER_BYTES / NTFS_WRITE_SECTOR_BYTES ||
	    !ntfs_bounds(position, NTFS_WRITE_RECORD_BYTES, volume->mft->initialized)) {
		return NTFS_CORRUPT;
	}
	run = ntfs_run_find(volume->mft, vcn);
	if (run == NULL || run->lcn == NTFS_HOLE || run->lcn > UINT64_MAX - (vcn - run->vcn)) {
		return NTFS_CORRUPT;
	}
	lcn = run->lcn + vcn - run->vcn;
	if (lcn != ntfs_u64(payload + update->lcns.offset) || lcn >= volume->info.cluster_count ||
	    lcn > UINT64_MAX / NTFS_WRITE_CLUSTER_BYTES ||
	    !ntfs_bounds(lcn * NTFS_WRITE_CLUSTER_BYTES, NTFS_WRITE_CLUSTER_BYTES,
		volume->info.size_bytes)) {
		return NTFS_CORRUPT;
	}
	result = ntfs_node_by_number(volume, NTFS_MFT_RECORD, &mft);
	if (result != NTFS_OK) {
		return result;
	}
	out->file.mft_reference = mft->reference;
	ntfs_node_close(mft);
	if (out->file.mft_reference != (UINT64_C(1) << NTFS_REFERENCE_SEQUENCE_SHIFT)) {
		return NTFS_STALE;
	}
	out->file.reference =
	    (uint64_t)ntfs_u16(header->sequence) << NTFS_REFERENCE_SEQUENCE_SHIFT | number;
	out->file.target_vcn = vcn;
	out->file.target_lcn = lcn;
	out->file.cluster_physical = lcn * NTFS_WRITE_CLUSTER_BYTES;
	out->file.cluster_index = update->cluster_index;
	out->file.snapshot_bytes = (uint16_t)update->redo.length;
	ntfs_copy(out->file.before, work->snapshot, sizeof(out->file.before));
	return NTFS_OK;
}

static enum ntfs_result
bind_change(struct ntfs_volume *volume, const struct ntfs_write_replay_input *input,
    struct ntfs_write_replay_workspace *work, struct ntfs_write_replay_plan *out)
{
	const struct ntfs_logfile_record *record = &work->record[NTFS_WRITE_REPLAY_UPDATE];
	const struct ntfs_logfile_update *update = &work->update[NTFS_WRITE_REPLAY_UPDATE];
	const uint8_t *payload = body(input, work, NTFS_WRITE_REPLAY_UPDATE);
	struct ntfs_attr_view standard, list, reparse;
	struct ntfs_node snapshot_node = {0};
	struct ntfs_stream *stream = NULL;
	const uint8_t *value;
	struct ntfs_disk_standard *after;
	struct ntfs_disk_record *header;
	size_t bytes, attribute_offset, value_offset, change;
	uint64_t modified, changed;
	enum ntfs_result result;

	if (input->packet[NTFS_WRITE_REPLAY_UPDATE].bytes != REPLAY_UPDATE_BYTES ||
	    record->flags != 0 || record->transaction != NTFS_WRITE_TRANSACTION_KEY ||
	    record->previous_lsn != work->record[NTFS_WRITE_REPLAY_SNAPSHOT].lsn ||
	    record->undo_next_lsn != record->previous_lsn ||
	    update->redo_operation != NTFS_LOG_OP_UPDATE_RESIDENT_VALUE ||
	    update->undo_operation != NTFS_LOG_OP_UPDATE_RESIDENT_VALUE || update->lcn_count != 1 ||
	    update->target_attribute != NTFS_WRITE_MFT_KEY ||
	    update->attribute_flags != NTFS_WRITE_MFT_TARGET_FLAG ||
	    update->target_vcn != out->file.target_vcn ||
	    update->cluster_index != out->file.cluster_index ||
	    ntfs_u64(payload + update->lcns.offset) != out->file.target_lcn ||
	    update->redo.offset != sizeof(struct ntfs_disk_log_update_storage) ||
	    update->redo.length != REPLAY_CHANGE_BYTES ||
	    update->undo.length != REPLAY_CHANGE_BYTES ||
	    update->undo.offset != update->redo.offset + update->redo.length) {
		return NTFS_UNSUPPORTED;
	}
	result = ntfs_attr_find(
	    work->snapshot, sizeof(work->snapshot), NTFS_ATTR_LIST, NULL, 0, UINT16_MAX, &list);
	if (result != NTFS_NOT_FOUND) {
		return result == NTFS_OK ? NTFS_UNSUPPORTED : result;
	}
	result = ntfs_attr_find(work->snapshot, sizeof(work->snapshot),
	    NTFS_ATTRIBUTE_REPARSE_POINT, NULL, 0, UINT16_MAX, &reparse);
	if (result != NTFS_NOT_FOUND) {
		return result == NTFS_OK ? NTFS_UNSUPPORTED : result;
	}
	result = ntfs_attr_find(work->snapshot, sizeof(work->snapshot), NTFS_ATTR_STANDARD, NULL, 0,
	    UINT16_MAX, &standard);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_attr_value(&standard, &value, &bytes);
	if (result != NTFS_OK || standard.flags != 0 || bytes != NTFS_WRITE_STANDARD_BYTES) {
		return result == NTFS_OK ? NTFS_UNSUPPORTED : result;
	}
	attribute_offset = (size_t)(standard.bytes - work->snapshot);
	value_offset = (size_t)(value - standard.bytes);
	change = attribute_offset + value_offset + offsetof(struct ntfs_disk_standard, modified);
	if (update->record_offset != attribute_offset ||
	    update->attribute_offset !=
		value_offset + offsetof(struct ntfs_disk_standard, modified) ||
	    !ntfs_bounds(change, REPLAY_CHANGE_BYTES, out->file.snapshot_bytes) ||
	    !ntfs_equal(value + offsetof(struct ntfs_disk_standard, modified),
		payload + update->undo.offset, REPLAY_CHANGE_BYTES)) {
		return NTFS_CORRUPT;
	}
	if ((ntfs_u32(((const struct ntfs_disk_standard *)value)->attributes) &
		(NTFS_FILE_READ_ONLY | NTFS_FILE_SYSTEM | NTFS_FILE_DIRECTORY | NTFS_FILE_REPARSE |
		    NTFS_FILE_SPARSE | NTFS_FILE_COMPRESSED | NTFS_FILE_ENCRYPTED)) != 0) {
		return NTFS_UNSUPPORTED;
	}
	/* The private attribute reader does not publish a node/volume metadata memo.
	 * This transient context only validates mappings in the captured before image. */
	snapshot_node.volume = volume;
	snapshot_node.reference = out->file.reference;
	snapshot_node.record = work->snapshot;
	result = ntfs_attribute_open(&snapshot_node, NTFS_ATTRIBUTE_DATA, NULL, 0, &stream);
	if (result != NTFS_OK) {
		return result;
	}
	if (stream->resident || stream->flags != 0 || stream->compression_unit != 0) {
		result = NTFS_UNSUPPORTED;
	}
	ntfs_stream_close(stream);
	if (result != NTFS_OK) {
		return result;
	}
	modified = ntfs_u64(payload + update->redo.offset);
	changed = ntfs_u64(payload + update->redo.offset + sizeof(uint64_t));
	if (modified > INT64_MAX || changed != modified ||
	    ntfs_u64(((const struct ntfs_disk_record *)work->snapshot)->lsn) >= record->lsn) {
		return NTFS_STALE;
	}
	ntfs_copy(out->file.after, work->snapshot, sizeof(out->file.after));
	header = (void *)out->file.after;
	after = (void *)(out->file.after + attribute_offset + value_offset);
	ntfs_put_u64(header->lsn, record->lsn);
	ntfs_put_u64(after->modified, modified);
	ntfs_put_u64(after->changed, changed);
	ntfs_put_u32(after->attributes, ntfs_u32(after->attributes) | NTFS_FILE_ARCHIVE);
	if (!ntfs_equal(
		out->file.after + change, payload + update->redo.offset, REPLAY_CHANGE_BYTES)) {
		return NTFS_CORRUPT;
	}
	out->file.record_offset = update->record_offset;
	out->file.attribute_offset = update->attribute_offset;
	out->file.change_bytes = REPLAY_CHANGE_BYTES;
	return NTFS_OK;
}

static enum ntfs_result
bind_compensation(const struct ntfs_write_replay_input *input,
    struct ntfs_write_replay_workspace *work, struct ntfs_write_replay_plan *out)
{
	const struct ntfs_logfile_record *record = &work->record[NTFS_WRITE_REPLAY_COMMIT];
	const struct ntfs_logfile_update *update = &work->update[NTFS_WRITE_REPLAY_COMMIT];
	const uint8_t *payload = body(input, work, NTFS_WRITE_REPLAY_COMMIT);
	const uint8_t *original = body(input, work, NTFS_WRITE_REPLAY_UPDATE);
	struct ntfs_disk_record *header;
	enum ntfs_result result;

	if (input->packet[NTFS_WRITE_REPLAY_COMMIT].bytes != REPLAY_COMPENSATION_BYTES ||
	    record->lsn != work->reservation.commit_lsn || record->flags != 0 ||
	    record->transaction != NTFS_WRITE_TRANSACTION_KEY ||
	    record->previous_lsn != work->reservation.update_lsn ||
	    record->undo_next_lsn != work->reservation.snapshot_lsn ||
	    update->redo_operation != NTFS_LOG_OP_UPDATE_RESIDENT_VALUE ||
	    update->undo_operation != NTFS_LOG_OP_COMPENSATION ||
	    update->target_attribute != NTFS_WRITE_MFT_KEY ||
	    update->attribute_flags != NTFS_WRITE_MFT_TARGET_FLAG || update->lcn_count != 1 ||
	    update->target_vcn != out->file.target_vcn ||
	    update->cluster_index != out->file.cluster_index ||
	    update->record_offset != out->file.record_offset ||
	    update->attribute_offset != out->file.attribute_offset ||
	    update->redo.offset != sizeof(struct ntfs_disk_log_update_storage) ||
	    update->redo.length != REPLAY_CHANGE_BYTES ||
	    update->undo.offset != record->data.length || update->undo.length != 0 ||
	    update->compensation_undo_bytes != REPLAY_CHANGE_BYTES ||
	    ntfs_u64(payload + update->lcns.offset) != out->file.target_lcn ||
	    !ntfs_equal(payload + update->redo.offset,
		original + work->update[NTFS_WRITE_REPLAY_UPDATE].undo.offset,
		REPLAY_CHANGE_BYTES)) {
		return NTFS_UNSUPPORTED;
	}
	result = ntfs_logfile_record_decode(input->abort.data, input->abort.bytes,
	    sizeof(struct ntfs_disk_log_record), &work->abort_record);
	if (result != NTFS_OK) {
		return result;
	}
	record = &work->abort_record;
	if (input->abort.bytes != REPLAY_COMMIT_BYTES ||
	    record->lsn !=
		work->reservation.commit_lsn + REPLAY_COMPENSATION_BYTES / NTFS_WIRE_ALIGNMENT ||
	    record->type != NTFS_LOGFILE_RECORD_UPDATE ||
	    record->client_sequence != work->record[0].client_sequence ||
	    record->client_index != 0 || record->flags != NTFS_LOGFILE_RECORD_DELETING ||
	    record->transaction != NTFS_WRITE_TRANSACTION_KEY ||
	    record->previous_lsn != work->reservation.commit_lsn || record->undo_next_lsn != 0) {
		return NTFS_UNSUPPORTED;
	}
	payload = (const uint8_t *)input->abort.data + record->data.offset;
	result = ntfs_logfile_update_decode(payload, record->data.length, &work->abort_update);
	if (result != NTFS_OK) {
		return result;
	}
	update = &work->abort_update;
	if (update->redo_operation != NTFS_LOG_OP_FORGET_TRANSACTION ||
	    update->undo_operation != NTFS_LOG_OP_COMPENSATION || !empty_target(update) ||
	    update->redo.offset != sizeof(struct ntfs_disk_log_update_storage) ||
	    update->redo.length != 0 || update->undo.offset != update->redo.offset ||
	    update->undo.length != 0 || update->compensation_undo_bytes != 0 ||
	    ntfs_u64(payload + sizeof(struct ntfs_disk_log_update)) != UINT64_MAX) {
		return NTFS_UNSUPPORTED;
	}
	ntfs_copy(out->file.after, out->file.before, sizeof(out->file.after));
	header = (void *)out->file.after;
	ntfs_put_u64(header->lsn, work->reservation.commit_lsn);
	out->compensated = true;
	out->compensation_lsn = work->reservation.commit_lsn;
	out->abort_lsn = record->lsn;
	return NTFS_OK;
}

static enum ntfs_result
prepare(struct ntfs_volume *volume, const struct ntfs_write_replay_input *input,
    struct ntfs_write_replay_workspace *work, struct ntfs_write_replay_plan *out)
{
	const struct ntfs_logfile_record *record;
	const struct ntfs_logfile_update *update;
	const uint8_t *payload;
	bool compensated = input->abort.bytes != 0;
	bool fourth = input->packet[NTFS_WRITE_REPLAY_COMMIT].bytes != 0;
	bool committed = fourth && !compensated;
	size_t index;
	enum ntfs_result result;

	if (volume->info.major_version != NTFS_VOLUME_MAJOR_VERSION ||
	    volume->info.minor_version != NTFS_VOLUME_MAX_MINOR_VERSION ||
	    volume->info.sector_size != NTFS_WRITE_SECTOR_BYTES ||
	    volume->info.cluster_size != NTFS_WRITE_CLUSTER_BYTES ||
	    volume->info.record_size != NTFS_WRITE_RECORD_BYTES ||
	    (input->restart.flags != 0 && input->restart.flags != NTFS_LOGFILE_RESTART_CLEAN)) {
		return NTFS_UNSUPPORTED;
	}
	for (index = 0; index < NTFS_WRITE_REPLAY_PACKETS; index++) {
		if (input->packet[index].bytes > sizeof(struct ntfs_disk_log_record) +
			sizeof(struct ntfs_disk_log_update_storage) + NTFS_WRITE_RECORD_BYTES) {
			return NTFS_RANGE;
		}
	}
	result = decode_packets(input, work, fourth);
	if (result == NTFS_OK) {
		result = bind_open(input, work);
	}
	if (result == NTFS_OK) {
		result = bind_snapshot(volume, input, work, out);
	}
	if (result == NTFS_OK) {
		result = bind_change(volume, input, work, out);
	}
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_write_journal_reserve_tail(
	    &input->restart, input->tail_lsn, out->file.snapshot_bytes, &work->reservation);
	if (result != NTFS_OK) {
		return result;
	}
	if (work->record[NTFS_WRITE_REPLAY_OPEN].lsn != work->reservation.open_lsn ||
	    work->record[NTFS_WRITE_REPLAY_SNAPSHOT].lsn != work->reservation.snapshot_lsn ||
	    work->record[NTFS_WRITE_REPLAY_UPDATE].lsn != work->reservation.update_lsn) {
		return NTFS_CORRUPT;
	}
	if (committed) {
		record = &work->record[NTFS_WRITE_REPLAY_COMMIT];
		update = &work->update[NTFS_WRITE_REPLAY_COMMIT];
		payload = body(input, work, NTFS_WRITE_REPLAY_COMMIT);
		if (input->packet[NTFS_WRITE_REPLAY_COMMIT].bytes != REPLAY_COMMIT_BYTES ||
		    record->lsn != work->reservation.commit_lsn ||
		    record->flags != NTFS_LOGFILE_RECORD_DELETING ||
		    record->transaction != NTFS_WRITE_TRANSACTION_KEY ||
		    record->previous_lsn != work->reservation.update_lsn ||
		    record->undo_next_lsn != 0 ||
		    update->redo_operation != NTFS_LOG_OP_FORGET_TRANSACTION ||
		    update->undo_operation != NTFS_LOG_OP_COMPENSATION || !empty_target(update) ||
		    update->redo.offset != sizeof(struct ntfs_disk_log_update_storage) ||
		    update->redo.length != 0 ||
		    update->undo.offset != sizeof(struct ntfs_disk_log_update_storage) ||
		    update->undo.length != 0 ||
		    ntfs_u64(payload + sizeof(struct ntfs_disk_log_update)) != UINT64_MAX) {
			return NTFS_UNSUPPORTED;
		}
	}
	if (compensated) {
		result = bind_compensation(input, work, out);
		if (result != NTFS_OK) {
			return result;
		}
	}
	result = ntfs_work(volume, sizeof(*out));
	if (result != NTFS_OK) {
		return result;
	}
	out->committed = committed;
	out->open_lsn = work->reservation.open_lsn;
	out->snapshot_lsn = work->reservation.snapshot_lsn;
	out->update_lsn = work->reservation.update_lsn;
	out->commit_lsn = committed ? work->reservation.commit_lsn : 0;
	out->end_lsn = compensated ? out->abort_lsn : committed ? out->commit_lsn : out->update_lsn;
	if (!committed && !compensated) {
		ntfs_copy(out->file.after, out->file.before, sizeof(out->file.after));
	}
	return ntfs_record_protect(out->file.after, sizeof(out->file.after),
	    out->file.protected_after, sizeof(out->file.protected_after));
}

enum ntfs_result
ntfs_write_replay_prepare(struct ntfs_volume *volume, const struct ntfs_write_replay_input *input,
    struct ntfs_write_replay_workspace *work, struct ntfs_write_replay_plan *out)
{
	size_t index;
	enum ntfs_result result;

	if (volume == NULL || input == NULL || work == NULL || out == NULL ||
	    !separate(volume, sizeof(*volume), out, sizeof(*out)) ||
	    !separate(volume, sizeof(*volume), work, sizeof(*work)) ||
	    !separate(input, sizeof(*input), out, sizeof(*out)) ||
	    !separate(input, sizeof(*input), work, sizeof(*work)) ||
	    !separate(work, sizeof(*work), out, sizeof(*out))) {
		return NTFS_INVALID;
	}
	for (index = 0; index < NTFS_WRITE_REPLAY_PACKETS; index++) {
		if ((input->packet[index].bytes == 0 && index != NTFS_WRITE_REPLAY_COMMIT) ||
		    (input->packet[index].bytes == 0 && input->packet[index].data != NULL) ||
		    !separate(
			input->packet[index].data, input->packet[index].bytes, out, sizeof(*out)) ||
		    !separate(input->packet[index].data, input->packet[index].bytes, work,
			sizeof(*work))) {
			return NTFS_INVALID;
		}
	}
	if ((input->abort.bytes == 0 && input->abort.data != NULL) ||
	    (input->abort.bytes != 0 && input->packet[NTFS_WRITE_REPLAY_COMMIT].bytes == 0) ||
	    input->abort.bytes > REPLAY_COMMIT_BYTES ||
	    !separate(input->abort.data, input->abort.bytes, out, sizeof(*out)) ||
	    !separate(input->abort.data, input->abort.bytes, work, sizeof(*work))) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	result = ntfs_operation_enter(volume);
	if (result == NTFS_OK) {
		result = prepare(volume, input, work, out);
		ntfs_operation_leave(volume);
	}
	if (result != NTFS_OK) {
		ntfs_zero(out, sizeof(*out));
	}
	return result;
}
