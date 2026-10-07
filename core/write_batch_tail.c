/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_batch_recover_internal.h"
#include "logfile_internal.h"
#include "write_payload.h"

static enum ntfs_result
recovery_tail_inverse(struct ntfs_write_batch_recovery *owner,
    const struct ntfs_logfile_record *record, const uint8_t *payload, size_t available,
    struct ntfs_batch_recovery_workspace *work)
{
	const struct ntfs_batch_recovery_packet *original;
	const struct ntfs_logfile_update *update;
	const uint8_t *old;
	struct ntfs_logfile_update_input inverse = {0};
	uint32_t encoded;
	enum ntfs_result result;

	if (owner->remaining_undo == 0 || record->flags != NTFS_LOGFILE_RECORD_MULTI_PAGE) {
		return NTFS_UNSUPPORTED;
	}
	original = &owner->packet[owner->first_update + owner->remaining_undo - 1];
	update = &original->update;
	if (update->undo_operation != NTFS_LOG_OP_UPDATE_NONRESIDENT_VALUE ||
	    update->undo.length != NTFS_WRITE_CLUSTER_BYTES ||
	    record->undo_next_lsn != original->record.undo_next_lsn) {
		return NTFS_CORRUPT;
	}
	old = original->bytes + original->record.data.offset;
	inverse.redo_operation = update->undo_operation;
	inverse.undo_operation = NTFS_LOG_OP_COMPENSATION;
	inverse.target_attribute = update->target_attribute;
	inverse.target_vcn = update->target_vcn;
	inverse.record_offset = update->record_offset;
	inverse.attribute_offset = update->attribute_offset;
	inverse.cluster_index = update->cluster_index;
	inverse.attribute_flags = update->attribute_flags;
	inverse.lcns = (struct ntfs_logfile_buffer){old + update->lcns.offset, update->lcns.length};
	inverse.redo = (struct ntfs_logfile_buffer){old + update->undo.offset, update->undo.length};
	result = ntfs_write_payload_encode(&inverse, work->record, sizeof(work->record), &encoded);
	if (result != NTFS_OK) {
		return result;
	}
	return record->data.length == encoded && available < encoded &&
		ntfs_equal(payload, work->record, available)
	    ? NTFS_OK
	    : NTFS_CORRUPT;
}

enum ntfs_result
ntfs_batch_recovery_tail_bind(struct ntfs_write_batch_recovery *owner, struct ntfs_logfile *log,
    struct ntfs_batch_recovery_workspace *work)
{
	struct ntfs_logfile_lsn location;
	struct ntfs_logfile_page_view page;
	struct ntfs_logfile_record record;
	const struct ntfs_disk_log_update_storage *stored;
	const struct ntfs_disk_log_update *update;
	const uint8_t *payload;
	uint32_t bytes, undo;
	uint16_t key, operation, flags;
	uint64_t previous, lcn;
	size_t available, target;
	enum ntfs_result result;

	if (owner->history.tail_lsn == 0) {
		return NTFS_OK;
	}
	if (!owner->history.tail_verified || owner->updates == 0 || owner->committed ||
	    owner->compensated) {
		return NTFS_UNSUPPORTED;
	}
	result = ntfs_logfile_lsn_decode(&owner->selected, owner->history.tail_lsn, &location);
	if (result == NTFS_OK) {
		result = ntfs_logfile_read_page(
		    log, location.page_offset, work->image, sizeof(work->image), &page);
	}
	if (result != NTFS_OK) {
		return result;
	}
	if (location.record_offset != owner->selected.page_data_offset || page.page.flags != 0 ||
	    page.page.last_end_lsn != 0 || page.page.next_record_offset != location.record_offset ||
	    page.page.page_count != 1 || page.page.page_position != 1) {
		return NTFS_UNSUPPORTED;
	}
	available = NTFS_WRITE_CLUSTER_BYTES - location.record_offset;
	result = ntfs_logfile_record_prefix(work->image + location.record_offset, available,
	    owner->selected.record_header_bytes, &record, &bytes);
	if (result != NTFS_OK) {
		return result;
	}
	if (bytes > NTFS_WRITE_BATCH_MAX_PACKET_BYTES) {
		return NTFS_RANGE;
	}
	if (record.lsn != owner->history.tail_lsn || record.client_index != 0 ||
	    record.client_sequence != owner->client.sequence) {
		return NTFS_STALE;
	}
	if (record.type != NTFS_LOGFILE_RECORD_UPDATE ||
	    record.transaction != NTFS_WRITE_TRANSACTION_KEY ||
	    (record.flags & NTFS_LOGFILE_RECORD_MULTI_PAGE) == 0) {
		return NTFS_UNSUPPORTED;
	}
	previous = owner->packet[owner->packets - 1].record.lsn;
	if (record.previous_lsn != previous || available < record.data.offset + sizeof(*stored) ||
	    bytes <= available) {
		return NTFS_CORRUPT;
	}
	payload = work->image + location.record_offset + record.data.offset;
	available -= record.data.offset;
	stored = (const void *)payload;
	update = &stored->header;
	key = ntfs_u16(update->target_attribute);
	for (target = 0; target < owner->targets; target++) {
		if (owner->target[target].key == key) {
			break;
		}
	}
	if (target == owner->targets ||
	    owner->target[target].flags != NTFS_BATCH_RECOVERY_INDEX_FLAG ||
	    ntfs_u16(update->attribute_flags) != NTFS_BATCH_RECOVERY_INDEX_FLAG) {
		return NTFS_STALE;
	}
	lcn = ntfs_u64(stored->first_lcn);
	if (ntfs_u16(update->lcns) != 1 || lcn == 0 || lcn >= owner->info.cluster_count ||
	    ntfs_u16(update->record_offset) != 0 || ntfs_u16(update->attribute_offset) != 0 ||
	    ntfs_u16(update->cluster_index) != 0 ||
	    ntfs_u64(update->target_vcn) > (uint64_t)INT64_MAX / NTFS_WRITE_CLUSTER_BYTES) {
		return NTFS_CORRUPT;
	}
	if (ntfs_u16(update->redo_operation) != NTFS_LOG_OP_UPDATE_NONRESIDENT_VALUE) {
		return NTFS_UNSUPPORTED;
	}
	operation = ntfs_u16(update->undo_operation);
	if (operation == NTFS_LOG_OP_COMPENSATION) {
		return recovery_tail_inverse(owner, &record, payload, available, work);
	}
	if (owner->compensations != 0 ||
	    (operation != NTFS_LOG_OP_NOOP && operation != NTFS_LOG_OP_UPDATE_NONRESIDENT_VALUE)) {
		return NTFS_UNSUPPORTED;
	}
	undo = operation == NTFS_LOG_OP_NOOP ? 0 : NTFS_WRITE_CLUSTER_BYTES;
	flags = NTFS_LOGFILE_RECORD_MULTI_PAGE | (undo == 0 ? NTFS_LOGFILE_RECORD_ADDING : 0);
	if (record.undo_next_lsn != previous || record.flags != flags ||
	    record.data.length != sizeof(*stored) + NTFS_WRITE_CLUSTER_BYTES + undo ||
	    ntfs_u16(update->redo_offset) != sizeof(*stored) ||
	    ntfs_u16(update->redo_bytes) != NTFS_WRITE_CLUSTER_BYTES ||
	    ntfs_u16(update->undo_offset) != sizeof(*stored) + NTFS_WRITE_CLUSTER_BYTES ||
	    ntfs_u16(update->undo_bytes) != undo) {
		return NTFS_CORRUPT;
	}
	/* No uncompleted payload contributes a metadata image or inverse. Only
	 * this independently bound successor permits reusing its reserved start. */
	return NTFS_OK;
}
