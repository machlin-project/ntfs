/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_internal.h"
#include <ntfs/record.h>

enum {
	WRITE_OPEN_PAYLOAD_BYTES = sizeof(struct ntfs_disk_log_update_storage) +
	    sizeof(struct ntfs_disk_log_open_attribute),
	WRITE_CHANGE_BYTES =
	    NTFS_WRITE_STANDARD_BYTES - offsetof(struct ntfs_disk_standard, modified),
	WRITE_CHANGE_PAYLOAD_BYTES =
	    sizeof(struct ntfs_disk_log_update_storage) + 2 * WRITE_CHANGE_BYTES
};

/* Exact opaque prefix of the retained native empty checkpoint family.
 * Its bytes are compared as a whole, without assigning unqualified field meaning. */
static const uint8_t empty_extension_prefix[NTFS_WRITE_QUIET_EXTENSION_PREFIX_BYTES] =
    "\x00\x00\x00\x00"
    "\x00\x00\x00\x00"
    "\x00\x00\x00\x01"
    "\x00\x00\x00\x00"
    "\x00\x10\x00\x00"
    "\x00\x00\x00\x00"
    "\x00\x00\x00\x00"
    "\x00\x00\x00\x00"
    "\x00\x00\x00\x00"
    "\x00\x00\x00\x00";

static bool
separate(const void *left, size_t left_bytes, const void *right, size_t right_bytes)
{
	uintptr_t a = (uintptr_t)left, b = (uintptr_t)right;

	return left != NULL && right != NULL && left_bytes <= UINTPTR_MAX - a &&
	    right_bytes <= UINTPTR_MAX - b && (a + left_bytes <= b || b + right_bytes <= a);
}

static uint64_t
lsn(const struct ntfs_logfile_restart *restart, uint64_t offset)
{
	uint32_t offset_bits = NTFS_LFS_LSN_BITS - restart->sequence_bits;
	uint64_t epoch = restart->current_lsn >> offset_bits;

	return epoch << offset_bits | offset >> NTFS_LFS_LSN_OFFSET_SHIFT;
}

static bool
qualified_restart(const struct ntfs_logfile_restart *restart)
{
	return restart->major == NTFS_LFS_MAJOR_LEGACY && restart->minor == NTFS_LFS_MINOR_LEGACY &&
	    restart->system_page_bytes == NTFS_WRITE_CLUSTER_BYTES &&
	    restart->log_page_bytes == NTFS_WRITE_CLUSTER_BYTES &&
	    restart->record_header_bytes == sizeof(struct ntfs_disk_log_record) &&
	    restart->page_data_offset == NTFS_WRITE_LOG_DATA_OFFSET && restart->client_count == 1 &&
	    restart->in_use_head == 0 && restart->free_head == NTFS_LOGFILE_NO_CLIENT &&
	    restart->flags == NTFS_LOGFILE_RESTART_CLEAN && restart->clean_hint;
}

static bool
same_restart(const struct ntfs_logfile_restart *a, const struct ntfs_logfile_restart *b)
{
	return a->current_lsn == b->current_lsn && a->file_bytes == b->file_bytes &&
	    a->usable_bytes == b->usable_bytes && a->circular_offset == b->circular_offset &&
	    a->system_page_bytes == b->system_page_bytes &&
	    a->log_page_bytes == b->log_page_bytes && a->sequence_bits == b->sequence_bits &&
	    a->last_data_bytes == b->last_data_bytes && a->open_count == b->open_count &&
	    a->major == b->major && a->minor == b->minor && a->flags == b->flags &&
	    a->client_count == b->client_count && a->free_head == b->free_head &&
	    a->in_use_head == b->in_use_head && a->record_header_bytes == b->record_header_bytes &&
	    a->page_data_offset == b->page_data_offset && a->area.offset == b->area.offset &&
	    a->area.length == b->area.length && a->clients.offset == b->clients.offset &&
	    a->clients.length == b->clients.length && a->clean_hint == b->clean_hint;
}

enum ntfs_result
ntfs_write_journal_reserve(const struct ntfs_logfile_restart *restart, uint16_t snapshot_bytes,
    struct ntfs_write_log_reservation *out)
{
	struct ntfs_logfile_lsn current;
	uint64_t first;
	uint32_t snapshot_offset, update_offset, checkpoint_offset;
	enum ntfs_result result;

	if (restart == NULL || out == NULL ||
	    !separate(restart, sizeof(*restart), out, sizeof(*out))) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (!qualified_restart(restart)) {
		return NTFS_UNSUPPORTED;
	}
	if (snapshot_bytes < sizeof(struct ntfs_disk_record) ||
	    snapshot_bytes > NTFS_WRITE_RECORD_BYTES || snapshot_bytes % NTFS_WIRE_ALIGNMENT != 0) {
		return NTFS_CORRUPT;
	}
	result = ntfs_logfile_lsn_decode(restart, restart->current_lsn, &current);
	if (result != NTFS_OK) {
		return result;
	}
	first = current.page_offset + NTFS_WRITE_CLUSTER_BYTES;
	if (!ntfs_bounds(
		first, NTFS_WRITE_LOG_PAGES * NTFS_WRITE_CLUSTER_BYTES, restart->usable_bytes)) {
		return NTFS_RANGE;
	}
	snapshot_offset = NTFS_WRITE_LOG_DATA_OFFSET + sizeof(struct ntfs_disk_log_record) +
	    WRITE_OPEN_PAYLOAD_BYTES;
	update_offset = snapshot_offset + sizeof(struct ntfs_disk_log_record) +
	    sizeof(struct ntfs_disk_log_update_storage) + snapshot_bytes;
	checkpoint_offset = NTFS_WRITE_LOG_DATA_OFFSET + NTFS_WRITE_BOOTSTRAP_BYTES;
	if (!ntfs_bounds(update_offset,
		sizeof(struct ntfs_disk_log_record) + WRITE_CHANGE_PAYLOAD_BYTES,
		NTFS_WRITE_CLUSTER_BYTES) ||
	    !ntfs_bounds(
		checkpoint_offset, NTFS_WRITE_CHECKPOINT_BYTES, NTFS_WRITE_CLUSTER_BYTES)) {
		return NTFS_RANGE;
	}
	out->prepare_offset = first;
	out->commit_offset = first + NTFS_WRITE_CLUSTER_BYTES;
	out->checkpoint_offset = first + 2 * NTFS_WRITE_CLUSTER_BYTES;
	out->open_lsn = lsn(restart, first + NTFS_WRITE_LOG_DATA_OFFSET);
	out->snapshot_lsn = lsn(restart, first + snapshot_offset);
	out->update_lsn = lsn(restart, first + update_offset);
	out->commit_lsn = lsn(restart, out->commit_offset + NTFS_WRITE_LOG_DATA_OFFSET);
	out->bootstrap_lsn = lsn(restart, out->checkpoint_offset + NTFS_WRITE_LOG_DATA_OFFSET);
	out->checkpoint_lsn = lsn(restart, out->checkpoint_offset + checkpoint_offset);
	out->snapshot_offset = (uint16_t)snapshot_offset;
	out->update_offset = (uint16_t)update_offset;
	out->checkpoint_record_offset = (uint16_t)checkpoint_offset;
	return NTFS_OK;
}

static enum ntfs_result
quiet_packets(
    const struct ntfs_write_journal_input *input, struct ntfs_write_journal_workspace *work)
{
	const struct ntfs_logfile_restart *restart = &work->restart[0];
	struct ntfs_logfile_record first, last;
	struct ntfs_logfile_update noop;
	struct ntfs_logfile_client_restart checkpoint;
	const uint8_t *body;
	enum ntfs_result result;
	size_t index;

	ntfs_copy(work->restored, input->restart[0], NTFS_WRITE_CLUSTER_BYTES);
	result = ntfs_fixup(work->restored, NTFS_WRITE_CLUSTER_BYTES, "RSTR");
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_logfile_client_decode(work->restored + restart->clients.offset,
	    sizeof(struct ntfs_disk_log_client), &work->client);
	if (result != NTFS_OK) {
		return result;
	}
	if (work->client.name_length != 4 || work->client.name[0] != 'N' ||
	    work->client.name[1] != 'T' || work->client.name[2] != 'F' ||
	    work->client.name[3] != 'S' || work->client.previous != NTFS_LOGFILE_NO_CLIENT ||
	    work->client.next != NTFS_LOGFILE_NO_CLIENT) {
		return NTFS_UNSUPPORTED;
	}
	result = ntfs_logfile_record_decode(input->bootstrap, NTFS_WRITE_BOOTSTRAP_BYTES,
	    sizeof(struct ntfs_disk_log_record), &first);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_logfile_record_decode(input->checkpoint, NTFS_WRITE_CHECKPOINT_BYTES,
	    sizeof(struct ntfs_disk_log_record), &last);
	if (result != NTFS_OK) {
		return result;
	}
	if (first.type != NTFS_LOGFILE_RECORD_UPDATE || first.flags != 0 ||
	    first.transaction != NTFS_WRITE_MFT_KEY || first.previous_lsn != 0 ||
	    first.undo_next_lsn != 0 || first.client_index != 0 ||
	    first.client_sequence != work->client.sequence ||
	    first.lsn != work->client.oldest_lsn || last.type != NTFS_LOGFILE_RECORD_RESTART ||
	    last.flags != 0 || last.transaction != 0 || last.previous_lsn != 0 ||
	    last.undo_next_lsn != 0 || last.client_index != 0 ||
	    last.client_sequence != work->client.sequence || last.lsn != work->client.restart_lsn ||
	    last.lsn != restart->current_lsn || first.lsn >= last.lsn) {
		return NTFS_UNSUPPORTED;
	}
	body = (const uint8_t *)input->bootstrap + first.data.offset;
	result = ntfs_logfile_update_decode(body, first.data.length, &noop);
	if (result != NTFS_OK) {
		return result;
	}
	if (noop.redo_operation != NTFS_LOG_OP_NOOP || noop.undo_operation != NTFS_LOG_OP_NOOP ||
	    noop.redo.length != 0 || noop.undo.length != 0 || noop.lcn_count != 0 ||
	    noop.target_attribute != 0 || noop.attribute_flags != 0 || noop.target_vcn != 0 ||
	    noop.cluster_index != 0 || noop.record_offset != 0 || noop.attribute_offset != 0 ||
	    ntfs_u64(body + sizeof(struct ntfs_disk_log_update)) != 0) {
		return NTFS_UNSUPPORTED;
	}
	body = (const uint8_t *)input->checkpoint + last.data.offset;
	result = ntfs_logfile_client_restart_decode(body, last.data.length, &checkpoint);
	if (result != NTFS_OK) {
		return result;
	}
	if (checkpoint.major != NTFS_LOG_CLIENT_MAJOR_ATTRIBUTES ||
	    checkpoint.minor != NTFS_LOG_CLIENT_MINOR || checkpoint.analysis_lsn != first.lsn ||
	    checkpoint.extension.length != NTFS_WRITE_QUIET_EXTENSION_BYTES ||
	    checkpoint.open_attributes.lsn != 0 || checkpoint.attribute_names.lsn != 0 ||
	    checkpoint.dirty_pages.lsn != 0 || checkpoint.transactions.lsn != 0 ||
	    checkpoint.open_attributes.bytes != 0 || checkpoint.attribute_names.bytes != 0 ||
	    checkpoint.dirty_pages.bytes != 0 || checkpoint.transactions.bytes != 0 ||
	    !ntfs_equal(body + sizeof(struct ntfs_disk_log_client_restart), empty_extension_prefix,
		NTFS_WRITE_QUIET_EXTENSION_PREFIX_BYTES) ||
	    ntfs_u64(body + last.data.length - sizeof(uint64_t)) != first.lsn) {
		return NTFS_UNSUPPORTED;
	}
	/* Both copies must bind the exact same selected client, independently of USA. */
	for (index = 1; index < NTFS_LFS_RESTART_PAGES; index++) {
		ntfs_copy(work->page, input->restart[index], NTFS_WRITE_CLUSTER_BYTES);
		result = ntfs_fixup(work->page, NTFS_WRITE_CLUSTER_BYTES, "RSTR");
		if (result != NTFS_OK) {
			return result;
		}
		if (!ntfs_equal(work->page + restart->clients.offset,
			work->restored + restart->clients.offset,
			sizeof(struct ntfs_disk_log_client))) {
			return NTFS_UNSUPPORTED;
		}
	}
	return NTFS_OK;
}

static enum ntfs_result
emit_packet(struct ntfs_write_journal_workspace *work, uint16_t offset, uint64_t sequence_lsn,
    uint64_t previous_lsn, uint64_t undo_next, uint32_t type, uint32_t transaction, uint16_t flags,
    const void *payload, uint32_t bytes)
{
	struct ntfs_logfile_record record = {0};

	if (!ntfs_bounds(
		offset, sizeof(struct ntfs_disk_log_record) + bytes, NTFS_WRITE_CLUSTER_BYTES)) {
		return NTFS_RANGE;
	}
	record.lsn = sequence_lsn;
	record.previous_lsn = previous_lsn;
	record.undo_next_lsn = undo_next;
	record.client_sequence = work->client.sequence;
	record.type = type;
	record.transaction = transaction;
	record.flags = flags;
	record.data.offset = sizeof(struct ntfs_disk_log_record);
	record.data.length = bytes;
	return ntfs_logfile_record_encode(
	    &record, payload, bytes, work->page + offset, NTFS_WRITE_CLUSTER_BYTES - offset);
}

static enum ntfs_result
payload(struct ntfs_write_journal_workspace *work, struct ntfs_logfile_update_input *input,
    uint32_t *bytes)
{
	struct ntfs_disk_log_update_storage *stored = (void *)work->payload;
	enum ntfs_result result;

	result = ntfs_logfile_update_measure(input, bytes);
	if (result == NTFS_OK) {
		result = ntfs_logfile_update_encode(input, work->payload, sizeof(work->payload));
	}
	if (result != NTFS_OK) {
		return result;
	}
	/* This exact native family stores empty spans at the following boundary.
	 * The generic encoder deliberately retains its canonical zero-span contract. */
	if (input->redo.bytes == 0) {
		ntfs_put_u16(stored->header.redo_offset, sizeof(*stored));
	}
	if (input->undo.bytes == 0) {
		ntfs_put_u16(stored->header.undo_offset, (uint16_t)*bytes);
	}
	if (input->lcns.bytes == 0) {
		ntfs_put_u64(stored->first_lcn, UINT64_MAX);
	}
	return NTFS_OK;
}

static enum ntfs_result
encode_page(struct ntfs_write_journal_workspace *work, uint64_t end_lsn, uint16_t next,
    bool checkpoint, uint8_t *output)
{
	struct ntfs_logfile_page_input input = {0};

	input.bytes = NTFS_WRITE_CLUSTER_BYTES;
	input.major = NTFS_LFS_MAJOR_LEGACY;
	input.minor = NTFS_LFS_MINOR_LEGACY;
	input.data_offset = NTFS_WRITE_LOG_DATA_OFFSET;
	input.page.copy_value = end_lsn;
	input.page.last_end_lsn = end_lsn;
	input.page.flags =
	    NTFS_LOGFILE_PAGE_RECORD_END | (checkpoint ? NTFS_LOGFILE_PAGE_CLIENT_RESTART : 0);
	input.page.page_count = 1;
	input.page.page_position = 1;
	input.page.next_record_offset = next;
	input.data.data = work->page + NTFS_WRITE_LOG_DATA_OFFSET;
	input.data.bytes = NTFS_WRITE_CLUSTER_BYTES - NTFS_WRITE_LOG_DATA_OFFSET;
	return ntfs_logfile_page_encode(
	    &input, work->restored, sizeof(work->restored), output, NTFS_WRITE_CLUSTER_BYTES);
}

static enum ntfs_result
encode_updates(const struct ntfs_write_journal_input *input,
    struct ntfs_write_journal_workspace *work, struct ntfs_write_journal_plan *out)
{
	const struct ntfs_write_file_plan *file = input->file;
	const struct ntfs_write_log_reservation *reservation = &out->reservation;
	struct ntfs_disk_log_open_attribute entry = {0};
	struct ntfs_logfile_update_input update = {0};
	uint8_t lcn_wire[sizeof(uint64_t)];
	uint32_t bytes;
	size_t change_offset;
	enum ntfs_result result;

	ntfs_zero(work->page, sizeof(work->page));
	ntfs_put_u32(entry.allocated, NTFS_LOG_TABLE_ALLOCATED);
	ntfs_put_u32(entry.attribute_type, NTFS_ATTRIBUTE_DATA);
	ntfs_put_u64(entry.reference, file->mft_reference);
	ntfs_put_u64(entry.open_lsn, work->restart[0].current_lsn);
	update.redo_operation = NTFS_LOG_OP_OPEN_NONRESIDENT_ATTRIBUTE;
	update.target_attribute = NTFS_WRITE_MFT_KEY;
	update.attribute_flags = NTFS_WRITE_MFT_TARGET_FLAG;
	update.redo = (struct ntfs_logfile_buffer){&entry, sizeof(entry)};
	result = payload(work, &update, &bytes);
	if (result == NTFS_OK) {
		result = emit_packet(work, NTFS_WRITE_LOG_DATA_OFFSET, reservation->open_lsn, 0, 0,
		    NTFS_LOGFILE_RECORD_UPDATE, NTFS_WRITE_MFT_KEY, NTFS_LOGFILE_RECORD_ADDING,
		    work->payload, bytes);
	}
	if (result != NTFS_OK) {
		return result;
	}
	ntfs_put_u64(lcn_wire, file->target_lcn);
	update.redo_operation = NTFS_LOG_OP_INITIALIZE_FILE_RECORD;
	update.lcns = (struct ntfs_logfile_buffer){lcn_wire, sizeof(lcn_wire)};
	update.target_vcn = file->target_vcn;
	update.cluster_index = file->cluster_index;
	update.redo = (struct ntfs_logfile_buffer){file->before, file->snapshot_bytes};
	result = payload(work, &update, &bytes);
	if (result == NTFS_OK) {
		result = emit_packet(work, reservation->snapshot_offset, reservation->snapshot_lsn,
		    0, 0, NTFS_LOGFILE_RECORD_UPDATE, NTFS_WRITE_TRANSACTION_KEY,
		    NTFS_LOGFILE_RECORD_ADDING, work->payload, bytes);
	}
	if (result != NTFS_OK) {
		return result;
	}
	change_offset = (size_t)file->record_offset + file->attribute_offset;
	update.redo_operation = NTFS_LOG_OP_UPDATE_RESIDENT_VALUE;
	update.undo_operation = NTFS_LOG_OP_UPDATE_RESIDENT_VALUE;
	update.record_offset = file->record_offset;
	update.attribute_offset = file->attribute_offset;
	update.redo = (struct ntfs_logfile_buffer){file->after + change_offset, file->change_bytes};
	update.undo =
	    (struct ntfs_logfile_buffer){file->before + change_offset, file->change_bytes};
	result = payload(work, &update, &bytes);
	if (result == NTFS_OK) {
		result = emit_packet(work, reservation->update_offset, reservation->update_lsn,
		    reservation->snapshot_lsn, reservation->snapshot_lsn,
		    NTFS_LOGFILE_RECORD_UPDATE, NTFS_WRITE_TRANSACTION_KEY, 0, work->payload,
		    bytes);
	}
	if (result == NTFS_OK) {
		result = encode_page(work, reservation->update_lsn,
		    (uint16_t)(reservation->update_offset + sizeof(struct ntfs_disk_log_record) +
			bytes),
		    false, out->prepare);
	}
	if (result != NTFS_OK) {
		return result;
	}
	ntfs_zero(work->page, sizeof(work->page));
	ntfs_zero(&update, sizeof(update));
	update.redo_operation = NTFS_LOG_OP_FORGET_TRANSACTION;
	update.undo_operation = NTFS_LOG_OP_COMPENSATION;
	update.target_attribute = NTFS_WRITE_MFT_KEY;
	update.attribute_flags = NTFS_WRITE_MFT_TARGET_FLAG;
	result = payload(work, &update, &bytes);
	if (result == NTFS_OK) {
		result = emit_packet(work, NTFS_WRITE_LOG_DATA_OFFSET, reservation->commit_lsn,
		    reservation->update_lsn, 0, NTFS_LOGFILE_RECORD_UPDATE,
		    NTFS_WRITE_TRANSACTION_KEY, NTFS_LOGFILE_RECORD_DELETING, work->payload, bytes);
	}
	if (result == NTFS_OK) {
		result = encode_page(work, reservation->commit_lsn,
		    NTFS_WRITE_LOG_DATA_OFFSET + sizeof(struct ntfs_disk_log_record) + bytes, false,
		    out->commit);
	}
	return result;
}

static enum ntfs_result
encode_checkpoint(const struct ntfs_write_journal_input *input,
    struct ntfs_write_journal_workspace *work, struct ntfs_write_journal_plan *out)
{
	const struct ntfs_write_log_reservation *reservation = &out->reservation;
	struct ntfs_disk_log_client_restart *body = (void *)work->payload;
	uint32_t bytes = NTFS_WRITE_CHECKPOINT_BYTES - sizeof(struct ntfs_disk_log_record);
	enum ntfs_result result;

	ntfs_zero(work->page, sizeof(work->page));
	result = emit_packet(work, NTFS_WRITE_LOG_DATA_OFFSET, reservation->bootstrap_lsn, 0, 0,
	    NTFS_LOGFILE_RECORD_UPDATE, NTFS_WRITE_MFT_KEY, 0,
	    (const uint8_t *)input->bootstrap + sizeof(struct ntfs_disk_log_record),
	    NTFS_WRITE_BOOTSTRAP_BYTES - sizeof(struct ntfs_disk_log_record));
	if (result != NTFS_OK) {
		return result;
	}
	ntfs_copy(work->payload,
	    (const uint8_t *)input->checkpoint + sizeof(struct ntfs_disk_log_record), bytes);
	ntfs_put_u64(body->analysis_lsn, reservation->bootstrap_lsn);
	/* Only the independently qualified empty native extension is reproduced;
	 * this does not interpret the final opaque word in arbitrary checkpoints. */
	ntfs_put_u64(work->payload + bytes - sizeof(uint64_t), reservation->bootstrap_lsn);
	result =
	    emit_packet(work, reservation->checkpoint_record_offset, reservation->checkpoint_lsn, 0,
		0, NTFS_LOGFILE_RECORD_RESTART, 0, 0, work->payload, bytes);
	if (result == NTFS_OK) {
		result = encode_page(work, reservation->checkpoint_lsn,
		    reservation->checkpoint_record_offset + NTFS_WRITE_CHECKPOINT_BYTES, true,
		    out->checkpoint);
	}
	return result;
}

static enum ntfs_result
encode_restarts(const struct ntfs_write_journal_input *input,
    struct ntfs_write_journal_workspace *work, struct ntfs_write_journal_plan *out)
{
	struct ntfs_disk_log_restart_area *area;
	struct ntfs_disk_log_client *client;
	enum ntfs_result result;
	size_t index;

	for (index = 0; index < NTFS_LFS_RESTART_PAGES; index++) {
		ntfs_copy(work->restored, input->restart[index], NTFS_WRITE_CLUSTER_BYTES);
		result = ntfs_fixup(work->restored, NTFS_WRITE_CLUSTER_BYTES, "RSTR");
		if (result != NTFS_OK) {
			return result;
		}
		area = (void *)(work->restored + work->restart[index].area.offset);
		ntfs_put_u16(area->flags, 0);
		result = ntfs_record_protect(work->restored, sizeof(work->restored),
		    out->dirty_restart[index], sizeof(out->dirty_restart[index]));
		if (result != NTFS_OK) {
			return result;
		}
		/* Advance again from the actual preceding publication, so a clean/dirty
		 * sector mix cannot pass USA using a reused protection sequence. */
		ntfs_copy(work->restored, out->dirty_restart[index], NTFS_WRITE_CLUSTER_BYTES);
		result = ntfs_fixup(work->restored, NTFS_WRITE_CLUSTER_BYTES, "RSTR");
		if (result != NTFS_OK) {
			return result;
		}
		area = (void *)(work->restored + work->restart[index].area.offset);
		client = (void *)(work->restored + work->restart[index].clients.offset);
		ntfs_put_u16(area->flags, NTFS_LOGFILE_RESTART_CLEAN);
		ntfs_put_u64(area->current_lsn, out->reservation.checkpoint_lsn);
		ntfs_put_u32(area->last_data_bytes,
		    NTFS_WRITE_CHECKPOINT_BYTES - sizeof(struct ntfs_disk_log_record));
		ntfs_put_u64(client->oldest_lsn, out->reservation.bootstrap_lsn);
		ntfs_put_u64(client->restart_lsn, out->reservation.checkpoint_lsn);
		result = ntfs_record_protect(work->restored, sizeof(work->restored),
		    out->clean_restart[index], sizeof(out->clean_restart[index]));
		if (result != NTFS_OK) {
			return result;
		}
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_write_journal_encode(const struct ntfs_write_journal_input *input,
    struct ntfs_write_journal_workspace *work, struct ntfs_write_journal_plan *out)
{
	const struct ntfs_write_file_plan *file;
	enum ntfs_result result;
	size_t index;

	if (input == NULL || work == NULL || out == NULL || input->file == NULL ||
	    !separate(input, sizeof(*input), out, sizeof(*out)) ||
	    !separate(work, sizeof(*work), out, sizeof(*out)) ||
	    !separate(input, sizeof(*input), work, sizeof(*work)) ||
	    !separate(input->file, sizeof(*input->file), out, sizeof(*out)) ||
	    !separate(input->file, sizeof(*input->file), work, sizeof(*work)) ||
	    !separate(input->bootstrap, NTFS_WRITE_BOOTSTRAP_BYTES, out, sizeof(*out)) ||
	    !separate(input->bootstrap, NTFS_WRITE_BOOTSTRAP_BYTES, work, sizeof(*work)) ||
	    !separate(input->checkpoint, NTFS_WRITE_CHECKPOINT_BYTES, out, sizeof(*out)) ||
	    !separate(input->checkpoint, NTFS_WRITE_CHECKPOINT_BYTES, work, sizeof(*work))) {
		return NTFS_INVALID;
	}
	for (index = 0; index < NTFS_LFS_RESTART_PAGES; index++) {
		if (!separate(input->restart[index], NTFS_WRITE_CLUSTER_BYTES, out, sizeof(*out)) ||
		    !separate(
			input->restart[index], NTFS_WRITE_CLUSTER_BYTES, work, sizeof(*work))) {
			return NTFS_INVALID;
		}
	}
	ntfs_zero(out, sizeof(*out));
	for (index = 0; index < NTFS_LFS_RESTART_PAGES; index++) {
		result = ntfs_logfile_restart_decode(input->restart[index],
		    NTFS_WRITE_CLUSTER_BYTES, input->file_bytes, work->restored,
		    sizeof(work->restored), &work->restart[index]);
		if (result != NTFS_OK) {
			goto failed;
		}
	}
	if (!same_restart(&work->restart[0], &work->restart[1]) ||
	    work->restart[0].file_bytes != input->file_bytes) {
		result = NTFS_UNSUPPORTED;
		goto failed;
	}
	result = quiet_packets(input, work);
	if (result != NTFS_OK) {
		goto failed;
	}
	file = input->file;
	if (file->mft_reference != (UINT64_C(1) << NTFS_REFERENCE_SEQUENCE_SHIFT) ||
	    (file->reference & NTFS_REFERENCE_RECORD_MASK) < NTFS_FIRST_USER_RECORD ||
	    file->cluster_index >= NTFS_WRITE_CLUSTER_BYTES / NTFS_WRITE_SECTOR_BYTES ||
	    file->cluster_index % (NTFS_WRITE_RECORD_BYTES / NTFS_WRITE_SECTOR_BYTES) != 0 ||
	    file->change_bytes != WRITE_CHANGE_BYTES ||
	    !ntfs_bounds((size_t)file->record_offset + file->attribute_offset, file->change_bytes,
		file->snapshot_bytes)) {
		result = NTFS_UNSUPPORTED;
		goto failed;
	}
	result =
	    ntfs_write_journal_reserve(&work->restart[0], file->snapshot_bytes, &out->reservation);
	if (result != NTFS_OK) {
		goto failed;
	}
	if (ntfs_u64(((const struct ntfs_disk_record *)file->after)->lsn) !=
		out->reservation.update_lsn ||
	    ntfs_u64(((const struct ntfs_disk_record *)file->before)->lsn) >=
		out->reservation.update_lsn) {
		result = NTFS_STALE;
		goto failed;
	}
	result = encode_updates(input, work, out);
	if (result == NTFS_OK) {
		result = encode_checkpoint(input, work, out);
	}
	if (result == NTFS_OK) {
		result = encode_restarts(input, work, out);
	}
	if (result == NTFS_OK) {
		return NTFS_OK;
	}
failed:
	ntfs_zero(out, sizeof(*out));
	return result;
}
