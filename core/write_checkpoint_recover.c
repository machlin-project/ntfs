/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_batch_recover_internal.h"
#include <ntfs/record.h>

static enum ntfs_result
checkpoint_root_transition_bind(struct ntfs_write_batch_recovery *owner,
    struct ntfs_batch_recovery_workspace *work, const struct ntfs_logfile_restart *older,
    const struct ntfs_logfile_restart *newer, uint64_t file_bytes)
{
	struct ntfs_batch_recovery_checkpoint *checkpoint = &owner->checkpoint;
	struct ntfs_logfile_restart parsed;
	struct ntfs_logfile_client client;
	struct ntfs_disk_log_restart_area *area;
	struct ntfs_disk_log_client *entry;
	enum ntfs_result result;

	if (older->flags != 0 ||
	    (newer->flags != 0 && newer->flags != NTFS_LOGFILE_RESTART_CLEAN) ||
	    older->client_count != 1 || newer->client_count != 1 ||
	    newer->last_data_bytes !=
		NTFS_WRITE_CHECKPOINT_BYTES - sizeof(struct ntfs_disk_log_record)) {
		return NTFS_UNSUPPORTED;
	}
	result = ntfs_logfile_restart_decode(work->restart[checkpoint->old_slot],
	    NTFS_WRITE_CLUSTER_BYTES, file_bytes, work->before, sizeof(work->before), &parsed);
	if (result == NTFS_OK) {
		result = ntfs_logfile_client_decode(work->before + older->clients.offset,
		    sizeof(struct ntfs_disk_log_client), &client);
	}
	if (result == NTFS_OK) {
		result = ntfs_logfile_restart_decode(work->restart[checkpoint->new_slot],
		    NTFS_WRITE_CLUSTER_BYTES, file_bytes, work->image, sizeof(work->image),
		    &parsed);
	}
	if (result == NTFS_OK) {
		result = ntfs_logfile_client_decode(work->image + newer->clients.offset,
		    sizeof(struct ntfs_disk_log_client), &checkpoint->client);
	}
	if (result != NTFS_OK) {
		return result;
	}
	if (checkpoint->client.oldest_lsn <= client.oldest_lsn ||
	    checkpoint->client.oldest_lsn >= newer->current_lsn ||
	    checkpoint->client.restart_lsn != newer->current_lsn) {
		return NTFS_STALE;
	}
	area = (void *)(work->before + older->area.offset);
	entry = (void *)(work->before + older->clients.offset);
	ntfs_put_u64(area->current_lsn, newer->current_lsn);
	ntfs_put_u32(area->last_data_bytes, newer->last_data_bytes);
	ntfs_put_u16(area->flags, newer->flags);
	ntfs_put_u64(entry->oldest_lsn, checkpoint->client.oldest_lsn);
	ntfs_put_u64(entry->restart_lsn, checkpoint->client.restart_lsn);
	if (!ntfs_write_restored_record_equal(
		work->before, work->image, NTFS_WRITE_CLUSTER_BYTES)) {
		return NTFS_STALE;
	}
	checkpoint->advanced = *newer;
	checkpoint->root_projection =
	    ntfs_batch_recovery_allocate(owner, NTFS_LFS_RESTART_PAGES * NTFS_WRITE_CLUSTER_BYTES);
	if (checkpoint->root_projection == NULL) {
		return NTFS_NO_MEMORY;
	}
	/* This is an explicitly private analysis view of the actual older root.
	 * The complete old history must prove the exact new root and checkpoint;
	 * neither this projection nor a larger CurrentLsn is physical evidence. */
	ntfs_copy(checkpoint->root_projection, work->restart[checkpoint->old_slot],
	    NTFS_WRITE_CLUSTER_BYTES);
	ntfs_copy(checkpoint->root_projection + NTFS_WRITE_CLUSTER_BYTES,
	    work->restart[checkpoint->old_slot], NTFS_WRITE_CLUSTER_BYTES);
	checkpoint->root_transition = checkpoint->projection_active = true;
	return NTFS_OK;
}

enum ntfs_result
ntfs_batch_checkpoint_roots_capture(struct ntfs_write_batch_recovery *owner,
    struct ntfs_volume *volume, struct ntfs_batch_recovery_workspace *work)
{
	struct ntfs_node *node = NULL;
	struct ntfs_stream *log = NULL;
	struct ntfs_logfile_restart restart[NTFS_LFS_RESTART_PAGES];
	struct ntfs_batch_recovery_checkpoint *checkpoint = &owner->checkpoint;
	bool valid[NTFS_LFS_RESTART_PAGES] = {false};
	size_t slot;
	enum ntfs_result result;

	result = ntfs_node_by_number(volume, NTFS_LOGFILE_RECORD, &node);
	if (result == NTFS_OK) {
		result = ntfs_stream_open(node, NULL, 0, &log);
	}
	for (slot = 0; result == NTFS_OK && slot < NTFS_LFS_RESTART_PAGES; slot++) {
		result = ntfs_batch_recovery_mapping(
		    log, slot * NTFS_WRITE_CLUSTER_BYTES, &checkpoint->physical[slot]);
		if (result == NTFS_OK) {
			result = ntfs_batch_recovery_read(owner, checkpoint->physical[slot],
			    work->restart[slot], NTFS_WRITE_CLUSTER_BYTES);
		}
		if (result != NTFS_OK) {
			break;
		}
		result = ntfs_logfile_restart_decode(work->restart[slot], NTFS_WRITE_CLUSTER_BYTES,
		    log->size, work->image, sizeof(work->image), &restart[slot]);
		valid[slot] = result == NTFS_OK;
		if (result == NTFS_CORRUPT || result == NTFS_UNSUPPORTED ||
		    result == NTFS_NOT_FOUND) {
			result = NTFS_OK;
		}
	}
	if (result == NTFS_OK && !valid[0] && !valid[1]) {
		result = NTFS_CORRUPT;
	}
	if (result == NTFS_OK) {
		checkpoint->old_slot = !valid[0] || (valid[1] && restart[1].flags == 0) ? 1 : 0;
	}
	if (result == NTFS_OK && valid[0] && valid[1] &&
	    restart[0].current_lsn != restart[1].current_lsn) {
		checkpoint->old_slot = restart[0].current_lsn < restart[1].current_lsn ? 0 : 1;
		checkpoint->new_slot = 1 - checkpoint->old_slot;
		result = checkpoint_root_transition_bind(owner, work,
		    &restart[checkpoint->old_slot], &restart[checkpoint->new_slot], log->size);
	}
	ntfs_stream_close(log);
	ntfs_node_close(node);
	return result;
}

enum ntfs_result
ntfs_batch_checkpoint_bind(struct ntfs_write_batch_recovery *owner)
{
	struct ntfs_batch_recovery_checkpoint *checkpoint = &owner->checkpoint;
	const struct ntfs_batch_recovery_packet *last, *marker;
	struct ntfs_logfile_restart advanced;
	struct ntfs_logfile_client client;
	struct ntfs_logfile_buffer anchor, packet;
	enum ntfs_result result;

	owner->operation_packets = owner->packets;
	if (owner->packets <= NTFS_BATCH_RECOVERY_ORIGIN_PACKETS ||
	    owner->packet[owner->packets - 1].record.type != NTFS_LOGFILE_RECORD_RESTART) {
		return checkpoint->root_transition ? NTFS_STALE : NTFS_OK;
	}
	last = &owner->packet[owner->packets - 1];
	marker = &owner->packet[owner->packets - 2];
	if (owner->history.tail_lsn != 0 || last->record.lsn != owner->history.completed_end_lsn ||
	    last->record.lsn <= owner->selected.current_lsn) {
		return NTFS_UNSUPPORTED;
	}
	advanced = owner->selected;
	advanced.current_lsn = last->record.lsn;
	client = owner->client;
	client.oldest_lsn = marker->record.lsn;
	client.restart_lsn = last->record.lsn;
	anchor = (struct ntfs_logfile_buffer){marker->bytes, marker->count};
	packet = (struct ntfs_logfile_buffer){last->bytes, last->count};
	result = ntfs_write_checkpoint_origin_bind(&advanced, &client, &anchor, &packet);
	if (result != NTFS_OK) {
		return result;
	}
	if (checkpoint->root_transition &&
	    (checkpoint->advanced.current_lsn != advanced.current_lsn ||
		checkpoint->client.oldest_lsn != client.oldest_lsn ||
		checkpoint->client.restart_lsn != client.restart_lsn ||
		checkpoint->client.sequence != client.sequence)) {
		return NTFS_STALE;
	}
	checkpoint->advanced = advanced;
	checkpoint->client = client;
	checkpoint->pending = true;
	owner->operation_packets--;
	return NTFS_OK;
}

static enum ntfs_result
checkpoint_circular_packet_match(struct ntfs_logfile *log,
    const struct ntfs_batch_recovery_packet *packet, struct ntfs_batch_recovery_workspace *work)
{
	struct ntfs_logfile_record_view view;
	enum ntfs_result result;

	result = ntfs_logfile_read_circular_record(
	    log, packet->record.lsn, work->record, sizeof(work->record), &view);
	if (result != NTFS_OK) {
		return result == NTFS_IO || result == NTFS_RANGE || result == NTFS_NO_MEMORY
		    ? result
		    : NTFS_STALE;
	}
	return view.bytes == packet->count && ntfs_equal(work->record, packet->bytes, packet->count)
	    ? NTFS_OK
	    : NTFS_STALE;
}

enum ntfs_result
ntfs_batch_checkpoint_origin_homes(struct ntfs_write_batch_recovery *owner,
    struct ntfs_logfile *log, struct ntfs_batch_recovery_workspace *work)
{
	enum ntfs_result result = NTFS_OK;

	if (owner->packet[0].count == NTFS_WRITE_FORGET_BYTES) {
		/* A new floor can no longer borrow missing origin homes from the copy
		 * slots which the next operation will reuse. A torn sole home refuses. */
		result = checkpoint_circular_packet_match(log, &owner->packet[0], work);
		if (result == NTFS_OK) {
			result = checkpoint_circular_packet_match(log, &owner->packet[1], work);
		}
	}
	if (result == NTFS_OK && owner->checkpoint.pending) {
		result = checkpoint_circular_packet_match(
		    log, &owner->packet[owner->operation_packets - 1], work);
	}
	return result;
}

static enum ntfs_result
checkpoint_marker_successor(const struct ntfs_logfile_restart *restart,
    const struct ntfs_batch_recovery_packet *marker, uint64_t *out)
{
	struct ntfs_logfile_lsn location;
	uint64_t page, sequence, maximum;
	size_t within;
	uint32_t offset_bits;
	enum ntfs_result result;

	result = ntfs_logfile_lsn_decode(restart, marker->record.lsn, &location);
	if (result != NTFS_OK) {
		return result;
	}
	if (!ntfs_bounds(location.record_offset, marker->count, NTFS_WRITE_CLUSTER_BYTES)) {
		return NTFS_UNSUPPORTED;
	}
	within = (location.record_offset + marker->count + NTFS_WIRE_ALIGNMENT - 1) &
	    ~(size_t)(NTFS_WIRE_ALIGNMENT - 1);
	page = location.page_offset;
	sequence = location.sequence;
	offset_bits = NTFS_LFS_LSN_BITS - restart->sequence_bits;
	maximum = UINT64_MAX >> offset_bits;
	if (!ntfs_bounds(within, sizeof(struct ntfs_disk_log_record), NTFS_WRITE_CLUSTER_BYTES)) {
		page += NTFS_WRITE_CLUSTER_BYTES;
		if (page == restart->usable_bytes) {
			if (sequence == maximum) {
				return NTFS_RANGE;
			}
			page = restart->circular_offset;
			sequence++;
		}
		within = NTFS_WRITE_LOG_DATA_OFFSET;
	}
	*out = sequence << offset_bits | (page + within) >> NTFS_LFS_LSN_OFFSET_SHIFT;
	return NTFS_OK;
}

enum ntfs_result
ntfs_batch_checkpoint_pages(
    struct ntfs_write_batch_recovery *owner, struct ntfs_write_batch_pages **out)
{
	struct ntfs_write_batch_pages_input input = {0};
	struct ntfs_write_batch_packet packet = {0};
	const struct ntfs_batch_recovery_packet *last, *marker;
	uint8_t *bytes;
	size_t actual;
	enum ntfs_result result;

	*out = NULL;
	if (!owner->checkpoint.pending) {
		return NTFS_OK;
	}
	last = &owner->packet[owner->packets - 1];
	marker = &owner->packet[owner->operation_packets - 1];
	input.restart = owner->origin;
	input.floor_lsn = owner->client.oldest_lsn;
	input.tail_lsn = marker->record.lsn;
	result = checkpoint_marker_successor(&owner->origin, marker, &input.next_lsn);
	if (result != NTFS_OK) {
		return result;
	}
	packet.record = last->record;
	packet.record.lsn = 0;
	packet.payload = (struct ntfs_logfile_buffer){
	    last->bytes + last->record.data.offset, last->record.data.length};
	packet.previous = packet.undo_next = SIZE_MAX;
	input.packet = &packet;
	input.packets = NTFS_WRITE_EMPTY_CHECKPOINT_PAGES;
	result = ntfs_write_batch_pages_prepare(&owner->reader, &input, out);
	if (result != NTFS_OK || ntfs_write_batch_pages_lsn(*out, 0) != last->record.lsn) {
		return result == NTFS_OK ? NTFS_STALE : result;
	}
	bytes = ntfs_batch_recovery_allocate(owner, NTFS_WRITE_CHECKPOINT_BYTES);
	if (bytes == NULL) {
		return NTFS_NO_MEMORY;
	}
	result = ntfs_write_batch_pages_packet_copy(
	    *out, 0, bytes, NTFS_WRITE_CHECKPOINT_BYTES, &actual);
	if (result == NTFS_OK &&
	    (actual != last->count || !ntfs_equal(bytes, last->bytes, actual))) {
		result = NTFS_STALE;
	}
	ntfs_batch_recovery_release(owner, bytes, NTFS_WRITE_CHECKPOINT_BYTES);
	return result;
}

static uint8_t *
checkpoint_recovery_publication(struct ntfs_write_batch_recovery *owner, uint64_t physical,
    enum ntfs_write_recovery_stage stage)
{
	uint8_t *image;

	if (owner->count == owner->capacity) {
		return NULL;
	}
	image = owner->frames + owner->count * NTFS_WRITE_CLUSTER_BYTES;
	owner->publication[owner->count++] =
	    (struct ntfs_write_batch_recovery_publication){physical, image, stage};
	return image;
}

static enum ntfs_result
checkpoint_recovery_root(struct ntfs_write_batch_recovery *owner,
    struct ntfs_batch_recovery_workspace *work, size_t slot, const uint8_t *previous,
    enum ntfs_write_recovery_stage stage, bool advanced, bool clean, uint8_t **out)
{
	struct ntfs_disk_log_restart_area *area;
	struct ntfs_disk_log_client *client;
	uint8_t *image;
	enum ntfs_result result;

	ntfs_copy(work->image, work->restart[owner->checkpoint.old_slot], NTFS_WRITE_CLUSTER_BYTES);
	result = ntfs_fixup(work->image, sizeof(work->image), "RSTR");
	if (result != NTFS_OK) {
		return result;
	}
	area = (void *)(work->image + owner->selected.area.offset);
	client = (void *)(work->image + owner->selected.clients.offset);
	ntfs_put_u16(area->flags, clean ? NTFS_LOGFILE_RESTART_CLEAN : 0);
	if (advanced) {
		ntfs_put_u64(area->current_lsn, owner->checkpoint.advanced.current_lsn);
		ntfs_put_u32(area->last_data_bytes,
		    NTFS_WRITE_CHECKPOINT_BYTES - sizeof(struct ntfs_disk_log_record));
		ntfs_put_u64(client->oldest_lsn, owner->checkpoint.client.oldest_lsn);
		ntfs_put_u64(client->restart_lsn, owner->checkpoint.client.restart_lsn);
	}
	image = checkpoint_recovery_publication(owner, owner->checkpoint.physical[slot], stage);
	if (image == NULL) {
		return NTFS_RANGE;
	}
	result =
	    ntfs_record_protect(work->image, sizeof(work->image), image, NTFS_WRITE_CLUSTER_BYTES);
	if (result == NTFS_OK) {
		result =
		    ntfs_write_guard_frame(previous, NTFS_WRITE_CLUSTER_BYTES, image, &work->guard);
	}
	if (result == NTFS_OK) {
		*out = image;
	}
	return result;
}

static enum ntfs_result
checkpoint_recovery_home(struct ntfs_write_batch_recovery *owner, struct ntfs_stream *log,
    const struct ntfs_write_batch_pages *pages, struct ntfs_batch_recovery_workspace *work)
{
	const struct ntfs_write_batch_page *page;
	uint64_t physical;
	uint8_t *image;
	enum ntfs_result result;

	if (ntfs_write_batch_pages_count(pages) != NTFS_WRITE_EMPTY_CHECKPOINT_PAGES) {
		return NTFS_CORRUPT;
	}
	page = ntfs_write_batch_pages_get(pages, 0);
	result = ntfs_batch_recovery_mapping(log, page->offset, &physical);
	if (result == NTFS_OK) {
		result =
		    ntfs_batch_recovery_read(owner, physical, work->before, sizeof(work->before));
	}
	if (result != NTFS_OK) {
		return result;
	}
	ntfs_copy(work->image, work->before, sizeof(work->image));
	result = ntfs_fixup(work->image, sizeof(work->image), "RCRD");
	ntfs_copy(work->guard.restored, page->protected_bytes, NTFS_WRITE_CLUSTER_BYTES);
	if (ntfs_fixup(work->guard.restored, NTFS_WRITE_CLUSTER_BYTES, "RCRD") != NTFS_OK) {
		return NTFS_CORRUPT;
	}
	if (result == NTFS_OK &&
	    ntfs_write_restored_record_equal(
		work->image, work->guard.restored, NTFS_WRITE_CLUSTER_BYTES)) {
		return NTFS_OK;
	}
	image =
	    checkpoint_recovery_publication(owner, physical, NTFS_WRITE_RECOVERY_CHECKPOINT_HOME);
	if (image == NULL) {
		return NTFS_RANGE;
	}
	ntfs_copy(image, page->protected_bytes, NTFS_WRITE_CLUSTER_BYTES);
	return ntfs_write_guard_frame(work->before, sizeof(work->before), image, &work->guard);
}

enum ntfs_result
ntfs_batch_checkpoint_prepare(struct ntfs_write_batch_recovery *owner, struct ntfs_stream *log,
    const struct ntfs_write_batch_pages *pages, struct ntfs_batch_recovery_workspace *work)
{
	const uint8_t *previous[NTFS_LFS_RESTART_PAGES];
	uint8_t *image;
	size_t slot, index;
	enum ntfs_result result;

	if (!owner->checkpoint.pending || pages == NULL || owner->count != 0 ||
	    (owner->updates != 0 && !owner->committed && !owner->compensated)) {
		return NTFS_UNSUPPORTED;
	}
	for (index = 0; owner->committed && index < owner->homes; index++) {
		if (!ntfs_equal(owner->home[index].source, owner->home[index].after,
			NTFS_WRITE_CLUSTER_BYTES)) {
			return NTFS_STALE;
		}
	}
	for (slot = 0; slot < NTFS_LFS_RESTART_PAGES; slot++) {
		previous[slot] = work->restart[slot];
		if (!owner->checkpoint.root_transition) {
			result = checkpoint_recovery_root(owner, work, slot, previous[slot],
			    slot == 0 ? NTFS_WRITE_RECOVERY_DIRTY_FIRST
				      : NTFS_WRITE_RECOVERY_DIRTY_SECOND,
			    false, false, &image);
			if (result != NTFS_OK) {
				return result;
			}
			previous[slot] = image;
		}
	}
	result = checkpoint_recovery_home(owner, log, pages, work);
	for (slot = 0; result == NTFS_OK && slot < NTFS_LFS_RESTART_PAGES; slot++) {
		result = checkpoint_recovery_root(owner, work, slot, previous[slot],
		    slot == 0 ? NTFS_WRITE_RECOVERY_ADVANCED_FIRST
			      : NTFS_WRITE_RECOVERY_ADVANCED_SECOND,
		    true, false, &image);
		if (result == NTFS_OK) {
			previous[slot] = image;
		}
	}
	for (slot = 0; result == NTFS_OK && slot < NTFS_LFS_RESTART_PAGES; slot++) {
		result = checkpoint_recovery_root(owner, work, slot, previous[slot],
		    slot == 0 ? NTFS_WRITE_RECOVERY_CLEAN_FIRST : NTFS_WRITE_RECOVERY_CLEAN_SECOND,
		    true, true, &image);
	}
	return result;
}
