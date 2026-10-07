/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_batch_recover_internal.h"
#include "write_payload.h"
#include "logfile_internal.h"
#include <ntfs/recovery.h>

static enum ntfs_result
recovery_packet_retain(
    void *context, const struct ntfs_logfile_record_view *view, const void *bytes)
{
	struct ntfs_write_batch_recovery *owner = context;
	struct ntfs_batch_recovery_packet *entries, *entry;
	size_t capacity;

	if (owner->packets == NTFS_WRITE_BATCH_MAX_PACKETS ||
	    view->bytes > NTFS_WRITE_BATCH_MAX_PACKET_BYTES) {
		return NTFS_RANGE;
	}
	if (view->record.client_index != 0 ||
	    view->record.client_sequence != owner->client.sequence) {
		return NTFS_STALE;
	}
	if (owner->packets == owner->packet_capacity) {
		capacity = owner->packet_capacity == 0
		    ? NTFS_BATCH_RECOVERY_INITIAL_PACKETS
		    : owner->packet_capacity * NTFS_VECTOR_GROWTH;
		if (capacity > NTFS_WRITE_BATCH_MAX_PACKETS) {
			capacity = NTFS_WRITE_BATCH_MAX_PACKETS;
		}
		entries = ntfs_batch_recovery_allocate(owner, capacity * sizeof(*entries));
		if (entries == NULL) {
			return NTFS_NO_MEMORY;
		}
		ntfs_copy(entries, owner->packet, owner->packets * sizeof(*entries));
		ntfs_batch_recovery_release(
		    owner, owner->packet, owner->packet_capacity * sizeof(*entries));
		owner->packet = entries;
		owner->packet_capacity = capacity;
	}
	entry = &owner->packet[owner->packets];
	entry->bytes = ntfs_batch_recovery_allocate(owner, view->bytes);
	if (entry->bytes == NULL) {
		return NTFS_NO_MEMORY;
	}
	entry->count = view->bytes;
	entry->record = view->record;
	entry->target = entry->home = SIZE_MAX;
	ntfs_copy(entry->bytes, bytes, view->bytes);
	owner->packets++;
	return NTFS_OK;
}

static enum ntfs_result
recovery_target_bind(struct ntfs_write_batch_recovery *owner, size_t ordinal)
{
	struct ntfs_batch_recovery_packet *packet = &owner->packet[ordinal];
	struct ntfs_batch_recovery_target *target = &owner->target[owner->targets];
	const struct ntfs_logfile_update *update = &packet->update;
	const uint8_t *payload = packet->bytes + packet->record.data.offset;
	const struct ntfs_disk_log_open_attribute *entry;
	uint64_t number;
	size_t unit, previous;
	uint16_t flags;

	if (packet->record.transaction != NTFS_WRITE_MFT_KEY || packet->record.previous_lsn != 0 ||
	    packet->record.undo_next_lsn != 0 || update->undo_operation != NTFS_LOG_OP_NOOP ||
	    update->lcn_count != 0 || update->redo.length != sizeof(*entry) ||
	    update->undo.length > NTFS_WRITE_MUTATION_TARGET_NAME_UNITS * sizeof(uint16_t) ||
	    update->undo.length % sizeof(uint16_t) != 0 || update->target_vcn != 0 ||
	    update->cluster_index != 0 || update->record_offset != 0 ||
	    update->attribute_offset != 0 ||
	    update->target_attribute != NTFS_WRITE_MFT_KEY + owner->targets * sizeof(*entry)) {
		return NTFS_UNSUPPORTED;
	}
	entry = (const void *)(payload + update->redo.offset);
	if (ntfs_u32(entry->allocated) != NTFS_LOG_TABLE_ALLOCATED || entry->dirty_pages != 0 ||
	    ntfs_u16(entry->reserved) != 0 || entry->reserved[sizeof(uint16_t)] != 0 ||
	    ntfs_u64(entry->name_pointer) != 0 ||
	    ntfs_u64(entry->open_lsn) != owner->packet[ordinal - 1].record.lsn) {
		return NTFS_CORRUPT;
	}
	target->key = update->target_attribute;
	target->flags = update->attribute_flags;
	target->identity.reference = ntfs_u64(entry->reference);
	target->identity.attribute_type = ntfs_u32(entry->attribute_type);
	target->identity.name_count = update->undo.length / sizeof(uint16_t);
	number = target->identity.reference & NTFS_REFERENCE_RECORD_MASK;
	if (target->identity.reference >> NTFS_REFERENCE_SEQUENCE_SHIFT == 0) {
		return NTFS_CORRUPT;
	}
	for (unit = 0; unit < target->identity.name_count; unit++) {
		target->identity.name[unit] =
		    ntfs_u16(payload + update->undo.offset + unit * sizeof(uint16_t));
	}
	if (target->identity.attribute_type == NTFS_ATTRIBUTE_DATA) {
		if (target->identity.name_count != 0 ||
		    (number != NTFS_MFT_RECORD && number != NTFS_BITMAP_RECORD)) {
			return NTFS_UNSUPPORTED;
		}
		flags = number == NTFS_MFT_RECORD ? NTFS_WRITE_MFT_TARGET_FLAG : 0;
	} else if (target->identity.attribute_type == NTFS_ATTR_BITMAP) {
		flags = 0;
		if ((number == NTFS_MFT_RECORD && target->identity.name_count != 0) ||
		    (number != NTFS_MFT_RECORD &&
			target->identity.name_count != NTFS_WRITE_MUTATION_TARGET_NAME_UNITS)) {
			return NTFS_UNSUPPORTED;
		}
	} else if (target->identity.attribute_type == NTFS_ATTR_INDEX_ALLOCATION) {
		flags = NTFS_BATCH_RECOVERY_INDEX_FLAG;
		if (target->identity.name_count != NTFS_WRITE_MUTATION_TARGET_NAME_UNITS) {
			return NTFS_UNSUPPORTED;
		}
	} else {
		return NTFS_UNSUPPORTED;
	}
	if (target->identity.name_count != 0 &&
	    (target->identity.name[0] != '$' || target->identity.name[1] != 'I' ||
		target->identity.name[2] != '3' || target->identity.name[3] != '0')) {
		return NTFS_UNSUPPORTED;
	}
	if (target->flags != flags ||
	    ntfs_u32(entry->index_buffer_bytes) !=
		(flags == NTFS_BATCH_RECOVERY_INDEX_FLAG ? NTFS_WRITE_CLUSTER_BYTES : 0) ||
	    (packet->record.flags & ~NTFS_LOGFILE_RECORD_MULTI_PAGE) !=
		(target->identity.name_count == 0 ? NTFS_LOGFILE_RECORD_ADDING : 0)) {
		return NTFS_CORRUPT;
	}
	for (previous = 0; previous < owner->targets; previous++) {
		if (owner->target[previous].identity.reference == target->identity.reference &&
		    owner->target[previous].identity.attribute_type ==
			target->identity.attribute_type &&
		    owner->target[previous].identity.name_count == target->identity.name_count) {
			return NTFS_CORRUPT;
		}
	}
	packet->target = owner->targets++;
	return NTFS_OK;
}

static bool
recovery_empty_control(const struct ntfs_batch_recovery_packet *packet)
{
	const struct ntfs_logfile_update *update = &packet->update;

	return update->redo_operation == NTFS_LOG_OP_FORGET_TRANSACTION &&
	    update->undo_operation == NTFS_LOG_OP_COMPENSATION && update->redo.length == 0 &&
	    update->undo.length == 0 && update->lcn_count == 0 && update->target_attribute == 0 &&
	    update->target_vcn == 0 && update->record_offset == 0 &&
	    update->attribute_offset == 0 && update->cluster_index == 0 &&
	    update->attribute_flags == 0 && packet->record.undo_next_lsn == 0 &&
	    (packet->record.flags & ~NTFS_LOGFILE_RECORD_MULTI_PAGE) ==
	    NTFS_LOGFILE_RECORD_DELETING;
}

static bool
recovery_compensation_matches(const struct ntfs_batch_recovery_packet *original,
    const struct ntfs_batch_recovery_packet *inverse)
{
	const struct ntfs_logfile_update *a = &original->update, *b = &inverse->update;
	const uint8_t *old = original->bytes + original->record.data.offset;
	const uint8_t *payload = inverse->bytes + inverse->record.data.offset;

	return b->redo_operation == a->undo_operation &&
	    b->undo_operation == NTFS_LOG_OP_COMPENSATION &&
	    b->target_attribute == a->target_attribute && b->target_vcn == a->target_vcn &&
	    b->record_offset == a->record_offset && b->attribute_offset == a->attribute_offset &&
	    b->cluster_index == a->cluster_index && b->attribute_flags == a->attribute_flags &&
	    b->lcn_count == a->lcn_count && b->lcns.length == a->lcns.length &&
	    b->redo.length == a->undo.length && b->undo.length == 0 &&
	    b->compensation_undo_bytes == b->redo.length &&
	    ntfs_equal(payload + b->lcns.offset, old + a->lcns.offset, b->lcns.length) &&
	    ntfs_equal(payload + b->redo.offset, old + a->undo.offset, b->redo.length) &&
	    (inverse->record.flags & ~NTFS_LOGFILE_RECORD_MULTI_PAGE) == 0 &&
	    inverse->record.undo_next_lsn == original->record.undo_next_lsn;
}

static enum ntfs_result
recovery_qualified_prefix(struct ntfs_write_batch_recovery *owner, struct ntfs_volume *volume,
    struct ntfs_batch_recovery_workspace *work)
{
	struct ntfs_logfile_buffer packet[NTFS_WRITE_REPLAY_MAX_PACKETS];
	struct ntfs_write_replay_plan *current;
	const struct ntfs_logfile_update *snapshot;
	uint64_t tail = 0;
	size_t first = NTFS_BATCH_RECOVERY_ORIGIN_PACKETS, index, count;
	enum ntfs_result result;

	while (owner->operation_packets - first >= 2) {
		snapshot = &owner->packet[first + NTFS_WRITE_REPLAY_SNAPSHOT].update;
		if (owner->packet[first].update.redo_operation !=
			NTFS_LOG_OP_OPEN_NONRESIDENT_ATTRIBUTE ||
		    snapshot->redo_operation != NTFS_LOG_OP_INITIALIZE_FILE_RECORD ||
		    snapshot->undo_operation != NTFS_LOG_OP_NOOP) {
			break;
		}
		if (owner->qualified == NULL) {
			owner->qualified_capacity =
			    owner->operation_packets / NTFS_WRITE_REPLAY_PACKETS;
			if (owner->qualified_capacity > NTFS_WRITE_HISTORY_TRANSACTIONS) {
				owner->qualified_capacity = NTFS_WRITE_HISTORY_TRANSACTIONS;
			}
			owner->qualified = ntfs_batch_recovery_allocate(
			    owner, owner->qualified_capacity * sizeof(*owner->qualified));
			if (owner->qualified == NULL) {
				return NTFS_NO_MEMORY;
			}
		}
		if (owner->qualified_count == owner->qualified_capacity) {
			return NTFS_RANGE;
		}
		count = owner->operation_packets - first;
		if (count > NTFS_WRITE_REPLAY_MAX_PACKETS) {
			count = NTFS_WRITE_REPLAY_MAX_PACKETS;
		}
		for (index = 0; index < count; index++) {
			packet[index] = (struct ntfs_logfile_buffer){
			    owner->packet[first + index].bytes, owner->packet[first + index].count};
		}
		current = &owner->qualified[owner->qualified_count];
		result = ntfs_write_history_prepare_transaction(
		    volume, &owner->origin, tail, packet, count, &work->replay, current, &count);
		if (result != NTFS_OK) {
			return result;
		}
		if (!current->committed && !current->compensated) {
			return NTFS_BUSY;
		}
		result = ntfs_write_history_bind_previous(
		    owner->qualified, owner->qualified_count, current);
		if (result != NTFS_OK) {
			return result;
		}
		owner->qualified_count++;
		tail = current->end_lsn;
		first += count;
	}
	owner->ordinary_first = first;
	return NTFS_OK;
}

static enum ntfs_result
recovery_lifetime_bind(struct ntfs_write_batch_recovery *owner, size_t *cursor)
{
	struct ntfs_batch_recovery_packet *packet;
	const struct ntfs_batch_recovery_packet *original;
	uint64_t previous = 0;
	size_t index, target;
	bool aborting = false;
	enum ntfs_result result;

	owner->targets = owner->updates = owner->compensations = owner->remaining_undo = 0;
	owner->committed = owner->compensated = false;
	owner->target = NULL;
	owner->target_capacity = 0;
	for (index = *cursor; index < owner->operation_packets &&
	    owner->packet[index].update.redo_operation == NTFS_LOG_OP_OPEN_NONRESIDENT_ATTRIBUTE;
	    index++) {
		if (owner->target_capacity != 0 &&
		    owner->packet[index].update.target_attribute == NTFS_WRITE_MFT_KEY) {
			break;
		}
		owner->target_capacity++;
	}
	if (owner->target_capacity == 0) {
		return NTFS_UNSUPPORTED;
	}
	owner->target =
	    ntfs_batch_recovery_allocate(owner, owner->target_capacity * sizeof(*owner->target));
	if (owner->target == NULL) {
		return NTFS_NO_MEMORY;
	}
	index = *cursor;
	while (index < owner->operation_packets) {
		packet = &owner->packet[index];
		if (packet->record.type != NTFS_LOGFILE_RECORD_UPDATE) {
			return NTFS_UNSUPPORTED;
		}
		result = ntfs_logfile_update_decode(packet->bytes + packet->record.data.offset,
		    packet->record.data.length, &packet->update);
		if (result != NTFS_OK) {
			return result;
		}
		if (packet->update.redo_operation != NTFS_LOG_OP_OPEN_NONRESIDENT_ATTRIBUTE ||
		    (owner->targets != 0 &&
			packet->update.target_attribute == NTFS_WRITE_MFT_KEY)) {
			break;
		}
		result = recovery_target_bind(owner, index++);
		if (result != NTFS_OK) {
			return result;
		}
	}
	owner->first_update = index;
	/* Attribute opens have no transaction undo obligation. A recovered prefix
	 * may end before the first update, then a later operation starts a fresh
	 * open group. Retain both actual groups without inventing a Forget. */
	if (index < owner->operation_packets &&
	    owner->packet[index].update.redo_operation == NTFS_LOG_OP_OPEN_NONRESIDENT_ATTRIBUTE) {
		*cursor = index;
		return NTFS_OK;
	}
	for (; index < owner->operation_packets; index++) {
		packet = &owner->packet[index];
		if (packet->record.type != NTFS_LOGFILE_RECORD_UPDATE ||
		    packet->record.transaction != NTFS_WRITE_TRANSACTION_KEY ||
		    packet->record.previous_lsn != previous || owner->targets == 0) {
			return NTFS_UNSUPPORTED;
		}
		result = ntfs_logfile_update_decode(packet->bytes + packet->record.data.offset,
		    packet->record.data.length, &packet->update);
		if (result != NTFS_OK) {
			return result;
		}
		if (recovery_empty_control(packet)) {
			if (owner->updates == 0 || (aborting && owner->remaining_undo != 0)) {
				return NTFS_CORRUPT;
			}
			owner->committed = !aborting;
			owner->compensated = aborting;
			index++;
			break;
		}
		if (packet->update.undo_operation == NTFS_LOG_OP_COMPENSATION) {
			if (!aborting) {
				aborting = true;
				owner->remaining_undo = owner->updates;
			}
			if (owner->remaining_undo == 0) {
				return NTFS_CORRUPT;
			}
			original = &owner->packet[owner->first_update + owner->remaining_undo - 1];
			if (!recovery_compensation_matches(original, packet)) {
				return NTFS_CORRUPT;
			}
			packet->target = original->target;
			owner->remaining_undo--;
			owner->compensations++;
		} else {
			if (aborting || packet->record.undo_next_lsn != previous ||
			    packet->update.lcn_count != 1) {
				return NTFS_UNSUPPORTED;
			}
			for (target = 0; target < owner->targets; target++) {
				if (packet->update.target_attribute == owner->target[target].key) {
					break;
				}
			}
			if (target == owner->targets ||
			    packet->update.attribute_flags != owner->target[target].flags) {
				return NTFS_STALE;
			}
			packet->target = target;
			owner->target[target].used = true;
			owner->updates++;
		}
		previous = packet->record.lsn;
	}
	if (!aborting) {
		owner->remaining_undo = owner->updates;
	}
	if (owner->committed) {
		for (target = 0; target < owner->targets; target++) {
			if (!owner->target[target].used) {
				return NTFS_CORRUPT;
			}
		}
	}
	*cursor = index;
	return NTFS_OK;
}

static enum ntfs_result
recovery_history_bind(struct ntfs_write_batch_recovery *owner, struct ntfs_volume *volume,
    struct ntfs_batch_recovery_workspace *work)
{
	struct ntfs_batch_recovery_packet *packet;
	struct ntfs_logfile_buffer anchor, checkpoint;
	size_t index, first;
	enum ntfs_result result;

	if (!owner->history.complete || !owner->history.endpoint_verified ||
	    owner->packets < NTFS_BATCH_RECOVERY_ORIGIN_PACKETS ||
	    owner->packet[1].count != NTFS_WRITE_CHECKPOINT_BYTES ||
	    !ntfs_equal(
		owner->packet[1].bytes, work->checkpoint_packet, NTFS_WRITE_CHECKPOINT_BYTES) ||
	    owner->selected.current_lsn != owner->client.restart_lsn ||
	    owner->selected.last_data_bytes !=
		NTFS_WRITE_CHECKPOINT_BYTES - sizeof(struct ntfs_disk_log_record)) {
		return NTFS_UNSUPPORTED;
	}
	owner->origin = owner->selected;
	anchor = (struct ntfs_logfile_buffer){owner->packet[0].bytes, owner->packet[0].count};
	checkpoint = (struct ntfs_logfile_buffer){owner->packet[1].bytes, owner->packet[1].count};
	result =
	    ntfs_write_checkpoint_origin_bind(&owner->origin, &owner->client, &anchor, &checkpoint);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_batch_checkpoint_bind(owner);
	if (result != NTFS_OK) {
		return result;
	}
	for (index = NTFS_BATCH_RECOVERY_ORIGIN_PACKETS; index < owner->operation_packets;
	    index++) {
		packet = &owner->packet[index];
		if (packet->record.type != NTFS_LOGFILE_RECORD_UPDATE) {
			return NTFS_UNSUPPORTED;
		}
		result = ntfs_logfile_update_decode(packet->bytes + packet->record.data.offset,
		    packet->record.data.length, &packet->update);
		if (result != NTFS_OK) {
			return result;
		}
	}
	result = recovery_qualified_prefix(owner, volume, work);
	if (result != NTFS_OK) {
		return result;
	}
	owner->first_update = owner->ordinary_first;
	if (owner->ordinary_first == owner->operation_packets) {
		return owner->history.tail_lsn == 0 ? NTFS_OK : NTFS_UNSUPPORTED;
	}
	owner->lifetime_capacity = owner->operation_packets - owner->ordinary_first;
	owner->lifetime = ntfs_batch_recovery_allocate(
	    owner, owner->lifetime_capacity * sizeof(*owner->lifetime));
	if (owner->lifetime == NULL) {
		return NTFS_NO_MEMORY;
	}
	index = owner->ordinary_first;
	while (index < owner->operation_packets) {
		first = index;
		result = recovery_lifetime_bind(owner, &index);
		owner->lifetime[owner->lifetimes++] = (struct ntfs_batch_recovery_lifetime){
		    owner->target, first, index, owner->targets, owner->target_capacity,
		    owner->first_update, owner->updates, owner->compensations,
		    owner->remaining_undo, owner->committed, owner->compensated};
		if (result != NTFS_OK) {
			return result;
		}
		if (index < owner->operation_packets && owner->updates != 0 && !owner->committed &&
		    !owner->compensated) {
			return NTFS_BUSY;
		}
	}
	if ((owner->committed || owner->compensated) && owner->history.tail_lsn != 0) {
		return NTFS_UNSUPPORTED;
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_batch_recovery_qualified_validate(struct ntfs_write_batch_recovery *owner,
    struct ntfs_volume *volume, struct ntfs_batch_recovery_workspace *work)
{
	struct ntfs_logfile_buffer packet[NTFS_WRITE_REPLAY_MAX_PACKETS];
	struct ntfs_write_replay_plan *current;
	uint64_t tail = 0;
	size_t first = NTFS_BATCH_RECOVERY_ORIGIN_PACKETS, transaction, index, count;
	enum ntfs_result result;

	/* Rebind against the fully reconstructed pre-operation MFT map. The
	 * temporary journal bootstrap may have used a committed or torn-after map. */
	for (transaction = 0; transaction < owner->qualified_count; transaction++) {
		count = owner->ordinary_first - first;
		if (count > NTFS_WRITE_REPLAY_MAX_PACKETS) {
			count = NTFS_WRITE_REPLAY_MAX_PACKETS;
		}
		for (index = 0; index < count; index++) {
			packet[index] = (struct ntfs_logfile_buffer){
			    owner->packet[first + index].bytes, owner->packet[first + index].count};
		}
		current = &owner->qualified[transaction];
		result = ntfs_write_history_prepare_transaction(
		    volume, &owner->origin, tail, packet, count, &work->replay, current, &count);
		if (result != NTFS_OK) {
			return result;
		}
		result = ntfs_write_history_bind_previous(owner->qualified, transaction, current);
		if (result != NTFS_OK) {
			return result;
		}
		tail = current->end_lsn;
		first += count;
	}
	if (first != owner->ordinary_first) {
		return NTFS_CORRUPT;
	}
	return ntfs_write_history_settled_plans(volume, owner->qualified, owner->qualified_count);
}

static enum ntfs_result
recovery_qualified_pages(struct ntfs_write_batch_recovery *owner, struct ntfs_logfile *log,
    struct ntfs_batch_recovery_workspace *work)
{
	struct ntfs_logfile_lsn location;
	struct ntfs_logfile_page_view page;
	const struct ntfs_batch_recovery_packet *packet;
	size_t index;
	enum ntfs_result result;

	/* These settled lifetimes use packed qualified pages, not the ordinary
	 * one-packet placement policy. Prove their complete circular homes directly
	 * before allowing subsequent recovery to reuse either tail-copy slot. */
	for (index = NTFS_BATCH_RECOVERY_ORIGIN_PACKETS; index < owner->ordinary_first; index++) {
		packet = &owner->packet[index];
		result = ntfs_logfile_lsn_decode(&owner->origin, packet->record.lsn, &location);
		if (result == NTFS_OK) {
			result = ntfs_logfile_read_page(
			    log, location.page_offset, work->image, sizeof(work->image), &page);
		}
		if (result != NTFS_OK) {
			return result;
		}
		if (page.storage != NTFS_LOGFILE_CIRCULAR ||
		    page.page.flags != NTFS_LOGFILE_PAGE_RECORD_END ||
		    page.page.last_end_lsn < packet->record.lsn ||
		    !ntfs_bounds(
			location.record_offset, packet->count, page.page.next_record_offset) ||
		    !ntfs_equal(
			work->image + location.record_offset, packet->bytes, packet->count)) {
			return NTFS_STALE;
		}
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_batch_recovery_capture(struct ntfs_write_batch_recovery *owner, struct ntfs_volume *volume,
    struct ntfs_batch_recovery_workspace *work)
{
	struct ntfs_logfile *log = NULL;
	struct ntfs_logfile_limits limits;
	struct ntfs_logfile_page_index_report index;
	enum ntfs_result result;

	ntfs_logfile_default_limits(&limits);
	limits.max_read_calls = NTFS_RECOVERY_DEFAULT_READ_CALLS;
	limits.max_read_bytes = NTFS_RECOVERY_DEFAULT_READ_BYTES;
	result = ntfs_logfile_open_volume_retained_impl(volume, &limits, NULL, &log);
	if (result == NTFS_OK) {
		result = ntfs_logfile_get_restart(log, &owner->selected);
	}
	if (result == NTFS_OK) {
		result = ntfs_logfile_get_client(log, 0, &owner->client);
	}
	if (result == NTFS_OK) {
		result = ntfs_logfile_prepare_write_page_index(
		    log, NTFS_BATCH_RECOVERY_INDEX_BYTES, &index);
	}
	if (result == NTFS_OK) {
		result = ntfs_logfile_capture_checkpoint(log, 0, owner->client.sequence, NULL,
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
		result = ntfs_logfile_visit_records(log, owner->client.oldest_lsn,
		    NTFS_WRITE_BATCH_MAX_PACKETS, work->record, sizeof(work->record),
		    recovery_packet_retain, owner, &owner->history);
	}
	if (result == NTFS_OK) {
		result = recovery_history_bind(owner, volume, work);
	}
	if (result == NTFS_OK) {
		result = recovery_qualified_pages(owner, log, work);
	}
	if (result == NTFS_OK) {
		result = ntfs_batch_checkpoint_origin_homes(owner, log, work);
	}
	if (result == NTFS_OK) {
		result = ntfs_batch_recovery_tail_bind(owner, log, work);
	}
	ntfs_logfile_close(log);
	return result;
}

static size_t
recovery_packet_ordinal(const struct ntfs_write_batch_recovery *owner, uint64_t lsn)
{
	size_t index;

	if (lsn == 0) {
		return SIZE_MAX;
	}
	for (index = owner->ordinary_first; index < owner->operation_packets; index++) {
		if (owner->packet[index].record.lsn == lsn) {
			return index - owner->ordinary_first;
		}
	}
	return SIZE_MAX;
}

enum ntfs_result
ntfs_batch_recovery_pages(struct ntfs_write_batch_recovery *owner,
    struct ntfs_write_batch_pages **original, struct ntfs_write_batch_pages **abort)
{
	struct ntfs_write_batch_packet *packet = NULL, *entry;
	struct ntfs_write_batch_pages_input input = {0};
	struct ntfs_logfile_update_input inverse;
	const struct ntfs_batch_recovery_packet *old;
	const uint8_t *payload;
	uint8_t *storage = NULL;
	size_t count, capacity, index, ordinal, bytes;
	uint32_t encoded;
	uint64_t previous;
	enum ntfs_result result = NTFS_OK;

	*original = *abort = NULL;
	count = owner->operation_packets - owner->ordinary_first;
	capacity = count > owner->remaining_undo + 1 ? count : owner->remaining_undo + 1;
	packet = ntfs_batch_recovery_allocate(owner, capacity * sizeof(*packet));
	if (packet == NULL) {
		return NTFS_NO_MEMORY;
	}
	for (index = 0; index < count; index++) {
		old = &owner->packet[index + owner->ordinary_first];
		packet[index].record = old->record;
		packet[index].record.lsn = 0;
		packet[index].record.previous_lsn = packet[index].record.undo_next_lsn = 0;
		packet[index].record.flags &= ~NTFS_LOGFILE_RECORD_MULTI_PAGE;
		packet[index].payload = (struct ntfs_logfile_buffer){
		    old->bytes + old->record.data.offset, old->record.data.length};
		packet[index].previous = recovery_packet_ordinal(owner, old->record.previous_lsn);
		packet[index].undo_next = recovery_packet_ordinal(owner, old->record.undo_next_lsn);
	}
	input.restart = owner->origin;
	input.floor_lsn = owner->client.oldest_lsn;
	input.tail_lsn = owner->packet[owner->ordinary_first - 1].record.lsn;
	input.packet = packet;
	input.packets = count;
	if (count != 0) {
		input.next_lsn = owner->packet[owner->ordinary_first].record.lsn;
		result = ntfs_write_batch_pages_prepare(&owner->reader, &input, original);
		for (index = 0; result == NTFS_OK && index < count; index++) {
			if (ntfs_write_batch_pages_lsn(*original, index) !=
			    owner->packet[index + owner->ordinary_first].record.lsn) {
				result = NTFS_STALE;
			}
		}
	}
	if (result != NTFS_OK || owner->committed || owner->compensated || owner->updates == 0) {
		goto done;
	}
	bytes = (owner->remaining_undo + 1) * NTFS_WRITE_BATCH_MAX_PACKET_BYTES;
	storage = ntfs_batch_recovery_allocate(owner, bytes);
	if (storage == NULL) {
		result = NTFS_NO_MEMORY;
		goto done;
	}
	ntfs_zero(packet, capacity * sizeof(*packet));
	for (index = 0; index <= owner->remaining_undo; index++) {
		entry = &packet[index];
		ntfs_zero(&inverse, sizeof(inverse));
		if (index == owner->remaining_undo) {
			inverse.redo_operation = NTFS_LOG_OP_FORGET_TRANSACTION;
			inverse.undo_operation = NTFS_LOG_OP_COMPENSATION;
			entry->record.flags = NTFS_LOGFILE_RECORD_DELETING;
		} else {
			ordinal = owner->first_update + owner->remaining_undo - 1 - index;
			old = &owner->packet[ordinal];
			payload = old->bytes + old->record.data.offset;
			inverse.redo_operation = old->update.undo_operation;
			inverse.undo_operation = NTFS_LOG_OP_COMPENSATION;
			inverse.target_attribute = old->update.target_attribute;
			inverse.target_vcn = old->update.target_vcn;
			inverse.record_offset = old->update.record_offset;
			inverse.attribute_offset = old->update.attribute_offset;
			inverse.cluster_index = old->update.cluster_index;
			inverse.attribute_flags = old->update.attribute_flags;
			inverse.lcns = (struct ntfs_logfile_buffer){
			    payload + old->update.lcns.offset, old->update.lcns.length};
			inverse.redo = (struct ntfs_logfile_buffer){
			    payload + old->update.undo.offset, old->update.undo.length};
			entry->record.undo_next_lsn = old->record.undo_next_lsn;
		}
		result = ntfs_write_payload_encode(&inverse,
		    storage + index * NTFS_WRITE_BATCH_MAX_PACKET_BYTES,
		    NTFS_WRITE_BATCH_MAX_PACKET_BYTES, &encoded);
		if (result != NTFS_OK) {
			goto done;
		}
		entry->record.type = NTFS_LOGFILE_RECORD_UPDATE;
		entry->record.transaction = NTFS_WRITE_TRANSACTION_KEY;
		entry->record.client_sequence = owner->client.sequence;
		entry->record.data =
		    (struct ntfs_logfile_span){sizeof(struct ntfs_disk_log_record), encoded};
		entry->payload = (struct ntfs_logfile_buffer){
		    storage + index * NTFS_WRITE_BATCH_MAX_PACKET_BYTES, encoded};
		entry->previous = index == 0 ? SIZE_MAX : index - 1;
		entry->undo_next = SIZE_MAX;
		previous = owner->packet[owner->packets - 1].record.lsn;
		entry->record.previous_lsn = index == 0 ? previous : 0;
	}
	input.tail_lsn = owner->history.completed_end_lsn;
	input.next_lsn = owner->history.next_lsn;
	input.packets = owner->remaining_undo + 1;
	result = ntfs_write_batch_pages_prepare(&owner->reader, &input, abort);
done:
	ntfs_batch_recovery_release(
	    owner, storage, (owner->remaining_undo + 1) * NTFS_WRITE_BATCH_MAX_PACKET_BYTES);
	ntfs_batch_recovery_release(owner, packet, capacity * sizeof(*packet));
	if (result != NTFS_OK) {
		ntfs_write_batch_pages_close(*original);
		ntfs_write_batch_pages_close(*abort);
		*original = *abort = NULL;
	}
	return result;
}
