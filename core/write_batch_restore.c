/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_batch_recover_internal.h"
#include "write_bitmap.h"
#include "write_retirement.h"
#include <ntfs/record.h>

static enum ntfs_result
recovery_logical_file(const void *bytes, uint64_t number)
{
	const struct ntfs_disk_record *header = bytes;
	const struct ntfs_disk_record_extension *extension =
	    (const void *)((const uint8_t *)bytes + sizeof(*header));
	struct ntfs_attr_view attribute;
	uint32_t position = ntfs_u16(header->attrs_offset), used = ntfs_u32(header->used);
	size_t usa = sizeof(*header) + sizeof(*extension);
	size_t words = NTFS_WRITE_RECORD_BYTES / NTFS_MST_STRIDE + 1;
	enum ntfs_result result;

	if (number > UINT32_MAX ||
	    !ntfs_equal(header->mst.magic, "FILE", sizeof(header->mst.magic)) ||
	    ntfs_u16(header->mst.usa_offset) != usa || ntfs_u16(header->mst.usa_count) != words ||
	    position < usa + words * sizeof(uint16_t) || position % NTFS_WIRE_ALIGNMENT != 0 ||
	    !ntfs_bounds(position, sizeof(uint32_t), used) || used > NTFS_WRITE_RECORD_BYTES ||
	    ntfs_u32(header->allocated) != NTFS_WRITE_RECORD_BYTES ||
	    ntfs_u16(header->sequence) == 0 || ntfs_u64(header->base_reference) != 0 ||
	    ntfs_u32(extension->record_number) != number ||
	    (ntfs_u16(header->flags) & ~(NTFS_RECORD_IN_USE | NTFS_RECORD_DIRECTORY)) != 0) {
		return NTFS_CORRUPT;
	}
	do {
		result = ntfs_attr_at(bytes, used, &position, &attribute);
	} while (result == NTFS_OK);
	return result == NTFS_END ? NTFS_OK : result;
}

enum ntfs_result
ntfs_batch_recovery_bootstrap(
    struct ntfs_write_batch_recovery *owner, struct ntfs_batch_recovery_workspace *work)
{
	enum ntfs_result result, primary, mirror;

	result = ntfs_boot(&owner->reader, &owner->info, &owner->mft_lcn, &owner->mirror_lcn);
	if (result != NTFS_OK) {
		return result;
	}
	if (owner->info.sector_size != NTFS_WRITE_SECTOR_BYTES ||
	    owner->info.cluster_size != NTFS_WRITE_CLUSTER_BYTES ||
	    owner->info.record_size != NTFS_WRITE_RECORD_BYTES ||
	    owner->info.index_size != NTFS_WRITE_CLUSTER_BYTES) {
		return NTFS_UNSUPPORTED;
	}
	result = ntfs_batch_recovery_read(owner, owner->mft_lcn * NTFS_WRITE_CLUSTER_BYTES,
	    work->before, NTFS_WRITE_RECORD_BYTES);
	if (result != NTFS_OK) {
		return result;
	}
	ntfs_copy(work->image, work->before, NTFS_WRITE_RECORD_BYTES);
	primary = ntfs_record_validate(work->image, NTFS_WRITE_RECORD_BYTES);
	if (primary == NTFS_OK) {
		primary = recovery_logical_file(work->image, NTFS_MFT_RECORD);
	}
	if (primary == NTFS_OK) {
		ntfs_copy(owner->bootstrap, work->before, NTFS_WRITE_RECORD_BYTES);
	}
	result = ntfs_batch_recovery_read(owner, owner->mirror_lcn * NTFS_WRITE_CLUSTER_BYTES,
	    work->before, NTFS_WRITE_RECORD_BYTES);
	if (result != NTFS_OK) {
		return result;
	}
	ntfs_copy(work->image, work->before, NTFS_WRITE_RECORD_BYTES);
	mirror = ntfs_record_validate(work->image, NTFS_WRITE_RECORD_BYTES);
	if (mirror == NTFS_OK) {
		mirror = recovery_logical_file(work->image, NTFS_MFT_RECORD);
	}
	if (primary != NTFS_OK && mirror != NTFS_OK) {
		return NTFS_CORRUPT;
	}
	if (primary != NTFS_OK) {
		ntfs_copy(owner->bootstrap, work->before, NTFS_WRITE_RECORD_BYTES);
	}
	/* This is temporary journal acquisition through one complete boot-bound
	 * replica. It is not mount admission or a silent mirror repair. Both full
	 * projected views and exact home provenance must pass before publication. */
	owner->view = NTFS_BATCH_RECOVERY_BOOTSTRAP;
	return NTFS_OK;
}

enum ntfs_result
ntfs_batch_recovery_mapping(const struct ntfs_stream *stream, uint64_t logical, uint64_t *out)
{
	const struct ntfs_run *run;
	uint64_t vcn, lcn;

	if (stream->resident || stream->metadata_only || stream->flags != 0 ||
	    stream->compression_unit != 0 ||
	    stream->clusters > UINT64_MAX / NTFS_WRITE_CLUSTER_BYTES ||
	    logical % NTFS_WRITE_CLUSTER_BYTES != 0 ||
	    !ntfs_bounds(logical, NTFS_WRITE_CLUSTER_BYTES,
		stream->clusters * (uint64_t)NTFS_WRITE_CLUSTER_BYTES)) {
		return NTFS_UNSUPPORTED;
	}
	vcn = logical / NTFS_WRITE_CLUSTER_BYTES;
	run = ntfs_run_find(stream, vcn);
	if (run == NULL || run->lcn == NTFS_HOLE || vcn < run->vcn ||
	    vcn - run->vcn >= run->length || run->lcn > UINT64_MAX - (vcn - run->vcn)) {
		return NTFS_CORRUPT;
	}
	lcn = run->lcn + vcn - run->vcn;
	if (lcn >= stream->volume->info.cluster_count) {
		return NTFS_CORRUPT;
	}
	*out = lcn * NTFS_WRITE_CLUSTER_BYTES;
	return NTFS_OK;
}

static enum ntfs_result
recovery_home_bind(
    struct ntfs_write_batch_recovery *owner, struct ntfs_batch_recovery_packet *packet)
{
	const struct ntfs_logfile_update *update = &packet->update;
	const uint8_t *payload = packet->bytes + packet->record.data.offset;
	const struct ntfs_batch_recovery_target *target = &owner->target[packet->target];
	struct ntfs_batch_recovery_home *home;
	uint64_t lcn, logical;
	size_t index;
	enum ntfs_write_mutation_region_kind kind;
	enum ntfs_result result;

	lcn = ntfs_u64(payload + update->lcns.offset);
	if (lcn == 0 || lcn >= owner->info.cluster_count ||
	    update->target_vcn > (uint64_t)INT64_MAX / NTFS_WRITE_CLUSTER_BYTES ||
	    update->record_offset != 0 || update->attribute_offset != 0) {
		return NTFS_CORRUPT;
	}
	logical = update->target_vcn * NTFS_WRITE_CLUSTER_BYTES;
	kind = target->flags == NTFS_WRITE_MFT_TARGET_FLAG    ? NTFS_WRITE_MUTATION_FILE
	    : target->flags == NTFS_BATCH_RECOVERY_INDEX_FLAG ? NTFS_WRITE_MUTATION_INDEX
							      : NTFS_WRITE_MUTATION_BITMAP;
	for (index = 0; index < owner->homes; index++) {
		home = &owner->home[index];
		if (home->physical == lcn * NTFS_WRITE_CLUSTER_BYTES) {
			if (home->target != packet->target || home->logical != logical ||
			    home->kind != kind) {
				return NTFS_STALE;
			}
			packet->home = index;
			return NTFS_OK;
		}
	}
	if (owner->homes == owner->home_capacity) {
		return NTFS_RANGE;
	}
	home = &owner->home[owner->homes];
	home->physical = lcn * NTFS_WRITE_CLUSTER_BYTES;
	home->logical = logical;
	home->target = packet->target;
	home->kind = kind;
	result =
	    ntfs_batch_recovery_read(owner, home->physical, home->source, sizeof(home->source));
	if (result != NTFS_OK) {
		return result;
	}
	ntfs_copy(home->before, home->source, sizeof(home->source));
	ntfs_copy(home->after, home->source, sizeof(home->source));
	packet->home = owner->homes++;
	return NTFS_OK;
}

static bool
recovery_file_pair(const struct ntfs_write_batch_recovery *owner, size_t ordinal)
{
	const struct ntfs_batch_recovery_packet *a, *b;

	if (ordinal == owner->first_update) {
		return false;
	}
	a = &owner->packet[ordinal - 1];
	b = &owner->packet[ordinal];
	return a->home == b->home && a->update.cluster_index == b->update.cluster_index &&
	    ((a->update.redo_operation == NTFS_LOG_OP_INITIALIZE_FILE_RECORD &&
		 a->update.undo_operation == NTFS_LOG_OP_INITIALIZE_FILE_RECORD) ||
		(a->update.redo_operation == NTFS_LOG_OP_NOOP &&
		    a->update.undo_operation == NTFS_LOG_OP_DEALLOCATE_FILE_RECORD));
}

static enum ntfs_result
recovery_file_compile(struct ntfs_write_batch_recovery *owner, size_t ordinal,
    struct ntfs_batch_recovery_workspace *work)
{
	const struct ntfs_batch_recovery_packet *packet = &owner->packet[ordinal];
	const struct ntfs_logfile_update *update = &packet->update;
	struct ntfs_batch_recovery_home *home = &owner->home[packet->home];
	const uint8_t *payload = packet->bytes + packet->record.data.offset;
	const struct ntfs_disk_record *old, *image;
	struct ntfs_disk_record *header;
	uint64_t number;
	size_t offset, slot;
	uint16_t flags = packet->record.flags & ~NTFS_LOGFILE_RECORD_MULTI_PAGE;
	uint16_t expected_flags = update->undo_operation == NTFS_LOG_OP_INITIALIZE_FILE_RECORD
	    ? 0
	    : NTFS_LOGFILE_RECORD_ADDING;
	enum ntfs_result result;

	offset = (size_t)update->cluster_index * NTFS_MST_STRIDE;
	if (offset % NTFS_WRITE_RECORD_BYTES != 0 ||
	    !ntfs_bounds(offset, NTFS_WRITE_RECORD_BYTES, NTFS_WRITE_CLUSTER_BYTES)) {
		return NTFS_CORRUPT;
	}
	slot = offset / NTFS_WRITE_RECORD_BYTES;
	number = (home->logical + offset) / NTFS_WRITE_RECORD_BYTES;
	if (update->redo_operation == NTFS_LOG_OP_NOOP &&
	    update->undo_operation == NTFS_LOG_OP_DEALLOCATE_FILE_RECORD) {
		if (update->redo.length != 0 ||
		    update->undo.length != sizeof(struct ntfs_disk_mst) ||
		    flags != NTFS_LOGFILE_RECORD_DELETING ||
		    (home->new_slots & (1u << slot)) != 0 ||
		    (home->old_slots & (1u << slot)) != 0) {
			return NTFS_CORRUPT;
		}
		ntfs_zero(work->image, sizeof(struct ntfs_disk_mst));
		if (!ntfs_equal(
			payload + update->undo.offset, work->image, sizeof(struct ntfs_disk_mst))) {
			return NTFS_UNSUPPORTED;
		}
		home->new_slots |= (uint8_t)(1u << slot);
		/* Before-image validation sees no FILE object in this unowned slot.
		 * These private bytes are never a promised on-media inverse. */
		if (owner->committed) {
			ntfs_zero(home->before + offset, NTFS_WRITE_RECORD_BYTES);
		}
		return NTFS_OK;
	}
	if (update->redo_operation == NTFS_LOG_OP_DEALLOCATE_FILE_RECORD) {
		if (flags != NTFS_LOGFILE_RECORD_DELETING || !recovery_file_pair(owner, ordinal) ||
		    (home->old_slots & (1u << slot)) == 0) {
			return NTFS_CORRUPT;
		}
		return ntfs_write_retirement_apply(payload, packet->record.data.length, false,
		    packet->record.lsn, home->after + offset, NTFS_WRITE_RECORD_BYTES);
	}
	if (update->redo_operation != NTFS_LOG_OP_INITIALIZE_FILE_RECORD ||
	    update->redo.length != NTFS_WRITE_RECORD_BYTES || flags != expected_flags) {
		return NTFS_UNSUPPORTED;
	}
	result = recovery_logical_file(payload + update->redo.offset, number);
	if (result != NTFS_OK) {
		return result;
	}
	if (update->undo_operation == NTFS_LOG_OP_INITIALIZE_FILE_RECORD) {
		if (update->undo.length != NTFS_WRITE_RECORD_BYTES ||
		    !ntfs_equal(payload + update->redo.offset, payload + update->undo.offset,
			NTFS_WRITE_RECORD_BYTES) ||
		    (home->old_slots & (1u << slot)) != 0 ||
		    (home->new_slots & (1u << slot)) != 0) {
			return NTFS_CORRUPT;
		}
		home->old_slots |= (uint8_t)(1u << slot);
		result = ntfs_record_protect(payload + update->redo.offset, NTFS_WRITE_RECORD_BYTES,
		    work->image, sizeof(work->image));
		if (result != NTFS_OK) {
			return result;
		}
		ntfs_copy(home->before + offset, work->image, NTFS_WRITE_RECORD_BYTES);
	} else if (update->undo_operation != NTFS_LOG_OP_NOOP || update->undo.length != 0 ||
	    !recovery_file_pair(owner, ordinal)) {
		return NTFS_CORRUPT;
	} else if ((home->old_slots & (1u << slot)) != 0) {
		old = (const void *)(home->after + offset);
		image = (const void *)(payload + update->redo.offset);
		if (ntfs_u16(image->sequence) != ntfs_u16(old->sequence)) {
			return NTFS_STALE;
		}
	}
	ntfs_copy(home->after + offset, payload + update->redo.offset, NTFS_WRITE_RECORD_BYTES);
	header = (void *)(home->after + offset);
	ntfs_put_u64(header->lsn, packet->record.lsn);
	home->slots |= (uint8_t)(1u << slot);
	return NTFS_OK;
}

static enum ntfs_result
recovery_index_compile(struct ntfs_write_batch_recovery *owner,
    const struct ntfs_batch_recovery_packet *packet, struct ntfs_batch_recovery_workspace *work)
{
	const struct ntfs_logfile_update *update = &packet->update;
	struct ntfs_batch_recovery_home *home = &owner->home[packet->home];
	const uint8_t *payload = packet->bytes + packet->record.data.offset;
	struct ntfs_disk_index_block *header;
	uint16_t flags = packet->record.flags & ~NTFS_LOGFILE_RECORD_MULTI_PAGE;
	enum ntfs_result result;

	if (update->redo_operation != NTFS_LOG_OP_UPDATE_NONRESIDENT_VALUE ||
	    update->redo.length != NTFS_WRITE_CLUSTER_BYTES || update->cluster_index != 0 ||
	    (update->undo_operation != NTFS_LOG_OP_NOOP &&
		update->undo_operation != NTFS_LOG_OP_UPDATE_NONRESIDENT_VALUE) ||
	    update->undo.length !=
		(update->undo_operation == NTFS_LOG_OP_NOOP ? 0 : NTFS_WRITE_CLUSTER_BYTES) ||
	    flags != (update->undo.length == 0 ? NTFS_LOGFILE_RECORD_ADDING : 0)) {
		return NTFS_UNSUPPORTED;
	}
	if (home->slots != 0) {
		return NTFS_CORRUPT;
	}
	home->slots = 1;
	home->old_index = update->undo.length != 0;
	if (home->old_index) {
		result = ntfs_record_protect(payload + update->undo.offset,
		    NTFS_WRITE_CLUSTER_BYTES, home->before, sizeof(home->before));
		if (result != NTFS_OK) {
			return result;
		}
		ntfs_copy(work->image, home->before, sizeof(work->image));
		result = ntfs_fixup(work->image, sizeof(work->image), "INDX");
		if (result != NTFS_OK ||
		    ntfs_u64(((struct ntfs_disk_index_block *)(void *)work->image)->vcn) !=
			home->logical / NTFS_WRITE_CLUSTER_BYTES) {
			return NTFS_CORRUPT;
		}
	}
	ntfs_copy(home->after, payload + update->redo.offset, NTFS_WRITE_CLUSTER_BYTES);
	header = (void *)home->after;
	if (!ntfs_equal(header->mst.magic, "INDX", sizeof(header->mst.magic)) ||
	    ntfs_u64(header->vcn) != home->logical / NTFS_WRITE_CLUSTER_BYTES) {
		return NTFS_CORRUPT;
	}
	ntfs_put_u64(header->lsn, packet->record.lsn);
	return NTFS_OK;
}

static enum ntfs_result
recovery_bitmap_compile(struct ntfs_write_batch_recovery *owner, size_t ordinal)
{
	const struct ntfs_batch_recovery_packet *packet = &owner->packet[ordinal], *previous;
	struct ntfs_batch_recovery_home *home = &owner->home[packet->home];
	const uint8_t *payload = packet->bytes + packet->record.data.offset;
	const struct ntfs_disk_log_bitmap_range *range, *old;
	uint32_t first, count, old_first, old_count;
	size_t index;
	enum ntfs_result result;

	if ((packet->record.flags & ~NTFS_LOGFILE_RECORD_MULTI_PAGE) != 0) {
		return NTFS_CORRUPT;
	}
	result = ntfs_write_bitmap_apply(
	    payload, packet->record.data.length, false, home->after, sizeof(home->after));
	if (result != NTFS_OK) {
		return result;
	}
	range = (const void *)(payload + packet->update.redo.offset);
	first = ntfs_u32(range->first);
	count = ntfs_u32(range->bits);
	for (index = owner->first_update; index < ordinal; index++) {
		previous = &owner->packet[index];
		if (previous->home != packet->home) {
			continue;
		}
		old = (const void *)(previous->bytes + previous->record.data.offset +
		    previous->update.redo.offset);
		old_first = ntfs_u32(old->first);
		old_count = ntfs_u32(old->bits);
		if (first < old_first + old_count && old_first < first + count) {
			return NTFS_CORRUPT;
		}
	}
	return ntfs_write_bitmap_apply(
	    payload, packet->record.data.length, true, home->before, sizeof(home->before));
}

static bool
recovery_torn_file_known(
    const uint8_t *raw, const uint8_t *before, const uint8_t *after, uint64_t number)
{
	const struct ntfs_disk_record *header = (const void *)raw;
	const struct ntfs_disk_record *old = (const void *)before, *image = (const void *)after;
	const struct ntfs_disk_record_extension *extension = (const void *)(raw + sizeof(*header));
	uint64_t lsn = ntfs_u64(header->lsn);

	return ntfs_equal(header->mst.magic, "FILE", sizeof(header->mst.magic)) &&
	    ntfs_u16(header->mst.usa_offset) == ntfs_u16(image->mst.usa_offset) &&
	    ntfs_u16(header->mst.usa_count) == ntfs_u16(image->mst.usa_count) &&
	    ntfs_u32(header->allocated) == NTFS_WRITE_RECORD_BYTES &&
	    ntfs_u64(header->base_reference) == 0 && ntfs_u32(extension->record_number) == number &&
	    (ntfs_u16(header->sequence) == ntfs_u16(old->sequence) ||
		ntfs_u16(header->sequence) == ntfs_u16(image->sequence)) &&
	    (ntfs_u16(header->flags) == ntfs_u16(old->flags) ||
		ntfs_u16(header->flags) == ntfs_u16(image->flags)) &&
	    (ntfs_u32(header->used) == ntfs_u32(old->used) ||
		ntfs_u32(header->used) == ntfs_u32(image->used)) &&
	    (lsn == ntfs_u64(old->lsn) || lsn == ntfs_u64(image->lsn));
}

static enum ntfs_result
recovery_files_protect(struct ntfs_write_batch_recovery *owner,
    struct ntfs_batch_recovery_home *home, struct ntfs_batch_recovery_workspace *work)
{
	struct ntfs_disk_record *header;
	size_t slot, offset;
	bool old, complete, known;
	enum ntfs_result result;

	for (slot = 0; slot < NTFS_BATCH_RECOVERY_FILE_SLOTS; slot++) {
		if ((home->slots & (1u << slot)) == 0) {
			continue;
		}
		offset = slot * NTFS_WRITE_RECORD_BYTES;
		old = (home->old_slots & (1u << slot)) != 0;
		if ((home->historical_free_slots & (1u << slot)) != 0) {
			/* The later initializer discarded free bytes. This privately
			 * reconstructed free state has its own generation/bitmap proof;
			 * it is never a physical recovery publication. */
			result = ntfs_record_protect(home->after + offset, NTFS_WRITE_RECORD_BYTES,
			    work->image, sizeof(work->image));
			if (result != NTFS_OK) {
				return result;
			}
			ntfs_copy(home->after + offset, work->image, NTFS_WRITE_RECORD_BYTES);
			continue;
		}
		ntfs_copy(work->image, home->source + offset, NTFS_WRITE_RECORD_BYTES);
		result = ntfs_record_decode(work->image, NTFS_WRITE_RECORD_BYTES, false);
		complete = result == NTFS_OK;
		known = complete &&
		    ntfs_write_restored_record_equal(
			work->image, home->after + offset, NTFS_WRITE_RECORD_BYTES);
		if (owner->historical && owner->committed && !known) {
			return NTFS_STALE;
		}
		if (owner->committed && known) {
			ntfs_copy(
			    home->after + offset, home->source + offset, NTFS_WRITE_RECORD_BYTES);
			continue;
		}
		if (old) {
			ntfs_copy(work->before, home->before + offset, NTFS_WRITE_RECORD_BYTES);
			result = ntfs_fixup(work->before, NTFS_WRITE_RECORD_BYTES, "FILE");
			if (result != NTFS_OK) {
				return result;
			}
			known = complete &&
			    ntfs_write_restored_record_equal(
				work->image, work->before, NTFS_WRITE_RECORD_BYTES);
			if (!known &&
			    (!owner->committed || complete ||
				!recovery_torn_file_known(home->source + offset, work->before,
				    home->after + offset,
				    (home->logical + offset) / NTFS_WRITE_RECORD_BYTES))) {
				return NTFS_STALE;
			}
		}
		if (!owner->committed) {
			/* The complete-operation protocol publishes metadata only after
			 * durable Forget. A loser retains its exact original home bytes. */
			result = ntfs_record_protect(home->after + offset, NTFS_WRITE_RECORD_BYTES,
			    work->image, sizeof(work->image));
			if (result != NTFS_OK) {
				return result;
			}
			ntfs_copy(home->after + offset, work->image, NTFS_WRITE_RECORD_BYTES);
			continue;
		}
		header = (void *)(home->after + offset);
		if ((home->slots & (1u << slot)) != 0 &&
		    !ntfs_equal(header->mst.magic, "FILE", sizeof(header->mst.magic))) {
			return NTFS_CORRUPT;
		}
		result = ntfs_record_protect(home->after + offset, NTFS_WRITE_RECORD_BYTES,
		    work->image, sizeof(work->image));
		if (result == NTFS_OK) {
			result = ntfs_write_guard_frame(home->source + offset,
			    NTFS_WRITE_RECORD_BYTES, work->image, &work->guard);
		}
		if (result != NTFS_OK) {
			return result;
		}
		ntfs_copy(home->after + offset, work->image, NTFS_WRITE_RECORD_BYTES);
		owner->reconstructed_files++;
	}
	return NTFS_OK;
}

static enum ntfs_result
recovery_index_protect(struct ntfs_write_batch_recovery *owner,
    struct ntfs_batch_recovery_home *home, struct ntfs_batch_recovery_workspace *work)
{
	const struct ntfs_disk_index_block *header, *before, *after;
	bool complete, known;
	enum ntfs_result result;

	ntfs_copy(work->image, home->source, sizeof(work->image));
	result = ntfs_fixup(work->image, sizeof(work->image), "INDX");
	complete = result == NTFS_OK;
	known = complete &&
	    ntfs_write_restored_record_equal(work->image, home->after, NTFS_WRITE_CLUSTER_BYTES);
	if (owner->historical && owner->committed && !known) {
		return NTFS_STALE;
	}
	if (owner->committed && known) {
		ntfs_copy(home->after, home->source, sizeof(home->after));
		return NTFS_OK;
	}
	if (home->old_index) {
		ntfs_copy(work->before, home->before, sizeof(work->before));
		result = ntfs_fixup(work->before, sizeof(work->before), "INDX");
		if (result != NTFS_OK) {
			return result;
		}
		known = complete &&
		    ntfs_write_restored_record_equal(
			work->image, work->before, NTFS_WRITE_CLUSTER_BYTES);
		header = (const void *)home->source;
		before = (const void *)work->before;
		after = (const void *)home->after;
		if (!known &&
		    (!owner->committed || complete ||
			!ntfs_equal(header->mst.magic, "INDX", sizeof(header->mst.magic)) ||
			ntfs_u16(header->mst.usa_offset) != ntfs_u16(after->mst.usa_offset) ||
			ntfs_u16(header->mst.usa_count) != ntfs_u16(after->mst.usa_count) ||
			ntfs_u64(header->vcn) != ntfs_u64(after->vcn) ||
			(ntfs_u64(header->lsn) != ntfs_u64(before->lsn) &&
			    ntfs_u64(header->lsn) != ntfs_u64(after->lsn)))) {
			return NTFS_STALE;
		}
	}
	if (!owner->committed) {
		result = ntfs_record_protect(
		    home->after, sizeof(home->after), work->image, sizeof(work->image));
		if (result == NTFS_OK) {
			ntfs_copy(home->after, work->image, sizeof(home->after));
		}
		return result;
	}
	result =
	    ntfs_record_protect(home->after, sizeof(home->after), work->image, sizeof(work->image));
	if (result == NTFS_OK) {
		result = ntfs_write_guard_frame(
		    home->source, sizeof(home->source), work->image, &work->guard);
	}
	if (result == NTFS_OK) {
		ntfs_copy(home->after, work->image, sizeof(home->after));
	}
	return result;
}

static enum ntfs_result
recovery_mirror_prepare(
    struct ntfs_write_batch_recovery *owner, struct ntfs_batch_recovery_workspace *work)
{
	struct ntfs_batch_recovery_home *primary, *mirror;
	size_t index, slot, offset;
	enum ntfs_result result;

	for (index = 0; index < owner->homes; index++) {
		primary = &owner->home[index];
		if (primary->kind != NTFS_WRITE_MUTATION_FILE || primary->logical != 0) {
			continue;
		}
		if (primary->physical != owner->mft_lcn * NTFS_WRITE_CLUSTER_BYTES ||
		    owner->homes == owner->home_capacity) {
			return NTFS_CORRUPT;
		}
		mirror = &owner->home[owner->homes++];
		mirror->kind = NTFS_WRITE_MUTATION_FILE;
		mirror->physical = owner->mirror_lcn * NTFS_WRITE_CLUSTER_BYTES;
		mirror->target = primary->target;
		mirror->mirror = true;
		mirror->slots = primary->slots;
		mirror->old_slots = primary->old_slots;
		mirror->new_slots = primary->new_slots;
		result = ntfs_batch_recovery_read(
		    owner, mirror->physical, mirror->source, sizeof(mirror->source));
		if (result != NTFS_OK) {
			return result;
		}
		ntfs_copy(mirror->before, mirror->source, sizeof(mirror->source));
		ntfs_copy(mirror->after, mirror->source, sizeof(mirror->source));
		for (slot = 0; slot < NTFS_BATCH_RECOVERY_FILE_SLOTS; slot++) {
			if ((primary->slots & (1u << slot)) == 0) {
				continue;
			}
			offset = slot * NTFS_WRITE_RECORD_BYTES;
			ntfs_copy(mirror->before + offset, primary->before + offset,
			    NTFS_WRITE_RECORD_BYTES);
			ntfs_copy(mirror->after + offset, primary->after + offset,
			    NTFS_WRITE_RECORD_BYTES);
		}
		return recovery_files_protect(owner, mirror, work);
	}
	return NTFS_OK;
}

static enum ntfs_result
recovery_cluster_free(struct ntfs_volume *volume, uint64_t physical)
{
	struct ntfs_node *node = NULL;
	struct ntfs_stream *bitmap = NULL;
	uint64_t cluster = physical / NTFS_WRITE_CLUSTER_BYTES;
	uint8_t byte;
	enum ntfs_result result;

	result = ntfs_node_by_number(volume, NTFS_BITMAP_RECORD, &node);
	if (result != NTFS_OK) {
		goto done;
	}
	result = ntfs_stream_open(node, NULL, 0, &bitmap);
	if (result != NTFS_OK) {
		goto done;
	}
	result = ntfs_stream_exact(bitmap, cluster / NTFS_BITS_PER_BYTE, &byte, sizeof(byte));
	if (result == NTFS_OK && (byte & (1u << (cluster % NTFS_BITS_PER_BYTE))) != 0) {
		result = NTFS_STALE;
	}
done:
	ntfs_stream_close(bitmap);
	ntfs_node_close(node);
	return result;
}

static enum ntfs_result
recovery_target_mapping(struct ntfs_write_batch_recovery *owner, struct ntfs_volume *volume,
    struct ntfs_batch_recovery_home *home, bool after)
{
	const struct ntfs_write_mutation_target *identity = &owner->target[home->target].identity;
	struct ntfs_node *node = NULL;
	struct ntfs_stream *stream = NULL, *bits = NULL;
	uint64_t physical, number;
	uint8_t bitmap;
	size_t slot;
	bool old_slot;
	enum ntfs_result result;

	if (home->mirror) {
		return home->physical == owner->mirror_lcn * NTFS_WRITE_CLUSTER_BYTES ? NTFS_OK
										      : NTFS_STALE;
	}
	result = ntfs_node_open(volume, identity->reference, &node);
	if (result == NTFS_OK) {
		result = ntfs_attribute_open(
		    node, identity->attribute_type, identity->name, identity->name_count, &stream);
	}
	/* A new index stream need not exist in the original directory. Its raw
	 * storage must be free in the original allocation map, and its projected
	 * FILE mapping is checked separately in the after view. */
	if (!after && !home->old_index && home->kind == NTFS_WRITE_MUTATION_INDEX &&
	    result == NTFS_NOT_FOUND) {
		home->unowned_cluster = true;
		result = recovery_cluster_free(volume, home->physical);
		goto done;
	}
	if (result != NTFS_OK) {
		goto done;
	}
	if (!after && home->kind == NTFS_WRITE_MUTATION_FILE &&
	    home->logical >= stream->clusters * (uint64_t)NTFS_WRITE_CLUSTER_BYTES &&
	    home->old_slots == 0) {
		home->unowned_cluster = true;
		result = recovery_cluster_free(volume, home->physical);
		goto done;
	}
	if (!after && !home->old_index && home->kind == NTFS_WRITE_MUTATION_INDEX &&
	    home->logical / NTFS_WRITE_CLUSTER_BYTES >= stream->clusters) {
		home->unowned_cluster = true;
		result = recovery_cluster_free(volume, home->physical);
		goto done;
	}
	result = ntfs_batch_recovery_mapping(stream, home->logical, &physical);
	if (result != NTFS_OK || physical != home->physical) {
		if (result == NTFS_OK) {
			result = NTFS_STALE;
		}
		goto done;
	}
	if (home->kind == NTFS_WRITE_MUTATION_FILE &&
	    ((!after && (home->old_slots | home->new_slots) != 0) ||
		(after && home->historical_free_slots != 0))) {
		result = ntfs_attribute_open(node, NTFS_ATTR_BITMAP, NULL, 0, &bits);
		for (slot = 0; result == NTFS_OK && slot < NTFS_BATCH_RECOVERY_FILE_SLOTS; slot++) {
			if (((after ? home->historical_free_slots
				    : home->old_slots | home->new_slots) &
				(1u << slot)) == 0) {
				continue;
			}
			old_slot = !after && (home->old_slots & (1u << slot)) != 0;
			number = home->logical / NTFS_WRITE_RECORD_BYTES + slot;
			if (!ntfs_bounds(number * NTFS_WRITE_RECORD_BYTES, NTFS_WRITE_RECORD_BYTES,
				stream->initialized)) {
				if (old_slot || after) {
					result = NTFS_STALE;
				}
				continue;
			}
			result = ntfs_stream_exact(
			    bits, number / NTFS_BITS_PER_BYTE, &bitmap, sizeof(bitmap));
			if (result == NTFS_OK &&
			    ((bitmap & (1u << (number % NTFS_BITS_PER_BYTE))) != 0) != old_slot) {
				result = NTFS_STALE;
			}
		}
	}
	if (!after && result == NTFS_OK && home->kind == NTFS_WRITE_MUTATION_INDEX) {
		result = ntfs_attribute_open(
		    node, NTFS_ATTR_BITMAP, identity->name, identity->name_count, &bits);
		if (result != NTFS_OK) {
			goto done;
		}
		number = home->logical / NTFS_WRITE_CLUSTER_BYTES;
		result =
		    ntfs_stream_exact(bits, number / NTFS_BITS_PER_BYTE, &bitmap, sizeof(bitmap));
		if (result == NTFS_OK &&
		    ((bitmap & (1u << (number % NTFS_BITS_PER_BYTE))) != 0) != home->old_index) {
			result = NTFS_STALE;
		}
	}
done:
	ntfs_stream_close(bits);
	ntfs_stream_close(stream);
	ntfs_node_close(node);
	return result;
}

static enum ntfs_result
recovery_views_validate(
    struct ntfs_write_batch_recovery *owner, struct ntfs_batch_recovery_workspace *work)
{
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *node = NULL;
	struct ntfs_stream *log = NULL;
	const struct ntfs_run *run;
	struct ntfs_limits limits;
	size_t view, index, other, target;
	bool after;
	enum ntfs_result result = NTFS_OK;

	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	if (owner->historical && owner->updates == 0 && owner->homes != 0) {
		return NTFS_CORRUPT;
	}
	for (view = 0; view < 2; view++) {
		after = view != 0;
		owner->view = after ? NTFS_BATCH_RECOVERY_AFTER : NTFS_BATCH_RECOVERY_BEFORE;
		result = ntfs_mount(&owner->reader, &limits, &volume);
		if (result != NTFS_OK) {
			goto done;
		}
		if (!after) {
			if (owner->lifetimes <= 1) {
				result =
				    ntfs_batch_recovery_qualified_validate(owner, volume, work);
				if (result != NTFS_OK) {
					goto done;
				}
			}
			/* Even a prepared open whose first update is absent belongs to a
			 * current sequence-bearing FILE. This protocol opens existing
			 * metadata owners, never a not-yet-created FILE identity. */
			for (target = 0; target < owner->targets; target++) {
				result = ntfs_node_open(
				    volume, owner->target[target].identity.reference, &node);
				ntfs_node_close(node);
				node = NULL;
				if (result != NTFS_OK) {
					goto done;
				}
			}
		}
		result = ntfs_node_by_number(volume, NTFS_LOGFILE_RECORD, &node);
		if (result == NTFS_OK) {
			result = ntfs_stream_open(node, NULL, 0, &log);
		}
		if (result != NTFS_OK) {
			goto done;
		}
		for (index = 0; index < owner->homes; index++) {
			for (other = 0; other < log->run_count; other++) {
				run = &log->runs[other];
				if (run->lcn == NTFS_HOLE ||
				    (owner->home[index].physical / NTFS_WRITE_CLUSTER_BYTES >=
					    run->lcn &&
					owner->home[index].physical / NTFS_WRITE_CLUSTER_BYTES -
						run->lcn <
					    run->length)) {
					result = NTFS_CORRUPT;
					goto done;
				}
			}
			result = recovery_target_mapping(owner, volume, &owner->home[index], after);
			if (result != NTFS_OK) {
				goto done;
			}
		}
		if (after && owner->historical && owner->committed) {
			/* The later lifetime's before view already validated this complete
			 * state. Reuse that verdict only after exact after/source equality;
			 * proven retired FILE slots are excluded from the comparison only
			 * after their clear MFT bits and mappings passed above. */
			result = ntfs_batch_recovery_historical_after_admit(owner);
			if (result != NTFS_OK) {
				goto done;
			}
		}
		ntfs_stream_close(log);
		log = NULL;
		ntfs_node_close(node);
		node = NULL;
		result = ntfs_unmount(volume);
		volume = NULL;
		if (result != NTFS_OK) {
			goto done;
		}
		/* An earlier open-only prefix changes no home. Its before view is the
		 * already validated later state; all opened owners still bind above. */
		if ((!after && (!owner->historical || owner->updates != 0)) ||
		    (owner->committed && !owner->historical)) {
			result = ntfs_validate(&owner->reader, &limits, NULL, &work->validation);
			if (result == NTFS_OK && !work->validation.complete) {
				result = NTFS_CORRUPT;
			}
			if (result != NTFS_OK) {
				goto done;
			}
		}
	}
done:
	ntfs_stream_close(log);
	ntfs_node_close(node);
	if (volume != NULL) {
		ntfs_unmount(volume);
	}
	owner->view = NTFS_BATCH_RECOVERY_SOURCE;
	return result;
}

enum ntfs_result
ntfs_batch_recovery_restore(
    struct ntfs_write_batch_recovery *owner, struct ntfs_batch_recovery_workspace *work)
{
	struct ntfs_batch_recovery_packet *packet;
	struct ntfs_batch_recovery_home *home;
	enum ntfs_write_mutation_region_kind phase = NTFS_WRITE_MUTATION_FILE;
	size_t index;
	enum ntfs_result result;

	owner->home_capacity = owner->updates + 1;
	owner->home =
	    ntfs_batch_recovery_allocate(owner, owner->home_capacity * sizeof(*owner->home));
	if (owner->home == NULL) {
		return NTFS_NO_MEMORY;
	}
	for (index = owner->first_update; index < owner->first_update + owner->updates; index++) {
		packet = &owner->packet[index];
		result = recovery_home_bind(owner, packet);
		if (result != NTFS_OK) {
			return result;
		}
		home = &owner->home[packet->home];
		if (home->kind < phase) {
			return NTFS_CORRUPT;
		}
		phase = home->kind;
		if (home->kind == NTFS_WRITE_MUTATION_FILE) {
			result = recovery_file_compile(owner, index, work);
		} else if (home->kind == NTFS_WRITE_MUTATION_INDEX) {
			result = recovery_index_compile(owner, packet, work);
		} else {
			result = recovery_bitmap_compile(owner, index);
		}
		if (result != NTFS_OK) {
			return result;
		}
	}
	result = recovery_mirror_prepare(owner, work);
	if (result != NTFS_OK) {
		return result;
	}
	for (index = 0; index < owner->homes; index++) {
		home = &owner->home[index];
		if (home->mirror) {
			continue;
		}
		result = ntfs_batch_recovery_history_home_admit(owner, home);
		if (result != NTFS_OK) {
			return result;
		}
		if (home->kind == NTFS_WRITE_MUTATION_FILE) {
			result = recovery_files_protect(owner, home, work);
		} else if (home->kind == NTFS_WRITE_MUTATION_INDEX) {
			result = recovery_index_protect(owner, home, work);
		} else {
			result =
			    ((!owner->committed &&
				 !ntfs_equal(home->source, home->before, sizeof(home->source))) ||
				(owner->historical && owner->committed &&
				    !ntfs_equal(home->source, home->after, sizeof(home->source))))
			    ? NTFS_STALE
			    : NTFS_OK;
		}
		if (result != NTFS_OK) {
			return result;
		}
	}
	return recovery_views_validate(owner, work);
}
