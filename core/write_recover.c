/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_recover.h"
#include "write_overlay.h"
#include <ntfs/record.h>

enum { RECOVER_ORIGIN_PACKETS = 2 };

static bool
write_recovery_separate(
    const void *left_input, size_t a_bytes, const void *right_input, size_t b_bytes)
{
	uintptr_t left = (uintptr_t)left_input, right = (uintptr_t)right_input;

	return left_input != NULL && right_input != NULL && a_bytes <= UINTPTR_MAX - left &&
	    b_bytes <= UINTPTR_MAX - right && (left + a_bytes <= right || right + b_bytes <= left);
}

static bool
write_recovery_physical_separate(uint64_t left_offset, uint64_t right_offset)
{
	return left_offset <= UINT64_MAX - NTFS_WRITE_CLUSTER_BYTES &&
	    right_offset <= UINT64_MAX - NTFS_WRITE_CLUSTER_BYTES &&
	    (left_offset + NTFS_WRITE_CLUSTER_BYTES <= right_offset ||
		right_offset + NTFS_WRITE_CLUSTER_BYTES <= left_offset);
}

static enum ntfs_result
write_recovery_physical(struct ntfs_stream *log, uint64_t offset, uint64_t *out)
{
	const struct ntfs_run *run;
	uint64_t vcn, lcn;

	if (offset % NTFS_WRITE_CLUSTER_BYTES != 0 ||
	    !ntfs_bounds(offset, NTFS_WRITE_CLUSTER_BYTES, log->initialized)) {
		return NTFS_CORRUPT;
	}
	vcn = offset / NTFS_WRITE_CLUSTER_BYTES;
	run = ntfs_run_find(log, vcn);
	if (run == NULL || run->lcn == NTFS_HOLE || vcn < run->vcn ||
	    vcn - run->vcn >= run->length || run->lcn > UINT64_MAX - (vcn - run->vcn)) {
		return NTFS_CORRUPT;
	}
	lcn = run->lcn + vcn - run->vcn;
	if (lcn >= log->volume->info.cluster_count || lcn > UINT64_MAX / NTFS_WRITE_CLUSTER_BYTES) {
		return NTFS_CORRUPT;
	}
	*out = lcn * NTFS_WRITE_CLUSTER_BYTES;
	return NTFS_OK;
}

static enum ntfs_result
write_recovery_roots(struct ntfs_stream *log, struct ntfs_write_recovery_workspace *work)
{
	struct ntfs_logfile_restart parsed;
	struct ntfs_disk_log_restart_area *area;
	size_t index, bytes, selected = NTFS_LFS_RESTART_PAGES;
	enum ntfs_result result;

	for (index = 0; index < NTFS_LFS_RESTART_PAGES; index++) {
		result = write_recovery_physical(
		    log, index * NTFS_WRITE_CLUSTER_BYTES, &work->restart_physical[index]);
		if (result == NTFS_OK) {
			result = ntfs_stream_read(log, index * NTFS_WRITE_CLUSTER_BYTES,
			    work->restart[index], NTFS_WRITE_CLUSTER_BYTES, &bytes);
			if (result == NTFS_OK && bytes != NTFS_WRITE_CLUSTER_BYTES) {
				result = NTFS_IO;
			}
		}
		if (result != NTFS_OK) {
			return result;
		}
		result = ntfs_logfile_restart_decode(work->restart[index], NTFS_WRITE_CLUSTER_BYTES,
		    log->size, work->guard.restored, NTFS_WRITE_CLUSTER_BYTES, &parsed);
		if (result != NTFS_OK) {
			work->mutation = true;
			continue;
		}
		if (parsed.flags != NTFS_LOGFILE_RESTART_CLEAN) {
			work->mutation = true;
		}
		if (parsed.current_lsn == work->history.selected.current_lsn &&
		    parsed.flags == work->history.selected.flags &&
		    parsed.open_count == work->history.selected.open_count &&
		    parsed.last_data_bytes == work->history.selected.last_data_bytes) {
			selected = index;
		}
	}
	if (selected == NTFS_LFS_RESTART_PAGES) {
		return NTFS_STALE;
	}
	for (index = 0; index < NTFS_LFS_RESTART_PAGES; index++) {
		ntfs_copy(work->guard.restored, work->restart[selected], NTFS_WRITE_CLUSTER_BYTES);
		result = ntfs_fixup(work->guard.restored, NTFS_WRITE_CLUSTER_BYTES, "RSTR");
		if (result != NTFS_OK) {
			return result;
		}
		area = (void *)(work->guard.restored + work->history.selected.area.offset);
		ntfs_put_u16(area->flags, 0);
		result = ntfs_record_protect(work->guard.restored, NTFS_WRITE_CLUSTER_BYTES,
		    work->dirty[index], NTFS_WRITE_CLUSTER_BYTES);
		if (result == NTFS_OK) {
			result = ntfs_write_guard_frame(work->restart[index],
			    NTFS_WRITE_CLUSTER_BYTES, work->dirty[index], &work->guard);
		}
		if (result != NTFS_OK) {
			return result;
		}
		ntfs_copy(work->guard.restored, work->dirty[index], NTFS_WRITE_CLUSTER_BYTES);
		result = ntfs_fixup(work->guard.restored, NTFS_WRITE_CLUSTER_BYTES, "RSTR");
		if (result != NTFS_OK) {
			return result;
		}
		area = (void *)(work->guard.restored + work->history.selected.area.offset);
		ntfs_put_u16(area->flags, NTFS_LOGFILE_RESTART_CLEAN);
		result = ntfs_record_protect(work->guard.restored, NTFS_WRITE_CLUSTER_BYTES,
		    work->clean[index], NTFS_WRITE_CLUSTER_BYTES);
		if (result == NTFS_OK) {
			result = ntfs_write_guard_frame(work->dirty[index],
			    NTFS_WRITE_CLUSTER_BYTES, work->clean[index], &work->guard);
		}
		if (result != NTFS_OK) {
			return result;
		}
	}
	return NTFS_OK;
}

static enum ntfs_result
write_recovery_log_home(
    struct ntfs_stream *log, size_t first, size_t count, struct ntfs_write_recovery_workspace *work)
{
	struct ntfs_logfile_page_input input = {0};
	struct ntfs_logfile_record record;
	struct ntfs_logfile_page observed;
	struct ntfs_logfile_lsn position;
	uint8_t *output = work->log_home[work->logs];
	uint64_t page = 0, last = 0;
	size_t index, next = NTFS_WRITE_LOG_DATA_OFFSET;
	enum ntfs_result result;

	ntfs_zero(work->guard.page, NTFS_WRITE_CLUSTER_BYTES);
	for (index = 0; index < count; index++) {
		result = ntfs_logfile_record_decode(work->history.packet[first + index],
		    work->history.bytes[first + index], sizeof(struct ntfs_disk_log_record),
		    &record);
		if (result == NTFS_OK) {
			result =
			    ntfs_logfile_lsn_decode(&work->history.origin, record.lsn, &position);
		}
		if (result != NTFS_OK) {
			return result;
		}
		if (position.record_offset != next ||
		    (index != 0 && position.page_offset != page) ||
		    !ntfs_bounds(
			next, work->history.bytes[first + index], NTFS_WRITE_CLUSTER_BYTES)) {
			return NTFS_CORRUPT;
		}
		page = position.page_offset;
		last = record.lsn;
		ntfs_copy(work->guard.page + next, work->history.packet[first + index],
		    work->history.bytes[first + index]);
		next += (work->history.bytes[first + index] + NTFS_WIRE_ALIGNMENT - 1u) /
		    NTFS_WIRE_ALIGNMENT * NTFS_WIRE_ALIGNMENT;
	}
	input.bytes = NTFS_WRITE_CLUSTER_BYTES;
	input.major = NTFS_LFS_MAJOR_LEGACY;
	input.minor = NTFS_LFS_MINOR_LEGACY;
	input.data_offset = NTFS_WRITE_LOG_DATA_OFFSET;
	input.page.copy_value = last;
	input.page.last_end_lsn = last;
	input.page.flags = NTFS_LOGFILE_PAGE_RECORD_END;
	input.page.page_count = 1;
	input.page.page_position = 1;
	input.page.next_record_offset = (uint16_t)next;
	input.data = (struct ntfs_logfile_buffer){work->guard.page + NTFS_WRITE_LOG_DATA_OFFSET,
	    NTFS_WRITE_CLUSTER_BYTES - NTFS_WRITE_LOG_DATA_OFFSET};
	result = ntfs_logfile_page_encode(&input, work->guard.restored, NTFS_WRITE_CLUSTER_BYTES,
	    output, NTFS_WRITE_CLUSTER_BYTES);
	if (result == NTFS_OK) {
		result = write_recovery_physical(log, page, &work->log_physical[work->logs]);
	}
	if (result == NTFS_OK) {
		result = work->backend.reader.read(work->backend.reader.context,
		    work->log_physical[work->logs], work->scratch, NTFS_WRITE_CLUSTER_BYTES);
	}
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_logfile_page_decode(work->scratch, NTFS_WRITE_CLUSTER_BYTES,
	    &work->history.origin, work->guard.restored, NTFS_WRITE_CLUSTER_BYTES, &observed);
	if (result == NTFS_OK && observed.copy_value == last && observed.last_end_lsn == last &&
	    observed.next_record_offset == next && observed.flags == NTFS_LOGFILE_PAGE_RECORD_END &&
	    observed.page_count == 1 && observed.page_position == 1 &&
	    ntfs_equal(work->guard.restored + NTFS_WRITE_LOG_DATA_OFFSET,
		work->guard.page + NTFS_WRITE_LOG_DATA_OFFSET, next - NTFS_WRITE_LOG_DATA_OFFSET)) {
		work->logs++;
		return NTFS_OK;
	}
	result =
	    ntfs_write_guard_frame(work->scratch, NTFS_WRITE_CLUSTER_BYTES, output, &work->guard);
	if (result == NTFS_OK) {
		work->log_changed[work->logs++] = true;
		work->mutation = true;
	}
	return result;
}

static enum ntfs_result
write_recovery_journal(struct ntfs_stream *log, struct ntfs_write_recovery_workspace *work)
{
	struct ntfs_write_replay_plan *current;
	size_t index, first = RECOVER_ORIGIN_PACKETS, count;
	enum ntfs_result result;

	for (index = 0; index < work->history.transactions; index++) {
		current = &work->history.transaction[index];
		result = write_recovery_log_home(log, first, current->prepared_packets, work);
		if (result != NTFS_OK) {
			return result;
		}
		count = current->packets;
		if (current->committed || current->compensated) {
			result = write_recovery_log_home(log, first + current->prepared_packets,
			    count - current->prepared_packets, work);
			if (result != NTFS_OK) {
				return result;
			}
		}
		first += count;
	}
	if (first != work->history.count) {
		return NTFS_CORRUPT;
	}
	if (work->history.transactions == 0) {
		return NTFS_OK;
	}
	current = &work->history.transaction[work->history.transactions - 1];
	if (current->committed || current->compensated) {
		return NTFS_OK;
	}
	result = ntfs_write_abort_encode(&work->history.origin, work->history.client.sequence,
	    &work->history_work.replay.reservation, &current->file, &work->guard, &work->abort);
	if (result == NTFS_OK) {
		result = write_recovery_physical(log, work->abort.offset, &work->abort_physical);
	}
	if (result == NTFS_OK) {
		result = write_recovery_physical(log,
		    (NTFS_LFS_RESTART_PAGES + 1) * NTFS_WRITE_CLUSTER_BYTES, &work->copy_physical);
	}
	if (result != NTFS_OK) {
		return result;
	}
	ntfs_copy(work->abort_page, work->abort.page, NTFS_WRITE_CLUSTER_BYTES);
	ntfs_copy(work->abort_copy, work->abort.copy, NTFS_WRITE_CLUSTER_BYTES);
	result = work->backend.reader.read(work->backend.reader.context, work->abort_physical,
	    work->scratch, NTFS_WRITE_CLUSTER_BYTES);
	if (result == NTFS_OK) {
		result = ntfs_write_guard_frame(
		    work->scratch, NTFS_WRITE_CLUSTER_BYTES, work->abort_page, &work->guard);
	}
	if (result == NTFS_OK) {
		result = work->backend.reader.read(work->backend.reader.context,
		    work->copy_physical, work->scratch, NTFS_WRITE_CLUSTER_BYTES);
	}
	if (result == NTFS_OK) {
		result = ntfs_write_guard_frame(
		    work->scratch, NTFS_WRITE_CLUSTER_BYTES, work->abort_copy, &work->guard);
	}
	if (result != NTFS_OK) {
		return result;
	}
	ntfs_copy(&current->file, &work->abort.file, sizeof(current->file));
	work->close_transaction = true;
	work->mutation = true;
	return NTFS_OK;
}

static bool
write_recovery_same_file(
    const uint8_t *actual, const struct ntfs_write_file_plan *file, const uint8_t *expected)
{
	const struct ntfs_disk_record *header = (const void *)expected;
	size_t first = ntfs_u16(header->mst.usa_offset);
	size_t end = first + (size_t)ntfs_u16(header->mst.usa_count) * sizeof(uint16_t);
	size_t used = file->snapshot_bytes;

	return end <= used && used <= NTFS_WRITE_RECORD_BYTES &&
	    ntfs_equal(actual, expected, first) &&
	    ntfs_equal(actual + end, expected + end, used - end);
}

static bool
write_recovery_apply_home_redo(struct ntfs_write_recovery_workspace *work, size_t packet,
    uint16_t record_offset, uint16_t attribute_offset, uint16_t bytes, uint64_t lsn)
{
	struct ntfs_logfile_record record;
	struct ntfs_logfile_update update;
	const uint8_t *body;

	if (ntfs_logfile_record_decode(work->history.packet[packet], work->history.bytes[packet],
		sizeof(struct ntfs_disk_log_record), &record) != NTFS_OK) {
		return false;
	}
	body = work->history.packet[packet] + record.data.offset;
	if (ntfs_logfile_update_decode(body, record.data.length, &update) != NTFS_OK ||
	    update.redo.length != bytes ||
	    !ntfs_bounds(
		(size_t)record_offset + attribute_offset, bytes, NTFS_WRITE_RECORD_BYTES)) {
		return false;
	}
	ntfs_put_u64(((struct ntfs_disk_record *)(void *)work->guard.page)->lsn, lsn);
	ntfs_copy(
	    work->guard.page + record_offset + attribute_offset, body + update.redo.offset, bytes);
	return true;
}

static bool
write_recovery_known_file(const uint8_t *actual, const struct ntfs_write_file_plan *file,
    struct ntfs_write_recovery_workspace *work, bool torn)
{
	const struct ntfs_write_replay_plan *transaction;
	const struct ntfs_disk_record *header = (const void *)actual;
	const struct ntfs_disk_record *before;
	size_t index, first = RECOVER_ORIGIN_PACKETS;
	uint64_t lsn = ntfs_u64(header->lsn);

	for (index = 0; index < work->history.transactions; index++) {
		transaction = &work->history.transaction[index];
		if (transaction->file.reference == file->reference) {
			before = (const void *)transaction->file.before;
			if (torn) {
				if (ntfs_equal(header->mst.magic, before->mst.magic,
					sizeof(header->mst.magic)) &&
				    ntfs_u16(header->sequence) == ntfs_u16(before->sequence) &&
				    ntfs_u16(header->flags) == ntfs_u16(before->flags) &&
				    ntfs_u16(header->mst.usa_offset) ==
					ntfs_u16(before->mst.usa_offset) &&
				    ntfs_u16(header->mst.usa_count) ==
					ntfs_u16(before->mst.usa_count) &&
				    ntfs_u32(header->used) == transaction->file.snapshot_bytes &&
				    ntfs_u32(header->allocated) == NTFS_WRITE_RECORD_BYTES &&
				    ntfs_u64(header->base_reference) == 0 &&
				    (lsn == ntfs_u64(before->lsn) ||
					lsn == transaction->update_lsn ||
					(transaction->file.resident_bytes != 0 &&
					    lsn == transaction->resident_lsn) ||
					(transaction->compensated &&
					    lsn == transaction->compensation_lsn) ||
					(transaction->compensated &&
					    transaction->file.resident_bytes != 0 &&
					    lsn == transaction->resident_compensation_lsn) ||
					(work->close_transaction &&
					    work->abort.file.reference == file->reference &&
					    lsn == work->abort.compensation_lsn))) {
					return true;
				}
			} else if (write_recovery_same_file(
				       actual, &transaction->file, transaction->file.before) ||
			    write_recovery_same_file(
				actual, &transaction->file, transaction->file.after)) {
				return true;
			} else {
				/* Even a complete uncommitted redo home belongs to the log's
				 * full snapshot and exact change; it must be compensated. */
				ntfs_copy(work->guard.page, transaction->file.before,
				    NTFS_WRITE_RECORD_BYTES);
				if (!write_recovery_apply_home_redo(work,
					first + NTFS_WRITE_REPLAY_UPDATE,
					transaction->file.record_offset,
					transaction->file.attribute_offset,
					transaction->file.change_bytes, transaction->update_lsn)) {
					return false;
				}
				if (write_recovery_same_file(
					actual, &transaction->file, work->guard.page)) {
					return true;
				}
				if (transaction->file.resident_bytes != 0) {
					if (!write_recovery_apply_home_redo(work,
						first + NTFS_WRITE_REPLAY_COMMIT,
						transaction->file.resident_record_offset,
						transaction->file.resident_attribute_offset,
						transaction->file.resident_bytes,
						transaction->resident_lsn)) {
						return false;
					}
					if (write_recovery_same_file(
						actual, &transaction->file, work->guard.page)) {
						return true;
					}
					if (transaction->compensated) {
						if (!write_recovery_apply_home_redo(work,
							first + transaction->prepared_packets,
							transaction->file.resident_record_offset,
							transaction->file.resident_attribute_offset,
							transaction->file.resident_bytes,
							transaction->resident_compensation_lsn)) {
							return false;
						}
						if (write_recovery_same_file(actual,
							&transaction->file, work->guard.page)) {
							return true;
						}
					}
				}
			}
		}
		first += transaction->packets;
	}
	return false;
}

static enum ntfs_result
write_recovery_files(struct ntfs_write_recovery_workspace *work)
{
	const struct ntfs_write_file_plan *file;
	size_t index, later, cluster, offset;
	enum ntfs_result result;

	for (index = 0; index < work->history.transactions; index++) {
		file = &work->history.transaction[index].file;
		for (later = index + 1; later < work->history.transactions; later++) {
			if (file->reference == work->history.transaction[later].file.reference) {
				break;
			}
		}
		if (later != work->history.transactions) {
			continue;
		}
		work->files++;
		for (cluster = 0; cluster < work->homes; cluster++) {
			if (work->home_physical[cluster] == file->cluster_physical) {
				break;
			}
		}
		if (cluster == work->homes) {
			work->home_physical[cluster] = file->cluster_physical;
			result = work->backend.reader.read(work->backend.reader.context,
			    file->cluster_physical, work->home[cluster], NTFS_WRITE_CLUSTER_BYTES);
			if (result != NTFS_OK) {
				return result;
			}
			work->homes++;
		}
		offset = (size_t)file->cluster_index * NTFS_WRITE_SECTOR_BYTES;
		ntfs_copy(work->scratch, work->home[cluster] + offset, NTFS_WRITE_RECORD_BYTES);
		ntfs_copy(work->guard.restored, work->scratch, NTFS_WRITE_RECORD_BYTES);
		result = ntfs_fixup(work->guard.restored, NTFS_WRITE_RECORD_BYTES, "FILE");
		if (result == NTFS_OK &&
		    write_recovery_same_file(work->guard.restored, file, file->after)) {
			continue;
		}
		if (!write_recovery_known_file(
			result == NTFS_OK ? work->guard.restored : work->scratch, file, work,
			result != NTFS_OK)) {
			return NTFS_STALE;
		}
		ntfs_copy(
		    work->home[cluster] + offset, file->protected_after, NTFS_WRITE_RECORD_BYTES);
		result = ntfs_write_guard_frame(work->scratch, NTFS_WRITE_RECORD_BYTES,
		    work->home[cluster] + offset, &work->guard);
		if (result != NTFS_OK) {
			return result;
		}
		work->home_changed[cluster] = true;
		work->mutation = true;
	}
	return NTFS_OK;
}

static enum ntfs_result
write_recovery_prepare(struct ntfs_volume *volume, struct ntfs_write_recovery_workspace *work)
{
	struct ntfs_node *node = NULL;
	struct ntfs_stream *log = NULL;
	size_t index, other;
	enum ntfs_result result;

	result = ntfs_write_history_capture(volume, &work->history_work, &work->history);
	if (result != NTFS_OK) {
		return result;
	}
	if (work->history.checkpoint_observed) {
		return NTFS_UNSUPPORTED;
	}
	result = ntfs_node_by_number(volume, NTFS_LOGFILE_RECORD, &node);
	if (result == NTFS_OK) {
		result = ntfs_stream_open(node, NULL, 0, &log);
	}
	if (result != NTFS_OK) {
		goto done;
	}
	if (log->resident || log->metadata_only || log->flags != 0 || log->compression_unit != 0 ||
	    log->initialized != log->size) {
		result = NTFS_UNSUPPORTED;
		goto done;
	}
	result = write_recovery_roots(log, work);
	if (result == NTFS_OK) {
		result = write_recovery_journal(log, work);
	}
	if (result == NTFS_OK) {
		result = write_recovery_files(work);
	}
	if (result != NTFS_OK) {
		goto done;
	}
	/* Full allocation/namespace validation below remains mandatory. These
	 * explicit physical disjointness checks also bind the prepared I/O set. */
	for (index = 0; index < work->homes; index++) {
		for (other = 0; other < work->logs; other++) {
			if (!write_recovery_physical_separate(
				work->home_physical[index], work->log_physical[other])) {
				result = NTFS_CORRUPT;
				goto done;
			}
		}
		for (other = 0; other < NTFS_LFS_RESTART_PAGES; other++) {
			if (!write_recovery_physical_separate(
				work->home_physical[index], work->restart_physical[other])) {
				result = NTFS_CORRUPT;
				goto done;
			}
		}
		if (work->close_transaction &&
		    (!write_recovery_physical_separate(
			 work->home_physical[index], work->abort_physical) ||
			!write_recovery_physical_separate(
			    work->home_physical[index], work->copy_physical))) {
			result = NTFS_CORRUPT;
			goto done;
		}
	}
	if (work->history.transactions != 0) {
		result = ntfs_write_validate_overlays(&work->backend.reader,
		    work->history.transaction, work->history.transactions, &work->validation);
	} else {
		result = ntfs_validate(&work->backend.reader, NULL, NULL, &work->validation);
	}
	if (result == NTFS_OK) {
		work->prepared = true;
	}

done:
	ntfs_stream_close(log);
	ntfs_node_close(node);
	return result;
}

enum ntfs_result
ntfs_write_recover_prepare(struct ntfs_volume *volume,
    const struct ntfs_overwrite_environment *backend, struct ntfs_write_recovery_workspace *work)
{
	uint32_t alignment;
	enum ntfs_result result;

	if (volume == NULL || backend == NULL || work == NULL ||
	    !write_recovery_separate(volume, sizeof(*volume), work, sizeof(*work)) ||
	    !write_recovery_separate(backend, sizeof(*backend), work, sizeof(*work))) {
		return NTFS_INVALID;
	}
	alignment = backend->alignment;
	if (backend->api_version != NTFS_OVERWRITE_API_VERSION ||
	    backend->reader.api_version != NTFS_API_VERSION || backend->reader.read == NULL ||
	    backend->reader.allocate == NULL || backend->reader.release == NULL ||
	    backend->write == NULL || backend->persist == NULL ||
	    alignment < NTFS_WRITE_SECTOR_BYTES || alignment > NTFS_WRITE_CLUSTER_BYTES ||
	    (alignment & (alignment - 1u)) != 0 || (uintptr_t)work % alignment != 0 ||
	    volume->info.sector_size != NTFS_WRITE_SECTOR_BYTES ||
	    volume->info.cluster_size != NTFS_WRITE_CLUSTER_BYTES ||
	    volume->info.record_size != NTFS_WRITE_RECORD_BYTES) {
		return NTFS_INVALID;
	}
	ntfs_zero(work, sizeof(*work));
	work->backend = *backend;
	result = ntfs_operation_enter(volume);
	if (result == NTFS_OK) {
		result = write_recovery_prepare(volume, work);
		ntfs_operation_leave(volume);
	}
	if (result != NTFS_OK) {
		ntfs_zero(work, sizeof(*work));
	}
	return result;
}

static enum ntfs_result
write_recovery_publish(struct ntfs_write_recovery_workspace *work, uint64_t physical,
    const void *bytes, enum ntfs_write_recovery_stage stage, bool *poisoned,
    struct ntfs_write_recovery_report *report)
{
	size_t transferred = 0;
	enum ntfs_result result;

	report->writes++;
	result = work->backend.write(
	    work->backend.reader.context, physical, bytes, NTFS_WRITE_CLUSTER_BYTES, &transferred);
	if (transferred <= NTFS_WRITE_CLUSTER_BYTES) {
		report->physical_bytes += transferred;
	}
	if (result != NTFS_OK || transferred != NTFS_WRITE_CLUSTER_BYTES) {
		*poisoned = true;
		return NTFS_IO;
	}
	report->barriers++;
	result = work->backend.persist(work->backend.reader.context);
	if (result != NTFS_OK) {
		*poisoned = true;
		return NTFS_IO;
	}
	report->durable_stage = stage;
	return NTFS_OK;
}

enum ntfs_result
ntfs_write_recover_execute(struct ntfs_write_recovery_workspace *work, bool *poisoned,
    struct ntfs_write_recovery_report *report)
{
	size_t index;
	enum ntfs_result result = NTFS_OK;

	if (work == NULL || poisoned == NULL || report == NULL ||
	    !write_recovery_separate(work, sizeof(*work), poisoned, sizeof(*poisoned)) ||
	    !write_recovery_separate(work, sizeof(*work), report, sizeof(*report)) ||
	    !write_recovery_separate(poisoned, sizeof(*poisoned), report, sizeof(*report))) {
		return NTFS_INVALID;
	}
	ntfs_zero(report, sizeof(*report));
	if (*poisoned) {
		report->poisoned = true;
		return NTFS_IO;
	}
	if (!work->prepared) {
		return NTFS_INVALID;
	}
	work->prepared = false;
	report->reconstructed_files = work->files;
	if (!work->mutation) {
		report->barriers++;
		result = work->backend.persist(work->backend.reader.context);
		if (result != NTFS_OK) {
			*poisoned = true;
			result = NTFS_IO;
		} else {
			report->homes_persisted = true;
			report->completed = true;
		}
		goto done;
	}
	for (index = 0; index < NTFS_LFS_RESTART_PAGES; index++) {
		result = write_recovery_publish(work, work->restart_physical[index],
		    work->dirty[index],
		    index == 0 ? NTFS_WRITE_RECOVERY_DIRTY_FIRST : NTFS_WRITE_RECOVERY_DIRTY_SECOND,
		    poisoned, report);
		if (result != NTFS_OK) {
			goto done;
		}
	}
	/* Complete authoritative copy-routed A/B homes before recycling a tail
	 * slot or allowing a later append to remove their only durable witness. */
	for (index = 0; index < work->logs; index++) {
		if (work->log_changed[index]) {
			result = write_recovery_publish(work, work->log_physical[index],
			    work->log_home[index], NTFS_WRITE_RECOVERY_LOG_HOMES, poisoned, report);
			if (result != NTFS_OK) {
				goto done;
			}
		}
	}
	if (work->close_transaction) {
		result = write_recovery_publish(work, work->copy_physical, work->abort_copy,
		    NTFS_WRITE_RECOVERY_ABORT_COPY, poisoned, report);
		if (result != NTFS_OK) {
			goto done;
		}
		report->compensation_persisted = true;
		result = write_recovery_publish(work, work->abort_physical, work->abort_page,
		    NTFS_WRITE_RECOVERY_ABORT_HOME, poisoned, report);
		if (result != NTFS_OK) {
			goto done;
		}
	}
	for (index = 0; index < work->homes; index++) {
		if (work->home_changed[index]) {
			result = write_recovery_publish(work, work->home_physical[index],
			    work->home[index], NTFS_WRITE_RECOVERY_FILE_HOMES, poisoned, report);
			if (result != NTFS_OK) {
				goto done;
			}
		}
	}
	report->homes_persisted = true;
	for (index = 0; index < NTFS_LFS_RESTART_PAGES; index++) {
		result = write_recovery_publish(work, work->restart_physical[index],
		    work->clean[index],
		    index == 0 ? NTFS_WRITE_RECOVERY_CLEAN_FIRST : NTFS_WRITE_RECOVERY_CLEAN_SECOND,
		    poisoned, report);
		if (result != NTFS_OK) {
			goto done;
		}
	}
	report->completed = true;

done:
	report->poisoned = *poisoned;
	return result;
}
