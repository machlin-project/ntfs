/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "pointer_range.h"
#include "write_owner.h"
#include "write_recover.h"
#include "write_transaction.h"
#include "write_overlay.h"
#include "logfile_tables_disk.h"
#include <ntfs/overwrite.h>

enum {
	OVERWRITE_INDEX_BYTES = 1024 * 1024,
	OVERWRITE_MAX_SPANS = NTFS_OVERWRITE_MAX_BYTES / NTFS_MST_STRIDE + 2,
	OVERWRITE_QUIET_RECORDS = 2,
	OVERWRITE_BOOTSTRAP_RECORD = 0,
	OVERWRITE_RESTART_RECORD = 1,
	OVERWRITE_PATH_SEPARATOR = '/'
};

struct ntfs_overwrite {
	struct ntfs_overwrite_environment backend;
	struct ntfs_environment reader;
	struct ntfs_info info;
	size_t live_bytes;
	uint64_t read_calls, read_bytes;
	bool claimed, poisoned;
};

struct overwrite_span {
	uint64_t physical, logical;
	uint32_t offset, bytes;
};

struct overwrite_journal_workspace {
	struct ntfs_logfile_restart restart;
	struct ntfs_logfile_client client;
	struct ntfs_logfile_report discovery;
	struct ntfs_logfile_page_index_report index;
	struct ntfs_logfile_checkpoint_capture capture;
	struct ntfs_recovery_record record;
};

static enum ntfs_result reject_change_journal(struct ntfs_volume *);
static enum ntfs_result transaction_write(void *, uint64_t, const void *, size_t, size_t *);
static enum ntfs_result transaction_persist(void *);

static void *
overwrite_allocate(void *context, size_t bytes)
{
	struct ntfs_overwrite *owner = context;
	void *buffer;

	if (bytes > NTFS_DEFAULT_MAX_LIVE_BYTES - owner->live_bytes) {
		return NULL;
	}
	buffer = owner->backend.reader.allocate(owner->backend.reader.context, bytes);
	if (buffer != NULL) {
		owner->live_bytes += bytes;
	}
	return buffer;
}

static void
overwrite_release(void *context, void *buffer, size_t bytes)
{
	struct ntfs_overwrite *owner = context;

	owner->backend.reader.release(owner->backend.reader.context, buffer, bytes);
	owner->live_bytes -= bytes;
}

static enum ntfs_result
overwrite_read(void *context, uint64_t offset, void *buffer, size_t bytes)
{
	struct ntfs_overwrite *owner = context;

	if (owner->poisoned) {
		return NTFS_IO;
	}
	if (!ntfs_bounds(offset, bytes, owner->reader.size_bytes)) {
		return NTFS_RANGE;
	}
	if (owner->read_calls == NTFS_DEFAULT_OPERATION_READ_CALLS ||
	    bytes > NTFS_DEFAULT_OPERATION_READ_BYTES - owner->read_bytes) {
		return NTFS_RANGE;
	}
	owner->read_calls++;
	owner->read_bytes += bytes;
	return owner->backend.reader.read(owner->backend.reader.context, offset, buffer, bytes);
}

static enum ntfs_result
quiet_journal(struct ntfs_overwrite *owner, struct ntfs_volume *volume,
    struct ntfs_overwrite_admission *admission)
{
	struct overwrite_journal_workspace *work;
	struct ntfs_logfile *source = NULL;
	struct ntfs_recovery *recovery = NULL;
	struct ntfs_logfile_limits limits;
	struct ntfs_logfile_update update;
	const void *packet, *checkpoint;
	uint64_t first_lsn;
	enum ntfs_result result;

	work = overwrite_allocate(owner, sizeof(*work));
	if (work == NULL) {
		return NTFS_NO_MEMORY;
	}
	ntfs_zero(work, sizeof(*work));
	ntfs_logfile_default_limits(&limits);
	limits.max_read_calls = NTFS_RECOVERY_DEFAULT_READ_CALLS;
	limits.max_read_bytes = NTFS_RECOVERY_DEFAULT_READ_BYTES;
	result = ntfs_logfile_open_volume(volume, &limits, &work->discovery, &source);
	if (result != NTFS_OK) {
		goto done;
	}
	result = ntfs_logfile_get_restart(source, &work->restart);
	if (result != NTFS_OK) {
		goto done;
	}
	if (!work->restart.clean_hint || work->restart.flags != NTFS_LOGFILE_RESTART_CLEAN ||
	    work->restart.client_count != 1 || work->restart.in_use_head != 0 ||
	    work->restart.free_head != NTFS_LOGFILE_NO_CLIENT ||
	    work->restart.major != NTFS_LFS_MAJOR_LEGACY ||
	    work->restart.minor != NTFS_LFS_MINOR_LEGACY ||
	    work->restart.system_page_bytes != NTFS_LFS_FAST_PAGE_BYTES ||
	    work->restart.log_page_bytes != NTFS_LFS_FAST_PAGE_BYTES ||
	    work->restart.page_data_offset != sizeof(struct ntfs_disk_log_fast_page) ||
	    work->restart.record_header_bytes != sizeof(struct ntfs_disk_log_record)) {
		result = NTFS_UNSUPPORTED;
		goto done;
	}
	result = ntfs_logfile_get_client(source, 0, &work->client);
	if (result != NTFS_OK) {
		goto done;
	}
	result = ntfs_logfile_prepare_page_index(source, OVERWRITE_INDEX_BYTES, &work->index);
	if (result != NTFS_OK) {
		goto done;
	}
	result = ntfs_recovery_open(
	    source, 0, work->client.sequence, NULL, &admission->recovery, &recovery);
	if (result != NTFS_OK) {
		goto done;
	}
	result = ntfs_recovery_get_checkpoint(recovery, &work->capture, &checkpoint);
	if (result != NTFS_OK) {
		goto done;
	}
	if (admission->recovery.records != OVERWRITE_QUIET_RECORDS ||
	    admission->recovery.history.tail_lsn != 0 || work->capture.snapshot.present_mask != 0 ||
	    work->capture.restart.major != NTFS_LOG_CLIENT_MAJOR_ATTRIBUTES ||
	    work->capture.restart.minor != NTFS_LOG_CLIENT_MINOR ||
	    work->capture.client.restart_lsn != work->restart.current_lsn ||
	    admission->recovery.history.completed_end_lsn != work->restart.current_lsn) {
		result = NTFS_UNSUPPORTED;
		goto done;
	}
	result =
	    ntfs_recovery_get_record(recovery, OVERWRITE_BOOTSTRAP_RECORD, &work->record, &packet);
	if (result != NTFS_OK) {
		goto done;
	}
	if (work->record.record.type != NTFS_LOGFILE_RECORD_UPDATE ||
	    work->record.record.previous_lsn != 0 || work->record.record.undo_next_lsn != 0 ||
	    work->record.record.flags != 0 || work->record.record.transaction == 0 ||
	    work->record.record.lsn != work->capture.client.oldest_lsn ||
	    work->record.record.lsn != work->capture.restart.analysis_lsn) {
		result = NTFS_UNSUPPORTED;
		goto done;
	}
	first_lsn = work->record.record.lsn;
	result =
	    ntfs_logfile_update_decode((const uint8_t *)packet + work->record.record.data.offset,
		work->record.record.data.length, &update);
	if (result != NTFS_OK) {
		goto done;
	}
	if (update.redo_operation != NTFS_LOG_OP_NOOP ||
	    update.undo_operation != NTFS_LOG_OP_NOOP || update.redo.length != 0 ||
	    update.undo.length != 0 || update.lcn_count != 0 || update.target_attribute != 0 ||
	    update.record_offset != 0 || update.attribute_offset != 0 ||
	    update.cluster_index != 0 || update.attribute_flags != 0 || update.target_vcn != 0) {
		result = NTFS_UNSUPPORTED;
		goto done;
	}
	result =
	    ntfs_recovery_get_record(recovery, OVERWRITE_RESTART_RECORD, &work->record, &packet);
	if (result != NTFS_OK) {
		goto done;
	}
	if (work->record.record.type != NTFS_LOGFILE_RECORD_RESTART ||
	    work->record.record.transaction != 0 || work->record.record.previous_lsn != 0 ||
	    work->record.record.undo_next_lsn != 0 || work->record.record.flags != 0 ||
	    work->record.record.lsn != work->capture.client.restart_lsn ||
	    first_lsn >= work->record.record.lsn) {
		result = NTFS_UNSUPPORTED;
		goto done;
	}
	admission->quiescent = true;

done:
	ntfs_recovery_close(recovery);
	ntfs_logfile_close(source);
	overwrite_release(owner, work, sizeof(*work));
	return result;
}

static enum ntfs_result
reject_hibernation(struct ntfs_volume *volume)
{
	static const uint16_t name[] = {'h', 'i', 'b', 'e', 'r', 'f', 'i', 'l', '.', 's', 'y', 's'};
	struct ntfs_node *root = NULL, *hibernation = NULL;
	enum ntfs_result result;

	result = ntfs_root(volume, &root);
	if (result == NTFS_OK) {
		result = ntfs_lookup(root, name, sizeof(name) / sizeof(*name), &hibernation);
		if (result == NTFS_OK) {
			result = NTFS_UNSUPPORTED;
		} else if (result == NTFS_NOT_FOUND) {
			result = NTFS_OK;
		}
	}
	ntfs_node_close(hibernation);
	ntfs_node_close(root);
	return result;
}

static enum ntfs_result
open_owner(const struct ntfs_overwrite_environment *environment,
    struct ntfs_overwrite_admission *admission, struct ntfs_overwrite **out,
    struct ntfs_write_recovery_report *recovery)
{
	struct ntfs_overwrite *owner;
	struct ntfs_volume *volume = NULL;
	struct ntfs_write_recovery_workspace *work = NULL;
	struct ntfs_overwrite_environment backend;
	void *allocation = NULL;
	size_t allocation_bytes;
	uintptr_t aligned;
	struct ntfs_limits limits;
	enum ntfs_result result, closed;

	if (environment == NULL || admission == NULL || out == NULL ||
	    !ntfs_pointer_ranges_separate(
		environment, sizeof(*environment), admission, sizeof(*admission)) ||
	    !ntfs_pointer_ranges_separate(environment, sizeof(*environment), out, sizeof(*out)) ||
	    !ntfs_pointer_ranges_separate(admission, sizeof(*admission), out, sizeof(*out))) {
		return NTFS_INVALID;
	}
	*out = NULL;
	ntfs_zero(admission, sizeof(*admission));
	if (environment->api_version != NTFS_OVERWRITE_API_VERSION ||
	    environment->reader.api_version != NTFS_API_VERSION ||
	    environment->reader.allocate == NULL || environment->reader.release == NULL ||
	    environment->reader.read == NULL || environment->claim == NULL ||
	    environment->unclaim == NULL || environment->write == NULL ||
	    environment->persist == NULL || environment->alignment < NTFS_MST_STRIDE ||
	    environment->alignment > NTFS_OVERWRITE_MAX_ALIGNMENT ||
	    (environment->alignment & (environment->alignment - 1u)) != 0) {
		return NTFS_INVALID;
	}
	allocation_bytes = sizeof(*work) + environment->alignment - 1u;
	owner = environment->reader.allocate(environment->reader.context, sizeof(*owner));
	if (owner == NULL) {
		return NTFS_NO_MEMORY;
	}
	ntfs_zero(owner, sizeof(*owner));
	owner->backend = *environment;
	owner->live_bytes = sizeof(*owner);
	owner->reader = (struct ntfs_environment){NTFS_API_VERSION, owner,
	    environment->reader.size_bytes, overwrite_read, overwrite_allocate, overwrite_release};
	result = environment->claim(environment->reader.context);
	if (result != NTFS_OK) {
		goto done;
	}
	owner->claimed = true;
	admission->claimed = true;
	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	if (recovery == NULL) {
		result = ntfs_validate(&owner->reader, &limits, NULL, &admission->validation);
		if (result != NTFS_OK) {
			goto done;
		}
	}
	result = ntfs_mount(&owner->reader, &limits, &volume);
	if (result != NTFS_OK) {
		goto done;
	}
	ntfs_get_info(volume, &owner->info);
	admission->info = owner->info;
	if (owner->info.cluster_size < environment->alignment ||
	    environment->alignment % owner->info.sector_size != 0) {
		result = NTFS_UNSUPPORTED;
		goto done;
	}
	result = reject_hibernation(volume);
	if (result == NTFS_OK && recovery == NULL) {
		result = quiet_journal(owner, volume, admission);
	} else if (result == NTFS_OK) {
		result = reject_change_journal(volume);
		if (result != NTFS_OK) {
			goto done;
		}
		allocation = overwrite_allocate(owner, allocation_bytes);
		if (allocation == NULL) {
			result = NTFS_NO_MEMORY;
			goto done;
		}
		aligned = ((uintptr_t)allocation + environment->alignment - 1u) &
		    ~(uintptr_t)(environment->alignment - 1u);
		work = (void *)aligned;
		backend = owner->backend;
		backend.reader = owner->reader;
		backend.write = transaction_write;
		backend.persist = transaction_persist;
		result = ntfs_write_recover_prepare(volume, &backend, work);
		if (result == NTFS_OK) {
			admission->validation = work->validation;
		}
	}

done:
	if (volume != NULL) {
		closed = ntfs_unmount(volume);
		if (closed != NTFS_OK) {
			result = closed;
		}
	}
	if (result == NTFS_OK && recovery != NULL) {
		result = ntfs_write_recover_execute(work, &owner->poisoned, recovery);
		admission->quiescent = result == NTFS_OK && recovery->homes_persisted;
		admission->persistence_succeeded = result == NTFS_OK && recovery->completed;
	} else if (result == NTFS_OK) {
		result = environment->persist(environment->reader.context);
		admission->persistence_succeeded = result == NTFS_OK;
	}
	if (allocation != NULL) {
		overwrite_release(owner, allocation, allocation_bytes);
	}
	if (result != NTFS_OK) {
		ntfs_overwrite_close(owner);
		return result;
	}
	*out = owner;
	return NTFS_OK;
}

enum ntfs_result
ntfs_overwrite_open(const struct ntfs_overwrite_environment *environment,
    struct ntfs_overwrite_admission *admission, struct ntfs_overwrite **out)
{
	return open_owner(environment, admission, out, NULL);
}

enum ntfs_result
ntfs_write_owner_open(const struct ntfs_overwrite_environment *environment,
    struct ntfs_overwrite_admission *admission, struct ntfs_write_recovery_report *recovery,
    struct ntfs_overwrite **out)
{
	if (environment == NULL || admission == NULL || recovery == NULL || out == NULL ||
	    !ntfs_pointer_ranges_separate(
		environment, sizeof(*environment), admission, sizeof(*admission)) ||
	    !ntfs_pointer_ranges_separate(environment, sizeof(*environment), out, sizeof(*out)) ||
	    !ntfs_pointer_ranges_separate(admission, sizeof(*admission), out, sizeof(*out)) ||
	    !ntfs_pointer_ranges_separate(
		environment, sizeof(*environment), recovery, sizeof(*recovery)) ||
	    !ntfs_pointer_ranges_separate(
		admission, sizeof(*admission), recovery, sizeof(*recovery)) ||
	    !ntfs_pointer_ranges_separate(out, sizeof(*out), recovery, sizeof(*recovery))) {
		return NTFS_INVALID;
	}
	ntfs_zero(recovery, sizeof(*recovery));
	return open_owner(environment, admission, out, recovery);
}

void
ntfs_overwrite_close(struct ntfs_overwrite *owner)
{
	struct ntfs_overwrite_environment backend;

	if (owner == NULL) {
		return;
	}
	backend = owner->backend;
	if (owner->claimed) {
		backend.unclaim(backend.reader.context);
	}
	backend.reader.release(backend.reader.context, owner, sizeof(*owner));
}

enum ntfs_result
ntfs_overwrite_resolve(
    struct ntfs_overwrite *owner, const uint16_t *path, size_t units, uint64_t *reference)
{
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *node = NULL, *child = NULL;
	struct ntfs_stat stat;
	size_t position = 0, start;
	enum ntfs_result result, closed;

	if (owner == NULL || reference == NULL || path == NULL || units == 0 ||
	    units > NTFS_OVERWRITE_MAX_PATH_UNITS ||
	    !ntfs_pointer_ranges_separate(
		path, units * sizeof(*path), reference, sizeof(*reference)) ||
	    !ntfs_pointer_ranges_separate(owner, sizeof(*owner), reference, sizeof(*reference)) ||
	    !ntfs_pointer_ranges_separate(path, units * sizeof(*path), owner, sizeof(*owner))) {
		return NTFS_INVALID;
	}
	*reference = 0;
	if (path[0] != OVERWRITE_PATH_SEPARATOR) {
		return NTFS_INVALID;
	}
	if (owner->poisoned) {
		return NTFS_IO;
	}
	owner->read_calls = 0;
	owner->read_bytes = 0;
	result = ntfs_mount(&owner->reader, NULL, &volume);
	if (result == NTFS_OK) {
		result = ntfs_root(volume, &node);
	}
	while (result == NTFS_OK && position < units) {
		if (path[position] == OVERWRITE_PATH_SEPARATOR) {
			position++;
			continue;
		}
		start = position;
		while (position < units && path[position] != OVERWRITE_PATH_SEPARATOR) {
			position++;
		}
		if (position - start > NTFS_NAME_MAX) {
			result = NTFS_RANGE;
			break;
		}
		result = ntfs_lookup(node, path + start, position - start, &child);
		ntfs_node_close(node);
		node = child;
		child = NULL;
		if (result == NTFS_OK) {
			result = ntfs_node_metadata(node, &stat);
			if (result == NTFS_OK &&
			    (stat.reparse ||
				(stat.reference & NTFS_REFERENCE_RECORD_MASK) <
				    NTFS_FIRST_USER_RECORD)) {
				result = NTFS_UNSUPPORTED;
			}
		}
	}
	if (result == NTFS_OK) {
		result = ntfs_node_metadata(node, &stat);
	}
	ntfs_node_close(node);
	if (volume != NULL) {
		closed = ntfs_unmount(volume);
		if (closed != NTFS_OK) {
			result = closed;
		}
	}
	if (result == NTFS_OK) {
		*reference = stat.reference;
	}
	return result;
}

static enum ntfs_result
prepare_range(struct ntfs_overwrite *owner, uint64_t reference, uint64_t offset, size_t bytes,
    struct overwrite_span *spans, uint32_t *count, uint8_t *image, uint64_t first, uint64_t end)
{
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *node = NULL;
	struct ntfs_stream *stream = NULL;
	const struct ntfs_run *run;
	struct ntfs_stat stat;
	uint64_t cursor, available, physical;
	uint32_t cluster;
	enum ntfs_result result, closed;

	result = ntfs_mount(&owner->reader, NULL, &volume);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_node_open(volume, reference, &node);
	if (result == NTFS_OK) {
		result = ntfs_node_stat(node, &stat);
	}
	if (result != NTFS_OK) {
		goto done;
	}
	if ((stat.reference & NTFS_REFERENCE_RECORD_MASK) < NTFS_FIRST_USER_RECORD ||
	    stat.directory || stat.reparse ||
	    (stat.file_attributes & (NTFS_FILE_READ_ONLY | NTFS_FILE_SYSTEM)) != 0) {
		result = NTFS_UNSUPPORTED;
		goto done;
	}
	result = ntfs_stream_open(node, NULL, 0, &stream);
	if (result != NTFS_OK) {
		goto done;
	}
	if (stream->resident || stream->metadata_only || stream->wof != NULL ||
	    stream->flags != 0 || stream->compression_unit != 0) {
		result = NTFS_UNSUPPORTED;
		goto done;
	}
	if (!ntfs_bounds(offset, bytes, stream->size) ||
	    !ntfs_bounds(offset, bytes, stream->initialized) || end > stream->allocated) {
		result = NTFS_RANGE;
		goto done;
	}
	cluster = owner->info.cluster_size;
	for (cursor = first; cursor < end; cursor += available) {
		run = ntfs_run_find(stream, cursor / cluster);
		if (run == NULL || run->lcn == NTFS_HOLE || *count == OVERWRITE_MAX_SPANS) {
			result = NTFS_CORRUPT;
			goto done;
		}
		physical = (run->lcn + cursor / cluster - run->vcn) * cluster + cursor % cluster;
		available = (run->vcn + run->length) * cluster - cursor;
		if (available > end - cursor) {
			available = end - cursor;
		}
		if (physical % owner->backend.alignment != 0 ||
		    available % owner->backend.alignment != 0 ||
		    !ntfs_bounds(physical, available, owner->info.size_bytes)) {
			result = NTFS_CORRUPT;
			goto done;
		}
		spans[*count] = (struct overwrite_span){
		    physical, cursor, (uint32_t)(cursor - first), (uint32_t)available};
		(*count)++;
		result = overwrite_read(owner, physical, image + cursor - first, (size_t)available);
		if (result != NTFS_OK) {
			goto done;
		}
	}

done:
	ntfs_stream_close(stream);
	ntfs_node_close(node);
	closed = ntfs_unmount(volume);
	return closed == NTFS_OK ? result : closed;
}

enum ntfs_result
ntfs_overwrite_range(struct ntfs_overwrite *owner, uint64_t reference, uint64_t offset,
    const void *data, size_t bytes, struct ntfs_overwrite_report *report)
{
	struct overwrite_span *spans;
	uint8_t *image, *allocation;
	uint64_t first, end, covered_first, covered_end;
	size_t image_bytes, allocation_bytes, transferred;
	uint32_t count = 0, ordinal;
	enum ntfs_result result;

	if (owner == NULL || report == NULL ||
	    !ntfs_pointer_ranges_separate(owner, sizeof(*owner), report, sizeof(*report)) ||
	    !ntfs_pointer_ranges_separate(data, bytes, report, sizeof(*report)) ||
	    !ntfs_pointer_ranges_separate(data, bytes, owner, sizeof(*owner))) {
		return NTFS_INVALID;
	}
	ntfs_zero(report, sizeof(*report));
	report->requested_bytes = bytes;
	if (owner->poisoned) {
		report->poisoned = true;
		return NTFS_IO;
	}
	if (bytes > NTFS_OVERWRITE_MAX_BYTES || bytes > UINT64_MAX - offset ||
	    offset + bytes > UINT64_MAX - owner->backend.alignment) {
		return NTFS_RANGE;
	}
	if (bytes == 0) {
		return NTFS_OK;
	}
	first = offset & ~(uint64_t)(owner->backend.alignment - 1u);
	end = (offset + bytes + owner->backend.alignment - 1u) &
	    ~(uint64_t)(owner->backend.alignment - 1u);
	image_bytes = (size_t)(end - first);
	allocation_bytes = image_bytes + owner->backend.alignment - 1u;
	spans = overwrite_allocate(owner, OVERWRITE_MAX_SPANS * sizeof(*spans));
	if (spans == NULL) {
		return NTFS_NO_MEMORY;
	}
	allocation = overwrite_allocate(owner, allocation_bytes);
	if (allocation == NULL) {
		overwrite_release(owner, spans, OVERWRITE_MAX_SPANS * sizeof(*spans));
		return NTFS_NO_MEMORY;
	}
	image = (void *)(((uintptr_t)allocation + owner->backend.alignment - 1u) &
	    ~(uintptr_t)(owner->backend.alignment - 1u));
	owner->read_calls = 0;
	owner->read_bytes = 0;
	result = prepare_range(owner, reference, offset, bytes, spans, &count, image, first, end);
	if (result != NTFS_OK) {
		goto done;
	}
	ntfs_copy(image + offset - first, data, bytes);
	for (ordinal = 0; ordinal < count; ordinal++) {
		transferred = 0;
		report->writes++;
		result =
		    owner->backend.write(owner->backend.reader.context, spans[ordinal].physical,
			image + spans[ordinal].offset, spans[ordinal].bytes, &transferred);
		if (transferred <= spans[ordinal].bytes) {
			report->physical_bytes += transferred;
		}
		if (result != NTFS_OK || transferred != spans[ordinal].bytes) {
			owner->poisoned = true;
			result = NTFS_IO;
			goto done;
		}
		covered_first = spans[ordinal].logical > offset ? spans[ordinal].logical : offset;
		covered_end = spans[ordinal].logical + spans[ordinal].bytes;
		if (covered_end > offset + bytes) {
			covered_end = offset + bytes;
		}
		report->completed_bytes += covered_end - covered_first;
	}
	result = owner->backend.persist(owner->backend.reader.context);
	if (result != NTFS_OK) {
		owner->poisoned = true;
		result = NTFS_IO;
	}
	report->persisted = result == NTFS_OK;

done:
	report->poisoned = owner->poisoned;
	overwrite_release(owner, allocation, allocation_bytes);
	overwrite_release(owner, spans, OVERWRITE_MAX_SPANS * sizeof(*spans));
	return result;
}

static enum ntfs_result
reject_change_journal(struct ntfs_volume *volume)
{
	static const uint16_t extend_name[] = {'$', 'E', 'x', 't', 'e', 'n', 'd'};
	static const uint16_t journal_name[] = {'$', 'U', 's', 'n', 'J', 'r', 'n', 'l'};
	struct ntfs_node *root = NULL, *extend = NULL, *journal = NULL;
	struct ntfs_stat stat;
	enum ntfs_result result;

	result = ntfs_root(volume, &root);
	if (result == NTFS_OK) {
		result = ntfs_lookup(
		    root, extend_name, sizeof(extend_name) / sizeof(*extend_name), &extend);
	}
	if (result == NTFS_NOT_FOUND) {
		result = NTFS_OK;
		goto done;
	}
	if (result == NTFS_OK) {
		result = ntfs_node_metadata(extend, &stat);
	}
	if (result == NTFS_OK &&
	    (!stat.directory ||
		(stat.reference & NTFS_REFERENCE_RECORD_MASK) != NTFS_EXTEND_RECORD)) {
		result = NTFS_CORRUPT;
	}
	if (result == NTFS_OK) {
		result = ntfs_lookup(
		    extend, journal_name, sizeof(journal_name) / sizeof(*journal_name), &journal);
		if (result == NTFS_OK) {
			result = NTFS_UNSUPPORTED;
		} else if (result == NTFS_NOT_FOUND) {
			result = NTFS_OK;
		}
	}

done:
	ntfs_node_close(journal);
	ntfs_node_close(extend);
	ntfs_node_close(root);
	return result;
}

static enum ntfs_result
transaction_write(void *context, uint64_t offset, const void *image, size_t bytes, size_t *actual)
{
	struct ntfs_overwrite *owner = context;

	return owner->backend.write(owner->backend.reader.context, offset, image, bytes, actual);
}

static enum ntfs_result
transaction_persist(void *context)
{
	struct ntfs_overwrite *owner = context;

	return owner->backend.persist(owner->backend.reader.context);
}

enum ntfs_result
ntfs_write_existing_range(struct ntfs_overwrite *owner, uint64_t reference, uint64_t offset,
    const void *data, size_t bytes, uint64_t filetime, struct ntfs_write_range_report *report)
{
	struct ntfs_write_transaction_workspace *transaction = NULL;
	struct ntfs_write_execution_workspace *execution;
	struct ntfs_write_replay_plan *overlay = NULL;
	struct ntfs_validation_report *validation = NULL;
	struct ntfs_write_data_span *data_spans = NULL;
	struct overwrite_span *spans = NULL;
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *node = NULL;
	struct ntfs_attr_view attribute;
	struct ntfs_overwrite_environment backend;
	uint8_t *image = NULL, *allocation = NULL, *execution_allocation = NULL;
	uint64_t first, end;
	size_t image_bytes, allocation_bytes, execution_bytes;
	uint32_t count = 0, index;
	enum ntfs_result result, closed;

	if (owner == NULL || report == NULL ||
	    !ntfs_pointer_ranges_separate(owner, sizeof(*owner), report, sizeof(*report)) ||
	    !ntfs_pointer_ranges_separate(data, bytes, report, sizeof(*report)) ||
	    !ntfs_pointer_ranges_separate(data, bytes, owner, sizeof(*owner))) {
		return NTFS_INVALID;
	}
	ntfs_zero(report, sizeof(*report));
	report->requested_bytes = bytes;
	if (owner->poisoned) {
		report->execution.poisoned = true;
		return NTFS_IO;
	}
	if (filetime > INT64_MAX) {
		return NTFS_INVALID;
	}
	if (bytes > NTFS_OVERWRITE_MAX_BYTES || bytes > UINT64_MAX - offset ||
	    offset + bytes > UINT64_MAX - owner->backend.alignment) {
		return NTFS_RANGE;
	}
	if (bytes == 0) {
		return NTFS_OK;
	}
	if (owner->info.sector_size != NTFS_WRITE_SECTOR_BYTES ||
	    owner->info.cluster_size != NTFS_WRITE_CLUSTER_BYTES ||
	    owner->info.record_size != NTFS_WRITE_RECORD_BYTES ||
	    owner->backend.alignment > NTFS_WRITE_CLUSTER_BYTES) {
		return NTFS_UNSUPPORTED;
	}
	first = offset & ~(uint64_t)(owner->backend.alignment - 1u);
	end = (offset + bytes + owner->backend.alignment - 1u) &
	    ~(uint64_t)(owner->backend.alignment - 1u);
	image_bytes = (size_t)(end - first);
	allocation_bytes = image_bytes + owner->backend.alignment - 1u;
	execution_bytes = sizeof(*execution) + NTFS_WRITE_CLUSTER_BYTES - 1u;
	transaction = overwrite_allocate(owner, sizeof(*transaction));
	validation = overwrite_allocate(owner, sizeof(*validation));
	overlay = overwrite_allocate(owner, sizeof(*overlay));
	spans = overwrite_allocate(owner, OVERWRITE_MAX_SPANS * sizeof(*spans));
	data_spans = overwrite_allocate(owner, OVERWRITE_MAX_SPANS * sizeof(*data_spans));
	allocation = overwrite_allocate(owner, allocation_bytes);
	execution_allocation = overwrite_allocate(owner, execution_bytes);
	if (transaction == NULL || validation == NULL || overlay == NULL || spans == NULL ||
	    data_spans == NULL || allocation == NULL || execution_allocation == NULL) {
		result = NTFS_NO_MEMORY;
		goto done;
	}
	image = (void *)(((uintptr_t)allocation + owner->backend.alignment - 1u) &
	    ~(uintptr_t)(owner->backend.alignment - 1u));
	execution = (void *)(((uintptr_t)execution_allocation + NTFS_WRITE_CLUSTER_BYTES - 1u) &
	    ~(uintptr_t)(NTFS_WRITE_CLUSTER_BYTES - 1u));
	owner->read_calls = 0;
	owner->read_bytes = 0;
	result = ntfs_validate(&owner->reader, NULL, NULL, validation);
	if (result == NTFS_OK) {
		result = ntfs_mount(&owner->reader, NULL, &volume);
	}
	if (result == NTFS_OK) {
		result = reject_hibernation(volume);
	}
	if (result == NTFS_OK) {
		result = reject_change_journal(volume);
	}
	if (result == NTFS_OK) {
		result = ntfs_node_open(volume, reference, &node);
	}
	if (result == NTFS_OK) {
		result = ntfs_attr_find(node->record, owner->info.record_size, NTFS_ATTRIBUTE_DATA,
		    NULL, 0, UINT16_MAX, &attribute);
		if (result == NTFS_OK && !attribute.disk->nonresident) {
			result = ntfs_write_prepare_resident_transaction(
			    node, filetime, offset, data, bytes, transaction);
		} else if (result == NTFS_OK || result == NTFS_NOT_FOUND) {
			result = ntfs_write_prepare_transaction(node, filetime, transaction);
		}
	}
	ntfs_node_close(node);
	node = NULL;
	if (volume != NULL) {
		closed = ntfs_unmount(volume);
		volume = NULL;
		if (closed != NTFS_OK) {
			result = closed;
		}
	}
	if (result != NTFS_OK) {
		goto done;
	}
	if (transaction->file.resident_bytes == 0) {
		result = prepare_range(
		    owner, reference, offset, bytes, spans, &count, image, first, end);
		if (result != NTFS_OK) {
			goto done;
		}
		ntfs_copy(image + offset - first, data, bytes);
		for (index = 0; index < count; index++) {
			data_spans[index] = (struct ntfs_write_data_span){
			    spans[index].physical, image + spans[index].offset, spans[index].bytes};
		}
	}
	transaction->execution.data = data_spans;
	transaction->execution.spans = count;
	ntfs_zero(overlay, sizeof(*overlay));
	ntfs_copy(&overlay->file, &transaction->file, sizeof(overlay->file));
	result = ntfs_write_validate_overlay(&owner->reader, overlay, validation);
	if (result != NTFS_OK) {
		goto done;
	}
	backend = owner->backend;
	backend.reader = owner->reader;
	backend.write = transaction_write;
	backend.persist = transaction_persist;
	result = ntfs_write_execute_prepare(&backend, &transaction->execution, execution);
	if (result == NTFS_OK) {
		result = ntfs_write_execute(execution, &owner->poisoned, &report->execution);
	}
	if (result == NTFS_OK) {
		report->completed_bytes = bytes;
	}

done:
	report->execution.poisoned = owner->poisoned;
	if (execution_allocation != NULL) {
		overwrite_release(owner, execution_allocation, execution_bytes);
	}
	if (allocation != NULL) {
		overwrite_release(owner, allocation, allocation_bytes);
	}
	if (data_spans != NULL) {
		overwrite_release(owner, data_spans, OVERWRITE_MAX_SPANS * sizeof(*data_spans));
	}
	if (spans != NULL) {
		overwrite_release(owner, spans, OVERWRITE_MAX_SPANS * sizeof(*spans));
	}
	if (overlay != NULL) {
		overwrite_release(owner, overlay, sizeof(*overlay));
	}
	if (validation != NULL) {
		overwrite_release(owner, validation, sizeof(*validation));
	}
	if (transaction != NULL) {
		overwrite_release(owner, transaction, sizeof(*transaction));
	}
	return result;
}
