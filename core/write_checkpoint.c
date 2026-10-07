/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_checkpoint.h"
#include "write_batch_history.h"
#include "write_batch_pages.h"
#include "logfile_internal.h"
#include "pointer_range.h"
#include <ntfs/record.h>

enum {
	CHECKPOINT_ROOT_STEPS = 3,
	CHECKPOINT_OLD_ROOTS = 0,
	CHECKPOINT_COPY = NTFS_LFS_RESTART_PAGES,
	CHECKPOINT_HOME = CHECKPOINT_COPY + NTFS_WRITE_EMPTY_CHECKPOINT_PAGES,
	CHECKPOINT_ADVANCED_ROOTS = CHECKPOINT_HOME + NTFS_WRITE_EMPTY_CHECKPOINT_PAGES,
	CHECKPOINT_CLEAN_ROOTS = CHECKPOINT_ADVANCED_ROOTS + NTFS_LFS_RESTART_PAGES,
	CHECKPOINT_PUBLICATIONS = CHECKPOINT_CLEAN_ROOTS + NTFS_LFS_RESTART_PAGES
};

struct ntfs_write_checkpoint {
	struct ntfs_overwrite_environment backend;
	struct ntfs_environment reader;
	struct ntfs_write_checkpoint_publication publication[CHECKPOINT_PUBLICATIONS];
	uint8_t *allocation, *frames;
	size_t allocation_bytes, live;
	uint64_t reads, read_bytes, allocations, allocated_bytes;
	bool prepared;
};

struct checkpoint_workspace {
	struct ntfs_write_batch_history history;
	struct ntfs_write_journal_workspace guard;
	uint8_t checkpoint[NTFS_WRITE_CHECKPOINT_BYTES], anchor[NTFS_WRITE_FORGET_BYTES];
	uint8_t roots[NTFS_LFS_RESTART_PAGES][NTFS_WRITE_CLUSTER_BYTES];
	uint8_t before[NTFS_WRITE_CLUSTER_BYTES], image[NTFS_WRITE_CLUSTER_BYTES];
	struct ntfs_logfile_restart restart[NTFS_LFS_RESTART_PAGES];
};

static void *
checkpoint_allocate(void *context, size_t bytes)
{
	struct ntfs_write_checkpoint *owner = context;
	void *memory;

	if (bytes == 0 || bytes > NTFS_DEFAULT_MAX_LIVE_BYTES - owner->live ||
	    owner->allocations == NTFS_DEFAULT_OPERATION_ALLOCATION_CALLS ||
	    bytes > NTFS_DEFAULT_OPERATION_ALLOCATION_BYTES - owner->allocated_bytes) {
		return NULL;
	}
	owner->allocations++;
	owner->allocated_bytes += bytes;
	memory = owner->backend.reader.allocate(owner->backend.reader.context, bytes);
	if (memory != NULL) {
		owner->live += bytes;
		ntfs_zero(memory, bytes);
	}
	return memory;
}

static void
checkpoint_release(void *context, void *memory, size_t bytes)
{
	struct ntfs_write_checkpoint *owner = context;

	if (memory != NULL) {
		owner->backend.reader.release(owner->backend.reader.context, memory, bytes);
		owner->live -= bytes;
	}
}

static enum ntfs_result
checkpoint_read(void *context, uint64_t physical, void *memory, size_t bytes)
{
	struct ntfs_write_checkpoint *owner = context;

	if (!ntfs_bounds(physical, bytes, owner->reader.size_bytes) ||
	    owner->reads == NTFS_DEFAULT_OPERATION_READ_CALLS ||
	    bytes > NTFS_DEFAULT_OPERATION_READ_BYTES - owner->read_bytes) {
		return NTFS_RANGE;
	}
	owner->reads++;
	owner->read_bytes += bytes;
	return owner->backend.reader.read(owner->backend.reader.context, physical, memory, bytes);
}

void
ntfs_write_checkpoint_close(struct ntfs_write_checkpoint *owner)
{
	struct ntfs_environment source;

	if (owner == NULL) {
		return;
	}
	source = owner->backend.reader;
	checkpoint_release(owner, owner->allocation, owner->allocation_bytes);
	source.release(source.context, owner, sizeof(*owner));
}

size_t
ntfs_write_checkpoint_count(const struct ntfs_write_checkpoint *owner)
{
	return owner == NULL ? 0 : CHECKPOINT_PUBLICATIONS;
}

const struct ntfs_write_checkpoint_publication *
ntfs_write_checkpoint_get(const struct ntfs_write_checkpoint *owner, size_t index)
{
	return owner == NULL || index >= CHECKPOINT_PUBLICATIONS ? NULL
								 : &owner->publication[index];
}

static uint8_t *
checkpoint_publication(struct ntfs_write_checkpoint *owner, size_t index, uint64_t physical,
    enum ntfs_write_checkpoint_stage stage)
{
	uint8_t *image = owner->frames + index * NTFS_WRITE_CLUSTER_BYTES;

	owner->publication[index] =
	    (struct ntfs_write_checkpoint_publication){physical, image, stage};
	return image;
}

static enum ntfs_result
checkpoint_log_physical(const struct ntfs_stream *log, uint64_t logical, uint64_t *physical)
{
	const struct ntfs_run *run;
	uint64_t vcn;

	if (logical % NTFS_WRITE_CLUSTER_BYTES != 0 ||
	    !ntfs_bounds(logical, NTFS_WRITE_CLUSTER_BYTES, log->initialized)) {
		return NTFS_CORRUPT;
	}
	vcn = logical / NTFS_WRITE_CLUSTER_BYTES;
	run = ntfs_run_find(log, vcn);
	if (run == NULL || run->lcn == NTFS_HOLE ||
	    run->lcn > UINT64_MAX / NTFS_WRITE_CLUSTER_BYTES - (vcn - run->vcn)) {
		return NTFS_CORRUPT;
	}
	*physical = (run->lcn + vcn - run->vcn) * NTFS_WRITE_CLUSTER_BYTES;
	return NTFS_OK;
}

static enum ntfs_result
checkpoint_packet_prepare(struct ntfs_write_checkpoint *owner, struct ntfs_volume *volume,
    struct checkpoint_workspace *work, struct ntfs_write_batch_pages **out)
{
	struct ntfs_logfile *log = NULL;
	struct ntfs_logfile_limits limits;
	struct ntfs_logfile_record_view view;
	struct ntfs_write_batch_pages_input input = {0};
	struct ntfs_write_batch_packet packet = {0};
	struct ntfs_disk_log_client_restart *restart;
	struct ntfs_logfile_restart advanced;
	struct ntfs_logfile_client client;
	struct ntfs_logfile_buffer anchor, checkpoint;
	size_t actual;
	enum ntfs_result result;

	if (work->history.history.completed_end_lsn == work->history.client.restart_lsn) {
		return NTFS_BUSY;
	}
	if (work->history.history.visited_records >= NTFS_WRITE_BATCH_MAX_PACKETS) {
		return NTFS_NO_SPACE;
	}
	ntfs_logfile_default_limits(&limits);
	limits.max_read_calls = NTFS_DEFAULT_OPERATION_READ_CALLS;
	limits.max_read_bytes = NTFS_DEFAULT_OPERATION_READ_BYTES;
	result = ntfs_logfile_open_volume_retained_impl(volume, &limits, NULL, &log);
	if (result == NTFS_OK) {
		result =
		    ntfs_logfile_read_circular_record(log, work->history.history.completed_end_lsn,
			work->anchor, sizeof(work->anchor), &view);
	}
	if (result == NTFS_OK && view.bytes != sizeof(work->anchor)) {
		result = NTFS_UNSUPPORTED;
	}
	if (result == NTFS_OK) {
		result = ntfs_logfile_read_circular_record(log, work->history.client.restart_lsn,
		    work->checkpoint, sizeof(work->checkpoint), &view);
	}
	if (result == NTFS_OK && view.bytes != sizeof(work->checkpoint)) {
		result = NTFS_UNSUPPORTED;
	}
	ntfs_logfile_close(log);
	if (result != NTFS_OK) {
		return result;
	}
	restart = (void *)(work->checkpoint + sizeof(struct ntfs_disk_log_record));
	ntfs_put_u64(restart->analysis_lsn, work->history.history.completed_end_lsn);
	ntfs_put_u64(work->checkpoint + sizeof(work->checkpoint) - sizeof(uint64_t),
	    work->history.history.completed_end_lsn);
	packet.record.type = NTFS_LOGFILE_RECORD_RESTART;
	packet.record.client_sequence = work->history.client.sequence;
	packet.record.data = (struct ntfs_logfile_span){sizeof(struct ntfs_disk_log_record),
	    NTFS_WRITE_CHECKPOINT_BYTES - sizeof(struct ntfs_disk_log_record)};
	packet.payload = (struct ntfs_logfile_buffer){restart, packet.record.data.length};
	packet.previous = packet.undo_next = SIZE_MAX;
	input.restart = work->history.origin;
	input.floor_lsn = work->history.client.oldest_lsn;
	input.tail_lsn = work->history.history.completed_end_lsn;
	input.next_lsn = work->history.history.next_lsn;
	input.packet = &packet;
	input.packets = NTFS_WRITE_EMPTY_CHECKPOINT_PAGES;
	result = ntfs_write_batch_pages_prepare(&owner->reader, &input, out);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_write_batch_pages_packet_copy(
	    *out, 0, work->checkpoint, sizeof(work->checkpoint), &actual);
	if (result != NTFS_OK) {
		return result;
	}
	advanced = work->history.selected;
	advanced.current_lsn = ntfs_write_batch_pages_lsn(*out, 0);
	client = work->history.client;
	client.oldest_lsn = work->history.history.completed_end_lsn;
	client.restart_lsn = advanced.current_lsn;
	anchor = (struct ntfs_logfile_buffer){work->anchor, sizeof(work->anchor)};
	checkpoint = (struct ntfs_logfile_buffer){work->checkpoint, actual};
	return ntfs_write_checkpoint_origin_bind(&advanced, &client, &anchor, &checkpoint);
}

static enum ntfs_result
checkpoint_log_prepare(struct ntfs_write_checkpoint *owner, struct ntfs_stream *log,
    const struct ntfs_write_batch_pages *pages, struct checkpoint_workspace *work)
{
	const struct ntfs_write_batch_page *page;
	uint64_t physical, copied;
	uint8_t *home, *copy;
	enum ntfs_result result;

	if (ntfs_write_batch_pages_count(pages) != NTFS_WRITE_EMPTY_CHECKPOINT_PAGES) {
		return NTFS_CORRUPT;
	}
	page = ntfs_write_batch_pages_get(pages, 0);
	result = checkpoint_log_physical(log, page->offset, &physical);
	if (result != NTFS_OK) {
		return result;
	}
	result = checkpoint_log_physical(
	    log, NTFS_LFS_RESTART_PAGES * NTFS_WRITE_CLUSTER_BYTES, &copied);
	if (result != NTFS_OK) {
		return result;
	}
	result = checkpoint_read(owner, physical, work->before, sizeof(work->before));
	if (result != NTFS_OK) {
		return result;
	}
	home = checkpoint_publication(owner, CHECKPOINT_HOME, physical, NTFS_WRITE_CHECKPOINT_HOME);
	copy = checkpoint_publication(owner, CHECKPOINT_COPY, copied, NTFS_WRITE_CHECKPOINT_COPY);
	ntfs_copy(home, page->protected_bytes, NTFS_WRITE_CLUSTER_BYTES);
	result = ntfs_write_guard_frame(work->before, sizeof(work->before), home, &work->guard);
	if (result == NTFS_OK) {
		result = ntfs_write_tail_copy_encode(&work->guard, home, page->offset, copy);
	}
	if (result == NTFS_OK) {
		result = checkpoint_read(owner, copied, work->before, sizeof(work->before));
	}
	if (result == NTFS_OK) {
		result =
		    ntfs_write_guard_frame(work->before, sizeof(work->before), copy, &work->guard);
	}
	return result;
}

static enum ntfs_result
checkpoint_roots_prepare(struct ntfs_write_checkpoint *owner, struct ntfs_stream *log,
    const struct ntfs_write_batch_pages *pages, struct checkpoint_workspace *work)
{
	struct ntfs_logfile_restart *restart;
	struct ntfs_logfile_client client;
	struct ntfs_disk_log_restart_area *area;
	struct ntfs_disk_log_client *entry;
	const uint8_t *previous;
	uint8_t *image;
	uint64_t physical;
	size_t slot, index, output;
	enum ntfs_result result;

	for (slot = 0; slot < NTFS_LFS_RESTART_PAGES; slot++) {
		result = checkpoint_log_physical(log, slot * NTFS_WRITE_CLUSTER_BYTES, &physical);
		if (result == NTFS_OK) {
			result = checkpoint_read(
			    owner, physical, work->roots[slot], NTFS_WRITE_CLUSTER_BYTES);
		}
		restart = &work->restart[slot];
		if (result == NTFS_OK) {
			result =
			    ntfs_logfile_restart_decode(work->roots[slot], NTFS_WRITE_CLUSTER_BYTES,
				log->size, work->image, sizeof(work->image), restart);
		}
		if (result == NTFS_OK) {
			result = ntfs_logfile_client_decode(work->image + restart->clients.offset,
			    sizeof(struct ntfs_disk_log_client), &client);
		}
		if (result != NTFS_OK) {
			return result;
		}
		if (restart->current_lsn != work->history.selected.current_lsn ||
		    restart->flags != NTFS_LOGFILE_RESTART_CLEAN ||
		    restart->last_data_bytes != work->history.selected.last_data_bytes ||
		    restart->open_count != work->history.selected.open_count ||
		    restart->file_bytes != work->history.selected.file_bytes ||
		    restart->sequence_bits != work->history.selected.sequence_bits ||
		    restart->system_page_bytes != NTFS_WRITE_CLUSTER_BYTES ||
		    restart->log_page_bytes != NTFS_WRITE_CLUSTER_BYTES ||
		    restart->record_header_bytes != sizeof(struct ntfs_disk_log_record) ||
		    restart->page_data_offset != NTFS_WRITE_LOG_DATA_OFFSET ||
		    restart->major != NTFS_LFS_MAJOR_LEGACY ||
		    restart->minor != NTFS_LFS_MINOR_LEGACY || restart->client_count != 1 ||
		    restart->in_use_head != 0 || restart->free_head != NTFS_LOGFILE_NO_CLIENT ||
		    client.oldest_lsn != work->history.client.oldest_lsn ||
		    client.restart_lsn != work->history.client.restart_lsn ||
		    client.sequence != work->history.client.sequence ||
		    client.previous != work->history.client.previous ||
		    client.next != work->history.client.next ||
		    client.name_length != work->history.client.name_length ||
		    !ntfs_equal(client.name, work->history.client.name, sizeof(client.name))) {
			return NTFS_STALE;
		}
		previous = work->roots[slot];
		for (index = 0; index < CHECKPOINT_ROOT_STEPS; index++) {
			ntfs_copy(work->image, previous, NTFS_WRITE_CLUSTER_BYTES);
			result = ntfs_fixup(work->image, sizeof(work->image), "RSTR");
			if (result != NTFS_OK) {
				return result;
			}
			area = (void *)(work->image + restart->area.offset);
			entry = (void *)(work->image + restart->clients.offset);
			ntfs_put_u16(area->flags,
			    index == CHECKPOINT_ROOT_STEPS - 1 ? NTFS_LOGFILE_RESTART_CLEAN : 0);
			if (index != 0) {
				ntfs_put_u64(
				    area->current_lsn, ntfs_write_batch_pages_lsn(pages, 0));
				ntfs_put_u32(area->last_data_bytes,
				    NTFS_WRITE_CHECKPOINT_BYTES -
					sizeof(struct ntfs_disk_log_record));
				ntfs_put_u64(
				    entry->oldest_lsn, work->history.history.completed_end_lsn);
				ntfs_put_u64(
				    entry->restart_lsn, ntfs_write_batch_pages_lsn(pages, 0));
			}
			output = (index == 0	      ? CHECKPOINT_OLD_ROOTS
					 : index == 1 ? CHECKPOINT_ADVANCED_ROOTS
						      : CHECKPOINT_CLEAN_ROOTS) +
			    slot;
			image = checkpoint_publication(owner, output, physical,
			    index == 0	     ? (slot == 0 ? NTFS_WRITE_CHECKPOINT_OLD_FIRST
							  : NTFS_WRITE_CHECKPOINT_OLD_SECOND)
				: index == 1 ? (slot == 0 ? NTFS_WRITE_CHECKPOINT_ADVANCED_FIRST
							  : NTFS_WRITE_CHECKPOINT_ADVANCED_SECOND)
					     : (slot == 0 ? NTFS_WRITE_CHECKPOINT_CLEAN_FIRST
							  : NTFS_WRITE_CHECKPOINT_CLEAN_SECOND));
			result = ntfs_record_protect(
			    work->image, sizeof(work->image), image, NTFS_WRITE_CLUSTER_BYTES);
			if (result == NTFS_OK) {
				result = ntfs_write_guard_frame(
				    previous, NTFS_WRITE_CLUSTER_BYTES, image, &work->guard);
			}
			if (result != NTFS_OK) {
				return result;
			}
			previous = image;
		}
	}
	return NTFS_OK;
}

static enum ntfs_result
checkpoint_prepare(struct ntfs_write_checkpoint *owner)
{
	struct checkpoint_workspace *work;
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *node = NULL;
	struct ntfs_stream *log = NULL;
	struct ntfs_write_batch_pages *pages = NULL;
	struct ntfs_limits limits;
	enum ntfs_result result;

	work = checkpoint_allocate(owner, sizeof(*work));
	if (work == NULL) {
		return NTFS_NO_MEMORY;
	}
	result = ntfs_write_batch_history_prepare(&owner->reader, &work->history);
	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	if (result == NTFS_OK) {
		result = ntfs_mount(&owner->reader, &limits, &volume);
	}
	if (result == NTFS_OK &&
	    (volume->info.sector_size != NTFS_WRITE_SECTOR_BYTES ||
		volume->info.cluster_size != NTFS_WRITE_CLUSTER_BYTES ||
		volume->info.record_size != NTFS_WRITE_RECORD_BYTES ||
		volume->info.index_size != NTFS_WRITE_CLUSTER_BYTES)) {
		result = NTFS_UNSUPPORTED;
	}
	if (result == NTFS_OK) {
		result = checkpoint_packet_prepare(owner, volume, work, &pages);
	}
	if (result == NTFS_OK) {
		result = ntfs_node_by_number(volume, NTFS_LOGFILE_RECORD, &node);
	}
	if (result == NTFS_OK) {
		result = ntfs_stream_open(node, NULL, 0, &log);
	}
	if (result == NTFS_OK &&
	    (log->resident || log->metadata_only || log->flags != 0 || log->compression_unit != 0 ||
		log->initialized != log->size || log->size != work->history.selected.file_bytes)) {
		result = NTFS_UNSUPPORTED;
	}
	if (result == NTFS_OK) {
		owner->allocation_bytes = CHECKPOINT_PUBLICATIONS * NTFS_WRITE_CLUSTER_BYTES +
		    owner->backend.alignment - 1u;
		owner->allocation = checkpoint_allocate(owner, owner->allocation_bytes);
		if (owner->allocation == NULL) {
			result = NTFS_NO_MEMORY;
		} else {
			owner->frames = (void *)(((uintptr_t)owner->allocation +
						     owner->backend.alignment - 1u) &
			    ~(uintptr_t)(owner->backend.alignment - 1u));
		}
	}
	if (result == NTFS_OK) {
		result = checkpoint_log_prepare(owner, log, pages, work);
	}
	if (result == NTFS_OK) {
		result = checkpoint_roots_prepare(owner, log, pages, work);
	}
	ntfs_stream_close(log);
	ntfs_node_close(node);
	if (volume != NULL) {
		ntfs_unmount(volume);
	}
	ntfs_write_batch_pages_close(pages);
	checkpoint_release(owner, work, sizeof(*work));
	return result;
}

enum ntfs_result
ntfs_write_checkpoint_prepare(
    const struct ntfs_overwrite_environment *backend, struct ntfs_write_checkpoint **out)
{
	struct ntfs_write_checkpoint *owner;
	enum ntfs_result result;

	if (!ntfs_pointer_range_valid(out, sizeof(*out)) ||
	    (backend != NULL &&
		!ntfs_pointer_ranges_separate(backend, sizeof(*backend), out, sizeof(*out)))) {
		return NTFS_INVALID;
	}
	*out = NULL;
	if (backend == NULL || backend->api_version != NTFS_OVERWRITE_API_VERSION ||
	    backend->reader.api_version != NTFS_API_VERSION || backend->reader.read == NULL ||
	    backend->reader.allocate == NULL || backend->reader.release == NULL ||
	    backend->write == NULL || backend->persist == NULL ||
	    backend->alignment < NTFS_WRITE_SECTOR_BYTES ||
	    backend->alignment > NTFS_WRITE_CLUSTER_BYTES ||
	    (backend->alignment & (backend->alignment - 1u)) != 0) {
		return NTFS_INVALID;
	}
	owner = backend->reader.allocate(backend->reader.context, sizeof(*owner));
	if (owner == NULL) {
		return NTFS_NO_MEMORY;
	}
	ntfs_zero(owner, sizeof(*owner));
	owner->backend = *backend;
	owner->live = owner->allocated_bytes = sizeof(*owner);
	owner->allocations = 1;
	owner->reader = (struct ntfs_environment){NTFS_API_VERSION, owner,
	    backend->reader.size_bytes, checkpoint_read, checkpoint_allocate, checkpoint_release};
	result = checkpoint_prepare(owner);
	if (result != NTFS_OK) {
		ntfs_write_checkpoint_close(owner);
		return result;
	}
	owner->prepared = true;
	*out = owner;
	return NTFS_OK;
}

static bool
checkpoint_output_separate(const struct ntfs_write_checkpoint *owner, const void *out, size_t bytes)
{
	return ntfs_pointer_ranges_separate(owner, sizeof(*owner), out, bytes) &&
	    ntfs_pointer_ranges_separate(owner->allocation, owner->allocation_bytes, out, bytes);
}

enum ntfs_result
ntfs_write_checkpoint_execute(struct ntfs_write_checkpoint *owner, bool *poisoned,
    struct ntfs_write_checkpoint_report *report)
{
	const struct ntfs_write_checkpoint_publication *publication;
	size_t index, transferred;
	enum ntfs_result result;

	if (owner == NULL || !checkpoint_output_separate(owner, poisoned, sizeof(*poisoned)) ||
	    !checkpoint_output_separate(owner, report, sizeof(*report)) ||
	    !ntfs_pointer_ranges_separate(poisoned, sizeof(*poisoned), report, sizeof(*report))) {
		return NTFS_INVALID;
	}
	ntfs_zero(report, sizeof(*report));
	if (*poisoned) {
		report->poisoned = true;
		return NTFS_IO;
	}
	if (!owner->prepared) {
		return NTFS_INVALID;
	}
	owner->prepared = false;
	report->barriers++;
	result = owner->backend.persist(owner->backend.reader.context);
	if (result == NTFS_OK) {
		report->homes_persisted = true;
		report->durable_stage = NTFS_WRITE_CHECKPOINT_HOMES_PERSISTED;
	}
	for (index = 0; result == NTFS_OK && index < CHECKPOINT_PUBLICATIONS; index++) {
		publication = &owner->publication[index];
		transferred = 0;
		report->writes++;
		result = owner->backend.write(owner->backend.reader.context, publication->physical,
		    publication->image, NTFS_WRITE_CLUSTER_BYTES, &transferred);
		if (transferred <= NTFS_WRITE_CLUSTER_BYTES) {
			report->physical_bytes += transferred;
		}
		if (result != NTFS_OK || transferred != NTFS_WRITE_CLUSTER_BYTES) {
			result = NTFS_IO;
			break;
		}
		report->barriers++;
		result = owner->backend.persist(owner->backend.reader.context);
		if (result != NTFS_OK) {
			result = NTFS_IO;
			break;
		}
		report->durable_stage = publication->stage;
		if (publication->stage == NTFS_WRITE_CHECKPOINT_HOME) {
			report->checkpoint_persisted = true;
		}
	}
	if (result == NTFS_OK) {
		report->completed = true;
	} else {
		*poisoned = true;
		result = NTFS_IO;
	}
	report->poisoned = *poisoned;
	return result;
}
