/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "pointer_range.h"
#include "write_batch_recover_internal.h"
#include "write_batch_history.h"
#include "mount_internal.h"
#include <ntfs/record.h>

void *
ntfs_batch_recovery_allocate(void *context, size_t bytes)
{
	struct ntfs_write_batch_recovery *owner = context;
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

void
ntfs_batch_recovery_release(void *context, void *memory, size_t bytes)
{
	struct ntfs_write_batch_recovery *owner = context;

	if (memory != NULL) {
		owner->backend.reader.release(owner->backend.reader.context, memory, bytes);
		owner->live -= bytes;
	}
}

enum ntfs_result
ntfs_batch_recovery_read(void *context, uint64_t physical, void *memory, size_t bytes)
{
	struct ntfs_write_batch_recovery *owner = context;

	if (!ntfs_bounds(physical, bytes, owner->reader.size_bytes) ||
	    owner->reads == NTFS_DEFAULT_OPERATION_READ_CALLS ||
	    bytes > NTFS_DEFAULT_OPERATION_READ_BYTES - owner->read_bytes) {
		return NTFS_RANGE;
	}
	owner->reads++;
	owner->read_bytes += bytes;
	return owner->backend.reader.read(owner->backend.reader.context, physical, memory, bytes);
}

static void
recovery_overlay_copy(uint64_t physical, void *memory, size_t bytes, uint64_t home,
    const void *image, size_t image_bytes)
{
	uint64_t first = physical > home ? physical : home;
	uint64_t end =
	    physical + bytes < home + image_bytes ? physical + bytes : home + image_bytes;

	if (first < end) {
		ntfs_copy((uint8_t *)memory + first - physical,
		    (const uint8_t *)image + first - home, (size_t)(end - first));
	}
}

enum ntfs_result
ntfs_batch_recovery_overlay_read(void *context, uint64_t physical, void *memory, size_t bytes)
{
	struct ntfs_write_batch_recovery *owner = context;
	const struct ntfs_batch_recovery_home *home;
	const struct ntfs_batch_recovery_projection *projection;
	size_t index;
	enum ntfs_result result;

	result = ntfs_batch_recovery_read(owner, physical, memory, bytes);
	if (result != NTFS_OK) {
		return result;
	}
	if (owner->checkpoint.projection_active) {
		for (index = 0; index < NTFS_LFS_RESTART_PAGES; index++) {
			recovery_overlay_copy(physical, memory, bytes,
			    owner->checkpoint.physical[index],
			    owner->checkpoint.root_projection + index * NTFS_WRITE_CLUSTER_BYTES,
			    NTFS_WRITE_CLUSTER_BYTES);
		}
	}
	if (owner->view == NTFS_BATCH_RECOVERY_BOOTSTRAP) {
		recovery_overlay_copy(physical, memory, bytes,
		    owner->mft_lcn * NTFS_WRITE_CLUSTER_BYTES, owner->bootstrap,
		    sizeof(owner->bootstrap));
		recovery_overlay_copy(physical, memory, bytes,
		    owner->mirror_lcn * NTFS_WRITE_CLUSTER_BYTES, owner->bootstrap,
		    sizeof(owner->bootstrap));
	} else if (owner->view == NTFS_BATCH_RECOVERY_BEFORE ||
	    owner->view == NTFS_BATCH_RECOVERY_AFTER) {
		for (index = 0; index < owner->homes; index++) {
			home = &owner->home[index];
			recovery_overlay_copy(physical, memory, bytes, home->physical,
			    owner->view == NTFS_BATCH_RECOVERY_BEFORE ? home->before : home->after,
			    NTFS_WRITE_CLUSTER_BYTES);
		}
	} else if (owner->view == NTFS_BATCH_RECOVERY_HISTORY) {
		for (index = 0; index < owner->projections; index++) {
			projection = &owner->projection[index];
			recovery_overlay_copy(physical, memory, bytes, projection->physical,
			    projection->before, sizeof(projection->before));
		}
	}
	return NTFS_OK;
}

static void
recovery_analysis_close(struct ntfs_write_batch_recovery *owner)
{
	size_t index;

	for (index = 0; index < owner->packets; index++) {
		ntfs_batch_recovery_release(
		    owner, owner->packet[index].bytes, owner->packet[index].count);
	}
	ntfs_batch_recovery_release(
	    owner, owner->packet, owner->packet_capacity * sizeof(*owner->packet));
	if (owner->lifetimes == 0) {
		ntfs_batch_recovery_release(
		    owner, owner->target, owner->target_capacity * sizeof(*owner->target));
	} else {
		for (index = 0; index < owner->lifetimes; index++) {
			ntfs_batch_recovery_release(owner, owner->lifetime[index].target,
			    owner->lifetime[index].target_capacity * sizeof(*owner->target));
		}
	}
	ntfs_batch_recovery_release(
	    owner, owner->home, owner->home_capacity * sizeof(*owner->home));
	ntfs_batch_recovery_release(
	    owner, owner->qualified, owner->qualified_capacity * sizeof(*owner->qualified));
	ntfs_batch_recovery_release(
	    owner, owner->lifetime, owner->lifetime_capacity * sizeof(*owner->lifetime));
	ntfs_batch_recovery_release(
	    owner, owner->projection, owner->projection_capacity * sizeof(*owner->projection));
	ntfs_batch_recovery_release(owner, owner->checkpoint.root_projection,
	    NTFS_LFS_RESTART_PAGES * NTFS_WRITE_CLUSTER_BYTES);
	owner->checkpoint.root_projection = NULL;
	owner->checkpoint.projection_active = false;
	owner->packet = NULL;
	owner->target = NULL;
	owner->home = NULL;
	owner->qualified = NULL;
	owner->lifetime = NULL;
	owner->projection = NULL;
	owner->packets = owner->packet_capacity = owner->operation_packets = owner->targets =
	    owner->target_capacity = 0;
	owner->homes = owner->home_capacity = 0;
	owner->qualified_count = owner->qualified_capacity = 0;
	owner->lifetimes = owner->lifetime_capacity = owner->projections =
	    owner->projection_capacity = 0;
}

void
ntfs_write_batch_recovery_close(struct ntfs_write_batch_recovery *owner)
{
	struct ntfs_environment reader;

	if (owner == NULL) {
		return;
	}
	reader = owner->backend.reader;
	recovery_analysis_close(owner);
	ntfs_batch_recovery_release(
	    owner, owner->publication, owner->capacity * sizeof(*owner->publication));
	ntfs_batch_recovery_release(owner, owner->allocation, owner->allocation_bytes);
	reader.release(reader.context, owner, sizeof(*owner));
}

size_t
ntfs_write_batch_recovery_count(const struct ntfs_write_batch_recovery *owner)
{
	return owner == NULL ? 0 : owner->count;
}

const struct ntfs_write_batch_recovery_publication *
ntfs_write_batch_recovery_get(const struct ntfs_write_batch_recovery *owner, size_t index)
{
	return owner == NULL || index >= owner->count ? NULL : &owner->publication[index];
}

static enum ntfs_result
recovery_history_write_refuse(
    void *context, uint64_t offset, const void *bytes, size_t count, size_t *actual)
{
	(void)context;
	(void)offset;
	(void)bytes;
	(void)count;
	*actual = 0;
	return NTFS_INVALID;
}

static enum ntfs_result
recovery_history_persist_refuse(void *context)
{
	(void)context;
	return NTFS_INVALID;
}

enum ntfs_result
ntfs_write_batch_history_prepare(
    const struct ntfs_environment *source, struct ntfs_write_batch_history *out)
{
	struct ntfs_write_batch_recovery *owner = NULL;
	struct ntfs_overwrite_environment backend = {0};
	enum ntfs_result result;

	if (!ntfs_pointer_range_valid(out, sizeof(*out)) ||
	    (source != NULL &&
		!ntfs_pointer_ranges_separate(source, sizeof(*source), out, sizeof(*out)))) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (source == NULL) {
		return NTFS_INVALID;
	}
	backend.reader = *source;
	backend.api_version = NTFS_OVERWRITE_API_VERSION;
	backend.alignment = NTFS_WRITE_SECTOR_BYTES;
	backend.write = recovery_history_write_refuse;
	backend.persist = recovery_history_persist_refuse;
	result = ntfs_write_batch_recover_prepare(&backend, &owner);
	if (result == NTFS_OK &&
	    (owner->count != 0 || !owner->prepared ||
		owner->selected.flags != NTFS_LOGFILE_RESTART_CLEAN)) {
		result = NTFS_BUSY;
	}
	if (result == NTFS_OK) {
		*out = (struct ntfs_write_batch_history){.selected = owner->selected,
		    .origin = owner->origin,
		    .client = owner->client,
		    .history = owner->history,
		    .resources = {owner->reads, owner->read_bytes, owner->allocations,
			owner->allocated_bytes}};
	}
	ntfs_write_batch_recovery_close(owner);
	return result;
}

bool
ntfs_write_batch_history_checkpoint_needed(const struct ntfs_write_batch_history *history)
{
	const struct ntfs_write_batch_resources *usage = &history->resources;

	return history->history.completed_end_lsn != history->client.restart_lsn &&
	    (usage->read_calls >= NTFS_DEFAULT_OPERATION_READ_CALLS /
			NTFS_WRITE_HISTORY_RECOVERY_RESERVE_DIVISOR ||
		usage->read_bytes >= NTFS_DEFAULT_OPERATION_READ_BYTES /
			NTFS_WRITE_HISTORY_RECOVERY_RESERVE_DIVISOR ||
		usage->allocation_calls >= NTFS_DEFAULT_OPERATION_ALLOCATION_CALLS /
			NTFS_WRITE_HISTORY_RECOVERY_RESERVE_DIVISOR ||
		usage->allocation_bytes >= NTFS_DEFAULT_OPERATION_ALLOCATION_BYTES /
			NTFS_WRITE_HISTORY_RECOVERY_RESERVE_DIVISOR);
}

static uint8_t *
recovery_publication(struct ntfs_write_batch_recovery *owner, uint64_t physical,
    enum ntfs_write_recovery_stage stage)
{
	uint8_t *frame = owner->frames + owner->count * NTFS_WRITE_CLUSTER_BYTES;

	owner->publication[owner->count++] =
	    (struct ntfs_write_batch_recovery_publication){physical, frame, stage};
	return frame;
}

static bool
recovery_restart_matches(const struct ntfs_logfile_restart *a, const struct ntfs_logfile_restart *b)
{
	return a->current_lsn == b->current_lsn && a->file_bytes == b->file_bytes &&
	    a->usable_bytes == b->usable_bytes && a->circular_offset == b->circular_offset &&
	    a->system_page_bytes == b->system_page_bytes &&
	    a->log_page_bytes == b->log_page_bytes && a->sequence_bits == b->sequence_bits &&
	    a->last_data_bytes == b->last_data_bytes && a->open_count == b->open_count &&
	    a->major == b->major && a->minor == b->minor && a->client_count == b->client_count &&
	    a->free_head == b->free_head && a->in_use_head == b->in_use_head &&
	    a->record_header_bytes == b->record_header_bytes &&
	    a->page_data_offset == b->page_data_offset && a->area.offset == b->area.offset &&
	    a->area.length == b->area.length && a->clients.offset == b->clients.offset &&
	    a->clients.length == b->clients.length;
}

static enum ntfs_result
recovery_restarts_prepare(struct ntfs_write_batch_recovery *owner, struct ntfs_stream *log,
    struct ntfs_batch_recovery_workspace *work, bool *changed)
{
	struct ntfs_logfile_restart parsed;
	struct ntfs_disk_log_restart_area *area;
	uint64_t physical[NTFS_LFS_RESTART_PAGES];
	uint8_t *dirty;
	size_t index, selected = NTFS_LFS_RESTART_PAGES;
	enum ntfs_result result;

	*changed = false;
	for (index = 0; index < NTFS_LFS_RESTART_PAGES; index++) {
		result = ntfs_batch_recovery_mapping(
		    log, index * NTFS_WRITE_CLUSTER_BYTES, &physical[index]);
		if (result == NTFS_OK) {
			result = ntfs_batch_recovery_read(
			    owner, physical[index], work->restart[index], NTFS_WRITE_CLUSTER_BYTES);
		}
		if (result != NTFS_OK) {
			return result;
		}
		result = ntfs_logfile_restart_decode(work->restart[index], NTFS_WRITE_CLUSTER_BYTES,
		    log->size, work->image, sizeof(work->image), &parsed);
		if (result != NTFS_OK) {
			*changed = true;
			continue;
		}
		if (!recovery_restart_matches(&parsed, &owner->selected)) {
			return NTFS_STALE;
		}
		if (parsed.flags != NTFS_LOGFILE_RESTART_CLEAN) {
			*changed = true;
		}
		if (parsed.flags == owner->selected.flags) {
			selected = index;
		}
	}
	if (selected == NTFS_LFS_RESTART_PAGES) {
		return NTFS_STALE;
	}
	for (index = 0; index < NTFS_LFS_RESTART_PAGES; index++) {
		ntfs_copy(work->image, work->restart[selected], NTFS_WRITE_CLUSTER_BYTES);
		result = ntfs_fixup(work->image, NTFS_WRITE_CLUSTER_BYTES, "RSTR");
		if (result != NTFS_OK) {
			return result;
		}
		area = (void *)(work->image + owner->selected.area.offset);
		ntfs_put_u16(area->flags, 0);
		dirty = recovery_publication(owner, physical[index],
		    index == 0 ? NTFS_WRITE_RECOVERY_DIRTY_FIRST
			       : NTFS_WRITE_RECOVERY_DIRTY_SECOND);
		result = ntfs_record_protect(
		    work->image, sizeof(work->image), dirty, NTFS_WRITE_CLUSTER_BYTES);
		if (result == NTFS_OK) {
			result = ntfs_write_guard_frame(
			    work->restart[index], NTFS_WRITE_CLUSTER_BYTES, dirty, &work->guard);
		}
		if (result != NTFS_OK) {
			return result;
		}
		ntfs_put_u16(area->flags, NTFS_LOGFILE_RESTART_CLEAN);
		result = ntfs_record_protect(
		    work->image, sizeof(work->image), work->clean[index], NTFS_WRITE_CLUSTER_BYTES);
		if (result == NTFS_OK) {
			result = ntfs_write_guard_frame(
			    dirty, NTFS_WRITE_CLUSTER_BYTES, work->clean[index], &work->guard);
		}
		if (result != NTFS_OK) {
			return result;
		}
	}
	return NTFS_OK;
}

static enum ntfs_result
recovery_log_homes_prepare(struct ntfs_write_batch_recovery *owner, struct ntfs_stream *log,
    const struct ntfs_write_batch_pages *pages, struct ntfs_batch_recovery_workspace *work)
{
	const struct ntfs_write_batch_page *page;
	uint8_t *image;
	uint64_t physical;
	size_t index;
	enum ntfs_result result;

	for (index = 0; index < ntfs_write_batch_pages_count(pages); index++) {
		page = ntfs_write_batch_pages_get(pages, index);
		result = ntfs_batch_recovery_mapping(log, page->offset, &physical);
		if (result == NTFS_OK) {
			result = ntfs_batch_recovery_read(
			    owner, physical, work->before, sizeof(work->before));
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
			continue;
		}
		image = recovery_publication(owner, physical, NTFS_WRITE_RECOVERY_LOG_HOMES);
		ntfs_copy(image, page->protected_bytes, NTFS_WRITE_CLUSTER_BYTES);
		result =
		    ntfs_write_guard_frame(work->before, sizeof(work->before), image, &work->guard);
		if (result != NTFS_OK) {
			return result;
		}
	}
	return NTFS_OK;
}

static enum ntfs_result
recovery_abort_prepare(struct ntfs_write_batch_recovery *owner, struct ntfs_stream *log,
    const struct ntfs_write_batch_pages *pages, struct ntfs_batch_recovery_workspace *work)
{
	const struct ntfs_write_batch_page *page;
	uint8_t *home, *copy;
	uint64_t physical, copy_physical;
	size_t index, slot;
	enum ntfs_result result;

	owner->abort_end = SIZE_MAX;
	if (pages == NULL) {
		return NTFS_OK;
	}
	for (slot = 0; slot < NTFS_LFS_LEGACY_TAIL_PAGES; slot++) {
		result = ntfs_batch_recovery_mapping(
		    log, (NTFS_LFS_RESTART_PAGES + slot) * NTFS_WRITE_CLUSTER_BYTES, &physical);
		if (result == NTFS_OK) {
			result = ntfs_batch_recovery_read(
			    owner, physical, work->copy[slot], NTFS_WRITE_CLUSTER_BYTES);
		}
		if (result != NTFS_OK) {
			return result;
		}
	}
	for (index = 0; index < ntfs_write_batch_pages_count(pages); index++) {
		page = ntfs_write_batch_pages_get(pages, index);
		slot = index % NTFS_LFS_LEGACY_TAIL_PAGES;
		result = ntfs_batch_recovery_mapping(log, page->offset, &physical);
		if (result != NTFS_OK) {
			return result;
		}
		result = ntfs_batch_recovery_mapping(log,
		    (NTFS_LFS_RESTART_PAGES + slot) * NTFS_WRITE_CLUSTER_BYTES, &copy_physical);
		if (result != NTFS_OK) {
			return result;
		}
		result =
		    ntfs_batch_recovery_read(owner, physical, work->before, sizeof(work->before));
		if (result != NTFS_OK) {
			return result;
		}
		copy = recovery_publication(owner, copy_physical, NTFS_WRITE_RECOVERY_ABORT_COPY);
		home = recovery_publication(owner, physical, NTFS_WRITE_RECOVERY_ABORT_HOME);
		if (index + 1 == ntfs_write_batch_pages_count(pages)) {
			owner->abort_end = owner->count - 2;
		}
		ntfs_copy(home, page->protected_bytes, NTFS_WRITE_CLUSTER_BYTES);
		result =
		    ntfs_write_guard_frame(work->before, sizeof(work->before), home, &work->guard);
		if (result == NTFS_OK) {
			result =
			    ntfs_write_tail_copy_encode(&work->guard, home, page->offset, copy);
		}
		if (result == NTFS_OK) {
			result = ntfs_write_guard_frame(
			    work->copy[slot], NTFS_WRITE_CLUSTER_BYTES, copy, &work->guard);
		}
		if (result != NTFS_OK) {
			return result;
		}
		ntfs_copy(work->copy[slot], copy, NTFS_WRITE_CLUSTER_BYTES);
	}
	return NTFS_OK;
}

static enum ntfs_result
recovery_prepare(struct ntfs_write_batch_recovery *owner)
{
	struct ntfs_batch_recovery_workspace *work;
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *node = NULL;
	struct ntfs_stream *log = NULL;
	struct ntfs_write_batch_pages *original = NULL, *abort = NULL;
	struct ntfs_write_batch_pages *checkpoint = NULL;
	struct ntfs_limits limits;
	struct ntfs_batch_recovery_home *home;
	uint8_t *image;
	size_t index, original_pages, abort_pages;
	bool roots_changed;
	enum ntfs_result result;

	work = ntfs_batch_recovery_allocate(owner, sizeof(*work));
	if (work == NULL) {
		return NTFS_NO_MEMORY;
	}
	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	result = ntfs_batch_recovery_bootstrap(owner, work);
	if (result == NTFS_OK) {
		result = ntfs_mount_journal(&owner->reader, &limits, &volume);
	}
	if (result == NTFS_OK) {
		result = ntfs_batch_checkpoint_roots_capture(owner, volume, work);
	}
	if (result == NTFS_OK) {
		result = ntfs_batch_recovery_capture(owner, volume, work);
	}
	owner->checkpoint.projection_active = false;
	if (volume != NULL) {
		ntfs_unmount(volume);
		volume = NULL;
	}
	owner->view = NTFS_BATCH_RECOVERY_SOURCE;
	if (result == NTFS_OK) {
		result = ntfs_batch_recovery_restore(owner, work);
	}
	if (result == NTFS_OK) {
		result = ntfs_batch_recovery_restore_history(owner, work);
	}
	if (result == NTFS_OK) {
		result = ntfs_batch_recovery_pages(owner, &original, &abort);
	}
	if (result == NTFS_OK) {
		result = ntfs_batch_checkpoint_pages(owner, &checkpoint);
	}
	if (result != NTFS_OK) {
		goto done;
	}
	owner->view = NTFS_BATCH_RECOVERY_BEFORE;
	result = ntfs_mount(&owner->reader, &limits, &volume);
	if (result == NTFS_OK) {
		result = ntfs_node_by_number(volume, NTFS_LOGFILE_RECORD, &node);
	}
	if (result == NTFS_OK) {
		result = ntfs_stream_open(node, NULL, 0, &log);
	}
	if (result != NTFS_OK) {
		goto done;
	}
	if (log->resident || log->metadata_only || log->flags != 0 || log->compression_unit != 0 ||
	    log->initialized != log->size || log->size != owner->selected.file_bytes) {
		result = NTFS_UNSUPPORTED;
		goto done;
	}
	original_pages = ntfs_write_batch_pages_count(original);
	abort_pages = ntfs_write_batch_pages_count(abort);
	owner->capacity =
	    2 * NTFS_LFS_RESTART_PAGES + original_pages + 2 * abort_pages + owner->homes;
	if (owner->checkpoint.pending) {
		owner->capacity +=
		    ntfs_write_batch_pages_count(checkpoint) + 2 * NTFS_LFS_RESTART_PAGES;
	}
	owner->publication =
	    ntfs_batch_recovery_allocate(owner, owner->capacity * sizeof(*owner->publication));
	owner->allocation_bytes =
	    owner->capacity * NTFS_WRITE_CLUSTER_BYTES + owner->backend.alignment - 1u;
	owner->allocation = ntfs_batch_recovery_allocate(owner, owner->allocation_bytes);
	if (owner->publication == NULL || owner->allocation == NULL) {
		result = NTFS_NO_MEMORY;
		goto done;
	}
	owner->frames = (void *)(((uintptr_t)owner->allocation + owner->backend.alignment - 1u) &
	    ~(uintptr_t)(owner->backend.alignment - 1u));
	if (owner->checkpoint.pending) {
		/* A checkpoint may discard only a fully settled prefix. Ordinary log
		 * reconstruction must require no repair, and no undo may remain. */
		result = recovery_log_homes_prepare(owner, log, original, work);
		if (result == NTFS_OK && (owner->count != 0 || abort != NULL)) {
			result = NTFS_STALE;
		}
		if (result == NTFS_OK) {
			result = ntfs_batch_checkpoint_prepare(owner, log, checkpoint, work);
		}
		goto done;
	}
	result = recovery_restarts_prepare(owner, log, work, &roots_changed);
	if (result == NTFS_OK) {
		result = recovery_log_homes_prepare(owner, log, original, work);
	}
	if (result == NTFS_OK) {
		result = recovery_abort_prepare(owner, log, abort, work);
	}
	for (index = 0; result == NTFS_OK && owner->committed && index < owner->homes; index++) {
		home = &owner->home[index];
		if (ntfs_equal(home->source, home->after, sizeof(home->source))) {
			continue;
		}
		image = recovery_publication(owner, home->physical, NTFS_WRITE_RECOVERY_FILE_HOMES);
		ntfs_copy(image, home->after, NTFS_WRITE_CLUSTER_BYTES);
	}
	if (result == NTFS_OK) {
		if (owner->count == NTFS_LFS_RESTART_PAGES && !roots_changed) {
			owner->count = 0;
		} else {
			for (index = 0; index < NTFS_LFS_RESTART_PAGES; index++) {
				image =
				    recovery_publication(owner, owner->publication[index].physical,
					index == 0 ? NTFS_WRITE_RECOVERY_CLEAN_FIRST
						   : NTFS_WRITE_RECOVERY_CLEAN_SECOND);
				ntfs_copy(image, work->clean[index], NTFS_WRITE_CLUSTER_BYTES);
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
	ntfs_write_batch_pages_close(original);
	ntfs_write_batch_pages_close(abort);
	ntfs_write_batch_pages_close(checkpoint);
	ntfs_batch_recovery_release(owner, work, sizeof(*work));
	return result;
}

enum ntfs_result
ntfs_write_batch_recover_prepare(
    const struct ntfs_overwrite_environment *backend, struct ntfs_write_batch_recovery **out)
{
	struct ntfs_write_batch_recovery *owner;
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
	owner->live = sizeof(*owner);
	owner->reader = (struct ntfs_environment){NTFS_API_VERSION, owner,
	    backend->reader.size_bytes, ntfs_batch_recovery_overlay_read,
	    ntfs_batch_recovery_allocate, ntfs_batch_recovery_release};
	result = recovery_prepare(owner);
	if (result != NTFS_OK) {
		ntfs_write_batch_recovery_close(owner);
		return result;
	}
	recovery_analysis_close(owner);
	owner->prepared = true;
	*out = owner;
	return NTFS_OK;
}

static bool
recovery_output_separate(
    const struct ntfs_write_batch_recovery *owner, const void *out, size_t bytes)
{
	return ntfs_pointer_ranges_separate(owner, sizeof(*owner), out, bytes) &&
	    ntfs_pointer_ranges_separate(
		owner->publication, owner->capacity * sizeof(*owner->publication), out, bytes) &&
	    ntfs_pointer_ranges_separate(owner->allocation, owner->allocation_bytes, out, bytes);
}

enum ntfs_result
ntfs_write_batch_recover_execute(struct ntfs_write_batch_recovery *owner, bool *poisoned,
    struct ntfs_write_recovery_report *report)
{
	const struct ntfs_write_batch_recovery_publication *step;
	size_t index, transferred;
	enum ntfs_result result = NTFS_OK;

	if (owner == NULL || poisoned == NULL || report == NULL ||
	    !recovery_output_separate(owner, poisoned, sizeof(*poisoned)) ||
	    !recovery_output_separate(owner, report, sizeof(*report)) ||
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
	report->reconstructed_files = owner->reconstructed_files;
	if (owner->checkpoint.pending) {
		report->barriers++;
		result = owner->backend.persist(owner->backend.reader.context);
		if (result == NTFS_OK) {
			report->homes_persisted = true;
			report->durable_stage = NTFS_WRITE_RECOVERY_SETTLED_HOMES;
		}
	}
	for (index = 0; result == NTFS_OK && index < owner->count; index++) {
		step = &owner->publication[index];
		transferred = 0;
		report->writes++;
		result = owner->backend.write(owner->backend.reader.context, step->physical,
		    step->image, NTFS_WRITE_CLUSTER_BYTES, &transferred);
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
		report->durable_stage = step->stage;
		if (step->stage == NTFS_WRITE_RECOVERY_ABORT_COPY && index == owner->abort_end) {
			report->compensation_persisted = true;
		}
		if (step->stage == NTFS_WRITE_RECOVERY_CLEAN_FIRST ||
		    step->stage == NTFS_WRITE_RECOVERY_CLEAN_SECOND) {
			report->homes_persisted = true;
		}
	}
	if (result == NTFS_OK && owner->count == 0) {
		report->barriers++;
		result = owner->backend.persist(owner->backend.reader.context);
		if (result != NTFS_OK) {
			result = NTFS_IO;
		}
	}
	if (result == NTFS_OK) {
		report->homes_persisted = true;
		report->completed = true;
	} else {
		*poisoned = true;
	}
	report->poisoned = *poisoned;
	return result;
}
