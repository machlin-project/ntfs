/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "pointer_range.h"
#include "write_batch_execute.h"
#include <ntfs/record.h>

struct ntfs_write_batch_execution {
	struct ntfs_overwrite_environment backend;
	struct ntfs_environment reader;
	struct ntfs_write_batch_publication *publication;
	uint8_t *allocation, *frames;
	size_t live, allocation_bytes, capacity, count;
	uint64_t read_calls, read_bytes, allocations, allocated_bytes;
	bool prepared;
};

struct batch_execute_workspace {
	struct ntfs_write_history_workspace history_work;
	struct ntfs_write_history history;
	struct ntfs_write_journal_workspace guard;
	struct ntfs_validation_report validation;
	uint8_t before[NTFS_WRITE_CLUSTER_BYTES], image[NTFS_WRITE_CLUSTER_BYTES];
	uint8_t copy[NTFS_LFS_LEGACY_TAIL_PAGES][NTFS_WRITE_CLUSTER_BYTES];
};

struct batch_home {
	size_t publication;
	uint8_t changed_slots;
};

static void *
batch_allocate(void *context, size_t bytes)
{
	struct ntfs_write_batch_execution *owner = context;
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
batch_release(void *context, void *memory, size_t bytes)
{
	struct ntfs_write_batch_execution *owner = context;

	if (memory != NULL) {
		owner->backend.reader.release(owner->backend.reader.context, memory, bytes);
		owner->live -= bytes;
	}
}

static enum ntfs_result
batch_read(void *context, uint64_t physical, void *memory, size_t bytes)
{
	struct ntfs_write_batch_execution *owner = context;

	if (!ntfs_bounds(physical, bytes, owner->reader.size_bytes) ||
	    owner->read_calls == NTFS_DEFAULT_OPERATION_READ_CALLS ||
	    bytes > NTFS_DEFAULT_OPERATION_READ_BYTES - owner->read_bytes) {
		return NTFS_RANGE;
	}
	owner->read_calls++;
	owner->read_bytes += bytes;
	return owner->backend.reader.read(owner->backend.reader.context, physical, memory, bytes);
}

void
ntfs_write_batch_execution_close(struct ntfs_write_batch_execution *owner)
{
	struct ntfs_environment environment;

	if (owner == NULL) {
		return;
	}
	environment = owner->backend.reader;
	batch_release(owner, owner->allocation, owner->allocation_bytes);
	batch_release(owner, owner->publication, owner->capacity * sizeof(*owner->publication));
	environment.release(environment.context, owner, sizeof(*owner));
}

size_t
ntfs_write_batch_execution_count(const struct ntfs_write_batch_execution *owner)
{
	return owner == NULL ? 0 : owner->count;
}

const struct ntfs_write_batch_publication *
ntfs_write_batch_execution_get(const struct ntfs_write_batch_execution *owner, size_t index)
{
	return owner == NULL || index >= owner->count ? NULL : &owner->publication[index];
}

static uint8_t *
publication(struct ntfs_write_batch_execution *owner, size_t index, uint64_t physical,
    enum ntfs_write_execution_stage stage, bool barrier)
{
	uint8_t *image = owner->frames + index * NTFS_WRITE_CLUSTER_BYTES;

	owner->publication[index] =
	    (struct ntfs_write_batch_publication){physical, image, stage, barrier};
	return image;
}

static enum ntfs_result
log_physical(const struct ntfs_stream *log, uint64_t offset, uint64_t *physical)
{
	const struct ntfs_run *run;
	uint64_t vcn;

	if (offset % NTFS_WRITE_CLUSTER_BYTES != 0 ||
	    !ntfs_bounds(offset, NTFS_WRITE_CLUSTER_BYTES, log->initialized)) {
		return NTFS_CORRUPT;
	}
	vcn = offset / NTFS_WRITE_CLUSTER_BYTES;
	run = ntfs_run_find(log, vcn);
	if (run == NULL || run->lcn == NTFS_HOLE ||
	    run->lcn > UINT64_MAX / NTFS_WRITE_CLUSTER_BYTES - (vcn - run->vcn)) {
		return NTFS_CORRUPT;
	}
	*physical = (run->lcn + vcn - run->vcn) * NTFS_WRITE_CLUSTER_BYTES;
	return NTFS_OK;
}

static enum ntfs_result
prepare_restarts(struct ntfs_write_batch_execution *owner, struct ntfs_stream *log,
    struct batch_execute_workspace *work)
{
	struct ntfs_logfile_restart restart;
	struct ntfs_logfile_client client;
	struct ntfs_disk_log_restart_area *area;
	uint64_t physical;
	uint8_t *dirty, *clean;
	size_t index;
	enum ntfs_result result;

	for (index = 0; index < NTFS_LFS_RESTART_PAGES; index++) {
		result = log_physical(log, index * NTFS_WRITE_CLUSTER_BYTES, &physical);
		if (result == NTFS_OK) {
			result = batch_read(owner, physical, work->before, sizeof(work->before));
		}
		if (result == NTFS_OK) {
			result = ntfs_logfile_restart_decode(work->before, sizeof(work->before),
			    log->size, work->image, sizeof(work->image), &restart);
		}
		if (result != NTFS_OK) {
			return result;
		}
		if (restart.major != NTFS_LFS_MAJOR_LEGACY ||
		    restart.minor != NTFS_LFS_MINOR_LEGACY ||
		    restart.system_page_bytes != NTFS_WRITE_CLUSTER_BYTES ||
		    restart.log_page_bytes != NTFS_WRITE_CLUSTER_BYTES ||
		    restart.file_bytes != work->history.selected.file_bytes ||
		    restart.sequence_bits != work->history.selected.sequence_bits ||
		    restart.record_header_bytes != sizeof(struct ntfs_disk_log_record) ||
		    restart.page_data_offset != NTFS_WRITE_LOG_DATA_OFFSET ||
		    restart.client_count != 1 || restart.in_use_head != 0 ||
		    restart.flags != NTFS_LOGFILE_RESTART_CLEAN) {
			return NTFS_UNSUPPORTED;
		}
		result = ntfs_logfile_client_decode(work->image + restart.clients.offset,
		    sizeof(struct ntfs_disk_log_client), &client);
		if (result != NTFS_OK) {
			return result;
		}
		if (client.sequence != work->history.client.sequence ||
		    client.oldest_lsn != work->history.client.oldest_lsn ||
		    client.restart_lsn != work->history.client.restart_lsn ||
		    client.name_length != work->history.client.name_length ||
		    !ntfs_equal(client.name, work->history.client.name, sizeof(client.name))) {
			return NTFS_STALE;
		}
		area = (void *)(work->image + restart.area.offset);
		ntfs_put_u16(area->flags, 0);
		dirty = publication(owner, index, physical,
		    index == 0 ? NTFS_WRITE_EXECUTION_DIRTY_FIRST
			       : NTFS_WRITE_EXECUTION_DIRTY_SECOND,
		    true);
		result = ntfs_record_protect(
		    work->image, sizeof(work->image), dirty, NTFS_WRITE_CLUSTER_BYTES);
		if (result == NTFS_OK) {
			result = ntfs_write_guard_frame(
			    work->before, sizeof(work->before), dirty, &work->guard);
		}
		if (result != NTFS_OK) {
			return result;
		}
		ntfs_put_u16(area->flags, NTFS_LOGFILE_RESTART_CLEAN);
		clean = publication(owner, owner->count - NTFS_LFS_RESTART_PAGES + index, physical,
		    index == 0 ? NTFS_WRITE_EXECUTION_CLEAN_FIRST
			       : NTFS_WRITE_EXECUTION_CLEAN_SECOND,
		    true);
		result = ntfs_record_protect(
		    work->image, sizeof(work->image), clean, NTFS_WRITE_CLUSTER_BYTES);
		if (result == NTFS_OK) {
			result = ntfs_write_guard_frame(
			    dirty, NTFS_WRITE_CLUSTER_BYTES, clean, &work->guard);
		}
		if (result != NTFS_OK) {
			return result;
		}
	}
	return NTFS_OK;
}

static enum ntfs_result
prepare_log_page(struct ntfs_write_batch_execution *owner, struct ntfs_stream *log,
    struct batch_execute_workspace *work, const struct ntfs_write_batch_page *page,
    size_t page_index, size_t output, bool terminal)
{
	uint64_t physical, copy_physical;
	uint8_t *home, *copy;
	size_t slot = page_index % NTFS_LFS_LEGACY_TAIL_PAGES;
	enum ntfs_result result;

	result = log_physical(log, page->offset, &physical);
	if (result == NTFS_OK) {
		result = log_physical(log,
		    (NTFS_LFS_RESTART_PAGES + slot) * NTFS_WRITE_CLUSTER_BYTES, &copy_physical);
	}
	if (result == NTFS_OK) {
		result = batch_read(owner, physical, work->before, sizeof(work->before));
	}
	if (result != NTFS_OK) {
		return result;
	}
	copy = publication(owner, output, copy_physical,
	    terminal ? NTFS_WRITE_EXECUTION_COMMIT_COPY : NTFS_WRITE_EXECUTION_PREPARE_COPY, true);
	home = publication(owner, output + 1, physical,
	    terminal ? NTFS_WRITE_EXECUTION_COMMIT_HOME : NTFS_WRITE_EXECUTION_PREPARE_HOME, true);
	ntfs_copy(home, page->protected_bytes, NTFS_WRITE_CLUSTER_BYTES);
	result = ntfs_write_guard_frame(work->before, sizeof(work->before), home, &work->guard);
	if (result == NTFS_OK) {
		result = ntfs_write_tail_copy_encode(&work->guard, home, page->offset, copy);
	}
	if (result == NTFS_OK) {
		result = ntfs_write_guard_frame(
		    work->copy[slot], NTFS_WRITE_CLUSTER_BYTES, copy, &work->guard);
	}
	if (result == NTFS_OK) {
		ntfs_copy(work->copy[slot], copy, NTFS_WRITE_CLUSTER_BYTES);
	}
	return result;
}

static enum ntfs_result
prepare_homes(struct ntfs_write_batch_execution *owner, const struct ntfs_write_program *program,
    const struct ntfs_write_batch_pages *pages, const struct ntfs_stream *log,
    struct batch_execute_workspace *work, struct batch_home *homes, size_t data_start,
    size_t metadata_start)
{
	struct ntfs_write_mutation_region region, primary;
	const struct ntfs_write_program_update *step;
	struct ntfs_logfile_update update;
	const struct ntfs_run *run;
	const struct ntfs_write_batch_page *last;
	uint8_t *image;
	size_t regions, index, other, slot, offset, data = data_start, metadata = metadata_start,
						    opens;
	enum ntfs_result result;

	regions = ntfs_write_program_regions(program);
	last = ntfs_write_batch_pages_get(pages, ntfs_write_batch_pages_count(pages) - 1);
	if (last == NULL || last->packet < ntfs_write_program_count(program)) {
		return NTFS_CORRUPT;
	}
	opens = last->packet - ntfs_write_program_count(program);
	for (index = 0; index < regions; index++) {
		result = ntfs_write_program_region(program, index, &region);
		if (result != NTFS_OK) {
			return result;
		}
		/* Metadata or DATA cannot overwrite any original journal allocation,
		 * including retained pages outside this particular batch's output. */
		for (other = 0; other < log->run_count; other++) {
			run = &log->runs[other];
			if (run->lcn == NTFS_HOLE ||
			    (region.physical / NTFS_WRITE_CLUSTER_BYTES >= run->lcn &&
				region.physical / NTFS_WRITE_CLUSTER_BYTES - run->lcn <
				    run->length)) {
				return NTFS_CORRUPT;
			}
		}
		result = batch_read(owner, region.physical, work->before, sizeof(work->before));
		if (result != NTFS_OK) {
			return result;
		}
		if (!ntfs_equal(work->before, region.before, region.bytes)) {
			return NTFS_STALE;
		}
		homes[index].publication =
		    region.kind == NTFS_WRITE_MUTATION_DATA ? data++ : metadata++;
		image = publication(owner, homes[index].publication, region.physical,
		    region.kind == NTFS_WRITE_MUTATION_DATA ? NTFS_WRITE_EXECUTION_DATA
							    : NTFS_WRITE_EXECUTION_METADATA_HOME,
		    region.kind != NTFS_WRITE_MUTATION_DATA);
		ntfs_copy(image,
		    region.kind == NTFS_WRITE_MUTATION_DATA ? region.after : region.before,
		    region.bytes);
		if (region.kind == NTFS_WRITE_MUTATION_FILE) {
			for (slot = 0; slot < region.bytes / NTFS_WRITE_RECORD_BYTES; slot++) {
				if ((region.predecessor.file_slots & (1u << slot)) == 0) {
					continue;
				}
				result = ntfs_record_decode(image + slot * NTFS_WRITE_RECORD_BYTES,
				    NTFS_WRITE_RECORD_BYTES, false);
				if (result != NTFS_OK) {
					return result;
				}
			}
		} else if (region.kind == NTFS_WRITE_MUTATION_INDEX &&
		    region.predecessor.index_allocated) {
			result = ntfs_fixup(image, region.bytes, "INDX");
			if (result != NTFS_OK) {
				return result;
			}
		}
	}
	if (data != data_start) {
		owner->publication[data - 1].barrier = true;
	}
	for (index = 0; index < ntfs_write_program_count(program); index++) {
		step = ntfs_write_program_get(program, index);
		if (step == NULL || step->region >= regions) {
			return NTFS_CORRUPT;
		}
		image = owner->frames + homes[step->region].publication * NTFS_WRITE_CLUSTER_BYTES;
		result = ntfs_write_program_apply(program, index, false,
		    ntfs_write_batch_pages_lsn(pages, opens + index), image,
		    NTFS_WRITE_CLUSTER_BYTES);
		if (result != NTFS_OK) {
			return result;
		}
		result = ntfs_write_program_region(program, step->region, &region);
		if (result == NTFS_OK && region.kind == NTFS_WRITE_MUTATION_FILE) {
			result = ntfs_logfile_update_decode(
			    step->payload.data, step->payload.bytes, &update);
			if (result == NTFS_OK && update.redo_operation != NTFS_LOG_OP_NOOP) {
				slot = (size_t)update.cluster_index * NTFS_MST_STRIDE /
				    NTFS_WRITE_RECORD_BYTES;
				homes[step->region].changed_slots |= (uint8_t)(1u << slot);
			}
		}
		if (result != NTFS_OK) {
			return result;
		}
	}
	/* Mirrors copy logical primary slots and their actual generated LSNs, then
	 * receive protection against their own independent physical before image. */
	for (index = 0; index < regions; index++) {
		result = ntfs_write_program_region(program, index, &region);
		if (result != NTFS_OK) {
			return result;
		}
		if (!region.target.mirror) {
			continue;
		}
		for (other = 0; other < regions; other++) {
			result = ntfs_write_program_region(program, other, &primary);
			if (result != NTFS_OK) {
				return result;
			}
			if (primary.kind == NTFS_WRITE_MUTATION_FILE && !primary.target.mirror &&
			    primary.target.reference == region.target.reference &&
			    primary.target.logical_offset == region.target.logical_offset) {
				break;
			}
		}
		if (other == regions) {
			return NTFS_CORRUPT;
		}
		homes[index].changed_slots = homes[other].changed_slots;
		for (slot = 0; slot < region.bytes / NTFS_WRITE_RECORD_BYTES; slot++) {
			if ((homes[index].changed_slots & (1u << slot)) != 0) {
				offset = slot * NTFS_WRITE_RECORD_BYTES;
				ntfs_copy(owner->frames +
					homes[index].publication * NTFS_WRITE_CLUSTER_BYTES +
					offset,
				    owner->frames +
					homes[other].publication * NTFS_WRITE_CLUSTER_BYTES +
					offset,
				    NTFS_WRITE_RECORD_BYTES);
			}
		}
	}
	for (index = 0; index < regions; index++) {
		result = ntfs_write_program_region(program, index, &region);
		if (result != NTFS_OK) {
			return result;
		}
		image = owner->frames + homes[index].publication * NTFS_WRITE_CLUSTER_BYTES;
		if (region.kind == NTFS_WRITE_MUTATION_FILE) {
			for (slot = 0; slot < region.bytes / NTFS_WRITE_RECORD_BYTES; slot++) {
				offset = slot * NTFS_WRITE_RECORD_BYTES;
				if ((homes[index].changed_slots & (1u << slot)) == 0) {
					ntfs_copy(image + offset, region.before + offset,
					    NTFS_WRITE_RECORD_BYTES);
					continue;
				}
				result = ntfs_record_protect(image + offset,
				    NTFS_WRITE_RECORD_BYTES, work->image, sizeof(work->image));
				if (result == NTFS_OK) {
					result = ntfs_write_guard_frame(region.before + offset,
					    NTFS_WRITE_RECORD_BYTES, work->image, &work->guard);
				}
				if (result != NTFS_OK) {
					return result;
				}
				ntfs_copy(image + offset, work->image, NTFS_WRITE_RECORD_BYTES);
			}
		} else if (region.kind == NTFS_WRITE_MUTATION_INDEX) {
			result = ntfs_record_protect(
			    image, region.bytes, work->image, sizeof(work->image));
			if (result == NTFS_OK) {
				result = ntfs_write_guard_frame(
				    region.before, region.bytes, work->image, &work->guard);
			}
			if (result != NTFS_OK) {
				return result;
			}
			ntfs_copy(image, work->image, region.bytes);
		}
	}
	return metadata == owner->count - NTFS_LFS_RESTART_PAGES && data == metadata_start - 2 &&
		data >= data_start
	    ? NTFS_OK
	    : NTFS_CORRUPT;
}

static enum ntfs_result
overlay_read(void *context, uint64_t physical, void *memory, size_t bytes)
{
	struct ntfs_write_batch_execution *owner = context;
	const struct ntfs_write_batch_publication *home;
	uint64_t first, end;
	size_t index;
	enum ntfs_result result;

	result = batch_read(owner, physical, memory, bytes);
	if (result != NTFS_OK) {
		return result;
	}
	for (index = 0; index < owner->count; index++) {
		home = &owner->publication[index];
		if (home->stage != NTFS_WRITE_EXECUTION_DATA &&
		    home->stage != NTFS_WRITE_EXECUTION_METADATA_HOME) {
			continue;
		}
		first = physical > home->physical ? physical : home->physical;
		end = physical + bytes < home->physical + NTFS_WRITE_CLUSTER_BYTES
		    ? physical + bytes
		    : home->physical + NTFS_WRITE_CLUSTER_BYTES;
		if (first < end) {
			ntfs_copy((uint8_t *)memory + first - physical,
			    home->image + first - home->physical, (size_t)(end - first));
		}
	}
	return NTFS_OK;
}

static enum ntfs_result
prepare_batch(struct ntfs_write_batch_execution *owner, const struct ntfs_write_program *program)
{
	struct batch_execute_workspace *work = NULL;
	struct batch_home *homes = NULL;
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *node = NULL;
	struct ntfs_stream *log = NULL;
	struct ntfs_write_batch_pages *pages = NULL;
	struct ntfs_write_batch_pages_input window = {0};
	struct ntfs_write_mutation_region region;
	struct ntfs_limits limits;
	struct ntfs_environment overlay;
	uint64_t physical;
	size_t regions, page_count, index, data_count = 0, data_start, metadata_start;
	enum ntfs_result result = NTFS_NO_MEMORY;

	regions = ntfs_write_program_regions(program);
	work = batch_allocate(owner, sizeof(*work));
	homes = batch_allocate(owner, regions * sizeof(*homes));
	if (work == NULL || homes == NULL) {
		goto done;
	}
	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	result = ntfs_mount(&owner->reader, &limits, &volume);
	if (result != NTFS_OK) {
		goto done;
	}
	if (volume->info.sector_size != NTFS_WRITE_SECTOR_BYTES ||
	    volume->info.cluster_size != NTFS_WRITE_CLUSTER_BYTES ||
	    volume->info.record_size != NTFS_WRITE_RECORD_BYTES ||
	    volume->info.index_size != NTFS_WRITE_CLUSTER_BYTES) {
		result = NTFS_UNSUPPORTED;
		goto done;
	}
	result = ntfs_write_history_capture(volume, &work->history_work, &work->history);
	if (result == NTFS_OK) {
		result = ntfs_write_history_settled(volume, &work->history);
	}
	if (result != NTFS_OK) {
		goto done;
	}
	if (work->history.selected.flags != NTFS_LOGFILE_RESTART_CLEAN ||
	    work->history.history.tail_lsn != 0 || !work->history.history.complete ||
	    !work->history.history.endpoint_verified) {
		result = NTFS_UNSUPPORTED;
		goto done;
	}
	window.restart = work->history.origin;
	window.floor_lsn = work->history.client.oldest_lsn;
	window.tail_lsn = work->history.history.completed_end_lsn;
	window.next_lsn = work->history.history.next_lsn;
	result = ntfs_write_program_pages_prepare(
	    &owner->reader, program, &work->history.client, &window, &pages);
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
	    log->initialized != log->size || log->size != window.restart.file_bytes) {
		result = NTFS_UNSUPPORTED;
		goto done;
	}
	for (index = 0; index < regions; index++) {
		result = ntfs_write_program_region(program, index, &region);
		if (result != NTFS_OK) {
			goto done;
		}
		data_count += region.kind == NTFS_WRITE_MUTATION_DATA;
	}
	page_count = ntfs_write_batch_pages_count(pages);
	if (page_count == 0 || page_count > NTFS_WRITE_BATCH_MAX_PAGES) {
		result = NTFS_CORRUPT;
		goto done;
	}
	owner->capacity = owner->count = 2 * NTFS_LFS_RESTART_PAGES + 2 * page_count + regions;
	owner->publication = batch_allocate(owner, owner->capacity * sizeof(*owner->publication));
	owner->allocation_bytes =
	    owner->capacity * NTFS_WRITE_CLUSTER_BYTES + owner->backend.alignment - 1u;
	owner->allocation = batch_allocate(owner, owner->allocation_bytes);
	if (owner->publication == NULL || owner->allocation == NULL) {
		result = NTFS_NO_MEMORY;
		goto done;
	}
	owner->frames = (void *)(((uintptr_t)owner->allocation + owner->backend.alignment - 1u) &
	    ~(uintptr_t)(owner->backend.alignment - 1u));
	result = prepare_restarts(owner, log, work);
	for (index = 0; result == NTFS_OK && index < NTFS_LFS_LEGACY_TAIL_PAGES; index++) {
		result = log_physical(
		    log, (NTFS_LFS_RESTART_PAGES + index) * NTFS_WRITE_CLUSTER_BYTES, &physical);
		if (result == NTFS_OK) {
			result = batch_read(
			    owner, physical, work->copy[index], NTFS_WRITE_CLUSTER_BYTES);
		}
	}
	for (index = 0; result == NTFS_OK && index + 1 < page_count; index++) {
		result =
		    prepare_log_page(owner, log, work, ntfs_write_batch_pages_get(pages, index),
			index, NTFS_LFS_RESTART_PAGES + 2 * index, false);
	}
	data_start = NTFS_LFS_RESTART_PAGES + 2 * (page_count - 1);
	metadata_start = data_start + data_count + 2;
	if (result == NTFS_OK) {
		result = prepare_log_page(owner, log, work,
		    ntfs_write_batch_pages_get(pages, page_count - 1), page_count - 1,
		    data_start + data_count, true);
	}
	if (result == NTFS_OK) {
		result = prepare_homes(
		    owner, program, pages, log, work, homes, data_start, metadata_start);
	}
	if (result == NTFS_OK) {
		overlay = owner->reader;
		overlay.read = overlay_read;
		result = ntfs_validate(&overlay, &limits, NULL, &work->validation);
		if (result == NTFS_OK && !work->validation.complete) {
			result = NTFS_CORRUPT;
		}
	}
done:
	ntfs_stream_close(log);
	ntfs_node_close(node);
	if (volume != NULL) {
		ntfs_unmount(volume);
	}
	ntfs_write_batch_pages_close(pages);
	batch_release(owner, homes, regions * sizeof(*homes));
	batch_release(owner, work, sizeof(*work));
	return result;
}

enum ntfs_result
ntfs_write_batch_execute_prepare(const struct ntfs_overwrite_environment *backend,
    const struct ntfs_write_program *program, struct ntfs_write_batch_execution **out)
{
	struct ntfs_write_batch_execution *owner;
	enum ntfs_result result;

	if (!ntfs_pointer_ranges_separate(out, sizeof(*out), out, 0) ||
	    (backend != NULL &&
		!ntfs_pointer_ranges_separate(backend, sizeof(*backend), out, sizeof(*out))) ||
	    (program != NULL && !ntfs_write_program_output_separate(program, out, sizeof(*out)))) {
		return NTFS_INVALID;
	}
	*out = NULL;
	if (backend == NULL || program == NULL ||
	    backend->api_version != NTFS_OVERWRITE_API_VERSION ||
	    backend->reader.api_version != NTFS_API_VERSION || backend->reader.read == NULL ||
	    backend->reader.allocate == NULL || backend->reader.release == NULL ||
	    backend->write == NULL || backend->persist == NULL ||
	    backend->alignment < NTFS_WRITE_SECTOR_BYTES ||
	    backend->alignment > NTFS_WRITE_CLUSTER_BYTES ||
	    (backend->alignment & (backend->alignment - 1u)) != 0 ||
	    ntfs_write_program_regions(program) == 0 ||
	    ntfs_write_program_regions(program) > NTFS_WRITE_BATCH_MAX_PACKETS) {
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
	    backend->reader.size_bytes, batch_read, batch_allocate, batch_release};
	result = prepare_batch(owner, program);
	if (result != NTFS_OK) {
		ntfs_write_batch_execution_close(owner);
		return result;
	}
	owner->prepared = true;
	*out = owner;
	return NTFS_OK;
}

static bool
output_separate(const struct ntfs_write_batch_execution *owner, const void *out, size_t bytes)
{
	return ntfs_pointer_ranges_separate(owner, sizeof(*owner), out, bytes) &&
	    ntfs_pointer_ranges_separate(
		owner->publication, owner->capacity * sizeof(*owner->publication), out, bytes) &&
	    ntfs_pointer_ranges_separate(owner->allocation, owner->allocation_bytes, out, bytes);
}

enum ntfs_result
ntfs_write_batch_execute(struct ntfs_write_batch_execution *owner, bool *poisoned,
    struct ntfs_write_execution_report *report)
{
	const struct ntfs_write_batch_publication *step;
	size_t index, transferred;
	enum ntfs_result result = NTFS_OK;

	if (owner == NULL || poisoned == NULL || report == NULL ||
	    !output_separate(owner, poisoned, sizeof(*poisoned)) ||
	    !output_separate(owner, report, sizeof(*report)) ||
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
	for (index = 0; index < owner->count; index++) {
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
		if (step->stage == NTFS_WRITE_EXECUTION_DATA) {
			report->data_bytes += NTFS_WRITE_CLUSTER_BYTES;
		}
		if (!step->barrier) {
			continue;
		}
		report->barriers++;
		result = owner->backend.persist(owner->backend.reader.context);
		if (result != NTFS_OK) {
			result = NTFS_IO;
			break;
		}
		report->durable_stage = step->stage;
		if (step->stage == NTFS_WRITE_EXECUTION_DATA) {
			report->data_persisted = true;
		} else if (step->stage == NTFS_WRITE_EXECUTION_COMMIT_COPY) {
			report->commit_persisted = true;
		}
	}
	if (result == NTFS_OK) {
		report->completed = true;
	} else {
		*poisoned = true;
	}
	report->poisoned = *poisoned;
	return result;
}
