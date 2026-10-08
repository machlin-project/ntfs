/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "logfile_source_internal.h"

static enum ntfs_result ntfs_logfile_load_legacy_page(struct ntfs_logfile *source, uint64_t offset,
    struct ntfs_logfile_report *work, struct ntfs_logfile_legacy_copies *copies,
    struct ntfs_logfile_page_view *out);
static enum ntfs_result ntfs_logfile_fast_target(struct ntfs_logfile *source, uint32_t *target);
static enum ntfs_result ntfs_logfile_reload_fast_copy(struct ntfs_logfile *source,
    struct ntfs_logfile_report *work, const struct ntfs_logfile_fast_copies *copies, unsigned index,
    struct ntfs_logfile_page_view *out);
static bool ntfs_logfile_same_fast_prefix(const struct ntfs_logfile_restart *restart,
    const struct ntfs_logfile_page *a, const uint8_t *a_bytes, const struct ntfs_logfile_page *b,
    const uint8_t *b_bytes);
static enum ntfs_result ntfs_logfile_load_fast_page(struct ntfs_logfile *source, uint64_t offset,
    struct ntfs_logfile_report *work, struct ntfs_logfile_fast_copies *copies,
    struct ntfs_logfile_page_view *out);
static enum ntfs_result ntfs_logfile_load_history_page(struct ntfs_logfile *source, uint64_t offset,
    uint64_t lsn, struct ntfs_logfile_report *work, const struct ntfs_logfile_record_copies *copies,
    struct ntfs_logfile_page_view *out);

enum ntfs_result
ntfs_logfile_load_page(struct ntfs_logfile *source, uint64_t offset,
    struct ntfs_logfile_report *work, struct ntfs_logfile_page_view *out)
{
	struct ntfs_logfile_page_view view = {0};
	const struct ntfs_logfile_restart *restart = &source->restart;
	enum ntfs_result result;

	if (offset % restart->log_page_bytes != 0 ||
	    offset < (uint64_t)NTFS_LFS_RESTART_PAGES * restart->system_page_bytes ||
	    !ntfs_bounds(offset, restart->log_page_bytes, restart->usable_bytes)) {
		return NTFS_INVALID;
	}
	/* Saturation disables reuse rather than allowing an old generation to match. */
	if (source->page_generation != UINT64_MAX) {
		source->page_generation++;
	}
	result =
	    ntfs_logfile_source_read(source, offset, source->raw, restart->log_page_bytes, work);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_logfile_page_decode(source->raw, restart->log_page_bytes, restart,
	    source->scratch, source->limits.max_page_bytes, &view.page);
	if (result != NTFS_OK) {
		return result;
	}
	view.offset = offset;
	view.storage = offset >= restart->circular_offset ? NTFS_LOGFILE_CIRCULAR
	    : restart->major == NTFS_LFS_MAJOR_FAST	  ? NTFS_LOGFILE_FAST_STORAGE
							  : NTFS_LOGFILE_LEGACY_TAIL;
	*out = view;
	return NTFS_OK;
}

enum ntfs_result
ntfs_logfile_read_page(struct ntfs_logfile *source, uint64_t offset, void *bytes, size_t capacity,
    struct ntfs_logfile_page_view *out)
{
	struct ntfs_logfile_report work = {0};
	struct ntfs_logfile_page_view view;
	const struct ntfs_logfile_restart *restart;
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (source == NULL || bytes == NULL) {
		return NTFS_INVALID;
	}
	restart = &source->restart;
	if (offset % restart->log_page_bytes != 0 ||
	    offset < (uint64_t)NTFS_LFS_RESTART_PAGES * restart->system_page_bytes ||
	    !ntfs_bounds(offset, restart->log_page_bytes, restart->usable_bytes)) {
		return NTFS_INVALID;
	}
	if (capacity < restart->log_page_bytes) {
		return NTFS_RANGE;
	}
	result = ntfs_logfile_load_page(source, offset, &work, &view);
	if (result == NTFS_OK) {
		ntfs_copy(bytes, source->scratch, restart->log_page_bytes);
		*out = view;
	}
	return result;
}

bool
ntfs_logfile_same_written_prefix(const struct ntfs_logfile_restart *restart,
    const struct ntfs_logfile_page *left_page, const uint8_t *a_bytes,
    const struct ntfs_logfile_page *right_page, const uint8_t *b_bytes)
{
	return left_page->flags == right_page->flags &&
	    left_page->next_record_offset == right_page->next_record_offset &&
	    left_page->next_record_offset >= restart->page_data_offset &&
	    ntfs_equal(a_bytes + restart->page_data_offset, b_bytes + restart->page_data_offset,
		left_page->next_record_offset - restart->page_data_offset);
}

enum ntfs_result
ntfs_logfile_scan_legacy_copies(struct ntfs_logfile *source, struct ntfs_logfile_report *work,
    struct ntfs_logfile_legacy_copies *copies)
{
	const struct ntfs_logfile_restart *restart = &source->restart;
	struct ntfs_logfile_page_view *page;
	uint64_t offset;
	unsigned index;
	enum ntfs_result result;

	for (index = 0; index < NTFS_LFS_LEGACY_TAIL_PAGES; index++) {
		page = &copies->pages[index];
		offset = (uint64_t)NTFS_LFS_RESTART_PAGES * restart->system_page_bytes +
		    (uint64_t)index * restart->log_page_bytes;
		result = ntfs_logfile_load_page(source, offset, work, page);
		if (source->backend_failed ||
		    (result != NTFS_OK && result != NTFS_CORRUPT && result != NTFS_NOT_FOUND)) {
			return result;
		}
		if (result != NTFS_OK || page->page.copy_value < restart->circular_offset ||
		    page->page.copy_value % restart->log_page_bytes != 0 ||
		    !ntfs_bounds(
			page->page.copy_value, restart->log_page_bytes, restart->usable_bytes)) {
			continue;
		}
		if ((page->page.flags &
			~(NTFS_LOGFILE_PAGE_RECORD_END | NTFS_LOGFILE_PAGE_CLIENT_RESTART)) != 0) {
			return NTFS_UNSUPPORTED;
		}
		copies->available[index] = true;
		if (index == 0) {
			ntfs_copy(copies->comparison, source->scratch, restart->log_page_bytes);
		} else if (copies->available[0] &&
		    copies->pages[0].page.copy_value == page->page.copy_value &&
		    copies->pages[0].page.last_end_lsn == page->page.last_end_lsn &&
		    !ntfs_logfile_same_written_prefix(restart, &copies->pages[0].page,
			copies->comparison, &page->page, source->scratch)) {
			return NTFS_UNSUPPORTED;
		}
	}
	return NTFS_OK;
}

static enum ntfs_result
ntfs_logfile_load_legacy_page(struct ntfs_logfile *source, uint64_t offset,
    struct ntfs_logfile_report *work, struct ntfs_logfile_legacy_copies *copies,
    struct ntfs_logfile_page_view *out)
{
	const struct ntfs_logfile_restart *restart = &source->restart;
	const struct ntfs_logfile_page_view *candidate = NULL;
	struct ntfs_logfile_page_view circular = {0}, tail = {0};
	enum ntfs_result circular_result, result;
	unsigned index;

	for (index = 0; index < NTFS_LFS_LEGACY_TAIL_PAGES; index++) {
		if (copies->available[index] && copies->pages[index].page.copy_value == offset &&
		    (candidate == NULL ||
			copies->pages[index].page.last_end_lsn > candidate->page.last_end_lsn)) {
			candidate = &copies->pages[index];
		}
	}
	circular_result = ntfs_logfile_load_page(source, offset, work, &circular);
	if (source->backend_failed ||
	    (circular_result != NTFS_OK && circular_result != NTFS_CORRUPT &&
		circular_result != NTFS_NOT_FOUND)) {
		return circular_result;
	}
	if (circular_result == NTFS_OK &&
	    (circular.page.flags &
		~(NTFS_LOGFILE_PAGE_RECORD_END | NTFS_LOGFILE_PAGE_CLIENT_RESTART)) != 0) {
		return NTFS_UNSUPPORTED;
	}
	if (candidate == NULL ||
	    (circular_result == NTFS_OK &&
		circular.page.last_end_lsn > candidate->page.last_end_lsn)) {
		if (circular_result == NTFS_OK) {
			*out = circular;
		}
		return circular_result;
	}
	if (candidate->page.last_end_lsn == 0 ||
	    (candidate->page.flags & NTFS_LOGFILE_PAGE_RECORD_END) == 0 ||
	    candidate->page.next_record_offset < restart->page_data_offset) {
		return NTFS_UNSUPPORTED;
	}
	if (circular_result == NTFS_OK) {
		ntfs_copy(copies->comparison, source->scratch, restart->log_page_bytes);
	}
	result = ntfs_logfile_load_page(source, candidate->offset, work, &tail);
	if (result != NTFS_OK) {
		return result;
	}
	if (tail.page.copy_value != candidate->page.copy_value ||
	    tail.page.last_end_lsn != candidate->page.last_end_lsn ||
	    tail.page.flags != candidate->page.flags ||
	    tail.page.next_record_offset != candidate->page.next_record_offset) {
		return NTFS_STALE;
	}
	if (circular_result == NTFS_OK && circular.page.last_end_lsn == tail.page.last_end_lsn &&
	    !ntfs_logfile_same_written_prefix(
		restart, &circular.page, copies->comparison, &tail.page, source->scratch)) {
		return NTFS_UNSUPPORTED;
	}
	*out = tail;
	return NTFS_OK;
}

static enum ntfs_result
ntfs_logfile_fast_target(struct ntfs_logfile *source, uint32_t *target)
{
	const struct ntfs_disk_log_fast_page *header = (const void *)source->scratch;
	uint32_t usa_end;

	usa_end = ntfs_u16(header->common.mst.usa_offset) +
	    (uint32_t)ntfs_u16(header->common.mst.usa_count) * NTFS_MST_WORD_BYTES;
	if (usa_end > offsetof(struct ntfs_disk_log_fast_page, file_offset)) {
		return NTFS_UNSUPPORTED;
	}
	*target = ntfs_u32(header->file_offset);
	return NTFS_OK;
}

enum ntfs_result
ntfs_logfile_observe_target(
    struct ntfs_logfile *source, struct ntfs_logfile_page_observation *observation)
{
	const struct ntfs_logfile_restart *restart = &source->restart;
	const struct ntfs_logfile_page *page = &observation->page;
	struct ntfs_logfile_lsn location;
	uint64_t target;
	uint32_t fast_offset, known_flags;
	enum ntfs_result result;

	known_flags = NTFS_LOGFILE_PAGE_RECORD_END | NTFS_LOGFILE_PAGE_CLIENT_RESTART;
	if ((page->flags & ~known_flags) != 0) {
		return NTFS_UNSUPPORTED;
	}
	if (observation->storage == NTFS_LOGFILE_LEGACY_TAIL) {
		target = page->copy_value;
	} else if (observation->storage == NTFS_LOGFILE_FAST_STORAGE) {
		if (restart->system_page_bytes != NTFS_LFS_FAST_PAGE_BYTES ||
		    restart->log_page_bytes != NTFS_LFS_FAST_PAGE_BYTES ||
		    restart->page_data_offset < sizeof(struct ntfs_disk_log_fast_page)) {
			return NTFS_UNSUPPORTED;
		}
		result = ntfs_logfile_fast_target(source, &fast_offset);
		if (result != NTFS_OK) {
			return result;
		}
		target = fast_offset;
	} else {
		target = observation->offset;
	}
	observation->target_offset = target;
	if (target < restart->circular_offset || target % restart->log_page_bytes != 0 ||
	    !ntfs_bounds(target, restart->log_page_bytes, restart->usable_bytes)) {
		return NTFS_CORRUPT;
	}
	if (observation->storage != NTFS_LOGFILE_LEGACY_TAIL) {
		result = ntfs_logfile_lsn_decode(restart, page->copy_value, &location);
		if (result != NTFS_OK) {
			return result;
		}
		if (page->copy_value < page->last_end_lsn) {
			return NTFS_CORRUPT;
		}
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_logfile_visit_pages(struct ntfs_logfile *source, ntfs_logfile_page_visitor visitor,
    void *context, struct ntfs_logfile_inventory *out)
{
	struct ntfs_logfile_report work = {0};
	struct ntfs_logfile_page_observation observation;
	struct ntfs_logfile_page_view page = {0};
	const struct ntfs_logfile_restart *restart;
	const struct ntfs_disk_mst *header;
	uint64_t offset, total_bytes, epoch;
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (source == NULL) {
		return NTFS_INVALID;
	}
	restart = &source->restart;
	header = (const void *)source->raw;
	offset = (uint64_t)NTFS_LFS_RESTART_PAGES * restart->system_page_bytes;
	total_bytes = restart->usable_bytes - offset;
	out->next_offset = offset;
	out->total_pages = (uint32_t)(total_bytes / restart->log_page_bytes);
	if (out->total_pages > source->limits.max_read_calls ||
	    total_bytes > source->limits.max_read_bytes) {
		return NTFS_RANGE;
	}
	while (offset < restart->usable_bytes) {
		ntfs_zero(&observation, sizeof(observation));
		observation.offset = offset;
		observation.storage = offset >= restart->circular_offset ? NTFS_LOGFILE_CIRCULAR
		    : restart->major == NTFS_LFS_MAJOR_FAST		 ? NTFS_LOGFILE_FAST_STORAGE
									 : NTFS_LOGFILE_LEGACY_TAIL;
		observation.target_result = NTFS_INVALID;
		result = ntfs_logfile_load_page(source, offset, &work, &page);
		out->read_calls = work.read_calls;
		out->read_bytes = work.read_bytes;
		if (source->backend_failed ||
		    (result != NTFS_OK && result != NTFS_CORRUPT && result != NTFS_NOT_FOUND)) {
			return result;
		}
		if (result == NTFS_CORRUPT &&
		    !ntfs_equal(header->magic, "RCRD", sizeof(header->magic))) {
			result = NTFS_NOT_FOUND;
		}
		observation.result = result;
		out->examined_pages++;
		if (result == NTFS_OK) {
			observation.page = page.page;
			out->decoded_pages++;
			observation.target_result =
			    ntfs_logfile_observe_target(source, &observation);
			if (observation.target_result == NTFS_UNSUPPORTED) {
				out->unsupported_targets++;
			} else if (observation.target_result != NTFS_OK) {
				out->invalid_targets++;
			} else {
				epoch = observation.storage == NTFS_LOGFILE_LEGACY_TAIL
				    ? observation.page.last_end_lsn
				    : observation.page.copy_value;
				if (epoch > out->max_observed_epoch_lsn) {
					out->max_observed_epoch_lsn = epoch;
				}
				if ((observation.page.flags & NTFS_LOGFILE_PAGE_RECORD_END) != 0 &&
				    observation.page.last_end_lsn > out->max_observed_end_lsn) {
					out->max_observed_end_lsn = observation.page.last_end_lsn;
				}
			}
		} else if (result == NTFS_NOT_FOUND) {
			out->missing_pages++;
		} else {
			out->corrupt_pages++;
		}
		if (visitor != NULL) {
			result = visitor(context, &observation);
			if (result != NTFS_OK) {
				return result;
			}
		}
		out->visited_pages++;
		offset += restart->log_page_bytes;
		out->next_offset = offset;
	}
	out->complete = true;
	return NTFS_OK;
}

enum ntfs_result
ntfs_logfile_scan_fast_copies(struct ntfs_logfile *source, struct ntfs_logfile_report *work,
    struct ntfs_logfile_fast_copies *copies)
{
	const struct ntfs_logfile_restart *restart = &source->restart;
	struct ntfs_logfile_page_view *page;
	struct ntfs_logfile_lsn location;
	uint64_t offset;
	uint32_t target;
	unsigned index;
	enum ntfs_result result;

	for (index = 0; index < NTFS_LOGFILE_FAST_COPY_PAGES; index++) {
		page = &copies->pages[index];
		offset = (uint64_t)NTFS_LFS_RESTART_PAGES * restart->system_page_bytes +
		    (uint64_t)index * restart->log_page_bytes;
		result = ntfs_logfile_load_page(source, offset, work, page);
		if (source->backend_failed ||
		    (result != NTFS_OK && result != NTFS_CORRUPT && result != NTFS_NOT_FOUND)) {
			return result;
		}
		if (result != NTFS_OK) {
			continue;
		}
		result = ntfs_logfile_fast_target(source, &target);
		if (result != NTFS_OK) {
			return result;
		}
		if (target < restart->circular_offset || target % restart->log_page_bytes != 0 ||
		    !ntfs_bounds(target, restart->log_page_bytes, restart->usable_bytes) ||
		    ntfs_logfile_lsn_decode(restart, page->page.copy_value, &location) != NTFS_OK ||
		    page->page.copy_value < page->page.last_end_lsn) {
			continue;
		}
		if ((page->page.flags &
			~(NTFS_LOGFILE_PAGE_RECORD_END | NTFS_LOGFILE_PAGE_CLIENT_RESTART)) != 0) {
			return NTFS_UNSUPPORTED;
		}
		copies->targets[index] = target;
		copies->available[index] = true;
	}
	return NTFS_OK;
}

static enum ntfs_result
ntfs_logfile_reload_fast_copy(struct ntfs_logfile *source, struct ntfs_logfile_report *work,
    const struct ntfs_logfile_fast_copies *copies, unsigned index,
    struct ntfs_logfile_page_view *out)
{
	uint32_t target;
	enum ntfs_result result;

	result = ntfs_logfile_load_page(source, copies->pages[index].offset, work, out);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_logfile_fast_target(source, &target);
	if (result != NTFS_OK) {
		return result;
	}
	if (target != copies->targets[index] ||
	    out->page.copy_value != copies->pages[index].page.copy_value ||
	    out->page.last_end_lsn != copies->pages[index].page.last_end_lsn ||
	    out->page.flags != copies->pages[index].page.flags ||
	    out->page.page_count != copies->pages[index].page.page_count ||
	    out->page.page_position != copies->pages[index].page.page_position ||
	    out->page.next_record_offset != copies->pages[index].page.next_record_offset) {
		return NTFS_STALE;
	}
	return NTFS_OK;
}

static bool
ntfs_logfile_same_fast_prefix(const struct ntfs_logfile_restart *restart,
    const struct ntfs_logfile_page *left_page, const uint8_t *a_bytes,
    const struct ntfs_logfile_page *right_page, const uint8_t *b_bytes)
{
	return left_page->last_end_lsn == right_page->last_end_lsn &&
	    ntfs_logfile_same_written_prefix(restart, left_page, a_bytes, right_page, b_bytes);
}

static enum ntfs_result
ntfs_logfile_load_fast_page(struct ntfs_logfile *source, uint64_t offset,
    struct ntfs_logfile_report *work, struct ntfs_logfile_fast_copies *copies,
    struct ntfs_logfile_page_view *out)
{
	const struct ntfs_logfile_restart *restart = &source->restart;
	const struct ntfs_logfile_page_view *candidate;
	struct ntfs_logfile_page_view circular = {0}, selected = {0}, duplicate = {0};
	struct ntfs_logfile_lsn location;
	enum ntfs_result circular_result, result;
	unsigned index, chosen = NTFS_LOGFILE_FAST_COPY_PAGES;

	for (index = 0; index < NTFS_LOGFILE_FAST_COPY_PAGES; index++) {
		if (copies->available[index] && copies->targets[index] == offset &&
		    (chosen == NTFS_LOGFILE_FAST_COPY_PAGES ||
			copies->pages[index].page.copy_value >
			    copies->pages[chosen].page.copy_value)) {
			chosen = index;
		}
	}
	circular_result = ntfs_logfile_load_page(source, offset, work, &circular);
	if (source->backend_failed ||
	    (circular_result != NTFS_OK && circular_result != NTFS_CORRUPT &&
		circular_result != NTFS_NOT_FOUND)) {
		return circular_result;
	}
	if (circular_result == NTFS_OK &&
	    (circular.page.flags &
		~(NTFS_LOGFILE_PAGE_RECORD_END | NTFS_LOGFILE_PAGE_CLIENT_RESTART)) != 0) {
		return NTFS_UNSUPPORTED;
	}
	if (circular_result == NTFS_OK &&
	    (ntfs_logfile_lsn_decode(restart, circular.page.copy_value, &location) != NTFS_OK ||
		circular.page.copy_value < circular.page.last_end_lsn)) {
		circular_result = NTFS_CORRUPT;
	}
	if (chosen == NTFS_LOGFILE_FAST_COPY_PAGES ||
	    (circular_result == NTFS_OK &&
		circular.page.copy_value > copies->pages[chosen].page.copy_value)) {
		if (circular_result == NTFS_OK) {
			*out = circular;
		}
		return circular_result;
	}
	candidate = &copies->pages[chosen];
	if (candidate->page.last_end_lsn == 0 ||
	    (candidate->page.flags & NTFS_LOGFILE_PAGE_RECORD_END) == 0 ||
	    candidate->page.next_record_offset < restart->page_data_offset) {
		return NTFS_UNSUPPORTED;
	}
	if (circular_result == NTFS_OK) {
		ntfs_copy(copies->comparison, source->scratch, restart->log_page_bytes);
	}
	result = ntfs_logfile_reload_fast_copy(source, work, copies, chosen, &selected);
	if (result != NTFS_OK) {
		return result;
	}
	if (circular_result == NTFS_OK && circular.page.copy_value == selected.page.copy_value &&
	    !ntfs_logfile_same_fast_prefix(
		restart, &circular.page, copies->comparison, &selected.page, source->scratch)) {
		return NTFS_UNSUPPORTED;
	}
	ntfs_copy(copies->comparison, source->scratch, restart->log_page_bytes);
	for (index = 0; index < NTFS_LOGFILE_FAST_COPY_PAGES; index++) {
		if (index == chosen || !copies->available[index] ||
		    copies->targets[index] != offset ||
		    copies->pages[index].page.copy_value != selected.page.copy_value) {
			continue;
		}
		result = ntfs_logfile_reload_fast_copy(source, work, copies, index, &duplicate);
		if (result != NTFS_OK) {
			return result;
		}
		if (!ntfs_logfile_same_fast_prefix(restart, &selected.page, copies->comparison,
			&duplicate.page, source->scratch)) {
			return NTFS_UNSUPPORTED;
		}
	}
	ntfs_copy(source->scratch, copies->comparison, restart->log_page_bytes);
	*out = selected;
	return NTFS_OK;
}

static enum ntfs_result
ntfs_logfile_load_history_page(struct ntfs_logfile *source, uint64_t offset, uint64_t lsn,
    struct ntfs_logfile_report *work, const struct ntfs_logfile_record_copies *copies,
    struct ntfs_logfile_page_view *out)
{
	const struct ntfs_logfile_restart *restart = &source->restart;
	const struct ntfs_logfile_index_entry *entry;
	const struct ntfs_logfile_page_view *selected;

	entry = &source->page_index
		     ->entries[(offset - restart->circular_offset) / restart->log_page_bytes];
	if (entry->blocked || entry->page.prefix_conflict ||
	    (entry->page.result == NTFS_UNSUPPORTED &&
		(entry->equal_candidates & (entry->equal_candidates - 1u)) != 0)) {
		return NTFS_UNSUPPORTED;
	}
	if (entry->page.result != NTFS_OK &&
	    !(entry->page.result == NTFS_UNSUPPORTED &&
		entry->page.selected.storage != NTFS_LOGFILE_CIRCULAR &&
		entry->page.selected.offset != 0)) {
		return entry->page.result;
	}
	selected = &entry->page.selected;
	/* A legacy tail preserves the completed prefix. A matching protected
	 * circular page can additionally contain the new spanning record beyond
	 * that prefix. Equal-end prefix agreement was checked by preparation. */
	if (selected->storage == NTFS_LOGFILE_LEGACY_TAIL && selected->page.last_end_lsn < lsn &&
	    entry->circular.offset != 0 &&
	    entry->circular.page.last_end_lsn == selected->page.last_end_lsn &&
	    (entry->circular.page.copy_value == lsn || entry->circular.page.copy_value == 0)) {
		selected = &entry->circular;
	}
	return ntfs_logfile_reload_record_page(source, selected, offset, work, copies, out);
}

enum ntfs_result
ntfs_logfile_reload_record_page(struct ntfs_logfile *source,
    const struct ntfs_logfile_page_view *selected, uint64_t target,
    struct ntfs_logfile_report *work, const struct ntfs_logfile_record_copies *copies,
    struct ntfs_logfile_page_view *out)
{
	struct ntfs_logfile_record_reuse *reuse = copies->reuse;
	const struct ntfs_logfile_checkpoint_capture_limits *limits = copies->capture_limits;
	enum ntfs_result result;

	/* Routing is evaluated for every requested LSN before consulting this slot:
	 * a legacy completed tail and a spanning circular start may share a target. */
	if (reuse != NULL && reuse->generation != 0 &&
	    reuse->generation == source->page_generation && reuse->generation != UINT64_MAX &&
	    reuse->physical == selected->offset && reuse->target == target) {
		*out = *selected;
		return NTFS_OK;
	}
	if (limits != NULL &&
	    (work->read_calls >= limits->max_read_calls ||
		work->read_bytes > limits->max_read_bytes ||
		source->restart.log_page_bytes > limits->max_read_bytes - work->read_bytes)) {
		return NTFS_RANGE;
	}
	result = ntfs_logfile_index_reload(source, selected, target, work, out);
	if (result == NTFS_OK && reuse != NULL) {
		reuse->generation = source->page_generation;
		reuse->physical = selected->offset;
		reuse->target = target;
	}
	return result;
}

enum ntfs_result
ntfs_logfile_load_record_page(struct ntfs_logfile *source, uint64_t offset, uint64_t lsn,
    struct ntfs_logfile_report *work, const struct ntfs_logfile_record_copies *copies,
    struct ntfs_logfile_page_view *out)
{
	const struct ntfs_logfile_checkpoint_capture_limits *limits;

	if (copies == NULL) {
		return ntfs_logfile_load_page(source, offset, work, out);
	}
	if (copies->indexed) {
		if (copies->history) {
			return ntfs_logfile_load_history_page(
			    source, offset, lsn, work, copies, out);
		}
		return ntfs_logfile_load_indexed_page(source, offset, work, copies, out);
	}
	limits = copies->capture_limits;
	if (limits != NULL &&
	    (work->read_calls >= limits->max_read_calls ||
		work->read_bytes > limits->max_read_bytes ||
		source->restart.log_page_bytes > limits->max_read_bytes - work->read_bytes)) {
		return NTFS_RANGE;
	}
	if (copies->legacy != NULL) {
		return ntfs_logfile_load_legacy_page(source, offset, work, copies->legacy, out);
	}
	return ntfs_logfile_load_fast_page(source, offset, work, copies->fast, out);
}
