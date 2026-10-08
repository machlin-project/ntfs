/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "logfile_source_internal.h"

static uint64_t ntfs_logfile_index_epoch(
    const struct ntfs_logfile_restart *restart, const struct ntfs_logfile_page *page);
static bool ntfs_logfile_same_page_metadata(
    const struct ntfs_logfile_page_view *a, const struct ntfs_logfile_page_view *b);
static uint32_t ntfs_logfile_retained_fast_target(
    struct ntfs_logfile *source, const struct ntfs_logfile_page_observation *observation);
static bool ntfs_logfile_index_uncompleted_copy(
    const struct ntfs_logfile_index_builder *builder, const struct ntfs_logfile_page_view *view);
static enum ntfs_result ntfs_logfile_index_collect(
    void *context, const struct ntfs_logfile_page_observation *observation);
static enum ntfs_result ntfs_logfile_index_compare(struct ntfs_logfile *source,
    struct ntfs_logfile_index_builder *builder, struct ntfs_logfile_index_entry *entry,
    struct ntfs_logfile_report *work, uint8_t *comparison);
static enum ntfs_result ntfs_logfile_index_compare_retained(struct ntfs_logfile *source,
    struct ntfs_logfile_index_entry *entry, struct ntfs_logfile_page_index *index,
    struct ntfs_logfile_report *work, uint8_t *comparison);
static enum ntfs_result ntfs_logfile_build_page_index(struct ntfs_logfile *source,
    uint64_t max_bytes, struct ntfs_logfile_page_index_report *out,
    bool admit_uncompleted_legacy_copies);

static uint64_t
ntfs_logfile_index_epoch(
    const struct ntfs_logfile_restart *restart, const struct ntfs_logfile_page *page)
{
	return restart->major == NTFS_LFS_MAJOR_LEGACY ? page->last_end_lsn : page->copy_value;
}

static bool
ntfs_logfile_same_page_metadata(
    const struct ntfs_logfile_page_view *a, const struct ntfs_logfile_page_view *b)
{
	return a->offset == b->offset && a->storage == b->storage &&
	    a->page.copy_value == b->page.copy_value &&
	    a->page.last_end_lsn == b->page.last_end_lsn && a->page.flags == b->page.flags &&
	    a->page.page_count == b->page.page_count &&
	    a->page.page_position == b->page.page_position &&
	    a->page.next_record_offset == b->page.next_record_offset;
}

static uint32_t
ntfs_logfile_retained_fast_target(
    struct ntfs_logfile *source, const struct ntfs_logfile_page_observation *observation)
{
	const struct ntfs_logfile_restart *restart = &source->restart;
	const struct ntfs_disk_log_fast_page *header = (const void *)source->scratch;
	struct ntfs_logfile_lsn started, ended;
	uint64_t fast_circular;
	uint32_t target;

	/* A clean Windows downgrade can retain a protected completed restart page
	 * inside the former fast area. This only nominates a duplicate: a separate
	 * exact comparison against its selected home is required before history
	 * can omit it. Other layouts and spanning transfers retain normal checks. */
	fast_circular = (uint64_t)(NTFS_LFS_RESTART_PAGES + NTFS_LOGFILE_FAST_COPY_PAGES) *
	    NTFS_LFS_FAST_PAGE_BYTES;
	if (restart->major != NTFS_LFS_MAJOR_LEGACY ||
	    restart->system_page_bytes != NTFS_LFS_FAST_PAGE_BYTES ||
	    restart->log_page_bytes != NTFS_LFS_FAST_PAGE_BYTES ||
	    restart->page_data_offset < sizeof(*header) ||
	    observation->storage != NTFS_LOGFILE_CIRCULAR || observation->result != NTFS_OK ||
	    observation->target_result != NTFS_OK || observation->offset >= fast_circular ||
	    observation->page.flags !=
		(NTFS_LOGFILE_PAGE_RECORD_END | NTFS_LOGFILE_PAGE_CLIENT_RESTART) ||
	    observation->page.page_count != 1 || observation->page.page_position != 1 ||
	    ntfs_u16(header->common.mst.usa_offset) != sizeof(header->common) ||
	    ntfs_u16(header->common.mst.usa_count) != NTFS_LFS_FAST_USA_WORDS ||
	    observation->page.next_record_offset <= restart->page_data_offset) {
		return 0;
	}
	target = ntfs_u32(header->file_offset);
	if (target < fast_circular || target % restart->log_page_bytes != 0 ||
	    !ntfs_bounds(target, restart->log_page_bytes, restart->usable_bytes) ||
	    ntfs_logfile_lsn_decode(restart, observation->page.copy_value, &started) != NTFS_OK ||
	    ntfs_logfile_lsn_decode(restart, observation->page.last_end_lsn, &ended) != NTFS_OK ||
	    started.page_offset != target || ended.page_offset != target) {
		return 0;
	}
	return target;
}

static bool
ntfs_logfile_index_uncompleted_copy(
    const struct ntfs_logfile_index_builder *builder, const struct ntfs_logfile_page_view *view)
{
	const struct ntfs_logfile_restart *restart = builder->restart;
	const struct ntfs_logfile_page *page = &view->page;

	return builder->admit_uncompleted_legacy_copies &&
	    restart->major == NTFS_LFS_MAJOR_LEGACY && restart->minor == NTFS_LFS_MINOR_LEGACY &&
	    restart->system_page_bytes == NTFS_LFS_FAST_PAGE_BYTES &&
	    restart->log_page_bytes == NTFS_LFS_FAST_PAGE_BYTES &&
	    restart->record_header_bytes == sizeof(struct ntfs_disk_log_record) &&
	    restart->page_data_offset == sizeof(struct ntfs_disk_log_fast_page) &&
	    view->storage == NTFS_LOGFILE_LEGACY_TAIL && page->flags == 0 &&
	    page->last_end_lsn == 0 && page->next_record_offset == restart->page_data_offset &&
	    page->page_count == 1 && page->page_position == 1;
}

static enum ntfs_result
ntfs_logfile_index_collect(void *context, const struct ntfs_logfile_page_observation *observation)
{
	struct ntfs_logfile_index_builder *builder = context;
	struct ntfs_logfile_page_index *index = builder->index;
	const struct ntfs_logfile_restart *restart = builder->restart;
	struct ntfs_logfile_index_entry *entry;
	struct ntfs_logfile_page_view view = {0};
	struct ntfs_logfile_lsn location;
	uint64_t target, epoch, bit;
	uint32_t slot;
	enum ntfs_result result;

	result = observation->result == NTFS_OK ? observation->target_result : observation->result;
	/* A legacy circular continuation can have no last-start witness. Its
	 * protected physical address and last-end epoch remain observable; this
	 * exception never routes a tail or qualifies continuation provenance. */
	if (restart->major == NTFS_LFS_MAJOR_LEGACY &&
	    observation->storage == NTFS_LOGFILE_CIRCULAR && observation->result == NTFS_OK &&
	    result == NTFS_NOT_FOUND && observation->page.copy_value == 0) {
		result = NTFS_OK;
	}
	if (observation->storage != NTFS_LOGFILE_CIRCULAR) {
		if (result != NTFS_OK) {
			index->report.unrouted_copies += observation->result != NTFS_NOT_FOUND;
			index->report.unsupported_copies += result == NTFS_UNSUPPORTED;
			if (observation->result == NTFS_OK) {
				epoch = observation->page.last_end_lsn;
				if (observation->storage == NTFS_LOGFILE_FAST_STORAGE &&
				    ntfs_logfile_lsn_decode(restart, observation->page.copy_value,
					&location) == NTFS_OK &&
				    observation->page.copy_value > epoch) {
					epoch = observation->page.copy_value;
				}
				if (epoch > index->unrouted_lsn) {
					index->unrouted_lsn = epoch;
				}
				if (epoch == 0 &&
				    ((observation->page.flags & NTFS_LOGFILE_PAGE_RECORD_END) !=
					    0 ||
					observation->page.next_record_offset >
					    restart->page_data_offset)) {
					index->unrouted_undated = true;
				}
			}
			return NTFS_OK;
		}
		slot = (uint32_t)((observation->offset - builder->first_offset) /
		    restart->log_page_bytes);
		target = observation->target_offset;
	} else {
		slot = builder->copy_pages;
		target = observation->offset;
	}
	entry = &index->entries[(target - restart->circular_offset) / restart->log_page_bytes];
	if (observation->storage == NTFS_LOGFILE_CIRCULAR && observation->result == NTFS_OK) {
		entry->circular.offset = observation->offset;
		entry->circular.storage = observation->storage;
		entry->circular.page = observation->page;
		entry->retained_target =
		    ntfs_logfile_retained_fast_target(builder->source, observation);
	}
	if (result != NTFS_OK) {
		if (result == NTFS_UNSUPPORTED) {
			entry->blocked = true;
			entry->page.result = NTFS_UNSUPPORTED;
		} else if (entry->equal_candidates == 0) {
			entry->page.result = result;
		}
		return NTFS_OK;
	}
	view.offset = observation->offset;
	view.storage = observation->storage;
	view.page = observation->page;
	if (observation->storage != NTFS_LOGFILE_CIRCULAR) {
		index->copies[slot] = view;
		index->copy_targets[slot] = target;
	} else {
		entry->circular = view;
	}
	epoch = ntfs_logfile_index_epoch(restart, &observation->page);
	bit = UINT64_C(1) << slot;
	if (entry->equal_candidates == 0 || epoch > entry->page.epoch_lsn) {
		entry->page.selected = view;
		entry->page.epoch_lsn = epoch;
		entry->page.result = NTFS_OK;
		entry->equal_candidates = bit;
	} else if (epoch == entry->page.epoch_lsn) {
		entry->equal_candidates |= bit;
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_logfile_index_reload(struct ntfs_logfile *source,
    const struct ntfs_logfile_page_view *expected, uint64_t target,
    struct ntfs_logfile_report *work, struct ntfs_logfile_page_view *out)
{
	struct ntfs_logfile_page_observation observation = {0};
	enum ntfs_result result;

	result = ntfs_logfile_load_page(source, expected->offset, work, out);
	if (result != NTFS_OK) {
		return result;
	}
	if (!ntfs_logfile_same_page_metadata(expected, out)) {
		return NTFS_STALE;
	}
	observation.offset = out->offset;
	observation.storage = out->storage;
	observation.page = out->page;
	result = ntfs_logfile_observe_target(source, &observation);
	if (source->restart.major == NTFS_LFS_MAJOR_LEGACY &&
	    out->storage == NTFS_LOGFILE_CIRCULAR && result == NTFS_NOT_FOUND &&
	    out->page.copy_value == 0) {
		result = NTFS_OK;
	}
	if (result != NTFS_OK) {
		return result;
	}
	return observation.target_offset == target ? NTFS_OK : NTFS_STALE;
}

static enum ntfs_result
ntfs_logfile_index_compare(struct ntfs_logfile *source, struct ntfs_logfile_index_builder *builder,
    struct ntfs_logfile_index_entry *entry, struct ntfs_logfile_report *work, uint8_t *comparison)
{
	const struct ntfs_logfile_restart *restart = builder->restart;
	struct ntfs_logfile_page_view canonical, duplicate, expected;
	uint64_t bit, offset;
	uint32_t slot;
	bool loaded = false;
	enum ntfs_result result;

	if (entry->blocked) {
		entry->page.result = NTFS_UNSUPPORTED;
	}
	if (entry->page.result != NTFS_OK) {
		return NTFS_OK;
	}
	/* The experimental serializer persists every segment separately. A copy
	 * without a complete prefix can supersede a torn uncompleted home, but it
	 * cannot supply an endpoint or complete-prefix comparison authority. The
	 * private recovery owner must bind the whole retained history independently. */
	if (ntfs_logfile_index_uncompleted_copy(builder, &entry->page.selected)) {
		return NTFS_OK;
	}
	if (entry->page.selected.storage != NTFS_LOGFILE_CIRCULAR &&
	    ((entry->page.selected.page.flags & NTFS_LOGFILE_PAGE_RECORD_END) == 0 ||
		entry->page.selected.page.last_end_lsn == 0 ||
		entry->page.selected.page.next_record_offset < restart->page_data_offset)) {
		entry->page.result = NTFS_UNSUPPORTED;
		return NTFS_OK;
	}
	if ((entry->equal_candidates & (entry->equal_candidates - 1u)) == 0) {
		return NTFS_OK;
	}
	for (slot = 0; slot <= builder->copy_pages; slot++) {
		bit = UINT64_C(1) << slot;
		if ((entry->equal_candidates & bit) == 0) {
			continue;
		}
		offset = slot == builder->copy_pages
		    ? entry->page.target_offset
		    : builder->first_offset + (uint64_t)slot * restart->log_page_bytes;
		if (offset == entry->page.selected.offset) {
			continue;
		}
		if (!loaded) {
			result = ntfs_logfile_index_reload(source, &entry->page.selected,
			    entry->page.target_offset, work, &canonical);
			if (result != NTFS_OK) {
				return result;
			}
			ntfs_copy(comparison, source->scratch, restart->log_page_bytes);
			loaded = true;
		}
		expected =
		    slot == builder->copy_pages ? entry->circular : builder->index->copies[slot];
		result = ntfs_logfile_index_reload(
		    source, &expected, entry->page.target_offset, work, &duplicate);
		if (result != NTFS_OK) {
			return result;
		}
		if (ntfs_logfile_index_epoch(restart, &duplicate.page) != entry->page.epoch_lsn) {
			return NTFS_STALE;
		}
		builder->index->report.compared_prefixes++;
		if (duplicate.page.last_end_lsn != canonical.page.last_end_lsn ||
		    !ntfs_logfile_same_written_prefix(
			restart, &canonical.page, comparison, &duplicate.page, source->scratch)) {
			entry->page.result = NTFS_UNSUPPORTED;
			entry->page.prefix_conflict = true;
		}
	}
	return NTFS_OK;
}

static enum ntfs_result
ntfs_logfile_index_compare_retained(struct ntfs_logfile *source,
    struct ntfs_logfile_index_entry *entry, struct ntfs_logfile_page_index *index,
    struct ntfs_logfile_report *work, uint8_t *comparison)
{
	const struct ntfs_logfile_restart *restart = &source->restart;
	const struct ntfs_logfile_index_entry *home;
	struct ntfs_logfile_page_view retained, selected;
	struct ntfs_logfile_page_observation observation = {0};
	enum ntfs_result result;

	if (entry->retained_target == 0 || entry->page.result != NTFS_OK ||
	    entry->page.selected.offset != entry->circular.offset) {
		return NTFS_OK;
	}
	home = &index->entries[(entry->retained_target - restart->circular_offset) /
	    restart->log_page_bytes];
	if (home->page.result != NTFS_OK || home->page.epoch_lsn != entry->page.epoch_lsn ||
	    home->page.selected.page.page_count != 1 ||
	    home->page.selected.page.page_position != 1 ||
	    home->page.selected.page.flags != entry->circular.page.flags ||
	    home->page.selected.page.last_end_lsn != entry->circular.page.last_end_lsn) {
		return NTFS_OK;
	}
	result = ntfs_logfile_index_reload(
	    source, &entry->circular, entry->page.target_offset, work, &retained);
	if (result != NTFS_OK) {
		return result;
	}
	observation.offset = retained.offset;
	observation.storage = retained.storage;
	observation.result = NTFS_OK;
	observation.target_result = NTFS_OK;
	observation.page = retained.page;
	if (ntfs_logfile_retained_fast_target(source, &observation) != entry->retained_target) {
		return NTFS_STALE;
	}
	ntfs_copy(comparison, source->scratch, restart->log_page_bytes);
	result = ntfs_logfile_index_reload(
	    source, &home->page.selected, home->page.target_offset, work, &selected);
	if (result != NTFS_OK) {
		return result;
	}
	index->report.compared_prefixes++;
	if (!ntfs_logfile_same_written_prefix(
		restart, &retained.page, comparison, &selected.page, source->scratch)) {
		entry->page.result = NTFS_UNSUPPORTED;
		entry->page.prefix_conflict = true;
	} else {
		entry->page.retained_fast_copy = true;
	}
	return NTFS_OK;
}

void
ntfs_logfile_clear_page_index(struct ntfs_logfile *source)
{
	struct ntfs_logfile_page_index *index;

	if (source != NULL && source->page_index != NULL) {
		index = source->page_index;
		source->page_index = NULL;
		source->environment.release(
		    source->environment.context, index, index->allocation_bytes);
	}
}

static enum ntfs_result
ntfs_logfile_build_page_index(struct ntfs_logfile *source, uint64_t max_bytes,
    struct ntfs_logfile_page_index_report *out, bool admit_uncompleted_legacy_copies)
{
	struct ntfs_logfile_report work = {0};
	struct ntfs_logfile_index_builder builder;
	struct ntfs_logfile_page_index *index;
	struct ntfs_logfile_index_entry *entry;
	const struct ntfs_logfile_restart *restart;
	uint8_t *comparison;
	uint64_t storage_pages, maximum_reads, required_bytes;
	uint32_t copies, targets, ordinal, retained_candidates = 0;
	bool existing_conflict;
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (source == NULL || max_bytes == 0) {
		return NTFS_INVALID;
	}
	if (source->page_index != NULL) {
		return NTFS_BUSY;
	}
	restart = &source->restart;
	if (restart->major == NTFS_LFS_MAJOR_FAST &&
	    (restart->system_page_bytes != NTFS_LFS_FAST_PAGE_BYTES ||
		restart->log_page_bytes != NTFS_LFS_FAST_PAGE_BYTES ||
		restart->page_data_offset < sizeof(struct ntfs_disk_log_fast_page))) {
		return NTFS_UNSUPPORTED;
	}
	copies = restart->major == NTFS_LFS_MAJOR_FAST ? NTFS_LOGFILE_FAST_COPY_PAGES
						       : NTFS_LFS_LEGACY_TAIL_PAGES;
	targets = (uint32_t)((restart->usable_bytes - restart->circular_offset) /
	    restart->log_page_bytes);
	storage_pages = (uint64_t)targets + copies;
	maximum_reads = storage_pages + (uint64_t)NTFS_LOGFILE_PREFIX_PAIR_READS * copies;
	required_bytes =
	    sizeof(*index) + (uint64_t)targets * sizeof(*entry) + restart->log_page_bytes;
	out->required_bytes = required_bytes;
	out->indexed_targets = targets;
	if (required_bytes > max_bytes || required_bytes > SIZE_MAX ||
	    maximum_reads > source->limits.max_read_calls ||
	    maximum_reads * restart->log_page_bytes > source->limits.max_read_bytes) {
		return NTFS_RANGE;
	}
	index = source->environment.allocate(source->environment.context, (size_t)required_bytes);
	if (index == NULL) {
		return NTFS_NO_MEMORY;
	}
	ntfs_zero(index, (size_t)required_bytes);
	index->allocation_bytes = (size_t)required_bytes;
	index->report = *out;
	for (ordinal = 0; ordinal < targets; ordinal++) {
		entry = &index->entries[ordinal];
		entry->page.target_offset =
		    restart->circular_offset + (uint64_t)ordinal * restart->log_page_bytes;
		entry->page.result = NTFS_NOT_FOUND;
	}
	builder = (struct ntfs_logfile_index_builder){index, restart,
	    (uint64_t)NTFS_LFS_RESTART_PAGES * restart->system_page_bytes, copies, source,
	    admit_uncompleted_legacy_copies};
	comparison = (uint8_t *)(index->entries + targets);
	result = ntfs_logfile_visit_pages(
	    source, ntfs_logfile_index_collect, &builder, &index->report.inventory);
	work.read_calls = index->report.inventory.read_calls;
	work.read_bytes = index->report.inventory.read_bytes;
	if (result == NTFS_OK) {
		for (ordinal = 0; ordinal < targets; ordinal++) {
			retained_candidates += index->entries[ordinal].retained_target != 0;
		}
		/* Candidate routing is untrusted until comparison. Reserve every pair
		 * before any comparison read, under the original whole-operation cap. */
		maximum_reads += (uint64_t)NTFS_LOGFILE_PREFIX_PAIR_READS * retained_candidates;
		if (maximum_reads > source->limits.max_read_calls ||
		    maximum_reads * restart->log_page_bytes > source->limits.max_read_bytes) {
			result = NTFS_RANGE;
		}
	}
	if (result == NTFS_OK) {
		for (ordinal = 0; ordinal < targets; ordinal++) {
			entry = &index->entries[ordinal];
			result =
			    ntfs_logfile_index_compare(source, &builder, entry, &work, comparison);
			if (result != NTFS_OK) {
				break;
			}
			index->report.selected_pages += entry->page.result == NTFS_OK;
			index->report.missing_targets += entry->page.result == NTFS_NOT_FOUND;
			index->report.corrupt_targets += entry->page.result == NTFS_CORRUPT;
			index->report.unsupported_targets += entry->page.result == NTFS_UNSUPPORTED;
			index->report.prefix_conflicts += entry->page.prefix_conflict;
		}
	}
	if (result == NTFS_OK) {
		for (ordinal = 0; ordinal < targets; ordinal++) {
			entry = &index->entries[ordinal];
			existing_conflict = entry->page.prefix_conflict;
			result = ntfs_logfile_index_compare_retained(
			    source, entry, index, &work, comparison);
			if (result != NTFS_OK) {
				break;
			}
			if (!existing_conflict && entry->page.prefix_conflict) {
				index->report.selected_pages--;
				index->report.unsupported_targets++;
				index->report.prefix_conflicts++;
			}
		}
	}
	index->report.read_calls = work.read_calls;
	index->report.read_bytes = work.read_bytes;
	if (result == NTFS_OK) {
		index->report.published = true;
		index->report.retained_bytes = required_bytes;
		source->page_index = index;
	}
	*out = index->report;
	if (result != NTFS_OK) {
		source->environment.release(
		    source->environment.context, index, index->allocation_bytes);
	}
	return result;
}

enum ntfs_result
ntfs_logfile_prepare_page_index(
    struct ntfs_logfile *source, uint64_t max_bytes, struct ntfs_logfile_page_index_report *out)
{
	return ntfs_logfile_build_page_index(source, max_bytes, out, false);
}

enum ntfs_result
ntfs_logfile_prepare_write_page_index(
    struct ntfs_logfile *source, uint64_t max_bytes, struct ntfs_logfile_page_index_report *out)
{
	return ntfs_logfile_build_page_index(source, max_bytes, out, true);
}

enum ntfs_result
ntfs_logfile_get_page_index_report(
    const struct ntfs_logfile *source, struct ntfs_logfile_page_index_report *out)
{
	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (source == NULL) {
		return NTFS_INVALID;
	}
	if (source->page_index == NULL) {
		return NTFS_NOT_FOUND;
	}
	*out = source->page_index->report;
	return NTFS_OK;
}

enum ntfs_result
ntfs_logfile_get_indexed_page(
    const struct ntfs_logfile *source, uint64_t offset, struct ntfs_logfile_indexed_page *out)
{
	const struct ntfs_logfile_restart *restart;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (source == NULL) {
		return NTFS_INVALID;
	}
	restart = &source->restart;
	if (offset < restart->circular_offset || offset % restart->log_page_bytes != 0 ||
	    !ntfs_bounds(offset, restart->log_page_bytes, restart->usable_bytes)) {
		return NTFS_INVALID;
	}
	if (source->page_index == NULL) {
		return NTFS_NOT_FOUND;
	}
	*out = source->page_index
		   ->entries[(offset - restart->circular_offset) / restart->log_page_bytes]
		   .page;
	return NTFS_OK;
}

enum ntfs_result
ntfs_logfile_load_indexed_page(struct ntfs_logfile *source, uint64_t offset,
    struct ntfs_logfile_report *work, struct ntfs_logfile_page_view *out)
{
	struct ntfs_logfile_indexed_page indexed;
	enum ntfs_result result;

	if (source->page_index != NULL && source->page_index->report.unsupported_copies != 0) {
		return NTFS_UNSUPPORTED;
	}
	result = ntfs_logfile_get_indexed_page(source, offset, &indexed);
	if (result != NTFS_OK) {
		return result;
	}
	if (indexed.result != NTFS_OK) {
		return indexed.result;
	}
	return ntfs_logfile_index_reload(source, &indexed.selected, offset, work, out);
}
