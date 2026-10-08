/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "logfile_source_internal.h"

struct ntfs_transaction_links {
	uint64_t lsn, undo_next_lsn;
};

static enum ntfs_result ntfs_logfile_assemble_record(struct ntfs_logfile *source,
    uint64_t requested_lsn, void *bytes, size_t capacity, struct ntfs_logfile_record_view *out,
    struct ntfs_logfile_report *work, const struct ntfs_logfile_record_copies *copies,
    struct ntfs_logfile_record_ending *ending);
static enum ntfs_result ntfs_logfile_capture_packet(struct ntfs_logfile *source, uint64_t lsn,
    uint8_t *workspace, size_t capacity, struct ntfs_logfile_span *span,
    struct ntfs_logfile_report *work, const struct ntfs_logfile_checkpoint_capture_limits *limits,
    struct ntfs_logfile_checkpoint_capture_report *report);
static enum ntfs_result ntfs_logfile_transaction_link(
    const struct ntfs_logfile *source, uint64_t lsn, uint64_t current, uint64_t oldest);
static bool ntfs_logfile_transaction_contains(const uint8_t *links, uint32_t count, uint64_t lsn);
static enum ntfs_result ntfs_logfile_checkpoint_transaction_seed(const struct ntfs_logfile *source,
    const struct ntfs_logfile_transaction *seed, uint64_t table_lsn, uint64_t oldest);
static enum ntfs_result ntfs_logfile_checkpoint_transaction_packet(
    void *context, const struct ntfs_logfile_record_view *view, const void *bytes);
static enum ntfs_result ntfs_logfile_history_bounds(struct ntfs_logfile *source, uint64_t first,
    struct ntfs_logfile_history_report *out, uint64_t *end_target);
static enum ntfs_result ntfs_logfile_history_next_lsn(const struct ntfs_logfile_restart *restart,
    uint64_t current, const struct ntfs_logfile_record_view *record,
    const struct ntfs_logfile_record_ending *ending, bool next_page, uint64_t *out);
static enum ntfs_result ntfs_logfile_history_tail(struct ntfs_logfile *source,
    const struct ntfs_logfile_record_view *last, const struct ntfs_logfile_record_ending *ending,
    struct ntfs_logfile_report *work, const struct ntfs_logfile_checkpoint_capture_limits *limits,
    struct ntfs_logfile_history_report *out);

static enum ntfs_result
ntfs_logfile_assemble_record(struct ntfs_logfile *source, uint64_t requested_lsn, void *bytes,
    size_t capacity, struct ntfs_logfile_record_view *out, struct ntfs_logfile_report *work,
    const struct ntfs_logfile_record_copies *copies, struct ntfs_logfile_record_ending *ending)
{
	struct ntfs_logfile_record_view view = {0};
	struct ntfs_logfile_page_view page;
	struct ntfs_logfile_lsn location, linked;
	const struct ntfs_logfile_restart *restart;
	const struct ntfs_disk_log_record *header;
	uint8_t *staged;
	uint64_t total, unique_capacity, offset;
	size_t copied, amount, record_offset;
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (ending != NULL) {
		ntfs_zero(ending, sizeof(*ending));
	}
	if (source == NULL || bytes == NULL) {
		return NTFS_INVALID;
	}
	restart = &source->restart;
	result = ntfs_logfile_lsn_decode(restart, requested_lsn, &location);
	if (result != NTFS_OK) {
		return result;
	}
	if (capacity < restart->record_header_bytes) {
		return NTFS_RANGE;
	}
	result = ntfs_logfile_load_record_page(
	    source, location.page_offset, requested_lsn, work, copies, &page);
	if (result != NTFS_OK) {
		return result;
	}
	if (ending != NULL && page.storage != NTFS_LOGFILE_LEGACY_TAIL &&
	    page.page.copy_value == 0) {
		return NTFS_STALE;
	}
	header = (const void *)(source->scratch + location.record_offset);
	if (ntfs_u64(header->lsn) != requested_lsn) {
		return NTFS_STALE;
	}
	total = (uint64_t)restart->record_header_bytes + ntfs_u32(header->data_bytes);
	unique_capacity = (restart->usable_bytes - restart->circular_offset) /
		restart->log_page_bytes * (restart->log_page_bytes - restart->page_data_offset) -
	    (location.record_offset - restart->page_data_offset);
	if (total > NTFS_LOGFILE_MAX_RECORD_BYTES || total > capacity || total > unique_capacity) {
		return NTFS_RANGE;
	}
	staged = source->environment.allocate(source->environment.context, (size_t)total);
	if (staged == NULL) {
		return NTFS_NO_MEMORY;
	}
	offset = location.page_offset;
	record_offset = location.record_offset;
	copied = 0;
	view.first_page_offset = offset;
	for (;;) {
		amount = restart->log_page_bytes - record_offset;
		if (amount > total - copied) {
			amount = (size_t)total - copied;
		}
		if (ending != NULL) {
			/* Continuation framing follows the record's byte extent, never an
			 * I/O transfer's count/position. A full continuation contains no
			 * other starts or ends; the first partial record leaves its free
			 * boundary at its own header. */
			if (page.storage != NTFS_LOGFILE_LEGACY_TAIL && page.page.copy_value != 0 &&
			    (page.page.copy_value < requested_lsn ||
				(copied + amount < total &&
				    page.page.copy_value != requested_lsn))) {
				result = NTFS_STALE;
				goto done;
			}
			if (copied + amount < total &&
			    (page.page.next_record_offset != record_offset ||
				(copied != 0 &&
				    ((page.page.flags & NTFS_LOGFILE_PAGE_RECORD_END) != 0 ||
					page.page.last_end_lsn != 0)))) {
				result = NTFS_CORRUPT;
				goto done;
			}
		}
		/* A spanning record starts beyond the last completed prefix. Only its
		 * ending circular segment, and every selected completed tail segment,
		 * must fit the page's declared written prefix. */
		if (copies != NULL &&
		    ((ending == NULL && page.storage != NTFS_LOGFILE_CIRCULAR) ||
			copied + amount == total) &&
		    !ntfs_bounds(record_offset, amount, page.page.next_record_offset)) {
			result = NTFS_CORRUPT;
			goto done;
		}
		ntfs_copy(staged + copied, source->scratch + record_offset, amount);
		copied += amount;
		view.pages_read++;
		view.copy_pages_read += page.storage != NTFS_LOGFILE_CIRCULAR;
		view.last_page_offset = offset;
		if (copied == total) {
			break;
		}
		offset += restart->log_page_bytes;
		if (offset == restart->usable_bytes) {
			offset = restart->circular_offset;
			view.wrapped = true;
		}
		if (offset == location.page_offset) {
			result = NTFS_RANGE;
			goto done;
		}
		result = ntfs_logfile_load_record_page(
		    source, offset, requested_lsn, work, copies, &page);
		if (result != NTFS_OK) {
			goto done;
		}
		record_offset = restart->page_data_offset;
	}
	if (copies != NULL &&
	    ((page.page.flags & NTFS_LOGFILE_PAGE_RECORD_END) == 0 ||
		page.page.last_end_lsn < requested_lsn)) {
		result = NTFS_STALE;
		goto done;
	}
	result = ntfs_logfile_record_decode(
	    staged, (size_t)total, restart->record_header_bytes, &view.record);
	if (result == NTFS_OK && ending != NULL && view.pages_read > 1 &&
	    (view.record.flags & NTFS_LOGFILE_RECORD_MULTI_PAGE) == 0) {
		result = NTFS_CORRUPT;
	}
	if (result == NTFS_OK &&
	    ((view.record.previous_lsn != 0 &&
		 ntfs_logfile_lsn_decode(restart, view.record.previous_lsn, &linked) != NTFS_OK) ||
		(view.record.undo_next_lsn != 0 &&
		    ntfs_logfile_lsn_decode(restart, view.record.undo_next_lsn, &linked) !=
			NTFS_OK))) {
		result = NTFS_CORRUPT;
	}
	if (result == NTFS_OK) {
		view.bytes = (uint32_t)total;
		view.read_calls = work->read_calls;
		view.read_bytes = work->read_bytes;
		ntfs_copy(bytes, staged, (size_t)total);
		*out = view;
		if (ending != NULL) {
			ending->page = page;
			ending->offset = offset;
			ending->end_offset = record_offset + amount;
		}
	}
done:
	source->environment.release(source->environment.context, staged, (size_t)total);
	return result;
}

enum ntfs_result
ntfs_logfile_read_circular_record(struct ntfs_logfile *source, uint64_t requested_lsn, void *bytes,
    size_t capacity, struct ntfs_logfile_record_view *out)
{
	struct ntfs_logfile_report work = {0};

	return ntfs_logfile_assemble_record(
	    source, requested_lsn, bytes, capacity, out, &work, NULL, NULL);
}

enum ntfs_result
ntfs_logfile_read_indexed_record(struct ntfs_logfile *source, uint64_t requested_lsn, void *bytes,
    size_t capacity, struct ntfs_logfile_record_view *out)
{
	struct ntfs_logfile_report work = {0};
	struct ntfs_logfile_record_copies route = {.indexed = true};

	return ntfs_logfile_assemble_record(
	    source, requested_lsn, bytes, capacity, out, &work, &route, NULL);
}

/* Keep packet acquisition scratch separate from the complete checkpoint
 * snapshot: inlining it exceeds the 2-KiB general-register-only kernel frame. */
static __attribute__((noinline)) enum ntfs_result
ntfs_logfile_capture_packet(struct ntfs_logfile *source, uint64_t lsn, uint8_t *workspace,
    size_t capacity, struct ntfs_logfile_span *span, struct ntfs_logfile_report *work,
    const struct ntfs_logfile_checkpoint_capture_limits *limits,
    struct ntfs_logfile_checkpoint_capture_report *report)
{
	struct ntfs_logfile_record_view view;
	struct ntfs_logfile_record_ending ending;
	struct ntfs_logfile_record_copies route = {.capture_limits = limits, .indexed = true};
	enum ntfs_result result;

	report->requested_lsn = lsn;
	result = ntfs_logfile_assemble_record(source, lsn, workspace + report->record_bytes,
	    capacity - report->record_bytes, &view, work, &route, &ending);
	report->read_calls = work->read_calls;
	report->read_bytes = work->read_bytes;
	if (result == NTFS_OK) {
		*span = (struct ntfs_logfile_span){report->record_bytes, view.bytes};
		report->record_bytes += view.bytes;
		report->acquired_records++;
		report->copy_pages_read += view.copy_pages_read;
	}
	return result;
}

enum ntfs_result
ntfs_logfile_capture_checkpoint(struct ntfs_logfile *source, uint16_t index, uint16_t sequence,
    const struct ntfs_logfile_checkpoint_capture_limits *limits, void *workspace, size_t capacity,
    void *names, size_t name_capacity, struct ntfs_logfile_checkpoint_capture *out,
    struct ntfs_logfile_checkpoint_capture_report *report)
{
	struct ntfs_logfile_checkpoint_capture value = {0};
	struct ntfs_logfile_checkpoint_dump dumps[NTFS_LOGFILE_CHECKPOINT_KINDS] = {0};
	struct ntfs_logfile_table_reference anchors[NTFS_LOGFILE_CHECKPOINT_KINDS];
	struct ntfs_logfile_report work = {0};
	struct ntfs_logfile_checkpoint_capture_limits admitted;
	const struct ntfs_logfile_checkpoint_capture_limits *budget = NULL;
	uint8_t *bytes = workspace;
	uint32_t kind, previous;
	enum ntfs_result result;

	_Static_assert(
	    NTFS_LOGFILE_CHECKPOINT_MAX_BYTES <= UINT32_MAX, "checkpoint workspace span capacity");
	if (out != NULL) {
		ntfs_zero(out, sizeof(*out));
	}
	if (report != NULL) {
		ntfs_zero(report, sizeof(*report));
	}
	if (out == NULL || report == NULL || source == NULL || workspace == NULL) {
		return NTFS_INVALID;
	}
	if (limits != NULL) {
		admitted = *limits;
		if (admitted.max_read_calls == 0 || admitted.max_read_bytes == 0) {
			return NTFS_INVALID;
		}
		budget = &admitted;
	}
	result = ntfs_logfile_get_active_client(source, index, sequence, &value.client);
	if (result != NTFS_OK) {
		return result;
	}
	if (!ntfs_logfile_is_ntfs_client(&value.client)) {
		return NTFS_UNSUPPORTED;
	}
	report->checkpoint_lsn = value.client.restart_lsn;
	if (value.client.restart_lsn == 0) {
		return NTFS_NOT_FOUND;
	}
	result = ntfs_logfile_capture_packet(source, value.client.restart_lsn, bytes, capacity,
	    &value.checkpoint, &work, budget, report);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_logfile_decode_client_restart_record(
	    source, bytes, value.checkpoint.length, &value.restart);
	if (result != NTFS_OK) {
		return result;
	}
	/* Admit the complete anchor set before any table read. This also prevents
	 * one packet being assigned two table roles by a forged restart payload. */
	for (kind = 0; kind < NTFS_LOGFILE_CHECKPOINT_KINDS; kind++) {
		result = ntfs_logfile_checkpoint_anchor(&source->restart, &value.restart,
		    value.client.restart_lsn, (enum ntfs_logfile_checkpoint_kind)kind,
		    &anchors[kind]);
		if (result == NTFS_NOT_FOUND) {
			continue;
		}
		if (result != NTFS_OK) {
			return result;
		}
		for (previous = 0; previous < kind; previous++) {
			if (anchors[previous].lsn == anchors[kind].lsn) {
				return NTFS_CORRUPT;
			}
		}
	}
	for (kind = 0; kind < NTFS_LOGFILE_CHECKPOINT_KINDS; kind++) {
		if (anchors[kind].lsn == 0) {
			continue;
		}
		result = ntfs_logfile_capture_packet(source, anchors[kind].lsn, bytes, capacity,
		    &value.dumps[kind], &work, budget, report);
		if (result != NTFS_OK) {
			return result;
		}
		dumps[kind] = (struct ntfs_logfile_checkpoint_dump){
		    bytes + value.dumps[kind].offset, value.dumps[kind].length};
	}
	result = ntfs_logfile_checkpoint_decode(
	    source, bytes, value.checkpoint.length, dumps, names, name_capacity, &value.snapshot);
	if (result != NTFS_OK) {
		return result;
	}
	value.client_index = index;
	value.client_sequence = sequence;
	value.bytes = report->record_bytes;
	*out = value;
	report->complete = true;
	return NTFS_OK;
}

static enum ntfs_result
ntfs_logfile_transaction_link(
    const struct ntfs_logfile *source, uint64_t lsn, uint64_t current, uint64_t oldest)
{
	struct ntfs_logfile_lsn location;

	if (lsn == 0) {
		return NTFS_OK;
	}
	if (lsn >= current) {
		return NTFS_CORRUPT;
	}
	if (lsn < oldest) {
		return NTFS_STALE;
	}
	return ntfs_logfile_lsn_decode(&source->restart, lsn, &location) == NTFS_OK ? NTFS_OK
										    : NTFS_CORRUPT;
}

static bool
ntfs_logfile_transaction_contains(const uint8_t *links, uint32_t count, uint64_t lsn)
{
	struct ntfs_transaction_links link;
	uint32_t first = 0, last = count, middle;

	while (first < last) {
		middle = first + (last - first) / 2;
		ntfs_copy(&link, links + (size_t)middle * sizeof(link), sizeof(link));
		if (link.lsn == lsn) {
			return true;
		}
		if (link.lsn > lsn) {
			first = middle + 1;
		} else {
			last = middle;
		}
	}
	return false;
}

enum ntfs_result
ntfs_logfile_visit_transaction(struct ntfs_logfile *source, uint16_t index, uint16_t sequence,
    uint32_t transaction, uint64_t root_lsn, const struct ntfs_logfile_transaction_limits *limits,
    void *workspace, size_t capacity, void *link_workspace, size_t link_capacity,
    ntfs_logfile_record_visitor visitor, void *context,
    struct ntfs_logfile_transaction_report *report)
{
	struct ntfs_logfile_transaction_limits admitted;
	struct ntfs_logfile_checkpoint_capture_limits budget;
	struct ntfs_logfile_record_copies route = {.capture_limits = &budget, .indexed = true};
	struct ntfs_logfile_report work = {0};
	struct ntfs_logfile_record_view view;
	struct ntfs_logfile_client client;
	struct ntfs_logfile_update update;
	struct ntfs_logfile_lsn location;
	struct ntfs_transaction_links link;
	struct ntfs_logfile_record_ending ending;
	uint8_t *links = link_workspace;
	uint64_t lsn;
	uint32_t item;
	enum ntfs_result result;

	_Static_assert(sizeof(link) == 2 * sizeof(uint64_t), "transaction link workspace");
	if (report != NULL) {
		ntfs_zero(report, sizeof(*report));
	}
	if (report == NULL || source == NULL || workspace == NULL || links == NULL ||
	    visitor == NULL || transaction == 0 || root_lsn == 0) {
		return NTFS_INVALID;
	}
	admitted = limits != NULL
	    ? *limits
	    : (struct ntfs_logfile_transaction_limits){NTFS_LOGFILE_TRANSACTION_MAX_RECORDS,
		  source->limits.max_read_calls, source->limits.max_read_bytes};
	if (admitted.max_records == 0 || admitted.max_read_calls == 0 ||
	    admitted.max_read_bytes == 0) {
		return NTFS_INVALID;
	}
	if (admitted.max_records > NTFS_LOGFILE_TRANSACTION_MAX_RECORDS ||
	    link_capacity / sizeof(link) < admitted.max_records) {
		return NTFS_RANGE;
	}
	budget = (struct ntfs_logfile_checkpoint_capture_limits){
	    admitted.max_read_calls, admitted.max_read_bytes};
	result = ntfs_logfile_get_active_client(source, index, sequence, &client);
	if (result != NTFS_OK) {
		return result;
	}
	if (!ntfs_logfile_is_ntfs_client(&client) || client.oldest_lsn == 0) {
		return NTFS_UNSUPPORTED;
	}
	if (ntfs_logfile_lsn_decode(&source->restart, client.oldest_lsn, &location) != NTFS_OK ||
	    ntfs_logfile_lsn_decode(&source->restart, root_lsn, &location) != NTFS_OK) {
		return NTFS_CORRUPT;
	}
	if (root_lsn < client.oldest_lsn) {
		return NTFS_STALE;
	}
	report->root_lsn = root_lsn;
	report->transaction = transaction;
	report->next_lsn = root_lsn;
	lsn = root_lsn;
	while (lsn != 0) {
		if (report->examined_records == admitted.max_records) {
			return NTFS_RANGE;
		}
		result = ntfs_logfile_assemble_record(
		    source, lsn, workspace, capacity, &view, &work, &route, &ending);
		report->read_calls = work.read_calls;
		report->read_bytes = work.read_bytes;
		if (result != NTFS_OK) {
			return result;
		}
		report->examined_records++;
		report->copy_pages_read += view.copy_pages_read;
		if (view.record.client_index != index || view.record.client_sequence != sequence ||
		    view.record.transaction != transaction) {
			return NTFS_STALE;
		}
		if (view.record.type != NTFS_LOGFILE_RECORD_UPDATE ||
		    (view.record.flags &
			(NTFS_LOGFILE_RECORD_ADDING | NTFS_LOGFILE_RECORD_DELETING)) != 0) {
			return NTFS_UNSUPPORTED;
		}
		result = ntfs_logfile_transaction_link(
		    source, view.record.previous_lsn, lsn, client.oldest_lsn);
		if (result == NTFS_OK) {
			result = ntfs_logfile_transaction_link(
			    source, view.record.undo_next_lsn, lsn, client.oldest_lsn);
		}
		if (result != NTFS_OK) {
			return result;
		}
		result = ntfs_logfile_update_decode((uint8_t *)workspace + view.record.data.offset,
		    view.record.data.length, &update);
		if (result != NTFS_OK) {
			return result;
		}
		if (report->control_lsn == 0 &&
		    (update.redo_operation == NTFS_LOG_OP_PREPARE_TRANSACTION ||
			update.redo_operation == NTFS_LOG_OP_COMMIT_TRANSACTION ||
			update.redo_operation == NTFS_LOG_OP_FORGET_TRANSACTION)) {
			report->control_lsn = lsn;
			report->control_operation = update.redo_operation;
		}
		link = (struct ntfs_transaction_links){lsn, view.record.undo_next_lsn};
		ntfs_copy(
		    links + (size_t)report->visited_records * sizeof(link), &link, sizeof(link));
		result = visitor(context, &view, workspace);
		if (result != NTFS_OK) {
			return result;
		}
		report->last_lsn = lsn;
		report->record_bytes += view.bytes;
		report->visited_records++;
		lsn = view.record.previous_lsn;
		report->next_lsn = lsn;
	}
	for (item = 0; item < report->visited_records; item++) {
		ntfs_copy(&link, links + (size_t)item * sizeof(link), sizeof(link));
		if (link.undo_next_lsn != 0) {
			if (!ntfs_logfile_transaction_contains(
				links, report->visited_records, link.undo_next_lsn)) {
				return NTFS_CORRUPT;
			}
			report->undo_references++;
		}
	}
	report->complete = true;
	return NTFS_OK;
}

static enum ntfs_result
ntfs_logfile_checkpoint_transaction_seed(const struct ntfs_logfile *source,
    const struct ntfs_logfile_transaction *seed, uint64_t table_lsn, uint64_t oldest)
{
	struct ntfs_logfile_lsn location;

	if (seed->first_lsn == 0 || seed->previous_lsn == 0) {
		return seed->state == NTFS_LOGFILE_TRANSACTION_UNINITIALIZED &&
			seed->first_lsn == 0 && seed->previous_lsn == 0 &&
			seed->undo_next_lsn == 0 && seed->undo_records == 0 && seed->undo_bytes == 0
		    ? NTFS_OK
		    : NTFS_UNSUPPORTED;
	}
	if (seed->first_lsn > seed->previous_lsn || seed->previous_lsn >= table_lsn ||
	    seed->undo_next_lsn > seed->previous_lsn ||
	    (seed->undo_next_lsn != 0 && seed->undo_next_lsn < seed->first_lsn)) {
		return NTFS_CORRUPT;
	}
	if (ntfs_logfile_lsn_decode(&source->restart, seed->first_lsn, &location) != NTFS_OK ||
	    ntfs_logfile_lsn_decode(&source->restart, seed->previous_lsn, &location) != NTFS_OK ||
	    (seed->undo_next_lsn != 0 &&
		ntfs_logfile_lsn_decode(&source->restart, seed->undo_next_lsn, &location) !=
		    NTFS_OK)) {
		return NTFS_CORRUPT;
	}
	if (oldest == 0) {
		return NTFS_UNSUPPORTED;
	}
	return seed->first_lsn < oldest ? NTFS_STALE : NTFS_OK;
}

static enum ntfs_result
ntfs_logfile_checkpoint_transaction_packet(
    void *context, const struct ntfs_logfile_record_view *view, const void *bytes)
{
	(void)context;
	(void)view;
	(void)bytes;
	return NTFS_OK;
}

enum ntfs_result
ntfs_logfile_visit_checkpoint_transactions(struct ntfs_logfile *source, uint16_t index,
    uint16_t sequence, const struct ntfs_logfile_checkpoint_transaction_limits *limits,
    const struct ntfs_logfile_checkpoint_transaction_workspace *workspace,
    ntfs_logfile_checkpoint_transaction_visitor visitor, void *context,
    struct ntfs_logfile_checkpoint_transaction_report *report)
{
	struct ntfs_logfile_checkpoint_capture capture;
	struct ntfs_logfile_checkpoint_transaction_view view;
	struct ntfs_logfile_checkpoint_transaction_limits admitted;
	struct ntfs_logfile_checkpoint_transaction_workspace buffers;
	struct ntfs_logfile_checkpoint_capture_limits budget;
	struct ntfs_logfile_transaction_limits chain_limits;
	const struct ntfs_logfile_checkpoint_table *table;
	const uint8_t *body;
	uint32_t item, key, nonempty = 0;
	enum ntfs_result result;

	if (report != NULL) {
		ntfs_zero(report, sizeof(*report));
	}
	if (source == NULL || workspace == NULL || report == NULL || visitor == NULL) {
		return NTFS_INVALID;
	}
	buffers = *workspace;
	admitted = limits != NULL
	    ? *limits
	    : (struct ntfs_logfile_checkpoint_transaction_limits){
		  NTFS_LOGFILE_TRANSACTION_MAX_RECORDS, NTFS_LOGFILE_TRANSACTION_MAX_RECORDS,
		  source->limits.max_read_calls, source->limits.max_read_bytes};
	if (buffers.checkpoint_records == NULL || buffers.record == NULL || buffers.links == NULL ||
	    admitted.max_transactions == 0 || admitted.max_records == 0 ||
	    admitted.max_read_calls == 0 || admitted.max_read_bytes == 0) {
		return NTFS_INVALID;
	}
	if (admitted.max_transactions > NTFS_LOGFILE_TRANSACTION_MAX_RECORDS ||
	    admitted.max_records > NTFS_LOGFILE_TRANSACTION_MAX_RECORDS ||
	    buffers.link_capacity / sizeof(struct ntfs_transaction_links) < admitted.max_records) {
		return NTFS_RANGE;
	}
	budget.max_read_calls = admitted.max_read_calls < source->limits.max_read_calls
	    ? admitted.max_read_calls
	    : source->limits.max_read_calls;
	budget.max_read_bytes = admitted.max_read_bytes < source->limits.max_read_bytes
	    ? admitted.max_read_bytes
	    : source->limits.max_read_bytes;
	result = ntfs_logfile_capture_checkpoint(source, index, sequence, &budget,
	    buffers.checkpoint_records, buffers.checkpoint_capacity, buffers.names,
	    buffers.name_capacity, &capture, &report->checkpoint);
	report->read_calls = report->checkpoint.read_calls;
	report->read_bytes = report->checkpoint.read_bytes;
	report->record_bytes = report->checkpoint.record_bytes;
	report->copy_pages_read = report->checkpoint.copy_pages_read;
	if (result != NTFS_OK) {
		return result;
	}
	if ((capture.snapshot.present_mask & (1u << NTFS_LOGFILE_CHECKPOINT_TRANSACTIONS)) == 0) {
		return NTFS_NOT_FOUND;
	}
	table = &capture.snapshot.tables[NTFS_LOGFILE_CHECKPOINT_TRANSACTIONS];
	body = (const uint8_t *)buffers.checkpoint_records +
	    capture.dumps[NTFS_LOGFILE_CHECKPOINT_TRANSACTIONS].offset + table->body.offset;
	report->table_lsn = table->table_lsn;
	report->allocated_transactions = table->table.allocated_count;
	if (table->table.allocated_count > admitted.max_transactions) {
		return NTFS_RANGE;
	}
	/* A bad later seed must not expose any earlier transaction to the visitor. */
	for (item = 0; item < table->table.entry_count; item++) {
		key = table->table.entries.offset + item * table->table.entry_bytes;
		result = ntfs_logfile_transaction_decode(
		    body + key, table->table.entry_bytes, &view.snapshot);
		if (result == NTFS_NOT_FOUND) {
			continue;
		}
		report->requested_transaction = key;
		if (result != NTFS_OK) {
			return result;
		}
		result = ntfs_logfile_checkpoint_transaction_seed(
		    source, &view.snapshot, table->table_lsn, capture.client.oldest_lsn);
		if (result != NTFS_OK) {
			return result;
		}
		if (view.snapshot.previous_lsn != 0) {
			nonempty++;
		}
	}
	report->requested_transaction = 0;
	if (nonempty > admitted.max_records) {
		return NTFS_RANGE;
	}
	for (item = 0; item < table->table.entry_count; item++) {
		key = table->table.entries.offset + item * table->table.entry_bytes;
		ntfs_zero(&view, sizeof(view));
		result = ntfs_logfile_transaction_decode(
		    body + key, table->table.entry_bytes, &view.snapshot);
		if (result == NTFS_NOT_FOUND) {
			continue;
		}
		if (result != NTFS_OK) {
			return result;
		}
		view.key = key;
		report->requested_transaction = key;
		if (view.snapshot.previous_lsn != 0) {
			if (report->read_calls == budget.max_read_calls ||
			    report->read_bytes == budget.max_read_bytes ||
			    report->examined_records == admitted.max_records) {
				return NTFS_RANGE;
			}
			chain_limits = (struct ntfs_logfile_transaction_limits){
			    admitted.max_records - report->examined_records,
			    budget.max_read_calls - report->read_calls,
			    budget.max_read_bytes - report->read_bytes};
			result = ntfs_logfile_visit_transaction(source, index, sequence, key,
			    view.snapshot.previous_lsn, &chain_limits, buffers.record,
			    buffers.record_capacity, buffers.links, buffers.link_capacity,
			    ntfs_logfile_checkpoint_transaction_packet, NULL, &view.chain);
			report->read_calls += view.chain.read_calls;
			report->read_bytes += view.chain.read_bytes;
			report->record_bytes += view.chain.record_bytes;
			report->copy_pages_read += view.chain.copy_pages_read;
			report->examined_records += view.chain.examined_records;
			report->checked_records += view.chain.visited_records;
			if (result != NTFS_OK) {
				return result;
			}
			if (view.chain.last_lsn != view.snapshot.first_lsn ||
			    (view.snapshot.undo_next_lsn != 0 &&
				!ntfs_logfile_transaction_contains(buffers.links,
				    view.chain.visited_records, view.snapshot.undo_next_lsn))) {
				return NTFS_CORRUPT;
			}
		} else {
			view.chain.transaction = key;
			view.chain.complete = true;
		}
		report->verified_transactions++;
		result = visitor(context, &view);
		if (result != NTFS_OK) {
			return result;
		}
		report->visited_transactions++;
	}
	report->complete = true;
	return NTFS_OK;
}

static enum ntfs_result
ntfs_logfile_history_bounds(struct ntfs_logfile *source, uint64_t first,
    struct ntfs_logfile_history_report *out, uint64_t *end_target)
{
	const struct ntfs_logfile_restart *restart = &source->restart;
	const struct ntfs_logfile_page_index *index = source->page_index;
	const struct ntfs_logfile_index_entry *entry;
	const struct ntfs_logfile_page_view *view;
	struct ntfs_logfile_lsn beginning, end, started;
	uint32_t ordinal, slot;
	uint64_t completed, candidate;
	bool duplicate = false;
	enum ntfs_result result;

	result = ntfs_logfile_lsn_decode(restart, first, &beginning);
	if (result != NTFS_OK) {
		return result;
	}
	if (index == NULL) {
		return NTFS_NOT_FOUND;
	}
	if (index->report.unsupported_copies != 0 || index->unrouted_undated ||
	    index->unrouted_lsn >= first) {
		return NTFS_UNSUPPORTED;
	}
	for (ordinal = 0; ordinal < index->report.indexed_targets; ordinal++) {
		entry = &index->entries[ordinal];
		if (entry->page.retained_fast_copy) {
			continue;
		}
		if (entry->blocked || entry->page.prefix_conflict ||
		    (entry->page.result == NTFS_UNSUPPORTED &&
			(entry->equal_candidates & (entry->equal_candidates - 1u)) != 0)) {
			return NTFS_UNSUPPORTED;
		}
		if (entry->page.result == NTFS_CORRUPT) {
			return NTFS_CORRUPT;
		}
		if (entry->page.result != NTFS_OK &&
		    !(entry->page.result == NTFS_UNSUPPORTED && entry->page.selected.offset != 0 &&
			entry->page.selected.storage != NTFS_LOGFILE_CIRCULAR)) {
			continue;
		}
		view = &entry->page.selected;
		completed = (view->page.flags & NTFS_LOGFILE_PAGE_RECORD_END) != 0
		    ? view->page.last_end_lsn
		    : 0;
		/* A newer partial page may replace obsolete records, but cannot
		 * erase a completed record in the requested retained interval. */
		if (entry->circular.offset != 0 &&
		    (entry->circular.page.flags & NTFS_LOGFILE_PAGE_RECORD_END) != 0 &&
		    entry->circular.page.last_end_lsn >= first &&
		    entry->circular.page.last_end_lsn > completed) {
			return NTFS_STALE;
		}
		if (completed > out->candidate_end_lsn) {
			out->candidate_end_lsn = completed;
			*end_target = entry->page.target_offset;
			duplicate = false;
		} else if (completed >= first && completed == out->candidate_end_lsn) {
			duplicate = true;
		}
		view = restart->major == NTFS_LFS_MAJOR_LEGACY ? &entry->circular
							       : &entry->page.selected;
		if (view->offset != 0 && view->page.copy_value > out->observed_start_lsn &&
		    ntfs_logfile_lsn_decode(restart, view->page.copy_value, &started) == NTFS_OK) {
			out->observed_start_lsn = view->page.copy_value;
		}
	}
	/* Copy targets come from their declared routing fields. A continuation's
	 * last-start LSN can name a different page. Keep this pass linear in the
	 * fixed copy count, rather than rechecking every slot for every target. */
	for (slot = 0; slot < NTFS_LOGFILE_FAST_COPY_PAGES; slot++) {
		view = &index->copies[slot];
		candidate = view->page.last_end_lsn;
		if (view->offset == 0 || (view->page.flags & NTFS_LOGFILE_PAGE_RECORD_END) == 0 ||
		    candidate < first) {
			continue;
		}
		entry = &index->entries[(index->copy_targets[slot] - restart->circular_offset) /
		    restart->log_page_bytes];
		completed = (entry->page.selected.page.flags & NTFS_LOGFILE_PAGE_RECORD_END) != 0
		    ? entry->page.selected.page.last_end_lsn
		    : 0;
		if (candidate > completed) {
			return NTFS_STALE;
		}
	}
	if (out->candidate_end_lsn == 0 || out->candidate_end_lsn < first) {
		return NTFS_NOT_FOUND;
	}
	if (duplicate) {
		return NTFS_CORRUPT;
	}
	result = ntfs_logfile_lsn_decode(restart, out->candidate_end_lsn, &end);
	if (result != NTFS_OK) {
		return result;
	}
	if (end.sequence < beginning.sequence || end.sequence - beginning.sequence > 1 ||
	    (end.sequence == beginning.sequence && end.file_offset < beginning.file_offset) ||
	    (end.sequence != beginning.sequence && end.page_offset >= beginning.page_offset)) {
		return NTFS_STALE;
	}
	return NTFS_OK;
}

static enum ntfs_result
ntfs_logfile_history_next_lsn(const struct ntfs_logfile_restart *restart, uint64_t current,
    const struct ntfs_logfile_record_view *record, const struct ntfs_logfile_record_ending *ending,
    bool next_page, uint64_t *out)
{
	struct ntfs_logfile_lsn location;
	uint64_t sequence, offset, record_offset, maximum_sequence;
	uint32_t offset_bits;
	enum ntfs_result result;

	result = ntfs_logfile_lsn_decode(restart, current, &location);
	if (result != NTFS_OK) {
		return result;
	}
	offset_bits = NTFS_LFS_LSN_BITS - restart->sequence_bits;
	maximum_sequence = UINT64_MAX >> offset_bits;
	sequence = location.sequence;
	if (record->wrapped) {
		if (sequence == maximum_sequence) {
			return NTFS_RANGE;
		}
		sequence++;
	}
	offset = ending->offset;
	record_offset =
	    (ending->end_offset + NTFS_WIRE_ALIGNMENT - 1) & ~(uint64_t)(NTFS_WIRE_ALIGNMENT - 1);
	if (next_page ||
	    !ntfs_bounds(record_offset, restart->record_header_bytes, restart->log_page_bytes)) {
		offset += restart->log_page_bytes;
		if (offset == restart->usable_bytes) {
			offset = restart->circular_offset;
			if (sequence == maximum_sequence) {
				return NTFS_RANGE;
			}
			sequence++;
		}
		record_offset = restart->page_data_offset;
	}
	*out = (sequence << offset_bits) | ((offset + record_offset) >> NTFS_LFS_LSN_OFFSET_SHIFT);
	return *out > current ? NTFS_OK : NTFS_CORRUPT;
}

static enum ntfs_result
ntfs_logfile_history_tail(struct ntfs_logfile *source, const struct ntfs_logfile_record_view *last,
    const struct ntfs_logfile_record_ending *ending, struct ntfs_logfile_report *work,
    const struct ntfs_logfile_checkpoint_capture_limits *limits,
    struct ntfs_logfile_history_report *out)
{
	const struct ntfs_logfile_restart *restart = &source->restart;
	const struct ntfs_logfile_index_entry *entry;
	const struct ntfs_logfile_page_view *expected;
	struct ntfs_logfile_page_view page;
	struct ntfs_logfile_record record;
	struct ntfs_logfile_lsn location, linked;
	uint64_t adjacent;
	uint32_t bytes;
	enum ntfs_result result;

	if (out->observed_start_lsn <= out->candidate_end_lsn) {
		return NTFS_OK;
	}
	out->tail_lsn = out->observed_start_lsn;
	result = ntfs_logfile_lsn_decode(restart, out->tail_lsn, &location);
	if (result != NTFS_OK) {
		return result;
	}
	if (out->tail_lsn != out->next_lsn) {
		result = ntfs_logfile_history_next_lsn(
		    restart, last->record.lsn, last, ending, true, &adjacent);
		if (result != NTFS_OK) {
			return result;
		}
		if (out->tail_lsn != adjacent) {
			return NTFS_STALE;
		}
	}
	entry = &source->page_index->entries[(location.page_offset - restart->circular_offset) /
	    restart->log_page_bytes];
	expected =
	    restart->major == NTFS_LFS_MAJOR_LEGACY ? &entry->circular : &entry->page.selected;
	if (expected->offset == 0 || expected->page.copy_value != out->tail_lsn) {
		return NTFS_STALE;
	}
	if (limits != NULL &&
	    (work->read_calls >= limits->max_read_calls ||
		work->read_bytes > limits->max_read_bytes ||
		restart->log_page_bytes > limits->max_read_bytes - work->read_bytes)) {
		return NTFS_RANGE;
	}
	result = ntfs_logfile_index_reload(source, expected, location.page_offset, work, &page);
	if (result != NTFS_OK) {
		return result;
	}
	if (page.page.next_record_offset != location.record_offset ||
	    page.page.last_end_lsn > out->candidate_end_lsn) {
		return NTFS_CORRUPT;
	}
	result = ntfs_logfile_record_prefix(source->scratch + location.record_offset,
	    restart->log_page_bytes - location.record_offset, restart->record_header_bytes, &record,
	    &bytes);
	if (result != NTFS_OK) {
		return result;
	}
	if (record.lsn != out->tail_lsn) {
		return NTFS_STALE;
	}
	if ((record.flags & NTFS_LOGFILE_RECORD_MULTI_PAGE) == 0 ||
	    bytes <= restart->log_page_bytes - location.record_offset ||
	    (record.previous_lsn != 0 &&
		ntfs_logfile_lsn_decode(restart, record.previous_lsn, &linked) != NTFS_OK) ||
	    (record.undo_next_lsn != 0 &&
		ntfs_logfile_lsn_decode(restart, record.undo_next_lsn, &linked) != NTFS_OK)) {
		return NTFS_CORRUPT;
	}
	out->tail_verified = true;
	out->next_lsn = out->tail_lsn;
	return NTFS_OK;
}

enum ntfs_result
ntfs_logfile_visit_records_limited(struct ntfs_logfile *source, uint64_t first,
    uint32_t max_records, const struct ntfs_logfile_checkpoint_capture_limits *limits,
    void *workspace, size_t capacity, ntfs_logfile_record_visitor visitor, void *context,
    struct ntfs_logfile_history_report *out)
{
	struct ntfs_logfile_record_copies route = {.indexed = true, .history = true};
	struct ntfs_logfile_checkpoint_capture_limits admitted;
	struct ntfs_logfile_report work = {0};
	struct ntfs_logfile_record_view record;
	struct ntfs_logfile_record_ending ending;
	struct ntfs_logfile_lsn location, beginning;
	struct ntfs_logfile_lsn started;
	const struct ntfs_logfile_restart *restart;
	const struct ntfs_logfile_index_entry *entry;
	uint64_t current, end_target, before_bytes, aligned, ending_sequence, last_start;
	uint32_t before_calls;
	bool pending_start;
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (source == NULL || workspace == NULL || max_records == 0) {
		return NTFS_INVALID;
	}
	if (limits != NULL) {
		admitted = *limits;
		if (admitted.max_read_calls == 0 || admitted.max_read_bytes == 0) {
			return NTFS_INVALID;
		}
		route.capture_limits = &admitted;
	}
	restart = &source->restart;
	if (capacity < restart->record_header_bytes) {
		return NTFS_RANGE;
	}
	out->first_lsn = first;
	out->next_lsn = first;
	result = ntfs_logfile_history_bounds(source, first, out, &end_target);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_logfile_lsn_decode(restart, first, &beginning);
	if (result != NTFS_OK) {
		return result;
	}
	current = first;
	for (;;) {
		if (out->examined_records == max_records) {
			result = NTFS_RANGE;
			break;
		}
		before_calls = work.read_calls;
		before_bytes = work.read_bytes;
		result = ntfs_logfile_assemble_record(
		    source, current, workspace, capacity, &record, &work, &route, &ending);
		if (result != NTFS_OK) {
			break;
		}
		record.read_calls -= before_calls;
		record.read_bytes -= before_bytes;
		aligned = (ending.end_offset + NTFS_WIRE_ALIGNMENT - 1) &
		    ~(uint64_t)(NTFS_WIRE_ALIGNMENT - 1);
		if (ending.page.page.last_end_lsn > out->candidate_end_lsn ||
		    aligned > ending.page.page.next_record_offset) {
			result = NTFS_CORRUPT;
			break;
		}
		result = ntfs_logfile_lsn_decode(restart, current, &location);
		if (result != NTFS_OK) {
			break;
		}
		ending_sequence = location.sequence + (record.wrapped ? 1u : 0u);
		if (ending_sequence - beginning.sequence > 1 ||
		    (ending_sequence != beginning.sequence &&
			ending.offset >= beginning.page_offset)) {
			result = NTFS_STALE;
			break;
		}
		if (current == out->candidate_end_lsn &&
		    (ending.offset != end_target || ending.page.page.last_end_lsn != current ||
			aligned != ending.page.page.next_record_offset)) {
			result = NTFS_CORRUPT;
			break;
		}
		out->examined_records++;
		out->last_lsn = current;
		out->record_bytes += record.bytes;
		out->copy_pages_read += record.copy_pages_read;
		out->wrapped |= record.wrapped;
		if (visitor != NULL) {
			result = visitor(context, &record, workspace);
			if (result != NTFS_OK) {
				break;
			}
		}
		out->visited_records++;
		if (current == out->candidate_end_lsn) {
			out->endpoint_verified = true;
			out->completed_end_lsn = current;
			result = ntfs_logfile_history_next_lsn(
			    restart, current, &record, &ending, false, &out->next_lsn);
			if (result == NTFS_OK) {
				result = ntfs_logfile_history_tail(
				    source, &record, &ending, &work, route.capture_limits, out);
			}
			out->complete = result == NTFS_OK;
			break;
		}
		/* A completed prefix can end at the next spanning record's header.
		 * Only a matching last-start witness keeps that boundary on this page;
		 * otherwise the closed prefix advances to the next physical payload. */
		last_start = ending.page.page.copy_value;
		if (restart->major == NTFS_LFS_MAJOR_LEGACY) {
			entry = &source->page_index
				     ->entries[(ending.offset - restart->circular_offset) /
					 restart->log_page_bytes];
			last_start = entry->circular.page.copy_value;
		}
		pending_start = last_start > current &&
		    ntfs_logfile_lsn_decode(restart, last_start, &started) == NTFS_OK &&
		    started.file_offset == ending.offset + aligned;
		result = ntfs_logfile_history_next_lsn(restart, current, &record, &ending,
		    aligned == ending.page.page.next_record_offset && !pending_start,
		    &out->next_lsn);
		if (result != NTFS_OK) {
			break;
		}
		current = out->next_lsn;
		result = ntfs_logfile_lsn_decode(restart, current, &location);
		if (result != NTFS_OK) {
			break;
		}
		if (current > out->candidate_end_lsn ||
		    location.sequence - beginning.sequence > 1 ||
		    (location.sequence != beginning.sequence &&
			location.page_offset >= beginning.page_offset)) {
			result = NTFS_STALE;
			break;
		}
		out->wrapped |= location.sequence != beginning.sequence;
	}
	out->read_calls = work.read_calls;
	out->read_bytes = work.read_bytes;
	return result;
}

enum ntfs_result
ntfs_logfile_visit_records(struct ntfs_logfile *source, uint64_t first, uint32_t max_records,
    void *workspace, size_t capacity, ntfs_logfile_record_visitor visitor, void *context,
    struct ntfs_logfile_history_report *out)
{
	return ntfs_logfile_visit_records_limited(
	    source, first, max_records, NULL, workspace, capacity, visitor, context, out);
}

enum ntfs_result
ntfs_logfile_read_legacy_record(struct ntfs_logfile *source, uint64_t requested_lsn, void *bytes,
    size_t capacity, struct ntfs_logfile_record_view *out)
{
	struct ntfs_logfile_legacy_copies copies = {0};
	struct ntfs_logfile_record_copies route = {.legacy = &copies};
	struct ntfs_logfile_report work = {0};
	struct ntfs_logfile_lsn location;
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (source == NULL || bytes == NULL) {
		return NTFS_INVALID;
	}
	if (source->restart.major != NTFS_LFS_MAJOR_LEGACY) {
		return NTFS_UNSUPPORTED;
	}
	result = ntfs_logfile_lsn_decode(&source->restart, requested_lsn, &location);
	if (result != NTFS_OK) {
		return result;
	}
	if (capacity < source->restart.record_header_bytes) {
		return NTFS_RANGE;
	}
	copies.comparison = source->environment.allocate(
	    source->environment.context, source->restart.log_page_bytes);
	if (copies.comparison == NULL) {
		return NTFS_NO_MEMORY;
	}
	result = ntfs_logfile_scan_legacy_copies(source, &work, &copies);
	if (result == NTFS_OK) {
		result = ntfs_logfile_assemble_record(
		    source, requested_lsn, bytes, capacity, out, &work, &route, NULL);
	}
	source->environment.release(
	    source->environment.context, copies.comparison, source->restart.log_page_bytes);
	return result;
}

enum ntfs_result
ntfs_logfile_read_fast_record(struct ntfs_logfile *source, uint64_t requested_lsn, void *bytes,
    size_t capacity, struct ntfs_logfile_record_view *out)
{
	struct ntfs_logfile_report work = {0};
	struct ntfs_logfile_lsn location;
	struct ntfs_logfile_record_copies route;
	const struct ntfs_logfile_restart *restart;
	struct ntfs_logfile_fast_copies *copies;
	size_t workspace_bytes;
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (source == NULL || bytes == NULL) {
		return NTFS_INVALID;
	}
	restart = &source->restart;
	if (restart->major != NTFS_LFS_MAJOR_FAST ||
	    restart->system_page_bytes != NTFS_LFS_FAST_PAGE_BYTES ||
	    restart->log_page_bytes != NTFS_LFS_FAST_PAGE_BYTES ||
	    restart->page_data_offset < sizeof(struct ntfs_disk_log_fast_page)) {
		return NTFS_UNSUPPORTED;
	}
	result = ntfs_logfile_lsn_decode(restart, requested_lsn, &location);
	if (result != NTFS_OK) {
		return result;
	}
	if (capacity < restart->record_header_bytes ||
	    source->limits.max_read_calls <= NTFS_LOGFILE_FAST_COPY_PAGES ||
	    source->limits.max_read_bytes <
		(uint64_t)(NTFS_LOGFILE_FAST_COPY_PAGES + 1) * restart->log_page_bytes) {
		return NTFS_RANGE;
	}
	workspace_bytes = sizeof(*copies) + restart->log_page_bytes;
	copies = source->environment.allocate(source->environment.context, workspace_bytes);
	if (copies == NULL) {
		return NTFS_NO_MEMORY;
	}
	ntfs_zero(copies, sizeof(*copies));
	copies->comparison = (uint8_t *)(copies + 1);
	route = (struct ntfs_logfile_record_copies){.fast = copies};
	result = ntfs_logfile_scan_fast_copies(source, &work, copies);
	if (result == NTFS_OK) {
		result = ntfs_logfile_assemble_record(
		    source, requested_lsn, bytes, capacity, out, &work, &route, NULL);
	}
	source->environment.release(source->environment.context, copies, workspace_bytes);
	return result;
}
