/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "pointer_range.h"
#include "write_batch_pages.h"
#include "logfile_tables_disk.h"

enum { NTFS_WRITE_BATCH_DATA_BYTES = NTFS_WRITE_CLUSTER_BYTES - NTFS_WRITE_LOG_DATA_OFFSET };

struct ntfs_write_batch_pages {
	void *context;
	void (*release)(void *, void *, size_t);
	size_t bytes, pages, packets;
	uint64_t next_lsn;
	uint64_t lsn[];
};

struct ntfs_batch_page_window {
	struct ntfs_logfile_lsn floor, tail, cursor;
	uint64_t page, sequence, maximum_sequence, available_pages, next_lsn;
	uint32_t offset_bits;
	size_t pages;
};

struct ntfs_batch_page_workspace {
	uint8_t packet[NTFS_WRITE_BATCH_MAX_PACKET_BYTES];
	uint8_t data[NTFS_WRITE_BATCH_DATA_BYTES], restored[NTFS_WRITE_CLUSTER_BYTES];
};

_Static_assert(_Alignof(struct ntfs_write_batch_page) <= _Alignof(uint64_t),
    "batch page storage follows the scalar LSN array");

bool
ntfs_write_batch_pages_output_separate(
    const struct ntfs_write_batch_pages *owner, const void *output, size_t bytes)
{
	return owner != NULL && ntfs_pointer_ranges_separate(owner, owner->bytes, output, bytes);
}

enum ntfs_result
ntfs_write_batch_pages_packet_copy(const struct ntfs_write_batch_pages *owner, size_t ordinal,
    void *output, size_t capacity, size_t *actual)
{
	const struct ntfs_write_batch_page *pages, *page;
	const struct ntfs_disk_log_record *record;
	const struct ntfs_disk_mst *mst;
	uint8_t *destination = output;
	size_t index, first, end, bytes, copied, count, offset, sector, tail, usa, byte, take;
	uint16_t marker;

	if (owner == NULL ||
	    !ntfs_write_batch_pages_output_separate(owner, actual, sizeof(*actual))) {
		return NTFS_INVALID;
	}
	if (ordinal >= owner->packets) {
		*actual = 0;
		return NTFS_END;
	}
	pages = ntfs_write_batch_pages_get(owner, 0);
	for (first = 0; first < owner->pages && pages[first].packet != ordinal; first++) {
	}
	if (first == owner->pages) {
		*actual = 0;
		return NTFS_CORRUPT;
	}
	record = (const void *)(pages[first].protected_bytes + NTFS_WRITE_LOG_DATA_OFFSET);
	bytes = sizeof(*record) + (size_t)ntfs_u32(record->data_bytes);
	if (bytes > NTFS_WRITE_BATCH_MAX_PACKET_BYTES) {
		*actual = 0;
		return NTFS_CORRUPT;
	}
	if (!ntfs_write_batch_pages_output_separate(owner, output, bytes) ||
	    !ntfs_pointer_ranges_separate(output, bytes, actual, sizeof(*actual))) {
		return NTFS_INVALID;
	}
	*actual = 0;
	if (capacity < bytes) {
		return NTFS_RANGE;
	}
	end = first;
	while (end < owner->pages && pages[end].packet == ordinal) {
		end++;
	}
	if (end - first !=
	    (bytes + NTFS_WRITE_BATCH_DATA_BYTES - 1) / NTFS_WRITE_BATCH_DATA_BYTES) {
		return NTFS_CORRUPT;
	}
	/* Validate every protected segment before any output byte is changed.
	 * The packet's own header begins at the canonical fresh data position. */
	for (index = first; index < end; index++) {
		page = &pages[index];
		mst = (const void *)page->protected_bytes;
		usa = ntfs_u16(mst->usa_offset);
		if (!ntfs_equal(mst->magic, "RCRD", sizeof(mst->magic)) ||
		    usa != sizeof(struct ntfs_disk_log_page) ||
		    ntfs_u16(mst->usa_count) != NTFS_WRITE_CLUSTER_BYTES / NTFS_MST_STRIDE + 1) {
			return NTFS_CORRUPT;
		}
		marker = ntfs_u16(page->protected_bytes + usa);
		if (marker == 0 || marker == UINT16_MAX) {
			return NTFS_CORRUPT;
		}
		for (sector = NTFS_MST_STRIDE; sector <= NTFS_WRITE_CLUSTER_BYTES;
		    sector += NTFS_MST_STRIDE) {
			if (ntfs_u16(page->protected_bytes + sector - sizeof(uint16_t)) != marker) {
				return NTFS_CORRUPT;
			}
		}
	}
	copied = 0;
	for (index = first; index < end; index++) {
		page = &pages[index];
		mst = (const void *)page->protected_bytes;
		usa = ntfs_u16(mst->usa_offset);
		count = bytes - copied;
		if (count > NTFS_WRITE_BATCH_DATA_BYTES) {
			count = NTFS_WRITE_BATCH_DATA_BYTES;
		}
		for (byte = 0; byte < count; byte += take) {
			offset = NTFS_WRITE_LOG_DATA_OFFSET + byte;
			tail = offset % NTFS_MST_STRIDE;
			if (tail < NTFS_MST_STRIDE - sizeof(uint16_t)) {
				take = NTFS_MST_STRIDE - sizeof(uint16_t) - tail;
				if (take > count - byte) {
					take = count - byte;
				}
				ntfs_copy(destination + copied + byte,
				    page->protected_bytes + offset, take);
			} else {
				take = NTFS_MST_STRIDE - tail;
				if (take > count - byte) {
					take = count - byte;
				}
				ntfs_copy(destination + copied + byte,
				    page->protected_bytes + usa +
					(offset / NTFS_MST_STRIDE + 1) * sizeof(uint16_t) + tail -
					(NTFS_MST_STRIDE - sizeof(uint16_t)),
				    take);
			}
		}
		copied += count;
	}
	*actual = bytes;
	return NTFS_OK;
}

static enum ntfs_result
batch_pages_admit_output(const struct ntfs_environment *source,
    const struct ntfs_write_batch_pages_input *input, struct ntfs_write_batch_pages **out)
{
	size_t index, array_bytes;

	if (!ntfs_pointer_range_valid(out, sizeof(*out)) ||
	    (source != NULL &&
		!ntfs_pointer_ranges_separate(source, sizeof(*source), out, sizeof(*out))) ||
	    (input != NULL &&
		!ntfs_pointer_ranges_separate(input, sizeof(*input), out, sizeof(*out)))) {
		return NTFS_INVALID;
	}
	if (source == NULL || input == NULL) {
		*out = NULL;
		return NTFS_INVALID;
	}
	if (input->packets > SIZE_MAX / sizeof(*input->packet)) {
		return NTFS_INVALID;
	}
	array_bytes = input->packets * sizeof(*input->packet);
	if (!ntfs_pointer_ranges_separate(input->packet, array_bytes, out, sizeof(*out))) {
		return NTFS_INVALID;
	}
	if (input->packets > NTFS_WRITE_BATCH_MAX_PACKETS) {
		*out = NULL;
		return NTFS_RANGE;
	}
	for (index = 0; index < input->packets; index++) {
		if (!ntfs_pointer_ranges_separate(input->packet[index].payload.data,
			input->packet[index].payload.bytes, out, sizeof(*out))) {
			return NTFS_INVALID;
		}
	}
	*out = NULL;
	return NTFS_OK;
}

static enum ntfs_result
batch_pages_advance(const struct ntfs_logfile_restart *restart,
    const struct ntfs_batch_page_window *window, uint64_t *page, uint64_t *sequence)
{
	*page += restart->log_page_bytes;
	if (*page == restart->usable_bytes) {
		if (*sequence == window->maximum_sequence) {
			return NTFS_RANGE;
		}
		*page = restart->circular_offset;
		(*sequence)++;
	}
	return NTFS_OK;
}

static uint64_t
batch_pages_encode_lsn(
    const struct ntfs_batch_page_window *window, uint64_t page, uint64_t sequence, size_t within)
{
	return (sequence << window->offset_bits) | ((page + within) >> NTFS_LFS_LSN_OFFSET_SHIFT);
}

static enum ntfs_result
batch_pages_window_prepare(
    const struct ntfs_write_batch_pages_input *input, struct ntfs_batch_page_window *window)
{
	const struct ntfs_logfile_restart *restart = &input->restart;
	uint64_t ring_pages;
	enum ntfs_result result;

	if (restart->major != NTFS_LFS_MAJOR_LEGACY || restart->minor != NTFS_LFS_MINOR_LEGACY ||
	    restart->system_page_bytes != NTFS_WRITE_CLUSTER_BYTES ||
	    restart->log_page_bytes != NTFS_WRITE_CLUSTER_BYTES ||
	    restart->record_header_bytes != sizeof(struct ntfs_disk_log_record) ||
	    restart->page_data_offset != NTFS_WRITE_LOG_DATA_OFFSET) {
		return NTFS_UNSUPPORTED;
	}
	result = ntfs_logfile_lsn_decode(restart, input->floor_lsn, &window->floor);
	if (result == NTFS_OK) {
		result = ntfs_logfile_lsn_decode(restart, input->tail_lsn, &window->tail);
	}
	if (result == NTFS_OK) {
		result = ntfs_logfile_lsn_decode(restart, input->next_lsn, &window->cursor);
	}
	if (result != NTFS_OK) {
		return result;
	}
	if (input->floor_lsn > input->tail_lsn || input->tail_lsn >= input->next_lsn) {
		return NTFS_INVALID;
	}
	if (window->cursor.sequence - window->floor.sequence > 1 ||
	    (window->cursor.sequence != window->floor.sequence &&
		window->cursor.page_offset > window->floor.page_offset)) {
		return NTFS_STALE;
	}
	window->offset_bits = NTFS_LFS_LSN_BITS - restart->sequence_bits;
	window->maximum_sequence = UINT64_MAX >> window->offset_bits;
	window->page = window->cursor.page_offset;
	window->sequence = window->cursor.sequence;
	/* At a revisited floor page every circular page is still retained. A
	 * partial cursor cannot be skipped to invent another free interval. */
	if (window->cursor.sequence != window->floor.sequence &&
	    window->cursor.page_offset == window->floor.page_offset) {
		window->available_pages = 0;
		return NTFS_OK;
	}
	if (window->cursor.record_offset != restart->page_data_offset) {
		result = batch_pages_advance(restart, window, &window->page, &window->sequence);
		if (result != NTFS_OK) {
			return result;
		}
	}
	ring_pages = (restart->usable_bytes - restart->circular_offset) / restart->log_page_bytes;
	window->available_pages = window->floor.page_offset >= window->page
	    ? (window->floor.page_offset - window->page) / restart->log_page_bytes
	    : ring_pages - (window->page - window->floor.page_offset) / restart->log_page_bytes;
	return NTFS_OK;
}

enum ntfs_result
ntfs_write_batch_pages_capacity_check(
    const struct ntfs_write_batch_pages_input *input, size_t pages)
{
	struct ntfs_batch_page_window window = {0};
	uint64_t page, sequence;
	size_t index;
	enum ntfs_result result;

	if (!ntfs_pointer_range_valid(input, sizeof(*input)) || input->packet != NULL ||
	    input->packets != 0 || pages == 0) {
		return NTFS_INVALID;
	}
	if (pages > NTFS_WRITE_BATCH_MAX_PAGES) {
		return NTFS_RANGE;
	}
	result = batch_pages_window_prepare(input, &window);
	if (result != NTFS_OK) {
		return result;
	}
	if (pages > window.available_pages) {
		return NTFS_NO_SPACE;
	}
	page = window.page;
	sequence = window.sequence;
	for (index = 1; index < pages; index++) {
		result = batch_pages_advance(&input->restart, &window, &page, &sequence);
		if (result != NTFS_OK) {
			return result;
		}
	}
	return NTFS_OK;
}

static enum ntfs_result
batch_pages_link_admit(const struct ntfs_write_batch_pages_input *input, size_t ordinal,
    size_t target, uint64_t absolute)
{
	const struct ntfs_logfile_record *record = &input->packet[ordinal].record;
	const struct ntfs_logfile_record *linked;
	struct ntfs_logfile_lsn location;

	if (target != SIZE_MAX) {
		if (target >= ordinal || absolute != 0) {
			return NTFS_INVALID;
		}
		linked = &input->packet[target].record;
		return linked->client_index == record->client_index &&
			linked->client_sequence == record->client_sequence &&
			linked->transaction == record->transaction
		    ? NTFS_OK
		    : NTFS_INVALID;
	}
	if (absolute == 0) {
		return NTFS_OK;
	}
	if (absolute < input->floor_lsn || absolute > input->tail_lsn) {
		return NTFS_INVALID;
	}
	return ntfs_logfile_lsn_decode(&input->restart, absolute, &location);
}

static enum ntfs_result
batch_pages_packets_admit(
    const struct ntfs_write_batch_pages_input *input, struct ntfs_batch_page_window *window)
{
	const struct ntfs_write_batch_packet *packet;
	struct ntfs_logfile_update update;
	uint16_t known_flags;
	size_t index, total, pages;
	enum ntfs_result result;

	known_flags = NTFS_LOGFILE_RECORD_MULTI_PAGE | NTFS_LOGFILE_RECORD_ADDING |
	    NTFS_LOGFILE_RECORD_DELETING;
	for (index = 0; index < input->packets; index++) {
		packet = &input->packet[index];
		if (packet->payload.bytes >
		    NTFS_WRITE_BATCH_MAX_PACKET_BYTES - sizeof(struct ntfs_disk_log_record)) {
			return NTFS_RANGE;
		}
		if (packet->open_predecessor &&
		    (packet->record.type != NTFS_LOGFILE_RECORD_UPDATE ||
			ntfs_logfile_update_decode(
			    packet->payload.data, packet->payload.bytes, &update) != NTFS_OK ||
			update.redo_operation != NTFS_LOG_OP_OPEN_NONRESIDENT_ATTRIBUTE ||
			update.undo_operation != NTFS_LOG_OP_NOOP ||
			update.redo.length != sizeof(struct ntfs_disk_log_open_attribute))) {
			return NTFS_INVALID;
		}
		total = sizeof(struct ntfs_disk_log_record) + packet->payload.bytes;
		pages = (total + NTFS_WRITE_BATCH_DATA_BYTES - 1) / NTFS_WRITE_BATCH_DATA_BYTES;
		if ((packet->record.flags & ~known_flags) != 0 ||
		    packet->record.data.offset != sizeof(struct ntfs_disk_log_record) ||
		    (packet->record.type != NTFS_LOGFILE_RECORD_UPDATE &&
			packet->record.type != NTFS_LOGFILE_RECORD_RESTART) ||
		    (packet->record.type == NTFS_LOGFILE_RECORD_RESTART && pages != 1)) {
			return NTFS_UNSUPPORTED;
		}
		if (packet->record.lsn != 0 ||
		    (packet->record.flags & NTFS_LOGFILE_RECORD_MULTI_PAGE) != 0 ||
		    packet->record.client_index >= input->restart.client_count ||
		    packet->record.client_index == NTFS_LOGFILE_NO_CLIENT ||
		    packet->record.data.length != packet->payload.bytes) {
			return NTFS_INVALID;
		}
		result = batch_pages_link_admit(
		    input, index, packet->previous, packet->record.previous_lsn);
		if (result == NTFS_OK) {
			result = batch_pages_link_admit(
			    input, index, packet->undo_next, packet->record.undo_next_lsn);
		}
		if (result != NTFS_OK) {
			return result;
		}
		if (pages > NTFS_WRITE_BATCH_MAX_PAGES - window->pages) {
			return NTFS_RANGE;
		}
		window->pages += pages;
	}
	return window->pages <= window->available_pages ? NTFS_OK : NTFS_NO_SPACE;
}

static enum ntfs_result
batch_pages_successor_prepare(
    const struct ntfs_write_batch_pages_input *input, struct ntfs_batch_page_window *window)
{
	uint64_t page = window->page, sequence = window->sequence;
	size_t index, bytes, last_bytes, next;
	enum ntfs_result result;

	for (index = 1; index < window->pages; index++) {
		result = batch_pages_advance(&input->restart, window, &page, &sequence);
		if (result != NTFS_OK) {
			return result;
		}
	}
	bytes =
	    sizeof(struct ntfs_disk_log_record) + input->packet[input->packets - 1].payload.bytes;
	last_bytes = (bytes - 1) % NTFS_WRITE_BATCH_DATA_BYTES + 1;
	next = (NTFS_WRITE_LOG_DATA_OFFSET + last_bytes + NTFS_WIRE_ALIGNMENT - 1) &
	    ~(size_t)(NTFS_WIRE_ALIGNMENT - 1);
	if (!ntfs_bounds(next, sizeof(struct ntfs_disk_log_record), NTFS_WRITE_CLUSTER_BYTES)) {
		result = batch_pages_advance(&input->restart, window, &page, &sequence);
		if (result != NTFS_OK) {
			return result;
		}
		next = NTFS_WRITE_LOG_DATA_OFFSET;
	}
	window->next_lsn = batch_pages_encode_lsn(window, page, sequence, next);
	return NTFS_OK;
}

static struct ntfs_write_batch_page *
batch_pages_page_storage(struct ntfs_write_batch_pages *plan)
{
	return (void *)(plan->lsn + plan->packets);
}

static enum ntfs_result
batch_pages_pages_encode(const struct ntfs_write_batch_pages_input *input,
    const struct ntfs_batch_page_window *window, struct ntfs_batch_page_workspace *work,
    struct ntfs_write_batch_pages *plan)
{
	struct ntfs_write_batch_page *pages = batch_pages_page_storage(plan);
	const struct ntfs_write_batch_packet *packet;
	struct ntfs_logfile_record record;
	struct ntfs_logfile_update update;
	struct ntfs_disk_log_open_attribute *entry;
	struct ntfs_logfile_page_input frame = {0};
	uint64_t page = window->page, sequence = window->sequence;
	size_t ordinal, output = 0, bytes, copied, take, next;
	enum ntfs_result result;

	frame.bytes = NTFS_WRITE_CLUSTER_BYTES;
	frame.major = NTFS_LFS_MAJOR_LEGACY;
	frame.minor = NTFS_LFS_MINOR_LEGACY;
	frame.data_offset = NTFS_WRITE_LOG_DATA_OFFSET;
	frame.page.page_count = 1;
	frame.page.page_position = 1;
	frame.data = (struct ntfs_logfile_buffer){work->data, sizeof(work->data)};
	for (ordinal = 0; ordinal < input->packets; ordinal++) {
		packet = &input->packet[ordinal];
		record = packet->record;
		bytes = sizeof(struct ntfs_disk_log_record) + packet->payload.bytes;
		plan->lsn[ordinal] =
		    batch_pages_encode_lsn(window, page, sequence, NTFS_WRITE_LOG_DATA_OFFSET);
		record.lsn = plan->lsn[ordinal];
		if (packet->previous != SIZE_MAX) {
			record.previous_lsn = plan->lsn[packet->previous];
		}
		if (packet->undo_next != SIZE_MAX) {
			record.undo_next_lsn = plan->lsn[packet->undo_next];
		}
		if (bytes > NTFS_WRITE_BATCH_DATA_BYTES) {
			record.flags |= NTFS_LOGFILE_RECORD_MULTI_PAGE;
		}
		result = ntfs_logfile_record_encode(&record, packet->payload.data,
		    packet->payload.bytes, work->packet, sizeof(work->packet));
		if (result != NTFS_OK) {
			return result;
		}
		if (packet->open_predecessor) {
			result = ntfs_logfile_update_decode(
			    work->packet + sizeof(struct ntfs_disk_log_record),
			    packet->payload.bytes, &update);
			if (result != NTFS_OK) {
				return result;
			}
			if (record.type != NTFS_LOGFILE_RECORD_UPDATE ||
			    update.redo_operation != NTFS_LOG_OP_OPEN_NONRESIDENT_ATTRIBUTE ||
			    update.undo_operation != NTFS_LOG_OP_NOOP ||
			    update.redo.length != sizeof(*entry)) {
				return NTFS_INVALID;
			}
			entry = (void *)(work->packet + sizeof(struct ntfs_disk_log_record) +
			    update.redo.offset);
			ntfs_put_u64(entry->open_lsn,
			    ordinal == 0 ? input->tail_lsn : plan->lsn[ordinal - 1]);
		}
		copied = 0;
		while (copied != bytes) {
			take = bytes - copied;
			if (take > sizeof(work->data)) {
				take = sizeof(work->data);
			}
			ntfs_zero(work->data, sizeof(work->data));
			ntfs_copy(work->data, work->packet + copied, take);
			/* Every circular segment covers the record being copied through it. */
			frame.page.copy_value = record.lsn;
			frame.page.last_end_lsn = copied + take == bytes ? record.lsn : 0;
			frame.page.flags =
			    copied + take == bytes ? NTFS_LOGFILE_PAGE_RECORD_END : 0;
			if (record.type == NTFS_LOGFILE_RECORD_RESTART && copied == 0) {
				frame.page.flags |= NTFS_LOGFILE_PAGE_CLIENT_RESTART;
			}
			next = copied + take == bytes
			    ? (NTFS_WRITE_LOG_DATA_OFFSET + take + NTFS_WIRE_ALIGNMENT - 1) &
				~(size_t)(NTFS_WIRE_ALIGNMENT - 1)
			    : NTFS_WRITE_LOG_DATA_OFFSET;
			frame.page.next_record_offset = (uint16_t)next;
			pages[output].offset = page;
			pages[output].packet = ordinal;
			result = ntfs_logfile_page_encode(&frame, work->restored,
			    sizeof(work->restored), pages[output].protected_bytes,
			    sizeof(pages[output].protected_bytes));
			if (result != NTFS_OK) {
				return result;
			}
			copied += take;
			output++;
			if (output != plan->pages) {
				result =
				    batch_pages_advance(&input->restart, window, &page, &sequence);
				if (result != NTFS_OK) {
					return result;
				}
			}
		}
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_write_batch_pages_prepare(const struct ntfs_environment *source,
    const struct ntfs_write_batch_pages_input *input, struct ntfs_write_batch_pages **out)
{
	struct ntfs_write_batch_pages *plan;
	struct ntfs_environment allocator;
	struct ntfs_batch_page_workspace *work;
	struct ntfs_batch_page_window window = {0};
	size_t bytes;
	enum ntfs_result result;

	result = batch_pages_admit_output(source, input, out);
	if (result != NTFS_OK) {
		return result;
	}
	if (source->api_version != NTFS_API_VERSION || source->allocate == NULL ||
	    source->release == NULL || input->packets == 0) {
		return NTFS_INVALID;
	}
	result = batch_pages_window_prepare(input, &window);
	if (result == NTFS_OK) {
		result = batch_pages_packets_admit(input, &window);
	}
	if (result == NTFS_OK) {
		result = batch_pages_successor_prepare(input, &window);
	}
	if (result != NTFS_OK) {
		return result;
	}
	/* Named packet/page caps bound both products and total retained memory.
	 * The allocator also accounts this storage alongside any immutable owner. */
	bytes = sizeof(*plan) + input->packets * sizeof(*plan->lsn) +
	    window.pages * sizeof(struct ntfs_write_batch_page);
	if (bytes > NTFS_DEFAULT_MAX_LIVE_BYTES - sizeof(*work)) {
		return NTFS_RANGE;
	}
	allocator = *source;
	plan = allocator.allocate(allocator.context, bytes);
	if (plan == NULL) {
		return NTFS_NO_MEMORY;
	}
	ntfs_zero(plan, bytes);
	plan->context = allocator.context;
	plan->release = allocator.release;
	plan->bytes = bytes;
	plan->pages = window.pages;
	plan->packets = input->packets;
	plan->next_lsn = window.next_lsn;
	work = allocator.allocate(allocator.context, sizeof(*work));
	if (work == NULL) {
		ntfs_write_batch_pages_close(plan);
		return NTFS_NO_MEMORY;
	}
	result = batch_pages_pages_encode(input, &window, work, plan);
	allocator.release(allocator.context, work, sizeof(*work));
	if (result != NTFS_OK) {
		ntfs_write_batch_pages_close(plan);
		return result;
	}
	*out = plan;
	return NTFS_OK;
}

size_t
ntfs_write_batch_pages_count(const struct ntfs_write_batch_pages *plan)
{
	return plan == NULL ? 0 : plan->pages;
}

const struct ntfs_write_batch_page *
ntfs_write_batch_pages_get(const struct ntfs_write_batch_pages *plan, size_t index)
{
	const struct ntfs_write_batch_page *pages;

	if (plan == NULL || index >= plan->pages) {
		return NULL;
	}
	pages = (const void *)(plan->lsn + plan->packets);
	return &pages[index];
}

uint64_t
ntfs_write_batch_pages_lsn(const struct ntfs_write_batch_pages *plan, size_t index)
{
	return plan == NULL || index >= plan->packets ? 0 : plan->lsn[index];
}

uint64_t
ntfs_write_batch_pages_next_lsn(const struct ntfs_write_batch_pages *plan)
{
	return plan == NULL ? 0 : plan->next_lsn;
}

void
ntfs_write_batch_pages_close(struct ntfs_write_batch_pages *plan)
{
	if (plan != NULL) {
		plan->release(plan->context, plan, plan->bytes);
	}
}
