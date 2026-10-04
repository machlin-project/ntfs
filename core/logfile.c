/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include <ntfs/logfile.h>

enum {
	LOG_MAX_CLIENTS = NTFS_LOGFILE_MAX_PAGE_BYTES / sizeof(struct ntfs_disk_log_client),
	LOG_CLIENT_BITMAP_BYTES = (LOG_MAX_CLIENTS + NTFS_BITS_PER_BYTE - 1) / NTFS_BITS_PER_BYTE
};

_Static_assert(NTFS_LOGFILE_CLIENT_NAME_UNITS * sizeof(uint16_t) == NTFS_LFS_CLIENT_NAME_BYTES,
    "public client name capacity");

static bool
page_size(uint32_t size)
{
	return size >= NTFS_MST_STRIDE && (size & (size - 1)) == 0;
}

static bool
version(uint16_t major, uint16_t minor)
{
	return (major == NTFS_LFS_MAJOR_LEGACY && minor == NTFS_LFS_MINOR_LEGACY) ||
	    (major == NTFS_LFS_MAJOR_FAST && minor == NTFS_LFS_MINOR_FAST);
}

static uint32_t
sequence_bits(uint64_t file_bytes)
{
	uint32_t width = 0;

	while (file_bytes != 0) {
		width++;
		file_bytes >>= 1;
	}
	return NTFS_LFS_LSN_BITS + NTFS_LFS_LSN_OFFSET_SHIFT - width;
}

static bool
geometry(const struct ntfs_logfile_restart *r)
{
	uint64_t minimum, circular, usable;

	if (r == NULL || !version(r->major, r->minor) || !page_size(r->system_page_bytes) ||
	    !page_size(r->log_page_bytes) || r->system_page_bytes > NTFS_LOGFILE_MAX_PAGE_BYTES ||
	    r->log_page_bytes > NTFS_LOGFILE_MAX_PAGE_BYTES || r->file_bytes == 0 ||
	    r->file_bytes > NTFS_LOGFILE_MAX_FILE_BYTES ||
	    r->record_header_bytes < sizeof(struct ntfs_disk_log_record) ||
	    r->record_header_bytes % NTFS_WIRE_ALIGNMENT != 0 ||
	    ((uint64_t)NTFS_LFS_RESTART_PAGES * r->system_page_bytes) % r->log_page_bytes != 0 ||
	    r->page_data_offset < sizeof(struct ntfs_disk_log_page) ||
	    r->page_data_offset < sizeof(struct ntfs_disk_log_page) +
		    (r->log_page_bytes / NTFS_MST_STRIDE + 1u) * NTFS_MST_WORD_BYTES ||
	    r->page_data_offset % NTFS_WIRE_ALIGNMENT != 0 ||
	    !ntfs_bounds(r->page_data_offset, r->record_header_bytes, r->log_page_bytes)) {
		return false;
	}
	minimum = (uint64_t)NTFS_LFS_RESTART_PAGES * r->system_page_bytes +
	    (uint64_t)NTFS_LFS_MIN_RECORD_PAGES * r->log_page_bytes;
	circular = (uint64_t)NTFS_LFS_RESTART_PAGES * r->system_page_bytes +
	    (uint64_t)(r->major == NTFS_LFS_MAJOR_FAST ? NTFS_LFS_FAST_PAGES
						       : NTFS_LFS_LEGACY_TAIL_PAGES) *
		r->log_page_bytes;
	usable = r->file_bytes - r->file_bytes % r->log_page_bytes;
	return usable >= minimum && r->usable_bytes == usable && r->circular_offset == circular &&
	    r->sequence_bits >= NTFS_LFS_LSN_OFFSET_SHIFT &&
	    r->sequence_bits <= sequence_bits(r->file_bytes);
}

enum ntfs_result
ntfs_logfile_lsn_decode(
    const struct ntfs_logfile_restart *r, uint64_t lsn, struct ntfs_logfile_lsn *out)
{
	struct ntfs_logfile_lsn info = {0};
	uint64_t mask;
	uint32_t offset_bits;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (!geometry(r)) {
		return NTFS_INVALID;
	}
	if (lsn == 0) {
		return NTFS_NOT_FOUND;
	}
	offset_bits = NTFS_LFS_LSN_BITS - r->sequence_bits;
	mask = (UINT64_C(1) << offset_bits) - 1;
	info.sequence = lsn >> offset_bits;
	info.file_offset = (lsn & mask) << NTFS_LFS_LSN_OFFSET_SHIFT;
	info.page_offset = info.file_offset - info.file_offset % r->log_page_bytes;
	info.record_offset = (uint32_t)(info.file_offset % r->log_page_bytes);
	if (info.file_offset < r->circular_offset ||
	    !ntfs_bounds(info.file_offset, r->record_header_bytes, r->usable_bytes) ||
	    info.record_offset < r->page_data_offset ||
	    !ntfs_bounds(info.record_offset, r->record_header_bytes, r->log_page_bytes)) {
		return NTFS_CORRUPT;
	}
	*out = info;
	return NTFS_OK;
}

enum ntfs_result
ntfs_logfile_client_restart_decode(
    const void *input, size_t size, struct ntfs_logfile_client_restart *out)
{
	const struct ntfs_disk_log_client_restart *header = input;
	uint32_t major, minor;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (input == NULL) {
		return NTFS_INVALID;
	}
	if (size > NTFS_LOGFILE_MAX_RECORD_BYTES) {
		return NTFS_RANGE;
	}
	if (size < sizeof(*header)) {
		return NTFS_CORRUPT;
	}
	major = ntfs_u32(header->major);
	minor = ntfs_u32(header->minor);
	if ((major != NTFS_LOG_CLIENT_MAJOR_BASE && major != NTFS_LOG_CLIENT_MAJOR_ATTRIBUTES) ||
	    minor != NTFS_LOG_CLIENT_MINOR) {
		return NTFS_UNSUPPORTED;
	}
	out->major = major;
	out->minor = minor;
	out->analysis_lsn = ntfs_u64(header->analysis_lsn);
	out->open_attributes.lsn = ntfs_u64(header->open_attributes_lsn);
	out->open_attributes.bytes = ntfs_u32(header->open_attributes_bytes);
	out->attribute_names.lsn = ntfs_u64(header->attribute_names_lsn);
	out->attribute_names.bytes = ntfs_u32(header->attribute_names_bytes);
	out->dirty_pages.lsn = ntfs_u64(header->dirty_pages_lsn);
	out->dirty_pages.bytes = ntfs_u32(header->dirty_pages_bytes);
	out->transactions.lsn = ntfs_u64(header->transactions_lsn);
	out->transactions.bytes = ntfs_u32(header->transactions_bytes);
	out->extension.offset = sizeof(*header);
	out->extension.length = (uint32_t)(size - sizeof(*header));
	return NTFS_OK;
}

enum ntfs_result
ntfs_logfile_client_decode(const void *buffer, size_t size, struct ntfs_logfile_client *out)
{
	const struct ntfs_disk_log_client *disk = buffer;
	struct ntfs_logfile_client client = {0};
	uint32_t name_bytes;
	size_t i;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (buffer == NULL) {
		return NTFS_INVALID;
	}
	if (size != sizeof(*disk)) {
		return NTFS_CORRUPT;
	}
	name_bytes = ntfs_u32(disk->name_bytes);
	if (name_bytes > sizeof(disk->name) || name_bytes % NTFS_UTF16_UNIT_BYTES != 0) {
		return NTFS_CORRUPT;
	}
	client.oldest_lsn = ntfs_u64(disk->oldest_lsn);
	client.restart_lsn = ntfs_u64(disk->restart_lsn);
	client.previous = ntfs_u16(disk->previous);
	client.next = ntfs_u16(disk->next);
	client.sequence = ntfs_u16(disk->sequence);
	client.name_length = (uint16_t)(name_bytes / NTFS_UTF16_UNIT_BYTES);
	for (i = 0; i < client.name_length; i++) {
		client.name[i] = ntfs_u16(disk->name + i * NTFS_UTF16_UNIT_BYTES);
	}
	*out = client;
	return NTFS_OK;
}

static enum ntfs_result
client_lists(const uint8_t *page, const struct ntfs_logfile_restart *r)
{
	struct ntfs_logfile_client client;
	struct ntfs_logfile_lsn lsn;
	uint8_t visited[LOG_CLIENT_BITMAP_BYTES] = {0};
	uint16_t index, previous, heads[] = {r->free_head, r->in_use_head};
	size_t list, count = 0;
	enum ntfs_result result;

	for (list = 0; list < sizeof(heads) / sizeof(heads[0]); list++) {
		previous = NTFS_LOGFILE_NO_CLIENT;
		index = heads[list];
		while (index != NTFS_LOGFILE_NO_CLIENT) {
			if (index >= r->client_count || count >= r->client_count ||
			    (visited[index / NTFS_BITS_PER_BYTE] &
				(1u << (index % NTFS_BITS_PER_BYTE))) != 0) {
				return NTFS_CORRUPT;
			}
			visited[index / NTFS_BITS_PER_BYTE] |=
			    (uint8_t)(1u << (index % NTFS_BITS_PER_BYTE));
			count++;
			result = ntfs_logfile_client_decode(page + r->clients.offset +
				(size_t)index * sizeof(struct ntfs_disk_log_client),
			    sizeof(struct ntfs_disk_log_client), &client);
			if (result != NTFS_OK || client.previous != previous) {
				return NTFS_CORRUPT;
			}
			/* Free records may retain stale LSNs from a prior client lifetime.
			 * Only active clients participate in restart LSN bounds. */
			if (list != 0) {
				if (client.oldest_lsn > r->current_lsn ||
				    client.restart_lsn > r->current_lsn ||
				    (client.oldest_lsn != 0 &&
					ntfs_logfile_lsn_decode(r, client.oldest_lsn, &lsn) !=
					    NTFS_OK) ||
				    (client.restart_lsn != 0 &&
					ntfs_logfile_lsn_decode(r, client.restart_lsn, &lsn) !=
					    NTFS_OK)) {
					return NTFS_CORRUPT;
				}
			}
			previous = index;
			index = client.next;
		}
	}
	return count == r->client_count ? NTFS_OK : NTFS_CORRUPT;
}

static enum ntfs_result
restore_page(const void *input, size_t size, size_t header_bytes, size_t data_offset,
    const char *magic, void *scratch, size_t scratch_bytes)
{
	const struct ntfs_disk_mst *mst = input;
	size_t usa_offset, usa_bytes;

	if (input == NULL || scratch == NULL) {
		return NTFS_INVALID;
	}
	if (size < header_bytes || size % NTFS_MST_STRIDE != 0 ||
	    !ntfs_equal(mst->magic, magic, sizeof(mst->magic))) {
		return NTFS_CORRUPT;
	}
	if (scratch_bytes < size) {
		return NTFS_RANGE;
	}
	usa_offset = ntfs_u16(mst->usa_offset);
	usa_bytes = (size_t)ntfs_u16(mst->usa_count) * NTFS_MST_WORD_BYTES;
	if (usa_offset < header_bytes || !ntfs_bounds(usa_offset, usa_bytes, data_offset)) {
		return NTFS_CORRUPT;
	}
	ntfs_copy(scratch, input, size);
	return ntfs_fixup(scratch, size, magic);
}

enum ntfs_result
ntfs_logfile_restart_decode(const void *input, size_t size, uint64_t available_file_bytes,
    void *scratch, size_t scratch_bytes, struct ntfs_logfile_restart *out)
{
	const struct ntfs_disk_log_restart_page *header = input;
	const struct ntfs_disk_log_restart_area *area;
	struct ntfs_logfile_restart info = {0};
	struct ntfs_logfile_lsn lsn;
	size_t clients_offset;
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (input == NULL || scratch == NULL) {
		return NTFS_INVALID;
	}
	if (size < sizeof(*header)) {
		return NTFS_CORRUPT;
	}
	if (ntfs_equal(header->mst.magic, "CHKD", sizeof(header->mst.magic))) {
		return NTFS_UNSUPPORTED;
	}
	if (!ntfs_equal(header->mst.magic, "RSTR", sizeof(header->mst.magic))) {
		return NTFS_CORRUPT;
	}
	info.major = ntfs_u16(header->major);
	info.minor = ntfs_u16(header->minor);
	if (!version(info.major, info.minor)) {
		/* An unknown version may use different integrity protection. Do not
		 * first apply this version's USA contract and mislabel it corrupt. */
		return NTFS_UNSUPPORTED;
	}
	info.system_page_bytes = ntfs_u32(header->system_page_bytes);
	info.log_page_bytes = ntfs_u32(header->log_page_bytes);
	if (!page_size(info.system_page_bytes) || !page_size(info.log_page_bytes)) {
		return NTFS_CORRUPT;
	}
	if (info.system_page_bytes > NTFS_LOGFILE_MAX_PAGE_BYTES ||
	    info.log_page_bytes > NTFS_LOGFILE_MAX_PAGE_BYTES) {
		return NTFS_UNSUPPORTED;
	}
	info.area.offset = ntfs_u16(header->area_offset);
	if (size != info.system_page_bytes || info.area.offset % NTFS_WIRE_ALIGNMENT != 0 ||
	    !ntfs_bounds(info.area.offset, sizeof(*area), size) ||
	    !ntfs_bounds(info.area.offset, sizeof(*area), NTFS_MST_STRIDE - NTFS_MST_WORD_BYTES)) {
		return NTFS_CORRUPT;
	}
	result = restore_page(
	    input, size, sizeof(*header), info.area.offset, "RSTR", scratch, scratch_bytes);
	if (result != NTFS_OK) {
		return result;
	}
	header = scratch;
	if (ntfs_u64(header->chkdsk_lsn) != 0) {
		return NTFS_CORRUPT;
	}
	area = (const void *)((const uint8_t *)scratch + info.area.offset);
	info.current_lsn = ntfs_u64(area->current_lsn);
	info.file_bytes = ntfs_u64(area->file_bytes);
	info.usable_bytes = info.file_bytes - info.file_bytes % info.log_page_bytes;
	info.circular_offset = (uint64_t)NTFS_LFS_RESTART_PAGES * info.system_page_bytes +
	    (uint64_t)(info.major == NTFS_LFS_MAJOR_FAST ? NTFS_LFS_FAST_PAGES
							 : NTFS_LFS_LEGACY_TAIL_PAGES) *
		info.log_page_bytes;
	info.client_count = ntfs_u16(area->clients);
	info.free_head = ntfs_u16(area->free_head);
	info.in_use_head = ntfs_u16(area->in_use_head);
	info.flags = ntfs_u16(area->flags);
	info.sequence_bits = ntfs_u32(area->sequence_bits);
	info.area.length = ntfs_u16(area->length);
	info.record_header_bytes = ntfs_u16(area->record_header_bytes);
	info.page_data_offset = ntfs_u16(area->page_data_offset);
	info.last_data_bytes = ntfs_u32(area->last_data_bytes);
	info.open_count = ntfs_u32(area->open_count);
	clients_offset = ntfs_u16(area->clients_offset);
	info.clients.offset = info.area.offset + (uint32_t)clients_offset;
	info.clients.length = (uint32_t)info.client_count * sizeof(struct ntfs_disk_log_client);
	if (!geometry(&info) || info.file_bytes > available_file_bytes ||
	    info.client_count > LOG_MAX_CLIENTS ||
	    !ntfs_bounds(info.area.offset, info.area.length, size) ||
	    clients_offset < sizeof(*area) || clients_offset % NTFS_WIRE_ALIGNMENT != 0 ||
	    !ntfs_bounds(clients_offset, info.clients.length, info.area.length) ||
	    info.clients.offset > NTFS_MST_STRIDE - NTFS_MST_WORD_BYTES ||
	    (info.current_lsn != 0 &&
		ntfs_logfile_lsn_decode(&info, info.current_lsn, &lsn) != NTFS_OK)) {
		return NTFS_CORRUPT;
	}
	if (info.last_data_bytes > NTFS_LOGFILE_MAX_RECORD_BYTES - info.record_header_bytes) {
		return NTFS_RANGE;
	}
	result = client_lists(scratch, &info);
	if (result != NTFS_OK) {
		return result;
	}
	info.clean_hint = info.in_use_head == NTFS_LOGFILE_NO_CLIENT ||
	    (info.flags & NTFS_LOGFILE_RESTART_CLEAN) != 0;
	*out = info;
	return NTFS_OK;
}

enum ntfs_result
ntfs_logfile_page_decode(const void *input, size_t size, const struct ntfs_logfile_restart *restart,
    void *scratch, size_t scratch_bytes, struct ntfs_logfile_page *out)
{
	const struct ntfs_disk_log_page *header;
	struct ntfs_logfile_page info = {0};
	struct ntfs_logfile_lsn lsn;
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (!geometry(restart)) {
		return NTFS_INVALID;
	}
	if (size != restart->log_page_bytes) {
		return NTFS_CORRUPT;
	}
	result = restore_page(input, size, sizeof(*header), restart->page_data_offset, "RCRD",
	    scratch, scratch_bytes);
	if (result != NTFS_OK) {
		return result;
	}
	header = scratch;
	info.copy_value = ntfs_u64(header->copy_value);
	info.last_end_lsn = ntfs_u64(header->last_end_lsn);
	info.flags = ntfs_u32(header->flags);
	info.page_count = ntfs_u16(header->page_count);
	info.page_position = ntfs_u16(header->page_position);
	info.next_record_offset = ntfs_u16(header->next_record_offset);
	if (info.page_position > info.page_count ||
	    ((info.page_position == 0) != (info.page_count == 0)) ||
	    (info.next_record_offset != 0 &&
		(info.next_record_offset < restart->page_data_offset ||
		    info.next_record_offset > size ||
		    info.next_record_offset % NTFS_WIRE_ALIGNMENT != 0)) ||
	    (info.last_end_lsn != 0 &&
		ntfs_logfile_lsn_decode(restart, info.last_end_lsn, &lsn) != NTFS_OK)) {
		return NTFS_CORRUPT;
	}
	*out = info;
	return NTFS_OK;
}

enum ntfs_result
ntfs_logfile_record_decode(
    const void *input, size_t size, uint16_t header_bytes, struct ntfs_logfile_record *out)
{
	const struct ntfs_disk_log_record *header = input;
	struct ntfs_logfile_record info = {0};

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (input == NULL || header_bytes < sizeof(*header) ||
	    header_bytes % NTFS_WIRE_ALIGNMENT != 0) {
		return NTFS_INVALID;
	}
	if (size > NTFS_LOGFILE_MAX_RECORD_BYTES) {
		return NTFS_RANGE;
	}
	if (size < header_bytes || ntfs_u32(header->data_bytes) != size - header_bytes) {
		return NTFS_CORRUPT;
	}
	info.lsn = ntfs_u64(header->lsn);
	info.previous_lsn = ntfs_u64(header->previous_lsn);
	info.undo_next_lsn = ntfs_u64(header->undo_next_lsn);
	info.type = ntfs_u32(header->type);
	info.transaction = ntfs_u32(header->transaction);
	info.client_sequence = ntfs_u16(header->client_sequence);
	info.client_index = ntfs_u16(header->client_index);
	info.flags = ntfs_u16(header->flags);
	info.data.offset = header_bytes;
	info.data.length = (uint32_t)(size - header_bytes);
	if (info.lsn == 0 || info.previous_lsn >= info.lsn || info.undo_next_lsn >= info.lsn ||
	    info.client_index == NTFS_LOGFILE_NO_CLIENT) {
		return NTFS_CORRUPT;
	}
	if ((info.flags &
		~(NTFS_LOGFILE_RECORD_MULTI_PAGE | NTFS_LOGFILE_RECORD_DELETING |
		    NTFS_LOGFILE_RECORD_ADDING)) != 0 ||
	    (info.type != NTFS_LOGFILE_RECORD_UPDATE && info.type != NTFS_LOGFILE_RECORD_RESTART)) {
		return NTFS_UNSUPPORTED;
	}
	*out = info;
	return NTFS_OK;
}

static bool
update_span(struct ntfs_logfile_span span, size_t prefix, size_t size)
{
	return span.offset % NTFS_WIRE_ALIGNMENT == 0 &&
	    ntfs_bounds(span.offset, span.length, size) &&
	    ((span.length == 0 && span.offset == 0) || span.offset >= prefix);
}

enum ntfs_result
ntfs_logfile_update_decode(const void *input, size_t size, struct ntfs_logfile_update *out)
{
	const struct ntfs_disk_log_update *header = input;
	struct ntfs_logfile_update info = {0};
	size_t prefix;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (input == NULL) {
		return NTFS_INVALID;
	}
	if (size > NTFS_LOGFILE_MAX_RECORD_BYTES) {
		return NTFS_RANGE;
	}
	if (size < sizeof(struct ntfs_disk_log_update_storage)) {
		return NTFS_CORRUPT;
	}
	info.redo_operation = ntfs_u16(header->redo_operation);
	info.undo_operation = ntfs_u16(header->undo_operation);
	info.redo =
	    (struct ntfs_logfile_span){ntfs_u16(header->redo_offset), ntfs_u16(header->redo_bytes)};
	info.undo =
	    (struct ntfs_logfile_span){ntfs_u16(header->undo_offset), ntfs_u16(header->undo_bytes)};
	info.target_attribute = ntfs_u16(header->target_attribute);
	info.lcn_count = ntfs_u16(header->lcns);
	info.record_offset = ntfs_u16(header->record_offset);
	info.attribute_offset = ntfs_u16(header->attribute_offset);
	info.cluster_index = ntfs_u16(header->cluster_index);
	info.attribute_flags = ntfs_u16(header->attribute_flags);
	info.target_vcn = ntfs_u64(header->target_vcn);
	info.lcns = (struct ntfs_logfile_span){
	    sizeof(*header), (uint32_t)info.lcn_count * sizeof(uint64_t)};
	/* Published offsets are relative to the complete client payload. Original
	 * checkpoint packets retain a reserved first slot with arbitrary stale bytes
	 * when lcn_count is zero; it changes span admission, never the vector count. */
	prefix = info.lcn_count == 0 ? sizeof(struct ntfs_disk_log_update_storage)
				     : sizeof(*header) + info.lcns.length;
	if (prefix > size || !update_span(info.redo, prefix, size) ||
	    !update_span(info.undo, prefix, size)) {
		return NTFS_CORRUPT;
	}
	*out = info;
	return NTFS_OK;
}
