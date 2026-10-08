/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include "logfile_tables_disk.h"
#include <ntfs/logfile_tables.h>

static bool
logfile_table_entry_offset(const struct ntfs_logfile_restart_table *table, uint32_t offset)
{
	return offset >= table->entries.offset &&
	    (offset - table->entries.offset) % table->entry_bytes == 0 &&
	    (offset - table->entries.offset) / table->entry_bytes < table->entry_count;
}

enum ntfs_result
ntfs_logfile_restart_table_decode(
    const void *input, size_t size, struct ntfs_logfile_restart_table *out)
{
	const struct ntfs_disk_log_table *header = input;
	const uint8_t *bytes = input;
	struct ntfs_logfile_restart_table table = {0};
	size_t index, entries_bytes;
	uint32_t allocated = 0, free_count = 0, offset, next, previous = 0;

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
	table.entry_bytes = ntfs_u16(header->entry_bytes);
	table.entry_count = ntfs_u16(header->entries);
	table.allocated_count = ntfs_u16(header->allocated);
	table.free_goal = ntfs_u32(header->free_goal);
	table.first_free = ntfs_u32(header->first_free);
	table.last_free = ntfs_u32(header->last_free);
	entries_bytes = (size_t)table.entry_count * table.entry_bytes;
	if (table.entry_bytes < sizeof(uint32_t) || table.allocated_count > table.entry_count ||
	    entries_bytes != size - sizeof(*header)) {
		return NTFS_CORRUPT;
	}
	table.entries.offset = sizeof(*header);
	table.entries.length = (uint32_t)entries_bytes;
	for (index = 0; index < table.entry_count; index++) {
		offset = table.entries.offset + (uint32_t)index * table.entry_bytes;
		next = ntfs_u32(bytes + offset);
		if (next == NTFS_LOG_TABLE_ALLOCATED) {
			allocated++;
		} else if (next != 0 && !logfile_table_entry_offset(&table, next)) {
			return NTFS_CORRUPT;
		}
	}
	if (allocated != table.allocated_count ||
	    (table.first_free != 0 && !logfile_table_entry_offset(&table, table.first_free)) ||
	    (table.last_free != 0 && !logfile_table_entry_offset(&table, table.last_free))) {
		return NTFS_CORRUPT;
	}
	offset = table.first_free;
	while (offset != 0) {
		/* A deterministic singly linked chain cannot repeat an entry and still
		 * terminate. Bounding it by the exact free count proves both acyclicity
		 * and complete coverage without allocating a table-sized bitmap. */
		if (free_count >= table.entry_count - allocated) {
			return NTFS_CORRUPT;
		}
		next = ntfs_u32(bytes + offset);
		if (next == NTFS_LOG_TABLE_ALLOCATED) {
			return NTFS_CORRUPT;
		}
		free_count++;
		previous = offset;
		offset = next;
	}
	if (free_count != table.entry_count - allocated || previous != table.last_free) {
		return NTFS_CORRUPT;
	}
	*out = table;
	return NTFS_OK;
}

static bool
logfile_table_client_version(uint32_t major, uint32_t minor)
{
	return (major == NTFS_LOG_CLIENT_MAJOR_BASE || major == NTFS_LOG_CLIENT_MAJOR_ATTRIBUTES) &&
	    minor == NTFS_LOG_CLIENT_MINOR;
}

enum ntfs_result
ntfs_logfile_open_attribute_decode(const void *input, size_t size, uint32_t major, uint32_t minor,
    struct ntfs_logfile_open_attribute *out)
{
	const struct ntfs_disk_log_open_attribute_base *base = input;
	const struct ntfs_disk_log_open_attribute *attributes = input;
	struct ntfs_logfile_open_attribute value = {0};
	size_t expected;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (input == NULL) {
		return NTFS_INVALID;
	}
	if (!logfile_table_client_version(major, minor)) {
		return NTFS_UNSUPPORTED;
	}
	expected = major == NTFS_LOG_CLIENT_MAJOR_BASE ? sizeof(*base) : sizeof(*attributes);
	if (size != expected) {
		return NTFS_CORRUPT;
	}
	if (ntfs_u32(input) != NTFS_LOG_TABLE_ALLOCATED) {
		return NTFS_NOT_FOUND;
	}
	if (major == NTFS_LOG_CLIENT_MAJOR_BASE) {
		value.reference = ntfs_u64(base->reference);
		value.open_lsn = ntfs_u64(base->open_lsn);
		value.attribute_type = ntfs_u32(base->attribute_type);
		value.index_buffer_bytes = ntfs_u32(base->index_buffer_bytes);
		value.legacy_attribute_offset = ntfs_u32(base->attribute_offset);
	} else {
		value.reference = ntfs_u64(attributes->reference);
		value.open_lsn = ntfs_u64(attributes->open_lsn);
		value.attribute_type = ntfs_u32(attributes->attribute_type);
		value.index_buffer_bytes = ntfs_u32(attributes->index_buffer_bytes);
		value.dirty_pages_known = true;
		value.dirty_pages = attributes->dirty_pages;
	}
	*out = value;
	return NTFS_OK;
}

enum ntfs_result
ntfs_logfile_dirty_page_decode(const void *input, size_t size, uint32_t major, uint32_t minor,
    struct ntfs_logfile_dirty_page *out)
{
	const struct ntfs_disk_log_dirty_page_base *base = input;
	const struct ntfs_disk_log_dirty_page *page = input;
	struct ntfs_logfile_dirty_page value = {0};
	size_t prefix, available;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (input == NULL) {
		return NTFS_INVALID;
	}
	if (!logfile_table_client_version(major, minor)) {
		return NTFS_UNSUPPORTED;
	}
	if (size > NTFS_LOGFILE_MAX_RECORD_BYTES) {
		return NTFS_RANGE;
	}
	prefix = major == NTFS_LOG_CLIENT_MAJOR_BASE ? sizeof(*base) : sizeof(*page);
	if (size < prefix || (size - prefix) % sizeof(uint64_t) != 0) {
		return NTFS_CORRUPT;
	}
	if (ntfs_u32(input) != NTFS_LOG_TABLE_ALLOCATED) {
		return NTFS_NOT_FOUND;
	}
	if (major == NTFS_LOG_CLIENT_MAJOR_BASE) {
		value.target_attribute = ntfs_u32(base->target_attribute);
		value.transfer_bytes = ntfs_u32(base->transfer_bytes);
		value.lcn_count = ntfs_u32(base->lcns);
		value.vcn = ntfs_u64(base->vcn);
		value.oldest_lsn = ntfs_u64(base->oldest_lsn);
	} else {
		value.target_attribute = ntfs_u32(page->target_attribute);
		value.transfer_bytes = ntfs_u32(page->transfer_bytes);
		value.lcn_count = ntfs_u32(page->lcns);
		value.vcn = ntfs_u64(page->vcn);
		value.oldest_lsn = ntfs_u64(page->oldest_lsn);
	}
	available = size - prefix;
	if (value.lcn_count > available / sizeof(uint64_t)) {
		return NTFS_CORRUPT;
	}
	value.lcns.offset = (uint32_t)prefix;
	value.lcns.length = value.lcn_count * sizeof(uint64_t);
	value.unused.offset = value.lcns.offset + value.lcns.length;
	value.unused.length = (uint32_t)(available - value.lcns.length);
	*out = value;
	return NTFS_OK;
}

enum ntfs_result
ntfs_logfile_transaction_decode(
    const void *input, size_t size, struct ntfs_logfile_transaction *out)
{
	const struct ntfs_disk_log_transaction *entry = input;
	struct ntfs_logfile_transaction value = {0};
	uint32_t state;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (input == NULL) {
		return NTFS_INVALID;
	}
	if (size != sizeof(*entry)) {
		return NTFS_CORRUPT;
	}
	if (ntfs_u32(entry->allocated) != NTFS_LOG_TABLE_ALLOCATED) {
		return NTFS_NOT_FOUND;
	}
	state = ntfs_u32(entry->state);
	if (state > NTFS_LOGFILE_TRANSACTION_COMMITTED) {
		return NTFS_UNSUPPORTED;
	}
	value.state = (enum ntfs_logfile_transaction_state)state;
	value.first_lsn = ntfs_u64(entry->first_lsn);
	value.previous_lsn = ntfs_u64(entry->previous_lsn);
	value.undo_next_lsn = ntfs_u64(entry->undo_next_lsn);
	value.undo_records = ntfs_u32(entry->undo_records);
	value.undo_bytes = ntfs_u32(entry->undo_bytes);
	*out = value;
	return NTFS_OK;
}

enum ntfs_result
ntfs_logfile_attribute_name_decode(
    const void *input, size_t size, struct ntfs_logfile_attribute_name *out)
{
	const struct ntfs_disk_log_attribute_name *header = input;
	const uint8_t *bytes = input;
	struct ntfs_logfile_attribute_name value = {0};
	uint16_t name_bytes;
	size_t total;

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
	value.target_attribute = ntfs_u16(header->target_attribute);
	name_bytes = ntfs_u16(header->name_bytes);
	if (value.target_attribute == 0) {
		return name_bytes == 0 ? NTFS_END : NTFS_CORRUPT;
	}
	total = sizeof(*header) + (size_t)name_bytes + sizeof(uint16_t);
	if (name_bytes % sizeof(uint16_t) != 0 || total > size ||
	    ntfs_u16(bytes + sizeof(*header) + name_bytes) != 0) {
		return NTFS_CORRUPT;
	}
	value.name_units = name_bytes / sizeof(uint16_t);
	value.bytes = (uint32_t)total;
	value.name = (struct ntfs_logfile_span){sizeof(*header), name_bytes};
	*out = value;
	return NTFS_OK;
}

enum ntfs_result
ntfs_logfile_attribute_names_decode(
    const void *input, size_t size, struct ntfs_logfile_attribute_names *out)
{
	struct ntfs_logfile_attribute_names value = {0};
	struct ntfs_logfile_attribute_name entry;
	const uint8_t *bytes = input;
	size_t offset = 0;
	enum ntfs_result result;

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
	for (;;) {
		result = ntfs_logfile_attribute_name_decode(bytes + offset, size - offset, &entry);
		if (result == NTFS_END) {
			if (size - offset != sizeof(struct ntfs_disk_log_attribute_name)) {
				return NTFS_CORRUPT;
			}
			value.entries.length = (uint32_t)offset;
			*out = value;
			return NTFS_OK;
		}
		if (result != NTFS_OK) {
			return result;
		}
		offset += entry.bytes;
		value.entry_count++;
	}
}
