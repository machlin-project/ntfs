/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include "logfile_tables_disk.h"
#include <ntfs/checkpoint.h>

static enum ntfs_result
validate_entries(const uint8_t *bytes, const struct ntfs_logfile_restart_table *table,
    enum ntfs_logfile_checkpoint_kind kind, uint32_t major, uint32_t minor)
{
	struct ntfs_logfile_open_attribute attribute;
	struct ntfs_logfile_dirty_page page;
	struct ntfs_logfile_transaction transaction;
	const void *entry;
	size_t expected, index;
	enum ntfs_result result;

	if (kind == NTFS_LOGFILE_CHECKPOINT_OPEN_ATTRIBUTES) {
		expected = major == NTFS_LOG_CLIENT_MAJOR_BASE
		    ? sizeof(struct ntfs_disk_log_open_attribute_base)
		    : sizeof(struct ntfs_disk_log_open_attribute);
		if (table->entry_bytes != expected) {
			return NTFS_UNSUPPORTED;
		}
	} else if (kind == NTFS_LOGFILE_CHECKPOINT_DIRTY_PAGES) {
		expected = major == NTFS_LOG_CLIENT_MAJOR_BASE
		    ? sizeof(struct ntfs_disk_log_dirty_page_base)
		    : sizeof(struct ntfs_disk_log_dirty_page);
		if (table->entry_bytes < expected ||
		    (table->entry_bytes - expected) % sizeof(uint64_t) != 0) {
			return NTFS_UNSUPPORTED;
		}
	} else if (table->entry_bytes != sizeof(struct ntfs_disk_log_transaction)) {
		return NTFS_UNSUPPORTED;
	}
	for (index = 0; index < table->entry_count; index++) {
		entry = bytes + table->entries.offset + index * table->entry_bytes;
		if (kind == NTFS_LOGFILE_CHECKPOINT_OPEN_ATTRIBUTES) {
			result = ntfs_logfile_open_attribute_decode(
			    entry, table->entry_bytes, major, minor, &attribute);
		} else if (kind == NTFS_LOGFILE_CHECKPOINT_DIRTY_PAGES) {
			result = ntfs_logfile_dirty_page_decode(
			    entry, table->entry_bytes, major, minor, &page);
		} else {
			result = ntfs_logfile_transaction_decode(
			    entry, table->entry_bytes, &transaction);
		}
		if (result != NTFS_OK && result != NTFS_NOT_FOUND) {
			return result;
		}
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_logfile_checkpoint_table_decode(const struct ntfs_logfile *source,
    enum ntfs_logfile_checkpoint_kind kind, const void *checkpoint_input, size_t checkpoint_bytes,
    const void *table_input, size_t table_bytes, struct ntfs_logfile_checkpoint_table *out)
{
	static const uint16_t operations[] = {NTFS_LOG_OP_OPEN_ATTRIBUTE_TABLE_DUMP,
	    NTFS_LOG_OP_ATTRIBUTE_NAMES_DUMP, NTFS_LOG_OP_DIRTY_PAGE_TABLE_DUMP,
	    NTFS_LOG_OP_TRANSACTION_TABLE_DUMP};
	const struct ntfs_disk_log_record *checkpoint = checkpoint_input;
	const uint8_t *bytes = table_input;
	struct ntfs_logfile_checkpoint_table value = {0};
	struct ntfs_logfile_client_restart client;
	struct ntfs_logfile_restart restart;
	struct ntfs_logfile_record record;
	struct ntfs_logfile_update update;
	struct ntfs_logfile_table_reference anchor;
	struct ntfs_logfile_lsn location;
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (kind < NTFS_LOGFILE_CHECKPOINT_OPEN_ATTRIBUTES ||
	    kind > NTFS_LOGFILE_CHECKPOINT_TRANSACTIONS) {
		return NTFS_INVALID;
	}
	result = ntfs_logfile_decode_client_restart_record(
	    source, checkpoint_input, checkpoint_bytes, &client);
	if (result != NTFS_OK) {
		return result;
	}
	value.checkpoint_lsn = ntfs_u64(checkpoint->lsn);
	switch (kind) {
	case NTFS_LOGFILE_CHECKPOINT_OPEN_ATTRIBUTES:
		anchor = client.open_attributes;
		break;
	case NTFS_LOGFILE_CHECKPOINT_ATTRIBUTE_NAMES:
		anchor = client.attribute_names;
		break;
	case NTFS_LOGFILE_CHECKPOINT_DIRTY_PAGES:
		anchor = client.dirty_pages;
		break;
	case NTFS_LOGFILE_CHECKPOINT_TRANSACTIONS:
		anchor = client.transactions;
		break;
	default:
		return NTFS_INVALID;
	}
	if (anchor.lsn == 0 && anchor.bytes == 0) {
		return NTFS_NOT_FOUND;
	}
	if (anchor.lsn == 0 || anchor.bytes == 0 || anchor.lsn >= value.checkpoint_lsn) {
		return NTFS_CORRUPT;
	}
	if (anchor.bytes > NTFS_LOGFILE_MAX_RECORD_BYTES) {
		return NTFS_RANGE;
	}
	result = ntfs_logfile_get_restart(source, &restart);
	if (result != NTFS_OK) {
		return result;
	}
	if (ntfs_logfile_lsn_decode(&restart, anchor.lsn, &location) != NTFS_OK) {
		return NTFS_CORRUPT;
	}
	result = ntfs_logfile_record_decode(
	    table_input, table_bytes, restart.record_header_bytes, &record);
	if (result != NTFS_OK) {
		return result;
	}
	if (record.lsn != anchor.lsn || record.client_index != ntfs_u16(checkpoint->client_index) ||
	    record.client_sequence != ntfs_u16(checkpoint->client_sequence)) {
		return NTFS_STALE;
	}
	if (record.type != NTFS_LOGFILE_RECORD_UPDATE) {
		return NTFS_UNSUPPORTED;
	}
	if ((record.previous_lsn != 0 &&
		ntfs_logfile_lsn_decode(&restart, record.previous_lsn, &location) != NTFS_OK) ||
	    (record.undo_next_lsn != 0 &&
		ntfs_logfile_lsn_decode(&restart, record.undo_next_lsn, &location) != NTFS_OK)) {
		return NTFS_CORRUPT;
	}
	result =
	    ntfs_logfile_update_decode(bytes + record.data.offset, record.data.length, &update);
	if (result != NTFS_OK) {
		return result;
	}
	if (update.redo_operation != operations[kind] ||
	    update.undo_operation != NTFS_LOG_OP_NOOP || update.undo.length != 0 ||
	    update.lcn_count != 0) {
		return NTFS_UNSUPPORTED;
	}
	if (update.redo.length != anchor.bytes) {
		return NTFS_CORRUPT;
	}
	value.body =
	    (struct ntfs_logfile_span){record.data.offset + update.redo.offset, update.redo.length};
	bytes += value.body.offset;
	if (kind == NTFS_LOGFILE_CHECKPOINT_ATTRIBUTE_NAMES) {
		result =
		    ntfs_logfile_attribute_names_decode(bytes, value.body.length, &value.names);
	} else {
		result = ntfs_logfile_restart_table_decode(bytes, value.body.length, &value.table);
		if (result == NTFS_OK) {
			result =
			    validate_entries(bytes, &value.table, kind, client.major, client.minor);
		}
	}
	if (result != NTFS_OK) {
		return result;
	}
	value.kind = kind;
	value.client_major = client.major;
	value.client_minor = client.minor;
	value.table_lsn = anchor.lsn;
	*out = value;
	return NTFS_OK;
}
