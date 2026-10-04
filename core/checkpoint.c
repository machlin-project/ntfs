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

static enum ntfs_result
attribute_index(const uint8_t *body, const struct ntfs_logfile_restart_table *table, uint32_t key,
    size_t *index)
{
	uint32_t relative;

	if (key < table->entries.offset || table->entry_bytes == 0) {
		return NTFS_CORRUPT;
	}
	relative = key - table->entries.offset;
	if (relative % table->entry_bytes != 0 ||
	    relative / table->entry_bytes >= table->entry_count ||
	    ntfs_u32(body + key) != NTFS_LOG_TABLE_ALLOCATED) {
		return NTFS_CORRUPT;
	}
	*index = relative / table->entry_bytes;
	return NTFS_OK;
}

static enum ntfs_result
validate_names(const uint8_t *body, const struct ntfs_logfile_attribute_names *names,
    const uint8_t *attributes, const struct ntfs_logfile_restart_table *table, uint8_t *workspace,
    size_t workspace_bytes)
{
	struct ntfs_logfile_attribute_name name;
	size_t needed, offset = 0, index;
	uint32_t count;
	uint8_t bit;
	enum ntfs_result result;

	_Static_assert(NTFS_LOGFILE_CHECKPOINT_NAME_WORKSPACE_BYTES >=
		(UINT16_MAX + NTFS_BITS_PER_BYTE - 1u) / NTFS_BITS_PER_BYTE,
	    "name membership scratch covers every restart-table entry");
	if (names->entry_count == 0) {
		return NTFS_OK;
	}
	if (names->entry_count > table->allocated_count) {
		return NTFS_CORRUPT;
	}
	needed = (table->entry_count + NTFS_BITS_PER_BYTE - 1u) / NTFS_BITS_PER_BYTE;
	if (workspace == NULL) {
		return NTFS_INVALID;
	}
	if (workspace_bytes < needed) {
		return NTFS_RANGE;
	}
	ntfs_zero(workspace, needed);
	for (count = 0; count < names->entry_count; count++) {
		result = ntfs_logfile_attribute_name_decode(
		    body + offset, names->entries.length - offset, &name);
		if (result != NTFS_OK) {
			return result;
		}
		result = attribute_index(attributes, table, name.target_attribute, &index);
		if (result != NTFS_OK) {
			return result;
		}
		bit = (uint8_t)(1u << (index % NTFS_BITS_PER_BYTE));
		if ((workspace[index / NTFS_BITS_PER_BYTE] & bit) != 0) {
			return NTFS_CORRUPT;
		}
		workspace[index / NTFS_BITS_PER_BYTE] |= bit;
		offset += name.bytes;
	}
	return NTFS_OK;
}

static enum ntfs_result
validate_dirty_targets(const uint8_t *body, const struct ntfs_logfile_checkpoint_table *dirty,
    const uint8_t *attributes, const struct ntfs_logfile_restart_table *table)
{
	struct ntfs_logfile_dirty_page page;
	size_t index, target;
	enum ntfs_result result;

	for (index = 0; index < dirty->table.entry_count; index++) {
		result = ntfs_logfile_dirty_page_decode(
		    body + dirty->table.entries.offset + index * dirty->table.entry_bytes,
		    dirty->table.entry_bytes, dirty->client_major, dirty->client_minor, &page);
		if (result == NTFS_NOT_FOUND) {
			continue;
		}
		if (result != NTFS_OK) {
			return result;
		}
		result = attribute_index(attributes, table, page.target_attribute, &target);
		if (result != NTFS_OK) {
			return result;
		}
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_logfile_checkpoint_decode(const struct ntfs_logfile *source, const void *checkpoint,
    size_t checkpoint_bytes,
    const struct ntfs_logfile_checkpoint_dump dumps[NTFS_LOGFILE_CHECKPOINT_KINDS], void *workspace,
    size_t workspace_bytes, struct ntfs_logfile_checkpoint_snapshot *out)
{
	const struct ntfs_disk_log_record *record = checkpoint;
	struct ntfs_logfile_checkpoint_snapshot value = {0};
	struct ntfs_logfile_client_restart client;
	const struct ntfs_logfile_checkpoint_table *open, *names, *dirty;
	const uint8_t *attributes = NULL;
	size_t kind, previous;
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (dumps == NULL) {
		return NTFS_INVALID;
	}
	result = ntfs_logfile_decode_client_restart_record(
	    source, checkpoint, checkpoint_bytes, &client);
	if (result != NTFS_OK) {
		return result;
	}
	for (kind = 0; kind < NTFS_LOGFILE_CHECKPOINT_KINDS; kind++) {
		result = ntfs_logfile_checkpoint_table_decode(source,
		    (enum ntfs_logfile_checkpoint_kind)kind, checkpoint, checkpoint_bytes,
		    dumps[kind].data, dumps[kind].bytes, &value.tables[kind]);
		if (result == NTFS_NOT_FOUND) {
			continue;
		}
		if (result != NTFS_OK) {
			return result;
		}
		for (previous = 0; previous < kind; previous++) {
			if ((value.present_mask & (1u << previous)) != 0 &&
			    value.tables[previous].table_lsn == value.tables[kind].table_lsn) {
				return NTFS_CORRUPT;
			}
		}
		value.present_mask |= 1u << kind;
	}
	open = &value.tables[NTFS_LOGFILE_CHECKPOINT_OPEN_ATTRIBUTES];
	names = &value.tables[NTFS_LOGFILE_CHECKPOINT_ATTRIBUTE_NAMES];
	dirty = &value.tables[NTFS_LOGFILE_CHECKPOINT_DIRTY_PAGES];
	if ((value.present_mask & (1u << NTFS_LOGFILE_CHECKPOINT_OPEN_ATTRIBUTES)) != 0) {
		attributes = (const uint8_t *)dumps[NTFS_LOGFILE_CHECKPOINT_OPEN_ATTRIBUTES].data +
		    open->body.offset;
	}
	if (attributes == NULL &&
	    (names->names.entry_count != 0 || dirty->table.allocated_count != 0)) {
		return NTFS_CORRUPT;
	}
	if ((value.present_mask & (1u << NTFS_LOGFILE_CHECKPOINT_ATTRIBUTE_NAMES)) != 0) {
		result = validate_names(
		    (const uint8_t *)dumps[NTFS_LOGFILE_CHECKPOINT_ATTRIBUTE_NAMES].data +
			names->body.offset,
		    &names->names, attributes, &open->table, workspace, workspace_bytes);
		if (result != NTFS_OK) {
			return result;
		}
	}
	if ((value.present_mask & (1u << NTFS_LOGFILE_CHECKPOINT_DIRTY_PAGES)) != 0) {
		result = validate_dirty_targets(
		    (const uint8_t *)dumps[NTFS_LOGFILE_CHECKPOINT_DIRTY_PAGES].data +
			dirty->body.offset,
		    dirty, attributes, &open->table);
		if (result != NTFS_OK) {
			return result;
		}
	}
	value.client_major = client.major;
	value.client_minor = client.minor;
	value.checkpoint_lsn = ntfs_u64(record->lsn);
	value.named_attributes = names->names.entry_count;
	value.dirty_pages = dirty->table.allocated_count;
	*out = value;
	return NTFS_OK;
}
