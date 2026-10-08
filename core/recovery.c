/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include "logfile_internal.h"
#include "logfile_tables_disk.h"
#include <ntfs/recovery.h>

struct ntfs_recovery {
	struct ntfs_environment environment;
	struct ntfs_volume *backing;
	struct ntfs_recovery_limits limits;
	struct ntfs_logfile_restart restart;
	struct ntfs_logfile_checkpoint_capture checkpoint;
	struct ntfs_recovery_record *records;
	struct ntfs_recovery_transaction *transactions;
	uint32_t *slots;
	uint8_t *checkpoint_bytes, *history_bytes;
	uint32_t record_count, transaction_count, history_size;
};

struct ntfs_recovery_workspace {
	struct ntfs_recovery *owner;
	struct ntfs_recovery_report *report;
};

enum {
	RECOVERY_STAGE_BYTES = NTFS_LOGFILE_MAX_RECORD_BYTES,
	RECOVERY_TABLE_KEY_BASE = sizeof(struct ntfs_disk_log_table),
	RECOVERY_TABLE_KEY_STRIDE = sizeof(struct ntfs_disk_log_transaction),
	/* Original Windows checkpoint dumps carry this common-header flag. Its
	 * meaning for ordinary updates remains unqualified. Exact checkpoint
	 * packet binding below is required before publication. */
	RECOVERY_CHECKPOINT_DUMP_FLAG = 0x0004
};

void
ntfs_recovery_default_limits(struct ntfs_recovery_limits *limits)
{
	if (limits != NULL) {
		*limits = (struct ntfs_recovery_limits){NTFS_RECOVERY_MAX_RECORDS,
		    NTFS_RECOVERY_MAX_HISTORY_BYTES, NTFS_RECOVERY_DEFAULT_READ_CALLS,
		    NTFS_RECOVERY_DEFAULT_READ_BYTES, NTFS_DEFAULT_MAX_LIVE_BYTES};
	}
}

static bool
recovery_valid_limits(const struct ntfs_recovery_limits *limits)
{
	return limits->max_records != 0 && limits->max_records <= NTFS_RECOVERY_MAX_RECORDS &&
	    limits->max_history_bytes != 0 &&
	    limits->max_history_bytes <= NTFS_RECOVERY_MAX_HISTORY_BYTES &&
	    limits->max_read_calls != 0 && limits->max_read_bytes != 0 &&
	    limits->max_live_bytes != 0;
}

static void
recovery_release(struct ntfs_recovery *owner, void *bytes, size_t size)
{
	if (bytes != NULL) {
		owner->environment.release(owner->environment.context, bytes, size);
	}
}

void
ntfs_recovery_close(struct ntfs_recovery *owner)
{
	struct ntfs_environment environment;
	struct ntfs_volume *backing;
	size_t count;

	if (owner == NULL) {
		return;
	}
	environment = owner->environment;
	backing = owner->backing;
	count = owner->limits.max_records;
	recovery_release(owner, owner->records, count * sizeof(*owner->records));
	recovery_release(owner, owner->transactions, count * sizeof(*owner->transactions));
	recovery_release(owner, owner->slots, count * sizeof(*owner->slots));
	recovery_release(owner, owner->checkpoint_bytes, NTFS_LOGFILE_CHECKPOINT_MAX_BYTES);
	recovery_release(owner, owner->history_bytes, owner->limits.max_history_bytes);
	environment.release(environment.context, owner, sizeof(*owner));
	if (backing != NULL) {
		backing->children--;
	}
}

static uint32_t
recovery_find_record(const struct ntfs_recovery *owner, uint64_t lsn)
{
	uint32_t low = 0, high = owner->record_count, middle;

	while (low < high) {
		middle = low + (high - low) / 2;
		if (owner->records[middle].record.lsn < lsn) {
			low = middle + 1;
		} else {
			high = middle;
		}
	}
	return low < owner->record_count && owner->records[low].record.lsn == lsn
	    ? low
	    : NTFS_RECOVERY_NO_EPOCH;
}

static enum ntfs_result
recovery_checkpoint_dump_flag(const struct ntfs_recovery *owner,
    const struct ntfs_logfile_record *record, const struct ntfs_logfile_update *update)
{
	enum ntfs_logfile_checkpoint_kind kind;
	uint16_t operation;

	for (kind = 0; kind < NTFS_LOGFILE_CHECKPOINT_KINDS; kind++) {
		operation = NTFS_LOG_OP_OPEN_ATTRIBUTE_TABLE_DUMP + (uint16_t)kind;
		if ((owner->checkpoint.snapshot.present_mask & (1u << kind)) != 0 &&
		    update->redo_operation == operation &&
		    record->lsn == owner->checkpoint.snapshot.tables[kind].table_lsn &&
		    update->undo_operation == NTFS_LOG_OP_NOOP && update->undo.length == 0 &&
		    update->lcn_count == 0) {
			return NTFS_OK;
		}
	}
	return NTFS_UNSUPPORTED;
}

static enum ntfs_result
recovery_retain_record(
    void *context, const struct ntfs_logfile_record_view *view, const void *bytes)
{
	struct ntfs_recovery_workspace *work = context;
	struct ntfs_recovery *owner = work->owner;
	const struct ntfs_logfile_record *record = &view->record;
	struct ntfs_recovery_record *retained;
	struct ntfs_logfile_update update;
	enum ntfs_result result;

	if (record->client_index != owner->checkpoint.client_index ||
	    record->client_sequence != owner->checkpoint.client_sequence) {
		return NTFS_STALE;
	}
	if (record->type == NTFS_LOGFILE_RECORD_UPDATE) {
		result = ntfs_logfile_update_decode(
		    (const uint8_t *)bytes + record->data.offset, record->data.length, &update);
		if (result != NTFS_OK) {
			return result;
		}
		if ((record->flags & ~NTFS_LOGFILE_RECORD_MULTI_PAGE) != 0 &&
		    ((record->flags & ~NTFS_LOGFILE_RECORD_MULTI_PAGE) !=
			    RECOVERY_CHECKPOINT_DUMP_FLAG ||
			recovery_checkpoint_dump_flag(owner, record, &update) != NTFS_OK)) {
			return NTFS_UNSUPPORTED;
		}
	} else if (record->type != NTFS_LOGFILE_RECORD_RESTART) {
		return NTFS_UNSUPPORTED;
	} else if ((record->flags & ~NTFS_LOGFILE_RECORD_MULTI_PAGE) != 0) {
		return NTFS_UNSUPPORTED;
	}
	if (owner->record_count == owner->limits.max_records ||
	    view->bytes > owner->limits.max_history_bytes - owner->history_size) {
		return NTFS_RANGE;
	}
	retained = &owner->records[owner->record_count];
	*retained = (struct ntfs_recovery_record){
	    *record, {owner->history_size, view->bytes}, NTFS_RECOVERY_NO_EPOCH};
	ntfs_copy(owner->history_bytes + owner->history_size, bytes, view->bytes);
	owner->record_count++;
	owner->history_size += view->bytes;
	work->report->records = owner->record_count;
	work->report->history_bytes = owner->history_size;
	return NTFS_OK;
}

static enum ntfs_result
recovery_bind_packet(const struct ntfs_recovery *owner, struct ntfs_logfile_span span)
{
	const struct ntfs_disk_log_record *header;
	const struct ntfs_recovery_record *record;
	uint32_t ordinal;

	if (span.length == 0) {
		return NTFS_OK;
	}
	header = (const void *)(owner->checkpoint_bytes + span.offset);
	ordinal = recovery_find_record(owner, ntfs_u64(header->lsn));
	if (ordinal == NTFS_RECOVERY_NO_EPOCH) {
		return NTFS_STALE;
	}
	record = &owner->records[ordinal];
	return record->packet.length == span.length &&
		ntfs_equal(owner->history_bytes + record->packet.offset, header, span.length)
	    ? NTFS_OK
	    : NTFS_STALE;
}

static bool
recovery_independent_operation(uint16_t operation)
{
	return operation == NTFS_LOG_OP_NOOP ||
	    operation == NTFS_LOG_OP_OPEN_ATTRIBUTE_TABLE_DUMP ||
	    operation == NTFS_LOG_OP_ATTRIBUTE_NAMES_DUMP ||
	    operation == NTFS_LOG_OP_DIRTY_PAGE_TABLE_DUMP ||
	    operation == NTFS_LOG_OP_TRANSACTION_TABLE_DUMP;
}

static enum ntfs_result
recovery_transaction_slot(const struct ntfs_recovery *owner, uint32_t key, uint32_t *slot)
{
	uint32_t relative;

	if (key < RECOVERY_TABLE_KEY_BASE) {
		return NTFS_CORRUPT;
	}
	relative = key - RECOVERY_TABLE_KEY_BASE;
	if (relative % RECOVERY_TABLE_KEY_STRIDE != 0) {
		return NTFS_CORRUPT;
	}
	*slot = relative / RECOVERY_TABLE_KEY_STRIDE;
	return *slot < owner->limits.max_records ? NTFS_OK : NTFS_RANGE;
}

static enum ntfs_result
recovery_advance_transaction(struct ntfs_recovery_transaction *transaction,
    const struct ntfs_logfile_record *record, const struct ntfs_logfile_update *update)
{
	if (transaction->records != 0 &&
	    transaction->state == NTFS_RECOVERY_TRANSACTION_FORGOTTEN) {
		return NTFS_CORRUPT;
	}
	if (update->redo_operation == NTFS_LOG_OP_PREPARE_TRANSACTION ||
	    update->redo_operation == NTFS_LOG_OP_COMMIT_TRANSACTION ||
	    update->redo_operation == NTFS_LOG_OP_FORGET_TRANSACTION) {
		if (update->redo.length != 0 || update->undo.length != 0 ||
		    update->lcn_count != 0 || update->target_attribute != 0 ||
		    update->record_offset != 0 || update->attribute_offset != 0 ||
		    update->cluster_index != 0 || update->attribute_flags != 0 ||
		    update->target_vcn != 0 ||
		    (update->undo_operation != NTFS_LOG_OP_NOOP &&
			update->undo_operation != NTFS_LOG_OP_COMPENSATION)) {
			return NTFS_UNSUPPORTED;
		}
		if (update->redo_operation == NTFS_LOG_OP_PREPARE_TRANSACTION) {
			if (transaction->state != NTFS_RECOVERY_TRANSACTION_ACTIVE) {
				return NTFS_UNSUPPORTED;
			}
			transaction->state = NTFS_RECOVERY_TRANSACTION_PREPARED;
		} else if (update->redo_operation == NTFS_LOG_OP_COMMIT_TRANSACTION) {
			if (transaction->state == NTFS_RECOVERY_TRANSACTION_COMMITTED) {
				return NTFS_UNSUPPORTED;
			}
			transaction->state = NTFS_RECOVERY_TRANSACTION_COMMITTED;
		} else {
			transaction->state = NTFS_RECOVERY_TRANSACTION_FORGOTTEN;
		}
		transaction->control_lsn = record->lsn;
		transaction->control_operation = update->redo_operation;
	}
	transaction->last_lsn = record->lsn;
	transaction->undo_next_lsn = record->undo_next_lsn;
	transaction->records++;
	return NTFS_OK;
}

static enum ntfs_result
recovery_analyze_transactions(struct ntfs_recovery *owner, struct ntfs_recovery_report *report)
{
	struct ntfs_recovery_record *packet;
	struct ntfs_recovery_transaction *transaction;
	struct ntfs_logfile_update update;
	const struct ntfs_logfile_record *record;
	uint32_t ordinal, slot, epoch, undo;
	enum ntfs_result result;

	for (ordinal = 0; ordinal < owner->limits.max_records; ordinal++) {
		owner->slots[ordinal] = NTFS_RECOVERY_NO_EPOCH;
	}
	for (ordinal = 0; ordinal < owner->record_count; ordinal++) {
		packet = &owner->records[ordinal];
		record = &packet->record;
		if (record->type == NTFS_LOGFILE_RECORD_RESTART) {
			continue;
		}
		result = ntfs_logfile_update_decode(
		    owner->history_bytes + packet->packet.offset + record->data.offset,
		    record->data.length, &update);
		if (result != NTFS_OK) {
			return result;
		}
		if (recovery_independent_operation(update.redo_operation) &&
		    (update.redo_operation != NTFS_LOG_OP_NOOP || record->transaction == 0)) {
			/* Checkpoint packets have their own framing, not transaction edges. */
			continue;
		}
		if (record->transaction == 0) {
			return NTFS_UNSUPPORTED;
		}
		result = recovery_transaction_slot(owner, record->transaction, &slot);
		if (result != NTFS_OK) {
			return result;
		}
		epoch = owner->slots[slot];
		if (epoch == NTFS_RECOVERY_NO_EPOCH || record->previous_lsn == 0) {
			if (epoch != NTFS_RECOVERY_NO_EPOCH &&
			    owner->transactions[epoch].state !=
				NTFS_RECOVERY_TRANSACTION_FORGOTTEN) {
				return NTFS_CORRUPT;
			}
			if (record->previous_lsn >= owner->checkpoint.client.oldest_lsn) {
				return NTFS_CORRUPT;
			}
			epoch = owner->transaction_count++;
			owner->slots[slot] = epoch;
			transaction = &owner->transactions[epoch];
			ntfs_zero(transaction, sizeof(*transaction));
			transaction->key = record->transaction;
			transaction->first_lsn = record->previous_lsn == 0 ? record->lsn : 0;
			transaction->predecessor_lsn = record->previous_lsn;
			transaction->complete_chain = record->previous_lsn == 0;
		} else {
			transaction = &owner->transactions[epoch];
			if (record->previous_lsn != transaction->last_lsn) {
				return NTFS_CORRUPT;
			}
		}
		if (record->undo_next_lsn != 0) {
			undo = recovery_find_record(owner, record->undo_next_lsn);
			if (undo == NTFS_RECOVERY_NO_EPOCH) {
				if (transaction->complete_chain ||
				    record->undo_next_lsn >= owner->checkpoint.client.oldest_lsn) {
					return NTFS_CORRUPT;
				}
			} else if (undo >= ordinal ||
			    owner->records[undo].transaction_epoch != epoch) {
				return NTFS_CORRUPT;
			}
		}
		packet->transaction_epoch = epoch;
		result = recovery_advance_transaction(transaction, record, &update);
		if (result != NTFS_OK) {
			return result;
		}
		report->transaction_epochs = owner->transaction_count;
	}
	for (epoch = 0; epoch < owner->transaction_count; epoch++) {
		transaction = &owner->transactions[epoch];
		if (!transaction->complete_chain) {
			report->partial_prefixes++;
			if (transaction->state != NTFS_RECOVERY_TRANSACTION_FORGOTTEN) {
				return NTFS_STALE;
			}
		}
		switch (transaction->state) {
		case NTFS_RECOVERY_TRANSACTION_ACTIVE:
			report->active_transactions++;
			break;
		case NTFS_RECOVERY_TRANSACTION_PREPARED:
			report->prepared_transactions++;
			break;
		case NTFS_RECOVERY_TRANSACTION_COMMITTED:
			report->committed_transactions++;
			break;
		case NTFS_RECOVERY_TRANSACTION_FORGOTTEN:
			report->forgotten_transactions++;
			break;
		}
	}
	return NTFS_OK;
}

static enum ntfs_result
recovery_verify_seeds(const struct ntfs_recovery *owner, struct ntfs_recovery_report *report)
{
	const struct ntfs_logfile_checkpoint_table *table;
	const struct ntfs_recovery_record *packet;
	const struct ntfs_recovery_transaction *transaction;
	const uint8_t *body, *entry;
	struct ntfs_logfile_transaction seed;
	uint32_t index, ordinal, undo, key;
	enum ntfs_result result;

	if ((owner->checkpoint.snapshot.present_mask &
		(1u << NTFS_LOGFILE_CHECKPOINT_TRANSACTIONS)) == 0) {
		return NTFS_OK;
	}
	table = &owner->checkpoint.snapshot.tables[NTFS_LOGFILE_CHECKPOINT_TRANSACTIONS];
	body = owner->checkpoint_bytes +
	    owner->checkpoint.dumps[NTFS_LOGFILE_CHECKPOINT_TRANSACTIONS].offset +
	    table->body.offset;
	for (index = 0; index < table->table.entry_count; index++) {
		key = table->table.entries.offset + index * table->table.entry_bytes;
		entry = body + key;
		result = ntfs_logfile_transaction_decode(entry, table->table.entry_bytes, &seed);
		if (result == NTFS_NOT_FOUND) {
			continue;
		}
		if (result != NTFS_OK) {
			return result;
		}
		if (seed.first_lsn == 0 || seed.previous_lsn == 0) {
			if (seed.state != NTFS_LOGFILE_TRANSACTION_UNINITIALIZED ||
			    seed.first_lsn != 0 || seed.previous_lsn != 0 ||
			    seed.undo_next_lsn != 0 || seed.undo_records != 0 ||
			    seed.undo_bytes != 0) {
				return NTFS_UNSUPPORTED;
			}
			report->verified_seeds++;
			continue;
		}
		ordinal = recovery_find_record(owner, seed.previous_lsn);
		if (ordinal == NTFS_RECOVERY_NO_EPOCH || seed.previous_lsn >= table->table_lsn) {
			return NTFS_STALE;
		}
		packet = &owner->records[ordinal];
		if (packet->transaction_epoch == NTFS_RECOVERY_NO_EPOCH) {
			return NTFS_CORRUPT;
		}
		transaction = &owner->transactions[packet->transaction_epoch];
		if (!transaction->complete_chain || transaction->key != key ||
		    transaction->first_lsn != seed.first_lsn) {
			return NTFS_CORRUPT;
		}
		if (seed.undo_next_lsn != 0) {
			undo = recovery_find_record(owner, seed.undo_next_lsn);
			if (undo == NTFS_RECOVERY_NO_EPOCH || undo > ordinal ||
			    owner->records[undo].transaction_epoch != packet->transaction_epoch) {
				return NTFS_CORRUPT;
			}
		}
		report->verified_seeds++;
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_recovery_open(struct ntfs_logfile *source, uint16_t index, uint16_t sequence,
    const struct ntfs_recovery_limits *limits, struct ntfs_recovery_report *report,
    struct ntfs_recovery **out)
{
	struct ntfs_recovery_limits policy;
	struct ntfs_environment environment;
	struct ntfs_logfile_limits source_limits;
	struct ntfs_logfile_checkpoint_capture_limits budget;
	struct ntfs_logfile_lsn location;
	struct ntfs_recovery *owner;
	struct ntfs_volume *backing;
	struct ntfs_recovery_workspace work;
	uint8_t *staging = NULL, *names = NULL;
	uint64_t reserved, retained;
	size_t records;
	uint32_t kind;
	enum ntfs_result result;

	if (out != NULL) {
		*out = NULL;
	}
	if (report == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(report, sizeof(*report));
	if (source == NULL || out == NULL) {
		return NTFS_INVALID;
	}
	if (limits == NULL) {
		ntfs_recovery_default_limits(&policy);
	} else {
		policy = *limits;
	}
	if (!recovery_valid_limits(&policy)) {
		return NTFS_INVALID;
	}
	result = ntfs_logfile_environment(source, &environment, &source_limits, &backing);
	if (result != NTFS_OK) {
		return result;
	}
	if (policy.max_read_calls > source_limits.max_read_calls) {
		policy.max_read_calls = source_limits.max_read_calls;
	}
	if (policy.max_read_bytes > source_limits.max_read_bytes) {
		policy.max_read_bytes = source_limits.max_read_bytes;
	}
	records = policy.max_records;
	retained = sizeof(*owner) +
	    records *
		(sizeof(*owner->records) + sizeof(*owner->transactions) + sizeof(*owner->slots)) +
	    NTFS_LOGFILE_CHECKPOINT_MAX_BYTES + policy.max_history_bytes;
	/* Reserve one private assembly allocation in addition to owned staging. */
	reserved =
	    retained + 2u * RECOVERY_STAGE_BYTES + NTFS_LOGFILE_CHECKPOINT_NAME_WORKSPACE_BYTES;
	report->reserved_bytes = reserved;
	if (reserved > policy.max_live_bytes || retained > SIZE_MAX) {
		return NTFS_RANGE;
	}
	if (backing != NULL && backing->children == UINT32_MAX) {
		return NTFS_RANGE;
	}
	owner = environment.allocate(environment.context, sizeof(*owner));
	if (owner == NULL) {
		return NTFS_NO_MEMORY;
	}
	ntfs_zero(owner, sizeof(*owner));
	owner->environment = environment;
	owner->backing = backing;
	owner->limits = policy;
	if (backing != NULL) {
		backing->children++;
	}
	owner->records =
	    environment.allocate(environment.context, records * sizeof(*owner->records));
	owner->transactions =
	    environment.allocate(environment.context, records * sizeof(*owner->transactions));
	owner->slots = environment.allocate(environment.context, records * sizeof(*owner->slots));
	owner->checkpoint_bytes =
	    environment.allocate(environment.context, NTFS_LOGFILE_CHECKPOINT_MAX_BYTES);
	owner->history_bytes = environment.allocate(environment.context, policy.max_history_bytes);
	staging = environment.allocate(environment.context, RECOVERY_STAGE_BYTES);
	names =
	    environment.allocate(environment.context, NTFS_LOGFILE_CHECKPOINT_NAME_WORKSPACE_BYTES);
	if (owner->records == NULL || owner->transactions == NULL || owner->slots == NULL ||
	    owner->checkpoint_bytes == NULL || owner->history_bytes == NULL || staging == NULL ||
	    names == NULL) {
		result = NTFS_NO_MEMORY;
		goto done;
	}
	result = ntfs_logfile_get_restart(source, &owner->restart);
	if (result != NTFS_OK) {
		goto done;
	}
	budget = (struct ntfs_logfile_checkpoint_capture_limits){
	    policy.max_read_calls, policy.max_read_bytes};
	result = ntfs_logfile_capture_checkpoint(source, index, sequence, &budget,
	    owner->checkpoint_bytes, NTFS_LOGFILE_CHECKPOINT_MAX_BYTES, names,
	    NTFS_LOGFILE_CHECKPOINT_NAME_WORKSPACE_BYTES, &owner->checkpoint, &report->checkpoint);
	report->read_calls = report->checkpoint.read_calls;
	report->read_bytes = report->checkpoint.read_bytes;
	if (result != NTFS_OK) {
		goto done;
	}
	if (owner->checkpoint.client.oldest_lsn == 0 ||
	    owner->checkpoint.restart.analysis_lsn < owner->checkpoint.client.oldest_lsn ||
	    owner->checkpoint.restart.analysis_lsn > owner->checkpoint.client.restart_lsn ||
	    ntfs_logfile_lsn_decode(
		&owner->restart, owner->checkpoint.restart.analysis_lsn, &location) != NTFS_OK) {
		result = NTFS_STALE;
		goto done;
	}
	if (report->read_calls >= budget.max_read_calls ||
	    report->read_bytes >= budget.max_read_bytes) {
		result = NTFS_RANGE;
		goto done;
	}
	budget.max_read_calls -= report->read_calls;
	budget.max_read_bytes -= report->read_bytes;
	work = (struct ntfs_recovery_workspace){owner, report};
	result = ntfs_logfile_visit_records_limited(source, owner->checkpoint.client.oldest_lsn,
	    policy.max_records, &budget, staging, RECOVERY_STAGE_BYTES, recovery_retain_record,
	    &work, &report->history);
	report->read_calls += report->history.read_calls;
	report->read_bytes += report->history.read_bytes;
	if (result != NTFS_OK) {
		goto done;
	}
	if (report->history.tail_lsn != 0) {
		result = NTFS_UNSUPPORTED;
		goto done;
	}
	if (recovery_find_record(owner, owner->checkpoint.restart.analysis_lsn) ==
	    NTFS_RECOVERY_NO_EPOCH) {
		result = NTFS_STALE;
		goto done;
	}
	result = recovery_bind_packet(owner, owner->checkpoint.checkpoint);
	for (kind = 0; result == NTFS_OK && kind < NTFS_LOGFILE_CHECKPOINT_KINDS; kind++) {
		result = recovery_bind_packet(owner, owner->checkpoint.dumps[kind]);
	}
	if (result == NTFS_OK) {
		result = recovery_analyze_transactions(owner, report);
	}
	if (result == NTFS_OK) {
		result = recovery_verify_seeds(owner, report);
	}
done:
	recovery_release(owner, staging, RECOVERY_STAGE_BYTES);
	recovery_release(owner, names, NTFS_LOGFILE_CHECKPOINT_NAME_WORKSPACE_BYTES);
	if (result != NTFS_OK) {
		ntfs_recovery_close(owner);
		return result;
	}
	report->published = true;
	report->retained_bytes = retained;
	*out = owner;
	return NTFS_OK;
}

enum ntfs_result
ntfs_recovery_get_checkpoint(const struct ntfs_recovery *owner,
    struct ntfs_logfile_checkpoint_capture *capture, const void **packets)
{
	if (capture != NULL) {
		ntfs_zero(capture, sizeof(*capture));
	}
	if (packets != NULL) {
		*packets = NULL;
	}
	if (owner == NULL || capture == NULL || packets == NULL) {
		return NTFS_INVALID;
	}
	*capture = owner->checkpoint;
	*packets = owner->checkpoint_bytes;
	return NTFS_OK;
}

enum ntfs_result
ntfs_recovery_get_record(const struct ntfs_recovery *owner, uint32_t ordinal,
    struct ntfs_recovery_record *record, const void **packet)
{
	if (record != NULL) {
		ntfs_zero(record, sizeof(*record));
	}
	if (packet != NULL) {
		*packet = NULL;
	}
	if (owner == NULL || record == NULL || packet == NULL) {
		return NTFS_INVALID;
	}
	if (ordinal >= owner->record_count) {
		return NTFS_END;
	}
	*record = owner->records[ordinal];
	*packet = owner->history_bytes + record->packet.offset;
	return NTFS_OK;
}

enum ntfs_result
ntfs_recovery_get_transaction(const struct ntfs_recovery *owner, uint32_t ordinal,
    struct ntfs_recovery_transaction *transaction)
{
	if (transaction == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(transaction, sizeof(*transaction));
	if (owner == NULL) {
		return NTFS_INVALID;
	}
	if (ordinal >= owner->transaction_count) {
		return NTFS_END;
	}
	*transaction = owner->transactions[ordinal];
	return NTFS_OK;
}
