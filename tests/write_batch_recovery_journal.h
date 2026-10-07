/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
/* Original payload copies belong to the test oracle, not to any closed C owner.
 * Inspect retained originals and newly appended inverse chains independently. */

struct recovery_journal {
	struct journal_oracle *original;
	uint64_t *lsn;
	size_t updates, remaining;
	bool aborting, forgotten, committed;
};

static enum ntfs_result
recovery_journal_visit(
    void *context, const struct ntfs_logfile_record_view *view, const void *bytes)
{
	struct recovery_journal *chain = context;
	struct journal_oracle *oracle = chain->original;
	const struct ntfs_logfile_record *record = &view->record;
	const uint8_t *payload = (const uint8_t *)bytes + record->data.offset;
	const struct journal_step *step;
	struct ntfs_logfile_update update, old;
	uint64_t undo_next;
	size_t original;

	assert(!chain->forgotten);
	if (record->lsn <= oracle->original.completed_end_lsn ||
	    oracle->records < oracle->targets) {
		return journal_visit(oracle, view, bytes);
	}
	assert(record->type == NTFS_LOGFILE_RECORD_UPDATE && record->client_index == 0 &&
	    record->client_sequence == oracle->client.sequence &&
	    record->transaction == NTFS_WRITE_TRANSACTION_KEY);
	assert(ntfs_logfile_update_decode(payload, record->data.length, &update) == NTFS_OK);
	if (update.undo_operation != NTFS_LOG_OP_COMPENSATION) {
		assert(!chain->aborting && chain->updates < oracle->steps);
		chain->lsn[chain->updates++] = record->lsn;
		chain->remaining++;
		return journal_visit(oracle, view, bytes);
	}
	assert(record->previous_lsn == oracle->transaction_lsn);
	if (update.redo_operation == NTFS_LOG_OP_FORGET_TRANSACTION) {
		assert(record->undo_next_lsn == 0 &&
		    record->flags == NTFS_LOGFILE_RECORD_DELETING && update.target_attribute == 0 &&
		    update.lcn_count == 0 && update.redo.length == 0 && update.undo.length == 0 &&
		    update.target_vcn == 0 && update.record_offset == 0 &&
		    update.attribute_offset == 0 && update.cluster_index == 0 &&
		    update.attribute_flags == 0);
		assert(chain->committed ? !chain->aborting && chain->updates == oracle->steps
					: chain->aborting && chain->remaining == 0);
		chain->forgotten = true;
	} else {
		assert(!chain->committed && chain->remaining != 0 &&
		    (record->flags & ~NTFS_LOGFILE_RECORD_MULTI_PAGE) == 0);
		chain->aborting = true;
		original = --chain->remaining;
		step = &oracle->step[original];
		assert(ntfs_logfile_update_decode(step->payload, step->bytes, &old) == NTFS_OK);
		undo_next = original == 0 ? 0 : chain->lsn[original - 1];
		assert(record->undo_next_lsn == undo_next &&
		    update.redo_operation == old.undo_operation &&
		    update.target_attribute == old.target_attribute &&
		    update.target_vcn == old.target_vcn &&
		    update.record_offset == old.record_offset &&
		    update.attribute_offset == old.attribute_offset &&
		    update.cluster_index == old.cluster_index &&
		    update.attribute_flags == old.attribute_flags &&
		    update.lcn_count == old.lcn_count && update.lcns.length == old.lcns.length &&
		    update.redo.length == old.undo.length && update.undo.length == 0 &&
		    update.compensation_undo_bytes == update.redo.length &&
		    memcmp(payload + update.lcns.offset, step->payload + old.lcns.offset,
			update.lcns.length) == 0 &&
		    memcmp(payload + update.redo.offset, step->payload + old.undo.offset,
			update.redo.length) == 0);
	}
	oracle->transaction_lsn = oracle->previous_lsn = record->lsn;
	oracle->observed++;
	return NTFS_OK;
}

static void
recovery_journal_check(struct recovery_case *source, bool committed)
{
	struct test_case *test = source->test;
	struct journal_oracle *oracle = source->oracle;
	struct recovery_journal chain = {.original = oracle, .committed = committed};
	struct ntfs_volume *volume = NULL;
	struct ntfs_logfile *log;
	struct ntfs_logfile_restart restart;
	struct ntfs_logfile_client client;
	struct ntfs_logfile_history_report history;
	const struct ntfs_write_mutation_region *region, *primary;
	uint8_t *record;
	uint64_t expected;
	size_t index, other, slot;

	chain.lsn = calloc(oracle->steps, sizeof(*chain.lsn));
	record = malloc(NTFS_WRITE_BATCH_MAX_PACKET_BYTES);
	assert(chain.lsn != NULL && record != NULL);
	oracle->records = oracle->observed = 0;
	oracle->transaction_lsn = 0;
	oracle->previous_lsn = oracle->original.completed_end_lsn;
	memset(oracle->home_lsn, 0, oracle->regions * TEST_FILE_SLOTS * sizeof(*oracle->home_lsn));
	log = journal_open(test, &volume);
	assert(ntfs_logfile_get_restart(log, &restart) == NTFS_OK &&
	    restart.flags == NTFS_LOGFILE_RESTART_CLEAN &&
	    restart.current_lsn == oracle->restart.current_lsn &&
	    restart.last_data_bytes == oracle->restart.last_data_bytes);
	assert(ntfs_logfile_get_client(log, 0, &client) == NTFS_OK &&
	    memcmp(&client, &oracle->client, sizeof(client)) == 0);
	assert(ntfs_logfile_visit_records(log, client.oldest_lsn, NTFS_WRITE_BATCH_MAX_PACKETS,
		   record, NTFS_WRITE_BATCH_MAX_PACKET_BYTES, recovery_journal_visit, &chain,
		   &history) == NTFS_OK &&
	    history.complete && history.endpoint_verified && history.tail_lsn == 0 &&
	    history.completed_end_lsn == oracle->previous_lsn &&
	    history.visited_records == oracle->observed);
	assert(chain.updates == 0 || chain.forgotten);
	assert(!committed || chain.forgotten);
	ntfs_logfile_close(log);
	assert(ntfs_unmount(volume) == NTFS_OK);
	for (index = 0; committed && index < oracle->regions; index++) {
		region = &oracle->region[index];
		other = index;
		if (region->target.mirror) {
			for (other = 0; other < oracle->regions; other++) {
				primary = &oracle->region[other];
				if (!primary->target.mirror &&
				    primary->kind == NTFS_WRITE_MUTATION_FILE &&
				    same_target(&primary->target, &region->target) &&
				    primary->target.logical_offset ==
					region->target.logical_offset) {
					break;
				}
			}
			assert(other < oracle->regions);
		}
		for (slot = 0; slot < TEST_FILE_SLOTS; slot++) {
			expected = oracle->home_lsn[other * TEST_FILE_SLOTS + slot];
			if (expected != 0) {
				assert(ntfs_u64(test->device.visible + region->physical +
					   slot * NTFS_WRITE_RECORD_BYTES +
					   offsetof(struct ntfs_disk_record, lsn)) == expected);
			}
		}
	}
	free(record);
	free(chain.lsn);
}

static void
recovery_journal_close(struct journal_oracle *oracle)
{
	size_t index;

	for (index = 0; index < oracle->steps; index++) {
		free(oracle->step[index].payload);
	}
	free(oracle->home_lsn);
	free(oracle->target);
	free(oracle->step);
	free(oracle);
}
