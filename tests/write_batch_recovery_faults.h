/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
/* Fresh recovery owners are given only failed callback bytes. No planner,
 * original program or previous recovery owner survives the reopen boundary. */

static void
recovery_input(struct recovery_case *source, const uint8_t *input)
{
	struct device *device = &source->test->device;

	memcpy(device->visible, input, device->bytes);
	memcpy(device->durable, input, device->bytes);
	device->writes = device->barriers = device->reads = device->allocations = 0;
	device->fail_write = device->fail_barrier = device->fail_read = device->fail_allocation = 0;
	device->overreport = device->short_success = device->persist_on_failure = false;
}

static void
recovery_failed_report(const struct ntfs_write_batch_recovery *owner,
    const struct ntfs_write_recovery_report *actual, size_t write_fault, size_t barrier_fault,
    size_t partial, bool overreport)
{
	struct ntfs_write_recovery_report expected = {0};
	const struct ntfs_write_batch_recovery_publication *step;
	size_t index, abort_end = SIZE_MAX;
	bool matches;

	for (index = 0; index < ntfs_write_batch_recovery_count(owner); index++) {
		step = ntfs_write_batch_recovery_get(owner, index);
		if (step->stage == NTFS_WRITE_RECOVERY_ABORT_COPY) {
			abort_end = index;
		}
	}
	for (index = 0; index < ntfs_write_batch_recovery_count(owner); index++) {
		step = ntfs_write_batch_recovery_get(owner, index);
		expected.writes++;
		if (expected.writes == write_fault) {
			expected.physical_bytes += overreport ? 0 : partial;
			break;
		}
		expected.physical_bytes += NTFS_WRITE_CLUSTER_BYTES;
		expected.barriers++;
		if (expected.barriers == barrier_fault) {
			break;
		}
		expected.durable_stage = step->stage;
		expected.compensation_persisted |= index == abort_end;
		expected.homes_persisted |= step->stage == NTFS_WRITE_RECOVERY_CLEAN_FIRST ||
		    step->stage == NTFS_WRITE_RECOVERY_CLEAN_SECOND;
	}
	matches = actual->writes == expected.writes && actual->barriers == expected.barriers &&
	    actual->physical_bytes == expected.physical_bytes &&
	    actual->durable_stage == expected.durable_stage &&
	    actual->compensation_persisted == expected.compensation_persisted &&
	    actual->homes_persisted == expected.homes_persisted && actual->poisoned &&
	    !actual->completed;
	if (!matches) {
		fprintf(stderr,
		    "recovery report failure: write=%zu barrier=%zu partial=%zu "
		    "overreport=%u, actual writes=%u barriers=%u stage=%u compensation=%u, "
		    "expected writes=%u barriers=%u stage=%u compensation=%u\n",
		    write_fault, barrier_fault, partial, overreport, actual->writes,
		    actual->barriers, actual->durable_stage, actual->compensation_persisted,
		    expected.writes, expected.barriers, expected.durable_stage,
		    expected.compensation_persisted);
	}
	assert(matches);
}

static void
recovery_prepare_faults(struct recovery_case *source, const uint8_t *input)
{
	struct test_case *test = source->test;
	struct ntfs_write_batch_recovery *owner = NULL;
	size_t mode, fault, allocations, reads;
	enum ntfs_result result;

	recovery_input(source, input);
	assert(ntfs_write_batch_recover_prepare(&test->backend, &owner) == NTFS_OK);
	allocations = test->device.allocations;
	reads = test->device.reads;
	ntfs_write_batch_recovery_close(owner);
	assert(test->device.live == 0);
	for (mode = 0; mode < 2; mode++) {
		for (fault = 1; fault <= (mode == 0 ? allocations : reads); fault++) {
			recovery_input(source, input);
			test->device.fail_allocation = mode == 0 ? fault : 0;
			test->device.fail_read = mode == 1 ? fault : 0;
			owner = (void *)(uintptr_t)1;
			result = ntfs_write_batch_recover_prepare(&test->backend, &owner);
			assert(result == (mode == 0 ? NTFS_NO_MEMORY : NTFS_IO) && owner == NULL &&
			    test->device.live == 0 && test->device.writes == 0 &&
			    test->device.barriers == 0 &&
			    memcmp(input, test->device.visible, test->device.bytes) == 0 &&
			    memcmp(input, test->device.durable, test->device.bytes) == 0);
		}
	}
	recovery_input(source, input);
	assert(ntfs_write_batch_recover_prepare(&test->backend, &owner) == NTFS_OK);
	ntfs_write_batch_recovery_close(owner);
	assert(test->device.live == 0);
	printf("PASS: fresh recovery refuses all %zu allocation and %zu read failures "
	       "without mutation, leaks or a published owner; retry succeeds\n",
	    allocations, reads);
}

static void
recovery_after_fault(struct recovery_case *source, bool committed, uint8_t *durable)
{
	struct test_case *test = source->test;

	memcpy(durable, test->device.durable, test->device.bytes);
	test->device.writes = test->device.barriers = 0;
	test->device.fail_write = test->device.fail_barrier = 0;
	test->device.overreport = test->device.short_success = false;
	recovery_check(source, committed);
	recovery_input(source, durable);
	recovery_check(source, committed);
}

static void
recovery_execution_faults(struct recovery_case *source, const uint8_t *input, bool committed)
{
	struct test_case *test = source->test;
	struct ntfs_write_batch_recovery *owner = NULL;
	struct ntfs_write_recovery_report report;
	uint8_t *durable;
	size_t count, index, mode, reads, allocations;
	bool poisoned;

	durable = malloc(test->device.bytes);
	assert(durable != NULL);
	recovery_input(source, input);
	assert(ntfs_write_batch_recover_prepare(&test->backend, &owner) == NTFS_OK);
	count = ntfs_write_batch_recovery_count(owner);
	ntfs_write_batch_recovery_close(owner);
	assert(count != 0 && test->device.live == 0);
	for (index = 1; index <= count; index++) {
		for (mode = 0; mode < TEST_FAULT_MODES; mode++) {
			recovery_input(source, input);
			test->device.fail_write = index;
			test->device.failure_bytes = mode == 0 ? 0
			    : mode == 1			       ? NTFS_WRITE_SECTOR_BYTES
			    : mode == 2			       ? NTFS_WRITE_CLUSTER_BYTES / 2
							       : NTFS_WRITE_CLUSTER_BYTES;
			test->device.overreport = mode == TEST_FAULT_MODES - 2;
			test->device.short_success = mode == TEST_FAULT_MODES - 1;
			if (test->device.short_success) {
				test->device.failure_bytes = NTFS_WRITE_SECTOR_BYTES;
			}
			assert(ntfs_write_batch_recover_prepare(&test->backend, &owner) == NTFS_OK);
			reads = test->device.reads;
			allocations = test->device.allocations;
			poisoned = false;
			assert(recovery_execute(test, owner, &poisoned, &report) == NTFS_IO &&
			    poisoned && test->device.reads == reads &&
			    test->device.allocations == allocations);
			recovery_failed_report(owner, &report, index, 0, test->device.failure_bytes,
			    test->device.overreport);
			assert(recovery_execute(test, owner, &poisoned, &report) == NTFS_IO &&
			    report.poisoned && test->device.writes == index);
			ntfs_write_batch_recovery_close(owner);
			assert(test->device.live == 0);
			recovery_after_fault(source, committed, durable);
		}
	}
	for (index = 1; index <= count; index++) {
		for (mode = 0; mode < 2; mode++) {
			recovery_input(source, input);
			test->device.fail_barrier = index;
			test->device.persist_on_failure = mode != 0;
			assert(ntfs_write_batch_recover_prepare(&test->backend, &owner) == NTFS_OK);
			reads = test->device.reads;
			allocations = test->device.allocations;
			poisoned = false;
			assert(recovery_execute(test, owner, &poisoned, &report) == NTFS_IO &&
			    poisoned && test->device.reads == reads &&
			    test->device.allocations == allocations);
			recovery_failed_report(owner, &report, 0, index, 0, false);
			assert(recovery_execute(test, owner, &poisoned, &report) == NTFS_IO &&
			    report.poisoned && test->device.barriers == index);
			ntfs_write_batch_recovery_close(owner);
			assert(test->device.live == 0);
			recovery_after_fault(source, committed, durable);
		}
	}
	printf("PASS: %zu actual recovery write and %zu barrier failures; both visible "
	       "and durable states recover again with fresh owners to %s metadata\n",
	    count * TEST_FAULT_MODES, count * 2, committed ? "committed" : "old");
	free(durable);
}

static void
recovery_callback_faults(const char *directory, enum ntfs_write_mutation_kind kind,
    enum test_profile profile, const char *image, bool prepare_faults)
{
	struct recovery_case *source;
	uint8_t *input;
	size_t committed;

	source = recovery_source(directory, image, kind, profile);
	input = malloc(source->test->device.bytes);
	assert(input != NULL);
	for (committed = 0; committed < 2; committed++) {
		recovery_state(source, source->commit + committed, 0, false);
		memcpy(input, source->test->device.visible, source->test->device.bytes);
		if (prepare_faults) {
			recovery_prepare_faults(source, input);
		}
		recovery_execution_faults(source, input, committed != 0);
	}
	free(input);
	recovery_source_close(source);
}

static void
recovery_tail_admission(const char *directory)
{
	enum {
		TAIL_CLIENT,
		TAIL_TRANSACTION,
		TAIL_PREVIOUS,
		TAIL_UNDO,
		TAIL_TARGET,
		TAIL_OPERATION,
		TAIL_LENGTH,
		TAIL_LCN,
		TAIL_FIELDS
	};
	struct recovery_case *source;
	struct test_case *test;
	struct ntfs_write_batch_recovery *owner = NULL;
	struct ntfs_disk_log_record *record;
	struct ntfs_disk_log_update_storage *stored;
	const struct ntfs_write_batch_publication *step;
	uint8_t *baseline, *input, *logical, *encoded;
	size_t publication, field;
	enum ntfs_result result;

	source = recovery_source(directory, "source.img", NTFS_WRITE_CREATE_FILE, TEST_DEFAULT);
	test = source->test;
	baseline = malloc(test->device.bytes);
	input = malloc(test->device.bytes);
	logical = malloc(NTFS_WRITE_CLUSTER_BYTES);
	encoded = malloc(NTFS_WRITE_CLUSTER_BYTES);
	assert(baseline != NULL && input != NULL && logical != NULL && encoded != NULL);
	for (publication = 0; publication < source->commit; publication++) {
		step = &source->publication[publication];
		if (step->stage != NTFS_WRITE_EXECUTION_PREPARE_HOME) {
			continue;
		}
		memcpy(logical, step->image, NTFS_WRITE_CLUSTER_BYTES);
		assert(ntfs_fixup(logical, NTFS_WRITE_CLUSTER_BYTES, "RCRD") == NTFS_OK);
		record = (void *)(logical + source->oracle->restart.page_data_offset);
		stored = (void *)((uint8_t *)record + sizeof(*record));
		if ((ntfs_u16(record->flags) & NTFS_LOGFILE_RECORD_MULTI_PAGE) != 0 &&
		    ntfs_u16(stored->header.redo_operation) ==
			NTFS_LOG_OP_UPDATE_NONRESIDENT_VALUE &&
		    ntfs_u16(stored->header.undo_operation) ==
			NTFS_LOG_OP_UPDATE_NONRESIDENT_VALUE) {
			break;
		}
	}
	assert(publication < source->commit);
	step = &source->publication[publication];
	recovery_state(source, publication + 1, 0, false);
	memcpy(baseline, test->device.visible, test->device.bytes);
	assert(ntfs_write_batch_recover_prepare(&test->backend, &owner) == NTFS_OK);
	ntfs_write_batch_recovery_close(owner);
	assert(test->device.live == 0);
	for (field = 0; field < TAIL_FIELDS; field++) {
		recovery_input(source, baseline);
		memcpy(logical, step->image, NTFS_WRITE_CLUSTER_BYTES);
		assert(ntfs_fixup(logical, NTFS_WRITE_CLUSTER_BYTES, "RCRD") == NTFS_OK);
		record = (void *)(logical + source->oracle->restart.page_data_offset);
		stored = (void *)((uint8_t *)record + sizeof(*record));
		switch (field) {
		case TAIL_CLIENT:
			ntfs_put_u16(record->client_sequence,
			    (uint16_t)(ntfs_u16(record->client_sequence) ^ 1u));
			break;
		case TAIL_TRANSACTION:
			ntfs_put_u32(record->transaction, NTFS_WRITE_MFT_KEY);
			break;
		case TAIL_PREVIOUS:
			ntfs_put_u64(record->previous_lsn, 0);
			break;
		case TAIL_UNDO:
			ntfs_put_u64(record->undo_next_lsn, 0);
			break;
		case TAIL_TARGET:
			ntfs_put_u16(stored->header.target_attribute, UINT16_MAX);
			break;
		case TAIL_OPERATION:
			ntfs_put_u16(
			    stored->header.redo_operation, NTFS_LOG_OP_UPDATE_RESIDENT_VALUE);
			break;
		case TAIL_LENGTH:
			ntfs_put_u32(record->data_bytes, NTFS_WRITE_BATCH_MAX_PACKET_BYTES);
			break;
		case TAIL_LCN:
			ntfs_put_u64(stored->first_lcn, 0);
			break;
		default:
			assert(false);
		}
		assert(ntfs_record_protect(logical, NTFS_WRITE_CLUSTER_BYTES, encoded,
			   NTFS_WRITE_CLUSTER_BYTES) == NTFS_OK);
		memcpy(test->device.visible + step->physical, encoded, NTFS_WRITE_CLUSTER_BYTES);
		memcpy(test->device.durable, test->device.visible, test->device.bytes);
		memcpy(input, test->device.visible, test->device.bytes);
		owner = (void *)(uintptr_t)1;
		result = ntfs_write_batch_recover_prepare(&test->backend, &owner);
		if (result == NTFS_OK) {
			fprintf(
			    stderr, "unfinished tail field %zu was incorrectly admitted\n", field);
		}
		assert(result != NTFS_OK && owner == NULL && test->device.live == 0 &&
		    test->device.writes == 0 && test->device.barriers == 0 &&
		    memcmp(input, test->device.visible, test->device.bytes) == 0 &&
		    memcmp(input, test->device.durable, test->device.bytes) == 0);
	}
	free(encoded);
	free(logical);
	free(input);
	free(baseline);
	recovery_source_close(source);
	puts("PASS: unrelated clients, transactions, links, targets, operations, sizes and "
	     "LCNs in an unfinished tail are refused without journal or metadata mutation");
}

static void
recovery_admission(const char *directory)
{
	static const uint32_t alignments[] = {0, NTFS_WRITE_SECTOR_BYTES / 2,
	    NTFS_WRITE_CLUSTER_BYTES * 2, NTFS_WRITE_SECTOR_BYTES + 1};
	struct recovery_case *source;
	struct test_case *test;
	struct ntfs_overwrite_environment backend, saved;
	struct ntfs_write_batch_recovery *owner = NULL;
	struct ntfs_write_recovery_report report, prior_report;
	const struct ntfs_write_batch_recovery_publication *step;
	uint8_t *frame;
	size_t index, reads, allocations;
	bool poisoned = false;

	source = recovery_source(directory, "source.img", NTFS_WRITE_CREATE_FILE, TEST_DEFAULT);
	test = source->test;
	recovery_state(source, source->commit + 1, 0, false);
	backend = saved = test->backend;
	assert(ntfs_write_batch_recover_prepare(&backend, (void *)&backend.reader.size_bytes) ==
		NTFS_INVALID &&
	    memcmp(&backend, &saved, sizeof(backend)) == 0);
	assert(ntfs_write_batch_recover_prepare(&backend, (void *)(uintptr_t)UINTPTR_MAX) ==
	    NTFS_INVALID);
	for (index = 0; index < sizeof(alignments) / sizeof(alignments[0]); index++) {
		backend.alignment = alignments[index];
		owner = (void *)(uintptr_t)1;
		assert(ntfs_write_batch_recover_prepare(&backend, &owner) == NTFS_INVALID &&
		    owner == NULL);
	}
	backend = saved;
	backend.persist = NULL;
	owner = (void *)(uintptr_t)1;
	assert(ntfs_write_batch_recover_prepare(&backend, &owner) == NTFS_INVALID &&
	    owner == NULL && test->device.allocations == 0 && test->device.reads == 0 &&
	    test->device.live == 0 && test->device.writes == 0 && test->device.barriers == 0);
	assert(ntfs_write_batch_recover_prepare(&saved, &owner) == NTFS_OK);
	step = ntfs_write_batch_recovery_get(owner, 0);
	assert(step != NULL &&
	    ntfs_write_batch_recovery_get(owner, ntfs_write_batch_recovery_count(owner)) == NULL);
	frame = malloc(NTFS_WRITE_CLUSTER_BYTES);
	assert(frame != NULL);
	memcpy(frame, step->image, NTFS_WRITE_CLUSTER_BYTES);
	memset(&report, TEST_PATTERN, sizeof(report));
	prior_report = report;
	reads = test->device.reads;
	allocations = test->device.allocations;
	assert(recovery_execute(test, owner, (void *)step->image, &report) == NTFS_INVALID &&
	    memcmp(&report, &prior_report, sizeof(report)) == 0);
	assert(recovery_execute(test, owner, &poisoned, (void *)step->image) == NTFS_INVALID &&
	    !poisoned && memcmp(frame, step->image, NTFS_WRITE_CLUSTER_BYTES) == 0);
	assert(
	    recovery_execute(test, owner, &poisoned, (void *)owner) == NTFS_INVALID && !poisoned);
	assert(recovery_execute(test, owner, (void *)&report, &report) == NTFS_INVALID &&
	    memcmp(&report, &prior_report, sizeof(report)) == 0 && test->device.reads == reads &&
	    test->device.allocations == allocations && test->device.writes == 0 &&
	    test->device.barriers == 0);
	assert(recovery_execute(test, owner, &poisoned, &report) == NTFS_OK && !poisoned &&
	    report.completed && test->device.reads == reads &&
	    test->device.allocations == allocations);
	assert(recovery_execute(test, owner, &poisoned, &report) == NTFS_INVALID);
	ntfs_write_batch_recovery_close(owner);
	assert(test->device.live == 0);
	recovery_metadata(source, true);
	recovery_journal_check(source, true);
	free(frame);
	recovery_source_close(source);
	assert(ntfs_write_batch_recovery_count(NULL) == 0 &&
	    ntfs_write_batch_recovery_get(NULL, 0) == NULL);
	ntfs_write_batch_recovery_close(NULL);
	puts("PASS: invalid backend, pointer overflow and preparation/execution aliases "
	     "refuse unchanged; copied owner executes once without reads or allocations");
}
