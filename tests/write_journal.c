/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_journal.h"
#include "fuzz_device.h"
#include "../adapters/posix/image.h"
#include <ntfs/record.h>
#include <ntfs/recovery.h>
#include <ntfs/validate.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_PATH_BYTES = 4096,
	TEST_INDEX_BYTES = 1024 * 1024,
	TEST_LOG_LOCATIONS = 7,
	TEST_NATIVE_LSN_OFFSET_BITS = 19,
	TEST_NATIVE_LOG_BYTES = 2523136
};

#define TEST_REFERENCE (UINT64_C(7) << NTFS_REFERENCE_SEQUENCE_SHIFT | UINT64_C(25))
#define TEST_FILETIME UINT64_C(134357146906613431)

struct journal_case {
	struct ntfs_write_journal_input input;
	struct ntfs_write_journal_workspace work;
	struct ntfs_write_journal_plan plan;
	struct ntfs_write_file_plan file;
	uint8_t restart[NTFS_LFS_RESTART_PAGES][NTFS_WRITE_CLUSTER_BYTES];
	uint8_t bootstrap[NTFS_WRITE_BOOTSTRAP_BYTES], checkpoint[NTFS_WRITE_CHECKPOINT_BYTES];
	struct ntfs_logfile_report discovery;
	struct ntfs_logfile_page_index_report index;
	struct ntfs_recovery_report recovery;
	struct ntfs_logfile_checkpoint_capture capture;
	struct ntfs_logfile_restart selected;
	uint64_t physical[TEST_LOG_LOCATIONS];
};

static uint8_t *
load(const char *directory, const char *name, size_t *bytes)
{
	char *path = malloc(TEST_PATH_BYTES);
	uint8_t *data;
	FILE *file;
	long length;
	int result;

	assert(path != NULL);
	result = snprintf(path, TEST_PATH_BYTES, "%s/%s", directory, name);
	assert(result > 0 && result < TEST_PATH_BYTES);
	file = fopen(path, "rb");
	free(path);
	assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
	length = ftell(file);
	assert(length > 0 && fseek(file, 0, SEEK_SET) == 0);
	*bytes = (size_t)length;
	data = malloc(*bytes);
	assert(data != NULL && fread(data, 1, *bytes, file) == *bytes);
	assert(fgetc(file) == EOF && !ferror(file) && fclose(file) == 0);
	return data;
}

static void
prepare(
    struct ntfs_volume *volume, uint64_t reference, uint64_t filetime, struct journal_case *test)
{
	struct ntfs_logfile *source = NULL;
	struct ntfs_recovery *recovery = NULL;
	struct ntfs_logfile_limits limits;
	struct ntfs_recovery_limits recovery_limits;
	struct ntfs_logfile_client client;
	struct ntfs_recovery_record record;
	struct ntfs_node *node = NULL, *log_node = NULL;
	struct ntfs_stream *log = NULL;
	const struct ntfs_run *run;
	const void *packet;
	uint64_t offsets[TEST_LOG_LOCATIONS];
	size_t bytes, index;

	ntfs_logfile_default_limits(&limits);
	limits.max_read_calls = NTFS_RECOVERY_DEFAULT_READ_CALLS;
	limits.max_read_bytes = NTFS_RECOVERY_DEFAULT_READ_BYTES;
	assert(ntfs_logfile_open_volume(volume, &limits, &test->discovery, &source) == NTFS_OK);
	assert(ntfs_logfile_get_restart(source, &test->selected) == NTFS_OK);
	assert(ntfs_logfile_get_client(source, 0, &client) == NTFS_OK);
	assert(ntfs_logfile_prepare_page_index(source, TEST_INDEX_BYTES, &test->index) == NTFS_OK);
	ntfs_recovery_default_limits(&recovery_limits);
	recovery_limits.max_records = 16;
	recovery_limits.max_history_bytes = NTFS_WRITE_CLUSTER_BYTES;
	recovery_limits.max_live_bytes = FUZZ_MEMORY_BUDGET;
	assert(ntfs_recovery_open(source, 0, client.sequence, &recovery_limits, &test->recovery,
		   &recovery) == NTFS_OK);
	assert(ntfs_recovery_get_checkpoint(recovery, &test->capture, &packet) == NTFS_OK);
	assert(test->recovery.records == 2 && test->recovery.history.tail_lsn == 0 &&
	    test->capture.snapshot.present_mask == 0 &&
	    test->recovery.history.completed_end_lsn == test->selected.current_lsn);
	assert(ntfs_recovery_get_record(recovery, 0, &record, &packet) == NTFS_OK);
	assert(record.packet.length == sizeof(test->bootstrap));
	memcpy(test->bootstrap, packet, sizeof(test->bootstrap));
	assert(ntfs_recovery_get_record(recovery, 1, &record, &packet) == NTFS_OK);
	assert(record.packet.length == sizeof(test->checkpoint));
	memcpy(test->checkpoint, packet, sizeof(test->checkpoint));
	ntfs_recovery_close(recovery);
	ntfs_logfile_close(source);
	assert(ntfs_node_open(volume, reference, &node) == NTFS_OK);
	assert(ntfs_write_journal_reserve(&test->selected,
		   (uint16_t)ntfs_u32(((const struct ntfs_disk_record *)node->record)->used),
		   &test->plan.reservation) == NTFS_OK);
	assert(ntfs_write_prepare_metadata(
		   node, filetime, test->plan.reservation.update_lsn, &test->file) == NTFS_OK);
	ntfs_node_close(node);
	assert(ntfs_node_by_number(volume, NTFS_LOGFILE_RECORD, &log_node) == NTFS_OK);
	assert(ntfs_stream_open(log_node, NULL, 0, &log) == NTFS_OK);
	assert(!log->resident && log->flags == 0 && log->initialized == log->size);
	for (index = 0; index < NTFS_LFS_RESTART_PAGES; index++) {
		assert(ntfs_stream_read(log, index * NTFS_WRITE_CLUSTER_BYTES, test->restart[index],
			   sizeof(test->restart[index]), &bytes) == NTFS_OK &&
		    bytes == sizeof(test->restart[index]));
		test->input.restart[index] = test->restart[index];
	}
	offsets[0] = 0;
	offsets[1] = NTFS_WRITE_CLUSTER_BYTES;
	offsets[2] = test->plan.reservation.prepare_offset;
	offsets[3] = test->plan.reservation.commit_offset;
	offsets[4] = test->plan.reservation.checkpoint_offset;
	offsets[5] = NTFS_LFS_RESTART_PAGES * NTFS_WRITE_CLUSTER_BYTES;
	offsets[6] = (NTFS_LFS_RESTART_PAGES + 1) * NTFS_WRITE_CLUSTER_BYTES;
	for (index = 0; index < TEST_LOG_LOCATIONS; index++) {
		run = ntfs_run_find(log, offsets[index] / NTFS_WRITE_CLUSTER_BYTES);
		assert(run != NULL && run->lcn != NTFS_HOLE);
		test->physical[index] =
		    (run->lcn + offsets[index] / NTFS_WRITE_CLUSTER_BYTES - run->vcn) *
		    NTFS_WRITE_CLUSTER_BYTES;
	}
	test->input.file_bytes = log->size;
	test->input.bootstrap = test->bootstrap;
	test->input.checkpoint = test->checkpoint;
	test->input.file = &test->file;
	ntfs_stream_close(log);
	ntfs_node_close(log_node);
	assert(ntfs_write_journal_encode(&test->input, &test->work, &test->plan) == NTFS_OK);
}

static void
golden(const char *directory, const char *name, const void *actual, size_t length)
{
	uint8_t *expected;
	size_t bytes;

	expected = load(directory, name, &bytes);
	assert(bytes == length && memcmp(expected, actual, length) == 0);
	free(expected);
}

static void
abort_golden(const char *directory, struct journal_case *test)
{
	struct ntfs_write_abort_plan *plan = calloc(1, sizeof(*plan));
	struct ntfs_logfile_record record;
	uint8_t *packet;
	size_t bytes;

	assert(plan != NULL);
	assert(ntfs_write_abort_encode(&test->selected, test->capture.client.sequence,
		   &test->plan.reservation, &test->file, &test->work, plan) == NTFS_OK);
	assert(plan->offset == test->plan.reservation.commit_offset &&
	    plan->compensation_lsn == test->plan.reservation.commit_lsn);
	golden(directory, "abort.expected", plan->page, sizeof(plan->page));
	golden(directory, "abort-copy.expected", plan->copy, sizeof(plan->copy));
	golden(directory, "abort-after.expected", plan->file.after, sizeof(plan->file.after));
	golden(directory, "abort-protected.expected", plan->file.protected_after,
	    sizeof(plan->file.protected_after));
	packet = load(directory, "abort.packet", &bytes);
	assert(ntfs_logfile_record_decode(
		   packet, bytes, sizeof(struct ntfs_disk_log_record), &record) == NTFS_OK &&
	    record.lsn == plan->end_lsn);
	free(packet);
	free(plan);
}

static void
refused(struct journal_case *test, enum ntfs_result result)
{
	const uint8_t *bytes = (const void *)&test->plan;
	size_t index;

	memset(&test->plan, -1, sizeof(test->plan));
	assert(ntfs_write_journal_encode(&test->input, &test->work, &test->plan) == result);
	for (index = 0; index < sizeof(test->plan); index++) {
		assert(bytes[index] == 0);
	}
}

static void
refusals(struct journal_case *test)
{
	struct ntfs_disk_record *after = (void *)test->file.after;
	struct ntfs_disk_log_update *noop =
	    (void *)(test->bootstrap + sizeof(struct ntfs_disk_log_record));
	struct ntfs_disk_log_record *bootstrap = (void *)test->bootstrap;
	struct ntfs_disk_log_client_restart *checkpoint =
	    (void *)(test->checkpoint + sizeof(struct ntfs_disk_log_record));
	struct ntfs_disk_log_client *client;
	struct ntfs_write_log_reservation reservation;
	struct ntfs_logfile_restart restart;
	uint64_t value;
	uint16_t short_value;
	uint8_t *original = malloc(sizeof(test->restart[1]));

	assert(original != NULL);
	assert(ntfs_write_journal_encode(&test->input, &test->work, (void *)&test->input) ==
	    NTFS_INVALID);
	assert(ntfs_write_journal_encode(&test->input, (void *)&test->plan, &test->plan) ==
	    NTFS_INVALID);
	assert(ntfs_write_journal_encode(&test->input, &test->work, (void *)&test->file) ==
	    NTFS_INVALID);
	value = ntfs_u64(after->lsn);
	ntfs_put_u64(after->lsn, value - 1);
	refused(test, NTFS_STALE);
	ntfs_put_u64(after->lsn, value);
	value = test->file.mft_reference;
	test->file.mft_reference++;
	refused(test, NTFS_UNSUPPORTED);
	test->file.mft_reference = value;
	short_value = test->file.change_bytes;
	test->file.change_bytes--;
	refused(test, NTFS_UNSUPPORTED);
	test->file.change_bytes = short_value;
	short_value = test->file.snapshot_bytes;
	test->file.snapshot_bytes = NTFS_WRITE_RECORD_BYTES + NTFS_WIRE_ALIGNMENT;
	refused(test, NTFS_CORRUPT);
	test->file.snapshot_bytes = short_value;
	test->file.cluster_index++;
	refused(test, NTFS_UNSUPPORTED);
	test->file.cluster_index--;
	ntfs_put_u16(noop->redo_operation, NTFS_LOG_OP_UPDATE_RESIDENT_VALUE);
	refused(test, NTFS_UNSUPPORTED);
	ntfs_put_u16(noop->redo_operation, NTFS_LOG_OP_NOOP);
	ntfs_put_u32(bootstrap->transaction, NTFS_WRITE_MFT_KEY + 1u);
	refused(test, NTFS_UNSUPPORTED);
	ntfs_put_u32(bootstrap->transaction, NTFS_WRITE_MFT_KEY);
	value = ntfs_u64(checkpoint->analysis_lsn);
	ntfs_put_u64(checkpoint->analysis_lsn, value + 1);
	refused(test, NTFS_UNSUPPORTED);
	ntfs_put_u64(checkpoint->analysis_lsn, value);
	test->checkpoint[sizeof(test->checkpoint) - sizeof(uint64_t)] ^= 1;
	refused(test, NTFS_UNSUPPORTED);
	test->checkpoint[sizeof(test->checkpoint) - sizeof(uint64_t)] ^= 1;
	test->checkpoint[sizeof(struct ntfs_disk_log_record) + sizeof(*checkpoint)] ^= 1;
	refused(test, NTFS_UNSUPPORTED);
	test->checkpoint[sizeof(struct ntfs_disk_log_record) + sizeof(*checkpoint)] ^= 1;
	memcpy(original, test->restart[1], sizeof(test->restart[1]));
	test->restart[1][NTFS_WRITE_SECTOR_BYTES - sizeof(uint16_t)] ^= 1;
	refused(test, NTFS_CORRUPT);
	memcpy(test->restart[1], original, sizeof(test->restart[1]));
	memcpy(test->work.restored, original, sizeof(test->work.restored));
	assert(ntfs_fixup(test->work.restored, sizeof(test->work.restored), "RSTR") == NTFS_OK);
	client = (void *)(test->work.restored + test->selected.clients.offset);
	ntfs_put_u16(client->sequence, (uint16_t)(ntfs_u16(client->sequence) + 1u));
	assert(ntfs_record_protect(test->work.restored, sizeof(test->work.restored),
		   test->restart[1], sizeof(test->restart[1])) == NTFS_OK);
	refused(test, NTFS_UNSUPPORTED);
	memcpy(test->restart[1], original, sizeof(test->restart[1]));
	restart = test->selected;
	restart.flags = 0;
	memset(&reservation, -1, sizeof(reservation));
	assert(ntfs_write_journal_reserve(&restart, test->file.snapshot_bytes, &reservation) ==
	    NTFS_UNSUPPORTED);
	assert(reservation.prepare_offset == 0 && reservation.checkpoint_lsn == 0);
	restart = test->selected;
	restart.current_lsn = (restart.current_lsn >> (NTFS_LFS_LSN_BITS - restart.sequence_bits))
		<< (NTFS_LFS_LSN_BITS - restart.sequence_bits) |
	    (restart.usable_bytes - NTFS_WRITE_CLUSTER_BYTES + NTFS_WRITE_LOG_DATA_OFFSET) >>
		NTFS_LFS_LSN_OFFSET_SHIFT;
	assert(ntfs_write_journal_reserve(&restart, test->file.snapshot_bytes, &reservation) ==
	    NTFS_RANGE);
	assert(reservation.prepare_offset == 0 && reservation.checkpoint_lsn == 0);
	assert(ntfs_write_journal_encode(&test->input, &test->work, &test->plan) == NTFS_OK);
	free(original);
	puts("PASS: stale/address/profile/quiet-input refusals, pointer guards, bounded "
	     "reservation and retry");
}

static void
quiet_profile_vectors(struct journal_case *test)
{
	static const struct {
		uint64_t historical, anchor, checkpoint;
	} native[] = {{UINT64_C(0x100000), UINT64_C(0x184408), UINT64_C(0x184415)},
	    {UINT64_C(0x280000), UINT64_C(0x304408), UINT64_C(0x304415)},
	    {UINT64_C(0x400000), UINT64_C(0x484408), UINT64_C(0x484415)},
	    {UINT64_C(0x580000), UINT64_C(0x604408), UINT64_C(0x604415)},
	    {UINT64_C(0x700000), UINT64_C(0x784408), UINT64_C(0x784415)},
	    /* The old literal is still valid when this profile's anchor permits it. */
	    {UINT64_C(0x1000000), UINT64_C(0x1084408), UINT64_C(0x1084415)}};
	uint8_t bootstrap[NTFS_WRITE_BOOTSTRAP_BYTES], checkpoint[NTFS_WRITE_CHECKPOINT_BYTES];
	struct ntfs_disk_log_record *first = (void *)bootstrap, *last = (void *)checkpoint;
	struct ntfs_disk_log_client_restart *body = (void *)(checkpoint + sizeof(*last));
	struct ntfs_disk_log_quiet_extension *extension = (void *)((uint8_t *)body + sizeof(*body));
	struct ntfs_logfile_restart restart = test->selected;
	struct ntfs_logfile_client client = test->capture.client;
	size_t index;

	memcpy(bootstrap, test->bootstrap, sizeof(bootstrap));
	memcpy(checkpoint, test->checkpoint, sizeof(checkpoint));
	/* The arbitrary historical signature from the old compact author falls
	 * outside this newly qualified profile, not a universal NTFS rule. */
	ntfs_put_u64(extension->historical_state, UINT64_C(0x1000000));
	assert(ntfs_write_quiet_bind(&restart, &client, bootstrap, checkpoint) == NTFS_UNSUPPORTED);
	restart.sequence_bits = NTFS_LFS_LSN_BITS - TEST_NATIVE_LSN_OFFSET_BITS;
	restart.file_bytes = TEST_NATIVE_LOG_BYTES;
	for (index = 0; index < sizeof(native) / sizeof(native[0]); index++) {
		restart.current_lsn = native[index].checkpoint;
		client.oldest_lsn = native[index].anchor;
		client.restart_lsn = native[index].checkpoint;
		ntfs_put_u64(first->lsn, native[index].anchor);
		ntfs_put_u64(last->lsn, native[index].checkpoint);
		ntfs_put_u64(body->analysis_lsn, native[index].anchor);
		ntfs_put_u64(extension->anchor_lsn, native[index].anchor);
		ntfs_put_u64(extension->historical_state, native[index].historical);
		assert(ntfs_write_quiet_bind(&restart, &client, bootstrap, checkpoint) == NTFS_OK);
		ntfs_put_u64(extension->historical_state, 0);
		assert(ntfs_write_quiet_bind(&restart, &client, bootstrap, checkpoint) == NTFS_UNSUPPORTED);
		ntfs_put_u64(extension->historical_state, native[index].historical | 1);
		assert(ntfs_write_quiet_bind(&restart, &client, bootstrap, checkpoint) == NTFS_UNSUPPORTED);
		ntfs_put_u64(extension->historical_state,
		    ((native[index].anchor >> TEST_NATIVE_LSN_OFFSET_BITS) + 1)
			<< TEST_NATIVE_LSN_OFFSET_BITS);
		assert(ntfs_write_quiet_bind(&restart, &client, bootstrap, checkpoint) == NTFS_UNSUPPORTED);
	}
}

static void
quiet_profile_preservation(struct journal_case *test)
{
	uint8_t saved[NTFS_WRITE_CHECKPOINT_BYTES], before[NTFS_WRITE_CHECKPOINT_BYTES];
	struct ntfs_disk_log_quiet_extension *source = (void *)(test->checkpoint +
	    sizeof(struct ntfs_disk_log_record) + sizeof(struct ntfs_disk_log_client_restart));
	const struct ntfs_disk_log_quiet_extension *encoded;
	uint32_t offset_bits = NTFS_LFS_LSN_BITS - test->selected.sequence_bits;
	uint64_t values[] = {UINT64_C(1) << offset_bits,
	    (test->capture.client.oldest_lsn >> offset_bits) << offset_bits,
	    ntfs_u64(source->historical_state)};
	size_t index;

	memcpy(saved, test->checkpoint, sizeof(saved));
	for (index = 0; index < sizeof(values) / sizeof(values[0]); index++) {
		ntfs_put_u64(source->historical_state, values[index]);
		memcpy(before, test->checkpoint, sizeof(before));
		assert(ntfs_write_journal_encode(&test->input, &test->work, &test->plan) == NTFS_OK);
		assert(memcmp(before, test->checkpoint, sizeof(before)) == 0);
		memcpy(test->work.restored, test->plan.checkpoint, sizeof(test->plan.checkpoint));
		assert(ntfs_fixup(test->work.restored, sizeof(test->plan.checkpoint), "RCRD") == NTFS_OK);
		encoded = (const void *)(test->work.restored +
		    test->plan.reservation.checkpoint_record_offset + sizeof(struct ntfs_disk_log_record) +
		    sizeof(struct ntfs_disk_log_client_restart));
		assert(memcmp(source, encoded,
			   offsetof(struct ntfs_disk_log_quiet_extension, anchor_lsn)) == 0);
		assert(ntfs_u64(encoded->anchor_lsn) == test->plan.reservation.bootstrap_lsn);
	}
	memcpy(test->checkpoint, saved, sizeof(saved));
	assert(ntfs_write_journal_encode(&test->input, &test->work, &test->plan) == NTFS_OK);
}

static void
copy_fixture(const char *directory, const char *name, void *out, size_t length)
{
	uint8_t *data;
	size_t bytes;

	data = load(directory, name, &bytes);
	assert(bytes == length);
	memcpy(out, data, bytes);
	free(data);
}

static void
followup(const char *directory, struct journal_case *test)
{
	struct ntfs_write_log_reservation reservation;
	uint64_t tail_lsn = test->plan.reservation.commit_lsn;
	uint64_t first = test->plan.reservation.commit_offset + NTFS_WRITE_CLUSTER_BYTES;

	copy_fixture(directory, "retained-0.expected", test->restart[0], sizeof(test->restart[0]));
	copy_fixture(directory, "retained-1.expected", test->restart[1], sizeof(test->restart[1]));
	copy_fixture(
	    directory, "followup-before.expected", test->file.before, sizeof(test->file.before));
	copy_fixture(
	    directory, "followup-after.expected", test->file.after, sizeof(test->file.after));
	copy_fixture(directory, "followup-protected.expected", test->file.protected_after,
	    sizeof(test->file.protected_after));
	test->input.tail_lsn = tail_lsn;
	assert(ntfs_write_journal_reserve_tail(
		   &test->selected, tail_lsn, test->file.snapshot_bytes, &reservation) == NTFS_OK);
	assert(reservation.prepare_offset == first &&
	    reservation.commit_offset == first + NTFS_WRITE_CLUSTER_BYTES);
	assert(ntfs_write_journal_encode(&test->input, &test->work, &test->plan) == NTFS_OK);
	golden(
	    directory, "followup-prepare.expected", test->plan.prepare, sizeof(test->plan.prepare));
	golden(directory, "followup-commit.expected", test->plan.commit, sizeof(test->plan.commit));
	golden(directory, "followup-dirty-0.expected", test->plan.dirty_restart[0],
	    sizeof(test->plan.dirty_restart[0]));
	golden(directory, "followup-dirty-1.expected", test->plan.dirty_restart[1],
	    sizeof(test->plan.dirty_restart[1]));
	golden(directory, "followup-retained-0.expected", test->plan.retained_restart[0],
	    sizeof(test->plan.retained_restart[0]));
	golden(directory, "followup-retained-1.expected", test->plan.retained_restart[1],
	    sizeof(test->plan.retained_restart[1]));
	test->input.tail_lsn = test->selected.current_lsn - 1;
	refused(test, NTFS_STALE);
	test->input.tail_lsn =
	    tail_lsn + (UINT64_C(1) << (NTFS_LFS_LSN_BITS - test->selected.sequence_bits));
	refused(test, NTFS_STALE);
	test->input.tail_lsn = tail_lsn;
	assert(ntfs_write_journal_encode(&test->input, &test->work, &test->plan) == NTFS_OK);
	puts("PASS: appended transaction and advanced USA retain exact original checkpoint roots; "
	     "stale and wrapped tail refusals");
}

static void
guards(const char *directory, struct journal_case *test)
{
	uint8_t *before = malloc(NTFS_WRITE_CLUSTER_BYTES);
	uint8_t *frame = malloc(NTFS_WRITE_CLUSTER_BYTES);
	uint8_t *mixed = malloc(NTFS_WRITE_CLUSTER_BYTES);
	size_t sector, bytes = NTFS_WRITE_CLUSTER_BYTES;
	unsigned mask, sectors = NTFS_WRITE_CLUSTER_BYTES / NTFS_MST_STRIDE;

	assert(before != NULL && frame != NULL && mixed != NULL);
	memcpy(before, test->plan.prepare, bytes);
	memcpy(frame, test->plan.prepare, bytes);
	assert(ntfs_write_guard_frame(before, bytes, frame, &test->work) == NTFS_OK);
	golden(directory, "guarded-prepare.expected", frame, bytes);
	for (mask = 1; mask + 1 < (1u << sectors); mask++) {
		for (sector = 0; sector < sectors; sector++) {
			memcpy(mixed + sector * NTFS_MST_STRIDE,
			    ((mask & (1u << sector)) ? frame : before) + sector * NTFS_MST_STRIDE,
			    NTFS_MST_STRIDE);
		}
		assert(ntfs_fixup(mixed, bytes, "RCRD") == NTFS_CORRUPT);
	}
	copy_fixture(directory, "guard-many-tail-before.input", before, bytes);
	memcpy(frame, test->plan.prepare, bytes);
	assert(ntfs_write_guard_frame(before, bytes, frame, &test->work) == NTFS_OK);
	golden(directory, "guard-many-tail.expected", frame, bytes);
	copy_fixture(directory, "guard-wrap-before.input", before, bytes);
	copy_fixture(directory, "guard-wrap-after.input", frame, bytes);
	assert(ntfs_write_guard_frame(before, bytes, frame, &test->work) == NTFS_OK);
	golden(directory, "prepare.expected", frame, bytes);
	assert(ntfs_write_guard_frame(frame, bytes, frame, &test->work) == NTFS_INVALID);
	assert(ntfs_write_guard_frame(before, bytes, frame, (void *)frame) == NTFS_INVALID);
	memcpy(frame, test->plan.prepare, bytes);
	frame[NTFS_MST_STRIDE - sizeof(uint16_t)] ^= 1;
	memcpy(mixed, frame, bytes);
	assert(ntfs_write_guard_frame(before, bytes, frame, &test->work) == NTFS_CORRUPT);
	assert(memcmp(frame, mixed, bytes) == 0);
	free(mixed);
	free(frame);
	free(before);
	puts("PASS: guarded USA avoids every preceding sector marker; all sector mixtures, "
	     "sequence wrap and unchanged invalid output");
}

static void
run_vectors(const char *directory)
{
	struct journal_case *test = calloc(1, sizeof(*test));
	struct fuzz_device device = {0};
	struct ntfs_environment environment;
	struct ntfs_limits limits;
	struct ntfs_volume *volume = NULL;
	uint8_t *data, *original, *mixed;
	size_t bytes, reads, allocations, prefix;

	assert(test != NULL);
	data = load(directory, "source.img", &bytes);
	original = malloc(bytes);
	mixed = malloc(NTFS_WRITE_CLUSTER_BYTES);
	assert(original != NULL && mixed != NULL);
	memcpy(original, data, bytes);
	device.data = data;
	device.size = bytes;
	environment = fuzz_environment(&device);
	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	assert(ntfs_mount(&environment, &limits, &volume) == NTFS_OK);
	prepare(volume, TEST_REFERENCE, TEST_FILETIME, test);
	assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
	golden(directory, "before.expected", test->file.before, sizeof(test->file.before));
	golden(directory, "after.expected", test->file.after, sizeof(test->file.after));
	golden(directory, "protected.expected", test->file.protected_after,
	    sizeof(test->file.protected_after));
	golden(directory, "prepare.expected", test->plan.prepare, sizeof(test->plan.prepare));
	golden(directory, "commit.expected", test->plan.commit, sizeof(test->plan.commit));
	golden(directory, "prepare-copy.expected", test->plan.prepare_copy,
	    sizeof(test->plan.prepare_copy));
	golden(directory, "commit-copy.expected", test->plan.commit_copy,
	    sizeof(test->plan.commit_copy));
	golden(
	    directory, "checkpoint.expected", test->plan.checkpoint, sizeof(test->plan.checkpoint));
	golden(directory, "dirty-0.expected", test->plan.dirty_restart[0],
	    sizeof(test->plan.dirty_restart[0]));
	golden(directory, "dirty-1.expected", test->plan.dirty_restart[1],
	    sizeof(test->plan.dirty_restart[1]));
	golden(directory, "clean-0.expected", test->plan.clean_restart[0],
	    sizeof(test->plan.clean_restart[0]));
	golden(directory, "clean-1.expected", test->plan.clean_restart[1],
	    sizeof(test->plan.clean_restart[1]));
	golden(directory, "retained-0.expected", test->plan.retained_restart[0],
	    sizeof(test->plan.retained_restart[0]));
	golden(directory, "retained-1.expected", test->plan.retained_restart[1],
	    sizeof(test->plan.retained_restart[1]));
	reads = device.reads;
	allocations = device.allocations;
	quiet_profile_vectors(test);
	quiet_profile_preservation(test);
	refusals(test);
	assert(device.reads == reads && device.allocations == allocations);
	for (prefix = NTFS_WRITE_SECTOR_BYTES; prefix < NTFS_WRITE_CLUSTER_BYTES;
	    prefix += NTFS_WRITE_SECTOR_BYTES) {
		memcpy(mixed, test->plan.dirty_restart[0], NTFS_WRITE_CLUSTER_BYTES);
		memcpy(mixed, test->plan.clean_restart[0], prefix);
		assert(ntfs_fixup(mixed, NTFS_WRITE_CLUSTER_BYTES, "RSTR") == NTFS_CORRUPT);
		memcpy(mixed, test->plan.dirty_restart[0], NTFS_WRITE_CLUSTER_BYTES);
		memcpy(mixed, test->plan.retained_restart[0], prefix);
		assert(ntfs_fixup(mixed, NTFS_WRITE_CLUSTER_BYTES, "RSTR") == NTFS_CORRUPT);
	}
	abort_golden(directory, test);
	guards(directory, test);
	followup(directory, test);
	assert(device.reads == reads && device.allocations == allocations);
	assert(memcmp(data, original, bytes) == 0);
	free(mixed);
	free(original);
	free(data);
	free(test);
	puts("PASS: independent whole-record/page goldens; WAL/commit copies, retained and "
	     "advanced checkpoints, repeated USA and immutable source");
}

static void
save(const char *directory, const char *name, const void *data, size_t bytes)
{
	char *path = malloc(TEST_PATH_BYTES);
	FILE *file;
	int result;

	assert(path != NULL);
	result = snprintf(path, TEST_PATH_BYTES, "%s/%s", directory, name);
	assert(result > 0 && result < TEST_PATH_BYTES);
	file = fopen(path, "wbx");
	free(path);
	assert(file != NULL && fwrite(data, 1, bytes, file) == bytes && fclose(file) == 0);
}

static void
native(const char *path, uint64_t reference, uint64_t filetime, const char *directory, bool copies)
{
	struct journal_case *test = calloc(1, sizeof(*test));
	struct ntfs_validation_report *validation = calloc(1, sizeof(*validation));
	struct ntfs_image image;
	struct ntfs_volume *volume = NULL;
	struct ntfs_limits limits;
	const struct ntfs_write_log_reservation *r;

	assert(test != NULL && validation != NULL);
	assert(ntfs_image_open(path, &image) == 0);
	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	assert(ntfs_validate(&image.environment, &limits, NULL, validation) == NTFS_OK);
	assert(ntfs_mount(&image.environment, &limits, &volume) == NTFS_OK);
	prepare(volume, reference, filetime, test);
	assert(ntfs_unmount(volume) == NTFS_OK);
	ntfs_image_close(&image);
	save(directory, "dirty-0.bin", test->plan.dirty_restart[0],
	    sizeof(test->plan.dirty_restart[0]));
	save(directory, "dirty-1.bin", test->plan.dirty_restart[1],
	    sizeof(test->plan.dirty_restart[1]));
	save(directory, "prepare.bin", test->plan.prepare, sizeof(test->plan.prepare));
	save(directory, "commit.bin", test->plan.commit, sizeof(test->plan.commit));
	save(directory, "checkpoint.bin", test->plan.checkpoint, sizeof(test->plan.checkpoint));
	save(directory, "clean-0.bin", test->plan.clean_restart[0],
	    sizeof(test->plan.clean_restart[0]));
	save(directory, "clean-1.bin", test->plan.clean_restart[1],
	    sizeof(test->plan.clean_restart[1]));
	save(directory, "before.bin", test->file.before, sizeof(test->file.before));
	save(directory, "after.bin", test->file.after, sizeof(test->file.after));
	save(directory, "protected.bin", test->file.protected_after,
	    sizeof(test->file.protected_after));
	if (copies) {
		save(directory, "prepare-copy.bin", test->plan.prepare_copy,
		    sizeof(test->plan.prepare_copy));
		save(directory, "commit-copy.bin", test->plan.commit_copy,
		    sizeof(test->plan.commit_copy));
		save(directory, "retained-0.bin", test->plan.retained_restart[0],
		    sizeof(test->plan.retained_restart[0]));
		save(directory, "retained-1.bin", test->plan.retained_restart[1],
		    sizeof(test->plan.retained_restart[1]));
	}
	r = &test->plan.reservation;
	printf("{\"scope\":\"private-native-WAL-plan-no-device-writes\",\"reference\":%llu,"
	       "\"filetime\":%llu,"
	       "\"prepare_offset\":%llu,\"commit_offset\":%llu,\"checkpoint_offset\":%llu,"
	       "\"open_lsn\":%llu,\"snapshot_lsn\":%llu,\"update_lsn\":%llu,\"commit_lsn\":%llu,"
	       "\"bootstrap_lsn\":%llu,\"checkpoint_lsn\":%llu,\"physical\":[%llu,%llu,%llu,%llu,%"
	       "llu],"
	       "\"copy_physical\":[%llu,%llu],"
	       "\"mft_cluster_physical\":%llu,\"mft_record_physical\":%llu}\n",
	    (unsigned long long)reference, (unsigned long long)filetime,
	    (unsigned long long)r->prepare_offset, (unsigned long long)r->commit_offset,
	    (unsigned long long)r->checkpoint_offset, (unsigned long long)r->open_lsn,
	    (unsigned long long)r->snapshot_lsn, (unsigned long long)r->update_lsn,
	    (unsigned long long)r->commit_lsn, (unsigned long long)r->bootstrap_lsn,
	    (unsigned long long)r->checkpoint_lsn, (unsigned long long)test->physical[0],
	    (unsigned long long)test->physical[1], (unsigned long long)test->physical[2],
	    (unsigned long long)test->physical[3], (unsigned long long)test->physical[4],
	    (unsigned long long)test->physical[5], (unsigned long long)test->physical[6],
	    (unsigned long long)test->file.cluster_physical,
	    (unsigned long long)(test->file.cluster_physical +
		test->file.cluster_index * NTFS_WRITE_SECTOR_BYTES));
	free(validation);
	free(test);
}

int
main(int argc, char **argv)
{
	char *end;
	uint64_t reference, filetime;

	if (argc == 2) {
		run_vectors(argv[1]);
		return 0;
	}
	assert(argc == 6 &&
	    (strcmp(argv[1], "--native") == 0 || strcmp(argv[1], "--native-copies") == 0));
	errno = 0;
	reference = strtoull(argv[3], &end, 16);
	assert(errno == 0 && end != argv[3] && *end == '\0');
	filetime = strtoull(argv[4], &end, 10);
	assert(errno == 0 && end != argv[4] && *end == '\0');
	native(argv[2], reference, filetime, argv[5], strcmp(argv[1], "--native-copies") == 0);
	return 0;
}
