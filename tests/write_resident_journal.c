/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_internal.h"
#include "fuzz_device.h"
#include "../adapters/posix/image.h"
#include <ntfs/record.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { TEST_PATH_BYTES = 4096, TEST_NAME_BYTES = 128, TEST_ROW_VALUES = 11 };

struct resident_case {
	struct ntfs_write_transaction_workspace transaction;
	struct ntfs_write_replay_input input;
	struct ntfs_write_replay_workspace work;
	struct ntfs_write_replay_plan replay;
	struct ntfs_write_abort_plan abort;
	struct ntfs_write_history_workspace history_work;
	struct ntfs_write_history history;
	struct ntfs_validation_report validation;
	uint8_t *packet[NTFS_WRITE_REPLAY_PACKETS], *resident, *compensation,
	    *resident_compensation, *aborted;
	size_t packet_bytes[NTFS_WRITE_REPLAY_PACKETS], resident_bytes, compensation_bytes,
	    resident_compensation_bytes, aborted_bytes;
};

struct writer {
	struct fuzz_device reader;
	uint8_t *image;
	uint32_t writes, barriers;
	bool owner_active, claimed;
	size_t write_reads, write_allocations;
};

static uint8_t *
load(const char *directory, const char *name, size_t *bytes)
{
	char path[TEST_PATH_BYTES];
	uint8_t *data;
	FILE *file;
	long length;
	int result;

	result = snprintf(path, sizeof(path), "%s/%s", directory, name);
	assert(result > 0 && (size_t)result < sizeof(path));
	file = fopen(path, "rb");
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
golden(const char *directory, const char *name, const void *actual, size_t length)
{
	uint8_t *data;
	size_t bytes;

	data = load(directory, name, &bytes);
	assert(bytes == length && memcmp(data, actual, bytes) == 0);
	free(data);
}

static void
zero_output(const void *data, size_t bytes)
{
	const uint8_t *value = data;
	size_t index;

	for (index = 0; index < bytes; index++) {
		assert(value[index] == 0);
	}
}

static void
packets(const char *directory, struct resident_case *test)
{
	static const char *names[NTFS_WRITE_REPLAY_PACKETS] = {
	    "open.packet", "snapshot.packet", "update.packet", "commit.packet"};
	size_t index;

	for (index = 0; index < NTFS_WRITE_REPLAY_PACKETS; index++) {
		test->packet[index] = load(directory, names[index], &test->packet_bytes[index]);
		test->input.packet[index] =
		    (struct ntfs_logfile_buffer){test->packet[index], test->packet_bytes[index]};
	}
	test->resident = load(directory, "resident.packet", &test->resident_bytes);
	test->compensation = load(directory, "compensation.packet", &test->compensation_bytes);
	test->resident_compensation =
	    load(directory, "resident-compensation.packet", &test->resident_compensation_bytes);
	test->aborted = load(directory, "abort.packet", &test->aborted_bytes);
	test->input.restart = test->transaction.history.origin;
	test->input.resident = (struct ntfs_logfile_buffer){test->resident, test->resident_bytes};
}

static void
replay(struct ntfs_volume *volume, const struct ntfs_environment *environment,
    const char *directory, struct resident_case *test, const unsigned long long *row)
{
	const char *expected;
	unsigned state;

	for (state = 0; state < 3; state++) {
		test->input.packet[NTFS_WRITE_REPLAY_COMMIT] = state == 0
		    ? (struct ntfs_logfile_buffer){test->packet[NTFS_WRITE_REPLAY_COMMIT],
			  test->packet_bytes[NTFS_WRITE_REPLAY_COMMIT]}
		    : state == 1
		    ? (struct ntfs_logfile_buffer){NULL, 0}
		    : (struct ntfs_logfile_buffer){test->compensation, test->compensation_bytes};
		test->input.abort = state == 2
		    ? (struct ntfs_logfile_buffer){test->aborted, test->aborted_bytes}
		    : (struct ntfs_logfile_buffer){NULL, 0};
		test->input.resident_compensation = state == 2
		    ? (struct ntfs_logfile_buffer){test->resident_compensation,
			  test->resident_compensation_bytes}
		    : (struct ntfs_logfile_buffer){NULL, 0};
		assert(ntfs_write_replay_prepare(
			   volume, &test->input, &test->work, &test->replay) == NTFS_OK);
		assert(test->replay.committed == (state == 0) &&
		    test->replay.compensated == (state == 2));
		assert(test->replay.resident_lsn == row[4] &&
		    test->replay.file.resident_bytes == row[3] &&
		    test->replay.prepared_packets == NTFS_WRITE_REPLAY_COMMIT + 1 &&
		    test->replay.packets ==
			(state == 0	     ? 5
				: state == 1 ? 4
					     : 7));
		if (state == 2) {
			assert(test->replay.resident_compensation_lsn == row[6] &&
			    test->replay.compensation_lsn == row[7] &&
			    test->replay.abort_lsn == row[8]);
		}
		expected = state == 0 ? "after.expected"
		    : state == 1      ? "before.expected"
				      : "abort-after.expected";
		golden(
		    directory, expected, test->replay.file.after, sizeof(test->replay.file.after));
		expected = state == 0 ? "protected.expected"
		    : state == 1      ? "undo-protected.expected"
				      : "abort-protected.expected";
		golden(directory, expected, test->replay.file.protected_after,
		    sizeof(test->replay.file.protected_after));
		assert(ntfs_write_validate_overlay(environment, &test->replay, &test->validation) ==
		    NTFS_OK);
	}
}

static void
refuse(struct ntfs_volume *volume, struct resident_case *test)
{
	memset(&test->replay, -1, sizeof(test->replay));
	assert(
	    ntfs_write_replay_prepare(volume, &test->input, &test->work, &test->replay) != NTFS_OK);
	zero_output(&test->replay, sizeof(test->replay));
}

static void
mutants(struct ntfs_volume *volume, struct resident_case *test)
{
	struct ntfs_disk_log_record *record = (void *)test->resident;
	struct ntfs_disk_log_update *update = (void *)(test->resident + sizeof(*record));
	uint64_t lsn;
	uint16_t value;
	uint8_t byte;
	size_t offset;

	test->input.packet[NTFS_WRITE_REPLAY_COMMIT] = (struct ntfs_logfile_buffer){
	    test->packet[NTFS_WRITE_REPLAY_COMMIT], test->packet_bytes[NTFS_WRITE_REPLAY_COMMIT]};
	test->input.abort = (struct ntfs_logfile_buffer){NULL, 0};
	test->input.resident_compensation = (struct ntfs_logfile_buffer){NULL, 0};
	lsn = ntfs_u64(record->previous_lsn);
	ntfs_put_u64(record->previous_lsn, 0);
	refuse(volume, test);
	ntfs_put_u64(record->previous_lsn, lsn);
	lsn = ntfs_u64(record->undo_next_lsn);
	ntfs_put_u64(record->undo_next_lsn, 0);
	refuse(volume, test);
	ntfs_put_u64(record->undo_next_lsn, lsn);
	value = ntfs_u16(update->record_offset);
	ntfs_put_u16(update->record_offset, value + NTFS_WIRE_ALIGNMENT);
	refuse(volume, test);
	ntfs_put_u16(update->record_offset, value);
	value = ntfs_u16(update->attribute_offset);
	ntfs_put_u16(update->attribute_offset, 0);
	refuse(volume, test);
	ntfs_put_u16(update->attribute_offset, value);
	value = ntfs_u16(update->attribute_flags);
	ntfs_put_u16(update->attribute_flags, 0);
	refuse(volume, test);
	ntfs_put_u16(update->attribute_flags, value);
	offset = sizeof(*record) + ntfs_u16(update->undo_offset);
	byte = test->resident[offset];
	test->resident[offset] ^= 1;
	refuse(volume, test);
	test->resident[offset] = byte;
	update = (void *)(test->resident_compensation + sizeof(*record));
	test->input.packet[NTFS_WRITE_REPLAY_COMMIT] =
	    (struct ntfs_logfile_buffer){test->compensation, test->compensation_bytes};
	test->input.abort = (struct ntfs_logfile_buffer){test->aborted, test->aborted_bytes};
	test->input.resident_compensation = (struct ntfs_logfile_buffer){
	    test->resident_compensation, test->resident_compensation_bytes};
	offset = sizeof(*record) + ntfs_u16(update->redo_offset);
	byte = test->resident_compensation[offset];
	test->resident_compensation[offset] ^= 1;
	refuse(volume, test);
	test->resident_compensation[offset] = byte;
	record = (void *)test->compensation;
	lsn = ntfs_u64(record->previous_lsn);
	ntfs_put_u64(record->previous_lsn, test->transaction.journal.reservation.update_lsn);
	refuse(volume, test);
	ntfs_put_u64(record->previous_lsn, lsn);
	assert(
	    ntfs_write_replay_prepare(volume, &test->input, &test->work, &test->replay) == NTFS_OK);
}

static enum ntfs_result
write_image(void *context, uint64_t physical, const void *data, size_t bytes, size_t *actual)
{
	struct writer *writer = context;

	assert((writer->owner_active ? writer->claimed : writer->reader.memory == 0) &&
	    ntfs_bounds(physical, bytes, writer->reader.size));
	assert(physical % NTFS_WRITE_SECTOR_BYTES == 0 && bytes % NTFS_WRITE_SECTOR_BYTES == 0);
	if (writer->owner_active) {
		if (writer->writes == 0) {
			writer->write_reads = writer->reader.reads;
			writer->write_allocations = writer->reader.allocations;
		}
		assert(writer->reader.reads == writer->write_reads &&
		    writer->reader.allocations == writer->write_allocations);
	}
	memcpy(writer->image + physical, data, bytes);
	writer->writes++;
	*actual = bytes;
	return NTFS_OK;
}

static enum ntfs_result
persist(void *context)
{
	struct writer *writer = context;

	assert(writer->owner_active ? writer->claimed
				    : writer->reader.memory == 0 && writer->writes != 0);
	if (writer->owner_active && writer->writes != 0) {
		assert(writer->reader.reads == writer->write_reads &&
		    writer->reader.allocations == writer->write_allocations);
	}
	writer->barriers++;
	return NTFS_OK;
}

static enum ntfs_result
claim(void *context)
{
	struct writer *writer = context;

	assert(writer->owner_active && !writer->claimed);
	writer->claimed = true;
	return NTFS_OK;
}

static void
unclaim(void *context)
{
	struct writer *writer = context;

	assert(writer->claimed);
	writer->claimed = false;
}

static void
owner_range(const char *directory, const uint8_t *source, size_t bytes, const uint8_t *payload,
    size_t payload_bytes, const unsigned long long *row, const struct ntfs_write_file_plan *file)
{
	struct writer writer = {0};
	struct ntfs_overwrite_environment backend = {0};
	struct ntfs_overwrite *owner = NULL;
	struct ntfs_overwrite_admission *admission;
	struct ntfs_write_recovery_report recovered;
	struct ntfs_write_range_report report;
	struct ntfs_attr_view attribute;
	const uint8_t *value;

	size_t ordinal, memory, value_bytes;

	admission = calloc(1, sizeof(*admission));
	writer.image = malloc(bytes);
	assert(admission != NULL && writer.image != NULL);
	memcpy(writer.image, source, bytes);
	writer.reader.data = writer.image;
	writer.reader.size = bytes;
	writer.owner_active = true;
	backend.reader = fuzz_environment(&writer.reader);
	backend.api_version = NTFS_OVERWRITE_API_VERSION;
	backend.alignment = NTFS_WRITE_SECTOR_BYTES;
	backend.claim = claim;
	backend.unclaim = unclaim;
	backend.write = write_image;
	backend.persist = persist;
	assert(ntfs_write_owner_open(&backend, admission, &recovered, &owner) == NTFS_OK);
	assert(admission->claimed && admission->quiescent && admission->persistence_succeeded &&
	    recovered.completed && recovered.writes == 0 && writer.claimed);
	memory = writer.reader.memory;
	writer.writes = 0;
	writer.barriers = 0;
	for (ordinal = 1; ordinal <= 7; ordinal++) {
		writer.reader.fail_allocation = writer.reader.allocations + ordinal;
		assert(ntfs_write_existing_range(owner, row[0], row[2], payload, payload_bytes,
			   row[1], &report) == NTFS_NO_MEMORY);
		assert(report.completed_bytes == 0 && !report.execution.poisoned &&
		    writer.writes == 0 && writer.barriers == 0 && writer.reader.memory == memory &&
		    memcmp(source, writer.image, bytes) == 0);
	}
	writer.reader.fail_allocation = 0;
	writer.reader.reads = 0;
	assert(ntfs_attr_find(file->before, sizeof(file->before), NTFS_ATTRIBUTE_DATA, NULL, 0,
		   UINT16_MAX, &attribute) == NTFS_OK);
	assert(ntfs_attr_value(&attribute, &value, &value_bytes) == NTFS_OK);
	assert(ntfs_write_existing_range(owner, row[0], value_bytes, payload, payload_bytes, row[1],
		   &report) == NTFS_RANGE);
	assert(report.completed_bytes == 0 && !report.execution.poisoned && writer.writes == 0 &&
	    writer.barriers == 0 && writer.reader.memory == memory &&
	    memcmp(source, writer.image, bytes) == 0);
	writer.reader.reads = 0;
	assert(ntfs_write_existing_range(owner,
		   row[0] + (UINT64_C(1) << NTFS_REFERENCE_SEQUENCE_SHIFT), row[2], payload,
		   payload_bytes, row[1], &report) == NTFS_STALE);
	assert(report.completed_bytes == 0 && !report.execution.poisoned && writer.writes == 0 &&
	    writer.barriers == 0 && writer.reader.memory == memory &&
	    memcmp(source, writer.image, bytes) == 0);
	writer.reader.reads = 0;
	assert(ntfs_write_existing_range(
		   owner, row[0], row[2], payload, payload_bytes, row[1], &report) == NTFS_OK);
	assert(report.requested_bytes == payload_bytes && report.completed_bytes == payload_bytes &&
	    report.execution.completed && report.execution.commit_persisted &&
	    report.execution.data_bytes == 0 && !report.execution.poisoned &&
	    writer.reader.memory == memory);
	golden(directory, "execute-final.img", writer.image, bytes);
	ntfs_overwrite_close(owner);
	assert(!writer.claimed && writer.reader.memory == 0);
	writer.reader.reads = 0;
	writer.writes = 0;
	writer.barriers = 0;
	owner = NULL;
	assert(ntfs_write_owner_open(&backend, admission, &recovered, &owner) == NTFS_OK);
	assert(recovered.completed && recovered.writes == 0 && recovered.barriers == 1);
	golden(directory, "execute-final.img", writer.image, bytes);
	ntfs_overwrite_close(owner);
	assert(!writer.claimed && writer.reader.memory == 0);
	free(writer.image);
	free(admission);
}

static void
execute(const char *directory, struct resident_case *test, const uint8_t *source, size_t bytes)
{
	struct writer writer = {0};
	struct ntfs_overwrite_environment backend = {0};
	struct ntfs_write_execution_report report;
	struct ntfs_write_execution_workspace *work;
	struct ntfs_environment reader;
	struct ntfs_volume *volume = NULL;
	bool poisoned = false;
	size_t capacity;

	writer.image = malloc(bytes);
	assert(writer.image != NULL);
	memcpy(writer.image, source, bytes);
	writer.reader.data = writer.image;
	writer.reader.size = bytes;
	reader = fuzz_environment(&writer.reader);
	backend.reader = reader;
	backend.api_version = NTFS_OVERWRITE_API_VERSION;
	backend.alignment = NTFS_WRITE_SECTOR_BYTES;
	backend.write = write_image;
	backend.persist = persist;
	capacity = (sizeof(*work) + NTFS_WRITE_CLUSTER_BYTES - 1u) / NTFS_WRITE_CLUSTER_BYTES *
	    NTFS_WRITE_CLUSTER_BYTES;
	work = aligned_alloc(NTFS_WRITE_CLUSTER_BYTES, capacity);
	assert(work != NULL);
	assert(ntfs_write_execute_prepare(&backend, &test->transaction.execution, work) == NTFS_OK);
	assert(ntfs_write_execute(work, &poisoned, &report) == NTFS_OK);
	assert(report.completed && report.commit_persisted && !report.poisoned && !poisoned &&
	    report.data_bytes == 0 && writer.writes != 0 && writer.barriers != 0);
	golden(directory, "execute-final.img", writer.reader.data, bytes);
	assert(ntfs_mount(&reader, NULL, &volume) == NTFS_OK);
	assert(ntfs_write_history_capture(volume, &test->history_work, &test->history) == NTFS_OK);
	assert(test->history.transactions == 1 && test->history.count == 7 &&
	    test->history.replay.committed && test->history.replay.file.resident_bytes != 0);
	assert(ntfs_write_history_settled(volume, &test->history) == NTFS_OK);
	assert(ntfs_unmount(volume) == NTFS_OK && writer.reader.memory == 0);
	free(work);
	free(writer.image);
}

static void
vectors(const char *directory)
{
	struct resident_case *test;
	struct fuzz_device device = {0};
	struct ntfs_environment environment;
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *node = NULL;
	char path[TEST_PATH_BYTES], name[TEST_NAME_BYTES];
	unsigned long long row[TEST_ROW_VALUES];
	uint8_t *source, *original, *payload;
	FILE *rows;
	size_t bytes, payload_bytes, index, count = 0;
	int result;

	result = snprintf(path, sizeof(path), "%s/cases.rows", directory);
	assert(result > 0 && (size_t)result < sizeof(path));
	rows = fopen(path, "rb");
	assert(rows != NULL);
	while (fscanf(rows, "%127s %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu", name,
		   &row[0], &row[1], &row[2], &row[3], &row[4], &row[5], &row[6], &row[7], &row[8],
		   &row[9], &row[10]) == TEST_ROW_VALUES + 1) {
		result = snprintf(path, sizeof(path), "%s/%s", directory, name);
		assert(result > 0 && (size_t)result < sizeof(path));
		test = calloc(1, sizeof(*test));
		assert(test != NULL);
		source = load(path, "source.img", &bytes);
		payload = load(path, "payload.input", &payload_bytes);
		original = malloc(bytes);
		assert(original != NULL && payload_bytes == row[3]);
		memcpy(original, source, bytes);
		device.data = source;
		device.size = bytes;
		environment = fuzz_environment(&device);
		assert(ntfs_mount(&environment, NULL, &volume) == NTFS_OK);
		assert(ntfs_node_open(volume, row[0], &node) == NTFS_OK);
		assert(ntfs_write_prepare_resident_transaction(node, row[1], row[2], payload,
			   payload_bytes, &test->transaction) == NTFS_OK);
		ntfs_node_close(node);
		node = NULL;
		assert(test->transaction.journal.reservation.resident_lsn == row[4] &&
		    test->transaction.journal.reservation.resident_offset == row[5]);
		golden(path, "before.expected", test->transaction.file.before,
		    sizeof(test->transaction.file.before));
		golden(path, "after.expected", test->transaction.file.after,
		    sizeof(test->transaction.file.after));
		golden(path, "protected.expected", test->transaction.file.protected_after,
		    sizeof(test->transaction.file.protected_after));
		golden(path, "prepare.expected", test->transaction.journal.prepare,
		    sizeof(test->transaction.journal.prepare));
		golden(path, "prepare-copy.expected", test->transaction.journal.prepare_copy,
		    sizeof(test->transaction.journal.prepare_copy));
		golden(path, "commit.expected", test->transaction.journal.commit,
		    sizeof(test->transaction.journal.commit));
		assert(ntfs_write_abort_encode(&test->transaction.history.origin,
			   test->transaction.history.client.sequence,
			   &test->transaction.journal.reservation, &test->transaction.file,
			   &test->transaction.journal_work, &test->abort) == NTFS_OK);
		assert(test->abort.resident_compensation_lsn == row[6] &&
		    test->abort.compensation_lsn == row[7] && test->abort.end_lsn == row[8]);
		golden(path, "abort.expected", test->abort.page, sizeof(test->abort.page));
		golden(path, "abort-copy.expected", test->abort.copy, sizeof(test->abort.copy));
		golden(path, "abort-protected.expected", test->abort.file.protected_after,
		    sizeof(test->abort.file.protected_after));
		packets(path, test);
		replay(volume, &environment, path, test, row);
		mutants(volume, test);
		assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
		assert(memcmp(original, source, bytes) == 0);
		execute(path, test, source, bytes);
		owner_range(
		    path, source, bytes, payload, payload_bytes, row, &test->transaction.file);
		for (index = 0; index < NTFS_WRITE_REPLAY_PACKETS; index++) {
			free(test->packet[index]);
		}
		free(test->resident);
		free(test->compensation);
		free(test->resident_compensation);
		free(test->aborted);
		free(test);
		free(source);
		free(original);
		free(payload);
		count++;
	}
	assert(feof(rows) && !ferror(rows) && fclose(rows) == 0 && count != 0);
	printf("PASS: %zu independent resident DATA/SI page/FILE/whole-image families; "
	       "winner/loser/compensation replay, eight invalid packet bindings, "
	       "retained owner range writes and allocation/range/sequence refusal each\n",
	    count);
}

static void
save(const char *directory, const char *name, const void *data, size_t bytes)
{
	char path[TEST_PATH_BYTES];
	FILE *file;
	int result;

	result = snprintf(path, sizeof(path), "%s/%s", directory, name);
	assert(result > 0 && (size_t)result < sizeof(path));
	file = fopen(path, "wbx");
	assert(file != NULL && fwrite(data, 1, bytes, file) == bytes && fclose(file) == 0);
}

static void
native(const char *path, uint64_t reference, uint64_t filetime, uint64_t offset,
    const char *payload_path, const char *directory)
{
	struct resident_case *test = calloc(1, sizeof(*test));
	struct ntfs_image image;
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *node = NULL;
	struct ntfs_limits limits;
	const struct ntfs_write_log_reservation *reservation;
	uint8_t *payload;
	size_t bytes, index;
	FILE *file;
	long length;

	assert(test != NULL);
	file = fopen(payload_path, "rb");
	assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
	length = ftell(file);
	assert(length > 0 && length <= NTFS_WRITE_RECORD_BYTES && fseek(file, 0, SEEK_SET) == 0);
	bytes = (size_t)length;
	payload = malloc(bytes);
	assert(payload != NULL && fread(payload, 1, bytes, file) == bytes);
	assert(fgetc(file) == EOF && !ferror(file) && fclose(file) == 0);
	assert(ntfs_image_open(path, &image) == 0);
	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	assert(ntfs_validate(&image.environment, &limits, NULL, &test->validation) == NTFS_OK);
	assert(ntfs_mount(&image.environment, &limits, &volume) == NTFS_OK);
	assert(ntfs_node_open(volume, reference, &node) == NTFS_OK);
	assert(ntfs_write_prepare_resident_transaction(
		   node, filetime, offset, payload, bytes, &test->transaction) == NTFS_OK);
	ntfs_node_close(node);
	assert(ntfs_unmount(volume) == NTFS_OK);
	test->replay.file = test->transaction.file;
	assert(ntfs_write_validate_overlay(&image.environment, &test->replay, &test->validation) ==
	    NTFS_OK);
	ntfs_image_close(&image);
	assert(
	    ntfs_write_abort_encode(&test->transaction.history.origin,
		test->transaction.history.client.sequence, &test->transaction.journal.reservation,
		&test->transaction.file, &test->transaction.journal_work, &test->abort) == NTFS_OK);
	save(directory, "before.bin", test->transaction.file.before,
	    sizeof(test->transaction.file.before));
	save(directory, "after.bin", test->transaction.file.after,
	    sizeof(test->transaction.file.after));
	save(directory, "protected.bin", test->transaction.file.protected_after,
	    sizeof(test->transaction.file.protected_after));
	save(directory, "prepare.bin", test->transaction.journal.prepare,
	    sizeof(test->transaction.journal.prepare));
	save(directory, "prepare-copy.bin", test->transaction.journal.prepare_copy,
	    sizeof(test->transaction.journal.prepare_copy));
	save(directory, "commit.bin", test->transaction.journal.commit,
	    sizeof(test->transaction.journal.commit));
	save(directory, "commit-copy.bin", test->transaction.journal.commit_copy,
	    sizeof(test->transaction.journal.commit_copy));
	save(directory, "abort.bin", test->abort.page, sizeof(test->abort.page));
	save(directory, "abort-copy.bin", test->abort.copy, sizeof(test->abort.copy));
	save(directory, "abort-protected.bin", test->abort.file.protected_after,
	    sizeof(test->abort.file.protected_after));
	for (index = 0; index < NTFS_LFS_RESTART_PAGES; index++) {
		save(directory, index == 0 ? "dirty-0.bin" : "dirty-1.bin",
		    test->transaction.journal.dirty_restart[index], NTFS_WRITE_CLUSTER_BYTES);
		save(directory, index == 0 ? "retained-0.bin" : "retained-1.bin",
		    test->transaction.journal.retained_restart[index], NTFS_WRITE_CLUSTER_BYTES);
	}
	reservation = &test->transaction.journal.reservation;
	printf("{\"success\":true,\"scope\":\"private-resident-WAL-plan-no-device-writes\","
	       "\"reference\":%llu,\"filetime\":%llu,\"offset\":%llu,\"bytes\":%zu,"
	       "\"prepare_offset\":%llu,\"commit_offset\":%llu,\"resident_lsn\":%llu,"
	       "\"compensation_lsn\":%llu,\"resident_compensation_lsn\":%llu,\"abort_lsn\":%llu,"
	       "\"file_physical\":%llu,\"physical\":[",
	    (unsigned long long)reference, (unsigned long long)filetime, (unsigned long long)offset,
	    bytes, (unsigned long long)reservation->prepare_offset,
	    (unsigned long long)reservation->commit_offset,
	    (unsigned long long)reservation->resident_lsn,
	    (unsigned long long)test->abort.compensation_lsn,
	    (unsigned long long)test->abort.resident_compensation_lsn,
	    (unsigned long long)test->abort.end_lsn,
	    (unsigned long long)(test->transaction.file.cluster_physical +
		(size_t)test->transaction.file.cluster_index * NTFS_WRITE_SECTOR_BYTES));
	for (index = 0; index < NTFS_WRITE_EXECUTE_LOG_LOCATIONS; index++) {
		printf("%s%llu", index == 0 ? "" : ",",
		    (unsigned long long)test->transaction.execution.physical[index]);
	}
	puts("],\"residentCoreWritesQualified\":false,\"generalNTFSWritesQualified\":false}");
	free(payload);
	free(test);
}

int
main(int argc, char **argv)
{
	char *end;
	uint64_t reference, filetime, offset;

	if (argc == 2) {
		vectors(argv[1]);
		return 0;
	}
	assert(argc == 8 && strcmp(argv[1], "--native") == 0);
	errno = 0;
	reference = strtoull(argv[3], &end, 16);
	assert(errno == 0 && end != argv[3] && *end == '\0');
	filetime = strtoull(argv[4], &end, 10);
	assert(errno == 0 && end != argv[4] && *end == '\0');
	offset = strtoull(argv[5], &end, 10);
	assert(errno == 0 && end != argv[5] && *end == '\0');
	native(argv[2], reference, filetime, offset, argv[6], argv[7]);
	return 0;
}
