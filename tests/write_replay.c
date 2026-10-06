/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_internal.h"
#include "fuzz_device.h"
#include <ntfs/record.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { TEST_PATH_BYTES = 4096, TEST_VALUES = 14, TEST_PARTIAL_DIVISOR = 2 };

struct replay_case {
	struct ntfs_write_replay_input input;
	struct ntfs_write_replay_workspace work;
	struct ntfs_write_replay_plan plan;
	uint8_t *packet[NTFS_WRITE_REPLAY_PACKETS];
	size_t packet_bytes[NTFS_WRITE_REPLAY_PACKETS];
	unsigned long long values[TEST_VALUES];
};

static bool full_failed_read;

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
	data = malloc(*bytes + 1);
	assert(data != NULL && fread(data, 1, *bytes, file) == *bytes);
	data[*bytes] = 0;
	assert(fgetc(file) == EOF && !ferror(file) && fclose(file) == 0);
	return data;
}

static void
initialize(const char *directory, struct replay_case *test)
{
	const char *names[] = {"open.packet", "snapshot.packet", "update.packet", "commit.packet"};
	unsigned long long *value = test->values;
	uint8_t *data, *restart, *work = malloc(NTFS_WRITE_CLUSTER_BYTES);
	size_t bytes, index;

	assert(work != NULL);
	for (index = 0; index < NTFS_WRITE_REPLAY_PACKETS; index++) {
		test->packet[index] = load(directory, names[index], &test->packet_bytes[index]);
		test->input.packet[index].data = test->packet[index];
		test->input.packet[index].bytes = test->packet_bytes[index];
	}
	data = load(directory, "replay.rows", &bytes);
	assert(sscanf((const char *)data,
		   "%llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
		   &value[0], &value[1], &value[2], &value[3], &value[4], &value[5], &value[6],
		   &value[7], &value[8], &value[9], &value[10], &value[11], &value[12],
		   &value[13]) == TEST_VALUES);
	free(data);
	restart = load(directory, "dirty-0.expected", &bytes);
	assert(bytes == NTFS_WRITE_CLUSTER_BYTES);
	assert(ntfs_logfile_restart_decode(restart, bytes, UINT64_MAX, work,
		   NTFS_WRITE_CLUSTER_BYTES, &test->input.restart) == NTFS_OK);
	free(restart);
	free(work);
}

static void
destroy(struct replay_case *test)
{
	size_t index;

	for (index = 0; index < NTFS_WRITE_REPLAY_PACKETS; index++) {
		free(test->packet[index]);
	}
	free(test);
}

static enum ntfs_result
partial_read(void *context, uint64_t offset, void *buffer, size_t bytes)
{
	struct fuzz_device *device = context;

	if (device->fail_read != 0 && device->reads + 1 == device->fail_read) {
		assert(ntfs_bounds(offset, bytes, device->size));
		memcpy(buffer, device->data + offset,
		    full_failed_read ? bytes : bytes / TEST_PARTIAL_DIVISOR);
	}
	return fuzz_read(context, offset, buffer, bytes);
}

static struct ntfs_volume *
mount(struct fuzz_device *device)
{
	struct ntfs_environment environment = fuzz_environment(device);
	struct ntfs_limits limits;
	struct ntfs_volume *volume = NULL;

	environment.read = partial_read;
	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	device->reads = 0;
	device->allocations = 0;
	assert(ntfs_mount(&environment, &limits, &volume) == NTFS_OK);
	device->reads = 0;
	device->allocations = 0;
	return volume;
}

static void
zero_output(const struct ntfs_write_replay_plan *plan)
{
	const uint8_t *bytes = (const void *)plan;
	size_t index;

	for (index = 0; index < sizeof(*plan); index++) {
		assert(bytes[index] == 0);
	}
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
oracle(const char *directory, const struct replay_case *test, bool committed)
{
	const unsigned long long *value = test->values;
	const struct ntfs_write_file_plan *file = &test->plan.file;

	assert(file->reference == value[0] && file->mft_reference == value[1] &&
	    file->target_vcn == value[2] && file->target_lcn == value[3] &&
	    file->cluster_physical == value[4] && file->cluster_index == value[5] &&
	    file->record_offset == value[6] && file->attribute_offset == value[7] &&
	    file->change_bytes == value[8] && file->snapshot_bytes == value[9]);
	assert(test->plan.open_lsn == value[10] && test->plan.snapshot_lsn == value[11] &&
	    test->plan.update_lsn == value[12] &&
	    test->plan.commit_lsn == (committed ? value[13] : 0) &&
	    test->plan.committed == committed);
	golden(directory, "before.expected", file->before, sizeof(file->before));
	golden(directory, committed ? "after.expected" : "before.expected", file->after,
	    sizeof(file->after));
	golden(directory, committed ? "protected.expected" : "undo-protected.expected",
	    file->protected_after, sizeof(file->protected_after));
}

static void
commit_input(struct replay_case *test, bool committed)
{
	test->input.packet[NTFS_WRITE_REPLAY_COMMIT].data =
	    committed ? test->packet[NTFS_WRITE_REPLAY_COMMIT] : NULL;
	test->input.packet[NTFS_WRITE_REPLAY_COMMIT].bytes =
	    committed ? test->packet_bytes[NTFS_WRITE_REPLAY_COMMIT] : 0;
}

static void
refused(struct ntfs_volume *volume, struct replay_case *test, enum ntfs_result expected)
{
	size_t memory = volume->live_bytes;
	uint32_t children = volume->children;

	memset(&test->plan, -1, sizeof(test->plan));
	assert(
	    ntfs_write_replay_prepare(volume, &test->input, &test->work, &test->plan) == expected);
	zero_output(&test->plan);
	assert(volume->live_bytes == memory && volume->children == children);
}

static void
change(struct ntfs_volume *volume, struct replay_case *test, size_t packet, size_t offset,
    uint64_t value, size_t bytes, enum ntfs_result expected)
{
	uint8_t saved[sizeof(uint64_t)], *field = test->packet[packet] + offset;

	assert(bytes <= sizeof(saved) && ntfs_bounds(offset, bytes, test->packet_bytes[packet]));
	memcpy(saved, field, bytes);
	if (bytes == sizeof(uint64_t)) {
		ntfs_put_u64(field, value);
	} else if (bytes == sizeof(uint32_t)) {
		ntfs_put_u32(field, (uint32_t)value);
	} else {
		assert(bytes == sizeof(uint16_t));
		ntfs_put_u16(field, (uint16_t)value);
	}
	refused(volume, test, expected);
	memcpy(field, saved, bytes);
}

static void
refusals(struct ntfs_volume *volume, struct replay_case *test)
{
	const size_t update = sizeof(struct ntfs_disk_log_record);
	const size_t snapshot = update + sizeof(struct ntfs_disk_log_update_storage);
	const size_t redo = snapshot, undo = redo + test->values[8];
	struct ntfs_info info = volume->info;
	struct ntfs_logfile_restart restart = test->input.restart;

	change(volume, test, NTFS_WRITE_REPLAY_OPEN,
	    offsetof(struct ntfs_disk_log_record, transaction), NTFS_WRITE_TRANSACTION_KEY,
	    sizeof(uint32_t), NTFS_UNSUPPORTED);
	change(volume, test, NTFS_WRITE_REPLAY_OPEN,
	    offsetof(struct ntfs_disk_log_record, previous_lsn), 1, sizeof(uint64_t),
	    NTFS_UNSUPPORTED);
	change(volume, test, NTFS_WRITE_REPLAY_OPEN, offsetof(struct ntfs_disk_log_record, lsn),
	    test->values[10] + 1, sizeof(uint64_t), NTFS_CORRUPT);
	change(volume, test, NTFS_WRITE_REPLAY_OPEN,
	    snapshot + offsetof(struct ntfs_disk_log_open_attribute, reference), test->values[0],
	    sizeof(uint64_t), NTFS_UNSUPPORTED);
	change(volume, test, NTFS_WRITE_REPLAY_OPEN,
	    snapshot + offsetof(struct ntfs_disk_log_open_attribute, open_lsn),
	    restart.current_lsn + 1, sizeof(uint64_t), NTFS_UNSUPPORTED);
	change(volume, test, NTFS_WRITE_REPLAY_SNAPSHOT,
	    offsetof(struct ntfs_disk_log_record, transaction), NTFS_WRITE_TRANSACTION_KEY + 1,
	    sizeof(uint32_t), NTFS_UNSUPPORTED);
	change(volume, test, NTFS_WRITE_REPLAY_SNAPSHOT,
	    offsetof(struct ntfs_disk_log_record, previous_lsn), test->values[10], sizeof(uint64_t),
	    NTFS_UNSUPPORTED);
	change(volume, test, NTFS_WRITE_REPLAY_SNAPSHOT,
	    update + offsetof(struct ntfs_disk_log_update, redo_operation),
	    NTFS_LOG_OP_UPDATE_RESIDENT_VALUE, sizeof(uint16_t), NTFS_UNSUPPORTED);
	change(volume, test, NTFS_WRITE_REPLAY_SNAPSHOT,
	    update + offsetof(struct ntfs_disk_log_update, target_vcn), test->values[2] + 1,
	    sizeof(uint64_t), NTFS_CORRUPT);
	change(volume, test, NTFS_WRITE_REPLAY_SNAPSHOT,
	    update + sizeof(struct ntfs_disk_log_update), test->values[3] + 1, sizeof(uint64_t),
	    NTFS_CORRUPT);
	change(volume, test, NTFS_WRITE_REPLAY_SNAPSHOT,
	    update + offsetof(struct ntfs_disk_log_update, cluster_index), test->values[5] + 1,
	    sizeof(uint16_t), NTFS_CORRUPT);
	change(volume, test, NTFS_WRITE_REPLAY_SNAPSHOT,
	    snapshot + offsetof(struct ntfs_disk_record, sequence), 0, sizeof(uint16_t),
	    NTFS_UNSUPPORTED);
	change(volume, test, NTFS_WRITE_REPLAY_SNAPSHOT,
	    snapshot + offsetof(struct ntfs_disk_record, base_reference), test->values[0],
	    sizeof(uint64_t), NTFS_UNSUPPORTED);
	change(volume, test, NTFS_WRITE_REPLAY_UPDATE,
	    offsetof(struct ntfs_disk_log_record, previous_lsn), test->values[10], sizeof(uint64_t),
	    NTFS_UNSUPPORTED);
	change(volume, test, NTFS_WRITE_REPLAY_UPDATE,
	    offsetof(struct ntfs_disk_log_record, undo_next_lsn), 0, sizeof(uint64_t),
	    NTFS_UNSUPPORTED);
	change(volume, test, NTFS_WRITE_REPLAY_UPDATE,
	    update + offsetof(struct ntfs_disk_log_update, record_offset), test->values[6] + 1,
	    sizeof(uint16_t), NTFS_CORRUPT);
	change(volume, test, NTFS_WRITE_REPLAY_UPDATE, undo, 1, sizeof(uint64_t), NTFS_CORRUPT);
	change(
	    volume, test, NTFS_WRITE_REPLAY_UPDATE, redo, UINT64_MAX, sizeof(uint64_t), NTFS_STALE);
	change(volume, test, NTFS_WRITE_REPLAY_UPDATE, redo + sizeof(uint64_t), 0, sizeof(uint64_t),
	    NTFS_STALE);
	change(volume, test, NTFS_WRITE_REPLAY_UPDATE,
	    redo + offsetof(struct ntfs_disk_standard, accessed) -
		offsetof(struct ntfs_disk_standard, modified),
	    UINT64_MAX, sizeof(uint64_t), NTFS_CORRUPT);
	change(volume, test, NTFS_WRITE_REPLAY_COMMIT,
	    offsetof(struct ntfs_disk_log_record, undo_next_lsn), test->values[12],
	    sizeof(uint64_t), NTFS_UNSUPPORTED);
	change(volume, test, NTFS_WRITE_REPLAY_COMMIT,
	    update + offsetof(struct ntfs_disk_log_update, redo_operation),
	    NTFS_LOG_OP_UPDATE_RESIDENT_VALUE, sizeof(uint16_t), NTFS_UNSUPPORTED);
	change(volume, test, NTFS_WRITE_REPLAY_COMMIT,
	    offsetof(struct ntfs_disk_log_record, transaction), NTFS_WRITE_TRANSACTION_KEY + 1,
	    sizeof(uint32_t), NTFS_UNSUPPORTED);
	volume->info.major_version++;
	refused(volume, test, NTFS_UNSUPPORTED);
	volume->info = info;
	test->input.restart.flags = UINT16_MAX;
	refused(volume, test, NTFS_UNSUPPORTED);
	test->input.restart = restart;
	assert(
	    ntfs_write_replay_prepare(volume, &test->input, &test->work, &test->plan) == NTFS_OK);
	puts("PASS: 25 identity, mapping, before/after value, transaction and geometry refusals");
}

static void
vectors(const char *directory)
{
	struct replay_case *test = calloc(1, sizeof(*test));
	struct fuzz_device device = {0};
	struct ntfs_volume *volume;
	struct ntfs_node *node = NULL;
	uint8_t *data, *original, *protected, *check = malloc(NTFS_WRITE_RECORD_BYTES);
	uint64_t home;
	size_t bytes, protected_bytes, index;
	bool committed;

	assert(test != NULL && check != NULL);
	initialize(directory, test);
	data = load(directory, "source.img", &bytes);
	original = malloc(bytes);
	assert(original != NULL);
	device.data = data;
	device.size = bytes;
	home = test->values[4] + test->values[5] * NTFS_WRITE_SECTOR_BYTES;
	assert(ntfs_bounds(home, NTFS_WRITE_RECORD_BYTES, bytes));
	protected = load(directory, "protected.expected", &protected_bytes);
	assert(protected_bytes == NTFS_WRITE_RECORD_BYTES);
	for (index = 0; index < 2; index++) {
		if (index != 0) {
			memcpy(data + home, protected, NTFS_WRITE_SECTOR_BYTES);
			memcpy(check, data + home, NTFS_WRITE_RECORD_BYTES);
			assert(
			    ntfs_record_validate(check, NTFS_WRITE_RECORD_BYTES) == NTFS_CORRUPT);
		}
		memcpy(original, data, bytes);
		volume = mount(&device);
		if (index != 0) {
			assert(ntfs_node_open(volume, test->values[0], &node) == NTFS_CORRUPT &&
			    node == NULL);
		}
		for (committed = false;; committed = true) {
			commit_input(test, committed);
			assert(ntfs_write_replay_prepare(
				   volume, &test->input, &test->work, &test->plan) == NTFS_OK);
			oracle(directory, test, committed);
			assert(volume->children == 0);
			if (committed) {
				break;
			}
		}
		if (index == 0) {
			refusals(volume, test);
		}
		assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
		assert(memcmp(data, original, bytes) == 0);
	}
	puts("PASS: winner/loser complete independent FILE/protection/address goldens, including "
	     "torn home");
	free(protected);
	free(check);
	free(original);
	free(data);
	destroy(test);
}

static void
faults(const char *directory)
{
	struct replay_case *test = calloc(1, sizeof(*test));
	struct fuzz_device device = {0};
	struct ntfs_volume *volume;
	uint8_t *data, *original;
	size_t bytes, reads, allocations, position;
	unsigned mode;

	assert(test != NULL);
	initialize(directory, test);
	data = load(directory, "source.img", &bytes);
	original = malloc(bytes);
	assert(original != NULL);
	memcpy(original, data, bytes);
	device.data = data;
	device.size = bytes;
	volume = mount(&device);
	assert(
	    ntfs_write_replay_prepare(volume, &test->input, &test->work, &test->plan) == NTFS_OK);
	reads = device.reads;
	allocations = device.allocations;
	assert(reads != 0 && allocations != 0);
	assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
	for (mode = 0; mode < 3; mode++) {
		full_failed_read = mode == 2;
		for (position = 1; position <= (mode == 0 ? allocations : reads); position++) {
			volume = mount(&device);
			device.fail_allocation = mode == 0 ? position : 0;
			device.fail_read = mode == 0 ? 0 : position;
			refused(volume, test, mode == 0 ? NTFS_NO_MEMORY : NTFS_IO);
			device.fail_allocation = 0;
			device.fail_read = 0;
			device.reads = 0;
			assert(ntfs_write_replay_prepare(
				   volume, &test->input, &test->work, &test->plan) == NTFS_OK);
			oracle(directory, test, true);
			assert(ntfs_unmount(volume) == NTFS_OK && device.memory == 0);
		}
	}
	assert(memcmp(data, original, bytes) == 0);
	printf(
	    "PASS: %zu required allocation and %zu partial/full read faults with cleanup/retry\n",
	    allocations, reads);
	free(original);
	free(data);
	destroy(test);
}

int
main(int argc, char **argv)
{
	assert(argc == 2);
	vectors(argv[1]);
	faults(argv[1]);
	return 0;
}
