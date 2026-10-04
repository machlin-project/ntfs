/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/checkpoint.h>
#include "fuzz_device.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_PATH_BYTES = 1024,
	TEST_NAME_BYTES = 128,
	TEST_SCAN_BYTES = 128,
	TEST_COLUMNS = 6,
	TEST_PREFIX_VALUES = 6,
	TEST_TABLE_VALUES = 6,
	TEST_VALUES = TEST_PREFIX_VALUES + NTFS_LOGFILE_CHECKPOINT_KINDS * TEST_TABLE_VALUES,
	TEST_INPUT_BYTES = 4 * 1024 * 1024,
	TEST_GUARD_BYTES = 32,
	TEST_GUARD_BYTE = 0xa5,
	TEST_UNALIGNED_BYTES = 1
};

struct guarded_snapshot {
	uint8_t before[TEST_GUARD_BYTES];
	struct ntfs_logfile_checkpoint_snapshot value;
	uint8_t after[TEST_GUARD_BYTES];
};

static void
guard(const uint8_t *bytes, size_t size)
{
	size_t index;

	for (index = 0; index < size; index++) {
		assert(bytes[index] == TEST_GUARD_BYTE);
	}
}

static uint8_t *
read_file(const char *directory, const char *name, const char *suffix, size_t *size)
{
	char path[TEST_PATH_BYTES];
	FILE *file;
	uint8_t *bytes;
	long length;
	int written;

	written = snprintf(path, sizeof(path), "%s/%s%s", directory, name, suffix);
	assert(written > 0 && (size_t)written < sizeof(path));
	file = fopen(path, "rb");
	assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
	length = ftell(file);
	assert(length >= 0 && length <= TEST_INPUT_BYTES && fseek(file, 0, SEEK_SET) == 0);
	*size = (size_t)length;
	bytes = malloc(*size == 0 ? 1 : *size);
	assert(bytes != NULL && fread(bytes, 1, *size, file) == *size && fclose(file) == 0);
	return bytes;
}

static void
values(const struct ntfs_logfile_checkpoint_snapshot *snapshot, uint64_t *out)
{
	const struct ntfs_logfile_checkpoint_table *table;
	const uint64_t prefix[] = {snapshot->present_mask, snapshot->client_major,
	    snapshot->client_minor, snapshot->checkpoint_lsn, snapshot->named_attributes,
	    snapshot->dirty_pages};
	size_t index, kind;

	_Static_assert(sizeof(prefix) == TEST_PREFIX_VALUES * sizeof(*prefix), "snapshot oracle");
	memcpy(out, prefix, sizeof(prefix));
	index = TEST_PREFIX_VALUES;
	for (kind = 0; kind < NTFS_LOGFILE_CHECKPOINT_KINDS; kind++) {
		table = &snapshot->tables[kind];
		out[index++] = table->kind;
		out[index++] = table->table_lsn;
		out[index++] = table->body.offset;
		out[index++] = table->body.length;
		out[index++] = table->table.allocated_count;
		out[index++] = table->names.entry_count;
	}
	assert(index == TEST_VALUES);
}

int
main(int argc, char **argv)
{
	char path[TEST_PATH_BYTES], name[TEST_NAME_BYTES], source_name[TEST_NAME_BYTES];
	char suffix[TEST_NAME_BYTES], scan[TEST_SCAN_BYTES];
	struct guarded_snapshot output, repeated;
	struct ntfs_logfile_checkpoint_snapshot zero = {0};
	struct ntfs_logfile_checkpoint_dump dumps[NTFS_LOGFILE_CHECKPOINT_KINDS];
	struct ntfs_logfile *source;
	struct ntfs_environment environment;
	struct fuzz_device device;
	FILE *cases, *expected_file;
	uint8_t *journal, *unchanged, *checkpoint, *guarded_checkpoint;
	uint8_t *raw[NTFS_LOGFILE_CHECKPOINT_KINDS], *guarded[NTFS_LOGFILE_CHECKPOINT_KINDS];
	uint8_t *workspace, *workspace_copy, *expected_workspace;
	uint64_t expected[TEST_VALUES], observed[TEST_VALUES];
	size_t sizes[NTFS_LOGFILE_CHECKPOINT_KINDS], source_bytes, checkpoint_bytes;
	size_t capacity, workspace_prefix, expected_workspace_bytes, workspace_size;
	size_t reads, allocations, memory, shift, prefix, index, kind, count = 0;
	unsigned code, null_workspace;
	int written;
	enum ntfs_result result;

	assert(argc == 2);
	written = snprintf(path, sizeof(path), "%s/cases.tsv", argv[1]);
	assert(written > 0 && (size_t)written < sizeof(path));
	written = snprintf(scan, sizeof(scan), "%%%zus %%%zus %%u %%zu %%u %%zu", sizeof(name) - 1,
	    sizeof(source_name) - 1);
	assert(written > 0 && (size_t)written < sizeof(scan));
	cases = fopen(path, "r");
	assert(cases != NULL);
	workspace_size = NTFS_LOGFILE_CHECKPOINT_NAME_WORKSPACE_BYTES + 2 * TEST_GUARD_BYTES +
	    TEST_UNALIGNED_BYTES;
	workspace = malloc(workspace_size);
	workspace_copy = malloc(workspace_size);
	assert(workspace != NULL && workspace_copy != NULL);
	while (fscanf(cases, scan, name, source_name, &code, &capacity, &null_workspace,
		   &workspace_prefix) == TEST_COLUMNS) {
		assert(capacity <= NTFS_LOGFILE_CHECKPOINT_NAME_WORKSPACE_BYTES &&
		    workspace_prefix <= NTFS_LOGFILE_CHECKPOINT_NAME_WORKSPACE_BYTES);
		journal = read_file(argv[1], source_name, "", &source_bytes);
		unchanged = malloc(source_bytes);
		assert(unchanged != NULL);
		memcpy(unchanged, journal, source_bytes);
		device = (struct fuzz_device){.data = journal, .size = source_bytes};
		environment = fuzz_environment(&device);
		assert(ntfs_logfile_open(&environment, NULL, NULL, &source) == NTFS_OK);
		checkpoint = read_file(argv[1], name, ".checkpoint", &checkpoint_bytes);
		guarded_checkpoint =
		    malloc(checkpoint_bytes + 2 * TEST_GUARD_BYTES + TEST_UNALIGNED_BYTES);
		assert(guarded_checkpoint != NULL);
		for (kind = 0; kind < NTFS_LOGFILE_CHECKPOINT_KINDS; kind++) {
			written = snprintf(suffix, sizeof(suffix), ".dump-%zu", kind);
			assert(written > 0 && (size_t)written < sizeof(suffix));
			raw[kind] = read_file(argv[1], name, suffix, &sizes[kind]);
			guarded[kind] =
			    malloc(sizes[kind] + 2 * TEST_GUARD_BYTES + TEST_UNALIGNED_BYTES);
			assert(guarded[kind] != NULL);
		}
		expected_workspace =
		    read_file(argv[1], name, ".workspace", &expected_workspace_bytes);
		assert(expected_workspace_bytes == workspace_prefix);
		written = snprintf(path, sizeof(path), "%s/%s.expected", argv[1], name);
		assert(written > 0 && (size_t)written < sizeof(path));
		expected_file = fopen(path, "r");
		assert(expected_file != NULL);
		for (index = 0; index < TEST_VALUES; index++) {
			assert(fscanf(expected_file, "%" SCNu64, &expected[index]) == 1);
		}
		assert(fscanf(expected_file, "%" SCNu64, &observed[0]) == EOF &&
		    fclose(expected_file) == 0);
		reads = device.reads;
		allocations = device.allocations;
		memory = device.memory;
		device.fail_read = reads + 1;
		device.fail_allocation = allocations + 1;
		for (shift = 0; shift <= TEST_UNALIGNED_BYTES; shift++) {
			prefix = TEST_GUARD_BYTES + shift;
			memset(guarded_checkpoint, TEST_GUARD_BYTE,
			    checkpoint_bytes + 2 * TEST_GUARD_BYTES + TEST_UNALIGNED_BYTES);
			memcpy(guarded_checkpoint + prefix, checkpoint, checkpoint_bytes);
			for (kind = 0; kind < NTFS_LOGFILE_CHECKPOINT_KINDS; kind++) {
				memset(guarded[kind], TEST_GUARD_BYTE,
				    sizes[kind] + 2 * TEST_GUARD_BYTES + TEST_UNALIGNED_BYTES);
				memcpy(guarded[kind] + prefix, raw[kind], sizes[kind]);
				dumps[kind] = (struct ntfs_logfile_checkpoint_dump){
				    .data = guarded[kind] + prefix, .bytes = sizes[kind]};
			}
			memset(workspace, TEST_GUARD_BYTE, workspace_size);
			memset(&output, TEST_GUARD_BYTE, sizeof(output));
			memset(&repeated, TEST_GUARD_BYTE, sizeof(repeated));
			result = ntfs_logfile_checkpoint_decode(source, guarded_checkpoint + prefix,
			    checkpoint_bytes, dumps, null_workspace ? NULL : workspace + prefix,
			    capacity, &output.value);
			memcpy(workspace_copy, workspace, workspace_size);
			assert(
			    ntfs_logfile_checkpoint_decode(source, guarded_checkpoint + prefix,
				checkpoint_bytes, dumps, null_workspace ? NULL : workspace + prefix,
				capacity, &repeated.value) == result);
			values(&output.value, observed);
			if ((unsigned)result != code ||
			    memcmp(expected, observed, sizeof(expected)) != 0) {
				fprintf(stderr, "%s: expected %u, observed %u\n", name, code,
				    (unsigned)result);
			}
			assert((unsigned)result == code &&
			    memcmp(expected, observed, sizeof(expected)) == 0);
			assert(memcmp(&output.value, &repeated.value, sizeof(output.value)) == 0);
			assert(memcmp(workspace, workspace_copy, workspace_size) == 0);
			if (result == NTFS_OK) {
				assert(memcmp(workspace + prefix, expected_workspace,
					   workspace_prefix) == 0);
			} else {
				assert(memcmp(&output.value, &zero, sizeof(zero)) == 0);
			}
			guard(workspace, prefix);
			guard(workspace + prefix + workspace_prefix,
			    workspace_size - prefix - workspace_prefix);
			assert(
			    memcmp(guarded_checkpoint + prefix, checkpoint, checkpoint_bytes) == 0);
			guard(guarded_checkpoint, prefix);
			guard(guarded_checkpoint + prefix + checkpoint_bytes, TEST_GUARD_BYTES);
			for (kind = 0; kind < NTFS_LOGFILE_CHECKPOINT_KINDS; kind++) {
				assert(memcmp(guarded[kind] + prefix, raw[kind], sizes[kind]) == 0);
				guard(guarded[kind], prefix);
				guard(guarded[kind] + prefix + sizes[kind], TEST_GUARD_BYTES);
			}
			guard(output.before, sizeof(output.before));
			guard(output.after, sizeof(output.after));
			guard(repeated.before, sizeof(repeated.before));
			guard(repeated.after, sizeof(repeated.after));
			assert(device.reads == reads && device.allocations == allocations &&
			    device.memory == memory);
		}
		assert(ntfs_logfile_checkpoint_decode(NULL, checkpoint, checkpoint_bytes, dumps,
			   workspace, capacity, &output.value) == NTFS_INVALID);
		assert(memcmp(&output.value, &zero, sizeof(zero)) == 0);
		assert(ntfs_logfile_checkpoint_decode(source, checkpoint, checkpoint_bytes, NULL,
			   workspace, capacity, &output.value) == NTFS_INVALID);
		assert(memcmp(&output.value, &zero, sizeof(zero)) == 0);
		assert(ntfs_logfile_checkpoint_decode(source, NULL, 0, dumps, workspace, capacity,
			   &output.value) == NTFS_INVALID);
		assert(memcmp(&output.value, &zero, sizeof(zero)) == 0);
		assert(ntfs_logfile_checkpoint_decode(source, checkpoint, checkpoint_bytes, dumps,
			   workspace, capacity, NULL) == NTFS_INVALID);
		assert(device.reads == reads && device.allocations == allocations &&
		    device.memory == memory);
		ntfs_logfile_close(source);
		assert(device.memory == 0 && memcmp(journal, unchanged, source_bytes) == 0);
		for (kind = 0; kind < NTFS_LOGFILE_CHECKPOINT_KINDS; kind++) {
			free(guarded[kind]);
			free(raw[kind]);
		}
		free(expected_workspace);
		free(guarded_checkpoint);
		free(checkpoint);
		free(unchanged);
		free(journal);
		count++;
	}
	assert(feof(cases) && fclose(cases) == 0 && count != 0);
	free(workspace_copy);
	free(workspace);
	printf(
	    "PASS: %zu complete checkpoint membership graphs, physical OAT keys, duplicate names, "
	    "free targets, exact/short workspace, guarded immutable unaligned inputs and no "
	    "callbacks; "
	    "no current history/recovery qualification\n",
	    count);
	return 0;
}
