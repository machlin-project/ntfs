/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/logfile.h>
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_FILE_BYTES = 1024 * 1024,
	TEST_PAGE_BYTES = 4096,
	TEST_PAGE_DATA_OFFSET = 64,
	TEST_RECORD_BYTES = 48,
	TEST_CLIENT_BYTES = 160,
	TEST_UPDATE_BYTES = 32,
	TEST_LCN_BYTES = sizeof(uint64_t),
	TEST_CIRCULAR_OFFSET = 16384,
	TEST_RECORD_FILE_OFFSET = 16448,
	TEST_SEQUENCE_BITS = 46,
	TEST_OFFSET_BITS = 18,
	TEST_LSN = 526344,
	TEST_LSN_SEQUENCE = 2,
	TEST_ALIGNMENT = 8,
	TEST_GUARD_BYTES = 32,
	TEST_GUARD_VALUE = 0xa5,
	TEST_PATH_BYTES = 1024,
	TEST_NAME_BYTES = 128,
	TEST_KIND_BYTES = 16,
	TEST_RESULT_BYTES = 32,
	TEST_CLIENTS_PER_LARGE_PAGE = 407
};

union test_output {
	struct ntfs_logfile_restart restart;
	struct ntfs_logfile_page page;
	struct ntfs_logfile_record record;
	struct ntfs_logfile_update update;
	struct ntfs_logfile_client client;
};

static uint8_t input[NTFS_LOGFILE_MAX_RECORD_BYTES], saved[NTFS_LOGFILE_MAX_RECORD_BYTES];
static uint8_t scratch[NTFS_LOGFILE_MAX_PAGE_BYTES + 2 * TEST_GUARD_BYTES];
static uint8_t restored[NTFS_LOGFILE_MAX_PAGE_BYTES];
static uint8_t configuration_bytes[NTFS_LOGFILE_MAX_PAGE_BYTES];
static uint8_t configuration_scratch[NTFS_LOGFILE_MAX_PAGE_BYTES];

static size_t
load(const char *directory, const char *name, void *bytes, size_t capacity)
{
	char path[TEST_PATH_BYTES];
	FILE *file;
	long length;
	int count;

	count = snprintf(path, sizeof(path), "%s/%s", directory, name);
	assert(count > 0 && (size_t)count < sizeof(path));
	file = fopen(path, "rb");
	assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
	length = ftell(file);
	assert(length > 0 && (size_t)length <= capacity);
	assert(fseek(file, 0, SEEK_SET) == 0);
	assert(fread(bytes, 1, (size_t)length, file) == (size_t)length);
	assert(fclose(file) == 0);
	return (size_t)length;
}

static enum ntfs_result
expected(const char *name)
{
	if (strcmp(name, "success") == 0) {
		return NTFS_OK;
	}
	if (strcmp(name, "corrupt") == 0) {
		return NTFS_CORRUPT;
	}
	if (strcmp(name, "unsupported") == 0) {
		return NTFS_UNSUPPORTED;
	}
	assert(strcmp(name, "range") == 0);
	return NTFS_RANGE;
}

static void
guards(size_t size)
{
	size_t i;

	for (i = 0; i < TEST_GUARD_BYTES; i++) {
		assert(scratch[i] == TEST_GUARD_VALUE);
	}
	for (i = TEST_GUARD_BYTES + size; i < sizeof(scratch); i++) {
		assert(scratch[i] == TEST_GUARD_VALUE);
	}
}

static struct ntfs_logfile_restart
configuration(const char *directory, const char *name, uint64_t file_bytes)
{
	struct ntfs_logfile_restart info;
	size_t size;

	size = load(directory, name, configuration_bytes, sizeof(configuration_bytes));
	assert(ntfs_logfile_restart_decode(configuration_bytes, size, file_bytes,
		   configuration_scratch, sizeof(configuration_scratch), &info) == NTFS_OK);
	return info;
}

static enum ntfs_result
decode(const char *kind, size_t size, uint64_t parameter, const struct ntfs_logfile_restart *config,
    union test_output *out, size_t *output_size)
{
	if (strcmp(kind, "restart") == 0) {
		*output_size = sizeof(out->restart);
		return ntfs_logfile_restart_decode(
		    input, size, parameter, scratch + TEST_GUARD_BYTES, size, &out->restart);
	}
	if (strcmp(kind, "page") == 0) {
		*output_size = sizeof(out->page);
		return ntfs_logfile_page_decode(
		    input, size, config, scratch + TEST_GUARD_BYTES, size, &out->page);
	}
	if (strcmp(kind, "record") == 0) {
		*output_size = sizeof(out->record);
		return ntfs_logfile_record_decode(input, size, (uint16_t)parameter, &out->record);
	}
	if (strcmp(kind, "update") == 0) {
		*output_size = sizeof(out->update);
		return ntfs_logfile_update_decode(input, size, &out->update);
	}
	assert(strcmp(kind, "client") == 0);
	*output_size = sizeof(out->client);
	return ntfs_logfile_client_decode(input, size, &out->client);
}

static void
cases(const char *directory)
{
	char path[TEST_PATH_BYTES], name[TEST_NAME_BYTES], kind[TEST_KIND_BYTES];
	char verdict[TEST_RESULT_BYTES], config_name[TEST_NAME_BYTES],
	    restored_name[2 * TEST_NAME_BYTES];
	struct ntfs_logfile_restart config = {0};
	union test_output first, second, zero = {0};
	FILE *manifest;
	uint64_t parameter;
	size_t size, output_size, repeated_size, restored_size, count = 0;
	enum ntfs_result result, repeat;
	int fields, printed;
	bool is_page;

	printed = snprintf(path, sizeof(path), "%s/cases.tsv", directory);
	assert(printed > 0 && (size_t)printed < sizeof(path));
	manifest = fopen(path, "r");
	assert(manifest != NULL);
	while ((fields = fscanf(manifest, "%127s %15s %31s %" SCNu64 " %127s", name, kind, verdict,
		    &parameter, config_name)) != EOF) {
		assert(fields == 5);
		size = load(directory, name, input, sizeof(input));
		memcpy(saved, input, size);
		memset(scratch, TEST_GUARD_VALUE, sizeof(scratch));
		memset(&first, TEST_GUARD_VALUE, sizeof(first));
		memset(&second, TEST_GUARD_VALUE, sizeof(second));
		is_page = strcmp(kind, "restart") == 0 || strcmp(kind, "page") == 0;
		if (strcmp(kind, "page") == 0) {
			config = configuration(directory, config_name, parameter);
		}
		result = decode(kind, size, parameter, &config, &first, &output_size);
		if (result != expected(verdict)) {
			fprintf(stderr, "%s: expected %s, got %s\n", name, verdict,
			    ntfs_result_string(result));
		}
		assert(result == expected(verdict));
		assert(memcmp(input, saved, size) == 0);
		guards(is_page ? size : 0);
		if (result == NTFS_OK && is_page) {
			printed =
			    snprintf(restored_name, sizeof(restored_name), "%s.restored", name);
			assert(printed > 0 && (size_t)printed < sizeof(restored_name));
			restored_size = load(directory, restored_name, restored, sizeof(restored));
			assert(restored_size == size &&
			    memcmp(scratch + TEST_GUARD_BYTES, restored, size) == 0);
		}
		memset(scratch, TEST_GUARD_VALUE, sizeof(scratch));
		repeat = decode(kind, size, parameter, &config, &second, &repeated_size);
		assert(result == repeat && repeated_size == output_size);
		assert(
		    memcmp(&first, &second, output_size) == 0 && memcmp(input, saved, size) == 0);
		guards(is_page ? size : 0);
		if (result != NTFS_OK) {
			assert(memcmp(&first, &zero, output_size) == 0);
		} else if (strcmp(name, "maximum-clients.restart") == 0) {
			assert(first.restart.client_count == TEST_CLIENTS_PER_LARGE_PAGE);
		}
		count++;
	}
	assert(fclose(manifest) == 0 && count != 0);
	printf("PASS: %zu independent LFS/client/page/record/update verdicts, exact restored bytes "
	       "and guards\n",
	    count);
}

static void
lsns(const char *directory)
{
	struct ntfs_logfile_restart config, bad;
	struct ntfs_logfile_lsn info, zero = {0};
	uint64_t offsets[] = {0, TEST_PAGE_DATA_OFFSET, TEST_CIRCULAR_OFFSET, TEST_FILE_BYTES,
	    TEST_CIRCULAR_OFFSET + TEST_PAGE_BYTES - TEST_RECORD_BYTES + TEST_ALIGNMENT};
	size_t i;
	uint64_t lsn;

	config = configuration(directory, "base.restart", TEST_FILE_BYTES);
	assert(config.sequence_bits == TEST_SEQUENCE_BITS);
	assert(ntfs_logfile_lsn_decode(&config, TEST_LSN, &info) == NTFS_OK);
	assert(info.sequence == TEST_LSN_SEQUENCE && info.file_offset == TEST_RECORD_FILE_OFFSET &&
	    info.page_offset == TEST_CIRCULAR_OFFSET &&
	    info.record_offset == TEST_PAGE_DATA_OFFSET);
	assert(ntfs_logfile_lsn_decode(&config, 0, &info) == NTFS_NOT_FOUND);
	assert(memcmp(&info, &zero, sizeof(info)) == 0);
	for (i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
		lsn = ((uint64_t)TEST_LSN_SEQUENCE << TEST_OFFSET_BITS) |
		    (offsets[i] / sizeof(uint64_t));
		assert(ntfs_logfile_lsn_decode(&config, lsn, &info) == NTFS_CORRUPT);
		assert(memcmp(&info, &zero, sizeof(info)) == 0);
	}
	bad = config;
	bad.sequence_bits = 0;
	assert(ntfs_logfile_lsn_decode(&bad, TEST_LSN, &info) == NTFS_INVALID);
	bad = config;
	bad.sequence_bits = UINT32_MAX;
	assert(ntfs_logfile_lsn_decode(&bad, TEST_LSN, &info) == NTFS_INVALID);
	bad = config;
	bad.circular_offset = UINT64_MAX;
	assert(ntfs_logfile_lsn_decode(&bad, TEST_LSN, &info) == NTFS_INVALID);
	bad = config;
	bad.log_page_bytes = 0;
	assert(ntfs_logfile_lsn_decode(&bad, TEST_LSN, &info) == NTFS_INVALID);
	assert(ntfs_logfile_lsn_decode(NULL, TEST_LSN, &info) == NTFS_INVALID);
	assert(ntfs_logfile_lsn_decode(&config, TEST_LSN, NULL) == NTFS_INVALID);
	puts("PASS: independent LSN fields, circular/page/header bounds and hostile caller "
	     "geometry");
}

static void
arguments(const char *directory)
{
	struct ntfs_logfile_restart config, r, zero_restart = {0};
	struct ntfs_logfile_page p, zero_page = {0};
	struct ntfs_logfile_record record;
	struct ntfs_logfile_update update;
	struct ntfs_logfile_client client;
	size_t size, i;

	size = load(directory, "base.restart", input, sizeof(input));
	memcpy(saved, input, size);
	for (i = 0; i < size; i++) {
		assert(ntfs_logfile_restart_decode(input, i, TEST_FILE_BYTES,
			   scratch + TEST_GUARD_BYTES, NTFS_LOGFILE_MAX_PAGE_BYTES,
			   &r) == NTFS_CORRUPT);
		assert(memcmp(&r, &zero_restart, sizeof(r)) == 0);
	}
	memset(scratch, TEST_GUARD_VALUE, sizeof(scratch));
	assert(ntfs_logfile_restart_decode(input, size, TEST_FILE_BYTES, scratch + TEST_GUARD_BYTES,
		   size - 1, &r) == NTFS_RANGE);
	guards(0);
	assert(ntfs_logfile_restart_decode(NULL, size, TEST_FILE_BYTES, scratch, size, &r) ==
	    NTFS_INVALID);
	assert(ntfs_logfile_restart_decode(input, size, TEST_FILE_BYTES, NULL, size, &r) ==
	    NTFS_INVALID);
	assert(ntfs_logfile_restart_decode(input, size, TEST_FILE_BYTES, scratch, size, NULL) ==
	    NTFS_INVALID);
	assert(memcmp(input, saved, size) == 0);
	config = configuration(directory, "base.restart", TEST_FILE_BYTES);
	size = load(directory, "base.page", input, sizeof(input));
	memset(scratch, TEST_GUARD_VALUE, sizeof(scratch));
	assert(ntfs_logfile_page_decode(
		   input, size, &config, scratch + TEST_GUARD_BYTES, size - 1, &p) == NTFS_RANGE);
	guards(0);
	assert(memcmp(&p, &zero_page, sizeof(p)) == 0);
	assert(ntfs_logfile_page_decode(input, size, NULL, scratch, size, &p) == NTFS_INVALID);
	assert(ntfs_logfile_page_decode(NULL, size, &config, scratch, size, &p) == NTFS_INVALID);
	assert(ntfs_logfile_page_decode(input, size, &config, NULL, size, &p) == NTFS_INVALID);
	assert(ntfs_logfile_page_decode(input, size, &config, scratch, size, NULL) == NTFS_INVALID);
	assert(ntfs_logfile_record_decode(NULL, 0, TEST_RECORD_BYTES, &record) == NTFS_INVALID);
	assert(ntfs_logfile_record_decode(input, size, TEST_RECORD_BYTES - 1, &record) ==
	    NTFS_INVALID);
	assert(ntfs_logfile_record_decode(input, size, TEST_RECORD_BYTES, NULL) == NTFS_INVALID);
	assert(ntfs_logfile_record_decode(input, NTFS_LOGFILE_MAX_RECORD_BYTES + 1u,
		   TEST_RECORD_BYTES, &record) == NTFS_RANGE);
	assert(ntfs_logfile_update_decode(NULL, 0, &update) == NTFS_INVALID);
	assert(ntfs_logfile_update_decode(input, 0, &update) == NTFS_CORRUPT);
	assert(ntfs_logfile_update_decode(input, size, NULL) == NTFS_INVALID);
	assert(ntfs_logfile_update_decode(input, NTFS_LOGFILE_MAX_RECORD_BYTES + 1u, &update) ==
	    NTFS_RANGE);
	assert(ntfs_logfile_client_decode(NULL, 0, &client) == NTFS_INVALID);
	assert(ntfs_logfile_client_decode(input, size, NULL) == NTFS_INVALID);
	puts("PASS: page truncations, scratch equality/exhaustion, argument/output policies and no "
	     "input mutation");
}

int
main(int argc, char **argv)
{
	assert(argc == 2);
	cases(argv[1]);
	lsns(argv[1]);
	arguments(argv[1]);
	return 0;
}
