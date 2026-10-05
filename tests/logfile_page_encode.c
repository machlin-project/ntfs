/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include <ntfs/logfile_encode.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_PATH_BYTES = 4096,
	TEST_NAME_BYTES = 128,
	TEST_FORMAT_BYTES = 64,
	TEST_COLUMNS = 2,
	TEST_GUARD_BYTES = 16,
	TEST_EXTRA_BYTES = 32,
	TEST_VARIANTS = 2,
	TEST_GUARD = 0xa5,
	TEST_PAGE_BYTES = 4096,
	TEST_DATA_OFFSET = 64,
	TEST_LOGFILE_BYTES = 8 * 1024 * 1024,
};

enum {
	PAGE_MODERN_VERSION,
	PAGE_UNKNOWN_VERSION,
	PAGE_UNKNOWN_MINOR,
	PAGE_UNKNOWN_FLAGS,
	PAGE_ZERO_SIZE,
	PAGE_SMALL_SIZE,
	PAGE_NON_POWER_SIZE,
	PAGE_POLICY_SIZE,
	PAGE_USA_OVERLAP,
	PAGE_UNALIGNED_DATA,
	PAGE_NO_HEADER_ROOM,
	PAGE_SHORT_DATA,
	PAGE_LONG_DATA,
	PAGE_OVERFLOW_DATA,
	PAGE_NULL_DATA,
	PAGE_ZERO_POSITION,
	PAGE_ZERO_COUNT,
	PAGE_EXCESS_POSITION,
	PAGE_NEXT_HEADER,
	PAGE_NEXT_EXCESS,
	PAGE_NEXT_UNALIGNED,
	PAGE_ERROR_CASES,
};

static uint8_t *
read_bytes(const char *directory, const char *name, const char *suffix, size_t *size)
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
	assert(length > 0 && fseek(file, 0, SEEK_SET) == 0);
	*size = (size_t)length;
	bytes = malloc(*size);
	assert(bytes != NULL && fread(bytes, 1, *size, file) == *size);
	assert(fclose(file) == 0);
	return bytes;
}

static void
unchanged(const uint8_t *bytes, size_t size)
{
	size_t index;

	for (index = 0; index < size; index++) {
		assert(bytes[index] == TEST_GUARD);
	}
}

static enum ntfs_result
encode_page(const struct ntfs_logfile_page_input *input, uint32_t file_offset, void *work,
    size_t work_bytes, void *output, size_t capacity)
{
	struct ntfs_logfile_fast_page_input fast;

	if (input->major == NTFS_LFS_MAJOR_FAST) {
		fast = (struct ntfs_logfile_fast_page_input){*input, file_offset};
		return ntfs_logfile_fast_page_encode(&fast, work, work_bytes, output, capacity);
	}
	return ntfs_logfile_page_encode(input, work, work_bytes, output, capacity);
}

static void
check_case(const char *directory, const char *name, uint16_t data_offset)
{
	struct ntfs_logfile_page_input input = {0}, copy;
	struct ntfs_logfile_restart restart;
	struct ntfs_logfile_page view;
	const struct ntfs_disk_log_page *header;
	const struct ntfs_disk_log_fast_page *fast_header;
	uint8_t *original, *golden, *config, *source, *work, *destination, *scratch, *output;
	size_t bytes, expected_bytes, config_bytes, allocation, shift, variant, capacity;
	uint32_t file_offset;

	original = read_bytes(directory, name, ".input", &bytes);
	golden = read_bytes(directory, name, ".expected", &expected_bytes);
	config = read_bytes(directory, name, ".restart", &config_bytes);
	assert(bytes == expected_bytes && bytes <= NTFS_LOGFILE_MAX_PAGE_BYTES);
	allocation = bytes + 2 * TEST_GUARD_BYTES + TEST_EXTRA_BYTES + TEST_VARIANTS;
	source = malloc(allocation);
	work = malloc(allocation);
	destination = malloc(allocation);
	assert(source != NULL && work != NULL && destination != NULL);
	assert(ntfs_logfile_restart_decode(config, config_bytes, TEST_LOGFILE_BYTES,
		   work + TEST_GUARD_BYTES, config_bytes, &restart) == NTFS_OK);
	assert(restart.log_page_bytes == bytes && restart.page_data_offset == data_offset);
	for (shift = 0; shift < TEST_VARIANTS; shift++) {
		memset(source, TEST_GUARD, allocation);
		memcpy(source + TEST_GUARD_BYTES + shift, original, bytes);
		header = (const void *)(source + TEST_GUARD_BYTES + shift);
		fast_header = (const void *)header;
		file_offset =
		    restart.major == NTFS_LFS_MAJOR_FAST ? ntfs_u32(fast_header->file_offset) : 0;
		input.bytes = (uint32_t)bytes;
		input.major = restart.major;
		input.minor = restart.minor;
		input.data_offset = data_offset;
		input.prior_update_sequence = ntfs_u16((const uint8_t *)header + sizeof(*header));
		input.page.copy_value = ntfs_u64(header->copy_value);
		input.page.last_end_lsn = ntfs_u64(header->last_end_lsn);
		input.page.flags = ntfs_u32(header->flags);
		input.page.page_count = ntfs_u16(header->page_count);
		input.page.page_position = ntfs_u16(header->page_position);
		input.page.next_record_offset = ntfs_u16(header->next_record_offset);
		input.data = (struct ntfs_logfile_buffer){
		    (const uint8_t *)header + data_offset, bytes - data_offset};
		memcpy(&copy, &input, sizeof(copy));
		scratch = work + TEST_GUARD_BYTES + shift;
		output = destination + TEST_GUARD_BYTES + shift;
		for (variant = 0; variant < TEST_VARIANTS; variant++) {
			capacity = bytes + variant * TEST_EXTRA_BYTES;
			memset(work, TEST_GUARD, allocation);
			memset(destination, TEST_GUARD, allocation);
			assert(encode_page(&input, file_offset, scratch, capacity, output,
				   capacity) == NTFS_OK);
			assert(memcmp(output, golden, bytes) == 0);
			assert(memcmp(&input, &copy, sizeof(copy)) == 0);
			assert(memcmp(header, original, bytes) == 0);
			unchanged(work, TEST_GUARD_BYTES + shift);
			unchanged(scratch + bytes, allocation - TEST_GUARD_BYTES - shift - bytes);
			unchanged(destination, TEST_GUARD_BYTES + shift);
			unchanged(output + bytes, allocation - TEST_GUARD_BYTES - shift - bytes);
			assert(ntfs_logfile_page_decode(
				   output, bytes, &restart, scratch, capacity, &view) == NTFS_OK);
			assert(view.copy_value == input.page.copy_value &&
			    view.last_end_lsn == input.page.last_end_lsn &&
			    view.flags == input.page.flags &&
			    view.page_count == input.page.page_count &&
			    view.page_position == input.page.page_position &&
			    view.next_record_offset == input.page.next_record_offset);
			assert(
			    memcmp(scratch + data_offset, input.data.data, input.data.bytes) == 0);
			assert(encode_page(&input, file_offset, scratch, capacity, output,
				   capacity) == NTFS_OK);
			assert(memcmp(output, golden, bytes) == 0);
		}
		memset(work, TEST_GUARD, allocation);
		memset(destination, TEST_GUARD, allocation);
		assert(encode_page(&input, file_offset, scratch, bytes - 1, output, bytes) ==
		    NTFS_RANGE);
		assert(encode_page(&input, file_offset, scratch, bytes, output, bytes - 1) ==
		    NTFS_RANGE);
		unchanged(work, allocation);
		unchanged(destination, allocation);
		unchanged(source, TEST_GUARD_BYTES + shift);
		unchanged(
		    (const uint8_t *)header + bytes, allocation - TEST_GUARD_BYTES - shift - bytes);
	}
	free(destination);
	free(work);
	free(source);
	free(config);
	free(golden);
	free(original);
}

static void
check_errors(void)
{
	struct ntfs_logfile_page_input base = {0}, input, copy;
	const struct ntfs_disk_log_page *header;
	uint8_t *body, *work, *output;
	size_t index, allocation = 2 * TEST_PAGE_BYTES + TEST_EXTRA_BYTES;
	enum ntfs_result expected;

	body = malloc(TEST_PAGE_BYTES);
	work = malloc(allocation);
	output = malloc(allocation);
	assert(body != NULL && work != NULL && output != NULL);
	memset(body, TEST_GUARD, TEST_PAGE_BYTES);
	base.bytes = TEST_PAGE_BYTES;
	base.major = NTFS_LFS_MAJOR_LEGACY;
	base.minor = NTFS_LFS_MINOR_LEGACY;
	base.data_offset = TEST_DATA_OFFSET;
	base.page.page_count = base.page.page_position = 1;
	base.data = (struct ntfs_logfile_buffer){body, TEST_PAGE_BYTES - TEST_DATA_OFFSET};
	for (index = 0; index < PAGE_ERROR_CASES; index++) {
		input = base;
		expected = NTFS_INVALID;
		switch (index) {
		case PAGE_MODERN_VERSION:
			input.major = NTFS_LFS_MAJOR_FAST;
			input.minor = NTFS_LFS_MINOR_FAST;
			expected = NTFS_UNSUPPORTED;
			break;
		case PAGE_UNKNOWN_VERSION:
			input.major = 0;
			expected = NTFS_UNSUPPORTED;
			break;
		case PAGE_UNKNOWN_MINOR:
			input.minor++;
			expected = NTFS_UNSUPPORTED;
			break;
		case PAGE_UNKNOWN_FLAGS:
			input.page.flags = NTFS_LOGFILE_PAGE_CLIENT_RESTART << 1;
			expected = NTFS_UNSUPPORTED;
			break;
		case PAGE_ZERO_SIZE:
			input.bytes = 0;
			break;
		case PAGE_SMALL_SIZE:
			input.bytes = NTFS_MST_STRIDE - 1;
			break;
		case PAGE_NON_POWER_SIZE:
			input.bytes = NTFS_MST_STRIDE + NTFS_MST_STRIDE / 2;
			break;
		case PAGE_POLICY_SIZE:
			input.bytes = NTFS_LOGFILE_MAX_PAGE_BYTES + NTFS_MST_STRIDE;
			expected = NTFS_RANGE;
			break;
		case PAGE_USA_OVERLAP:
			input.data_offset = sizeof(struct ntfs_disk_log_page);
			break;
		case PAGE_UNALIGNED_DATA:
			input.data_offset++;
			break;
		case PAGE_NO_HEADER_ROOM:
			input.data_offset = TEST_PAGE_BYTES - NTFS_WIRE_ALIGNMENT;
			break;
		case PAGE_SHORT_DATA:
			input.data.bytes--;
			break;
		case PAGE_LONG_DATA:
			input.data.bytes++;
			break;
		case PAGE_OVERFLOW_DATA:
			input.data.bytes = SIZE_MAX;
			break;
		case PAGE_NULL_DATA:
			input.data.data = NULL;
			break;
		case PAGE_ZERO_POSITION:
			input.page.page_position = 0;
			break;
		case PAGE_ZERO_COUNT:
			input.page.page_count = 0;
			break;
		case PAGE_EXCESS_POSITION:
			input.page.page_position++;
			break;
		case PAGE_NEXT_HEADER:
			input.page.next_record_offset = TEST_DATA_OFFSET - NTFS_WIRE_ALIGNMENT;
			break;
		case PAGE_NEXT_EXCESS:
			input.page.next_record_offset = TEST_PAGE_BYTES + NTFS_WIRE_ALIGNMENT;
			break;
		case PAGE_NEXT_UNALIGNED:
			input.page.next_record_offset = TEST_DATA_OFFSET + 1;
			break;
		}
		memcpy(&copy, &input, sizeof(copy));
		memset(work, TEST_GUARD, allocation);
		memset(output, TEST_GUARD, allocation);
		assert(ntfs_logfile_page_encode(&input, work, allocation, output, allocation) ==
		    expected);
		assert(memcmp(&input, &copy, sizeof(copy)) == 0);
		unchanged(work, allocation);
		unchanged(output, allocation);
	}
	assert(
	    ntfs_logfile_page_encode(NULL, work, allocation, output, allocation) == NTFS_INVALID);
	assert(
	    ntfs_logfile_page_encode(&base, NULL, allocation, output, allocation) == NTFS_INVALID);
	assert(ntfs_logfile_page_encode(&base, work, allocation, NULL, allocation) == NTFS_INVALID);
	assert(ntfs_logfile_page_encode((const void *)(UINTPTR_MAX - sizeof(base) + 1), work,
		   allocation, output, allocation) == NTFS_INVALID);
	assert(ntfs_logfile_page_encode(&base, (void *)(UINTPTR_MAX - TEST_PAGE_BYTES + 1),
		   allocation, output, allocation) == NTFS_INVALID);
	assert(ntfs_logfile_page_encode(&base, work, allocation,
		   (void *)(UINTPTR_MAX - TEST_PAGE_BYTES + 1), allocation) == NTFS_INVALID);
	input = base;
	input.data.data = (const void *)(UINTPTR_MAX - input.data.bytes + 1);
	assert(
	    ntfs_logfile_page_encode(&input, work, allocation, output, allocation) == NTFS_INVALID);
	input = base;
	memcpy(&copy, &input, sizeof(copy));
	assert(ntfs_logfile_page_encode(&input, &input, allocation, output, allocation) ==
	    NTFS_INVALID);
	assert(
	    ntfs_logfile_page_encode(&input, work, allocation, &input, allocation) == NTFS_INVALID);
	assert(memcmp(&input, &copy, sizeof(copy)) == 0);
	assert(ntfs_logfile_page_encode(&base, output, allocation, output, allocation) ==
	    NTFS_INVALID);
	assert(ntfs_logfile_page_encode(&base, output + 1, allocation - 1, output, allocation) ==
	    NTFS_INVALID);
	assert(ntfs_logfile_page_encode(&base, output, allocation, output + 1, allocation - 1) ==
	    NTFS_INVALID);
	input = base;
	input.data.data = work;
	assert(
	    ntfs_logfile_page_encode(&input, work, allocation, output, allocation) == NTFS_INVALID);
	input.data.data = output;
	assert(
	    ntfs_logfile_page_encode(&input, work, allocation, output, allocation) == NTFS_INVALID);
	input.data.data = work + 1;
	assert(
	    ntfs_logfile_page_encode(&input, work, allocation, output, allocation) == NTFS_INVALID);
	input.data.data = output + 1;
	assert(
	    ntfs_logfile_page_encode(&input, work, allocation, output, allocation) == NTFS_INVALID);
	unchanged(work, allocation);
	unchanged(output, allocation);
	unchanged(body, TEST_PAGE_BYTES);
	/* Unused capacities may contain inputs. Only each used page must be separate. */
	input = base;
	input.data.data = output + TEST_PAGE_BYTES;
	assert(ntfs_logfile_page_encode(&input, work, allocation, output, allocation) == NTFS_OK);
	unchanged(output + TEST_PAGE_BYTES, allocation - TEST_PAGE_BYTES);
	memset(output, TEST_GUARD, allocation);
	input.data.data = work + TEST_PAGE_BYTES;
	assert(ntfs_logfile_page_encode(&input, work, allocation, output, allocation) == NTFS_OK);
	unchanged(work + TEST_PAGE_BYTES, allocation - TEST_PAGE_BYTES);
	input = base;
	input.page.copy_value = input.page.last_end_lsn = UINT64_MAX;
	assert(ntfs_logfile_page_encode(&input, work, allocation, output, allocation) == NTFS_OK);
	header = (const void *)output;
	assert(ntfs_u64(header->copy_value) == UINT64_MAX &&
	    ntfs_u64(header->last_end_lsn) == UINT64_MAX);
	free(output);
	free(work);
	free(body);
}

static void
check_fast_errors(void)
{
	struct ntfs_logfile_fast_page_input base = {0}, input, copy;
	struct ntfs_logfile_fast_page_input *alias;
	const struct ntfs_disk_log_fast_page *header;
	uint8_t *body, *work, *output;
	size_t index, allocation = 2 * TEST_PAGE_BYTES + TEST_EXTRA_BYTES;
	enum ntfs_result expected;

	body = malloc(TEST_PAGE_BYTES);
	work = malloc(allocation);
	output = malloc(allocation);
	assert(body != NULL && work != NULL && output != NULL);
	memset(body, TEST_GUARD, TEST_PAGE_BYTES);
	base.common.bytes = TEST_PAGE_BYTES;
	base.common.major = NTFS_LFS_MAJOR_FAST;
	base.common.minor = NTFS_LFS_MINOR_FAST;
	base.common.data_offset = TEST_DATA_OFFSET;
	base.common.page.page_count = base.common.page.page_position = 1;
	base.common.data = (struct ntfs_logfile_buffer){body, TEST_PAGE_BYTES - TEST_DATA_OFFSET};
	base.file_offset = UINT32_MAX;
	for (index = 0; index < PAGE_ERROR_CASES; index++) {
		input = base;
		expected = NTFS_INVALID;
		switch (index) {
		case PAGE_MODERN_VERSION:
			input.common.major = NTFS_LFS_MAJOR_LEGACY;
			input.common.minor = NTFS_LFS_MINOR_LEGACY;
			expected = NTFS_UNSUPPORTED;
			break;
		case PAGE_UNKNOWN_VERSION:
			input.common.major = 0;
			expected = NTFS_UNSUPPORTED;
			break;
		case PAGE_UNKNOWN_MINOR:
			input.common.minor++;
			expected = NTFS_UNSUPPORTED;
			break;
		case PAGE_UNKNOWN_FLAGS:
			input.common.page.flags = NTFS_LOGFILE_PAGE_CLIENT_RESTART << 1;
			expected = NTFS_UNSUPPORTED;
			break;
		case PAGE_ZERO_SIZE:
			input.common.bytes = 0;
			expected = NTFS_UNSUPPORTED;
			break;
		case PAGE_SMALL_SIZE:
			input.common.bytes = TEST_PAGE_BYTES / 2;
			expected = NTFS_UNSUPPORTED;
			break;
		case PAGE_NON_POWER_SIZE:
			input.common.bytes++;
			expected = NTFS_UNSUPPORTED;
			break;
		case PAGE_POLICY_SIZE:
			input.common.bytes = NTFS_LOGFILE_MAX_PAGE_BYTES + NTFS_MST_STRIDE;
			expected = NTFS_UNSUPPORTED;
			break;
		case PAGE_USA_OVERLAP:
			input.common.data_offset =
			    sizeof(struct ntfs_disk_log_fast_page) - NTFS_WIRE_ALIGNMENT;
			break;
		case PAGE_UNALIGNED_DATA:
			input.common.data_offset++;
			break;
		case PAGE_NO_HEADER_ROOM:
			input.common.data_offset = TEST_PAGE_BYTES - NTFS_WIRE_ALIGNMENT;
			break;
		case PAGE_SHORT_DATA:
			input.common.data.bytes--;
			break;
		case PAGE_LONG_DATA:
			input.common.data.bytes++;
			break;
		case PAGE_OVERFLOW_DATA:
			input.common.data.bytes = SIZE_MAX;
			break;
		case PAGE_NULL_DATA:
			input.common.data.data = NULL;
			break;
		case PAGE_ZERO_POSITION:
			input.common.page.page_position = 0;
			break;
		case PAGE_ZERO_COUNT:
			input.common.page.page_count = 0;
			break;
		case PAGE_EXCESS_POSITION:
			input.common.page.page_position++;
			break;
		case PAGE_NEXT_HEADER:
			input.common.page.next_record_offset =
			    TEST_DATA_OFFSET - NTFS_WIRE_ALIGNMENT;
			break;
		case PAGE_NEXT_EXCESS:
			input.common.page.next_record_offset =
			    TEST_PAGE_BYTES + NTFS_WIRE_ALIGNMENT;
			break;
		case PAGE_NEXT_UNALIGNED:
			input.common.page.next_record_offset = TEST_DATA_OFFSET + 1;
			break;
		}
		copy = input;
		memset(work, TEST_GUARD, allocation);
		memset(output, TEST_GUARD, allocation);
		assert(ntfs_logfile_fast_page_encode(
			   &input, work, allocation, output, allocation) == expected);
		assert(memcmp(&input, &copy, sizeof(input)) == 0);
		unchanged(work, allocation);
		unchanged(output, allocation);
	}
	assert(ntfs_logfile_fast_page_encode(NULL, work, allocation, output, allocation) ==
	    NTFS_INVALID);
	assert(ntfs_logfile_fast_page_encode(&base, NULL, allocation, output, allocation) ==
	    NTFS_INVALID);
	assert(ntfs_logfile_fast_page_encode(&base, work, allocation, NULL, allocation) ==
	    NTFS_INVALID);
	assert(ntfs_logfile_fast_page_encode((const void *)(UINTPTR_MAX - sizeof(base) + 1), work,
		   allocation, output, allocation) == NTFS_INVALID);
	input = base;
	input.common.data.data = (const void *)(UINTPTR_MAX - input.common.data.bytes + 1);
	assert(ntfs_logfile_fast_page_encode(&input, work, allocation, output, allocation) ==
	    NTFS_INVALID);
	assert(ntfs_logfile_fast_page_encode(&base, work, allocation, work + 1, allocation - 1) ==
	    NTFS_INVALID);
	/* The extended descriptor tail must also remain outside both used buffers. */
	alias = (void *)output;
	*alias = base;
	assert(ntfs_logfile_fast_page_encode(alias, work, allocation, output + sizeof(base.common),
		   allocation - sizeof(base.common)) == NTFS_INVALID);
	assert(memcmp(alias, &base, sizeof(base)) == 0);
	alias = (void *)work;
	*alias = base;
	assert(ntfs_logfile_fast_page_encode(alias, work + sizeof(base.common),
		   allocation - sizeof(base.common), output, allocation) == NTFS_INVALID);
	assert(memcmp(alias, &base, sizeof(base)) == 0);
	input = base;
	input.common.data.data = output;
	assert(ntfs_logfile_fast_page_encode(&input, work, allocation, output, allocation) ==
	    NTFS_INVALID);
	input.common.data.data = work;
	assert(ntfs_logfile_fast_page_encode(&input, work, allocation, output, allocation) ==
	    NTFS_INVALID);
	input = base;
	input.common.page.copy_value = input.common.page.last_end_lsn = UINT64_MAX;
	assert(
	    ntfs_logfile_fast_page_encode(&input, work, allocation, output, allocation) == NTFS_OK);
	header = (const void *)output;
	assert(ntfs_u32(header->file_offset) == UINT32_MAX);
	assert(ntfs_u64(header->common.copy_value) == UINT64_MAX &&
	    ntfs_u64(header->common.last_end_lsn) == UINT64_MAX);
	unchanged(body, TEST_PAGE_BYTES);
	free(output);
	free(work);
	free(body);
}

int
main(int argc, char **argv)
{
	char path[TEST_PATH_BYTES], name[TEST_NAME_BYTES], format[TEST_FORMAT_BYTES];
	FILE *cases;
	unsigned data_offset;
	size_t count = 0;
	int written;

	assert(argc == 2);
	written = snprintf(path, sizeof(path), "%s/cases.tsv", argv[1]);
	assert(written > 0 && (size_t)written < sizeof(path));
	written = snprintf(format, sizeof(format), "%%%zus %%u", sizeof(name) - 1);
	assert(written > 0 && (size_t)written < sizeof(format));
	cases = fopen(path, "r");
	assert(cases != NULL);
	while (fscanf(cases, format, name, &data_offset) == TEST_COLUMNS) {
		assert(data_offset <= UINT16_MAX);
		check_case(argv[1], name, (uint16_t)data_offset);
		count++;
	}
	assert(feof(cases) && count != 0 && fclose(cases) == 0);
	check_errors();
	check_fast_errors();
	printf("PASS: %zu exact private RCRD pages, guarded byte alignment/capacities, "
	       "USA advancement/tails, repeatability, alias/width/version refusals and unchanged "
	       "errors\n",
	    count);
	return 0;
}
