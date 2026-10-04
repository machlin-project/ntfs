/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include <ntfs/logfile_encode.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_RECORD,
	TEST_UPDATE,
	TEST_PATH_BYTES = 4096,
	TEST_NAME_BYTES = 128,
	TEST_FORMAT_BYTES = 64,
	TEST_COLUMNS = 5,
	TEST_GUARD_BYTES = 16,
	TEST_EXTRA_BYTES = 32,
	TEST_ALIGNMENT_VARIANTS = 2,
	TEST_CAPACITY_VARIANTS = 2,
	TEST_GUARD = 0xa5,
	TEST_DATA_BYTES = 16,
	TEST_OUTPUT_BYTES = 128,
	TEST_MEASURE_SENTINEL = 0xabcdef,
	TEST_UNKNOWN_FLAG = 0x8000,
	TEST_UNKNOWN_TYPE = NTFS_LOGFILE_RECORD_RESTART + 1
};

enum {
	RECORD_ZERO_LSN,
	RECORD_PREVIOUS_ORDER,
	RECORD_UNDO_ORDER,
	RECORD_ABSENT_CLIENT,
	RECORD_LENGTH_MISMATCH,
	RECORD_UNALIGNED_HEADER,
	RECORD_MISSING_HEADER,
	RECORD_EXTENDED_HEADER,
	RECORD_UNKNOWN_FLAGS,
	RECORD_UNKNOWN_TYPE,
	RECORD_ERROR_CASES
};

enum {
	UPDATE_PARTIAL_LCN,
	UPDATE_LCN_COUNT_OVERFLOW,
	UPDATE_REDO_LENGTH_OVERFLOW,
	UPDATE_UNDO_LENGTH_OVERFLOW,
	UPDATE_REDO_OFFSET_OVERFLOW,
	UPDATE_UNDO_OFFSET_OVERFLOW,
	UPDATE_NULL_REDO,
	UPDATE_ERROR_CASES
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
	assert(length >= 0 && fseek(file, 0, SEEK_SET) == 0);
	*size = (size_t)length;
	bytes = malloc(*size + 1);
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

static struct ntfs_logfile_update_input
update_input(const uint8_t *bytes, const struct ntfs_logfile_update *view)
{
	struct ntfs_logfile_update_input input = {0};

	input.target_vcn = view->target_vcn;
	input.redo_operation = view->redo_operation;
	input.undo_operation = view->undo_operation;
	input.target_attribute = view->target_attribute;
	input.record_offset = view->record_offset;
	input.attribute_offset = view->attribute_offset;
	input.cluster_index = view->cluster_index;
	input.attribute_flags = view->attribute_flags;
	input.lcns = (struct ntfs_logfile_buffer){bytes + view->lcns.offset, view->lcns.length};
	input.redo = (struct ntfs_logfile_buffer){bytes + view->redo.offset, view->redo.length};
	input.undo = (struct ntfs_logfile_buffer){bytes + view->undo.offset, view->undo.length};
	return input;
}

static void
check_case(const char *directory, const char *name, unsigned kind, uint16_t header_bytes,
    enum ntfs_result expected_result, size_t expected_bytes)
{
	struct ntfs_logfile_record record, record_after, record_copy;
	struct ntfs_logfile_update view, encoded_view;
	struct ntfs_logfile_update_input input, input_copy;
	uint8_t *original, *golden, *source, *destination, *output;
	size_t original_bytes, golden_bytes, allocation, shift, capacity_index, capacity;
	uint32_t measured;
	enum ntfs_result result;

	original = read_bytes(directory, name, ".input", &original_bytes);
	golden = read_bytes(directory, name, ".expected", &golden_bytes);
	assert(golden_bytes == expected_bytes);
	allocation = original_bytes > expected_bytes ? original_bytes : expected_bytes;
	allocation += TEST_EXTRA_BYTES + 2 * TEST_GUARD_BYTES + TEST_ALIGNMENT_VARIANTS;
	source = malloc(original_bytes + 2 * TEST_GUARD_BYTES + TEST_ALIGNMENT_VARIANTS);
	destination = malloc(allocation);
	assert(source != NULL && destination != NULL);
	for (shift = 0; shift < TEST_ALIGNMENT_VARIANTS; shift++) {
		memset(source, TEST_GUARD,
		    original_bytes + 2 * TEST_GUARD_BYTES + TEST_ALIGNMENT_VARIANTS);
		memcpy(source + TEST_GUARD_BYTES + shift, original, original_bytes);
		output = destination + TEST_GUARD_BYTES + shift;
		if (kind == TEST_RECORD) {
			assert(ntfs_logfile_record_decode(source + TEST_GUARD_BYTES + shift,
				   original_bytes, header_bytes, &record) == NTFS_OK);
			memcpy(&record_copy, &record, sizeof(record));
		} else {
			assert(kind == TEST_UPDATE);
			assert(ntfs_logfile_update_decode(source + TEST_GUARD_BYTES + shift,
				   original_bytes, &view) == NTFS_OK);
			input = update_input(source + TEST_GUARD_BYTES + shift, &view);
			memcpy(&input_copy, &input, sizeof(input));
			measured = TEST_MEASURE_SENTINEL;
			assert(ntfs_logfile_update_measure(&input, &measured) == NTFS_OK);
			assert(measured == expected_bytes);
		}
		for (capacity_index = 0; capacity_index < TEST_CAPACITY_VARIANTS;
		    capacity_index++) {
			memset(destination, TEST_GUARD, allocation);
			capacity = expected_result == NTFS_OK ? expected_bytes : original_bytes;
			capacity += capacity_index * TEST_EXTRA_BYTES;
			if (kind == TEST_RECORD) {
				result = ntfs_logfile_record_encode(&record,
				    source + TEST_GUARD_BYTES + shift + header_bytes,
				    original_bytes - header_bytes, output, capacity);
				assert(memcmp(&record, &record_copy, sizeof(record)) == 0);
			} else {
				result = ntfs_logfile_update_encode(&input, output, capacity);
				assert(memcmp(&input, &input_copy, sizeof(input)) == 0);
			}
			if (result != expected_result) {
				fprintf(stderr, "%s: expected %u, got %u\n", name,
				    (unsigned)expected_result, (unsigned)result);
				abort();
			}
			if (result == NTFS_OK) {
				assert(memcmp(output, golden, expected_bytes) == 0);
				unchanged(destination, TEST_GUARD_BYTES + shift);
				unchanged(output + expected_bytes,
				    allocation - TEST_GUARD_BYTES - shift - expected_bytes);
				if (kind == TEST_RECORD) {
					assert(ntfs_logfile_record_decode(output, expected_bytes,
						   NTFS_LOGFILE_RECORD_HEADER_BYTES,
						   &record_after) == NTFS_OK);
				} else {
					assert(ntfs_logfile_update_decode(output, expected_bytes,
						   &encoded_view) == NTFS_OK);
				}
			} else {
				unchanged(destination, allocation);
			}
		}
		if (expected_result == NTFS_OK) {
			memset(destination, TEST_GUARD, allocation);
			if (kind == TEST_RECORD) {
				result = ntfs_logfile_record_encode(&record,
				    source + TEST_GUARD_BYTES + shift + header_bytes,
				    original_bytes - header_bytes, output, expected_bytes - 1);
			} else {
				result =
				    ntfs_logfile_update_encode(&input, output, expected_bytes - 1);
			}
			assert(result == NTFS_RANGE);
			unchanged(destination, allocation);
		}
		assert(memcmp(source + TEST_GUARD_BYTES + shift, original, original_bytes) == 0);
		unchanged(source, TEST_GUARD_BYTES + shift);
		unchanged(source + TEST_GUARD_BYTES + shift + original_bytes,
		    TEST_GUARD_BYTES + TEST_ALIGNMENT_VARIANTS - shift);
	}
	free(destination);
	free(source);
	free(golden);
	free(original);
}

static void
bad_record(
    struct ntfs_logfile_record *record, const void *data, size_t bytes, enum ntfs_result expected)
{
	uint8_t output[TEST_OUTPUT_BYTES];
	struct ntfs_logfile_record copy;

	memcpy(&copy, record, sizeof(copy));
	memset(output, TEST_GUARD, sizeof(output));
	assert(ntfs_logfile_record_encode(record, data, bytes, output, sizeof(output)) == expected);
	assert(memcmp(record, &copy, sizeof(copy)) == 0);
	unchanged(output, sizeof(output));
}

static void
record_errors(void)
{
	struct ntfs_logfile_record base = {0}, record;
	uint8_t data[TEST_DATA_BYTES], output[TEST_OUTPUT_BYTES];
	size_t index;

	memset(data, TEST_GUARD, sizeof(data));
	base.lsn = UINT64_MAX;
	base.type = NTFS_LOGFILE_RECORD_UPDATE;
	base.data = (struct ntfs_logfile_span){NTFS_LOGFILE_RECORD_HEADER_BYTES, sizeof(data)};
	for (index = 0; index < RECORD_ERROR_CASES; index++) {
		record = base;
		switch (index) {
		case RECORD_ZERO_LSN:
			record.lsn = 0;
			break;
		case RECORD_PREVIOUS_ORDER:
			record.previous_lsn = record.lsn;
			break;
		case RECORD_UNDO_ORDER:
			record.undo_next_lsn = record.lsn;
			break;
		case RECORD_ABSENT_CLIENT:
			record.client_index = NTFS_LOGFILE_NO_CLIENT;
			break;
		case RECORD_LENGTH_MISMATCH:
			record.data.length++;
			break;
		case RECORD_UNALIGNED_HEADER:
			record.data.offset--;
			break;
		case RECORD_MISSING_HEADER:
			record.data.offset = 0;
			break;
		case RECORD_EXTENDED_HEADER:
			record.data.offset += NTFS_WIRE_ALIGNMENT;
			break;
		case RECORD_UNKNOWN_FLAGS:
			record.flags = TEST_UNKNOWN_FLAG;
			break;
		case RECORD_UNKNOWN_TYPE:
			record.type = TEST_UNKNOWN_TYPE;
			break;
		}
		bad_record(&record, data, sizeof(data),
		    index >= RECORD_EXTENDED_HEADER ? NTFS_UNSUPPORTED : NTFS_INVALID);
	}
	bad_record(&base, NULL, sizeof(data), NTFS_INVALID);
	bad_record(&base, data, NTFS_LOGFILE_MAX_RECORD_BYTES, NTFS_RANGE);
	bad_record(&base, data, SIZE_MAX, NTFS_RANGE);
	bad_record(
	    &base, (const void *)(UINTPTR_MAX - sizeof(data) + 1), sizeof(data), NTFS_INVALID);
	memset(output, TEST_GUARD, sizeof(output));
	assert(ntfs_logfile_record_encode(NULL, data, sizeof(data), output, sizeof(output)) ==
	    NTFS_INVALID);
	assert(ntfs_logfile_record_encode((const void *)(UINTPTR_MAX - sizeof(base) + 1), data,
		   sizeof(data), output, sizeof(output)) == NTFS_INVALID);
	unchanged(output, sizeof(output));
	assert(ntfs_logfile_record_encode(&base, data, sizeof(data), NULL, sizeof(output)) ==
	    NTFS_INVALID);
	assert(ntfs_logfile_record_encode(&base, data, sizeof(data),
		   (void *)(UINTPTR_MAX - NTFS_LOGFILE_RECORD_HEADER_BYTES + 1),
		   sizeof(output)) == NTFS_INVALID);
	record = base;
	assert(ntfs_logfile_record_encode(&record, data, sizeof(data), &record, sizeof(output)) ==
	    NTFS_INVALID);
	assert(memcmp(&record, &base, sizeof(record)) == 0);
	assert(ntfs_logfile_record_encode(
		   &base, output + 1, sizeof(data), output, sizeof(output)) == NTFS_INVALID);
	assert(ntfs_logfile_record_encode(
		   &base, output, sizeof(data), output + 1, sizeof(output) - 1) == NTFS_INVALID);
	unchanged(output, sizeof(output));
	/* Empty borrowed input may share the destination: there are no input bytes. */
	record = base;
	record.data.length = 0;
	assert(ntfs_logfile_record_encode(
		   &record, output, 0, output, NTFS_LOGFILE_RECORD_HEADER_BYTES) == NTFS_OK);
	assert(ntfs_logfile_record_encode(
		   &record, NULL, 0, output, NTFS_LOGFILE_RECORD_HEADER_BYTES) == NTFS_OK);
	/* Capacity beyond the used output is not an input/output overlap. */
	memset(output, TEST_GUARD, sizeof(output));
	assert(ntfs_logfile_record_encode(&base, output + sizeof(output) - sizeof(data),
		   sizeof(data), output, sizeof(output)) == NTFS_OK);
	unchanged(output + NTFS_LOGFILE_RECORD_HEADER_BYTES + sizeof(data),
	    sizeof(output) - NTFS_LOGFILE_RECORD_HEADER_BYTES - sizeof(data));
}

static void
bad_update(const struct ntfs_logfile_update_input *input, enum ntfs_result expected)
{
	struct ntfs_logfile_update_input copy;
	uint8_t output[TEST_OUTPUT_BYTES];
	uint32_t measured = TEST_MEASURE_SENTINEL;

	memcpy(&copy, input, sizeof(copy));
	memset(output, TEST_GUARD, sizeof(output));
	assert(ntfs_logfile_update_measure(input, &measured) == expected);
	assert(measured == TEST_MEASURE_SENTINEL);
	assert(ntfs_logfile_update_encode(input, output, sizeof(output)) == expected);
	assert(memcmp(input, &copy, sizeof(copy)) == 0);
	unchanged(output, sizeof(output));
}

static void
update_errors(void)
{
	struct ntfs_logfile_update_input base = {0}, input, copy;
	_Alignas(uint64_t) uint8_t data[TEST_DATA_BYTES], output[TEST_OUTPUT_BYTES];
	uint32_t measured = TEST_MEASURE_SENTINEL;
	size_t index;

	memset(data, TEST_GUARD, sizeof(data));
	base.redo = (struct ntfs_logfile_buffer){data, sizeof(data)};
	for (index = 0; index < UPDATE_ERROR_CASES; index++) {
		input = base;
		switch (index) {
		case UPDATE_PARTIAL_LCN:
			input.lcns.bytes = 1;
			break;
		case UPDATE_LCN_COUNT_OVERFLOW:
			input.lcns.bytes = ((size_t)UINT16_MAX + 1) * sizeof(uint64_t);
			break;
		case UPDATE_REDO_LENGTH_OVERFLOW:
			input.redo.bytes = (size_t)UINT16_MAX + 1;
			break;
		case UPDATE_UNDO_LENGTH_OVERFLOW:
			input.undo.bytes = SIZE_MAX;
			break;
		case UPDATE_REDO_OFFSET_OVERFLOW:
			input.lcns.bytes = (UINT16_MAX / sizeof(uint64_t)) * sizeof(uint64_t);
			break;
		case UPDATE_UNDO_OFFSET_OVERFLOW:
			input.lcns.bytes = ((UINT16_MAX - sizeof(struct ntfs_disk_log_update)) /
					       sizeof(uint64_t)) *
			    sizeof(uint64_t);
			input.redo.bytes = 1;
			input.undo = (struct ntfs_logfile_buffer){data, 1};
			break;
		case UPDATE_NULL_REDO:
			input.redo.data = NULL;
			break;
		}
		bad_update(&input,
		    index == UPDATE_PARTIAL_LCN || index == UPDATE_NULL_REDO ? NTFS_INVALID
									     : NTFS_RANGE);
	}
	input = base;
	input.lcns = (struct ntfs_logfile_buffer){NULL, sizeof(uint64_t)};
	bad_update(&input, NTFS_INVALID);
	input = base;
	input.undo = (struct ntfs_logfile_buffer){NULL, 1};
	bad_update(&input, NTFS_INVALID);
	input = base;
	input.redo.data = (const void *)(UINTPTR_MAX - sizeof(data) + 1);
	bad_update(&input, NTFS_INVALID);
	memset(output, TEST_GUARD, sizeof(output));
	assert(ntfs_logfile_update_measure(NULL, &measured) == NTFS_INVALID);
	assert(ntfs_logfile_update_measure(&base, NULL) == NTFS_INVALID);
	assert(ntfs_logfile_update_encode(NULL, output, sizeof(output)) == NTFS_INVALID);
	assert(ntfs_logfile_update_encode(&base, NULL, sizeof(output)) == NTFS_INVALID);
	assert(ntfs_logfile_update_encode((const void *)(UINTPTR_MAX - sizeof(base) + 1), output,
		   sizeof(output)) == NTFS_INVALID);
	assert(ntfs_logfile_update_encode(&base,
		   (void *)(UINTPTR_MAX - sizeof(struct ntfs_disk_log_update_storage) + 1),
		   sizeof(output)) == NTFS_INVALID);
	assert(measured == TEST_MEASURE_SENTINEL);
	unchanged(output, sizeof(output));
	input = base;
	memcpy(&copy, &input, sizeof(copy));
	assert(ntfs_logfile_update_encode(&input, &input, sizeof(output)) == NTFS_INVALID);
	assert(ntfs_logfile_update_measure(&input, (void *)&input.target_vcn) == NTFS_INVALID);
	assert(memcmp(&input, &copy, sizeof(copy)) == 0);
	input = base;
	input.redo.data = output + 1;
	assert(ntfs_logfile_update_encode(&input, output, sizeof(output)) == NTFS_INVALID);
	input.redo.data = output;
	assert(ntfs_logfile_update_encode(&input, output + 1, sizeof(output) - 1) == NTFS_INVALID);
	assert(ntfs_logfile_update_measure(&input, (void *)output) == NTFS_INVALID);
	input = base;
	input.lcns = (struct ntfs_logfile_buffer){output, sizeof(uint64_t)};
	assert(ntfs_logfile_update_encode(&input, output, sizeof(output)) == NTFS_INVALID);
	input = base;
	input.undo = (struct ntfs_logfile_buffer){output, sizeof(uint64_t)};
	assert(ntfs_logfile_update_encode(&input, output, sizeof(output)) == NTFS_INVALID);
	unchanged(output, sizeof(output));
	unchanged(data, sizeof(data));
	input = (struct ntfs_logfile_update_input){0};
	input.lcns.data = output;
	input.redo.data = output;
	input.undo.data = output;
	assert(ntfs_logfile_update_encode(
		   &input, output, sizeof(struct ntfs_disk_log_update_storage)) == NTFS_OK);
	memset(output, TEST_GUARD, sizeof(output));
	input = base;
	input.redo.data = output + sizeof(output) - sizeof(data);
	assert(ntfs_logfile_update_encode(&input, output, sizeof(output)) == NTFS_OK);
	unchanged(output + sizeof(struct ntfs_disk_log_update_storage) + sizeof(data),
	    sizeof(output) - sizeof(struct ntfs_disk_log_update_storage) - sizeof(data));
}

int
main(int argc, char **argv)
{
	char path[TEST_PATH_BYTES], name[TEST_NAME_BYTES], format[TEST_FORMAT_BYTES];
	FILE *cases;
	unsigned kind, header_bytes, code;
	size_t expected_bytes, count = 0;
	int written;

	assert(argc == 2);
	written = snprintf(path, sizeof(path), "%s/cases.tsv", argv[1]);
	assert(written > 0 && (size_t)written < sizeof(path));
	written = snprintf(format, sizeof(format), "%%%zus %%u %%u %%u %%zu", sizeof(name) - 1);
	assert(written > 0 && (size_t)written < sizeof(format));
	cases = fopen(path, "r");
	assert(cases != NULL);
	while (fscanf(cases, format, name, &kind, &header_bytes, &code, &expected_bytes) ==
	    TEST_COLUMNS) {
		assert(header_bytes <= UINT16_MAX);
		check_case(argv[1], name, kind, (uint16_t)header_bytes, (enum ntfs_result)code,
		    expected_bytes);
		count++;
	}
	assert(feof(cases) && count != 0 && fclose(cases) == 0);
	record_errors();
	update_errors();
	printf("PASS: %zu exact logical log packets, aligned/unaligned inputs and outputs, "
	       "wire/policy/capacity boundaries, alias/range admission and unchanged errors\n",
	    count);
	return 0;
}
