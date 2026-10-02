/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include <ntfs/logfile.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	FUZZ_RESTART,
	FUZZ_PAGE,
	FUZZ_RECORD,
	FUZZ_UPDATE,
	FUZZ_CLIENT,
	FUZZ_KINDS,
	FUZZ_INPUT_BYTES = 128 * 1024,
	FUZZ_GUARD_BYTES = 32,
	FUZZ_GUARD_VALUE = 0xa5,
	FUZZ_MUTATIONS = 1024,
	FUZZ_GENERIC_PERIOD = 4
};

/* Independent test envelope, not a stored LFS structure. Configuration is a
 * raw restart page only in page mode; the tested packet follows it. */
struct fuzz_logfile_header {
	uint8_t kind, argument[sizeof(uint64_t)], configuration_bytes[sizeof(uint32_t)];
};

union fuzz_output {
	struct ntfs_logfile_restart restart;
	struct ntfs_logfile_page page;
	struct ntfs_logfile_record record;
	struct ntfs_logfile_update update;
	struct ntfs_logfile_client client;
};

static uint8_t scratch[2][NTFS_LOGFILE_MAX_PAGE_BYTES + 2 * FUZZ_GUARD_BYTES];
static uint8_t configuration_scratch[NTFS_LOGFILE_MAX_PAGE_BYTES + 2 * FUZZ_GUARD_BYTES];
static uint8_t original[FUZZ_INPUT_BYTES];

static void
guard(const uint8_t *bytes, size_t used, size_t size)
{
	size_t i;

	for (i = 0; i < FUZZ_GUARD_BYTES; i++) {
		assert(bytes[i] == FUZZ_GUARD_VALUE);
	}
	for (i = FUZZ_GUARD_BYTES + used; i < size; i++) {
		assert(bytes[i] == FUZZ_GUARD_VALUE);
	}
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const struct fuzz_logfile_header *header = (const void *)data;
	const uint8_t *packet, *configuration;
	struct ntfs_logfile_restart restart;
	struct ntfs_logfile_lsn lsn, repeated_lsn, zero_lsn = {0};
	union fuzz_output outputs[2], zero = {0};
	enum ntfs_result results[2], result, repeat;
	size_t packet_size, configuration_size, output_size = 0, used = 0, i;
	uint64_t argument, candidate_lsn;
	unsigned kind;

	if (size < sizeof(*header) || size > FUZZ_INPUT_BYTES) {
		return 0;
	}
	memcpy(original, data, size);
	argument = ntfs_u64(header->argument);
	kind = header->kind % FUZZ_KINDS;
	configuration_size = kind == FUZZ_PAGE ? ntfs_u32(header->configuration_bytes) : 0;
	if (configuration_size > size - sizeof(*header)) {
		return 0;
	}
	configuration = data + sizeof(*header);
	packet = configuration + configuration_size;
	packet_size = size - sizeof(*header) - configuration_size;
	if (kind == FUZZ_PAGE) {
		memset(configuration_scratch, FUZZ_GUARD_VALUE, sizeof(configuration_scratch));
		result = ntfs_logfile_restart_decode(configuration, configuration_size, argument,
		    configuration_scratch + FUZZ_GUARD_BYTES, NTFS_LOGFILE_MAX_PAGE_BYTES,
		    &restart);
		guard(configuration_scratch,
		    configuration_size > NTFS_LOGFILE_MAX_PAGE_BYTES ? 0 : configuration_size,
		    sizeof(configuration_scratch));
		if (result != NTFS_OK) {
			assert(memcmp(data, original, size) == 0);
			return 0;
		}
	}
	for (i = 0; i < 2; i++) {
		memset(scratch[i], FUZZ_GUARD_VALUE, sizeof(scratch[i]));
		memset(&outputs[i], FUZZ_GUARD_VALUE, sizeof(outputs[i]));
		switch (kind) {
		case FUZZ_RESTART:
			output_size = sizeof(outputs[i].restart);
			used = packet_size > NTFS_LOGFILE_MAX_PAGE_BYTES ? 0 : packet_size;
			results[i] = ntfs_logfile_restart_decode(packet, packet_size, argument,
			    scratch[i] + FUZZ_GUARD_BYTES, NTFS_LOGFILE_MAX_PAGE_BYTES,
			    &outputs[i].restart);
			break;
		case FUZZ_PAGE:
			output_size = sizeof(outputs[i].page);
			used = packet_size > NTFS_LOGFILE_MAX_PAGE_BYTES ? 0 : packet_size;
			results[i] = ntfs_logfile_page_decode(packet, packet_size, &restart,
			    scratch[i] + FUZZ_GUARD_BYTES, NTFS_LOGFILE_MAX_PAGE_BYTES,
			    &outputs[i].page);
			break;
		case FUZZ_RECORD:
			output_size = sizeof(outputs[i].record);
			results[i] = ntfs_logfile_record_decode(
			    packet, packet_size, (uint16_t)argument, &outputs[i].record);
			break;
		case FUZZ_UPDATE:
			output_size = sizeof(outputs[i].update);
			results[i] =
			    ntfs_logfile_update_decode(packet, packet_size, &outputs[i].update);
			break;
		case FUZZ_CLIENT:
			output_size = sizeof(outputs[i].client);
			results[i] =
			    ntfs_logfile_client_decode(packet, packet_size, &outputs[i].client);
			break;
		}
		guard(scratch[i], used, sizeof(scratch[i]));
		if (results[i] != NTFS_OK) {
			assert(memcmp(&outputs[i], &zero, output_size) == 0);
		}
	}
	assert(results[0] == results[1] && memcmp(&outputs[0], &outputs[1], output_size) == 0);
	assert(memcmp(scratch[0], scratch[1], sizeof(scratch[0])) == 0);
	assert(memcmp(data, original, size) == 0);
	if (kind == FUZZ_RESTART && results[0] == NTFS_OK) {
		candidate_lsn = argument ^ outputs[0].restart.current_lsn;
		result = ntfs_logfile_lsn_decode(&outputs[0].restart, candidate_lsn, &lsn);
		repeat = ntfs_logfile_lsn_decode(&outputs[1].restart, candidate_lsn, &repeated_lsn);
		assert(result == repeat && memcmp(&lsn, &repeated_lsn, sizeof(lsn)) == 0);
		if (result != NTFS_OK) {
			assert(memcmp(&lsn, &zero_lsn, sizeof(lsn)) == 0);
		}
	}
	return 0;
}

static bool
unprotect(uint8_t *page, size_t size, size_t header_bytes)
{
	const struct ntfs_disk_mst *mst = (const void *)page;
	size_t offset, count, i, tail;
	uint16_t sequence;

	if (size < header_bytes || size > NTFS_LOGFILE_MAX_PAGE_BYTES ||
	    size % NTFS_MST_STRIDE != 0) {
		return false;
	}
	offset = ntfs_u16(mst->usa_offset);
	count = ntfs_u16(mst->usa_count);
	if (offset < header_bytes || count != size / NTFS_MST_STRIDE + 1 ||
	    !ntfs_bounds(
		offset, count * NTFS_MST_WORD_BYTES, NTFS_MST_STRIDE - NTFS_MST_WORD_BYTES)) {
		return false;
	}
	sequence = ntfs_u16(page + offset);
	for (i = 1; i < count; i++) {
		tail = i * NTFS_MST_STRIDE - NTFS_MST_WORD_BYTES;
		if (ntfs_u16(page + tail) != sequence) {
			return false;
		}
	}
	for (i = 1; i < count; i++) {
		ntfs_copy(page + i * NTFS_MST_STRIDE - NTFS_MST_WORD_BYTES,
		    page + offset + i * NTFS_MST_WORD_BYTES, NTFS_MST_WORD_BYTES);
	}
	return true;
}

static void
protect(uint8_t *page, size_t size)
{
	const struct ntfs_disk_mst *mst = (const void *)page;
	size_t offset = ntfs_u16(mst->usa_offset), i, tail;

	for (i = 1; i <= size / NTFS_MST_STRIDE; i++) {
		tail = i * NTFS_MST_STRIDE - NTFS_MST_WORD_BYTES;
		ntfs_copy(
		    page + offset + i * NTFS_MST_WORD_BYTES, page + tail, NTFS_MST_WORD_BYTES);
		ntfs_copy(page + tail, page + offset, NTFS_MST_WORD_BYTES);
	}
}

static size_t
structured_mutate(uint8_t *data, size_t size, unsigned seed)
{
	const struct fuzz_logfile_header *envelope = (const void *)data;
	const struct ntfs_disk_log_restart_page *restart;
	const struct ntfs_disk_mst *mst;
	uint8_t *page;
	size_t configuration_size, page_bytes, minimum, position, usa_offset, usa_bytes;
	unsigned kind;
	bool restored_page = false;

	if (size < sizeof(*envelope)) {
		return size;
	}
	kind = envelope->kind % FUZZ_KINDS;
	configuration_size = kind == FUZZ_PAGE ? ntfs_u32(envelope->configuration_bytes) : 0;
	if (configuration_size > size - sizeof(*envelope)) {
		return size;
	}
	page = data + sizeof(*envelope) + configuration_size;
	page_bytes = size - sizeof(*envelope) - configuration_size;
	minimum = 0;
	if (kind == FUZZ_RESTART) {
		minimum = sizeof(*restart);
		restored_page = unprotect(page, page_bytes, minimum);
		if (restored_page) {
			restart = (const void *)page;
			minimum = ntfs_u16(restart->area_offset);
		}
	} else if (kind == FUZZ_PAGE) {
		minimum = sizeof(struct ntfs_disk_log_page);
		restored_page = unprotect(page, page_bytes, minimum);
	}
	if (page_bytes > minimum) {
		position = minimum + (size_t)seed % (page_bytes - minimum);
		if (restored_page) {
			/* Never mutate USA storage after restoring it; resealing must use
			 * the original checked location, count and sequence. */
			mst = (const void *)page;
			usa_offset = ntfs_u16(mst->usa_offset);
			usa_bytes = (size_t)ntfs_u16(mst->usa_count) * NTFS_MST_WORD_BYTES;
			if (position >= usa_offset && position - usa_offset < usa_bytes) {
				position = usa_offset + usa_bytes;
			}
			assert(position < page_bytes);
		}
		page[position] ^=
		    (uint8_t)(1u << ((seed / FUZZ_GENERIC_PERIOD) % NTFS_BITS_PER_BYTE));
	}
	if (restored_page) {
		protect(page, page_bytes);
	}
	return size;
}

#ifndef NTFS_FUZZ_STANDALONE
size_t LLVMFuzzerMutate(uint8_t *, size_t, size_t);

size_t
LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t maximum, unsigned seed)
{
	if (seed % FUZZ_GENERIC_PERIOD == 0) {
		return LLVMFuzzerMutate(data, size, maximum);
	}
	return structured_mutate(data, size, seed);
}
#else
int
main(int argc, char **argv)
{
	FILE *file;
	uint8_t *bytes, *copy;
	long length;
	size_t i;

	assert(argc == 2);
	file = fopen(argv[1], "rb");
	assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
	length = ftell(file);
	assert(length > 0 && (size_t)length <= FUZZ_INPUT_BYTES);
	assert(fseek(file, 0, SEEK_SET) == 0);
	bytes = malloc((size_t)length);
	copy = malloc((size_t)length);
	assert(bytes != NULL && copy != NULL &&
	    fread(bytes, 1, (size_t)length, file) == (size_t)length);
	assert(fclose(file) == 0);
	LLVMFuzzerTestOneInput(bytes, (size_t)length);
	for (i = 0; i < FUZZ_MUTATIONS; i++) {
		memcpy(copy, bytes, (size_t)length);
		structured_mutate(copy, (size_t)length, (unsigned)i);
		LLVMFuzzerTestOneInput(copy, (size_t)length);
	}
	free(copy);
	free(bytes);
	puts("PASS: structured log-page mutations preserve USA and check deterministic errors, "
	     "scratch guards and immutable inputs");
	return 0;
}
#endif
