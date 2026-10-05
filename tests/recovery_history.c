/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/recovery.h>
#include "fuzz_device.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_RECORDS = 64,
	TEST_HISTORY_BYTES = 64 * 1024,
	TEST_READ_CALLS = 4096,
	TEST_READ_BYTES = 16 * 1024 * 1024,
	TEST_SENTINEL = 0xa7,
	TEST_STATE_VALUES = 10,
	TEST_PATH_BYTES = 4096
};

enum { TEST_CLIENT_SEQUENCE = 7, TEST_VOLUME_LOW_MEMORY = 6 * 1024 * 1024 };

struct test_device {
	struct fuzz_device device;
	enum ntfs_result failure;
	bool full_failure;
	struct ntfs_recovery_limits *alter_limits;
};

static void *
allocate(void *context, size_t bytes)
{
	struct test_device *device = context;

	return fuzz_allocate(&device->device, bytes);
}

static void
release(void *context, void *bytes, size_t size)
{
	struct test_device *device = context;

	fuzz_release(&device->device, bytes, size);
}

static enum ntfs_result
read_source(void *context, uint64_t offset, void *bytes, size_t size)
{
	struct test_device *device = context;

	assert(offset <= device->device.size && size <= device->device.size - offset);
	device->device.reads++;
	if (device->alter_limits != NULL) {
		*device->alter_limits = (struct ntfs_recovery_limits){0};
		device->alter_limits = NULL;
	}
	if (device->device.reads == device->device.fail_read) {
		if (device->full_failure) {
			memcpy(bytes, device->device.data + (size_t)offset, size);
		} else {
			memset(bytes, TEST_SENTINEL, size / 2);
		}
		return device->failure;
	}
	memcpy(bytes, device->device.data + (size_t)offset, size);
	return NTFS_OK;
}

static uint8_t *
load(const char *directory, const char *name, const char *suffix, size_t *size)
{
	char path[TEST_PATH_BYTES];
	FILE *file;
	uint8_t *bytes;
	long length;

	assert(
	    snprintf(path, sizeof(path), "%s/%s%s", directory, name, suffix) < (int)sizeof(path));
	file = fopen(path, "rb");
	assert(file != NULL);
	assert(fseek(file, 0, SEEK_END) == 0);
	length = ftell(file);
	assert(length > 0);
	assert(fseek(file, 0, SEEK_SET) == 0);
	*size = (size_t)length;
	bytes = malloc(*size);
	assert(bytes != NULL && fread(bytes, 1, *size, file) == *size);
	assert(fclose(file) == 0);
	return bytes;
}

static struct ntfs_recovery_limits
policy(void)
{
	return (struct ntfs_recovery_limits){
	    TEST_RECORDS, TEST_HISTORY_BYTES, TEST_READ_CALLS, TEST_READ_BYTES, FUZZ_MEMORY_BUDGET};
}

static struct ntfs_logfile *
open_source(struct test_device *device)
{
	struct ntfs_environment environment = {
	    NTFS_API_VERSION, device, device->device.size, read_source, allocate, release};
	struct ntfs_logfile_limits limits = {
	    NTFS_LOGFILE_MAX_PAGE_BYTES, TEST_READ_CALLS, TEST_READ_BYTES};
	struct ntfs_logfile_page_index_report report;
	struct ntfs_logfile *source = NULL;

	assert(ntfs_logfile_open(&environment, &limits, NULL, &source) == NTFS_OK);
	assert(ntfs_logfile_prepare_page_index(source, TEST_HISTORY_BYTES * 2, &report) == NTFS_OK);
	return source;
}

static bool
zero(const void *memory, size_t size)
{
	const uint8_t *bytes = memory;
	size_t index;

	for (index = 0; index < size; index++) {
		if (bytes[index] != 0) {
			return false;
		}
	}
	return true;
}

static void
check_records(
    const struct ntfs_recovery *owner, const uint8_t *expected, size_t size, uint32_t count)
{
	struct ntfs_recovery_record record;
	const void *packet;
	size_t position = 0;
	uint32_t ordinal;

	for (ordinal = 0; ordinal < count; ordinal++) {
		assert(ntfs_recovery_get_record(owner, ordinal, &record, &packet) == NTFS_OK);
		assert(record.packet.offset == position && record.packet.length <= size - position);
		assert(memcmp(packet, expected + position, record.packet.length) == 0);
		position += record.packet.length;
	}
	assert(position == size);
	memset(&record, TEST_SENTINEL, sizeof(record));
	packet = expected;
	assert(ntfs_recovery_get_record(owner, count, &record, &packet) == NTFS_END);
	assert(packet == NULL && zero(&record, sizeof(record)));
}

static void
check_states(
    const struct ntfs_recovery *owner, const char *directory, const char *name, uint32_t count)
{
	struct ntfs_recovery_transaction transaction;
	char path[TEST_PATH_BYTES];
	FILE *file;
	uint64_t actual[TEST_STATE_VALUES], expected;
	uint32_t ordinal, field;

	assert(snprintf(path, sizeof(path), "%s/%s.states", directory, name) < (int)sizeof(path));
	file = fopen(path, "r");
	assert(file != NULL);
	for (ordinal = 0; ordinal < count; ordinal++) {
		assert(ntfs_recovery_get_transaction(owner, ordinal, &transaction) == NTFS_OK);
		actual[0] = transaction.key;
		actual[1] = transaction.records;
		actual[2] = transaction.first_lsn;
		actual[3] = transaction.last_lsn;
		actual[4] = transaction.predecessor_lsn;
		actual[5] = transaction.undo_next_lsn;
		actual[6] = transaction.control_lsn;
		actual[7] = transaction.control_operation;
		actual[8] = transaction.state;
		actual[9] = transaction.complete_chain;
		for (field = 0; field < TEST_STATE_VALUES; field++) {
			assert(fscanf(file, "%" SCNu64, &expected) == 1);
			assert(actual[field] == expected);
		}
	}
	assert(fscanf(file, "%" SCNu64, &expected) == EOF);
	assert(fclose(file) == 0);
	memset(&transaction, TEST_SENTINEL, sizeof(transaction));
	assert(ntfs_recovery_get_transaction(owner, count, &transaction) == NTFS_END);
	assert(zero(&transaction, sizeof(transaction)));
}

static void
check_volume(const char *directory, const char *packet_name)
{
	struct test_device device;
	struct ntfs_environment environment;
	struct ntfs_limits volume_limits;
	struct ntfs_logfile_limits source_limits;
	struct ntfs_recovery_limits limits;
	struct ntfs_logfile_page_index_report preparation;
	struct ntfs_recovery_report report;
	struct ntfs_recovery *owner;
	struct ntfs_volume *volume;
	struct ntfs_logfile *source;
	uint8_t *image, *packets;
	size_t image_size, packet_size, variant, reads;

	image = load(directory, "volume-history.img", "", &image_size);
	packets = load(directory, packet_name, ".packets", &packet_size);
	for (variant = 0; variant < 2; variant++) {
		memset(&device, 0, sizeof(device));
		device.device.data = image;
		device.device.size = image_size;
		environment = (struct ntfs_environment){
		    NTFS_API_VERSION, &device, image_size, read_source, allocate, release};
		ntfs_default_limits(&volume_limits);
		volume_limits.record_cache_entries = 0;
		volume_limits.max_live_bytes =
		    variant == 0 ? FUZZ_MEMORY_BUDGET : TEST_VOLUME_LOW_MEMORY;
		assert(ntfs_mount(&environment, &volume_limits, &volume) == NTFS_OK);
		source_limits = (struct ntfs_logfile_limits){
		    NTFS_LOGFILE_MAX_PAGE_BYTES, TEST_READ_CALLS, TEST_READ_BYTES};
		assert(ntfs_logfile_open_volume(volume, &source_limits, NULL, &source) == NTFS_OK);
		assert(ntfs_logfile_prepare_page_index(
			   source, TEST_HISTORY_BYTES * 2, &preparation) == NTFS_OK);
		limits = policy();
		owner = NULL;
		if (variant == 0) {
			assert(ntfs_recovery_open(source, 0, TEST_CLIENT_SEQUENCE, &limits, &report,
				   &owner) == NTFS_OK);
			assert(ntfs_unmount(volume) == NTFS_BUSY);
			ntfs_logfile_close(source);
			assert(ntfs_unmount(volume) == NTFS_BUSY);
			reads = device.device.reads;
			check_records(owner, packets, packet_size, report.records);
			assert(device.device.reads == reads);
			ntfs_recovery_close(owner);
		} else {
			reads = device.device.reads;
			assert(ntfs_recovery_open(source, 0, TEST_CLIENT_SEQUENCE, &limits, &report,
				   &owner) == NTFS_NO_MEMORY);
			assert(owner == NULL && report.read_calls == 0 &&
			    device.device.reads == reads);
			ntfs_logfile_close(source);
		}
		assert(ntfs_unmount(volume) == NTFS_OK && device.device.memory == 0);
	}
	free(packets);
	free(image);
}

static void
faults(struct ntfs_logfile *source, struct test_device *device, size_t source_memory,
    const struct ntfs_recovery_report *baseline, size_t allocations, uint16_t sequence)
{
	struct ntfs_recovery_limits limits;
	struct ntfs_recovery_report report;
	struct ntfs_recovery *owner;

	enum ntfs_result failures[] = {NTFS_IO, NTFS_RANGE, NTFS_STALE, NTFS_NO_MEMORY};

	size_t index, before, variant, full;

	for (index = 1; index <= allocations; index++) {
		limits = policy();
		before = device->device.reads;
		device->device.fail_allocation = device->device.allocations + index;
		owner = NULL;
		assert(ntfs_recovery_open(source, 0, sequence, &limits, &report, &owner) ==
		    NTFS_NO_MEMORY);
		assert(owner == NULL && !report.published && report.retained_bytes == 0);
		assert(device->device.memory == source_memory);
		if (index <= 8) {
			assert(device->device.reads == before);
		}
		device->device.fail_allocation = 0;
		assert(
		    ntfs_recovery_open(source, 0, sequence, &limits, &report, &owner) == NTFS_OK);
		ntfs_recovery_close(owner);
		assert(device->device.memory == source_memory);
	}
	for (full = 0; full < 2; full++) {
		device->full_failure = full != 0;
		for (variant = 0; variant < sizeof(failures) / sizeof(failures[0]); variant++) {
			device->failure = failures[variant];
			for (index = 1; index <= baseline->read_calls; index++) {
				limits = policy();
				before = device->device.reads;
				device->device.fail_read = before + index;
				owner = NULL;
				assert(ntfs_recovery_open(source, 0, sequence, &limits, &report,
					   &owner) == failures[variant]);
				assert(owner == NULL && !report.published &&
				    report.read_calls == index);
				assert(device->device.reads == before + index);
				assert(device->device.memory == source_memory &&
				    report.retained_bytes == 0);
				device->device.fail_read = 0;
				assert(ntfs_recovery_open(source, 0, sequence, &limits, &report,
					   &owner) == NTFS_OK);
				ntfs_recovery_close(owner);
			}
		}
	}
	limits = policy();
	limits.max_read_calls = baseline->read_calls - 1;
	before = device->device.reads;
	assert(ntfs_recovery_open(source, 0, sequence, &limits, &report, &owner) == NTFS_RANGE);
	assert(owner == NULL && report.read_calls == limits.max_read_calls);
	assert(device->device.reads == before + limits.max_read_calls);
	limits = policy();
	limits.max_read_bytes = baseline->read_bytes - 1;
	assert(ntfs_recovery_open(source, 0, sequence, &limits, &report, &owner) == NTFS_RANGE);
	assert(owner == NULL && report.read_bytes < limits.max_read_bytes);
	limits = policy();
	limits.max_read_calls = baseline->read_calls;
	limits.max_read_bytes = baseline->read_bytes;
	assert(ntfs_recovery_open(source, 0, sequence, &limits, &report, &owner) == NTFS_OK);
	ntfs_recovery_close(owner);
	limits = policy();
	limits.max_records = baseline->records - 1;
	assert(ntfs_recovery_open(source, 0, sequence, &limits, &report, &owner) == NTFS_RANGE);
	assert(owner == NULL && !report.published);
	limits = policy();
	limits.max_history_bytes = baseline->history_bytes - 1;
	assert(ntfs_recovery_open(source, 0, sequence, &limits, &report, &owner) == NTFS_RANGE);
	assert(owner == NULL && !report.published);
	limits = policy();
	limits.max_live_bytes = baseline->reserved_bytes - 1;
	before = device->device.reads;
	assert(ntfs_recovery_open(source, 0, sequence, &limits, &report, &owner) == NTFS_RANGE);
	assert(owner == NULL && report.reserved_bytes == baseline->reserved_bytes);
	assert(device->device.reads == before);
	limits = policy();
	device->alter_limits = &limits;
	assert(ntfs_recovery_open(source, 0, sequence, &limits, &report, &owner) == NTFS_OK);
	assert(limits.max_records == 0 && report.published);
	ntfs_recovery_close(owner);
	limits = policy();
	before = device->device.reads;
	assert(ntfs_recovery_open(source, 0, sequence + 1, &limits, &report, &owner) == NTFS_STALE);
	assert(owner == NULL && device->device.reads == before);
	assert(device->device.memory == source_memory);
}

int
main(int argc, char **argv)
{
	struct ntfs_recovery_report report, baseline;
	struct ntfs_recovery_limits limits;
	struct ntfs_logfile_checkpoint_capture capture;
	struct ntfs_recovery *owner;
	struct ntfs_logfile *source;
	struct test_device device;
	const void *captured;
	uint8_t *image, *packets, *original;
	char listing_path[TEST_PATH_BYTES], name[TEST_PATH_BYTES];
	FILE *listing;
	size_t image_size, packet_size, memory, before_allocations, before_reads, allocations;
	unsigned code, records, bytes, epochs, seeds, partial, cases = 0;
	enum ntfs_result result;

	assert(argc == 2);
	assert(snprintf(listing_path, sizeof(listing_path), "%s/cases.txt", argv[1]) <
	    (int)sizeof(listing_path));
	listing = fopen(listing_path, "r");
	assert(listing != NULL);
	while (fscanf(listing, "%4095s %u %u %u %u %u %u", name, &code, &records, &bytes, &epochs,
		   &seeds, &partial) == 7) {
		image = load(argv[1], name, "", &image_size);
		packets = load(argv[1], name, ".packets", &packet_size);
		original = malloc(image_size);
		assert(original != NULL);
		memcpy(original, image, image_size);
		memset(&device, 0, sizeof(device));
		device.device.data = image;
		device.device.size = image_size;
		source = open_source(&device);
		memory = device.device.memory;
		before_allocations = device.device.allocations;
		before_reads = device.device.reads;
		limits = policy();
		owner = NULL;
		result =
		    ntfs_recovery_open(source, 0, TEST_CLIENT_SEQUENCE, &limits, &report, &owner);
		if (result != (enum ntfs_result)code) {
			fprintf(stderr,
			    "%s: expected %u, received %d, capture %u, history %u, epochs %u\n",
			    name, code, (int)result, report.checkpoint.acquired_records,
			    report.history.visited_records, report.transaction_epochs);
		}
		assert(result == (enum ntfs_result)code);
		allocations = device.device.allocations - before_allocations;
		assert(report.read_calls == device.device.reads - before_reads);
		if (code == NTFS_OK) {
			assert(owner != NULL && report.published && report.history.complete);
			assert(report.records == records && report.history_bytes == bytes);
			assert(
			    report.transaction_epochs == epochs && report.verified_seeds == seeds);
			assert(report.partial_prefixes == partial && report.retained_bytes != 0);
			check_records(owner, packets, packet_size, records);
			check_states(owner, argv[1], name, epochs);
			assert(ntfs_recovery_get_checkpoint(owner, &capture, &captured) == NTFS_OK);
			assert(captured != NULL && capture.client_sequence == TEST_CLIENT_SEQUENCE);
			baseline = report;
			ntfs_recovery_close(owner);
			assert(device.device.memory == memory);
			if (cases == 0) {
				faults(source, &device, memory, &baseline, allocations,
				    TEST_CLIENT_SEQUENCE);
			}
			limits = policy();
			assert(ntfs_recovery_open(source, 0, TEST_CLIENT_SEQUENCE, &limits, &report,
				   &owner) == NTFS_OK);
			ntfs_logfile_close(source);
			source = NULL;
			before_reads = device.device.reads;
			before_allocations = device.device.allocations;
			check_records(owner, packets, packet_size, records);
			check_states(owner, argv[1], name, epochs);
			assert(device.device.reads == before_reads &&
			    device.device.allocations == before_allocations);
			ntfs_recovery_close(owner);
		} else {
			assert(owner == NULL && !report.published && report.retained_bytes == 0);
			assert(device.device.memory == memory);
		}
		ntfs_logfile_close(source);
		assert(device.device.memory == 0 && memcmp(image, original, image_size) == 0);
		free(image);
		free(packets);
		free(original);
		cases++;
	}
	assert(feof(listing) && cases != 0 && fclose(listing) == 0);
	check_volume(argv[1], "checkpoint-active-then-forget-0-0-0.journal");
	ntfs_recovery_close(NULL);
	printf("%u retained client-history profiles passed\n", cases);
	return 0;
}
