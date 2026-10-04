/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include "logfile_tables_disk.h"
#include <ntfs/logfile.h>
#include <ntfs/logfile_tables.h>
#include <ntfs/record.h>
#include "fuzz_device.h"
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
	FUZZ_SOURCE,
	FUZZ_CIRCULAR_RECORD,
	FUZZ_CLIENT_RESTART,
	FUZZ_CLIENT_RESTART_RECORD,
	FUZZ_RESTART_TABLE,
	FUZZ_OPEN_ATTRIBUTE,
	FUZZ_DIRTY_PAGE,
	FUZZ_TRANSACTION,
	FUZZ_PROTECTED_RECORD,
	FUZZ_KINDS,
	/* Full 1-MiB source fixtures plus their framing fit this test envelope. */
	FUZZ_INPUT_BYTES = 2 * 1024 * 1024,
	FUZZ_GUARD_BYTES = 32,
	FUZZ_GUARD_VALUE = 0xa5,
	FUZZ_MUTATIONS = 1024,
	FUZZ_GENERIC_PERIOD = 4,
	FUZZ_SOURCE_ALLOCATIONS = 4,
	FUZZ_SOURCE_OWNER_BYTES = 4096,
	FUZZ_SOURCE_PAGE_BUFFERS = 3,
	FUZZ_RECORD_MUTATION_PAGES = 4,
	FUZZ_FAULT_ALLOCATION = 1u << NTFS_BITS_PER_BYTE,
	FUZZ_BUDGET_SHIFT = 2 * NTFS_BITS_PER_BYTE,
	FUZZ_PARTIAL_READ_BYTE = 0x71,
	FUZZ_PARTIAL_READ_DENOMINATOR = 2
};

enum { FUZZ_CLIENT_VERSION_SHIFT = sizeof(uint32_t) * NTFS_BITS_PER_BYTE };

_Static_assert(NTFS_PROTECTED_RECORD_MAX_BYTES == NTFS_LOGFILE_MAX_PAGE_BYTES,
    "protected-record fuzz scratch capacity");

/* Independent test envelope, not a stored LFS structure. Configuration is a
 * raw restart page only in page mode; the tested packet follows it. Circular
 * record mode uses argument as the LSN and configuration_bytes as fault/budget
 * controls, without a configuration payload. Client-restart-record mode uses
 * a complete logical source as configuration, followed by an exact record. */
struct fuzz_logfile_header {
	uint8_t kind, argument[sizeof(uint64_t)], configuration_bytes[sizeof(uint32_t)];
};

union fuzz_output {
	struct ntfs_logfile_restart restart;
	struct ntfs_logfile_page page;
	struct ntfs_logfile_record record;
	struct ntfs_logfile_update update;
	struct ntfs_logfile_client client;
	struct ntfs_logfile_client_restart client_restart;
	struct ntfs_logfile_restart_table table;
	struct ntfs_logfile_open_attribute attribute;
	struct ntfs_logfile_dirty_page dirty_page;
	struct ntfs_logfile_transaction transaction;
};

struct fuzz_restart_output {
	uint8_t before[FUZZ_GUARD_BYTES];
	struct ntfs_logfile_client_restart value;
	uint8_t after[FUZZ_GUARD_BYTES];
};

static uint8_t scratch[2][NTFS_LOGFILE_MAX_PAGE_BYTES + 2 * FUZZ_GUARD_BYTES];
static uint8_t configuration_scratch[NTFS_LOGFILE_MAX_PAGE_BYTES + 2 * FUZZ_GUARD_BYTES];
static uint8_t record_scratch[2][NTFS_LOGFILE_MAX_RECORD_BYTES + 2 * FUZZ_GUARD_BYTES];
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

static void
fuzz_protected_record(const uint8_t *packet, size_t size, uint64_t argument)
{
	const struct ntfs_disk_mst *header = (const void *)packet;
	enum ntfs_result results[2];
	size_t capacity, used = 0, i, offset, usa_bytes;

	capacity = (size_t)(argument % (NTFS_PROTECTED_RECORD_MAX_BYTES + 1u));
	for (i = 0; i < sizeof(results) / sizeof(results[0]); i++) {
		memset(scratch[i], FUZZ_GUARD_VALUE, sizeof(scratch[i]));
		results[i] =
		    ntfs_record_protect(packet, size, scratch[i] + FUZZ_GUARD_BYTES, capacity);
		if (results[i] == NTFS_OK) {
			used = size;
		}
		guard(scratch[i], used, sizeof(scratch[i]));
	}
	assert(results[0] == results[1]);
	assert(memcmp(scratch[0], scratch[1], sizeof(scratch[0])) == 0);
	if (results[0] == NTFS_OK) {
		memcpy(record_scratch[0], scratch[0] + FUZZ_GUARD_BYTES, size);
		assert(ntfs_fixup(record_scratch[0], size, (const char *)header->magic) == NTFS_OK);
		offset = ntfs_u16(header->usa_offset);
		usa_bytes = (size_t)ntfs_u16(header->usa_count) * NTFS_MST_WORD_BYTES;
		for (i = 0; i < size; i++) {
			if (i < offset || i - offset >= usa_bytes) {
				assert(record_scratch[0][i] == packet[i]);
			}
		}
	}
}

static void
fuzz_source(const uint8_t *bytes, size_t size, uint64_t argument)
{
	struct ntfs_logfile_report reports[2];
	struct ntfs_logfile_restart restarts[2];
	struct ntfs_logfile_client clients[2], active_clients[2], wrong_client, zero_client = {0};
	struct ntfs_logfile_page_view views[2], zero_view = {0};
	struct ntfs_logfile *source;
	struct fuzz_device device;
	struct ntfs_environment environment;

	enum ntfs_result results[2], page_results[2] = {NTFS_INVALID, NTFS_INVALID};

	enum ntfs_result active_results[2] = {NTFS_INVALID, NTFS_INVALID};

	size_t i, reads, allocations, used[2] = {0, 0};
	uint16_t index;

	memset(restarts, 0, sizeof(restarts));
	memset(clients, 0, sizeof(clients));
	memset(active_clients, 0, sizeof(active_clients));
	memset(views, 0, sizeof(views));
	for (i = 0; i < sizeof(results) / sizeof(results[0]); i++) {
		device = (struct fuzz_device){.data = bytes,
		    .size = size,
		    .fail_read = argument % (NTFS_LOGFILE_DEFAULT_READ_CALLS + 1u),
		    .fail_allocation =
			(argument >> NTFS_BITS_PER_BYTE) % (FUZZ_SOURCE_ALLOCATIONS + 1u)};
		environment = fuzz_environment(&device);
		memset(scratch[i], FUZZ_GUARD_VALUE, sizeof(scratch[i]));
		results[i] = ntfs_logfile_open(&environment, NULL, &reports[i], &source);
		assert(reports[i].read_calls <= NTFS_LOGFILE_DEFAULT_READ_CALLS &&
		    reports[i].read_bytes <= NTFS_LOGFILE_DEFAULT_READ_BYTES &&
		    reports[i].probe_count <= NTFS_LOGFILE_RESTART_PROBES);
		if (results[i] == NTFS_OK) {
			assert(source != NULL && reports[i].scan_complete &&
			    reports[i].selected_probe < reports[i].probe_count &&
			    device.memory <= FUZZ_SOURCE_OWNER_BYTES +
				    FUZZ_SOURCE_PAGE_BUFFERS * NTFS_LOGFILE_MAX_PAGE_BYTES);
			assert(ntfs_logfile_get_restart(source, &restarts[i]) == NTFS_OK);
			if (restarts[i].client_count != 0) {
				index = (uint16_t)(argument % restarts[i].client_count);
				assert(
				    ntfs_logfile_get_client(source, index, &clients[i]) == NTFS_OK);
				reads = device.reads;
				allocations = device.allocations;
				active_results[i] = ntfs_logfile_get_active_client(
				    source, index, clients[i].sequence, &active_clients[i]);
				assert(active_results[i] == NTFS_OK ||
				    active_results[i] == NTFS_STALE);
				assert(
				    memcmp(&active_clients[i],
					active_results[i] == NTFS_OK ? &clients[i] : &zero_client,
					sizeof(active_clients[i])) == 0);
				assert(ntfs_logfile_get_active_client(source, index,
					   (uint16_t)(clients[i].sequence + 1u),
					   &wrong_client) == NTFS_STALE);
				assert(memcmp(&wrong_client, &zero_client, sizeof(wrong_client)) ==
					0 &&
				    device.reads == reads && device.allocations == allocations);
			}
			page_results[i] = ntfs_logfile_read_page(source,
			    restarts[i].circular_offset, scratch[i] + FUZZ_GUARD_BYTES,
			    NTFS_LOGFILE_MAX_PAGE_BYTES, &views[i]);
			if (page_results[i] == NTFS_OK) {
				used[i] = restarts[i].log_page_bytes;
			} else {
				assert(memcmp(&views[i], &zero_view, sizeof(zero_view)) == 0);
			}
			ntfs_logfile_close(source);
		} else {
			assert(
			    source == NULL && reports[i].selected_probe == NTFS_LOGFILE_NO_PROBE);
		}
		assert(device.memory == 0);
		guard(scratch[i], used[i], sizeof(scratch[i]));
	}
	assert(
	    results[0] == results[1] && page_results[0] == page_results[1] && used[0] == used[1]);
	assert(memcmp(&reports[0], &reports[1], sizeof(reports[0])) == 0);
	assert(memcmp(&restarts[0], &restarts[1], sizeof(restarts[0])) == 0);
	assert(memcmp(&clients[0], &clients[1], sizeof(clients[0])) == 0);
	assert(active_results[0] == active_results[1] &&
	    memcmp(&active_clients[0], &active_clients[1], sizeof(active_clients[0])) == 0);
	assert(memcmp(&views[0], &views[1], sizeof(views[0])) == 0);
	assert(memcmp(scratch[0], scratch[1], sizeof(scratch[0])) == 0);
}

static enum ntfs_result
partial_read(void *context, uint64_t offset, void *bytes, size_t size)
{
	enum ntfs_result result = fuzz_read(context, offset, bytes, size);

	if (result == NTFS_IO) {
		memset(bytes, FUZZ_PARTIAL_READ_BYTE, size / FUZZ_PARTIAL_READ_DENOMINATOR);
	}
	return result;
}

static void
fuzz_circular_record(const uint8_t *bytes, size_t size, uint64_t requested_lsn, uint32_t controls)
{
	struct ntfs_logfile_record_view views[2] = {0}, zero_view = {0};
	struct ntfs_logfile_report reports[2];
	struct ntfs_logfile_limits limits;
	struct ntfs_logfile *source;
	struct fuzz_device device;
	struct ntfs_environment environment;

	enum ntfs_result results[2], record_results[2] = {NTFS_INVALID, NTFS_INVALID};

	size_t i, memory, reads, fail_read, capacity, guarded_bytes, used[2] = {0};
	uint32_t budget = controls >> FUZZ_BUDGET_SHIFT;

	ntfs_logfile_default_limits(&limits);
	capacity = size < NTFS_LOGFILE_MAX_RECORD_BYTES ? size : NTFS_LOGFILE_MAX_RECORD_BYTES;
	guarded_bytes = capacity + 2 * FUZZ_GUARD_BYTES;
	if (budget != 0) {
		limits.max_read_calls = 1u + budget % NTFS_LOGFILE_DEFAULT_READ_CALLS;
		limits.max_read_bytes = 1u + budget * NTFS_MST_STRIDE;
	}
	for (i = 0; i < sizeof(results) / sizeof(results[0]); i++) {
		device = (struct fuzz_device){.data = bytes, .size = size};
		environment = fuzz_environment(&device);
		environment.read = partial_read;
		memset(record_scratch[i], FUZZ_GUARD_VALUE, guarded_bytes);
		results[i] = ntfs_logfile_open(&environment, &limits, &reports[i], &source);
		assert(reports[i].read_calls <= limits.max_read_calls &&
		    reports[i].read_bytes <= limits.max_read_bytes);
		if (results[i] == NTFS_OK) {
			memory = device.memory;
			reads = device.reads;
			assert(memory <= FUZZ_SOURCE_OWNER_BYTES +
				FUZZ_SOURCE_PAGE_BUFFERS * limits.max_page_bytes);
			fail_read = (controls & UINT8_MAX) % (NTFS_LOGFILE_DEFAULT_READ_CALLS + 1u);
			device.fail_read = fail_read == 0 ? 0 : reads + fail_read;
			device.fail_allocation =
			    (controls & FUZZ_FAULT_ALLOCATION) != 0 ? device.allocations + 1 : 0;
			record_results[i] = ntfs_logfile_read_circular_record(source, requested_lsn,
			    record_scratch[i] + FUZZ_GUARD_BYTES, capacity, &views[i]);
			assert(device.memory == memory &&
			    device.reads - reads <= limits.max_read_calls);
			if (record_results[i] == NTFS_OK) {
				used[i] = views[i].bytes;
				assert(used[i] <= capacity &&
				    views[i].record.lsn == requested_lsn &&
				    views[i].read_calls == device.reads - reads &&
				    views[i].read_calls == views[i].pages_read &&
				    views[i].read_bytes <= limits.max_read_bytes);
			} else {
				assert(memcmp(&views[i], &zero_view, sizeof(zero_view)) == 0);
			}
			ntfs_logfile_close(source);
		} else {
			assert(source == NULL);
		}
		assert(device.memory == 0);
		guard(record_scratch[i], used[i], guarded_bytes);
	}
	assert(results[0] == results[1] && record_results[0] == record_results[1]);
	assert(memcmp(&reports[0], &reports[1], sizeof(reports[0])) == 0);
	assert(memcmp(&views[0], &views[1], sizeof(views[0])) == 0);
	assert(memcmp(record_scratch[0], record_scratch[1], guarded_bytes) == 0);
}

static void
fuzz_client_restart_record(const uint8_t *configuration, size_t configuration_size,
    const uint8_t *packet, size_t packet_size, uint64_t argument)
{
	struct fuzz_restart_output outputs[2];
	struct ntfs_logfile_client_restart zero = {0};
	struct ntfs_logfile *source;
	struct fuzz_device device;
	struct ntfs_environment environment;
	enum ntfs_result results[2];
	size_t i, j, reads, allocations, memory;

	for (i = 0; i < sizeof(results) / sizeof(results[0]); i++) {
		device = (struct fuzz_device){.data = configuration,
		    .size = configuration_size,
		    .fail_read = argument % (NTFS_LOGFILE_DEFAULT_READ_CALLS + 1u),
		    .fail_allocation =
			(argument >> NTFS_BITS_PER_BYTE) % (FUZZ_SOURCE_ALLOCATIONS + 1u)};
		environment = fuzz_environment(&device);
		memset(&outputs[i], FUZZ_GUARD_VALUE, sizeof(outputs[i]));
		results[i] = ntfs_logfile_open(&environment, NULL, NULL, &source);
		assert(device.reads <= NTFS_LOGFILE_DEFAULT_READ_CALLS);
		if (results[i] == NTFS_OK) {
			assert(source != NULL &&
			    device.memory <= FUZZ_SOURCE_OWNER_BYTES +
				    FUZZ_SOURCE_PAGE_BUFFERS * NTFS_LOGFILE_MAX_PAGE_BYTES);
			reads = device.reads;
			allocations = device.allocations;
			memory = device.memory;
			device.fail_read = reads + 1;
			device.fail_allocation = allocations + 1;
			results[i] = ntfs_logfile_decode_client_restart_record(
			    source, packet, packet_size, &outputs[i].value);
			assert(device.reads == reads && device.allocations == allocations &&
			    device.memory == memory);
			ntfs_logfile_close(source);
		} else {
			assert(source == NULL);
			memset(&outputs[i].value, 0, sizeof(outputs[i].value));
		}
		assert(device.memory == 0);
		if (results[i] != NTFS_OK) {
			assert(memcmp(&outputs[i].value, &zero, sizeof(zero)) == 0);
		}
		for (j = 0; j < FUZZ_GUARD_BYTES; j++) {
			assert(outputs[i].before[j] == FUZZ_GUARD_VALUE &&
			    outputs[i].after[j] == FUZZ_GUARD_VALUE);
		}
	}
	assert(results[0] == results[1] &&
	    memcmp(&outputs[0].value, &outputs[1].value, sizeof(outputs[0].value)) == 0);
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
	configuration_size = kind == FUZZ_PAGE || kind == FUZZ_CLIENT_RESTART_RECORD
	    ? ntfs_u32(header->configuration_bytes)
	    : 0;
	if (configuration_size > size - sizeof(*header)) {
		return 0;
	}
	configuration = data + sizeof(*header);
	packet = configuration + configuration_size;
	packet_size = size - sizeof(*header) - configuration_size;
	if (kind == FUZZ_CLIENT_RESTART_RECORD) {
		fuzz_client_restart_record(
		    configuration, configuration_size, packet, packet_size, argument);
		assert(memcmp(data, original, size) == 0);
		return 0;
	}
	if (kind == FUZZ_SOURCE) {
		fuzz_source(packet, packet_size, argument);
		assert(memcmp(data, original, size) == 0);
		return 0;
	}
	if (kind == FUZZ_CIRCULAR_RECORD) {
		fuzz_circular_record(
		    packet, packet_size, argument, ntfs_u32(header->configuration_bytes));
		assert(memcmp(data, original, size) == 0);
		return 0;
	}
	if (kind == FUZZ_PROTECTED_RECORD) {
		fuzz_protected_record(packet, packet_size, argument);
		assert(memcmp(data, original, size) == 0);
		return 0;
	}
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
		case FUZZ_CLIENT_RESTART:
			output_size = sizeof(outputs[i].client_restart);
			results[i] = ntfs_logfile_client_restart_decode(
			    packet, packet_size, &outputs[i].client_restart);
			break;
		case FUZZ_RESTART_TABLE:
			output_size = sizeof(outputs[i].table);
			results[i] = ntfs_logfile_restart_table_decode(
			    packet, packet_size, &outputs[i].table);
			break;
		case FUZZ_OPEN_ATTRIBUTE:
			output_size = sizeof(outputs[i].attribute);
			results[i] = ntfs_logfile_open_attribute_decode(packet, packet_size,
			    (uint32_t)argument, (uint32_t)(argument >> FUZZ_CLIENT_VERSION_SHIFT),
			    &outputs[i].attribute);
			break;
		case FUZZ_DIRTY_PAGE:
			output_size = sizeof(outputs[i].dirty_page);
			results[i] = ntfs_logfile_dirty_page_decode(packet, packet_size,
			    (uint32_t)argument, (uint32_t)(argument >> FUZZ_CLIENT_VERSION_SHIFT),
			    &outputs[i].dirty_page);
			break;
		case FUZZ_TRANSACTION:
			output_size = sizeof(outputs[i].transaction);
			results[i] = ntfs_logfile_transaction_decode(
			    packet, packet_size, &outputs[i].transaction);
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

static bool
record_mutation_page(uint8_t **bytes, size_t *size, uint64_t lsn, unsigned seed, size_t *minimum)
{
	const struct ntfs_disk_log_restart_page *header = (const void *)*bytes;
	struct ntfs_logfile_restart restart;
	struct ntfs_logfile_lsn location;
	uint64_t offset, ring_bytes;
	size_t system_bytes;
	unsigned position;

	if (*size < sizeof(*header)) {
		return false;
	}
	system_bytes = ntfs_u32(header->system_page_bytes);
	if (system_bytes > *size || system_bytes > NTFS_LOGFILE_MAX_PAGE_BYTES ||
	    ntfs_logfile_restart_decode(*bytes, system_bytes, *size,
		configuration_scratch + FUZZ_GUARD_BYTES, NTFS_LOGFILE_MAX_PAGE_BYTES,
		&restart) != NTFS_OK ||
	    ntfs_logfile_lsn_decode(&restart, lsn, &location) != NTFS_OK) {
		return false;
	}
	/* Focus resealed mutations on the header and nearby continuations. Generic
	 * mutation still reaches arbitrary storage and damaged protection words. */
	position = (seed / FUZZ_GENERIC_PERIOD) % FUZZ_RECORD_MUTATION_PAGES;
	ring_bytes = restart.usable_bytes - restart.circular_offset;
	offset = restart.circular_offset +
	    (location.page_offset - restart.circular_offset +
		(uint64_t)position * restart.log_page_bytes) %
		ring_bytes;
	if (!ntfs_bounds(offset, restart.log_page_bytes, *size)) {
		return false;
	}
	*bytes += (size_t)offset;
	*size = restart.log_page_bytes;
	*minimum = position == 0 ? location.record_offset : restart.page_data_offset;
	return true;
}

static size_t
structured_mutate(uint8_t *data, size_t size, unsigned seed)
{
	const struct fuzz_logfile_header *envelope = (const void *)data;
	const struct ntfs_disk_log_restart_page *restart;
	const struct ntfs_disk_mst *mst;
	uint8_t *page;
	size_t configuration_size, page_bytes, minimum, position, usa_offset, usa_bytes;
	size_t candidate_offset, candidate_bytes;
	size_t mutation_end, area_bytes, record_header_bytes;
	const struct ntfs_disk_log_restart_area *area;
	const struct ntfs_disk_log_table *table;
	unsigned kind;
	bool restored_page = false, record_page = false, source_kind;

	if (size < sizeof(*envelope)) {
		return size;
	}
	kind = envelope->kind % FUZZ_KINDS;
	configuration_size = kind == FUZZ_PAGE || kind == FUZZ_CLIENT_RESTART_RECORD
	    ? ntfs_u32(envelope->configuration_bytes)
	    : 0;
	if (configuration_size > size - sizeof(*envelope)) {
		return size;
	}
	page = data + sizeof(*envelope) + configuration_size;
	page_bytes = size - sizeof(*envelope) - configuration_size;
	source_kind = kind == FUZZ_SOURCE || kind == FUZZ_CIRCULAR_RECORD;
	if (kind == FUZZ_CLIENT_RESTART_RECORD &&
	    (seed / FUZZ_GENERIC_PERIOD) % FUZZ_GENERIC_PERIOD == 0) {
		page = data + sizeof(*envelope);
		page_bytes = configuration_size;
		source_kind = true;
	}
	minimum = 0;
	if (kind == FUZZ_CIRCULAR_RECORD &&
	    (seed / (FUZZ_GENERIC_PERIOD * FUZZ_RECORD_MUTATION_PAGES)) % FUZZ_GENERIC_PERIOD !=
		0) {
		record_page = record_mutation_page(
		    &page, &page_bytes, ntfs_u64(envelope->argument), seed, &minimum);
	}
	if (source_kind && !record_page && page_bytes >= sizeof(*restart)) {
		restart = (const void *)page;
		candidate_offset = (seed / FUZZ_GENERIC_PERIOD) % NTFS_LFS_RESTART_PAGES == 0
		    ? 0
		    : ntfs_u32(restart->system_page_bytes);
		if (ntfs_bounds(candidate_offset, sizeof(*restart), page_bytes)) {
			restart = (const void *)(page + candidate_offset);
			candidate_bytes = ntfs_u32(restart->system_page_bytes);
			if (candidate_bytes >= NTFS_MST_STRIDE &&
			    candidate_bytes <= NTFS_LOGFILE_MAX_PAGE_BYTES &&
			    (candidate_bytes & (candidate_bytes - 1u)) == 0 &&
			    ntfs_bounds(candidate_offset, candidate_bytes, page_bytes)) {
				page += candidate_offset;
				page_bytes = candidate_bytes;
			}
		}
	}
	if (record_page) {
		restored_page = unprotect(page, page_bytes, sizeof(struct ntfs_disk_log_page));
	} else if (kind == FUZZ_RESTART || source_kind) {
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
	mutation_end = page_bytes;
	if (kind == FUZZ_CLIENT_RESTART_RECORD && !source_kind) {
		record_header_bytes = sizeof(struct ntfs_disk_log_record);
		if (configuration_size >= sizeof(*restart)) {
			restart = (const void *)(data + sizeof(*envelope));
			candidate_offset = ntfs_u16(restart->area_offset);
			if (ntfs_bounds(candidate_offset, sizeof(*area), configuration_size)) {
				area = (const void *)(data + sizeof(*envelope) + candidate_offset);
				candidate_bytes = ntfs_u16(area->record_header_bytes);
				if (candidate_bytes >= record_header_bytes) {
					record_header_bytes = candidate_bytes;
				}
			}
		}
		if (ntfs_bounds(record_header_bytes, sizeof(struct ntfs_disk_log_client_restart),
			page_bytes)) {
			mutation_end =
			    record_header_bytes + sizeof(struct ntfs_disk_log_client_restart);
			/* Preserve snapshot identity and version for deep field mutations. */
			if ((seed / FUZZ_GENERIC_PERIOD) % FUZZ_GENERIC_PERIOD != 1) {
				minimum = record_header_bytes +
				    offsetof(struct ntfs_disk_log_client_restart, analysis_lsn);
			}
		}
	}
	if (kind == FUZZ_CLIENT_RESTART &&
	    page_bytes >= sizeof(struct ntfs_disk_log_client_restart)) {
		/* Focus on declared prefix fields even when an opaque extension is
		 * large. Most structured mutations preserve the version gate. */
		mutation_end = sizeof(struct ntfs_disk_log_client_restart);
		if ((seed / FUZZ_GENERIC_PERIOD) % FUZZ_GENERIC_PERIOD != 0) {
			minimum = offsetof(struct ntfs_disk_log_client_restart, analysis_lsn);
		}
	}
	if (kind == FUZZ_RESTART_TABLE && page_bytes >= sizeof(*table) &&
	    (seed / FUZZ_GENERIC_PERIOD) % FUZZ_GENERIC_PERIOD != 0) {
		table = (const void *)page;
		candidate_bytes = ntfs_u16(table->entry_bytes);
		area_bytes = ntfs_u16(table->entries);
		if (candidate_bytes >= sizeof(uint32_t) && area_bytes != 0) {
			candidate_offset = sizeof(*table) +
			    ((seed / FUZZ_GENERIC_PERIOD) % area_bytes) * candidate_bytes;
			if (ntfs_bounds(candidate_offset, sizeof(uint32_t), page_bytes)) {
				/* Preserve table framing and focus on allocation/free-link words.
				 */
				minimum = candidate_offset;
				mutation_end = minimum + sizeof(uint32_t);
			}
		}
	}
	if ((kind == FUZZ_OPEN_ATTRIBUTE || kind == FUZZ_DIRTY_PAGE || kind == FUZZ_TRANSACTION) &&
	    page_bytes >= sizeof(uint32_t) &&
	    (seed / FUZZ_GENERIC_PERIOD) % FUZZ_GENERIC_PERIOD != 0) {
		/* Keep the allocated marker for deep typed fields and vector bounds. */
		minimum = sizeof(uint32_t);
	}
	if (kind == FUZZ_PROTECTED_RECORD && page_bytes >= sizeof(struct ntfs_disk_mst) &&
	    (seed / FUZZ_GENERIC_PERIOD) % FUZZ_GENERIC_PERIOD != 0) {
		minimum = sizeof(struct ntfs_disk_mst);
	}
	if (!record_page && (kind == FUZZ_RESTART || source_kind) && restored_page &&
	    ntfs_bounds(minimum, sizeof(*area), page_bytes)) {
		area = (const void *)(page + minimum);
		area_bytes = ntfs_u16(area->length);
		if (area_bytes >= sizeof(*area) && ntfs_bounds(minimum, area_bytes, page_bytes)) {
			mutation_end = minimum + area_bytes;
		}
	}
	if (mutation_end > minimum) {
		position = minimum + (size_t)seed % (mutation_end - minimum);
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
