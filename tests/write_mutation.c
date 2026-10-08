/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_mutation.h"
#include "write_bitmap.h"
#include "write_retirement.h"
#include "write_program.h"
#include <ntfs/record.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_PATH_BYTES = 4096,
	TEST_NAME_UNITS = 255,
	TEST_READ_BYTES = 1024 * 1024,
	TEST_WRITE_OFFSET = 257,
	TEST_GROW_BYTES = 299999,
	TEST_SHRINK_BYTES = 19,
	TEST_REGROW_BYTES = TEST_WRITE_OFFSET + 65537,
	TEST_CHILDREN = 96,
	TEST_FRAGMENT_FILES = 96,
	TEST_REUSE_OPERATIONS = 512,
	TEST_FIRST_RESERVED_RECORD = 16,
	TEST_FIRST_ALLOCATABLE_RECORD = 24,
	TEST_RESERVED_RECORDS = TEST_FIRST_ALLOCATABLE_RECORD - TEST_FIRST_RESERVED_RECORD,
	TEST_INLINE_SPILL_NAME_UNITS = 180,
	TEST_INLINE_SPILL_CHILDREN = 24,
	TEST_PATTERN = 0xd3
};

enum {
	TEST_PROGRAM_JOURNAL_BYTES = 16 * 1024 * 1024,
	TEST_PROGRAM_OFFSET_BITS = 22,
	TEST_PROGRAM_CLIENT_SEQUENCE = 7
};

#define TEST_FILETIME UINT64_C(134357146906613431)
#define TEST_RETIREMENT_REDO_LSN UINT64_C(9001)
#define TEST_RETIREMENT_UNDO_LSN UINT64_C(9003)
#define TEST_PROGRAM_LSN UINT64_C(100001)

struct test_device {
	uint8_t *visible, *durable;
	size_t bytes, live_bytes, allocations, read_calls, writes, barriers;
	size_t fail_allocation, fail_read, fail_write, fail_barrier, failed_prefix;
	bool claimed, executing, fault_triggered;
};

struct test_case {
	struct test_device device;
	struct ntfs_overwrite_environment backend;
	struct ntfs_overwrite *owner;
	struct ntfs_overwrite_admission admission;
	struct ntfs_write_recovery_report recovery;
	uint64_t root_reference, time;
};

static uint8_t *
load(const char *directory, const char *name, size_t *bytes)
{
	char *path;
	uint8_t *data;
	FILE *file;
	long length;
	int count;

	path = malloc(TEST_PATH_BYTES);
	assert(path != NULL);
	count = snprintf(path, TEST_PATH_BYTES, "%s/%s", directory, name);
	assert(count > 0 && count < TEST_PATH_BYTES);
	file = fopen(path, "rb");
	free(path);
	assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
	length = ftell(file);
	assert(length >= 0 && fseek(file, 0, SEEK_SET) == 0);
	*bytes = (size_t)length;
	data = malloc(*bytes == 0 ? 1 : *bytes);
	assert(data != NULL);
	assert(fread(data, 1, *bytes, file) == *bytes);
	assert(fgetc(file) == EOF && !ferror(file) && fclose(file) == 0);
	return data;
}

static void *
allocate(void *context, size_t bytes)
{
	struct test_device *device = context;
	void *memory = NULL;

	assert(!device->executing && bytes != 0);
	device->allocations++;
	if (device->allocations == device->fail_allocation) {
		device->fault_triggered = true;
		return NULL;
	}
	if (bytes > NTFS_DEFAULT_MAX_LIVE_BYTES - device->live_bytes) {
		return NULL;
	}
	assert(posix_memalign(&memory, NTFS_WRITE_CLUSTER_BYTES, bytes) == 0 && memory != NULL);
	device->live_bytes += bytes;
	return memory;
}

static void
release(void *context, void *memory, size_t bytes)
{
	struct test_device *device = context;

	assert(memory != NULL && bytes <= device->live_bytes);
	device->live_bytes -= bytes;
	free(memory);
}

static enum ntfs_result
read_image(void *context, uint64_t first, void *memory, size_t bytes)
{
	struct test_device *device = context;

	assert(!device->executing);
	assert(first <= device->bytes && bytes <= device->bytes - first);
	device->read_calls++;
	if (device->read_calls == device->fail_read) {
		device->fault_triggered = true;
		memset(memory, TEST_PATTERN, bytes);
		return NTFS_IO;
	}
	memcpy(memory, device->visible + first, bytes);
	return NTFS_OK;
}

static enum ntfs_result
claim(void *context)
{
	struct test_device *device = context;

	assert(!device->claimed);
	device->claimed = true;
	return NTFS_OK;
}

static void
unclaim(void *context)
{
	struct test_device *device = context;

	assert(device->claimed && !device->executing);
	device->claimed = false;
}

static enum ntfs_result
write_image(void *context, uint64_t first, const void *memory, size_t bytes, size_t *actual)
{
	struct test_device *device = context;
	size_t prefix;

	assert(device->claimed && bytes != 0);
	assert(first <= device->bytes && bytes <= device->bytes - first);
	assert(first % NTFS_WRITE_SECTOR_BYTES == 0 && bytes % NTFS_WRITE_SECTOR_BYTES == 0);
	assert((uintptr_t)memory % NTFS_WRITE_SECTOR_BYTES == 0);
	device->executing = true;
	device->writes++;
	if (device->writes == device->fail_write) {
		device->fault_triggered = true;
		prefix = device->failed_prefix < bytes ? device->failed_prefix : bytes;
		memcpy(device->visible + first, memory, prefix);
		memcpy(device->durable + first, memory, prefix);
		*actual = prefix;
		return NTFS_IO;
	}
	memcpy(device->visible + first, memory, bytes);
	*actual = bytes;
	return NTFS_OK;
}

static enum ntfs_result
persist_image(void *context)
{
	struct test_device *device = context;

	assert(device->claimed);
	device->executing = true;
	device->barriers++;
	memcpy(device->durable, device->visible, device->bytes);
	if (device->barriers == device->fail_barrier) {
		device->fault_triggered = true;
		return NTFS_IO;
	}
	return NTFS_OK;
}

static struct ntfs_volume *
view(struct test_case *test)
{
	struct ntfs_volume *volume = NULL;
	struct ntfs_limits limits;

	assert(!test->device.executing);
	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	assert(ntfs_mount(&test->backend.reader, &limits, &volume) == NTFS_OK);
	return volume;
}

static void
validate(struct test_case *test)
{
	struct ntfs_validation_report *report;
	struct ntfs_limits limits;
	struct ntfs_validation_limits validation_limits;

	assert(!test->device.executing);
	report = calloc(1, sizeof(*report));
	assert(report != NULL);
	ntfs_default_limits(&limits);
	ntfs_validation_default_limits(&validation_limits);
	assert(
	    ntfs_validate(&test->backend.reader, &limits, &validation_limits, report) == NTFS_OK);
	assert(report->complete);
	free(report);
}

static void
open_owner(struct test_case *test)
{
#if !defined(NTFS_TEST_MUTATION_PLAN)
	enum ntfs_result result;

	assert(test->owner == NULL && !test->device.claimed);
	result =
	    ntfs_write_owner_open(&test->backend, &test->admission, &test->recovery, &test->owner);
	test->device.executing = false;
	assert(result == NTFS_OK && test->owner != NULL && test->device.claimed);
#else
	assert(test->owner == NULL && !test->device.claimed);
#endif
}

static struct test_case *
prepare_image(const char *directory, const char *image)
{
	struct test_case *test;
	struct ntfs_volume *volume;
	struct ntfs_node *node = NULL;
	struct ntfs_stat metadata;

	test = calloc(1, sizeof(*test));
	assert(test != NULL);
	test->device.visible = load(directory, image, &test->device.bytes);
	test->device.durable = malloc(test->device.bytes);
	assert(test->device.durable != NULL);
	memcpy(test->device.durable, test->device.visible, test->device.bytes);
	test->backend.reader = (struct ntfs_environment){.api_version = NTFS_API_VERSION,
	    .context = &test->device,
	    .size_bytes = test->device.bytes,
	    .allocate = allocate,
	    .release = release,
	    .read = read_image};
	test->backend.api_version = NTFS_OVERWRITE_API_VERSION;
	test->backend.alignment = NTFS_WRITE_SECTOR_BYTES;
	test->backend.claim = claim;
	test->backend.unclaim = unclaim;
	test->backend.write = write_image;
	test->backend.persist = persist_image;
	test->time = TEST_FILETIME;
	volume = view(test);
	assert(ntfs_root(volume, &node) == NTFS_OK);
	assert(ntfs_node_stat(node, &metadata) == NTFS_OK && metadata.directory);
	test->root_reference = metadata.reference;
	ntfs_node_close(node);
	assert(ntfs_unmount(volume) == NTFS_OK);
	validate(test);
	open_owner(test);
	return test;
}

static struct test_case *
prepare(const char *directory)
{
	return prepare_image(directory, "source.img");
}

static void
finish(struct test_case *test)
{
	assert(!test->device.executing);
	ntfs_overwrite_close(test->owner);
	assert(!test->device.claimed && test->device.live_bytes == 0);
	free(test->device.visible);
	free(test->device.durable);
	free(test);
}

static struct ntfs_write_name
name(uint64_t parent, const char *text, uint16_t *units)
{
	size_t count, index;

	count = strlen(text);
	assert(count > 0 && count <= TEST_NAME_UNITS);
	for (index = 0; index < count; index++) {
		assert((unsigned char)text[index] < 0x80);
		units[index] = (uint16_t)(unsigned char)text[index];
	}
	return (struct ntfs_write_name){parent, units, count};
}

static uint64_t
mutation_reference(const struct ntfs_write_mutation_report *report)
{
#if defined(NTFS_TEST_MUTATION_PLAN)
	assert(!report->execution.completed && report->execution.writes == 0 &&
	    report->execution.barriers == 0 && !report->execution.poisoned);
#else
	assert(report->execution.completed && !report->execution.poisoned);
#endif
	return report->reference;
}

#if defined(NTFS_TEST_MUTATION_PLAN)
static struct {
	size_t programs, updates, inverse_prefixes, allocation_faults;
	size_t original_file_slots, original_index_buffers, unowned_file_signatures,
	    unowned_index_signatures, unused_mapped_index_buffers;
} program_checks;

static void
verify_predecessors(struct test_case *test, const struct ntfs_write_mutation_plan *plan)
{
	struct ntfs_volume *volume;
	struct ntfs_node *mft = NULL, *node = NULL;
	struct ntfs_stream *mft_bitmap = NULL, *allocation = NULL, *bitmap = NULL;
	struct ntfs_write_mutation_region region;
	const struct ntfs_run *run;
	uint8_t bit, expected;
	uint64_t number, vcn, logical, physical;
	size_t index, slot, offset;
	enum ntfs_result result;
	bool owned;

	/* Use the unchanged input's immutable reader, independent of the mutation
	 * owner's projected maps, bitmaps and predecessor implementation. */
	volume = view(test);
	assert(ntfs_node_by_number(volume, NTFS_MFT_RECORD, &mft) == NTFS_OK);
	assert(ntfs_attribute_open(mft, NTFS_ATTR_BITMAP, NULL, 0, &mft_bitmap) == NTFS_OK);
	for (index = 0; index < ntfs_write_mutation_plan_count(plan); index++) {
		assert(ntfs_write_mutation_plan_region(plan, index, &region) == NTFS_OK);
		expected = 0;
		owned = false;
		if (region.kind == NTFS_WRITE_MUTATION_FILE) {
			for (slot = 0; slot < region.bytes / NTFS_WRITE_RECORD_BYTES; slot++) {
				offset = slot * NTFS_WRITE_RECORD_BYTES;
				logical = region.target.logical_offset + offset;
				if (memcmp(region.before + offset, "FILE",
					sizeof(((struct ntfs_disk_mst *)0)->magic)) != 0) {
					continue;
				}
				if (!ntfs_bounds(logical, NTFS_WRITE_RECORD_BYTES,
					volume->mft->initialized)) {
					program_checks.unowned_file_signatures++;
					continue;
				}
				if (region.target.mirror) {
					physical =
					    volume->mirror_lcn * NTFS_WRITE_CLUSTER_BYTES + logical;
				} else {
					vcn = logical / NTFS_WRITE_CLUSTER_BYTES;
					run = ntfs_run_find(volume->mft, vcn);
					assert(run != NULL && run->lcn != NTFS_HOLE);
					physical =
					    (run->lcn + vcn - run->vcn) * NTFS_WRITE_CLUSTER_BYTES +
					    logical % NTFS_WRITE_CLUSTER_BYTES;
				}
				assert(physical == region.physical + offset);
				number = logical / NTFS_WRITE_RECORD_BYTES;
				assert(ntfs_stream_exact(mft_bitmap, number / NTFS_BITS_PER_BYTE,
					   &bit, sizeof(bit)) == NTFS_OK);
				if ((bit & (1u << (number % NTFS_BITS_PER_BYTE))) == 0) {
					program_checks.unowned_file_signatures++;
					continue;
				}
				expected |= (uint8_t)(1u << slot);
				program_checks.original_file_slots++;
			}
		} else if (region.kind == NTFS_WRITE_MUTATION_INDEX) {
			number = region.target.reference & NTFS_REFERENCE_RECORD_MASK;
			bit = 0;
			if (number / NTFS_BITS_PER_BYTE < mft_bitmap->size) {
				assert(ntfs_stream_exact(mft_bitmap, number / NTFS_BITS_PER_BYTE,
					   &bit, sizeof(bit)) == NTFS_OK);
			}
			if ((bit & (1u << (number % NTFS_BITS_PER_BYTE))) != 0) {
				assert(ntfs_node_open(volume, region.target.reference, &node) ==
				    NTFS_OK);
				result = ntfs_attribute_open(node, NTFS_ATTR_INDEX_ALLOCATION,
				    region.target.name, region.target.name_count, &allocation);
				assert(result == NTFS_OK || result == NTFS_NOT_FOUND);
				if (allocation != NULL &&
				    ntfs_bounds(region.target.logical_offset, region.bytes,
					allocation->initialized)) {
					vcn =
					    region.target.logical_offset / NTFS_WRITE_CLUSTER_BYTES;
					assert(ntfs_attribute_open(node, NTFS_ATTR_BITMAP,
						   region.target.name, region.target.name_count,
						   &bitmap) == NTFS_OK);
					assert(ntfs_stream_exact(bitmap, vcn / NTFS_BITS_PER_BYTE,
						   &bit, sizeof(bit)) == NTFS_OK);
					owned = (bit & (1u << (vcn % NTFS_BITS_PER_BYTE))) != 0;
					run = ntfs_run_find(allocation, vcn);
					assert(run != NULL && run->lcn != NTFS_HOLE);
					physical =
					    (run->lcn + vcn - run->vcn) * NTFS_WRITE_CLUSTER_BYTES;
					assert(physical == region.physical);
					if (!owned) {
						program_checks.unused_mapped_index_buffers++;
					}
				}
				ntfs_stream_close(bitmap);
				ntfs_stream_close(allocation);
				ntfs_node_close(node);
				bitmap = allocation = NULL;
				node = NULL;
			}
			if (owned) {
				program_checks.original_index_buffers++;
			} else if (memcmp(region.before, "INDX",
				       sizeof(((struct ntfs_disk_mst *)0)->magic)) == 0) {
				program_checks.unowned_index_signatures++;
			}
		}
		assert(region.predecessor.file_slots == expected);
		assert(region.predecessor.index_allocated == owned);
	}
	ntfs_stream_close(mft_bitmap);
	ntfs_node_close(mft);
	assert(ntfs_unmount(volume) == NTFS_OK);
}

static void
program_logical(const struct ntfs_write_mutation_region *region, const void *source, void *out)
{
	uint8_t *bytes = out;
	size_t offset;

	memcpy(out, source, region->bytes);
	if (region->kind == NTFS_WRITE_MUTATION_FILE) {
		for (offset = 0; offset < region->bytes; offset += NTFS_WRITE_RECORD_BYTES) {
			if (((region->predecessor.file_slots &
				 (1u << (offset / NTFS_WRITE_RECORD_BYTES))) != 0 ||
				(source != region->before &&
				    memcmp(region->before + offset, region->after + offset,
					NTFS_WRITE_RECORD_BYTES) != 0)) &&
			    memcmp(bytes + offset, "FILE",
				sizeof(((struct ntfs_disk_mst *)0)->magic)) == 0) {
				assert(ntfs_record_decode(bytes + offset, NTFS_WRITE_RECORD_BYTES,
					   false) == NTFS_OK);
			}
		}
	} else if (region->kind == NTFS_WRITE_MUTATION_INDEX &&
	    (source != region->before || region->predecessor.index_allocated)) {
		assert(ntfs_fixup(bytes, region->bytes, "INDX") == NTFS_OK);
	}
}

static void
program_equal(const struct ntfs_write_mutation_region *region, const void *actual, bool undo)
{
	const uint8_t *bytes = actual;
	uint8_t *expected, *normalized;
	const struct ntfs_disk_mst *mst;
	struct ntfs_disk_record *header;
	size_t offset, first, count, end, span;

	expected = malloc(region->bytes);
	normalized = malloc(region->bytes);
	assert(expected != NULL && normalized != NULL);
	program_logical(region, undo ? region->before : region->after, expected);
	memcpy(normalized, actual, region->bytes);
	span = region->kind == NTFS_WRITE_MUTATION_FILE ? NTFS_WRITE_RECORD_BYTES : region->bytes;
	if (region->kind == NTFS_WRITE_MUTATION_FILE || region->kind == NTFS_WRITE_MUTATION_INDEX) {
		for (offset = 0; offset < region->bytes; offset += span) {
			mst = (const void *)(expected + offset);
			if (region->kind == NTFS_WRITE_MUTATION_FILE &&
			    (region->predecessor.file_slots &
				(1u << (offset / NTFS_WRITE_RECORD_BYTES))) == 0 &&
			    memcmp(region->before + offset, region->after + offset, span) == 0) {
				/* Untouched free storage stays raw, byte for byte. It has
				 * no logical FILE object whose LSN/USA can be normalized. */
				continue;
			}
			if (undo &&
			    (region->kind == NTFS_WRITE_MUTATION_FILE
				    ? (region->predecessor.file_slots &
					  (1u << (offset / NTFS_WRITE_RECORD_BYTES))) == 0
				    : !region->predecessor.index_allocated)) {
				/* A newly initialized unowned slot consumes a generation
				 * on rollback; no old FILE object or index was published. */
				if (undo && region->kind == NTFS_WRITE_MUTATION_INDEX) {
					memcpy(normalized + offset, expected + offset, span);
				} else if (undo && region->kind == NTFS_WRITE_MUTATION_FILE &&
				    memcmp(bytes + offset, expected + offset, span) != 0) {
					header = (void *)(normalized + offset);
					assert(ntfs_u16(header->flags) == 0);
					assert(ntfs_u16(header->sequence) != 0);
					assert(
					    memcmp(&header->mst, (uint8_t[sizeof(header->mst)]){0},
						sizeof(header->mst)) == 0);
					memcpy(normalized + offset, expected + offset, span);
				}
				continue;
			}
			first = ntfs_u16(mst->usa_offset);
			count = ntfs_u16(mst->usa_count);
			end = first + count * sizeof(uint16_t);
			assert(end <= span);
			memcpy(normalized + offset + first, expected + offset + first, end - first);
			memcpy(normalized + offset + offsetof(struct ntfs_disk_record, lsn),
			    expected + offset + offsetof(struct ntfs_disk_record, lsn),
			    sizeof(((struct ntfs_disk_record *)0)->lsn));
		}
	}
	if (memcmp(normalized, expected, region->bytes) != 0) {
		for (offset = 0; offset < region->bytes && normalized[offset] == expected[offset];
		    offset++) {
		}
		fprintf(stderr,
		    "program %s mismatch: kind=%u physical=%llu logical=%llu old-slots=%u "
		    "byte=%zu actual=%u expected=%u\n",
		    undo ? "inverse" : "forward", region->kind,
		    (unsigned long long)region->physical,
		    (unsigned long long)region->target.logical_offset,
		    region->predecessor.file_slots, offset, normalized[offset], expected[offset]);
	}
	assert(memcmp(normalized, expected, region->bytes) == 0);
	free(normalized);
	free(expected);
}

static struct ntfs_write_batch_pages_input
program_window(struct ntfs_logfile_client *client)
{
	struct ntfs_write_batch_pages_input input = {0};
	uint64_t floor;

	floor = (UINT64_C(1) << TEST_PROGRAM_OFFSET_BITS) |
	    (((NTFS_LFS_RESTART_PAGES + NTFS_LFS_LEGACY_TAIL_PAGES) * NTFS_WRITE_CLUSTER_BYTES +
		 NTFS_WRITE_LOG_DATA_OFFSET) >>
		NTFS_LFS_LSN_OFFSET_SHIFT);
	/* Use a named synthetic retained record. This descriptor proves no native
	 * source history; the independent placement suite owns physical goldens. */
	input.restart.file_bytes = input.restart.usable_bytes = TEST_PROGRAM_JOURNAL_BYTES;
	input.restart.circular_offset =
	    (NTFS_LFS_RESTART_PAGES + NTFS_LFS_LEGACY_TAIL_PAGES) * NTFS_WRITE_CLUSTER_BYTES;
	input.restart.system_page_bytes = input.restart.log_page_bytes = NTFS_WRITE_CLUSTER_BYTES;
	input.restart.sequence_bits = 64 - TEST_PROGRAM_OFFSET_BITS;
	input.restart.major = NTFS_LFS_MAJOR_LEGACY;
	input.restart.minor = NTFS_LFS_MINOR_LEGACY;
	input.restart.record_header_bytes = sizeof(struct ntfs_disk_log_record);
	input.restart.page_data_offset = NTFS_WRITE_LOG_DATA_OFFSET;
	input.restart.client_count = 1;
	input.restart.in_use_head = 0;
	input.restart.free_head = NTFS_LOGFILE_NO_CLIENT;
	input.floor_lsn = input.tail_lsn = floor;
	input.next_lsn = floor + (NTFS_WRITE_BOOTSTRAP_BYTES >> NTFS_LFS_LSN_OFFSET_SHIFT);
	*client = (struct ntfs_logfile_client){0};
	client->oldest_lsn = client->restart_lsn = floor;
	client->sequence = TEST_PROGRAM_CLIENT_SEQUENCE;
	client->previous = client->next = NTFS_LOGFILE_NO_CLIENT;
	client->name_length = sizeof("NTFS") - 1;
	client->name[0] = 'N';
	client->name[1] = 'T';
	client->name[2] = 'F';
	client->name[3] = 'S';
	return input;
}

static uint64_t
program_successor(const struct ntfs_write_batch_pages *pages, size_t ordinal,
    const struct ntfs_logfile_restart *restart)
{
	const struct ntfs_write_batch_page *page, *last = NULL;
	const struct ntfs_disk_log_page *header;
	struct ntfs_logfile_lsn first;
	uint64_t sequence, physical;
	size_t index, within;

	assert(ntfs_logfile_lsn_decode(
		   restart, ntfs_write_batch_pages_lsn(pages, ordinal), &first) == NTFS_OK);
	for (index = 0; index < ntfs_write_batch_pages_count(pages); index++) {
		page = ntfs_write_batch_pages_get(pages, index);
		if (page->packet == ordinal) {
			last = page;
		}
	}
	assert(last != NULL);
	header = (const void *)last->protected_bytes;
	within = ntfs_u16(header->next_record_offset);
	sequence = first.sequence + (last->offset < first.page_offset ? 1 : 0);
	physical = last->offset;
	if (within + sizeof(struct ntfs_disk_log_record) > NTFS_WRITE_CLUSTER_BYTES) {
		physical += NTFS_WRITE_CLUSTER_BYTES;
		if (physical == restart->usable_bytes) {
			physical = restart->circular_offset;
			sequence++;
		}
		within = NTFS_WRITE_LOG_DATA_OFFSET;
	}
	return (sequence << (64 - restart->sequence_bits)) |
	    ((physical + within) >> NTFS_LFS_LSN_OFFSET_SHIFT);
}

static void
program_page_faults(struct test_case *test, const struct ntfs_write_program *program,
    const struct ntfs_write_batch_pages *original, size_t prefix,
    const struct ntfs_logfile_client *client, const struct ntfs_write_batch_pages_input *input,
    const struct ntfs_write_batch_pages *expected)
{
	struct ntfs_write_batch_pages *pages = NULL;
	struct ntfs_logfile_client saved_client = *client;
	struct ntfs_write_batch_pages_input saved_input = *input;
	const struct ntfs_write_batch_page *actual, *golden;
	size_t fault, attempts, index, retained, reads;

	retained = test->device.live_bytes;
	reads = test->device.read_calls;
	test->device.allocations = 0;
	if (original == NULL) {
		assert(ntfs_write_program_pages_prepare(
			   &test->backend.reader, program, client, input, &pages) == NTFS_OK);
	} else {
		assert(ntfs_write_program_compensation_prepare(&test->backend.reader, program,
			   original, prefix, client, input, &pages) == NTFS_OK);
	}
	attempts = test->device.allocations;
	assert(attempts != 0);
	ntfs_write_batch_pages_close(pages);
	assert(test->device.live_bytes == retained);
	for (fault = 1; fault <= attempts; fault++) {
		test->device.allocations = 0;
		test->device.fail_allocation = fault;
		test->device.fault_triggered = false;
		pages = (void *)(uintptr_t)1;
		if (original == NULL) {
			assert(ntfs_write_program_pages_prepare(&test->backend.reader, program,
				   client, input, &pages) == NTFS_NO_MEMORY);
		} else {
			assert(
			    ntfs_write_program_compensation_prepare(&test->backend.reader, program,
				original, prefix, client, input, &pages) == NTFS_NO_MEMORY);
		}
		assert(pages == NULL && test->device.fault_triggered &&
		    test->device.live_bytes == retained);
		program_checks.allocation_faults++;
		test->device.fail_allocation = 0;
		if (original == NULL) {
			assert(ntfs_write_program_pages_prepare(&test->backend.reader, program,
				   client, input, &pages) == NTFS_OK);
		} else {
			assert(ntfs_write_program_compensation_prepare(&test->backend.reader,
				   program, original, prefix, client, input, &pages) == NTFS_OK);
		}
		assert(
		    ntfs_write_batch_pages_count(pages) == ntfs_write_batch_pages_count(expected) &&
		    ntfs_write_batch_pages_next_lsn(pages) ==
			ntfs_write_batch_pages_next_lsn(expected));
		for (index = 0; index < ntfs_write_batch_pages_count(pages); index++) {
			actual = ntfs_write_batch_pages_get(pages, index);
			golden = ntfs_write_batch_pages_get(expected, index);
			assert(actual->offset == golden->offset &&
			    actual->packet == golden->packet &&
			    memcmp(actual->protected_bytes, golden->protected_bytes,
				sizeof(actual->protected_bytes)) == 0);
		}
		ntfs_write_batch_pages_close(pages);
		assert(test->device.live_bytes == retained && test->device.read_calls == reads);
		assert(memcmp(client, &saved_client, sizeof(*client)) == 0 &&
		    memcmp(input, &saved_input, sizeof(*input)) == 0);
	}
}

static void
program_partial_inverse(struct test_case *test, const struct ntfs_write_program *program,
    const struct ntfs_write_batch_pages *pages, size_t opens, size_t prefix,
    const struct ntfs_logfile_client *client, const struct ntfs_write_batch_pages_input *input)
{
	struct ntfs_write_batch_pages *inverse = NULL;
	struct ntfs_write_batch_pages_input placement = *input;
	struct ntfs_write_mutation_region region;
	const struct ntfs_write_program_update *step;
	struct ntfs_logfile_record record;
	struct ntfs_logfile_update update, original;
	const uint8_t *payload;
	uint8_t *logical, *packet;
	size_t index, ordinal, bytes, regions, retained;
	uint64_t previous;

	regions = ntfs_write_program_regions(program);
	retained = test->device.live_bytes;
	logical = malloc(regions * NTFS_WRITE_CLUSTER_BYTES);
	packet = malloc(NTFS_WRITE_BATCH_MAX_PACKET_BYTES);
	assert(logical != NULL && packet != NULL);
	for (index = 0; index < regions; index++) {
		assert(ntfs_write_program_region(program, index, &region) == NTFS_OK);
		program_logical(&region, region.before, logical + index * NTFS_WRITE_CLUSTER_BYTES);
	}
	for (index = 0; index < prefix; index++) {
		step = ntfs_write_program_get(program, index);
		assert(ntfs_write_program_apply(program, index, false,
			   ntfs_write_batch_pages_lsn(pages, opens + index),
			   logical + step->region * NTFS_WRITE_CLUSTER_BYTES,
			   NTFS_WRITE_CLUSTER_BYTES) == NTFS_OK);
	}
	placement.tail_lsn = ntfs_write_batch_pages_lsn(pages, opens + prefix - 1);
	placement.next_lsn = program_successor(pages, opens + prefix - 1, &input->restart);
	assert(ntfs_write_program_compensation_prepare(&test->backend.reader, program, pages,
		   prefix, client, &placement, &inverse) == NTFS_OK);
	for (index = 0; index < prefix; index++) {
		ordinal = prefix - 1 - index;
		step = ntfs_write_program_get(program, ordinal);
		assert(ntfs_logfile_update_decode(
			   step->payload.data, step->payload.bytes, &original) == NTFS_OK);
		assert(ntfs_write_batch_pages_packet_copy(inverse, index, packet,
			   NTFS_WRITE_BATCH_MAX_PACKET_BYTES, &bytes) == NTFS_OK);
		assert(ntfs_logfile_record_decode(
			   packet, bytes, sizeof(struct ntfs_disk_log_record), &record) == NTFS_OK);
		payload = packet + record.data.offset;
		assert(ntfs_logfile_update_decode(payload, record.data.length, &update) == NTFS_OK);
		previous = index == 0 ? placement.tail_lsn
				      : ntfs_write_batch_pages_lsn(inverse, index - 1);
		assert(record.previous_lsn == previous &&
		    record.undo_next_lsn ==
			(ordinal == 0 ? 0
				      : ntfs_write_batch_pages_lsn(pages, opens + ordinal - 1)));
		assert(update.redo_operation == original.undo_operation &&
		    update.undo_operation == NTFS_LOG_OP_COMPENSATION &&
		    update.redo.length == original.undo.length && update.undo.length == 0 &&
		    memcmp(payload + update.redo.offset,
			(const uint8_t *)step->payload.data + original.undo.offset,
			original.undo.length) == 0);
		assert(ntfs_write_program_apply(program, ordinal, true,
			   ntfs_write_batch_pages_lsn(inverse, index),
			   logical + step->region * NTFS_WRITE_CLUSTER_BYTES,
			   NTFS_WRITE_CLUSTER_BYTES) == NTFS_OK);
	}
	for (index = 0; index < regions; index++) {
		assert(ntfs_write_program_region(program, index, &region) == NTFS_OK);
		if (!region.target.mirror && region.kind != NTFS_WRITE_MUTATION_DATA) {
			program_equal(&region, logical + index * NTFS_WRITE_CLUSTER_BYTES, true);
		}
	}
	ntfs_write_batch_pages_close(inverse);
	assert(test->device.live_bytes == retained);
	program_checks.inverse_prefixes++;
	free(packet);
	free(logical);
}

static void
program_binding_checks(struct test_case *test, const struct ntfs_write_program *program,
    const struct ntfs_write_batch_pages *pages, size_t prefix,
    const struct ntfs_logfile_client *client, const struct ntfs_write_batch_pages_input *input)
{
	struct ntfs_write_batch_pages *failed = (void *)(uintptr_t)1;
	struct ntfs_write_batch_pages_input placement = *input;
	struct ntfs_logfile_client changed = *client;
	const struct ntfs_write_batch_page *page;
	struct ntfs_disk_log_record *record;
	uint8_t *protected_bytes, *snapshot;
	size_t retained, reads;
	uint16_t sequence;

	retained = test->device.live_bytes;
	reads = test->device.read_calls;
	page = ntfs_write_batch_pages_get(pages, 0);
	assert(page != NULL);
	protected_bytes = (void *)page->protected_bytes;
	snapshot = malloc(NTFS_WRITE_CLUSTER_BYTES);
	assert(snapshot != NULL);
	memcpy(snapshot, protected_bytes, NTFS_WRITE_CLUSTER_BYTES);
	assert(ntfs_write_program_compensation_prepare(&test->backend.reader, program, pages,
		   prefix, client, input, (void *)protected_bytes) == NTFS_INVALID);
	assert(memcmp(snapshot, protected_bytes, NTFS_WRITE_CLUSTER_BYTES) == 0);
	placement.tail_lsn++;
	assert(ntfs_write_program_compensation_prepare(&test->backend.reader, program, pages,
		   prefix, client, &placement, &failed) == NTFS_STALE &&
	    failed == NULL);
	changed.sequence++;
	failed = (void *)(uintptr_t)1;
	assert(ntfs_write_program_compensation_prepare(&test->backend.reader, program, pages,
		   prefix, &changed, input, &failed) == NTFS_STALE &&
	    failed == NULL);
	record = (void *)(protected_bytes + NTFS_WRITE_LOG_DATA_OFFSET);
	sequence = ntfs_u16(record->client_sequence);
	ntfs_put_u16(record->client_sequence, (uint16_t)(sequence + 1u));
	failed = (void *)(uintptr_t)1;
	assert(ntfs_write_program_compensation_prepare(&test->backend.reader, program, pages,
		   prefix, client, input, &failed) == NTFS_STALE &&
	    failed == NULL);
	memcpy(protected_bytes, snapshot, NTFS_WRITE_CLUSTER_BYTES);
	protected_bytes[NTFS_MST_STRIDE - sizeof(uint16_t)] ^= 1;
	failed = (void *)(uintptr_t)1;
	assert(ntfs_write_program_compensation_prepare(&test->backend.reader, program, pages,
		   prefix, client, input, &failed) == NTFS_CORRUPT &&
	    failed == NULL);
	memcpy(protected_bytes, snapshot, NTFS_WRITE_CLUSTER_BYTES);
	assert(test->device.live_bytes == retained && test->device.read_calls == reads);
	free(snapshot);
}

static void
verify_program(struct test_case *test, const struct ntfs_write_mutation_plan *plan)
{
	struct ntfs_write_program *program = NULL, *failed;
	struct ntfs_write_batch_pages *pages = NULL, *compensation = NULL;
	struct ntfs_logfile_client client;
	struct ntfs_write_batch_pages_input input, inverse;
	struct ntfs_write_mutation_region region, primary, plan_region;
	const struct ntfs_write_program_update *step;
	struct ntfs_logfile_record record;
	struct ntfs_logfile_update update, original;
	const struct ntfs_disk_log_open_attribute *entry;
	const uint8_t *payload;
	uint8_t *logical, *packet, *saved;
	size_t regions, index, other, count, opens, ordinal, bytes, saved_bytes;
	size_t live, reads, allocations, fault;
	uint64_t previous;
	static bool faults_checked;
	bool check_page_faults = !faults_checked;

	verify_predecessors(test, plan);
	live = test->device.live_bytes;
	reads = test->device.read_calls;
	test->device.allocations = 0;
	assert(ntfs_write_program_prepare(&test->backend.reader, plan, &program) == NTFS_OK);
	allocations = test->device.allocations;
	assert(test->device.read_calls == reads);
	regions = ntfs_write_program_regions(program);
	count = ntfs_write_program_count(program);
	assert(regions == ntfs_write_mutation_plan_count(plan) && count != 0);
	if (!faults_checked) {
		size_t retained = test->device.live_bytes;

		for (fault = 1; fault <= allocations; fault++) {
			test->device.allocations = 0;
			test->device.fail_allocation = fault;
			test->device.fault_triggered = false;
			failed = (void *)(uintptr_t)1;
			assert(ntfs_write_program_prepare(&test->backend.reader, plan, &failed) ==
			    NTFS_NO_MEMORY);
			assert(failed == NULL && test->device.fault_triggered);
			assert(test->device.live_bytes == retained);
			program_checks.allocation_faults++;
			test->device.fail_allocation = 0;
			assert(ntfs_write_program_prepare(&test->backend.reader, plan, &failed) ==
			    NTFS_OK);
			assert(ntfs_write_program_count(failed) == count);
			ntfs_write_program_close(failed);
			assert(test->device.live_bytes == retained);
		}
		faults_checked = true;
	}
	logical = malloc(regions * NTFS_WRITE_CLUSTER_BYTES);
	packet = malloc(NTFS_WRITE_BATCH_MAX_PACKET_BYTES);
	saved = malloc(NTFS_WRITE_BATCH_MAX_PACKET_BYTES);
	assert(logical != NULL && packet != NULL && saved != NULL);
	for (index = 0; index < regions; index++) {
		assert(ntfs_write_program_region(program, index, &region) == NTFS_OK);
		program_logical(&region, region.before, logical + index * NTFS_WRITE_CLUSTER_BYTES);
		assert(ntfs_write_program_region(program, index, (void *)region.before) ==
		    NTFS_INVALID);
		assert(ntfs_write_mutation_plan_region(plan, index, &plan_region) == NTFS_OK);
		assert(ntfs_write_program_prepare(
			   &test->backend.reader, plan, (void *)plan_region.after) == NTFS_INVALID);
	}
	for (index = 0; index < count; index++) {
		step = ntfs_write_program_get(program, index);
		assert(step != NULL && step->region < regions);
		assert(ntfs_logfile_update_decode(
			   step->payload.data, step->payload.bytes, &update) == NTFS_OK);
		if (update.redo_operation == NTFS_LOG_OP_INITIALIZE_FILE_RECORD &&
		    update.undo_operation == NTFS_LOG_OP_INITIALIZE_FILE_RECORD) {
			/* Native ADDING admission excludes a real FILE initialization undo. */
			assert(step->record_flags == 0);
		} else if (update.redo_operation == NTFS_LOG_OP_INITIALIZE_FILE_RECORD &&
		    update.undo_operation == NTFS_LOG_OP_NOOP) {
			assert(step->record_flags == NTFS_LOGFILE_RECORD_ADDING);
		}
		assert(ntfs_write_program_region(program, step->region, &region) == NTFS_OK);
		assert(!region.target.mirror && region.kind != NTFS_WRITE_MUTATION_DATA);
		assert(update.lcn_count == 1);
		assert(ntfs_u64((const uint8_t *)step->payload.data + update.lcns.offset) *
			NTFS_WRITE_CLUSTER_BYTES ==
		    region.physical);
		assert(
		    update.target_vcn * NTFS_WRITE_CLUSTER_BYTES == region.target.logical_offset);
		assert(ntfs_write_program_apply(program, index, false, TEST_PROGRAM_LSN + index,
			   logical + step->region * NTFS_WRITE_CLUSTER_BYTES,
			   NTFS_WRITE_CLUSTER_BYTES) == NTFS_OK);
	}
	for (index = 0; index < regions; index++) {
		assert(ntfs_write_program_region(program, index, &region) == NTFS_OK);
		if (region.target.mirror) {
			for (other = 0; other < regions; other++) {
				assert(
				    ntfs_write_program_region(program, other, &primary) == NTFS_OK);
				if (!primary.target.mirror &&
				    primary.kind == NTFS_WRITE_MUTATION_FILE &&
				    primary.target.logical_offset == region.target.logical_offset) {
					break;
				}
			}
			assert(other < regions);
			memcpy(logical + index * NTFS_WRITE_CLUSTER_BYTES,
			    logical + other * NTFS_WRITE_CLUSTER_BYTES, NTFS_WRITE_CLUSTER_BYTES);
		}
		if (region.kind != NTFS_WRITE_MUTATION_DATA) {
			program_equal(&region, logical + index * NTFS_WRITE_CLUSTER_BYTES, false);
		}
	}
	input = program_window(&client);
	assert(ntfs_write_program_pages_prepare(
		   &test->backend.reader, program, &client, &input, &pages) == NTFS_OK);
	opens = 0;
	for (ordinal = 0;; ordinal++) {
		assert(ntfs_write_batch_pages_packet_copy(pages, ordinal, packet,
			   NTFS_WRITE_BATCH_MAX_PACKET_BYTES, &bytes) == NTFS_OK);
		assert(ntfs_logfile_record_decode(
			   packet, bytes, sizeof(struct ntfs_disk_log_record), &record) == NTFS_OK);
		payload = packet + record.data.offset;
		assert(ntfs_logfile_update_decode(payload, record.data.length, &update) == NTFS_OK);
		if (update.redo_operation != NTFS_LOG_OP_OPEN_NONRESIDENT_ATTRIBUTE) {
			break;
		}
		entry = (const void *)(payload + update.redo.offset);
		assert(update.target_attribute ==
		    NTFS_WRITE_MFT_KEY + opens * sizeof(struct ntfs_disk_log_open_attribute));
		assert(ntfs_u64(entry->open_lsn) ==
		    (opens == 0 ? input.tail_lsn : ntfs_write_batch_pages_lsn(pages, ordinal - 1)));
		assert(record.client_sequence == client.sequence && record.previous_lsn == 0 &&
		    record.undo_next_lsn == 0);
		opens++;
	}
	assert(opens != 0);
	if (check_page_faults) {
		program_page_faults(test, program, NULL, 0, &client, &input, pages);
	}
	for (index = 0; index < count; index++) {
		assert(ntfs_write_batch_pages_packet_copy(pages, opens + index, packet,
			   NTFS_WRITE_BATCH_MAX_PACKET_BYTES, &bytes) == NTFS_OK);
		assert(ntfs_logfile_record_decode(
			   packet, bytes, sizeof(struct ntfs_disk_log_record), &record) == NTFS_OK);
		step = ntfs_write_program_get(program, index);
		assert(record.data.length == step->payload.bytes);
		assert((record.flags & ~NTFS_LOGFILE_RECORD_MULTI_PAGE) == step->record_flags);
		assert(memcmp(packet + record.data.offset, step->payload.data,
			   step->payload.bytes) == 0);
		previous = index == 0 ? 0 : ntfs_write_batch_pages_lsn(pages, opens + index - 1);
		assert(record.previous_lsn == previous && record.undo_next_lsn == previous);
		assert(record.transaction == NTFS_WRITE_TRANSACTION_KEY);
	}
	step = ntfs_write_program_get(program, 0);
	saved_bytes = step->payload.bytes;
	memcpy(saved, step->payload.data, saved_bytes);
	inverse = input;
	inverse.tail_lsn = ntfs_write_batch_pages_lsn(pages, opens + count - 1);
	inverse.next_lsn = program_successor(pages, opens + count - 1, &input.restart);
	assert(ntfs_write_program_compensation_prepare(&test->backend.reader, program, pages, count,
		   &client, &inverse, &compensation) == NTFS_OK);
	if (check_page_faults) {
		program_page_faults(test, program, pages, count, &client, &inverse, compensation);
		program_binding_checks(test, program, pages, count, &client, &inverse);
	}
	for (index = 0; index < count; index++) {
		step = ntfs_write_program_get(program, count - 1 - index);
		assert(ntfs_logfile_update_decode(
			   step->payload.data, step->payload.bytes, &original) == NTFS_OK);
		assert(ntfs_write_batch_pages_packet_copy(compensation, index, packet,
			   NTFS_WRITE_BATCH_MAX_PACKET_BYTES, &bytes) == NTFS_OK);
		assert(ntfs_logfile_record_decode(
			   packet, bytes, sizeof(struct ntfs_disk_log_record), &record) == NTFS_OK);
		payload = packet + record.data.offset;
		assert(ntfs_logfile_update_decode(payload, record.data.length, &update) == NTFS_OK);
		assert(update.redo_operation == original.undo_operation &&
		    update.undo_operation == NTFS_LOG_OP_COMPENSATION);
		assert(update.redo.length == original.undo.length && update.undo.length == 0);
		assert(update.compensation_undo_bytes == original.undo.length);
		/* Native empty Noop redo requires DELETING even in a compensation. */
		assert((record.flags & ~NTFS_LOGFILE_RECORD_MULTI_PAGE) ==
		    (update.redo_operation == NTFS_LOG_OP_NOOP ? NTFS_LOGFILE_RECORD_DELETING : 0));
		assert(memcmp(payload + update.redo.offset,
			   (const uint8_t *)step->payload.data + original.undo.offset,
			   original.undo.length) == 0);
		previous = index == 0 ? inverse.tail_lsn
				      : ntfs_write_batch_pages_lsn(compensation, index - 1);
		assert(record.previous_lsn == previous);
		assert(record.undo_next_lsn ==
		    (count - 1 - index == 0
			    ? 0
			    : ntfs_write_batch_pages_lsn(pages, opens + count - 2 - index)));
		assert(ntfs_write_program_apply(program, count - 1 - index, true,
			   TEST_PROGRAM_LSN + count + index,
			   logical + step->region * NTFS_WRITE_CLUSTER_BYTES,
			   NTFS_WRITE_CLUSTER_BYTES) == NTFS_OK);
	}
	for (index = 0; index < regions; index++) {
		assert(ntfs_write_program_region(program, index, &region) == NTFS_OK);
		if (region.target.mirror || region.kind == NTFS_WRITE_MUTATION_DATA) {
			continue;
		}
		program_equal(&region, logical + index * NTFS_WRITE_CLUSTER_BYTES, true);
	}
	for (index = 1; index < count; index++) {
		step = ntfs_write_program_get(program, index - 1);
		assert(ntfs_logfile_update_decode(
			   step->payload.data, step->payload.bytes, &update) == NTFS_OK);
		if (check_page_faults || index == 1 || index == count / 2 || index == count - 1 ||
		    (update.redo_operation == NTFS_LOG_OP_INITIALIZE_FILE_RECORD &&
			update.undo_operation == NTFS_LOG_OP_NOOP)) {
			program_partial_inverse(
			    test, program, pages, opens, index, &client, &input);
		}
	}
	assert(test->device.read_calls == reads);
	assert(test->device.writes == 0 && test->device.barriers == 0);
	ntfs_write_program_close(program);
	assert(ntfs_write_batch_pages_packet_copy(
		   pages, opens, packet, NTFS_WRITE_BATCH_MAX_PACKET_BYTES, &bytes) == NTFS_OK);
	assert(ntfs_logfile_record_decode(
		   packet, bytes, sizeof(struct ntfs_disk_log_record), &record) == NTFS_OK);
	assert(record.data.length == saved_bytes &&
	    memcmp(packet + record.data.offset, saved, saved_bytes) == 0);
	ntfs_write_batch_pages_close(compensation);
	ntfs_write_batch_pages_close(pages);
	assert(test->device.live_bytes == live);
	program_checks.programs++;
	program_checks.updates += count;
	program_checks.inverse_prefixes++;
	free(saved);
	free(packet);
	free(logical);
}

static void
same_target(
    const struct ntfs_write_mutation_target *left, const struct ntfs_write_mutation_target *right)
{
	assert(left->reference == right->reference &&
	    left->logical_offset == right->logical_offset &&
	    left->attribute_type == right->attribute_type &&
	    left->name_count == right->name_count && left->mirror == right->mirror);
	assert(memcmp(left->name, right->name, sizeof(left->name)) == 0);
}

static void
verify_target(struct ntfs_volume *volume, const struct ntfs_write_mutation_region *region)
{
	static const uint16_t index_name[NTFS_WRITE_MUTATION_TARGET_NAME_UNITS] = {
	    '$', 'I', '3', '0'};
	const struct ntfs_write_mutation_target *target = &region->target;
	const struct ntfs_run *run;
	struct ntfs_node *node = NULL;
	struct ntfs_stream *stream = NULL;
	struct ntfs_attr_view attribute;
	uint64_t number, vcn, physical;
	size_t index;

	number = target->reference & NTFS_REFERENCE_RECORD_MASK;
	assert(target->reference >> NTFS_REFERENCE_SEQUENCE_SHIFT != 0);
	assert(target->logical_offset % NTFS_WRITE_CLUSTER_BYTES == 0);
	assert(
	    target->name_count == 0 || target->name_count == NTFS_WRITE_MUTATION_TARGET_NAME_UNITS);
	if (target->name_count != 0) {
		assert(memcmp(target->name, index_name, sizeof(index_name)) == 0);
	}
	for (index = target->name_count; index < NTFS_WRITE_MUTATION_TARGET_NAME_UNITS; index++) {
		assert(target->name[index] == 0);
	}
	assert(!target->mirror || region->kind == NTFS_WRITE_MUTATION_FILE);
	if (region->kind == NTFS_WRITE_MUTATION_FILE) {
		assert(number == NTFS_MFT_RECORD && target->attribute_type == NTFS_ATTRIBUTE_DATA &&
		    target->name_count == 0);
	} else if (region->kind == NTFS_WRITE_MUTATION_INDEX) {
		assert(target->attribute_type == NTFS_ATTR_INDEX_ALLOCATION &&
		    target->name_count == NTFS_WRITE_MUTATION_TARGET_NAME_UNITS);
	} else if (region->kind == NTFS_WRITE_MUTATION_BITMAP) {
		assert(
		    (number == NTFS_BITMAP_RECORD &&
			target->attribute_type == NTFS_ATTRIBUTE_DATA && target->name_count == 0) ||
		    (number == NTFS_MFT_RECORD && target->attribute_type == NTFS_ATTR_BITMAP &&
			target->name_count == 0) ||
		    (number >= NTFS_FIRST_USER_RECORD &&
			target->attribute_type == NTFS_ATTR_BITMAP &&
			target->name_count == NTFS_WRITE_MUTATION_TARGET_NAME_UNITS));
	} else {
		assert(region->kind == NTFS_WRITE_MUTATION_DATA &&
		    number >= NTFS_FIRST_USER_RECORD &&
		    target->attribute_type == NTFS_ATTRIBUTE_DATA && target->name_count == 0);
	}
	assert(ntfs_node_open(volume, target->reference, &node) == NTFS_OK);
	assert(ntfs_attr_find(node->record, NTFS_WRITE_RECORD_BYTES, target->attribute_type,
		   target->name, target->name_count, UINT16_MAX, &attribute) == NTFS_OK);
	assert(ntfs_stream_from_attr(volume, &attribute, &stream) == NTFS_OK);
	assert(!stream->resident && target->logical_offset < stream->allocated);
	vcn = target->logical_offset / NTFS_WRITE_CLUSTER_BYTES;
	run = ntfs_run_find(stream, vcn);
	assert(run != NULL && run->lcn != NTFS_HOLE);
	physical = target->mirror
	    ? volume->mirror_lcn * NTFS_WRITE_CLUSTER_BYTES + target->logical_offset
	    : (run->lcn + vcn - run->vcn) * NTFS_WRITE_CLUSTER_BYTES;
	assert(region->physical == physical);
	ntfs_stream_close(stream);
	ntfs_node_close(node);
}

static void
frame_guards(const uint8_t *before, const uint8_t *after, size_t bytes, const char *magic)
{
	uint8_t *mixed;
	size_t sector;
	unsigned mask, sectors = (unsigned)(bytes / NTFS_MST_STRIDE);

	assert(bytes == NTFS_WRITE_CLUSTER_BYTES || bytes == NTFS_WRITE_RECORD_BYTES);
	mixed = malloc(bytes);
	assert(mixed != NULL);
	memcpy(mixed, after, bytes);
	assert(ntfs_fixup(mixed, bytes, magic) == NTFS_OK);
	for (mask = 1; mask + 1 < (1u << sectors); mask++) {
		for (sector = 0; sector < sectors; sector++) {
			memcpy(mixed + sector * NTFS_MST_STRIDE,
			    ((mask & (1u << sector)) ? after : before) + sector * NTFS_MST_STRIDE,
			    NTFS_MST_STRIDE);
		}
		assert(ntfs_fixup(mixed, bytes, magic) == NTFS_CORRUPT);
	}
	free(mixed);
}

static void
verify_retirements(struct test_case *test, const struct ntfs_write_mutation_region *region)
{
	struct ntfs_write_mutation_region retirement = *region;
	struct ntfs_write_retirement_program *program = NULL;
	const struct ntfs_write_retirement_update *step;
	const struct ntfs_disk_record *before, *after;
	struct ntfs_disk_record *header;
	struct ntfs_logfile_update update;
	uint8_t *isolated, *logical, *wanted;
	size_t offset, count = 0, ordinal, live, reads, first, bytes;

	if (region->target.mirror) {
		return;
	}
	isolated = malloc(region->bytes);
	assert(isolated != NULL);
	memcpy(isolated, region->before, region->bytes);
	for (offset = 0; offset < region->bytes; offset += NTFS_WRITE_RECORD_BYTES) {
		before = (const void *)(region->before + offset);
		after = (const void *)(region->after + offset);
		if ((region->predecessor.file_slots & (1u << (offset / NTFS_WRITE_RECORD_BYTES))) !=
			0 &&
		    memcmp(before->mst.magic, "FILE", sizeof(before->mst.magic)) == 0 &&
		    (ntfs_u16(before->flags) & NTFS_RECORD_IN_USE) != 0 &&
		    ntfs_u16(after->flags) == 0) {
			memcpy(isolated + offset, after, NTFS_WRITE_RECORD_BYTES);
			count++;
		}
	}
	if (count == 0) {
		free(isolated);
		return;
	}
	/* Parent/neighbor FILE updates remain part of the complete ordinary plan.
	 * Isolate this operation family to check its emitted snapshot and inverse;
	 * this test does not manufacture a complete cross-object native transaction. */
	retirement.after = isolated;
	live = test->device.live_bytes;
	reads = test->device.read_calls;
	assert(ntfs_write_retirement_program_prepare(
		   &test->backend.reader, &retirement, NTFS_WRITE_MFT_KEY, &program) == NTFS_OK);
	assert(ntfs_write_retirement_program_count(program) == 2 * count);
	logical = malloc(NTFS_WRITE_RECORD_BYTES);
	wanted = malloc(NTFS_WRITE_RECORD_BYTES);
	assert(logical != NULL && wanted != NULL);
	for (ordinal = 1; ordinal < 2 * count; ordinal += 2) {
		step = ntfs_write_retirement_program_get(program, ordinal);
		assert(step != NULL &&
		    ntfs_logfile_update_decode(step->payload.data, step->payload.bytes, &update) ==
			NTFS_OK);
		offset = (size_t)update.cluster_index * NTFS_WRITE_SECTOR_BYTES;
		memcpy(logical, region->before + offset, NTFS_WRITE_RECORD_BYTES);
		memcpy(wanted, region->after + offset, NTFS_WRITE_RECORD_BYTES);
		assert(ntfs_record_decode(logical, NTFS_WRITE_RECORD_BYTES, false) == NTFS_OK);
		assert(ntfs_record_decode(wanted, NTFS_WRITE_RECORD_BYTES, false) == NTFS_OK);
		header = (void *)wanted;
		ntfs_put_u64(header->lsn, TEST_RETIREMENT_REDO_LSN);
		first = ntfs_u16(header->mst.usa_offset);
		bytes = (size_t)ntfs_u16(header->mst.usa_count) * NTFS_MST_WORD_BYTES;
		memcpy(wanted + first, logical + first, bytes);
		assert(ntfs_write_retirement_apply(step->payload.data, step->payload.bytes, false,
			   TEST_RETIREMENT_REDO_LSN, logical, NTFS_WRITE_RECORD_BYTES) == NTFS_OK);
		assert(memcmp(logical, wanted, NTFS_WRITE_RECORD_BYTES) == 0);
		memcpy(wanted, region->before + offset, NTFS_WRITE_RECORD_BYTES);
		assert(ntfs_record_decode(wanted, NTFS_WRITE_RECORD_BYTES, false) == NTFS_OK);
		header = (void *)wanted;
		ntfs_put_u64(header->lsn, TEST_RETIREMENT_UNDO_LSN);
		assert(ntfs_write_retirement_apply(step->payload.data, step->payload.bytes, true,
			   TEST_RETIREMENT_UNDO_LSN, logical, NTFS_WRITE_RECORD_BYTES) == NTFS_OK);
		assert(memcmp(logical, wanted, NTFS_WRITE_RECORD_BYTES) == 0);
	}
	free(logical);
	free(wanted);
	free(isolated);
	ntfs_write_retirement_program_close(program);
	assert(test->device.live_bytes == live && test->device.read_calls == reads);
}

static void
same_plan(
    const struct ntfs_write_mutation_plan *expected, const struct ntfs_write_mutation_plan *actual)
{
	struct ntfs_write_mutation_region left, right;
	size_t index;

	assert(ntfs_write_mutation_plan_reference(expected) ==
	    ntfs_write_mutation_plan_reference(actual));
	assert(ntfs_write_mutation_plan_count(expected) == ntfs_write_mutation_plan_count(actual));
	for (index = 0; index < ntfs_write_mutation_plan_count(expected); index++) {
		assert(ntfs_write_mutation_plan_region(expected, index, &left) == NTFS_OK);
		assert(ntfs_write_mutation_plan_region(actual, index, &right) == NTFS_OK);
		assert(left.physical == right.physical && left.kind == right.kind &&
		    left.bytes == right.bytes &&
		    left.predecessor.file_slots == right.predecessor.file_slots &&
		    left.predecessor.index_allocated == right.predecessor.index_allocated);
		same_target(&left.target, &right.target);
		assert(memcmp(left.before, right.before, left.bytes) == 0);
		assert(memcmp(left.after, right.after, left.bytes) == 0);
	}
}

static void
fault_request(struct test_case *test, const struct ntfs_write_mutation_request *request)
{
	struct ntfs_write_mutation_plan *expected = NULL, *actual;
	struct test_device *device = &test->device;
	uint8_t *source;
	struct ntfs_write_mutation_region region;
	size_t allocations, reads, live, index, pass;
	enum ntfs_result result;

	source = malloc(device->bytes);
	assert(source != NULL && device->live_bytes == 0);
	memcpy(source, device->visible, device->bytes);
	device->allocations = 0;
	device->read_calls = 0;
	assert(ntfs_write_mutation_prepare(&test->backend.reader, request, &expected) == NTFS_OK);
	allocations = device->allocations;
	reads = device->read_calls;
	live = device->live_bytes;
	assert(allocations != 0 && reads != 0);
	assert(ntfs_write_mutation_plan_count(expected) != 0);
	assert(ntfs_write_mutation_plan_region(expected, 0, &region) == NTFS_OK);
	assert(ntfs_write_mutation_plan_region(expected, 0, (void *)region.before) == NTFS_INVALID);
	assert(ntfs_write_mutation_plan_region(expected, 0, (void *)region.after) == NTFS_INVALID);
	assert(ntfs_write_mutation_plan_view(expected, (void *)region.before) == NTFS_INVALID);
	assert(ntfs_write_mutation_plan_view(expected, (void *)region.after) == NTFS_INVALID);
	assert(memcmp(source + region.physical, region.before, region.bytes) == 0);
	for (pass = 0; pass < 2; pass++) {
		for (index = 1; index <= (pass == 0 ? allocations : reads); index++) {
			actual = (void *)(uintptr_t)1;
			device->allocations = 0;
			device->read_calls = 0;
			device->fault_triggered = false;
			device->fail_allocation = pass == 0 ? index : 0;
			device->fail_read = pass == 1 ? index : 0;
			result =
			    ntfs_write_mutation_prepare(&test->backend.reader, request, &actual);
			assert(device->fault_triggered);
			assert(result == (pass == 0 ? NTFS_NO_MEMORY : NTFS_IO));
			assert(actual == NULL && device->live_bytes == live);
			assert(device->writes == 0 && device->barriers == 0);
			assert(memcmp(source, device->visible, device->bytes) == 0);
			device->fail_allocation = 0;
			device->fail_read = 0;
			assert(ntfs_write_mutation_prepare(
				   &test->backend.reader, request, &actual) == NTFS_OK);
			same_plan(expected, actual);
			ntfs_write_mutation_plan_close(actual);
			assert(device->live_bytes == live);
		}
	}
	ntfs_write_mutation_plan_close(expected);
	assert(device->live_bytes == 0 && memcmp(source, device->visible, device->bytes) == 0);
	free(source);
}
#endif

static enum ntfs_result
mutate(struct test_case *test, const struct ntfs_write_mutation_request *request,
    struct ntfs_write_mutation_report *report)
{
#if defined(NTFS_TEST_MUTATION_PLAN)
	struct ntfs_write_mutation_plan *plan = NULL;
	struct ntfs_write_mutation_region region;
	struct ntfs_environment projected;
	struct ntfs_validation_report *validation;
	struct ntfs_volume *volume = NULL;
	struct ntfs_limits limits;
	uint8_t *before;
	size_t index, offset;
	enum ntfs_result result;
	static bool index_guard_checked;

	before = malloc(test->device.bytes);
	assert(before != NULL);
	memcpy(before, test->device.visible, test->device.bytes);
	memset(report, 0, sizeof(*report));
	result = ntfs_write_mutation_prepare(&test->backend.reader, request, &plan);
	assert(memcmp(before, test->device.visible, test->device.bytes) == 0);
	assert(test->device.writes == 0 && test->device.barriers == 0);
	if (result == NTFS_OK) {
		assert(plan != NULL);
		assert(ntfs_write_mutation_plan_view(plan, &projected) == NTFS_OK);
		validation = calloc(1, sizeof(*validation));
		assert(validation != NULL);
		assert(ntfs_validate(&projected, NULL, NULL, validation) == NTFS_OK);
		assert(validation->complete);
		free(validation);
		ntfs_default_limits(&limits);
		limits.record_cache_entries = 0;
		assert(ntfs_mount(&projected, &limits, &volume) == NTFS_OK);
		verify_program(test, plan);
		report->reference = ntfs_write_mutation_plan_reference(plan);
		report->requested_bytes = request->bytes;
		/* The semantic oracle publishes private planned bytes in test memory.
		 * It does not call a writer, journal, persistence or recovery executor. */
		for (index = 0; index < ntfs_write_mutation_plan_count(plan); index++) {
			assert(ntfs_write_mutation_plan_region(plan, index, &region) == NTFS_OK);
			assert(region.bytes > 0 && region.physical <= test->device.bytes &&
			    region.bytes <= test->device.bytes - region.physical);
			assert(memcmp(before + region.physical, region.before, region.bytes) == 0);
			verify_target(volume, &region);
			if (region.kind == NTFS_WRITE_MUTATION_BITMAP) {
				struct ntfs_write_bitmap_program *program = NULL;
				const struct ntfs_logfile_buffer *payload;
				uint8_t *bitmap;
				size_t step, live, reads;

				live = test->device.live_bytes;
				reads = test->device.read_calls;
				/* This pure test key describes a modern OAT coordinate;
				 * no actual OAT/history binding or recovery is implied. */
				assert(ntfs_write_bitmap_program_prepare(&test->backend.reader,
					   &region, NTFS_WRITE_MFT_KEY, &program) == NTFS_OK);
				bitmap = malloc(region.bytes);
				assert(bitmap != NULL);
				memcpy(bitmap, region.before, region.bytes);
				for (step = 0; step < ntfs_write_bitmap_program_count(program);
				    step++) {
					payload = ntfs_write_bitmap_program_get(program, step);
					assert(
					    ntfs_write_bitmap_apply(payload->data, payload->bytes,
						false, bitmap, region.bytes) == NTFS_OK);
				}
				assert(memcmp(bitmap, region.after, region.bytes) == 0);
				for (step = ntfs_write_bitmap_program_count(program); step != 0;
				    step--) {
					payload = ntfs_write_bitmap_program_get(program, step - 1);
					assert(
					    ntfs_write_bitmap_apply(payload->data, payload->bytes,
						true, bitmap, region.bytes) == NTFS_OK);
				}
				assert(memcmp(bitmap, region.before, region.bytes) == 0);
				free(bitmap);
				ntfs_write_bitmap_program_close(program);
				assert(test->device.live_bytes == live &&
				    test->device.read_calls == reads);
			}
			if (region.kind == NTFS_WRITE_MUTATION_INDEX && !index_guard_checked) {
				frame_guards(region.before, region.after, region.bytes, "INDX");
				index_guard_checked = true;
			}
			if (region.kind == NTFS_WRITE_MUTATION_FILE) {
				verify_retirements(test, &region);
				for (offset = 0; offset < region.bytes;
				    offset += NTFS_WRITE_RECORD_BYTES) {
					if (memcmp(region.before + offset, region.after + offset,
						NTFS_WRITE_RECORD_BYTES) != 0) {
						frame_guards(region.before + offset,
						    region.after + offset, NTFS_WRITE_RECORD_BYTES,
						    "FILE");
					}
				}
			}
		}
		assert(ntfs_unmount(volume) == NTFS_OK);
		for (index = 0; index < ntfs_write_mutation_plan_count(plan); index++) {
			assert(ntfs_write_mutation_plan_region(plan, index, &region) == NTFS_OK);
			memcpy(test->device.visible + region.physical, region.after, region.bytes);
		}
		memcpy(test->device.durable, test->device.visible, test->device.bytes);
	} else {
		assert(plan == NULL);
	}
	ntfs_write_mutation_plan_close(plan);
	free(before);
	return result;
#else
	switch (request->kind) {
	case NTFS_WRITE_CREATE_FILE:
		return ntfs_write_create_file(
		    test->owner, &request->source, request->filetime, report);
	case NTFS_WRITE_CREATE_DIRECTORY:
		return ntfs_write_create_directory(
		    test->owner, &request->source, request->filetime, report);
	case NTFS_WRITE_RESIZE_FILE:
		return ntfs_write_resize_file(
		    test->owner, request->reference, request->size, request->filetime, report);
	case NTFS_WRITE_GROWING_RANGE:
		return ntfs_write_growing_range(test->owner, request->reference, request->offset,
		    request->data, request->bytes, request->filetime, report);
	case NTFS_WRITE_REMOVE_FILE:
		return ntfs_write_remove_file(
		    test->owner, &request->source, request->filetime, report);
	case NTFS_WRITE_REMOVE_DIRECTORY:
		return ntfs_write_remove_directory(
		    test->owner, &request->source, request->filetime, report);
	case NTFS_WRITE_RENAME:
		return ntfs_write_rename(test->owner, &request->source, &request->destination,
		    request->replace, request->filetime, report);
	case NTFS_WRITE_SET_TIMES:
		return NTFS_UNSUPPORTED;
	}
	return NTFS_INVALID;
#endif
}

static uint64_t
create(struct test_case *test, uint64_t parent, const char *text, bool directory)
{
	struct ntfs_write_mutation_report report;
	struct ntfs_write_mutation_request request = {0};
	uint16_t units[TEST_NAME_UNITS];
	enum ntfs_result result;

	request.source = name(parent, text, units);
	test->time++;
	request.kind = directory ? NTFS_WRITE_CREATE_DIRECTORY : NTFS_WRITE_CREATE_FILE;
	request.filetime = test->time;
	result = mutate(test, &request, &report);
	test->device.executing = false;
	if (result != NTFS_OK) {
		fprintf(stderr, "create %s: %s\n", text, ntfs_result_string(result));
	}
	assert(result == NTFS_OK && mutation_reference(&report) != 0);
	assert(memcmp(test->device.visible, test->device.durable, test->device.bytes) == 0);
	return report.reference;
}

static void
check_name(struct test_case *test, uint64_t parent, const char *text, uint64_t reference,
    enum ntfs_result expected)
{
	struct ntfs_volume *volume;
	struct ntfs_node *parent_node = NULL, *child = NULL;
	struct ntfs_stat metadata;
	struct ntfs_write_name entry;
	uint16_t units[TEST_NAME_UNITS];
	enum ntfs_result result;

	entry = name(parent, text, units);
	volume = view(test);
	assert(ntfs_node_open(volume, parent, &parent_node) == NTFS_OK);
	result = ntfs_lookup(parent_node, entry.units, entry.count, &child);
	assert(result == expected);
	if (result == NTFS_OK) {
		assert(
		    ntfs_node_stat(child, &metadata) == NTFS_OK && metadata.reference == reference);
	} else {
		assert(child == NULL);
	}
	ntfs_node_close(child);
	ntfs_node_close(parent_node);
	assert(ntfs_unmount(volume) == NTFS_OK);
}

static void
check_unpaired_name(struct test_case *test, uint64_t parent, const char *text, uint64_t reference)
{
	struct ntfs_volume *volume;
	struct ntfs_node *parent_node = NULL, *child = NULL;
	struct ntfs_write_name entry;
	struct ntfs_dirent stored;
	struct ntfs_link_counts counts;
	struct ntfs_attr_view attribute;
	const struct ntfs_disk_filename *filename;
	const struct ntfs_disk_resident *resident;
	const uint8_t *value;
	uint16_t units[TEST_NAME_UNITS];
	size_t bytes, index;

	entry = name(parent, text, units);
	volume = view(test);
	assert(ntfs_node_open(volume, parent, &parent_node) == NTFS_OK);
	assert(
	    ntfs_lookup_entry(parent_node, entry.units, entry.count, &child, &stored) == NTFS_OK);
	assert(stored.reference == reference && stored.parent_reference == parent &&
	    stored.name_namespace == NTFS_NAMESPACE_POSIX && stored.name_length == entry.count);
	assert(ntfs_node_link_counts(child, &counts) == NTFS_OK);
	assert(counts.physical_names == 1 && counts.primary_names == 1 && counts.dos_aliases == 0);
	assert(ntfs_attr_find(child->record, NTFS_WRITE_RECORD_BYTES, NTFS_ATTR_FILENAME, NULL, 0,
		   UINT16_MAX, &attribute) == NTFS_OK);
	assert(ntfs_attr_value(&attribute, &value, &bytes) == NTFS_OK);
	assert(bytes == sizeof(*filename) + entry.count * NTFS_UTF16_UNIT_BYTES);
	filename = (const void *)value;
	resident = (const void *)(attribute.bytes + sizeof(struct ntfs_disk_attr));
	assert(resident->indexed == 1 && filename->name_namespace == NTFS_NAMESPACE_POSIX &&
	    filename->length == entry.count && ntfs_u64(filename->parent) == parent);
	for (index = 0; index < entry.count; index++) {
		assert(stored.name[index] == entry.units[index]);
		assert(ntfs_u16(value + sizeof(*filename) + index * NTFS_UTF16_UNIT_BYTES) ==
		    entry.units[index]);
	}
	ntfs_node_close(child);
	ntfs_node_close(parent_node);
	assert(ntfs_unmount(volume) == NTFS_OK);
}

static void
check_data(struct test_case *test, uint64_t reference, const char *directory, const char *file)
{
	struct ntfs_volume *volume;
	struct ntfs_node *node = NULL;
	struct ntfs_stream *stream = NULL;
	struct ntfs_stat metadata;
	uint8_t *wanted, *actual;
	size_t bytes, read;

	wanted = load(directory, file, &bytes);
	actual = malloc(bytes == 0 ? 1 : bytes);
	assert(actual != NULL);
	volume = view(test);
	assert(ntfs_node_open(volume, reference, &node) == NTFS_OK);
	assert(ntfs_node_stat(node, &metadata) == NTFS_OK && !metadata.directory &&
	    metadata.size == bytes);
	assert(ntfs_stream_open(node, NULL, 0, &stream) == NTFS_OK);
	assert(ntfs_stream_size(stream) == bytes);
	assert(ntfs_stream_read(stream, 0, actual, bytes, &read) == NTFS_OK && read == bytes);
	assert(memcmp(wanted, actual, bytes) == 0);
	ntfs_stream_close(stream);
	ntfs_node_close(node);
	assert(ntfs_unmount(volume) == NTFS_OK);
	free(actual);
	free(wanted);
}

static void
check_security(struct test_case *test, uint64_t reference, const char *directory, const char *file)
{
	struct ntfs_volume *volume;
	struct ntfs_node *node = NULL;
	struct ntfs_security *security = NULL;
	uint8_t *wanted, *actual;
	size_t bytes, copied;

	wanted = load(directory, file, &bytes);
	actual = malloc(bytes);
	assert(actual != NULL);
	volume = view(test);
	assert(ntfs_node_open(volume, reference, &node) == NTFS_OK);
	assert(ntfs_security_open(node, &security) == NTFS_OK);
	assert(ntfs_security_size(security) == bytes);
	assert(ntfs_security_copy(security, actual, bytes, &copied) == NTFS_OK && copied == bytes);
	assert(memcmp(wanted, actual, bytes) == 0);
	ntfs_security_close(security);
	ntfs_node_close(node);
	assert(ntfs_unmount(volume) == NTFS_OK);
	free(actual);
	free(wanted);
}

static void
check_stale(struct test_case *test, uint64_t reference)
{
	struct ntfs_volume *volume;
	struct ntfs_node *node = NULL;
	enum ntfs_result result;

	volume = view(test);
	result = ntfs_node_open(volume, reference, &node);
	assert((result == NTFS_STALE || result == NTFS_NOT_FOUND) && node == NULL);
	assert(ntfs_unmount(volume) == NTFS_OK);
}

static void
resize(struct test_case *test, uint64_t reference, uint64_t bytes)
{
	struct ntfs_write_mutation_report report;
	struct ntfs_write_mutation_request request = {0};
	enum ntfs_result result;

	test->time++;
	request.kind = NTFS_WRITE_RESIZE_FILE;
	request.reference = reference;
	request.size = bytes;
	request.filetime = test->time;
	result = mutate(test, &request, &report);
	test->device.executing = false;
	assert(result == NTFS_OK && mutation_reference(&report) == reference);
	assert(memcmp(test->device.visible, test->device.durable, test->device.bytes) == 0);
}

static void
write_data(
    struct test_case *test, uint64_t reference, uint64_t offset, const uint8_t *data, size_t bytes)
{
	struct ntfs_write_mutation_report report;
	struct ntfs_write_mutation_request request = {0};
	enum ntfs_result result;

	test->time++;
	request.kind = NTFS_WRITE_GROWING_RANGE;
	request.reference = reference;
	request.offset = offset;
	request.data = data;
	request.bytes = bytes;
	request.filetime = test->time;
	result = mutate(test, &request, &report);
	test->device.executing = false;
	assert(result == NTFS_OK && mutation_reference(&report) == reference);
	assert(report.requested_bytes == bytes);
#if !defined(NTFS_TEST_MUTATION_PLAN)
	assert(report.completed_bytes == bytes);
#endif
	assert(memcmp(test->device.visible, test->device.durable, test->device.bytes) == 0);
}

static void
remove_entry(struct test_case *test, uint64_t parent, const char *text, bool directory,
    enum ntfs_result expected)
{
	struct ntfs_write_mutation_report report;
	struct ntfs_write_mutation_request request = {0};
	uint16_t units[TEST_NAME_UNITS];
	uint8_t *before;
	enum ntfs_result result;

	request.source = name(parent, text, units);
	before = malloc(test->device.bytes);
	assert(before != NULL);
	memcpy(before, test->device.visible, test->device.bytes);
	test->time++;
	request.kind = directory ? NTFS_WRITE_REMOVE_DIRECTORY : NTFS_WRITE_REMOVE_FILE;
	request.filetime = test->time;
	result = mutate(test, &request, &report);
	test->device.executing = false;
	assert(result == expected);
	if (result == NTFS_OK) {
		assert(mutation_reference(&report) != 0);
	} else {
		assert(memcmp(before, test->device.visible, test->device.bytes) == 0);
	}
	assert(memcmp(test->device.visible, test->device.durable, test->device.bytes) == 0);
	free(before);
}

static void
rename_entry(struct test_case *test, uint64_t source_parent, const char *source,
    uint64_t destination_parent, const char *destination, bool replace_existing,
    enum ntfs_result expected)
{
	struct ntfs_write_mutation_report report;
	struct ntfs_write_mutation_request request = {0};
	uint16_t source_units[TEST_NAME_UNITS], destination_units[TEST_NAME_UNITS];
	uint8_t *before;
	enum ntfs_result result;

	request.source = name(source_parent, source, source_units);
	request.destination = name(destination_parent, destination, destination_units);
	before = malloc(test->device.bytes);
	assert(before != NULL);
	memcpy(before, test->device.visible, test->device.bytes);
	test->time++;
	request.kind = NTFS_WRITE_RENAME;
	request.replace = replace_existing;
	request.filetime = test->time;
	result = mutate(test, &request, &report);
	test->device.executing = false;
	assert(result == expected);
	if (result == NTFS_OK) {
		assert(mutation_reference(&report) != 0);
	} else {
		assert(memcmp(before, test->device.visible, test->device.bytes) == 0);
	}
	assert(memcmp(test->device.visible, test->device.durable, test->device.bytes) == 0);
	free(before);
}

static void
mixed_operations(const char *source, const char *cases)
{
	struct test_case *test;
	uint8_t *payload, *replacement;
	size_t bytes, replacement_bytes;
	uint64_t left, right, alpha, victim, created;

	test = prepare(source);
	left = create(test, test->root_reference, "mutation-left", true);
	right = create(test, test->root_reference, "mutation-right", true);
	alpha = create(test, left, "alpha.txt", false);
	check_unpaired_name(test, test->root_reference, "mutation-left", left);
	check_unpaired_name(test, test->root_reference, "mutation-right", right);
	check_unpaired_name(test, left, "alpha.txt", alpha);
	check_security(test, left, cases, "directory-security.bin");
	check_security(test, right, cases, "directory-security.bin");
	check_security(test, alpha, cases, "child-file-security.bin");
	check_data(test, alpha, cases, "empty.bin");
	payload = load(cases, "payload.bin", &bytes);
	write_data(test, alpha, TEST_WRITE_OFFSET, payload, bytes);
	check_data(test, alpha, cases, "written.bin");
	resize(test, alpha, TEST_GROW_BYTES);
	check_data(test, alpha, cases, "grown.bin");
	resize(test, alpha, TEST_SHRINK_BYTES);
	check_data(test, alpha, cases, "shrunk.bin");
	resize(test, alpha, TEST_REGROW_BYTES);
	check_data(test, alpha, cases, "regrown.bin");
	check_security(test, alpha, cases, "child-file-security.bin");
	victim = create(test, right, "beta.txt", false);
	replacement = load(cases, "replacement.bin", &replacement_bytes);
	write_data(test, victim, 0, replacement, replacement_bytes);
	rename_entry(test, left, "alpha.txt", right, "beta.txt", false, NTFS_EXISTS);
	check_name(test, left, "alpha.txt", alpha, NTFS_OK);
	check_name(test, right, "beta.txt", victim, NTFS_OK);
	rename_entry(test, left, "alpha.txt", right, "beta.txt", true, NTFS_OK);
	check_name(test, left, "alpha.txt", 0, NTFS_NOT_FOUND);
	check_name(test, right, "beta.txt", alpha, NTFS_OK);
	check_unpaired_name(test, right, "beta.txt", alpha);
	check_stale(test, victim);
	check_data(test, alpha, cases, "regrown.bin");
	remove_entry(test, test->root_reference, "mutation-right", true, NTFS_NOT_EMPTY);
	remove_entry(test, right, "beta.txt", false, NTFS_OK);
	check_stale(test, alpha);
	created = create(test, right, "reused.txt", false);
	assert(created != alpha && created != victim);
	check_stale(test, alpha);
	check_data(test, created, cases, "empty.bin");
	remove_entry(test, right, "reused.txt", false, NTFS_OK);
	remove_entry(test, test->root_reference, "mutation-left", true, NTFS_OK);
	remove_entry(test, test->root_reference, "mutation-right", true, NTFS_OK);
	check_stale(test, left);
	check_stale(test, right);
	validate(test);
	ntfs_overwrite_close(test->owner);
	test->owner = NULL;
	open_owner(test);
	assert(test->recovery.writes == 0);
	validate(test);
	free(payload);
	free(replacement);
	finish(test);
	puts("PASS: mixed growth, zero gaps, shrink, rename replacement, removal and stale "
	     "generations");
}

#if defined(NTFS_TEST_MUTATION_PLAN)
static uint64_t
directory_reference(struct test_case *test, uint64_t parent, const char *text)
{
	struct ntfs_volume *volume = view(test);
	struct ntfs_node *directory = NULL, *child = NULL;
	struct ntfs_stat stat;
	uint16_t units[TEST_NAME_UNITS];
	struct ntfs_write_name entry = name(parent, text, units);

	assert(ntfs_node_open(volume, parent, &directory) == NTFS_OK);
	assert(ntfs_lookup(directory, entry.units, entry.count, &child) == NTFS_OK);
	assert(ntfs_node_stat(child, &stat) == NTFS_OK && stat.directory);
	ntfs_node_close(child);
	ntfs_node_close(directory);
	assert(ntfs_unmount(volume) == NTFS_OK);
	return stat.reference;
}

static void
directory_ancestry(const char *cases)
{
	static const char *const valid[] = {
	    "win32-dos", "dos-win32", "posix", "win32", "win32-dos-combined"};
	static const char *const invalid[] = {"different-parent", "zero-sequence", "dos-only",
	    "duplicate-primary", "unknown-namespace", "self-parent", "length-mismatch",
	    "physical-count", "attribute-flags", "named-attribute", "missing-filename"};
	struct test_case *test;
	const struct ntfs_disk_boot *boot;
	struct ntfs_write_mutation_request request = {0};
	struct ntfs_write_mutation_plan *plan = NULL;
	struct ntfs_volume *volume;
	struct ntfs_node *node = NULL;
	struct ntfs_stat stat;
	uint16_t source_units[TEST_NAME_UNITS], destination_units[TEST_NAME_UNITS];
	uint8_t *before, *record;
	uint64_t ancestor, left, right, nested, deep, file, physical;
	char label[128];
	size_t profile, bytes, live;
	int count;

	for (profile = 0; profile < sizeof(valid) / sizeof(*valid); profile++) {
		count = snprintf(label, sizeof(label), "ancestor-%s.img", valid[profile]);
		assert(count > 0 && (size_t)count < sizeof(label));
		test = prepare_image(cases, label);
		ancestor = directory_reference(test, test->root_reference, "AncestorDirectory");
		left = directory_reference(test, ancestor, "left");
		right = directory_reference(test, ancestor, "right");
		nested = directory_reference(test, left, "nested");
		deep = directory_reference(test, nested, "deep");
		volume = view(test);
		assert(ntfs_node_open(volume, deep, &node) == NTFS_OK);
		request.source = name(deep, "data.bin", source_units);
		{
			struct ntfs_node *child = NULL;

			assert(ntfs_lookup(node, request.source.units, request.source.count,
				   &child) == NTFS_OK);
			assert(ntfs_node_stat(child, &stat) == NTFS_OK);
			file = stat.reference;
			ntfs_node_close(child);
		}
		ntfs_node_close(node);
		node = NULL;
		assert(ntfs_unmount(volume) == NTFS_OK);
		before = malloc(NTFS_WRITE_RECORD_BYTES);
		assert(before != NULL);
		boot = (const void *)test->device.visible;
		physical = ntfs_u64(boot->mft_lcn) * NTFS_WRITE_CLUSTER_BYTES +
		    (ancestor & NTFS_REFERENCE_RECORD_MASK) * NTFS_WRITE_RECORD_BYTES;
		memcpy(before, test->device.visible + physical, NTFS_WRITE_RECORD_BYTES);
		/* A descendant cannot become a destination, regardless of ancestor aliases. */
		rename_entry(test, left, "nested", deep, "loop", false, NTFS_INVALID);
		rename_entry(test, left, "nested", right, "moved", false, NTFS_OK);
		check_name(test, left, "nested", 0, NTFS_NOT_FOUND);
		check_name(test, right, "moved", nested, NTFS_OK);
		check_name(test, nested, "deep", deep, NTFS_OK);
		check_name(test, deep, "data.bin", file, NTFS_OK);
		check_data(test, file, cases, "ancestor-child.bin");
		validate(test);
		assert(
		    memcmp(before, test->device.visible + physical, NTFS_WRITE_RECORD_BYTES) == 0);
		rename_entry(test, right, "moved", left, "returned", false, NTFS_OK);
		check_name(test, left, "returned", nested, NTFS_OK);
		check_data(test, file, cases, "ancestor-child.bin");
		validate(test);
		if (profile < 2) {
			rename_entry(test, test->root_reference, "AncestorDirectory",
			    test->root_reference, "changed-pair", false, NTFS_UNSUPPORTED);
		}
		assert(
		    memcmp(before, test->device.visible + physical, NTFS_WRITE_RECORD_BYTES) == 0);
		free(before);
		finish(test);
	}
	for (profile = 0; profile < sizeof(invalid) / sizeof(*invalid); profile++) {
		test = prepare_image(cases, "ancestor-win32-dos.img");
		ancestor = directory_reference(test, test->root_reference, "AncestorDirectory");
		left = directory_reference(test, ancestor, "left");
		right = directory_reference(test, ancestor, "right");
		count =
		    snprintf(label, sizeof(label), "ancestor-invalid-%s.record", invalid[profile]);
		assert(count > 0 && (size_t)count < sizeof(label));
		record = load(cases, label, &bytes);
		assert(bytes == NTFS_WRITE_RECORD_BYTES);
		boot = (const void *)test->device.visible;
		physical = ntfs_u64(boot->mft_lcn) * NTFS_WRITE_CLUSTER_BYTES +
		    (ancestor & NTFS_REFERENCE_RECORD_MASK) * NTFS_WRITE_RECORD_BYTES;
		memcpy(test->device.visible + physical, record, bytes);
		memcpy(test->device.durable, test->device.visible, test->device.bytes);
		free(record);
		before = malloc(test->device.bytes);
		assert(before != NULL);
		memcpy(before, test->device.visible, test->device.bytes);
		request.kind = NTFS_WRITE_RENAME;
		request.source = name(left, "nested", source_units);
		request.destination = name(right, "moved", destination_units);
		request.filetime = TEST_FILETIME;
		live = test->device.live_bytes;
		assert(ntfs_write_mutation_prepare(&test->backend.reader, &request, &plan) ==
			NTFS_CORRUPT &&
		    plan == NULL);
		assert(test->device.writes == 0 && test->device.barriers == 0 &&
		    test->device.live_bytes == live &&
		    memcmp(before, test->device.visible, test->device.bytes) == 0);
		free(before);
		finish(test);
	}
	puts("PASS: paired/single directory ancestry, cross-parent moves and cycle refusal, "
	     "unchanged ancestor aliases, malformed-parent refusal before publication");
}
#endif

static void
generic_inheritance(const char *cases)
{
	struct test_case *test;
	uint64_t directory, direct, descendant;

	test = prepare_image(cases, "generic-security.img");
	directory = create(test, test->root_reference, "generic-directory", true);
	direct = create(test, test->root_reference, "generic-file", false);
	descendant = create(test, directory, "generic-descendant", false);
	check_security(test, directory, cases, "generic-directory-security.bin");
	check_security(test, direct, cases, "generic-file-security.bin");
	check_security(test, descendant, cases, "generic-file-security.bin");
	validate(test);
	finish(test);
	puts("PASS: generic rights retain propagation masks and map effective creator owner/group "
	     "rights for files, directories and descendants");
}

#if defined(NTFS_TEST_MUTATION_PLAN)
static void
local_index_update(struct test_case *test, uint64_t reference)
{
	struct ntfs_write_mutation_request request = {.kind = NTFS_WRITE_RESIZE_FILE,
	    .reference = reference,
	    .size = 1,
	    .filetime = TEST_FILETIME + 1};
	struct ntfs_write_mutation_plan *plan = NULL;
	struct ntfs_write_mutation_region region;
	size_t index, changed = 0;

	assert(ntfs_write_mutation_prepare(&test->backend.reader, &request, &plan) == NTFS_OK);
	assert(ntfs_write_mutation_plan_count(plan) != 0);
	for (index = 0; index < ntfs_write_mutation_plan_count(plan); index++) {
		assert(ntfs_write_mutation_plan_region(plan, index, &region) == NTFS_OK);
		changed += region.kind == NTFS_WRITE_MUTATION_INDEX;
	}
	assert(changed <= 1);
	verify_program(test, plan);
	ntfs_write_mutation_plan_close(plan);
}
#endif

static void
index_and_MFT_growth_image(const char *source, const char *cases, const char *image, bool root)
{
	struct test_case *test;
	uint64_t *references;
	uint64_t directory;
	char *path;
	char text[TEST_NAME_UNITS + 2];
	FILE *rows;
	size_t index, count;
	int length;

	test = prepare_image(source, image);
	directory = root ? test->root_reference
			 : create(test, test->root_reference, "mutation-index", true);
	references = calloc(TEST_CHILDREN, sizeof(*references));
	assert(references != NULL);
	path = malloc(TEST_PATH_BYTES);
	assert(path != NULL);
	length = snprintf(path, TEST_PATH_BYTES, "%s/children.rows", cases);
	assert(length > 0 && length < TEST_PATH_BYTES);
	rows = fopen(path, "rb");
	free(path);
	assert(rows != NULL);
	for (index = 0; index < TEST_CHILDREN; index++) {
		assert(fgets(text, sizeof(text), rows) != NULL);
		count = strlen(text);
		assert(count > 1 && text[count - 1] == '\n');
		text[count - 1] = '\0';
		references[index] = create(test, directory, text, false);
	}
	assert(fgetc(rows) == EOF && !ferror(rows));
#if defined(NTFS_TEST_MUTATION_PLAN)
	local_index_update(test, references[TEST_CHILDREN / 2]);
#endif
	validate(test);
	assert(fseek(rows, 0, SEEK_SET) == 0);
	for (index = 0; index < TEST_CHILDREN; index++) {
		assert(fgets(text, sizeof(text), rows) != NULL);
		text[strlen(text) - 1] = '\0';
		check_name(test, directory, text, references[index], NTFS_OK);
		check_data(test, references[index], cases, "empty.bin");
	}
	assert(fseek(rows, 0, SEEK_SET) == 0);
	for (index = 0; index < TEST_CHILDREN; index++) {
		assert(fgets(text, sizeof(text), rows) != NULL);
		text[strlen(text) - 1] = '\0';
		remove_entry(test, directory, text, false, NTFS_OK);
		check_stale(test, references[index]);
	}
	assert(fclose(rows) == 0);
	if (!root) {
		remove_entry(test, test->root_reference, "mutation-index", true, NTFS_OK);
	}
	validate(test);
	free(references);
	finish(test);
	puts("PASS: directory index splits, MFT growth, complete lookup and deletion");
}

static void
index_and_MFT_growth(const char *source, const char *cases)
{
	index_and_MFT_growth_image(source, cases, "source.img", false);
}

#if defined(NTFS_TEST_MUTATION_PLAN)
static void
unused_storage(const char *cases)
{
	static const char *const images[] = {"unused-index-torn.img", "unused-file-torn.img",
	    "unused-file-stale.img", "unused-index-stale.img", "unused-index-unused-slot.img",
	    "unused-mft-tail-stale.img", "unused-mft-tail-torn.img"};
	size_t index;

	for (index = 0; index < sizeof(images) / sizeof(images[0]); index++) {
		index_and_MFT_growth_image(cases, cases, images[index], true);
	}
	assert(program_checks.unowned_file_signatures != 0 &&
	    program_checks.unowned_index_signatures != 0 &&
	    program_checks.unused_mapped_index_buffers != 0);
	puts("PASS: stale or malformed free FILE/INDX bytes and allocated unused index buffers");
}

static void
owned_index_damage(const char *source)
{
	struct test_case *test;
	struct ntfs_volume *volume;
	struct ntfs_node *root = NULL;
	struct ntfs_stream *allocation = NULL;
	struct ntfs_write_mutation_plan *failed;
	struct ntfs_write_mutation_request request = {0};
	const struct ntfs_run *run;
	uint8_t *snapshot;
	uint16_t units[TEST_NAME_UNITS], original;
	uint64_t physical;
	size_t index, offset;
	static const size_t offsets[] = {
	    offsetof(struct ntfs_disk_mst, usa_count), NTFS_MST_STRIDE - NTFS_MST_WORD_BYTES};

	test = prepare(source);
	volume = view(test);
	assert(ntfs_root(volume, &root) == NTFS_OK);
	assert(
	    ntfs_attribute_open(root, NTFS_ATTR_INDEX_ALLOCATION, (uint16_t[]){'$', 'I', '3', '0'},
		NTFS_WRITE_MUTATION_TARGET_NAME_UNITS, &allocation) == NTFS_OK);
	run = ntfs_run_find(allocation, 0);
	assert(run != NULL && run->lcn != NTFS_HOLE);
	physical = run->lcn * NTFS_WRITE_CLUSTER_BYTES;
	ntfs_stream_close(allocation);
	ntfs_node_close(root);
	assert(ntfs_unmount(volume) == NTFS_OK);
	request.kind = NTFS_WRITE_CREATE_FILE;
	request.filetime = TEST_FILETIME;
	request.source = name(test->root_reference, "owned-index-must-refuse.txt", units);
	snapshot = malloc(test->device.bytes);
	assert(snapshot != NULL);
	for (index = 0; index < sizeof(offsets) / sizeof(offsets[0]); index++) {
		offset = (size_t)physical + offsets[index];
		original = ntfs_u16(test->device.visible + offset);
		ntfs_put_u16(test->device.visible + offset, index == 0 ? 0 : (original ^ 1u));
		memcpy(snapshot, test->device.visible, test->device.bytes);
		failed = (void *)(uintptr_t)1;
		assert(ntfs_write_mutation_prepare(&test->backend.reader, &request, &failed) ==
		    NTFS_CORRUPT);
		assert(failed == NULL && test->device.live_bytes == 0 && test->device.writes == 0 &&
		    test->device.barriers == 0);
		assert(memcmp(snapshot, test->device.visible, test->device.bytes) == 0);
		ntfs_put_u16(test->device.visible + offset, original);
	}
	free(snapshot);
	finish(test);
	puts("PASS: malformed owned INDX geometry and torn sector refuse unchanged");
}
#endif

static void
sustained_reuse(const char *source, const char *cases)
{
	struct test_case *test;
	uint8_t *payload;
	size_t bytes, index;
	uint64_t current, previous = 0;

	test = prepare(source);
	payload = load(cases, "payload.bin", &bytes);
	for (index = 0; index < TEST_REUSE_OPERATIONS; index++) {
		current = create(test, test->root_reference, "mutation-reuse.txt", false);
		assert(current != previous);
		if (previous != 0) {
			check_stale(test, previous);
		}
		write_data(test, current, TEST_WRITE_OFFSET, payload, bytes);
		check_data(test, current, cases, "written.bin");
		resize(test, current, TEST_SHRINK_BYTES);
		check_data(test, current, cases, "shrunk.bin");
		remove_entry(test, test->root_reference, "mutation-reuse.txt", false, NTFS_OK);
		check_stale(test, current);
		previous = current;
	}
	validate(test);
	free(payload);
	finish(test);
	puts("PASS: sustained allocation/free and reference generations");
}

static void
fragmented_growth(const char *source, const char *cases)
{
	struct test_case *test;
	struct ntfs_volume *volume;
	struct ntfs_node *node = NULL;
	struct ntfs_stream *stream = NULL;
	uint64_t references[TEST_FRAGMENT_FILES], target;
	uint8_t *payload;
	char text[32];
	size_t index, bytes;

	test = prepare(source);
	for (index = 0; index < TEST_FRAGMENT_FILES; index++) {
		assert(snprintf(text, sizeof(text), "fragment-%zu", index) > 0);
		references[index] = create(test, test->root_reference, text, false);
		resize(test, references[index], NTFS_WRITE_CLUSTER_BYTES);
	}
	for (index = 0; index < TEST_FRAGMENT_FILES; index += 2) {
		assert(snprintf(text, sizeof(text), "fragment-%zu", index) > 0);
		remove_entry(test, test->root_reference, text, false, NTFS_OK);
	}
	target = create(test, test->root_reference, "fragment-grown.txt", false);
	payload = load(cases, "payload.bin", &bytes);
	write_data(test, target, TEST_WRITE_OFFSET, payload, bytes);
	check_data(test, target, cases, "written.bin");
	volume = view(test);
	assert(ntfs_node_open(volume, target, &node) == NTFS_OK);
	assert(ntfs_stream_open(node, NULL, 0, &stream) == NTFS_OK);
	assert(!stream->resident && stream->run_count > 1);
	ntfs_stream_close(stream);
	ntfs_node_close(node);
	assert(ntfs_unmount(volume) == NTFS_OK);
	for (index = 1; index < TEST_FRAGMENT_FILES; index += 2) {
		assert(snprintf(text, sizeof(text), "fragment-%zu", index) > 0);
		remove_entry(test, test->root_reference, text, false, NTFS_OK);
	}
	validate(test);
	free(payload);
	finish(test);
	puts("PASS: fragmented growth and zero gap without changing surviving files");
}

static void
full_space(const char *source)
{
	struct test_case *test;
	struct ntfs_write_mutation_request request = {0};
	struct ntfs_write_mutation_report report;
	uint64_t *references;
	uint8_t *before;
	char text[32];
	size_t capacity, count = 0, index;
	enum ntfs_result result;

	test = prepare(source);
	capacity = test->device.bytes / TEST_READ_BYTES + 2;
	references = calloc(capacity, sizeof(*references));
	before = malloc(test->device.bytes);
	assert(references != NULL && before != NULL);
	for (;;) {
		assert(count < capacity);
		assert(snprintf(text, sizeof(text), "full-space-%zu", count) > 0);
		references[count] = create(test, test->root_reference, text, false);
		memcpy(before, test->device.visible, test->device.bytes);
		request.kind = NTFS_WRITE_RESIZE_FILE;
		request.reference = references[count];
		request.size = TEST_READ_BYTES;
		request.filetime = ++test->time;
		result = mutate(test, &request, &report);
		test->device.executing = false;
		count++;
		if (result == NTFS_NO_SPACE) {
			assert(memcmp(before, test->device.visible, test->device.bytes) == 0);
			assert(!report.execution.poisoned);
			break;
		}
		assert(result == NTFS_OK && mutation_reference(&report) == request.reference);
	}
	assert(count > 1);
	remove_entry(test, test->root_reference, "full-space-0", false, NTFS_OK);
	resize(test, references[count - 1], TEST_READ_BYTES);
	for (index = 1; index < count; index++) {
		assert(snprintf(text, sizeof(text), "full-space-%zu", index) > 0);
		remove_entry(test, test->root_reference, text, false, NTFS_OK);
	}
	validate(test);
	free(before);
	free(references);
	finish(test);
	puts("PASS: ENOSPC leaves all bytes unchanged and freed space is reusable");
}

#if defined(NTFS_TEST_MUTATION_PLAN)
static void
preparation_faults(const char *source, const char *cases)
{
	struct test_case *test;
	struct ntfs_write_mutation_request request = {0};
	uint16_t source_units[TEST_NAME_UNITS], destination_units[TEST_NAME_UNITS];
	uint8_t *payload;
	size_t bytes;
	uint64_t reference;

	test = prepare(source);
	request.kind = NTFS_WRITE_CREATE_FILE;
	request.source = name(test->root_reference, "fault-file.txt", source_units);
	request.filetime = ++test->time;
	fault_request(test, &request);
	request.kind = NTFS_WRITE_CREATE_DIRECTORY;
	fault_request(test, &request);
	reference = create(test, test->root_reference, "fault-file.txt", false);
	request.kind = NTFS_WRITE_GROWING_RANGE;
	request.reference = reference;
	request.offset = TEST_WRITE_OFFSET;
	payload = load(cases, "payload.bin", &bytes);
	request.data = payload;
	request.bytes = bytes;
	request.filetime = ++test->time;
	fault_request(test, &request);
	write_data(test, reference, TEST_WRITE_OFFSET, payload, bytes);
	request.kind = NTFS_WRITE_RESIZE_FILE;
	request.size = TEST_SHRINK_BYTES;
	request.filetime = ++test->time;
	fault_request(test, &request);
	request.kind = NTFS_WRITE_RENAME;
	request.destination = name(test->root_reference, "renamed-file.txt", destination_units);
	request.filetime = ++test->time;
	fault_request(test, &request);
	request.kind = NTFS_WRITE_REMOVE_FILE;
	request.filetime = ++test->time;
	fault_request(test, &request);
	free(payload);
	finish(test);
	puts("PASS: every preparation allocation/read failure, unchanged source and exact retry");
}

static void
input_admission(const char *source)
{
	struct test_case *test;
	struct ntfs_write_mutation_request request = {0}, saved_request;
	struct ntfs_environment saved_environment;
	struct ntfs_write_mutation_plan *plan;
	_Alignas(sizeof(void *)) uint16_t units[TEST_NAME_UNITS], saved_units[TEST_NAME_UNITS];
	uint8_t payload[NTFS_WRITE_RECORD_BYTES], saved_payload[NTFS_WRITE_RECORD_BYTES];
	uint64_t reference;

	test = prepare(source);
	reference = create(test, test->root_reference, "admission-file.txt", false);
	request.kind = NTFS_WRITE_CREATE_FILE;
	request.source = name(test->root_reference, "admission-new.txt", units);
	request.filetime = ++test->time;
	test->device.allocations = 0;
	test->device.read_calls = 0;
	saved_environment = test->backend.reader;
	assert(ntfs_write_mutation_prepare(
		   &test->backend.reader, &request, (void *)&test->backend.reader) == NTFS_INVALID);
	assert(memcmp(&saved_environment, &test->backend.reader, sizeof(saved_environment)) == 0);
	saved_request = request;
	assert(ntfs_write_mutation_prepare(&test->backend.reader, &request, (void *)&request) ==
	    NTFS_INVALID);
	assert(memcmp(&saved_request, &request, sizeof(saved_request)) == 0);
	memcpy(saved_units, units, sizeof(units));
	assert(ntfs_write_mutation_prepare(&test->backend.reader, &request, (void *)units) ==
	    NTFS_INVALID);
	assert(memcmp(saved_units, units, sizeof(units)) == 0);
	memset(payload, TEST_PATTERN, sizeof(payload));
	memcpy(saved_payload, payload, sizeof(payload));
	request.kind = NTFS_WRITE_GROWING_RANGE;
	request.reference = reference;
	request.data = payload;
	request.bytes = sizeof(payload);
	assert(ntfs_write_mutation_prepare(&test->backend.reader, &request, (void *)payload) ==
	    NTFS_INVALID);
	assert(memcmp(saved_payload, payload, sizeof(payload)) == 0);
	request.kind = NTFS_WRITE_CREATE_FILE;
	request.source.units = (const void *)(UINTPTR_MAX - NTFS_UTF16_UNIT_BYTES + 1u);
	plan = (void *)(uintptr_t)1;
	assert(ntfs_write_mutation_prepare(&test->backend.reader, &request, &plan) == NTFS_INVALID);
	assert(test->device.allocations == 0 && test->device.read_calls == 0);
	plan = (void *)(uintptr_t)1;
	assert(ntfs_write_mutation_prepare(NULL, &request, &plan) == NTFS_INVALID && plan == NULL);
	plan = (void *)(uintptr_t)1;
	assert(ntfs_write_mutation_prepare(&test->backend.reader, NULL, &plan) == NTFS_INVALID &&
	    plan == NULL);
	finish(test);
	puts(
	    "PASS: borrowed-input/output alias and overflowing pointer admission before callbacks");
}

static void
mirror_predecessor(const char *source)
{
	struct test_case *test;
	struct ntfs_write_mutation_request request = {0};
	struct ntfs_write_mutation_report report;
	struct ntfs_write_mutation_plan *plan = NULL;
	struct ntfs_write_mutation_region region;
	const struct ntfs_disk_record *header;
	struct ntfs_disk_record *changed_header;
	struct ntfs_volume *volume = NULL;
	uint8_t *restored, *protected_old;
	uint16_t units[TEST_NAME_UNITS], marker;
	uint64_t physical = 0;
	size_t index, offset;
	bool found = false;

	test = prepare(source);
	request.kind = NTFS_WRITE_CREATE_FILE;
	request.source = name(test->root_reference, "mirror-predecessor.txt", units);
	request.filetime = ++test->time;
	restored = malloc(NTFS_WRITE_RECORD_BYTES);
	protected_old = malloc(NTFS_WRITE_RECORD_BYTES);
	assert(restored != NULL && protected_old != NULL);
	assert(ntfs_write_mutation_prepare(&test->backend.reader, &request, &plan) == NTFS_OK);
	for (index = 0; index < ntfs_write_mutation_plan_count(plan) && !found; index++) {
		assert(ntfs_write_mutation_plan_region(plan, index, &region) == NTFS_OK);
		if (!region.target.mirror) {
			continue;
		}
		for (offset = 0; offset < region.bytes; offset += NTFS_WRITE_RECORD_BYTES) {
			if (memcmp(region.before + offset, region.after + offset,
				NTFS_WRITE_RECORD_BYTES) == 0) {
				continue;
			}
			header = (const void *)(region.after + offset);
			marker = ntfs_u16(region.after + offset + ntfs_u16(header->mst.usa_offset));
			assert(marker != 0 && marker != UINT16_MAX);
			memcpy(restored, region.before + offset, NTFS_WRITE_RECORD_BYTES);
			assert(ntfs_fixup(restored, NTFS_WRITE_RECORD_BYTES, "FILE") == NTFS_OK);
			header = (const void *)restored;
			/* Give the replica the exact sequence that primary-only guarding
			 * would have reused. Its semantic FILE contents stay unchanged. */
			ntfs_put_u16(
			    restored + ntfs_u16(header->mst.usa_offset), (uint16_t)(marker - 1u));
			assert(ntfs_record_protect(restored, NTFS_WRITE_RECORD_BYTES, protected_old,
				   NTFS_WRITE_RECORD_BYTES) == NTFS_OK);
			physical = region.physical + offset;
			found = true;
			break;
		}
	}
	assert(found);
	ntfs_write_mutation_plan_close(plan);
	memcpy(test->device.visible + physical, protected_old, NTFS_WRITE_RECORD_BYTES);
	memcpy(test->device.durable, test->device.visible, test->device.bytes);
	validate(test);
	/* Only the independent protection sequence is excluded at bootstrap.
	 * A different restored FILE field must still refuse the whole mount. */
	changed_header = (void *)restored;
	ntfs_put_u64(changed_header->lsn, ntfs_u64(changed_header->lsn) ^ 1u);
	assert(ntfs_record_protect(restored, NTFS_WRITE_RECORD_BYTES,
		   test->device.visible + physical, NTFS_WRITE_RECORD_BYTES) == NTFS_OK);
	assert(ntfs_mount(&test->backend.reader, NULL, &volume) == NTFS_CORRUPT && volume == NULL);
	memcpy(test->device.visible + physical, protected_old, NTFS_WRITE_RECORD_BYTES);
	assert(mutate(test, &request, &report) == NTFS_OK);
	validate(test);
	free(protected_old);
	free(restored);
	finish(test);
	puts("PASS: each MFT replica excludes its actual predecessor USA and every mixed sector "
	     "pair");
}

static void
retired_record_reading(const char *source)
{
	struct test_case *test;
	struct ntfs_volume *volume;
	struct ntfs_node *node;
	const struct ntfs_run *run;
	struct ntfs_disk_record *header, *expected;
	uint8_t original[NTFS_WRITE_RECORD_BYTES];
	uint8_t *logical;
	uint64_t reference, offset, vcn, physical;
	size_t first, end;
	unsigned variant;

	test = prepare(source);
	reference = create(test, test->root_reference, "retired.txt", false);
	volume = view(test);
	offset = (reference & NTFS_REFERENCE_RECORD_MASK) * volume->info.record_size;
	vcn = offset / volume->info.cluster_size;
	run = ntfs_run_find(volume->mft, vcn);
	assert(run != NULL && run->lcn != NTFS_HOLE);
	physical = (run->lcn + vcn - run->vcn) * volume->info.cluster_size +
	    offset % volume->info.cluster_size;
	assert(ntfs_unmount(volume) == NTFS_OK);
	assert(ntfs_bounds(physical, sizeof(original), test->device.bytes));
	logical = malloc(2 * NTFS_WRITE_RECORD_BYTES);
	assert(logical != NULL);
	memcpy(logical, test->device.visible + physical, NTFS_WRITE_RECORD_BYTES);
	assert(ntfs_record_validate(logical, NTFS_WRITE_RECORD_BYTES) == NTFS_OK);
	expected = (void *)logical;
	assert(ntfs_u16(expected->links) == 1);
	ntfs_put_u16(
	    expected->sequence, (uint16_t)((reference >> NTFS_REFERENCE_SEQUENCE_SHIFT) + 1u));
	ntfs_put_u16(expected->flags, 0);
	remove_entry(test, test->root_reference, "retired.txt", false, NTFS_OK);
	check_stale(test, reference);
	memcpy(logical + NTFS_WRITE_RECORD_BYTES, test->device.visible + physical,
	    NTFS_WRITE_RECORD_BYTES);
	assert(ntfs_record_decode(
		   logical + NTFS_WRITE_RECORD_BYTES, NTFS_WRITE_RECORD_BYTES, false) == NTFS_OK);
	first = ntfs_u16(expected->mst.usa_offset);
	end = first + ntfs_u16(expected->mst.usa_count) * NTFS_MST_WORD_BYTES;
	assert(end <= NTFS_WRITE_RECORD_BYTES);
	assert(memcmp(logical, logical + NTFS_WRITE_RECORD_BYTES, first) == 0);
	assert(memcmp(logical + end, logical + NTFS_WRITE_RECORD_BYTES + end,
		   NTFS_WRITE_RECORD_BYTES - end) == 0);
	free(logical);
	memcpy(original, test->device.visible + physical, sizeof(original));
	for (variant = 0; variant < 3; variant++) {
		header = (void *)(test->device.visible + physical);
		if (variant == 0) {
			test->device.visible[physical + NTFS_MST_STRIDE - NTFS_MST_WORD_BYTES] ^= 1;
		} else if (variant == 1) {
			ntfs_put_u16(header->sequence, 0);
		} else {
			ntfs_put_u32(
			    header->allocated, NTFS_WRITE_RECORD_BYTES - NTFS_WIRE_ALIGNMENT);
		}
		volume = view(test);
		node = (void *)(uintptr_t)1;
		assert(ntfs_node_open(volume, reference, &node) == NTFS_CORRUPT && node == NULL);
		assert(ntfs_unmount(volume) == NTFS_OK);
		memcpy(test->device.visible + physical, original, sizeof(original));
	}
	validate(test);
	finish(test);
	puts("PASS: retirement preserves links and attributes; stale references refuse and "
	     "malformed or torn free FILE stays corrupt");
}
#endif

#if defined(NTFS_TEST_MUTATION_PLAN)
struct bitmap_storage_expectation {
	uint8_t *attribute, *tail;
	size_t attribute_bytes;
	uint64_t number, tail_physical;
	uint32_t type;
};

static void
check_bitmap_storage(struct test_case *test, const struct bitmap_storage_expectation *expected)
{
	const struct ntfs_disk_boot *boot = (const void *)test->device.visible;
	struct ntfs_attr_view attribute;
	uint8_t *logical;
	uint64_t physical;

	physical = ntfs_u64(boot->mft_lcn) * NTFS_WRITE_CLUSTER_BYTES +
	    expected->number * NTFS_WRITE_RECORD_BYTES;
	assert(physical <= test->device.bytes &&
	    NTFS_WRITE_RECORD_BYTES <= test->device.bytes - physical);
	logical = malloc(NTFS_WRITE_RECORD_BYTES);
	assert(logical != NULL);
	memcpy(logical, test->device.visible + physical, NTFS_WRITE_RECORD_BYTES);
	assert(ntfs_record_decode(logical, NTFS_WRITE_RECORD_BYTES, false) == NTFS_OK);
	assert(ntfs_attr_find(logical, NTFS_WRITE_RECORD_BYTES, expected->type, NULL, 0, UINT16_MAX,
		   &attribute) == NTFS_OK);
	assert(attribute.disk->nonresident && attribute.length == expected->attribute_bytes);
	assert(memcmp(attribute.bytes, expected->attribute, expected->attribute_bytes) == 0);
	assert(expected->tail_physical <= test->device.bytes &&
	    NTFS_WRITE_CLUSTER_BYTES <= test->device.bytes - expected->tail_physical);
	assert(memcmp(test->device.visible + expected->tail_physical, expected->tail,
		   NTFS_WRITE_CLUSTER_BYTES) == 0);
	free(logical);
}

static void
bitmap_storage_preservation(const char *cases)
{
	static const char *profiles[] = {
	    "bitmap-storage-mft", "bitmap-storage-volume", "bitmap-storage-both"};
	struct bitmap_storage_expectation expected[2];
	struct test_case *test;
	FILE *contract;
	char *path, *file;
	uint8_t *payload;
	uint64_t reference;
	unsigned number, type;
	unsigned long long physical;
	size_t profile, count, index, bytes, tail_bytes;
	int length, fields;

	path = malloc(TEST_PATH_BYTES);
	file = malloc(TEST_PATH_BYTES);
	assert(path != NULL && file != NULL);
	payload = load(cases, "payload.bin", &bytes);
	for (profile = 0; profile < sizeof(profiles) / sizeof(*profiles); profile++) {
		length = snprintf(file, TEST_PATH_BYTES, "%s.img", profiles[profile]);
		assert(length > 0 && length < TEST_PATH_BYTES);
		test = prepare_image(cases, file);
		length = snprintf(path, TEST_PATH_BYTES, "%s/%s.rows", cases, profiles[profile]);
		assert(length > 0 && length < TEST_PATH_BYTES);
		contract = fopen(path, "rb");
		assert(contract != NULL);
		count = 0;
		for (;;) {
			fields = fscanf(contract, "%u %x %llu", &number, &type, &physical);
			if (fields == EOF) {
				assert(feof(contract) && !ferror(contract));
				break;
			}
			assert(fields == 3 && count < sizeof(expected) / sizeof(*expected));
			expected[count].number = number;
			expected[count].type = type;
			expected[count].tail_physical = physical;
			length = snprintf(
			    file, TEST_PATH_BYTES, "%s-%u.attribute", profiles[profile], number);
			assert(length > 0 && length < TEST_PATH_BYTES);
			expected[count].attribute =
			    load(cases, file, &expected[count].attribute_bytes);
			length = snprintf(
			    file, TEST_PATH_BYTES, "%s-%u.tail", profiles[profile], number);
			assert(length > 0 && length < TEST_PATH_BYTES);
			expected[count].tail = load(cases, file, &tail_bytes);
			assert(tail_bytes == NTFS_WRITE_CLUSTER_BYTES);
			check_bitmap_storage(test, &expected[count]);
			count++;
		}
		assert(count != 0 && fclose(contract) == 0);
		reference = create(test, test->root_reference, "bitmap-storage.txt", false);
		for (index = 0; index < count; index++) {
			check_bitmap_storage(test, &expected[index]);
		}
		write_data(test, reference, TEST_WRITE_OFFSET, payload, bytes);
		check_data(test, reference, cases, "written.bin");
		for (index = 0; index < count; index++) {
			check_bitmap_storage(test, &expected[index]);
		}
		resize(test, reference, TEST_SHRINK_BYTES);
		check_data(test, reference, cases, "shrunk.bin");
		remove_entry(test, test->root_reference, "bitmap-storage.txt", false, NTFS_OK);
		for (index = 0; index < count; index++) {
			check_bitmap_storage(test, &expected[index]);
			free(expected[index].attribute);
			free(expected[index].tail);
		}
		validate(test);
		finish(test);
	}
	free(payload);
	free(path);
	free(file);
	puts("PASS: bitmap bit changes retain original attributes, mappings and allocated tail "
	     "bytes");
}

static uint64_t
free_inventory(struct test_case *test, uint64_t number, uint32_t type, uint64_t first)
{
	struct ntfs_volume *volume;
	struct ntfs_node *node = NULL;
	struct ntfs_stream *stream = NULL;
	uint8_t *bits;
	uint64_t count, bit, free_count = 0;

	volume = view(test);
	count = number == NTFS_MFT_RECORD ? volume->mft->initialized / NTFS_WRITE_RECORD_BYTES
					  : volume->info.cluster_count;
	assert(ntfs_node_by_number(volume, number, &node) == NTFS_OK);
	assert(ntfs_attribute_open(node, type, NULL, 0, &stream) == NTFS_OK);
	assert(stream->size <= SIZE_MAX &&
	    (count + NTFS_BITS_PER_BYTE - 1) / NTFS_BITS_PER_BYTE <= stream->size);
	bits = malloc((size_t)stream->size);
	assert(bits != NULL && ntfs_stream_exact(stream, 0, bits, (size_t)stream->size) == NTFS_OK);
	for (bit = first; bit < count; bit++) {
		free_count +=
		    (bits[bit / NTFS_BITS_PER_BYTE] & (1u << (bit % NTFS_BITS_PER_BYTE))) == 0;
	}
	free(bits);
	ntfs_stream_close(stream);
	ntfs_node_close(node);
	assert(ntfs_unmount(volume) == NTFS_OK);
	return free_count;
}

static void
directory_inline_spill(const char *cases)
{
	struct test_case *test;
	struct ntfs_volume *volume;
	struct ntfs_node *node = NULL;
	struct ntfs_stream *allocation = NULL;
	struct ntfs_write_mutation_request request = {0};
	struct ntfs_write_mutation_report report;
	const struct ntfs_disk_record *header;
	const uint16_t index_name[] = {'$', 'I', '3', '0'};
	uint64_t directory, references[TEST_INLINE_SPILL_CHILDREN];
	uint16_t units[TEST_NAME_UNITS];
	char (*names)[TEST_INLINE_SPILL_NAME_UNITS + 1];
	size_t index, prefix, minimum_allocation;
	enum ntfs_result result;

	test = prepare_image(cases, "directory-inline-spill.img");
	names = calloc(TEST_INLINE_SPILL_CHILDREN, sizeof(*names));
	assert(names != NULL);
	directory = create(test, test->root_reference, "r", true);
	check_security(test, directory, cases, "inline-spill-directory.bin");
	for (index = 0; index < TEST_INLINE_SPILL_CHILDREN; index++) {
		prefix = (size_t)snprintf(names[index], sizeof(names[index]), "spill-%zu-", index);
		assert(prefix > 0 && prefix < TEST_INLINE_SPILL_NAME_UNITS);
		memset(names[index] + prefix, 'n', TEST_INLINE_SPILL_NAME_UNITS - prefix);
		names[index][TEST_INLINE_SPILL_NAME_UNITS] = '\0';
		request.kind = NTFS_WRITE_CREATE_FILE;
		request.source = name(directory, names[index], units);
		request.filetime = ++test->time;
		result = mutate(test, &request, &report);
		if (result != NTFS_OK) {
			fprintf(stderr, "inline spill child %zu: %s\n", index,
			    ntfs_result_string(result));
		}
		assert(result == NTFS_OK);
		references[index] = mutation_reference(&report);
		check_security(test, references[index], cases, "inline-spill-file.bin");
		if (index == 0) {
			volume = view(test);
			assert(ntfs_node_open(volume, directory, &node) == NTFS_OK);
			header = (const void *)node->record;
			minimum_allocation = sizeof(struct ntfs_disk_attr) +
			    sizeof(struct ntfs_disk_nonresident) +
			    NTFS_WRITE_MUTATION_TARGET_NAME_UNITS * NTFS_UTF16_UNIT_BYTES;
			assert(
			    NTFS_WRITE_RECORD_BYTES - ntfs_u32(header->used) < minimum_allocation);
			assert(ntfs_attribute_open(node, NTFS_ATTR_INDEX_ALLOCATION, index_name,
				   NTFS_WRITE_MUTATION_TARGET_NAME_UNITS,
				   &allocation) == NTFS_NOT_FOUND &&
			    allocation == NULL);
			ntfs_node_close(node);
			assert(ntfs_unmount(volume) == NTFS_OK);
		}
	}
	volume = view(test);
	assert(ntfs_node_open(volume, directory, &node) == NTFS_OK);
	assert(ntfs_attribute_open(node, NTFS_ATTR_INDEX_ALLOCATION, index_name,
		   NTFS_WRITE_MUTATION_TARGET_NAME_UNITS, &allocation) == NTFS_OK);
	assert(allocation->allocated > NTFS_WRITE_CLUSTER_BYTES);
	ntfs_stream_close(allocation);
	ntfs_node_close(node);
	assert(ntfs_unmount(volume) == NTFS_OK);
	for (index = 0; index < TEST_INLINE_SPILL_CHILDREN; index++) {
		check_name(test, directory, names[index], references[index], NTFS_OK);
		check_data(test, references[index], cases, "empty.bin");
		remove_entry(test, directory, names[index], false, NTFS_OK);
	}
	remove_entry(test, test->root_reference, "r", true, NTFS_OK);
	validate(test);
	free(names);
	finish(test);
	puts("PASS: full inline directory root spills to multiple INDX blocks without temporary "
	     "FILE-capacity refusal");
}

static uint64_t
check_allocation_reservation(struct test_case *test, const uint8_t *expected, size_t bytes)
{
	struct ntfs_volume *volume;
	uint8_t *actual;
	uint64_t records;

	assert(bytes == TEST_RESERVED_RECORDS * NTFS_WRITE_RECORD_BYTES);
	actual = malloc(bytes);
	assert(actual != NULL);
	volume = view(test);
	records = volume->mft->initialized / NTFS_WRITE_RECORD_BYTES;
	assert(ntfs_stream_exact(volume->mft, TEST_FIRST_RESERVED_RECORD * NTFS_WRITE_RECORD_BYTES,
		   actual, bytes) == NTFS_OK);
	assert(memcmp(expected, actual, bytes) == 0);
	free(actual);
	assert(ntfs_unmount(volume) == NTFS_OK);
	assert(free_inventory(test, NTFS_MFT_RECORD, NTFS_ATTR_BITMAP, TEST_FIRST_RESERVED_RECORD) -
		free_inventory(
		    test, NTFS_MFT_RECORD, NTFS_ATTR_BITMAP, TEST_FIRST_ALLOCATABLE_RECORD) ==
	    TEST_RESERVED_RECORDS);
	return records;
}

static void
allocation_reservation(const char *cases)
{
	struct test_case *test;
	struct ntfs_write_mutation_request request = {0};
	struct ntfs_write_mutation_report report;
	uint8_t *expected, *before;
	uint16_t units[TEST_NAME_UNITS];
	uint64_t references[TEST_CHILDREN], directory, initial, available, reference;
	char text[TEST_NAME_UNITS + 1];
	size_t bytes, index;
	enum ntfs_result result;

	test = prepare_image(cases, "allocation-reservation.img");
	expected = load(cases, "allocation-reservation.bin", &bytes);
	initial = check_allocation_reservation(test, expected, bytes);
	for (index = 0; index < TEST_CHILDREN; index++) {
		assert(snprintf(text, sizeof(text), "reservation-%zu", index) > 0);
		references[index] = create(test, test->root_reference, text, false);
		assert((references[index] & NTFS_REFERENCE_RECORD_MASK) >=
		    TEST_FIRST_ALLOCATABLE_RECORD);
		check_allocation_reservation(test, expected, bytes);
	}
	assert(check_allocation_reservation(test, expected, bytes) > initial);
	directory = create(test, test->root_reference, "reservation-pressure", true);
	available =
	    free_inventory(test, NTFS_MFT_RECORD, NTFS_ATTR_BITMAP, TEST_FIRST_ALLOCATABLE_RECORD);
	assert(available < NTFS_WRITE_CLUSTER_BYTES / NTFS_WRITE_RECORD_BYTES);
	resize(test, references[0],
	    free_inventory(test, NTFS_BITMAP_RECORD, NTFS_ATTRIBUTE_DATA, 0) *
		NTFS_WRITE_CLUSTER_BYTES);
	assert(free_inventory(test, NTFS_BITMAP_RECORD, NTFS_ATTRIBUTE_DATA, 0) == 0);
	for (index = 0; index < available; index++) {
		assert(snprintf(text, sizeof(text), "r%zu", index) > 0);
		reference = create(test, directory, text, false);
		assert((reference & NTFS_REFERENCE_RECORD_MASK) >= TEST_FIRST_ALLOCATABLE_RECORD);
	}
	assert(free_inventory(
		   test, NTFS_MFT_RECORD, NTFS_ATTR_BITMAP, TEST_FIRST_ALLOCATABLE_RECORD) == 0);
	before = malloc(test->device.bytes);
	assert(before != NULL);
	memcpy(before, test->device.visible, test->device.bytes);
	request.kind = NTFS_WRITE_CREATE_FILE;
	request.source = name(directory, "full", units);
	request.filetime = ++test->time;
	result = mutate(test, &request, &report);
	assert(result == NTFS_NO_SPACE && !report.execution.poisoned);
	assert(memcmp(before, test->device.visible, test->device.bytes) == 0);
	assert(memcmp(before, test->device.durable, test->device.bytes) == 0);
	check_allocation_reservation(test, expected, bytes);
	resize(test, references[0], 0);
	for (index = 0; index < TEST_CHILDREN; index++) {
		assert(snprintf(text, sizeof(text), "reservation-%zu", index) > 0);
		remove_entry(test, test->root_reference, text, false, NTFS_OK);
	}
	for (index = 0; index < available; index++) {
		assert(snprintf(text, sizeof(text), "r%zu", index) > 0);
		remove_entry(test, directory, text, false, NTFS_OK);
	}
	remove_entry(test, test->root_reference, "reservation-pressure", true, NTFS_OK);
	reference = create(test, test->root_reference, "reservation-reuse", false);
	assert((reference & NTFS_REFERENCE_RECORD_MASK) >= TEST_FIRST_ALLOCATABLE_RECORD);
	check_stale(test, references[0]);
	check_allocation_reservation(test, expected, bytes);
	validate(test);
	free(before);
	free(expected);
	finish(test);
	puts("PASS: ordinary allocation preserves reserved FILE slots and bitmap bits through "
	     "MFT growth, ENOSPC, removal and reuse");
}
#endif

int
main(int argc, char **argv)
{
#if defined(NTFS_TEST_MUTATION_PLAN)
	assert(argc == 3 ||
	    (argc == 4 &&
		(strcmp(argv[3], "allocation-reservation") == 0 ||
		    strcmp(argv[3], "directory-inline-spill") == 0 ||
		    strcmp(argv[3], "security-inheritance") == 0 ||
		    strcmp(argv[3], "directory-ancestry") == 0)));
	if (argc == 4 && strcmp(argv[3], "directory-ancestry") == 0) {
		directory_ancestry(argv[2]);
		return 0;
	}
	if (argc == 4 && strcmp(argv[3], "security-inheritance") == 0) {
		generic_inheritance(argv[2]);
		return 0;
	}
	if (argc == 4 && strcmp(argv[3], "directory-inline-spill") == 0) {
		directory_inline_spill(argv[2]);
		return 0;
	}
	allocation_reservation(argv[2]);
	if (argc == 4) {
		return 0;
	}
	directory_inline_spill(argv[2]);
	directory_ancestry(argv[2]);
	bitmap_storage_preservation(argv[2]);
	unused_storage(argv[2]);
	owned_index_damage(argv[1]);
#else
	assert(argc == 3);
#endif
	mixed_operations(argv[1], argv[2]);
	generic_inheritance(argv[2]);
	index_and_MFT_growth(argv[1], argv[2]);
	fragmented_growth(argv[1], argv[2]);
	full_space(argv[1]);
	sustained_reuse(argv[1], argv[2]);
#if defined(NTFS_TEST_MUTATION_PLAN)
	input_admission(argv[1]);
	preparation_faults(argv[1], argv[2]);
	mirror_predecessor(argv[1]);
	retired_record_reading(argv[1]);
	printf("PASS: %zu private mutation programs, %zu metadata updates, %zu inverse prefixes, "
	       "%zu program/page/compensation allocation failures with exact retry\n",
	    program_checks.programs, program_checks.updates, program_checks.inverse_prefixes,
	    program_checks.allocation_faults);
	printf("PASS: %zu original FILE slots, %zu original INDX buffers, %zu unowned FILE "
	       "signatures, %zu unowned INDX signatures, %zu allocated unused INDX buffers\n",
	    program_checks.original_file_slots, program_checks.original_index_buffers,
	    program_checks.unowned_file_signatures, program_checks.unowned_index_signatures,
	    program_checks.unused_mapped_index_buffers);
	puts("Private planning and journal preparation only: no device execution, persistence "
	     "or native recovery qualification");
#endif
	return 0;
}
