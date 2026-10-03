/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/access.h>
#include <ntfs/logfile.h>
#include "fixture.h"
#include "fuzz_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_FILE_RECORD = 24,
	TEST_FILE_SEQUENCE = 7,
	TEST_CATALOG_ENTRIES = 2,
	TEST_BUFFER_BYTES = 2 * TEST_COMPRESSION_UNIT_BYTES,
	TEST_SIBLING_LIMIT = 1024,
	TEST_SENTINEL = 0xa5,
	TEST_REPEATED_COPIES = 2
};

enum profile_kind {
	PROFILE_DIRECTORY,
	PROFILE_DATA,
	PROFILE_ADS,
	PROFILE_REPARSE,
	PROFILE_SECURITY,
	PROFILE_JOURNAL
};

struct profile {
	const char *image, *filename, *expected;
	enum profile_kind kind;
};

struct test_device {
	struct fuzz_device device;
	uint64_t read_bytes, allocation_bytes, peak;
	struct ntfs_volume *mounted;
	struct ntfs_operation *scope;
	bool check_active_call;
};

static void *
allocate(void *context, size_t size)
{
	struct test_device *device = context;
	void *bytes;

	device->allocation_bytes += size;
	bytes = fuzz_allocate(&device->device, size);
	if (device->device.memory > device->peak) {
		device->peak = device->device.memory;
	}
	return bytes;
}

static void
release(void *context, void *bytes, size_t size)
{
	struct test_device *device = context;

	fuzz_release(&device->device, bytes, size);
}

static enum ntfs_result
read_bytes(void *context, uint64_t offset, void *bytes, size_t size)
{
	struct test_device *device = context;
	struct ntfs_operation child = {0};
	struct ntfs_operation_usage usage = {0};

	device->read_bytes += size;
	if (device->check_active_call) {
		device->check_active_call = false;
		assert(ntfs_operation_begin(device->mounted, NULL, &child) == NTFS_BUSY);
		assert(ntfs_operation_end(device->scope, &usage) == NTFS_BUSY);
		assert(ntfs_unmount(device->mounted) == NTFS_BUSY);
	}
	return fuzz_read(&device->device, offset, bytes, size);
}

static struct ntfs_environment
environment(struct test_device *device)
{
	return (struct ntfs_environment){
	    NTFS_API_VERSION, device, device->device.size, read_bytes, allocate, release};
}

static uint8_t *
load(const char *directory, const char *name, size_t *size)
{
	char *path;
	FILE *file;
	long length;
	uint8_t *bytes;
	size_t capacity = strlen(directory) + sizeof("/") + strlen(name);

	path = malloc(capacity);
	assert(path != NULL && snprintf(path, capacity, "%s/%s", directory, name) > 0);
	file = fopen(path, "rb");
	free(path);
	assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
	length = ftell(file);
	assert(length > 0 && length <= TEST_IMAGE_BYTES && fseek(file, 0, SEEK_SET) == 0);
	bytes = malloc((size_t)length);
	assert(bytes != NULL && fread(bytes, 1, (size_t)length, file) == (size_t)length);
	assert(fclose(file) == 0);
	*size = (size_t)length;
	return bytes;
}

static struct ntfs_volume *
mount_device(struct test_device *device, uint64_t live, bool cache)
{
	struct ntfs_environment env = environment(device);
	struct ntfs_limits limits;
	struct ntfs_volume *volume;

	ntfs_default_limits(&limits);
	limits.record_cache_entries = cache ? NTFS_DEFAULT_RECORD_CACHE_ENTRIES : 0;
	if (live != 0) {
		limits.max_live_bytes = live;
	}
	assert(ntfs_mount(&env, &limits, &volume) == NTFS_OK);
	return volume;
}

static enum ntfs_result
lookup(struct ntfs_volume *volume, const char *filename, struct ntfs_node **out)
{
	struct ntfs_node *root = NULL;
	uint16_t name[NTFS_NAME_MAX];
	size_t length;
	enum ntfs_result result;

	*out = NULL;
	assert(ntfs_utf8_to_utf16(filename, strlen(filename), name, NTFS_NAME_MAX, &length) ==
	    NTFS_OK);
	result = ntfs_root(volume, &root);
	if (result == NTFS_OK) {
		result = ntfs_lookup(root, name, length, out);
	}
	ntfs_node_close(root);
	return result;
}

static enum ntfs_result
perform(struct ntfs_volume *volume, const struct profile *profile, const uint8_t *expected,
    size_t expected_size)
{
	static const uint16_t notes[] = {'n', 'o', 't', 'e', 's'};
	static const uint16_t target[] = u"..\\\u03a9-target.txt";
	static const char ads[] = "alternate payload";
	struct ntfs_node *node = NULL;
	struct ntfs_stream *stream = NULL;
	struct ntfs_directory *directory = NULL;
	struct ntfs_stream_catalog *catalog = NULL;
	struct ntfs_reparse *reparse = NULL;
	struct ntfs_security *security = NULL;
	struct ntfs_logfile *journal = NULL;
	struct ntfs_logfile_restart restart;
	struct ntfs_logfile_page_view page;
	struct ntfs_security_info security_info;
	struct ntfs_access_token token = {0};
	struct ntfs_dacl_decision decision;
	struct ntfs_stream_name stream_name;
	struct ntfs_dirent entry;
	struct ntfs_stat stat;
	uint16_t units[NTFS_NAME_MAX];
	uint8_t *bytes = malloc(TEST_BUFFER_BYTES);
	size_t size, count = 0;
	uint64_t free_clusters;
	enum ntfs_result result;

	assert(bytes != NULL);
	if (profile->kind == PROFILE_JOURNAL) {
		result = ntfs_logfile_open_volume(volume, NULL, NULL, &journal);
		if (result == NTFS_OK) {
			assert(ntfs_logfile_get_restart(journal, &restart) == NTFS_OK);
			assert(restart.log_page_bytes == expected_size);
			result = ntfs_logfile_read_page(
			    journal, restart.circular_offset, bytes, TEST_BUFFER_BYTES, &page);
			if (result == NTFS_OK) {
				assert(memcmp(bytes, expected, expected_size) == 0);
			}
		}
		goto finish;
	}
	if (profile->kind == PROFILE_DIRECTORY) {
		result = ntfs_count_free_clusters(volume, &free_clusters);
		if (result == NTFS_OK) {
			assert(free_clusters ==
			    TEST_IMAGE_BYTES / TEST_CLUSTER_BYTES - TEST_ALLOCATED_CLUSTERS);
			result = ntfs_root(volume, &node);
		}
		if (result == NTFS_OK) {
			result = ntfs_directory_open(node, &directory);
		}
		if (result == NTFS_OK) {
			while ((result = ntfs_directory_next(directory, &entry)) == NTFS_OK) {
				assert(entry.reference != 0 && entry.name_length > 0);
				count++;
			}
			if (result == NTFS_END) {
				assert(count == TEST_FILE_COUNT);
				result = NTFS_OK;
			}
		}
		goto finish;
	}
	result = lookup(volume, profile->filename, &node);
	if (result == NTFS_OK) {
		result = ntfs_node_stat(node, &stat);
	}
	if (result != NTFS_OK) {
		goto finish;
	}
	if (profile->kind == PROFILE_REPARSE) {
		result = ntfs_reparse_open(node, &reparse);
		if (result == NTFS_OK) {
			result = ntfs_reparse_bytes(reparse, bytes, TEST_BUFFER_BYTES, &size);
		}
		if (result == NTFS_OK) {
			assert(size <= NTFS_REPARSE_MAX_BYTES);
			result = ntfs_reparse_name(
			    reparse, NTFS_REPARSE_SUBSTITUTE_NAME, units, NTFS_NAME_MAX, &size);
		}
		if (result == NTFS_OK) {
			assert(size == sizeof(target) / sizeof(target[0]) - 1);
			assert(memcmp(units, target, size * sizeof(units[0])) == 0);
		}
	} else if (profile->kind == PROFILE_SECURITY) {
		result = ntfs_security_open(node, &security);
		if (result == NTFS_OK) {
			result = ntfs_security_copy(security, bytes, TEST_BUFFER_BYTES, &size);
		}
		if (result == NTFS_OK) {
			assert(size == expected_size && memcmp(bytes, expected, size) == 0);
			ntfs_security_get_info(security, &security_info);
			token.user = security_info.owner;
			result = ntfs_security_evaluate_dacl(
			    security, &token, NTFS_FILE_READ_DATA, NULL, &decision);
		}
		if (result == NTFS_OK) {
			assert(decision.allowed && decision.granted == NTFS_FILE_READ_DATA);
		}
	} else {
		if (profile->kind == PROFILE_ADS) {
			result = ntfs_stream_catalog_open(node, TEST_CATALOG_ENTRIES, &catalog);
			if (result == NTFS_OK) {
				assert(ntfs_stream_catalog_count(catalog) == TEST_CATALOG_ENTRIES);
				result = ntfs_stream_catalog_entry(
				    catalog, TEST_CATALOG_ENTRIES - 1, &stream_name);
			}
			if (result == NTFS_OK) {
				assert(stream_name.length == sizeof(notes) / sizeof(notes[0]) &&
				    memcmp(stream_name.units, notes, sizeof(notes)) == 0);
				result = ntfs_stream_open(
				    node, notes, sizeof(notes) / sizeof(notes[0]), &stream);
			}
		} else {
			result = ntfs_stream_open(node, NULL, 0, &stream);
		}
		if (result == NTFS_OK) {
			result = ntfs_stream_read(stream, 0, bytes, TEST_BUFFER_BYTES, &size);
		}
		if (result == NTFS_OK) {
			if (profile->kind == PROFILE_ADS) {
				assert(size == sizeof(ads) - 1 && memcmp(bytes, ads, size) == 0);
			} else {
				assert(size == expected_size && stat.size == expected_size &&
				    memcmp(bytes, expected, size) == 0);
			}
		}
	}
finish:
	ntfs_logfile_close(journal);
	ntfs_security_close(security);
	ntfs_reparse_close(reparse);
	ntfs_stream_catalog_close(catalog);
	ntfs_directory_close(directory);
	ntfs_stream_close(stream);
	ntfs_node_close(node);
	free(bytes);
	return result;
}

static uint64_t *
ceiling(struct ntfs_operation_limits *limits, enum ntfs_operation_limit dimension)
{
	switch (dimension) {
	case NTFS_OPERATION_LIMIT_READ_CALLS:
		return &limits->read_calls;
	case NTFS_OPERATION_LIMIT_READ_BYTES:
		return &limits->read_bytes;
	case NTFS_OPERATION_LIMIT_ALLOCATION_CALLS:
		return &limits->allocation_calls;
	case NTFS_OPERATION_LIMIT_ALLOCATION_BYTES:
		return &limits->allocation_bytes;
	case NTFS_OPERATION_LIMIT_WORK:
		return &limits->work;
	default:
		assert(false);
		return NULL;
	}
}

static uint64_t
used(const struct ntfs_operation_usage *usage, enum ntfs_operation_limit dimension)
{
	switch (dimension) {
	case NTFS_OPERATION_LIMIT_READ_CALLS:
		return usage->read_calls;
	case NTFS_OPERATION_LIMIT_READ_BYTES:
		return usage->read_bytes;
	case NTFS_OPERATION_LIMIT_ALLOCATION_CALLS:
		return usage->allocation_calls;
	case NTFS_OPERATION_LIMIT_ALLOCATION_BYTES:
		return usage->allocation_bytes;
	case NTFS_OPERATION_LIMIT_WORK:
		return usage->work;
	default:
		assert(false);
		return 0;
	}
}

static struct ntfs_operation_usage
run_profile(const uint8_t *image, size_t image_size, const struct profile *profile,
    const uint8_t *expected, size_t expected_size, const struct ntfs_operation_limits *limits,
    uint64_t live, enum ntfs_operation_limit refused)
{
	struct test_device device = {.device = {.data = image, .size = image_size}};
	struct ntfs_volume *volume = mount_device(&device, live, false);
	struct ntfs_operation operation = {0};
	struct ntfs_operation_usage usage, last;
	uint64_t allocation_bytes = device.allocation_bytes, read_bytes_before = device.read_bytes;
	size_t allocations = device.device.allocations, reads = device.device.reads;
	enum ntfs_result result, quota;

	device.peak = device.device.memory;
	assert(ntfs_operation_begin(volume, limits, &operation) == NTFS_OK);
	result = perform(volume, profile, expected, expected_size);
	quota = ntfs_operation_result(&operation);
	assert(ntfs_operation_end(&operation, &usage) == NTFS_OK);
	assert(usage.read_calls == device.device.reads - reads &&
	    usage.read_bytes == device.read_bytes - read_bytes_before &&
	    usage.allocation_calls == device.device.allocations - allocations &&
	    usage.allocation_bytes == device.allocation_bytes - allocation_bytes &&
	    usage.peak_live_bytes == device.peak && usage.exhausted == refused);
	ntfs_get_operation_usage(volume, &last);
	assert(memcmp(&usage, &last, sizeof(last)) == 0);
	if (refused == NTFS_OPERATION_LIMIT_NONE) {
		assert(result == NTFS_OK && quota == NTFS_OK);
	} else {
		assert(result != NTFS_OK &&
		    quota ==
			(refused == NTFS_OPERATION_LIMIT_ALLOCATION_CALLS ||
				    refused == NTFS_OPERATION_LIMIT_ALLOCATION_BYTES ||
				    refused == NTFS_OPERATION_LIMIT_LIVE_BYTES
				? NTFS_NO_MEMORY
				: NTFS_RANGE));
	}
	assert(ntfs_unmount(volume) == NTFS_OK && device.device.memory == 0);
	return usage;
}

static void
profile_boundaries(
    const char *directory, const char *journal_directory, const char *source_directory)
{
	static const struct profile profiles[] = {{"standard.img", NULL, NULL, PROFILE_DIRECTORY},
	    {"nested-index.img", NULL, NULL, PROFILE_DIRECTORY},
	    {"mft-nonresident-list.img", "extended.bin", "expected/extended.bin", PROFILE_DATA},
	    {"standard.img", "fragmented.bin", "expected/fragmented.bin", PROFILE_DATA},
	    {"standard.img", "sparse.bin", "expected/sparse.bin", PROFILE_DATA},
	    {"standard.img", "compressed.bin", "expected/compressed.bin", PROFILE_DATA},
	    {"standard.img", "streamed.txt", NULL, PROFILE_ADS},
	    {"reparse-resident-extension.img", "hello.txt", NULL, PROFILE_REPARSE},
	    {"secure-tree.img", "hello.txt", "secure-expected/256.bin", PROFILE_SECURITY},
	    {"wof-file-4k.img", "hello.txt", "wof-file-4k.data", PROFILE_DATA},
	    {"wof-file-lzx-packed.img", "hello.txt", "wof-file-lzx-packed.data", PROFILE_DATA},
	    {"nonresident-list.img", NULL, "system-4096.journal.page", PROFILE_JOURNAL}};
	struct ntfs_operation_usage baseline, mount_usage;
	struct ntfs_operation_limits limits;
	struct test_device device;
	struct ntfs_volume *volume;
	uint8_t *image, *expected, *original;
	size_t image_size, expected_size, i, cases = 0;
	uint64_t live;
	enum ntfs_operation_limit dimension;
	const char *images, *expectations;

	for (i = 0; i < sizeof(profiles) / sizeof(profiles[0]); i++) {
		images = profiles[i].kind == PROFILE_JOURNAL ? journal_directory : directory;
		expectations = profiles[i].kind == PROFILE_JOURNAL ? source_directory : directory;
		image = load(images, profiles[i].image, &image_size);
		original = malloc(image_size);
		assert(original != NULL);
		memcpy(original, image, image_size);
		expected = NULL;
		expected_size = 0;
		if (profiles[i].expected != NULL) {
			expected = load(expectations, profiles[i].expected, &expected_size);
			assert(expected_size <= TEST_BUFFER_BYTES);
		}
		baseline = run_profile(image, image_size, &profiles[i], expected, expected_size,
		    NULL, 0, NTFS_OPERATION_LIMIT_NONE);
		for (dimension = NTFS_OPERATION_LIMIT_READ_CALLS;
		    dimension <= NTFS_OPERATION_LIMIT_WORK; dimension++) {
			assert(used(&baseline, dimension) > 1);
			ntfs_operation_default_limits(&limits);
			*ceiling(&limits, dimension) = used(&baseline, dimension);
			(void)run_profile(image, image_size, &profiles[i], expected, expected_size,
			    &limits, 0, NTFS_OPERATION_LIMIT_NONE);
			(*ceiling(&limits, dimension))--;
			(void)run_profile(image, image_size, &profiles[i], expected, expected_size,
			    &limits, 0, dimension);
			cases += 2;
		}
		device = (struct test_device){.device = {.data = image, .size = image_size}};
		volume = mount_device(&device, 0, false);
		ntfs_get_operation_usage(volume, &mount_usage);
		assert(ntfs_unmount(volume) == NTFS_OK && device.device.memory == 0);
		live = baseline.peak_live_bytes > mount_usage.peak_live_bytes
		    ? baseline.peak_live_bytes
		    : mount_usage.peak_live_bytes;
		(void)run_profile(image, image_size, &profiles[i], expected, expected_size, NULL,
		    live, NTFS_OPERATION_LIMIT_NONE);
		if (baseline.peak_live_bytes > mount_usage.peak_live_bytes) {
			(void)run_profile(image, image_size, &profiles[i], expected, expected_size,
			    NULL, live - 1, NTFS_OPERATION_LIMIT_LIVE_BYTES);
			cases++;
		}
		cases++;
		assert(memcmp(image, original, image_size) == 0);
		free(original);
		free(expected);
		free(image);
	}
	printf("PASS: %zu profiles, %zu exact/one-below operation boundaries; independently "
	       "counted callbacks/bytes/live peak and original content\n",
	    sizeof(profiles) / sizeof(profiles[0]), cases);
}

static void
mount_boundaries(const uint8_t *image, size_t size)
{
	struct test_device device = {.device = {.data = image, .size = size}};
	struct ntfs_environment env;
	struct ntfs_limits limits;
	struct ntfs_volume *volume = mount_device(&device, 0, false);
	struct ntfs_operation_usage baseline;
	struct ntfs_io_statistics io;
	enum ntfs_operation_limit dimension;
	enum ntfs_result result;

	ntfs_get_operation_usage(volume, &baseline);
	ntfs_get_io_statistics(volume, &io);
	assert(baseline.read_calls == device.device.reads &&
	    baseline.read_bytes == device.read_bytes &&
	    baseline.allocation_calls == device.device.allocations &&
	    baseline.allocation_bytes == device.allocation_bytes &&
	    baseline.peak_live_bytes == device.peak);
	assert(baseline.read_calls == io.read_calls + 1 &&
	    baseline.read_bytes == io.read_bytes + TEST_SECTOR_BYTES);
	assert(ntfs_unmount(volume) == NTFS_OK && device.device.memory == 0);
	for (dimension = NTFS_OPERATION_LIMIT_READ_CALLS; dimension <= NTFS_OPERATION_LIMIT_WORK;
	    dimension++) {
		ntfs_default_limits(&limits);
		limits.record_cache_entries = 0;
		*ceiling(&limits.operation, dimension) = used(&baseline, dimension);
		device = (struct test_device){.device = {.data = image, .size = size}};
		env = environment(&device);
		assert(ntfs_mount(&env, &limits, &volume) == NTFS_OK);
		assert(ntfs_unmount(volume) == NTFS_OK && device.device.memory == 0);
		(*ceiling(&limits.operation, dimension))--;
		device = (struct test_device){.device = {.data = image, .size = size}};
		env = environment(&device);
		result = ntfs_mount(&env, &limits, &volume);
		assert(result ==
		    (dimension == NTFS_OPERATION_LIMIT_ALLOCATION_CALLS ||
				dimension == NTFS_OPERATION_LIMIT_ALLOCATION_BYTES
			    ? NTFS_NO_MEMORY
			    : NTFS_RANGE));
		assert(volume == NULL && device.device.memory == 0);
		assert(device.device.reads <= limits.operation.read_calls &&
		    device.read_bytes <= limits.operation.read_bytes &&
		    device.device.allocations <= limits.operation.allocation_calls &&
		    device.allocation_bytes <= limits.operation.allocation_bytes);
	}
	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	limits.max_live_bytes = baseline.peak_live_bytes;
	device = (struct test_device){.device = {.data = image, .size = size}};
	env = environment(&device);
	assert(ntfs_mount(&env, &limits, &volume) == NTFS_OK);
	assert(ntfs_unmount(volume) == NTFS_OK && device.device.memory == 0);
	limits.max_live_bytes--;
	device = (struct test_device){.device = {.data = image, .size = size}};
	env = environment(&device);
	assert(ntfs_mount(&env, &limits, &volume) == NTFS_NO_MEMORY && volume == NULL &&
	    device.device.memory == 0);
	ntfs_default_limits(&limits);
	limits.max_live_bytes = 1;
	device = (struct test_device){.device = {.data = image, .size = size}};
	env = environment(&device);
	assert(ntfs_mount(&env, &limits, &volume) == NTFS_NO_MEMORY && volume == NULL);
	ntfs_default_limits(&limits);
	limits.operation.allocation_bytes = 1;
	assert(ntfs_mount(&env, &limits, &volume) == NTFS_NO_MEMORY && volume == NULL);
	limits.operation.work = 0;
	assert(ntfs_mount(&env, &limits, &volume) == NTFS_INVALID && volume == NULL);
	env.api_version = NTFS_API_VERSION - 1;
	assert(ntfs_mount(&env, NULL, &volume) == NTFS_INVALID && volume == NULL);
	assert(device.device.allocations == 0 && device.device.reads == 0 &&
	    device.device.memory == 0);
	puts("PASS: mount quota includes boot and volume allocation; exact thresholds, "
	     "pre-callback rejection and old ABI refusal");
}

static void
nested_lifetime(const uint8_t *image, size_t size)
{
	struct test_device device = {.device = {.data = image, .size = size}};
	struct test_device other = {.device = {.data = image, .size = size}};
	struct ntfs_volume *volume = mount_device(&device, 0, false), *other_volume;
	struct ntfs_node *node;
	struct ntfs_stat stat, zero = {0};
	struct ntfs_operation parent = {0}, child = {0}, saved,
			      scopes[NTFS_OPERATION_MAX_DEPTH + 1] = {0};
	struct ntfs_operation_usage usage, sentinel;
	struct ntfs_operation_limits limits;
	struct ntfs_info info;
	size_t reads, allocations, i;

	assert(ntfs_root(volume, &node) == NTFS_OK && ntfs_node_metadata(node, &stat) == NTFS_OK);
	reads = device.device.reads;
	allocations = device.device.allocations;
	device.device.fail_read = reads + 1;
	device.device.fail_allocation = allocations + 1;
	ntfs_get_operation_limits(volume, &limits);
	limits.work = TEST_REPEATED_COPIES * sizeof(stat);
	assert(ntfs_operation_begin(volume, &limits, &parent) == NTFS_OK);
	for (i = 0; i < TEST_REPEATED_COPIES; i++) {
		assert(ntfs_operation_begin(volume, NULL, &child) == NTFS_OK);
		saved = parent;
		memset(&sentinel, TEST_SENTINEL, sizeof(sentinel));
		usage = sentinel;
		assert(ntfs_operation_end(&parent, &usage) == NTFS_BUSY);
		assert(memcmp(&parent, &saved, sizeof(saved)) == 0 &&
		    memcmp(&usage, &sentinel, sizeof(usage)) == 0);
		assert(ntfs_node_metadata(node, &stat) == NTFS_OK);
		assert(ntfs_operation_end(&child, &child.usage) == NTFS_OK);
		assert(child.usage.work == sizeof(stat));
	}
	assert(ntfs_operation_begin(volume, NULL, &child) == NTFS_OK);
	memset(&stat, TEST_SENTINEL, sizeof(stat));
	assert(ntfs_node_metadata(node, &stat) == NTFS_RANGE &&
	    memcmp(&stat, &zero, sizeof(stat)) == 0);
	assert(parent.usage.work == limits.work && child.usage.work == 0 &&
	    ntfs_operation_check(volume) == NTFS_RANGE);
	assert(ntfs_operation_end(&child, &usage) == NTFS_OK &&
	    usage.exhausted == NTFS_OPERATION_LIMIT_WORK);
	assert(ntfs_node_metadata(node, &stat) == NTFS_RANGE);
	ntfs_get_info(volume, &info);
	assert(info.record_size == TEST_MFT_RECORD_BYTES);
	assert(device.device.reads == reads && device.device.allocations == allocations);
	assert(ntfs_operation_end(&parent, &usage) == NTFS_OK);
	assert(ntfs_node_metadata(node, &stat) == NTFS_OK);
	device.device.fail_read = 0;
	device.device.fail_allocation = 0;
	ntfs_node_close(node);
	other_volume = mount_device(&other, 0, false);
	assert(ntfs_operation_begin(volume, NULL, &parent) == NTFS_OK);
	assert(ntfs_operation_begin(other_volume, NULL, &parent) == NTFS_BUSY);
	assert(ntfs_operation_begin(volume, NULL, &child) == NTFS_OK);
	assert(ntfs_unmount(volume) == NTFS_OK && device.device.memory == 0);
	assert(ntfs_operation_end(&parent, &usage) == NTFS_OK &&
	    ntfs_operation_end(&child, NULL) == NTFS_OK);
	assert(ntfs_operation_end(&parent, NULL) == NTFS_INVALID);
	for (i = 0; i < NTFS_OPERATION_MAX_DEPTH; i++) {
		assert(ntfs_operation_begin(other_volume, NULL, &scopes[i]) == NTFS_OK);
	}
	assert(ntfs_operation_begin(other_volume, NULL, &scopes[NTFS_OPERATION_MAX_DEPTH]) ==
	    NTFS_BUSY);
	for (i = NTFS_OPERATION_MAX_DEPTH; i != 0; i--) {
		assert(ntfs_operation_end(&scopes[i - 1], NULL) == NTFS_OK);
	}
	ntfs_get_operation_limits(other_volume, &limits);
	limits.read_bytes++;
	assert(ntfs_operation_begin(other_volume, &limits, &parent) == NTFS_INVALID);
	ntfs_get_operation_limits(other_volume, &limits);
	limits.read_calls = 0;
	assert(ntfs_operation_begin(other_volume, &limits, &parent) == NTFS_INVALID);
	assert(ntfs_unmount(other_volume) == NTFS_OK && other.device.memory == 0);
	puts("PASS: nested credits cannot reset; sticky no-I/O refusal, zero output, LIFO/alias "
	     "report, depth/cross-owner bounds and detached end");
}

static void
faults_and_optional_cache(const uint8_t *image, size_t size)
{
	struct test_device device = {.device = {.data = image, .size = size}};
	struct ntfs_volume *volume = mount_device(&device, 0, false);
	struct ntfs_node *node = NULL;
	struct ntfs_operation operation = {0};
	struct ntfs_operation_usage usage, mandatory;
	struct ntfs_operation_limits limits;
	struct ntfs_io_statistics before, after;
	size_t reads, allocations;
	uint64_t reference =
	    TEST_FILE_RECORD | (uint64_t)TEST_FILE_SEQUENCE << NTFS_REFERENCE_SEQUENCE_SHIFT;

	assert(ntfs_node_open(volume, reference, &node) == NTFS_OK);
	ntfs_get_operation_usage(volume, &mandatory);
	ntfs_node_close(node);
	assert(ntfs_operation_begin(volume, NULL, &operation) == NTFS_OK);
	device.device.fail_read = device.device.reads + 1;
	assert(ntfs_node_open(volume, reference, &node) == NTFS_IO && node == NULL);
	assert(operation.usage.read_calls == 1 &&
	    operation.usage.read_bytes == TEST_MFT_RECORD_BYTES &&
	    ntfs_operation_result(&operation) == NTFS_OK);
	device.device.fail_read = 0;
	device.device.fail_allocation = device.device.allocations + 1;
	allocations = device.device.allocations;
	assert(ntfs_node_open(volume, reference, &node) == NTFS_NO_MEMORY && node == NULL);
	assert(device.device.allocations == allocations + 1 &&
	    ntfs_operation_result(&operation) == NTFS_OK);
	device.device.fail_allocation = 0;
	device.mounted = volume;
	device.scope = &operation;
	device.check_active_call = true;
	assert(ntfs_node_open(volume, reference, &node) == NTFS_OK);
	assert(!device.check_active_call);
	ntfs_node_close(node);
	assert(ntfs_operation_end(&operation, &usage) == NTFS_OK);
	assert(ntfs_unmount(volume) == NTFS_OK && device.device.memory == 0);
	device = (struct test_device){.device = {.data = image, .size = size}};
	volume = mount_device(&device, 0, true);
	ntfs_get_operation_limits(volume, &limits);
	limits.allocation_calls = mandatory.allocation_calls;
	limits.allocation_bytes = mandatory.allocation_bytes;
	assert(ntfs_operation_begin(volume, &limits, &operation) == NTFS_OK);
	allocations = device.device.allocations;
	assert(ntfs_node_open(volume, reference, &node) == NTFS_OK);
	assert(device.device.allocations - allocations == mandatory.allocation_calls);
	assert(ntfs_operation_end(&operation, &usage) == NTFS_OK &&
	    usage.exhausted == NTFS_OPERATION_LIMIT_NONE);
	ntfs_node_close(node);
	reads = device.device.reads;
	ntfs_get_io_statistics(volume, &before);
	assert(ntfs_node_open(volume, reference, &node) == NTFS_OK && device.device.reads > reads);
	ntfs_node_close(node);
	reads = device.device.reads;
	assert(ntfs_node_open(volume, reference, &node) == NTFS_OK && device.device.reads == reads);
	ntfs_node_close(node);
	ntfs_get_io_statistics(volume, &after);
	assert(after.record_cache_hits > before.record_cache_hits);
	assert(ntfs_unmount(volume) == NTFS_OK && device.device.memory == 0);
	puts("PASS: failed backend attempts count without quota poisoning; optional cache omitted "
	     "before callback and filled by a fresh retry");
}

static void
aggregate_live(const uint8_t *image, size_t size)
{
	struct test_device device = {.device = {.data = image, .size = size}};
	struct ntfs_volume *volume = mount_device(&device, 0, false);
	struct ntfs_operation_usage mount_usage, usage;
	struct ntfs_operation operation = {0};
	struct ntfs_node **nodes = calloc(TEST_SIBLING_LIMIT, sizeof(*nodes));
	size_t count = 0, i;
	enum ntfs_result result;

	assert(nodes != NULL);
	ntfs_get_operation_usage(volume, &mount_usage);
	assert(ntfs_unmount(volume) == NTFS_OK && device.device.memory == 0);
	device = (struct test_device){.device = {.data = image, .size = size}};
	volume = mount_device(&device, mount_usage.peak_live_bytes, false);
	assert(ntfs_operation_begin(volume, NULL, &operation) == NTFS_OK);
	while (count < TEST_SIBLING_LIMIT) {
		result = ntfs_root(volume, &nodes[count]);
		assert(device.device.memory <= mount_usage.peak_live_bytes);
		if (result != NTFS_OK) {
			assert(result == NTFS_NO_MEMORY && nodes[count] == NULL &&
			    operation.usage.exhausted == NTFS_OPERATION_LIMIT_LIVE_BYTES);
			break;
		}
		count++;
	}
	assert(count > 0 && count < TEST_SIBLING_LIMIT && ntfs_unmount(volume) == NTFS_BUSY);
	for (i = 0; i < count; i++) {
		ntfs_node_close(nodes[i]);
	}
	assert(ntfs_operation_end(&operation, &usage) == NTFS_OK);
	assert(ntfs_root(volume, &nodes[0]) == NTFS_OK);
	ntfs_node_close(nodes[0]);
	assert(ntfs_unmount(volume) == NTFS_OK && device.device.memory == 0);
	free(nodes);
	puts("PASS: sibling owners share one live-memory cap; cleanup under exhaustion permits a "
	     "fresh operation");
}

static void
codec_retry(const char *directory)
{
	static const struct profile profiles[] = {
	    {"standard.img", "compressed.bin", "expected/compressed.bin", PROFILE_DATA},
	    {"wof-file-4k.img", "hello.txt", "wof-file-4k.data", PROFILE_DATA},
	    {"wof-file-lzx-packed.img", "hello.txt", "wof-file-lzx-packed.data", PROFILE_DATA}};
	struct test_device device;
	struct ntfs_volume *volume;
	struct ntfs_node *node;
	struct ntfs_stream *stream;
	struct ntfs_operation operation = {0};
	struct ntfs_operation_limits limits;
	struct ntfs_operation_usage baseline;
	uint8_t *image, *expected, bytes[TEST_REPEATED_COPIES];
	size_t image_size, expected_size, i, done, reads;

	for (i = 0; i < sizeof(profiles) / sizeof(profiles[0]); i++) {
		image = load(directory, profiles[i].image, &image_size);
		expected = load(directory, profiles[i].expected, &expected_size);
		assert(expected_size >= sizeof(bytes));
		device = (struct test_device){.device = {.data = image, .size = image_size}};
		volume = mount_device(&device, 0, false);
		assert(lookup(volume, profiles[i].filename, &node) == NTFS_OK);
		assert(ntfs_stream_open(node, NULL, 0, &stream) == NTFS_OK);
		assert(ntfs_stream_read(stream, 0, bytes, sizeof(bytes), &done) == NTFS_OK &&
		    done == sizeof(bytes));
		ntfs_get_operation_usage(volume, &baseline);
		ntfs_stream_close(stream);
		assert(ntfs_stream_open(node, NULL, 0, &stream) == NTFS_OK);
		ntfs_get_operation_limits(volume, &limits);
		limits.work = baseline.work - 1;
		assert(ntfs_operation_begin(volume, &limits, &operation) == NTFS_OK);
		memset(bytes, TEST_SENTINEL, sizeof(bytes));
		assert(ntfs_stream_read(stream, 0, bytes, sizeof(bytes), &done) == NTFS_RANGE &&
		    done == 0);
		assert(bytes[0] == TEST_SENTINEL && bytes[sizeof(bytes) - 1] == TEST_SENTINEL);
		assert(ntfs_operation_result(&operation) == NTFS_RANGE &&
		    ntfs_operation_end(&operation, NULL) == NTFS_OK);
		reads = device.device.reads;
		assert(ntfs_stream_read(stream, 0, bytes, sizeof(bytes), &done) == NTFS_OK &&
		    done == sizeof(bytes));
		assert(device.device.reads > reads && memcmp(bytes, expected, sizeof(bytes)) == 0);
		ntfs_get_operation_limits(volume, &limits);
		limits.work = sizeof(bytes) - 1;
		assert(ntfs_operation_begin(volume, &limits, &operation) == NTFS_OK);
		reads = device.device.reads;
		assert(ntfs_stream_read(stream, 0, bytes, sizeof(bytes), &done) == NTFS_RANGE &&
		    done == 0 && device.device.reads == reads);
		assert(ntfs_operation_end(&operation, NULL) == NTFS_OK);
		assert(ntfs_stream_read(stream, 0, bytes, sizeof(bytes), &done) == NTFS_OK &&
		    done == sizeof(bytes) && device.device.reads == reads);
		assert(memcmp(bytes, expected, sizeof(bytes)) == 0);
		ntfs_stream_close(stream);
		ntfs_node_close(node);
		assert(ntfs_unmount(volume) == NTFS_OK && device.device.memory == 0);
		free(expected);
		free(image);
	}
	puts("PASS: LZNT1/XPRESS/LZX cold-fill work refusal does not publish cache data; "
	     "same-stream fresh retry and cached-copy quotas");
}

int
main(int argc, char **argv)
{
	uint8_t *image, *original;
	size_t size;

	assert(argc == 4);
	image = load(argv[1], "standard.img", &size);
	original = malloc(size);
	assert(original != NULL);
	memcpy(original, image, size);
	mount_boundaries(image, size);
	nested_lifetime(image, size);
	faults_and_optional_cache(image, size);
	aggregate_live(image, size);
	assert(memcmp(image, original, size) == 0);
	free(original);
	free(image);
	profile_boundaries(argv[1], argv[2], argv[3]);
	codec_retry(argv[1]);
	return 0;
}
