/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/ntfs.h>
#include "fuzz_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { TEST_REPEATED_METADATA = 32, TEST_IMAGE_LIMIT = 8 * 1024 * 1024 };

static size_t
exercise(struct fuzz_device *device, size_t fail_allocation, bool fail_read)
{
	struct ntfs_environment env = fuzz_environment(device);
	struct ntfs_limits limits;
	struct ntfs_volume *volume;
	struct ntfs_node *root;
	struct ntfs_stat before, after;
	size_t allocations, reads, i;
	enum ntfs_result result;

	device->fail_allocation = 0;
	device->fail_read = 0;
	/* Isolate node-local reuse from mount's already checked temporary root. */
	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	assert(ntfs_mount(&env, &limits, &volume) == NTFS_OK);
	assert(ntfs_root(volume, &root) == NTFS_OK);
	allocations = device->allocations;
	reads = device->reads;
	if (fail_allocation != 0) {
		device->fail_allocation = allocations + fail_allocation;
	}
	if (fail_read) {
		device->fail_read = reads + 1;
	}
	result = ntfs_node_stat(root, &before);
	allocations = device->allocations - allocations;
	if (fail_allocation != 0 || fail_read) {
		assert(result == (fail_read ? NTFS_IO : NTFS_NO_MEMORY));
		device->fail_allocation = 0;
		device->fail_read = 0;
		/* Failed presence validation must remain retryable, never cached as
		 * success or as a permanent error on otherwise immutable media. */
		reads = device->reads;
		assert(ntfs_node_stat(root, &before) == NTFS_OK);
		assert(device->reads > reads);
	} else {
		assert(result == NTFS_OK && device->reads > reads);
	}
	assert(before.directory && !before.reparse && before.reference != 0);
	reads = device->reads;
	device->fail_read = reads + 1;
	device->fail_allocation = device->allocations + 1;
	for (i = 0; i < TEST_REPEATED_METADATA; i++) {
		memset(&after, 0, sizeof(after));
		assert(ntfs_node_stat(root, &after) == NTFS_OK);
		assert(memcmp(&before, &after, sizeof(after)) == 0);
		assert(device->reads == reads);
	}
	assert(ntfs_unmount(volume) == NTFS_BUSY);
	ntfs_node_close(root);
	assert(ntfs_unmount(volume) == NTFS_OK && device->memory == 0);
	return allocations;
}

int
main(int argc, char **argv)
{
	struct fuzz_device device = {0};
	FILE *source;
	uint8_t *image;
	long length;
	size_t allocations, i;

	assert(argc == 2);
	source = fopen(argv[1], "rb");
	assert(source != NULL && fseek(source, 0, SEEK_END) == 0);
	length = ftell(source);
	assert(length > 0 && length <= TEST_IMAGE_LIMIT);
	assert(fseek(source, 0, SEEK_SET) == 0);
	image = malloc((size_t)length);
	assert(image != NULL && fread(image, 1, (size_t)length, source) == (size_t)length);
	assert(fclose(source) == 0);
	device.data = image;
	device.size = (size_t)length;
	allocations = exercise(&device, 0, false);
	for (i = 1; i <= allocations; i++) {
		device.reads = 0;
		exercise(&device, i, false);
	}
	device.reads = 0;
	exercise(&device, 0, true);
	free(image);
	printf("PASS: verified metadata has no repeated I/O/allocation; %zu allocation faults and "
	       "read-failure retry; counted owner lifetime\n",
	    allocations);
	return 0;
}
