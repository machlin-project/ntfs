/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "fuzz_device.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

union fuzz_allocation {
	max_align_t alignment;
	size_t size;
};

void *
fuzz_allocate(void *context, size_t size)
{
	struct fuzz_device *d = context;
	union fuzz_allocation *p;

	d->allocations++;
	if (d->allocations == d->fail_allocation || size > FUZZ_MEMORY_BUDGET - d->memory) {
		return NULL;
	}
	p = malloc(sizeof(*p) + size);
	if (p == NULL) {
		return NULL;
	}
	p->size = size;
	d->memory += size;
	return p + 1;
}

void
fuzz_release(void *context, void *memory, size_t size)
{
	struct fuzz_device *d = context;
	union fuzz_allocation *p = (union fuzz_allocation *)memory - 1;

	assert(p->size == size && size <= d->memory);
	d->memory -= size;
	free(p);
}

enum ntfs_result
fuzz_read(void *context, uint64_t offset, void *memory, size_t size)
{
	struct fuzz_device *d = context;

	if (++d->reads > FUZZ_READ_BUDGET || d->reads == d->fail_read || offset > d->size ||
	    size > d->size - offset) {
		return NTFS_IO;
	}
	memcpy(memory, d->data + offset, size);
	return NTFS_OK;
}

struct ntfs_environment
fuzz_environment(struct fuzz_device *device)
{
	return (struct ntfs_environment){
	    NTFS_API_VERSION, device, device->size, fuzz_read, fuzz_allocate, fuzz_release};
}
