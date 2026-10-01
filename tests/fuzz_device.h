/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef NTFS_FUZZ_DEVICE_H
#define NTFS_FUZZ_DEVICE_H
#include <ntfs/ntfs.h>

enum { FUZZ_MEMORY_BUDGET = 8 * 1024 * 1024, FUZZ_READ_BUDGET = 4096 };

struct fuzz_device {
	const uint8_t *data;
	size_t size, memory, reads, allocations, fail_read, fail_allocation;
};

void *fuzz_allocate(void *, size_t);
void fuzz_release(void *, void *, size_t);
enum ntfs_result fuzz_read(void *, uint64_t, void *, size_t);
struct ntfs_environment fuzz_environment(struct fuzz_device *);
#endif
