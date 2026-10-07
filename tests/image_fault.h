/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef NTFS_TEST_IMAGE_FAULT_H
#define NTFS_TEST_IMAGE_FAULT_H

#include "../adapters/posix/overwrite_image.h"

/* Bounded instrumentation for one native-image transaction. All event storage
 * is reserved before owner admission. Product transports never use this shim. */
enum {
	NTFS_IMAGE_FAULT_EVENTS = 32,
	NTFS_IMAGE_FAULT_STORAGE_BYTES = NTFS_IMAGE_FAULT_EVENTS * NTFS_OVERWRITE_MAX_BYTES
};

struct ntfs_image_fault_event {
	uint64_t physical;
	size_t bytes, completed;
	enum ntfs_result native_result, result;
	bool barrier, injected, native_attempted;
};

enum {
	NTFS_IMAGE_FAULT_ALLOCATION_BYTES = NTFS_IMAGE_FAULT_EVENTS *
	    (NTFS_OVERWRITE_MAX_BYTES + sizeof(struct ntfs_image_fault_event))
};

struct ntfs_image_fault {
	struct ntfs_overwrite_image image;
	struct ntfs_overwrite_environment environment;
	struct ntfs_image_fault_event *event;
	uint8_t *storage;
	size_t event_capacity, event_bytes, events, writes, barriers, fail_write, fail_barrier,
	    prefix;
	bool enabled, triggered, native_failure;
};

int ntfs_image_fault_open(const char *, size_t, size_t, size_t, struct ntfs_image_fault *);
/* The private caller supplies measured event capacity and the maximum transfer
 * size. Both allocations retain the default profile's bounded storage ceiling.
 * No growth or allocation occurs after the owner is admitted. */
int ntfs_image_fault_open_bounded(
    const char *, size_t, size_t, size_t, size_t, size_t, struct ntfs_image_fault *);
void ntfs_image_fault_close(struct ntfs_image_fault *);
int ntfs_image_fault_dump(const struct ntfs_image_fault *, const char *);

#endif
