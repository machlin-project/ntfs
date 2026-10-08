/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_VALIDATE_INTERNAL_H
#define MACHLIN_NTFS_VALIDATE_INTERNAL_H

#include "internal.h"
#include <ntfs/validate.h>

enum {
	VALIDATION_DEFAULT_RECORDS = 1048576,
	VALIDATION_DEFAULT_RUNS = 1048576,
	VALIDATION_DEFAULT_LINKS = 1048576,
	VALIDATION_DEFAULT_MEMORY = 64 * 1024 * 1024,
	VALIDATION_DEFAULT_READ_CALLS = 1048576,
	VALIDATION_VECTOR_START = 16,
	VALIDATION_VECTOR_GROWTH = 2,
	VALIDATION_FILENAME_SOURCE = 1,
	VALIDATION_INDEX_SOURCE = 2,
	VALIDATION_LINK_PAIR = 2,
	VALIDATION_RESERVED_FIRST = 12,
	VALIDATION_RESERVED_LAST = 15,
	VALIDATION_DIRECTORY_VISITING = 1,
	VALIDATION_DIRECTORY_VISITED = 2
};

#define VALIDATION_DEFAULT_READ_BYTES (UINT64_C(4) * 1024 * 1024 * 1024)
#define VALIDATION_DEFAULT_WORK (UINT64_C(4) * 1024 * 1024 * 1024)

struct ntfs_validation_record {
	uint64_t reference, base, parent;
	uint32_t security_id;
	uint16_t primary_names, dos_names;
	uint16_t flags, links;
	uint8_t directory_state;
	bool reserved_empty;
	bool reserved_inert;
	bool hidden_system;
};

struct ntfs_validation_run {
	uint64_t first, end, reference;
	uint32_t type;
};

struct ntfs_validation_link {
	uint64_t parent, reference;
	uint32_t offset;
	uint16_t length;
	uint8_t name_namespace, source;
};

struct ntfs_validation_context {
	struct ntfs_environment source;
	struct ntfs_validation_limits limits;
	struct ntfs_validation_report *report;
	struct ntfs_volume *volume;
	struct ntfs_validation_record *records;
	struct ntfs_validation_run *runs;
	struct ntfs_validation_link *links;
	uint16_t *names;
	uint32_t run_count, run_capacity, link_count, link_capacity;
	uint32_t name_count, name_capacity;
	size_t memory;
	bool has_security_ids;
	enum ntfs_result failure;
};

enum ntfs_result ntfs_validation_limit_failure(
    struct ntfs_validation_context *v, enum ntfs_validation_limit limit);
enum ntfs_result ntfs_validation_charge(struct ntfs_validation_context *v, uint64_t units);
void *ntfs_validation_allocate(void *context, size_t size);
void ntfs_validation_release(void *context, void *memory, size_t size);
enum ntfs_result ntfs_validation_read(void *context, uint64_t offset, void *bytes, size_t size);
enum ntfs_result ntfs_validation_grow(struct ntfs_validation_context *v, void **buffer,
    uint32_t *capacity, uint32_t needed, size_t element_size, uint32_t maximum,
    enum ntfs_validation_limit limit);
struct ntfs_validation_record *ntfs_validation_checked_reference(
    struct ntfs_validation_context *v, uint64_t reference);
enum ntfs_result ntfs_validation_scan_records(struct ntfs_validation_context *v);
enum ntfs_result ntfs_validation_sort(struct ntfs_validation_context *v, void *storage,
    size_t stride, uint32_t count,
    int (*compare)(struct ntfs_validation_context *, const void *, const void *));
enum ntfs_result ntfs_validation_index_inventory_work(void *context, uint64_t units);
enum ntfs_result ntfs_validation_scan_namespace(struct ntfs_validation_context *v);
enum ntfs_result ntfs_validation_scan_allocation(struct ntfs_validation_context *v);
enum ntfs_result ntfs_validation_scan_boot(struct ntfs_validation_context *v);
enum ntfs_result ntfs_validation_scan_mirror(struct ntfs_validation_context *v);
enum ntfs_result ntfs_validation_remember_link(struct ntfs_validation_context *v, uint64_t parent,
    uint64_t reference, const uint16_t *name, uint16_t length, uint8_t name_namespace,
    uint8_t source);
enum ntfs_result ntfs_validation_scan_attributes(struct ntfs_validation_context *v);
enum ntfs_result ntfs_validation_scan_security(struct ntfs_validation_context *validation);

#endif
