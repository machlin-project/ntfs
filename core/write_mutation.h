/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_MUTATION_H
#define MACHLIN_NTFS_WRITE_MUTATION_H
#include "write_execute.h"

struct ntfs_write_name {
	uint64_t parent_reference;
	const uint16_t *units;
	size_t count;
};

struct ntfs_write_mutation_report {
	struct ntfs_write_execution_report execution;
	uint64_t reference, requested_bytes, completed_bytes;
};

enum ntfs_write_mutation_kind {
	NTFS_WRITE_CREATE_FILE,
	NTFS_WRITE_CREATE_DIRECTORY,
	NTFS_WRITE_RESIZE_FILE,
	NTFS_WRITE_GROWING_RANGE,
	NTFS_WRITE_REMOVE_FILE,
	NTFS_WRITE_REMOVE_DIRECTORY,
	NTFS_WRITE_RENAME
};

struct ntfs_write_mutation_request {
	enum ntfs_write_mutation_kind kind;
	struct ntfs_write_name source, destination;
	uint64_t reference, offset, size, filetime;
	const void *data;
	size_t bytes;
	bool replace;
};

enum ntfs_write_mutation_region_kind {
	NTFS_WRITE_MUTATION_FILE,
	NTFS_WRITE_MUTATION_INDEX,
	NTFS_WRITE_MUTATION_BITMAP,
	NTFS_WRITE_MUTATION_DATA
};

enum { NTFS_WRITE_MUTATION_TARGET_NAME_UNITS = 4 };

/* Logical stream identity belongs to the mutation owner, which has the checked
 * FILE reference and mapping at the point of preparation. A mirror region is a
 * replica of the named MFT stream region, not another journal target. */
struct ntfs_write_mutation_target {
	uint64_t reference, logical_offset;
	uint32_t attribute_type;
	uint16_t name[NTFS_WRITE_MUTATION_TARGET_NAME_UNITS];
	size_t name_count;
	bool mirror;
};

/* Original object ownership, independent of projected allocation and signatures
 * in free storage. FILE bits name framed, originally allocated predecessors in
 * consecutive 1-KiB slots; an INDX predecessor requires its original mapping
 * and index bitmap. Framed free FILE storage is not an old object. */
struct ntfs_write_mutation_predecessor {
	uint8_t file_slots;
	bool index_allocated;
};

struct ntfs_write_mutation_region {
	uint64_t physical;
	const uint8_t *before, *after;
	size_t bytes;
	enum ntfs_write_mutation_region_kind kind;
	struct ntfs_write_mutation_target target;
	struct ntfs_write_mutation_predecessor predecessor;
};

struct ntfs_write_mutation_plan;

/* Pure complete-image preparation. The returned private regions and projected
 * immutable view are planning evidence, not an execution/recovery capability.
 * Source bytes remain unchanged. Borrowed source/request/name/data ranges must
 * be disjoint from output; invalid aliases leave their bytes unchanged. Other
 * failed preparations publish NULL. The native journal owner must separately bind
 * every region, reserve WAL/recovery and close this view before any transfer. */
enum ntfs_result ntfs_write_mutation_prepare(const struct ntfs_environment *,
    const struct ntfs_write_mutation_request *, struct ntfs_write_mutation_plan **);
enum ntfs_result ntfs_write_mutation_plan_view(
    const struct ntfs_write_mutation_plan *, struct ntfs_environment *);
enum ntfs_result ntfs_write_mutation_plan_region(
    const struct ntfs_write_mutation_plan *, size_t, struct ntfs_write_mutation_region *);
size_t ntfs_write_mutation_plan_count(const struct ntfs_write_mutation_plan *);
uint64_t ntfs_write_mutation_plan_reference(const struct ntfs_write_mutation_plan *);
void ntfs_write_mutation_plan_close(struct ntfs_write_mutation_plan *);

/* These operations share the exclusive image owner and its poison/lifetime
 * contract. Borrowed names and data remain immutable and disjoint from output.
 * All fallible reservations and complete metadata validation precede writes.
 * No immutable core child survives mutation. Success is durable and publishes
 * the complete namespace/allocation change; report.reference is sequence-bearing.
 * This interface does not grant FSKit admission for unqualified operations. */
enum ntfs_result ntfs_write_create_file(struct ntfs_overwrite *, const struct ntfs_write_name *,
    uint64_t filetime, struct ntfs_write_mutation_report *);
enum ntfs_result ntfs_write_create_directory(struct ntfs_overwrite *,
    const struct ntfs_write_name *, uint64_t filetime, struct ntfs_write_mutation_report *);
enum ntfs_result ntfs_write_resize_file(struct ntfs_overwrite *, uint64_t reference, uint64_t bytes,
    uint64_t filetime, struct ntfs_write_mutation_report *);
enum ntfs_result ntfs_write_growing_range(struct ntfs_overwrite *, uint64_t reference,
    uint64_t offset, const void *, size_t, uint64_t filetime, struct ntfs_write_mutation_report *);
enum ntfs_result ntfs_write_remove_file(struct ntfs_overwrite *, const struct ntfs_write_name *,
    uint64_t filetime, struct ntfs_write_mutation_report *);
enum ntfs_result ntfs_write_remove_directory(struct ntfs_overwrite *,
    const struct ntfs_write_name *, uint64_t filetime, struct ntfs_write_mutation_report *);
enum ntfs_result ntfs_write_rename(struct ntfs_overwrite *, const struct ntfs_write_name *source,
    const struct ntfs_write_name *destination, bool replace, uint64_t filetime,
    struct ntfs_write_mutation_report *);

#endif
