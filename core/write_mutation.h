/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_MUTATION_H
#define MACHLIN_NTFS_WRITE_MUTATION_H
#include "write_execute.h"
#include "write_checkpoint.h"

struct ntfs_write_name {
	uint64_t parent_reference;
	const uint16_t *units;
	size_t count;
};

struct ntfs_write_mutation_report {
	struct ntfs_write_execution_report execution;
	struct ntfs_write_checkpoint_report checkpoint;
	uint64_t reference, requested_bytes, completed_bytes;
	bool initial_persistence_attempted, initial_persistence_succeeded, checkpointed;
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

enum ntfs_write_creation_time_field {
	NTFS_WRITE_CREATION_CREATED = 1u << 0,
	NTFS_WRITE_CREATION_MODIFIED = 1u << 1,
	NTFS_WRITE_CREATION_CHANGED = 1u << 2,
	NTFS_WRITE_CREATION_ACCESSED = 1u << 3,
	NTFS_WRITE_CREATION_ALL_TIMES = NTFS_WRITE_CREATION_CREATED | NTFS_WRITE_CREATION_MODIFIED |
	    NTFS_WRITE_CREATION_CHANGED | NTFS_WRITE_CREATION_ACCESSED
};

/* Optional creation FILETIMEs, in unsigned 100-ns ticks since 1601. Unselected
 * fields default to the operation time. Both the new standard information and
 * filename/index cache carry these values; the parent keeps the operation time. */
struct ntfs_write_creation_times {
	uint64_t created, modified, changed, accessed;
	uint32_t fields;
};

struct ntfs_write_mutation_request {
	enum ntfs_write_mutation_kind kind;
	struct ntfs_write_name source, destination;
	uint64_t reference, offset, size, filetime;
	struct ntfs_write_creation_times creation_times;
	const void *data;
	size_t bytes;
	bool replace;
};

struct ntfs_write_mutation_item {
	struct ntfs_stat stat;
	struct ntfs_link_counts links;
};

/* Value-only final metadata for native reply preparation. Retired items retain
 * their old sequence-bearing identity and sizes but project zero live links.
 * No node, stream, source callback or borrowed request storage escapes here. */
struct ntfs_write_mutation_preview {
	enum ntfs_write_mutation_kind kind;
	struct ntfs_write_mutation_item item, source_directory, destination_directory, over_item;
	uint64_t requested_bytes, free_clusters;
	bool item_exists, source_directory_present, destination_directory_present;
	bool over_item_present, over_item_exists, checkpoint_required;
};

struct ntfs_write_mutation_execution;

/* Validate request values and name spans without callbacks or allocation. */
bool ntfs_write_mutation_request_valid(const struct ntfs_write_mutation_request *);

/* Preparation reserves the complete mutation, optional checkpoint and exact
 * projected metadata without writes or persistence. Request/name/data storage
 * can be released after return. One prepared child excludes further owner work.
 * Native callers construct all fallible replies before execute. Execution is
 * one-shot, performs no reads/allocation, and permanently poisons uncertain I/O.
 * Closing a prepared child without execution leaves all media bytes unchanged.
 * Closing its parent defers claim release until the child closes and prevents
 * execution. The borrowed preview remains valid through child close. */
enum ntfs_result ntfs_write_mutation_execution_prepare(struct ntfs_overwrite *,
    const struct ntfs_write_mutation_request *, struct ntfs_write_mutation_execution **);
const struct ntfs_write_mutation_preview *ntfs_write_mutation_execution_preview(
    const struct ntfs_write_mutation_execution *);
enum ntfs_result ntfs_write_mutation_execution_execute(
    struct ntfs_write_mutation_execution *, struct ntfs_write_mutation_report *);
void ntfs_write_mutation_execution_close(struct ntfs_write_mutation_execution *);

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
 * Journal-space reclamation prepares a checkpoint and rebinds execution to its
 * exact private final view before either operation can write. Failed preparation
 * therefore cannot publish a checkpoint. The report retains checkpoint and
 * initial-persistence outcomes independently of mutation completion.
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
