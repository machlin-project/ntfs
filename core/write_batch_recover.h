/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_BATCH_RECOVER_H
#define MACHLIN_NTFS_WRITE_BATCH_RECOVER_H
#include "write_execute.h"

struct ntfs_write_batch_recovery;

struct ntfs_write_batch_recovery_publication {
	uint64_t physical;
	const uint8_t *image;
	enum ntfs_write_recovery_stage stage;
};

/* Experimental journal-derived recovery of the complete ordinary-mutation
 * family. No original mutation plan, program or execution owner is an input.
 * Admission retains an exact quiet or settled-Forget origin, a settled qualified prefix and
 * complete ordinary-operation lifetimes. Only the last lifetime may require
 * redo or remaining compensation. Earlier complete before/after object views,
 * physical mappings and FILE retirement/reuse generations are proved privately
 * against the full retained history. Original free bytes discarded by later
 * initialization are never fabricated as physical source evidence. Unproved
 * index/cluster reuse remains unsupported. Experimental settled checkpoint
 * recovery proves the complete old history, actual terminal Forget and new
 * checkpoint before advancing disagreeing valid roots. New-origin circular
 * packet homes must be complete before the next operation reuses copy slots.
 * The caller authorizes and exclusively claims this immutable backend, excludes
 * readers throughout preparation/execution and keeps its allocator alive until
 * close. Preparation owns every aligned publication and closes every immutable
 * child before returning. No media write/persistence occurs during preparation.
 * Unsupported histories and unproved targets fail closed. Alias failures leave
 * output unchanged; other failures publish NULL. Execution consumes the owner
 * once, reads/allocates nothing and permanently poisons uncertain transfers or
 * barriers. This private interface does not admit new FSKit operations or claim
 * Windows recovery qualification. */
enum ntfs_result ntfs_write_batch_recover_prepare(
    const struct ntfs_overwrite_environment *, struct ntfs_write_batch_recovery **);
enum ntfs_result ntfs_write_batch_recover_execute(
    struct ntfs_write_batch_recovery *, bool *, struct ntfs_write_recovery_report *);
size_t ntfs_write_batch_recovery_count(const struct ntfs_write_batch_recovery *);
const struct ntfs_write_batch_recovery_publication *ntfs_write_batch_recovery_get(
    const struct ntfs_write_batch_recovery *, size_t);
void ntfs_write_batch_recovery_close(struct ntfs_write_batch_recovery *);

#endif
