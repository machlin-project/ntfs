/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_RETIREMENT_H
#define MACHLIN_NTFS_WRITE_RETIREMENT_H
#include "write_mutation.h"

enum {
	NTFS_WRITE_RETIREMENT_PREFIX_BYTES = offsetof(struct ntfs_disk_record, used),
	NTFS_WRITE_RETIREMENT_RECORDS = NTFS_WRITE_CLUSTER_BYTES / NTFS_WRITE_RECORD_BYTES,
	NTFS_WRITE_RETIREMENT_MAX_UPDATES = 2 * NTFS_WRITE_RETIREMENT_RECORDS
};

struct ntfs_write_retirement_update {
	struct ntfs_logfile_buffer payload;
	uint16_t record_flags;
};

struct ntfs_write_retirement_program;

/* Compile a checked primary MFT cluster containing only FILE retirement changes.
 * Each retired slot has a full used-prefix Initialize/Noop before-snapshot and
 * a Deallocate/Initialize pair with the native 24-byte header inverse. Retiring
 * advances the reference generation, clears flags and preserves links, attribute
 * bodies and every other logical byte. USA storage and FILE LSN are publication
 * fields. Unchanged neighbors may be uninitialized; changed active/nonretirement
 * slots, mirrors and other geometry are refused. Modern OAT key membership and
 * logical/physical mappings belong to the caller, not this scalar description.
 * The allocated result owns its payloads after source/region close or mutation.
 * Complete pointer admission precedes publication; aliases/range overflow leave
 * output unchanged, other errors publish NULL. Only allocate/release callbacks
 * occur. No device mutation, selected history, compensation or writable admission
 * is supplied. WAL links, complete cross-object recovery, sector protection and
 * barriers remain obligations of the native transaction owner. */
enum ntfs_result ntfs_write_retirement_program_prepare(const struct ntfs_environment *,
    const struct ntfs_write_mutation_region *, uint16_t key,
    struct ntfs_write_retirement_program **);
size_t ntfs_write_retirement_program_count(const struct ntfs_write_retirement_program *);
const struct ntfs_write_retirement_update *ntfs_write_retirement_program_get(
    const struct ntfs_write_retirement_program *, size_t);
void ntfs_write_retirement_program_close(struct ntfs_write_retirement_program *);

/* Apply one native Deallocate/Initialize pair to a private restored FILE buffer.
 * Both the active predecessor and its exact retired successor are admitted;
 * unrelated generations or changed link/header geometry are STALE. The undo
 * copies only the native header prefix, leaving the complete body untouched.
 * Redo increments sequence (zero is skipped), clears flags and retains links.
 * Repeated redo/undo is idempotent. lsn is the owning redo/compensation LSN and
 * must be nonzero; this helper does not choose replay eligibility or history.
 * Complete admission precedes changing bytes. Every error preserves the FILE;
 * payload and destination are disjoint. No callbacks, allocation, protection,
 * disk/OAT binding or recovery admission occur. */
enum ntfs_result ntfs_write_retirement_apply(
    const void *payload, size_t bytes, bool undo, uint64_t lsn, void *, size_t);

#endif
