/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_OWNER_H
#define MACHLIN_NTFS_WRITE_OWNER_H
#include "write_status.h"
#include <ntfs/overwrite.h>

/* Private image owner admission including executed bounded native recovery.
 * Public metadata-preserving overwrite admission remains unchanged. */
enum ntfs_result ntfs_write_owner_open(const struct ntfs_overwrite_environment *,
    struct ntfs_overwrite_admission *, struct ntfs_write_recovery_report *,
    struct ntfs_overwrite **);

struct ntfs_write_range_report {
	struct ntfs_write_execution_report execution;
	uint64_t requested_bytes, completed_bytes;
};

/* Private bounded image writing. The separate overwrite owner supplies
 * exclusive authorized claim, memory/read governors and the true persistence
 * transport. Fresh full validation, native history/settled-home binding and
 * absence of hibernation/change-journal state precede private planning. Every
 * immutable epoch closes before device writes. Allocation/size/namespace/ADS
 * stay unchanged; resident DATA and initialized nonresident ranges use their
 * owning FILE journal family and update ordinary SI times. FSKit's image owner
 * calls this helper only after closing all immutable readers. Block resources
 * remain read-only, and the metadata-preserving overwrite API is separate. */
enum ntfs_result ntfs_write_existing_range(struct ntfs_overwrite *, uint64_t reference,
    uint64_t offset, const void *, size_t, uint64_t filetime, struct ntfs_write_range_report *);

#endif
