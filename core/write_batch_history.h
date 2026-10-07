/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_BATCH_HISTORY_H
#define MACHLIN_NTFS_WRITE_BATCH_HISTORY_H
#include <ntfs/logfile.h>
#include <ntfs/ntfs.h>

enum { NTFS_WRITE_HISTORY_RECOVERY_RESERVE_DIVISOR = 4 };

struct ntfs_write_batch_resources {
	uint64_t read_calls, read_bytes, allocation_calls, allocation_bytes;
};

struct ntfs_write_batch_history {
	struct ntfs_logfile_restart selected, origin;
	struct ntfs_logfile_client client;
	struct ntfs_logfile_history_report history;
	struct ntfs_write_batch_resources resources;
};

/* Acquire the actual complete retained history and prove all metadata/journal
 * homes already settled before another ordinary operation. The caller owns an
 * exclusive immutable source. This interface has no write/persistence callback,
 * retains no children and publishes only values after closing recovery analysis.
 * Required recovery returns BUSY; unknown history fails closed. Ordinary errors
 * clear the output; an output/source alias leaves it unchanged. */
enum ntfs_result ntfs_write_batch_history_prepare(
    const struct ntfs_environment *, struct ntfs_write_batch_history *);

/* A settled prefix using a quarter of an aggregate recovery budget must be
 * checkpointed before another lifetime is appended. One request can acquire
 * that prefix first for ordinary execution and again for checkpoint preparation;
 * the remaining reserve covers the projected new operation and recovery/undo.
 * This is admission pressure, not a larger recovery or allocator limit. */
bool ntfs_write_batch_history_checkpoint_needed(const struct ntfs_write_batch_history *);

#endif
