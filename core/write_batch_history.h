/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_BATCH_HISTORY_H
#define MACHLIN_NTFS_WRITE_BATCH_HISTORY_H
#include <ntfs/logfile.h>
#include <ntfs/ntfs.h>

struct ntfs_write_batch_history {
	struct ntfs_logfile_restart selected, origin;
	struct ntfs_logfile_client client;
	struct ntfs_logfile_history_report history;
};

/* Acquire the actual complete retained history and prove all metadata/journal
 * homes already settled before another ordinary operation. The caller owns an
 * exclusive immutable source. This interface has no write/persistence callback,
 * retains no children and publishes only values after closing recovery analysis.
 * Required recovery returns BUSY; unknown history fails closed. Ordinary errors
 * clear the output; an output/source alias leaves it unchanged. */
enum ntfs_result ntfs_write_batch_history_prepare(
    const struct ntfs_environment *, struct ntfs_write_batch_history *);

#endif
