/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_RECOVER_H
#define MACHLIN_NTFS_WRITE_RECOVER_H
#include "write_history.h"
#include "write_status.h"
#include <ntfs/overwrite.h>

struct ntfs_write_recovery_workspace {
	/* Complete aligned publications; no read epoch survives execution. */
	uint8_t restart[NTFS_LFS_RESTART_PAGES][NTFS_WRITE_CLUSTER_BYTES];
	uint8_t dirty[NTFS_LFS_RESTART_PAGES][NTFS_WRITE_CLUSTER_BYTES];
	uint8_t clean[NTFS_LFS_RESTART_PAGES][NTFS_WRITE_CLUSTER_BYTES];
	uint8_t home[NTFS_WRITE_HISTORY_TRANSACTIONS][NTFS_WRITE_CLUSTER_BYTES];
	uint8_t log_home[2 * NTFS_WRITE_HISTORY_TRANSACTIONS][NTFS_WRITE_CLUSTER_BYTES];
	uint8_t scratch[NTFS_WRITE_CLUSTER_BYTES];
	uint8_t abort_page[NTFS_WRITE_CLUSTER_BYTES], abort_copy[NTFS_WRITE_CLUSTER_BYTES];
	struct ntfs_write_abort_plan abort;
	struct ntfs_write_history_workspace history_work;
	struct ntfs_write_history history;
	struct ntfs_write_journal_workspace guard;
	struct ntfs_validation_report validation;
	struct ntfs_overwrite_environment backend;
	uint64_t restart_physical[NTFS_LFS_RESTART_PAGES], abort_physical, copy_physical;
	uint64_t home_physical[NTFS_WRITE_HISTORY_TRANSACTIONS];
	uint64_t log_physical[2 * NTFS_WRITE_HISTORY_TRANSACTIONS];
	uint32_t homes, logs, files;
	bool home_changed[NTFS_WRITE_HISTORY_TRANSACTIONS];
	bool log_changed[2 * NTFS_WRITE_HISTORY_TRANSACTIONS];
	bool close_transaction, mutation, prepared;
};

/* Private recovery experiment: acquire exact owning history, preflight all
 * publications and validate the complete reconstructed volume. Only the known
 * bounded family can be redone or compensated; C checkpoints/unknown histories
 * remain refused. The caller exclusively claims the backend and closes every
 * immutable child/volume before execute. Execution allocates and reads nothing,
 * retains original checkpoint roots, and poisons after any uncertain I/O. */
enum ntfs_result ntfs_write_recover_prepare(struct ntfs_volume *,
    const struct ntfs_overwrite_environment *, struct ntfs_write_recovery_workspace *);
enum ntfs_result ntfs_write_recover_execute(
    struct ntfs_write_recovery_workspace *, bool *poisoned, struct ntfs_write_recovery_report *);

#endif
