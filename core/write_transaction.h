/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_TRANSACTION_H
#define MACHLIN_NTFS_WRITE_TRANSACTION_H
#include "write_execute.h"
#include "write_history.h"

struct ntfs_write_transaction_workspace {
	struct ntfs_write_history_workspace history_work;
	struct ntfs_write_history history;
	struct ntfs_write_journal_workspace journal_work;
	struct ntfs_write_journal_plan journal;
	struct ntfs_write_file_plan file;
	uint8_t restart[NTFS_LFS_RESTART_PAGES][NTFS_WRITE_CLUSTER_BYTES];
	struct ntfs_write_execution_input execution;
};

/* Prepare one bounded append from the exact owning retained history. Every
 * preceding transaction must already have its complete committed home image;
 * prepared, torn, unpublished-checkpoint and unknown histories require recovery
 * instead of another mutation. Physical journal mappings and FILE metadata are
 * captured under the caller's immutable serialized epoch. No write occurs. */
enum ntfs_result ntfs_write_prepare_transaction(
    struct ntfs_node *, uint64_t filetime, struct ntfs_write_transaction_workspace *);
enum ntfs_result ntfs_write_prepare_resident_transaction(struct ntfs_node *, uint64_t filetime,
    uint64_t offset, const void *, size_t, struct ntfs_write_transaction_workspace *);

#endif
