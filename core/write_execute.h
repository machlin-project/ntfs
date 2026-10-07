/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_EXECUTE_H
#define MACHLIN_NTFS_WRITE_EXECUTE_H
#include "write_journal.h"
#include "write_status.h"
#include <ntfs/overwrite.h>

enum {
	NTFS_WRITE_EXECUTE_RESTART_FIRST,
	NTFS_WRITE_EXECUTE_RESTART_SECOND,
	NTFS_WRITE_EXECUTE_PREPARE_HOME,
	NTFS_WRITE_EXECUTE_COMMIT_HOME,
	NTFS_WRITE_EXECUTE_PREPARE_COPY,
	NTFS_WRITE_EXECUTE_COMMIT_COPY,
	NTFS_WRITE_EXECUTE_LOG_LOCATIONS,
	NTFS_WRITE_EXECUTE_FRAMES = 8,
	NTFS_WRITE_EXECUTE_MAX_SPANS = NTFS_OVERWRITE_MAX_BYTES / NTFS_MST_STRIDE + 2,
	NTFS_WRITE_EXECUTE_MAX_DATA_BYTES = NTFS_OVERWRITE_MAX_BYTES + NTFS_WRITE_CLUSTER_BYTES
};

struct ntfs_write_data_span {
	uint64_t physical;
	const void *image;
	size_t bytes;
};

struct ntfs_write_execution_input {
	const struct ntfs_write_journal_plan *journal;
	const struct ntfs_write_file_plan *file;
	const void *restart[NTFS_LFS_RESTART_PAGES];
	uint64_t physical[NTFS_WRITE_EXECUTE_LOG_LOCATIONS];
	const struct ntfs_write_data_span *data;
	size_t spans;
};

struct ntfs_write_execution_workspace {
	/* The caller aligns this complete private object to the device alignment. */
	uint8_t frame[NTFS_WRITE_EXECUTE_FRAMES][NTFS_WRITE_CLUSTER_BYTES];
	uint8_t home[NTFS_WRITE_CLUSTER_BYTES], before[NTFS_WRITE_CLUSTER_BYTES];
	struct ntfs_write_journal_workspace guard;
	struct ntfs_overwrite_environment backend;
	struct ntfs_write_data_span data[NTFS_WRITE_EXECUTE_MAX_SPANS];
	uint64_t physical[NTFS_WRITE_EXECUTE_LOG_LOCATIONS], home_physical;
	size_t spans;
	bool prepared;
};

/* Private experiment for the native retained-root transaction protocol. The
 * owning caller has authorized and exclusively claimed the resource, bound the
 * complete native history and every physical mapping, and validated the full
 * reconstructed volume. Preparation reads exact preceding physical images and
 * guards every MST publication before mutation. All immutable epochs/children
 * close before execution. This helper cannot acquire ownership or admit FSKit
 * writes; native interruption acceptance remains a separate gate.
 * Workspace and borrowed data stay private and unchanged between calls.
 * Execution performs no allocation/read, uses a true persistence barrier after
 * each metadata publication and the complete initialized data overwrite, and
 * permanently poisons caller state after any uncertain attempted I/O. */
enum ntfs_result ntfs_write_execute_prepare(const struct ntfs_overwrite_environment *,
    const struct ntfs_write_execution_input *, struct ntfs_write_execution_workspace *);
enum ntfs_result ntfs_write_execute(
    struct ntfs_write_execution_workspace *, bool *poisoned, struct ntfs_write_execution_report *);

#endif
