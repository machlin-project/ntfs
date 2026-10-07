/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_BATCH_EXECUTE_H
#define MACHLIN_NTFS_WRITE_BATCH_EXECUTE_H
#include "write_program.h"

struct ntfs_write_batch_execution;

struct ntfs_write_batch_publication {
	uint64_t physical;
	const uint8_t *image;
	enum ntfs_write_execution_stage stage;
	bool barrier;
};

/* Experimental complete-operation physical preparation. The caller already
 * authorizes/exclusively claims the backend and excludes all external readers.
 * The sealed program must describe this exact immutable claimed source; its
 * logical/physical mapping proof belongs to the mutation planner. The caller
 * preserves that source from planning through execution, or supplies an exact
 * copy. This executor does not independently resolve every logical target.
 * This owner acquires the original settled qualified history, derives its exact
 * successor, creates the complete program's pages and rechecks every changed
 * physical before image. All copied/aligned publications, guards and metadata
 * validation precede output. Every internal immutable child closes on return.
 * Program bytes may be released after success. Failed preparation writes and
 * persists nothing; aliases preserve output, other failures publish NULL.
 * Execute performs no reads/allocation, consumes the preparation once and
 * poisons after any uncertain attempted write/barrier. New families still need
 * journal-derived recovery and Windows acceptance before owner/FSKit admission.
 * Backend allocator/context live until close; alignment is 512..4096 bytes. */
enum ntfs_result ntfs_write_batch_execute_prepare(const struct ntfs_overwrite_environment *,
    const struct ntfs_write_program *, struct ntfs_write_batch_execution **);
enum ntfs_result ntfs_write_batch_execute(
    struct ntfs_write_batch_execution *, bool *poisoned, struct ntfs_write_execution_report *);
size_t ntfs_write_batch_execution_count(const struct ntfs_write_batch_execution *);
const struct ntfs_write_batch_publication *ntfs_write_batch_execution_get(
    const struct ntfs_write_batch_execution *, size_t);
void ntfs_write_batch_execution_close(struct ntfs_write_batch_execution *);

#endif
