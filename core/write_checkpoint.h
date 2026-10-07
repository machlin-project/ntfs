/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_CHECKPOINT_H
#define MACHLIN_NTFS_WRITE_CHECKPOINT_H
#include "write_journal.h"
#include <ntfs/overwrite.h>

enum ntfs_write_checkpoint_stage {
	NTFS_WRITE_CHECKPOINT_NONE,
	NTFS_WRITE_CHECKPOINT_HOMES_PERSISTED,
	NTFS_WRITE_CHECKPOINT_OLD_FIRST,
	NTFS_WRITE_CHECKPOINT_OLD_SECOND,
	NTFS_WRITE_CHECKPOINT_COPY,
	NTFS_WRITE_CHECKPOINT_HOME,
	NTFS_WRITE_CHECKPOINT_ADVANCED_FIRST,
	NTFS_WRITE_CHECKPOINT_ADVANCED_SECOND,
	NTFS_WRITE_CHECKPOINT_CLEAN_FIRST,
	NTFS_WRITE_CHECKPOINT_CLEAN_SECOND
};

struct ntfs_write_checkpoint_publication {
	uint64_t physical;
	const uint8_t *image;
	enum ntfs_write_checkpoint_stage stage;
};

struct ntfs_write_checkpoint_report {
	uint64_t physical_bytes;
	uint32_t writes, barriers;
	enum ntfs_write_checkpoint_stage durable_stage;
	bool homes_persisted, checkpoint_persisted, completed, poisoned;
};

struct ntfs_write_checkpoint;

/* Experimental settled-history checkpoint. The caller exclusively claims this
 * exact immutable offline image and excludes external readers until close.
 * Preparation acquires the complete history and requires all journal/metadata
 * homes settled. Its actual final Forget becomes the new floor; an open-only
 * suffix, live undo or an unproved home cannot be discarded. Every copied aligned
 * frame is guarded against its actual physical predecessor. All internal
 * immutable children close before return; preparation writes/persists nothing.
 * Execution first persists the settled homes, then publishes dirty old roots,
 * the checkpoint copy/home, dirty advanced roots and clean advanced roots, with
 * a barrier after each transfer. It reads/allocates nothing, consumes once and
 * poisons uncertain I/O. Subsequent mutation requires both roots settled.
 * Output aliases preserve inputs; other preparation errors publish NULL.
 * This private interface supplies no new installed FSKit admission or native
 * recovery qualification. Backend allocator/context stay alive until close. */
enum ntfs_result ntfs_write_checkpoint_prepare(
    const struct ntfs_overwrite_environment *, struct ntfs_write_checkpoint **);
enum ntfs_result ntfs_write_checkpoint_execute(
    struct ntfs_write_checkpoint *, bool *, struct ntfs_write_checkpoint_report *);
size_t ntfs_write_checkpoint_count(const struct ntfs_write_checkpoint *);
const struct ntfs_write_checkpoint_publication *ntfs_write_checkpoint_get(
    const struct ntfs_write_checkpoint *, size_t);
void ntfs_write_checkpoint_close(struct ntfs_write_checkpoint *);

#endif
