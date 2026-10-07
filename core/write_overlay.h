/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_OVERLAY_H
#define MACHLIN_NTFS_WRITE_OVERLAY_H
#include "write_replay.h"
#include <ntfs/validate.h>

/* A fresh immutable full-volume validator sees only this reconstructed FILE
 * overlay. Native source bytes, volume flags and callbacks are unchanged. No
 * memo/child from the original read epoch is reused or survives validation. */
enum ntfs_result ntfs_write_validate_overlay(const struct ntfs_environment *,
    const struct ntfs_write_replay_plan *, struct ntfs_validation_report *);
enum ntfs_result ntfs_write_validate_overlays(const struct ntfs_environment *,
    const struct ntfs_write_replay_plan *, size_t count, struct ntfs_validation_report *);

#endif
