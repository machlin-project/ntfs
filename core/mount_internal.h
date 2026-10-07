/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_MOUNT_INTERNAL_H
#define MACHLIN_NTFS_MOUNT_INTERNAL_H
#include <ntfs/ntfs.h>

/* Private journal-acquisition owner. Boot geometry, complete MFT replicas,
 * mappings, volume information and collation retain their ordinary checks.
 * Namespace admission is deferred because a committed root FILE may be torn.
 * The caller must close this owner without publishing it, bind journal-derived
 * repair privately and validate complete projected volumes before any write.
 * Public read-only mount admission is unchanged. */
enum ntfs_result ntfs_mount_journal(
    const struct ntfs_environment *, const struct ntfs_limits *, struct ntfs_volume **);

#endif
