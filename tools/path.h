/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef NTFS_TOOL_PATH_H
#define NTFS_TOOL_PATH_H
#include <ntfs/ntfs.h>

/* Tool-only UTF-8 path handling, with no symlink traversal or native I/O. */
enum ntfs_result ntfs_tool_resolve(struct ntfs_volume *, const char *, struct ntfs_node **);
enum ntfs_result ntfs_tool_parent(
    struct ntfs_volume *, const char *, struct ntfs_node **, uint16_t *, size_t *);
#endif
