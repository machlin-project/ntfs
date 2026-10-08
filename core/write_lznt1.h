/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_LZNT1_H
#define MACHLIN_NTFS_WRITE_LZNT1_H
#include <ntfs/ntfs.h>

/* Private resource policies, not NTFS format limits. */
enum { NTFS_WRITE_LZNT1_MAX_BYTES = 1024 * 1024 };

/* Original bounded LZNT1 byte encoder. Each 4096-byte source chunk has its own
 * dictionary. A compressed body is used only when shorter than its raw source;
 * otherwise that chunk is emitted uncompressed. Empty input emits zero bytes.
 * No end marker or allocation padding is added. This does not authorize NTFS
 * unit placement, compressed stream metadata, allocation, WAL or any mutation.
 *
 * The bound query does not inspect input. Measure computes the exact size.
 * Encode accepts that exact capacity; capacities below the raw bound are measured
 * before publishing bytes. Raw-bound capacity needs only one encoding pass.
 * All errors leave output and size results unchanged. After valid disjoint
 * buffer admission, workspace is mutable, even when encode returns RANGE for
 * insufficient output. All capacities participate in alias/range checks. The
 * workspace needs no alignment; its unused tail stays unchanged. Empty input
 * needs no workspace. Inputs must remain immutable throughout each call.
 *
 * Work and memory are bounded: one candidate per three-byte hash, no chains,
 * one pass for measure and one or two for encode, constant stack, fixed caller
 * workspace, at most MAX_BYTES input. No callbacks or allocator calls occur. */
size_t ntfs_write_lznt1_workspace_size(void);
enum ntfs_result ntfs_write_lznt1_bound(size_t, size_t *);
enum ntfs_result ntfs_write_lznt1_measure(const void *, size_t, void *, size_t, size_t *);
enum ntfs_result ntfs_write_lznt1_encode(
    const void *, size_t, void *, size_t, void *, size_t, size_t *);

#endif
