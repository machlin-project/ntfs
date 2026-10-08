/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_SPARSE_H
#define MACHLIN_NTFS_WRITE_SPARSE_H
#include "internal.h"

/* Resource policy for this private transform, not an NTFS format limit. */
enum { NTFS_WRITE_SPARSE_MAX_RUNS = 512, NTFS_WRITE_SPARSE_MAX_ZERO_SPANS = 2 };

struct ntfs_write_sparse_input {
	const struct ntfs_run *runs;
	size_t count;
	uint32_t cluster_bytes;
	uint64_t volume_clusters, logical_clusters, offset, bytes;
};

struct ntfs_write_sparse_zero {
	uint64_t physical, bytes;
};

struct ntfs_write_sparse_view {
	const struct ntfs_run *before, *after, *retired;
	size_t before_count, after_count, retired_count;
	struct ntfs_write_sparse_zero zero[NTFS_WRITE_SPARSE_MAX_ZERO_SPANS];
	size_t zero_count;
};

struct ntfs_write_sparse_plan;

/* Private uncompressed zero/punch transform over a complete cluster-rounded
 * mapping. Runs start at VCN zero, are contiguous/nonempty, have bounded physical
 * extents or NTFS_HOLE, and do not cross-own any physical cluster. Geometry uses
 * the existing reader's 512..65536-byte power-of-two cluster bounds. Counts and
 * arithmetic are checked before traversal; the policy caps pair comparisons.
 *
 * Fully covered clusters become holes; at most two partial physical clusters
 * produce exact byte-zero spans. Existing holes require no physical zero. The
 * original mapping is retained verbatim; projected runs merge only physically
 * contiguous mappings or adjacent holes. Retired runs are original full-cluster
 * candidates, not permission to clear allocation or reuse their storage.
 *
 * One owned allocation retains all results after input changes. No read/write
 * callbacks occur. Invalid aliases and over-policy input spans preserve output;
 * other post-admission errors publish NULL. The context must survive close.
 * A zero-length request owns
 * an unchanged plan, after the same validation. This API has no execution path:
 * the caller still owes stream/FILE ownership, partial-data before images, VDL,
 * sparse flags/size accounting, bitmap/SI/FN updates, WAL and native recovery. */
enum ntfs_result ntfs_write_sparse_prepare(const struct ntfs_environment *,
    const struct ntfs_write_sparse_input *, struct ntfs_write_sparse_plan **);
const struct ntfs_write_sparse_view *ntfs_write_sparse_plan_view(
    const struct ntfs_write_sparse_plan *);
void ntfs_write_sparse_plan_close(struct ntfs_write_sparse_plan *);

#endif
