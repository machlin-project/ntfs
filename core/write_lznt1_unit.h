/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_LZNT1_UNIT_H
#define MACHLIN_NTFS_WRITE_LZNT1_UNIT_H
#include "internal.h"

enum ntfs_write_lznt1_unit_kind {
	NTFS_WRITE_LZNT1_UNIT_EMPTY,
	NTFS_WRITE_LZNT1_UNIT_SPARSE,
	NTFS_WRITE_LZNT1_UNIT_RAW,
	NTFS_WRITE_LZNT1_UNIT_PACKED
};

struct ntfs_write_lznt1_unit_input {
	const void *source;
	size_t source_bytes, logical_bytes, initialized_bytes;
	uint32_t cluster_bytes;
};

struct ntfs_write_lznt1_unit_view {
	enum ntfs_write_lznt1_unit_kind kind;
	const uint8_t *payload;
	size_t stored_bytes, encoded_bytes, unit_bytes, logical_bytes, initialized_bytes;
	uint32_t cluster_bytes, logical_clusters, physical_clusters, hole_clusters;
};

struct ntfs_write_lznt1_unit;

/* Private new-content packet owner for the reader's 16-cluster LZNT1 profile,
 * with power-of-two clusters from 512 through 4096 bytes. Source declarations
 * are at most one unit; initialized_bytes must fit source_bytes/logical_bytes.
 * Only the initialized prefix is read. The rest of the full unit is zero,
 * including bytes past logical EOF. Nonempty results describe a complete
 * logical unit; these counts do not decide a native FILE tail's mapping span.
 *
 * Empty logical content owns an EMPTY result. All-zero normalized content owns
 * a SPARSE result. Otherwise PACKED storage needs a physical prefix shorter
 * than the unit and a positive virtual-hole suffix. Its stored bytes are whole
 * clusters. Exact packet boundaries need no marker; padding contains a complete
 * zero header. A one-byte padding gap needs another cluster, or RAW fallback.
 * RAW storage owns the complete normalized unit without LZNT1 chunk headers.
 *
 * One allocation owns the result after caller data/metadata change. Nonzero
 * content uses sizeof(owner) + unit bytes + encoder bound + encoder workspace;
 * all-zero/empty results need only the owner. No read callback, physical cluster
 * allocation, runlist, bitmap, FILE, WAL or media operation occurs. The allocator
 * context must survive close, and all input storage stays immutable during the
 * call. Pre-allocation admission errors preserve out; allocation/encoding errors
 * publish NULL. Out may not overlap any declared input/environment/source span.
 * This API does not enable compressed filesystem writes. */
enum ntfs_result ntfs_write_lznt1_unit_prepare(const struct ntfs_environment *,
    const struct ntfs_write_lznt1_unit_input *, struct ntfs_write_lznt1_unit **);
const struct ntfs_write_lznt1_unit_view *ntfs_write_lznt1_unit_view(
    const struct ntfs_write_lznt1_unit *);
void ntfs_write_lznt1_unit_close(struct ntfs_write_lznt1_unit *);

#endif
