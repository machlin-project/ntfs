/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_BITMAP_H
#define MACHLIN_NTFS_WRITE_BITMAP_H
#include "write_mutation.h"

enum {
	NTFS_WRITE_BITMAP_MAX_RANGES = 4096,
	NTFS_WRITE_BITMAP_PAYLOAD_BYTES = sizeof(struct ntfs_disk_log_update_storage) +
	    2 * sizeof(struct ntfs_disk_log_bitmap_range)
};

struct ntfs_write_bitmap_program;

/* Compile one checked logical bitmap cluster into native set/clear updates.
 * first/bits are relative bit coordinates within target_vcn, not stream-global
 * bit numbers or bytes. Every maximal changed interval has one exact inverse;
 * unchanged bits never enter a range. Physical geometry and sequence-bearing
 * stream identity come from the mutation owner; key must name its separately
 * bound modern OAT entry. This descriptor does not prove that OAT membership.
 * Only nonresident bitmap regions in the ordinary 4-KiB profile are supported.
 * Complete preflight precedes allocation. Output owns all bytes after source
 * close/input changes, and empty programs are valid. Rejected input/output
 * aliases or pointer overflow preserve the output slot and borrowed bytes;
 * other errors publish NULL. Allocator/context survive until program close.
 * No callbacks except allocate/release, device mutation or writable admission.
 * Common-header links, placement, compensation, durable ordering and complete
 * cross-object recovery remain obligations of the transaction owner. */
enum ntfs_result ntfs_write_bitmap_program_prepare(const struct ntfs_environment *,
    const struct ntfs_write_mutation_region *, uint16_t key, struct ntfs_write_bitmap_program **);
size_t ntfs_write_bitmap_program_count(const struct ntfs_write_bitmap_program *);
const struct ntfs_logfile_buffer *ntfs_write_bitmap_program_get(
    const struct ntfs_write_bitmap_program *, size_t);
void ntfs_write_bitmap_program_close(struct ntfs_write_bitmap_program *);

/* Apply one structurally admitted native set/clear pair to private logical
 * bytes, forward or inverse. Complete validation precedes changing any bit;
 * all errors preserve the destination. Payload and destination are disjoint.
 * Native shared redo/undo range storage is accepted. Only one cluster, one LCN,
 * zero record/attribute/cluster offsets and zero target flags are supported.
 * This pure arithmetic helper does not bind the OAT, mapping or disk address,
 * choose transaction state, replay a dirty volume or produce compensation. */
enum ntfs_result ntfs_write_bitmap_apply(
    const void *payload, size_t bytes, bool undo, void *bitmap, size_t bitmap_bytes);

#endif
