/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_RECORD_H
#define MACHLIN_NTFS_RECORD_H
#include <ntfs/ntfs.h>

#ifdef __cplusplus
extern "C" {
#endif

enum { NTFS_PROTECTED_RECORD_MAX_BYTES = 64 * 1024 };

/* Encode USA protection from a complete private, already restored FILE, INDX,
 * RSTR or RCRD snapshot. Input remains unchanged; used input/output ranges must
 * be disjoint and may be byte aligned. Advance the stored 16-bit sequence,
 * skipping zero and UINT16_MAX; zero/reserved initial sequences start at one.
 * Save every restored 512-byte-stride tail before replacing it with this sequence.
 * Validate the complete protection geometry/capacity before changing output;
 * failures leave every output byte unchanged. Capacity needs at least size.
 * This bounded byte primitive allocates/reads/writes no device. It establishes
 * protection only: higher record contents, private ownership, log ordering and
 * durable publication must be qualified by the transaction/recovery owner. */
enum ntfs_result ntfs_record_protect(const void *input, size_t size, void *output, size_t capacity);

#ifdef __cplusplus
}
#endif
#endif
