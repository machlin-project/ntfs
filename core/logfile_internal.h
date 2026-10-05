/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_LOGFILE_INTERNAL_H
#define MACHLIN_NTFS_LOGFILE_INTERNAL_H
#include <ntfs/checkpoint.h>

/* Decode a complete header with a possibly absent client-data body. Available
 * bytes describe real input; total measures the declared complete record. */
enum ntfs_result ntfs_logfile_record_prefix(const void *, size_t available, uint16_t header_bytes,
    struct ntfs_logfile_record *, uint32_t *total);

/* Validate one decoded checkpoint anchor before admitting its packet read. */
enum ntfs_result ntfs_logfile_checkpoint_anchor(const struct ntfs_logfile_restart *,
    const struct ntfs_logfile_client_restart *, uint64_t checkpoint_lsn,
    enum ntfs_logfile_checkpoint_kind, struct ntfs_logfile_table_reference *);

#endif
