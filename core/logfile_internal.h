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

/* Allocation-only context for an independent recovery-input owner. A volume
 * source returns governed volume callbacks and its lifetime owner, not the
 * source's temporary backing stream. The caller must retain that volume before
 * source close. This does not grant read or write access to the byte source. */
enum ntfs_result ntfs_logfile_environment(const struct ntfs_logfile *, struct ntfs_environment *,
    struct ntfs_logfile_limits *, struct ntfs_volume **);

/* Experimental physical-writer recovery only. A protected legacy transfer with
 * no complete record can supersede its torn home, but supplies no completed end
 * witness. This does not change public reader policy. */
enum ntfs_result ntfs_logfile_prepare_write_page_index(
    struct ntfs_logfile *, uint64_t max_bytes, struct ntfs_logfile_page_index_report *);

/* Tightened whole-walk credits, including the unfinished successor probe. */
enum ntfs_result ntfs_logfile_visit_records_limited(struct ntfs_logfile *, uint64_t first_lsn,
    uint32_t max_records, const struct ntfs_logfile_checkpoint_capture_limits *, void *workspace,
    size_t capacity, ntfs_logfile_record_visitor, void *context,
    struct ntfs_logfile_history_report *);

#endif
