/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_JOURNAL_H
#define MACHLIN_NTFS_WRITE_JOURNAL_H
#include "write_metadata.h"
#include "logfile_tables_disk.h"
#include <ntfs/logfile_encode.h>

enum {
	NTFS_WRITE_LOG_DATA_OFFSET = 64,
	NTFS_WRITE_LOG_PAGES = 3,
	NTFS_WRITE_MFT_KEY = sizeof(struct ntfs_disk_log_table),
	NTFS_WRITE_TRANSACTION_KEY =
	    sizeof(struct ntfs_disk_log_table) + sizeof(struct ntfs_disk_log_transaction),
	NTFS_WRITE_MFT_TARGET_FLAG = 2,
	NTFS_WRITE_QUIET_EXTENSION_BYTES = 48,
	NTFS_WRITE_QUIET_EXTENSION_PREFIX_BYTES =
	    NTFS_WRITE_QUIET_EXTENSION_BYTES - sizeof(uint64_t),
	NTFS_WRITE_BOOTSTRAP_BYTES = sizeof(struct ntfs_disk_log_record) +
	    sizeof(struct ntfs_disk_log_update_storage) + 2 * sizeof(uint64_t),
	NTFS_WRITE_CHECKPOINT_BYTES = sizeof(struct ntfs_disk_log_record) +
	    sizeof(struct ntfs_disk_log_client_restart) + NTFS_WRITE_QUIET_EXTENSION_BYTES,
	NTFS_WRITE_UPDATE_PAYLOAD_BYTES =
	    sizeof(struct ntfs_disk_log_update_storage) + 2 * NTFS_WRITE_RECORD_BYTES
};

struct ntfs_write_log_reservation {
	uint64_t prepare_offset, commit_offset, checkpoint_offset;
	uint64_t open_lsn, snapshot_lsn, update_lsn, commit_lsn, bootstrap_lsn, checkpoint_lsn;
	uint64_t resident_lsn;
	uint16_t snapshot_offset, update_offset, checkpoint_record_offset, resident_offset;
};

struct ntfs_write_journal_input {
	uint64_t file_bytes;
	/* Zero selects the quiet checkpoint. A later value must already belong to
	 * the caller's complete verified retained history; it never advances roots. */
	uint64_t tail_lsn;
	const void *restart[NTFS_LFS_RESTART_PAGES];
	const void *bootstrap, *checkpoint;
	const struct ntfs_write_file_plan *file;
};

struct ntfs_write_journal_plan {
	struct ntfs_write_log_reservation reservation;
	uint8_t dirty_restart[NTFS_LFS_RESTART_PAGES][NTFS_WRITE_CLUSTER_BYTES];
	uint8_t prepare[NTFS_WRITE_CLUSTER_BYTES], commit[NTFS_WRITE_CLUSTER_BYTES];
	uint8_t prepare_copy[NTFS_WRITE_CLUSTER_BYTES], commit_copy[NTFS_WRITE_CLUSTER_BYTES];
	uint8_t checkpoint[NTFS_WRITE_CLUSTER_BYTES];
	uint8_t clean_restart[NTFS_LFS_RESTART_PAGES][NTFS_WRITE_CLUSTER_BYTES];
	/* Complete-home publication retaining the original owning checkpoint.
	 * This alternative has no checkpoint page write or history truncation. */
	uint8_t retained_restart[NTFS_LFS_RESTART_PAGES][NTFS_WRITE_CLUSTER_BYTES];
};

struct ntfs_write_journal_workspace {
	uint8_t restored[NTFS_WRITE_CLUSTER_BYTES], page[NTFS_WRITE_CLUSTER_BYTES];
	uint8_t payload[NTFS_WRITE_UPDATE_PAYLOAD_BYTES];
	struct ntfs_logfile_restart restart[NTFS_LFS_RESTART_PAGES];
	struct ntfs_logfile_client client;
};

/* Pure reservations/serialization for the separately qualified native family.
 * The owning caller must establish complete quiet-history provenance, exclusive
 * ownership, checked physical mappings and barriers. These helpers do no I/O and
 * do not admit writable operations. Ring wrap and growth are explicitly refused.
 * Caller output/workspace are complete separate private objects; failed output
 * is zero after pointer admission. Borrowed snapshots remain immutable. */
enum ntfs_result ntfs_write_journal_reserve(const struct ntfs_logfile_restart *,
    uint16_t snapshot_bytes, struct ntfs_write_log_reservation *);
enum ntfs_result ntfs_write_journal_reserve_tail(const struct ntfs_logfile_restart *,
    uint64_t tail_lsn, uint16_t snapshot_bytes, struct ntfs_write_log_reservation *);
enum ntfs_result ntfs_write_journal_reserve_resident_tail(const struct ntfs_logfile_restart *,
    uint64_t tail_lsn, uint16_t snapshot_bytes, uint16_t resident_bytes,
    struct ntfs_write_log_reservation *);
enum ntfs_result ntfs_write_journal_encode(const struct ntfs_write_journal_input *,
    struct ntfs_write_journal_workspace *, struct ntfs_write_journal_plan *);
/* Reprotect one complete private FILE/INDX/RSTR/RCRD publication with a USA marker
 * absent from every sector tail and plausible USA marker in its actual preceding
 * physical image. Failure leaves the protected output unchanged. The caller
 * supplies complete old bytes under exclusive ownership before any write. */
enum ntfs_result ntfs_write_guard_frame(
    const void *before, size_t bytes, void *protected_after, struct ntfs_write_journal_workspace *);
/* Encode the established LFS 1.1 tail-copy route from a complete protected home.
 * Actual physical predecessor protection remains the publication owner's job. */
enum ntfs_result ntfs_write_tail_copy_encode(
    struct ntfs_write_journal_workspace *, const void *home, uint64_t target, void *out);
/* Pure binding of the exact retained quiet packet family. The supplied origin
 * describes its stored client restart, independently of a later LFS endpoint.
 * Complete history ownership and physical recovery remain caller obligations. */
enum ntfs_result ntfs_write_quiet_bind(const struct ntfs_logfile_restart *,
    const struct ntfs_logfile_client *, const void *bootstrap, const void *checkpoint);

struct ntfs_write_abort_plan {
	uint64_t offset, compensation_lsn, end_lsn, resident_compensation_lsn;
	struct ntfs_write_file_plan file;
	uint8_t page[NTFS_WRITE_CLUSTER_BYTES], copy[NTFS_WRITE_CLUSTER_BYTES];
};

/* Pure native compensation plus transaction deletion in one complete B page.
 * The caller owns the unfinished exact transaction/reservation and must persist
 * a guarded copy and home before publishing the undo FILE image. */
enum ntfs_result ntfs_write_abort_encode(const struct ntfs_logfile_restart *, uint16_t sequence,
    const struct ntfs_write_log_reservation *, const struct ntfs_write_file_plan *,
    struct ntfs_write_journal_workspace *, struct ntfs_write_abort_plan *);

#endif
