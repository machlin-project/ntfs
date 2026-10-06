/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_INTERNAL_H
#define MACHLIN_NTFS_WRITE_INTERNAL_H
#include "internal.h"
#include "logfile_tables_disk.h"
#include <ntfs/logfile_encode.h>

enum {
	NTFS_WRITE_SECTOR_BYTES = 512,
	NTFS_WRITE_CLUSTER_BYTES = 4096,
	NTFS_WRITE_RECORD_BYTES = 1024,
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
	NTFS_WRITE_STANDARD_BYTES =
	    sizeof(struct ntfs_disk_standard) + sizeof(struct ntfs_disk_standard_extension)
};

struct ntfs_write_file_plan {
	uint64_t reference, mft_reference, target_vcn, target_lcn, cluster_physical;
	uint16_t cluster_index, record_offset, attribute_offset, change_bytes, snapshot_bytes;
	/* Complete private restored FILE snapshots, followed by protected output.
	 * No borrowed node, record, attribute or stream survives preparation. */
	uint8_t before[NTFS_WRITE_RECORD_BYTES], after[NTFS_WRITE_RECORD_BYTES];
	uint8_t protected_after[NTFS_WRITE_RECORD_BYTES];
};

/* Private preparation for the qualified native ordinary-file mutation family.
 * No device writes occur. The caller owns/serializes the immutable node and
 * supplies separate private output storage. Success contains only values/bytes;
 * failures zero the output after pointer admission. The journal owner must bind
 * the supplied new LSN, reserve its log and close immutable owners before writes.
 * This does not itself admit metadata mutation or a writable FSKit operation. */
enum ntfs_result ntfs_write_prepare_metadata(
    struct ntfs_node *, uint64_t filetime, uint64_t lsn, struct ntfs_write_file_plan *);

struct ntfs_write_log_reservation {
	uint64_t prepare_offset, commit_offset, checkpoint_offset;
	uint64_t open_lsn, snapshot_lsn, update_lsn, commit_lsn, bootstrap_lsn, checkpoint_lsn;
	uint16_t snapshot_offset, update_offset, checkpoint_record_offset;
};

struct ntfs_write_journal_input {
	uint64_t file_bytes;
	const void *restart[NTFS_LFS_RESTART_PAGES];
	const void *bootstrap, *checkpoint;
	const struct ntfs_write_file_plan *file;
};

struct ntfs_write_journal_plan {
	struct ntfs_write_log_reservation reservation;
	uint8_t dirty_restart[NTFS_LFS_RESTART_PAGES][NTFS_WRITE_CLUSTER_BYTES];
	uint8_t prepare[NTFS_WRITE_CLUSTER_BYTES], commit[NTFS_WRITE_CLUSTER_BYTES];
	uint8_t checkpoint[NTFS_WRITE_CLUSTER_BYTES];
	uint8_t clean_restart[NTFS_LFS_RESTART_PAGES][NTFS_WRITE_CLUSTER_BYTES];
};

struct ntfs_write_journal_workspace {
	uint8_t restored[NTFS_WRITE_CLUSTER_BYTES], page[NTFS_WRITE_CLUSTER_BYTES];
	uint8_t payload[sizeof(struct ntfs_disk_log_update_storage) + NTFS_WRITE_RECORD_BYTES];
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
enum ntfs_result ntfs_write_journal_encode(const struct ntfs_write_journal_input *,
    struct ntfs_write_journal_workspace *, struct ntfs_write_journal_plan *);

#endif
