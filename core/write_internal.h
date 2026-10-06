/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_INTERNAL_H
#define MACHLIN_NTFS_WRITE_INTERNAL_H
#include "internal.h"
#include "logfile_tables_disk.h"
#include <ntfs/checkpoint.h>
#include <ntfs/logfile_encode.h>
#include <ntfs/overwrite.h>
#include <ntfs/validate.h>

struct ntfs_validation_report;

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
	    sizeof(struct ntfs_disk_standard) + sizeof(struct ntfs_disk_standard_extension),
	NTFS_WRITE_UPDATE_PAYLOAD_BYTES =
	    sizeof(struct ntfs_disk_log_update_storage) + 2 * NTFS_WRITE_RECORD_BYTES
};

struct ntfs_write_file_plan {
	uint64_t reference, mft_reference, target_vcn, target_lcn, cluster_physical;
	uint16_t cluster_index, record_offset, attribute_offset, change_bytes, snapshot_bytes;
	uint16_t resident_record_offset, resident_attribute_offset, resident_bytes;
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

/* Prepare an unchanged-size resident DATA overwrite and SI times in one private
 * FILE image. The journal must separately bind both resident update operations;
 * this pure helper does not grant write or recovery admission. */
enum ntfs_result ntfs_write_prepare_resident_metadata(struct ntfs_node *, uint64_t filetime,
    uint64_t lsn, uint64_t offset, const void *, size_t, struct ntfs_write_file_plan *);

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
/* Reprotect one complete private FILE/RSTR/RCRD publication with a USA marker
 * absent from every sector tail and plausible USA marker in its actual preceding
 * physical image. Failure leaves the protected output unchanged. The caller
 * supplies complete old bytes under exclusive ownership before any write. */
enum ntfs_result ntfs_write_guard_frame(
    const void *before, size_t bytes, void *protected_after, struct ntfs_write_journal_workspace *);
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

enum {
	NTFS_WRITE_REPLAY_OPEN,
	NTFS_WRITE_REPLAY_SNAPSHOT,
	NTFS_WRITE_REPLAY_UPDATE,
	NTFS_WRITE_REPLAY_COMMIT,
	NTFS_WRITE_REPLAY_PACKETS,
	NTFS_WRITE_REPLAY_MAX_PACKETS = NTFS_WRITE_REPLAY_PACKETS + 3
};

struct ntfs_write_replay_input {
	struct ntfs_logfile_restart restart;
	uint64_t tail_lsn;
	/* The complete owning history must bind these exact consecutive packets.
	 * Only COMMIT may be absent. Packet admission alone is not history ownership. */
	struct ntfs_logfile_buffer packet[NTFS_WRITE_REPLAY_PACKETS];
	/* Present only when packet[COMMIT] is the complete native compensation
	 * update followed by this exact transaction deletion record. */
	struct ntfs_logfile_buffer abort;
	/* A resident DATA update follows SI. On undo its compensation precedes
	 * packet[COMMIT], which remains the SI compensation followed by abort. */
	struct ntfs_logfile_buffer resident, resident_compensation;
};

struct ntfs_write_replay_workspace {
	struct ntfs_logfile_record record[NTFS_WRITE_REPLAY_PACKETS];
	struct ntfs_logfile_update update[NTFS_WRITE_REPLAY_PACKETS];
	struct ntfs_logfile_record abort_record;
	struct ntfs_logfile_update abort_update;
	struct ntfs_logfile_record resident_record, resident_compensation_record;
	struct ntfs_logfile_update resident_update, resident_compensation_update;
	struct ntfs_write_log_reservation reservation;
	uint8_t snapshot[NTFS_WRITE_RECORD_BYTES], checked[NTFS_WRITE_RECORD_BYTES];
};

struct ntfs_write_replay_plan {
	struct ntfs_write_file_plan file;
	uint64_t open_lsn, snapshot_lsn, update_lsn, commit_lsn;
	uint64_t compensation_lsn, abort_lsn, end_lsn;
	uint64_t resident_lsn, resident_compensation_lsn;
	uint16_t prepared_packets, packets;
	bool committed, compensated;
};

/* Bind one qualified complete ordinary-file transaction to the current checked
 * MFT map and prepare private redo/undo FILE output, even when home USA is torn.
 * This validates packet identity, full before image and allowed metadata change;
 * it performs no device writes and retains no children. The caller must first
 * own complete current history, then validate the whole reconstructed image
 * through an immutable overlay before any physical mutation or checkpoint.
 * Dirty native history and checkpoint publication do not gain admission here. */
enum ntfs_result ntfs_write_replay_prepare(struct ntfs_volume *,
    const struct ntfs_write_replay_input *, struct ntfs_write_replay_workspace *,
    struct ntfs_write_replay_plan *);

enum {
	NTFS_WRITE_HISTORY_TRANSACTIONS = 64,
	NTFS_WRITE_HISTORY_PACKETS =
	    2 + NTFS_WRITE_HISTORY_TRANSACTIONS * NTFS_WRITE_REPLAY_MAX_PACKETS + 2,
	NTFS_WRITE_HISTORY_PACKET_BYTES =
	    sizeof(struct ntfs_disk_log_record) + NTFS_WRITE_UPDATE_PAYLOAD_BYTES,
	NTFS_WRITE_HISTORY_INDEX_BYTES = 1024 * 1024
};

struct ntfs_write_history {
	struct ntfs_logfile_restart selected, origin;
	struct ntfs_logfile_client client;
	struct ntfs_logfile_history_report history;
	struct ntfs_write_replay_plan replay;
	struct ntfs_write_replay_plan transaction[NTFS_WRITE_HISTORY_TRANSACTIONS];
	uint32_t count, transactions, bytes[NTFS_WRITE_HISTORY_PACKETS];
	bool pending, checkpoint_observed;
	uint8_t packet[NTFS_WRITE_HISTORY_PACKETS][NTFS_WRITE_HISTORY_PACKET_BYTES];
};

struct ntfs_write_history_workspace {
	struct ntfs_logfile_report discovery;
	struct ntfs_logfile_page_index_report index;
	struct ntfs_logfile_checkpoint_capture capture;
	struct ntfs_logfile_checkpoint_capture_report checkpoint;
	struct ntfs_logfile_history_report history;
	struct ntfs_write_replay_workspace replay;
	uint8_t record[NTFS_WRITE_HISTORY_PACKET_BYTES],
	    checkpoint_packet[NTFS_WRITE_CHECKPOINT_BYTES];
};

/* Acquire one complete retained quiet origin and bounded exact following
 * transactions through the independently verified physical endpoint. Packet
 * bytes survive source close; no read children, I/O capability or device writes
 * survive. Unknown operations, extra records and unfinished tails fail closed.
 * A reconstructed FILE still requires full immutable-overlay validation before
 * any owning recovery execution. Native checkpoint publication remains separate. */
enum ntfs_result ntfs_write_history_capture(
    struct ntfs_volume *, struct ntfs_write_history_workspace *, struct ntfs_write_history *);

/* A fresh immutable full-volume validator sees only this reconstructed FILE
 * overlay. Native source bytes, volume flags and callbacks are unchanged. No
 * memo/child from the original read epoch is reused or survives validation. */
enum ntfs_result ntfs_write_validate_overlay(const struct ntfs_environment *,
    const struct ntfs_write_replay_plan *, struct ntfs_validation_report *);
enum ntfs_result ntfs_write_validate_overlays(const struct ntfs_environment *,
    const struct ntfs_write_replay_plan *, size_t count, struct ntfs_validation_report *);

enum {
	NTFS_WRITE_EXECUTE_RESTART_FIRST,
	NTFS_WRITE_EXECUTE_RESTART_SECOND,
	NTFS_WRITE_EXECUTE_PREPARE_HOME,
	NTFS_WRITE_EXECUTE_COMMIT_HOME,
	NTFS_WRITE_EXECUTE_PREPARE_COPY,
	NTFS_WRITE_EXECUTE_COMMIT_COPY,
	NTFS_WRITE_EXECUTE_LOG_LOCATIONS,
	NTFS_WRITE_EXECUTE_FRAMES = 8,
	NTFS_WRITE_EXECUTE_MAX_SPANS = NTFS_OVERWRITE_MAX_BYTES / NTFS_MST_STRIDE + 2,
	NTFS_WRITE_EXECUTE_MAX_DATA_BYTES = NTFS_OVERWRITE_MAX_BYTES + NTFS_WRITE_CLUSTER_BYTES
};

enum ntfs_write_execution_stage {
	NTFS_WRITE_EXECUTION_NONE,
	NTFS_WRITE_EXECUTION_DIRTY_FIRST,
	NTFS_WRITE_EXECUTION_DIRTY_SECOND,
	NTFS_WRITE_EXECUTION_PREPARE_COPY,
	NTFS_WRITE_EXECUTION_PREPARE_HOME,
	NTFS_WRITE_EXECUTION_DATA,
	NTFS_WRITE_EXECUTION_COMMIT_COPY,
	NTFS_WRITE_EXECUTION_COMMIT_HOME,
	NTFS_WRITE_EXECUTION_FILE_HOME,
	NTFS_WRITE_EXECUTION_CLEAN_FIRST,
	NTFS_WRITE_EXECUTION_CLEAN_SECOND
};

struct ntfs_write_data_span {
	uint64_t physical;
	const void *image;
	size_t bytes;
};

struct ntfs_write_execution_input {
	const struct ntfs_write_journal_plan *journal;
	const struct ntfs_write_file_plan *file;
	const void *restart[NTFS_LFS_RESTART_PAGES];
	uint64_t physical[NTFS_WRITE_EXECUTE_LOG_LOCATIONS];
	const struct ntfs_write_data_span *data;
	size_t spans;
};

struct ntfs_write_transaction_workspace {
	struct ntfs_write_history_workspace history_work;
	struct ntfs_write_history history;
	struct ntfs_write_journal_workspace journal_work;
	struct ntfs_write_journal_plan journal;
	struct ntfs_write_file_plan file;
	uint8_t restart[NTFS_LFS_RESTART_PAGES][NTFS_WRITE_CLUSTER_BYTES];
	struct ntfs_write_execution_input execution;
};

/* Prepare one bounded append from the exact owning retained history. Every
 * preceding transaction must already have its complete committed home image;
 * prepared, torn, unpublished-checkpoint and unknown histories require recovery
 * instead of another mutation. Physical journal mappings and FILE metadata are
 * captured under the caller's immutable serialized epoch. No write occurs. */
enum ntfs_result ntfs_write_prepare_transaction(
    struct ntfs_node *, uint64_t filetime, struct ntfs_write_transaction_workspace *);
enum ntfs_result ntfs_write_prepare_resident_transaction(struct ntfs_node *, uint64_t filetime,
    uint64_t offset, const void *, size_t, struct ntfs_write_transaction_workspace *);
enum ntfs_result ntfs_write_history_settled(
    struct ntfs_volume *, const struct ntfs_write_history *);

struct ntfs_write_execution_report {
	uint64_t physical_bytes, data_bytes;
	uint32_t writes, barriers;
	enum ntfs_write_execution_stage durable_stage;
	bool data_persisted, commit_persisted, completed, poisoned;
};

struct ntfs_write_execution_workspace {
	/* The caller aligns this complete private object to the device alignment. */
	uint8_t frame[NTFS_WRITE_EXECUTE_FRAMES][NTFS_WRITE_CLUSTER_BYTES];
	uint8_t home[NTFS_WRITE_CLUSTER_BYTES], before[NTFS_WRITE_CLUSTER_BYTES];
	struct ntfs_write_journal_workspace guard;
	struct ntfs_overwrite_environment backend;
	struct ntfs_write_data_span data[NTFS_WRITE_EXECUTE_MAX_SPANS];
	uint64_t physical[NTFS_WRITE_EXECUTE_LOG_LOCATIONS], home_physical;
	size_t spans;
	bool prepared;
};

/* Private experiment for the native retained-root transaction protocol. The
 * owning caller has authorized and exclusively claimed the resource, bound the
 * complete native history and every physical mapping, and validated the full
 * reconstructed volume. Preparation reads exact preceding physical images and
 * guards every MST publication before mutation. All immutable epochs/children
 * close before execution. This helper cannot acquire ownership or admit FSKit
 * writes; native interruption acceptance remains a separate gate.
 * Workspace and borrowed data stay private and unchanged between calls.
 * Execution performs no allocation/read, uses a true persistence barrier after
 * each metadata publication and the complete initialized data overwrite, and
 * permanently poisons caller state after any uncertain attempted I/O. */
enum ntfs_result ntfs_write_execute_prepare(const struct ntfs_overwrite_environment *,
    const struct ntfs_write_execution_input *, struct ntfs_write_execution_workspace *);
enum ntfs_result ntfs_write_execute(
    struct ntfs_write_execution_workspace *, bool *poisoned, struct ntfs_write_execution_report *);

enum ntfs_write_recovery_stage {
	NTFS_WRITE_RECOVERY_NONE,
	NTFS_WRITE_RECOVERY_DIRTY_FIRST,
	NTFS_WRITE_RECOVERY_DIRTY_SECOND,
	NTFS_WRITE_RECOVERY_LOG_HOMES,
	NTFS_WRITE_RECOVERY_ABORT_COPY,
	NTFS_WRITE_RECOVERY_ABORT_HOME,
	NTFS_WRITE_RECOVERY_FILE_HOMES,
	NTFS_WRITE_RECOVERY_CLEAN_FIRST,
	NTFS_WRITE_RECOVERY_CLEAN_SECOND
};

struct ntfs_write_recovery_report {
	uint64_t physical_bytes;
	uint32_t writes, barriers, reconstructed_files;
	enum ntfs_write_recovery_stage durable_stage;
	bool compensation_persisted, homes_persisted, completed, poisoned;
};

struct ntfs_write_recovery_workspace {
	/* Complete aligned publications; no read epoch survives execution. */
	uint8_t restart[NTFS_LFS_RESTART_PAGES][NTFS_WRITE_CLUSTER_BYTES];
	uint8_t dirty[NTFS_LFS_RESTART_PAGES][NTFS_WRITE_CLUSTER_BYTES];
	uint8_t clean[NTFS_LFS_RESTART_PAGES][NTFS_WRITE_CLUSTER_BYTES];
	uint8_t home[NTFS_WRITE_HISTORY_TRANSACTIONS][NTFS_WRITE_CLUSTER_BYTES];
	uint8_t log_home[2 * NTFS_WRITE_HISTORY_TRANSACTIONS][NTFS_WRITE_CLUSTER_BYTES];
	uint8_t scratch[NTFS_WRITE_CLUSTER_BYTES];
	uint8_t abort_page[NTFS_WRITE_CLUSTER_BYTES], abort_copy[NTFS_WRITE_CLUSTER_BYTES];
	struct ntfs_write_abort_plan abort;
	struct ntfs_write_history_workspace history_work;
	struct ntfs_write_history history;
	struct ntfs_write_journal_workspace guard;
	struct ntfs_validation_report validation;
	struct ntfs_overwrite_environment backend;
	uint64_t restart_physical[NTFS_LFS_RESTART_PAGES], abort_physical, copy_physical;
	uint64_t home_physical[NTFS_WRITE_HISTORY_TRANSACTIONS];
	uint64_t log_physical[2 * NTFS_WRITE_HISTORY_TRANSACTIONS];
	uint32_t homes, logs, files;
	bool home_changed[NTFS_WRITE_HISTORY_TRANSACTIONS];
	bool log_changed[2 * NTFS_WRITE_HISTORY_TRANSACTIONS];
	bool close_transaction, mutation, prepared;
};

/* Private recovery experiment: acquire exact owning history, preflight all
 * publications and validate the complete reconstructed volume. Only the known
 * bounded family can be redone or compensated; C checkpoints/unknown histories
 * remain refused. The caller exclusively claims the backend and closes every
 * immutable child/volume before execute. Execution allocates and reads nothing,
 * retains original checkpoint roots, and poisons after any uncertain I/O. */
enum ntfs_result ntfs_write_recover_prepare(struct ntfs_volume *,
    const struct ntfs_overwrite_environment *, struct ntfs_write_recovery_workspace *);
enum ntfs_result ntfs_write_recover_execute(
    struct ntfs_write_recovery_workspace *, bool *poisoned, struct ntfs_write_recovery_report *);
/* Private image owner admission including executed bounded native recovery.
 * Public metadata-preserving overwrite admission remains unchanged. */
enum ntfs_result ntfs_write_owner_open(const struct ntfs_overwrite_environment *,
    struct ntfs_overwrite_admission *, struct ntfs_write_recovery_report *,
    struct ntfs_overwrite **);

struct ntfs_write_range_report {
	struct ntfs_write_execution_report execution;
	uint64_t requested_bytes, completed_bytes;
};

/* Private bounded image writing. The separate overwrite owner supplies
 * exclusive authorized claim, memory/read governors and the true persistence
 * transport. Fresh full validation, native history/settled-home binding and
 * absence of hibernation/change-journal state precede private planning. Every
 * immutable epoch closes before device writes. Allocation/size/namespace/ADS
 * stay unchanged; resident DATA and initialized nonresident ranges use their
 * owning FILE journal family and update ordinary SI times. FSKit's image owner
 * calls this helper only after closing all immutable readers. Block resources
 * remain read-only, and the metadata-preserving overwrite API is separate. */
enum ntfs_result ntfs_write_existing_range(struct ntfs_overwrite *, uint64_t reference,
    uint64_t offset, const void *, size_t, uint64_t filetime, struct ntfs_write_range_report *);

#endif
