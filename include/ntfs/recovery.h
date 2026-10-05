/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_RECOVERY_H
#define MACHLIN_NTFS_RECOVERY_H
#include <ntfs/checkpoint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	NTFS_RECOVERY_MAX_RECORDS = 4096,
	NTFS_RECOVERY_MAX_HISTORY_BYTES = 16 * 1024 * 1024,
	NTFS_RECOVERY_DEFAULT_READ_CALLS = 16384,
	NTFS_RECOVERY_DEFAULT_READ_BYTES = 64 * 1024 * 1024
};

enum ntfs_recovery_transaction_state {
	NTFS_RECOVERY_TRANSACTION_ACTIVE,
	NTFS_RECOVERY_TRANSACTION_PREPARED,
	NTFS_RECOVERY_TRANSACTION_COMMITTED,
	NTFS_RECOVERY_TRANSACTION_FORGOTTEN
};

struct ntfs_recovery_limits {
	uint32_t max_records, max_history_bytes, max_read_calls;
	uint64_t max_read_bytes, max_live_bytes;
};

struct ntfs_recovery_record {
	struct ntfs_logfile_record record;
	struct ntfs_logfile_span packet;
	/* NO_EPOCH denotes a restart or transaction-independent observation. */
	uint32_t transaction_epoch;
};

#define NTFS_RECOVERY_NO_EPOCH UINT32_MAX

struct ntfs_recovery_transaction {
	uint32_t key, records;
	uint64_t first_lsn, last_lsn, predecessor_lsn, undo_next_lsn, control_lsn;
	uint16_t control_operation;
	enum ntfs_recovery_transaction_state state;
	/* A forgotten prefix may begin before the retained oldest LSN. Such a
	 * prefix cannot supply an undo plan. All remaining lifetimes are complete. */
	bool complete_chain;
};

struct ntfs_recovery_report {
	struct ntfs_logfile_checkpoint_capture_report checkpoint;
	struct ntfs_logfile_history_report history;
	uint64_t read_bytes, reserved_bytes, retained_bytes;
	uint32_t read_calls, records, history_bytes, transaction_epochs, verified_seeds;
	uint32_t active_transactions, prepared_transactions, committed_transactions;
	uint32_t forgotten_transactions, partial_prefixes;
	bool published;
};

struct ntfs_recovery;

void ntfs_recovery_default_limits(struct ntfs_recovery_limits *);

/* Own a complete immutable NTFS client analysis input. The source must have a
 * prepared page index and remain externally serialized/immutable during open.
 * Acquire the owning checkpoint internally, then walk from the selected client's
 * retained oldest LSN through the independently framed completed endpoint.
 * Bind the checkpoint, every dump and analysis lower bound to exact packets in
 * that interval. One shared read ceiling covers acquisition, history and tail
 * probing; source preparation/discovery is separate. A native checkpoint dump
 * flag is admitted only on exact selected anchors with no undo action/data and
 * later exact packet binding; its ordinary-update meaning remains unqualified.
 * Unknown client lifetimes,
 * competing copies, unsupported unfinished tails and incomplete live chains
 * refuse. A complete old prefix is not inferred from a reused transaction key.
 * Previous/undo links bind packet identity and transaction lifetime. Physical
 * transaction-table keys, stored first/previous/undo roots and empty allocated
 * seeds are checked against this same owned history. Raw snapshot states/undo
 * credits are not converted into recovery decisions.
 * Control observations advance original serialized transaction lifetimes through
 * Prepare, Commit and Forget; ordinary Windows Forget need not have Commit.
 * Prepared/committed terminal states remain observations, not replay authority.
 * Native operation targets, OAT/DPT evolution, compensation execution, volume
 * addresses, persistence and Windows recovery qualification remain separate.
 * No write capability is added to the read environment or this input owner.
 * Limits are copied before any callback and positive, capped by the named record/
 * byte policies. All storage is reserved before packet reads, including staging
 * headroom. Allocation failure releases everything and allows retry. Failed opens
 * publish NULL and retain exact partial reports. Successful queried packets and
 * value snapshots survive source close; the allocation context must outlive this
 * owner. A volume-backed source supplies a separate counted volume child, so
 * source close never leaves a dangling stream allocator; unmount stays BUSY
 * until this owner closes. Its storage retains the volume's memory governor.
 * Close performs no reads or writes. Queries allocate/read nothing.
 * Output/report/source are disjoint; borrowed query bytes remain immutable until
 * close. Getters zero outputs on error and return END for past-end ordinals. */
enum ntfs_result ntfs_recovery_open(struct ntfs_logfile *, uint16_t client_index,
    uint16_t client_sequence, const struct ntfs_recovery_limits *, struct ntfs_recovery_report *,
    struct ntfs_recovery **out);
void ntfs_recovery_close(struct ntfs_recovery *);
enum ntfs_result ntfs_recovery_get_checkpoint(
    const struct ntfs_recovery *, struct ntfs_logfile_checkpoint_capture *, const void **packets);
enum ntfs_result ntfs_recovery_get_record(const struct ntfs_recovery *, uint32_t ordinal,
    struct ntfs_recovery_record *, const void **packet);
enum ntfs_result ntfs_recovery_get_transaction(
    const struct ntfs_recovery *, uint32_t ordinal, struct ntfs_recovery_transaction *);

#ifdef __cplusplus
}
#endif
#endif
