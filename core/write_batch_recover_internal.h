/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_BATCH_RECOVER_INTERNAL_H
#define MACHLIN_NTFS_WRITE_BATCH_RECOVER_INTERNAL_H
#include "write_batch_recover.h"
#include "write_batch_pages.h"
#include "write_mutation.h"
#include "write_history.h"
#include <ntfs/checkpoint.h>
#include <ntfs/validate.h>

enum {
	NTFS_BATCH_RECOVERY_ORIGIN_PACKETS = 2,
	NTFS_BATCH_RECOVERY_INDEX_BYTES = 1024 * 1024,
	NTFS_BATCH_RECOVERY_FILE_SLOTS = NTFS_WRITE_CLUSTER_BYTES / NTFS_WRITE_RECORD_BYTES,
	NTFS_BATCH_RECOVERY_INDEX_FLAG = 8,
	NTFS_BATCH_RECOVERY_INITIAL_PACKETS = 16
};

enum ntfs_batch_recovery_view {
	NTFS_BATCH_RECOVERY_SOURCE,
	NTFS_BATCH_RECOVERY_BOOTSTRAP,
	NTFS_BATCH_RECOVERY_BEFORE,
	NTFS_BATCH_RECOVERY_AFTER,
	NTFS_BATCH_RECOVERY_HISTORY
};

struct ntfs_batch_recovery_packet {
	uint8_t *bytes;
	size_t count, target, home;
	struct ntfs_logfile_record record;
	struct ntfs_logfile_update update;
};

struct ntfs_batch_recovery_target {
	struct ntfs_write_mutation_target identity;
	uint16_t key, flags;
	bool used;
};

struct ntfs_batch_recovery_home {
	uint64_t physical;
	size_t target;
	enum ntfs_write_mutation_region_kind kind;
	uint64_t logical;
	uint8_t source[NTFS_WRITE_CLUSTER_BYTES], before[NTFS_WRITE_CLUSTER_BYTES],
	    after[NTFS_WRITE_CLUSTER_BYTES];
	uint8_t slots, old_slots, new_slots, historical_free_slots;
	bool old_index, mirror, unowned_cluster;
};

struct ntfs_batch_recovery_lifetime {
	struct ntfs_batch_recovery_target *target;
	size_t first, end, targets, target_capacity;
	size_t first_update, updates, compensations, remaining_undo;
	bool committed, compensated;
};

struct ntfs_batch_recovery_projection {
	uint64_t physical;
	uint8_t before[NTFS_WRITE_CLUSTER_BYTES];
	uint8_t unknown_slots;
	uint16_t next_sequence[NTFS_BATCH_RECOVERY_FILE_SLOTS];
	bool unknown_index, unowned_cluster;
};

struct ntfs_batch_recovery_checkpoint {
	struct ntfs_logfile_restart advanced;
	struct ntfs_logfile_client client;
	uint8_t *root_projection;
	uint64_t physical[NTFS_LFS_RESTART_PAGES];
	size_t old_slot, new_slot;
	bool root_transition, projection_active, pending;
};

struct ntfs_write_batch_recovery {
	struct ntfs_overwrite_environment backend;
	struct ntfs_environment reader;
	struct ntfs_info info;
	uint64_t mft_lcn, mirror_lcn;
	uint8_t bootstrap[NTFS_WRITE_RECORD_BYTES];
	enum ntfs_batch_recovery_view view;
	struct ntfs_logfile_restart selected, origin;
	struct ntfs_logfile_client client;
	struct ntfs_logfile_history_report history;
	struct ntfs_batch_recovery_checkpoint checkpoint;
	struct ntfs_batch_recovery_packet *packet;
	struct ntfs_batch_recovery_target *target;
	struct ntfs_batch_recovery_home *home;
	struct ntfs_write_replay_plan *qualified;
	struct ntfs_batch_recovery_lifetime *lifetime;
	struct ntfs_batch_recovery_projection *projection;
	struct ntfs_write_batch_recovery *history_owner;
	size_t packets, packet_capacity, operation_packets, targets, target_capacity, homes,
	    home_capacity;
	size_t qualified_count, qualified_capacity, ordinary_first;
	size_t lifetimes, lifetime_capacity, projections, projection_capacity;
	size_t first_update, updates, compensations, remaining_undo;
	bool committed, compensated, prepared, historical;
	struct ntfs_write_batch_recovery_publication *publication;
	uint8_t *allocation, *frames;
	size_t count, capacity, allocation_bytes, live, abort_end;
	uint64_t reads, read_bytes, allocations, allocated_bytes;
	uint32_t reconstructed_files;
};

struct ntfs_batch_recovery_workspace {
	struct ntfs_write_journal_workspace guard;
	struct ntfs_logfile_checkpoint_capture capture;
	struct ntfs_logfile_checkpoint_capture_report checkpoint;
	struct ntfs_validation_report validation;
	struct ntfs_write_replay_workspace replay;
	uint8_t record[NTFS_WRITE_BATCH_MAX_PACKET_BYTES];
	uint8_t checkpoint_packet[NTFS_WRITE_CHECKPOINT_BYTES];
	uint8_t image[NTFS_WRITE_CLUSTER_BYTES], before[NTFS_WRITE_CLUSTER_BYTES];
	uint8_t restart[NTFS_LFS_RESTART_PAGES][NTFS_WRITE_CLUSTER_BYTES];
	uint8_t clean[NTFS_LFS_RESTART_PAGES][NTFS_WRITE_CLUSTER_BYTES];
	uint8_t copy[NTFS_LFS_LEGACY_TAIL_PAGES][NTFS_WRITE_CLUSTER_BYTES];
};

void *ntfs_batch_recovery_allocate(void *, size_t);
void ntfs_batch_recovery_release(void *, void *, size_t);
enum ntfs_result ntfs_batch_recovery_read(void *, uint64_t, void *, size_t);
enum ntfs_result ntfs_batch_recovery_overlay_read(void *, uint64_t, void *, size_t);
enum ntfs_result ntfs_batch_recovery_bootstrap(
    struct ntfs_write_batch_recovery *, struct ntfs_batch_recovery_workspace *);
enum ntfs_result ntfs_batch_recovery_capture(struct ntfs_write_batch_recovery *,
    struct ntfs_volume *, struct ntfs_batch_recovery_workspace *);
enum ntfs_result ntfs_batch_recovery_qualified_validate(struct ntfs_write_batch_recovery *,
    struct ntfs_volume *, struct ntfs_batch_recovery_workspace *);
enum ntfs_result ntfs_batch_recovery_tail_bind(struct ntfs_write_batch_recovery *,
    struct ntfs_logfile *, struct ntfs_batch_recovery_workspace *);
enum ntfs_result ntfs_batch_recovery_restore(
    struct ntfs_write_batch_recovery *, struct ntfs_batch_recovery_workspace *);
enum ntfs_result ntfs_batch_recovery_restore_history(
    struct ntfs_write_batch_recovery *, struct ntfs_batch_recovery_workspace *);
void ntfs_batch_recovery_lifetime_select(
    struct ntfs_write_batch_recovery *, const struct ntfs_batch_recovery_lifetime *);
enum ntfs_result ntfs_batch_recovery_history_home_admit(
    const struct ntfs_write_batch_recovery *, struct ntfs_batch_recovery_home *);
enum ntfs_result ntfs_batch_recovery_historical_after_admit(
    const struct ntfs_write_batch_recovery *);
enum ntfs_result ntfs_batch_recovery_pages(struct ntfs_write_batch_recovery *,
    struct ntfs_write_batch_pages **, struct ntfs_write_batch_pages **);
enum ntfs_result ntfs_batch_recovery_mapping(const struct ntfs_stream *, uint64_t, uint64_t *);
enum ntfs_result ntfs_batch_checkpoint_roots_capture(struct ntfs_write_batch_recovery *,
    struct ntfs_volume *, struct ntfs_batch_recovery_workspace *);
enum ntfs_result ntfs_batch_checkpoint_bind(struct ntfs_write_batch_recovery *);
enum ntfs_result ntfs_batch_checkpoint_origin_homes(struct ntfs_write_batch_recovery *,
    struct ntfs_logfile *, struct ntfs_batch_recovery_workspace *);
enum ntfs_result ntfs_batch_checkpoint_pages(
    struct ntfs_write_batch_recovery *, struct ntfs_write_batch_pages **);
enum ntfs_result ntfs_batch_checkpoint_prepare(struct ntfs_write_batch_recovery *,
    struct ntfs_stream *, const struct ntfs_write_batch_pages *,
    struct ntfs_batch_recovery_workspace *);

#endif
