/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_REPLAY_H
#define MACHLIN_NTFS_WRITE_REPLAY_H
#include "write_journal.h"

enum {
	NTFS_WRITE_REPLAY_OPEN,
	NTFS_WRITE_REPLAY_SNAPSHOT,
	NTFS_WRITE_REPLAY_UPDATE,
	NTFS_WRITE_REPLAY_COMMIT,
	NTFS_WRITE_REPLAY_PACKETS,
	NTFS_WRITE_REPLAY_MAX_PACKETS = NTFS_WRITE_REPLAY_PACKETS + 3,
	NTFS_WRITE_REPLAY_PACKET_BYTES =
	    sizeof(struct ntfs_disk_log_record) + NTFS_WRITE_UPDATE_PAYLOAD_BYTES
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

#endif
