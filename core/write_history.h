/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_HISTORY_H
#define MACHLIN_NTFS_WRITE_HISTORY_H
#include "write_replay.h"
#include <ntfs/checkpoint.h>

enum {
	NTFS_WRITE_HISTORY_TRANSACTIONS = 64,
	NTFS_WRITE_HISTORY_PACKETS =
	    2 + NTFS_WRITE_HISTORY_TRANSACTIONS * NTFS_WRITE_REPLAY_MAX_PACKETS + 2,
	NTFS_WRITE_HISTORY_PACKET_BYTES = NTFS_WRITE_REPLAY_PACKET_BYTES,
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

enum ntfs_result ntfs_write_history_settled(
    struct ntfs_volume *, const struct ntfs_write_history *);

#endif
