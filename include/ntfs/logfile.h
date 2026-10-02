/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_LOGFILE_H
#define MACHLIN_NTFS_LOGFILE_H
#include <ntfs/ntfs.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	/* Parser work policies, not native recovery or write limits. */
	NTFS_LOGFILE_MAX_PAGE_BYTES = 65536,
	NTFS_LOGFILE_MAX_RECORD_BYTES = 1024 * 1024,
	NTFS_LOGFILE_CLIENT_NAME_UNITS = 64,
	NTFS_LOGFILE_NO_CLIENT = UINT16_MAX,
	NTFS_LOGFILE_RESTART_CLEAN = 0x0002,
	NTFS_LOGFILE_RECORD_UPDATE = 1,
	NTFS_LOGFILE_RECORD_RESTART = 2,
	NTFS_LOGFILE_RECORD_MULTI_PAGE = 0x0001,
	NTFS_LOGFILE_RECORD_DELETING = 0x0002,
	NTFS_LOGFILE_RECORD_ADDING = 0x0004
};

/* Observed LFS file-size ceiling. Larger journals need separate qualification. */
#define NTFS_LOGFILE_MAX_FILE_BYTES UINT64_C(0x100000000)

struct ntfs_logfile_span {
	uint32_t offset, length;
};

struct ntfs_logfile_restart {
	uint64_t current_lsn, file_bytes, usable_bytes, circular_offset;
	uint32_t system_page_bytes, log_page_bytes, sequence_bits, last_data_bytes, open_count;
	uint16_t major, minor, flags, client_count, free_head, in_use_head;
	uint16_t record_header_bytes, page_data_offset;
	struct ntfs_logfile_span area, clients;
	/* An on-disk hint only. It never authorizes mounting dirty media or writes. */
	bool clean_hint;
};

struct ntfs_logfile_client {
	uint64_t oldest_lsn, restart_lsn;
	uint16_t previous, next, sequence, name_length;
	uint16_t name[NTFS_LOGFILE_CLIENT_NAME_UNITS];
};

struct ntfs_logfile_lsn {
	uint64_t sequence, file_offset, page_offset;
	uint32_t record_offset;
};

struct ntfs_logfile_page {
	/* This union's wire value is an LSN in circular pages, an offset in tails.
	 * Routing tail/fast-page copies is deliberately outside this decoder. */
	uint64_t copy_value, last_end_lsn;
	uint32_t flags;
	uint16_t page_count, page_position, next_record_offset;
};

struct ntfs_logfile_record {
	uint64_t lsn, previous_lsn, undo_next_lsn;
	uint32_t type, transaction;
	uint16_t client_sequence, client_index, flags;
	struct ntfs_logfile_span data;
};

struct ntfs_logfile_update {
	uint64_t target_vcn;
	uint16_t redo_operation, undo_operation, target_attribute, lcn_count;
	uint16_t record_offset, attribute_offset, cluster_index, attribute_flags;
	struct ntfs_logfile_span redo, undo, lcns;
};

/* Independent immutable-byte primitives; no allocation, device I/O or writes.
 * Output structures are zero on error. Inputs, outputs and scratch must not
 * overlap. Scratch may change on failure; publish it only after success.
 * Pages use the fixed 512-byte USA stride, independently of device geometry.
 * Scratch needs at least size bytes, with byte alignment. Decoded pages retain
 * their headers/USA but contain restored sector tails; do not decode them again.
 * Restart decoding supports LFS 1.1/2.0 common framing and complete client lists.
 * CHKD, other versions and pages above the policy cap are unsupported. */
enum ntfs_result ntfs_logfile_restart_decode(const void *input, size_t size,
    uint64_t available_file_bytes, void *scratch, size_t scratch_bytes,
    struct ntfs_logfile_restart *);
/* One restored 160-byte client record. Names are lossless host-endian UTF-16;
 * name_length counts units and no terminator is added. The restart decoder
 * additionally validates list membership and each client's LSN geometry. */
enum ntfs_result ntfs_logfile_client_decode(const void *, size_t, struct ntfs_logfile_client *);
/* A zero LSN returns NOT_FOUND. Nonzero offsets must address a complete header
 * in the circular area, never a restart, tail/fast page, or page header. */
enum ntfs_result ntfs_logfile_lsn_decode(
    const struct ntfs_logfile_restart *, uint64_t lsn, struct ntfs_logfile_lsn *);
enum ntfs_result ntfs_logfile_page_decode(const void *input, size_t size,
    const struct ntfs_logfile_restart *, void *scratch, size_t scratch_bytes,
    struct ntfs_logfile_page *);
/* An exact logical LFS record after USA restoration and, when necessary,
 * caller-owned multi-page assembly. size excludes trailing alignment padding.
 * header_bytes comes from a validated restart area. No tail selection, client
 * identity resolution, transaction analysis or redo/undo execution is implied. */
enum ntfs_result ntfs_logfile_record_decode(
    const void *, size_t size, uint16_t header_bytes, struct ntfs_logfile_record *);
/* The complete NTFS update client payload, excluding the LFS record header.
 * Spans are relative to this payload, including its 32-byte fixed header.
 * Aligned redo/undo spans follow a nonempty LCN vector. LCN-less packets remain
 * unsupported pending qualification of their conflicting published offset bases.
 * The shared prefix through LCN count suffices for this rejection; no unresolved
 * target-VCN layout is presumed for a shorter LCN-less packet.
 * Their original client bytes remain available through the LFS record decoder.
 * Operation codes, target identifiers and LCNs are opaque format values; they
 * confer no writable address or recovery decision. Redo/undo may share bytes. */
enum ntfs_result ntfs_logfile_update_decode(const void *, size_t, struct ntfs_logfile_update *);

#ifdef __cplusplus
}
#endif
#endif
