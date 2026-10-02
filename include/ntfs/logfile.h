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
	NTFS_LOGFILE_RECORD_ADDING = 0x0004,
	/* Offset zero plus each possible second-copy page size, 512..65536. */
	NTFS_LOGFILE_RESTART_PROBES = 9,
	NTFS_LOGFILE_NO_PROBE = UINT16_MAX,
	NTFS_LOGFILE_DEFAULT_READ_CALLS = 32,
	NTFS_LOGFILE_DEFAULT_READ_BYTES = 256 * 1024
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

struct ntfs_logfile;

enum ntfs_logfile_selection {
	NTFS_LOGFILE_UNSELECTED,
	NTFS_LOGFILE_SINGLE_COPY,
	NTFS_LOGFILE_EQUAL_COPIES,
	NTFS_LOGFILE_NEWER_COPY,
	NTFS_LOGFILE_CONFLICT
};

enum ntfs_logfile_storage {
	NTFS_LOGFILE_CIRCULAR,
	NTFS_LOGFILE_LEGACY_TAIL,
	NTFS_LOGFILE_FAST_STORAGE
};

struct ntfs_logfile_limits {
	/* Per operation. Discovery has at most 18 exact reads; page read has one. */
	uint32_t max_page_bytes, max_read_calls;
	uint64_t max_read_bytes;
};

struct ntfs_logfile_probe {
	uint64_t offset;
	uint32_t page_bytes;
	enum ntfs_result result;
	/* Zero unless this candidate was fully decoded successfully. */
	struct ntfs_logfile_restart restart;
};

struct ntfs_logfile_report {
	uint64_t read_bytes;
	uint32_t read_calls;
	uint16_t probe_count, selected_probe;
	bool scan_complete;
	enum ntfs_logfile_selection selection;
	struct ntfs_logfile_probe probes[NTFS_LOGFILE_RESTART_PROBES];
};

struct ntfs_logfile_page_view {
	uint64_t offset;
	enum ntfs_logfile_storage storage;
	struct ntfs_logfile_page page;
};

/* Independent ownership of a logical, immutable $LogFile byte source, not a
 * volume environment. Its context must outlive the owner; calls are serialized.
 * Defaults cap pages at 64 KiB, discovery at 32 reads/256 KiB. No disk-sized
 * allocation occurs: storage is the owner plus three max_page_bytes buffers.
 * All possible second-copy offsets are probed even when the first header is bad.
 * Selection requires compatible geometry and increasing LSNs; equal-LSN areas
 * must have identical declared bytes, ignoring page USA differences. Conflicts
 * and unknown-version candidates reject rather than silently choosing an older
 * copy. A selected restart is not a complete post-crash journal history.
 * On failure *out is NULL. The optional report retains bounded partial evidence;
 * scan_complete describes probing only, never consistency/recovery acceptance.
 * Limits are optional; max_page_bytes is a power of two, 512..65536, and read
 * budgets are positive. report/outputs and environment/source are disjoint. */
void ntfs_logfile_default_limits(struct ntfs_logfile_limits *);
enum ntfs_result ntfs_logfile_open(const struct ntfs_environment *,
    const struct ntfs_logfile_limits *, struct ntfs_logfile_report *, struct ntfs_logfile **out);
/* Bind the fixed $LogFile MFT record's unnamed stream in an existing immutable
 * volume. The counted backing stream keeps unmount BUSY through owner close;
 * source nodes are temporary. Ordinary fully initialized, unencoded storage is
 * supported; reparse/directory/view/uninterpreted or encoded/sparse/partial-VDL
 * system-file forms reject explicitly. The usual extent/list/sequence checks
 * apply before journal reads. Limits/report describe logical reads after stream
 * construction, separately from native physical I/O and metadata/run budgets.
 * This does not mount media, authorize dirty mounts or add a write capability. */
enum ntfs_result ntfs_logfile_open_volume(struct ntfs_volume *, const struct ntfs_logfile_limits *,
    struct ntfs_logfile_report *, struct ntfs_logfile **out);
void ntfs_logfile_close(struct ntfs_logfile *);
/* Cached selected restart/client snapshots use no allocation or device reads.
 * Error outputs are zero; client indexes past the bounded array return END. */
enum ntfs_result ntfs_logfile_get_restart(
    const struct ntfs_logfile *, struct ntfs_logfile_restart *);
enum ntfs_result ntfs_logfile_get_client(
    const struct ntfs_logfile *, uint16_t index, struct ntfs_logfile_client *);
/* A physical protected page from tail/fast/circular storage; no copy routing or
 * record assembly is implied. Offset is aligned and after both restart pages.
 * Capacity needs log_page_bytes. Errors leave output bytes unchanged and view
 * zero, including partial backend reads. No source page is changed or cached. */
enum ntfs_result ntfs_logfile_read_page(struct ntfs_logfile *, uint64_t offset, void *,
    size_t capacity, struct ntfs_logfile_page_view *);

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
