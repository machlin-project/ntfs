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
	NTFS_LOGFILE_PAGE_RECORD_END = 0x00000001,
	NTFS_LOGFILE_PAGE_CLIENT_RESTART = 0x00000002,
	NTFS_LOGFILE_FAST_COPY_PAGES = 32,
	NTFS_LOGFILE_TRANSACTION_MAX_RECORDS = 4096,
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

struct ntfs_logfile_table_reference {
	uint64_t lsn;
	uint32_t bytes;
};

struct ntfs_logfile_client_restart {
	uint32_t major, minor;
	uint64_t analysis_lsn;
	struct ntfs_logfile_table_reference open_attributes, attribute_names, dirty_pages,
	    transactions;
	struct ntfs_logfile_span extension;
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
	/* Per operation. Discovery has at most 18 exact reads; a physical page read
	 * has one; circular-record assembly shares credits across all its pages. */
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

struct ntfs_logfile_page_observation {
	uint64_t offset, target_offset;
	enum ntfs_logfile_storage storage;
	/* Decode success preserves the complete common header, even when routing
	 * is unsupported. Missing signatures are NOT_FOUND; invalid RCRD is CORRUPT.
	 * target_result describes addressing/known flags, not written provenance. */
	enum ntfs_result result, target_result;
	struct ntfs_logfile_page page;
};

struct ntfs_logfile_inventory {
	uint64_t read_bytes, next_offset, max_observed_epoch_lsn, max_observed_end_lsn;
	uint32_t read_calls, total_pages, examined_pages, visited_pages;
	uint32_t decoded_pages, missing_pages, corrupt_pages, invalid_targets, unsupported_targets;
	bool complete;
};

typedef enum ntfs_result (*ntfs_logfile_page_visitor)(
    void *, const struct ntfs_logfile_page_observation *);

struct ntfs_logfile_indexed_page {
	struct ntfs_logfile_page_view selected;
	uint64_t target_offset, epoch_lsn;
	enum ntfs_result result;
	bool prefix_conflict;
};

struct ntfs_logfile_page_index_report {
	struct ntfs_logfile_inventory inventory;
	uint64_t required_bytes, retained_bytes, read_bytes;
	uint32_t read_calls, indexed_targets, selected_pages, missing_targets, corrupt_targets;
	uint32_t unsupported_targets, prefix_conflicts, compared_prefixes, unrouted_copies;
	uint32_t unsupported_copies;
	bool published;
};

struct ntfs_logfile_record_view {
	struct ntfs_logfile_record record;
	uint64_t first_page_offset, last_page_offset, read_bytes;
	uint32_t bytes, pages_read, copy_pages_read, read_calls;
	bool wrapped;
};

struct ntfs_logfile_history_report {
	uint64_t first_lsn, candidate_end_lsn, completed_end_lsn, last_lsn, next_lsn;
	uint64_t observed_start_lsn, tail_lsn, record_bytes, read_bytes;
	uint32_t read_calls, examined_records, visited_records, copy_pages_read;
	bool endpoint_verified, tail_verified, complete, wrapped;
};

struct ntfs_logfile_transaction_limits {
	uint32_t max_records, max_read_calls;
	uint64_t max_read_bytes;
};

struct ntfs_logfile_transaction_report {
	uint64_t root_lsn, last_lsn, next_lsn, control_lsn, record_bytes, read_bytes;
	uint32_t transaction, read_calls, examined_records, visited_records, copy_pages_read;
	uint32_t undo_references;
	uint16_t control_operation;
	bool complete;
};

typedef enum ntfs_result (*ntfs_logfile_record_visitor)(
    void *, const struct ntfs_logfile_record_view *, const void *record_bytes);

/* Walk one NTFS transaction's complete previous-LSN chain, newest first, from
 * an explicit root. Require a prepared immutable source index, active client
 * index/sequence, exact NTFS name and nonzero transaction/root/retained oldest
 * LSN. Every complete packet must be UPDATE, bind that same client/transaction,
 * remain inside the retained lower bound and have strictly older previous/undo
 * links with valid geometry. ADDING/DELETING client-lifecycle flags refuse.
 * After the previous chain ends at zero, verify every undo-next link names a
 * member of this same chain, including transaction-key reuse boundaries. No
 * previous-chain cycle or outside undo branch is accepted. NTFS update spans
 * are decoded; operation/target semantics remain separate. control_lsn/operation
 * observe only the most recent Prepare/Commit/Forget marker, not a recovery
 * decision. A marker alone never authorizes redo or undo.
 * NULL limits inherits source I/O ceilings and MAX_RECORDS. Explicit positive
 * limits may tighten or further cap I/O, never raise source ceilings; max_records
 * is at most MAX_RECORDS. Link scratch reserves max_records * two uint64_t values
 * before I/O, accepts byte alignment and is private temporary storage. Record
 * workspace follows indexed-record staging/capacity rules. No retained allocation
 * occurs; one bounded record staging allocation exists at a time. All reads share
 * one operation budget. Source preparation/discovery reads are separate.
 * A required report retains attempted reads and examined/delivered packet counts;
 * complete is set only after the whole chain and all undo edges pass. Visitors
 * receive borrowed exact bytes. Each view's page/copy counts cover that packet;
 * its read-call/byte counters are cumulative across the operation. Calls are
 * externally serialized; retain analysis in private
 * state until complete success. Visitors must not reenter the source or alter
 * private workspaces. Limits are copied before callbacks. A callback error
 * propagates exactly. Workspaces
 * may change on failure, unused link scratch remains untouched, and input, output,
 * workspaces and source are disjoint. This verifies selected packet/chain binding;
 * checkpoint analysis bounds, current continuation freshness, dirty/OAT state,
 * native transaction semantics, replay and writable admission remain separate. */
enum ntfs_result ntfs_logfile_visit_transaction(struct ntfs_logfile *, uint16_t client_index,
    uint16_t client_sequence, uint32_t transaction, uint64_t root_lsn,
    const struct ntfs_logfile_transaction_limits *, void *record_workspace, size_t record_capacity,
    void *link_workspace, size_t link_capacity, ntfs_logfile_record_visitor, void *context,
    struct ntfs_logfile_transaction_report *);

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
/* Resolve an active client index/sequence pair in the selected immutable
 * restart snapshot. Inactive, absent or mismatched entries return STALE with
 * zero output; sequence zero and UINT16_MAX remain valid field values. This
 * bounded cached lookup allocates/reads nothing. Matching the pair does not
 * establish a record's written/current history or interpret client payloads. */
enum ntfs_result ntfs_logfile_get_active_client(
    const struct ntfs_logfile *, uint16_t index, uint16_t sequence, struct ntfs_logfile_client *);
/* Decode an exact already assembled client-restart record against this owner's
 * selected snapshot. Require the RESTART type, active index/sequence, exact NTFS
 * client name and equality with its nonzero stored restart LSN before decoding
 * the client prefix. Absent/free/mismatched identity or LSN returns STALE;
 * another client name/type is UNSUPPORTED. Framing/payload errors retain their
 * decoder result. Input is immutable/disjoint from source/output; errors zero
 * output, with no allocation or I/O. extension is relative to the client payload.
 * This binds snapshot identity only: page integrity, continuation provenance,
 * current written history, registration lifetime, tables and recovery are not
 * qualified. Native admission must still precede this cached operation. */
enum ntfs_result ntfs_logfile_decode_client_restart_record(
    const struct ntfs_logfile *, const void *, size_t, struct ntfs_logfile_client_restart *);
/* A physical protected page from tail/fast/circular storage; no copy routing or
 * record assembly is implied. Offset is aligned and after both restart pages.
 * Capacity needs log_page_bytes. Errors leave output bytes unchanged and view
 * zero, including partial backend reads. No source page is changed or cached. */
enum ntfs_result ntfs_logfile_read_page(struct ntfs_logfile *, uint64_t offset, void *,
    size_t capacity, struct ntfs_logfile_page_view *);
/* Observe every complete physical record-storage page in ascending offset,
 * including all tail/fast slots and the circular area. The complete scan's
 * exact read count/bytes must fit the source limits before any read or visitor.
 * No allocation occurs; callbacks borrow one metadata observation until return.
 * Missing/torn/invalid pages are visited with explicit structural results;
 * a backend failure aborts with its exact result and never visits partial bytes.
 * Known-layout targets require circular bounds and valid epoch/LSN geometry;
 * unknown layouts/flags remain visible with UNSUPPORTED target_result. Epoch is
 * last-end for legacy tails, last-start for circular/modern pages. Maxima cover
 * only routing-valid headers; no duplicate resolution or history selection occurs.
 * An optional visitor can stop with any non-OK result. Calls must not reenter
 * this owner or mutate its source. Output retains partial counters on failure;
 * next_offset is the first page whose visit has not succeeded; retry starts at
 * the first storage page. complete requires every visitor to succeed. NULL
 * visitor observes only the summary. Output/context/source are
 * disjoint. Complete means physical coverage, never current history, continuation
 * provenance, recovery or writable admission. Ordinary defaults can refuse RANGE. */
enum ntfs_result ntfs_logfile_visit_pages(struct ntfs_logfile *, ntfs_logfile_page_visitor,
    void *context, struct ntfs_logfile_inventory *);
/* Prepare an optional owner-retained circular-target index from the complete
 * physical inventory. Positive max_bytes bounds the one private allocation,
 * including metadata and comparison scratch. Admission reserves the complete
 * scan plus at most two reads per copy slot before allocation/I/O. The same
 * operation credits cover every scan, reload and comparison; defaults refuse.
 * Compatible legacy epochs use last-end LSN; modern epochs use last-start LSN.
 * Protected legacy circular continuations can retain a zero last-start field;
 * their physical address and last-end epoch select no continuation provenance.
 * Every equally newest candidate must agree on flags, last-end, next-record
 * boundary and complete restored written prefix. Conflicts remain UNSUPPORTED
 * per target; unknown circular flags also block that target. Unroutable copy
 * evidence remains in the report, never silently becoming current history.
 * Selected copy pages require a completed nonempty prefix. A complete index can
 * retain missing/corrupt/unsupported targets. Backend/reload/allocation errors
 * publish nothing and permit retry. A second preparation returns BUSY without
 * callbacks. Report is required, zeroed initially, and preserves partial work;
 * required_bytes is measurable on a too-small positive memory bound, retained
 * bytes are nonzero only after publication. Source/report are disjoint.
 * Preparation does not qualify the active window, endpoint, continuations,
 * recovery or writable admission. All calls remain serialized and immutable. */
enum ntfs_result ntfs_logfile_prepare_page_index(
    struct ntfs_logfile *, uint64_t max_bytes, struct ntfs_logfile_page_index_report *);
/* Cached index queries have no allocation/I/O. A page query returns metadata
 * with its separate result, including unresolved targets; function errors zero
 * output. Target offsets are complete aligned circular pages. Report queries
 * return the original preparation counters, not new work. An absent index is
 * NOT_FOUND. Clear releases all retained index bytes without disturbing cached
 * restart/client snapshots. Owner close also clears the index. */
enum ntfs_result ntfs_logfile_get_indexed_page(
    const struct ntfs_logfile *, uint64_t target_offset, struct ntfs_logfile_indexed_page *);
enum ntfs_result ntfs_logfile_get_page_index_report(
    const struct ntfs_logfile *, struct ntfs_logfile_page_index_report *);
void ntfs_logfile_clear_page_index(struct ntfs_logfile *);
/* Assemble an exact record from physical circular storage by its LSN. Only the
 * first segment has a record header; continuations begin at page_data_offset.
 * USA and common page/record framing are checked, including linked-LSN geometry.
 * A record may wrap once; no physical page is revisited. Transfer page_count/
 * position and opaque copy values do not select segments or current history.
 * This does not route tail/fast copies, resolve active clients or qualify a
 * post-crash record. It is a physical diagnostic observation, not recovery.
 * The operation shares one read budget across every page, stages at most one
 * MAX_RECORD_BYTES allocation and copies exact header/client bytes without
 * alignment padding only on success. Bytes/out/source must be disjoint. Errors
 * leave caller bytes unchanged and view zero; a different header LSN is STALE. */
enum ntfs_result ntfs_logfile_read_circular_record(struct ntfs_logfile *, uint64_t lsn, void *,
    size_t capacity, struct ntfs_logfile_record_view *);
/* Assemble a diagnostic LFS 1.1 record with completed legacy tail copies routed
 * to their declared circular page. Both tail slots are examined before choosing
 * the newest matching last_end_lsn. Torn/malformed copies are unavailable; exact
 * backend failures retain their result. Equal epochs require identical declared
 * written prefixes, ignoring USA, transfer metadata and unused page capacity.
 * A newer circular page wins. Unknown page flags or an unresolved matching tail
 * without a completed/written prefix return UNSUPPORTED. LFS 2.0 routing remains
 * UNSUPPORTED. This is immutable copy selection, not complete current history,
 * continuation provenance, recovery or mutation admission.
 * Logical page offsets remain circular addresses; copy_pages_read counts segments
 * selected from tail storage. All physical reads, including the two-slot scan,
 * share the operation's credits. Temporary storage adds one log_page_bytes
 * allocation to the exact staged record. Every selected tail segment and the
 * ending circular segment must fit NextRecordOffset; violations are CORRUPT.
 * Earlier circular segments may extend beyond it because an unfinished record
 * leaves that field at its start. The final RecordEnd/last_end_lsn witness is
 * still required. Errors preserve bytes and zero out. */
enum ntfs_result ntfs_logfile_read_legacy_record(struct ntfs_logfile *, uint64_t lsn, void *,
    size_t capacity, struct ntfs_logfile_record_view *);
/* Observe a completed LFS 2.0 record with fast copies routed to their stored
 * circular targets. The supported fast layout has 4-KiB system/log pages and a
 * DWORD target after the nine-word USA capacity and its word padding. Larger
 * data/header offsets remain valid; USA overlap with that target is UNSUPPORTED.
 * All 32 slots are examined. Valid target copies are ordered by their common
 * last-start LSN, not slot position or transfer count. Equal latest epochs must
 * have equal last-end LSNs and complete written prefixes, ignoring USA, transfer
 * fields and unused bytes. A newer circular page wins. Torn/malformed slots are
 * unavailable; backend errors and shared read-credit refusals retain their result.
 * An unresolved matching latest copy or conflicting prefix is UNSUPPORTED.
 * Selected fast segments and the final circular segment must fit NextRecordOffset;
 * the final RecordEnd/last_end_lsn witness is required. Incomplete fast segments
 * are not assembled. Logical offsets remain circular; copy_pages_read counts
 * selected fast segments. Temporary storage is at most 2 KiB of slot metadata,
 * one log page and one exact staged record, with errors preserving bytes/zero view.
 * At least 33 reads/132 KiB must be admitted before work; ordinary 32-read defaults
 * therefore return RANGE. Additional selected/duplicate copies and continuations
 * share that same budget. This is per-target immutable copy observation, not a
 * complete current circular history, continuation provenance, recovery or writes. */
enum ntfs_result ntfs_logfile_read_fast_record(struct ntfs_logfile *, uint64_t lsn, void *,
    size_t capacity, struct ntfs_logfile_record_view *);
/* Assemble exact observed record bytes using an explicitly prepared page index,
 * rechecking the selected protected page/header/target at every segment under
 * one operation budget. This avoids repeated copy-slot scans. Unqualified copy
 * flags/layouts refuse record acquisition globally; their target is unknown. Missing or
 * unresolved indexed targets refuse; errors leave bytes unchanged/view zero.
 * Complete physical selection still does not prove active history, continuation
 * provenance, native recovery or write admission. */
enum ntfs_result ntfs_logfile_read_indexed_record(struct ntfs_logfile *, uint64_t lsn, void *,
    size_t capacity, struct ntfs_logfile_record_view *);

/* Walk the selected written record interval from an explicit exact first LSN.
 * Requires a prepared index. A greatest completed-page LSN is a candidate only:
 * exact record framing, adjacent payload geometry, one-wrap/no-page-revisit
 * bounds, completion tags and written boundaries must agree through that end.
 * The caller-owned workspace holds one exact record, including its header;
 * records remain capped at MAX_RECORD_BYTES. Each record uses one bounded
 * private staging allocation. Every read across the entire walk and optional
 * unfinished-header verification shares the source's operation credits.
 * max_records is positive; exhaustion refuses RANGE rather than truncating.
 * The transient visitor receives complete unpadded bytes and per-record read
 * counters, never transfer-position-derived fragments. Successful visitor calls
 * advance visited_records; stops/errors preserve partial report evidence.
 * A tagged unfinished successor is verified separately and never visited as a
 * complete record. Complete means the requested selected framing interval only;
 * it does not choose a client's lower bound, validate native transactions or
 * qualify recovery, durability or writes. RSTR CurrentLsn is not a ceiling.
 * Visitor/context are optional. Calls remain serialized; a visitor must not
 * reenter the owner. Workspace/report/source/context are disjoint. Workspace
 * is temporary storage; report is required and initially zero on every call. */
enum ntfs_result ntfs_logfile_visit_records(struct ntfs_logfile *, uint64_t first_lsn,
    uint32_t max_records, void *workspace, size_t capacity, ntfs_logfile_record_visitor,
    void *context, struct ntfs_logfile_history_report *);

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
 * Aligned redo/undo spans follow the declared LCN vector. Stored headers reserve
 * one LCN slot even for count zero: that slot is opaque unused capacity, excluded
 * from the returned empty vector, and data spans must follow the stored prefix.
 * Empty spans may use offset zero; nonempty spans are aligned absolute offsets
 * from the client payload start. Compact/truncated forms without the reserved
 * storage are CORRUPT. Original input and unused capacity remain uninterpreted.
 * Operation codes, target identifiers and LCNs are opaque format values; they
 * confer no writable address or recovery decision. Redo/undo may share bytes. */
enum ntfs_result ntfs_logfile_update_decode(const void *, size_t, struct ntfs_logfile_update *);
/* Decode the complete bounded NTFS client payload's 64-byte common restart
 * prefix for client formats 0.0/1.0. Other client versions are UNSUPPORTED.
 * Original input remains immutable; outputs are zero on error. extension names
 * the opaque remaining bytes relative to the payload. No table/anchor geometry,
 * presence, record ownership, current history or extension semantics are inferred.
 * Raw LSN/byte-count pairs authorize no reads, allocations or recovery action.
 * A qualified caller must separately establish the containing LFS record and
 * selected active client. Inputs and output are disjoint; no allocation/I/O. */
enum ntfs_result ntfs_logfile_client_restart_decode(
    const void *, size_t, struct ntfs_logfile_client_restart *);

#ifdef __cplusplus
}
#endif
#endif
