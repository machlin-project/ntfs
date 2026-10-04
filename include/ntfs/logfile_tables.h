/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_LOGFILE_TABLES_H
#define MACHLIN_NTFS_LOGFILE_TABLES_H
#include <ntfs/logfile.h>

#ifdef __cplusplus
extern "C" {
#endif

enum ntfs_logfile_transaction_state {
	NTFS_LOGFILE_TRANSACTION_UNINITIALIZED = 0,
	NTFS_LOGFILE_TRANSACTION_ACTIVE = 1,
	NTFS_LOGFILE_TRANSACTION_PREPARED = 2,
	NTFS_LOGFILE_TRANSACTION_COMMITTED = 3
};

struct ntfs_logfile_restart_table {
	uint16_t entry_bytes, entry_count, allocated_count;
	uint32_t free_goal, first_free, last_free;
	struct ntfs_logfile_span entries;
};

struct ntfs_logfile_open_attribute {
	uint64_t reference, open_lsn;
	uint32_t attribute_type, index_buffer_bytes, legacy_attribute_offset;
	bool dirty_pages_known;
	uint8_t dirty_pages;
};

struct ntfs_logfile_dirty_page {
	uint64_t vcn, oldest_lsn;
	uint32_t target_attribute, transfer_bytes, lcn_count;
	struct ntfs_logfile_span lcns, unused;
};

struct ntfs_logfile_transaction {
	uint64_t first_lsn, previous_lsn, undo_next_lsn;
	uint32_t undo_records, undo_bytes;
	enum ntfs_logfile_transaction_state state;
};

struct ntfs_logfile_attribute_name {
	uint16_t target_attribute, name_units;
	uint32_t bytes;
	struct ntfs_logfile_span name;
};

struct ntfs_logfile_attribute_names {
	uint32_t entry_count;
	struct ntfs_logfile_span entries;
};

/* Decode one exact immutable restart table, bounded by MAX_RECORD_BYTES.
 * Validate every allocation/link word, the declared allocation count and the
 * complete free chain, including termination, coverage and its stored tail.
 * Entry links are byte offsets from the table start; zero ends the free chain.
 * Reserved fields and free_goal remain opaque. No allocation or I/O occurs.
 * Inputs/outputs are disjoint, byte alignment is sufficient, errors zero output.
 * Entry contents, checkpoint ownership/current history and recovery remain
 * separate contracts. An empty table has no entries and both free links zero. */
enum ntfs_result ntfs_logfile_restart_table_decode(
    const void *, size_t, struct ntfs_logfile_restart_table *);

/* Decode allocated NTFS 3.0/3.1 open-attribute entries for client 0.0/1.0.
 * Sizes are exact for the selected version; free entries return NOT_FOUND and
 * their stale payload is ignored. Live-system pointers confer no disk address
 * and are never exposed. The client-0 self-reference is observed only, without
 * resolving the documented historical entry-size discrepancy. Its dirty-page
 * field is unavailable; dirty_pages_known is false. Client-1 retains the raw
 * dirty-page byte without imposing an unqualified canonical Boolean rule.
 * Raw references, types and geometry still require owning validation. */
enum ntfs_result ntfs_logfile_open_attribute_decode(const void *, size_t, uint32_t client_major,
    uint32_t client_minor, struct ntfs_logfile_open_attribute *);

/* A complete bounded dirty-page table entry for client 0.0/1.0. LCN spans are
 * relative to this entry. The declared vector must fit; remaining whole LCN
 * slots are unused fixed-entry capacity, retained as an opaque span. Free
 * entries return NOT_FOUND without interpreting stale fields. Raw target/VCN/
 * LSN/transfer/LCNs do not authorize a volume read, write or recovery action. */
enum ntfs_result ntfs_logfile_dirty_page_decode(const void *, size_t, uint32_t client_major,
    uint32_t client_minor, struct ntfs_logfile_dirty_page *);

/* One exact transaction-table entry. Free entries return NOT_FOUND; allocated
 * unknown states are UNSUPPORTED. LSN links and undo credits are raw observed
 * values, not a validated native transaction or a recovery decision. All entry
 * decoders leave input immutable and zero output on error, without allocation
 * or I/O; they require disjoint input/output and accept byte alignment. */
enum ntfs_result ntfs_logfile_transaction_decode(
    const void *, size_t, struct ntfs_logfile_transaction *);

/* Decode one bounded attribute-name entry from a remaining immutable packet.
 * name is a byte span of lossless little-endian UTF-16, excluding its required
 * zero terminator; bytes includes prefix/name/terminator. Name length is stored
 * in bytes, not UTF-16 units. No alignment padding follows an entry. A zero
 * target and zero length form the four-byte list terminator and return END with
 * zero output. A zero target with a name is CORRUPT. Extra following bytes are
 * not interpreted by this entry primitive; names_decode validates the full list.
 * Stored target offsets, duplicate membership and name semantics require owning
 * table/attribute validation. No normalization or surrogate replacement occurs. */
enum ntfs_result ntfs_logfile_attribute_name_decode(
    const void *, size_t, struct ntfs_logfile_attribute_name *);

/* Validate an exact complete name dump through its final four-byte terminator,
 * with linear work and constant scratch. Entries excludes that final terminator.
 * An empty dump has zero entries and the exact terminator. Missing terminators,
 * odd/truncated names, nonzero string terminators and trailing bytes are CORRUPT.
 * Both name decoders allocate/read nothing, accept byte alignment, preserve
 * immutable disjoint input and zero output on error; MAX_RECORD_BYTES bounds work.
 * Framing establishes no current checkpoint ownership or cross-table binding. */
enum ntfs_result ntfs_logfile_attribute_names_decode(
    const void *, size_t, struct ntfs_logfile_attribute_names *);

#ifdef __cplusplus
}
#endif
#endif
