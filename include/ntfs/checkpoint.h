/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_CHECKPOINT_H
#define MACHLIN_NTFS_CHECKPOINT_H
#include <ntfs/logfile_tables.h>

#ifdef __cplusplus
extern "C" {
#endif

enum ntfs_logfile_checkpoint_kind {
	NTFS_LOGFILE_CHECKPOINT_OPEN_ATTRIBUTES,
	NTFS_LOGFILE_CHECKPOINT_ATTRIBUTE_NAMES,
	NTFS_LOGFILE_CHECKPOINT_DIRTY_PAGES,
	NTFS_LOGFILE_CHECKPOINT_TRANSACTIONS
};

struct ntfs_logfile_checkpoint_table {
	enum ntfs_logfile_checkpoint_kind kind;
	uint32_t client_major, client_minor;
	uint64_t checkpoint_lsn, table_lsn;
	/* Relative to the complete supplied table record, not its client payload. */
	struct ntfs_logfile_span body;
	/* Names use names; other kinds use table. Their spans are relative to body. */
	struct ntfs_logfile_restart_table table;
	struct ntfs_logfile_attribute_names names;
};

/* Bind one exact assembled dump record to an exact selected-client restart record.
 * The checkpoint must match this owner's active NTFS identity/stored restart LSN.
 * Its table anchor must have consistent nonzero LSN/byte-count fields, address the
 * selected circular geometry and precede the checkpoint. A zero/zero anchor returns
 * NOT_FOUND without interpreting table input; an inconsistent pair is CORRUPT.
 * The dump must match anchor LSN and client index/sequence, have UPDATE type, the
 * matching dump redo opcode, no LCN vector, no undo action/data and exact declared
 * body length. Nonzero previous/undo links must address the selected geometry.
 * Foreign identities/LSNs are STALE; unsupported action/layout families
 * return UNSUPPORTED. Framing failures retain their decoder result.
 * Complete free topology and every allocated versioned entry are checked before
 * publication; free payloads stay opaque. Names require exact full-list framing.
 * These are NTFS 3.0/3.1 client-0/client-1 layouts. References, LSN links, names,
 * dirty targets/LCNs and transaction meaning still require cross-table/volume and
 * current-history validation. This binds immutable snapshot identity, not written
 * page/continuation provenance, analysis, replay or mutation admission.
 * No allocation or I/O occurs. Inputs remain immutable, accept byte alignment and
 * are disjoint from output. Errors zero output. Native admission must precede use.
 * Caller owns both exact record buffers; returned spans borrow table_record bytes. */
enum ntfs_result ntfs_logfile_checkpoint_table_decode(const struct ntfs_logfile *,
    enum ntfs_logfile_checkpoint_kind, const void *checkpoint_record, size_t checkpoint_bytes,
    const void *table_record, size_t table_bytes, struct ntfs_logfile_checkpoint_table *);

#ifdef __cplusplus
}
#endif
#endif
