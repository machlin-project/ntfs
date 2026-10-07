/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_BATCH_PAGES_H
#define MACHLIN_NTFS_WRITE_BATCH_PAGES_H
#include "write_journal.h"

enum {
	NTFS_WRITE_BATCH_MAX_PACKETS = 4096,
	NTFS_WRITE_BATCH_MAX_PAGES = 4096,
	NTFS_WRITE_BATCH_MAX_PACKET_BYTES = sizeof(struct ntfs_disk_log_record) +
	    sizeof(struct ntfs_disk_log_update_storage) + 2 * NTFS_WRITE_CLUSTER_BYTES
};

struct ntfs_write_batch_packet {
	/* This LSN and MULTI_PAGE are assigned by the placement owner. A link
	 * names an earlier input ordinal, or SIZE_MAX to use record's absolute
	 * link (zero or a proved member of the retained input history). */
	struct ntfs_logfile_record record;
	struct ntfs_logfile_buffer payload;
	size_t previous, undo_next;
};

struct ntfs_write_batch_pages_input {
	struct ntfs_logfile_restart restart;
	/* The owning immutable history has proved the complete retained interval.
	 * Its floor page, including its prefix, cannot be overwritten by this batch.
	 * This scalar descriptor alone does not prove that history or ownership. */
	uint64_t floor_lsn, tail_lsn, next_lsn;
	/* next_lsn is the proved successor after tail_lsn's complete byte extent,
	 * including continuation/wrap, not a value derived from its start page.
	 * A partial successor page stays protected; a fresh payload-start cursor
	 * may use that page. The whole floor page is always protected. */
	const struct ntfs_write_batch_packet *packet;
	size_t packets;
};

struct ntfs_write_batch_page {
	uint64_t offset;
	size_t packet;
	/* Physical output still needs binding, actual-predecessor USA protection,
	 * immutable-owner teardown and WAL/commit/barrier ordering before use. */
	uint8_t protected_bytes[NTFS_WRITE_CLUSTER_BYTES];
};

struct ntfs_write_batch_pages;

/* Pure complete bounded ring placement and native LFS 1.1 continuation framing.
 * Each packet starts in a fresh page; each page describes a separate one-page
 * physical transfer and carries the packet's LSN, including pure continuations.
 * A later commit cannot share its prepared page. The owner
 * must persist every complete packet before publishing dependent home bytes.
 * Input record.lsn and MULTI_PAGE are zero, data.offset names the common header,
 * and data.length equals the payload length. Ordinal links precede their packet
 * and bind the same client sequence/transaction; absolute links must already be
 * proved within floor_lsn..tail_lsn. Spanning client restarts remain unsupported.
 * Output owns all copied bytes and scalar LSNs; borrowed payloads are not retained.
 * Errors close partial storage and publish NULL after complete output-slot
 * pointer/overlap admission. Rejected pointer aliases/ranges preserve inputs
 * and the output slot. No source read/write occurs.
 * Allocator/context remain alive until close. This interface supplies no native
 * NTFS update semantics, checkpoint/recovery decision or writable admission. */
enum ntfs_result ntfs_write_batch_pages_prepare(const struct ntfs_environment *,
    const struct ntfs_write_batch_pages_input *, struct ntfs_write_batch_pages **);
/* Pure capacity/sequence admission for a fresh-page suffix of the same proved
 * retained window. Input packet/packets are empty. This neither claims media nor
 * changes its floor; exclusive ownership and the actual history remain required. */
enum ntfs_result ntfs_write_batch_pages_capacity_check(
    const struct ntfs_write_batch_pages_input *, size_t pages);
size_t ntfs_write_batch_pages_count(const struct ntfs_write_batch_pages *);
const struct ntfs_write_batch_page *ntfs_write_batch_pages_get(
    const struct ntfs_write_batch_pages *, size_t);
uint64_t ntfs_write_batch_pages_lsn(const struct ntfs_write_batch_pages *, size_t);
uint64_t ntfs_write_batch_pages_next_lsn(const struct ntfs_write_batch_pages *);
/* Private composition helpers. Storage remains immutable; copying reconstructs
 * exactly one logical packet from its owned protected pages without callbacks.
 * Complete framing/USA/capacity admission precedes publication. Outputs must
 * be disjoint from the owner and each other; aliases preserve borrowed bytes. */
bool ntfs_write_batch_pages_output_separate(
    const struct ntfs_write_batch_pages *, const void *, size_t);
enum ntfs_result ntfs_write_batch_pages_packet_copy(
    const struct ntfs_write_batch_pages *, size_t, void *, size_t, size_t *);
void ntfs_write_batch_pages_close(struct ntfs_write_batch_pages *);

#endif
