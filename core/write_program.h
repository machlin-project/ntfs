/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_PROGRAM_H
#define MACHLIN_NTFS_WRITE_PROGRAM_H
#include "write_batch_pages.h"
#include "write_mutation.h"

struct ntfs_write_program;

struct ntfs_write_program_update {
	struct ntfs_logfile_buffer payload;
	size_t region;
	uint16_t record_flags;
};

/* Compile the complete sealed mutation, preserving every logical stream target,
 * primary/mirror relationship, original storage ownership and private images.
 * Unowned FILE/INDX signature bytes do not supply an old metadata inverse.
 * DATA is ordered
 * initialization, not logged metadata. Mirrors share their primary MFT target.
 * This experimental composition uses complete FILE Initialize images and INDX
 * nonresident images with native bitmap/deallocation operations. The full-image
 * inverse composition has not received native Windows recovery qualification:
 * this is private transaction preparation, not device or FSKit admission.
 * The result owns all bytes after plan close. Only allocation/release callbacks
 * occur. Output/input aliases are rejected unchanged; other failures publish NULL.
 * The allocator context survives close. Complete owning history, physical mapping,
 * actual-predecessor guards and durable execution remain caller obligations. */
enum ntfs_result ntfs_write_program_prepare(const struct ntfs_environment *,
    const struct ntfs_write_mutation_plan *, struct ntfs_write_program **);
size_t ntfs_write_program_count(const struct ntfs_write_program *);
size_t ntfs_write_program_regions(const struct ntfs_write_program *);
const struct ntfs_write_program_update *ntfs_write_program_get(
    const struct ntfs_write_program *, size_t);
enum ntfs_result ntfs_write_program_region(
    const struct ntfs_write_program *, size_t, struct ntfs_write_mutation_region *);
void ntfs_write_program_close(struct ntfs_write_program *);
bool ntfs_write_program_output_separate(const struct ntfs_write_program *, const void *, size_t);

/* Apply an owned operation to disjoint private RESTORED cluster bytes. LSN is
 * supplied by the journal/compensation owner; this does not select replay state.
 * Fresh previously uninitialized FILE undo leaves an unallocated generation,
 * rather than promising restoration of bytes that belonged to no FILE object.
 * No protection, allocation, I/O or source access occurs; errors preserve output. */
enum ntfs_result ntfs_write_program_apply(
    const struct ntfs_write_program *, size_t, bool undo, uint64_t lsn, void *, size_t);

/* Place all OAT opens, all metadata updates and one terminal Forget as one bounded
 * LFS batch. Open LSNs bind the actual preceding completed packet, including its
 * measured extent. Transaction previous/undo links name earlier update ordinals.
 * input.packet/packets must be empty; input supplies an independently proved
 * floor/tail/successor and selected client geometry. These routines neither prove
 * that history nor write a device. Output owns protected pages after program close.
 * Inverses are compensation records with original undo-next links, followed by
 * Forget. prefix is a count of complete metadata updates, not partial packets. */
enum ntfs_result ntfs_write_program_pages_prepare(const struct ntfs_environment *,
    const struct ntfs_write_program *, const struct ntfs_logfile_client *,
    const struct ntfs_write_batch_pages_input *, struct ntfs_write_batch_pages **);
enum ntfs_result ntfs_write_program_compensation_prepare(const struct ntfs_environment *,
    const struct ntfs_write_program *, const struct ntfs_write_batch_pages *, size_t prefix,
    const struct ntfs_logfile_client *, const struct ntfs_write_batch_pages_input *,
    struct ntfs_write_batch_pages **);
#endif
