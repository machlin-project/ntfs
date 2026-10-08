/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_REPARSE_H
#define MACHLIN_NTFS_WRITE_REPARSE_H
#include <ntfs/ntfs.h>

struct ntfs_write_reparse_input {
	enum ntfs_reparse_kind kind;
	uint32_t flags;
	const uint16_t *substitute, *display;
	size_t substitute_units, display_units;
};

/* Pure private Microsoft symlink/junction payload authoring. Names retain exact
 * nonzero UTF-16 units, including unpaired surrogates. Substitute is nonempty;
 * display may be empty. The canonical layout stores substitute then display,
 * each with a zero terminator excluded from its declared byte length. Reserved
 * bytes are zero. Symlinks accept only the relative flag; junctions accept none.
 * Complete bytes, including the common header, cannot exceed the reparse cap.
 * No target/path policy, namespace mutation, reparse-index ownership, security
 * authorization, journal/recovery or native filesystem admission is conferred.
 *
 * Inputs stay immutable. All errors preserve both output bytes and size output.
 * Outputs must be disjoint from every input and each other; input names may
 * share storage. Size checks precede walking either bounded name. There are no
 * callbacks or allocations. Encoding changes only the returned byte extent. */
enum ntfs_result ntfs_write_reparse_size(const struct ntfs_write_reparse_input *, size_t *);
enum ntfs_result ntfs_write_reparse_encode(
    const struct ntfs_write_reparse_input *, void *, size_t, size_t *);

#endif
