/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WOF_H
#define MACHLIN_NTFS_WOF_H
#include <ntfs/ntfs.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	NTFS_WOF_CURRENT_VERSION = 1,
	NTFS_WOF_PROVIDER_WIM = 1,
	NTFS_WOF_PROVIDER_FILE = 2,
	NTFS_WOF_FILE_CURRENT_VERSION = 1,
	NTFS_WOF_XPRESS_4K = 0,
	NTFS_WOF_LZX_32K = 1,
	NTFS_WOF_XPRESS_8K = 2,
	NTFS_WOF_XPRESS_16K = 3,
	NTFS_WOF_UNIT_4K = 4096,
	NTFS_WOF_UNIT_8K = 8192,
	NTFS_WOF_UNIT_16K = 16384,
	NTFS_WOF_UNIT_32K = 32768,
	/* Work policy: default tables occupy at most 8 MiB; absolute cap 128 MiB.
	 * These are not NTFS format limits. Zero selects the default. */
	NTFS_WOF_DEFAULT_MAX_CHUNKS = 1048576,
	NTFS_WOF_MAX_CHUNKS = 16777216,
	NTFS_XPRESS_MAX_BLOCK = 65536,
	NTFS_LZX_MAX_BLOCK = NTFS_WOF_UNIT_32K
};

struct ntfs_wof_info {
	uint32_t version, provider, provider_version, algorithm, unit_size;
};

struct ntfs_wof_layout {
	uint64_t logical_size, stored_size, table_size;
	uint32_t algorithm, unit_size, chunks, offset_size;
};

struct ntfs_wof_span {
	uint64_t logical_offset, stored_offset;
	uint32_t logical_size, stored_size;
	bool uncompressed;
};

/* Standalone metadata primitive; public streams own file-provider reading.
 * Decode the complete Microsoft reparse envelope and the observed 16-byte
 * file-provider payload. WIM, future versions/lengths and unknown algorithms are
 * unsupported. Errors zero outputs.
 * Inputs and output structures must not overlap. */
enum ntfs_result ntfs_wof_decode(const void *, size_t, struct ntfs_wof_info *);
/* Decode an existing immutable reparse snapshot without another copy or I/O. */
enum ntfs_result ntfs_reparse_wof_info(const struct ntfs_reparse *, struct ntfs_wof_info *);
/* Exact stored UTF-16 name of the provider backing stream. It remains visible
 * in the lossless catalog, but public reads of that encoding are unsupported. */
bool ntfs_wof_is_backing_stream(const uint16_t *, size_t);
enum ntfs_result ntfs_wof_layout_init(uint32_t algorithm, uint64_t logical_size,
    uint64_t stored_size, uint32_t maximum_chunks, struct ntfs_wof_layout *);
/* start/end are cumulative offsets relative to the end of the chunk table.
 * This checks one span; only a complete table pass establishes global ordering. */
enum ntfs_result ntfs_wof_chunk_span(const struct ntfs_wof_layout *, uint32_t chunk, uint64_t start,
    uint64_t end, struct ntfs_wof_span *);
enum ntfs_result ntfs_wof_table_validate(
    const struct ntfs_wof_layout *, const void *table, size_t table_size);

/* One independent XPRESS-Huffman block, with an exact expected output size.
 * No allocation or I/O. Scratch must have the queried size/alignment; input,
 * output, scratch and written must not overlap. No multi-block continuation.
 * Failure leaves written zero, but may replace an output prefix and scratch.
 * A caller publishing a cache must decode privately and publish only on success. */
size_t ntfs_xpress_workspace_size(void);
size_t ntfs_xpress_workspace_alignment(void);
enum ntfs_result ntfs_xpress_huffman_decode(const void *input, size_t size, void *output,
    size_t expected, void *workspace, size_t workspace_size, size_t *written);

/* One independent WOF/WIM LZX unit with a 32-KiB window. This variant has no
 * CAB/Delta stream header or external dictionary. Scratch/output publication
 * follows the XPRESS contract above. Encoded blocks receive the WIM x86 CALL
 * inverse transform; a provider's equal-size raw chunk must bypass this API. */
size_t ntfs_lzx_workspace_size(void);
size_t ntfs_lzx_workspace_alignment(void);
enum ntfs_result ntfs_lzx_decode(const void *input, size_t size, void *output, size_t expected,
    void *workspace, size_t workspace_size, size_t *written);

#ifdef __cplusplus
}
#endif
#endif
