/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_LOGFILE_ENCODE_H
#define MACHLIN_NTFS_LOGFILE_ENCODE_H
#include <ntfs/logfile.h>

#ifdef __cplusplus
extern "C" {
#endif

enum { NTFS_LOGFILE_RECORD_HEADER_BYTES = 48 };

struct ntfs_logfile_buffer {
	const void *data;
	size_t bytes;
};

struct ntfs_logfile_update_input {
	uint64_t target_vcn;
	uint16_t redo_operation, undo_operation, target_attribute;
	uint16_t record_offset, attribute_offset, cluster_index, attribute_flags;
	/* The LCN vector contains little-endian uint64_t wire values, not pointers
	 * or host-endian numbers. Count derives from its complete byte length. */
	struct ntfs_logfile_buffer lcns, redo, undo;
};

struct ntfs_logfile_page_input {
	uint32_t bytes;
	uint16_t major, minor, data_offset, prior_update_sequence;
	struct ntfs_logfile_page page;
	/* Complete restored data region, including any caller-owned unused bytes. */
	struct ntfs_logfile_buffer data;
};

/* Encode one private logical LFS packet with the known common header. data.offset
 * must name that header and data.length must equal payload_bytes. Extended headers
 * and unknown types/flags are UNSUPPORTED; invalid descriptions are INVALID.
 * The scalar LSN/order/client framing matches record_decode. Physical LSN geometry,
 * active identity, multi-page placement and flag planning belong to the owning
 * journal planner. No current-history or native transaction decision is implied.
 * Padding is zero. No trailing alignment bytes are included in the output size. */
enum ntfs_result ntfs_logfile_record_encode(const struct ntfs_logfile_record *, const void *payload,
    size_t payload_bytes, void *output, size_t capacity);

/* Measure or encode one canonical NTFS update payload. Byte alignment suffices for
 * borrowed buffers; NULL is permitted only for empty buffers. Inputs stay immutable
 * throughout the call. Borrowed inputs may alias each other. Each length/start and
 * the derived LCN count must fit its wire field; policy/width/capacity refusals are
 * RANGE. The LCN byte length must be a multiple of sizeof(uint64_t).
 * Empty redo/undo spans have offset zero. Nonempty redo follows the stored LCN
 * prefix; nonempty undo follows aligned redo. Count zero reserves one zero LCN slot.
 * Inter-span padding is zero; no trailing padding is added. Raw operations, flags,
 * targets and vector values remain opaque and authorize no recovery/address/write.
 * Measure publishes the exact byte count only on success. */
enum ntfs_result ntfs_logfile_update_measure(
    const struct ntfs_logfile_update_input *, uint32_t *bytes);
enum ntfs_result ntfs_logfile_update_encode(
    const struct ntfs_logfile_update_input *, void *output, size_t capacity);

/* Construct one private common-header LFS 1.1 RCRD page and generate USA protection.
 * Modern/unknown versions and unknown page flags are UNSUPPORTED. Page size is a
 * bounded power of two; data_offset must leave the complete canonical USA and room
 * for a common record header. data.bytes must exactly fill the remaining region.
 * Transfer position/count and nonzero next-record boundaries have scalar framing
 * checks. copy_value and last_end_lsn are opaque: routing, LSN geometry, completion,
 * transfer planning and durable native publication belong to the journal owner.
 * Reserved header/padding is zero; all borrowed data is preserved, including tails.
 * prior_update_sequence advances under record_protect's reserved-value rules.
 * Caller workspace and output each need bytes capacity. Used workspace/output must
 * be disjoint from each other, the description and borrowed data; unused capacity
 * may alias inputs. Borrowed bytes may be unaligned. Complete admission precedes
 * publication; errors preserve output. Workspace contents are disposable. No
 * allocation, callback or device I/O occurs. This does not plan a native WAL page. */
enum ntfs_result ntfs_logfile_page_encode(const struct ntfs_logfile_page_input *, void *workspace,
    size_t workspace_bytes, void *output, size_t capacity);

/* All operations perform complete admission before publication. Used output
 * must be disjoint from the descriptor and every nonempty borrowed input; overlap
 * or address-range overflow returns INVALID. Every error preserves the entire
 * output, and unused capacity remains unchanged. No allocation, callback or I/O
 * occurs. These private encoders do not give the immutable owner write capability. */

#ifdef __cplusplus
}
#endif
#endif
