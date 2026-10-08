/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_USN_H
#define MACHLIN_NTFS_USN_H
#include <ntfs/ntfs.h>

enum {
	NTFS_USN_VERSION_2 = 2,
	NTFS_USN_VERSION_3 = 3,
	NTFS_USN_RECORD_ALIGNMENT = sizeof(uint64_t),
	NTFS_USN_FILE_ID_BYTES = 16,
	NTFS_USN_V2_FILE_ID_BYTES = sizeof(uint64_t)
};

/* Private work budget, not an NTFS field or a Windows coalescing limit. */
enum { NTFS_USN_MAX_REASON_INPUTS = 4096 };

/* Microsoft USN_RECORD_V2/V3 fixed prefixes, excluding the variable name.
 * Byte-array fields permit unaligned wire storage without native ABI padding. */
struct ntfs_disk_usn_header {
	uint8_t record_length[sizeof(uint32_t)];
	uint8_t major_version[sizeof(uint16_t)], minor_version[sizeof(uint16_t)];
};

struct ntfs_disk_usn_tail {
	uint8_t usn[sizeof(uint64_t)], timestamp[sizeof(uint64_t)];
	uint8_t reason[sizeof(uint32_t)], source_info[sizeof(uint32_t)];
	uint8_t security_id[sizeof(uint32_t)], file_attributes[sizeof(uint32_t)];
	uint8_t filename_length[sizeof(uint16_t)], filename_offset[sizeof(uint16_t)];
};

struct ntfs_disk_usn_v2 {
	struct ntfs_disk_usn_header header;
	uint8_t file_id[NTFS_USN_V2_FILE_ID_BYTES], parent_id[NTFS_USN_V2_FILE_ID_BYTES];
	struct ntfs_disk_usn_tail tail;
};

struct ntfs_disk_usn_v3 {
	struct ntfs_disk_usn_header header;
	uint8_t file_id[NTFS_USN_FILE_ID_BYTES], parent_id[NTFS_USN_FILE_ID_BYTES];
	struct ntfs_disk_usn_tail tail;
};

_Static_assert(sizeof(struct ntfs_disk_usn_header) == 8, "USN common prefix");
_Static_assert(sizeof(struct ntfs_disk_usn_tail) == 36, "USN common suffix");
_Static_assert(sizeof(struct ntfs_disk_usn_v2) == 60, "USN V2 fixed prefix");
_Static_assert(sizeof(struct ntfs_disk_usn_v3) == 76, "USN V3 fixed prefix");
_Static_assert(offsetof(struct ntfs_disk_usn_v2, tail) == 24, "USN V2 suffix position");
_Static_assert(offsetof(struct ntfs_disk_usn_v3, tail) == 40, "USN V3 suffix position");

/* IDs are opaque bytes in wire order. V2 uses the first eight bytes and requires
 * zero upper bytes. USN is nonnegative; timestamp retains all FILETIME bits.
 * Reason, source, security and attribute fields are opaque, including unknown
 * flag bits. No record/parent identity, time or Windows operation is inferred.
 * Names are borrowed UTF-16LE byte spans, not host-endian strings. No terminator,
 * normalization, surrogate or namespace policy is imposed; empty names and
 * embedded zero units are structurally representable. */
struct ntfs_usn_record {
	uint16_t major_version, minor_version;
	uint8_t file_id[NTFS_USN_FILE_ID_BYTES], parent_id[NTFS_USN_FILE_ID_BYTES];
	uint64_t usn, timestamp;
	uint32_t reason, source_info, security_id, file_attributes;
	const uint8_t *filename;
	size_t filename_bytes;
};

struct ntfs_usn_view {
	struct ntfs_usn_record record;
	uint32_t record_bytes;
	uint16_t filename_offset;
};

/* Decode only the first complete record. RecordLength consumes an aligned
 * extent inside available bytes; following records are untouched. The wire
 * address itself may be unaligned. FileNameOffset, not the fixed prefix size,
 * selects the borrowed name. Gap/trailing bytes are opaque. Only V2.0/V3.0 are
 * supported. This is bounded record framing, not $J sparse-stream traversal or
 * an FSCTL buffer parser (which may have its own leading USN/cursor).
 *
 * Encode emits the canonical fixed prefix, exact name and zero 8-byte padding.
 * Size/encode share admission and do not promise byte-exact reproduction of
 * decoded gaps or padding. No allocation, callbacks, writes or journal admission.
 * All errors preserve every output; success leaves unused capacity unchanged.
 * Output ranges must be disjoint from all inputs and each other. Typed objects
 * retain ordinary C alignment requirements; wire and name bytes need none. */
enum ntfs_result ntfs_usn_record_decode(const void *, size_t, struct ntfs_usn_view *);
enum ntfs_result ntfs_usn_record_size(const struct ntfs_usn_record *, size_t *);
enum ntfs_result ntfs_usn_record_encode(const struct ntfs_usn_record *, void *, size_t, size_t *);

/* Pure bitwise union of an explicit caller-selected list of reason words.
 * All bits survive, including unknown flags. An empty list produces zero.
 * There is no object grouping, close reset, rename pairing, deduplication,
 * timestamp, source-info propagation or Windows coalescing decision here.
 * Count multiplication is checked and count cannot exceed the private work
 * budget. Work is linear in count, with no allocation. The input words and
 * output must be aligned for uint32_t; misalignment returns INVALID. Output
 * must be separate from the input span; all errors leave it unchanged. */
enum ntfs_result ntfs_usn_reason_union(const uint32_t *, size_t, uint32_t *);

#endif
