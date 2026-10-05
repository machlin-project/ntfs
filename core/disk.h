/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef NTFS_DISK_H
#define NTFS_DISK_H
#include <stdint.h>
#include <stddef.h>

enum {
	NTFS_BITS_PER_BYTE = 8,
	NTFS_WIRE_ALIGNMENT = 8,
	NTFS_UTF16_UNIT_BYTES = sizeof(uint16_t),
	NTFS_UTF16_CODE_UNITS = UINT16_MAX + 1u,
	NTFS_BOOT_BYTES = 512,
	NTFS_BOOT_SIGNATURE = 0xaa55,
	NTFS_SECTOR_MIN_BYTES = 512,
	NTFS_SECTOR_MAX_BYTES = 4096,
	NTFS_SIZE_CODE_EXPONENT_FLAG = 0x80,
	NTFS_VOLUME_MAJOR_VERSION = 3,
	NTFS_VOLUME_MAX_MINOR_VERSION = 1,
	NTFS_MST_STRIDE = 512,
	NTFS_MST_WORD_BYTES = sizeof(uint16_t),
	NTFS_ATTR_STANDARD = 0x10,
	NTFS_ATTR_LIST = 0x20,
	NTFS_ATTR_FILENAME = 0x30,
	NTFS_ATTR_SECURITY_DESCRIPTOR = 0x50,
	NTFS_ATTR_VOLUME_NAME = 0x60,
	NTFS_ATTR_VOLUME_INFO = 0x70,
	NTFS_ATTR_INDEX_ROOT = 0x90,
	NTFS_ATTR_INDEX_ALLOCATION = 0xa0,
	NTFS_ATTR_BITMAP = 0xb0,
	NTFS_RECORD_IN_USE = 1,
	NTFS_RECORD_DIRECTORY = 2,
	/* Observed on $Extend records; no behavior is inferred from this bit. */
	NTFS_RECORD_UNINTERPRETED = 4,
	NTFS_RECORD_VIEW_INDEX = 8,
	NTFS_STANDARD_DIRECTORY_CASE_INSENSITIVE = 0,
	NTFS_STANDARD_DIRECTORY_CASE_SENSITIVE = 1,
	NTFS_ATTR_COMPRESSED = 1,
	NTFS_ATTR_COMPRESSION_MASK = 0xff,
	NTFS_ATTR_ENCRYPTED = 0x4000,
	NTFS_ATTR_SPARSE = 0x8000,
	NTFS_FILE_READ_ONLY = 0x1,
	NTFS_FILE_HIDDEN = 0x2,
	NTFS_FILE_SYSTEM = 0x4,
	NTFS_FILE_DIRECTORY = 0x10000000,
	NTFS_FILE_SPARSE = 0x200,
	NTFS_FILE_REPARSE = 0x400,
	NTFS_FILE_COMPRESSED = 0x800,
	NTFS_FILE_ENCRYPTED = 0x4000,
	NTFS_INDEX_CHILD = 1,
	NTFS_INDEX_END = 2,
	NTFS_INDEX_LARGE = 1,
	NTFS_COLLATION_FILENAME = 1,
	NTFS_COLLATION_ULONG = 16,
	NTFS_COLLATION_SECURITY_HASH = 18,
	NTFS_INDEX_VIEW_TYPE = 0,
	NTFS_VOLUME_DIRTY = 1,
	NTFS_MFT_RECORD = 0,
	NTFS_MFT_MIRROR_RECORD = 1,
	NTFS_MFT_MIRROR_REQUIRED_RECORDS = 4,
	NTFS_LOGFILE_RECORD = 2,
	NTFS_VOLUME_RECORD = 3,
	NTFS_BITMAP_RECORD = 6,
	NTFS_BOOT_RECORD = 7,
	NTFS_BAD_CLUSTERS_RECORD = 8,
	NTFS_SECURE_RECORD = 9,
	NTFS_UPCASE_RECORD = 10,
	NTFS_EXTEND_RECORD = 11,
	NTFS_UPCASE_BYTES = NTFS_UTF16_CODE_UNITS * NTFS_UTF16_UNIT_BYTES,
	NTFS_COMPRESSION_UNIT_SHIFT = 4,
	NTFS_COMPRESSION_CLUSTERS = 1u << NTFS_COMPRESSION_UNIT_SHIFT,
	NTFS_COMPRESSION_MAX_CLUSTER_BYTES = 4096,
	NTFS_LZNT1_CHUNK = 4096,
	NTFS_LZNT1_HEADER_BYTES = sizeof(uint16_t),
	NTFS_LZNT1_TOKEN_BYTES = sizeof(uint16_t),
	NTFS_LZNT1_SIGNATURE_MASK = 0x7000,
	NTFS_LZNT1_SIGNATURE = 0x3000,
	NTFS_LZNT1_COMPRESSED = 0x8000,
	NTFS_LZNT1_LENGTH_MASK = 0x0fff,
	NTFS_LZNT1_TOKEN_INITIAL_SHIFT = 12,
	NTFS_LZNT1_TOKEN_SHIFT_THRESHOLD = 16,
	NTFS_LZNT1_MIN_MATCH = 3,
	NTFS_RUN_LENGTH_WIDTH_MASK = 0x0f,
	NTFS_RUN_OFFSET_WIDTH_SHIFT = 4,
	NTFS_RUN_INTEGER_BYTES = sizeof(uint64_t),
	NTFS_RUN_NEGATIVE_FLAG = 0x80
};

enum {
	NTFS_SDS_ALIGNMENT = 16,
	NTFS_SDS_BLOCK_BYTES = 256 * 1024,
	NTFS_SDS_PAIR_BYTES = 2 * NTFS_SDS_BLOCK_BYTES,
	NTFS_SECURITY_HASH_ROTATION = 3,
	NTFS_SECURITY_HASH_BITS = sizeof(uint32_t) * NTFS_BITS_PER_BYTE
};

enum {
	NTFS_XPRESS_SYMBOLS = 512,
	NTFS_XPRESS_SYMBOL_BITS = 9,
	NTFS_XPRESS_LITERAL_SYMBOLS = 256,
	NTFS_XPRESS_END_SYMBOL = NTFS_XPRESS_LITERAL_SYMBOLS,
	NTFS_XPRESS_LENGTH_BITS = 4,
	NTFS_XPRESS_LENGTHS_PER_BYTE = NTFS_BITS_PER_BYTE / NTFS_XPRESS_LENGTH_BITS,
	NTFS_XPRESS_MAX_CODE_BITS = 15,
	NTFS_XPRESS_WORD_BYTES = sizeof(uint16_t),
	NTFS_XPRESS_WORD_BITS = NTFS_XPRESS_WORD_BYTES * NTFS_BITS_PER_BYTE,
	NTFS_XPRESS_RESERVOIR_BITS = sizeof(uint32_t) * NTFS_BITS_PER_BYTE,
	NTFS_XPRESS_LOOKAHEAD_WORDS = NTFS_XPRESS_RESERVOIR_BITS / NTFS_XPRESS_WORD_BITS,
	NTFS_XPRESS_MATCH_LENGTH_BITS = 4,
	NTFS_XPRESS_MATCH_LENGTH_MASK = (1u << NTFS_XPRESS_MATCH_LENGTH_BITS) - 1,
	NTFS_XPRESS_MIN_MATCH = 3,
	NTFS_XPRESS_LONG_LENGTH = NTFS_XPRESS_MATCH_LENGTH_MASK,
	NTFS_XPRESS_LENGTH_ESCAPE = UINT8_MAX
};

struct ntfs_disk_xpress {
	uint8_t lengths[NTFS_XPRESS_SYMBOLS / NTFS_XPRESS_LENGTHS_PER_BYTE];
};

enum {
	NTFS_LZX_WORD_BYTES = sizeof(uint16_t),
	NTFS_LZX_WORD_BITS = NTFS_LZX_WORD_BYTES * NTFS_BITS_PER_BYTE,
	NTFS_LZX_WINDOW_BITS = 15,
	NTFS_LZX_POSITION_SLOTS = 2 * NTFS_LZX_WINDOW_BITS,
	NTFS_LZX_LITERAL_SYMBOLS = 256,
	NTFS_LZX_LENGTH_HEADER_BITS = 3,
	NTFS_LZX_LENGTH_HEADERS = 1u << NTFS_LZX_LENGTH_HEADER_BITS,
	NTFS_LZX_MAIN_SYMBOLS =
	    NTFS_LZX_LITERAL_SYMBOLS + NTFS_LZX_POSITION_SLOTS * NTFS_LZX_LENGTH_HEADERS,
	NTFS_LZX_MIN_MATCH = 2,
	NTFS_LZX_MAX_MATCH = 257,
	NTFS_LZX_LENGTH_ESCAPE = NTFS_LZX_LENGTH_HEADERS - 1,
	NTFS_LZX_SECONDARY_BASE = NTFS_LZX_MIN_MATCH + NTFS_LZX_LENGTH_ESCAPE,
	NTFS_LZX_LENGTH_SYMBOLS = NTFS_LZX_MAX_MATCH - NTFS_LZX_SECONDARY_BASE + 1,
	NTFS_LZX_MAX_CODE_BITS = 16,
	NTFS_LZX_PRETREE_SYMBOLS = 20,
	NTFS_LZX_PRETREE_LENGTH_BITS = 4,
	NTFS_LZX_PRETREE_MAX_BITS = (1u << NTFS_LZX_PRETREE_LENGTH_BITS) - 1,
	NTFS_LZX_ZERO_SHORT = 17,
	NTFS_LZX_ZERO_LONG = 18,
	NTFS_LZX_REPEAT_LENGTH = 19,
	NTFS_LZX_ZERO_SHORT_BITS = 4,
	NTFS_LZX_ZERO_LONG_BITS = 5,
	NTFS_LZX_REPEAT_LENGTH_BITS = 1,
	NTFS_LZX_ZERO_SHORT_BASE = 4,
	NTFS_LZX_ZERO_LONG_BASE = 20,
	NTFS_LZX_REPEAT_LENGTH_BASE = 4,
	NTFS_LZX_LENGTH_MODULUS = NTFS_LZX_MAX_CODE_BITS + 1,
	NTFS_LZX_ALIGNED_BITS = 3,
	NTFS_LZX_ALIGNED_SYMBOLS = 1u << NTFS_LZX_ALIGNED_BITS,
	NTFS_LZX_ALIGNED_LENGTH_BITS = 3,
	NTFS_LZX_ALIGNED_MAX_BITS = (1u << NTFS_LZX_ALIGNED_LENGTH_BITS) - 1,
	NTFS_LZX_BLOCK_TYPE_BITS = 3,
	NTFS_LZX_DEFAULT_SIZE_BITS = 1,
	NTFS_LZX_EXPLICIT_SIZE_BITS = 16,
	NTFS_LZX_VERBATIM = 1,
	NTFS_LZX_ALIGNED = 2,
	NTFS_LZX_RAW = 3,
	NTFS_LZX_REPEATED_OFFSETS = 3,
	NTFS_LZX_OFFSET_BIAS = 2,
	NTFS_LZX_INITIAL_OFFSET = 1,
	/* WIM's fixed transform parameter is independent of the logical file size. */
	NTFS_LZX_E8_TRANSLATION_SIZE = 12000000,
	NTFS_LZX_E8_OPCODE = 0xe8,
	NTFS_LZX_E8_TAIL_BYTES = 10,
	NTFS_LZX_E8_OPERAND_BYTES = sizeof(uint32_t)
};

struct ntfs_disk_lzx_offsets {
	uint8_t repeated[NTFS_LZX_REPEATED_OFFSETS][sizeof(uint32_t)];
};

#define NTFS_REPARSE_MICROSOFT UINT32_C(0x80000000)
#define NTFS_REPARSE_NAME_SURROGATE UINT32_C(0x20000000)
#define NTFS_REPARSE_DIRECTORY UINT32_C(0x10000000)
#define NTFS_REPARSE_RESERVED_BITS UINT32_C(0x0fff0000)
#define NTFS_REPARSE_CLOUD_VARIANT_MASK UINT32_C(0x0000f000)
#define NTFS_REPARSE_RESERVED_TAG_MAX UINT32_C(2)

#define NTFS_ATTR_END UINT32_C(0xffffffff)
#define NTFS_HOLE UINT64_MAX
#define NTFS_TIME_EPOCH UINT64_C(116444736000000000)
#define NTFS_TIME_TICKS UINT64_C(10000000)
#define NTFS_TIME_NANOSECONDS_PER_TICK 100u

/* Every wire field is an array of bytes: alignment and host endian independent. */
struct ntfs_disk_boot {
	uint8_t jump[3], oem[8], sector_size[2], sectors_per_cluster;
	uint8_t reserved_sectors[2], fat_count, root_entries[2], small_sectors[2];
	uint8_t media, sectors_per_fat[2], sectors_per_track[2], heads[2];
	uint8_t hidden_sectors[4], large_sectors[4], reserved[4];
	uint8_t sectors[8], mft_lcn[8], mirror_lcn[8];
	uint8_t record_code, record_reserved[3], index_code, index_reserved[3];
	uint8_t serial[8], checksum[4], code[426], signature[2];
};

struct ntfs_disk_mst {
	uint8_t magic[4], usa_offset[2], usa_count[2];
};

enum {
	NTFS_LFS_MAJOR_LEGACY = 1,
	NTFS_LFS_MINOR_LEGACY = 1,
	NTFS_LFS_MAJOR_FAST = 2,
	NTFS_LFS_MINOR_FAST = 0,
	NTFS_LFS_RESTART_PAGES = 2,
	NTFS_LFS_LEGACY_TAIL_PAGES = 2,
	NTFS_LFS_FAST_PAGE_BYTES = 4096,
	NTFS_LFS_FAST_USA_WORDS = NTFS_LFS_FAST_PAGE_BYTES / NTFS_MST_STRIDE + 1,
	NTFS_LFS_MIN_RECORD_PAGES = 48,
	NTFS_LFS_CLIENT_NAME_BYTES = 128,
	NTFS_LFS_LSN_OFFSET_SHIFT = 3,
	NTFS_LFS_LSN_BITS = sizeof(uint64_t) * NTFS_BITS_PER_BYTE
};

enum {
	NTFS_LOG_CLIENT_MAJOR_BASE = 0,
	NTFS_LOG_CLIENT_MAJOR_ATTRIBUTES = 1,
	NTFS_LOG_CLIENT_MINOR = 0
};

/* The 30-byte common restart prefix ends before the first possible USA word.
 * That word is not a fixed header field. */
struct ntfs_disk_log_restart_page {
	struct ntfs_disk_mst mst;
	uint8_t chkdsk_lsn[sizeof(uint64_t)];
	uint8_t system_page_bytes[sizeof(uint32_t)], log_page_bytes[sizeof(uint32_t)];
	uint8_t area_offset[sizeof(uint16_t)], minor[sizeof(uint16_t)], major[sizeof(uint16_t)];
};

struct ntfs_disk_log_restart_area {
	uint8_t current_lsn[sizeof(uint64_t)], clients[sizeof(uint16_t)];
	uint8_t free_head[sizeof(uint16_t)], in_use_head[sizeof(uint16_t)], flags[sizeof(uint16_t)];
	uint8_t sequence_bits[sizeof(uint32_t)], length[sizeof(uint16_t)];
	uint8_t clients_offset[sizeof(uint16_t)], file_bytes[sizeof(uint64_t)];
	uint8_t last_data_bytes[sizeof(uint32_t)], record_header_bytes[sizeof(uint16_t)];
	uint8_t page_data_offset[sizeof(uint16_t)], open_count[sizeof(uint32_t)];
	uint8_t reserved[sizeof(uint32_t)];
};

struct ntfs_disk_log_client {
	uint8_t oldest_lsn[sizeof(uint64_t)], restart_lsn[sizeof(uint64_t)];
	uint8_t previous[sizeof(uint16_t)], next[sizeof(uint16_t)], sequence[sizeof(uint16_t)];
	uint8_t reserved[6], name_bytes[sizeof(uint32_t)], name[NTFS_LFS_CLIENT_NAME_BYTES];
};

struct ntfs_disk_log_page {
	struct ntfs_disk_mst mst;
	uint8_t copy_value[sizeof(uint64_t)], flags[sizeof(uint32_t)];
	uint8_t page_count[sizeof(uint16_t)], page_position[sizeof(uint16_t)];
	uint8_t next_record_offset[sizeof(uint16_t)], reserved[3 * sizeof(uint16_t)];
	uint8_t last_end_lsn[sizeof(uint64_t)];
};

/* LFS 2.0 fast copies store a DWORD target beyond the common header and
 * 4-KiB protection-array capacity. The actual USA still has its stored offset. */
struct ntfs_disk_log_fast_page {
	struct ntfs_disk_log_page common;
	uint8_t usa_capacity[NTFS_LFS_FAST_USA_WORDS * sizeof(uint16_t)];
	uint8_t padding[sizeof(uint16_t)], file_offset[sizeof(uint32_t)];
};

struct ntfs_disk_log_record {
	uint8_t lsn[sizeof(uint64_t)], previous_lsn[sizeof(uint64_t)],
	    undo_next_lsn[sizeof(uint64_t)];
	uint8_t data_bytes[sizeof(uint32_t)], client_sequence[sizeof(uint16_t)];
	uint8_t client_index[sizeof(uint16_t)], type[sizeof(uint32_t)],
	    transaction[sizeof(uint32_t)];
	uint8_t flags[sizeof(uint16_t)], reserved[3 * sizeof(uint16_t)];
};

struct ntfs_disk_log_update {
	uint8_t redo_operation[sizeof(uint16_t)], undo_operation[sizeof(uint16_t)];
	uint8_t redo_offset[sizeof(uint16_t)], redo_bytes[sizeof(uint16_t)];
	uint8_t undo_offset[sizeof(uint16_t)], undo_bytes[sizeof(uint16_t)];
	uint8_t target_attribute[sizeof(uint16_t)], lcns[sizeof(uint16_t)];
	uint8_t record_offset[sizeof(uint16_t)], attribute_offset[sizeof(uint16_t)];
	uint8_t cluster_index[sizeof(uint16_t)], attribute_flags[sizeof(uint16_t)];
	uint8_t target_vcn[sizeof(uint64_t)];
};

/* Stored update headers reserve a first LCN slot even when the declared vector
 * is empty. Its stale bytes remain opaque capacity, never a physical address. */
struct ntfs_disk_log_update_storage {
	struct ntfs_disk_log_update header;
	uint8_t first_lcn[sizeof(uint64_t)];
};

/* NTFS client data, distinct from an LFS restart-page area. Additional fields
 * after this common prefix require separate interpretation and qualification. */
struct ntfs_disk_log_client_restart {
	uint8_t major[sizeof(uint32_t)], minor[sizeof(uint32_t)];
	uint8_t analysis_lsn[sizeof(uint64_t)];
	uint8_t open_attributes_lsn[sizeof(uint64_t)], attribute_names_lsn[sizeof(uint64_t)];
	uint8_t dirty_pages_lsn[sizeof(uint64_t)], transactions_lsn[sizeof(uint64_t)];
	uint8_t open_attributes_bytes[sizeof(uint32_t)], attribute_names_bytes[sizeof(uint32_t)];
	uint8_t dirty_pages_bytes[sizeof(uint32_t)], transactions_bytes[sizeof(uint32_t)];
};

struct ntfs_disk_record {
	struct ntfs_disk_mst mst;
	uint8_t lsn[8], sequence[2], links[2], attrs_offset[2], flags[2];
	uint8_t used[4], allocated[4], base_reference[8], next_instance[2];
};

/* NTFS 3.1 adds these fields before the update sequence array. Earlier records
 * have only the common header. The reader does not require this optional tail. */
struct ntfs_disk_record_extension {
	uint8_t reserved[2], record_number[4];
};

struct ntfs_disk_attr {
	uint8_t type[4], length[4], nonresident, name_length, name_offset[2];
	uint8_t flags[2], instance[2];
};

struct ntfs_disk_resident {
	uint8_t length[4], offset[2], indexed, reserved;
};

struct ntfs_disk_nonresident {
	uint8_t lowest[8], highest[8], mapping_offset[2], compression_unit;
	uint8_t reserved[5], allocated[8], size[8], initialized[8];
};

struct ntfs_disk_compressed_tail {
	uint8_t physical_size[8];
};

struct ntfs_disk_attr_list {
	uint8_t type[4], length[2], name_length, name_offset;
	uint8_t lowest[8], reference[8], instance[2];
};

struct ntfs_disk_standard {
	uint8_t created[8], modified[8], changed[8], accessed[8], attributes[4];
	uint8_t max_versions[4], version[4], class_id[4];
};

/* Overlay of version when modern directory version numbering is disabled. */
struct ntfs_disk_standard_policy {
	uint8_t directory_flags;
	uint8_t storage_hint[sizeof(uint32_t) - sizeof(uint8_t)];
};

_Static_assert(sizeof(struct ntfs_disk_standard_policy) == sizeof(uint32_t), "directory policy");

struct ntfs_disk_standard_extension {
	uint8_t owner_id[4], security_id[4], quota[8], usn[8];
};

struct ntfs_disk_filename {
	uint8_t parent[8], created[8], modified[8], changed[8], accessed[8];
	uint8_t allocated[8], size[8], attributes[4], reparse[4], length, name_namespace;
};

struct ntfs_disk_volume_info {
	uint8_t reserved[8], major, minor, flags[2];
};

struct ntfs_disk_index_root {
	uint8_t type[4], collation[4], block_size[4], clusters_per_block, reserved[3];
};

struct ntfs_disk_index_header {
	uint8_t entries_offset[4], used[4], allocated[4], flags, reserved[3];
};

struct ntfs_disk_index_block {
	struct ntfs_disk_mst mst;
	uint8_t lsn[8], vcn[8];
	struct ntfs_disk_index_header header;
};

struct ntfs_disk_index_entry {
	uint8_t reference[8], length[2], key_length[2], flags[2], reserved[2];
};

struct ntfs_disk_view_entry {
	uint8_t data_offset[2], data_length[2], reserved1[4];
	uint8_t length[2], key_length[2], flags[2], reserved2[2];
};

struct ntfs_disk_security_locator {
	uint8_t hash[4], security_id[4], offset[8], length[4];
};

struct ntfs_disk_security_hash_key {
	uint8_t hash[4], security_id[4];
};

struct ntfs_disk_security_descriptor {
	uint8_t revision, resource_manager, control[sizeof(uint16_t)];
	uint8_t owner[sizeof(uint32_t)], group[sizeof(uint32_t)];
	uint8_t sacl[sizeof(uint32_t)], dacl[sizeof(uint32_t)];
};

struct ntfs_disk_sid {
	uint8_t revision, count, authority[6];
};

struct ntfs_disk_acl {
	uint8_t revision, reserved1, length[sizeof(uint16_t)];
	uint8_t count[sizeof(uint16_t)], reserved2[sizeof(uint16_t)];
};

struct ntfs_disk_ace {
	uint8_t type, flags, length[sizeof(uint16_t)];
};

struct ntfs_disk_reparse {
	uint8_t tag[4], length[2], reserved[2];
};

/* Stored WOF file-provider metadata, not WOFAPI's parameter structures. */
struct ntfs_disk_wof_file {
	uint8_t version[4], provider[4], provider_version[4], algorithm[4];
};

struct ntfs_disk_guid {
	uint8_t data1[4], data2[2], data3[2], data4[8];
};

struct ntfs_disk_reparse_guid {
	struct ntfs_disk_reparse header;
	struct ntfs_disk_guid guid;
};

struct ntfs_disk_reparse_names {
	uint8_t substitute_offset[2], substitute_length[2], print_offset[2], print_length[2];
};

struct ntfs_disk_reparse_symlink {
	struct ntfs_disk_reparse_names names;
	uint8_t flags[4];
};

_Static_assert(sizeof(struct ntfs_disk_boot) == 512, "boot layout");
_Static_assert(sizeof(struct ntfs_disk_log_restart_page) == 30, "LFS restart prefix");
_Static_assert(sizeof(struct ntfs_disk_log_restart_area) == 48, "LFS restart area prefix");
_Static_assert(sizeof(struct ntfs_disk_log_client) == 160, "LFS client record");
_Static_assert(sizeof(struct ntfs_disk_log_page) == 40, "LFS record page prefix");
_Static_assert(sizeof(struct ntfs_disk_log_record) == 48, "LFS logical record prefix");
_Static_assert(sizeof(struct ntfs_disk_log_update_storage) == 40, "NTFS stored update prefix");
_Static_assert(sizeof(struct ntfs_disk_log_update) == 32, "NTFS log update prefix");
_Static_assert(
    sizeof(struct ntfs_disk_log_client_restart) == 64, "NTFS client restart common prefix");
_Static_assert(sizeof(struct ntfs_disk_record) == 42, "common record layout");
_Static_assert(sizeof(struct ntfs_disk_record_extension) == 6, "NTFS 3.1 record extension");
_Static_assert(sizeof(struct ntfs_disk_nonresident) == 48, "attribute layout");
_Static_assert(sizeof(struct ntfs_disk_filename) == 66, "filename layout");
_Static_assert(sizeof(struct ntfs_disk_attr_list) == 26, "attribute list layout");
_Static_assert(sizeof(struct ntfs_disk_view_entry) == 16, "view index entry layout");
_Static_assert(sizeof(struct ntfs_disk_security_locator) == 20, "SDS locator layout");
_Static_assert(sizeof(struct ntfs_disk_security_hash_key) == 8, "SDH key layout");
_Static_assert(
    sizeof(struct ntfs_disk_security_descriptor) == 20, "self-relative descriptor header");
_Static_assert(sizeof(struct ntfs_disk_sid) == 8, "SID header");
_Static_assert(sizeof(struct ntfs_disk_acl) == 8, "ACL header");
_Static_assert(sizeof(struct ntfs_disk_ace) == 4, "ACE header");
_Static_assert(sizeof(struct ntfs_disk_reparse) == 8, "reparse header layout");
_Static_assert(sizeof(struct ntfs_disk_wof_file) == 16, "stored WOF file-provider layout");
_Static_assert(sizeof(struct ntfs_disk_xpress) == 256, "XPRESS code length table");
_Static_assert(sizeof(struct ntfs_disk_lzx_offsets) == NTFS_LZX_REPEATED_OFFSETS * sizeof(uint32_t),
    "LZX raw repeated offsets");
_Static_assert(sizeof(struct ntfs_disk_reparse_guid) == 24, "GUID reparse header layout");
_Static_assert(sizeof(struct ntfs_disk_reparse_names) == 8, "mount point payload header");
_Static_assert(sizeof(struct ntfs_disk_reparse_symlink) == 12, "symlink payload header");
#endif
