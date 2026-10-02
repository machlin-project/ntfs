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
	NTFS_FILE_DIRECTORY = 0x10000000,
	NTFS_FILE_REPARSE = 0x400,
	NTFS_INDEX_CHILD = 1,
	NTFS_INDEX_END = 2,
	NTFS_INDEX_LARGE = 1,
	NTFS_COLLATION_FILENAME = 1,
	NTFS_COLLATION_ULONG = 16,
	NTFS_COLLATION_SECURITY_HASH = 18,
	NTFS_INDEX_VIEW_TYPE = 0,
	NTFS_VOLUME_DIRTY = 1,
	NTFS_MFT_RECORD = 0,
	NTFS_VOLUME_RECORD = 3,
	NTFS_BITMAP_RECORD = 6,
	NTFS_BAD_CLUSTERS_RECORD = 8,
	NTFS_SECURE_RECORD = 9,
	NTFS_UPCASE_RECORD = 10,
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
_Static_assert(sizeof(struct ntfs_disk_reparse_guid) == 24, "GUID reparse header layout");
_Static_assert(sizeof(struct ntfs_disk_reparse_names) == 8, "mount point payload header");
_Static_assert(sizeof(struct ntfs_disk_reparse_symlink) == 12, "symlink payload header");
#endif
