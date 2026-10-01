/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef NTFS_DISK_H
#define NTFS_DISK_H
#include <stdint.h>
#include <stddef.h>

enum {
	NTFS_BOOT_BYTES = 512,
	NTFS_MST_STRIDE = 512,
	NTFS_ATTR_STANDARD = 0x10,
	NTFS_ATTR_LIST = 0x20,
	NTFS_ATTR_FILENAME = 0x30,
	NTFS_ATTR_VOLUME_NAME = 0x60,
	NTFS_ATTR_VOLUME_INFO = 0x70,
	NTFS_ATTR_INDEX_ROOT = 0x90,
	NTFS_ATTR_INDEX_ALLOCATION = 0xa0,
	NTFS_ATTR_BITMAP = 0xb0,
	NTFS_RECORD_IN_USE = 1,
	NTFS_RECORD_DIRECTORY = 2,
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
	NTFS_NAMESPACE_DOS = 2,
	NTFS_VOLUME_DIRTY = 1,
	NTFS_MFT_RECORD = 0,
	NTFS_VOLUME_RECORD = 3,
	NTFS_BITMAP_RECORD = 6,
	NTFS_UPCASE_RECORD = 10,
	NTFS_UPCASE_BYTES = 131072,
	NTFS_MAX_RECORD_BYTES = 65536,
	NTFS_DIRECTORY_DEPTH = 32,
	NTFS_COMPRESSION_CLUSTERS = 16,
	NTFS_LZNT1_CHUNK = 4096,
	NTFS_MAX_IO = 1048576
};

#define NTFS_ATTR_END UINT32_C(0xffffffff)
#define NTFS_HOLE UINT64_MAX
#define NTFS_TIME_EPOCH UINT64_C(116444736000000000)
#define NTFS_TIME_TICKS UINT64_C(10000000)

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

_Static_assert(sizeof(struct ntfs_disk_boot) == 512, "boot layout");
_Static_assert(sizeof(struct ntfs_disk_record) == 48, "record layout");
_Static_assert(sizeof(struct ntfs_disk_nonresident) == 48, "attribute layout");
_Static_assert(sizeof(struct ntfs_disk_filename) == 66, "filename layout");
_Static_assert(sizeof(struct ntfs_disk_attr_list) == 26, "attribute list layout");
#endif
