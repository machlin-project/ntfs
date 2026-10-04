/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_LOGFILE_TABLES_DISK_H
#define MACHLIN_NTFS_LOGFILE_TABLES_DISK_H
#include <stdint.h>

#define NTFS_LOG_TABLE_ALLOCATED UINT32_MAX

/* Native NTFS checkpoint layouts; live pointer fields remain opaque bytes. */
struct ntfs_disk_log_table {
	uint8_t entry_bytes[sizeof(uint16_t)], entries[sizeof(uint16_t)];
	uint8_t allocated[sizeof(uint16_t)], reserved[3 * sizeof(uint16_t)];
	uint8_t free_goal[sizeof(uint32_t)], first_free[sizeof(uint32_t)];
	uint8_t last_free[sizeof(uint32_t)];
};

struct ntfs_disk_log_open_attribute_base {
	uint8_t allocated[sizeof(uint32_t)], attribute_offset[sizeof(uint32_t)];
	uint8_t reference[sizeof(uint64_t)], open_lsn[sizeof(uint64_t)];
	uint8_t reserved[sizeof(uint32_t)], attribute_type[sizeof(uint32_t)];
	uint8_t name_pointer[sizeof(uint64_t)], index_buffer_bytes[sizeof(uint32_t)];
};

struct ntfs_disk_log_open_attribute {
	uint8_t allocated[sizeof(uint32_t)], index_buffer_bytes[sizeof(uint32_t)];
	uint8_t attribute_type[sizeof(uint32_t)], dirty_pages, reserved[3];
	uint8_t reference[sizeof(uint64_t)], open_lsn[sizeof(uint64_t)];
	uint8_t name_pointer[sizeof(uint64_t)];
};

struct ntfs_disk_log_dirty_page_base {
	uint8_t allocated[sizeof(uint32_t)], target_attribute[sizeof(uint32_t)];
	uint8_t transfer_bytes[sizeof(uint32_t)], lcns[sizeof(uint32_t)];
	uint8_t reserved[sizeof(uint32_t)], vcn[sizeof(uint64_t)], oldest_lsn[sizeof(uint64_t)];
};

struct ntfs_disk_log_dirty_page {
	uint8_t allocated[sizeof(uint32_t)], target_attribute[sizeof(uint32_t)];
	uint8_t transfer_bytes[sizeof(uint32_t)], lcns[sizeof(uint32_t)];
	uint8_t vcn[sizeof(uint64_t)], oldest_lsn[sizeof(uint64_t)];
};

struct ntfs_disk_log_transaction {
	uint8_t allocated[sizeof(uint32_t)], state[sizeof(uint32_t)];
	uint8_t first_lsn[sizeof(uint64_t)], previous_lsn[sizeof(uint64_t)];
	uint8_t undo_next_lsn[sizeof(uint64_t)], undo_records[sizeof(uint32_t)];
	uint8_t undo_bytes[sizeof(uint32_t)];
};

struct ntfs_disk_log_attribute_name {
	uint8_t target_attribute[sizeof(uint16_t)], name_bytes[sizeof(uint16_t)];
};

_Static_assert(sizeof(struct ntfs_disk_log_table) == 24, "NTFS restart table header");
_Static_assert(
    sizeof(struct ntfs_disk_log_open_attribute_base) == 44, "NTFS client-0 open attribute entry");
_Static_assert(
    sizeof(struct ntfs_disk_log_open_attribute) == 40, "NTFS client-1 open attribute entry");
_Static_assert(
    sizeof(struct ntfs_disk_log_dirty_page_base) == 36, "NTFS client-0 dirty page prefix");
_Static_assert(sizeof(struct ntfs_disk_log_dirty_page) == 32, "NTFS client-1 dirty page prefix");
_Static_assert(sizeof(struct ntfs_disk_log_transaction) == 40, "NTFS transaction entry");
_Static_assert(sizeof(struct ntfs_disk_log_attribute_name) == 4, "NTFS attribute name prefix");
#endif
