/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_LOGFILE_SOURCE_INTERNAL_H
#define MACHLIN_NTFS_LOGFILE_SOURCE_INTERNAL_H

#include "internal.h"
#include "logfile_internal.h"
#include "logfile_tables_disk.h"

struct ntfs_logfile_index_entry {
	struct ntfs_logfile_indexed_page page;
	struct ntfs_logfile_page_view circular;
	uint64_t equal_candidates;
	uint32_t retained_target;
	bool blocked;
};

struct ntfs_logfile_page_index {
	struct ntfs_logfile_page_index_report report;
	struct ntfs_logfile_page_view copies[NTFS_LOGFILE_FAST_COPY_PAGES];
	uint64_t copy_targets[NTFS_LOGFILE_FAST_COPY_PAGES];
	uint64_t unrouted_lsn;
	size_t allocation_bytes;
	bool unrouted_undated;
	struct ntfs_logfile_index_entry entries[];
};

struct ntfs_logfile_index_builder {
	struct ntfs_logfile_page_index *index;
	const struct ntfs_logfile_restart *restart;
	uint64_t first_offset;
	uint32_t copy_pages;
	struct ntfs_logfile *source;
	bool admit_uncompleted_legacy_copies;
};

struct ntfs_logfile {
	struct ntfs_environment environment;
	struct ntfs_logfile_limits limits;
	struct ntfs_logfile_report report;
	struct ntfs_logfile_restart restart;
	uint8_t *raw, *scratch, *selected;
	bool backend_failed;
	struct ntfs_stream *backing;
	struct ntfs_logfile_page_index *page_index;
};

struct ntfs_logfile_legacy_copies {
	struct ntfs_logfile_page_view pages[NTFS_LFS_LEGACY_TAIL_PAGES];
	bool available[NTFS_LFS_LEGACY_TAIL_PAGES];
	uint8_t *comparison;
};

struct ntfs_logfile_fast_copies {
	struct ntfs_logfile_page_view pages[NTFS_LOGFILE_FAST_COPY_PAGES];
	uint32_t targets[NTFS_LOGFILE_FAST_COPY_PAGES];
	bool available[NTFS_LOGFILE_FAST_COPY_PAGES];
	uint8_t *comparison;
};

struct ntfs_logfile_record_copies {
	struct ntfs_logfile_legacy_copies *legacy;
	struct ntfs_logfile_fast_copies *fast;
	const struct ntfs_logfile_checkpoint_capture_limits *capture_limits;
	bool indexed, history;
};

struct ntfs_logfile_record_ending {
	struct ntfs_logfile_page_view page;
	uint64_t offset;
	size_t end_offset;
};

enum {
	NTFS_LOGFILE_FAST_METADATA_BYTES = 2 * 1024,
	NTFS_LOGFILE_INDEX_METADATA_BYTES = 4 * 1024,
	NTFS_LOGFILE_PREFIX_PAIR_READS = 2
};

_Static_assert(sizeof(struct ntfs_logfile_fast_copies) <= NTFS_LOGFILE_FAST_METADATA_BYTES,
    "fast-copy metadata policy");
_Static_assert(NTFS_LOGFILE_MAX_FILE_BYTES / NTFS_MST_STRIDE <= UINT32_MAX,
    "physical inventory counter capacity");
_Static_assert(
    sizeof(struct ntfs_logfile_page_index) == offsetof(struct ntfs_logfile_page_index, entries),
    "page-index flexible-array placement");
_Static_assert(sizeof(struct ntfs_logfile_page_index) <= NTFS_LOGFILE_INDEX_METADATA_BYTES,
    "page-index fixed metadata policy");
_Static_assert(NTFS_LOGFILE_FAST_COPY_PAGES < sizeof(uint64_t) * NTFS_BITS_PER_BYTE,
    "copy slots and circular candidate fit the index mask");
_Static_assert(sizeof(struct ntfs_disk_log_fast_page) ==
	NTFS_LFS_FAST_USA_WORDS * sizeof(uint16_t) + sizeof(struct ntfs_disk_log_page) +
	    sizeof(uint16_t) + sizeof(uint32_t),
    "fast-page prefix layout");

enum ntfs_result ntfs_logfile_source_read(struct ntfs_logfile *source, uint64_t offset,
    void *buffer, size_t size, struct ntfs_logfile_report *work);
bool ntfs_logfile_is_ntfs_client(const struct ntfs_logfile_client *client);
enum ntfs_result ntfs_logfile_load_page(struct ntfs_logfile *source, uint64_t offset,
    struct ntfs_logfile_report *work, struct ntfs_logfile_page_view *out);
bool ntfs_logfile_same_written_prefix(const struct ntfs_logfile_restart *restart,
    const struct ntfs_logfile_page *a, const uint8_t *a_bytes, const struct ntfs_logfile_page *b,
    const uint8_t *b_bytes);
enum ntfs_result ntfs_logfile_scan_legacy_copies(struct ntfs_logfile *source,
    struct ntfs_logfile_report *work, struct ntfs_logfile_legacy_copies *copies);
enum ntfs_result ntfs_logfile_observe_target(
    struct ntfs_logfile *source, struct ntfs_logfile_page_observation *observation);
enum ntfs_result ntfs_logfile_index_reload(struct ntfs_logfile *source,
    const struct ntfs_logfile_page_view *expected, uint64_t target,
    struct ntfs_logfile_report *work, struct ntfs_logfile_page_view *out);
enum ntfs_result ntfs_logfile_load_indexed_page(struct ntfs_logfile *source, uint64_t offset,
    struct ntfs_logfile_report *work, struct ntfs_logfile_page_view *out);
enum ntfs_result ntfs_logfile_scan_fast_copies(struct ntfs_logfile *source,
    struct ntfs_logfile_report *work, struct ntfs_logfile_fast_copies *copies);
enum ntfs_result ntfs_logfile_load_record_page(struct ntfs_logfile *source, uint64_t offset,
    uint64_t lsn, struct ntfs_logfile_report *work, const struct ntfs_logfile_record_copies *copies,
    struct ntfs_logfile_page_view *out);

#endif
