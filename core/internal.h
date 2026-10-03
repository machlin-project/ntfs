/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef NTFS_INTERNAL_H
#define NTFS_INTERNAL_H
#include <ntfs/ntfs.h>
#include <ntfs/security.h>
#include <ntfs/access.h>
#include <ntfs/logfile.h>
#include "disk.h"

/* Implementation budgets are distinct from disk-format fields. */
enum {
	NTFS_MAX_RECORD_BYTES = 65536,
	NTFS_MAX_CLUSTER_BYTES = 65536,
	NTFS_MAX_INDEX_BYTES = 65536,
	NTFS_MAX_CONFIGURED_RUNS = 1048576,
	NTFS_MAX_CONFIGURED_ATTRIBUTE_LIST = 16777216,
	NTFS_MAX_CONFIGURED_RECORD_CACHE = 4096,
	NTFS_MAX_CONFIGURED_DIRECTORY_NODES = 1048576,
	NTFS_DIRECTORY_DEPTH = 32,
	NTFS_SECURITY_INDEX_DEPTH = 32,
	NTFS_SECURITY_COMPARE_BYTES = 4096,
	NTFS_MAX_IO = 1048576,
	NTFS_BITMAP_SCAN_BYTES = 4096,
	/* Directory inventory uses a small stack page within the 2-KiB frame cap. */
	NTFS_INDEX_BITMAP_SCAN_BYTES = 256,
	NTFS_RUN_INITIAL_CAPACITY = 8,
	NTFS_CATALOG_INITIAL_CAPACITY = 8,
	NTFS_VISITED_INITIAL_CAPACITY = 64,
	NTFS_VECTOR_GROWTH = 2,
	NTFS_VISITED_LOAD_DENOMINATOR = 2,
	NTFS_COMPRESSION_BUFFERS = 2,
	NTFS_WOF_TABLE_PAGE_BYTES = 4096,
	NTFS_VCN_HASH_SHIFT = sizeof(uint32_t) * NTFS_BITS_PER_BYTE
};

/* Odd multiplicative factor derived from the golden ratio; hash sequential VCNs
 * using the upper half of the full-width product. */
#define NTFS_VCN_HASH_MULTIPLIER UINT64_C(11400714819323198485)

struct ntfs_run {
	uint64_t vcn, length, lcn;
};

struct ntfs_wof_stream;

struct ntfs_stream {
	struct ntfs_volume *volume;
	uint64_t size, initialized, allocated, physical_size, clusters;
	uint16_t flags, compression_unit;
	bool external, resident;
	/* Metadata descriptions validate mappings but never provide readable data. */
	bool metadata_only;
	uint8_t *value;
	size_t value_allocation;
	struct ntfs_run *runs;
	uint32_t run_count, run_capacity;
	uint8_t *compression_buffer;
	uint64_t cached_unit;
	struct ntfs_wof_stream *wof;
};

struct ntfs_record_cache {
	uint64_t number, stamp;
	uint8_t *bytes;
};

struct ntfs_volume {
	struct ntfs_environment env;
	struct ntfs_limits limits;
	struct ntfs_info info;
	struct ntfs_stream *mft;
	uint8_t *upcase;
	uint64_t mft_lcn, mirror_lcn, clock;
	struct ntfs_record_cache *cache;
	uint32_t children;
	struct ntfs_io_statistics stats;
	uint64_t live_bytes;
	uint32_t operation_calls, operation_scopes;
	struct ntfs_operation *operation;
	struct ntfs_operation implicit_operation;
	struct ntfs_operation_usage last_operation;
};

struct ntfs_node {
	struct ntfs_volume *volume;
	uint64_t reference;
	uint8_t *record;
	/* Valid only after complete metadata and reparse-presence validation.
	 * The immutable medium and this node's record snapshot share one lifetime. */
	struct ntfs_stat metadata;
	bool metadata_verified;
};

struct ntfs_attr_view {
	const struct ntfs_disk_attr *disk;
	const uint8_t *bytes;
	uint32_t length, type;
	uint16_t flags, instance;
};

uint16_t ntfs_u16(const void *);
uint32_t ntfs_u32(const void *);
uint64_t ntfs_u64(const void *);
void ntfs_copy(void *, const void *, size_t);
void ntfs_zero(void *, size_t);
bool ntfs_equal(const void *, const void *, size_t);
bool ntfs_bounds(uint64_t, uint64_t, uint64_t);
void *ntfs_alloc(struct ntfs_volume *, size_t);
/* Optional metadata retention may be omitted without exhausting a call. */
void *ntfs_alloc_optional(struct ntfs_volume *, size_t);
void ntfs_free(struct ntfs_volume *, void *, size_t);
bool ntfs_operation_limits_valid(const struct ntfs_operation_limits *);
enum ntfs_result ntfs_operation_enter(struct ntfs_volume *);
void ntfs_operation_leave(struct ntfs_volume *);
void ntfs_operation_detach(struct ntfs_volume *);
enum ntfs_result ntfs_operation_read(struct ntfs_volume *, size_t);
bool ntfs_operation_allocate(struct ntfs_volume *, size_t, bool);
void ntfs_operation_allocated(struct ntfs_volume *, size_t);
enum ntfs_result ntfs_work(struct ntfs_volume *, uint64_t);
enum ntfs_result ntfs_dacl_evaluate_volume(struct ntfs_volume *, const void *, size_t,
    const struct ntfs_access_token *, uint32_t, const struct ntfs_dacl_limits *,
    struct ntfs_dacl_decision *);
struct ntfs_volume *ntfs_directory_volume(const struct ntfs_directory *);
/* Diagnostic-only comparison after complete ordinary directory enumeration.
 * Every used bitmap slot must name a visited block; free storage stays opaque.
 * The callback charges the diagnostic's work plane in addition to core scope
 * credits. The failure cluster is physical, or zero for an out-of-span bit. */
enum ntfs_result ntfs_directory_check_allocation(struct ntfs_directory *, struct ntfs_node *,
    enum ntfs_result (*charge)(void *, uint64_t), void *, uint64_t *cluster);
struct ntfs_volume *ntfs_catalog_volume(const struct ntfs_stream_catalog *);
struct ntfs_volume *ntfs_reparse_volume(const struct ntfs_reparse *);
struct ntfs_volume *ntfs_security_volume(const struct ntfs_security *);

enum ntfs_result ntfs_count_free_clusters_impl(struct ntfs_volume *volume, uint64_t *out);
enum ntfs_result ntfs_node_open_impl(
    struct ntfs_volume *volume, uint64_t reference, struct ntfs_node **out);
enum ntfs_result ntfs_root_impl(struct ntfs_volume *volume, struct ntfs_node **out);
enum ntfs_result ntfs_node_metadata_impl(struct ntfs_node *node, struct ntfs_stat *out);
enum ntfs_result ntfs_node_stat_impl(struct ntfs_node *node, struct ntfs_stat *out);
enum ntfs_result ntfs_stream_open_impl(
    struct ntfs_node *node, const uint16_t *name, size_t length, struct ntfs_stream **out);
enum ntfs_result ntfs_stream_read_impl(
    struct ntfs_stream *stream, uint64_t offset, void *bytes, size_t length, size_t *out);
enum ntfs_result ntfs_directory_open_impl(struct ntfs_node *node, struct ntfs_directory **out);
enum ntfs_result ntfs_directory_next_impl(
    struct ntfs_directory *directory, struct ntfs_dirent *out);
enum ntfs_result ntfs_lookup_entry_impl(struct ntfs_node *node, const uint16_t *name, size_t length,
    struct ntfs_node **out, struct ntfs_dirent *entry);
enum ntfs_result ntfs_lookup_impl(
    struct ntfs_node *node, const uint16_t *name, size_t length, struct ntfs_node **out);
enum ntfs_result ntfs_stream_catalog_open_impl(
    struct ntfs_node *node, uint32_t maximum, struct ntfs_stream_catalog **out);
enum ntfs_result ntfs_stream_catalog_entry_impl(
    const struct ntfs_stream_catalog *catalog, uint32_t index, struct ntfs_stream_name *out);
enum ntfs_result ntfs_reparse_open_impl(struct ntfs_node *node, struct ntfs_reparse **out);
enum ntfs_result ntfs_reparse_bytes_impl(
    const struct ntfs_reparse *snapshot, void *bytes, size_t capacity, size_t *out);
enum ntfs_result ntfs_reparse_name_impl(const struct ntfs_reparse *snapshot,
    enum ntfs_reparse_name_type type, uint16_t *units, size_t capacity, size_t *out);
enum ntfs_result ntfs_security_resolve_impl(
    struct ntfs_volume *volume, uint32_t id, struct ntfs_security **out);
enum ntfs_result ntfs_security_open_impl(struct ntfs_node *node, struct ntfs_security **out);
enum ntfs_result ntfs_security_copy_impl(
    const struct ntfs_security *snapshot, void *bytes, size_t capacity, size_t *out);
enum ntfs_result ntfs_security_evaluate_dacl_impl(const struct ntfs_security *snapshot,
    const struct ntfs_access_token *token, uint32_t desired, const struct ntfs_dacl_limits *limits,
    struct ntfs_dacl_decision *out);
enum ntfs_result ntfs_logfile_open_volume_impl(struct ntfs_volume *volume,
    const struct ntfs_logfile_limits *limits, struct ntfs_logfile_report *report,
    struct ntfs_logfile **out);
enum ntfs_result ntfs_io(struct ntfs_volume *, uint64_t, void *, size_t);
enum ntfs_result ntfs_boot(
    const struct ntfs_environment *, struct ntfs_info *, uint64_t *, uint64_t *);
enum ntfs_result ntfs_fixup(void *, size_t, const char *);
enum ntfs_result ntfs_record_validate(void *, size_t);
enum ntfs_result ntfs_record_read(struct ntfs_volume *, uint64_t, uint8_t **);
enum ntfs_result ntfs_attr_at(const uint8_t *, size_t, uint32_t *, struct ntfs_attr_view *);
enum ntfs_result ntfs_attr_find(
    const uint8_t *, size_t, uint32_t, const uint16_t *, size_t, uint16_t, struct ntfs_attr_view *);
enum ntfs_result ntfs_attr_value(const struct ntfs_attr_view *, const uint8_t **, size_t *);
enum ntfs_result ntfs_stream_from_attr(
    struct ntfs_volume *, const struct ntfs_attr_view *, struct ntfs_stream **);
enum ntfs_result ntfs_stream_metadata_from_attr(
    struct ntfs_volume *, const struct ntfs_attr_view *, struct ntfs_stream **);
enum ntfs_result ntfs_stream_append(struct ntfs_stream *, const struct ntfs_attr_view *);
enum ntfs_result ntfs_bad_clusters_from_attr(
    struct ntfs_node *, const struct ntfs_attr_view *, struct ntfs_stream **);
enum ntfs_result ntfs_attribute_open(
    struct ntfs_node *, uint32_t, const uint16_t *, size_t, struct ntfs_stream **);
enum ntfs_result ntfs_attribute_list_read(struct ntfs_node *, uint8_t **, size_t *);
enum ntfs_result ntfs_list_entry_at(
    const uint8_t *, size_t, size_t *, const struct ntfs_disk_attr_list **);
enum ntfs_result ntfs_attribute_type_present(struct ntfs_node *, uint32_t, bool *);
enum ntfs_result ntfs_listed_attribute(const uint8_t *, uint32_t, const uint16_t *, size_t,
    uint16_t, uint64_t, struct ntfs_attr_view *);
enum ntfs_result ntfs_mft_open(struct ntfs_volume *, uint8_t *, struct ntfs_stream **);
enum ntfs_result ntfs_stream_raw(struct ntfs_stream *, uint64_t, void *, size_t);
enum ntfs_result ntfs_attribute_sizes(struct ntfs_node *, uint64_t *, uint64_t *);
enum ntfs_result ntfs_attribute_metadata_open(
    struct ntfs_node *, uint32_t, const uint16_t *, size_t, struct ntfs_stream **);
enum ntfs_result ntfs_wof_sizes(struct ntfs_node *, uint64_t *, uint64_t *);
enum ntfs_result ntfs_wof_open(struct ntfs_node *, const uint16_t *, size_t, struct ntfs_stream **);
enum ntfs_result ntfs_wof_read(struct ntfs_stream *, uint64_t, void *, size_t, size_t *);
void ntfs_wof_close(struct ntfs_wof_stream *);
enum ntfs_result ntfs_stream_exact(struct ntfs_stream *, uint64_t, void *, size_t);
const struct ntfs_run *ntfs_run_find(const struct ntfs_stream *, uint64_t);
int ntfs_name_compare(struct ntfs_volume *, const uint16_t *, size_t, const uint8_t *, size_t);
enum ntfs_result ntfs_node_by_number(struct ntfs_volume *, uint64_t, struct ntfs_node **);

#endif
