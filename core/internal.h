/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef NTFS_INTERNAL_H
#define NTFS_INTERNAL_H
#include <ntfs/ntfs.h>
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
	NTFS_RUN_INITIAL_CAPACITY = 8,
	NTFS_CATALOG_INITIAL_CAPACITY = 8,
	NTFS_VISITED_INITIAL_CAPACITY = 64,
	NTFS_VECTOR_GROWTH = 2,
	NTFS_VISITED_LOAD_DENOMINATOR = 2,
	NTFS_COMPRESSION_BUFFERS = 2,
	NTFS_VCN_HASH_SHIFT = sizeof(uint32_t) * NTFS_BITS_PER_BYTE
};

/* Odd multiplicative factor derived from the golden ratio; hash sequential VCNs
 * using the upper half of the full-width product. */
#define NTFS_VCN_HASH_MULTIPLIER UINT64_C(11400714819323198485)

struct ntfs_run {
	uint64_t vcn, length, lcn;
};

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
void ntfs_free(struct ntfs_volume *, void *, size_t);
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
enum ntfs_result ntfs_stream_exact(struct ntfs_stream *, uint64_t, void *, size_t);
const struct ntfs_run *ntfs_run_find(const struct ntfs_stream *, uint64_t);
int ntfs_name_compare(struct ntfs_volume *, const uint16_t *, size_t, const uint8_t *, size_t);
enum ntfs_result ntfs_node_by_number(struct ntfs_volume *, uint64_t, struct ntfs_node **);

#endif
