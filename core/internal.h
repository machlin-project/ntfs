/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef NTFS_INTERNAL_H
#define NTFS_INTERNAL_H
#include <ntfs/ntfs.h>
#include "disk.h"

struct ntfs_run {
	uint64_t vcn, length, lcn;
};

struct ntfs_stream {
	struct ntfs_volume *volume;
	uint64_t size, initialized, allocated, physical_size, clusters;
	uint16_t flags, compression_unit;
	bool external, resident;
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
enum ntfs_result ntfs_stream_append(struct ntfs_stream *, const struct ntfs_attr_view *);
enum ntfs_result ntfs_attribute_open(
    struct ntfs_node *, uint32_t, const uint16_t *, size_t, struct ntfs_stream **);
enum ntfs_result ntfs_stream_raw(struct ntfs_stream *, uint64_t, void *, size_t);
enum ntfs_result ntfs_stream_exact(struct ntfs_stream *, uint64_t, void *, size_t);
const struct ntfs_run *ntfs_run_find(const struct ntfs_stream *, uint64_t);
int ntfs_name_compare(struct ntfs_volume *, const uint16_t *, size_t, const uint8_t *, size_t);
enum ntfs_result ntfs_node_by_number(struct ntfs_volume *, uint64_t, struct ntfs_node **);

#endif
