/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_MUTATION_INTERNAL_H
#define MACHLIN_NTFS_WRITE_MUTATION_INTERNAL_H
#include "write_mutation.h"

enum {
	/* Ordinary base-record allocation leaves the extension/recovery reserve
	 * available. Existing object admission still begins at record 16. */
	NTFS_MUTATION_FIRST_ALLOCATABLE_RECORD = 24,
	/* MS-FSA FileLinkInformation caps logical links, not stored DOS aliases. */
	NTFS_MUTATION_MAX_PRIMARY_LINKS = 1024,
	NTFS_MUTATION_INITIAL_REGIONS = 16,
	NTFS_MUTATION_MAX_REGIONS = 4096,
	NTFS_MUTATION_INITIAL_RECORDS = 8,
	NTFS_MUTATION_MAX_RECORDS = 4096,
	NTFS_MUTATION_LOOKUP_SLOTS_PER_ENTRY = 2,
	NTFS_MUTATION_HASH_SHIFT = sizeof(uint32_t) * NTFS_BITS_PER_BYTE,
	NTFS_MUTATION_MAX_BITMAP_BYTES = 4 * 1024 * 1024,
	NTFS_MUTATION_BITMAP_PAGE_BYTES = NTFS_WRITE_CLUSTER_BYTES,
	NTFS_MUTATION_BITMAP_WINDOW_BYTES = 16 * NTFS_MUTATION_BITMAP_PAGE_BYTES,
	NTFS_MUTATION_BITMAP_SUMMARY_BYTES =
	    NTFS_MUTATION_MAX_BITMAP_BYTES / NTFS_MUTATION_BITMAP_PAGE_BYTES / NTFS_BITS_PER_BYTE,
	NTFS_MUTATION_STREAM_CACHE_ENTRIES = 8,
	NTFS_MUTATION_INITIAL_KEYS = 16,
	NTFS_MUTATION_MAX_KEYS = 65536,
	NTFS_MUTATION_MAX_RUNS = 4096,
	NTFS_MUTATION_FILENAME_BYTES =
	    sizeof(struct ntfs_disk_filename) + NTFS_NAME_MAX * NTFS_UTF16_UNIT_BYTES,
	NTFS_MUTATION_INDEX_ENTRIES_OFFSET = 64,
	NTFS_MUTATION_SECURITY_BYTES = NTFS_WRITE_RECORD_BYTES,
	NTFS_MUTATION_HEADER_ALIGNMENT = 4,
	NTFS_MUTATION_SECURITY_REVISION = 1,
	NTFS_MUTATION_ACL_REVISION = 2,
	NTFS_MUTATION_CREATOR_AUTHORITY = 3,
	NTFS_MUTATION_CREATOR_OWNER = 0,
	NTFS_MUTATION_CREATOR_GROUP = 1
};

#define NTFS_MUTATION_HASH_MULTIPLIER UINT64_C(11400714819323198485)

_Static_assert(NTFS_MUTATION_MAX_REGIONS <= UINT16_MAX && NTFS_MUTATION_MAX_RECORDS <= UINT16_MAX,
    "Mutation lookup slots hold a vector index plus one");

struct ntfs_mutation_patch {
	uint64_t physical;
	enum ntfs_write_mutation_region_kind kind;
	struct ntfs_write_mutation_target target;
	struct ntfs_write_mutation_predecessor predecessor;
	bool bound;
	uint8_t before[NTFS_WRITE_CLUSTER_BYTES], after[NTFS_WRITE_CLUSTER_BYTES];
};

struct ntfs_mutation_record {
	uint64_t number, reference, physical, revision;
	bool changed;
	uint8_t bytes[NTFS_WRITE_RECORD_BYTES];
};

struct ntfs_mutation_bitmap_page {
	uint8_t before[NTFS_MUTATION_BITMAP_PAGE_BYTES], after[NTFS_MUTATION_BITMAP_PAGE_BYTES];
};

struct ntfs_mutation_bitmap_view {
	const uint8_t *before;
	uint8_t *after;
	size_t bytes;
};

struct ntfs_mutation_bitmap {
	struct ntfs_mutation_record *record;
	struct ntfs_stream *stream;
	uint32_t type;
	uint8_t *before, *after;
	size_t bytes, original_bytes;
	struct ntfs_mutation_bitmap_page **pages;
	size_t page_capacity, window_index, window_bytes, window_capacity;
	uint8_t full_pages[NTFS_MUTATION_BITMAP_SUMMARY_BYTES];
	uint8_t *window;
	bool window_valid;
};

struct ntfs_mutation_key {
	uint64_t reference;
	uint16_t bytes;
	uint8_t value[NTFS_MUTATION_FILENAME_BYTES];
};

struct ntfs_mutation_index_tree;

struct ntfs_mutation_directory {
	struct ntfs_mutation_record *record;
	struct ntfs_mutation_key *keys;
	struct ntfs_mutation_index_tree *tree;
	size_t count, capacity;
	bool case_sensitive;
};

struct ntfs_mutation_stream_entry {
	struct ntfs_mutation_record *record;
	struct ntfs_stream *stream;
	uint64_t revision;
	uint32_t type;
	size_t name_count;
	uint16_t name[NTFS_WRITE_MUTATION_TARGET_NAME_UNITS];
};

struct ntfs_write_mutation_plan {
	struct ntfs_environment source;
	struct ntfs_volume *volume;
	struct ntfs_stream *mft;
	struct ntfs_info info;
	struct ntfs_mutation_patch **patches;
	struct ntfs_mutation_record **records;
	size_t patch_count, patch_capacity, record_count, record_capacity, live_bytes;
	uint64_t read_calls, read_bytes, allocation_calls, allocation_bytes, work;
	uint64_t reference, filetime;
	struct ntfs_mutation_bitmap allocation, mft_bitmap;
	struct ntfs_write_journal_workspace *guard;
	uint8_t *scratch, *protected_record;
	bool sealed, operation_active;
	struct ntfs_mutation_stream_entry streams[NTFS_MUTATION_STREAM_CACHE_ENTRIES];
	size_t stream_cursor;
};

/* Insertion order owns the public region order. A half-full, power-of-two hash
 * table follows each pointer vector in the same allocation. Zero is empty;
 * every other slot names a completely acquired vector entry (index plus one).
 * Vector growth retains the original allocation-call/failure boundaries. */
static inline size_t
ntfs_mutation_vector_bytes(size_t capacity)
{
	return capacity *
	    (sizeof(void *) + NTFS_MUTATION_LOOKUP_SLOTS_PER_ENTRY * sizeof(uint16_t));
}

static inline uint16_t *
ntfs_mutation_vector_slots(void *vector, size_t capacity)
{
	return (void *)((uint8_t *)vector + capacity * sizeof(void *));
}

static inline size_t
ntfs_mutation_hash(uint64_t key, size_t capacity)
{
	key ^= key >> NTFS_MUTATION_HASH_SHIFT;
	return (size_t)((key * NTFS_MUTATION_HASH_MULTIPLIER) >> NTFS_MUTATION_HASH_SHIFT) &
	    (capacity * NTFS_MUTATION_LOOKUP_SLOTS_PER_ENTRY - 1u);
}

/* Equivalent wire byte rounding; callers retain their existing size admission
 * and ownership policy. These helpers perform no allocation or I/O. */
static inline size_t
ntfs_mutation_align_bytes(size_t bytes)
{
	return (bytes + NTFS_WIRE_ALIGNMENT - 1u) & ~(size_t)(NTFS_WIRE_ALIGNMENT - 1u);
}

/* A revision invalidates every description of this private record. Borrowers
 * retain immutable snapshots until close; reuse never survives a record edit. */
static inline void
ntfs_mutation_record_changed(struct ntfs_mutation_record *record)
{
	record->changed = true;
	record->revision++;
}

static inline bool
ntfs_mutation_bitmap_full(const struct ntfs_mutation_bitmap *bitmap, size_t offset)
{
	size_t page = offset / NTFS_MUTATION_BITMAP_PAGE_BYTES;

	return bitmap->after == NULL && page / NTFS_BITS_PER_BYTE < sizeof(bitmap->full_pages) &&
	    (bitmap->full_pages[page / NTFS_BITS_PER_BYTE] & (1u << (page % NTFS_BITS_PER_BYTE))) !=
	    0;
}

extern const uint16_t ntfs_mutation_index_name[4];

void *ntfs_mutation_allocate(struct ntfs_write_mutation_plan *, size_t);
void ntfs_mutation_release(struct ntfs_write_mutation_plan *, void *, size_t);
enum ntfs_result ntfs_mutation_work(struct ntfs_write_mutation_plan *, uint64_t);
enum ntfs_result ntfs_mutation_read(struct ntfs_write_mutation_plan *, uint64_t, void *, size_t);
enum ntfs_result ntfs_mutation_patch(struct ntfs_write_mutation_plan *, uint64_t,
    enum ntfs_write_mutation_region_kind, struct ntfs_mutation_patch **);
enum ntfs_result ntfs_mutation_write(struct ntfs_write_mutation_plan *, uint64_t, const void *,
    size_t, enum ntfs_write_mutation_region_kind, const struct ntfs_write_mutation_target *);
enum ntfs_result ntfs_mutation_record_get(
    struct ntfs_write_mutation_plan *, uint64_t, bool, struct ntfs_mutation_record **);
enum ntfs_result ntfs_mutation_record_admit(
    struct ntfs_mutation_record *, bool directory, bool parent);
enum ntfs_result ntfs_mutation_record_replace(struct ntfs_write_mutation_plan *,
    struct ntfs_mutation_record *, const struct ntfs_attr_view *, const void *, size_t);
enum ntfs_result ntfs_mutation_resident(struct ntfs_write_mutation_plan *,
    struct ntfs_mutation_record *, uint32_t, const uint16_t *, size_t, const void *, size_t,
    uint16_t);
enum ntfs_result ntfs_mutation_nonresident(struct ntfs_write_mutation_plan *,
    struct ntfs_mutation_record *, uint32_t, const uint16_t *, size_t, const struct ntfs_run *,
    size_t, uint64_t, uint64_t, uint16_t);
enum ntfs_result ntfs_mutation_attribute_remove(struct ntfs_write_mutation_plan *,
    struct ntfs_mutation_record *, uint32_t, const uint16_t *, size_t);
enum ntfs_result ntfs_mutation_stream(struct ntfs_write_mutation_plan *,
    struct ntfs_mutation_record *, uint32_t, const uint16_t *, size_t, struct ntfs_stream **);
enum ntfs_result ntfs_mutation_stream_read(
    struct ntfs_write_mutation_plan *, const struct ntfs_stream *, uint64_t, void *, size_t);
enum ntfs_result ntfs_mutation_stream_write(struct ntfs_write_mutation_plan *,
    const struct ntfs_mutation_record *, uint32_t, const uint16_t *, size_t,
    const struct ntfs_stream *, uint64_t, const void *, size_t,
    enum ntfs_write_mutation_region_kind);
enum ntfs_result ntfs_mutation_touch(struct ntfs_mutation_record *, uint64_t, bool);
enum ntfs_result ntfs_mutation_bitmap_open(
    struct ntfs_write_mutation_plan *, struct ntfs_mutation_bitmap *, uint64_t, uint32_t);
enum ntfs_result ntfs_mutation_bitmap_grow(
    struct ntfs_write_mutation_plan *, struct ntfs_mutation_bitmap *, size_t);
enum ntfs_result ntfs_mutation_bitmap_flush(
    struct ntfs_write_mutation_plan *, struct ntfs_mutation_bitmap *);
void ntfs_mutation_bitmap_close(struct ntfs_write_mutation_plan *, struct ntfs_mutation_bitmap *);
/* Read-only views may alias a replaceable read window. Acquire a writable view
 * before changing after bytes; consume a view before acquiring another one. */
enum ntfs_result ntfs_mutation_bitmap_view(struct ntfs_write_mutation_plan *,
    struct ntfs_mutation_bitmap *, size_t, bool, struct ntfs_mutation_bitmap_view *);
enum ntfs_result ntfs_mutation_bitmap_test(
    struct ntfs_write_mutation_plan *, struct ntfs_mutation_bitmap *, uint64_t, bool, bool *);
enum ntfs_result ntfs_mutation_bitmap_set(
    struct ntfs_write_mutation_plan *, struct ntfs_mutation_bitmap *, uint64_t, bool);
bool ntfs_mutation_bit(const uint8_t *, size_t, uint64_t);
void ntfs_mutation_set_bit(uint8_t *, uint64_t, bool);
enum ntfs_result ntfs_mutation_allocate_runs(
    struct ntfs_write_mutation_plan *, uint64_t, uint64_t, struct ntfs_run **, size_t *);
enum ntfs_result ntfs_mutation_free_runs(
    struct ntfs_write_mutation_plan *, const struct ntfs_stream *, uint64_t);
enum ntfs_result ntfs_mutation_resize_runs(struct ntfs_write_mutation_plan *,
    const struct ntfs_stream *, uint64_t, struct ntfs_run **, size_t *);
enum ntfs_result ntfs_mutation_new_record(
    struct ntfs_write_mutation_plan *, struct ntfs_mutation_record **);
enum ntfs_result ntfs_mutation_resize(struct ntfs_write_mutation_plan *,
    struct ntfs_mutation_record *, uint64_t, uint64_t, const void *, size_t);
enum ntfs_result ntfs_mutation_directory_open(struct ntfs_write_mutation_plan *,
    struct ntfs_mutation_record *, struct ntfs_mutation_directory *);
void ntfs_mutation_directory_close(
    struct ntfs_write_mutation_plan *, struct ntfs_mutation_directory *);
enum ntfs_result ntfs_mutation_directory_find(struct ntfs_write_mutation_plan *,
    struct ntfs_mutation_directory *, const struct ntfs_write_name *, size_t *);
enum ntfs_result ntfs_mutation_directory_add(struct ntfs_write_mutation_plan *,
    struct ntfs_mutation_directory *, uint64_t, const void *, size_t);
enum ntfs_result ntfs_mutation_directory_remove(
    struct ntfs_write_mutation_plan *, struct ntfs_mutation_directory *, size_t);
enum ntfs_result ntfs_mutation_directory_update(struct ntfs_write_mutation_plan *,
    struct ntfs_mutation_directory *, size_t, const void *, size_t);
enum ntfs_result ntfs_mutation_directory_store(
    struct ntfs_write_mutation_plan *, struct ntfs_mutation_directory *, bool);
enum ntfs_result ntfs_mutation_security_inherit(
    struct ntfs_write_mutation_plan *, struct ntfs_mutation_record *, bool, uint8_t **, size_t *);
/* Pure count admission: no allocator, callback or output mutation. */
enum ntfs_result ntfs_mutation_hardlink_count_admit(const struct ntfs_link_counts *);
enum ntfs_result ntfs_mutation_hardlink(
    struct ntfs_write_mutation_plan *, const struct ntfs_write_mutation_request *);
enum ntfs_result ntfs_mutation_namespace(
    struct ntfs_write_mutation_plan *, const struct ntfs_write_mutation_request *);
enum ntfs_result ntfs_mutation_filename_sizes(
    struct ntfs_write_mutation_plan *, struct ntfs_mutation_record *, uint64_t, uint64_t);

#endif
