/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_H
#define MACHLIN_NTFS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NTFS_API_VERSION 1u
#define NTFS_NAME_MAX 255u
#define NTFS_UTF8_NAME_MAX (NTFS_NAME_MAX * 3u)
#define NTFS_ROOT_RECORD 5u
#define NTFS_REFERENCE_RECORD_MASK UINT64_C(0x0000ffffffffffff)
#define NTFS_REFERENCE_SEQUENCE_SHIFT 48u
#define NTFS_ATTRIBUTE_DATA 0x80u
#define NTFS_ATTRIBUTE_REPARSE_POINT 0xc0u
#define NTFS_FILE_ATTRIBUTE_DIRECTORY 0x10000000u

enum ntfs_result {
	NTFS_OK,
	NTFS_NOT_NTFS,
	NTFS_CORRUPT,
	NTFS_UNSUPPORTED,
	NTFS_IO,
	NTFS_NO_MEMORY,
	NTFS_NOT_FOUND,
	NTFS_NOT_DIRECTORY,
	NTFS_IS_DIRECTORY,
	NTFS_INVALID,
	NTFS_STALE,
	NTFS_RANGE,
	NTFS_READ_ONLY,
	NTFS_DIRTY,
	NTFS_END,
	NTFS_BUSY
};

struct ntfs_volume;
struct ntfs_node;
struct ntfs_stream;
struct ntfs_directory;

/* The caller serializes a volume and all its children. The resource must remain
 * immutable and exclusively owned for their lifetime. There is no write callback.
 * Reads are exact, bounded, synchronous; partial backend reads return NTFS_IO.
 * Allocation returns storage aligned for any core type; free receives its size. */
struct ntfs_environment {
	uint32_t api_version;
	void *context;
	uint64_t size_bytes;
	enum ntfs_result (*read)(void *, uint64_t, void *, size_t);
	void *(*allocate)(void *, size_t);
	void (*release)(void *, void *, size_t);
};

struct ntfs_limits {
	uint32_t max_runs;	       /* Per stream, default 65536. */
	uint32_t max_attribute_list;   /* Bytes, default 1 MiB. */
	uint32_t record_cache_entries; /* Default 64; zero disables cache. */
	uint32_t max_directory_nodes;  /* Per iterator, default 65536. */
};

struct ntfs_info {
	uint64_t serial;
	uint64_t size_bytes;
	uint64_t cluster_count;
	uint32_t sector_size;
	uint32_t cluster_size;
	uint32_t record_size;
	uint32_t index_size;
	uint16_t volume_flags;
	uint8_t major_version;
	uint8_t minor_version;
	char label[NTFS_UTF8_NAME_MAX + 1];
};

struct ntfs_time {
	int64_t seconds;
	uint32_t nanoseconds;
};

struct ntfs_stat {
	uint64_t reference;
	uint64_t size;
	uint64_t allocated_size;
	uint32_t file_attributes;
	uint32_t security_id;
	uint16_t links;
	bool directory;
	bool reparse;
	struct ntfs_time created, modified, changed, accessed;
};

struct ntfs_dirent {
	uint64_t reference;
	uint64_t parent_reference;
	uint64_t size;
	uint32_t file_attributes;
	uint8_t name_namespace;
	uint16_t name_length;
	uint16_t name[NTFS_NAME_MAX];
};

struct ntfs_io_statistics {
	uint64_t read_calls, read_bytes, record_cache_hits, record_cache_misses;
};

void ntfs_default_limits(struct ntfs_limits *);
const char *ntfs_result_string(enum ntfs_result);
/* Probe decodes only the boot sector; successful probe is not mount acceptance. */
enum ntfs_result ntfs_probe(const struct ntfs_environment *, struct ntfs_info *);
enum ntfs_result ntfs_mount(
    const struct ntfs_environment *, const struct ntfs_limits *, struct ntfs_volume **);
/* Fails BUSY while any caller-owned nodes/streams/iterators exist. */
enum ntfs_result ntfs_unmount(struct ntfs_volume *);
void ntfs_get_info(const struct ntfs_volume *, struct ntfs_info *);
void ntfs_get_io_statistics(const struct ntfs_volume *, struct ntfs_io_statistics *);
enum ntfs_result ntfs_count_free_clusters(struct ntfs_volume *, uint64_t *);
enum ntfs_result ntfs_root(struct ntfs_volume *, struct ntfs_node **);
enum ntfs_result ntfs_node_open(struct ntfs_volume *, uint64_t reference, struct ntfs_node **);
void ntfs_node_close(struct ntfs_node *);
enum ntfs_result ntfs_node_stat(struct ntfs_node *, struct ntfs_stat *);
enum ntfs_result ntfs_lookup(struct ntfs_node *, const uint16_t *, size_t, struct ntfs_node **);
/* Also returns the stored name, preserving case and hard-link provenance. */
enum ntfs_result ntfs_lookup_entry(
    struct ntfs_node *, const uint16_t *, size_t, struct ntfs_node **, struct ntfs_dirent *);
/* Streams remain valid after closing their source node. Empty name = default data.
 * Named data streams are exposed as NTFS streams, never silently as POSIX xattrs. */
enum ntfs_result ntfs_stream_open(
    struct ntfs_node *, const uint16_t *, size_t, struct ntfs_stream **);
void ntfs_stream_close(struct ntfs_stream *);
uint64_t ntfs_stream_size(const struct ntfs_stream *);
enum ntfs_result ntfs_stream_read(struct ntfs_stream *, uint64_t, void *, size_t, size_t *);
/* Persistent in-order B-tree cursor: linear enumeration, bounded depth and memory.
 * NTFS_END is stable; DOS aliases are returned with namespace=2 for caller policy. */
enum ntfs_result ntfs_directory_open(struct ntfs_node *, struct ntfs_directory **);
enum ntfs_result ntfs_directory_next(struct ntfs_directory *, struct ntfs_dirent *);
void ntfs_directory_close(struct ntfs_directory *);
enum ntfs_result ntfs_utf8_to_utf16(const char *, size_t, uint16_t *, size_t, size_t *);
enum ntfs_result ntfs_utf16_to_utf8(const uint16_t *, size_t, char *, size_t, size_t *);
void ntfs_decode_time(uint64_t, struct ntfs_time *);
/* Independent bounded LZNT1 decoder, also usable by format tests/fuzzers. */
enum ntfs_result ntfs_lznt1_decode(const void *, size_t, void *, size_t, size_t *);

#ifdef __cplusplus
}
#endif
#endif
