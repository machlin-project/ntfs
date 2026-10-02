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
#define NTFS_FIRST_USER_RECORD 16u
#define NTFS_REFERENCE_RECORD_MASK UINT64_C(0x0000ffffffffffff)
#define NTFS_REFERENCE_SEQUENCE_SHIFT 48u
#define NTFS_ATTRIBUTE_DATA 0x80u
#define NTFS_ATTRIBUTE_REPARSE_POINT 0xc0u
#define NTFS_FILE_ATTRIBUTE_DIRECTORY 0x10000000u
#define NTFS_REPARSE_TAG_MOUNT_POINT UINT32_C(0xa0000003)
#define NTFS_REPARSE_TAG_SYMLINK UINT32_C(0xa000000c)
#define NTFS_REPARSE_TAG_WOF UINT32_C(0x80000017)
#define NTFS_REPARSE_TAG_CLOUD UINT32_C(0x9000001a)
#define NTFS_REPARSE_SYMLINK_RELATIVE UINT32_C(0x00000001)

/* Windows' complete reparse-buffer limit, including the common header. */
#define NTFS_REPARSE_MAX_BYTES 16384u

enum ntfs_reparse_kind {
	NTFS_REPARSE_UNKNOWN,
	NTFS_REPARSE_SYMLINK,
	NTFS_REPARSE_MOUNT_POINT,
	NTFS_REPARSE_WOF,
	NTFS_REPARSE_CLOUD
};

enum ntfs_reparse_name_type { NTFS_REPARSE_SUBSTITUTE_NAME, NTFS_REPARSE_PRINT_NAME };

struct ntfs_reparse_info {
	uint32_t tag;
	enum ntfs_reparse_kind kind;
	uint32_t flags;
	size_t substitute_length, print_length; /* UTF-16 code units, excluding terminators. */
};

enum ntfs_name_namespace {
	NTFS_NAMESPACE_POSIX = 0,
	NTFS_NAMESPACE_WIN32 = 1,
	NTFS_NAMESPACE_DOS = 2,
	NTFS_NAMESPACE_WIN32_DOS = 3
};

enum {
	NTFS_DEFAULT_MAX_RUNS = 65536,
	NTFS_DEFAULT_MAX_ATTRIBUTE_LIST = 1048576,
	NTFS_DEFAULT_RECORD_CACHE_ENTRIES = 64,
	NTFS_DEFAULT_MAX_DIRECTORY_NODES = 65536,
	/* An immutable stream-name snapshot stays below 3 MiB at this cap. */
	NTFS_MAX_STREAM_CATALOG_ENTRIES = 4096
};

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
struct ntfs_reparse;
struct ntfs_stream_catalog;

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
	uint32_t max_runs;	       /* Per stream. */
	uint32_t max_attribute_list;   /* Bytes. */
	uint32_t record_cache_entries; /* Zero disables the cache. */
	uint32_t max_directory_nodes;  /* Per directory iterator or security index seek. */
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
	/* Stored policy of this directory, independent of its parent's policy.
	 * False on files and legacy version-numbered directories. */
	bool case_sensitive;
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

struct ntfs_stream_name {
	uint16_t length;
	uint16_t units[NTFS_NAME_MAX];
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
/* Ordinary-file sizes validate the complete unnamed-stream mapping without
 * reading content. Directory/reparse nodes retain base metadata only.
 * Successful stat does not imply support for decryption or decompression. */
enum ntfs_result ntfs_node_stat(struct ntfs_node *, struct ntfs_stat *);
/* Validate Microsoft reparse-buffer framing and link name spans. WOF, cloud and
 * unknown Microsoft payloads remain opaque: recognizing a tag is not data support.
 * GUID framing is UNSUPPORTED, including Microsoft-tagged candidates whose size
 * fits only that envelope. Output is zeroed on every failure. */
enum ntfs_result ntfs_reparse_decode(const void *, size_t, struct ntfs_reparse_info *);
/* Reparse metadata owns an immutable snapshot and remains valid after node close.
 * Opening an ordinary node returns NOT_FOUND; a flagged node missing its attribute
 * is CORRUPT. These calls never follow links or interpret Windows target paths. */
enum ntfs_result ntfs_reparse_open(struct ntfs_node *, struct ntfs_reparse **);
void ntfs_reparse_close(struct ntfs_reparse *);
void ntfs_reparse_get_info(const struct ntfs_reparse *, struct ntfs_reparse_info *);
/* Copy host-endian UTF-16 units losslessly, including unpaired surrogates. No NUL
 * terminator is added. RANGE reports required units without changing the buffer;
 * NULL/zero capacity queries the size. Non-link payloads return UNSUPPORTED. */
enum ntfs_result ntfs_reparse_name(
    const struct ntfs_reparse *, enum ntfs_reparse_name_type, uint16_t *, size_t, size_t *);
/* Lookup uses the parent's stored case policy: exact UTF-16 in sensitive
 * directories, $UpCase folding otherwise. The B-tree retains filename collation
 * in both modes. Folded collisions in an insensitive directory are UNSUPPORTED;
 * lookup never chooses an arbitrary entry. Each searched directory owns its flag. */
enum ntfs_result ntfs_lookup(struct ntfs_node *, const uint16_t *, size_t, struct ntfs_node **);
/* Also returns the stored name, preserving case and hard-link provenance. */
enum ntfs_result ntfs_lookup_entry(
    struct ntfs_node *, const uint16_t *, size_t, struct ntfs_node **, struct ntfs_dirent *);
/* Streams remain valid after closing their source node. Empty name = default data.
 * Stream names use exact UTF-16 matching; each stream has independent data flags.
 * Named data streams also exist on directories. Native xattr mapping is separate. */
enum ntfs_result ntfs_stream_open(
    struct ntfs_node *, const uint16_t *, size_t, struct ntfs_stream **);
/* Inventory of stored $DATA names, including the unnamed stream. Names are
 * sorted by exact UTF-16 units, without folding or conversion; encrypted and
 * provider-owned streams remain visible. This checks first-extent references and
 * headers, not complete stream mappings or content support. Stream open performs
 * those checks separately. The immutable snapshot survives source-node close.
 * maximum_entries must be between one and NTFS_MAX_STREAM_CATALOG_ENTRIES. */
enum ntfs_result ntfs_stream_catalog_open(
    struct ntfs_node *, uint32_t maximum_entries, struct ntfs_stream_catalog **);
uint32_t ntfs_stream_catalog_count(const struct ntfs_stream_catalog *);
/* Zero-based indexed copying, with END and zeroed output after the last entry. */
enum ntfs_result ntfs_stream_catalog_entry(
    const struct ntfs_stream_catalog *, uint32_t, struct ntfs_stream_name *);
void ntfs_stream_catalog_close(struct ntfs_stream_catalog *);
void ntfs_stream_close(struct ntfs_stream *);
uint64_t ntfs_stream_size(const struct ntfs_stream *);
enum ntfs_result ntfs_stream_read(struct ntfs_stream *, uint64_t, void *, size_t, size_t *);
/* Persistent in-order B-tree cursor: linear enumeration, bounded depth and memory.
 * NTFS_END is stable; NTFS_NAMESPACE_DOS aliases are returned for caller policy. */
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
