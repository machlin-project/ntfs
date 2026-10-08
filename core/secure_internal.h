/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_SECURE_INTERNAL_H
#define MACHLIN_NTFS_SECURE_INTERNAL_H

#include "internal.h"
#include <ntfs/access.h>

struct ntfs_security {
	struct ntfs_volume *volume;
	struct ntfs_security_info info;
	uint8_t *bytes;
	size_t size;
	uint32_t id;
};

struct ntfs_secure_index_key {
	uint32_t hash, id;
};

struct ntfs_secure_index_bounds {
	struct ntfs_secure_index_key lower, upper;
	bool has_lower, has_upper;
};

struct ntfs_secure_index_choice {
	struct ntfs_secure_index_bounds bounds;
	struct ntfs_disk_security_locator locator;
	uint64_t vcn;
	bool found, child;
};

struct ntfs_secure_index_frame {
	uint8_t *bytes;
	size_t allocation, position, end;
	struct ntfs_secure_index_bounds bounds;
	struct ntfs_secure_index_key previous;
	bool has_previous, descended, owned;
};

struct ntfs_secure_index_cursor {
	struct ntfs_volume *volume;
	struct ntfs_stream *root, *allocation, *bitmap;
	struct ntfs_secure_index_frame frames[NTFS_SECURITY_INDEX_DEPTH];
	struct ntfs_index_visited visited;
	uint64_t store_size;
	uint32_t block_size, depth;
	bool by_hash;
	enum ntfs_result (*charge)(void *, uint64_t);
	void *context;
};

enum ntfs_result ntfs_secure_index_seek(struct ntfs_node *node, bool by_hash,
    struct ntfs_secure_index_key target, uint64_t store_size,
    struct ntfs_disk_security_locator *out);
void ntfs_secure_cursor_close(struct ntfs_secure_index_cursor *cursor);
enum ntfs_result ntfs_secure_cursor_open(struct ntfs_node *node, bool by_hash, uint64_t store_size,
    enum ntfs_result (*charge)(void *, uint64_t), void *context,
    struct ntfs_secure_index_cursor **out);
enum ntfs_result ntfs_secure_cursor_next(
    struct ntfs_secure_index_cursor *cursor, struct ntfs_disk_security_locator *out);
enum ntfs_result ntfs_secure_read_descriptor(struct ntfs_stream *store,
    const struct ntfs_disk_security_locator *locator, struct ntfs_security *snapshot,
    enum ntfs_result (*charge)(void *, uint64_t), void *context);

#endif
