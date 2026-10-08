/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_DIRECTORY_INTERNAL_H
#define MACHLIN_NTFS_WRITE_DIRECTORY_INTERNAL_H
#include "write_mutation_internal.h"

enum {
	/* Internal deletion can enlarge its replacement key and receive a child
	 * split before splitting this node. Reserve both transient entries. */
	NTFS_MUTATION_INDEX_NODE_BYTES = NTFS_WRITE_CLUSTER_BYTES +
	    2 *
		(NTFS_MUTATION_FILENAME_BYTES + sizeof(struct ntfs_disk_index_entry) +
		    sizeof(uint64_t)),
	NTFS_MUTATION_INDEX_CONTENT_BYTES =
	    NTFS_WRITE_CLUSTER_BYTES - NTFS_MUTATION_INDEX_ENTRIES_OFFSET
};

#define NTFS_MUTATION_INDEX_ROOT_VCN UINT64_MAX

struct ntfs_mutation_index_node {
	uint64_t vcn;
	size_t used;
	bool child, dirty, live;
	uint8_t entries[NTFS_MUTATION_INDEX_NODE_BYTES];
};

struct ntfs_mutation_index_tree {
	struct ntfs_mutation_index_node *root, **nodes;
	size_t count, capacity;
};

int ntfs_mutation_key_compare(struct ntfs_write_mutation_plan *, const struct ntfs_mutation_key *,
    const struct ntfs_mutation_key *);
enum ntfs_result ntfs_mutation_index_load(struct ntfs_write_mutation_plan *,
    struct ntfs_mutation_directory *, uint64_t, const uint8_t *, size_t);
void ntfs_mutation_index_close(
    struct ntfs_write_mutation_plan *, struct ntfs_mutation_index_tree *);
enum ntfs_result ntfs_mutation_index_edit(struct ntfs_write_mutation_plan *,
    struct ntfs_mutation_directory *, const struct ntfs_mutation_key *, bool);
size_t ntfs_mutation_index_encode(uint8_t *, const struct ntfs_mutation_key *, bool, uint64_t);
size_t ntfs_mutation_index_root_limit(const struct ntfs_mutation_record *);
enum ntfs_result ntfs_mutation_index_fit_root(
    struct ntfs_write_mutation_plan *, struct ntfs_mutation_directory *, size_t);

#endif
