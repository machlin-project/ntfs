/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_OWNER_INTERNAL_H
#define MACHLIN_NTFS_WRITE_OWNER_INTERNAL_H
#include "internal.h"
#include "write_owner.h"

struct ntfs_write_mutation_execution;

/* One exclusive claim, poison latch and governed reader serve both separately
 * admitted writer capabilities. No mounted immutable child is retained here. */
struct ntfs_overwrite {
	struct ntfs_overwrite_environment backend;
	struct ntfs_environment reader;
	struct ntfs_info info;
	struct ntfs_write_mutation_execution *mutation;
	size_t live_bytes;
	uint64_t read_calls, read_bytes;
	bool claimed, poisoned, mutations, closing;
};

enum ntfs_result ntfs_write_owner_claim(
    const struct ntfs_overwrite_environment *, struct ntfs_overwrite **);
struct ntfs_overwrite_environment ntfs_write_owner_backend(struct ntfs_overwrite *);
void ntfs_write_owner_begin(struct ntfs_overwrite *);
enum ntfs_result ntfs_write_owner_check_hibernation(struct ntfs_volume *);
enum ntfs_result ntfs_write_owner_check_change_journal(struct ntfs_volume *);

#endif
