/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_PROGRAM_INTERNAL_H
#define MACHLIN_NTFS_WRITE_PROGRAM_INTERNAL_H
#include "write_program.h"
#include "write_payload.h"

/* One retained program owner shared only by metadata compilation/application
 * and packet/page composition. Payloads and region storage have one lifetime. */
struct program_target {
	struct ntfs_write_mutation_target identity;
	uint16_t key, flags;
};

struct program_region {
	struct ntfs_write_mutation_region view;
	size_t target;
	uint8_t before[NTFS_WRITE_CLUSTER_BYTES], after[NTFS_WRITE_CLUSTER_BYTES];
};

struct ntfs_write_program {
	struct ntfs_environment environment;
	size_t live, regions, targets, count, capacity;
	struct program_region *region;
	struct program_target *target;
	struct ntfs_write_program_update *update;
};

#endif
