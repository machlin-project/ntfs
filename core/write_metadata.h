/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_METADATA_H
#define MACHLIN_NTFS_WRITE_METADATA_H
#include "internal.h"

enum {
	NTFS_WRITE_SECTOR_BYTES = 512,
	NTFS_WRITE_CLUSTER_BYTES = 4096,
	NTFS_WRITE_RECORD_BYTES = 1024,
	NTFS_WRITE_STANDARD_BYTES =
	    sizeof(struct ntfs_disk_standard) + sizeof(struct ntfs_disk_standard_extension)
};

struct ntfs_write_file_plan {
	uint64_t reference, mft_reference, target_vcn, target_lcn, cluster_physical;
	uint16_t cluster_index, record_offset, attribute_offset, change_bytes, snapshot_bytes;
	uint16_t resident_record_offset, resident_attribute_offset, resident_bytes;
	/* Complete private restored FILE snapshots, followed by protected output.
	 * No borrowed node, record, attribute or stream survives preparation. */
	uint8_t before[NTFS_WRITE_RECORD_BYTES], after[NTFS_WRITE_RECORD_BYTES];
	uint8_t protected_after[NTFS_WRITE_RECORD_BYTES];
};

/* Compare caller-validated restored metadata bytes, excluding only the right
 * image's USA storage. The caller supplies complete readable images and their
 * explicit comparison length; identity, framing and history proofs stay there.
 * LSNs and every other byte remain significant. No I/O/allocation occurs. */
bool ntfs_write_restored_record_equal(const uint8_t *, const uint8_t *, size_t);

/* Private preparation for the qualified native ordinary-file mutation family.
 * No device writes occur. The caller owns/serializes the immutable node and
 * supplies separate private output storage. Success contains only values/bytes;
 * failures zero the output after pointer admission. The journal owner must bind
 * the supplied new LSN, reserve its log and close immutable owners before writes.
 * This does not itself admit metadata mutation or a writable FSKit operation. */
enum ntfs_result ntfs_write_prepare_metadata(
    struct ntfs_node *, uint64_t filetime, uint64_t lsn, struct ntfs_write_file_plan *);

/* Prepare an unchanged-size resident DATA overwrite and SI times in one private
 * FILE image. The journal must separately bind both resident update operations;
 * this pure helper does not grant write or recovery admission. */
enum ntfs_result ntfs_write_prepare_resident_metadata(struct ntfs_node *, uint64_t filetime,
    uint64_t lsn, uint64_t offset, const void *, size_t, struct ntfs_write_file_plan *);

#endif
