/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef NTFS_VALIDATE_H
#define NTFS_VALIDATE_H
#include <ntfs/ntfs.h>

enum ntfs_validation_stage {
	NTFS_VALIDATION_SETUP,
	NTFS_VALIDATION_MOUNT,
	NTFS_VALIDATION_RECORDS,
	NTFS_VALIDATION_ATTRIBUTES,
	NTFS_VALIDATION_NAMESPACE,
	NTFS_VALIDATION_ALLOCATION,
	NTFS_VALIDATION_FINISHED,
	/* Appended to preserve the numeric values of existing report stages. */
	NTFS_VALIDATION_MIRROR
};

enum ntfs_validation_limit {
	NTFS_VALIDATION_LIMIT_NONE,
	NTFS_VALIDATION_LIMIT_MEMORY,
	NTFS_VALIDATION_LIMIT_READ_CALLS,
	NTFS_VALIDATION_LIMIT_READ_BYTES,
	NTFS_VALIDATION_LIMIT_WORK,
	NTFS_VALIDATION_LIMIT_RECORDS,
	NTFS_VALIDATION_LIMIT_RUNS,
	NTFS_VALIDATION_LIMIT_LINKS
};

struct ntfs_validation_limits {
	uint32_t max_records, max_runs, max_links;
	size_t max_memory_bytes;
	uint64_t max_read_calls, max_read_bytes, max_work_units;
};

struct ntfs_validation_report {
	enum ntfs_result result;
	enum ntfs_validation_stage stage;
	enum ntfs_validation_limit exhausted;
	bool complete;
	uint64_t record_number;
	uint64_t reference, related_reference;
	uint32_t attribute_type;
	uint64_t cluster;
	uint64_t record_slots, records_scanned, base_records, extension_records;
	uint64_t attributes, streams, physical_runs, claimed_clusters;
	uint64_t filename_attributes, index_entries, directories;
	uint64_t deferred_dos_link_counts;
	uint64_t allocated_clusters, unclaimed_clusters;
	uint64_t read_calls, read_bytes, allocation_calls, work_units;
	size_t peak_memory_bytes;
	/* Only the mandatory four-record prefix is compared. Extra declared slots
	 * are reported explicitly; their Windows-dependent coverage is unqualified. */
	uint64_t mirror_record_slots, mirror_records_compared, mirror_unchecked_records;
};

void ntfs_validation_default_limits(struct ntfs_validation_limits *);

/* Uses a private mount, never mutates an existing mounted owner and never writes.
 * The source must remain immutable for the complete synchronous call. Failures
 * retain partial counters and the current subject, never a complete verdict.
 * The diagnostic checks supported metadata, filename indexes and physical run
 * ownership; it does not replay journals, repair media or enforce authorization. */
enum ntfs_result ntfs_validate(const struct ntfs_environment *, const struct ntfs_limits *,
    const struct ntfs_validation_limits *, struct ntfs_validation_report *);

#endif
