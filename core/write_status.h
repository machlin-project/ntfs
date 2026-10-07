/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_WRITE_STATUS_H
#define MACHLIN_NTFS_WRITE_STATUS_H
#include <stdbool.h>
#include <stdint.h>

enum ntfs_write_execution_stage {
	NTFS_WRITE_EXECUTION_NONE,
	NTFS_WRITE_EXECUTION_DIRTY_FIRST,
	NTFS_WRITE_EXECUTION_DIRTY_SECOND,
	NTFS_WRITE_EXECUTION_PREPARE_COPY,
	NTFS_WRITE_EXECUTION_PREPARE_HOME,
	NTFS_WRITE_EXECUTION_DATA,
	NTFS_WRITE_EXECUTION_COMMIT_COPY,
	NTFS_WRITE_EXECUTION_COMMIT_HOME,
	NTFS_WRITE_EXECUTION_FILE_HOME,
	NTFS_WRITE_EXECUTION_CLEAN_FIRST,
	NTFS_WRITE_EXECUTION_CLEAN_SECOND,
	NTFS_WRITE_EXECUTION_METADATA_HOME
};

struct ntfs_write_execution_report {
	uint64_t physical_bytes, data_bytes;
	uint32_t writes, barriers;
	enum ntfs_write_execution_stage durable_stage;
	bool data_persisted, commit_persisted, completed, poisoned;
};

enum ntfs_write_recovery_stage {
	NTFS_WRITE_RECOVERY_NONE,
	NTFS_WRITE_RECOVERY_DIRTY_FIRST,
	NTFS_WRITE_RECOVERY_DIRTY_SECOND,
	NTFS_WRITE_RECOVERY_LOG_HOMES,
	NTFS_WRITE_RECOVERY_ABORT_COPY,
	NTFS_WRITE_RECOVERY_ABORT_HOME,
	NTFS_WRITE_RECOVERY_FILE_HOMES,
	NTFS_WRITE_RECOVERY_CLEAN_FIRST,
	NTFS_WRITE_RECOVERY_CLEAN_SECOND
};

struct ntfs_write_recovery_report {
	uint64_t physical_bytes;
	uint32_t writes, barriers, reconstructed_files;
	enum ntfs_write_recovery_stage durable_stage;
	bool compensation_persisted, homes_persisted, completed, poisoned;
};

#endif
