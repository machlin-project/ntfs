/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_overlay.h"
#include "write_history.h"
#include <ntfs/validate.h>

struct ntfs_write_overlay_storage {
	struct ntfs_environment reader;
	const struct ntfs_write_replay_plan *plan;
	size_t count;
};

static bool
write_overlay_separate(const void *left, size_t left_bytes, const void *right, size_t right_bytes)
{
	uintptr_t left_address = (uintptr_t)left, right_address = (uintptr_t)right;

	return left != NULL && right != NULL && left_bytes <= UINTPTR_MAX - left_address &&
	    right_bytes <= UINTPTR_MAX - right_address &&
	    (left_address + left_bytes <= right_address ||
		right_address + right_bytes <= left_address);
}

static void *
write_overlay_allocate(void *context, size_t bytes)
{
	struct ntfs_write_overlay_storage *overlay = context;

	return overlay->reader.allocate(overlay->reader.context, bytes);
}

static void
write_overlay_release(void *context, void *buffer, size_t bytes)
{
	struct ntfs_write_overlay_storage *overlay = context;

	overlay->reader.release(overlay->reader.context, buffer, bytes);
}

static enum ntfs_result
write_overlay_read(void *context, uint64_t offset, void *buffer, size_t bytes)
{
	struct ntfs_write_overlay_storage *overlay = context;
	const struct ntfs_write_file_plan *file;
	uint64_t home, first, end;
	size_t index;
	enum ntfs_result result;

	if (!ntfs_bounds(offset, bytes, overlay->reader.size_bytes)) {
		return NTFS_RANGE;
	}
	result = overlay->reader.read(overlay->reader.context, offset, buffer, bytes);
	if (result != NTFS_OK) {
		return result;
	}
	for (index = 0; index < overlay->count; index++) {
		file = &overlay->plan[index].file;
		home = file->cluster_physical +
		    file->cluster_index * (uint64_t)NTFS_WRITE_SECTOR_BYTES;
		first = offset > home ? offset : home;
		end = offset + bytes < home + NTFS_WRITE_RECORD_BYTES
		    ? offset + bytes
		    : home + NTFS_WRITE_RECORD_BYTES;
		if (first < end) {
			ntfs_copy((uint8_t *)buffer + first - offset,
			    file->protected_after + first - home, (size_t)(end - first));
		}
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_write_validate_overlays(const struct ntfs_environment *reader,
    const struct ntfs_write_replay_plan *plan, size_t count, struct ntfs_validation_report *report)
{
	struct ntfs_write_overlay_storage overlay;
	struct ntfs_environment environment;
	struct ntfs_limits limits;
	const struct ntfs_write_file_plan *file;
	uint64_t displacement, home, previous_home;
	size_t index, previous;

	if (reader == NULL || plan == NULL || report == NULL || count == 0 ||
	    count > NTFS_WRITE_HISTORY_TRANSACTIONS ||
	    !write_overlay_separate(reader, sizeof(*reader), report, sizeof(*report)) ||
	    !write_overlay_separate(plan, count * sizeof(*plan), report, sizeof(*report)) ||
	    reader->api_version != NTFS_API_VERSION || reader->read == NULL ||
	    reader->allocate == NULL || reader->release == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(report, sizeof(*report));
	for (index = 0; index < count; index++) {
		file = &plan[index].file;
		if (file->cluster_index >= NTFS_WRITE_CLUSTER_BYTES / NTFS_WRITE_SECTOR_BYTES ||
		    file->cluster_index % (NTFS_WRITE_RECORD_BYTES / NTFS_WRITE_SECTOR_BYTES) !=
			0 ||
		    file->cluster_physical % NTFS_WRITE_CLUSTER_BYTES != 0) {
			return NTFS_CORRUPT;
		}
		displacement = file->cluster_index * (uint64_t)NTFS_WRITE_SECTOR_BYTES;
		if (file->cluster_physical > UINT64_MAX - displacement ||
		    !ntfs_bounds(
			file->cluster_physical, NTFS_WRITE_CLUSTER_BYTES, reader->size_bytes)) {
			return NTFS_RANGE;
		}
		home = file->cluster_physical + displacement;
		for (previous = 0; previous < index; previous++) {
			previous_home = plan[previous].file.cluster_physical +
			    plan[previous].file.cluster_index * (uint64_t)NTFS_WRITE_SECTOR_BYTES;
			if (previous_home == home &&
			    plan[previous].file.reference != file->reference) {
				return NTFS_STALE;
			}
		}
	}
	overlay.reader = *reader;
	overlay.plan = plan;
	overlay.count = count;
	environment = (struct ntfs_environment){NTFS_API_VERSION, &overlay, reader->size_bytes,
	    write_overlay_read, write_overlay_allocate, write_overlay_release};
	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	return ntfs_validate(&environment, &limits, NULL, report);
}

enum ntfs_result
ntfs_write_validate_overlay(const struct ntfs_environment *reader,
    const struct ntfs_write_replay_plan *plan, struct ntfs_validation_report *report)
{
	return ntfs_write_validate_overlays(reader, plan, 1, report);
}
