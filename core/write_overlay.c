/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_internal.h"
#include <ntfs/validate.h>

struct write_overlay {
	struct ntfs_environment reader;
	const struct ntfs_write_replay_plan *plan;
	size_t count;
};

static bool
separate(const void *left, size_t left_bytes, const void *right, size_t right_bytes)
{
	uintptr_t a = (uintptr_t)left, b = (uintptr_t)right;

	return left != NULL && right != NULL && left_bytes <= UINTPTR_MAX - a &&
	    right_bytes <= UINTPTR_MAX - b && (a + left_bytes <= b || b + right_bytes <= a);
}

static void *
allocate(void *context, size_t bytes)
{
	struct write_overlay *overlay = context;

	return overlay->reader.allocate(overlay->reader.context, bytes);
}

static void
release(void *context, void *buffer, size_t bytes)
{
	struct write_overlay *overlay = context;

	overlay->reader.release(overlay->reader.context, buffer, bytes);
}

static enum ntfs_result
read(void *context, uint64_t offset, void *buffer, size_t bytes)
{
	struct write_overlay *overlay = context;
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
	struct write_overlay overlay;
	struct ntfs_environment environment;
	struct ntfs_limits limits;
	const struct ntfs_write_file_plan *file;
	uint64_t displacement, home, previous_home;
	size_t index, previous;

	if (reader == NULL || plan == NULL || report == NULL || count == 0 ||
	    count > NTFS_WRITE_HISTORY_TRANSACTIONS ||
	    !separate(reader, sizeof(*reader), report, sizeof(*report)) ||
	    !separate(plan, count * sizeof(*plan), report, sizeof(*report)) ||
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
	environment = (struct ntfs_environment){
	    NTFS_API_VERSION, &overlay, reader->size_bytes, read, allocate, release};
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
