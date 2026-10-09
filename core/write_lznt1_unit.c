/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_lznt1_unit.h"
#include "write_lznt1.h"
#include "pointer_range.h"

struct ntfs_write_lznt1_unit {
	struct ntfs_environment environment;
	size_t allocation;
	struct ntfs_write_lznt1_unit_view view;
	uint8_t storage[];
};

static bool
unit_add_size(size_t *total, size_t bytes)
{
	if (bytes > SIZE_MAX - *total) {
		return false;
	}
	*total += bytes;
	return true;
}

enum ntfs_result
ntfs_write_lznt1_unit_prepare(const struct ntfs_environment *environment,
    const struct ntfs_write_lznt1_unit_input *input, struct ntfs_write_lznt1_unit **out)
{
	struct ntfs_environment owned_environment;
	struct ntfs_write_lznt1_unit_input source;
	struct ntfs_write_lznt1_unit *unit;
	struct ntfs_write_lznt1_unit_view *view;
	const uint8_t *bytes;
	uint8_t *plain, *encoded, *workspace;
	size_t unit_bytes, bound, workspace_bytes, allocation = sizeof(*unit), index,
	       encoded_bytes, stored_bytes, remainder;
	bool zero = true;
	enum ntfs_result result;

	if (!ntfs_pointer_range_valid(out, sizeof(*out)) ||
	    !ntfs_pointer_range_valid(environment, sizeof(*environment)) ||
	    !ntfs_pointer_range_valid(input, sizeof(*input)) ||
	    !ntfs_pointer_ranges_separate(environment, sizeof(*environment), out, sizeof(*out)) ||
	    !ntfs_pointer_ranges_separate(input, sizeof(*input), out, sizeof(*out))) {
		return NTFS_INVALID;
	}
	owned_environment = *environment;
	source = *input;
	if (owned_environment.api_version != NTFS_API_VERSION ||
	    owned_environment.allocate == NULL || owned_environment.release == NULL) {
		return NTFS_INVALID;
	}
	if (source.cluster_bytes < NTFS_MST_STRIDE ||
	    source.cluster_bytes > NTFS_COMPRESSION_MAX_CLUSTER_BYTES ||
	    (source.cluster_bytes & (source.cluster_bytes - 1u)) != 0) {
		return NTFS_UNSUPPORTED;
	}
	unit_bytes = source.cluster_bytes;
	if (unit_bytes > SIZE_MAX / NTFS_COMPRESSION_CLUSTERS) {
		return NTFS_RANGE;
	}
	unit_bytes *= NTFS_COMPRESSION_CLUSTERS;
	if (source.source_bytes > unit_bytes || source.logical_bytes > unit_bytes ||
	    source.initialized_bytes > source.source_bytes ||
	    source.initialized_bytes > source.logical_bytes) {
		return NTFS_RANGE;
	}
	if (!ntfs_pointer_range_valid(source.source, source.source_bytes) ||
	    !ntfs_pointer_ranges_separate(source.source, source.source_bytes, out, sizeof(*out))) {
		return NTFS_INVALID;
	}
	result = ntfs_write_lznt1_bound(unit_bytes, &bound);
	if (result != NTFS_OK) {
		return result;
	}
	workspace_bytes = ntfs_write_lznt1_workspace_size();
	bytes = source.source;
	for (index = 0; index < source.initialized_bytes; index++) {
		if (bytes[index] != 0) {
			zero = false;
			break;
		}
	}
	if (!zero && (!unit_add_size(&allocation, unit_bytes) ||
			!unit_add_size(&allocation, bound) ||
			!unit_add_size(&allocation, workspace_bytes))) {
		return NTFS_RANGE;
	}
	*out = NULL;
	unit = owned_environment.allocate(owned_environment.context, allocation);
	if (unit == NULL) {
		return NTFS_NO_MEMORY;
	}
	ntfs_zero(unit, sizeof(*unit));
	unit->environment = owned_environment;
	unit->allocation = allocation;
	view = &unit->view;
	view->cluster_bytes = source.cluster_bytes;
	view->unit_bytes = unit_bytes;
	view->logical_bytes = source.logical_bytes;
	view->initialized_bytes = source.initialized_bytes;
	if (source.logical_bytes == 0) {
		view->kind = NTFS_WRITE_LZNT1_UNIT_EMPTY;
		*out = unit;
		return NTFS_OK;
	}
	view->logical_clusters = NTFS_COMPRESSION_CLUSTERS;
	if (zero) {
		view->kind = NTFS_WRITE_LZNT1_UNIT_SPARSE;
		view->hole_clusters = NTFS_COMPRESSION_CLUSTERS;
		*out = unit;
		return NTFS_OK;
	}
	plain = unit->storage;
	encoded = plain + unit_bytes;
	workspace = encoded + bound;
	ntfs_zero(plain, unit_bytes);
	ntfs_copy(plain, bytes, source.initialized_bytes);
	result = ntfs_write_lznt1_encode(
	    plain, unit_bytes, workspace, workspace_bytes, encoded, bound, &encoded_bytes);
	if (result != NTFS_OK) {
		ntfs_write_lznt1_unit_close(unit);
		return result;
	}
	stored_bytes = encoded_bytes;
	remainder = stored_bytes % source.cluster_bytes;
	if (remainder != 0 &&
	    !unit_add_size(&stored_bytes, source.cluster_bytes - remainder)) {
		ntfs_write_lznt1_unit_close(unit);
		return NTFS_RANGE;
	}
	/* The decoder admits an exact packet end or a complete zero header, never
	 * one dangling padding byte. Do not write padding until it fits the unit. */
	if (stored_bytes - encoded_bytes == NTFS_LZNT1_HEADER_BYTES - 1u &&
	    !unit_add_size(&stored_bytes, source.cluster_bytes)) {
		ntfs_write_lznt1_unit_close(unit);
		return NTFS_RANGE;
	}
	if (stored_bytes < unit_bytes) {
		ntfs_zero(encoded + encoded_bytes, stored_bytes - encoded_bytes);
		view->kind = NTFS_WRITE_LZNT1_UNIT_PACKED;
		view->payload = encoded;
		view->stored_bytes = stored_bytes;
		view->encoded_bytes = encoded_bytes;
		view->physical_clusters = (uint32_t)(stored_bytes / source.cluster_bytes);
		view->hole_clusters = NTFS_COMPRESSION_CLUSTERS - view->physical_clusters;
	} else {
		view->kind = NTFS_WRITE_LZNT1_UNIT_RAW;
		view->payload = plain;
		view->stored_bytes = unit_bytes;
		view->physical_clusters = NTFS_COMPRESSION_CLUSTERS;
	}
	*out = unit;
	return NTFS_OK;
}

const struct ntfs_write_lznt1_unit_view *
ntfs_write_lznt1_unit_view(const struct ntfs_write_lznt1_unit *unit)
{
	return unit == NULL ? NULL : &unit->view;
}

void
ntfs_write_lznt1_unit_close(struct ntfs_write_lznt1_unit *unit)
{
	struct ntfs_environment environment;
	size_t bytes;

	if (unit == NULL) {
		return;
	}
	environment = unit->environment;
	bytes = unit->allocation;
	environment.release(environment.context, unit, bytes);
}
