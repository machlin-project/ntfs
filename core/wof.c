/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include <ntfs/wof.h>

static uint32_t
unit_size(uint32_t algorithm)
{
	switch (algorithm) {
	case NTFS_WOF_XPRESS_4K:
		return NTFS_WOF_UNIT_4K;
	case NTFS_WOF_LZX_32K:
		return NTFS_WOF_UNIT_32K;
	case NTFS_WOF_XPRESS_8K:
		return NTFS_WOF_UNIT_8K;
	case NTFS_WOF_XPRESS_16K:
		return NTFS_WOF_UNIT_16K;
	default:
		return 0;
	}
}

enum ntfs_result
ntfs_wof_decode(const void *buffer, size_t size, struct ntfs_wof_info *out)
{
	const struct ntfs_disk_wof_file *disk;
	struct ntfs_reparse_info reparse;
	struct ntfs_wof_info info;
	size_t payload_size;
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	result = ntfs_reparse_decode(buffer, size, &reparse);
	if (result != NTFS_OK) {
		return result;
	}
	if (reparse.kind != NTFS_REPARSE_WOF) {
		return NTFS_UNSUPPORTED;
	}
	payload_size = size - sizeof(struct ntfs_disk_reparse);
	disk = (const void *)((const uint8_t *)buffer + sizeof(struct ntfs_disk_reparse));
	/* Read the external prefix before selecting its provider-specific shape. */
	if (payload_size < offsetof(struct ntfs_disk_wof_file, provider_version)) {
		return NTFS_CORRUPT;
	}
	ntfs_zero(&info, sizeof(info));
	info.version = ntfs_u32(disk->version);
	info.provider = ntfs_u32(disk->provider);
	if (info.version != NTFS_WOF_CURRENT_VERSION || info.provider != NTFS_WOF_PROVIDER_FILE) {
		return NTFS_UNSUPPORTED;
	}
	if (payload_size < sizeof(*disk)) {
		return NTFS_CORRUPT;
	}
	if (payload_size != sizeof(*disk)) {
		return NTFS_UNSUPPORTED;
	}
	info.provider_version = ntfs_u32(disk->provider_version);
	info.algorithm = ntfs_u32(disk->algorithm);
	info.unit_size = unit_size(info.algorithm);
	if (info.provider_version != NTFS_WOF_FILE_CURRENT_VERSION || info.unit_size == 0) {
		return NTFS_UNSUPPORTED;
	}
	*out = info;
	return NTFS_OK;
}

enum ntfs_result
ntfs_wof_layout_init(uint32_t algorithm, uint64_t logical_size, uint64_t stored_size,
    uint32_t maximum_chunks, struct ntfs_wof_layout *out)
{
	struct ntfs_wof_layout layout;
	uint64_t chunks;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (maximum_chunks > NTFS_WOF_MAX_CHUNKS) {
		return NTFS_INVALID;
	}
	if (maximum_chunks == 0) {
		maximum_chunks = NTFS_WOF_DEFAULT_MAX_CHUNKS;
	}
	ntfs_zero(&layout, sizeof(layout));
	layout.algorithm = algorithm;
	layout.unit_size = unit_size(algorithm);
	if (layout.unit_size == 0) {
		return NTFS_UNSUPPORTED;
	}
	if (logical_size > INT64_MAX || stored_size > INT64_MAX) {
		return NTFS_CORRUPT;
	}
	chunks = logical_size == 0 ? 0 : (logical_size - 1) / layout.unit_size + 1;
	if (chunks > maximum_chunks) {
		return NTFS_RANGE;
	}
	layout.logical_size = logical_size;
	layout.stored_size = stored_size;
	layout.chunks = (uint32_t)chunks;
	layout.offset_size = logical_size <= UINT32_MAX ? sizeof(uint32_t) : sizeof(uint64_t);
	/* First start is implicit zero; the final end is the backing stream size. */
	layout.table_size = chunks == 0 ? 0 : (chunks - 1) * layout.offset_size;
	if (stored_size < layout.table_size || stored_size - layout.table_size < chunks ||
	    stored_size - layout.table_size > logical_size) {
		return NTFS_CORRUPT;
	}
	*out = layout;
	return NTFS_OK;
}

static bool
valid_layout(const struct ntfs_wof_layout *layout)
{
	struct ntfs_wof_layout expected;

	return layout != NULL &&
	    ntfs_wof_layout_init(layout->algorithm, layout->logical_size, layout->stored_size,
		NTFS_WOF_MAX_CHUNKS, &expected) == NTFS_OK &&
	    layout->unit_size == expected.unit_size && layout->chunks == expected.chunks &&
	    layout->offset_size == expected.offset_size &&
	    layout->table_size == expected.table_size;
}

static enum ntfs_result
checked_span(const struct ntfs_wof_layout *layout, uint32_t chunk, uint64_t start, uint64_t end,
    struct ntfs_wof_span *out)
{
	struct ntfs_wof_span span;
	uint64_t payload_size, remaining;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (chunk >= layout->chunks) {
		return NTFS_RANGE;
	}
	payload_size = layout->stored_size - layout->table_size;
	ntfs_zero(&span, sizeof(span));
	span.logical_offset = (uint64_t)chunk * layout->unit_size;
	remaining = layout->logical_size - span.logical_offset;
	span.logical_size = remaining < layout->unit_size ? (uint32_t)remaining : layout->unit_size;
	if (start >= end || end > payload_size || end - start > span.logical_size ||
	    (chunk == 0 && start != 0) || (chunk == layout->chunks - 1 && end != payload_size)) {
		return NTFS_CORRUPT;
	}
	span.stored_offset = layout->table_size + start;
	span.stored_size = (uint32_t)(end - start);
	span.uncompressed = span.stored_size == span.logical_size;
	*out = span;
	return NTFS_OK;
}

enum ntfs_result
ntfs_wof_chunk_span(const struct ntfs_wof_layout *layout, uint32_t chunk, uint64_t start,
    uint64_t end, struct ntfs_wof_span *out)
{
	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (!valid_layout(layout)) {
		return NTFS_INVALID;
	}
	return checked_span(layout, chunk, start, end, out);
}

enum ntfs_result
ntfs_wof_table_validate(const struct ntfs_wof_layout *layout, const void *buffer, size_t size)
{
	const uint8_t *table = buffer;
	struct ntfs_wof_span span;
	uint64_t start = 0, end;
	uint32_t chunk;
	enum ntfs_result result;

	if (!valid_layout(layout) || (size != 0 && buffer == NULL)) {
		return NTFS_INVALID;
	}
	if (size != layout->table_size) {
		return NTFS_CORRUPT;
	}
	for (chunk = 0; chunk < layout->chunks; chunk++) {
		if (chunk == layout->chunks - 1) {
			end = layout->stored_size - layout->table_size;
		} else {
			end = layout->offset_size == sizeof(uint32_t)
			    ? ntfs_u32(table + (size_t)chunk * layout->offset_size)
			    : ntfs_u64(table + (size_t)chunk * layout->offset_size);
		}
		result = checked_span(layout, chunk, start, end, &span);
		if (result != NTFS_OK) {
			return result;
		}
		start = end;
	}
	return NTFS_OK;
}
