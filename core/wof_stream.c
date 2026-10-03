/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include <ntfs/wof.h>

static const uint16_t backing_name[] = {
    'W', 'o', 'f', 'C', 'o', 'm', 'p', 'r', 'e', 's', 's', 'e', 'd', 'D', 'a', 't', 'a'};

struct ntfs_wof_stream {
	struct ntfs_stream *backing;
	struct ntfs_wof_layout layout;
	uint8_t *page, *buffers;
	size_t buffer_size;
	uint64_t cached_page, cached_unit;
};

bool
ntfs_wof_is_backing_stream(const uint16_t *name, size_t length)
{
	size_t i;

	if (name == NULL || length != sizeof(backing_name) / sizeof(backing_name[0])) {
		return false;
	}
	for (i = 0; i < length; i++) {
		if (name[i] != backing_name[i]) {
			return false;
		}
	}
	return true;
}

static enum ntfs_result
provider_info(struct ntfs_node *node, struct ntfs_wof_info *info)
{
	struct ntfs_reparse *snapshot = NULL;
	struct ntfs_stat metadata;
	enum ntfs_result result;

	result = ntfs_reparse_open(node, &snapshot);
	if (result == NTFS_OK) {
		result = ntfs_reparse_wof_info(snapshot, info);
	}
	ntfs_reparse_close(snapshot);
	if (result == NTFS_OK) {
		result = ntfs_node_metadata(node, &metadata);
		if (result == NTFS_OK && metadata.directory) {
			result = NTFS_CORRUPT;
		}
	}
	return result;
}

static enum ntfs_result
storage(struct ntfs_node *node, const struct ntfs_wof_info *info, bool readable,
    struct ntfs_stream **backing, struct ntfs_wof_layout *layout)
{
	struct ntfs_stream *placeholder = NULL, *data = NULL;
	enum ntfs_result result;

	*backing = NULL;
	result = ntfs_attribute_metadata_open(node, NTFS_ATTRIBUTE_DATA, NULL, 0, &placeholder);
	if (result != NTFS_OK) {
		return result == NTFS_NOT_FOUND ? NTFS_CORRUPT : result;
	}
	/* The placeholder's VDL does not describe provider content. Complete mapping
	 * validation already proves every run is a hole when physical_size is zero. */
	if ((placeholder->resident && placeholder->size != 0) ||
	    (!placeholder->resident && placeholder->flags != NTFS_ATTR_SPARSE) ||
	    placeholder->physical_size != 0) {
		result = NTFS_CORRUPT;
		goto finish;
	}
	result = readable ? ntfs_attribute_open(node, NTFS_ATTRIBUTE_DATA, backing_name,
				sizeof(backing_name) / sizeof(backing_name[0]), &data)
			  : ntfs_attribute_metadata_open(node, NTFS_ATTRIBUTE_DATA, backing_name,
				sizeof(backing_name) / sizeof(backing_name[0]), &data);
	if (result == NTFS_NOT_FOUND) {
		result = NTFS_CORRUPT;
	}
	if (result != NTFS_OK) {
		goto finish;
	}
	if (data->initialized != data->size) {
		result = NTFS_CORRUPT;
		goto finish;
	}
	result = ntfs_wof_layout_init(
	    info->algorithm, placeholder->size, data->size, NTFS_WOF_DEFAULT_MAX_CHUNKS, layout);
	if (result == NTFS_OK) {
		*backing = data;
		data = NULL;
	}
finish:
	ntfs_stream_close(placeholder);
	ntfs_stream_close(data);
	return result;
}

enum ntfs_result
ntfs_wof_sizes(struct ntfs_node *node, uint64_t *size, uint64_t *allocated)
{
	struct ntfs_wof_info info;
	struct ntfs_wof_layout layout;
	struct ntfs_stream *backing = NULL;
	enum ntfs_result result;

	result = provider_info(node, &info);
	if (result == NTFS_UNSUPPORTED) {
		return NTFS_NOT_FOUND;
	}
	if (result == NTFS_OK) {
		result = storage(node, &info, false, &backing, &layout);
	}
	if (result == NTFS_OK) {
		*size = layout.logical_size;
		*allocated = backing->physical_size;
	}
	ntfs_stream_close(backing);
	return result;
}

static enum ntfs_result
table_offset(struct ntfs_wof_stream *wof, uint32_t index, uint64_t *value)
{
	uint64_t offset = (uint64_t)index * wof->layout.offset_size;
	uint64_t page = offset - offset % NTFS_WOF_TABLE_PAGE_BYTES;
	size_t size, within = (size_t)(offset - page);
	enum ntfs_result result;

	if (!ntfs_bounds(offset, wof->layout.offset_size, wof->layout.table_size)) {
		return NTFS_CORRUPT;
	}
	if (wof->cached_page != page) {
		wof->cached_page = UINT64_MAX;
		size = wof->layout.table_size - page < NTFS_WOF_TABLE_PAGE_BYTES
		    ? (size_t)(wof->layout.table_size - page)
		    : NTFS_WOF_TABLE_PAGE_BYTES;
		result = ntfs_stream_exact(wof->backing, page, wof->page, size);
		if (result != NTFS_OK) {
			return result;
		}
		wof->cached_page = page;
	}
	*value = wof->layout.offset_size == sizeof(uint32_t) ? ntfs_u32(wof->page + within)
							     : ntfs_u64(wof->page + within);
	return NTFS_OK;
}

static enum ntfs_result
table_validate(struct ntfs_wof_stream *wof)
{
	struct ntfs_wof_span span;
	uint64_t start = 0, end;
	uint32_t chunk;
	enum ntfs_result result;

	if (wof->layout.table_size != 0) {
		wof->page = ntfs_alloc(wof->backing->volume, NTFS_WOF_TABLE_PAGE_BYTES);
		if (wof->page == NULL) {
			return NTFS_NO_MEMORY;
		}
	}
	for (chunk = 0; chunk < wof->layout.chunks; chunk++) {
		end = wof->layout.stored_size - wof->layout.table_size;
		if (chunk != wof->layout.chunks - 1) {
			result = table_offset(wof, chunk, &end);
			if (result != NTFS_OK) {
				return result;
			}
		}
		result = ntfs_wof_chunk_span(&wof->layout, chunk, start, end, &span);
		if (result != NTFS_OK) {
			return result;
		}
		start = end;
	}
	return NTFS_OK;
}

void
ntfs_wof_close(struct ntfs_wof_stream *wof)
{
	struct ntfs_volume *volume;

	if (wof == NULL) {
		return;
	}
	volume = wof->backing->volume;
	ntfs_free(volume, wof->page, NTFS_WOF_TABLE_PAGE_BYTES);
	ntfs_free(volume, wof->buffers, wof->buffer_size);
	ntfs_stream_close(wof->backing);
	ntfs_free(volume, wof, sizeof(*wof));
}

enum ntfs_result
ntfs_wof_open(struct ntfs_node *node, const uint16_t *name, size_t length, struct ntfs_stream **out)
{
	struct ntfs_wof_info info;
	struct ntfs_wof_layout layout;
	struct ntfs_stream *backing = NULL, *stream = NULL;
	struct ntfs_wof_stream *wof = NULL;
	enum ntfs_result result;

	result = provider_info(node, &info);
	if (result != NTFS_OK) {
		return result;
	}
	if (length != 0) {
		return ntfs_wof_is_backing_stream(name, length)
		    ? NTFS_UNSUPPORTED
		    : ntfs_attribute_open(node, NTFS_ATTRIBUTE_DATA, name, length, out);
	}
	result = storage(node, &info, true, &backing, &layout);
	if (result != NTFS_OK) {
		return result;
	}
	wof = ntfs_alloc(node->volume, sizeof(*wof));
	if (wof == NULL) {
		ntfs_stream_close(backing);
		return NTFS_NO_MEMORY;
	}
	wof->backing = backing;
	wof->layout = layout;
	wof->cached_page = UINT64_MAX;
	wof->cached_unit = UINT64_MAX;
	result = table_validate(wof);
	if (result == NTFS_OK) {
		stream = ntfs_alloc(node->volume, sizeof(*stream));
		if (stream == NULL) {
			result = NTFS_NO_MEMORY;
		}
	}
	if (result != NTFS_OK) {
		ntfs_wof_close(wof);
		return result;
	}
	stream->volume = node->volume;
	stream->size = layout.logical_size;
	stream->initialized = layout.logical_size;
	stream->physical_size = backing->physical_size;
	stream->cached_unit = UINT64_MAX;
	stream->wof = wof;
	*out = stream;
	return NTFS_OK;
}

static enum ntfs_result
decoded_unit(struct ntfs_wof_stream *wof, uint32_t chunk)
{
	struct ntfs_wof_span span;
	uint64_t start = 0, end = wof->layout.stored_size - wof->layout.table_size;
	size_t unit = wof->layout.unit_size, written;
	size_t scratch_size = wof->layout.algorithm == NTFS_WOF_LZX_32K
	    ? ntfs_lzx_workspace_size()
	    : ntfs_xpress_workspace_size();
	uint8_t *input, *workspace;
	enum ntfs_result result;

	if (wof->cached_unit == chunk) {
		return NTFS_OK;
	}
	wof->cached_unit = UINT64_MAX;
	if (wof->buffers == NULL) {
		wof->buffer_size = unit * NTFS_COMPRESSION_BUFFERS + scratch_size;
		wof->buffers = ntfs_alloc(wof->backing->volume, wof->buffer_size);
		if (wof->buffers == NULL) {
			return NTFS_NO_MEMORY;
		}
	}
	if (chunk != 0) {
		result = table_offset(wof, chunk - 1, &start);
		if (result != NTFS_OK) {
			return result;
		}
	}
	if (chunk != wof->layout.chunks - 1) {
		result = table_offset(wof, chunk, &end);
		if (result != NTFS_OK) {
			return result;
		}
	}
	result = ntfs_wof_chunk_span(&wof->layout, chunk, start, end, &span);
	if (result != NTFS_OK) {
		return result;
	}
	input = span.uncompressed ? wof->buffers : wof->buffers + unit;
	result = ntfs_stream_exact(wof->backing, span.stored_offset, input, span.stored_size);
	if (result != NTFS_OK) {
		return result;
	}
	if (!span.uncompressed) {
		result = ntfs_work(wof->backing->volume, unit);
		if (result != NTFS_OK) {
			return result;
		}
		workspace = wof->buffers + unit * NTFS_COMPRESSION_BUFFERS;
		result = wof->layout.algorithm == NTFS_WOF_LZX_32K
		    ? ntfs_lzx_decode(input, span.stored_size, wof->buffers, span.logical_size,
			  workspace, scratch_size, &written)
		    : ntfs_xpress_huffman_decode(input, span.stored_size, wof->buffers,
			  span.logical_size, workspace, scratch_size, &written);
		if (result != NTFS_OK || written != span.logical_size) {
			return result == NTFS_RANGE || result == NTFS_OK ? NTFS_CORRUPT : result;
		}
	}
	ntfs_zero(wof->buffers + span.logical_size, unit - span.logical_size);
	wof->cached_unit = chunk;
	return NTFS_OK;
}

enum ntfs_result
ntfs_wof_read(
    struct ntfs_stream *stream, uint64_t offset, void *buffer, size_t length, size_t *done)
{
	struct ntfs_wof_stream *wof = stream->wof;
	uint8_t *bytes = buffer;
	uint32_t unit = wof->layout.unit_size;
	size_t within, take;
	enum ntfs_result result;

	while (length != 0) {
		within = (size_t)(offset % unit);
		take = length < unit - within ? length : unit - within;
		result = decoded_unit(wof, (uint32_t)(offset / unit));
		if (result != NTFS_OK) {
			return result;
		}
		ntfs_copy(bytes, wof->buffers + within, take);
		bytes += take;
		offset += take;
		length -= take;
		*done += take;
	}
	return NTFS_OK;
}
