/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"

static enum ntfs_result
stream_acquire_from_attr(struct ntfs_volume *volume, const struct ntfs_attr_view *attribute_view,
    bool metadata_only, struct ntfs_stream **out)
{
	struct ntfs_stream *stream;
	const struct ntfs_disk_nonresident *disk;
	const uint8_t *value;
	size_t length;
	enum ntfs_result result;

	*out = NULL;
	if ((attribute_view->flags &
		~(NTFS_ATTR_SPARSE | NTFS_ATTR_ENCRYPTED | NTFS_ATTR_COMPRESSION_MASK)) != 0) {
		return NTFS_UNSUPPORTED;
	}
	if (!metadata_only &&
	    ((attribute_view->flags & NTFS_ATTR_ENCRYPTED) != 0 ||
		((attribute_view->flags & NTFS_ATTR_COMPRESSION_MASK) != 0 &&
		    (attribute_view->flags & NTFS_ATTR_COMPRESSION_MASK) !=
			NTFS_ATTR_COMPRESSED))) {
		return NTFS_UNSUPPORTED;
	}
	stream = ntfs_alloc(volume, sizeof(*stream));
	if (stream == NULL) {
		return NTFS_NO_MEMORY;
	}
	stream->volume = volume;
	stream->flags = attribute_view->flags;
	stream->metadata_only = metadata_only;
	ntfs_unit_cache_initialize(&stream->decoded);
	result = NTFS_OK;
	if (!attribute_view->disk->nonresident) {
		result = ntfs_attr_value(attribute_view, &value, &length);
		if (attribute_view->flags != 0) {
			result = NTFS_CORRUPT;
		}
		if (result == NTFS_OK) {
			stream->resident = true;
			stream->size = length;
			stream->initialized = length;
			stream->allocated = length;
			stream->value_allocation = metadata_only ? 0 : length;
			if (length != 0 && !metadata_only) {
				stream->value = ntfs_alloc(volume, length);
				if (stream->value == NULL) {
					result = NTFS_NO_MEMORY;
				} else {
					ntfs_copy(stream->value, value, length);
				}
			}
		}
	} else {
		disk = (const void *)(attribute_view->bytes + sizeof(struct ntfs_disk_attr));
		stream->size = ntfs_u64(disk->size);
		stream->initialized = ntfs_u64(disk->initialized);
		stream->allocated = ntfs_u64(disk->allocated);
		stream->compression_unit = disk->compression_unit;
		if (ntfs_u64(disk->lowest) != 0 || stream->size > INT64_MAX ||
		    stream->initialized > stream->size || stream->allocated > INT64_MAX ||
		    stream->allocated % volume->info.cluster_size != 0) {
			result = NTFS_CORRUPT;
		}
		if ((stream->flags & (NTFS_ATTR_COMPRESSION_MASK | NTFS_ATTR_SPARSE)) != 0) {
			const struct ntfs_disk_compressed_tail *tail;

			if (ntfs_u16(disk->mapping_offset) <
			    sizeof(struct ntfs_disk_attr) + sizeof(*disk) + sizeof(*tail)) {
				result = NTFS_CORRUPT;
			} else {
				tail = (const void *)(attribute_view->bytes +
				    sizeof(struct ntfs_disk_attr) + sizeof(*disk));
				stream->physical_size = ntfs_u64(tail->physical_size);
				if (stream->physical_size > INT64_MAX ||
				    stream->physical_size % volume->info.cluster_size != 0) {
					result = NTFS_CORRUPT;
				}
			}
		}
		if (!metadata_only && (stream->flags & NTFS_ATTR_COMPRESSED) != 0) {
			if (stream->compression_unit != NTFS_COMPRESSION_UNIT_SHIFT ||
			    volume->info.cluster_size > NTFS_COMPRESSION_MAX_CLUSTER_BYTES) {
				result = NTFS_UNSUPPORTED;
			}
		} else if (!metadata_only && stream->compression_unit != 0 &&
		    (stream->flags & NTFS_ATTR_SPARSE) == 0) {
			result = NTFS_UNSUPPORTED;
		}
		if (result == NTFS_OK) {
			result = ntfs_stream_append(stream, attribute_view);
		}
	}
	if (result != NTFS_OK) {
		ntfs_stream_close(stream);
		return result;
	}
	*out = stream;
	return NTFS_OK;
}

enum ntfs_result
ntfs_stream_from_attr(struct ntfs_volume *volume, const struct ntfs_attr_view *attribute_view,
    struct ntfs_stream **out)
{
	return stream_acquire_from_attr(volume, attribute_view, false, out);
}

enum ntfs_result
ntfs_stream_metadata_from_attr(struct ntfs_volume *volume,
    const struct ntfs_attr_view *attribute_view, struct ntfs_stream **out)
{
	return stream_acquire_from_attr(volume, attribute_view, true, out);
}

uint64_t
ntfs_stream_size(const struct ntfs_stream *stream)
{
	return stream == NULL ? 0 : stream->size;
}

void
ntfs_stream_close(struct ntfs_stream *stream)
{
	struct ntfs_volume *volume;

	if (stream == NULL) {
		return;
	}
	volume = stream->volume;
	if (stream->external) {
		volume->children--;
	}
	ntfs_wof_close(stream->wof);
	ntfs_free(volume, stream->value, stream->value_allocation);
	ntfs_free(volume, stream->runs, (size_t)stream->run_capacity * sizeof(*stream->runs));
	ntfs_unit_cache_release(volume, &stream->decoded,
	    (size_t)volume->info.cluster_size * NTFS_COMPRESSION_CLUSTERS);
	ntfs_free(volume, stream->compression_buffer,
	    (size_t)volume->info.cluster_size * NTFS_COMPRESSION_CLUSTERS *
		NTFS_COMPRESSION_BUFFERS);
	ntfs_free(volume, stream, sizeof(*stream));
}
