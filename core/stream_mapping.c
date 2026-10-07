/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"

static enum ntfs_result
stream_append_run(struct ntfs_stream *stream, uint64_t vcn, uint64_t count, uint64_t lcn)
{
	struct ntfs_run *runs, *last;
	uint32_t capacity;

	if (stream->run_count != 0) {
		last = &stream->runs[stream->run_count - 1];
		if (last->vcn + last->length == vcn &&
		    ((last->lcn == NTFS_HOLE && lcn == NTFS_HOLE) ||
			(last->lcn != NTFS_HOLE && lcn != NTFS_HOLE &&
			    last->lcn + last->length == lcn))) {
			last->length += count;
			return NTFS_OK;
		}
	}
	if (stream->run_count == stream->volume->limits.max_runs) {
		return NTFS_RANGE;
	}
	if (stream->run_count == stream->run_capacity) {
		capacity = stream->run_capacity == 0 ? NTFS_RUN_INITIAL_CAPACITY
						     : stream->run_capacity * NTFS_VECTOR_GROWTH;
		if (capacity > stream->volume->limits.max_runs) {
			capacity = stream->volume->limits.max_runs;
		}
		runs = ntfs_alloc(stream->volume, (size_t)capacity * sizeof(*runs));
		if (runs == NULL) {
			return NTFS_NO_MEMORY;
		}
		ntfs_copy(runs, stream->runs, (size_t)stream->run_count * sizeof(*runs));
		ntfs_free(
		    stream->volume, stream->runs, (size_t)stream->run_capacity * sizeof(*runs));
		stream->runs = runs;
		stream->run_capacity = capacity;
	}
	stream->runs[stream->run_count++] = (struct ntfs_run){vcn, count, lcn};
	return NTFS_OK;
}

static enum ntfs_result
stream_append_mapping(
    struct ntfs_stream *stream, const struct ntfs_attr_view *attr, bool implicit_holes)
{
	const struct ntfs_disk_nonresident *disk;
	const uint8_t *mapping, *mapping_end;
	uint64_t vcn, highest, lcn = 0, count, magnitude, raw, mapped;
	unsigned count_bytes, offset_bytes, byte;
	enum ntfs_result result;

	result = ntfs_work(stream->volume, attr->length);
	if (result != NTFS_OK) {
		return result;
	}
	if (!attr->disk->nonresident || attr->flags != stream->flags) {
		return NTFS_CORRUPT;
	}
	disk = (const void *)(attr->bytes + sizeof(struct ntfs_disk_attr));
	if (disk->compression_unit != stream->compression_unit) {
		return NTFS_CORRUPT;
	}
	vcn = ntfs_u64(disk->lowest);
	highest = ntfs_u64(disk->highest);
	if (vcn != stream->clusters ||
	    (highest < vcn && !(vcn == 0 && highest == UINT64_MAX && stream->size == 0))) {
		return NTFS_CORRUPT;
	}
	mapping = attr->bytes + ntfs_u16(disk->mapping_offset);
	mapping_end = attr->bytes + attr->length;
	while (mapping < mapping_end && *mapping != 0) {
		count_bytes = *mapping & NTFS_RUN_LENGTH_WIDTH_MASK;
		offset_bytes = *mapping >> NTFS_RUN_OFFSET_WIDTH_SHIFT;
		mapping++;
		if (count_bytes == 0 || count_bytes > NTFS_RUN_INTEGER_BYTES ||
		    offset_bytes > NTFS_RUN_INTEGER_BYTES ||
		    (size_t)(mapping_end - mapping) < count_bytes + offset_bytes) {
			return NTFS_CORRUPT;
		}
		count = 0;
		for (byte = 0; byte < count_bytes; byte++) {
			count |= (uint64_t)mapping[byte] << (byte * NTFS_BITS_PER_BYTE);
		}
		mapping += count_bytes;
		if (count == 0 || count > INT64_MAX || vcn > INT64_MAX - count ||
		    highest == UINT64_MAX || count > highest - vcn + 1) {
			return NTFS_CORRUPT;
		}
		mapped = NTFS_HOLE;
		if (offset_bytes != 0) {
			raw = 0;
			for (byte = 0; byte < offset_bytes; byte++) {
				raw |= (uint64_t)mapping[byte] << (byte * NTFS_BITS_PER_BYTE);
			}
			if ((mapping[offset_bytes - 1] & NTFS_RUN_NEGATIVE_FLAG) != 0) {
				if (offset_bytes < NTFS_RUN_INTEGER_BYTES) {
					raw |= UINT64_MAX << (offset_bytes * NTFS_BITS_PER_BYTE);
				}
				magnitude = ~raw + 1;
				if (magnitude > lcn) {
					return NTFS_CORRUPT;
				}
				lcn -= magnitude;
			} else {
				if (raw > INT64_MAX || lcn > (uint64_t)INT64_MAX - raw) {
					return NTFS_CORRUPT;
				}
				lcn += raw;
			}
			if (!ntfs_bounds(lcn, count, stream->volume->info.cluster_count)) {
				return NTFS_CORRUPT;
			}
			mapped = lcn;
		} else if (!implicit_holes &&
		    (stream->flags & (NTFS_ATTR_SPARSE | NTFS_ATTR_COMPRESSION_MASK)) == 0) {
			return NTFS_CORRUPT;
		}
		mapping += offset_bytes;
		result = stream_append_run(stream, vcn, count, mapped);
		if (result != NTFS_OK) {
			return result;
		}
		vcn += count;
	}
	if (mapping == mapping_end || vcn != highest + 1) {
		return NTFS_CORRUPT;
	}
	stream->clusters = vcn;
	return NTFS_OK;
}

enum ntfs_result
ntfs_stream_append(struct ntfs_stream *stream, const struct ntfs_attr_view *attr)
{
	return stream_append_mapping(stream, attr, false);
}

/* Internal diagnostic storage only. The $Bad stream describes physical bad
 * clusters, not readable content. Its holes need no ordinary sparse flag. */
enum ntfs_result
ntfs_bad_clusters_from_attr(
    struct ntfs_node *node, const struct ntfs_attr_view *attr, struct ntfs_stream **out)
{
	static const uint16_t name[] = {'$', 'B', 'a', 'd'};
	struct ntfs_volume *volume = node->volume;
	const struct ntfs_disk_nonresident *disk;
	struct ntfs_stream *stream;
	uint64_t bytes;
	size_t unit;
	enum ntfs_result result;

	*out = NULL;
	if ((node->reference & NTFS_REFERENCE_RECORD_MASK) != NTFS_BAD_CLUSTERS_RECORD ||
	    attr->type != NTFS_ATTRIBUTE_DATA || !attr->disk->nonresident ||
	    attr->disk->name_length != sizeof(name) / sizeof(name[0])) {
		return NTFS_NOT_FOUND;
	}
	for (unit = 0; unit < sizeof(name) / sizeof(name[0]); unit++) {
		if (ntfs_u16(attr->bytes + ntfs_u16(attr->disk->name_offset) +
			unit * NTFS_UTF16_UNIT_BYTES) != name[unit]) {
			return NTFS_NOT_FOUND;
		}
	}
	if (attr->flags != 0) {
		return NTFS_UNSUPPORTED;
	}
	disk = (const void *)(attr->bytes + sizeof(struct ntfs_disk_attr));
	if (volume->info.cluster_count > (uint64_t)INT64_MAX / volume->info.cluster_size) {
		return NTFS_CORRUPT;
	}
	bytes = volume->info.cluster_count * volume->info.cluster_size;
	if (ntfs_u64(disk->lowest) != 0 || ntfs_u64(disk->size) != bytes ||
	    ntfs_u64(disk->allocated) != bytes ||
	    (ntfs_u64(disk->initialized) != 0 && ntfs_u64(disk->initialized) != bytes) ||
	    disk->compression_unit != 0) {
		return NTFS_CORRUPT;
	}
	stream = ntfs_alloc(volume, sizeof(*stream));
	if (stream == NULL) {
		return NTFS_NO_MEMORY;
	}
	stream->volume = volume;
	stream->size = bytes;
	stream->allocated = bytes;
	stream->initialized = ntfs_u64(disk->initialized);
	ntfs_unit_cache_initialize(&stream->decoded);
	stream->metadata_only = true;
	result = stream_append_mapping(stream, attr, true);
	if (result != NTFS_OK) {
		ntfs_stream_close(stream);
		return result;
	}
	*out = stream;
	return NTFS_OK;
}

enum ntfs_result
ntfs_bad_clusters_append(struct ntfs_stream *stream, const struct ntfs_attr_view *attr)
{
	return stream_append_mapping(stream, attr, true);
}

enum ntfs_result
ntfs_bad_clusters_validate(struct ntfs_stream *stream)
{
	uint64_t mapped = 0;
	uint32_t index;
	enum ntfs_result result;

	if (stream->clusters != stream->volume->info.cluster_count) {
		return NTFS_CORRUPT;
	}
	result = ntfs_work(stream->volume, stream->run_count);
	if (result != NTFS_OK) {
		return result;
	}
	for (index = 0; index < stream->run_count; index++) {
		if (stream->runs[index].lcn == NTFS_HOLE) {
			continue;
		}
		if (stream->runs[index].lcn != stream->runs[index].vcn) {
			return NTFS_CORRUPT;
		}
		mapped += stream->runs[index].length;
	}
	stream->physical_size = mapped * stream->volume->info.cluster_size;
	return NTFS_OK;
}

const struct ntfs_run *
ntfs_run_find(const struct ntfs_stream *stream, uint64_t vcn)
{
	uint32_t low = 0, high = stream->run_count, mid;

	while (low < high) {
		mid = low + (high - low) / 2;
		if (vcn < stream->runs[mid].vcn) {
			high = mid;
		} else if (vcn - stream->runs[mid].vcn >= stream->runs[mid].length) {
			low = mid + 1;
		} else {
			return &stream->runs[mid];
		}
	}
	return NULL;
}
