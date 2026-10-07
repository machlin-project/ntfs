/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"

static const struct ntfs_run *
stream_read_run(struct ntfs_stream *stream, uint64_t vcn)
{
	const struct ntfs_run *run;
	uint32_t position = stream->read_run;

	if (position < stream->run_count) {
		run = &stream->runs[position];
		if (vcn >= run->vcn && vcn - run->vcn < run->length) {
			return run;
		}
		if (position + 1 < stream->run_count) {
			run++;
			if (vcn >= run->vcn && vcn - run->vcn < run->length) {
				stream->read_run = position + 1;
				return run;
			}
		}
	}
	run = ntfs_run_find(stream, vcn);
	if (run != NULL) {
		stream->read_run = (uint32_t)(run - stream->runs);
	}
	return run;
}

enum ntfs_result
ntfs_stream_raw(struct ntfs_stream *stream, uint64_t offset, void *buffer, size_t length)
{
	const struct ntfs_run *run;
	uint8_t *bytes = buffer;
	uint64_t vcn, available, physical;
	size_t take, within;
	uint32_t cluster = stream->volume->info.cluster_size;
	enum ntfs_result result;

	if (stream->metadata_only || stream->wof != NULL) {
		return NTFS_UNSUPPORTED;
	}
	result = ntfs_work(stream->volume, length);
	if (result != NTFS_OK) {
		return result;
	}
	while (length != 0) {
		vcn = offset / cluster;
		within = (size_t)(offset % cluster);
		run = stream_read_run(stream, vcn);
		if (run == NULL) {
			return NTFS_CORRUPT;
		}
		available = (run->length - (vcn - run->vcn)) * cluster - within;
		take = available < length ? (size_t)available : length;
		if (take > NTFS_MAX_IO) {
			take = NTFS_MAX_IO;
		}
		if (run->lcn == NTFS_HOLE) {
			ntfs_zero(bytes, take);
		} else {
			physical = (run->lcn + (vcn - run->vcn)) * cluster + within;
			result = ntfs_io(stream->volume, physical, bytes, take);
			if (result != NTFS_OK) {
				return result;
			}
		}
		bytes += take;
		offset += take;
		length -= take;
	}
	return NTFS_OK;
}

static enum ntfs_result
stream_decode_unit(struct ntfs_stream *stream, uint64_t unit)
{
	const struct ntfs_run *run;
	uint32_t cluster = stream->volume->info.cluster_size;
	size_t size = (size_t)cluster * NTFS_COMPRESSION_CLUSTERS, packed = 0, produced;
	uint64_t vcn, start, needed;
	unsigned index, count, span;
	bool hole = false;
	enum ntfs_result result;
	uint8_t *source, *output;

	if (stream->decoded.current == unit ||
	    ntfs_unit_cache_reuse(&stream->decoded, stream->compression_buffer, unit)) {
		return NTFS_OK;
	}
	if (stream->compression_buffer == NULL) {
		stream->compression_buffer =
		    ntfs_alloc(stream->volume, size * NTFS_COMPRESSION_BUFFERS);
		if (stream->compression_buffer == NULL) {
			return NTFS_NO_MEMORY;
		}
	}
	output = ntfs_unit_cache_prepare(
	    stream->volume, &stream->decoded, stream->compression_buffer, size);
	source = stream->compression_buffer + size;
	start = unit * size;
	if (unit * NTFS_COMPRESSION_CLUSTERS >= stream->clusters) {
		return NTFS_CORRUPT;
	}
	count = stream->clusters - unit * NTFS_COMPRESSION_CLUSTERS < NTFS_COMPRESSION_CLUSTERS
	    ? (unsigned)(stream->clusters - unit * NTFS_COMPRESSION_CLUSTERS)
	    : NTFS_COMPRESSION_CLUSTERS;
	for (index = 0; index < count; index += span) {
		vcn = unit * NTFS_COMPRESSION_CLUSTERS + index;
		run = stream_read_run(stream, vcn);
		if (run == NULL) {
			return NTFS_CORRUPT;
		}
		span = run->length - (vcn - run->vcn) < count - index
		    ? (unsigned)(run->length - (vcn - run->vcn))
		    : count - index;
		if (run->lcn == NTFS_HOLE) {
			hole = true;
			continue;
		}
		if (hole) {
			return NTFS_CORRUPT;
		}
		result = ntfs_io(stream->volume, (run->lcn + vcn - run->vcn) * cluster,
		    source + packed, (size_t)span * cluster);
		if (result != NTFS_OK) {
			return result;
		}
		packed += (size_t)span * cluster;
	}
	/* Private decode/copy work is additional to delivered and encoded bytes. */
	result = ntfs_work(stream->volume, size);
	if (result != NTFS_OK) {
		return result;
	}
	if (!hole) {
		ntfs_copy(output, source, packed);
		ntfs_zero(output + packed, size - packed);
	} else if (packed == 0) {
		ntfs_zero(output, size);
	} else {
		result = ntfs_lznt1_decode(source, packed, output, size, &produced);
		if (result != NTFS_OK) {
			return result == NTFS_RANGE ? NTFS_CORRUPT : result;
		}
		needed = stream->initialized > start ? stream->initialized - start : 0;
		if (needed > size) {
			needed = size;
		}
		if (produced < needed) {
			return NTFS_CORRUPT;
		}
		ntfs_zero(output + produced, size - produced);
	}
	ntfs_unit_cache_publish(&stream->decoded, unit, output);
	return NTFS_OK;
}

enum ntfs_result
ntfs_stream_read_impl(
    struct ntfs_stream *stream, uint64_t offset, void *buffer, size_t length, size_t *done)
{
	uint8_t *bytes = buffer;
	size_t take, unit_size, within;
	uint64_t available;
	enum ntfs_result result;

	if (done == NULL) {
		return NTFS_INVALID;
	}
	*done = 0;
	if (stream == NULL || (length != 0 && buffer == NULL)) {
		return NTFS_INVALID;
	}
	if (stream->metadata_only) {
		return NTFS_UNSUPPORTED;
	}
	if (offset >= stream->size) {
		return NTFS_OK;
	}
	if (length > stream->size - offset) {
		length = (size_t)(stream->size - offset);
	}
	result = ntfs_work(stream->volume, length);
	if (result != NTFS_OK) {
		return result;
	}
	if (stream->wof != NULL) {
		return ntfs_wof_read(stream, offset, buffer, length, done);
	}
	while (length != 0) {
		take = length < NTFS_MAX_IO ? length : NTFS_MAX_IO;
		if (offset >= stream->initialized) {
			ntfs_zero(bytes, take);
		} else {
			available = stream->initialized - offset;
			if (take > available) {
				take = (size_t)available;
			}
			if (stream->resident) {
				ntfs_copy(bytes, stream->value + (size_t)offset, take);
			} else if ((stream->flags & NTFS_ATTR_COMPRESSED) != 0) {
				unit_size = (size_t)stream->volume->info.cluster_size *
				    NTFS_COMPRESSION_CLUSTERS;
				within = (size_t)(offset % unit_size);
				if (take > unit_size - within) {
					take = unit_size - within;
				}
				result = stream_decode_unit(stream, offset / unit_size);
				if (result != NTFS_OK) {
					return result;
				}
				ntfs_copy(bytes, stream->decoded.output + within, take);
			} else {
				result = ntfs_stream_raw(stream, offset, bytes, take);
				if (result != NTFS_OK) {
					return result;
				}
			}
		}
		offset += take;
		bytes += take;
		length -= take;
		*done += take;
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_stream_exact(struct ntfs_stream *stream, uint64_t offset, void *buffer, size_t size)
{
	size_t done;
	enum ntfs_result result;

	if (!ntfs_bounds(offset, size, stream->size)) {
		return NTFS_CORRUPT;
	}
	result = ntfs_stream_read(stream, offset, buffer, size, &done);
	return result == NTFS_OK && done != size ? NTFS_IO : result;
}
