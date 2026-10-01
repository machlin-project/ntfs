/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"

static enum ntfs_result
append_run(struct ntfs_stream *s, uint64_t vcn, uint64_t count, uint64_t lcn)
{
	struct ntfs_run *runs, *last;
	uint32_t capacity;

	if (s->run_count != 0) {
		last = &s->runs[s->run_count - 1];
		if (last->vcn + last->length == vcn &&
		    ((last->lcn == NTFS_HOLE && lcn == NTFS_HOLE) ||
			(last->lcn != NTFS_HOLE && lcn != NTFS_HOLE &&
			    last->lcn + last->length == lcn))) {
			last->length += count;
			return NTFS_OK;
		}
	}
	if (s->run_count == s->volume->limits.max_runs) {
		return NTFS_RANGE;
	}
	if (s->run_count == s->run_capacity) {
		capacity = s->run_capacity == 0 ? NTFS_RUN_INITIAL_CAPACITY
						: s->run_capacity * NTFS_VECTOR_GROWTH;
		if (capacity > s->volume->limits.max_runs) {
			capacity = s->volume->limits.max_runs;
		}
		runs = ntfs_alloc(s->volume, (size_t)capacity * sizeof(*runs));
		if (runs == NULL) {
			return NTFS_NO_MEMORY;
		}
		ntfs_copy(runs, s->runs, (size_t)s->run_count * sizeof(*runs));
		ntfs_free(s->volume, s->runs, (size_t)s->run_capacity * sizeof(*runs));
		s->runs = runs;
		s->run_capacity = capacity;
	}
	s->runs[s->run_count++] = (struct ntfs_run){vcn, count, lcn};
	return NTFS_OK;
}

enum ntfs_result
ntfs_stream_append(struct ntfs_stream *s, const struct ntfs_attr_view *a)
{
	const struct ntfs_disk_nonresident *n;
	const uint8_t *p, *end;
	uint64_t vcn, highest, lcn = 0, count, magnitude, raw, mapped;
	unsigned count_bytes, offset_bytes, i;
	enum ntfs_result result;

	if (!a->disk->nonresident || a->flags != s->flags) {
		return NTFS_CORRUPT;
	}
	n = (const void *)(a->bytes + sizeof(struct ntfs_disk_attr));
	if (n->compression_unit != s->compression_unit) {
		return NTFS_CORRUPT;
	}
	vcn = ntfs_u64(n->lowest);
	highest = ntfs_u64(n->highest);
	if (vcn != s->clusters ||
	    (highest < vcn && !(vcn == 0 && highest == UINT64_MAX && s->size == 0))) {
		return NTFS_CORRUPT;
	}
	p = a->bytes + ntfs_u16(n->mapping_offset);
	end = a->bytes + a->length;
	while (p < end && *p != 0) {
		count_bytes = *p & NTFS_RUN_LENGTH_WIDTH_MASK;
		offset_bytes = *p >> NTFS_RUN_OFFSET_WIDTH_SHIFT;
		p++;
		if (count_bytes == 0 || count_bytes > NTFS_RUN_INTEGER_BYTES ||
		    offset_bytes > NTFS_RUN_INTEGER_BYTES ||
		    (size_t)(end - p) < count_bytes + offset_bytes) {
			return NTFS_CORRUPT;
		}
		count = 0;
		for (i = 0; i < count_bytes; i++) {
			count |= (uint64_t)p[i] << (i * NTFS_BITS_PER_BYTE);
		}
		p += count_bytes;
		if (count == 0 || count > INT64_MAX || vcn > INT64_MAX - count ||
		    highest == UINT64_MAX || count > highest - vcn + 1) {
			return NTFS_CORRUPT;
		}
		mapped = NTFS_HOLE;
		if (offset_bytes != 0) {
			raw = 0;
			for (i = 0; i < offset_bytes; i++) {
				raw |= (uint64_t)p[i] << (i * NTFS_BITS_PER_BYTE);
			}
			if ((p[offset_bytes - 1] & NTFS_RUN_NEGATIVE_FLAG) != 0) {
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
			if (!ntfs_bounds(lcn, count, s->volume->info.cluster_count)) {
				return NTFS_CORRUPT;
			}
			mapped = lcn;
		} else if ((s->flags & (NTFS_ATTR_SPARSE | NTFS_ATTR_COMPRESSED)) == 0) {
			return NTFS_CORRUPT;
		}
		p += offset_bytes;
		result = append_run(s, vcn, count, mapped);
		if (result != NTFS_OK) {
			return result;
		}
		vcn += count;
	}
	if (p == end || vcn != highest + 1) {
		return NTFS_CORRUPT;
	}
	s->clusters = vcn;
	return NTFS_OK;
}

enum ntfs_result
ntfs_stream_from_attr(
    struct ntfs_volume *v, const struct ntfs_attr_view *a, struct ntfs_stream **out)
{
	struct ntfs_stream *s;
	const struct ntfs_disk_nonresident *n;
	const uint8_t *value;
	size_t length;
	enum ntfs_result result;

	*out = NULL;
	if ((a->flags & ~(NTFS_ATTR_SPARSE | NTFS_ATTR_ENCRYPTED | NTFS_ATTR_COMPRESSION_MASK)) !=
		0 ||
	    (a->flags & NTFS_ATTR_ENCRYPTED) != 0 ||
	    ((a->flags & NTFS_ATTR_COMPRESSION_MASK) != 0 &&
		(a->flags & NTFS_ATTR_COMPRESSION_MASK) != NTFS_ATTR_COMPRESSED)) {
		return NTFS_UNSUPPORTED;
	}
	s = ntfs_alloc(v, sizeof(*s));
	if (s == NULL) {
		return NTFS_NO_MEMORY;
	}
	s->volume = v;
	s->flags = a->flags;
	s->cached_unit = UINT64_MAX;
	result = NTFS_OK;
	if (!a->disk->nonresident) {
		result = ntfs_attr_value(a, &value, &length);
		if (a->flags != 0) {
			result = NTFS_CORRUPT;
		}
		if (result == NTFS_OK) {
			s->resident = true;
			s->size = length;
			s->initialized = length;
			s->allocated = length;
			s->value_allocation = length;
			if (length != 0) {
				s->value = ntfs_alloc(v, length);
				if (s->value == NULL) {
					result = NTFS_NO_MEMORY;
				} else {
					ntfs_copy(s->value, value, length);
				}
			}
		}
	} else {
		n = (const void *)(a->bytes + sizeof(struct ntfs_disk_attr));
		s->size = ntfs_u64(n->size);
		s->initialized = ntfs_u64(n->initialized);
		s->allocated = ntfs_u64(n->allocated);
		s->compression_unit = n->compression_unit;
		if (ntfs_u64(n->lowest) != 0 || s->size > INT64_MAX || s->initialized > s->size ||
		    s->allocated > INT64_MAX || s->allocated % v->info.cluster_size != 0) {
			result = NTFS_CORRUPT;
		}
		if ((s->flags & (NTFS_ATTR_COMPRESSED | NTFS_ATTR_SPARSE)) != 0) {
			const struct ntfs_disk_compressed_tail *tail;

			if (ntfs_u16(n->mapping_offset) <
			    sizeof(struct ntfs_disk_attr) + sizeof(*n) + sizeof(*tail)) {
				result = NTFS_CORRUPT;
			} else {
				tail = (const void *)(a->bytes + sizeof(struct ntfs_disk_attr) +
				    sizeof(*n));
				s->physical_size = ntfs_u64(tail->physical_size);
				if (s->physical_size > INT64_MAX ||
				    s->physical_size % v->info.cluster_size != 0) {
					result = NTFS_CORRUPT;
				}
			}
		}
		if ((s->flags & NTFS_ATTR_COMPRESSED) != 0) {
			if (s->compression_unit != NTFS_COMPRESSION_UNIT_SHIFT ||
			    v->info.cluster_size > NTFS_COMPRESSION_MAX_CLUSTER_BYTES) {
				result = NTFS_UNSUPPORTED;
			}
		} else if (s->compression_unit != 0 && (s->flags & NTFS_ATTR_SPARSE) == 0) {
			result = NTFS_UNSUPPORTED;
		}
		if (result == NTFS_OK) {
			result = ntfs_stream_append(s, a);
		}
	}
	if (result != NTFS_OK) {
		ntfs_stream_close(s);
		return result;
	}
	*out = s;
	return NTFS_OK;
}

const struct ntfs_run *
ntfs_run_find(const struct ntfs_stream *s, uint64_t vcn)
{
	uint32_t low = 0, high = s->run_count, mid;

	while (low < high) {
		mid = low + (high - low) / 2;
		if (vcn < s->runs[mid].vcn) {
			high = mid;
		} else if (vcn - s->runs[mid].vcn >= s->runs[mid].length) {
			low = mid + 1;
		} else {
			return &s->runs[mid];
		}
	}
	return NULL;
}

enum ntfs_result
ntfs_stream_raw(struct ntfs_stream *s, uint64_t offset, void *buffer, size_t length)
{
	const struct ntfs_run *r;
	uint8_t *bytes = buffer;
	uint64_t vcn, available, physical;
	size_t take, within;
	uint32_t cluster = s->volume->info.cluster_size;
	enum ntfs_result result;

	while (length != 0) {
		vcn = offset / cluster;
		within = (size_t)(offset % cluster);
		r = ntfs_run_find(s, vcn);
		if (r == NULL) {
			return NTFS_CORRUPT;
		}
		available = (r->length - (vcn - r->vcn)) * cluster - within;
		take = available < length ? (size_t)available : length;
		if (take > NTFS_MAX_IO) {
			take = NTFS_MAX_IO;
		}
		if (r->lcn == NTFS_HOLE) {
			ntfs_zero(bytes, take);
		} else {
			physical = (r->lcn + (vcn - r->vcn)) * cluster + within;
			result = ntfs_io(s->volume, physical, bytes, take);
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
compression_unit(struct ntfs_stream *s, uint64_t unit)
{
	const struct ntfs_run *r;
	uint32_t cluster = s->volume->info.cluster_size;
	size_t size = (size_t)cluster * NTFS_COMPRESSION_CLUSTERS, packed = 0, produced;
	uint64_t vcn, start, needed;
	unsigned i, count, span;
	bool hole = false;
	enum ntfs_result result;
	uint8_t *source;

	if (s->cached_unit == unit) {
		return NTFS_OK;
	}
	if (s->compression_buffer == NULL) {
		s->compression_buffer = ntfs_alloc(s->volume, size * NTFS_COMPRESSION_BUFFERS);
		if (s->compression_buffer == NULL) {
			return NTFS_NO_MEMORY;
		}
	}
	s->cached_unit = UINT64_MAX;
	source = s->compression_buffer + size;
	start = unit * size;
	if (unit * NTFS_COMPRESSION_CLUSTERS >= s->clusters) {
		return NTFS_CORRUPT;
	}
	count = s->clusters - unit * NTFS_COMPRESSION_CLUSTERS < NTFS_COMPRESSION_CLUSTERS
	    ? (unsigned)(s->clusters - unit * NTFS_COMPRESSION_CLUSTERS)
	    : NTFS_COMPRESSION_CLUSTERS;
	for (i = 0; i < count; i += span) {
		vcn = unit * NTFS_COMPRESSION_CLUSTERS + i;
		r = ntfs_run_find(s, vcn);
		if (r == NULL) {
			return NTFS_CORRUPT;
		}
		span = r->length - (vcn - r->vcn) < count - i
		    ? (unsigned)(r->length - (vcn - r->vcn))
		    : count - i;
		if (r->lcn == NTFS_HOLE) {
			hole = true;
			continue;
		}
		if (hole) {
			return NTFS_CORRUPT;
		}
		result = ntfs_io(s->volume, (r->lcn + vcn - r->vcn) * cluster, source + packed,
		    (size_t)span * cluster);
		if (result != NTFS_OK) {
			return result;
		}
		packed += (size_t)span * cluster;
	}
	if (!hole) {
		ntfs_copy(s->compression_buffer, source, packed);
		ntfs_zero(s->compression_buffer + packed, size - packed);
	} else if (packed == 0) {
		ntfs_zero(s->compression_buffer, size);
	} else {
		result = ntfs_lznt1_decode(source, packed, s->compression_buffer, size, &produced);
		if (result != NTFS_OK) {
			return result == NTFS_RANGE ? NTFS_CORRUPT : result;
		}
		needed = s->initialized > start ? s->initialized - start : 0;
		if (needed > size) {
			needed = size;
		}
		if (produced < needed) {
			return NTFS_CORRUPT;
		}
		ntfs_zero(s->compression_buffer + produced, size - produced);
	}
	s->cached_unit = unit;
	return NTFS_OK;
}

enum ntfs_result
ntfs_stream_read(struct ntfs_stream *s, uint64_t offset, void *buffer, size_t length, size_t *done)
{
	uint8_t *bytes = buffer;
	size_t take, unit_size, within;
	uint64_t available;
	enum ntfs_result result;

	if (done == NULL) {
		return NTFS_INVALID;
	}
	*done = 0;
	if (s == NULL || (length != 0 && buffer == NULL)) {
		return NTFS_INVALID;
	}
	if (offset >= s->size) {
		return NTFS_OK;
	}
	if (length > s->size - offset) {
		length = (size_t)(s->size - offset);
	}
	while (length != 0) {
		take = length < NTFS_MAX_IO ? length : NTFS_MAX_IO;
		if (offset >= s->initialized) {
			ntfs_zero(bytes, take);
		} else {
			available = s->initialized - offset;
			if (take > available) {
				take = (size_t)available;
			}
			if (s->resident) {
				ntfs_copy(bytes, s->value + (size_t)offset, take);
			} else if ((s->flags & NTFS_ATTR_COMPRESSED) != 0) {
				unit_size = (size_t)s->volume->info.cluster_size *
				    NTFS_COMPRESSION_CLUSTERS;
				within = (size_t)(offset % unit_size);
				if (take > unit_size - within) {
					take = unit_size - within;
				}
				result = compression_unit(s, offset / unit_size);
				if (result != NTFS_OK) {
					return result;
				}
				ntfs_copy(bytes, s->compression_buffer + within, take);
			} else {
				result = ntfs_stream_raw(s, offset, bytes, take);
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
ntfs_stream_exact(struct ntfs_stream *s, uint64_t offset, void *buffer, size_t size)
{
	size_t done;
	enum ntfs_result result;

	if (!ntfs_bounds(offset, size, s->size)) {
		return NTFS_CORRUPT;
	}
	result = ntfs_stream_read(s, offset, buffer, size, &done);
	return result == NTFS_OK && done != size ? NTFS_IO : result;
}

uint64_t
ntfs_stream_size(const struct ntfs_stream *s)
{
	return s == NULL ? 0 : s->size;
}

void
ntfs_stream_close(struct ntfs_stream *s)
{
	struct ntfs_volume *v;

	if (s == NULL) {
		return;
	}
	v = s->volume;
	if (s->external) {
		v->children--;
	}
	ntfs_free(v, s->value, s->value_allocation);
	ntfs_free(v, s->runs, (size_t)s->run_capacity * sizeof(*s->runs));
	ntfs_free(v, s->compression_buffer,
	    (size_t)v->info.cluster_size * NTFS_COMPRESSION_CLUSTERS * NTFS_COMPRESSION_BUFFERS);
	ntfs_free(v, s, sizeof(*s));
}
