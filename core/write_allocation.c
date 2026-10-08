/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_mutation_internal.h"

bool
ntfs_mutation_bit(const uint8_t *bitmap, size_t bytes, uint64_t bit)
{
	return bit / NTFS_BITS_PER_BYTE < bytes &&
	    (bitmap[bit / NTFS_BITS_PER_BYTE] & (1u << (bit % NTFS_BITS_PER_BYTE))) != 0;
}

void
ntfs_mutation_set_bit(uint8_t *bitmap, uint64_t bit, bool value)
{
	uint8_t mask = (uint8_t)(1u << (bit % NTFS_BITS_PER_BYTE));

	if (value) {
		bitmap[bit / NTFS_BITS_PER_BYTE] |= mask;
	} else {
		bitmap[bit / NTFS_BITS_PER_BYTE] &= (uint8_t)~mask;
	}
}

static enum ntfs_result
mutation_allocation_append_run(
    struct ntfs_run *runs, size_t *count, uint64_t vcn, uint64_t lcn, uint64_t length)
{
	struct ntfs_run *last;

	if (*count != 0) {
		last = &runs[*count - 1u];
		if (last->vcn + last->length == vcn && last->lcn + last->length == lcn) {
			last->length += length;
			return NTFS_OK;
		}
	}
	if (*count == NTFS_MUTATION_MAX_RUNS) {
		return NTFS_RANGE;
	}
	runs[(*count)++] = (struct ntfs_run){vcn, length, lcn};
	return NTFS_OK;
}

enum { MUTATION_BITMAP_WORD_BITS = sizeof(uint64_t) * NTFS_BITS_PER_BYTE };

static uint64_t
mutation_allocation_mask(unsigned bits)
{
	return bits == MUTATION_BITMAP_WORD_BITS ? UINT64_MAX : (UINT64_C(1) << bits) - 1;
}

static uint64_t
mutation_allocation_word(const uint8_t *bytes, size_t size)
{
	uint64_t value = 0;
	size_t index;

	if (size >= sizeof(value)) {
		return ntfs_u64(bytes);
	}
	for (index = 0; index < size; index++) {
		value |= (uint64_t)bytes[index] << (index * NTFS_BITS_PER_BYTE);
	}
	return value;
}

static void
mutation_allocation_put_word(uint8_t *bytes, size_t size, uint64_t value)
{
	size_t index;

	if (size >= sizeof(value)) {
		ntfs_put_u64(bytes, value);
		return;
	}
	for (index = 0; index < size; index++) {
		bytes[index] = (uint8_t)(value >> (index * NTFS_BITS_PER_BYTE));
	}
}

enum ntfs_result
ntfs_mutation_allocate_runs(struct ntfs_write_mutation_plan *plan, uint64_t vcn, uint64_t clusters,
    struct ntfs_run **out, size_t *count)
{
	struct ntfs_mutation_bitmap *bitmap = &plan->allocation;
	struct ntfs_mutation_bitmap_view view = {0};
	struct ntfs_run *runs;
	uint64_t cluster, available, current, shifted, mask;
	size_t byte, bytes, base = 0, within;
	unsigned bits, first, length;
	enum ntfs_result result = NTFS_OK;

	*out = NULL;
	*count = 0;
	if (clusters > plan->info.cluster_count || vcn > UINT64_MAX - clusters) {
		return NTFS_NO_SPACE;
	}
	result = ntfs_mutation_work(plan, plan->info.cluster_count);
	if (result != NTFS_OK) {
		return result;
	}
	runs = ntfs_mutation_allocate(plan, NTFS_MUTATION_MAX_RUNS * sizeof(*runs));
	if (runs == NULL) {
		return NTFS_NO_MEMORY;
	}
	/* Original allocations stay unavailable even after private retirement.
	 * No precommit payload can overwrite storage belonging to the old state. */
	for (cluster = 0; cluster < plan->info.cluster_count && clusters != 0;
	    cluster += MUTATION_BITMAP_WORD_BITS) {
		byte = (size_t)(cluster / NTFS_BITS_PER_BYTE);
		if (ntfs_mutation_bitmap_full(bitmap, byte)) {
			cluster = (byte / NTFS_MUTATION_BITMAP_PAGE_BYTES + 1) *
				NTFS_MUTATION_BITMAP_PAGE_BYTES * NTFS_BITS_PER_BYTE -
			    MUTATION_BITMAP_WORD_BITS;
			continue;
		}
		if (byte - base >= view.bytes) {
			base = byte;
			result = ntfs_mutation_bitmap_view(plan, bitmap, base, false, &view);
			if (result != NTFS_OK) {
				break;
			}
		}
		within = byte - base;
		bytes = view.bytes - within;
		bits = plan->info.cluster_count - cluster < MUTATION_BITMAP_WORD_BITS
		    ? (unsigned)(plan->info.cluster_count - cluster)
		    : MUTATION_BITMAP_WORD_BITS;
		current = mutation_allocation_word(view.after + within, bytes);
		available = ~(mutation_allocation_word(view.before + within, bytes) | current) &
		    mutation_allocation_mask(bits);
		if (available == 0) {
			continue;
		}
		if (view.before == view.after) {
			result = ntfs_mutation_bitmap_view(plan, bitmap, base, true, &view);
			if (result != NTFS_OK) {
				break;
			}
		}
		while (available != 0 && clusters != 0) {
			first = (unsigned)__builtin_ctzll(available);
			shifted = available >> first;
			length = shifted == UINT64_MAX ? MUTATION_BITMAP_WORD_BITS
						       : (unsigned)__builtin_ctzll(~shifted);
			if (length > clusters) {
				length = (unsigned)clusters;
			}
			result = mutation_allocation_append_run(
			    runs, count, vcn, cluster + first, length);
			if (result != NTFS_OK) {
				break;
			}
			mask = mutation_allocation_mask(length) << first;
			current |= mask;
			available &= ~mask;
			vcn += length;
			clusters -= length;
		}
		mutation_allocation_put_word(view.after + within, bytes, current);
		if (result != NTFS_OK) {
			break;
		}
	}
	if (result == NTFS_OK && clusters != 0) {
		result = NTFS_NO_SPACE;
	}
	if (result != NTFS_OK) {
		ntfs_mutation_release(plan, runs, NTFS_MUTATION_MAX_RUNS * sizeof(*runs));
		*count = 0;
		return result;
	}
	*out = runs;
	return NTFS_OK;
}

static enum ntfs_result
mutation_allocation_clear(struct ntfs_write_mutation_plan *plan,
    struct ntfs_mutation_bitmap *bitmap, uint64_t first, uint64_t end)
{
	struct ntfs_mutation_bitmap_view view = {0};
	uint64_t current, mask, missing;
	size_t byte, bytes, base = 0, relative;
	unsigned within, take;
	enum ntfs_result result;

	while (first < end) {
		within = (unsigned)(first % MUTATION_BITMAP_WORD_BITS);
		byte = (size_t)((first - within) / NTFS_BITS_PER_BYTE);
		if (byte >= bitmap->bytes) {
			return NTFS_CORRUPT;
		}
		if (byte - base >= view.bytes) {
			base = byte;
			result = ntfs_mutation_bitmap_view(plan, bitmap, base, true, &view);
			if (result != NTFS_OK) {
				return result;
			}
		}
		relative = byte - base;
		bytes = view.bytes - relative;
		take = MUTATION_BITMAP_WORD_BITS - within;
		if (end - first < take) {
			take = (unsigned)(end - first);
		}
		current = mutation_allocation_word(view.after + relative, bytes);
		mask = mutation_allocation_mask(take) << within;
		missing = mask & ~current;
		/* Preserve the bitwise failure state: clear exactly the allocated
		 * prefix preceding the first missing bit, even in a partial word. */
		if (missing != 0) {
			mask &= mutation_allocation_mask((unsigned)__builtin_ctzll(missing));
		}
		mutation_allocation_put_word(view.after + relative, bytes, current & ~mask);
		if (missing != 0) {
			return NTFS_CORRUPT;
		}
		first += take;
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_mutation_free_runs(
    struct ntfs_write_mutation_plan *plan, const struct ntfs_stream *stream, uint64_t retain)
{
	const struct ntfs_run *run;
	uint64_t first;
	size_t index;
	enum ntfs_result result;

	if (stream->resident) {
		return NTFS_OK;
	}
	result = ntfs_mutation_work(plan, stream->clusters);
	if (result != NTFS_OK) {
		return result;
	}
	for (index = 0; index < stream->run_count; index++) {
		run = &stream->runs[index];
		if (run->lcn == NTFS_HOLE ||
		    !ntfs_bounds(run->lcn, run->length, plan->info.cluster_count)) {
			return NTFS_CORRUPT;
		}
		first = retain > run->vcn ? retain - run->vcn : 0;
		if (first >= run->length) {
			continue;
		}
		result = mutation_allocation_clear(
		    plan, &plan->allocation, run->lcn + first, run->lcn + run->length);
		if (result != NTFS_OK) {
			return result;
		}
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_mutation_resize_runs(struct ntfs_write_mutation_plan *plan, const struct ntfs_stream *stream,
    uint64_t clusters, struct ntfs_run **out, size_t *count)
{
	struct ntfs_run *runs, *added = NULL;
	uint64_t take, current = 0;
	size_t index, additions = 0;
	enum ntfs_result result = NTFS_OK;

	*out = NULL;
	*count = 0;
	runs = ntfs_mutation_allocate(plan, NTFS_MUTATION_MAX_RUNS * sizeof(*runs));
	if (runs == NULL) {
		return NTFS_NO_MEMORY;
	}
	if (!stream->resident) {
		for (index = 0; index < stream->run_count && current < clusters; index++) {
			take = stream->runs[index].length;
			if (take > clusters - current) {
				take = clusters - current;
			}
			result = mutation_allocation_append_run(
			    runs, count, current, stream->runs[index].lcn, take);
			if (result != NTFS_OK) {
				goto done;
			}
			current += take;
		}
	}
	if (current < clusters) {
		result = ntfs_mutation_allocate_runs(
		    plan, current, clusters - current, &added, &additions);
		if (result != NTFS_OK) {
			goto done;
		}
		for (index = 0; index < additions; index++) {
			result = mutation_allocation_append_run(
			    runs, count, added[index].vcn, added[index].lcn, added[index].length);
			if (result != NTFS_OK) {
				goto done;
			}
		}
	}
	result = ntfs_mutation_free_runs(plan, stream, clusters);

done:
	ntfs_mutation_release(plan, added, NTFS_MUTATION_MAX_RUNS * sizeof(*added));
	if (result != NTFS_OK) {
		ntfs_mutation_release(plan, runs, NTFS_MUTATION_MAX_RUNS * sizeof(*runs));
		*count = 0;
		return result;
	}
	*out = runs;
	return NTFS_OK;
}

static enum ntfs_result
mutation_allocation_grow_mft(struct ntfs_write_mutation_plan *plan)
{
	struct ntfs_mutation_record *record, *mft;
	struct ntfs_stream *stream = NULL;
	struct ntfs_run *runs = NULL;
	uint64_t initialized, clusters, first, number;
	size_t count = 0, bitmap_bytes;
	enum ntfs_result result;

	initialized = plan->mft->initialized;
	if (initialized % NTFS_WRITE_CLUSTER_BYTES != 0 ||
	    initialized >
		(uint64_t)UINT32_MAX * NTFS_WRITE_RECORD_BYTES - NTFS_WRITE_CLUSTER_BYTES) {
		return NTFS_UNSUPPORTED;
	}
	initialized += NTFS_WRITE_CLUSTER_BYTES;
	clusters = plan->mft->clusters;
	if (clusters < initialized / NTFS_WRITE_CLUSTER_BYTES) {
		clusters = initialized / NTFS_WRITE_CLUSTER_BYTES;
	}
	bitmap_bytes = (size_t)((initialized / NTFS_WRITE_RECORD_BYTES + NTFS_BITS_PER_BYTE - 1u) /
	    NTFS_BITS_PER_BYTE);
	bitmap_bytes =
	    (bitmap_bytes + NTFS_WIRE_ALIGNMENT - 1u) & ~(size_t)(NTFS_WIRE_ALIGNMENT - 1u);
	result = ntfs_mutation_bitmap_grow(plan, &plan->mft_bitmap, bitmap_bytes);
	if (result != NTFS_OK) {
		goto done;
	}
	result = ntfs_mutation_resize_runs(plan, plan->mft, clusters, &runs, &count);
	if (result != NTFS_OK) {
		goto done;
	}
	result = ntfs_mutation_record_get(plan, NTFS_MFT_RECORD, true, &mft);
	if (result != NTFS_OK) {
		goto done;
	}
	result = ntfs_mutation_nonresident(plan, mft, NTFS_ATTRIBUTE_DATA, NULL, 0, runs, count,
	    plan->mft->size > initialized ? plan->mft->size : initialized, initialized, 0);
	if (result == NTFS_OK) {
		result = ntfs_mutation_stream(plan, mft, NTFS_ATTRIBUTE_DATA, NULL, 0, &stream);
	}
done:
	ntfs_mutation_release(plan, runs, NTFS_MUTATION_MAX_RUNS * sizeof(*runs));
	if (result != NTFS_OK) {
		ntfs_stream_close(stream);
		return result;
	}
	first = plan->mft->initialized / NTFS_WRITE_RECORD_BYTES;
	ntfs_stream_close(plan->mft);
	plan->mft = stream;
	for (number = first; number < initialized / NTFS_WRITE_RECORD_BYTES; number++) {
		result = ntfs_mutation_record_get(plan, number, true, &record);
		if (result != NTFS_OK) {
			return result;
		}
	}
	return NTFS_OK;
}

static enum ntfs_result
mutation_allocation_first_record(struct ntfs_write_mutation_plan *plan,
    struct ntfs_mutation_bitmap *bitmap, uint64_t records, uint64_t *out)
{
	struct ntfs_mutation_bitmap_view view;
	uint64_t number, available, limit;
	size_t byte, bytes, within;
	unsigned bits, first = NTFS_MUTATION_FIRST_ALLOCATABLE_RECORD;
	enum ntfs_result result;

	*out = records;
	if (records <= first) {
		return NTFS_OK;
	}
	for (byte = 0; byte < bitmap->bytes && byte * NTFS_BITS_PER_BYTE < records;
	    byte += view.bytes) {
		if (ntfs_mutation_bitmap_full(bitmap, byte)) {
			view.bytes = NTFS_MUTATION_BITMAP_PAGE_BYTES;
			first = 0;
			continue;
		}
		result = ntfs_mutation_bitmap_view(plan, bitmap, byte, false, &view);
		if (result != NTFS_OK) {
			return result;
		}
		limit = records - byte * NTFS_BITS_PER_BYTE;
		if (limit > view.bytes * NTFS_BITS_PER_BYTE) {
			limit = view.bytes * NTFS_BITS_PER_BYTE;
		}
		for (number = 0; number < limit; number += MUTATION_BITMAP_WORD_BITS) {
			within = (size_t)(number / NTFS_BITS_PER_BYTE);
			bytes = view.bytes - within;
			bits = limit - number < MUTATION_BITMAP_WORD_BITS
			    ? (unsigned)(limit - number)
			    : MUTATION_BITMAP_WORD_BITS;
			available = ~(mutation_allocation_word(view.before + within, bytes) |
					mutation_allocation_word(view.after + within, bytes)) &
			    mutation_allocation_mask(bits) & ~mutation_allocation_mask(first);
			if (available != 0) {
				*out = byte * NTFS_BITS_PER_BYTE + number +
				    (unsigned)__builtin_ctzll(available);
				return NTFS_OK;
			}
			first = 0;
		}
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_mutation_new_record(struct ntfs_write_mutation_plan *plan, struct ntfs_mutation_record **out)
{
	struct ntfs_mutation_bitmap_view view;
	uint64_t number, records;
	enum ntfs_result result;

	*out = NULL;
	for (;;) {
		records = plan->mft->initialized / NTFS_WRITE_RECORD_BYTES;
		result = ntfs_mutation_work(plan, records);
		if (result != NTFS_OK) {
			return result;
		}
		result =
		    mutation_allocation_first_record(plan, &plan->mft_bitmap, records, &number);
		if (result != NTFS_OK) {
			return result;
		}
		if (number < records) {
			/* Reserve the writable page before publishing an allocated record. */
			result = ntfs_mutation_bitmap_view(plan, &plan->mft_bitmap,
			    (size_t)(number / NTFS_BITS_PER_BYTE), true, &view);
			if (result != NTFS_OK) {
				return result;
			}
			result = ntfs_mutation_record_get(plan, number, true, out);
			if (result == NTFS_OK) {
				ntfs_mutation_set_bit(
				    view.after, number % NTFS_BITS_PER_BYTE, true);
			}
			return result;
		}
		result = mutation_allocation_grow_mft(plan);
		if (result != NTFS_OK) {
			return result;
		}
	}
}
