/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include "pointer_range.h"
#include "write_lznt1.h"

enum {
	LZNT1_HASH_BUCKETS = 4096,
	LZNT1_HASH_MULTIPLIER = 251,
	LZNT1_HASH_ENTRY_BYTES = sizeof(uint16_t),
	LZNT1_HASH_BYTES = LZNT1_HASH_BUCKETS * LZNT1_HASH_ENTRY_BYTES,
	LZNT1_WORKSPACE_BYTES = LZNT1_HASH_BYTES + NTFS_LZNT1_CHUNK
};

_Static_assert(NTFS_LZNT1_CHUNK < UINT16_MAX, "chunk positions fit hash entries");
_Static_assert((LZNT1_HASH_BUCKETS & (LZNT1_HASH_BUCKETS - 1)) == 0,
    "hash bucket count is a power of two");

size_t
ntfs_write_lznt1_workspace_size(void)
{
	return LZNT1_WORKSPACE_BYTES;
}

enum ntfs_result
ntfs_write_lznt1_bound(size_t bytes, size_t *bound)
{
	size_t chunks;

	if (!ntfs_pointer_range_valid(bound, sizeof(*bound))) {
		return NTFS_INVALID;
	}
	if (bytes > NTFS_WRITE_LZNT1_MAX_BYTES) {
		return NTFS_RANGE;
	}
	chunks = bytes / NTFS_LZNT1_CHUNK + (bytes % NTFS_LZNT1_CHUNK != 0);
	if (chunks > (SIZE_MAX - bytes) / NTFS_LZNT1_HEADER_BYTES) {
		return NTFS_RANGE;
	}
	*bound = bytes + chunks * NTFS_LZNT1_HEADER_BYTES;
	return NTFS_OK;
}

static enum ntfs_result
lznt1_write_admit(const void *input, size_t bytes, void *workspace, size_t workspace_capacity,
    size_t *written)
{
	if (bytes > NTFS_WRITE_LZNT1_MAX_BYTES) {
		return NTFS_RANGE;
	}
	if (!ntfs_pointer_range_valid(input, bytes) ||
	    !ntfs_pointer_range_valid(workspace, workspace_capacity) ||
	    !ntfs_pointer_range_valid(written, sizeof(*written)) ||
	    !ntfs_pointer_ranges_separate(input, bytes, workspace, workspace_capacity) ||
	    !ntfs_pointer_ranges_separate(input, bytes, written, sizeof(*written)) ||
	    !ntfs_pointer_ranges_separate(workspace, workspace_capacity, written, sizeof(*written))) {
		return NTFS_INVALID;
	}
	if (bytes != 0 && workspace_capacity < LZNT1_WORKSPACE_BYTES) {
		return NTFS_RANGE;
	}
	return NTFS_OK;
}

static size_t
lznt1_write_hash(const uint8_t *bytes)
{
	uint32_t value = bytes[0];

	value = value * LZNT1_HASH_MULTIPLIER + bytes[1];
	value = value * LZNT1_HASH_MULTIPLIER + bytes[2];
	return (value & (LZNT1_HASH_BUCKETS - 1)) * LZNT1_HASH_ENTRY_BYTES;
}

/* Returns a body size strictly below bytes, or bytes for raw fallback. The
 * temporary body never grows beyond its source size or the chunk scratch. */
static size_t
lznt1_write_chunk(const uint8_t *input, size_t bytes, uint8_t *workspace)
{
	uint8_t *body = workspace + LZNT1_HASH_BYTES;
	size_t position = 0, stored = 0, flag_at = 0, hash, previous, length, maximum,
	       displacement = 0, next, index, threshold;
	uint16_t candidate, token, mask;
	unsigned bit = 0, shift;

	ntfs_zero(workspace, LZNT1_HASH_BYTES);
	while (position < bytes) {
		if (bit == 0) {
			if (stored == bytes) {
				return bytes;
			}
			flag_at = stored++;
			body[flag_at] = 0;
		}
		length = 0;
		shift = NTFS_LZNT1_TOKEN_INITIAL_SHIFT;
		mask = NTFS_LZNT1_LENGTH_MASK;
		/* MS-XCA width transitions occur after positions 16, 32, ...,
		 * 2048. Position zero never produces a backward reference. */
		threshold = NTFS_LZNT1_TOKEN_SHIFT_THRESHOLD;
		while (position > threshold) {
			threshold *= 2;
			shift--;
			mask >>= 1;
		}
		maximum = bytes - position;
		if (maximum > (size_t)mask + NTFS_LZNT1_MIN_MATCH) {
			maximum = (size_t)mask + NTFS_LZNT1_MIN_MATCH;
		}
		if (maximum >= NTFS_LZNT1_MIN_MATCH) {
			hash = lznt1_write_hash(input + position);
			candidate = ntfs_u16(workspace + hash);
			if (candidate != 0) {
				previous = candidate - 1u;
				displacement = position - previous;
				/* Stored dictionary positions always precede this one.
				 * The width check makes that invariant explicit on wire. */
				if (displacement <= (size_t)(UINT16_MAX >> shift) + 1) {
					while (length < maximum &&
					    input[previous + length] == input[position + length]) {
						length++;
					}
				}
			}
		}
		if (length >= NTFS_LZNT1_MIN_MATCH) {
			if (bytes - stored <= NTFS_LZNT1_TOKEN_BYTES) {
				return bytes;
			}
			token = (uint16_t)(((displacement - 1) << shift) |
			    (length - NTFS_LZNT1_MIN_MATCH));
			body[flag_at] |= (uint8_t)(1u << bit);
			ntfs_put_u16(body + stored, token);
			stored += NTFS_LZNT1_TOKEN_BYTES;
		} else {
			if (bytes - stored <= 1) {
				return bytes;
			}
			body[stored++] = input[position];
			length = 1;
		}
		next = position + length;
		/* Index each consumed position once. No speculative three-byte
		 * read crosses the end, including the tail of a match. */
		for (index = position; index < next && bytes - index >= NTFS_LZNT1_MIN_MATCH;
		    index++) {
			hash = lznt1_write_hash(input + index);
			ntfs_put_u16(workspace + hash, (uint16_t)(index + 1));
		}
		position = next;
		bit = (bit + 1) % NTFS_BITS_PER_BYTE;
	}
	return stored;
}

static size_t
lznt1_write_walk(const uint8_t *input, size_t bytes, uint8_t *workspace, uint8_t *output)
{
	size_t position = 0, stored = 0, chunk, body;
	uint16_t header;

	while (position < bytes) {
		chunk = bytes - position;
		if (chunk > NTFS_LZNT1_CHUNK) {
			chunk = NTFS_LZNT1_CHUNK;
		}
		body = lznt1_write_chunk(input + position, chunk, workspace);
		if (output != NULL) {
			header = (uint16_t)(NTFS_LZNT1_SIGNATURE | (body - 1));
			if (body < chunk) {
				header |= NTFS_LZNT1_COMPRESSED;
			}
			ntfs_put_u16(output + stored, header);
			ntfs_copy(output + stored + NTFS_LZNT1_HEADER_BYTES,
			    body < chunk ? workspace + LZNT1_HASH_BYTES : input + position, body);
		}
		stored += NTFS_LZNT1_HEADER_BYTES + body;
		position += chunk;
	}
	return stored;
}

enum ntfs_result
ntfs_write_lznt1_measure(const void *input, size_t bytes, void *workspace,
    size_t workspace_capacity, size_t *written)
{
	enum ntfs_result result;
	size_t required;

	result = lznt1_write_admit(input, bytes, workspace, workspace_capacity, written);
	if (result != NTFS_OK) {
		return result;
	}
	required = lznt1_write_walk(input, bytes, workspace, NULL);
	*written = required;
	return NTFS_OK;
}

enum ntfs_result
ntfs_write_lznt1_encode(const void *input, size_t bytes, void *workspace,
    size_t workspace_capacity, void *output, size_t capacity, size_t *written)
{
	enum ntfs_result result;
	size_t required;

	result = lznt1_write_admit(input, bytes, workspace, workspace_capacity, written);
	if (result != NTFS_OK) {
		return result;
	}
	if (!ntfs_pointer_range_valid(output, capacity) ||
	    !ntfs_pointer_ranges_separate(input, bytes, output, capacity) ||
	    !ntfs_pointer_ranges_separate(workspace, workspace_capacity, output, capacity) ||
	    !ntfs_pointer_ranges_separate(output, capacity, written, sizeof(*written))) {
		return NTFS_INVALID;
	}
	required = lznt1_write_walk(input, bytes, workspace, NULL);
	if (capacity < required) {
		return NTFS_RANGE;
	}
	/* Every possible failure precedes publication. The source remains immutable
	 * and the second deterministic walk needs no further resource admission. */
	(void)lznt1_write_walk(input, bytes, workspace, output);
	*written = required;
	return NTFS_OK;
}
