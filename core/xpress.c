/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include <ntfs/wof.h>

/* An eight-bit prefix cache avoids a 64-KiB expanded tree. Longer codes use
 * canonical buckets; all scratch belongs to the caller, not the C stack. */
enum { XPRESS_PREFIX_BITS = 8, XPRESS_PREFIX_ENTRIES = 1u << XPRESS_PREFIX_BITS };

struct ntfs_xpress_workspace {
	uint32_t first[NTFS_XPRESS_MAX_CODE_BITS + 1];
	uint16_t count[NTFS_XPRESS_MAX_CODE_BITS + 1];
	uint16_t base[NTFS_XPRESS_MAX_CODE_BITS + 1];
	uint16_t symbols[NTFS_XPRESS_SYMBOLS];
	uint16_t prefix[XPRESS_PREFIX_ENTRIES];
};

struct ntfs_xpress_reader {
	const uint8_t *bytes;
	size_t size, position;
	uint32_t value;
	unsigned valid;
};

size_t
ntfs_xpress_workspace_size(void)
{
	return sizeof(struct ntfs_xpress_workspace);
}

size_t
ntfs_xpress_workspace_alignment(void)
{
	return _Alignof(struct ntfs_xpress_workspace);
}

static unsigned
xpress_symbol_length(const struct ntfs_disk_xpress *header, unsigned symbol)
{
	return (header->lengths[symbol / NTFS_XPRESS_LENGTHS_PER_BYTE] >>
		   ((symbol % NTFS_XPRESS_LENGTHS_PER_BYTE) * NTFS_XPRESS_LENGTH_BITS)) &
	    ((1u << NTFS_XPRESS_LENGTH_BITS) - 1);
}

static enum ntfs_result
xpress_build_tree(const struct ntfs_disk_xpress *header, struct ntfs_xpress_workspace *tree)
{
	uint16_t next[NTFS_XPRESS_MAX_CODE_BITS + 1];
	uint32_t slots = 1, code = 0;
	unsigned bits, symbol, used = 0, prefix, repeats, i;

	/* Every used symbol and prefix is overwritten below. Only counts carry
	 * incremental state, so do not clear the entire caller workspace twice. */
	ntfs_zero(tree->count, sizeof(tree->count));
	for (symbol = 0; symbol < NTFS_XPRESS_SYMBOLS; symbol++) {
		bits = xpress_symbol_length(header, symbol);
		if (bits != 0) {
			tree->count[bits]++;
		}
	}
	for (bits = 1; bits <= NTFS_XPRESS_MAX_CODE_BITS; bits++) {
		slots <<= 1;
		if (tree->count[bits] > slots) {
			return NTFS_CORRUPT;
		}
		slots -= tree->count[bits];
		code = (code + tree->count[bits - 1]) << 1;
		tree->first[bits] = code;
		tree->base[bits] = (uint16_t)used;
		next[bits] = (uint16_t)used;
		used += tree->count[bits];
	}
	if (slots != 0) {
		return NTFS_CORRUPT;
	}
	for (symbol = 0; symbol < NTFS_XPRESS_SYMBOLS; symbol++) {
		bits = xpress_symbol_length(header, symbol);
		if (bits != 0) {
			tree->symbols[next[bits]++] = (uint16_t)symbol;
		}
	}
	prefix = 0;
	for (bits = 1; bits <= XPRESS_PREFIX_BITS; bits++) {
		repeats = 1u << (XPRESS_PREFIX_BITS - bits);
		for (i = 0; i < tree->count[bits]; i++) {
			for (symbol = 0; symbol < repeats; symbol++) {
				tree->prefix[prefix++] =
				    (uint16_t)((bits << NTFS_XPRESS_SYMBOL_BITS) |
					tree->symbols[tree->base[bits] + i]);
			}
		}
	}
	/* Canonical short codes fill one contiguous prefix; only the tail needs
	 * the long-code marker. Completeness was checked before any table writes. */
	while (prefix < XPRESS_PREFIX_ENTRIES) {
		tree->prefix[prefix++] = UINT16_MAX;
	}
	return NTFS_OK;
}

static enum ntfs_result
xpress_take_bits(struct ntfs_xpress_reader *reader, unsigned bits, uint32_t *out)
{
	*out = 0;
	if (bits == 0) {
		return NTFS_OK;
	}
	*out = reader->value >> (NTFS_XPRESS_RESERVOIR_BITS - bits);
	reader->value <<= bits;
	reader->valid -= bits;
	if (reader->valid < NTFS_XPRESS_WORD_BITS) {
		if (reader->size - reader->position < NTFS_XPRESS_WORD_BYTES) {
			return NTFS_CORRUPT;
		}
		reader->value |= (uint32_t)ntfs_u16(reader->bytes + reader->position)
		    << (NTFS_XPRESS_RESERVOIR_BITS - NTFS_XPRESS_WORD_BITS - reader->valid);
		reader->position += NTFS_XPRESS_WORD_BYTES;
		reader->valid += NTFS_XPRESS_WORD_BITS;
	}
	return NTFS_OK;
}

/* A fixed split of the six widths after the usual nine-bit code avoids
 * carrying loop bounds across the overwhelmingly common prefix/9-bit path. */
_Static_assert(NTFS_XPRESS_MAX_CODE_BITS == XPRESS_PREFIX_BITS + 7,
    "fixed canonical search covers the remaining six widths");

static inline bool
xpress_before_bucket_end(const struct ntfs_xpress_workspace *tree, uint32_t code, unsigned bits)
{
	return code <
	    ((tree->first[bits] + tree->count[bits]) << (NTFS_XPRESS_MAX_CODE_BITS - bits));
}

static enum ntfs_result
xpress_take_symbol(
    struct ntfs_xpress_reader *reader, const struct ntfs_xpress_workspace *tree, unsigned *out)
{
	uint16_t entry;
	uint32_t code, offset, ignored;
	unsigned bits;

	entry = tree->prefix[reader->value >> (NTFS_XPRESS_RESERVOIR_BITS - XPRESS_PREFIX_BITS)];
	if (entry != UINT16_MAX) {
		*out = entry & (NTFS_XPRESS_SYMBOLS - 1);
		return xpress_take_bits(reader, entry >> NTFS_XPRESS_SYMBOL_BITS, &ignored);
	}
	/* The reservoir already holds at least one word. A prefix miss rules out
	 * all shorter codes; inspect the remaining buckets without consuming bits.
	 * One final take preserves the mandatory post-consumption refill, including
	 * its position relative to raw match-length extension bytes. */
	bits = XPRESS_PREFIX_BITS + 1;
	code = reader->value >> (NTFS_XPRESS_RESERVOIR_BITS - bits);
	offset = code - tree->first[bits];
	if (offset >= tree->count[bits]) {
		/* Normalized canonical bucket ends are monotone. Every table
		 * index here is constant and below the validated maximum width. */
		code = reader->value >> (NTFS_XPRESS_RESERVOIR_BITS - NTFS_XPRESS_MAX_CODE_BITS);
		if (xpress_before_bucket_end(tree, code, XPRESS_PREFIX_BITS + 4)) {
			if (xpress_before_bucket_end(tree, code, XPRESS_PREFIX_BITS + 3)) {
				bits = xpress_before_bucket_end(tree, code, XPRESS_PREFIX_BITS + 2)
				    ? XPRESS_PREFIX_BITS + 2
				    : XPRESS_PREFIX_BITS + 3;
			} else {
				bits = XPRESS_PREFIX_BITS + 4;
			}
		} else if (xpress_before_bucket_end(tree, code, XPRESS_PREFIX_BITS + 6)) {
			bits = xpress_before_bucket_end(tree, code, XPRESS_PREFIX_BITS + 5)
			    ? XPRESS_PREFIX_BITS + 5
			    : XPRESS_PREFIX_BITS + 6;
		} else {
			bits = NTFS_XPRESS_MAX_CODE_BITS;
		}
		code = reader->value >> (NTFS_XPRESS_RESERVOIR_BITS - bits);
		offset = code - tree->first[bits];
		if (offset >= tree->count[bits]) {
			return NTFS_CORRUPT;
		}
	}
	*out = tree->symbols[tree->base[bits] + offset];
	return xpress_take_bits(reader, bits, &ignored);
}

static enum ntfs_result
xpress_match_length(struct ntfs_xpress_reader *reader, unsigned code, uint32_t *length)
{
	uint32_t extra;

	*length = code + NTFS_XPRESS_MIN_MATCH;
	if (code != NTFS_XPRESS_LONG_LENGTH) {
		return NTFS_OK;
	}
	if (reader->position == reader->size) {
		return NTFS_CORRUPT;
	}
	extra = reader->bytes[reader->position++];
	if (extra != NTFS_XPRESS_LENGTH_ESCAPE) {
		*length += extra;
		return NTFS_OK;
	}
	if (reader->size - reader->position < sizeof(uint16_t)) {
		return NTFS_CORRUPT;
	}
	extra = ntfs_u16(reader->bytes + reader->position);
	reader->position += sizeof(uint16_t);
	/* A zero word introduces a >=64-KiB length in the encoding grammar.
	 * Such a match cannot fit this single block after its required prefix. */
	if (extra < NTFS_XPRESS_LONG_LENGTH) {
		return NTFS_CORRUPT;
	}
	*length = extra + NTFS_XPRESS_MIN_MATCH;
	return NTFS_OK;
}

enum ntfs_result
ntfs_xpress_huffman_decode(const void *input, size_t size, void *output, size_t expected,
    void *workspace, size_t workspace_size, size_t *written)
{
	const uint8_t *src = input;
	uint8_t *dst = output;
	struct ntfs_xpress_workspace *tree = workspace;
	struct ntfs_xpress_reader reader;
	size_t position = 0;
	uint32_t distance, low, length;
	unsigned symbol, distance_bits;
	enum ntfs_result result;

	if (written == NULL) {
		return NTFS_INVALID;
	}
	*written = 0;
	if ((size != 0 && input == NULL) || (expected != 0 && output == NULL) ||
	    workspace == NULL ||
	    (uintptr_t)workspace % _Alignof(struct ntfs_xpress_workspace) != 0) {
		return NTFS_INVALID;
	}
	if (expected > NTFS_XPRESS_MAX_BLOCK || workspace_size < sizeof(*tree)) {
		return NTFS_RANGE;
	}
	if (size < sizeof(struct ntfs_disk_xpress) +
		NTFS_XPRESS_LOOKAHEAD_WORDS * NTFS_XPRESS_WORD_BYTES) {
		return NTFS_CORRUPT;
	}
	result = xpress_build_tree(input, tree);
	if (result != NTFS_OK) {
		return result;
	}
	reader.bytes = src;
	reader.size = size;
	reader.position = sizeof(struct ntfs_disk_xpress);
	reader.value = (uint32_t)ntfs_u16(src + reader.position) << NTFS_XPRESS_WORD_BITS;
	reader.position += NTFS_XPRESS_WORD_BYTES;
	reader.value |= ntfs_u16(src + reader.position);
	reader.position += NTFS_XPRESS_WORD_BYTES;
	reader.valid = NTFS_XPRESS_RESERVOIR_BITS;
	while (position < expected) {
		result = xpress_take_symbol(&reader, tree, &symbol);
		if (result != NTFS_OK) {
			return result;
		}
		if (symbol < NTFS_XPRESS_LITERAL_SYMBOLS) {
			dst[position++] = (uint8_t)symbol;
			continue;
		}
		symbol -= NTFS_XPRESS_LITERAL_SYMBOLS;
		result =
		    xpress_match_length(&reader, symbol & NTFS_XPRESS_MATCH_LENGTH_MASK, &length);
		if (result != NTFS_OK) {
			return result;
		}
		distance_bits = symbol >> NTFS_XPRESS_MATCH_LENGTH_BITS;
		result = xpress_take_bits(&reader, distance_bits, &low);
		if (result != NTFS_OK) {
			return result;
		}
		distance = (1u << distance_bits) + low;
		if (distance > position || length > expected - position) {
			return NTFS_CORRUPT;
		}
		ntfs_lz_copy(dst + position, distance, length);
		position += length;
	}
	/* An EOF symbol is optional if the final words have already been consumed.
	 * Otherwise one EOF must exhaust the input. Lookahead/padding bits are not
	 * required to be zero by the decoder contract. */
	if (reader.position != size) {
		result = xpress_take_symbol(&reader, tree, &symbol);
		if (result != NTFS_OK || symbol != NTFS_XPRESS_END_SYMBOL ||
		    reader.position != size) {
			return NTFS_CORRUPT;
		}
	}
	*written = expected;
	return NTFS_OK;
}
