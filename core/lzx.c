/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include <ntfs/wof.h>

/* Small canonical buckets with an eight-bit shortcut. Complete alphabets and
 * prior block lengths live in caller scratch, keeping kernel-sized frames. */
enum { LZX_PREFIX_BITS = 8, LZX_PREFIX_ENTRIES = 1u << LZX_PREFIX_BITS, LZX_SYMBOL_BITS = 9 };

struct ntfs_lzx_tree {
	uint32_t first[NTFS_LZX_MAX_CODE_BITS + 1];
	uint16_t count[NTFS_LZX_MAX_CODE_BITS + 1], base[NTFS_LZX_MAX_CODE_BITS + 1];
	uint16_t prefix[LZX_PREFIX_ENTRIES], used;
};

struct ntfs_lzx_workspace {
	struct ntfs_lzx_tree main, length, pre, aligned;
	uint16_t main_symbols[NTFS_LZX_MAIN_SYMBOLS], length_symbols[NTFS_LZX_LENGTH_SYMBOLS];
	uint16_t pre_symbols[NTFS_LZX_PRETREE_SYMBOLS], aligned_symbols[NTFS_LZX_ALIGNED_SYMBOLS];
	uint8_t main_lengths[NTFS_LZX_MAIN_SYMBOLS], length_lengths[NTFS_LZX_LENGTH_SYMBOLS];
	uint8_t pre_lengths[NTFS_LZX_PRETREE_SYMBOLS], aligned_lengths[NTFS_LZX_ALIGNED_SYMBOLS];
	uint32_t repeated[NTFS_LZX_REPEATED_OFFSETS];
};

struct ntfs_lzx_reader {
	const uint8_t *bytes;
	size_t size, position;
	uint32_t value;
	unsigned valid;
};

size_t
ntfs_lzx_workspace_size(void)
{
	return sizeof(struct ntfs_lzx_workspace);
}

size_t
ntfs_lzx_workspace_alignment(void)
{
	return _Alignof(struct ntfs_lzx_workspace);
}

static enum ntfs_result
lzx_take_bits(struct ntfs_lzx_reader *reader, unsigned bits, uint32_t *out)
{
	unsigned take;
	uint32_t value = 0;

	while (bits != 0) {
		if (reader->valid == 0) {
			if (reader->size - reader->position < NTFS_LZX_WORD_BYTES) {
				return NTFS_CORRUPT;
			}
			reader->value = ntfs_u16(reader->bytes + reader->position);
			reader->position += NTFS_LZX_WORD_BYTES;
			reader->valid = NTFS_LZX_WORD_BITS;
		}
		take = bits < reader->valid ? bits : reader->valid;
		value = (value << take) |
		    ((reader->value >> (reader->valid - take)) & ((1u << take) - 1));
		reader->valid -= take;
		bits -= take;
	}
	*out = value;
	return NTFS_OK;
}

static enum ntfs_result
lzx_build_tree(struct ntfs_lzx_tree *tree, const uint8_t *lengths, unsigned count, unsigned maximum,
    uint16_t *symbols)
{
	uint16_t next[NTFS_LZX_MAX_CODE_BITS + 1];
	uint32_t slots = 1, code = 0;
	unsigned symbol, bits, used = 0, prefix, repeats, index;

	ntfs_zero(tree, sizeof(*tree));
	for (symbol = 0; symbol < count; symbol++) {
		bits = lengths[symbol];
		if (bits > maximum) {
			return NTFS_CORRUPT;
		}
		if (bits != 0) {
			tree->count[bits]++;
		}
	}
	for (bits = 1; bits <= NTFS_LZX_MAX_CODE_BITS; bits++) {
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
	if (used != 0 && slots != 0) {
		return NTFS_CORRUPT;
	}
	tree->used = (uint16_t)used;
	for (symbol = 0; symbol < count; symbol++) {
		bits = lengths[symbol];
		if (bits != 0) {
			symbols[next[bits]++] = (uint16_t)symbol;
		}
	}
	for (prefix = 0; prefix < LZX_PREFIX_ENTRIES; prefix++) {
		tree->prefix[prefix] = UINT16_MAX;
	}
	for (bits = 1; bits <= LZX_PREFIX_BITS; bits++) {
		repeats = 1u << (LZX_PREFIX_BITS - bits);
		for (index = 0; index < tree->count[bits]; index++) {
			prefix = (tree->first[bits] + index) << (LZX_PREFIX_BITS - bits);
			for (symbol = 0; symbol < repeats; symbol++) {
				tree->prefix[prefix + symbol] =
				    (uint16_t)((bits << LZX_SYMBOL_BITS) |
					symbols[tree->base[bits] + index]);
			}
		}
	}
	return NTFS_OK;
}

static enum ntfs_result
lzx_take_symbol(struct ntfs_lzx_reader *reader, const struct ntfs_lzx_tree *tree,
    const uint16_t *symbols, unsigned *out)
{
	uint16_t entry;
	uint32_t code = 0, bit, ignored;
	unsigned bits;
	enum ntfs_result result;

	if (tree->used == 0) {
		return NTFS_CORRUPT;
	}
	if (reader->valid >= LZX_PREFIX_BITS) {
		entry = tree->prefix[(reader->value >> (reader->valid - LZX_PREFIX_BITS)) &
		    (LZX_PREFIX_ENTRIES - 1)];
		if (entry != UINT16_MAX) {
			*out = entry & ((1u << LZX_SYMBOL_BITS) - 1);
			return lzx_take_bits(reader, entry >> LZX_SYMBOL_BITS, &ignored);
		}
	}
	for (bits = 1; bits <= NTFS_LZX_MAX_CODE_BITS; bits++) {
		result = lzx_take_bits(reader, 1, &bit);
		if (result != NTFS_OK) {
			return result;
		}
		code = (code << 1) | bit;
		if (code >= tree->first[bits] && code - tree->first[bits] < tree->count[bits]) {
			*out = symbols[tree->base[bits] + code - tree->first[bits]];
			return NTFS_OK;
		}
	}
	return NTFS_CORRUPT;
}

static enum ntfs_result
lzx_read_lengths(struct ntfs_lzx_reader *reader, struct ntfs_lzx_workspace *work, uint8_t *lengths,
    unsigned count)
{
	uint32_t value, extra;
	unsigned index, symbol, repeat, length;
	enum ntfs_result result;

	for (index = 0; index < NTFS_LZX_PRETREE_SYMBOLS; index++) {
		result = lzx_take_bits(reader, NTFS_LZX_PRETREE_LENGTH_BITS, &value);
		if (result != NTFS_OK) {
			return result;
		}
		work->pre_lengths[index] = (uint8_t)value;
	}
	result = lzx_build_tree(&work->pre, work->pre_lengths, NTFS_LZX_PRETREE_SYMBOLS,
	    NTFS_LZX_PRETREE_MAX_BITS, work->pre_symbols);
	if (result != NTFS_OK) {
		return result;
	}
	index = 0;
	while (index < count) {
		result = lzx_take_symbol(reader, &work->pre, work->pre_symbols, &symbol);
		if (result != NTFS_OK) {
			return result;
		}
		repeat = 1;
		if (symbol == NTFS_LZX_ZERO_SHORT || symbol == NTFS_LZX_ZERO_LONG) {
			result = lzx_take_bits(reader,
			    symbol == NTFS_LZX_ZERO_SHORT ? NTFS_LZX_ZERO_SHORT_BITS
							  : NTFS_LZX_ZERO_LONG_BITS,
			    &extra);
			if (result != NTFS_OK) {
				return result;
			}
			length = 0;
			repeat = extra +
			    (symbol == NTFS_LZX_ZERO_SHORT ? NTFS_LZX_ZERO_SHORT_BASE
							   : NTFS_LZX_ZERO_LONG_BASE);
		} else {
			if (symbol == NTFS_LZX_REPEAT_LENGTH) {
				result = lzx_take_bits(reader, NTFS_LZX_REPEAT_LENGTH_BITS, &extra);
				if (result != NTFS_OK) {
					return result;
				}
				repeat = extra + NTFS_LZX_REPEAT_LENGTH_BASE;
				result =
				    lzx_take_symbol(reader, &work->pre, work->pre_symbols, &symbol);
				if (result != NTFS_OK) {
					return result;
				}
				if (symbol >= NTFS_LZX_LENGTH_MODULUS) {
					return NTFS_CORRUPT;
				}
			}
			length = (lengths[index] + NTFS_LZX_LENGTH_MODULUS - symbol) %
			    NTFS_LZX_LENGTH_MODULUS;
		}
		if (result != NTFS_OK) {
			return result;
		}
		if (repeat > count - index) {
			return NTFS_CORRUPT;
		}
		while (repeat-- != 0) {
			lengths[index++] = (uint8_t)length;
		}
	}
	return NTFS_OK;
}

static enum ntfs_result
lzx_read_trees(struct ntfs_lzx_reader *reader, struct ntfs_lzx_workspace *work, unsigned type)
{
	uint32_t value;
	unsigned index;
	enum ntfs_result result;

	if (type == NTFS_LZX_ALIGNED) {
		for (index = 0; index < NTFS_LZX_ALIGNED_SYMBOLS; index++) {
			result = lzx_take_bits(reader, NTFS_LZX_ALIGNED_LENGTH_BITS, &value);
			if (result != NTFS_OK) {
				return result;
			}
			work->aligned_lengths[index] = (uint8_t)value;
		}
		result = lzx_build_tree(&work->aligned, work->aligned_lengths,
		    NTFS_LZX_ALIGNED_SYMBOLS, NTFS_LZX_ALIGNED_MAX_BITS, work->aligned_symbols);
		if (result != NTFS_OK) {
			return result;
		}
	}
	result = lzx_read_lengths(reader, work, work->main_lengths, NTFS_LZX_LITERAL_SYMBOLS);
	if (result == NTFS_OK) {
		result =
		    lzx_read_lengths(reader, work, work->main_lengths + NTFS_LZX_LITERAL_SYMBOLS,
			NTFS_LZX_MAIN_SYMBOLS - NTFS_LZX_LITERAL_SYMBOLS);
	}
	if (result == NTFS_OK) {
		result =
		    lzx_read_lengths(reader, work, work->length_lengths, NTFS_LZX_LENGTH_SYMBOLS);
	}
	if (result == NTFS_OK) {
		result = lzx_build_tree(&work->main, work->main_lengths, NTFS_LZX_MAIN_SYMBOLS,
		    NTFS_LZX_MAX_CODE_BITS, work->main_symbols);
	}
	if (result == NTFS_OK) {
		result = lzx_build_tree(&work->length, work->length_lengths,
		    NTFS_LZX_LENGTH_SYMBOLS, NTFS_LZX_MAX_CODE_BITS, work->length_symbols);
	}
	return result;
}

static enum ntfs_result
lzx_match_offset(struct ntfs_lzx_reader *reader, struct ntfs_lzx_workspace *work, unsigned type,
    unsigned slot, uint32_t *distance)
{
	unsigned bits, low;
	uint32_t extra, saved;
	enum ntfs_result result;

	if (slot < NTFS_LZX_REPEATED_OFFSETS) {
		*distance = work->repeated[slot];
		work->repeated[slot] = work->repeated[0];
		work->repeated[0] = *distance;
		return NTFS_OK;
	}
	bits = slot < NTFS_LZX_REPEATED_OFFSETS + 1 ? 0 : slot / 2 - 1;
	*distance = slot == NTFS_LZX_REPEATED_OFFSETS
	    ? NTFS_LZX_INITIAL_OFFSET
	    : ((2u + (slot & 1u)) << bits) - NTFS_LZX_OFFSET_BIAS;
	if (type == NTFS_LZX_ALIGNED && bits >= NTFS_LZX_ALIGNED_BITS) {
		result = lzx_take_bits(reader, bits - NTFS_LZX_ALIGNED_BITS, &extra);
		if (result != NTFS_OK) {
			return result;
		}
		result = lzx_take_symbol(reader, &work->aligned, work->aligned_symbols, &low);
		if (result != NTFS_OK) {
			return result;
		}
		extra = (extra << NTFS_LZX_ALIGNED_BITS) | low;
	} else {
		result = lzx_take_bits(reader, bits, &extra);
	}
	if (result != NTFS_OK) {
		return result;
	}
	*distance += extra;
	saved = work->repeated[1];
	work->repeated[1] = work->repeated[0];
	work->repeated[2] = saved;
	work->repeated[0] = *distance;
	return NTFS_OK;
}

static enum ntfs_result
lzx_raw_block(
    struct ntfs_lzx_reader *reader, struct ntfs_lzx_workspace *work, uint8_t *output, size_t size)
{
	const struct ntfs_disk_lzx_offsets *offsets;
	uint32_t ignored;
	unsigned index;
	enum ntfs_result result;

	/* Even an already aligned header carries a full padding word. */
	result = lzx_take_bits(
	    reader, reader->valid == 0 ? NTFS_LZX_WORD_BITS : reader->valid, &ignored);
	if (result != NTFS_OK || reader->size - reader->position < sizeof(*offsets)) {
		return NTFS_CORRUPT;
	}
	offsets = (const void *)(reader->bytes + reader->position);
	reader->position += sizeof(*offsets);
	for (index = 0; index < NTFS_LZX_REPEATED_OFFSETS; index++) {
		work->repeated[index] = ntfs_u32(offsets->repeated[index]);
	}
	if (size > reader->size - reader->position) {
		return NTFS_CORRUPT;
	}
	ntfs_copy(output, reader->bytes + reader->position, size);
	reader->position += size;
	if (size % NTFS_LZX_WORD_BYTES != 0) {
		if (reader->position == reader->size) {
			return NTFS_CORRUPT;
		}
		reader->position++;
	}
	return NTFS_OK;
}

static void
lzx_inverse_calls(uint8_t *output, size_t size)
{
	size_t index = 0, byte;
	uint32_t word;
	int64_t value;

	if (size <= NTFS_LZX_E8_TAIL_BYTES) {
		return;
	}
	while (index < size - NTFS_LZX_E8_TAIL_BYTES) {
		index += ntfs_find_byte(
		    output + index, size - NTFS_LZX_E8_TAIL_BYTES - index, NTFS_LZX_E8_OPCODE);
		if (index == size - NTFS_LZX_E8_TAIL_BYTES) {
			break;
		}
		index++;
		word = ntfs_u32(output + index);
		value = word;
		if (word > INT32_MAX) {
			value -= (int64_t)UINT32_MAX + 1;
		}
		if (value >= -(int64_t)(index - 1) && value < NTFS_LZX_E8_TRANSLATION_SIZE) {
			value = value >= 0 ? value - (int64_t)(index - 1)
					   : value + NTFS_LZX_E8_TRANSLATION_SIZE;
			word = (uint32_t)value;
			for (byte = 0; byte < NTFS_LZX_E8_OPERAND_BYTES; byte++) {
				output[index + byte] =
				    (uint8_t)(word >> (byte * NTFS_BITS_PER_BYTE));
			}
		}
		index += NTFS_LZX_E8_OPERAND_BYTES;
	}
}

enum ntfs_result
ntfs_lzx_decode(const void *input, size_t size, void *output, size_t expected, void *workspace,
    size_t workspace_size, size_t *written)
{
	struct ntfs_lzx_workspace *work = workspace;
	struct ntfs_lzx_reader reader;
	uint8_t *bytes = output;
	size_t position = 0, limit, index;
	uint32_t type, default_size, block_size, distance;
	unsigned symbol, header, length;
	enum ntfs_result result;

	if (written == NULL) {
		return NTFS_INVALID;
	}
	*written = 0;
	if ((input == NULL && size != 0) || (output == NULL && expected != 0) ||
	    workspace == NULL || (uintptr_t)workspace % _Alignof(struct ntfs_lzx_workspace) != 0) {
		return NTFS_INVALID;
	}
	if (workspace_size < sizeof(*work) || expected > NTFS_LZX_MAX_BLOCK) {
		return NTFS_RANGE;
	}
	if (expected == 0) {
		return size == 0 ? NTFS_OK : NTFS_CORRUPT;
	}
	ntfs_zero(work, sizeof(*work));
	for (index = 0; index < NTFS_LZX_REPEATED_OFFSETS; index++) {
		work->repeated[index] = NTFS_LZX_INITIAL_OFFSET;
	}
	reader = (struct ntfs_lzx_reader){.bytes = input, .size = size};
	while (position < expected) {
		result = lzx_take_bits(&reader, NTFS_LZX_BLOCK_TYPE_BITS, &type);
		if (result != NTFS_OK) {
			return result;
		}
		result = lzx_take_bits(&reader, NTFS_LZX_DEFAULT_SIZE_BITS, &default_size);
		if (result != NTFS_OK) {
			return result;
		}
		block_size = NTFS_LZX_MAX_BLOCK;
		if (default_size == 0) {
			result = lzx_take_bits(&reader, NTFS_LZX_EXPLICIT_SIZE_BITS, &block_size);
			if (result != NTFS_OK) {
				return result;
			}
		}
		if (block_size == 0 || block_size > expected - position) {
			return NTFS_CORRUPT;
		}
		if (type == NTFS_LZX_RAW) {
			result = lzx_raw_block(&reader, work, bytes + position, block_size);
			if (result != NTFS_OK) {
				return result;
			}
			position += block_size;
			continue;
		}
		if (type != NTFS_LZX_VERBATIM && type != NTFS_LZX_ALIGNED) {
			return NTFS_CORRUPT;
		}
		result = lzx_read_trees(&reader, work, type);
		if (result != NTFS_OK) {
			return result;
		}
		limit = position + block_size;
		while (position < limit) {
			result = lzx_take_symbol(&reader, &work->main, work->main_symbols, &symbol);
			if (result != NTFS_OK) {
				return result;
			}
			if (symbol < NTFS_LZX_LITERAL_SYMBOLS) {
				bytes[position++] = (uint8_t)symbol;
				continue;
			}
			symbol -= NTFS_LZX_LITERAL_SYMBOLS;
			header = symbol & (NTFS_LZX_LENGTH_HEADERS - 1);
			length = header + NTFS_LZX_MIN_MATCH;
			if (header == NTFS_LZX_LENGTH_ESCAPE) {
				result = lzx_take_symbol(
				    &reader, &work->length, work->length_symbols, &length);
				if (result != NTFS_OK) {
					return result;
				}
				length += NTFS_LZX_SECONDARY_BASE;
			}
			result = lzx_match_offset(
			    &reader, work, type, symbol >> NTFS_LZX_LENGTH_HEADER_BITS, &distance);
			if (result != NTFS_OK) {
				return result;
			}
			if (distance == 0 || distance > position || length > limit - position) {
				return NTFS_CORRUPT;
			}
			ntfs_lz_copy(bytes + position, distance, length);
			position += length;
		}
	}
	/* A producer may reserve one zero lookahead word after the final word.
	 * Unused bits in the consumed word are padding, not extra tokens. */
	if (reader.position != size &&
	    (size - reader.position != NTFS_LZX_WORD_BYTES ||
		ntfs_u16(reader.bytes + reader.position) != 0)) {
		return NTFS_CORRUPT;
	}
	lzx_inverse_calls(bytes, expected);
	*written = expected;
	return NTFS_OK;
}
