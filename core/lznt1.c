/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"

enum ntfs_result
ntfs_lznt1_decode(const void *input, size_t size, void *output, size_t capacity, size_t *written)
{
	const uint8_t *source_bytes = input;
	uint8_t *destination_bytes = output;
	size_t input_offset = 0, output_offset = 0, end, base, chunk, displacement, length,
	       position;
	uint16_t header, token, mask;
	unsigned bit, shift;
	uint8_t flags;

	if (written == NULL) {
		return NTFS_INVALID;
	}
	*written = 0;
	if ((size != 0 && input == NULL) || (capacity != 0 && output == NULL)) {
		return NTFS_INVALID;
	}
	while (input_offset < size) {
		if (size - input_offset < NTFS_LZNT1_HEADER_BYTES) {
			return NTFS_CORRUPT;
		}
		header = ntfs_u16(source_bytes + input_offset);
		input_offset += NTFS_LZNT1_HEADER_BYTES;
		if (header == 0) {
			break;
		}
		if ((header & NTFS_LZNT1_SIGNATURE_MASK) != NTFS_LZNT1_SIGNATURE) {
			return NTFS_CORRUPT;
		}
		chunk = (header & NTFS_LZNT1_LENGTH_MASK) + 1u;
		if (chunk > size - input_offset) {
			return NTFS_CORRUPT;
		}
		end = input_offset + chunk;
		base = output_offset;
		if ((header & NTFS_LZNT1_COMPRESSED) == 0) {
			if (chunk > capacity - output_offset) {
				return NTFS_RANGE;
			}
			ntfs_copy(
			    destination_bytes + output_offset, source_bytes + input_offset, chunk);
			output_offset += chunk;
			input_offset = end;
		} else {
			while (input_offset < end) {
				flags = source_bytes[input_offset++];
				for (bit = 0; bit < NTFS_BITS_PER_BYTE && input_offset < end;
				    bit++) {
					if ((flags & (1u << bit)) == 0) {
						if (output_offset - base == NTFS_LZNT1_CHUNK) {
							return NTFS_CORRUPT;
						}
						if (output_offset == capacity) {
							return NTFS_RANGE;
						}
						destination_bytes[output_offset++] =
						    source_bytes[input_offset++];
					} else {
						if (end - input_offset < NTFS_LZNT1_TOKEN_BYTES ||
						    output_offset == base) {
							return NTFS_CORRUPT;
						}
						token = ntfs_u16(source_bytes + input_offset);
						input_offset += NTFS_LZNT1_TOKEN_BYTES;
						mask = NTFS_LZNT1_LENGTH_MASK;
						shift = NTFS_LZNT1_TOKEN_INITIAL_SHIFT;
						position = output_offset - base - 1;
						while (
						    position >= NTFS_LZNT1_TOKEN_SHIFT_THRESHOLD) {
							mask >>= 1;
							shift--;
							position >>= 1;
						}
						displacement = (token >> shift) + 1u;
						length = (token & mask) + NTFS_LZNT1_MIN_MATCH;
						if (displacement > output_offset - base ||
						    length >
							NTFS_LZNT1_CHUNK - (output_offset - base)) {
							return NTFS_CORRUPT;
						}
						if (length > capacity - output_offset) {
							return NTFS_RANGE;
						}
						ntfs_lz_copy(destination_bytes + output_offset,
						    displacement, length);
						output_offset += length;
					}
				}
			}
		}
		/* A following chunk starts on a 4 KiB output boundary. Short
		 * final chunks are legal; interior short chunks are corrupt. */
		if (output_offset - base != NTFS_LZNT1_CHUNK &&
		    size - input_offset >= NTFS_LZNT1_HEADER_BYTES &&
		    ntfs_u16(source_bytes + input_offset) != 0) {
			return NTFS_CORRUPT;
		}
	}
	*written = output_offset;
	return NTFS_OK;
}
