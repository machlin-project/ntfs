/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"

enum ntfs_result
ntfs_lznt1_decode(const void *input, size_t size, void *output, size_t capacity, size_t *written)
{
	const uint8_t *src = input;
	uint8_t *dst = output;
	size_t in = 0, out = 0, end, base, chunk, displacement, length, position, i;
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
	while (in < size) {
		if (size - in < NTFS_LZNT1_HEADER_BYTES) {
			return NTFS_CORRUPT;
		}
		header = ntfs_u16(src + in);
		in += NTFS_LZNT1_HEADER_BYTES;
		if (header == 0) {
			break;
		}
		if ((header & NTFS_LZNT1_SIGNATURE_MASK) != NTFS_LZNT1_SIGNATURE) {
			return NTFS_CORRUPT;
		}
		chunk = (header & NTFS_LZNT1_LENGTH_MASK) + 1u;
		if (chunk > size - in) {
			return NTFS_CORRUPT;
		}
		end = in + chunk;
		base = out;
		if ((header & NTFS_LZNT1_COMPRESSED) == 0) {
			if (chunk > capacity - out) {
				return NTFS_RANGE;
			}
			ntfs_copy(dst + out, src + in, chunk);
			out += chunk;
			in = end;
		} else {
			while (in < end) {
				flags = src[in++];
				for (bit = 0; bit < NTFS_BITS_PER_BYTE && in < end; bit++) {
					if ((flags & (1u << bit)) == 0) {
						if (out - base == NTFS_LZNT1_CHUNK) {
							return NTFS_CORRUPT;
						}
						if (out == capacity) {
							return NTFS_RANGE;
						}
						dst[out++] = src[in++];
					} else {
						if (end - in < NTFS_LZNT1_TOKEN_BYTES ||
						    out == base) {
							return NTFS_CORRUPT;
						}
						token = ntfs_u16(src + in);
						in += NTFS_LZNT1_TOKEN_BYTES;
						mask = NTFS_LZNT1_LENGTH_MASK;
						shift = NTFS_LZNT1_TOKEN_INITIAL_SHIFT;
						position = out - base - 1;
						while (
						    position >= NTFS_LZNT1_TOKEN_SHIFT_THRESHOLD) {
							mask >>= 1;
							shift--;
							position >>= 1;
						}
						displacement = (token >> shift) + 1u;
						length = (token & mask) + NTFS_LZNT1_MIN_MATCH;
						if (displacement > out - base ||
						    length > NTFS_LZNT1_CHUNK - (out - base)) {
							return NTFS_CORRUPT;
						}
						if (length > capacity - out) {
							return NTFS_RANGE;
						}
						for (i = 0; i < length; i++) {
							dst[out] = dst[out - displacement];
							out++;
						}
					}
				}
			}
		}
		/* A following chunk starts on a 4 KiB output boundary. Short
		 * final chunks are legal; interior short chunks are corrupt. */
		if (out - base != NTFS_LZNT1_CHUNK && size - in >= NTFS_LZNT1_HEADER_BYTES &&
		    ntfs_u16(src + in) != 0) {
			return NTFS_CORRUPT;
		}
	}
	*written = out;
	return NTFS_OK;
}
