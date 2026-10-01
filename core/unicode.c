/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"

enum {
	UNICODE_ASCII_LIMIT = 0x80,
	UNICODE_TWO_BYTE_LIMIT = 0x800,
	UNICODE_BMP_LIMIT = 0x10000,
	UNICODE_MAX_CODE_POINT = 0x10ffff,
	UTF16_HIGH_FIRST = 0xd800,
	UTF16_HIGH_LAST = 0xdbff,
	UTF16_LOW_FIRST = 0xdc00,
	UTF16_LOW_LAST = 0xdfff,
	UTF16_SURROGATE_BITS = 10,
	UTF16_SURROGATE_MASK = (1u << UTF16_SURROGATE_BITS) - 1,
	UTF16_PAIR_UNITS = 2,
	UTF8_CONTINUATION_PREFIX = 0x80,
	UTF8_CONTINUATION_PREFIX_MASK = 0xc0,
	UTF8_CONTINUATION_MASK = 0x3f,
	UTF8_CONTINUATION_BITS = 6,
	UTF8_TWO_PREFIX = 0xc0,
	UTF8_TWO_FIRST = 0xc2,
	UTF8_TWO_LAST = 0xdf,
	UTF8_TWO_MASK = 0x1f,
	UTF8_TWO_BYTES = 2,
	UTF8_THREE_PREFIX = 0xe0,
	UTF8_THREE_LAST = 0xef,
	UTF8_THREE_MASK = 0x0f,
	UTF8_THREE_BYTES = 3,
	UTF8_FOUR_PREFIX = 0xf0,
	UTF8_FOUR_LAST = 0xf4,
	UTF8_FOUR_MASK = 0x07,
	UTF8_FOUR_BYTES = 4
};

enum ntfs_result
ntfs_utf8_to_utf16(const char *input, size_t size, uint16_t *out, size_t capacity, size_t *written)
{
	const uint8_t *s = (const void *)input;
	size_t i = 0, n = 0;
	uint32_t code, minimum;
	unsigned tails, j;
	uint8_t b;

	if (written == NULL) {
		return NTFS_INVALID;
	}
	*written = 0;
	if ((size != 0 && input == NULL) || (capacity != 0 && out == NULL)) {
		return NTFS_INVALID;
	}
	while (i < size) {
		b = s[i++];
		if (b < UNICODE_ASCII_LIMIT) {
			code = b;
			tails = 0;
			minimum = 0;
		} else if (b >= UTF8_TWO_FIRST && b <= UTF8_TWO_LAST) {
			code = b & UTF8_TWO_MASK;
			tails = UTF8_TWO_BYTES - 1;
			minimum = UNICODE_ASCII_LIMIT;
		} else if (b >= UTF8_THREE_PREFIX && b <= UTF8_THREE_LAST) {
			code = b & UTF8_THREE_MASK;
			tails = UTF8_THREE_BYTES - 1;
			minimum = UNICODE_TWO_BYTE_LIMIT;
		} else if (b >= UTF8_FOUR_PREFIX && b <= UTF8_FOUR_LAST) {
			code = b & UTF8_FOUR_MASK;
			tails = UTF8_FOUR_BYTES - 1;
			minimum = UNICODE_BMP_LIMIT;
		} else {
			return NTFS_INVALID;
		}
		if (tails > size - i) {
			return NTFS_INVALID;
		}
		for (j = 0; j < tails; j++) {
			b = s[i++];
			if ((b & UTF8_CONTINUATION_PREFIX_MASK) != UTF8_CONTINUATION_PREFIX) {
				return NTFS_INVALID;
			}
			code = (code << UTF8_CONTINUATION_BITS) | (b & UTF8_CONTINUATION_MASK);
		}
		if (code < minimum || code > UNICODE_MAX_CODE_POINT ||
		    (code >= UTF16_HIGH_FIRST && code <= UTF16_LOW_LAST)) {
			return NTFS_INVALID;
		}
		if (code >= UNICODE_BMP_LIMIT) {
			if (capacity - n < UTF16_PAIR_UNITS) {
				return NTFS_RANGE;
			}
			code -= UNICODE_BMP_LIMIT;
			out[n++] = (uint16_t)(UTF16_HIGH_FIRST | (code >> UTF16_SURROGATE_BITS));
			out[n++] = (uint16_t)(UTF16_LOW_FIRST | (code & UTF16_SURROGATE_MASK));
		} else {
			if (n == capacity) {
				return NTFS_RANGE;
			}
			out[n++] = (uint16_t)code;
		}
	}
	*written = n;
	return NTFS_OK;
}

enum ntfs_result
ntfs_utf16_to_utf8(const uint16_t *input, size_t size, char *out, size_t capacity, size_t *written)
{
	size_t i = 0, n = 0;
	uint32_t code;
	unsigned count, j;

	if (written == NULL) {
		return NTFS_INVALID;
	}
	*written = 0;
	if ((size != 0 && input == NULL) || (capacity != 0 && out == NULL)) {
		return NTFS_INVALID;
	}
	while (i < size) {
		code = input[i++];
		if (code >= UTF16_HIGH_FIRST && code <= UTF16_HIGH_LAST) {
			if (i == size || input[i] < UTF16_LOW_FIRST || input[i] > UTF16_LOW_LAST) {
				return NTFS_INVALID;
			}
			code = UNICODE_BMP_LIMIT +
			    ((code - UTF16_HIGH_FIRST) << UTF16_SURROGATE_BITS) +
			    (input[i++] - UTF16_LOW_FIRST);
		} else if (code >= UTF16_LOW_FIRST && code <= UTF16_LOW_LAST) {
			return NTFS_INVALID;
		}
		count = code < UNICODE_ASCII_LIMIT  ? 1
		    : code < UNICODE_TWO_BYTE_LIMIT ? UTF8_TWO_BYTES
		    : code < UNICODE_BMP_LIMIT	    ? UTF8_THREE_BYTES
						    : UTF8_FOUR_BYTES;
		if (count > capacity - n) {
			return NTFS_RANGE;
		}
		if (count == 1) {
			out[n++] = (char)code;
		} else {
			for (j = count - 1; j > 0; j--) {
				out[n + j] = (char)(UTF8_CONTINUATION_PREFIX |
				    (code & UTF8_CONTINUATION_MASK));
				code >>= UTF8_CONTINUATION_BITS;
			}
			out[n] = (char)((count == UTF8_TWO_BYTES	    ? UTF8_TWO_PREFIX
						: count == UTF8_THREE_BYTES ? UTF8_THREE_PREFIX
									    : UTF8_FOUR_PREFIX) |
			    code);
			n += count;
		}
	}
	*written = n;
	return NTFS_OK;
}

int
ntfs_name_compare(struct ntfs_volume *v, const uint16_t *name, size_t length, const uint8_t *other,
    size_t other_length)
{
	size_t i, count = length < other_length ? length : other_length;
	uint16_t a, b;

	for (i = 0; i < count; i++) {
		a = ntfs_u16(v->upcase + (size_t)name[i] * NTFS_UTF16_UNIT_BYTES);
		b = ntfs_u16(v->upcase +
		    (size_t)ntfs_u16(other + i * NTFS_UTF16_UNIT_BYTES) * NTFS_UTF16_UNIT_BYTES);
		if (a != b) {
			return a < b ? -1 : 1;
		}
	}
	return length == other_length ? 0 : length < other_length ? -1 : 1;
}
