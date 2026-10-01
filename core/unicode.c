/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"

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
		if (b < 0x80) {
			code = b;
			tails = 0;
			minimum = 0;
		} else if (b >= 0xc2 && b <= 0xdf) {
			code = b & 0x1f;
			tails = 1;
			minimum = 0x80;
		} else if (b >= 0xe0 && b <= 0xef) {
			code = b & 0x0f;
			tails = 2;
			minimum = 0x800;
		} else if (b >= 0xf0 && b <= 0xf4) {
			code = b & 7;
			tails = 3;
			minimum = 0x10000;
		} else {
			return NTFS_INVALID;
		}
		if (tails > size - i) {
			return NTFS_INVALID;
		}
		for (j = 0; j < tails; j++) {
			b = s[i++];
			if ((b & 0xc0) != 0x80) {
				return NTFS_INVALID;
			}
			code = (code << 6) | (b & 0x3f);
		}
		if (code < minimum || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) {
			return NTFS_INVALID;
		}
		if (code >= 0x10000) {
			if (capacity - n < 2) {
				return NTFS_RANGE;
			}
			code -= 0x10000;
			out[n++] = (uint16_t)(0xd800 | (code >> 10));
			out[n++] = (uint16_t)(0xdc00 | (code & 0x3ff));
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
		if (code >= 0xd800 && code <= 0xdbff) {
			if (i == size || input[i] < 0xdc00 || input[i] > 0xdfff) {
				return NTFS_INVALID;
			}
			code = 0x10000 + ((code - 0xd800) << 10) + (input[i++] - 0xdc00);
		} else if (code >= 0xdc00 && code <= 0xdfff) {
			return NTFS_INVALID;
		}
		count = code < 0x80 ? 1 : code < 0x800 ? 2 : code < 0x10000 ? 3 : 4;
		if (count > capacity - n) {
			return NTFS_RANGE;
		}
		if (count == 1) {
			out[n++] = (char)code;
		} else {
			for (j = count - 1; j > 0; j--) {
				out[n + j] = (char)(0x80 | (code & 0x3f));
				code >>= 6;
			}
			out[n] = (char)((count == 2 ? 0xc0 : count == 3 ? 0xe0 : 0xf0) | code);
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
		a = ntfs_u16(v->upcase + (size_t)name[i] * 2);
		b = ntfs_u16(v->upcase + (size_t)ntfs_u16(other + i * 2) * 2);
		if (a != b) {
			return a < b ? -1 : 1;
		}
	}
	return length == other_length ? 0 : length < other_length ? -1 : 1;
}
