/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_FSKIT_WIRE_BYTES_H
#define MACHLIN_NTFS_FSKIT_WIRE_BYTES_H
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

static inline void
ntfs_native_store_little(uint8_t *bytes, size_t width, uint64_t value)
{
	size_t i;

	for (i = 0; i < width; i++) {
		bytes[i] = (uint8_t)(value >> (i * CHAR_BIT));
	}
}

#endif
