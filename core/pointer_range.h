/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_POINTER_RANGE_H
#define MACHLIN_NTFS_POINTER_RANGE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Check address arithmetic only; this does not prove accessible storage. An
 * empty range has no bytes, may be NULL and is separate from every valid range.
 * Callers retain their own required-pointer and output-publication policies. */
static inline bool
ntfs_pointer_range_valid(const void *pointer, size_t bytes)
{
	return bytes == 0 || (pointer != NULL && bytes <= UINTPTR_MAX - (uintptr_t)pointer);
}

static inline bool
ntfs_pointer_ranges_separate(
    const void *left, size_t left_bytes, const void *right, size_t right_bytes)
{
	uintptr_t a = (uintptr_t)left, b = (uintptr_t)right;

	return ntfs_pointer_range_valid(left, left_bytes) &&
	    ntfs_pointer_range_valid(right, right_bytes) &&
	    (left_bytes == 0 || right_bytes == 0 ||
		(a <= b ? b - a >= left_bytes : a - b >= right_bytes));
}

#endif
