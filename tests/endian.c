/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { TEST_ALIGNMENTS = 32, TEST_GUARD = 0xa5 };

int
main(void)
{
	uint8_t *bytes;
	uint64_t value, expected;
	size_t alignment, width, bit, index;

	for (alignment = 0; alignment < TEST_ALIGNMENTS; alignment++) {
		for (width = sizeof(uint16_t); width <= sizeof(uint64_t); width *= 2) {
			bytes = malloc(alignment + width);
			assert(bytes != NULL);
			for (bit = 0; bit <= width * NTFS_BITS_PER_BYTE; bit++) {
				value = bit == width * NTFS_BITS_PER_BYTE ? UINT64_MAX
									  : UINT64_C(1) << bit;
				memset(bytes, TEST_GUARD, alignment + width);
				if (width == sizeof(uint16_t)) {
					ntfs_put_u16(bytes + alignment, (uint16_t)value);
				} else if (width == sizeof(uint32_t)) {
					ntfs_put_u32(bytes + alignment, (uint32_t)value);
				} else {
					ntfs_put_u64(bytes + alignment, value);
				}
				expected = 0;
				for (index = 0; index < width; index++) {
					assert(bytes[alignment + index] ==
					    (uint8_t)(value >> (index * NTFS_BITS_PER_BYTE)));
					expected |= (uint64_t)bytes[alignment + index]
					    << (index * NTFS_BITS_PER_BYTE);
				}
				assert((width == sizeof(uint16_t) ? ntfs_u16(bytes + alignment)
					       : width == sizeof(uint32_t)
					       ? ntfs_u32(bytes + alignment)
					       : ntfs_u64(bytes + alignment)) == expected);
				for (index = 0; index < alignment; index++) {
					assert(bytes[index] == TEST_GUARD);
				}
			}
			free(bytes);
		}
	}
	puts("little-endian loads/stores: independent bytes, 32 alignments, exact ends pass");
	return 0;
}
