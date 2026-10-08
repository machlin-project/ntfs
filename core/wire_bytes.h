/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef NTFS_WIRE_BYTES_H
#define NTFS_WIRE_BYTES_H
#include "disk.h"

/* Unaligned little-endian fields; each access touches exactly its wire width. */
static inline uint16_t
ntfs_u16(const void *input)
{
#if !defined(NTFS_WIRE_BYTES_PORTABLE) && defined(__BYTE_ORDER__) &&                               \
    __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	uint16_t value;

	__builtin_memcpy(&value, input, sizeof(value));
	return value;
#else
	const uint8_t *bytes = input;

	return (uint16_t)(bytes[0] | (uint16_t)bytes[1] << NTFS_BITS_PER_BYTE);
#endif
}

static inline uint32_t
ntfs_u32(const void *input)
{
#if !defined(NTFS_WIRE_BYTES_PORTABLE) && defined(__BYTE_ORDER__) &&                               \
    __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	uint32_t value;

	__builtin_memcpy(&value, input, sizeof(value));
	return value;
#else
	const uint8_t *bytes = input;

	return (uint32_t)ntfs_u16(bytes) |
	    (uint32_t)ntfs_u16(bytes + sizeof(uint16_t)) << (sizeof(uint16_t) * NTFS_BITS_PER_BYTE);
#endif
}

static inline uint64_t
ntfs_u64(const void *input)
{
#if !defined(NTFS_WIRE_BYTES_PORTABLE) && defined(__BYTE_ORDER__) &&                               \
    __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	uint64_t value;

	__builtin_memcpy(&value, input, sizeof(value));
	return value;
#else
	const uint8_t *bytes = input;

	return (uint64_t)ntfs_u32(bytes) |
	    (uint64_t)ntfs_u32(bytes + sizeof(uint32_t)) << (sizeof(uint32_t) * NTFS_BITS_PER_BYTE);
#endif
}

static inline void
ntfs_put_u16(void *output, uint16_t value)
{
#if !defined(NTFS_WIRE_BYTES_PORTABLE) && defined(__BYTE_ORDER__) &&                               \
    __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	__builtin_memcpy(output, &value, sizeof(value));
#else
	uint8_t *bytes = output;

	bytes[0] = (uint8_t)value;
	bytes[1] = (uint8_t)(value >> NTFS_BITS_PER_BYTE);
#endif
}

static inline void
ntfs_put_u32(void *output, uint32_t value)
{
#if !defined(NTFS_WIRE_BYTES_PORTABLE) && defined(__BYTE_ORDER__) &&                               \
    __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	__builtin_memcpy(output, &value, sizeof(value));
#else
	uint8_t *bytes = output;

	ntfs_put_u16(bytes, (uint16_t)value);
	ntfs_put_u16(
	    bytes + sizeof(uint16_t), (uint16_t)(value >> (sizeof(uint16_t) * NTFS_BITS_PER_BYTE)));
#endif
}

static inline void
ntfs_put_u64(void *output, uint64_t value)
{
#if !defined(NTFS_WIRE_BYTES_PORTABLE) && defined(__BYTE_ORDER__) &&                               \
    __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	__builtin_memcpy(output, &value, sizeof(value));
#else
	uint8_t *bytes = output;

	ntfs_put_u32(bytes, (uint32_t)value);
	ntfs_put_u32(
	    bytes + sizeof(uint32_t), (uint32_t)(value >> (sizeof(uint32_t) * NTFS_BITS_PER_BYTE)));
#endif
}

#endif
