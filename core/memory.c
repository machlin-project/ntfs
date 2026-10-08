/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"

#if defined(__aarch64__) && defined(__ARM_NEON) && !defined(KERNEL) && !defined(_KERNEL) &&        \
    !defined(__KERNEL__) && !defined(NTFS_NO_SIMD) && !defined(NTFS_MEMORY_PORTABLE)
#include <arm_neon.h>
#define NTFS_MEMORY_NEON 1
#endif

#if defined(KERNEL) || defined(_KERNEL) || defined(__KERNEL__) || defined(NTFS_NO_SIMD)
#define NTFS_MEMORY_GENERAL_REGISTERS 1
#endif

enum { NTFS_MEMORY_VECTOR_BYTES = 16 };
#ifdef NTFS_MEMORY_GENERAL_REGISTERS
enum { NTFS_MEMORY_ZERO_BLOCK_MIN = 256 };
#else
enum { NTFS_MEMORY_ZERO_BLOCK_MIN = 16384 };
#endif

#ifndef NTFS_MEMORY_PORTABLE
static inline uint64_t
memory_load_word(const uint8_t *bytes)
{
	uint64_t value;

	/* Fixed-size compiler copies admit unaligned, arbitrarily typed storage.
	 * Supported freestanding builds lower these to loads/stores, without libc. */
	__builtin_memcpy(&value, bytes, sizeof(value));
	return value;
}

#ifdef NTFS_MEMORY_GENERAL_REGISTERS
static inline void
memory_store_word(uint8_t *bytes, uint64_t value)
{
	__builtin_memcpy(bytes, &value, sizeof(value));
}
#endif
#endif

void
ntfs_copy(void *destination, const void *source, size_t bytes)
{
	uint8_t *output = destination;
	const uint8_t *input = source;
	size_t position = 0;

	/* Preserve the original forward-copy semantics, including LZ overlap.
	 * Each wide load must finish before its store and use already valid bytes. */
#if defined(NTFS_MEMORY_GENERAL_REGISTERS) && !defined(NTFS_MEMORY_PORTABLE)
	if ((uintptr_t)output <= (uintptr_t)input ||
	    (uintptr_t)output - (uintptr_t)input >= sizeof(uint64_t)) {
		while (bytes - position >= sizeof(uint64_t)) {
			memory_store_word(output + position, memory_load_word(input + position));
			position += sizeof(uint64_t);
		}
	}
#endif
	for (; position < bytes; position++) {
		output[position] = input[position];
	}
}

#if defined(__aarch64__) && !defined(NTFS_MEMORY_PORTABLE)
enum { NTFS_DCZID_PROHIBITED = 1u << 4, NTFS_DCZID_SIZE_MASK = 0xf, NTFS_DCZID_WORD_BYTES = 4 };

static size_t
memory_zero_blocks(uint8_t *output, size_t size)
{
	uint64_t description;
	size_t block, prefix, position;

	if (size < NTFS_MEMORY_ZERO_BLOCK_MIN) {
		return 0;
	}
	__asm__ volatile("mrs %0, dczid_el0" : "=r"(description));
	if ((description & NTFS_DCZID_PROHIBITED) != 0) {
		return 0;
	}
	block = (size_t)NTFS_DCZID_WORD_BYTES << (description & NTFS_DCZID_SIZE_MASK);
	prefix = (block - (uintptr_t)output % block) % block;
	if (prefix > size || block > size - prefix) {
		return 0;
	}
	for (position = 0; position < prefix; position++) {
		output[position] = 0;
	}
	/* Normal RAM only. Every naturally aligned block lies wholly in the
	 * supplied span; DC ZVA uses no vector or floating-point registers. */
	while (block <= size - position) {
		__asm__ volatile("dc zva, %0" : : "r"(output + position) : "memory");
		position += block;
	}
	return position;
}
#endif

void
ntfs_zero(void *destination, size_t bytes)
{
	uint8_t *output = destination;
	size_t position = 0;

#if defined(__aarch64__) && !defined(NTFS_MEMORY_PORTABLE)
	position = memory_zero_blocks(output, bytes);
#endif
#if defined(NTFS_MEMORY_GENERAL_REGISTERS) && !defined(NTFS_MEMORY_PORTABLE)
	while (bytes - position >= sizeof(uint64_t)) {
		memory_store_word(output + position, 0);
		position += sizeof(uint64_t);
	}
#endif
	for (; position < bytes; position++) {
		output[position] = 0;
	}
}

bool
ntfs_equal(const void *left, const void *right, size_t bytes)
{
	const uint8_t *left_bytes = left, *right_bytes = right;
	size_t position = 0;

#ifdef NTFS_MEMORY_NEON
	while (bytes - position >= NTFS_MEMORY_VECTOR_BYTES) {
		if (vminvq_u8(vceqq_u8(vld1q_u8(left_bytes + position),
			vld1q_u8(right_bytes + position))) != UINT8_MAX) {
			return false;
		}
		position += NTFS_MEMORY_VECTOR_BYTES;
	}
#endif
#ifndef NTFS_MEMORY_PORTABLE
	while (bytes - position >= sizeof(uint64_t)) {
		if (memory_load_word(left_bytes + position) !=
		    memory_load_word(right_bytes + position)) {
			return false;
		}
		position += sizeof(uint64_t);
	}
#endif
	for (; position < bytes; position++) {
		if (left_bytes[position] != right_bytes[position]) {
			return false;
		}
	}
	return true;
}

size_t
ntfs_find_byte(const void *input, size_t size, uint8_t value)
{
	const uint8_t *bytes = input;
	size_t position = 0;
#if !defined(NTFS_MEMORY_NEON) && !defined(NTFS_MEMORY_PORTABLE)
	const uint64_t low_bits = UINT64_C(0x0101010101010101);
	const uint64_t high_bits = UINT64_C(0x8080808080808080);
	uint64_t word;
#endif

#ifdef NTFS_MEMORY_NEON
	while (size - position >= NTFS_MEMORY_VECTOR_BYTES) {
		if (vmaxvq_u8(vceqq_u8(vld1q_u8(bytes + position), vdupq_n_u8(value))) != 0) {
			break;
		}
		position += NTFS_MEMORY_VECTOR_BYTES;
	}
#elif !defined(NTFS_MEMORY_PORTABLE)
	while (size - position >= sizeof(uint64_t)) {
		word = memory_load_word(bytes + position) ^ (low_bits * value);
		if (((word - low_bits) & ~word & high_bits) != 0) {
			break;
		}
		position += sizeof(uint64_t);
	}
#endif
	while (position < size && bytes[position] != value) {
		position++;
	}
	return position;
}

void
ntfs_lz_copy(uint8_t *output, size_t distance, size_t length)
{
	size_t position;

	/* Callers validate a nonzero distance into the same output object and
	 * the entire destination span before entering. Short matches need no setup. */
	if (length < NTFS_MEMORY_VECTOR_BYTES) {
		for (position = 0; position < length; position++) {
			output[position] = (output - distance)[position];
		}
		return;
	}
	/* Build a wider repeated prefix using disjoint, exact copies. The source
	 * remains the original prefix and never includes uninitialized output. */
	while (distance < NTFS_MEMORY_VECTOR_BYTES && distance <= length) {
		ntfs_copy(output, output - distance, distance);
		output += distance;
		length -= distance;
		distance *= 2;
	}
#ifdef NTFS_MEMORY_NEON
	while (length >= NTFS_MEMORY_VECTOR_BYTES) {
		vst1q_u8(output, vld1q_u8(output - distance));
		output += NTFS_MEMORY_VECTOR_BYTES;
		length -= NTFS_MEMORY_VECTOR_BYTES;
	}
#endif
	ntfs_copy(output, output - distance, length);
}
