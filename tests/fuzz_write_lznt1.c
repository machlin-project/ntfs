/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_lznt1.h"
#include "write_lznt1_unit.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { FUZZ_GUARD_BYTES = 32, FUZZ_GUARD = 0xa5, FUZZ_SMOKE_CASES = 512,
	FUZZ_UNIT_SMOKE_CASES = 2, FUZZ_SMOKE_BYTES = 65536 };
enum { UNIT_HEADER_BYTES = 6, UNIT_FULL_LOGICAL = 1, UNIT_FULL_INITIALIZED = 2,
	UNIT_ALLOCATION_REFUSAL = 4, UNIT_MIN_CLUSTER = 512, UNIT_GEOMETRIES = 4,
	UNIT_CLUSTERS = 16, CHUNK_BYTES = 4096, PACKET_HEADER_BYTES = 2,
	WORD_HIGH_MULTIPLIER = 256, FLAG_BITS = 8, MIN_MATCH = 3,
	SIGNATURE_MASK = 0x7000, SIGNATURE = 0x3000, COMPRESSED = 0x8000 };

struct unit_allocator {
	uint8_t *base;
	size_t bytes, calls, live;
	bool refuse;
};

static void
check_guard(const uint8_t *bytes, size_t count)
{
	size_t index;

	for (index = 0; index < count; index++) {
		assert(bytes[index] == FUZZ_GUARD);
	}
}

/* Separate packet framing and position-width table, checked against original
 * plaintext. Product decode below is an additional oracle, not the sole one. */
static void
inspect_packet(const uint8_t *packet, size_t bytes, const uint8_t *plain, size_t plain_bytes)
{
	static const size_t ends[] = {16, 32, 64, 128, 256, 512, 1024, 2048, 4096};
	static const unsigned widths[] = {12, 11, 10, 9, 8, 7, 6, 5, 4};
	size_t cursor = 0, position = 0, end, base, count, index, width, length, distance;
	unsigned header, flags, bit, token;

	while (cursor < bytes) {
		assert(bytes - cursor >= PACKET_HEADER_BYTES);
		header = packet[cursor] + WORD_HIGH_MULTIPLIER * packet[cursor + 1];
		cursor += PACKET_HEADER_BYTES;
		assert((header & SIGNATURE_MASK) == SIGNATURE);
		count = header % CHUNK_BYTES + 1;
		assert(count <= bytes - cursor && position < plain_bytes);
		end = cursor + count;
		base = position;
		if ((header & COMPRESSED) == 0) {
			assert(count <= plain_bytes - position);
			assert(memcmp(packet + cursor, plain + position, count) == 0);
			cursor = end;
			position += count;
		} else {
			while (cursor < end) {
				flags = packet[cursor++];
				for (bit = 0; bit < FLAG_BITS && cursor < end; bit++) {
					if ((flags & (1u << bit)) == 0) {
						assert(position < plain_bytes);
						assert(packet[cursor++] == plain[position++]);
						continue;
					}
					assert(end - cursor >= PACKET_HEADER_BYTES && position > base);
					token = packet[cursor] + WORD_HIGH_MULTIPLIER * packet[cursor + 1];
					cursor += PACKET_HEADER_BYTES;
					for (width = 0; position - base > ends[width]; width++) {
						assert(width + 1 < sizeof(ends) / sizeof(*ends));
					}
					length = token % (1u << widths[width]) + MIN_MATCH;
					distance = token / (1u << widths[width]) + 1;
					assert(distance <= position - base && length <= plain_bytes - position);
					assert(length <= CHUNK_BYTES - (position - base));
					for (index = 0; index < length; index++) {
						assert(plain[position + index] == plain[position - distance + index]);
					}
					position += length;
				}
			}
		}
		assert(position - base == (plain_bytes - base < CHUNK_BYTES ? plain_bytes - base : CHUNK_BYTES));
	}
	assert(position == plain_bytes);
}

static void *
unit_allocate(void *context, size_t bytes)
{
	struct unit_allocator *model = context;

	model->calls++;
	assert(model->live == 0 && bytes <= SIZE_MAX - 2 * FUZZ_GUARD_BYTES);
	if (model->refuse) {
		return NULL;
	}
	model->base = malloc(bytes + 2 * FUZZ_GUARD_BYTES);
	assert(model->base);
	memset(model->base, FUZZ_GUARD, bytes + 2 * FUZZ_GUARD_BYTES);
	model->bytes = bytes;
	model->live = 1;
	return model->base + FUZZ_GUARD_BYTES;
}

static void
unit_release(void *context, void *buffer, size_t bytes)
{
	struct unit_allocator *model = context;

	assert(model->live == 1 && bytes == model->bytes && buffer == model->base + FUZZ_GUARD_BYTES);
	check_guard(model->base, FUZZ_GUARD_BYTES);
	check_guard(model->base + FUZZ_GUARD_BYTES + bytes, FUZZ_GUARD_BYTES);
	free(model->base);
	model->base = NULL;
	model->live = 0;
}

static void
check_unit(const uint8_t *data, size_t size)
{
	struct unit_allocator model = {0};
	struct ntfs_environment environment = {NTFS_API_VERSION, &model, 0, NULL, unit_allocate, unit_release};
	struct ntfs_write_lznt1_unit_input input;
	struct ntfs_write_lznt1_unit *unit = NULL;
	const struct ntfs_write_lznt1_unit_view *view;
	uint8_t *plain, *decoded;
	size_t unit_bytes, available, initialized, logical, index, written;
	uint32_t cluster;
	bool zero = true;

	if (size < UNIT_HEADER_BYTES) {
		return;
	}
	cluster = UNIT_MIN_CLUSTER << (data[0] % UNIT_GEOMETRIES);
	unit_bytes = (size_t)cluster * UNIT_CLUSTERS;
	available = size - UNIT_HEADER_BYTES;
	if (available > unit_bytes) {
		available = unit_bytes;
	}
	logical = data[2] + WORD_HIGH_MULTIPLIER * data[3];
	logical = (data[1] & UNIT_FULL_LOGICAL) != 0 ? unit_bytes : logical % (unit_bytes + 1);
	initialized = available < logical ? available : logical;
	if ((data[1] & UNIT_FULL_INITIALIZED) == 0) {
		initialized = (data[4] + WORD_HIGH_MULTIPLIER * data[5]) % (initialized + 1);
	}
	plain = calloc(unit_bytes, 1);
	decoded = malloc(unit_bytes);
	assert(plain && decoded);
	memcpy(plain, data + UNIT_HEADER_BYTES, initialized);
	for (index = 0; index < initialized; index++) {
		zero = zero && plain[index] == 0;
	}
	input = (struct ntfs_write_lznt1_unit_input){data + UNIT_HEADER_BYTES, available, logical, initialized, cluster};
	if ((data[1] & UNIT_ALLOCATION_REFUSAL) != 0) {
		model.refuse = true;
		unit = (void *)&model;
		assert(ntfs_write_lznt1_unit_prepare(&environment, &input, &unit) == NTFS_NO_MEMORY);
		assert(unit == NULL && model.calls == 1 && model.live == 0);
		model.refuse = false;
		model.calls = 0;
	}
	assert(ntfs_write_lznt1_unit_prepare(&environment, &input, &unit) == NTFS_OK);
	assert(unit && model.calls == 1 && model.live == 1);
	view = ntfs_write_lznt1_unit_view(unit);
	assert(view && view->cluster_bytes == cluster && view->unit_bytes == unit_bytes);
	assert(view->logical_bytes == logical && view->initialized_bytes == initialized);
	assert(view->logical_clusters == (logical == 0 ? 0 : UNIT_CLUSTERS));
	assert(view->physical_clusters + view->hole_clusters == view->logical_clusters);
	assert(view->stored_bytes == (size_t)view->physical_clusters * cluster);
	memset(&environment, 0, sizeof(environment));
	memset(&input, 0, sizeof(input));
	if (logical == 0 || zero) {
		assert(view->kind == (logical == 0 ? NTFS_WRITE_LZNT1_UNIT_EMPTY : NTFS_WRITE_LZNT1_UNIT_SPARSE));
		assert(view->payload == NULL && view->stored_bytes == 0 && view->encoded_bytes == 0);
	} else if (view->kind == NTFS_WRITE_LZNT1_UNIT_RAW) {
		assert(view->physical_clusters == UNIT_CLUSTERS && view->encoded_bytes == 0);
		assert(memcmp(view->payload, plain, unit_bytes) == 0);
	} else {
		assert(view->kind == NTFS_WRITE_LZNT1_UNIT_PACKED);
		assert(view->physical_clusters > 0 && view->physical_clusters < UNIT_CLUSTERS);
		assert(view->encoded_bytes <= view->stored_bytes);
		assert(view->stored_bytes == view->encoded_bytes || view->stored_bytes - view->encoded_bytes >= PACKET_HEADER_BYTES);
		inspect_packet(view->payload, view->encoded_bytes, plain, unit_bytes);
		for (index = view->encoded_bytes; index < view->stored_bytes; index++) {
			assert(view->payload[index] == 0);
		}
		assert(ntfs_lznt1_decode(view->payload, view->stored_bytes, decoded, unit_bytes, &written) == NTFS_OK);
		assert(written == unit_bytes && memcmp(decoded, plain, unit_bytes) == 0);
	}
	ntfs_write_lznt1_unit_close(unit);
	assert(model.live == 0);
	free(decoded);
	free(plain);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t *scratch, *output, *second, *decoded;
	size_t workspace, bound = SIZE_MAX, required = SIZE_MAX, written = SIZE_MAX,
			  done = SIZE_MAX, capacity, alignment;
	enum ntfs_result result;

	if (size > NTFS_WRITE_LZNT1_MAX_BYTES) {
		assert(ntfs_write_lznt1_bound(size, &bound) == NTFS_RANGE && bound == SIZE_MAX);
		check_unit(data, size);
		return 0;
	}
	assert(ntfs_write_lznt1_bound(size, &bound) == NTFS_OK);
	workspace = ntfs_write_lznt1_workspace_size();
	alignment = size == 0 ? 0 : data[0] % FUZZ_GUARD_BYTES;
	scratch = malloc(workspace + alignment);
	output = malloc(bound + FUZZ_GUARD_BYTES);
	second = malloc(bound + FUZZ_GUARD_BYTES);
	decoded = malloc(size + alignment);
	assert(scratch && output && second && (decoded || size + alignment == 0));
	assert(ntfs_write_lznt1_measure(data, size, scratch + alignment, workspace, &required) ==
		NTFS_OK &&
	    required <= bound);
	memset(output, FUZZ_GUARD, bound + FUZZ_GUARD_BYTES);
	capacity = required != 0 && (data[0] & 1u) != 0 ? required - 1 : required;
	result = ntfs_write_lznt1_encode(
	    data, size, scratch + alignment, workspace, output, capacity, &written);
	if (capacity < required) {
		assert(result == NTFS_RANGE && written == SIZE_MAX);
		check_guard(output, bound + FUZZ_GUARD_BYTES);
		result = ntfs_write_lznt1_encode(
		    data, size, scratch + alignment, workspace, output, required, &written);
	}
	assert(result == NTFS_OK && written == required);
	inspect_packet(output, written, data, size);
	check_guard(output + written, bound + FUZZ_GUARD_BYTES - written);
	assert(ntfs_write_lznt1_encode(
		   data, size, scratch + alignment, workspace, second, bound, &done) == NTFS_OK &&
	    done == written);
	assert(memcmp(output, second, written) == 0);
	assert(ntfs_lznt1_decode(output, written, size == 0 ? NULL : decoded + alignment, size,
		   &done) == NTFS_OK &&
	    done == size);
	if (size != 0) {
		assert(memcmp(data, decoded + alignment, size) == 0);
	}
	free(decoded);
	free(second);
	free(output);
	free(scratch);
	check_unit(data, size);
	return 0;
}

#ifdef NTFS_FUZZ_STANDALONE
int
main(void)
{
	uint8_t *input;
	uint32_t state = UINT32_C(0x4c5a4e54);
	size_t index, run, size;

	input = malloc(FUZZ_SMOKE_BYTES + UNIT_HEADER_BYTES);
	assert(input);
	memset(input, 0, FUZZ_SMOKE_BYTES);
	for (run = 0; run < FUZZ_SMOKE_CASES; run++) {
		size = run < 32 ? run : (run * 257) % FUZZ_SMOKE_BYTES;
		for (index = 0; index < size; index++) {
			state ^= state << 13;
			state ^= state >> 17;
			state ^= state << 5;
			input[index] =
			    run % 3 == 0 ? (uint8_t)state : (uint8_t)(index % (run % 29 + 1));
		}
		(void)LLVMFuzzerTestOneInput(input, size);
	}
	/* Unit framing must not prevent full initialized 64-KiB coverage. Both
	 * framed shapes also exercise the ordinary byte encoder within its 1-MiB limit. */
	for (run = 0; run < FUZZ_UNIT_SMOKE_CASES; run++) {
		memset(input, 0, UNIT_HEADER_BYTES);
		input[0] = UNIT_GEOMETRIES - 1;
		input[1] = UNIT_FULL_LOGICAL | UNIT_FULL_INITIALIZED | UNIT_ALLOCATION_REFUSAL;
		for (index = 0; index < FUZZ_SMOKE_BYTES; index++) {
			state ^= state << 13;
			state ^= state >> 17;
			state ^= state << 5;
			input[UNIT_HEADER_BYTES + index] = run == 0 ? (uint8_t)state : (uint8_t)(index % 3);
		}
		(void)LLVMFuzzerTestOneInput(input, FUZZ_SMOKE_BYTES + UNIT_HEADER_BYTES);
	}
	free(input);
	printf("PASS: %d deterministic LZNT1 encoder/unit fuzz smoke inputs\n",
	    FUZZ_SMOKE_CASES + FUZZ_UNIT_SMOKE_CASES);
	return 0;
}
#endif
