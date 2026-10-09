/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_lznt1_unit.h"
#include "write_lznt1.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { GUARD_BYTES = 32, GUARD = 0xa5, ALIGNMENTS = 16, CHUNK_BYTES = 4096,
	HEADER_BYTES = 2, CLUSTERS = 16, MIN_CLUSTER = 512, MAX_CLUSTER = 4096,
	WORD_HIGH_MULTIPLIER = 256, FLAG_BITS = 8, MIN_MATCH = 3,
	SIGNATURE_MASK = 0x7000, SIGNATURE = 0x3000, COMPRESSED = 0x8000,
	OWNER_METADATA_BUDGET = 1024, REPEATED_PACKET_BYTES = 6,
	PATH_BYTES = 1024, RANDOM_CASES = 128, ANY_KIND = -1, ANY_PHYSICAL = CLUSTERS + 1 };

struct allocation_model {
	uint8_t *base;
	size_t bytes, calls, live, releases, reads;
	bool fail, exact_end;
};

static size_t checks;
static size_t owner_bytes;
static size_t exported;
static const char *corpus;

static void *
allocate(void *context, size_t bytes)
{
	struct allocation_model *model = context;
	size_t total = GUARD_BYTES + bytes + (model->exact_end ? 0 : GUARD_BYTES);

	model->calls++;
	assert(model->live == 0);
	if (model->fail) {
		return NULL;
	}
	model->base = malloc(total);
	assert(model->base != NULL);
	memset(model->base, GUARD, total);
	model->bytes = bytes;
	model->live = 1;
	return model->base + GUARD_BYTES;
}

static void
release(void *context, void *buffer, size_t bytes)
{
	struct allocation_model *model = context;
	size_t index;

	assert(model->live == 1 && buffer == model->base + GUARD_BYTES && bytes == model->bytes);
	for (index = 0; index < GUARD_BYTES; index++) {
		assert(model->base[index] == GUARD);
		if (!model->exact_end) {
			assert(model->base[GUARD_BYTES + bytes + index] == GUARD);
		}
	}
	free(model->base);
	model->base = NULL;
	model->live = 0;
	model->releases++;
}

static enum ntfs_result
read_forbidden(void *context, uint64_t offset, void *buffer, size_t bytes)
{
	struct allocation_model *model = context;

	(void)offset;
	(void)buffer;
	(void)bytes;
	model->reads++;
	return NTFS_IO;
}

static struct ntfs_environment
environment(struct allocation_model *model)
{
	struct ntfs_environment result = {NTFS_API_VERSION, model, 0, read_forbidden,
	    allocate, release};

	return result;
}

/* Independently walk generated packet bytes using an explicit position table.
 * Compare every literal and reference with the normalized original plaintext;
 * the product decoder is only an additional oracle below. */
static void
inspect(const uint8_t *packet, size_t bytes, const uint8_t *plain, size_t plain_bytes)
{
	static const size_t ends[] = {16, 32, 64, 128, 256, 512, 1024, 2048, 4096};
	static const unsigned widths[] = {12, 11, 10, 9, 8, 7, 6, 5, 4};
	size_t cursor = 0, position = 0, end, base, count, index, width, length, distance;
	unsigned header, flags, bit, token;

	while (cursor < bytes) {
		assert(bytes - cursor >= HEADER_BYTES);
		header = packet[cursor] + WORD_HIGH_MULTIPLIER * packet[cursor + 1];
		cursor += HEADER_BYTES;
		assert((header & SIGNATURE_MASK) == SIGNATURE);
		count = header % CHUNK_BYTES + 1;
		assert(count <= bytes - cursor);
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
					assert(end - cursor >= HEADER_BYTES && position > base);
					token = packet[cursor] + WORD_HIGH_MULTIPLIER * packet[cursor + 1];
					cursor += HEADER_BYTES;
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
		assert(position - base == CHUNK_BYTES);
	}
	assert(position == plain_bytes);
}

static void
noise(uint8_t *bytes, size_t count)
{
	uint32_t state = UINT32_C(0x4c5a4e54);
	size_t index;

	for (index = 0; index < count; index++) {
		state ^= state << 13;
		state ^= state >> 17;
		state ^= state << 5;
		bytes[index] = (uint8_t)state;
	}
}

static void
emit(const char *suffix, const uint8_t *bytes, size_t count)
{
	char path[PATH_BYTES];
	FILE *file;
	int length;

	length = snprintf(path, sizeof(path), "%s/unit-%04zu.%s", corpus, checks, suffix);
	assert(length > 0 && (size_t)length < sizeof(path));
	file = fopen(path, "wbx");
	assert(file && fwrite(bytes, 1, count, file) == count && fclose(file) == 0);
}

static void
check(const uint8_t *original, size_t source_bytes, size_t logical, size_t initialized,
    uint32_t cluster, size_t alignment, int expected_kind,
    size_t expected_encoded, unsigned expected_physical)
{
	struct allocation_model model = {0};
	struct ntfs_environment env = environment(&model);
	struct ntfs_write_lznt1_unit_input input;
	struct ntfs_write_lznt1_unit *unit = NULL;
	const struct ntfs_write_lznt1_unit_view *view;
	uint8_t *source, *plain, *decoded;
	size_t unit_bytes = (size_t)cluster * CLUSTERS, index, written, bound;
	enum ntfs_write_lznt1_unit_kind kind;
	unsigned physical;
	bool zero = true;

	source = malloc(alignment + source_bytes + 1);
	plain = calloc(unit_bytes, 1);
	decoded = malloc(unit_bytes);
	assert(source && plain && decoded);
	memset(source, GUARD, alignment + source_bytes + 1);
	memcpy(source + alignment + 1, original, source_bytes);
	memcpy(plain, original, initialized);
	for (index = 0; index < initialized; index++) {
		zero = zero && original[index] == 0;
	}
	input = (struct ntfs_write_lznt1_unit_input){source + alignment + 1, source_bytes,
	    logical, initialized, cluster};
	model.exact_end = checks % 2 != 0;
	assert(ntfs_write_lznt1_unit_prepare(&env, &input, &unit) == NTFS_OK);
	assert(unit && model.calls == 1 && model.live == 1 && model.reads == 0);
	assert(memcmp(source + alignment + 1, original, source_bytes) == 0);
	assert(ntfs_write_lznt1_bound(unit_bytes, &bound) == NTFS_OK);
	view = ntfs_write_lznt1_unit_view(unit);
	assert(view && view->unit_bytes == unit_bytes);
	kind = view->kind;
	physical = view->physical_clusters;
	assert(expected_kind == ANY_KIND || kind == (enum ntfs_write_lznt1_unit_kind)expected_kind);
	assert(expected_physical == ANY_PHYSICAL || physical == expected_physical);
	assert(logical == 0 ? kind == NTFS_WRITE_LZNT1_UNIT_EMPTY
	    : zero ? kind == NTFS_WRITE_LZNT1_UNIT_SPARSE
	           : (kind == NTFS_WRITE_LZNT1_UNIT_RAW || kind == NTFS_WRITE_LZNT1_UNIT_PACKED));
	/* Owner metadata is small; the rest is one unit, bound and codec workspace. */
	if (kind == NTFS_WRITE_LZNT1_UNIT_EMPTY && owner_bytes == 0) {
		owner_bytes = model.bytes;
	}
	assert(owner_bytes != 0 && owner_bytes <= OWNER_METADATA_BUDGET);
	assert(model.bytes == owner_bytes + ((kind == NTFS_WRITE_LZNT1_UNIT_RAW ||
	    kind == NTFS_WRITE_LZNT1_UNIT_PACKED) ? unit_bytes + bound + ntfs_write_lznt1_workspace_size() : 0));
	assert(view->logical_bytes == logical && view->initialized_bytes == initialized);
	assert(view->cluster_bytes == cluster && view->physical_clusters == physical);
	assert(view->logical_clusters == (logical == 0 ? 0 : CLUSTERS));
	assert(view->physical_clusters + view->hole_clusters == view->logical_clusters);
	assert(view->stored_bytes == (size_t)physical * cluster);
	if (expected_encoded != SIZE_MAX) {
		assert(view->encoded_bytes == expected_encoded);
	}
	/* Inputs and borrowed environment disappear before any result inspection. */
	memset(source + alignment + 1, 0x3c, source_bytes);
	memset(&input, 0, sizeof(input));
	memset(&env, 0, sizeof(env));
	if (kind == NTFS_WRITE_LZNT1_UNIT_PACKED) {
		assert(view->payload && view->encoded_bytes <= view->stored_bytes);
		assert(physical > 0 && physical < CLUSTERS);
		assert(view->stored_bytes == view->encoded_bytes ||
		    view->stored_bytes - view->encoded_bytes >= HEADER_BYTES);
		assert(view->stored_bytes - view->encoded_bytes < cluster ||
		    view->stored_bytes - view->encoded_bytes == cluster + 1u);
		inspect(view->payload, view->encoded_bytes, plain, unit_bytes);
		for (index = view->encoded_bytes; index < view->stored_bytes; index++) {
			assert(view->payload[index] == 0);
		}
		assert(ntfs_lznt1_decode(view->payload, view->stored_bytes, decoded,
		    unit_bytes, &written) == NTFS_OK && written == unit_bytes);
		assert(memcmp(decoded, plain, unit_bytes) == 0);
		if (corpus != NULL) {
			emit("data", plain, unit_bytes);
			emit("packed", view->payload, view->stored_bytes);
			exported++;
		}
	} else if (kind == NTFS_WRITE_LZNT1_UNIT_RAW) {
		assert(view->payload && view->encoded_bytes == 0 && physical == CLUSTERS);
		assert(memcmp(view->payload, plain, unit_bytes) == 0);
	} else {
		assert(view->payload == NULL && view->stored_bytes == 0 && view->encoded_bytes == 0);
		assert(model.bytes == owner_bytes);
		for (index = 0; index < unit_bytes; index++) {
			assert(plain[index] == 0);
		}
	}
	for (index = 0; index <= alignment; index++) {
		assert(source[index] == GUARD);
	}
	ntfs_write_lznt1_unit_close(unit);
	assert(model.live == 0 && model.releases == 1 && model.reads == 0);
	free(decoded);
	free(plain);
	free(source);
	checks++;
}

static void
content_cases(void)
{
	uint8_t *bytes;
	size_t size, alignment, logical, initialized;
	uint32_t cluster;

	bytes = malloc(MAX_CLUSTER * CLUSTERS);
	assert(bytes);
	for (cluster = MIN_CLUSTER; cluster <= MAX_CLUSTER; cluster *= 2) {
		size = (size_t)cluster * CLUSTERS;
		memset(bytes, 0, size);
		check(bytes, 0, 0, 0, cluster, 0, NTFS_WRITE_LZNT1_UNIT_EMPTY, 0, 0);
		check(bytes, size, size, size, cluster, 1, NTFS_WRITE_LZNT1_UNIT_SPARSE, 0, 0);
		memset(bytes, 'A', size);
		for (alignment = 0; alignment < ALIGNMENTS; alignment++) {
			check(bytes, size, size, size, cluster, alignment,
			    NTFS_WRITE_LZNT1_UNIT_PACKED, (size / CHUNK_BYTES) * REPEATED_PACKET_BYTES, 1);
		}
		noise(bytes, size);
		check(bytes, size, size, size, cluster, 2, NTFS_WRITE_LZNT1_UNIT_RAW, 0, CLUSTERS);
		/* No source byte after VDL may enter a packet, including nonzero EOF tails. */
		for (logical = cluster - 1; logical <= cluster + 1; logical++) {
			for (initialized = 0; initialized <= 1; initialized++) {
				memset(bytes, 0xe7, size);
				bytes[0] = initialized != 0 ? 'Q' : 0;
				check(bytes, size, logical, initialized, cluster, logical % ALIGNMENTS,
				    initialized == 0 ? NTFS_WRITE_LZNT1_UNIT_SPARSE : NTFS_WRITE_LZNT1_UNIT_PACKED,
				    initialized == 0 ? 0 : SIZE_MAX, initialized == 0 ? 0 : 1);
			}
		}
		memset(bytes, 'R', size);
		check(bytes, 1, size, 1, cluster, 3, NTFS_WRITE_LZNT1_UNIT_PACKED, SIZE_MAX, 1);
		check(bytes, size, size - 1, size - 1, cluster, 4,
		    NTFS_WRITE_LZNT1_UNIT_PACKED, SIZE_MAX, 1);
		check(bytes, size, 0, 0, cluster, 5, NTFS_WRITE_LZNT1_UNIT_EMPTY, 0, 0);
	}
	free(bytes);
}

static void
padding_cases(void)
{
	enum { UNIT_BYTES = MIN_CLUSTER * CLUSTERS };
	static const struct {
		unsigned leading, physical;
		size_t prefix, encoded;
	} cases[] = {{0, 1, 156, MIN_CLUSTER - 2}, {0, 2, 157, MIN_CLUSTER - 1},
	    {4, 1, 161, MIN_CLUSTER}, {0, CLUSTERS, 7168, MIN_CLUSTER * (CLUSTERS - 1) - 1}};
	uint8_t *bytes, *random, *workspace, *packet, *decoded;
	size_t index, encoded, bound, written, workspace_bytes, chunk;

	bytes = calloc(UNIT_BYTES, 1);
	random = malloc(UNIT_BYTES);
	workspace_bytes = ntfs_write_lznt1_workspace_size();
	workspace = malloc(workspace_bytes);
	assert(ntfs_write_lznt1_bound(UNIT_BYTES, &bound) == NTFS_OK);
	packet = malloc(bound + MIN_CLUSTER);
	decoded = malloc(UNIT_BYTES);
	assert(bytes && random && workspace && packet && decoded);
	/* Fixed independently authored plaintext from retained bounded discovery.
	 * These exact packet lengths protect four different storage boundaries. */
	for (index = 0; index < sizeof(cases) / sizeof(*cases); index++) {
		memset(bytes, 0, UNIT_BYTES);
		noise(random, UNIT_BYTES);
		for (chunk = 0; chunk < UNIT_BYTES; chunk += CHUNK_BYTES) {
			memset(random + chunk, 'A', cases[index].leading);
		}
		memcpy(bytes, random, cases[index].prefix);
		assert(ntfs_write_lznt1_measure(bytes, UNIT_BYTES, workspace, workspace_bytes,
		    &encoded) == NTFS_OK && encoded == cases[index].encoded);
		assert(ntfs_write_lznt1_encode(bytes, UNIT_BYTES, workspace, workspace_bytes,
		    packet, bound, &written) == NTFS_OK && written == encoded);
		inspect(packet, encoded, bytes, UNIT_BYTES);
		if (encoded % MIN_CLUSTER == MIN_CLUSTER - 1) {
			packet[encoded] = 0;
			assert(ntfs_lznt1_decode(packet, encoded + 1, decoded, UNIT_BYTES,
			    &written) == NTFS_CORRUPT && written == 0);
		}
		check(bytes, UNIT_BYTES, UNIT_BYTES, UNIT_BYTES, MIN_CLUSTER, index,
		    cases[index].physical == CLUSTERS ? NTFS_WRITE_LZNT1_UNIT_RAW : NTFS_WRITE_LZNT1_UNIT_PACKED,
		    cases[index].physical == CLUSTERS ? 0 : encoded, cases[index].physical);
	}
	free(decoded);
	free(packet);
	free(workspace);
	free(random);
	free(bytes);
}

static void
randomized_cases(void)
{
	uint8_t *bytes;
	uint32_t state = UINT32_C(0x554e4954), cluster;
	size_t run, size, logical, initialized, index, declared;

	bytes = malloc(MAX_CLUSTER * CLUSTERS);
	assert(bytes);
	for (run = 0; run < RANDOM_CASES; run++) {
		cluster = MIN_CLUSTER << ((run / 4) % 4);
		size = (size_t)cluster * CLUSTERS;
		noise(bytes, size);
		for (index = 0; index < size; index++) {
			if (run % 4 == 1) {
				bytes[index] = (uint8_t)(index % 31);
			} else if (run % 4 == 3 || (run % 4 == 2 && index >= size / 2)) {
				bytes[index] = 0;
			}
		}
		state ^= state << 13;
		state ^= state >> 17;
		state ^= state << 5;
		logical = run % 17 == 0 ? 0 : (size_t)(state % size) + 1;
		if (run % 7 == 0) {
			logical = size;
		}
		initialized = (state >> 9) % (logical + 1);
		if (run % 9 == 0) {
			initialized = logical;
		}
		declared = run % 2 != 0 ? initialized : size;
		check(bytes, declared, logical, initialized, cluster, run % ALIGNMENTS,
		    ANY_KIND, SIZE_MAX, ANY_PHYSICAL);
	}
	free(bytes);
}

static void
admission(void)
{
	struct allocation_model model = {0};
	struct ntfs_environment env = environment(&model), bad_env;
	struct ntfs_write_lznt1_unit_input input, bad_input;
	struct ntfs_write_lznt1_unit *unit = (void *)(uintptr_t)1, *sentinel = unit;
	uint8_t *bytes, *copy;
	uint8_t input_snapshot[sizeof(input)], environment_snapshot[sizeof(env)];
	size_t size = MIN_CLUSTER * CLUSTERS;
	uint32_t invalid[] = {0, MIN_CLUSTER - 1, MIN_CLUSTER + 1, MAX_CLUSTER * 2, UINT32_MAX};
	size_t index;

	bytes = malloc(size + sizeof(unit));
	copy = malloc(size);
	assert(bytes && copy);
	memset(bytes, 'A', size);
	input = (struct ntfs_write_lznt1_unit_input){bytes, size, size, size, MIN_CLUSTER};
	assert(ntfs_write_lznt1_unit_prepare(NULL, &input, &unit) == NTFS_INVALID && unit == sentinel);
	assert(ntfs_write_lznt1_unit_prepare(&env, NULL, &unit) == NTFS_INVALID && unit == sentinel);
	assert(ntfs_write_lznt1_unit_prepare(&env, &input, NULL) == NTFS_INVALID);
	assert(ntfs_write_lznt1_unit_prepare(&env, &input,
	    (void *)(UINTPTR_MAX - 3u)) == NTFS_INVALID);
	assert(ntfs_write_lznt1_unit_prepare((void *)(UINTPTR_MAX - 3u),
	    &input, &unit) == NTFS_INVALID && unit == sentinel);
	for (index = 0; index < sizeof(invalid) / sizeof(*invalid); index++) {
		bad_input = input;
		bad_input.cluster_bytes = invalid[index];
		assert(ntfs_write_lznt1_unit_prepare(&env, &bad_input, &unit) == NTFS_UNSUPPORTED && unit == sentinel);
	}
	bad_env = env;
	bad_env.allocate = NULL;
	assert(ntfs_write_lznt1_unit_prepare(&bad_env, &input, &unit) == NTFS_INVALID && unit == sentinel);
	bad_env = env;
	bad_env.release = NULL;
	assert(ntfs_write_lznt1_unit_prepare(&bad_env, &input, &unit) == NTFS_INVALID && unit == sentinel);
	bad_env = env;
	bad_env.api_version++;
	assert(ntfs_write_lznt1_unit_prepare(&bad_env, &input, &unit) == NTFS_INVALID && unit == sentinel);
	bad_input = input;
	bad_input.source_bytes = SIZE_MAX;
	assert(ntfs_write_lznt1_unit_prepare(&env, &bad_input, &unit) == NTFS_RANGE && unit == sentinel);
	bad_input = input;
	bad_input.logical_bytes++;
	assert(ntfs_write_lznt1_unit_prepare(&env, &bad_input, &unit) == NTFS_RANGE && unit == sentinel);
	bad_input = input;
	bad_input.initialized_bytes++;
	assert(ntfs_write_lznt1_unit_prepare(&env, &bad_input, &unit) == NTFS_RANGE && unit == sentinel);
	bad_input = input;
	bad_input.logical_bytes = 1;
	bad_input.initialized_bytes = 2;
	assert(ntfs_write_lznt1_unit_prepare(&env, &bad_input, &unit) == NTFS_RANGE && unit == sentinel);
	bad_input = input;
	bad_input.source_bytes = 0;
	bad_input.initialized_bytes = 1;
	assert(ntfs_write_lznt1_unit_prepare(&env, &bad_input, &unit) == NTFS_RANGE && unit == sentinel);
	bad_input = input;
	bad_input.source = NULL;
	assert(ntfs_write_lznt1_unit_prepare(&env, &bad_input, &unit) == NTFS_INVALID && unit == sentinel);
	bad_input.source = (void *)(UINTPTR_MAX - 3u);
	assert(ntfs_write_lznt1_unit_prepare(&env, &bad_input, &unit) == NTFS_INVALID && unit == sentinel);
	memcpy(input_snapshot, &input, sizeof(input));
	assert(ntfs_write_lznt1_unit_prepare(&env, &input, (void *)&input) == NTFS_INVALID);
	assert(memcmp(&input, input_snapshot, sizeof(input)) == 0);
	memcpy(environment_snapshot, &env, sizeof(env));
	assert(ntfs_write_lznt1_unit_prepare(&env, &input, (void *)&env) == NTFS_INVALID);
	assert(memcmp(&env, environment_snapshot, sizeof(env)) == 0);
	memcpy(copy, bytes, size);
	input.initialized_bytes = 1;
	assert(ntfs_write_lznt1_unit_prepare(&env, &input, (void *)(bytes + size - sizeof(unit))) == NTFS_INVALID);
	assert(memcmp(bytes, copy, size) == 0 && model.calls == 0);
	model.fail = true;
	assert(ntfs_write_lznt1_unit_prepare(&env, &input, &unit) == NTFS_NO_MEMORY && unit == NULL);
	assert(model.calls == 1 && model.live == 0 && model.releases == 0 && model.reads == 0);
	assert(memcmp(bytes, copy, size) == 0);
	model.fail = false;
	assert(ntfs_write_lznt1_unit_prepare(&env, &input, (void *)(bytes + size)) == NTFS_OK);
	memcpy(&unit, bytes + size, sizeof(unit));
	assert(unit && memcmp(bytes, copy, size) == 0);
	ntfs_write_lznt1_unit_close(unit);
	assert(model.live == 0 && model.releases == 1 && model.reads == 0);
	input = (struct ntfs_write_lznt1_unit_input){NULL, 0, 1, 0, MIN_CLUSTER};
	assert(ntfs_write_lznt1_unit_prepare(&env, &input, &unit) == NTFS_OK);
	assert(ntfs_write_lznt1_unit_view(unit)->kind == NTFS_WRITE_LZNT1_UNIT_SPARSE);
	ntfs_write_lznt1_unit_close(unit);
	assert(model.live == 0 && model.releases == 2 && model.reads == 0);
	assert(ntfs_write_lznt1_unit_view(NULL) == NULL);
	ntfs_write_lznt1_unit_close(NULL);
	free(copy);
	free(bytes);
}

int
main(int argc, char **argv)
{
	assert(argc == 1 || argc == 2);
	corpus = argc == 2 ? argv[1] : NULL;
	assert(setvbuf(stdout, NULL, _IONBF, 0) == 0);
	content_cases();
	padding_cases();
	randomized_cases();
	admission();
	printf("PASS: %zu owned LZNT1 units, geometry, padding, VDL, guards, aliases and allocation failure\n", checks);
	if (corpus != NULL) {
		printf("Exported %zu independently verified padded unit packet pairs\n", exported);
	}
	return 0;
}
