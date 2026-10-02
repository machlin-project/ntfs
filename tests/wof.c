/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/wof.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	BYTE_BITS = 8,
	CODE_LENGTH_BYTES = 256,
	LOOKAHEAD_BYTES = 2 * sizeof(uint16_t),
	GUARD_BYTES = sizeof(max_align_t),
	GUARD_VALUE = 0xa5,
	PATH_BYTES = 1024,
	CASE_NAME_BYTES = 128,
	UNSUPPORTED_ALGORITHM = 4,
	FUTURE_VERSION = 2,
	TRAILING_BYTES = 16,
	WORKSPACE_CEILING = 2048,
	UNIT_4K_BYTES = 4096,
	UNIT_8K_BYTES = 8192,
	UNIT_16K_BYTES = 16384,
	UNIT_32K_BYTES = 32768,
	SMALL_CHUNKS = 3,
	PACKED_CHUNK_BYTES = 100,
	FINAL_CHUNK_BYTES = 3,
	OVERSUBSCRIBED_LENGTH_BYTE = 0x11
};

struct test_wof_packet {
	uint8_t tag[sizeof(uint32_t)], length[sizeof(uint16_t)], reserved[sizeof(uint16_t)];
	uint8_t version[sizeof(uint32_t)], provider[sizeof(uint32_t)];
	uint8_t provider_version[sizeof(uint32_t)], algorithm[sizeof(uint32_t)];
};

static void
store_integer(uint8_t *bytes, size_t size, uint64_t value)
{
	size_t i;

	for (i = 0; i < size; i++) {
		bytes[i] = (uint8_t)(value >> (i * BYTE_BITS));
	}
}

static void
metadata(void)
{
	static const uint32_t units[] = {
	    UNIT_4K_BYTES, UNIT_32K_BYTES, UNIT_8K_BYTES, UNIT_16K_BYTES};
	struct test_wof_packet packet = {0};
	struct ntfs_wof_info info, zero = {0};
	uint8_t future[sizeof(packet) + sizeof(uint32_t)], unaligned[sizeof(packet) + 1];
	size_t i;

	store_integer(packet.tag, sizeof(packet.tag), NTFS_REPARSE_TAG_WOF);
	store_integer(packet.length, sizeof(packet.length),
	    sizeof(packet) - offsetof(struct test_wof_packet, version));
	store_integer(packet.reserved, sizeof(packet.reserved), UINT16_MAX);
	store_integer(packet.version, sizeof(packet.version), NTFS_WOF_CURRENT_VERSION);
	store_integer(packet.provider, sizeof(packet.provider), NTFS_WOF_PROVIDER_FILE);
	store_integer(packet.provider_version, sizeof(packet.provider_version),
	    NTFS_WOF_FILE_CURRENT_VERSION);
	for (i = 0; i < sizeof(units) / sizeof(units[0]); i++) {
		store_integer(packet.algorithm, sizeof(packet.algorithm), i);
		assert(ntfs_wof_decode(&packet, sizeof(packet), &info) == NTFS_OK);
		assert(info.algorithm == i && info.unit_size == units[i] &&
		    info.provider == NTFS_WOF_PROVIDER_FILE);
		memcpy(unaligned + 1, &packet, sizeof(packet));
		assert(ntfs_wof_decode(unaligned + 1, sizeof(packet), &info) == NTFS_OK);
	}
	store_integer(packet.algorithm, sizeof(packet.algorithm), UNSUPPORTED_ALGORITHM);
	assert(ntfs_wof_decode(&packet, sizeof(packet), &info) == NTFS_UNSUPPORTED);
	assert(memcmp(&info, &zero, sizeof(info)) == 0);
	store_integer(packet.algorithm, sizeof(packet.algorithm), NTFS_WOF_XPRESS_4K);
	store_integer(packet.provider_version, sizeof(packet.provider_version), FUTURE_VERSION);
	assert(ntfs_wof_decode(&packet, sizeof(packet), &info) == NTFS_UNSUPPORTED);
	store_integer(packet.provider_version, sizeof(packet.provider_version),
	    NTFS_WOF_FILE_CURRENT_VERSION);
	store_integer(packet.version, sizeof(packet.version), FUTURE_VERSION);
	assert(ntfs_wof_decode(&packet, sizeof(packet), &info) == NTFS_UNSUPPORTED);
	store_integer(packet.version, sizeof(packet.version), NTFS_WOF_CURRENT_VERSION);
	store_integer(packet.provider, sizeof(packet.provider), NTFS_WOF_PROVIDER_WIM);
	assert(ntfs_wof_decode(&packet, sizeof(packet), &info) == NTFS_UNSUPPORTED);
	store_integer(packet.provider, sizeof(packet.provider), NTFS_WOF_PROVIDER_FILE);
	for (i = 0; i < sizeof(packet); i++) {
		store_integer(packet.length, sizeof(packet.length),
		    i >= offsetof(struct test_wof_packet, version)
			? i - offsetof(struct test_wof_packet, version)
			: 0);
		assert(ntfs_wof_decode(&packet, i, &info) == NTFS_CORRUPT);
		assert(memcmp(&info, &zero, sizeof(info)) == 0);
	}
	memset(future, 0, sizeof(future));
	memcpy(future, &packet, sizeof(packet));
	store_integer(future + offsetof(struct test_wof_packet, length), sizeof(packet.length),
	    sizeof(future) - offsetof(struct test_wof_packet, version));
	assert(ntfs_wof_decode(future, sizeof(future), &info) == NTFS_UNSUPPORTED);
	assert(ntfs_wof_decode(NULL, 0, &info) == NTFS_INVALID);
	assert(ntfs_wof_decode(&packet, sizeof(packet), NULL) == NTFS_INVALID);
}

static void
tables(void)
{
	struct ntfs_wof_layout layout, zero = {0}, forged;
	struct ntfs_wof_span span, empty = {0};
	uint8_t small[(SMALL_CHUNKS - 1) * sizeof(uint32_t)], *large;
	uint64_t logical, stored, offset;
	uint32_t i;
	const uint64_t packed_payload = (SMALL_CHUNKS - 1) * PACKED_CHUNK_BYTES + FINAL_CHUNK_BYTES;

	assert(ntfs_wof_layout_init(NTFS_WOF_XPRESS_4K, 0, 0, 0, &layout) == NTFS_OK);
	assert(layout.chunks == 0 && ntfs_wof_table_validate(&layout, NULL, 0) == NTFS_OK);
	assert(ntfs_wof_chunk_span(&layout, 0, 0, 0, &span) == NTFS_RANGE);
	assert(memcmp(&span, &empty, sizeof(span)) == 0);
	assert(ntfs_wof_layout_init(
		   NTFS_WOF_XPRESS_4K, NTFS_WOF_UNIT_4K, NTFS_WOF_UNIT_4K, 0, &layout) == NTFS_OK);
	assert(layout.chunks == 1 && layout.table_size == 0);
	assert(ntfs_wof_table_validate(&layout, NULL, 0) == NTFS_OK);
	assert(ntfs_wof_chunk_span(&layout, 0, 0, NTFS_WOF_UNIT_4K, &span) == NTFS_OK &&
	    span.uncompressed);
	assert(ntfs_wof_layout_init(NTFS_WOF_XPRESS_4K,
		   (SMALL_CHUNKS - 1) * NTFS_WOF_UNIT_4K + FINAL_CHUNK_BYTES,
		   sizeof(small) + packed_payload, 0, &layout) == NTFS_OK);
	store_integer(small, sizeof(uint32_t), PACKED_CHUNK_BYTES);
	store_integer(small + sizeof(uint32_t), sizeof(uint32_t), 2 * PACKED_CHUNK_BYTES);
	assert(ntfs_wof_table_validate(&layout, small, sizeof(small)) == NTFS_OK);
	assert(ntfs_wof_chunk_span(&layout, SMALL_CHUNKS - 1, 2 * PACKED_CHUNK_BYTES,
		   packed_payload, &span) == NTFS_OK);
	assert(span.logical_size == FINAL_CHUNK_BYTES &&
	    span.stored_offset == sizeof(small) + 2 * PACKED_CHUNK_BYTES && span.uncompressed);
	store_integer(small + sizeof(uint32_t), sizeof(uint32_t), PACKED_CHUNK_BYTES);
	assert(ntfs_wof_table_validate(&layout, small, sizeof(small)) == NTFS_CORRUPT);
	store_integer(small + sizeof(uint32_t), sizeof(uint32_t), PACKED_CHUNK_BYTES - 1);
	assert(ntfs_wof_table_validate(&layout, small, sizeof(small)) == NTFS_CORRUPT);
	store_integer(small + sizeof(uint32_t), sizeof(uint32_t), 2 * PACKED_CHUNK_BYTES - 1);
	assert(ntfs_wof_table_validate(&layout, small, sizeof(small)) == NTFS_CORRUPT);
	store_integer(small + sizeof(uint32_t), sizeof(uint32_t), UINT32_MAX);
	assert(ntfs_wof_table_validate(&layout, small, sizeof(small)) == NTFS_CORRUPT);
	assert(ntfs_wof_table_validate(&layout, small, sizeof(small) - 1) == NTFS_CORRUPT);
	assert(ntfs_wof_table_validate(&layout, NULL, sizeof(small)) == NTFS_INVALID);
	assert(ntfs_wof_chunk_span(&layout, 0, 1, PACKED_CHUNK_BYTES, &span) == NTFS_CORRUPT);
	assert(ntfs_wof_chunk_span(&layout, SMALL_CHUNKS - 1, 2 * PACKED_CHUNK_BYTES,
		   packed_payload - 1, &span) == NTFS_CORRUPT);
	assert(ntfs_wof_chunk_span(&layout, 1, 0, NTFS_WOF_UNIT_4K + 1, &span) == NTFS_CORRUPT);
	forged = layout;
	forged.table_size++;
	assert(ntfs_wof_chunk_span(&forged, 0, 0, 1, &span) == NTFS_INVALID);
	assert(memcmp(&span, &empty, sizeof(span)) == 0);
	assert(ntfs_wof_layout_init(NTFS_WOF_XPRESS_4K, NTFS_WOF_UNIT_4K + 1, sizeof(uint32_t) + 2,
		   1, &layout) == NTFS_RANGE);
	assert(memcmp(&layout, &zero, sizeof(layout)) == 0);
	assert(ntfs_wof_layout_init(UNSUPPORTED_ALGORITHM, 0, 0, 0, &layout) == NTFS_UNSUPPORTED);
	assert(ntfs_wof_layout_init(NTFS_WOF_XPRESS_4K, 0, 1, 0, &layout) == NTFS_CORRUPT);
	assert(ntfs_wof_layout_init(NTFS_WOF_XPRESS_4K, UINT64_MAX, 0, 0, &layout) == NTFS_CORRUPT);
	assert(ntfs_wof_layout_init(NTFS_WOF_XPRESS_4K, 1, UINT64_MAX, 0, &layout) == NTFS_CORRUPT);
	assert(ntfs_wof_layout_init(NTFS_WOF_XPRESS_4K, 0, 0, NTFS_WOF_MAX_CHUNKS + 1, &layout) ==
	    NTFS_INVALID);
	assert(ntfs_wof_layout_init(NTFS_WOF_XPRESS_4K,
		   (uint64_t)NTFS_WOF_UNIT_4K * NTFS_WOF_DEFAULT_MAX_CHUNKS + 1, 0, 0,
		   &layout) == NTFS_RANGE);
	logical = UINT32_MAX;
	stored = logical + ((logical - 1) / NTFS_WOF_UNIT_32K) * sizeof(uint32_t);
	assert(ntfs_wof_layout_init(NTFS_WOF_LZX_32K, logical, stored, 0, &layout) == NTFS_OK);
	assert(layout.offset_size == sizeof(uint32_t));
	logical = (uint64_t)UINT32_MAX + 1;
	stored = logical + ((logical - 1) / NTFS_WOF_UNIT_32K) * sizeof(uint64_t);
	assert(ntfs_wof_layout_init(NTFS_WOF_LZX_32K, logical, stored, 0, &layout) == NTFS_OK);
	assert(layout.offset_size == sizeof(uint64_t));
	logical += NTFS_WOF_UNIT_32K;
	stored = logical + ((logical - 1) / NTFS_WOF_UNIT_32K) * sizeof(uint64_t);
	assert(ntfs_wof_layout_init(NTFS_WOF_LZX_32K, logical, stored, 0, &layout) == NTFS_OK);
	assert(layout.offset_size == sizeof(uint64_t));
	large = malloc((size_t)layout.table_size);
	assert(large != NULL);
	for (i = 0; i < layout.chunks - 1; i++) {
		offset = (uint64_t)(i + 1) * NTFS_WOF_UNIT_32K;
		store_integer(large + (size_t)i * sizeof(uint64_t), sizeof(uint64_t), offset);
	}
	assert(ntfs_wof_table_validate(&layout, large, (size_t)layout.table_size) == NTFS_OK);
	store_integer(
	    large + (size_t)(layout.chunks - 2) * sizeof(uint64_t), sizeof(uint64_t), UINT64_MAX);
	assert(ntfs_wof_table_validate(&layout, large, (size_t)layout.table_size) == NTFS_CORRUPT);
	free(large);
}

static uint8_t *
load(const char *directory, const char *name, const char *suffix, size_t *size)
{
	char path[PATH_BYTES];
	FILE *file;
	long length;
	uint8_t *bytes;
	int result;

	result = snprintf(path, sizeof(path), "%s/%s%s", directory, name, suffix);
	assert(result > 0 && (size_t)result < sizeof(path));
	file = fopen(path, "rb");
	assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
	length = ftell(file);
	assert(length >= 0 && fseek(file, 0, SEEK_SET) == 0);
	*size = (size_t)length;
	bytes = malloc(*size + TRAILING_BYTES);
	assert(bytes != NULL && fread(bytes, 1, *size, file) == *size);
	assert(fclose(file) == 0);
	return bytes;
}

static void
guards(const uint8_t *bytes, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++) {
		assert(bytes[i] == GUARD_VALUE);
	}
}

static void
codec(const char *directory, bool invalid)
{
	char name[CASE_NAME_BYTES];
	FILE *manifest;
	uint8_t *packed, *original, *output, *scratch, *workspace;
	size_t packed_size, original_size, workspace_size, done, count = 0, i;
	uint8_t *manifest_bytes;
	size_t manifest_size;

	/* Open the controlled case list through the same checked path helper. */
	manifest_bytes = load(directory, "cases", ".txt", &manifest_size);
	manifest = tmpfile();
	assert(manifest != NULL &&
	    fwrite(manifest_bytes, 1, manifest_size, manifest) == manifest_size);
	assert(fseek(manifest, 0, SEEK_SET) == 0);
	free(manifest_bytes);
	workspace_size = ntfs_xpress_workspace_size();
	assert(workspace_size < WORKSPACE_CEILING &&
	    GUARD_BYTES % ntfs_xpress_workspace_alignment() == 0);
	scratch = malloc(workspace_size + 2 * GUARD_BYTES);
	assert(scratch != NULL);
	workspace = scratch + GUARD_BYTES;
	while (fgets(name, sizeof(name), manifest) != NULL) {
		name[strcspn(name, "\n")] = '\0';
		packed = load(directory, name, ".xpress", &packed_size);
		original = load(directory, name, ".data", &original_size);
		output = malloc(original_size + 2 * GUARD_BYTES);
		assert(output != NULL);
		memset(output, GUARD_VALUE, original_size + 2 * GUARD_BYTES);
		memset(scratch, GUARD_VALUE, workspace_size + 2 * GUARD_BYTES);
		assert(ntfs_xpress_huffman_decode(packed, packed_size, output + GUARD_BYTES,
			   original_size, workspace, workspace_size,
			   &done) == (invalid ? NTFS_CORRUPT : NTFS_OK));
		assert(done == (invalid ? 0 : original_size));
		if (!invalid) {
			assert(memcmp(output + GUARD_BYTES, original, original_size) == 0);
		}
		guards(output, GUARD_BYTES);
		guards(output + GUARD_BYTES + original_size, GUARD_BYTES);
		guards(scratch, GUARD_BYTES);
		guards(scratch + GUARD_BYTES + workspace_size, GUARD_BYTES);
		memset(output, GUARD_VALUE, original_size + 2 * GUARD_BYTES);
		assert(ntfs_xpress_huffman_decode(packed, packed_size, output + GUARD_BYTES,
			   original_size, workspace, workspace_size - 1, &done) == NTFS_RANGE &&
		    done == 0);
		guards(output, original_size + 2 * GUARD_BYTES);
		assert(ntfs_xpress_huffman_decode(packed, packed_size, output + GUARD_BYTES,
			   original_size, workspace + 1, workspace_size, &done) == NTFS_INVALID &&
		    done == 0);
		memset(packed + packed_size, GUARD_VALUE, TRAILING_BYTES);
		assert(ntfs_xpress_huffman_decode(packed, packed_size + TRAILING_BYTES,
			   output + GUARD_BYTES, original_size, workspace, workspace_size,
			   &done) == NTFS_CORRUPT &&
		    done == 0);
		for (i = 0; i < CODE_LENGTH_BYTES + LOOKAHEAD_BYTES; i++) {
			assert(
			    ntfs_xpress_huffman_decode(packed, i, output + GUARD_BYTES,
				original_size, workspace, workspace_size, &done) == NTFS_CORRUPT &&
			    done == 0);
		}
		free(output);
		free(original);
		free(packed);
		count++;
	}
	assert(fclose(manifest) == 0 && count != 0);
	printf("PASS: %zu independent XPRESS %s vectors, scratch/output guards and truncations\n",
	    count, invalid ? "invalid" : "content");
	free(scratch);
}

static void
codec_errors(void)
{
	uint8_t input[CODE_LENGTH_BYTES + LOOKAHEAD_BYTES] = {0}, output[NTFS_WOF_UNIT_4K];
	uint8_t *workspace;
	size_t workspace_size, done;

	workspace_size = ntfs_xpress_workspace_size();
	workspace = malloc(workspace_size);
	assert(workspace != NULL);
	assert(ntfs_xpress_huffman_decode(input, sizeof(input), output, sizeof(output), workspace,
		   workspace_size, &done) == NTFS_CORRUPT &&
	    done == 0);
	memset(input, OVERSUBSCRIBED_LENGTH_BYTE, CODE_LENGTH_BYTES);
	assert(ntfs_xpress_huffman_decode(input, sizeof(input), output, sizeof(output), workspace,
		   workspace_size, &done) == NTFS_CORRUPT &&
	    done == 0);
	assert(ntfs_xpress_huffman_decode(input, sizeof(input), output, NTFS_XPRESS_MAX_BLOCK + 1,
		   workspace, workspace_size, &done) == NTFS_RANGE &&
	    done == 0);
	assert(ntfs_xpress_huffman_decode(NULL, 1, output, sizeof(output), workspace,
		   workspace_size, &done) == NTFS_INVALID &&
	    done == 0);
	assert(ntfs_xpress_huffman_decode(input, sizeof(input), NULL, 1, workspace, workspace_size,
		   &done) == NTFS_INVALID &&
	    done == 0);
	assert(ntfs_xpress_huffman_decode(input, sizeof(input), output, sizeof(output), NULL,
		   workspace_size, &done) == NTFS_INVALID &&
	    done == 0);
	assert(ntfs_xpress_huffman_decode(input, sizeof(input), output, sizeof(output), workspace,
		   workspace_size, NULL) == NTFS_INVALID);
	free(workspace);
}

int
main(int argc, char **argv)
{
	assert(argc == 3);
	metadata();
	tables();
	codec(argv[1], false);
	codec(argv[2], true);
	codec_errors();
	puts("PASS: WOF provider framing, bounded layouts, cumulative tables and 4-GiB widths");
	return 0;
}
