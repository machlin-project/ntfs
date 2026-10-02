/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/wof.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	GUARD_BYTES = sizeof(max_align_t),
	GUARD_VALUE = 0xa5,
	PATH_BYTES = 1024,
	CASE_NAME_BYTES = 128,
	TRAILING_BYTES = 16,
	/* Independent policy ceiling; the query must remain smaller than a unit. */
	WORKSPACE_CEILING = 8192
};

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
	size_t index;

	for (index = 0; index < size; index++) {
		assert(bytes[index] == GUARD_VALUE);
	}
}

static void
codec(const char *directory, bool invalid)
{
	char name[CASE_NAME_BYTES];
	FILE *manifest;
	uint8_t *packed, *saved, *original, *output, *scratch, *workspace, *list;
	size_t packed_size, original_size, workspace_size, done, count = 0, list_size;
	enum ntfs_result result;

	list = load(directory, "cases", ".txt", &list_size);
	manifest = tmpfile();
	assert(manifest != NULL && fwrite(list, 1, list_size, manifest) == list_size);
	assert(fseek(manifest, 0, SEEK_SET) == 0);
	free(list);
	workspace_size = ntfs_lzx_workspace_size();
	assert(workspace_size < WORKSPACE_CEILING &&
	    GUARD_BYTES % ntfs_lzx_workspace_alignment() == 0);
	scratch = malloc(workspace_size + 2 * GUARD_BYTES);
	assert(scratch != NULL);
	workspace = scratch + GUARD_BYTES;
	while (fgets(name, sizeof(name), manifest) != NULL) {
		name[strcspn(name, "\n")] = '\0';
		packed = load(directory, name, ".lzx", &packed_size);
		original = load(directory, name, ".data", &original_size);
		saved = malloc(packed_size + 1);
		output = malloc(original_size + 2 * GUARD_BYTES);
		assert(saved != NULL && output != NULL);
		memcpy(saved, packed, packed_size);
		memset(output, GUARD_VALUE, original_size + 2 * GUARD_BYTES);
		memset(scratch, GUARD_VALUE, workspace_size + 2 * GUARD_BYTES);
		result = ntfs_lzx_decode(packed, packed_size, output + GUARD_BYTES, original_size,
		    workspace, workspace_size, &done);
		if (result != (invalid ? NTFS_CORRUPT : NTFS_OK) ||
		    (!invalid && memcmp(output + GUARD_BYTES, original, original_size) != 0)) {
			fprintf(stderr, "LZX case %s: result=%u done=%zu expected=%zu\n", name,
			    result, done, original_size);
			abort();
		}
		assert(done == (invalid ? 0 : original_size));
		guards(output, GUARD_BYTES);
		guards(output + GUARD_BYTES + original_size, GUARD_BYTES);
		guards(scratch, GUARD_BYTES);
		guards(scratch + GUARD_BYTES + workspace_size, GUARD_BYTES);
		memset(output, GUARD_VALUE, original_size + 2 * GUARD_BYTES);
		assert(ntfs_lzx_decode(packed, packed_size, output + GUARD_BYTES, original_size,
			   workspace, workspace_size - 1, &done) == NTFS_RANGE &&
		    done == 0);
		guards(output, original_size + 2 * GUARD_BYTES);
		assert(ntfs_lzx_decode(packed, packed_size, output + GUARD_BYTES, original_size,
			   workspace + 1, workspace_size, &done) == NTFS_INVALID &&
		    done == 0);
		guards(output, original_size + 2 * GUARD_BYTES);
		memset(packed + packed_size, GUARD_VALUE, TRAILING_BYTES);
		assert(ntfs_lzx_decode(packed, packed_size + TRAILING_BYTES, output + GUARD_BYTES,
			   original_size, workspace, workspace_size, &done) == NTFS_CORRUPT &&
		    done == 0);
		/* A previous failed decode must not poison the next independent unit. */
		assert(ntfs_lzx_decode(packed, packed_size, output + GUARD_BYTES, original_size,
			   workspace, workspace_size, &done) == (invalid ? NTFS_CORRUPT : NTFS_OK));
		if (!invalid) {
			assert(done == original_size &&
			    memcmp(output + GUARD_BYTES, original, original_size) == 0);
		}
		assert(memcmp(packed, saved, packed_size) == 0);
		guards(output, GUARD_BYTES);
		guards(output + GUARD_BYTES + original_size, GUARD_BYTES);
		guards(scratch, GUARD_BYTES);
		guards(scratch + GUARD_BYTES + workspace_size, GUARD_BYTES);
		free(output);
		free(saved);
		free(original);
		free(packed);
		count++;
	}
	assert(fclose(manifest) == 0 && count != 0);
	printf("PASS: %zu independent LZX %s vectors, guards, immutable input and retry\n", count,
	    invalid ? "invalid" : "content");
	printf("LZX scratch: %zu bytes, alignment %zu\n", workspace_size,
	    ntfs_lzx_workspace_alignment());
	free(scratch);
}

static void
arguments(void)
{
	uint8_t input[sizeof(uint16_t)] = {0}, output;
	void *workspace;
	size_t size = ntfs_lzx_workspace_size(), done;

	workspace = malloc(size);
	assert(workspace != NULL);
	assert(ntfs_lzx_decode(NULL, 0, NULL, 0, workspace, size, &done) == NTFS_OK && done == 0);
	assert(ntfs_lzx_decode(input, sizeof(input), &output, NTFS_LZX_MAX_BLOCK + 1, workspace,
		   size, &done) == NTFS_RANGE &&
	    done == 0);
	assert(ntfs_lzx_decode(NULL, 1, &output, 1, workspace, size, &done) == NTFS_INVALID &&
	    done == 0);
	assert(ntfs_lzx_decode(input, sizeof(input), NULL, 1, workspace, size, &done) ==
		NTFS_INVALID &&
	    done == 0);
	assert(
	    ntfs_lzx_decode(input, sizeof(input), &output, 1, NULL, size, &done) == NTFS_INVALID &&
	    done == 0);
	assert(ntfs_lzx_decode(input, sizeof(input), &output, 1, workspace, size, NULL) ==
	    NTFS_INVALID);
	free(workspace);
}

int
main(int argc, char **argv)
{
	assert(argc == 3);
	codec(argv[1], false);
	codec(argv[2], true);
	arguments();
	return 0;
}
