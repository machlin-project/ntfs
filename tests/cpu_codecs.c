/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/wof.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { ALIGNMENTS = 32, PATH_BYTES = 1024, NAME_BYTES = 128, CODEC_BYTES = 16, GUARD = 0xa5 };

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
	assert(length > 0 && fseek(file, 0, SEEK_SET) == 0);
	*size = (size_t)length;
	bytes = malloc(*size);
	assert(bytes != NULL && fread(bytes, 1, *size, file) == *size);
	assert(fclose(file) == 0);
	return bytes;
}

int
main(int argc, char **argv)
{
	char path[PATH_BYTES], codec[CODEC_BYTES], name[NAME_BYTES];
	FILE *manifest;
	uint8_t *packed, *expected, *input, *output, *workspace;
	size_t size, expected_size, workspace_size, alignment, done, index, count = 0;
	enum ntfs_result result;
	int length;

	assert(argc == 2);
	length = snprintf(path, sizeof(path), "%s/cases.txt", argv[1]);
	assert(length > 0 && (size_t)length < sizeof(path));
	manifest = fopen(path, "r");
	assert(manifest != NULL);
	workspace_size = ntfs_lzx_workspace_size();
	if (workspace_size < ntfs_xpress_workspace_size()) {
		workspace_size = ntfs_xpress_workspace_size();
	}
	workspace = malloc(workspace_size);
	assert(workspace != NULL);
	while (fscanf(manifest, "%15s %127s", codec, name) == 2) {
		packed = load(argv[1], name, ".packed", &size);
		expected = load(argv[1], name, ".data", &expected_size);
		for (alignment = 0; alignment < ALIGNMENTS; alignment++) {
			/* Exact allocation ends make even one-byte speculative reads fail ASan. */
			input = malloc(size + alignment);
			output = malloc(expected_size + alignment);
			assert(input != NULL && output != NULL);
			memcpy(input + alignment, packed, size);
			memset(output, GUARD, expected_size + alignment);
			if (strcmp(codec, "lznt1") == 0) {
				result = ntfs_lznt1_decode(input + alignment, size,
				    output + alignment, expected_size, &done);
			} else if (strcmp(codec, "xpress") == 0) {
				result = ntfs_xpress_huffman_decode(input + alignment, size,
				    output + alignment, expected_size, workspace, workspace_size,
				    &done);
			} else {
				assert(strcmp(codec, "lzx") == 0);
				result =
				    ntfs_lzx_decode(input + alignment, size, output + alignment,
					expected_size, workspace, workspace_size, &done);
			}
			if (result != NTFS_OK || done != expected_size ||
			    memcmp(output + alignment, expected, expected_size) != 0) {
				fprintf(stderr, "%s alignment=%zu result=%u written=%zu\n", name,
				    alignment, result, done);
				abort();
			}
			for (index = 0; index < alignment; index++) {
				assert(output[index] == GUARD);
			}
			assert(memcmp(input + alignment, packed, size) == 0);
			free(output);
			free(input);
		}
		free(expected);
		free(packed);
		count++;
	}
	assert(feof(manifest) && fclose(manifest) == 0 && count > 0);
	free(workspace);
	printf("PASS: %zu independent codec packets at %u alignments with exact allocation ends\n",
	    count, ALIGNMENTS);
	return 0;
}
