/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/wof.h>
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { PATH_BYTES = 1024, NAME_BYTES = 128, CODEC_BYTES = 16, GUARD = 0xa5, INPUT_OFFSET = 3 };

typedef enum ntfs_result (*decoder)(const void *, size_t, void *, size_t, void *, size_t, size_t *);

struct context {
	decoder decode;
	void *workspace;
	size_t workspace_size;
#ifdef NTFS_HUFFMAN_REFERENCE
	decoder reference;
	void *reference_workspace;
	size_t reference_workspace_size;
#endif
};

#ifdef NTFS_HUFFMAN_REFERENCE
/* Optional differential run links renamed objects from a frozen Git revision.
 * The reference implementation itself is never copied into project sources. */
size_t reference_xpress_workspace_size(void);
size_t reference_lzx_workspace_size(void);
enum ntfs_result reference_xpress_huffman_decode(
    const void *, size_t, void *, size_t, void *, size_t, size_t *);
enum ntfs_result reference_lzx_decode(
    const void *, size_t, void *, size_t, void *, size_t, size_t *);
#endif

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

static void
check(struct context *context, const uint8_t *packed, size_t size, const uint8_t *expected,
    size_t expected_size, int require_success)
{
	uint8_t *input, *output;
	size_t done, index;
	enum ntfs_result result;
#ifdef NTFS_HUFFMAN_REFERENCE
	uint8_t *reference_output;
	size_t reference_done;
	enum ntfs_result reference_result;
#endif

	/* Exact allocation ends expose any speculative word fetch to ASan. */
	input = malloc(size + INPUT_OFFSET);
	output = malloc(expected_size + INPUT_OFFSET);
	assert(input != NULL && output != NULL);
	memset(input, GUARD, INPUT_OFFSET);
	memcpy(input + INPUT_OFFSET, packed, size);
	memset(output, GUARD, expected_size + INPUT_OFFSET);
	memset(context->workspace, GUARD, context->workspace_size);
	done = SIZE_MAX;
	result = context->decode(input + INPUT_OFFSET, size, output + INPUT_OFFSET, expected_size,
	    context->workspace, context->workspace_size, &done);
	assert(result == NTFS_OK || result == NTFS_CORRUPT);
	assert(done == (result == NTFS_OK ? expected_size : 0));
	if (require_success) {
		assert(result == NTFS_OK);
	}
	if (result == NTFS_OK && expected != NULL) {
		assert(memcmp(output + INPUT_OFFSET, expected, expected_size) == 0);
	}
#ifdef NTFS_HUFFMAN_REFERENCE
	reference_output = malloc(expected_size + INPUT_OFFSET);
	assert(reference_output != NULL);
	memset(reference_output, GUARD, expected_size + INPUT_OFFSET);
	memset(context->reference_workspace, GUARD, context->reference_workspace_size);
	reference_done = SIZE_MAX;
	reference_result = context->reference(input + INPUT_OFFSET, size,
	    reference_output + INPUT_OFFSET, expected_size, context->reference_workspace,
	    context->reference_workspace_size, &reference_done);
	assert(result == reference_result && done == reference_done);
	/* Include the partial output on errors: moving a refill must not publish
	 * an extra literal or match before reporting the same truncation. */
	assert(memcmp(output, reference_output, expected_size + INPUT_OFFSET) == 0);
	free(reference_output);
#endif
	assert(memcmp(input + INPUT_OFFSET, packed, size) == 0);
	for (index = 0; index < INPUT_OFFSET; index++) {
		assert(input[index] == GUARD && output[index] == GUARD);
	}
	free(output);
	free(input);
}

int
main(int argc, char **argv)
{
	char path[PATH_BYTES], codec[CODEC_BYTES], name[NAME_BYTES];
	FILE *manifest;
	struct context context;
	uint8_t *packed, *original;
	size_t size, original_size, index, count = 0, checks = 0;
	int length;

	assert(argc == 2);
	length = snprintf(path, sizeof(path), "%s/cases.txt", argv[1]);
	assert(length > 0 && (size_t)length < sizeof(path));
	manifest = fopen(path, "r");
	assert(manifest != NULL);
	while (fscanf(manifest, "%15s %127s", codec, name) == 2) {
		packed = load(argv[1], name, ".packed", &size);
		original = load(argv[1], name, ".data", &original_size);
		if (strcmp(codec, "xpress") == 0) {
			context.decode = ntfs_xpress_huffman_decode;
			context.workspace_size = ntfs_xpress_workspace_size();
#ifdef NTFS_HUFFMAN_REFERENCE
			context.reference = reference_xpress_huffman_decode;
			context.reference_workspace_size = reference_xpress_workspace_size();
#endif
		} else {
			assert(strcmp(codec, "lzx") == 0);
			context.decode = ntfs_lzx_decode;
			context.workspace_size = ntfs_lzx_workspace_size();
#ifdef NTFS_HUFFMAN_REFERENCE
			context.reference = reference_lzx_decode;
			context.reference_workspace_size = reference_lzx_workspace_size();
#endif
		}
		context.workspace = malloc(context.workspace_size);
		assert(context.workspace != NULL);
#ifdef NTFS_HUFFMAN_REFERENCE
		context.reference_workspace = malloc(context.reference_workspace_size);
		assert(context.reference_workspace != NULL);
#endif
		check(&context, packed, size, original, original_size, 1);
		checks++;
		for (index = 0; index < size; index++) {
			/* Every byte truncation, including odd word ends. */
			check(&context, packed, index, original, original_size, 0);
			/* Cycle the changed bit through every header and payload byte. */
			packed[index] ^= (uint8_t)(1u << (index % CHAR_BIT));
			check(&context, packed, size, NULL, original_size, 0);
			packed[index] ^= (uint8_t)(1u << (index % CHAR_BIT));
			checks += 2;
		}
		free(context.workspace);
#ifdef NTFS_HUFFMAN_REFERENCE
		free(context.reference_workspace);
#endif
		free(original);
		free(packed);
		count++;
	}
	assert(feof(manifest) && fclose(manifest) == 0 && count > 0);
	printf("PASS: %zu Huffman packets, %zu boundary/truncation/mutation checks", count, checks);
#ifdef NTFS_HUFFMAN_REFERENCE
	printf(" with identical reference status, length and partial output");
#endif
	printf("\n");
	return 0;
}
