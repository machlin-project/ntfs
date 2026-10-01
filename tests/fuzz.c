/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/ntfs.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

struct fuzz_device {
	const uint8_t *data;
	size_t size, memory, reads;
};

union fuzz_allocation {
	max_align_t alignment;
	size_t size;
};

static void *
fuzz_allocate(void *context, size_t size)
{
	struct fuzz_device *d = context;
	union fuzz_allocation *p;

	if (size > 8388608 - d->memory) {
		return NULL;
	}
	p = malloc(sizeof(*p) + size);
	if (p == NULL) {
		return NULL;
	}
	p->size = size;
	d->memory += size;
	return p + 1;
}

static void
fuzz_release(void *context, void *memory, size_t size)
{
	struct fuzz_device *d = context;
	union fuzz_allocation *p = (union fuzz_allocation *)memory - 1;

	assert(p->size == size);
	d->memory -= size;
	free(p);
}

static enum ntfs_result
fuzz_read(void *context, uint64_t offset, void *memory, size_t size)
{
	struct fuzz_device *d = context;

	if (++d->reads > 4096 || offset > d->size || size > d->size - offset) {
		return NTFS_IO;
	}
	memcpy(memory, d->data + offset, size);
	return NTFS_OK;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct fuzz_device d = {data, size, 0, 0};
	struct ntfs_environment env = {
	    NTFS_API_VERSION, &d, size, fuzz_read, fuzz_allocate, fuzz_release};
	struct ntfs_limits limits = {1024, 65536, 4, 128};
	struct ntfs_volume *v = NULL;
	struct ntfs_node *root = NULL, *node = NULL;
	struct ntfs_directory *directory = NULL;
	struct ntfs_stream *stream = NULL;
	struct ntfs_dirent entry;
	uint8_t buffer[1024];
	size_t i, count;

	if (ntfs_mount(&env, &limits, &v) == NTFS_OK && ntfs_root(v, &root) == NTFS_OK &&
	    ntfs_directory_open(root, &directory) == NTFS_OK) {
		for (i = 0; i < 64 && ntfs_directory_next(directory, &entry) == NTFS_OK; i++) {
			if (ntfs_node_open(v, entry.reference, &node) == NTFS_OK) {
				if (ntfs_stream_open(node, NULL, 0, &stream) == NTFS_OK) {
					(void)ntfs_stream_read(
					    stream, 0, buffer, sizeof(buffer), &count);
					ntfs_stream_close(stream);
					stream = NULL;
				}
				ntfs_node_close(node);
				node = NULL;
			}
		}
	}
	ntfs_directory_close(directory);
	ntfs_node_close(root);
	assert(ntfs_unmount(v) == NTFS_OK && d.memory == 0);
	return 0;
}
#ifdef NTFS_FUZZ_STANDALONE
int
main(int argc, char **argv)
{
	FILE *file;
	uint8_t *data, old;
	long bytes;
	size_t i, offset;
	uint32_t random = 0x85a7f12d;

	assert(argc == 2);
	file = fopen(argv[1], "rb");
	assert(file != NULL);
	assert(fseek(file, 0, SEEK_END) == 0);
	bytes = ftell(file);
	assert(bytes > 0);
	rewind(file);
	data = malloc((size_t)bytes);
	assert(data != NULL);
	assert(fread(data, 1, (size_t)bytes, file) == (size_t)bytes);
	fclose(file);
	LLVMFuzzerTestOneInput(data, (size_t)bytes);
	for (i = 0; i < 2000; i++) {
		random = random * 1664525u + 1013904223u;
		offset = random % ((size_t)bytes < 524288 ? (size_t)bytes : 524288);
		old = data[offset];
		data[offset] ^= (uint8_t)(1u << (i % 8));
		LLVMFuzzerTestOneInput(data, (size_t)bytes);
		data[offset] = old;
	}
	free(data);
	puts("PASS: 2000 deterministic image mutations with bounded memory/I/O");
	return 0;
}
#endif
