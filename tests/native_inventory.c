/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "image.h"
#include <ntfs/ntfs.h>
#include <ntfs/security.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

enum { DECIMAL_RADIX = 10, MAX_DATA_BYTES = 1024 * 1024, MAX_DESCRIPTOR_BYTES = 65536 };

static void
hex_bytes(const uint8_t *value, size_t bytes)
{
	size_t index;

	putchar('"');
	for (index = 0; index < bytes; index++) {
		printf("%02x", value[index]);
	}
	putchar('"');
}

int
main(int argc, char **argv)
{
	struct ntfs_image image;
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *parent = NULL, *node = NULL;
	struct ntfs_directory *directory = NULL;
	struct ntfs_security *security = NULL;
	struct ntfs_stream *stream = NULL;
	struct ntfs_dirent entry;
	struct ntfs_stat stat;
	uint8_t *data, *descriptor;
	char *tail;
	uint64_t reference;
	size_t units, bytes, actual;
	enum ntfs_result result;

	assert(argc == 3);
	errno = 0;
	reference = strtoull(argv[2], &tail, DECIMAL_RADIX);
	assert(errno == 0 && tail != argv[2] && *tail == '\0' && argv[2][0] != '-');
	assert(ntfs_image_open(argv[1], &image) == 0);
	assert(ntfs_mount(&image.environment, NULL, &volume) == NTFS_OK);
	assert(ntfs_node_open(volume, reference, &parent) == NTFS_OK);
	assert(ntfs_directory_open(parent, &directory) == NTFS_OK);
	while ((result = ntfs_directory_next(directory, &entry)) == NTFS_OK) {
		assert(ntfs_node_open(volume, entry.reference, &node) == NTFS_OK);
		assert(ntfs_node_stat(node, &stat) == NTFS_OK && !stat.directory && !stat.reparse &&
		    stat.reference == entry.reference && stat.links == 1 &&
		    stat.size <= MAX_DATA_BYTES);
		assert(ntfs_security_open(node, &security) == NTFS_OK);
		bytes = ntfs_security_size(security);
		assert(bytes > 0 && bytes <= MAX_DESCRIPTOR_BYTES);
		descriptor = malloc(bytes);
		assert(descriptor != NULL &&
		    ntfs_security_copy(security, descriptor, bytes, &actual) == NTFS_OK &&
		    actual == bytes);
		data = malloc((size_t)stat.size + 1);
		assert(data != NULL && ntfs_stream_open(node, NULL, 0, &stream) == NTFS_OK);
		assert(
		    ntfs_stream_read(stream, 0, data, (size_t)stat.size + 1, &actual) == NTFS_OK &&
		    actual == stat.size);
		printf("{\"reference\":\"%" PRIu64 "\",\"parentReference\":\"%" PRIu64
		       "\",\"size\":%" PRIu64
		       ",\"links\":%u,\"namespace\":%u,\"modifiedSeconds\":\"%" PRId64
		       "\",\"modifiedNanoseconds\":%u,\"nameUnits\":[",
		    stat.reference, entry.parent_reference, stat.size, stat.links,
		    entry.name_namespace, stat.modified.seconds, stat.modified.nanoseconds);
		for (units = 0; units < entry.name_length; units++) {
			printf("%s%u", units == 0 ? "" : ",", entry.name[units]);
		}
		printf("],\"dataHex\":");
		hex_bytes(data, (size_t)stat.size);
		printf(",\"descriptorHex\":");
		hex_bytes(descriptor, bytes);
		puts("}");
		free(data);
		free(descriptor);
		ntfs_stream_close(stream);
		ntfs_security_close(security);
		ntfs_node_close(node);
		node = NULL;
		stream = NULL;
		security = NULL;
	}
	assert(result == NTFS_END);
	ntfs_directory_close(directory);
	ntfs_node_close(parent);
	assert(ntfs_unmount(volume) == NTFS_OK);
	ntfs_image_close(&image);
	return 0;
}
