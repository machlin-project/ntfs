/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/ntfs.h>
#include "image.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

static enum ntfs_result
resolve(struct ntfs_volume *v, const char *path, struct ntfs_node **out)
{
	struct ntfs_node *node = NULL, *child = NULL;
	uint16_t name[NTFS_NAME_MAX];
	const char *end;
	size_t length;
	enum ntfs_result result;

	result = ntfs_root(v, &node);
	*out = NULL;
	while (result == NTFS_OK && *path != 0) {
		if (*path == '/') {
			path++;
			continue;
		}
		end = strchr(path, '/');
		if (end == NULL) {
			end = path + strlen(path);
		}
		result =
		    ntfs_utf8_to_utf16(path, (size_t)(end - path), name, NTFS_NAME_MAX, &length);
		if (result == NTFS_OK) {
			result = ntfs_lookup(node, name, length, &child);
		}
		ntfs_node_close(node);
		node = child;
		child = NULL;
		path = end;
	}
	if (result != NTFS_OK) {
		ntfs_node_close(node);
		return result;
	}
	*out = node;
	return NTFS_OK;
}

int
main(int argc, char **argv)
{
	struct ntfs_image image;
	struct ntfs_volume *v = NULL;
	struct ntfs_node *node = NULL;
	struct ntfs_stream *stream = NULL;
	struct ntfs_directory *directory = NULL;
	struct ntfs_info info;
	struct ntfs_stat st;
	struct ntfs_dirent entry;
	uint16_t stream_name[NTFS_NAME_MAX];
	char name[NTFS_UTF8_NAME_MAX + 1];
	uint8_t *buffer = NULL;
	size_t done, length = 0;
	uint64_t offset = 0, free_clusters;
	enum ntfs_result result;
	int error;

	if (argc < 3) {
		fprintf(stderr, "usage: ntfs-inspect IMAGE info|ls|stat|cat [PATH] [STREAM]\n");
		return 2;
	}
	error = ntfs_image_open(argv[1], &image);
	if (error != 0) {
		fprintf(stderr, "image: %s\n", strerror(error));
		return 1;
	}
	result = ntfs_mount(&image.environment, NULL, &v);
	if (result != NTFS_OK) {
		goto finish;
	}
	if (strcmp(argv[2], "info") == 0) {
		ntfs_get_info(v, &info);
		result = ntfs_count_free_clusters(v, &free_clusters);
		if (result == NTFS_OK) {
			printf("NTFS "
			       "%u.%u\nlabel=%s\nsector=%u\ncluster=%u\nrecord=%u\nindex=%u\nbytes="
			       "%" PRIu64 "\nfree_clusters=%" PRIu64 "\n",
			    info.major_version, info.minor_version, info.label, info.sector_size,
			    info.cluster_size, info.record_size, info.index_size, info.size_bytes,
			    free_clusters);
		}
		goto finish;
	}
	result = resolve(v, argc > 3 ? argv[3] : "/", &node);
	if (result != NTFS_OK) {
		goto finish;
	}
	if (strcmp(argv[2], "stat") == 0) {
		result = ntfs_node_stat(node, &st);
		if (result == NTFS_OK) {
			printf("reference=%" PRIu64 "\nsize=%" PRIu64 "\nallocated=%" PRIu64
			       "\nlinks=%u\ndirectory=%d\n",
			    st.reference, st.size, st.allocated_size, st.links, st.directory);
		}
	} else if (strcmp(argv[2], "ls") == 0) {
		result = ntfs_directory_open(node, &directory);
		if (result != NTFS_OK) {
			goto finish;
		}
		while ((result = ntfs_directory_next(directory, &entry)) == NTFS_OK) {
			if (entry.name_namespace == 2) {
				continue;
			}
			result = ntfs_utf16_to_utf8(
			    entry.name, entry.name_length, name, NTFS_UTF8_NAME_MAX, &done);
			if (result != NTFS_OK) {
				break;
			}
			name[done] = 0;
			printf("%s\n", name);
		}
		if (result == NTFS_END) {
			result = NTFS_OK;
		}
	} else if (strcmp(argv[2], "cat") == 0) {
		if (argc > 4) {
			result = ntfs_utf8_to_utf16(
			    argv[4], strlen(argv[4]), stream_name, NTFS_NAME_MAX, &length);
		}
		if (result == NTFS_OK) {
			result = ntfs_stream_open(node, stream_name, length, &stream);
		}
		if (result != NTFS_OK) {
			goto finish;
		}
		buffer = malloc(1048576);
		if (buffer == NULL) {
			result = NTFS_NO_MEMORY;
			goto finish;
		}
		do {
			result = ntfs_stream_read(stream, offset, buffer, 1048576, &done);
			if (result != NTFS_OK) {
				break;
			}
			if (fwrite(buffer, 1, done, stdout) != done) {
				result = NTFS_IO;
				break;
			}
			offset += done;
		} while (done != 0);
	} else {
		result = NTFS_INVALID;
	}
finish:
	free(buffer);
	ntfs_directory_close(directory);
	ntfs_stream_close(stream);
	ntfs_node_close(node);
	if (ntfs_unmount(v) != NTFS_OK) {
		result = NTFS_BUSY;
	}
	ntfs_image_close(&image);
	if (result != NTFS_OK) {
		fprintf(stderr, "%s\n", ntfs_result_string(result));
		return 1;
	}
	return 0;
}
