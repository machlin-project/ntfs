/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "path.h"
#include <stdlib.h>
#include <string.h>

enum ntfs_result
ntfs_tool_resolve(struct ntfs_volume *v, const char *path, struct ntfs_node **out)
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

enum ntfs_result
ntfs_tool_parent(struct ntfs_volume *v, const char *path, struct ntfs_node **out, uint16_t *name,
    size_t *name_length)
{
	const char *last = strrchr(path, '/');
	char *parent;
	size_t bytes;
	enum ntfs_result result;

	*out = NULL;
	if (last == NULL) {
		result = ntfs_utf8_to_utf16(path, strlen(path), name, NTFS_NAME_MAX, name_length);
		if (result == NTFS_OK && *name_length != 0) {
			result = ntfs_root(v, out);
		}
		return result == NTFS_OK && *name_length == 0 ? NTFS_INVALID : result;
	}
	result = ntfs_utf8_to_utf16(last + 1, strlen(last + 1), name, NTFS_NAME_MAX, name_length);
	if (result != NTFS_OK || *name_length == 0) {
		return result == NTFS_OK ? NTFS_INVALID : result;
	}
	bytes = (size_t)(last - path);
	parent = malloc(bytes + 1);
	if (parent == NULL) {
		return NTFS_NO_MEMORY;
	}
	memcpy(parent, path, bytes);
	parent[bytes] = 0;
	result = ntfs_tool_resolve(v, parent, out);
	free(parent);
	return result;
}
