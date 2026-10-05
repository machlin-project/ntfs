/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_OVERWRITE_IMAGE_H
#define MACHLIN_NTFS_OVERWRITE_IMAGE_H
#include <ntfs/overwrite.h>

/* Private offline-image transport. The caller owns the image and excludes
 * uncooperative access/mappings; flock excludes other cooperating owners.
 * This transport never opens devices, creates/truncates files or changes modes. */
struct ntfs_overwrite_image {
	int fd;
	bool claimed, uncertain;
	struct ntfs_overwrite_environment environment;
};

int ntfs_overwrite_image_open(const char *, struct ntfs_overwrite_image *);
void ntfs_overwrite_image_close(struct ntfs_overwrite_image *);
#endif
