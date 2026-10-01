/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef NTFS_POSIX_IMAGE_H
#define NTFS_POSIX_IMAGE_H
#include <ntfs/ntfs.h>

struct ntfs_image {
	int fd;
	struct ntfs_environment environment;
};

int ntfs_image_open(const char *, struct ntfs_image *);
void ntfs_image_close(struct ntfs_image *);
#endif
