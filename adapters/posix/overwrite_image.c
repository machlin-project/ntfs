/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "overwrite_image.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

static void *
image_allocate(void *context, size_t bytes)
{
	(void)context;
	return malloc(bytes);
}

static void
image_release(void *context, void *buffer, size_t bytes)
{
	(void)context;
	(void)bytes;
	free(buffer);
}

static enum ntfs_result
image_claim(void *context)
{
	struct ntfs_overwrite_image *image = context;

	if (image->uncertain) {
		return NTFS_IO;
	}
	if (image->claimed) {
		return NTFS_BUSY;
	}
	if (flock(image->fd, LOCK_EX | LOCK_NB) != 0) {
		return errno == EWOULDBLOCK ? NTFS_BUSY : NTFS_IO;
	}
	image->claimed = true;
	return NTFS_OK;
}

static void
image_unclaim(void *context)
{
	struct ntfs_overwrite_image *image = context;

	if (image->claimed) {
		if (flock(image->fd, LOCK_UN) != 0) {
			image->uncertain = true;
		}
		image->claimed = false;
	}
}

static enum ntfs_result
image_read(void *context, uint64_t offset, void *buffer, size_t bytes)
{
	struct ntfs_overwrite_image *image = context;
	uint8_t *position = buffer;
	ssize_t transferred;

	if (!image->claimed || image->uncertain || offset > image->environment.reader.size_bytes ||
	    bytes > image->environment.reader.size_bytes - offset) {
		return NTFS_IO;
	}
	while (bytes != 0) {
		transferred = pread(image->fd, position, bytes, (off_t)offset);
		if (transferred < 0 && errno == EINTR) {
			continue;
		}
		if (transferred <= 0) {
			return NTFS_IO;
		}
		offset += (size_t)transferred;
		position += transferred;
		bytes -= (size_t)transferred;
	}
	return NTFS_OK;
}

static enum ntfs_result
image_write(void *context, uint64_t offset, const void *buffer, size_t bytes, size_t *actual)
{
	struct ntfs_overwrite_image *image = context;
	const uint8_t *position = buffer;
	ssize_t transferred;

	*actual = 0;
	if (!image->claimed || image->uncertain || offset > image->environment.reader.size_bytes ||
	    bytes > image->environment.reader.size_bytes - offset) {
		image->uncertain = true;
		return NTFS_IO;
	}
	while (bytes != 0) {
		transferred = pwrite(image->fd, position, bytes, (off_t)offset);
		if (transferred < 0 && errno == EINTR) {
			continue;
		}
		if (transferred <= 0) {
			image->uncertain = true;
			return NTFS_IO;
		}
		offset += (size_t)transferred;
		position += transferred;
		bytes -= (size_t)transferred;
		*actual += (size_t)transferred;
	}
	return NTFS_OK;
}

static enum ntfs_result
image_persist(void *context)
{
	struct ntfs_overwrite_image *image = context;
	int status;

	if (!image->claimed || image->uncertain) {
		return NTFS_IO;
	}
	do {
		status = fsync(image->fd);
	} while (status != 0 && errno == EINTR);
#ifdef __APPLE__
	/* A file-system/cache-only flush cannot substitute for F_FULLFSYNC. */
	if (status == 0) {
		do {
			status = fcntl(image->fd, F_FULLFSYNC);
		} while (status != 0 && errno == EINTR);
	}
#endif
	if (status != 0) {
		image->uncertain = true;
		return NTFS_IO;
	}
	return NTFS_OK;
}

int
ntfs_overwrite_image_open(const char *path, struct ntfs_overwrite_image *image)
{
	struct stat status;
	int saved;

	*image = (struct ntfs_overwrite_image){.fd = -1};
	image->fd = open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
	if (image->fd < 0) {
		return errno;
	}
	if (fstat(image->fd, &status) != 0) {
		saved = errno;
		ntfs_overwrite_image_close(image);
		return saved;
	}
	if (!S_ISREG(status.st_mode) || status.st_size <= 0 || status.st_nlink != 1 ||
	    (status.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) == 0) {
		ntfs_overwrite_image_close(image);
		return EINVAL;
	}
	image->environment =
	    (struct ntfs_overwrite_environment){{NTFS_API_VERSION, image, (uint64_t)status.st_size,
						    image_read, image_allocate, image_release},
		NTFS_OVERWRITE_API_VERSION, NTFS_OVERWRITE_MIN_ALIGNMENT, image_claim,
		image_unclaim, image_write, image_persist};
	return 0;
}

void
ntfs_overwrite_image_close(struct ntfs_overwrite_image *image)
{
	if (image->fd >= 0) {
		image_unclaim(image);
		close(image->fd);
		image->fd = -1;
	}
}
