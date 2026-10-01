/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "image.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static enum ntfs_result
image_read(void *context, uint64_t offset, void *buffer, size_t length)
{
	struct ntfs_image *image = context;
	uint8_t *bytes = buffer;
	ssize_t count;

	if (offset > image->environment.size_bytes ||
	    length > image->environment.size_bytes - offset) {
		return NTFS_IO;
	}
	while (length != 0) {
		count = pread(image->fd, bytes, length, (off_t)offset);
		if (count < 0 && errno == EINTR) {
			continue;
		}
		if (count <= 0) {
			return NTFS_IO;
		}
		offset += (size_t)count;
		bytes += count;
		length -= (size_t)count;
	}
	return NTFS_OK;
}

static void *
image_allocate(void *context, size_t size)
{
	(void)context;
	return malloc(size);
}

static void
image_release(void *context, void *buffer, size_t size)
{
	(void)context;
	(void)size;
	free(buffer);
}

int
ntfs_image_open(const char *path, struct ntfs_image *image)
{
	struct stat st;
	int saved;

	*image = (struct ntfs_image){.fd = -1};
	image->fd = open(path, O_RDONLY | O_CLOEXEC);
	if (image->fd < 0) {
		return errno;
	}
	if (fstat(image->fd, &st) != 0) {
		saved = errno;
		close(image->fd);
		image->fd = -1;
		return saved;
	}
	if (!S_ISREG(st.st_mode) || st.st_size < 0) {
		close(image->fd);
		image->fd = -1;
		return EINVAL;
	}
	image->environment = (struct ntfs_environment){NTFS_API_VERSION, image,
	    (uint64_t)st.st_size, image_read, image_allocate, image_release};
	return 0;
}

void
ntfs_image_close(struct ntfs_image *image)
{
	if (image->fd >= 0) {
		close(image->fd);
		image->fd = -1;
	}
}
