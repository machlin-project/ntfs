/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* The independent standard/NTFS 3.0 author supplies these exact content files. */
static const char *const names[] = {
    "hello.txt",
    "fragmented.bin",
    "compressed.bin",
    "extended.bin",
    "middle.dat",
    "sparse.bin",
    "streamed.txt",
    "tail.bin",
    "Ωmega.txt",
};

enum {
	FILE_COUNT = sizeof(names) / sizeof(names[0]),
	CONTENT_LIMIT = 1024 * 1024,
	READ_WINDOW = 997,
	READ_GUARD = 0xa6,
	READ_GUARD_BYTES = 1,
	DIRECTORY_STREAM_COUNT = 2,
	FILE_MODE = 0400,
	DIRECTORY_MODE = 0500,
};

_Static_assert(FILE_COUNT < sizeof(uint64_t) * CHAR_BIT, "enumeration mask capacity");

#define CHECK(expression)                                                                          \
	do {                                                                                       \
		if (!(expression)) {                                                               \
			fprintf(stderr, "%s:%d: %s (errno %d)\n", __FILE__, __LINE__, #expression, \
			    errno);                                                                \
			exit(EXIT_FAILURE);                                                        \
		}                                                                                  \
	} while (0)

static ssize_t
read_at(int fd, void *buffer, size_t bytes, off_t offset)
{
	ssize_t result;

	do {
		result = pread(fd, buffer, bytes, offset);
	} while (result < 0 && errno == EINTR);
	return result;
}

static void
check_file(int root, int oracle, size_t index, const struct stat *root_stat)
{
	struct stat expected_stat, actual_stat;
	uint8_t *expected, window[READ_WINDOW + 2 * READ_GUARD_BYTES];
	void *mapping;
	size_t bytes, offset, amount, received;
	ssize_t result;
	int expected_fd, actual_fd, writing, writing_error;

	expected_fd = openat(oracle, names[index], O_RDONLY | O_NOFOLLOW);
	CHECK(expected_fd >= 0 && fstat(expected_fd, &expected_stat) == 0);
	CHECK(S_ISREG(expected_stat.st_mode) && expected_stat.st_size > 0 &&
	    expected_stat.st_size <= CONTENT_LIMIT);
	bytes = (size_t)expected_stat.st_size;
	expected = malloc(bytes);
	CHECK(expected != NULL);
	for (offset = 0; offset < bytes; offset += (size_t)result) {
		result = read_at(expected_fd, expected + offset, bytes - offset, (off_t)offset);
		CHECK(result > 0);
	}
	CHECK(close(expected_fd) == 0);
	actual_fd = openat(root, names[index], O_RDONLY | O_NOFOLLOW);
	CHECK(actual_fd >= 0 && fstat(actual_fd, &actual_stat) == 0);
	CHECK(S_ISREG(actual_stat.st_mode) && actual_stat.st_size == expected_stat.st_size);
	CHECK((actual_stat.st_mode & ALLPERMS) == FILE_MODE);
	CHECK(actual_stat.st_uid == root_stat->st_uid && actual_stat.st_gid == root_stat->st_gid);
	CHECK(actual_stat.st_ino != 0);
	for (offset = 0; offset < bytes; offset += received) {
		amount = bytes - offset < READ_WINDOW ? bytes - offset : READ_WINDOW;
		memset(window, READ_GUARD, sizeof(window));
		result = read_at(actual_fd, window + READ_GUARD_BYTES, amount, (off_t)offset);
		CHECK(result > 0 && (size_t)result <= amount);
		received = (size_t)result;
		CHECK(window[0] == READ_GUARD && window[received + READ_GUARD_BYTES] == READ_GUARD);
		CHECK(memcmp(window + READ_GUARD_BYTES, expected + offset, received) == 0);
	}
	memset(window, READ_GUARD, sizeof(window));
	CHECK(read_at(actual_fd, window + READ_GUARD_BYTES, READ_WINDOW, (off_t)bytes) == 0);
	for (offset = 0; offset < sizeof(window); offset++) {
		CHECK(window[offset] == READ_GUARD);
	}
	mapping = mmap(NULL, bytes, PROT_READ, MAP_PRIVATE, actual_fd, 0);
	CHECK(mapping != MAP_FAILED && memcmp(mapping, expected, bytes) == 0);
	CHECK(munmap(mapping, bytes) == 0);
	errno = 0;
	mapping = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_SHARED, actual_fd, 0);
	CHECK(mapping == MAP_FAILED && (errno == EACCES || errno == EROFS));
	errno = 0;
	writing = openat(root, names[index], O_WRONLY | O_NOFOLLOW);
	writing_error = errno;
	CHECK(writing == -1 && (writing_error == EROFS || writing_error == EACCES));
	CHECK(close(actual_fd) == 0);
	free(expected);
	printf("{\"file\":\"%s\",\"bytes\":%zu,\"writeOpenErrno\":%d}\n", names[index], bytes,
	    writing_error);
}

struct directory_progress {
	uint64_t seen;
	unsigned current, parent;
	bool complete;
};

static void
directory_step(DIR *directory, struct directory_progress *progress)
{
	struct dirent *entry;
	size_t index;
	uint64_t bit;

	if (progress->complete) {
		return;
	}
	errno = 0;
	entry = readdir(directory);
	if (entry == NULL) {
		CHECK(errno == 0);
		progress->complete = true;
		return;
	}
	if (strcmp(entry->d_name, ".") == 0) {
		CHECK(++progress->current == 1);
		return;
	}
	if (strcmp(entry->d_name, "..") == 0) {
		CHECK(++progress->parent == 1);
		return;
	}
	for (index = 0; index < FILE_COUNT; index++) {
		if (strcmp(entry->d_name, names[index]) == 0) {
			break;
		}
	}
	CHECK(index < FILE_COUNT);
	bit = UINT64_C(1) << index;
	CHECK((progress->seen & bit) == 0);
	progress->seen |= bit;
}

static void
check_directories(int root)
{
	struct directory_progress first = {0}, second = {0};
	DIR *left, *right;
	uint64_t all;
	int fd;

	/* Independent open descriptions are needed; dup() would share their offset. */
	fd = openat(root, ".", O_RDONLY | O_DIRECTORY);
	CHECK(fd >= 0);
	left = fdopendir(fd);
	CHECK(left != NULL);
	fd = openat(root, ".", O_RDONLY | O_DIRECTORY);
	CHECK(fd >= 0);
	right = fdopendir(fd);
	CHECK(right != NULL);
	while (!first.complete || !second.complete) {
		directory_step(left, &first);
		directory_step(right, &second);
	}
	all = (UINT64_C(1) << FILE_COUNT) - 1;
	CHECK(first.seen == all && second.seen == all);
	CHECK(first.current == 1 && first.parent == 1 && second.current == 1 && second.parent == 1);
	CHECK(closedir(left) == 0 && closedir(right) == 0);
}

int
main(int argc, char **argv)
{
	struct statfs filesystem;
	struct stat root_stat, canonical, alternate;
	size_t index;
	int root, oracle, creating, create_error;

	if (argc != 3) {
		fprintf(stderr, "Usage: ntfs-mounted-read MOUNT_POINT EXPECTED_DIRECTORY\n");
		return EXIT_FAILURE;
	}
	root = open(argv[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
	oracle = open(argv[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
	CHECK(root >= 0 && oracle >= 0 && fstatfs(root, &filesystem) == 0);
	CHECK(strcmp(filesystem.f_fstypename, "machlinntfs") == 0);
	CHECK((filesystem.f_flags & MNT_RDONLY) != 0 && fstat(root, &root_stat) == 0);
	printf("{\"filesystem\":\"%s\",\"readOnly\":true,\"uid\":%u,\"gid\":%u,\"mode\":%u}\n",
	    filesystem.f_fstypename, root_stat.st_uid, root_stat.st_gid,
	    root_stat.st_mode & ALLPERMS);
	CHECK((root_stat.st_mode & ALLPERMS) == DIRECTORY_MODE);
	check_directories(root);
	for (index = 0; index < FILE_COUNT; index++) {
		check_file(root, oracle, index, &root_stat);
	}
	CHECK(fstatat(root, "hello.txt", &canonical, AT_SYMLINK_NOFOLLOW) == 0);
	CHECK(fstatat(root, "HELLO.TXT", &alternate, AT_SYMLINK_NOFOLLOW) == 0);
	CHECK(canonical.st_ino == alternate.st_ino && canonical.st_dev == alternate.st_dev);
	errno = 0;
	creating = openat(root, ".ntfs-write-refusal", O_CREAT | O_EXCL | O_WRONLY, FILE_MODE);
	create_error = errno;
	CHECK(creating == -1 && (create_error == EROFS || create_error == EACCES));
	CHECK(close(oracle) == 0 && close(root) == 0);
	printf("{\"result\":\"PASS\",\"files\":%u,\"directoryStreams\":%u,\"createErrno\":%d}\n",
	    (unsigned)FILE_COUNT, DIRECTORY_STREAM_COUNT, create_error);
	return EXIT_SUCCESS;
}
