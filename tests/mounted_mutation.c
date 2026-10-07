/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Run only on the explicitly selected installed FSKit image mount. Byte
 * expectations come from separate files outside that mount, never the writer. */
enum {
	WRITE_OFFSET = 257,
	WRITE_BYTES = 65537,
	FILE_BYTES = WRITE_OFFSET + WRITE_BYTES,
	SHRINK_BYTES = 19,
	MAPPED_OFFSET = 3997,
	MAPPED_BYTES = 257,
	REUSE_CYCLES = 16,
	FILE_MODE = 0600,
	DIRECTORY_MODE = 0700,
	READ_WINDOW = 4096
};

static const char namespace_name[] = "MachlinNativeMutation";

#define CHECK(condition)                                                                           \
	do {                                                                                       \
		if (!(condition)) {                                                                \
			fprintf(stderr, "%s:%u: %s (errno %d)\n", __FILE__, __LINE__, #condition,  \
			    errno);                                                                \
			exit(EXIT_FAILURE);                                                        \
		}                                                                                  \
	} while (0)

static void
read_exact(int fd, uint8_t *bytes, size_t length)
{
	size_t offset = 0, amount;
	ssize_t completed;
	struct stat stat;

	CHECK(fstat(fd, &stat) == 0 && S_ISREG(stat.st_mode) && stat.st_size == (off_t)length);
	while (offset < length) {
		amount = length - offset > READ_WINDOW ? READ_WINDOW : length - offset;
		completed = pread(fd, bytes + offset, amount, (off_t)offset);
		CHECK(completed > 0 && (size_t)completed <= amount);
		offset += (size_t)completed;
	}
}

static uint8_t *
oracle(const char *path, size_t length)
{
	uint8_t *bytes = malloc(length);
	int fd;

	CHECK(bytes != NULL);
	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	CHECK(fd >= 0);
	read_exact(fd, bytes, length);
	CHECK(close(fd) == 0);
	return bytes;
}

static void
same_contents(int fd, const uint8_t *expected, uint8_t *scratch)
{
	read_exact(fd, scratch, FILE_BYTES);
	CHECK(memcmp(scratch, expected, FILE_BYTES) == 0);
}

static ino_t
metadata(const char *stage, int fd, bool directory)
{
	struct stat stat;

	CHECK(fstat(fd, &stat) == 0 &&
	    (directory ? S_ISDIR(stat.st_mode) : S_ISREG(stat.st_mode)) &&
	    stat.st_uid == getuid() && stat.st_gid == getgid() &&
	    (stat.st_mode & ALLPERMS) == (directory ? DIRECTORY_MODE : FILE_MODE));
	printf("{\"stage\":\"%s\",\"inode\":%llu,\"bytes\":%lld,\"links\":%u,"
	       "\"directory\":%s,\"uid\":%u,\"gid\":%u,\"mode\":%u,"
	       "\"modifiedSeconds\":%lld,\"modifiedNanoseconds\":%ld,"
	       "\"changedSeconds\":%lld,\"changedNanoseconds\":%ld}\n",
	    stage, (unsigned long long)stat.st_ino, (long long)stat.st_size, stat.st_nlink,
	    directory ? "true" : "false", stat.st_uid, stat.st_gid, stat.st_mode & ALLPERMS,
	    (long long)stat.st_mtimespec.tv_sec, stat.st_mtimespec.tv_nsec,
	    (long long)stat.st_ctimespec.tv_sec, stat.st_ctimespec.tv_nsec);
	return stat.st_ino;
}

static int
directory_at(int parent, const char *name)
{
	int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);

	CHECK(fd >= 0);
	return fd;
}

static int
create_at(int parent, const char *name)
{
	int fd =
	    openat(parent, name, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, FILE_MODE);

	CHECK(fd >= 0);
	return fd;
}

static void
absent_at(int parent, const char *name)
{
	struct stat stat;

	errno = 0;
	CHECK(fstatat(parent, name, &stat, AT_SYMLINK_NOFOLLOW) == -1 && errno == ENOENT);
}

static void
mutation(int parent, const uint8_t *payload, const uint8_t *final, uint8_t *scratch)
{
	uint8_t *expected = calloc(1, FILE_BYTES);
	uint8_t *mappedRead, *mappedWrite;
	ino_t identity, directoryIdentity, previous = 0;
	int root, left, right, nested, deep, fd, observer, victim, temporary;
	size_t index;

	CHECK(expected != NULL);
	absent_at(parent, namespace_name);
	CHECK(mkdirat(parent, namespace_name, DIRECTORY_MODE) == 0);
	root = directory_at(parent, namespace_name);
	(void)metadata("created-root-directory", root, true);
	CHECK(mkdirat(root, "left", DIRECTORY_MODE) == 0);
	CHECK(mkdirat(root, "right", DIRECTORY_MODE) == 0);
	left = directory_at(root, "left");
	right = directory_at(root, "right");
	CHECK(mkdirat(left, "nested", DIRECTORY_MODE) == 0);
	nested = directory_at(left, "nested");
	directoryIdentity = metadata("created-nested-directory", nested, true);
	CHECK(mkdirat(nested, "deep", DIRECTORY_MODE) == 0);
	deep = directory_at(nested, "deep");
	fd = create_at(deep, "data.bin");
	identity = metadata("created-file", fd, false);
	CHECK(pwrite(fd, payload, WRITE_BYTES, WRITE_OFFSET) == WRITE_BYTES && fsync(fd) == 0);
	memcpy(expected + WRITE_OFFSET, payload, WRITE_BYTES);
	same_contents(fd, expected, scratch);
	CHECK(metadata("growing-write", fd, false) == identity);
	CHECK(ftruncate(fd, SHRINK_BYTES) == 0 && fsync(fd) == 0);
	CHECK(metadata("shrink", fd, false) == identity);
	CHECK(ftruncate(fd, FILE_BYTES) == 0 && fsync(fd) == 0);
	memset(expected, 0, FILE_BYTES);
	same_contents(fd, expected, scratch);
	CHECK(pwrite(fd, payload, WRITE_BYTES, WRITE_OFFSET) == WRITE_BYTES && fsync(fd) == 0);
	memcpy(expected + WRITE_OFFSET, payload, WRITE_BYTES);
	observer = openat(deep, "data.bin", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	CHECK(observer >= 0);
	mappedRead = mmap(NULL, FILE_BYTES, PROT_READ, MAP_SHARED, observer, 0);
	mappedWrite = mmap(NULL, FILE_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	CHECK(mappedRead != MAP_FAILED && mappedWrite != MAP_FAILED &&
	    memcmp(mappedRead, expected, FILE_BYTES) == 0);
	CHECK(close(fd) == 0);
	memcpy(mappedWrite + MAPPED_OFFSET, final + MAPPED_OFFSET, MAPPED_BYTES);
	CHECK(msync(mappedWrite, FILE_BYTES, MS_SYNC) == 0 && fsync(observer) == 0);
	same_contents(observer, final, scratch);
	CHECK(memcmp(mappedRead, final, FILE_BYTES) == 0 &&
	    memcmp(mappedWrite, final, FILE_BYTES) == 0);
	CHECK(metadata("mapping-after-writer-close", observer, false) == identity);
	CHECK(munmap(mappedWrite, FILE_BYTES) == 0 && munmap(mappedRead, FILE_BYTES) == 0);
	/* The explicit current contract refuses retirement with an admitted open.
	 * This records an unsupported operation separately from completed writes. */
	errno = 0;
	CHECK(unlinkat(deep, "data.bin", 0) == -1 && errno == ENOTSUP);
	puts("{\"stage\":\"open-unlink\",\"result\":\"UNSUPPORTED\"}");
	CHECK(close(observer) == 0);
	CHECK(renameat(left, "nested", right, "moved") == 0);
	absent_at(left, "nested");
	CHECK(metadata("held-directory-after-move", nested, true) == directoryIdentity);
	fd = openat(deep, "data.bin", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	CHECK(fd >= 0 && metadata("held-descendant-after-move", fd, false) == identity);
	same_contents(fd, final, scratch);
	CHECK(close(fd) == 0);
	victim = create_at(right, "final.bin");
	CHECK(metadata("replacement-victim", victim, false) != identity);
	CHECK(close(victim) == 0);
	CHECK(renameat(deep, "data.bin", right, "final.bin") == 0);
	absent_at(deep, "data.bin");
	fd = openat(right, "final.bin", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	CHECK(fd >= 0 && metadata("replacement-source", fd, false) == identity);
	same_contents(fd, final, scratch);
	CHECK(close(fd) == 0);
	CHECK(close(deep) == 0 && close(nested) == 0);
	errno = 0;
	CHECK(unlinkat(right, "moved", AT_REMOVEDIR) == -1 && errno == ENOTEMPTY);
	CHECK(unlinkat(right, "moved/deep", AT_REMOVEDIR) == 0);
	CHECK(unlinkat(right, "moved", AT_REMOVEDIR) == 0);
	for (index = 0; index < REUSE_CYCLES; index++) {
		temporary = create_at(root, "reuse.bin");
		CHECK(metadata("generation-reuse", temporary, false) != previous);
		{
			struct stat stat;

			CHECK(fstat(temporary, &stat) == 0);
			previous = stat.st_ino;
		}
		CHECK(close(temporary) == 0 && unlinkat(root, "reuse.bin", 0) == 0);
	}
	temporary = create_at(root, "removed.bin");
	CHECK(close(temporary) == 0 && unlinkat(root, "removed.bin", 0) == 0);
	absent_at(root, "removed.bin");
	CHECK(close(left) == 0 && close(right) == 0);
	CHECK(unlinkat(root, "left", AT_REMOVEDIR) == 0);
	CHECK(fsync(root) == 0 && close(root) == 0);
	free(expected);
}

static void
check(int parent, const uint8_t *final, uint8_t *scratch)
{
	int root, right, file;

	root = directory_at(parent, namespace_name);
	(void)metadata("fresh-root-directory", root, true);
	right = directory_at(root, "right");
	file = openat(right, "final.bin", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	CHECK(file >= 0);
	(void)metadata("fresh-final-file", file, false);
	same_contents(file, final, scratch);
	absent_at(root, "left");
	absent_at(root, "removed.bin");
	absent_at(root, "reuse.bin");
	absent_at(right, "moved");
	CHECK(close(file) == 0 && close(right) == 0 && close(root) == 0);
}

int
main(int argc, char **argv)
{
	struct statfs filesystem;
	uint8_t *payload, *final, *scratch;
	int parent;
	bool writing;

	if (argc != 5 || (strcmp(argv[1], "write") != 0 && strcmp(argv[1], "check") != 0)) {
		fprintf(stderr,
		    "Usage: ntfs-mounted-mutation write|check TEST_DIRECTORY PAYLOAD FINAL\n");
		return EXIT_FAILURE;
	}
	CHECK(getuid() == geteuid() && geteuid() != 0);
	writing = strcmp(argv[1], "write") == 0;
	payload = oracle(argv[3], WRITE_BYTES);
	final = oracle(argv[4], FILE_BYTES);
	scratch = malloc(FILE_BYTES);
	CHECK(scratch != NULL);
	parent = open(argv[2], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	CHECK(parent >= 0 && fstatfs(parent, &filesystem) == 0 &&
	    strcmp(filesystem.f_fstypename, "machlinntfs") == 0 &&
	    (filesystem.f_flags & MNT_RDONLY) == 0);
	if (writing) {
		mutation(parent, payload, final, scratch);
	}
	check(parent, final, scratch);
	CHECK(close(parent) == 0);
	free(payload);
	free(final);
	free(scratch);
	puts("{\"result\":\"PASS\",\"nativeSyscalls\":true,\"guiInputUsed\":false}");
	return EXIT_SUCCESS;
}
