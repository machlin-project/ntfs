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

/* The independent Windows workload owns this initialized ordinary-file range.
 * These are native syscall tests, never a direct call to the portable writer. */
enum {
	FILE_BYTES = 1024 * 1024,
	WRITE_OFFSET = 3997,
	WRITE_BYTES = 8193,
	PAYLOAD_MULTIPLIER = 29,
	PAYLOAD_INCREMENT = 7,
	MAPPED_PATCH_OFFSET = 1801,
	MAPPED_PATCH_BYTES = 257,
	MAPPED_PATCH_MASK = 0x3f,
	READ_WINDOW = 65521,
	FILE_MODE = 0600
};

#define CHECK(condition)                                                                           \
	do {                                                                                       \
		if (!(condition)) {                                                                \
			fprintf(stderr, "%s:%u: %s (errno %d)\n", __FILE__, __LINE__, #condition,  \
			    errno);                                                                \
			exit(EXIT_FAILURE);                                                        \
		}                                                                                  \
	} while (0)

static void
read_contents(int fd, uint8_t *bytes)
{
	size_t offset = 0, length;
	ssize_t completed;
	struct stat stat;

	CHECK(fstat(fd, &stat) == 0 && S_ISREG(stat.st_mode) && stat.st_size == FILE_BYTES);
	while (offset < FILE_BYTES) {
		length = FILE_BYTES - offset;
		if (length > READ_WINDOW) {
			length = READ_WINDOW;
		}
		completed = pread(fd, bytes + offset, length, (off_t)offset);
		CHECK(completed > 0 && (size_t)completed <= length);
		offset += (size_t)completed;
	}
}

static uint8_t *
oracle(const char *path)
{
	uint8_t *bytes = malloc(FILE_BYTES);
	int fd;

	CHECK(bytes != NULL);
	fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	CHECK(fd >= 0);
	read_contents(fd, bytes);
	CHECK(close(fd) == 0);
	return bytes;
}

static void
same_contents(int fd, const uint8_t *expected, uint8_t *scratch)
{
	read_contents(fd, scratch);
	CHECK(memcmp(scratch, expected, FILE_BYTES) == 0);
}

static void
metadata(const char *stage, int fd)
{
	struct stat stat;

	CHECK(fstat(fd, &stat) == 0);
	printf("{\"stage\":\"%s\",\"realUserID\":%u,\"effectiveUserID\":%u,"
	       "\"uid\":%u,\"gid\":%u,\"mode\":%u,\"inode\":%llu,\"bytes\":%lld,"
	       "\"modifiedSeconds\":%lld,\"modifiedNanoseconds\":%ld,"
	       "\"changedSeconds\":%lld,\"changedNanoseconds\":%ld}\n",
	    stage, getuid(), geteuid(), stat.st_uid, stat.st_gid, stat.st_mode & ALLPERMS,
	    (unsigned long long)stat.st_ino, (long long)stat.st_size,
	    (long long)stat.st_mtimespec.tv_sec, stat.st_mtimespec.tv_nsec,
	    (long long)stat.st_ctimespec.tv_sec, stat.st_ctimespec.tv_nsec);
}

static void
deny_fresh_opens(const char *path)
{
	const int modes[] = {O_RDONLY, O_WRONLY, O_RDWR};
	size_t index;
	int fd, saved;

	for (index = 0; index < sizeof(modes) / sizeof(modes[0]); index++) {
		errno = 0;
		fd = open(path, modes[index] | O_NOFOLLOW | O_CLOEXEC);
		saved = errno;
		CHECK(fd < 0 && saved == EACCES);
		printf("{\"stage\":\"denied-open\",\"realUserID\":%u,"
		       "\"effectiveUserID\":%u,\"accessMode\":%d,\"errno\":%d}\n",
		    getuid(), geteuid(), modes[index], saved);
	}
}

int
main(int argc, char **argv)
{
	struct statfs filesystem;
	struct stat before, after;
	uint8_t *baseline, *final, *expected, *scratch;
	uint8_t payload[WRITE_BYTES];
	uint8_t *mappedRead, *mappedWrite;
	size_t index;
	bool writing;
	int fd, observer;

	if (argc == 3 && strcmp(argv[1], "deny") == 0) {
		/* The harness first proves that this exact path belongs to our mounted
		 * FSKit volume and primes it as its owner. Parent paths are searchable. */
		deny_fresh_opens(argv[2]);
		return EXIT_SUCCESS;
	}
	if (argc != 5 || (strcmp(argv[1], "write") != 0 && strcmp(argv[1], "check") != 0)) {
		fprintf(stderr,
		    "Usage: ntfs-mounted-write write|check FILE BASELINE FINAL\n"
		    "       ntfs-mounted-write deny FILE\n");
		return EXIT_FAILURE;
	}
	writing = strcmp(argv[1], "write") == 0;
	CHECK(getuid() == geteuid() && geteuid() != 0);
	baseline = oracle(argv[3]);
	final = oracle(argv[4]);
	expected = malloc(FILE_BYTES);
	scratch = malloc(FILE_BYTES);
	CHECK(expected != NULL && scratch != NULL);
	memcpy(expected, baseline, FILE_BYTES);
	for (index = 0; index < WRITE_BYTES; index++) {
		payload[index] = (uint8_t)(index * PAYLOAD_MULTIPLIER + PAYLOAD_INCREMENT);
	}
	memcpy(expected + WRITE_OFFSET, payload, WRITE_BYTES);
	for (index = 0; index < MAPPED_PATCH_BYTES; index++) {
		expected[WRITE_OFFSET + MAPPED_PATCH_OFFSET + index] ^= MAPPED_PATCH_MASK;
	}
	CHECK(memcmp(expected, final, FILE_BYTES) == 0);
	fd = open(argv[2], (writing ? O_RDWR : O_RDONLY) | O_NOFOLLOW | O_CLOEXEC);
	CHECK(fd >= 0 && fstatfs(fd, &filesystem) == 0);
	CHECK(strcmp(filesystem.f_fstypename, "machlinntfs") == 0);
	CHECK((filesystem.f_flags & MNT_RDONLY) == 0 && fstat(fd, &before) == 0);
	CHECK(before.st_uid == getuid() && (before.st_mode & ALLPERMS) == FILE_MODE);
	metadata("before", fd);
	if (writing) {
		same_contents(fd, baseline, scratch);
		observer = open(argv[2], O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
		CHECK(observer >= 0);
		mappedRead = mmap(NULL, FILE_BYTES, PROT_READ, MAP_SHARED, observer, 0);
		CHECK(mappedRead != MAP_FAILED && memcmp(mappedRead, baseline, FILE_BYTES) == 0);
		CHECK(pwrite(fd, payload, sizeof(payload), WRITE_OFFSET) == WRITE_BYTES);
		CHECK(fsync(fd) == 0);
		memcpy(expected, baseline, FILE_BYTES);
		memcpy(expected + WRITE_OFFSET, payload, WRITE_BYTES);
		same_contents(fd, expected, scratch);
		same_contents(observer, expected, scratch);
		CHECK(memcmp(mappedRead, expected, FILE_BYTES) == 0);
		metadata("after-pwrite-fsync", observer);
		mappedWrite = mmap(NULL, FILE_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		CHECK(mappedWrite != MAP_FAILED);
		/* The kernel must retain the write capability for this mapping after
		 * its descriptor closes, until native page-out and final mmap close. */
		CHECK(close(fd) == 0);
		fd = -1;
		for (index = 0; index < MAPPED_PATCH_BYTES; index++) {
			mappedWrite[WRITE_OFFSET + MAPPED_PATCH_OFFSET + index] ^=
			    MAPPED_PATCH_MASK;
		}
		CHECK(msync(mappedWrite, FILE_BYTES, MS_SYNC) == 0 && fsync(observer) == 0);
		CHECK(memcmp(mappedRead, final, FILE_BYTES) == 0);
		same_contents(observer, final, scratch);
		CHECK(munmap(mappedWrite, FILE_BYTES) == 0 && munmap(mappedRead, FILE_BYTES) == 0);
		CHECK(close(observer) == 0);
		fd = open(argv[2], O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
		CHECK(fd >= 0);
	}
	same_contents(fd, final, scratch);
	CHECK(fstat(fd, &after) == 0 && before.st_ino == after.st_ino &&
	    before.st_size == after.st_size && before.st_uid == after.st_uid &&
	    before.st_gid == after.st_gid && before.st_mode == after.st_mode);
	CHECK(after.st_mtimespec.tv_sec == after.st_ctimespec.tv_sec &&
	    after.st_mtimespec.tv_nsec == after.st_ctimespec.tv_nsec);
	metadata("final", fd);
	CHECK(close(fd) == 0);
	free(scratch);
	free(expected);
	free(final);
	free(baseline);
	printf("{\"result\":\"PASS\",\"writing\":%s,\"exactBytes\":%u,"
	       "\"mmapWriteAfterDescriptorClose\":%s}\n",
	    writing ? "true" : "false", FILE_BYTES, writing ? "true" : "false");
	return EXIT_SUCCESS;
}
