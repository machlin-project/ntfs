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

/* The independent Windows workloads own these ordinary-file byte ranges.
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
	RESIDENT_FILE_BYTES = 47,
	RESIDENT_WRITE_OFFSET = 5,
	RESIDENT_MAPPED_PATCH_OFFSET = 4,
	RESIDENT_MAPPED_PATCH_BYTES = 4,
	READ_WINDOW = 65521,
	FILE_MODE = 0600
};

struct write_profile {
	size_t file_bytes, write_offset, write_bytes, mapped_offset, mapped_bytes;
	bool resident;
};

static const uint8_t resident_payload[] = "MACHLIN_RESIDENT";
static const struct write_profile initialized_profile = {
    FILE_BYTES, WRITE_OFFSET, WRITE_BYTES, MAPPED_PATCH_OFFSET, MAPPED_PATCH_BYTES, false};
static const struct write_profile resident_profile = {RESIDENT_FILE_BYTES, RESIDENT_WRITE_OFFSET,
    sizeof(resident_payload) - 1u, RESIDENT_MAPPED_PATCH_OFFSET, RESIDENT_MAPPED_PATCH_BYTES, true};

#define CHECK(condition)                                                                           \
	do {                                                                                       \
		if (!(condition)) {                                                                \
			fprintf(stderr, "%s:%u: %s (errno %d)\n", __FILE__, __LINE__, #condition,  \
			    errno);                                                                \
			exit(EXIT_FAILURE);                                                        \
		}                                                                                  \
	} while (0)

static void
read_contents(int fd, uint8_t *bytes, size_t file_bytes)
{
	size_t offset = 0, length;
	ssize_t completed;
	struct stat stat;

	CHECK(fstat(fd, &stat) == 0 && S_ISREG(stat.st_mode) && stat.st_size == (off_t)file_bytes);
	while (offset < file_bytes) {
		length = file_bytes - offset;
		if (length > READ_WINDOW) {
			length = READ_WINDOW;
		}
		completed = pread(fd, bytes + offset, length, (off_t)offset);
		CHECK(completed > 0 && (size_t)completed <= length);
		offset += (size_t)completed;
	}
}

static uint8_t *
oracle(const char *path, size_t file_bytes)
{
	uint8_t *bytes = malloc(file_bytes);
	int fd;

	CHECK(bytes != NULL);
	fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	CHECK(fd >= 0);
	read_contents(fd, bytes, file_bytes);
	CHECK(close(fd) == 0);
	return bytes;
}

static void
same_contents(int fd, const uint8_t *expected, uint8_t *scratch, size_t file_bytes)
{
	read_contents(fd, scratch, file_bytes);
	CHECK(memcmp(scratch, expected, file_bytes) == 0);
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
	const struct write_profile *profile;
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
	if (argc != 5 ||
	    (strcmp(argv[1], "write") != 0 && strcmp(argv[1], "check") != 0 &&
		strcmp(argv[1], "resident-write") != 0 && strcmp(argv[1], "resident-check") != 0)) {
		fprintf(stderr,
		    "Usage: ntfs-mounted-write write|check|resident-write|resident-check FILE "
		    "BASELINE FINAL\n"
		    "       ntfs-mounted-write deny FILE\n");
		return EXIT_FAILURE;
	}
	profile = strncmp(argv[1], "resident-", sizeof("resident-") - 1u) == 0
	    ? &resident_profile
	    : &initialized_profile;
	writing = strcmp(argv[1], "write") == 0 || strcmp(argv[1], "resident-write") == 0;
	CHECK(getuid() == geteuid() && geteuid() != 0);
	baseline = oracle(argv[3], profile->file_bytes);
	final = oracle(argv[4], profile->file_bytes);
	expected = malloc(profile->file_bytes);
	scratch = malloc(profile->file_bytes);
	CHECK(expected != NULL && scratch != NULL);
	memcpy(expected, baseline, profile->file_bytes);
	for (index = 0; index < profile->write_bytes; index++) {
		payload[index] = profile->resident
		    ? resident_payload[index]
		    : (uint8_t)(index * PAYLOAD_MULTIPLIER + PAYLOAD_INCREMENT);
	}
	memcpy(expected + profile->write_offset, payload, profile->write_bytes);
	for (index = 0; index < profile->mapped_bytes; index++) {
		expected[profile->write_offset + profile->mapped_offset + index] ^=
		    MAPPED_PATCH_MASK;
	}
	CHECK(memcmp(expected, final, profile->file_bytes) == 0);
	fd = open(argv[2], (writing ? O_RDWR : O_RDONLY) | O_NOFOLLOW | O_CLOEXEC);
	CHECK(fd >= 0 && fstatfs(fd, &filesystem) == 0);
	CHECK(strcmp(filesystem.f_fstypename, "machlinntfs") == 0);
	CHECK((filesystem.f_flags & MNT_RDONLY) == 0 && fstat(fd, &before) == 0);
	CHECK(before.st_uid == getuid() && (before.st_mode & ALLPERMS) == FILE_MODE);
	metadata("before", fd);
	if (writing) {
		same_contents(fd, baseline, scratch, profile->file_bytes);
		observer = open(argv[2], O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
		CHECK(observer >= 0);
		mappedRead = mmap(NULL, profile->file_bytes, PROT_READ, MAP_SHARED, observer, 0);
		CHECK(mappedRead != MAP_FAILED &&
		    memcmp(mappedRead, baseline, profile->file_bytes) == 0);
		CHECK(pwrite(fd, payload, profile->write_bytes, (off_t)profile->write_offset) ==
		    (ssize_t)profile->write_bytes);
		CHECK(fsync(fd) == 0);
		memcpy(expected, baseline, profile->file_bytes);
		memcpy(expected + profile->write_offset, payload, profile->write_bytes);
		same_contents(fd, expected, scratch, profile->file_bytes);
		same_contents(observer, expected, scratch, profile->file_bytes);
		CHECK(memcmp(mappedRead, expected, profile->file_bytes) == 0);
		metadata("after-pwrite-fsync", observer);
		mappedWrite =
		    mmap(NULL, profile->file_bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		CHECK(mappedWrite != MAP_FAILED);
		/* The kernel must retain the write capability for this mapping after
		 * its descriptor closes, until native page-out and final mmap close. */
		CHECK(close(fd) == 0);
		fd = -1;
		for (index = 0; index < profile->mapped_bytes; index++) {
			mappedWrite[profile->write_offset + profile->mapped_offset + index] ^=
			    MAPPED_PATCH_MASK;
		}
		CHECK(
		    msync(mappedWrite, profile->file_bytes, MS_SYNC) == 0 && fsync(observer) == 0);
		CHECK(memcmp(mappedRead, final, profile->file_bytes) == 0);
		same_contents(observer, final, scratch, profile->file_bytes);
		CHECK(munmap(mappedWrite, profile->file_bytes) == 0 &&
		    munmap(mappedRead, profile->file_bytes) == 0);
		CHECK(close(observer) == 0);
		fd = open(argv[2], O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
		CHECK(fd >= 0);
	}
	same_contents(fd, final, scratch, profile->file_bytes);
	CHECK(fstat(fd, &after) == 0 && before.st_ino == after.st_ino &&
	    before.st_size == after.st_size && before.st_uid == after.st_uid &&
	    before.st_gid == after.st_gid && before.st_mode == after.st_mode);
	CHECK(after.st_mtimespec.tv_sec == after.st_ctimespec.tv_sec &&
	    after.st_mtimespec.tv_nsec == after.st_ctimespec.tv_nsec);
	if (writing && profile->resident) {
		CHECK(after.st_mtimespec.tv_sec > before.st_mtimespec.tv_sec ||
		    (after.st_mtimespec.tv_sec == before.st_mtimespec.tv_sec &&
			after.st_mtimespec.tv_nsec > before.st_mtimespec.tv_nsec));
	}
	metadata("final", fd);
	CHECK(close(fd) == 0);
	free(scratch);
	free(expected);
	free(final);
	free(baseline);
	printf("{\"result\":\"PASS\",\"writing\":%s,\"exactBytes\":%zu,\"resident\":%s,"
	       "\"mmapWriteAfterDescriptorClose\":%s}\n",
	    writing ? "true" : "false", profile->file_bytes, profile->resident ? "true" : "false",
	    writing ? "true" : "false");
	return EXIT_SUCCESS;
}
