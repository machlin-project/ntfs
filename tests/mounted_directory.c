/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <sys/mount.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum {
	PRESSURE_FILES = 320,
	REPLACEMENT_FILES = 80,
	NAME_UNITS = 180,
	PAYLOAD_BYTES = 129,
	REPLACEMENT_ID = PRESSURE_FILES,
	ENUMERATION_INTERVAL = 32
};

enum directory_phase { PHASE_EMPTY, PHASE_FULL, PHASE_CONTRACTED, PHASE_REUSED };

#define CHECK(condition)                                                                           \
	do {                                                                                       \
		if (!(condition)) {                                                                \
			fprintf(stderr, "%s:%d: %s (errno=%d)\n", __FILE__, __LINE__, #condition,  \
			    errno);                                                                \
			exit(EXIT_FAILURE);                                                        \
		}                                                                                  \
	} while (0)

struct expected_directory {
	bool pressure[PRESSURE_FILES], replacement[REPLACEMENT_FILES], moved;
};

static void
pressure_name(unsigned identifier, char name[NAME_UNITS + 1])
{
	int prefix;

	CHECK(identifier < PRESSURE_FILES);
	prefix = snprintf(name, NAME_UNITS + 1, "pressure-%04u-", identifier);
	CHECK(prefix > 0 && prefix < NAME_UNITS);
	memset(name + prefix, 'n', NAME_UNITS - (size_t)prefix);
	name[NAME_UNITS] = '\0';
}

static void
replacement_name(unsigned identifier, char name[NAME_UNITS + 1])
{
	CHECK(identifier < REPLACEMENT_FILES);
	CHECK(snprintf(name, NAME_UNITS + 1, "replacement-%04u", identifier) > 0);
}

static void
payload(unsigned identifier, uint8_t bytes[PAYLOAD_BYTES])
{
	size_t index;

	for (index = 0; index < PAYLOAD_BYTES; index++) {
		bytes[index] = (uint8_t)(identifier * 17u + index * 37u + 11u);
	}
	/* Bind all 400 identities, including identifiers sharing a low byte. */
	bytes[0] = (uint8_t)(identifier >> 8);
	bytes[1] = (uint8_t)identifier;
}

static void
create_file(int directory, const char *name, unsigned identifier)
{
	uint8_t bytes[PAYLOAD_BYTES];
	int fd;

	payload(identifier, bytes);
	fd = openat(directory, name, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
	CHECK(fd >= 0);
	CHECK(pwrite(fd, bytes, sizeof(bytes), 0) == (ssize_t)sizeof(bytes));
	CHECK(fsync(fd) == 0 && close(fd) == 0);
}

static void
verify_file(int directory, const char *name, unsigned identifier, const char *parent, bool report)
{
	uint8_t expected[PAYLOAD_BYTES], observed[PAYLOAD_BYTES + 1];
	struct stat st;
	int fd;

	payload(identifier, expected);
	fd = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	CHECK(fd >= 0 && fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_nlink == 1 &&
	    st.st_size == PAYLOAD_BYTES);
	CHECK(pread(fd, observed, sizeof(observed), 0) == PAYLOAD_BYTES);
	CHECK(memcmp(expected, observed, PAYLOAD_BYTES) == 0 && close(fd) == 0);
	if (report) {
		printf("{\"path\":\"%s/%s\",\"identifier\":%u,\"inode\":\"%" PRIu64
		       "\",\"bytes\":%d,\"modifiedSeconds\":\"%" PRId64
		       "\",\"modifiedNanoseconds\":%ld}\n",
		    parent, name, identifier, (uint64_t)st.st_ino, PAYLOAD_BYTES,
		    (int64_t)st.st_mtimespec.tv_sec, st.st_mtimespec.tv_nsec);
	}
}

static void
absent(int directory, const char *name)
{
	struct stat st;

	errno = 0;
	CHECK(fstatat(directory, name, &st, AT_SYMLINK_NOFOLLOW) == -1 && errno == ENOENT);
}

static void
enumerate(DIR *directory, const struct expected_directory *expected, bool moved)
{
	bool pressure_seen[PRESSURE_FILES] = {false}, replacement_seen[REPLACEMENT_FILES] = {false};
	bool moved_seen = false, matched;
	struct dirent *entry;
	char name[NAME_UNITS + 1];
	unsigned index;

	/* Reuse the same DIR through mutations, but begin a fresh enumeration. */
	rewinddir(directory);
	for (;;) {
		errno = 0;
		entry = readdir(directory);
		if (entry == NULL) {
			CHECK(errno == 0);
			break;
		}
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
			continue;
		}
		if (moved) {
			CHECK(expected->moved && !moved_seen &&
			    strcmp(entry->d_name, "sustained-renamed") == 0);
			moved_seen = true;
			continue;
		}
		matched = false;
		for (index = 0; index < PRESSURE_FILES; index++) {
			pressure_name(index, name);
			if (strcmp(entry->d_name, name) == 0) {
				CHECK(expected->pressure[index] && !pressure_seen[index]);
				pressure_seen[index] = matched = true;
				break;
			}
		}
		if (!matched) {
			for (index = 0; index < REPLACEMENT_FILES; index++) {
				replacement_name(index, name);
				if (strcmp(entry->d_name, name) == 0) {
					CHECK(expected->replacement[index] &&
					    !replacement_seen[index]);
					replacement_seen[index] = matched = true;
					break;
				}
			}
		}
		CHECK(matched);
	}
	if (moved) {
		CHECK(moved_seen == expected->moved);
	} else {
		CHECK(memcmp(pressure_seen, expected->pressure, sizeof(pressure_seen)) == 0);
		CHECK(
		    memcmp(replacement_seen, expected->replacement, sizeof(replacement_seen)) == 0);
	}
}

static void
verify(int growth, int move, DIR *growth_iterator, DIR *move_iterator,
    const struct expected_directory *expected, bool report)
{
	char name[NAME_UNITS + 1];
	unsigned index;

	enumerate(growth_iterator, expected, false);
	enumerate(move_iterator, expected, true);
	for (index = 0; index < PRESSURE_FILES; index++) {
		pressure_name(index, name);
		if (expected->pressure[index]) {
			verify_file(growth, name, index, "native-growth", report);
		} else {
			absent(growth, name);
		}
	}
	for (index = 0; index < REPLACEMENT_FILES; index++) {
		replacement_name(index, name);
		if (expected->replacement[index]) {
			verify_file(growth, name, REPLACEMENT_ID + index, "native-growth", report);
		} else {
			absent(growth, name);
		}
	}
	if (expected->moved) {
		verify_file(move, "sustained-renamed", 0, "native-move", report);
	} else {
		absent(move, "sustained-renamed");
	}
}

static void
expected_phase(enum directory_phase phase, struct expected_directory *expected)
{
	unsigned index;

	memset(expected, 0, sizeof(*expected));
	for (index = 0; index < PRESSURE_FILES; index++) {
		expected->pressure[index] = phase == PHASE_FULL ||
		    ((phase == PHASE_CONTRACTED || phase == PHASE_REUSED) && index % 4 == 0 &&
			index != 0);
	}
	for (index = 0; index < REPLACEMENT_FILES; index++) {
		expected->replacement[index] = phase == PHASE_REUSED;
	}
	expected->moved = phase == PHASE_CONTRACTED || phase == PHASE_REUSED;
}

static enum directory_phase
phase(const char *name)
{
	if (strcmp(name, "full") == 0) {
		return PHASE_FULL;
	}
	if (strcmp(name, "contracted") == 0) {
		return PHASE_CONTRACTED;
	}
	if (strcmp(name, "reused") == 0) {
		return PHASE_REUSED;
	}
	CHECK(strcmp(name, "empty") == 0);
	return PHASE_EMPTY;
}

int
main(int argc, char **argv)
{
	struct statfs filesystem;
	struct stat before, after;
	struct expected_directory expected;
	DIR *growth_iterator, *move_iterator;
	char name[NAME_UNITS + 1];
	const char *action, *root;
	unsigned index;
	int parent, growth, move;
	bool checking;

	CHECK(argc == 3 || argc == 4);
	action = argv[1];
	checking = strcmp(action, "check") == 0;
	CHECK(argc == (checking ? 4 : 3));
	CHECK(checking || strcmp(action, "populate") == 0 || strcmp(action, "contract") == 0 ||
	    strcmp(action, "reuse") == 0 || strcmp(action, "empty") == 0);
	root = argv[argc - 1];
	CHECK(getuid() == geteuid() && geteuid() != 0);
	parent = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	CHECK(parent >= 0 && fstatfs(parent, &filesystem) == 0 &&
	    strcmp(filesystem.f_fstypename, "machlinntfs") == 0 &&
	    (filesystem.f_flags & MNT_RDONLY) == 0);
	if (strcmp(action, "populate") == 0) {
		/* Refuse a partially completed prior run before making any change. */
		absent(parent, "native-growth");
		absent(parent, "native-move");
		CHECK(mkdirat(parent, "native-growth", 0700) == 0);
		CHECK(mkdirat(parent, "native-move", 0700) == 0);
	}
	growth = openat(parent, "native-growth", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	move = openat(parent, "native-move", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	CHECK(growth >= 0 && move >= 0);
	growth_iterator = fdopendir(dup(growth));
	move_iterator = fdopendir(dup(move));
	CHECK(growth_iterator != NULL && move_iterator != NULL);
	expected_phase(checking			  ? phase(argv[2])
		: strcmp(action, "populate") == 0 ? PHASE_EMPTY
		: strcmp(action, "contract") == 0 ? PHASE_FULL
		: strcmp(action, "reuse") == 0	  ? PHASE_CONTRACTED
						  : PHASE_REUSED,
	    &expected);
	verify(growth, move, growth_iterator, move_iterator, &expected, checking);
	if (strcmp(action, "populate") == 0) {
		for (index = 0; index < PRESSURE_FILES; index++) {
			pressure_name(index, name);
			/* Cache an absent lookup before publishing this name. */
			absent(growth, name);
			create_file(growth, name, index);
			expected.pressure[index] = true;
			verify_file(growth, name, index, "native-growth", false);
			if ((index + 1) % ENUMERATION_INTERVAL == 0) {
				enumerate(growth_iterator, &expected, false);
			}
		}
	} else if (strcmp(action, "contract") == 0) {
		pressure_name(0, name);
		CHECK(fstatat(growth, name, &before, AT_SYMLINK_NOFOLLOW) == 0);
		CHECK(renameat(growth, name, move, "sustained-renamed") == 0);
		CHECK(fstatat(move, "sustained-renamed", &after, AT_SYMLINK_NOFOLLOW) == 0 &&
		    before.st_ino == after.st_ino);
		expected.pressure[0] = false;
		expected.moved = true;
		for (index = 0; index < PRESSURE_FILES; index++) {
			if (index % 4 != 0) {
				pressure_name(index, name);
				CHECK(unlinkat(growth, name, 0) == 0);
				expected.pressure[index] = false;
				absent(growth, name);
			}
			if ((index + 1) % ENUMERATION_INTERVAL == 0) {
				enumerate(growth_iterator, &expected, false);
			}
		}
	} else if (strcmp(action, "reuse") == 0) {
		for (index = 0; index < REPLACEMENT_FILES; index++) {
			replacement_name(index, name);
			create_file(growth, name, REPLACEMENT_ID + index);
			expected.replacement[index] = true;
		}
	} else if (!checking) {
		for (index = 0; index < PRESSURE_FILES; index++) {
			if (expected.pressure[index]) {
				pressure_name(index, name);
				CHECK(unlinkat(growth, name, 0) == 0);
				expected.pressure[index] = false;
			}
		}
		for (index = 0; index < REPLACEMENT_FILES; index++) {
			replacement_name(index, name);
			CHECK(unlinkat(growth, name, 0) == 0);
			expected.replacement[index] = false;
		}
		CHECK(unlinkat(move, "sustained-renamed", 0) == 0);
		expected.moved = false;
	}
	if (!checking) {
		CHECK(fsync(growth) == 0 && fsync(move) == 0 && fsync(parent) == 0);
		verify(growth, move, growth_iterator, move_iterator, &expected, true);
	}
	CHECK(closedir(growth_iterator) == 0 && closedir(move_iterator) == 0);
	CHECK(close(growth) == 0 && close(move) == 0 && close(parent) == 0);
	puts("{\"result\":\"PASS\",\"nativeSyscalls\":true,\"guiInputUsed\":false}");
	return EXIT_SUCCESS;
}
