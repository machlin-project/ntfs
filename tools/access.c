/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "disk.h"
#include <ntfs/access.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum {
	ACCESS_TRANSPORT_VERSION = 1,
	ACCESS_TRANSPORT_USER_DENY_ONLY = 1,
	ACCESS_TRANSPORT_RESTRICTED = 2,
	ACCESS_TRANSPORT_MAX_BYTES = 2 * 1024 * 1024,
	ACCESS_TRANSPORT_ERROR = 2
};

/* Diagnostic transport, not an on-disk NTFS structure or authorization API.
 * Original MS-DTYP SID packets follow this header: user, attributed groups,
 * restricting SIDs, then the original self-relative descriptor bytes. */
struct access_header {
	uint8_t magic[4], version[sizeof(uint32_t)], desired[sizeof(uint32_t)];
	uint8_t flags[sizeof(uint32_t)], groups[sizeof(uint32_t)];
	uint8_t restricting[sizeof(uint32_t)], descriptor[sizeof(uint32_t)];
};

_Static_assert(sizeof(struct access_header) == 4 + 6 * sizeof(uint32_t), "access header");

static uint32_t
word(const uint8_t *bytes)
{
	uint32_t value = 0;
	size_t i;

	for (i = 0; i < sizeof(value); i++) {
		value |= (uint32_t)bytes[i] << (i * CHAR_BIT);
	}
	return value;
}

static bool
take_sid(const uint8_t **cursor, size_t *remaining, struct ntfs_sid *sid)
{
	const struct ntfs_disk_sid *header;
	size_t size;

	if (*remaining < sizeof(*header)) {
		return false;
	}
	header = (const void *)*cursor;
	if (header->count > NTFS_SID_MAX_SUBAUTHORITIES) {
		return false;
	}
	size = sizeof(*header) + (size_t)header->count * sizeof(uint32_t);
	if (size > *remaining || ntfs_security_sid_decode(*cursor, size, sid) != NTFS_OK) {
		return false;
	}
	*cursor += size;
	*remaining -= size;
	return true;
}

static uint8_t *
read_request(const char *path, size_t *size)
{
	struct stat info;
	uint8_t *bytes = NULL, extra;
	size_t position = 0;
	ssize_t got;
	int fd;

	fd = open(path, O_RDONLY | O_NONBLOCK);
	if (fd < 0) {
		return NULL;
	}
	if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) ||
	    info.st_size < (off_t)sizeof(struct access_header) ||
	    info.st_size > ACCESS_TRANSPORT_MAX_BYTES) {
		goto done;
	}
	*size = (size_t)info.st_size;
	bytes = malloc(*size);
	if (bytes == NULL) {
		goto done;
	}
	while (position < *size) {
		got = read(fd, bytes + position, *size - position);
		if (got < 0 && errno == EINTR) {
			continue;
		}
		if (got <= 0) {
			goto invalid;
		}
		position += (size_t)got;
	}
	do {
		got = read(fd, &extra, sizeof(extra));
	} while (got < 0 && errno == EINTR);
	if (got != 0) {
		goto invalid;
	}
	goto done;
invalid:
	free(bytes);
	bytes = NULL;
done:
	close(fd);
	return bytes;
}

int
main(int argc, char **argv)
{
	struct ntfs_access_token token = {0};
	struct ntfs_token_group *groups = NULL;
	struct ntfs_sid *restricting = NULL;
	struct ntfs_dacl_decision decision;
	const struct access_header *header;
	const uint8_t *cursor;
	uint8_t *bytes = NULL;
	size_t size, remaining, i;
	uint32_t flags, descriptor;
	enum ntfs_result result;
	int status = ACCESS_TRANSPORT_ERROR;

	if (argc != 2) {
		fprintf(stderr, "Usage: ntfs-dacl-evaluate REQUEST\n");
		return status;
	}
	bytes = read_request(argv[1], &size);
	if (bytes == NULL) {
		goto done;
	}
	header = (const void *)bytes;
	flags = word(header->flags);
	token.group_count = word(header->groups);
	token.restricting_count = word(header->restricting);
	descriptor = word(header->descriptor);
	if (memcmp(header->magic, "NTAC", sizeof(header->magic)) != 0 ||
	    word(header->version) != ACCESS_TRANSPORT_VERSION ||
	    (flags & ~(ACCESS_TRANSPORT_USER_DENY_ONLY | ACCESS_TRANSPORT_RESTRICTED)) != 0 ||
	    token.group_count > NTFS_ACCESS_MAX_SIDS ||
	    token.restricting_count > NTFS_ACCESS_MAX_SIDS ||
	    descriptor > NTFS_SECURITY_MAX_BYTES) {
		goto done;
	}
	cursor = bytes + sizeof(*header);
	remaining = size - sizeof(*header);
	if (!take_sid(&cursor, &remaining, &token.user)) {
		goto done;
	}
	if (token.group_count != 0) {
		groups = calloc(token.group_count, sizeof(*groups));
		if (groups == NULL) {
			goto done;
		}
	}
	if (token.restricting_count != 0) {
		restricting = calloc(token.restricting_count, sizeof(*restricting));
		if (restricting == NULL) {
			goto done;
		}
	}
	for (i = 0; i < token.group_count; i++) {
		if (remaining < sizeof(groups[i].attributes)) {
			goto done;
		}
		groups[i].attributes = word(cursor);
		cursor += sizeof(groups[i].attributes);
		remaining -= sizeof(groups[i].attributes);
		if (!take_sid(&cursor, &remaining, &groups[i].sid)) {
			goto done;
		}
	}
	for (i = 0; i < token.restricting_count; i++) {
		if (!take_sid(&cursor, &remaining, &restricting[i])) {
			goto done;
		}
	}
	if (remaining != descriptor) {
		goto done;
	}
	token.groups = groups;
	token.restricting = restricting;
	token.user_deny_only = (flags & ACCESS_TRANSPORT_USER_DENY_ONLY) != 0;
	token.restricted = (flags & ACCESS_TRANSPORT_RESTRICTED) != 0;
	result =
	    ntfs_dacl_evaluate(cursor, remaining, &token, word(header->desired), NULL, &decision);
	printf("{\"schema_version\":%u,\"code\":%d,\"result\":\"%s\",\"allowed\":%s,"
	       "\"requested\":%" PRIu32 ",\"granted\":%" PRIu32 ",\"sid_comparisons\":%" PRIu32
	       "}\n",
	    ACCESS_TRANSPORT_VERSION, (int)result, ntfs_result_string(result),
	    decision.allowed ? "true" : "false", decision.requested, decision.granted,
	    decision.sid_comparisons);
	status = 0;
done:
	free(restricting);
	free(groups);
	free(bytes);
	if (status != 0) {
		fprintf(stderr, "Invalid or unreadable bounded access request\n");
	}
	return status;
}
