/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include <ntfs/access.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	FUZZ_NT_AUTHORITY = 5,
	FUZZ_BUILTIN_DOMAIN = 32,
	FUZZ_RESTRICTED = 0x01,
	FUZZ_USER_DENY_ONLY = 0x02,
	FUZZ_NO_GROUP = 0x04,
	FUZZ_INVALID_SID = 0x08,
	FUZZ_MUTATIONS = 512
};

/* Test envelope only; fields are independently authored by fuzz_seeds.py. */
struct fuzz_access_header {
	uint8_t desired[sizeof(uint32_t)], comparisons[sizeof(uint32_t)], flags;
	uint8_t attributes[sizeof(uint32_t)], user[sizeof(uint32_t)];
	uint8_t group[sizeof(uint32_t)], restricting[sizeof(uint32_t)];
};

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const struct fuzz_access_header *header = (const void *)data;
	struct ntfs_token_group group = {.sid = {.authority = FUZZ_NT_AUTHORITY,
					     .subauthorities = {FUZZ_BUILTIN_DOMAIN},
					     .count = 2}};
	struct ntfs_sid restricting = group.sid;
	struct ntfs_access_token token = {
	    .user = group.sid, .groups = &group, .restricting = &restricting};
	struct ntfs_dacl_limits limits;
	struct ntfs_dacl_decision first, second, zero = {0};
	uint32_t desired;
	enum ntfs_result result, repeat;

	if (size < sizeof(*header) || size > NTFS_SECURITY_MAX_BYTES) {
		return 0;
	}
	ntfs_dacl_default_limits(&limits);
	limits.max_sid_comparisons =
	    ntfs_u32(header->comparisons) % NTFS_ACCESS_DEFAULT_COMPARISONS + 1;
	token.user.subauthorities[token.user.count - 1] = ntfs_u32(header->user);
	group.sid.subauthorities[group.sid.count - 1] = ntfs_u32(header->group);
	restricting.subauthorities[restricting.count - 1] = ntfs_u32(header->restricting);
	token.user_deny_only = (header->flags & FUZZ_USER_DENY_ONLY) != 0;
	token.restricted = (header->flags & FUZZ_RESTRICTED) != 0;
	token.restricting_count = token.restricted ? 1 : 0;
	token.group_count = (header->flags & FUZZ_NO_GROUP) != 0 ? 0 : 1;
	group.attributes = ntfs_u32(header->attributes);
	if ((header->flags & FUZZ_INVALID_SID) != 0) {
		token.user.count = NTFS_SID_MAX_SUBAUTHORITIES + 1;
	}
	desired = ntfs_u32(header->desired);
	memset(&first, UINT8_MAX, sizeof(first));
	result = ntfs_dacl_evaluate(
	    data + sizeof(*header), size - sizeof(*header), &token, desired, &limits, &first);
	repeat = ntfs_dacl_evaluate(
	    data + sizeof(*header), size - sizeof(*header), &token, desired, &limits, &second);
	assert(result == repeat);
	if (result != NTFS_OK) {
		assert(memcmp(&first, &zero, sizeof(first)) == 0);
		assert(memcmp(&second, &zero, sizeof(second)) == 0);
	} else {
		assert(first.allowed == second.allowed && first.requested == second.requested &&
		    first.granted == second.granted &&
		    first.sid_comparisons == second.sid_comparisons);
		assert(first.requested == ntfs_file_map_rights(desired));
		assert(first.granted == (first.allowed ? first.requested : 0));
		assert((first.granted & ~NTFS_FILE_ALL_ACCESS) == 0);
		assert(first.sid_comparisons <= limits.max_sid_comparisons);
	}
	return 0;
}

#ifdef NTFS_FUZZ_STANDALONE
int
main(int argc, char **argv)
{
	FILE *file;
	uint8_t *bytes, saved;
	long length;
	size_t i, position;

	assert(argc == 2);
	file = fopen(argv[1], "rb");
	assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
	length = ftell(file);
	assert(length > 0 && (size_t)length <= NTFS_SECURITY_MAX_BYTES);
	assert(fseek(file, 0, SEEK_SET) == 0);
	bytes = malloc((size_t)length);
	assert(bytes != NULL && fread(bytes, 1, (size_t)length, file) == (size_t)length);
	assert(fclose(file) == 0);
	LLVMFuzzerTestOneInput(bytes, (size_t)length);
	for (i = 0; i < FUZZ_MUTATIONS; i++) {
		position = i % (size_t)length;
		saved = bytes[position];
		bytes[position] ^= (uint8_t)(1u << (i % NTFS_BITS_PER_BYTE));
		LLVMFuzzerTestOneInput(bytes, (size_t)length);
		bytes[position] = saved;
	}
	free(bytes);
	puts("PASS: bounded deterministic DACL/token mutations, zero errors and exact decisions");
	return 0;
}
#endif
