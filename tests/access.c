/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/access.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

enum {
	TEST_BUFFER_BYTES = 8192,
	TEST_BITS_PER_BYTE = 8,
	TEST_AUTHORITY_BYTES = 6,
	TEST_REVISION = 1,
	TEST_ACL_REVISION = 2,
	TEST_OBJECT_ACL_REVISION = 4,
	TEST_NT_AUTHORITY = 5,
	TEST_MANDATORY_AUTHORITY = 16,
	TEST_HIGH_INTEGRITY_RID = 0x3000,
	TEST_MANDATORY_NO_READ_UP = 0x02,
	TEST_USER_RID = 1001,
	TEST_GROUP_RID = 2001,
	TEST_OWNER_RID = 1003,
	TEST_RESTRICTING_RID = 3001,
	TEST_OWNER_RIGHTS_AUTHORITY = 3,
	TEST_OWNER_RIGHTS_RID = 4,
	TEST_UNKNOWN_ACE = 0xfe,
	TEST_UNKNOWN_FLAG = 0x20,
	TEST_SENTINEL = 0xa5,
	TEST_ORDERED_ACES = 4,
	TEST_ORDER_CHOICES = 8,
	TEST_ORDER_REQUESTS = 8,
	TEST_GROUP_MODES = 3,
	TEST_RESTRICTION_MODES = 2,
	TEST_STORED_MASK_FORMS = 2,
	TEST_WORK_ACES = 300
};

#define TEST_RESERVED_ACCESS UINT32_C(0x04000000)
#define TEST_AUTHORITY_MAX UINT64_C(0xffffffffffff)
#define TEST_RIGHTS (NTFS_FILE_READ_DATA | NTFS_FILE_WRITE_DATA | NTFS_FILE_EXECUTE)
#define TEST_FILE_GENERIC_READ UINT32_C(0x00120089)
#define TEST_FILE_GENERIC_WRITE UINT32_C(0x00120116)
#define TEST_FILE_GENERIC_EXECUTE UINT32_C(0x001200a0)
#define TEST_FILE_ALL_ACCESS UINT32_C(0x001f01ff)

/* Independently authored Microsoft wire layouts, without core/disk.h. */
struct test_descriptor {
	uint8_t revision, manager, control[sizeof(uint16_t)];
	uint8_t owner[sizeof(uint32_t)], group[sizeof(uint32_t)];
	uint8_t sacl[sizeof(uint32_t)], dacl[sizeof(uint32_t)];
};

struct test_sid_header {
	uint8_t revision, count, authority[TEST_AUTHORITY_BYTES];
};

struct test_acl {
	uint8_t revision, reserved, length[sizeof(uint16_t)];
	uint8_t count[sizeof(uint16_t)], reserved2[sizeof(uint16_t)];
};

struct test_ace_header {
	uint8_t type, flags, length[sizeof(uint16_t)], mask[sizeof(uint32_t)];
};

struct test_ace {
	uint8_t type, flags;
	uint32_t mask;
	struct ntfs_sid trustee;
};

static const struct ntfs_sid user_sid = {
    .authority = TEST_NT_AUTHORITY, .subauthorities = {TEST_USER_RID}, .count = 1};
static const struct ntfs_sid group_sid = {
    .authority = TEST_NT_AUTHORITY, .subauthorities = {TEST_GROUP_RID}, .count = 1};
static const struct ntfs_sid owner_sid = {
    .authority = TEST_NT_AUTHORITY, .subauthorities = {TEST_OWNER_RID}, .count = 1};
static const struct ntfs_sid restricting_sid = {
    .authority = TEST_NT_AUTHORITY, .subauthorities = {TEST_RESTRICTING_RID}, .count = 1};
static const struct ntfs_sid owner_rights = {.authority = TEST_OWNER_RIGHTS_AUTHORITY,
    .subauthorities = {TEST_OWNER_RIGHTS_RID},
    .count = 1};
static size_t decisions, ordered_decisions;

static void
store(void *buffer, uint64_t value, size_t bytes)
{
	uint8_t *out = buffer;
	size_t i;

	for (i = 0; i < bytes; i++) {
		out[i] = (uint8_t)value;
		value >>= TEST_BITS_PER_BYTE;
	}
}

static size_t
write_sid(uint8_t *buffer, const struct ntfs_sid *sid)
{
	struct test_sid_header *header = (void *)buffer;
	uint64_t authority = sid->authority;
	size_t i;

	header->revision = TEST_REVISION;
	header->count = sid->count;
	for (i = 0; i < sizeof(header->authority); i++) {
		header->authority[sizeof(header->authority) - i - 1] = (uint8_t)authority;
		authority >>= TEST_BITS_PER_BYTE;
	}
	for (i = 0; i < sid->count; i++) {
		store(buffer + sizeof(*header) + i * sizeof(uint32_t), sid->subauthorities[i],
		    sizeof(uint32_t));
	}
	return sizeof(*header) + sid->count * sizeof(uint32_t);
}

static size_t
write_ace(uint8_t *buffer, const struct test_ace *ace)
{
	struct test_ace_header *header = (void *)buffer;
	size_t size = sizeof(*header);

	header->type = ace->type;
	header->flags = ace->flags;
	store(header->mask, ace->mask, sizeof(header->mask));
	if (ace->type == NTFS_ACE_ALLOW_OBJECT || ace->type == NTFS_ACE_DENY_OBJECT) {
		store(buffer + size, 0, sizeof(uint32_t));
		size += sizeof(uint32_t);
	}
	size += write_sid(buffer + size, &ace->trustee);
	store(header->length, size, sizeof(header->length));
	return size;
}

static size_t
descriptor(uint8_t *buffer, const struct ntfs_sid *owner, enum ntfs_acl_state state,
    const struct test_ace *aces, size_t count)
{
	struct test_descriptor *header = (void *)buffer;
	struct test_acl *acl;
	size_t position = sizeof(*header), acl_offset, i;
	uint16_t control = NTFS_SD_SELF_RELATIVE;

	memset(buffer, 0, TEST_BUFFER_BYTES);
	header->revision = TEST_REVISION;
	store(header->owner, position, sizeof(header->owner));
	position += write_sid(buffer + position, owner);
	store(header->group, position, sizeof(header->group));
	position += write_sid(buffer + position, &group_sid);
	if (state != NTFS_ACL_ABSENT) {
		control |= NTFS_SD_DACL_PRESENT;
	}
	store(header->control, control, sizeof(header->control));
	if (state == NTFS_ACL_ABSENT || state == NTFS_ACL_NULL) {
		assert(count == 0);
		return position;
	}
	acl_offset = position;
	store(header->dacl, acl_offset, sizeof(header->dacl));
	acl = (void *)(buffer + acl_offset);
	acl->revision = TEST_OBJECT_ACL_REVISION;
	store(acl->count, count, sizeof(acl->count));
	position += sizeof(*acl);
	for (i = 0; i < count; i++) {
		assert(position + sizeof(struct test_ace_header) + sizeof(uint32_t) +
			sizeof(struct test_sid_header) +
			NTFS_SID_MAX_SUBAUTHORITIES * sizeof(uint32_t) <=
		    TEST_BUFFER_BYTES);
		position += write_ace(buffer + position, &aces[i]);
	}
	store(acl->length, position - acl_offset, sizeof(acl->length));
	return position;
}

static struct ntfs_dacl_decision
check(const void *bytes, size_t size, const struct ntfs_access_token *token, uint32_t desired,
    const struct ntfs_dacl_limits *limits, enum ntfs_result expected, bool allowed)
{
	struct ntfs_dacl_decision out, zero = {0};
	enum ntfs_result result;

	memset(&out, TEST_SENTINEL, sizeof(out));
	result = ntfs_dacl_evaluate(bytes, size, token, desired, limits, &out);
	if (result != expected || (result == NTFS_OK && out.allowed != allowed)) {
		fprintf(stderr, "decision %zu: result=%d expected=%d allowed=%d expected=%d\n",
		    decisions, result, expected, out.allowed, allowed);
		assert(false);
	}
	if (result == NTFS_OK) {
		assert(out.requested == ntfs_file_map_rights(desired));
		if (allowed && (desired & NTFS_ACCESS_MAXIMUM_ALLOWED) != 0) {
			assert(out.granted != 0 && (out.granted & ~TEST_FILE_ALL_ACCESS) == 0);
			assert((out.requested & ~NTFS_ACCESS_MAXIMUM_ALLOWED & ~out.granted) == 0);
		} else {
			assert(out.granted == (allowed ? out.requested : 0));
		}
		assert(out.sid_comparisons <= (limits == NULL ? NTFS_ACCESS_DEFAULT_COMPARISONS
							      : limits->max_sid_comparisons));
	} else {
		assert(memcmp(&out, &zero, sizeof(out)) == 0);
	}
	decisions++;
	return out;
}

static void
check_maximum(const void *bytes, size_t size, const struct ntfs_access_token *token,
    uint32_t required, uint32_t granted)
{
	struct ntfs_dacl_decision out;

	out = check(bytes, size, token, required | NTFS_ACCESS_MAXIMUM_ALLOWED, NULL, NTFS_OK,
	    granted != 0);
	assert(out.granted == granted);
}

static void
basic_tests(void)
{
	uint8_t bytes[TEST_BUFFER_BYTES];
	struct ntfs_token_group group = {.sid = group_sid, .attributes = NTFS_GROUP_ENABLED};
	struct ntfs_access_token token = {.user = user_sid, .groups = &group, .group_count = 1};
	struct test_ace aces[] = {{NTFS_ACE_ALLOW, 0, NTFS_FILE_READ_DATA, user_sid},
	    {NTFS_ACE_DENY, 0, NTFS_FILE_READ_DATA, user_sid},
	    {NTFS_ACE_ALLOW, 0, NTFS_FILE_WRITE_DATA, group_sid}};
	size_t size, i;
	const uint32_t group_modes[] = {0, NTFS_GROUP_ENABLED_BY_DEFAULT, NTFS_GROUP_ENABLED,
	    NTFS_GROUP_DENY_ONLY, NTFS_GROUP_MANDATORY | NTFS_GROUP_DENY_ONLY,
	    NTFS_GROUP_ENABLED | NTFS_GROUP_RESOURCE | NTFS_GROUP_LOGON_ID};
	const uint32_t generic[] = {NTFS_ACCESS_GENERIC_READ, NTFS_ACCESS_GENERIC_WRITE,
	    NTFS_ACCESS_GENERIC_EXECUTE, NTFS_ACCESS_GENERIC_ALL};
	const uint32_t mapped[] = {NTFS_FILE_GENERIC_READ, NTFS_FILE_GENERIC_WRITE,
	    NTFS_FILE_GENERIC_EXECUTE, NTFS_FILE_ALL_ACCESS};

	assert(NTFS_FILE_GENERIC_READ == TEST_FILE_GENERIC_READ);
	assert(NTFS_FILE_GENERIC_WRITE == TEST_FILE_GENERIC_WRITE);
	assert(NTFS_FILE_GENERIC_EXECUTE == TEST_FILE_GENERIC_EXECUTE);
	assert(NTFS_FILE_ALL_ACCESS == TEST_FILE_ALL_ACCESS);
	for (i = 0; i < sizeof(generic) / sizeof(generic[0]); i++) {
		assert(ntfs_file_map_rights(generic[i]) == mapped[i]);
		assert(ntfs_file_map_rights(generic[i] | TEST_RESERVED_ACCESS) ==
		    (mapped[i] | TEST_RESERVED_ACCESS));
		aces[0].mask = mapped[i];
		size = descriptor(bytes, &owner_sid, NTFS_ACL_PRESENT, aces, 1);
		(void)check(bytes, size, &token, generic[i], NULL, NTFS_OK, true);
		(void)check(bytes, size, &token, mapped[i], NULL, NTFS_OK, true);
	}
	aces[0].mask = NTFS_FILE_READ_DATA;
	size = descriptor(bytes, &owner_sid, NTFS_ACL_PRESENT, aces, 3);
	(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, NULL, NTFS_OK, true);
	(void)check(
	    bytes, size, &token, NTFS_FILE_READ_DATA | NTFS_FILE_WRITE_DATA, NULL, NTFS_OK, true);
	(void)check(bytes, size, &token, TEST_RIGHTS, NULL, NTFS_OK, false);
	aces[0].type = NTFS_ACE_DENY;
	aces[1].type = NTFS_ACE_ALLOW;
	size = descriptor(bytes, &owner_sid, NTFS_ACL_PRESENT, aces, 3);
	(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, NULL, NTFS_OK, false);
	aces[0].mask = 0;
	aces[1].mask = NTFS_FILE_WRITE_DATA;
	size = descriptor(bytes, &owner_sid, NTFS_ACL_PRESENT, aces, 2);
	(void)check(bytes, size, &token, NTFS_FILE_WRITE_DATA, NULL, NTFS_OK, true);
	aces[0] = (struct test_ace){NTFS_ACE_ALLOW, 0, NTFS_FILE_READ_DATA, group_sid};
	for (i = 0; i < sizeof(group_modes) / sizeof(group_modes[0]); i++) {
		group.attributes = group_modes[i];
		aces[0].type = NTFS_ACE_ALLOW;
		size = descriptor(bytes, &owner_sid, NTFS_ACL_PRESENT, aces, 1);
		(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, NULL, NTFS_OK,
		    (group_modes[i] & NTFS_GROUP_ENABLED) != 0);
		aces[0].type = NTFS_ACE_DENY;
		aces[1] = (struct test_ace){NTFS_ACE_ALLOW, 0, NTFS_FILE_READ_DATA, user_sid};
		size = descriptor(bytes, &owner_sid, NTFS_ACL_PRESENT, aces, 2);
		(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, NULL, NTFS_OK,
		    (group_modes[i] & (NTFS_GROUP_ENABLED | NTFS_GROUP_DENY_ONLY)) == 0);
	}
	group.attributes = NTFS_GROUP_ENABLED;
	aces[0] = (struct test_ace){NTFS_ACE_ALLOW, 0, NTFS_FILE_READ_DATA, user_sid};
	token.user_deny_only = true;
	size = descriptor(bytes, &owner_sid, NTFS_ACL_PRESENT, aces, 1);
	(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, NULL, NTFS_OK, false);
	aces[0].type = NTFS_ACE_DENY;
	aces[1] = (struct test_ace){NTFS_ACE_ALLOW, 0, NTFS_FILE_READ_DATA, group_sid};
	size = descriptor(bytes, &owner_sid, NTFS_ACL_PRESENT, aces, 2);
	(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, NULL, NTFS_OK, false);
	/* Generic read and write both include SYNCHRONIZE: a write deny overlaps read. */
	token.user_deny_only = false;
	aces[0].mask = TEST_FILE_GENERIC_WRITE;
	aces[1].mask = TEST_FILE_GENERIC_READ;
	size = descriptor(bytes, &owner_sid, NTFS_ACL_PRESENT, aces, 2);
	(void)check(bytes, size, &token, NTFS_ACCESS_GENERIC_READ, NULL, NTFS_OK, false);
	aces[0].flags = NTFS_ACE_INHERIT_ONLY | NTFS_ACE_CONTAINER_INHERIT;
	size = descriptor(bytes, &owner_sid, NTFS_ACL_PRESENT, aces, 2);
	(void)check(bytes, size, &token, NTFS_ACCESS_GENERIC_READ, NULL, NTFS_OK, true);
	aces[0].flags = NTFS_ACE_INHERITED | NTFS_ACE_OBJECT_INHERIT | NTFS_ACE_NO_PROPAGATE;
	size = descriptor(bytes, &owner_sid, NTFS_ACL_PRESENT, aces, 2);
	(void)check(bytes, size, &token, NTFS_ACCESS_GENERIC_READ, NULL, NTFS_OK, false);
}

static void
stored_mask_tests(void)
{
	uint8_t bytes[TEST_BUFFER_BYTES], saved[TEST_BUFFER_BYTES];
	struct ntfs_access_token tokens[] = {{.user = user_sid}, {.user = owner_sid},
	    {.user = user_sid,
		.restricting = &restricting_sid,
		.restricting_count = 1,
		.restricted = true}};
	struct test_ace aces[] = {
	    {NTFS_ACE_ALLOW, 0, TEST_FILE_ALL_ACCESS, user_sid}, {NTFS_ACE_ALLOW, 0, 0, user_sid}};
	const struct ntfs_sid trustees[] = {user_sid, restricting_sid};
	const uint32_t generic[] = {NTFS_ACCESS_GENERIC_READ, NTFS_ACCESS_GENERIC_WRITE,
	    NTFS_ACCESS_GENERIC_EXECUTE, NTFS_ACCESS_GENERIC_ALL};
	const uint32_t requests[] = {0, NTFS_FILE_READ_DATA, NTFS_ACCESS_GENERIC_READ,
	    NTFS_ACCESS_READ_CONTROL | NTFS_ACCESS_WRITE_DAC, NTFS_ACCESS_MAXIMUM_ALLOWED,
	    NTFS_ACCESS_MAXIMUM_ALLOWED | NTFS_FILE_READ_DATA};
	const uint8_t types[] = {NTFS_ACE_ALLOW, NTFS_ACE_DENY};
	size_t mask, type, trustee, context, request, mixed, size, before = decisions;

	/* These wire policy expectations are independent of the decision loop.
	 * A later unsupported mask is checked even after a sufficient allow, for
	 * nonmatching trustees, zero requests, implicit owners and restrictions. */
	for (mask = 0; mask < sizeof(generic) / sizeof(generic[0]); mask++) {
		for (type = 0; type < sizeof(types) / sizeof(types[0]); type++) {
			for (trustee = 0; trustee < sizeof(trustees) / sizeof(trustees[0]);
			    trustee++) {
				aces[1].type = types[type];
				aces[1].trustee = trustees[trustee];
				for (mixed = 0; mixed < TEST_STORED_MASK_FORMS; mixed++) {
					aces[1].mask =
					    generic[mask] | (mixed ? NTFS_FILE_READ_DATA : 0);
					size = descriptor(bytes, &owner_sid, NTFS_ACL_PRESENT, aces,
					    sizeof(aces) / sizeof(aces[0]));
					memcpy(saved, bytes, size);
					for (context = 0;
					    context < sizeof(tokens) / sizeof(tokens[0]);
					    context++) {
						for (request = 0; request <
						    sizeof(requests) / sizeof(requests[0]);
						    request++) {
							(void)check(bytes, size, &tokens[context],
							    requests[request], NULL,
							    NTFS_UNSUPPORTED, false);
							assert(memcmp(bytes, saved, size) == 0);
						}
					}
				}
			}
			/* Inherit-only data retains byte framing without applying its mask
			 * to this object. It cannot alter a concrete preceding grant. */
			aces[1].mask = generic[mask];
			aces[1].flags = NTFS_ACE_INHERIT_ONLY;
			size = descriptor(bytes, &owner_sid, NTFS_ACL_PRESENT, aces,
			    sizeof(aces) / sizeof(aces[0]));
			(void)check(
			    bytes, size, &tokens[0], NTFS_ACCESS_GENERIC_READ, NULL, NTFS_OK, true);
			aces[1].flags = 0;
		}
	}
	printf("PASS: %zu stored generic/mixed-mask policy verdicts, complete later-ACE "
	       "checks, owner/restricting/zero-request boundaries and inherit-only framing\n",
	    decisions - before);
}

static void
ownership_and_restriction_tests(void)
{
	uint8_t bytes[TEST_BUFFER_BYTES];
	struct ntfs_token_group group = {.sid = group_sid, .attributes = NTFS_GROUP_ENABLED};
	struct ntfs_access_token token = {.user = user_sid, .groups = &group, .group_count = 1};
	struct test_ace aces[] = {{NTFS_ACE_DENY, 0, NTFS_ACCESS_WRITE_DAC, user_sid},
	    {NTFS_ACE_ALLOW, 0, NTFS_FILE_READ_DATA, owner_rights}};
	size_t size;
	unsigned state;

	for (state = NTFS_ACL_ABSENT; state <= NTFS_ACL_EMPTY; state++) {
		size = descriptor(bytes, &owner_sid, state, NULL, 0);
		(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, NULL, NTFS_OK,
		    state != NTFS_ACL_EMPTY);
		(void)check(bytes, size, &token, 0, NULL, NTFS_OK, false);
	}
	size = descriptor(bytes, &user_sid, NTFS_ACL_EMPTY, NULL, 0);
	(void)check(bytes, size, &token, NTFS_ACCESS_READ_CONTROL | NTFS_ACCESS_WRITE_DAC, NULL,
	    NTFS_OK, true);
	(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, NULL, NTFS_OK, false);
	(void)check(bytes, size, &token, NTFS_ACCESS_WRITE_OWNER, NULL, NTFS_OK, false);
	size = descriptor(bytes, &user_sid, NTFS_ACL_PRESENT, aces, 1);
	(void)check(bytes, size, &token, NTFS_ACCESS_WRITE_DAC, NULL, NTFS_OK, true);
	token.user_deny_only = true;
	(void)check(bytes, size, &token, NTFS_ACCESS_WRITE_DAC, NULL, NTFS_OK, false);
	token.user_deny_only = false;
	/* Active OWNER RIGHTS suppress implicit owner grants even with a zero mask. */
	aces[0].trustee = owner_rights;
	aces[0].mask = 0;
	size = descriptor(bytes, &user_sid, NTFS_ACL_PRESENT, aces, 2);
	(void)check(bytes, size, &token, NTFS_ACCESS_WRITE_DAC, NULL, NTFS_OK, false);
	(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, NULL, NTFS_OK, true);
	size = descriptor(bytes, &owner_sid, NTFS_ACL_PRESENT, aces, 2);
	(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, NULL, NTFS_OK, false);
	aces[0].flags = NTFS_ACE_INHERIT_ONLY;
	aces[1].flags = NTFS_ACE_INHERIT_ONLY;
	size = descriptor(bytes, &user_sid, NTFS_ACL_PRESENT, aces, 2);
	(void)check(bytes, size, &token, NTFS_ACCESS_WRITE_DAC, NULL, NTFS_OK, true);
	size = descriptor(bytes, &group_sid, NTFS_ACL_EMPTY, NULL, 0);
	(void)check(bytes, size, &token, NTFS_ACCESS_READ_CONTROL, NULL, NTFS_OK, false);
	group.attributes |= NTFS_GROUP_OWNER;
	(void)check(bytes, size, &token, NTFS_ACCESS_READ_CONTROL, NULL, NTFS_OK, true);
	group.attributes = NTFS_GROUP_OWNER | NTFS_GROUP_DENY_ONLY;
	(void)check(bytes, size, &token, NTFS_ACCESS_READ_CONTROL, NULL, NTFS_OK, false);
	group.attributes = NTFS_GROUP_ENABLED;
	token.restricted = true;
	token.restricting = &restricting_sid;
	token.restricting_count = 1;
	aces[0] = (struct test_ace){NTFS_ACE_ALLOW, 0, NTFS_FILE_READ_DATA, user_sid};
	aces[1] = (struct test_ace){NTFS_ACE_ALLOW, 0, NTFS_FILE_READ_DATA, restricting_sid};
	size = descriptor(bytes, &owner_sid, NTFS_ACL_PRESENT, aces, 1);
	(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, NULL, NTFS_OK, false);
	size = descriptor(bytes, &owner_sid, NTFS_ACL_PRESENT, aces + 1, 1);
	(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, NULL, NTFS_OK, false);
	size = descriptor(bytes, &owner_sid, NTFS_ACL_PRESENT, aces, 2);
	(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, NULL, NTFS_OK, true);
	aces[1].type = NTFS_ACE_DENY;
	size = descriptor(bytes, &owner_sid, NTFS_ACL_PRESENT, aces, 2);
	(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, NULL, NTFS_OK, false);
	token.restricting_count = 0;
	(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, NULL, NTFS_OK, false);
	size = descriptor(bytes, &owner_sid, NTFS_ACL_NULL, NULL, 0);
	(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, NULL, NTFS_OK, true);
	/* An empty restricting list cannot qualify ownership in both contexts. */
	size = descriptor(bytes, &user_sid, NTFS_ACL_EMPTY, NULL, 0);
	(void)check(bytes, size, &token, NTFS_ACCESS_READ_CONTROL, NULL, NTFS_OK, false);
	aces[0] = (struct test_ace){NTFS_ACE_ALLOW, 0, NTFS_FILE_READ_DATA, owner_rights};
	size = descriptor(bytes, &user_sid, NTFS_ACL_PRESENT, aces, 1);
	(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, NULL, NTFS_OK, false);
}

static void
native_extension_tests(void)
{
	uint8_t bytes[TEST_BUFFER_BYTES];
	struct ntfs_token_group group = {.sid = group_sid, .attributes = NTFS_GROUP_ENABLED};
	struct ntfs_access_token token = {.user = user_sid, .groups = &group, .group_count = 1};
	struct test_ace aces[] = {{NTFS_ACE_ALLOW, 0, NTFS_FILE_READ_DATA, user_sid},
	    {NTFS_ACE_DENY, 0, NTFS_FILE_READ_DATA, user_sid},
	    {NTFS_ACE_ALLOW, 0, NTFS_FILE_WRITE_DATA, user_sid}};
	const uint32_t controls = NTFS_ACCESS_READ_CONTROL | NTFS_ACCESS_WRITE_DAC;
	struct ntfs_dacl_limits limits;
	struct ntfs_dacl_decision out;
	size_t size;
	unsigned state;

	/* Literal native witnesses discriminate ordered maximum access from
	 * subtracting every deny mask after collecting every allow mask. */
	size = descriptor(bytes, &owner_sid, NTFS_ACL_PRESENT, aces, 3);
	check_maximum(bytes, size, &token, 0, NTFS_FILE_READ_DATA | NTFS_FILE_WRITE_DATA);
	check_maximum(bytes, size, &token, NTFS_FILE_READ_DATA,
	    NTFS_FILE_READ_DATA | NTFS_FILE_WRITE_DATA);
	check_maximum(bytes, size, &token, NTFS_FILE_EXECUTE, 0);
	aces[0].type = NTFS_ACE_DENY;
	aces[1].type = NTFS_ACE_ALLOW;
	size = descriptor(bytes, &owner_sid, NTFS_ACL_PRESENT, aces, 3);
	check_maximum(bytes, size, &token, 0, NTFS_FILE_WRITE_DATA);
	check_maximum(bytes, size, &token, NTFS_FILE_READ_DATA, 0);
	for (state = NTFS_ACL_ABSENT; state <= NTFS_ACL_EMPTY; state++) {
		size = descriptor(bytes, &owner_sid, state, NULL, 0);
		check_maximum(bytes, size, &token, 0,
		    state == NTFS_ACL_EMPTY ? 0 : TEST_FILE_ALL_ACCESS);
	}
	size = descriptor(bytes, &user_sid, NTFS_ACL_EMPTY, NULL, 0);
	check_maximum(bytes, size, &token, 0, controls);
	check_maximum(bytes, size, &token, NTFS_FILE_READ_DATA, 0);
	token.restricted = true;
	token.restricting = &user_sid;
	token.restricting_count = 1;
	check_maximum(bytes, size, &token, 0, controls);
	(void)check(bytes, size, &token, controls, NULL, NTFS_OK, true);
	token.restricting = &group_sid;
	check_maximum(bytes, size, &token, 0, 0);
	(void)check(bytes, size, &token, controls, NULL, NTFS_OK, false);
	/* With the owner absent from the restricting list, OWNER RIGHTS does
	 * not match even in the ordinary pass. The group allow can then grant. */
	aces[0] = (struct test_ace){NTFS_ACE_DENY, 0, controls, owner_rights};
	aces[1] = (struct test_ace){NTFS_ACE_ALLOW, 0, controls, group_sid};
	size = descriptor(bytes, &user_sid, NTFS_ACL_PRESENT, aces, 2);
	(void)check(bytes, size, &token, controls, NULL, NTFS_OK, true);
	check_maximum(bytes, size, &token, 0, controls);
	token.restricting = &user_sid;
	(void)check(bytes, size, &token, controls, NULL, NTFS_OK, false);
	check_maximum(bytes, size, &token, 0, 0);
	/* Ordinary ownership alone cannot bypass a user deny for a restricted
	 * token. Both contexts qualifying ownership restore the implied grant. */
	aces[0].trustee = user_sid;
	size = descriptor(bytes, &user_sid, NTFS_ACL_PRESENT, aces, 2);
	(void)check(bytes, size, &token, controls, NULL, NTFS_OK, true);
	check_maximum(bytes, size, &token, 0, controls);
	token.restricting = &group_sid;
	(void)check(bytes, size, &token, controls, NULL, NTFS_OK, false);
	check_maximum(bytes, size, &token, 0, 0);
	aces[0] = (struct test_ace){NTFS_ACE_ALLOW, 0, NTFS_FILE_READ_DATA, owner_rights};
	aces[1] = (struct test_ace){NTFS_ACE_DENY, 0, NTFS_FILE_READ_DATA, user_sid};
	aces[2] = (struct test_ace){NTFS_ACE_ALLOW, 0, NTFS_FILE_READ_DATA, group_sid};
	size = descriptor(bytes, &user_sid, NTFS_ACL_PRESENT, aces, 3);
	(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, NULL, NTFS_OK, false);
	check_maximum(bytes, size, &token, 0, 0);
	token.restricting = &user_sid;
	(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, NULL, NTFS_OK, true);
	check_maximum(bytes, size, &token, 0, NTFS_FILE_READ_DATA);
	token.restricting = &group_sid;
	aces[0] = (struct test_ace){NTFS_ACE_ALLOW, 0, NTFS_FILE_READ_DATA, user_sid};
	aces[1] = (struct test_ace){NTFS_ACE_ALLOW, 0,
	    NTFS_FILE_READ_DATA | NTFS_FILE_WRITE_DATA, group_sid};
	size = descriptor(bytes, &owner_sid, NTFS_ACL_PRESENT, aces, 2);
	check_maximum(bytes, size, &token, 0, NTFS_FILE_READ_DATA | NTFS_FILE_WRITE_DATA);
	token.restricting = &user_sid;
	check_maximum(bytes, size, &token, 0, NTFS_FILE_READ_DATA);
	check_maximum(bytes, size, &token, NTFS_FILE_WRITE_DATA, 0);
	token.restricting = &group_sid;
	ntfs_dacl_default_limits(&limits);
	out = check(bytes, size, &token, NTFS_ACCESS_MAXIMUM_ALLOWED, &limits, NTFS_OK, true);
	assert(out.sid_comparisons > 1);
	limits.max_sid_comparisons = out.sid_comparisons;
	(void)check(bytes, size, &token, NTFS_ACCESS_MAXIMUM_ALLOWED, &limits, NTFS_OK, true);
	limits.max_sid_comparisons--;
	(void)check(bytes, size, &token, NTFS_ACCESS_MAXIMUM_ALLOWED, &limits, NTFS_RANGE, false);
}

/* A different oracle: for each individual right, the first applicable ACE wins.
 * No RemainingAccess mask or parser expressions from the implementation. */
static bool
right_allowed(const struct test_ace *aces, size_t count, uint32_t right, uint32_t group_flags,
    bool restricting)
{
	size_t i;
	uint32_t rid;
	bool match;

	for (i = 0; i < count; i++) {
		if ((aces[i].flags & NTFS_ACE_INHERIT_ONLY) != 0 || (aces[i].mask & right) == 0) {
			continue;
		}
		rid = aces[i].trustee.subauthorities[0];
		if (restricting) {
			match = rid == TEST_RESTRICTING_RID;
		} else {
			match = rid == TEST_USER_RID ||
			    (rid == TEST_GROUP_RID &&
				((group_flags & NTFS_GROUP_ENABLED) != 0 ||
				    (aces[i].type == NTFS_ACE_DENY &&
					(group_flags & NTFS_GROUP_DENY_ONLY) != 0)));
		}
		if (match) {
			return aces[i].type == NTFS_ACE_ALLOW;
		}
	}
	return false;
}

static void
ordered_tests(void)
{
	const struct test_ace options[TEST_ORDER_CHOICES] = {
	    {NTFS_ACE_ALLOW, 0, NTFS_FILE_READ_DATA, user_sid},
	    {NTFS_ACE_ALLOW, 0, NTFS_FILE_WRITE_DATA, group_sid},
	    {NTFS_ACE_DENY, 0, NTFS_FILE_READ_DATA | NTFS_FILE_EXECUTE, group_sid},
	    {NTFS_ACE_DENY, 0, NTFS_FILE_WRITE_DATA, user_sid},
	    {NTFS_ACE_ALLOW, 0, TEST_RIGHTS, owner_sid},
	    {NTFS_ACE_ALLOW, NTFS_ACE_INHERIT_ONLY, NTFS_FILE_EXECUTE, user_sid},
	    {NTFS_ACE_ALLOW, 0, TEST_RIGHTS, restricting_sid},
	    {NTFS_ACE_DENY, 0, NTFS_FILE_WRITE_DATA, restricting_sid}};
	const uint32_t rights[] = {NTFS_FILE_READ_DATA, NTFS_FILE_WRITE_DATA, NTFS_FILE_EXECUTE};
	const uint32_t group_modes[] = {0, NTFS_GROUP_ENABLED, NTFS_GROUP_DENY_ONLY};
	uint8_t bytes[TEST_BUFFER_BYTES];
	struct test_ace aces[TEST_ORDERED_ACES];
	struct ntfs_token_group group = {.sid = group_sid};
	struct ntfs_access_token token = {.user = user_sid, .groups = &group, .group_count = 1};
	size_t sequences = 1, sequence, value, i, size, mode, restriction, request;
	uint32_t desired, maximum;
	bool expected;

	for (i = 0; i < TEST_ORDERED_ACES; i++) {
		sequences *= TEST_ORDER_CHOICES;
	}
	for (sequence = 0; sequence < sequences; sequence++) {
		value = sequence;
		for (i = 0; i < TEST_ORDERED_ACES; i++) {
			aces[i] = options[value % TEST_ORDER_CHOICES];
			value /= TEST_ORDER_CHOICES;
		}
		size = descriptor(bytes, &owner_sid, NTFS_ACL_PRESENT, aces, TEST_ORDERED_ACES);
		for (mode = 0; mode < TEST_GROUP_MODES; mode++) {
			group.attributes = group_modes[mode];
			for (restriction = 0; restriction < TEST_RESTRICTION_MODES; restriction++) {
				token.restricted = restriction != 0;
				token.restricting = &restricting_sid;
				token.restricting_count = restriction;
				maximum = 0;
				for (i = 0; i < sizeof(rights) / sizeof(rights[0]); i++) {
					if (right_allowed(aces, TEST_ORDERED_ACES, rights[i],
						group.attributes, false) &&
					    (!token.restricted || right_allowed(aces, TEST_ORDERED_ACES,
								 rights[i], group.attributes, true))) {
						maximum |= rights[i];
					}
				}
				check_maximum(bytes, size, &token, 0, maximum);
				for (request = 0; request < TEST_ORDER_REQUESTS; request++) {
					desired = 0;
					expected = request != 0;
					for (i = 0; i < sizeof(rights) / sizeof(rights[0]); i++) {
						if ((request & ((size_t)1 << i)) == 0) {
							continue;
						}
						desired |= rights[i];
						expected &= right_allowed(aces, TEST_ORDERED_ACES,
						    rights[i], group.attributes, false);
						if (token.restricted) {
							expected &=
							    right_allowed(aces, TEST_ORDERED_ACES,
								rights[i], group.attributes, true);
						}
					}
					(void)check(
					    bytes, size, &token, desired, NULL, NTFS_OK, expected);
					ordered_decisions++;
				}
			}
		}
	}
}

static void
boundary_tests(void)
{
	uint8_t bytes[TEST_BUFFER_BYTES], saved[TEST_BUFFER_BYTES];
	struct test_descriptor *header = (void *)bytes;
	struct test_acl *acl;
	struct test_ace_header *wire_ace, *later_ace;
	struct test_ace aces[] = {{NTFS_ACE_ALLOW, 0, NTFS_FILE_READ_DATA, user_sid},
	    {NTFS_ACE_DENY, 0, NTFS_FILE_WRITE_DATA, group_sid}};
	struct ntfs_token_group group = {.sid = group_sid, .attributes = NTFS_GROUP_ENABLED};
	struct ntfs_access_token token = {.user = user_sid, .groups = &group, .group_count = 1};
	struct ntfs_dacl_limits limits;
	struct ntfs_dacl_decision decision;
	struct ntfs_security_info info;
	size_t size, i;
	const uint8_t unsupported[] = {NTFS_ACE_ALLOW_CALLBACK, NTFS_ACE_DENY_CALLBACK,
	    NTFS_ACE_ALLOW_OBJECT, NTFS_ACE_DENY_OBJECT, NTFS_ACE_AUDIT, TEST_UNKNOWN_ACE};
	const uint32_t bad_masks[] = {NTFS_ACCESS_SYSTEM_SECURITY,
	    TEST_RESERVED_ACCESS, NTFS_FILE_ALL_ACCESS + 1};
	static struct ntfs_token_group many[NTFS_ACCESS_MAX_SIDS + 1];

	size = descriptor(bytes, &owner_sid, NTFS_ACL_PRESENT, aces, 2);
	memcpy(saved, bytes, size);
	(void)check(NULL, size, &token, NTFS_FILE_READ_DATA, NULL, NTFS_INVALID, false);
	(void)check(bytes, size, NULL, NTFS_FILE_READ_DATA, NULL, NTFS_INVALID, false);
	assert(ntfs_dacl_evaluate(bytes, size, &token, 0, NULL, NULL) == NTFS_INVALID);
	for (i = 0; i < size; i++) {
		(void)check(bytes, i, &token, NTFS_FILE_READ_DATA, NULL, NTFS_CORRUPT, false);
	}
	(void)check(bytes, NTFS_SECURITY_MAX_BYTES + 1, &token, 0, NULL, NTFS_RANGE, false);
	store(header->owner, 0, sizeof(header->owner));
	(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, NULL, NTFS_CORRUPT, false);
	memcpy(bytes, saved, size);
	store(header->group, 0, sizeof(header->group));
	(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, NULL, NTFS_CORRUPT, false);
	memcpy(bytes, saved, size);
	assert(ntfs_security_decode(bytes, size, &info) == NTFS_OK);
	acl = (void *)(bytes + info.dacl.span.offset);
	wire_ace = (void *)((uint8_t *)acl + sizeof(*acl));
	/* Invalid framing after a sufficient allow must still be detected. */
	later_ace = (void *)((uint8_t *)wire_ace + sizeof(*wire_ace) +
	    sizeof(struct test_sid_header) + user_sid.count * sizeof(uint32_t));
	store(later_ace->length, 0, sizeof(later_ace->length));
	(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, NULL, NTFS_CORRUPT, false);
	for (i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); i++) {
		aces[1].type = unsupported[i];
		size = descriptor(bytes, &owner_sid, NTFS_ACL_PRESENT, aces, 2);
		(void)check(
		    bytes, size, &token, NTFS_FILE_READ_DATA, NULL, NTFS_UNSUPPORTED, false);
		(void)check(bytes, size, &token, NTFS_ACCESS_MAXIMUM_ALLOWED, NULL,
		    NTFS_UNSUPPORTED, false);
		aces[1].flags = NTFS_ACE_INHERIT_ONLY;
		size = descriptor(bytes, &owner_sid, NTFS_ACL_PRESENT, aces, 2);
		(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, NULL, NTFS_OK, true);
		aces[1].flags = 0;
	}
	aces[1].type = NTFS_ACE_DENY;
	aces[1].flags = TEST_UNKNOWN_FLAG;
	size = descriptor(bytes, &owner_sid, NTFS_ACL_PRESENT, aces, 2);
	(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, NULL, NTFS_UNSUPPORTED, false);
	aces[1].flags = 0;
	for (i = 0; i < sizeof(bad_masks) / sizeof(bad_masks[0]); i++) {
		aces[1].mask = bad_masks[i];
		size = descriptor(bytes, &owner_sid, NTFS_ACL_PRESENT, aces, 2);
		(void)check(
		    bytes, size, &token, NTFS_FILE_READ_DATA, NULL, NTFS_UNSUPPORTED, false);
		(void)check(bytes, size, &token, bad_masks[i], NULL, NTFS_UNSUPPORTED, false);
	}
	aces[1].mask = NTFS_FILE_WRITE_DATA;
	size = descriptor(bytes, &owner_sid, NTFS_ACL_PRESENT, aces, 2);
	token.user.count = NTFS_SID_MAX_SUBAUTHORITIES + 1;
	(void)check(bytes, size, &token, 0, NULL, NTFS_INVALID, false);
	token.user = user_sid;
	token.user.authority = TEST_AUTHORITY_MAX + 1;
	(void)check(bytes, size, &token, 0, NULL, NTFS_INVALID, false);
	token.user = user_sid;
	token.groups = NULL;
	(void)check(bytes, size, &token, 0, NULL, NTFS_INVALID, false);
	token.groups = &group;
	group.attributes = NTFS_GROUP_ENABLED | NTFS_GROUP_DENY_ONLY;
	(void)check(bytes, size, &token, 0, NULL, NTFS_INVALID, false);
	group.attributes = NTFS_GROUP_INTEGRITY | NTFS_GROUP_INTEGRITY_ENABLED;
	(void)check(bytes, size, &token, 0, NULL, NTFS_UNSUPPORTED, false);
	group.attributes = NTFS_GROUP_ENABLED;
	token.restricting_count = 1;
	token.restricted = true;
	(void)check(bytes, size, &token, 0, NULL, NTFS_INVALID, false);
	token.restricting = &restricting_sid;
	token.restricted = false;
	(void)check(bytes, size, &token, 0, NULL, NTFS_INVALID, false);
	token.restricting_count = 0;
	ntfs_dacl_default_limits(&limits);
	ntfs_dacl_default_limits(NULL);
	decision = check(bytes, size, &token, NTFS_FILE_READ_DATA, &limits, NTFS_OK, true);
	limits.max_sid_comparisons = decision.sid_comparisons;
	(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, &limits, NTFS_OK, true);
	limits.max_sid_comparisons--;
	(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, &limits, NTFS_RANGE, false);
	limits.max_sid_comparisons = 0;
	(void)check(bytes, size, &token, 0, &limits, NTFS_INVALID, false);
	limits.max_sid_comparisons = NTFS_ACCESS_MAX_COMPARISONS + 1;
	(void)check(bytes, size, &token, 0, &limits, NTFS_INVALID, false);
	ntfs_dacl_default_limits(&limits);
	limits.max_sids = 0;
	(void)check(bytes, size, &token, 0, &limits, NTFS_INVALID, false);
	limits.max_sids = NTFS_ACCESS_MAX_SIDS + 1;
	(void)check(bytes, size, &token, 0, &limits, NTFS_INVALID, false);
	ntfs_dacl_default_limits(&limits);
	for (i = 0; i < sizeof(many) / sizeof(many[0]); i++) {
		many[i] = group;
	}
	token.groups = many;
	token.group_count = NTFS_ACCESS_MAX_SIDS;
	(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, &limits, NTFS_OK, true);
	token.group_count++;
	(void)check(bytes, size, &token, 0, &limits, NTFS_RANGE, false);
	token.group_count = 1;
	limits.max_sids = 1;
	(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, &limits, NTFS_OK, true);
	token.group_count = 2;
	(void)check(bytes, size, &token, 0, &limits, NTFS_RANGE, false);
}

static void
sid_and_work_tests(void)
{
	uint8_t bytes[TEST_BUFFER_BYTES], before[TEST_BUFFER_BYTES];
	struct ntfs_sid long_sid = {
	    .authority = TEST_AUTHORITY_MAX, .count = NTFS_SID_MAX_SUBAUTHORITIES};
	struct ntfs_access_token token = {.user = user_sid};
	struct ntfs_dacl_limits limits;
	struct ntfs_dacl_decision decision;
	struct test_ace ace = {NTFS_ACE_ALLOW, 0, NTFS_FILE_READ_DATA, long_sid};
	struct test_descriptor *header = (void *)bytes;
	struct test_acl *sacl;
	size_t size, i, sacl_offset;
	static struct ntfs_token_group groups[NTFS_ACCESS_MAX_SIDS];
	static struct test_ace repeated[TEST_WORK_ACES];

	for (i = 0; i < long_sid.count; i++) {
		long_sid.subauthorities[i] = UINT32_MAX - (uint32_t)i;
	}
	ace.trustee = long_sid;
	token.user = long_sid;
	size = descriptor(bytes, &owner_sid, NTFS_ACL_PRESENT, &ace, 1);
	memcpy(before, bytes, size);
	(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, NULL, NTFS_OK, true);
	token.user.subauthorities[token.user.count - 1]--;
	(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, NULL, NTFS_OK, false);
	token.user = user_sid;
	token.user.subauthorities[NTFS_SID_MAX_SUBAUTHORITIES - 1] = UINT32_MAX;
	ace.trustee = user_sid;
	size = descriptor(bytes, &owner_sid, NTFS_ACL_PRESENT, &ace, 1);
	memcpy(before, bytes, size);
	(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, NULL, NTFS_OK, true);
	assert(memcmp(bytes, before, size) == 0);
	/* SACL framing is checked, but this API intentionally makes no SACL decision. */
	sacl_offset = size;
	store(header->sacl, sacl_offset, sizeof(header->sacl));
	store(header->control, NTFS_SD_SELF_RELATIVE | NTFS_SD_DACL_PRESENT | NTFS_SD_SACL_PRESENT,
	    sizeof(header->control));
	sacl = (void *)(bytes + size);
	sacl->revision = TEST_ACL_REVISION;
	store(sacl->count, 1, sizeof(sacl->count));
	size += sizeof(*sacl);
	ace.type = NTFS_ACE_MANDATORY_LABEL;
	ace.mask = TEST_MANDATORY_NO_READ_UP;
	ace.trustee = (struct ntfs_sid){.authority = TEST_MANDATORY_AUTHORITY,
	    .subauthorities = {TEST_HIGH_INTEGRITY_RID},
	    .count = 1};
	size += write_ace(bytes + size, &ace);
	store(sacl->length, size - sacl_offset, sizeof(sacl->length));
	(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, NULL, NTFS_OK, true);
	for (i = 0; i < NTFS_ACCESS_MAX_SIDS; i++) {
		groups[i] =
		    (struct ntfs_token_group){group_sid, NTFS_GROUP_ENABLED | NTFS_GROUP_OWNER};
	}
	for (i = 0; i < sizeof(repeated) / sizeof(repeated[0]); i++) {
		repeated[i] = (struct test_ace){NTFS_ACE_ALLOW, 0, NTFS_FILE_READ_DATA, owner_sid};
	}
	token.groups = groups;
	token.group_count = NTFS_ACCESS_MAX_SIDS;
	size = descriptor(
	    bytes, &owner_sid, NTFS_ACL_PRESENT, repeated, sizeof(repeated) / sizeof(repeated[0]));
	(void)check(bytes, size, &token, NTFS_FILE_READ_DATA, NULL, NTFS_RANGE, false);
	ntfs_dacl_default_limits(&limits);
	limits.max_sid_comparisons = NTFS_ACCESS_MAX_COMPARISONS;
	decision = check(bytes, size, &token, NTFS_FILE_READ_DATA, &limits, NTFS_OK, false);
	assert(decision.sid_comparisons ==
	    (token.group_count + 1) * (sizeof(repeated) / sizeof(repeated[0]) + 1));
	token.group_count = SIZE_MAX;
	(void)check(bytes, size, &token, 0, NULL, NTFS_RANGE, false);
	token.group_count = 0;
	token.restricted = true;
	token.restricting_count = SIZE_MAX;
	token.restricting = &restricting_sid;
	(void)check(bytes, size, &token, 0, NULL, NTFS_RANGE, false);
}

int
main(void)
{
	basic_tests();
	stored_mask_tests();
	ownership_and_restriction_tests();
	native_extension_tests();
	ordered_tests();
	boundary_tests();
	sid_and_work_tests();
	printf("PASS: %zu DACL decisions including %zu independent per-right ordered token "
	       "oracles; exact masks, ownership, restrictions, unsupported cases and budgets\n",
	    decisions, ordered_decisions);
	return 0;
}
