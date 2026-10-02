/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/security.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

enum {
	TEST_BITS_PER_BYTE = 8,
	TEST_SD_REVISION = 1,
	TEST_SID_REVISION = 1,
	TEST_ACL_REVISION = 2,
	TEST_OBJECT_ACL_REVISION = 4,
	TEST_AUTHORITY_BYTES = 6,
	TEST_GUID_BYTES = 16,
	TEST_BUFFER_BYTES = 1024,
	TEST_SID_SUBAUTHORITIES = 3,
	TEST_UNKNOWN_ACE = 0xfe,
	TEST_UNKNOWN_OBJECT_FLAG = 0x00000004,
	TEST_INITIAL_FILL = 0x5a,
	TEST_METADATA_MUTATIONS = 2000,
	TEST_FILE_READ_DATA = 0x00000001,
	TEST_READ_CONTROL = 0x00020000
};

#define TEST_AUTHORITY UINT64_C(0x010203040506)
#define TEST_SUBAUTHORITY UINT32_C(0xfedcba98)

/* Independent MS-DTYP wire authors, separate from the core's decoder layouts. */
struct test_descriptor {
	uint8_t revision, manager, control[sizeof(uint16_t)];
	uint8_t owner[sizeof(uint32_t)], group[sizeof(uint32_t)];
	uint8_t sacl[sizeof(uint32_t)], dacl[sizeof(uint32_t)];
};

struct test_sid {
	uint8_t revision, count, authority[TEST_AUTHORITY_BYTES];
	uint8_t subauthorities[NTFS_SID_MAX_SUBAUTHORITIES][sizeof(uint32_t)];
};

struct test_acl {
	uint8_t revision, reserved1, length[sizeof(uint16_t)];
	uint8_t count[sizeof(uint16_t)], reserved2[sizeof(uint16_t)];
};

struct test_ace {
	uint8_t type, flags, length[sizeof(uint16_t)];
};

struct test_ace_mask {
	struct test_ace header;
	uint8_t mask[sizeof(uint32_t)];
};

static void
store(void *buffer, uint64_t value, size_t size)
{
	uint8_t *bytes = buffer;
	size_t i;

	for (i = 0; i < size; i++) {
		bytes[i] = (uint8_t)value;
		value >>= TEST_BITS_PER_BYTE;
	}
}

static size_t
make_sid(void *buffer, uint8_t count)
{
	struct test_sid sid = {.revision = TEST_SID_REVISION, .count = count};
	uint64_t authority = TEST_AUTHORITY;
	size_t i,
	    size = offsetof(struct test_sid, subauthorities) + (size_t)count * sizeof(uint32_t);

	assert(count <= NTFS_SID_MAX_SUBAUTHORITIES);
	for (i = 0; i < sizeof(sid.authority); i++) {
		sid.authority[sizeof(sid.authority) - i - 1] = (uint8_t)authority;
		authority >>= TEST_BITS_PER_BYTE;
	}
	for (i = 0; i < count; i++) {
		store(sid.subauthorities[i], TEST_SUBAUTHORITY + i, sizeof(uint32_t));
	}
	memcpy(buffer, &sid, size);
	return size;
}

static void
sid_tests(void)
{
	uint8_t buffer[sizeof(struct test_sid) + sizeof(uint32_t)];
	struct test_sid *header = (void *)buffer;
	struct ntfs_sid sid, zero = {0};
	size_t count, length, prefix, i;

	for (count = 0; count <= NTFS_SID_MAX_SUBAUTHORITIES; count++) {
		length = make_sid(buffer, (uint8_t)count);
		assert(ntfs_security_sid_decode(buffer, length, &sid) == NTFS_OK);
		assert(sid.authority == TEST_AUTHORITY && sid.count == count);
		for (i = 0; i < count; i++) {
			assert(sid.subauthorities[i] == TEST_SUBAUTHORITY + i);
		}
		for (i = count; i < NTFS_SID_MAX_SUBAUTHORITIES; i++) {
			assert(sid.subauthorities[i] == 0);
		}
		for (prefix = 0; prefix < length; prefix++) {
			memset(&sid, TEST_INITIAL_FILL, sizeof(sid));
			assert(ntfs_security_sid_decode(buffer, prefix, &sid) == NTFS_CORRUPT);
			assert(memcmp(&sid, &zero, sizeof(sid)) == 0);
		}
		memset(&sid, TEST_INITIAL_FILL, sizeof(sid));
		assert(ntfs_security_sid_decode(buffer, length + 1, &sid) == NTFS_CORRUPT);
		assert(memcmp(&sid, &zero, sizeof(sid)) == 0);
	}
	length = make_sid(buffer, NTFS_SID_MAX_SUBAUTHORITIES);
	memset(header->authority, UINT8_MAX, sizeof(header->authority));
	assert(ntfs_security_sid_decode(buffer, length, &sid) == NTFS_OK);
	assert(sid.authority == ((UINT64_C(1) << (TEST_AUTHORITY_BYTES * TEST_BITS_PER_BYTE)) - 1));
	header->revision++;
	assert(ntfs_security_sid_decode(buffer, length, &sid) == NTFS_CORRUPT);
	assert(memcmp(&sid, &zero, sizeof(sid)) == 0);
	header->revision = TEST_SID_REVISION;
	header->count = NTFS_SID_MAX_SUBAUTHORITIES + 1;
	assert(ntfs_security_sid_decode(buffer, length, &sid) == NTFS_CORRUPT);
	assert(memcmp(&sid, &zero, sizeof(sid)) == 0);
	assert(ntfs_security_sid_decode(NULL, length, &sid) == NTFS_INVALID);
	assert(memcmp(&sid, &zero, sizeof(sid)) == 0);
	assert(ntfs_security_sid_decode(buffer, length, NULL) == NTFS_INVALID);
}

static size_t
make_ace(void *buffer, uint8_t type, bool object, uint32_t object_flags, bool application)
{
	struct test_ace_mask *ace = buffer;
	uint8_t *bytes = buffer;
	size_t position = sizeof(*ace);

	memset(buffer, 0, TEST_BUFFER_BYTES);
	ace->header.type = type;
	ace->header.flags = NTFS_ACE_OBJECT_INHERIT | NTFS_ACE_INHERIT_ONLY;
	store(ace->mask, TEST_FILE_READ_DATA | TEST_READ_CONTROL, sizeof(ace->mask));
	if (object) {
		store(bytes + position, object_flags, sizeof(object_flags));
		position += sizeof(object_flags);
		if ((object_flags & NTFS_ACE_OBJECT_TYPE_PRESENT) != 0) {
			memset(bytes + position, TEST_INITIAL_FILL, TEST_GUID_BYTES);
			position += TEST_GUID_BYTES;
		}
		if ((object_flags & NTFS_ACE_INHERITED_OBJECT_TYPE_PRESENT) != 0) {
			memset(bytes + position, TEST_INITIAL_FILL + 1, TEST_GUID_BYTES);
			position += TEST_GUID_BYTES;
		}
	}
	position += make_sid(bytes + position, TEST_SID_SUBAUTHORITIES);
	if (application) {
		memset(bytes + position, TEST_INITIAL_FILL, sizeof(uint32_t));
		position += sizeof(uint32_t);
	}
	store(ace->header.length, position, sizeof(ace->header.length));
	return position;
}

static void
check_ace(const void *buffer, size_t size, enum ntfs_result expected)
{
	struct ntfs_ace_info info, zero = {0};
	enum ntfs_result result;

	memset(&info, TEST_INITIAL_FILL, sizeof(info));
	result = ntfs_security_ace_decode(buffer, size, &info);
	assert(result == expected);
	if (result != NTFS_OK) {
		assert(memcmp(&info, &zero, sizeof(info)) == 0);
	}
}

static void
ace_tests(void)
{
	const struct {
		uint8_t type;
		bool object, application;
	} cases[] = {{NTFS_ACE_ALLOW, false, false}, {NTFS_ACE_DENY, false, false},
	    {NTFS_ACE_AUDIT, false, false}, {NTFS_ACE_ALLOW_OBJECT, true, false},
	    {NTFS_ACE_DENY_OBJECT, true, false}, {NTFS_ACE_AUDIT_OBJECT, true, false},
	    {NTFS_ACE_ALLOW_CALLBACK, false, true}, {NTFS_ACE_DENY_CALLBACK, false, true},
	    {NTFS_ACE_AUDIT_CALLBACK, false, true}, {NTFS_ACE_ALLOW_CALLBACK_OBJECT, true, true},
	    {NTFS_ACE_DENY_CALLBACK_OBJECT, true, true},
	    {NTFS_ACE_AUDIT_CALLBACK_OBJECT, true, true}, {NTFS_ACE_MANDATORY_LABEL, false, false},
	    {NTFS_ACE_RESOURCE_ATTRIBUTE, false, true}, {NTFS_ACE_SCOPED_POLICY, false, false}};

	uint8_t buffer[TEST_BUFFER_BYTES];
	struct test_ace *header = (void *)buffer;
	struct test_sid *sid;
	struct ntfs_ace_info info;
	size_t i, length, truncation;
	uint32_t flags;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		for (flags = 0; flags <=
		    (NTFS_ACE_OBJECT_TYPE_PRESENT | NTFS_ACE_INHERITED_OBJECT_TYPE_PRESENT);
		    flags++) {
			length = make_ace(
			    buffer, cases[i].type, cases[i].object, flags, cases[i].application);
			assert(ntfs_security_ace_decode(buffer, length, &info) == NTFS_OK);
			assert(info.type == cases[i].type && !info.opaque &&
			    info.object == cases[i].object);
			assert(info.trustee.authority == TEST_AUTHORITY &&
			    info.trustee.count == TEST_SID_SUBAUTHORITIES);
			assert(info.trustee.subauthorities[0] == TEST_SUBAUTHORITY);
			assert(info.trustee.subauthorities[TEST_SID_SUBAUTHORITIES - 1] ==
			    TEST_SUBAUTHORITY + TEST_SID_SUBAUTHORITIES - 1);
			assert(info.mask == (TEST_FILE_READ_DATA | TEST_READ_CONTROL));
			assert(info.application_data == cases[i].application);
			assert(info.application.length ==
			    (cases[i].application ? sizeof(uint32_t) : 0));
			assert(info.object_type.length ==
			    (cases[i].object && (flags & NTFS_ACE_OBJECT_TYPE_PRESENT)
				    ? TEST_GUID_BYTES
				    : 0));
			assert(info.inherited_object_type.length ==
			    (cases[i].object && (flags & NTFS_ACE_INHERITED_OBJECT_TYPE_PRESENT)
				    ? TEST_GUID_BYTES
				    : 0));
			for (truncation = 0; truncation < length; truncation++) {
				check_ace(buffer, truncation, NTFS_CORRUPT);
			}
		}
	}
	length = make_ace(buffer, NTFS_ACE_ALLOW, false, 0, true);
	assert(
	    ntfs_security_ace_decode(buffer, length, &info) == NTFS_OK && !info.application_data);
	sid = (void *)(buffer + info.sid.offset);
	sid->count = NTFS_SID_MAX_SUBAUTHORITIES + 1;
	check_ace(buffer, length, NTFS_CORRUPT);
	length = make_ace(buffer, NTFS_ACE_ALLOW, false, 0, false);
	assert(ntfs_security_ace_decode(buffer, length, &info) == NTFS_OK);
	sid = (void *)(buffer + info.sid.offset);
	sid->revision++;
	check_ace(buffer, length, NTFS_CORRUPT);
	length = make_ace(buffer, NTFS_ACE_ALLOW_OBJECT, true, TEST_UNKNOWN_OBJECT_FLAG, false);
	check_ace(buffer, length, NTFS_UNSUPPORTED);
	length = make_ace(buffer, TEST_UNKNOWN_ACE, false, 0, true);
	assert(ntfs_security_ace_decode(buffer, length, &info) == NTFS_OK && info.opaque &&
	    info.sid.length == 0);
	header->type = TEST_UNKNOWN_ACE;
	store(header->length, sizeof(*header), sizeof(header->length));
	assert(ntfs_security_ace_decode(buffer, sizeof(*header), &info) == NTFS_OK && info.opaque);
	check_ace(NULL, sizeof(*header), NTFS_INVALID);
	assert(ntfs_security_ace_decode(buffer, sizeof(*header), NULL) == NTFS_INVALID);
}

static size_t
make_descriptor(void *buffer, bool object)
{
	struct test_descriptor *header = buffer;
	struct test_acl *acl;
	uint8_t *bytes = buffer, ace[TEST_BUFFER_BYTES];
	size_t position = sizeof(*header), acl_offset, length;

	memset(buffer, 0, TEST_BUFFER_BYTES);
	header->revision = TEST_SD_REVISION;
	header->manager = TEST_INITIAL_FILL;
	store(header->control,
	    NTFS_SD_SELF_RELATIVE | NTFS_SD_RESOURCE_MANAGER_VALID | NTFS_SD_DACL_PRESENT,
	    sizeof(header->control));
	/* Group precedes owner; identical owner/group spans are valid. */
	store(header->group, position, sizeof(header->group));
	store(header->owner, position, sizeof(header->owner));
	position += make_sid(bytes + position, NTFS_SID_MAX_SUBAUTHORITIES);
	acl_offset = position;
	acl = (void *)(bytes + position);
	store(header->dacl, position, sizeof(header->dacl));
	acl->revision = object ? TEST_OBJECT_ACL_REVISION : TEST_ACL_REVISION;
	store(acl->count, 2, sizeof(acl->count));
	position += sizeof(*acl);
	/* Preserve a noncanonical allow/deny order; decoding must not sort it. */
	length = make_ace(ace, object ? NTFS_ACE_ALLOW_OBJECT : NTFS_ACE_ALLOW, object,
	    NTFS_ACE_OBJECT_TYPE_PRESENT, false);
	memcpy(bytes + position, ace, length);
	position += length;
	length = make_ace(ace, NTFS_ACE_DENY_CALLBACK, false, 0, true);
	memcpy(bytes + position, ace, length);
	position += length;
	store(acl->length, position - acl_offset, sizeof(acl->length));
	return position;
}

static void
check_descriptor(const void *buffer, size_t size, enum ntfs_result expected)
{
	struct ntfs_security_info info, zero = {0};
	enum ntfs_result result;

	memset(&info, TEST_INITIAL_FILL, sizeof(info));
	result = ntfs_security_decode(buffer, size, &info);
	assert(result == expected);
	if (result != NTFS_OK) {
		assert(memcmp(&info, &zero, sizeof(info)) == 0);
	}
}

static void
descriptor_tests(void)
{
	uint8_t buffer[TEST_BUFFER_BYTES], changed[TEST_BUFFER_BYTES];
	struct test_descriptor *header = (void *)buffer;
	struct test_descriptor *changed_header = (void *)changed;
	struct test_acl *acl;
	struct test_ace *ace;
	struct ntfs_security_info info, zero = {0};
	size_t length, i, position, bit;
	enum ntfs_result result;

	length = make_descriptor(buffer, false);
	assert(ntfs_security_decode(buffer, length, &info) == NTFS_OK);
	assert(info.owner_span.offset == info.group_span.offset &&
	    info.owner.count == NTFS_SID_MAX_SUBAUTHORITIES);
	assert(info.owner.authority == TEST_AUTHORITY);
	assert(info.owner.subauthorities[NTFS_SID_MAX_SUBAUTHORITIES - 1] ==
	    TEST_SUBAUTHORITY + NTFS_SID_MAX_SUBAUTHORITIES - 1);
	assert(info.dacl.state == NTFS_ACL_PRESENT && info.dacl.entries == 2 &&
	    info.dacl.application_data && !info.dacl.opaque_aces);
	assert(info.sacl.state == NTFS_ACL_ABSENT && info.resource_manager == TEST_INITIAL_FILL);
	for (i = 0; i < length; i++) {
		check_descriptor(buffer, i, NTFS_CORRUPT);
	}
	check_descriptor(buffer, sizeof(buffer), NTFS_OK);
	check_descriptor(NULL, length, NTFS_INVALID);
	check_descriptor(buffer, NTFS_SECURITY_MAX_BYTES + 1, NTFS_RANGE);
	assert(ntfs_security_decode(buffer, length, NULL) == NTFS_INVALID);
	for (i = 0; i < TEST_METADATA_MUTATIONS; i++) {
		memcpy(changed, buffer, length);
		position = i % length;
		bit = i / length % TEST_BITS_PER_BYTE;
		changed[position] ^= (uint8_t)(1u << bit);
		memset(&info, TEST_INITIAL_FILL, sizeof(info));
		result = ntfs_security_decode(changed, length, &info);
		if (result != NTFS_OK) {
			assert(memcmp(&info, &zero, sizeof(info)) == 0);
		}
	}
	memcpy(changed, buffer, length);
	store(changed_header->owner, UINT32_MAX, sizeof(changed_header->owner));
	check_descriptor(changed, length, NTFS_CORRUPT);
	memcpy(changed, buffer, length);
	store(changed_header->group, sizeof(*header) - 1, sizeof(changed_header->group));
	check_descriptor(changed, length, NTFS_CORRUPT);
	memcpy(changed, buffer, length);
	store(changed_header->control, NTFS_SD_DACL_PRESENT, sizeof(changed_header->control));
	check_descriptor(changed, length, NTFS_UNSUPPORTED);
	length = make_descriptor(buffer, true);
	assert(ntfs_security_decode(buffer, length, &info) == NTFS_OK);
	acl = (void *)(buffer + info.dacl.span.offset);
	acl->revision = TEST_ACL_REVISION;
	check_descriptor(buffer, length, NTFS_CORRUPT);
	length = make_descriptor(buffer, false);
	assert(ntfs_security_decode(buffer, length, &info) == NTFS_OK);
	acl = (void *)(buffer + info.dacl.span.offset);
	ace = (void *)((uint8_t *)acl + sizeof(*acl));
	store(ace->length, 0, sizeof(ace->length));
	check_descriptor(buffer, length, NTFS_CORRUPT);
	length = make_descriptor(buffer, false);
	assert(ntfs_security_decode(buffer, length, &info) == NTFS_OK);
	acl = (void *)(buffer + info.dacl.span.offset);
	store(acl->count, UINT16_MAX, sizeof(acl->count));
	check_descriptor(buffer, length, NTFS_CORRUPT);
	length = make_descriptor(buffer, false);
	assert(ntfs_security_decode(buffer, length, &info) == NTFS_OK);
	acl = (void *)(buffer + info.dacl.span.offset);
	ace = (void *)((uint8_t *)acl + sizeof(*acl));
	ace->type = TEST_UNKNOWN_ACE;
	assert(ntfs_security_decode(buffer, length, &info) == NTFS_OK && info.dacl.opaque_aces);
	acl->reserved1 = 1;
	check_descriptor(buffer, length, NTFS_CORRUPT);
	length = make_descriptor(buffer, false);
	assert(ntfs_security_decode(buffer, length, &info) == NTFS_OK);
	acl = (void *)(buffer + info.dacl.span.offset);
	store(acl->count, 0, sizeof(acl->count));
	assert(ntfs_security_decode(buffer, length, &info) == NTFS_OK &&
	    info.dacl.state == NTFS_ACL_EMPTY);
	/* A present NULL DACL differs from both absent and empty DACL states. */
	store(header->dacl, 0, sizeof(header->dacl));
	assert(ntfs_security_decode(buffer, length, &info) == NTFS_OK &&
	    info.dacl.state == NTFS_ACL_NULL);
	store(header->control, NTFS_SD_SELF_RELATIVE, sizeof(header->control));
	assert(ntfs_security_decode(buffer, length, &info) == NTFS_OK &&
	    info.dacl.state == NTFS_ACL_ABSENT);
	store(header->dacl, sizeof(*header), sizeof(header->dacl));
	check_descriptor(buffer, length, NTFS_CORRUPT);
}

int
main(void)
{
	sid_tests();
	ace_tests();
	descriptor_tests();
	puts(
	    "PASS: bounded self-relative descriptors, lossless SID values, absent/null/empty ACLs, "
	    "object/callback/opaque ACEs and corruption boundaries; no access decisions");
	return 0;
}
