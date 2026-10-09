/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "security_edit.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_BITS_PER_BYTE = 8,
	TEST_ALIGNMENT = sizeof(uint32_t),
	TEST_DESCRIPTOR_REVISION = 1,
	TEST_SID_REVISION = 1,
	TEST_ACL_REVISION = 2,
	TEST_OBJECT_ACL_REVISION = 4,
	TEST_AUTHORITY_BYTES = 6,
	TEST_UNKNOWN_ACE = 0xfe,
	TEST_FILL = 0x5a,
	TEST_BUFFER_BYTES = 256,
	TEST_SIZE_SENTINEL = 0x1234,
	TEST_DACL_BITS = 0x150c,
	TEST_SELF_RELATIVE = 0x8000,
	TEST_DACL_PRESENT = 0x0004,
	TEST_SACL_PRESENT = 0x0010,
	TEST_DACL_PROTECTED = 0x1000,
	TEST_UNSUPPORTED_OBJECT_FLAG = 0x00000004
};

/* Independent named wire layouts, not the core's disk structures. */
struct wire_descriptor {
	uint8_t revision, manager, control[sizeof(uint16_t)];
	uint8_t owner[sizeof(uint32_t)], group[sizeof(uint32_t)];
	uint8_t sacl[sizeof(uint32_t)], dacl[sizeof(uint32_t)];
};

struct wire_sid {
	uint8_t revision, count, authority[TEST_AUTHORITY_BYTES];
	uint8_t subauthorities[NTFS_SID_MAX_SUBAUTHORITIES][sizeof(uint32_t)];
};

struct wire_acl {
	uint8_t revision, reserved1, length[sizeof(uint16_t)];
	uint8_t count[sizeof(uint16_t)], reserved2[sizeof(uint16_t)];
};

struct wire_ace {
	uint8_t type, flags, length[sizeof(uint16_t)];
};

struct component {
	const uint8_t *bytes;
	size_t length;
	uint32_t offset;
};

/* Literal packets independently transcribed from MS-DTYP field descriptions.
 * Original: empty DACL, group, opaque SACL with free space, owner, unused tail.
 * Donor: callback + unknown ACE, four free ACL bytes; its generic mask, flags,
 * application data and unknown body are intentionally copied exactly. */
static const uint8_t original_golden[] = {
    1, 0x7c, 0xff, 0xfa, 0x38, 0, 0, 0, 0x1c, 0, 0, 0, 0x28, 0, 0, 0, 0x14, 0, 0, 0,
    2, 0, 8, 0, 0, 0, 0, 0,
    1, 1, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0,
    2, 0, 0x10, 0, 1, 0, 0, 0, 0xfe, 0x81, 4, 0, 0xde, 0xad, 0xbe, 0xef,
    1, 1, 0, 0, 0, 0, 0, 5, 0x12, 0, 0, 0,
    0xa1, 0xb2, 0xc3, 0xd4
};

static const uint8_t donor_golden[] = {
    1, 0xa6, 4, 0x85, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x14, 0, 0, 0,
    4, 0, 0x2c, 0, 2, 0, 0, 0,
    9, 0x1b, 0x18, 0, 1, 0, 0, 0x80, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
    0x61, 0x72, 0x74, 0x78,
    0xfd, 0xa5, 8, 0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0
};

static const uint8_t edited_golden[] = {
    1, 0x7c, 0xf7, 0xef, 0x14, 0, 0, 0, 0x20, 0, 0, 0, 0x2c, 0, 0, 0, 0x3c, 0, 0, 0,
    1, 1, 0, 0, 0, 0, 0, 5, 0x12, 0, 0, 0,
    1, 1, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0,
    2, 0, 0x10, 0, 1, 0, 0, 0, 0xfe, 0x81, 4, 0, 0xde, 0xad, 0xbe, 0xef,
    4, 0, 0x2c, 0, 2, 0, 0, 0,
    9, 0x1b, 0x18, 0, 1, 0, 0, 0x80, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
    0x61, 0x72, 0x74, 0x78,
    0xfd, 0xa5, 8, 0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0
};

static uint32_t
load(const void *buffer, size_t bytes)
{
	const uint8_t *input = buffer;
	uint32_t value = 0;
	size_t index;

	assert(bytes <= sizeof(value));
	for (index = 0; index < bytes; index++) {
		value |= (uint32_t)input[index] << (index * TEST_BITS_PER_BYTE);
	}
	return value;
}

static void
store(void *buffer, uint32_t value, size_t bytes)
{
	uint8_t *output = buffer;
	size_t index;

	for (index = 0; index < bytes; index++) {
		output[index] = (uint8_t)value;
		value >>= TEST_BITS_PER_BYTE;
	}
}

static struct component
read_component(const void *buffer, size_t size, const uint8_t *field, bool acl)
{
	const uint8_t *bytes = buffer;
	const struct wire_acl *header;
	const struct wire_sid *sid;
	struct component result = {0};

	result.offset = load(field, sizeof(uint32_t));
	if (result.offset == 0) {
		return result;
	}
	assert(result.offset >= sizeof(struct wire_descriptor) && result.offset <= size);
	result.bytes = bytes + result.offset;
	if (acl) {
		assert(size - result.offset >= sizeof(*header));
		header = (const void *)result.bytes;
		result.length = load(header->length, sizeof(header->length));
	} else {
		assert(size - result.offset >= offsetof(struct wire_sid, subauthorities));
		sid = (const void *)result.bytes;
		result.length = offsetof(struct wire_sid, subauthorities) +
		    sid->count * sizeof(uint32_t);
	}
	assert(result.length <= size - result.offset);
	return result;
}

static void
same_component(struct component source, struct component output)
{
	assert(source.length == output.length);
	assert(output.offset % TEST_ALIGNMENT == 0);
	if (source.length != 0) {
		assert(memcmp(source.bytes, output.bytes, source.length) == 0);
	}
}

static void
component_oracle(const struct ntfs_security_edit_input *input, const void *output, size_t size)
{
	const struct wire_descriptor *original = input->original, *donor = input->dacl_source;
	const struct wire_descriptor *edited = output;
	struct component owner, group, sacl, dacl;
	uint32_t old_control, donor_control, control;

	assert(size >= sizeof(*edited) && size <= NTFS_SECURITY_MAX_BYTES);
	assert(edited->revision == original->revision && edited->manager == original->manager);
	old_control = load(original->control, sizeof(original->control));
	donor_control = load(donor->control, sizeof(donor->control));
	control = load(edited->control, sizeof(edited->control));
	assert((control & TEST_DACL_BITS) == (donor_control & TEST_DACL_BITS));
	assert((control & ~TEST_DACL_BITS) == (old_control & ~TEST_DACL_BITS));
	owner = read_component(output, size, edited->owner, false);
	group = read_component(output, size, edited->group, false);
	sacl = read_component(output, size, edited->sacl, true);
	dacl = read_component(output, size, edited->dacl, true);
	same_component(read_component(input->original, input->original_bytes, original->owner, false), owner);
	same_component(read_component(input->original, input->original_bytes, original->group, false), group);
	same_component(read_component(input->original, input->original_bytes, original->sacl, true), sacl);
	same_component(read_component(input->dacl_source, input->dacl_source_bytes, donor->dacl, true), dacl);
	/* Components must be independent output storage even if inputs alias. */
	if (owner.length != 0 && group.length != 0) {
		assert(owner.offset + owner.length <= group.offset);
	}
	if (group.length != 0 && sacl.length != 0) {
		assert(group.offset + group.length <= sacl.offset);
	}
	if (sacl.length != 0 && dacl.length != 0) {
		assert(sacl.offset + sacl.length <= dacl.offset);
	}
}

static void
check_failure(const struct ntfs_security_edit_input *input, enum ntfs_result expected)
{
	uint8_t output[TEST_BUFFER_BYTES], before[TEST_BUFFER_BYTES];
	size_t size = TEST_SIZE_SENTINEL;

	memset(output, TEST_FILL, sizeof(output));
	memcpy(before, output, sizeof(before));
	assert(ntfs_security_edit_dacl_size(input, &size) == expected);
	assert(size == TEST_SIZE_SENTINEL);
	assert(ntfs_security_edit_dacl_encode(input, output, sizeof(output), &size) == expected);
	assert(size == TEST_SIZE_SENTINEL && memcmp(output, before, sizeof(output)) == 0);
}

static void
check_success(const struct ntfs_security_edit_input *input)
{
	uint8_t output[TEST_BUFFER_BYTES], before[TEST_BUFFER_BYTES];
	uint8_t original[TEST_BUFFER_BYTES], donor[TEST_BUFFER_BYTES];
	size_t size = TEST_SIZE_SENTINEL, written, index;

	assert(input->original_bytes <= sizeof(original) && input->dacl_source_bytes <= sizeof(donor));
	memcpy(original, input->original, input->original_bytes);
	memcpy(donor, input->dacl_source, input->dacl_source_bytes);
	assert(ntfs_security_edit_dacl_size(input, &size) == NTFS_OK);
	assert(size < sizeof(output));
	memset(output, TEST_FILL, sizeof(output));
	memcpy(before, output, sizeof(before));
	written = TEST_SIZE_SENTINEL;
	assert(ntfs_security_edit_dacl_encode(input, output, size - 1, &written) == NTFS_RANGE);
	assert(written == TEST_SIZE_SENTINEL && memcmp(output, before, sizeof(output)) == 0);
	assert(ntfs_security_edit_dacl_encode(input, output, size, &written) == NTFS_OK);
	assert(written == size);
	component_oracle(input, output, size);
	for (index = size; index < sizeof(output); index++) {
		assert(output[index] == TEST_FILL);
	}
	assert(ntfs_security_edit_dacl_encode(input, output, size + 1, &written) == NTFS_OK);
	component_oracle(input, output, written);
	assert(output[size] == TEST_FILL);
	assert(memcmp(original, input->original, input->original_bytes) == 0);
	assert(memcmp(donor, input->dacl_source, input->dacl_source_bytes) == 0);
}

static void
golden_tests(void)
{
	struct ntfs_security_edit_input input = {original_golden, donor_golden,
	    sizeof(original_golden), sizeof(donor_golden)};
	uint8_t output[TEST_BUFFER_BYTES];
	size_t size = 0;

	check_success(&input);
	assert(ntfs_security_edit_dacl_encode(&input, output, sizeof(output), &size) == NTFS_OK);
	assert(size == sizeof(edited_golden) && memcmp(output, edited_golden, size) == 0);
	input.original = output;
	input.original_bytes = size;
	input.dacl_source = output;
	input.dacl_source_bytes = size;
	check_success(&input);
}

static size_t
make_sid(void *buffer, uint8_t count)
{
	struct wire_sid *sid = buffer;
	size_t index, bytes = offsetof(struct wire_sid, subauthorities) + count * sizeof(uint32_t);

	assert(count <= NTFS_SID_MAX_SUBAUTHORITIES);
	memset(buffer, 0, bytes);
	sid->revision = TEST_SID_REVISION;
	sid->count = count;
	sid->authority[TEST_AUTHORITY_BYTES - 1] = 5;
	for (index = 0; index < count; index++) {
		store(sid->subauthorities[index], (uint32_t)index + 1, sizeof(uint32_t));
	}
	return bytes;
}

static size_t
make_acl(void *buffer, size_t bytes, uint16_t entries)
{
	struct wire_acl *acl = buffer;
	struct wire_ace *ace;
	size_t index;

	assert(bytes <= UINT16_MAX && bytes >= sizeof(*acl));
	assert(entries <= (bytes - sizeof(*acl)) / sizeof(*ace));
	memset(buffer, TEST_FILL, bytes);
	memset(acl, 0, sizeof(*acl));
	acl->revision = TEST_ACL_REVISION;
	store(acl->length, (uint32_t)bytes, sizeof(acl->length));
	store(acl->count, entries, sizeof(acl->count));
	for (index = 0; index < entries; index++) {
		ace = (void *)((uint8_t *)buffer + sizeof(*acl) + index * sizeof(*ace));
		ace->type = TEST_UNKNOWN_ACE;
		ace->flags = (uint8_t)index;
		store(ace->length, sizeof(*ace), sizeof(ace->length));
	}
	return bytes;
}

static size_t
make_descriptor(void *buffer, enum ntfs_acl_state dacl, enum ntfs_acl_state sacl,
    uint16_t control)
{
	struct wire_descriptor *header = buffer;
	size_t size = sizeof(*header);

	memset(buffer, 0, TEST_BUFFER_BYTES);
	header->revision = TEST_DESCRIPTOR_REVISION;
	header->manager = TEST_FILL;
	control = (uint16_t)((control | TEST_SELF_RELATIVE) &
	    ~(TEST_DACL_PRESENT | TEST_SACL_PRESENT));
	if (dacl != NTFS_ACL_ABSENT) {
		control |= TEST_DACL_PRESENT;
	}
	if (sacl != NTFS_ACL_ABSENT) {
		control |= TEST_SACL_PRESENT;
	}
	store(header->control, control, sizeof(header->control));
	if (sacl == NTFS_ACL_EMPTY || sacl == NTFS_ACL_PRESENT) {
		store(header->sacl, (uint32_t)size, sizeof(header->sacl));
		size += make_acl((uint8_t *)buffer + size,
		    sizeof(struct wire_acl) + sizeof(struct wire_ace), sacl == NTFS_ACL_PRESENT);
	}
	if (dacl == NTFS_ACL_EMPTY || dacl == NTFS_ACL_PRESENT) {
		store(header->dacl, (uint32_t)size, sizeof(header->dacl));
		size += make_acl((uint8_t *)buffer + size,
		    sizeof(struct wire_acl) + sizeof(struct wire_ace), dacl == NTFS_ACL_PRESENT);
	}
	return size;
}

static void
state_control_tests(void)
{
	uint8_t original[TEST_BUFFER_BYTES], donor[TEST_BUFFER_BYTES];
	struct ntfs_security_edit_input input = {original, donor, 0, 0};
	unsigned old_state, new_state, sacl_state, bit;

	for (old_state = NTFS_ACL_ABSENT; old_state <= NTFS_ACL_PRESENT; old_state++) {
		for (new_state = NTFS_ACL_ABSENT; new_state <= NTFS_ACL_PRESENT; new_state++) {
			for (sacl_state = NTFS_ACL_ABSENT; sacl_state <= NTFS_ACL_PRESENT; sacl_state++) {
				for (bit = 0; bit < sizeof(uint16_t) * TEST_BITS_PER_BYTE; bit++) {
					input.original_bytes = make_descriptor(original,
					    (enum ntfs_acl_state)old_state, (enum ntfs_acl_state)sacl_state,
					    (uint16_t)(1u << bit));
					input.dacl_source_bytes = make_descriptor(donor,
					    (enum ntfs_acl_state)new_state, NTFS_ACL_NULL,
					    (uint16_t)~(1u << bit));
					check_success(&input);
				}
			}
		}
	}
}

static void
truncation_tests(void)
{
	struct ntfs_security_edit_input input = {original_golden, donor_golden,
	    sizeof(original_golden), sizeof(donor_golden)};
	size_t size;

	for (size = 0; size < sizeof(donor_golden); size++) {
		input.dacl_source_bytes = size;
		check_failure(&input, NTFS_CORRUPT);
	}
	input.dacl_source_bytes = sizeof(donor_golden);
	/* The original's final DWORD is unused descriptor storage. */
	for (size = 0; size < sizeof(original_golden) - sizeof(uint32_t); size++) {
		input.original_bytes = size;
		check_failure(&input, NTFS_CORRUPT);
	}
	for (; size <= sizeof(original_golden); size++) {
		input.original_bytes = size;
		check_success(&input);
	}
}

static void
malformed_tests(void)
{
	uint8_t original[TEST_BUFFER_BYTES], donor[TEST_BUFFER_BYTES];
	struct wire_descriptor *header = (void *)donor;
	struct wire_acl *acl = (void *)(donor + sizeof(*header));
	struct wire_ace *ace = (void *)((uint8_t *)acl + sizeof(*acl));
	struct ntfs_security_edit_input input = {original, donor,
	    sizeof(original_golden), sizeof(donor_golden)};

	memcpy(original, original_golden, sizeof(original_golden));
	memcpy(donor, donor_golden, sizeof(donor_golden));
	header->revision++;
	check_failure(&input, NTFS_CORRUPT);
	header->revision--;
	store(header->control, TEST_DACL_PRESENT, sizeof(header->control));
	check_failure(&input, NTFS_UNSUPPORTED);
	memcpy(donor, donor_golden, sizeof(donor_golden));
	store(header->control, TEST_SELF_RELATIVE, sizeof(header->control));
	check_failure(&input, NTFS_CORRUPT);
	memcpy(donor, donor_golden, sizeof(donor_golden));
	acl->reserved1 = 1;
	check_failure(&input, NTFS_CORRUPT);
	acl->reserved1 = 0;
	acl->reserved2[0] = 1;
	check_failure(&input, NTFS_CORRUPT);
	acl->reserved2[0] = 0;
	acl->revision = 3;
	check_failure(&input, NTFS_UNSUPPORTED);
	acl->revision = TEST_OBJECT_ACL_REVISION;
	store(acl->count, UINT16_MAX, sizeof(acl->count));
	check_failure(&input, NTFS_CORRUPT);
	memcpy(donor, donor_golden, sizeof(donor_golden));
	store(ace->length, 0, sizeof(ace->length));
	check_failure(&input, NTFS_CORRUPT);
	store(ace->length, sizeof(*ace) + 1, sizeof(ace->length));
	check_failure(&input, NTFS_CORRUPT);
	store(ace->length, UINT16_MAX, sizeof(ace->length));
	check_failure(&input, NTFS_CORRUPT);
	memcpy(donor, donor_golden, sizeof(donor_golden));
	/* Known object ACEs with unknown object flags are not opaque escapes. */
	ace->type = NTFS_ACE_ALLOW_OBJECT;
	store((uint8_t *)ace + sizeof(*ace) + sizeof(uint32_t),
	    TEST_UNSUPPORTED_OBJECT_FLAG, sizeof(uint32_t));
	check_failure(&input, NTFS_UNSUPPORTED);
	memcpy(donor, donor_golden, sizeof(donor_golden));
	/* Validate even donor fields that are not selected for copying. */
	store(header->owner, sizeof(*header) - 1, sizeof(header->owner));
	check_failure(&input, NTFS_CORRUPT);
	memcpy(donor, donor_golden, sizeof(donor_golden));
	((struct wire_descriptor *)(void *)original)->dacl[0] = 1;
	check_failure(&input, NTFS_CORRUPT);
}

static void
component_alias_tests(void)
{
	uint8_t buffer[TEST_BUFFER_BYTES];
	struct wire_descriptor *header = (void *)buffer;
	struct wire_acl *acl;
	struct wire_ace *ace;
	struct ntfs_security_edit_input input = {buffer, buffer, 0, 0};
	size_t size;

	size = make_descriptor(buffer, NTFS_ACL_PRESENT, NTFS_ACL_ABSENT, 0);
	/* Exact owner/group and SACL/DACL aliases become independent copies. */
	store(header->sacl, sizeof(*header), sizeof(header->sacl));
	store(header->control, TEST_SELF_RELATIVE | TEST_DACL_PRESENT | TEST_SACL_PRESENT,
	    sizeof(header->control));
	store(header->owner, (uint32_t)size, sizeof(header->owner));
	store(header->group, (uint32_t)size, sizeof(header->group));
	size += make_sid(buffer + size, NTFS_SID_MAX_SUBAUTHORITIES);
	input.original_bytes = size;
	input.dacl_source_bytes = size;
	check_success(&input);
	/* Input component order and byte alignment are not decoder restrictions.
	 * New output offsets are aligned while the exact component is preserved. */
	memmove(buffer + sizeof(*header) + 1, buffer + sizeof(*header), size - sizeof(*header));
	header->owner[0]++;
	header->group[0]++;
	header->sacl[0]++;
	header->dacl[0]++;
	input.original_bytes++;
	input.dacl_source_bytes++;
	check_success(&input);
	/* A zero-subauthority SID inside an opaque ACE is a partial component
	 * overlap. The existing decoder admits each independently checked span. */
	size = make_descriptor(buffer, NTFS_ACL_PRESENT, NTFS_ACL_ABSENT, 0);
	acl = (void *)(buffer + sizeof(*header));
	ace = (void *)((uint8_t *)acl + sizeof(*acl));
	size += make_sid(buffer + size, 0);
	store(acl->length, (uint32_t)(size - sizeof(*header)), sizeof(acl->length));
	store(ace->length, (uint32_t)(size - sizeof(*header) - sizeof(*acl)), sizeof(ace->length));
	store(header->owner, sizeof(*header) + sizeof(*acl) + sizeof(*ace), sizeof(header->owner));
	store(header->group, load(header->owner, sizeof(header->owner)), sizeof(header->group));
	input.original_bytes = size;
	input.dacl_source_bytes = size;
	check_success(&input);
	/* Source descriptors may also overlap each other at different bases. */
	memcpy(buffer, original_golden, sizeof(original_golden));
	memcpy(buffer + sizeof(original_golden), donor_golden, sizeof(donor_golden));
	input.original_bytes = sizeof(original_golden) + sizeof(donor_golden);
	input.dacl_source = buffer + sizeof(original_golden);
	input.dacl_source_bytes = sizeof(donor_golden);
	check_success(&input);
}

static void
argument_alias_tests(void)
{
	union {
		max_align_t alignment;
		uint8_t bytes[TEST_BUFFER_BYTES * 2];
	} storage;
	uint8_t before[sizeof(storage.bytes)], output[TEST_BUFFER_BYTES];
	struct ntfs_security_edit_input input = {storage.bytes, donor_golden,
	    sizeof(original_golden), sizeof(donor_golden)}, saved;
	size_t written = TEST_SIZE_SENTINEL, index;

	memset(storage.bytes, TEST_FILL, sizeof(storage.bytes));
	memcpy(storage.bytes, original_golden, sizeof(original_golden));
	memcpy(before, storage.bytes, sizeof(before));
	for (index = 0; index < sizeof(original_golden); index++) {
		assert(ntfs_security_edit_dacl_encode(&input, storage.bytes + index,
		    TEST_BUFFER_BYTES, &written) == NTFS_INVALID);
		assert(written == TEST_SIZE_SENTINEL);
		assert(memcmp(storage.bytes, before, sizeof(before)) == 0);
	}
	assert(ntfs_security_edit_dacl_size(&input, (size_t *)(void *)storage.bytes) == NTFS_INVALID);
	assert(ntfs_security_edit_dacl_encode(&input, output, sizeof(output),
	    (size_t *)(void *)storage.bytes) == NTFS_INVALID);
	assert(memcmp(storage.bytes, before, sizeof(before)) == 0);
	assert(ntfs_security_edit_dacl_encode(&input, (void *)donor_golden,
	    sizeof(donor_golden), &written) == NTFS_INVALID);
	/* Even unreferenced trailing source bytes belong to the immutable range. */
	input.original_bytes = TEST_BUFFER_BYTES;
	assert(ntfs_security_edit_dacl_encode(&input, storage.bytes + sizeof(original_golden),
	    TEST_BUFFER_BYTES, &written) == NTFS_INVALID);
	assert(memcmp(storage.bytes, before, sizeof(before)) == 0);
	input.original_bytes = sizeof(original_golden);
	/* The written slot aliases output capacity beyond the produced extent. */
	assert(ntfs_security_edit_dacl_encode(&input, storage.bytes + TEST_BUFFER_BYTES,
	    TEST_BUFFER_BYTES, (size_t *)(void *)(storage.bytes + sizeof(storage.bytes) - sizeof(size_t))) == NTFS_INVALID);
	assert(memcmp(storage.bytes, before, sizeof(before)) == 0);
	saved = input;
	assert(ntfs_security_edit_dacl_size(&input, &input.original_bytes) == NTFS_INVALID);
	assert(ntfs_security_edit_dacl_encode(&input, &input, sizeof(input), &written) == NTFS_INVALID);
	assert(memcmp(&input, &saved, sizeof(input)) == 0);
	assert(ntfs_security_edit_dacl_encode(&input, output, sizeof(output), &input.original_bytes) == NTFS_INVALID);
	assert(ntfs_security_edit_dacl_size(&input, NULL) == NTFS_INVALID);
	assert(ntfs_security_edit_dacl_encode(&input, NULL, 0, &written) == NTFS_INVALID);
	assert(ntfs_security_edit_dacl_encode(&input, output, sizeof(output), NULL) == NTFS_INVALID);
	assert(ntfs_security_edit_dacl_encode(&input, (void *)(uintptr_t)(UINTPTR_MAX - 1),
	    sizeof(struct wire_descriptor), &written) == NTFS_INVALID);
	check_failure(NULL, NTFS_INVALID);
	input.original = NULL;
	check_failure(&input, NTFS_INVALID);
	input = saved;
	input.original = (void *)(uintptr_t)(UINTPTR_MAX - 1);
	check_failure(&input, NTFS_INVALID);
	input = saved;
	input.dacl_source_bytes = NTFS_SECURITY_MAX_BYTES + 1u;
	check_failure(&input, NTFS_RANGE);
	input = saved;
	input.original_bytes = SIZE_MAX;
	check_failure(&input, NTFS_RANGE);
}

static void
maximum_tests(void)
{
	const size_t maximum_acl = UINT16_MAX;
	const uint16_t maximum_entries = (uint16_t)((UINT16_MAX - sizeof(struct wire_acl)) /
	    sizeof(struct wire_ace));
	uint8_t *original = malloc(NTFS_SECURITY_MAX_BYTES), *output = malloc(NTFS_SECURITY_MAX_BYTES);
	struct wire_descriptor *header = (void *)original;
	struct wire_acl *acl;
	struct ntfs_security_edit_input input = {original, original, 0, 0};
	size_t position = sizeof(*header), size, written, index;

	assert(original != NULL && output != NULL);
	memset(original, TEST_FILL, NTFS_SECURITY_MAX_BYTES);
	memset(header, 0, sizeof(*header));
	header->revision = TEST_DESCRIPTOR_REVISION;
	store(header->control, TEST_SELF_RELATIVE | TEST_DACL_PRESENT | TEST_SACL_PRESENT,
	    sizeof(header->control));
	store(header->owner, (uint32_t)position, sizeof(header->owner));
	position += make_sid(original + position, NTFS_SID_MAX_SUBAUTHORITIES);
	store(header->group, (uint32_t)position, sizeof(header->group));
	position += make_sid(original + position, NTFS_SID_MAX_SUBAUTHORITIES);
	store(header->sacl, (uint32_t)position, sizeof(header->sacl));
	position += make_acl(original + position, maximum_acl, maximum_entries);
	/* Deliberately no input alignment padding before the second maximum ACL. */
	store(header->dacl, (uint32_t)position, sizeof(header->dacl));
	acl = (void *)(original + position);
	position += make_acl(acl, maximum_acl, maximum_entries);
	input.original_bytes = NTFS_SECURITY_MAX_BYTES;
	input.dacl_source_bytes = NTFS_SECURITY_MAX_BYTES;
	assert(ntfs_security_edit_dacl_size(&input, &size) == NTFS_OK);
	assert(size == position + 1);
	memset(output, TEST_FILL, NTFS_SECURITY_MAX_BYTES);
	written = TEST_SIZE_SENTINEL;
	assert(ntfs_security_edit_dacl_encode(&input, output, size - 1, &written) == NTFS_RANGE);
	assert(written == TEST_SIZE_SENTINEL);
	for (index = 0; index < NTFS_SECURITY_MAX_BYTES; index++) {
		assert(output[index] == TEST_FILL);
	}
	assert(ntfs_security_edit_dacl_encode(&input, output, size, &written) == NTFS_OK);
	assert(written == size && output[size] == TEST_FILL);
	component_oracle(&input, output, size);
	assert(output[load(((struct wire_descriptor *)(void *)output)->dacl, sizeof(uint32_t)) - 1] == 0);
	assert(ntfs_security_edit_dacl_encode(&input, output, size + 1, &written) == NTFS_OK);
	assert(output[size] == TEST_FILL);
	store(acl->count, maximum_entries + 1u, sizeof(acl->count));
	check_failure(&input, NTFS_CORRUPT);
	store(acl->count, UINT16_MAX, sizeof(acl->count));
	check_failure(&input, NTFS_CORRUPT);
	store(acl->count, maximum_entries, sizeof(acl->count));
	input.original_bytes++;
	check_failure(&input, NTFS_RANGE);
	free(output);
	free(original);
}

static void
mutation_tests(void)
{
	uint8_t original[sizeof(original_golden)], donor[sizeof(donor_golden)];
	struct ntfs_security_edit_input input = {original, donor, sizeof(original), sizeof(donor)};
	uint8_t *selected;
	size_t index, size;
	unsigned source, bit;
	enum ntfs_result result;

	memcpy(original, original_golden, sizeof(original));
	memcpy(donor, donor_golden, sizeof(donor));
	for (source = 0; source < 2; source++) {
		selected = source == 0 ? original : donor;
		for (index = 0; index < (source == 0 ? sizeof(original) : sizeof(donor)); index++) {
			for (bit = 0; bit < TEST_BITS_PER_BYTE; bit++) {
				selected[index] ^= (uint8_t)(1u << bit);
				result = ntfs_security_edit_dacl_size(&input, &size);
				if (result == NTFS_OK) {
					check_success(&input);
				} else {
					check_failure(&input, result);
				}
				selected[index] ^= (uint8_t)(1u << bit);
			}
		}
	}
	assert(memcmp(original, original_golden, sizeof(original)) == 0);
	assert(memcmp(donor, donor_golden, sizeof(donor)) == 0);
}

int
main(void)
{
	golden_tests();
	state_control_tests();
	truncation_tests();
	malformed_tests();
	component_alias_tests();
	argument_alias_tests();
	maximum_tests();
	mutation_tests();
	puts("security editing: literal wire, component preservation, states, bounds and aliases passed");
	return 0;
}
