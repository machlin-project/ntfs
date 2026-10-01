/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include <ntfs/security.h>

enum {
	SECURITY_DESCRIPTOR_REVISION = 1,
	SECURITY_SID_REVISION = 1,
	SECURITY_ACL_REVISION = 2,
	SECURITY_ACL_OBJECT_REVISION = 4,
	SECURITY_DWORD_ALIGNMENT = sizeof(uint32_t),
	SECURITY_AUTHORITY_BYTES = 6
};

struct disk_security_descriptor {
	uint8_t revision, resource_manager, control[sizeof(uint16_t)];
	uint8_t owner[sizeof(uint32_t)], group[sizeof(uint32_t)];
	uint8_t sacl[sizeof(uint32_t)], dacl[sizeof(uint32_t)];
};

struct disk_sid {
	uint8_t revision, count, authority[SECURITY_AUTHORITY_BYTES];
};

struct disk_acl {
	uint8_t revision, reserved1, length[sizeof(uint16_t)];
	uint8_t count[sizeof(uint16_t)], reserved2[sizeof(uint16_t)];
};

struct disk_ace {
	uint8_t type, flags, length[sizeof(uint16_t)];
};

_Static_assert(sizeof(struct disk_security_descriptor) == 20, "self-relative descriptor header");
_Static_assert(sizeof(struct disk_sid) == 8, "SID header");
_Static_assert(sizeof(struct disk_acl) == 8, "ACL header");
_Static_assert(sizeof(struct disk_ace) == 4, "ACE header");

static enum ntfs_result
decode_sid(const uint8_t *bytes, size_t available, struct ntfs_sid *sid, uint32_t *length)
{
	const struct disk_sid *header;
	size_t size, i;

	if (available < sizeof(*header)) {
		return NTFS_CORRUPT;
	}
	header = (const void *)bytes;
	if (header->revision != SECURITY_SID_REVISION ||
	    header->count > NTFS_SID_MAX_SUBAUTHORITIES) {
		return NTFS_CORRUPT;
	}
	size = sizeof(*header) + (size_t)header->count * sizeof(uint32_t);
	if (size > available) {
		return NTFS_CORRUPT;
	}
	sid->count = header->count;
	/* IdentifierAuthority is a six-byte big-endian integer; subauthorities
	 * use the descriptor's little-endian DWORD representation. */
	for (i = 0; i < sizeof(header->authority); i++) {
		sid->authority = sid->authority << NTFS_BITS_PER_BYTE | header->authority[i];
	}
	for (i = 0; i < header->count; i++) {
		sid->subauthorities[i] = ntfs_u32(bytes + sizeof(*header) + i * sizeof(uint32_t));
	}
	*length = (uint32_t)size;
	return NTFS_OK;
}

static bool
object_ace(uint8_t type)
{
	return type == NTFS_ACE_ALLOW_OBJECT || type == NTFS_ACE_DENY_OBJECT ||
	    type == NTFS_ACE_AUDIT_OBJECT || type == NTFS_ACE_ALLOW_CALLBACK_OBJECT ||
	    type == NTFS_ACE_DENY_CALLBACK_OBJECT || type == NTFS_ACE_AUDIT_CALLBACK_OBJECT;
}

static bool
application_ace(uint8_t type)
{
	return type == NTFS_ACE_ALLOW_CALLBACK || type == NTFS_ACE_DENY_CALLBACK ||
	    type == NTFS_ACE_AUDIT_CALLBACK || type == NTFS_ACE_ALLOW_CALLBACK_OBJECT ||
	    type == NTFS_ACE_DENY_CALLBACK_OBJECT || type == NTFS_ACE_AUDIT_CALLBACK_OBJECT ||
	    type == NTFS_ACE_RESOURCE_ATTRIBUTE;
}

static bool
known_ace(uint8_t type)
{
	return object_ace(type) || application_ace(type) || type == NTFS_ACE_ALLOW ||
	    type == NTFS_ACE_DENY || type == NTFS_ACE_AUDIT || type == NTFS_ACE_MANDATORY_LABEL ||
	    type == NTFS_ACE_SCOPED_POLICY;
}

enum ntfs_result
ntfs_security_ace_decode(const void *buffer, size_t size, struct ntfs_ace_info *out)
{
	const uint8_t *bytes = buffer;
	const struct disk_ace *header = buffer;
	struct ntfs_ace_info info = {0};
	size_t position;
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (buffer == NULL) {
		return NTFS_INVALID;
	}
	if (size < sizeof(*header) || size > UINT16_MAX || size % SECURITY_DWORD_ALIGNMENT != 0 ||
	    ntfs_u16(header->length) != size) {
		return NTFS_CORRUPT;
	}
	info.type = header->type;
	info.flags = header->flags;
	info.length = (uint16_t)size;
	info.opaque = !known_ace(info.type);
	if (info.opaque) {
		*out = info;
		return NTFS_OK;
	}
	position = sizeof(*header);
	if (!ntfs_bounds(position, sizeof(info.mask), size)) {
		return NTFS_CORRUPT;
	}
	info.mask = ntfs_u32(bytes + position);
	position += sizeof(info.mask);
	info.object = object_ace(info.type);
	if (info.object) {
		if (!ntfs_bounds(position, sizeof(info.object_flags), size)) {
			return NTFS_CORRUPT;
		}
		info.object_flags = ntfs_u32(bytes + position);
		position += sizeof(info.object_flags);
		if ((info.object_flags &
			~(NTFS_ACE_OBJECT_TYPE_PRESENT | NTFS_ACE_INHERITED_OBJECT_TYPE_PRESENT)) !=
		    0) {
			return NTFS_UNSUPPORTED;
		}
		if ((info.object_flags & NTFS_ACE_OBJECT_TYPE_PRESENT) != 0) {
			if (!ntfs_bounds(position, sizeof(struct ntfs_disk_guid), size)) {
				return NTFS_CORRUPT;
			}
			info.object_type = (struct ntfs_security_span){
			    (uint32_t)position, sizeof(struct ntfs_disk_guid)};
			position += sizeof(struct ntfs_disk_guid);
		}
		if ((info.object_flags & NTFS_ACE_INHERITED_OBJECT_TYPE_PRESENT) != 0) {
			if (!ntfs_bounds(position, sizeof(struct ntfs_disk_guid), size)) {
				return NTFS_CORRUPT;
			}
			info.inherited_object_type = (struct ntfs_security_span){
			    (uint32_t)position, sizeof(struct ntfs_disk_guid)};
			position += sizeof(struct ntfs_disk_guid);
		}
	}
	info.sid.offset = (uint32_t)position;
	result = decode_sid(bytes + position, size - position, &info.trustee, &info.sid.length);
	if (result != NTFS_OK) {
		return result;
	}
	position += info.sid.length;
	if (application_ace(info.type)) {
		info.application =
		    (struct ntfs_security_span){(uint32_t)position, (uint32_t)(size - position)};
		info.application_data = info.application.length != 0;
	}
	/* MS-DTYP permits additional bytes even on non-callback ACEs. Preserve
	 * the complete input and ignore that padding rather than reinterpreting it. */
	*out = info;
	return NTFS_OK;
}

static enum ntfs_result
decode_acl(
    const uint8_t *bytes, size_t size, uint32_t offset, bool present, struct ntfs_acl_info *info)
{
	const struct disk_acl *header;
	const struct disk_ace *entry;
	struct ntfs_ace_info ace;
	size_t position, length, i;
	enum ntfs_result result;

	info->state = present ? NTFS_ACL_NULL : NTFS_ACL_ABSENT;
	if (!present) {
		return offset == 0 ? NTFS_OK : NTFS_CORRUPT;
	}
	if (offset == 0) {
		return NTFS_OK;
	}
	if (offset < sizeof(struct disk_security_descriptor) ||
	    !ntfs_bounds(offset, sizeof(*header), size)) {
		return NTFS_CORRUPT;
	}
	header = (const void *)(bytes + offset);
	length = ntfs_u16(header->length);
	if (length < sizeof(*header) || !ntfs_bounds(offset, length, size) ||
	    header->reserved1 != 0 || ntfs_u16(header->reserved2) != 0) {
		return NTFS_CORRUPT;
	}
	if (header->revision != SECURITY_ACL_REVISION &&
	    header->revision != SECURITY_ACL_OBJECT_REVISION) {
		return NTFS_UNSUPPORTED;
	}
	info->span = (struct ntfs_security_span){offset, (uint32_t)length};
	info->revision = header->revision;
	info->entries = ntfs_u16(header->count);
	info->state = info->entries == 0 ? NTFS_ACL_EMPTY : NTFS_ACL_PRESENT;
	position = sizeof(*header);
	for (i = 0; i < info->entries; i++) {
		if (!ntfs_bounds(position, sizeof(*entry), length)) {
			return NTFS_CORRUPT;
		}
		entry = (const void *)(bytes + offset + position);
		if (!ntfs_bounds(position, ntfs_u16(entry->length), length)) {
			return NTFS_CORRUPT;
		}
		result = ntfs_security_ace_decode(entry, ntfs_u16(entry->length), &ace);
		if (result != NTFS_OK) {
			return result;
		}
		if (ace.object && header->revision != SECURITY_ACL_OBJECT_REVISION) {
			return NTFS_CORRUPT;
		}
		info->opaque_aces |= ace.opaque;
		info->application_data |= ace.application_data;
		position += ace.length;
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_security_decode(const void *buffer, size_t size, struct ntfs_security_info *out)
{
	const uint8_t *bytes = buffer;
	const struct disk_security_descriptor *header = buffer;
	struct ntfs_security_info info = {0};
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (buffer == NULL) {
		return NTFS_INVALID;
	}
	if (size > NTFS_SECURITY_MAX_BYTES) {
		return NTFS_RANGE;
	}
	if (size < sizeof(*header) || header->revision != SECURITY_DESCRIPTOR_REVISION) {
		return NTFS_CORRUPT;
	}
	info.control = ntfs_u16(header->control);
	info.resource_manager = header->resource_manager;
	if ((info.control & NTFS_SD_SELF_RELATIVE) == 0) {
		return NTFS_UNSUPPORTED;
	}
	info.owner_span.offset = ntfs_u32(header->owner);
	info.group_span.offset = ntfs_u32(header->group);
	if (info.owner_span.offset != 0) {
		if (info.owner_span.offset < sizeof(*header) || info.owner_span.offset > size) {
			return NTFS_CORRUPT;
		}
		result = decode_sid(bytes + info.owner_span.offset, size - info.owner_span.offset,
		    &info.owner, &info.owner_span.length);
		if (result != NTFS_OK) {
			return result;
		}
	}
	if (info.group_span.offset != 0) {
		if (info.group_span.offset < sizeof(*header) || info.group_span.offset > size) {
			return NTFS_CORRUPT;
		}
		result = decode_sid(bytes + info.group_span.offset, size - info.group_span.offset,
		    &info.group, &info.group_span.length);
		if (result != NTFS_OK) {
			return result;
		}
	}
	result = decode_acl(bytes, size, ntfs_u32(header->sacl),
	    (info.control & NTFS_SD_SACL_PRESENT) != 0, &info.sacl);
	if (result == NTFS_OK) {
		result = decode_acl(bytes, size, ntfs_u32(header->dacl),
		    (info.control & NTFS_SD_DACL_PRESENT) != 0, &info.dacl);
	}
	if (result == NTFS_OK) {
		*out = info;
	}
	return result;
}
