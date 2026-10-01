/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_SECURITY_H
#define MACHLIN_NTFS_SECURITY_H
#include <ntfs/ntfs.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NTFS_SID_MAX_SUBAUTHORITIES 15u
/* Aggregate descriptor policy budget, separate from 16-bit ACL/ACE wire sizes. */
#define NTFS_SECURITY_MAX_BYTES 1048576u

enum {
	NTFS_SD_OWNER_DEFAULTED = 0x0001,
	NTFS_SD_GROUP_DEFAULTED = 0x0002,
	NTFS_SD_DACL_PRESENT = 0x0004,
	NTFS_SD_DACL_DEFAULTED = 0x0008,
	NTFS_SD_SACL_PRESENT = 0x0010,
	NTFS_SD_SACL_DEFAULTED = 0x0020,
	NTFS_SD_DACL_AUTO_INHERIT_REQUEST = 0x0100,
	NTFS_SD_SACL_AUTO_INHERIT_REQUEST = 0x0200,
	NTFS_SD_DACL_AUTO_INHERITED = 0x0400,
	NTFS_SD_SACL_AUTO_INHERITED = 0x0800,
	NTFS_SD_DACL_PROTECTED = 0x1000,
	NTFS_SD_SACL_PROTECTED = 0x2000,
	NTFS_SD_RESOURCE_MANAGER_VALID = 0x4000,
	NTFS_SD_SELF_RELATIVE = 0x8000,
	NTFS_ACE_ALLOW = 0x00,
	NTFS_ACE_DENY = 0x01,
	NTFS_ACE_AUDIT = 0x02,
	NTFS_ACE_ALLOW_OBJECT = 0x05,
	NTFS_ACE_DENY_OBJECT = 0x06,
	NTFS_ACE_AUDIT_OBJECT = 0x07,
	NTFS_ACE_ALLOW_CALLBACK = 0x09,
	NTFS_ACE_DENY_CALLBACK = 0x0a,
	NTFS_ACE_ALLOW_CALLBACK_OBJECT = 0x0b,
	NTFS_ACE_DENY_CALLBACK_OBJECT = 0x0c,
	NTFS_ACE_AUDIT_CALLBACK = 0x0d,
	NTFS_ACE_AUDIT_CALLBACK_OBJECT = 0x0f,
	NTFS_ACE_MANDATORY_LABEL = 0x11,
	NTFS_ACE_RESOURCE_ATTRIBUTE = 0x12,
	NTFS_ACE_SCOPED_POLICY = 0x13,
	NTFS_ACE_OBJECT_TYPE_PRESENT = 0x00000001,
	NTFS_ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x00000002,
	NTFS_ACE_OBJECT_INHERIT = 0x01,
	NTFS_ACE_CONTAINER_INHERIT = 0x02,
	NTFS_ACE_NO_PROPAGATE = 0x04,
	NTFS_ACE_INHERIT_ONLY = 0x08,
	NTFS_ACE_INHERITED = 0x10,
	NTFS_ACE_SUCCESSFUL_ACCESS = 0x40,
	NTFS_ACE_FAILED_ACCESS = 0x80
};

enum ntfs_acl_state { NTFS_ACL_ABSENT, NTFS_ACL_NULL, NTFS_ACL_EMPTY, NTFS_ACL_PRESENT };

/* Offsets describe checked spans in the caller's immutable input. They are not
 * pointers, borrowed native objects, or authorization decisions. */
struct ntfs_security_span {
	uint32_t offset, length;
};

struct ntfs_sid {
	uint64_t authority;
	uint32_t subauthorities[NTFS_SID_MAX_SUBAUTHORITIES];
	uint8_t count;
};

struct ntfs_ace_info {
	uint8_t type, flags;
	uint16_t length;
	uint32_t mask, object_flags;
	bool opaque, object, application_data;
	struct ntfs_sid trustee;
	struct ntfs_security_span sid, object_type, inherited_object_type, application;
};

struct ntfs_acl_info {
	enum ntfs_acl_state state;
	struct ntfs_security_span span;
	uint16_t entries;
	uint8_t revision;
	bool opaque_aces, application_data;
};

struct ntfs_security_info {
	uint16_t control;
	uint8_t resource_manager;
	struct ntfs_security_span owner_span, group_span;
	struct ntfs_sid owner, group;
	struct ntfs_acl_info dacl, sacl;
};

/* MS-DTYP framing, SID, ACL and known ACE layout checks. Decode does not reorder
 * ACEs, interpret callback conditions, map identities, or grant access. Unknown
 * ACE bodies are retained as opaque checked spans. Outputs are zero on failure.
 * ACE decode takes one complete ACE; descriptor decode permits unused trailing
 * storage and shared SID spans. Its offsets need not follow a particular order. */
enum ntfs_result ntfs_security_decode(const void *, size_t, struct ntfs_security_info *);
enum ntfs_result ntfs_security_ace_decode(const void *, size_t, struct ntfs_ace_info *);

#ifdef __cplusplus
}
#endif
#endif
