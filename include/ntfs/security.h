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
/* One complete MS-DTYP SID packet, without trailing storage. No allocation/I/O;
 * failure zeroes the output. Input and output storage must not overlap. */
enum ntfs_result ntfs_security_sid_decode(const void *, size_t, struct ntfs_sid *);

struct ntfs_security;

/* Immutable original self-relative bytes from a per-file attribute or $Secure:$SII;
 * indexed storage is cross-checked against $SDH, the hash and both SDS copies. Only the
 * searched index paths are validated, not every descriptor/index on the volume.
 * The snapshot survives node close and prevents unmount until closed. These
 * operations do not open file content, follow reparse points or grant access.
 * A node with no security ID uses its resident/nonresident $SECURITY_DESCRIPTOR
 * attribute, bounded by NTFS_SECURITY_MAX_BYTES. A missing descriptor or referenced
 * missing ID is CORRUPT. A nonzero ID never falls back to per-file storage.
 * Direct resolution returns NOT_FOUND for an absent ID and INVALID for ID zero.
 * Outputs are NULL on failure; volume and children require serialization. */
enum ntfs_result ntfs_security_open(struct ntfs_node *, struct ntfs_security **);
enum ntfs_result ntfs_security_resolve(struct ntfs_volume *, uint32_t, struct ntfs_security **);
void ntfs_security_close(struct ntfs_security *);
/* Zero identifies a per-file attribute, or a NULL snapshot. */
uint32_t ntfs_security_id(const struct ntfs_security *);
size_t ntfs_security_size(const struct ntfs_security *);
void ntfs_security_get_info(const struct ntfs_security *, struct ntfs_security_info *);
/* Whole-descriptor copy, without the SDS header or padding. NULL/zero queries
 * the required byte count; RANGE leaves the destination unchanged. Accessors
 * perform no I/O/allocation. A NULL snapshot is INVALID. */
enum ntfs_result ntfs_security_copy(const struct ntfs_security *, void *, size_t, size_t *);

/* Diagnostic policy, independent of SID/ACL and index wire limits. */
enum {
	NTFS_SECURITY_STORE_DEFAULT_DESCRIPTORS = 65536,
	NTFS_SECURITY_STORE_MAX_DESCRIPTORS = 1048576
};

enum ntfs_security_store_stage {
	NTFS_SECURITY_STORE_SETUP,
	NTFS_SECURITY_STORE_SII,
	NTFS_SECURITY_STORE_SII_ALLOCATION,
	NTFS_SECURITY_STORE_SDH,
	NTFS_SECURITY_STORE_SDH_ALLOCATION,
	NTFS_SECURITY_STORE_DESCRIPTORS,
	NTFS_SECURITY_STORE_FINISHED
};

struct ntfs_security_store_limits {
	uint32_t max_descriptors;
};

struct ntfs_security_store_report {
	enum ntfs_result result;
	enum ntfs_security_store_stage stage;
	bool complete, descriptor_limit;
	uint64_t reference;
	uint32_t security_id, hash;
	uint64_t offset, cluster;
	uint64_t sii_entries, sdh_entries, sii_blocks, sdh_blocks;
	uint64_t descriptors, descriptor_bytes;
};

void ntfs_security_store_default_limits(struct ntfs_security_store_limits *);
/* Complete bounded traversal of both supported $Secure view indexes, their
 * allocation bitmaps and every indexed descriptor/hash/copy. Requires immutable
 * media and the ordinary serialized mounted owner. NULL limits select defaults.
 * It does not interpret unused SDS gaps, inspect every FILE security reference,
 * repair media or enforce authorization. Failure retains partial counters and
 * subject fields; complete is false. Subjects identify the current/last examined
 * object; block counts include admitted VCNs even if a later read fails. Input
 * limits and output storage must not overlap. Invalid arguments do no callback work.
 * Mounted operation/live-storage limits apply in addition to this catalog cap. */
enum ntfs_result ntfs_security_store_validate(struct ntfs_volume *,
    const struct ntfs_security_store_limits *, struct ntfs_security_store_report *);

#ifdef __cplusplus
}
#endif
#endif
