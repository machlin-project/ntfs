/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_ACCESS_H
#define MACHLIN_NTFS_ACCESS_H
#include <ntfs/security.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	NTFS_FILE_READ_DATA = 0x00000001,
	NTFS_FILE_LIST_DIRECTORY = NTFS_FILE_READ_DATA,
	NTFS_FILE_WRITE_DATA = 0x00000002,
	NTFS_FILE_ADD_FILE = NTFS_FILE_WRITE_DATA,
	NTFS_FILE_APPEND_DATA = 0x00000004,
	NTFS_FILE_ADD_SUBDIRECTORY = NTFS_FILE_APPEND_DATA,
	NTFS_FILE_READ_EA = 0x00000008,
	NTFS_FILE_WRITE_EA = 0x00000010,
	NTFS_FILE_EXECUTE = 0x00000020,
	NTFS_FILE_TRAVERSE = NTFS_FILE_EXECUTE,
	NTFS_FILE_DELETE_CHILD = 0x00000040,
	NTFS_FILE_READ_ATTRIBUTES = 0x00000080,
	NTFS_FILE_WRITE_ATTRIBUTES = 0x00000100,
	NTFS_ACCESS_DELETE = 0x00010000,
	NTFS_ACCESS_READ_CONTROL = 0x00020000,
	NTFS_ACCESS_WRITE_DAC = 0x00040000,
	NTFS_ACCESS_WRITE_OWNER = 0x00080000,
	NTFS_ACCESS_SYNCHRONIZE = 0x00100000,
	NTFS_ACCESS_SYSTEM_SECURITY = 0x01000000,
	NTFS_ACCESS_MAXIMUM_ALLOWED = 0x02000000,
	NTFS_GROUP_MANDATORY = 0x00000001,
	NTFS_GROUP_ENABLED_BY_DEFAULT = 0x00000002,
	NTFS_GROUP_ENABLED = 0x00000004,
	NTFS_GROUP_OWNER = 0x00000008,
	NTFS_GROUP_DENY_ONLY = 0x00000010,
	NTFS_GROUP_INTEGRITY = 0x00000020,
	NTFS_GROUP_INTEGRITY_ENABLED = 0x00000040,
	/* Policy ceilings, not NTFS format values; per-call limits cannot exceed them. */
	NTFS_ACCESS_MAX_SIDS = 1024,
	NTFS_ACCESS_DEFAULT_COMPARISONS = 262144,
	NTFS_ACCESS_MAX_COMPARISONS = 1048576
};

#define NTFS_ACCESS_GENERIC_ALL UINT32_C(0x10000000)
#define NTFS_ACCESS_GENERIC_EXECUTE UINT32_C(0x20000000)
#define NTFS_ACCESS_GENERIC_WRITE UINT32_C(0x40000000)
#define NTFS_ACCESS_GENERIC_READ UINT32_C(0x80000000)
#define NTFS_GROUP_RESOURCE UINT32_C(0x20000000)
#define NTFS_GROUP_LOGON_ID UINT32_C(0xc0000000)
#define NTFS_ACCESS_STANDARD_ALL                                                                   \
	(NTFS_ACCESS_DELETE | NTFS_ACCESS_READ_CONTROL | NTFS_ACCESS_WRITE_DAC |                   \
	    NTFS_ACCESS_WRITE_OWNER | NTFS_ACCESS_SYNCHRONIZE)
#define NTFS_FILE_ALL_ACCESS                                                                       \
	(NTFS_ACCESS_STANDARD_ALL | NTFS_FILE_READ_DATA | NTFS_FILE_WRITE_DATA |                   \
	    NTFS_FILE_APPEND_DATA | NTFS_FILE_READ_EA | NTFS_FILE_WRITE_EA | NTFS_FILE_EXECUTE |   \
	    NTFS_FILE_DELETE_CHILD | NTFS_FILE_READ_ATTRIBUTES | NTFS_FILE_WRITE_ATTRIBUTES)
#define NTFS_FILE_GENERIC_READ                                                                     \
	(NTFS_ACCESS_READ_CONTROL | NTFS_ACCESS_SYNCHRONIZE | NTFS_FILE_READ_DATA |                \
	    NTFS_FILE_READ_EA | NTFS_FILE_READ_ATTRIBUTES)
#define NTFS_FILE_GENERIC_WRITE                                                                    \
	(NTFS_ACCESS_READ_CONTROL | NTFS_ACCESS_SYNCHRONIZE | NTFS_FILE_WRITE_DATA |               \
	    NTFS_FILE_APPEND_DATA | NTFS_FILE_WRITE_EA | NTFS_FILE_WRITE_ATTRIBUTES)
#define NTFS_FILE_GENERIC_EXECUTE                                                                  \
	(NTFS_ACCESS_READ_CONTROL | NTFS_ACCESS_SYNCHRONIZE | NTFS_FILE_EXECUTE |                  \
	    NTFS_FILE_READ_ATTRIBUTES)

struct ntfs_token_group {
	struct ntfs_sid sid;
	uint32_t attributes;
};

/* Caller-owned immutable authorization context, not an identity authenticator.
 * The user participates unless deny-only. Disabled groups cannot grant/deny;
 * deny-only groups only deny; enabled OWNER groups qualify for ownership.
 * A restricting list is a second check, not additional ordinary membership.
 * restricted=true with an empty list retains the restriction, never disables it.
 * Native token extraction/identity mapping must establish all of these values. */
struct ntfs_access_token {
	struct ntfs_sid user;
	const struct ntfs_token_group *groups;
	const struct ntfs_sid *restricting;
	size_t group_count, restricting_count;
	bool user_deny_only, restricted;
};

struct ntfs_dacl_limits {
	uint32_t max_sids, max_sid_comparisons;
};

struct ntfs_dacl_decision {
	uint32_t requested, granted, sid_comparisons;
	bool allowed;
};

/* Map generic file/directory rights, preserving unknown bits for validation. */
uint32_t ntfs_file_map_rights(uint32_t);
void ntfs_dacl_default_limits(struct ntfs_dacl_limits *);

/* Discretionary plane only: an allowed result is not complete authorization.
 * Validates the whole descriptor and all applicable DACL ACEs before deciding.
 * Maps generic requests to exact file/directory masks. Stored plain ordered
 * allow/deny ACEs require concrete rights; applicable stored generic bits return
 * UNSUPPORTED, never an inferred grant. Supports inherit-only exclusion, owner
 * READ_CONTROL/WRITE_DAC and OWNER RIGHTS (S-1-3-4).
 * Unknown/object/callback ACEs applying to this object, unknown masks/attributes,
 * MAXIMUM_ALLOWED and ACCESS_SYSTEM_SECURITY return UNSUPPORTED. Restricted-owner
 * implied/OWNER RIGHTS semantics await native qualification and are UNSUPPORTED.
 * SACL decisions, privileges, mandatory integrity, claims, traversal/delete-parent
 * alternatives and native authorization belong to other owning-layer contracts.
 * No allocation/I/O or mutations. Input/output storage must not overlap; inputs
 * remain immutable throughout. NULL limits select defaults. Errors zero decision;
 * NTFS_OK with allowed=false is a valid denial with granted=0, never partial grant.
 * Owner/group SIDs are required here, although the framing decoder permits absence. */
enum ntfs_result ntfs_dacl_evaluate(const void *, size_t, const struct ntfs_access_token *,
    uint32_t, const struct ntfs_dacl_limits *, struct ntfs_dacl_decision *);
/* Same contract, evaluated against an immutable original storage snapshot. */
enum ntfs_result ntfs_security_evaluate_dacl(const struct ntfs_security *,
    const struct ntfs_access_token *, uint32_t, const struct ntfs_dacl_limits *,
    struct ntfs_dacl_decision *);

#ifdef __cplusplus
}
#endif
#endif
