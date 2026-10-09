/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include <ntfs/access.h>

enum { OWNER_RIGHTS_AUTHORITY = 3, OWNER_RIGHTS_RID = 4 };

#define SID_AUTHORITY_MAX UINT64_C(0xffffffffffff)
#define OWNER_IMPLIED_ACCESS (NTFS_ACCESS_READ_CONTROL | NTFS_ACCESS_WRITE_DAC)
#define GROUP_ATTRIBUTES                                                                           \
	(NTFS_GROUP_MANDATORY | NTFS_GROUP_ENABLED_BY_DEFAULT | NTFS_GROUP_ENABLED |               \
	    NTFS_GROUP_OWNER | NTFS_GROUP_DENY_ONLY | NTFS_GROUP_RESOURCE | NTFS_GROUP_LOGON_ID)
#define APPLICABLE_ACE_FLAGS                                                                       \
	(NTFS_ACE_OBJECT_INHERIT | NTFS_ACE_CONTAINER_INHERIT | NTFS_ACE_NO_PROPAGATE |            \
	    NTFS_ACE_INHERITED)

struct ntfs_dacl_work {
	const struct ntfs_access_token *token;
	struct ntfs_volume *volume;
	uint32_t comparisons, maximum;
};

uint32_t
ntfs_file_map_rights(uint32_t mask)
{
	uint32_t result = mask &
	    ~(NTFS_ACCESS_GENERIC_READ | NTFS_ACCESS_GENERIC_WRITE | NTFS_ACCESS_GENERIC_EXECUTE |
		NTFS_ACCESS_GENERIC_ALL);

	if ((mask & NTFS_ACCESS_GENERIC_READ) != 0) {
		result |= NTFS_FILE_GENERIC_READ;
	}
	if ((mask & NTFS_ACCESS_GENERIC_WRITE) != 0) {
		result |= NTFS_FILE_GENERIC_WRITE;
	}
	if ((mask & NTFS_ACCESS_GENERIC_EXECUTE) != 0) {
		result |= NTFS_FILE_GENERIC_EXECUTE;
	}
	if ((mask & NTFS_ACCESS_GENERIC_ALL) != 0) {
		result |= NTFS_FILE_ALL_ACCESS;
	}
	return result;
}

void
ntfs_dacl_default_limits(struct ntfs_dacl_limits *limits)
{
	if (limits != NULL) {
		*limits = (struct ntfs_dacl_limits){
		    NTFS_ACCESS_MAX_SIDS, NTFS_ACCESS_DEFAULT_COMPARISONS};
	}
}

static bool
access_valid_sid(const struct ntfs_sid *sid)
{
	return sid->authority <= SID_AUTHORITY_MAX && sid->count <= NTFS_SID_MAX_SUBAUTHORITIES;
}

static bool
access_owner_rights_sid(const struct ntfs_sid *sid)
{
	return sid->authority == OWNER_RIGHTS_AUTHORITY && sid->count == 1 &&
	    sid->subauthorities[0] == OWNER_RIGHTS_RID;
}

static enum ntfs_result
access_validate_token(const struct ntfs_access_token *token, const struct ntfs_dacl_limits *limits)
{
	size_t i;
	uint32_t flags;

	if (token == NULL || !access_valid_sid(&token->user) ||
	    (token->group_count != 0 && token->groups == NULL) ||
	    (token->restricting_count != 0 && token->restricting == NULL) ||
	    (!token->restricted && token->restricting_count != 0)) {
		return NTFS_INVALID;
	}
	if (token->group_count > limits->max_sids || token->restricting_count > limits->max_sids) {
		return NTFS_RANGE;
	}
	for (i = 0; i < token->group_count; i++) {
		flags = token->groups[i].attributes;
		if (!access_valid_sid(&token->groups[i].sid) ||
		    (flags & (NTFS_GROUP_ENABLED | NTFS_GROUP_DENY_ONLY)) ==
			(NTFS_GROUP_ENABLED | NTFS_GROUP_DENY_ONLY)) {
			return NTFS_INVALID;
		}
		if ((flags & ~GROUP_ATTRIBUTES) != 0) {
			return NTFS_UNSUPPORTED;
		}
	}
	for (i = 0; i < token->restricting_count; i++) {
		if (!access_valid_sid(&token->restricting[i])) {
			return NTFS_INVALID;
		}
	}
	return NTFS_OK;
}

static enum ntfs_result
access_compare_sid(struct ntfs_dacl_work *work, const struct ntfs_sid *left_sid,
    const struct ntfs_sid *right_sid, bool *same)
{
	size_t i;
	enum ntfs_result result;

	*same = false;
	if (work->comparisons == work->maximum) {
		return NTFS_RANGE;
	}
	if (work->volume != NULL) {
		result = ntfs_work(work->volume, 1);
		if (result != NTFS_OK) {
			return result;
		}
	}
	work->comparisons++;
	if (left_sid->authority != right_sid->authority || left_sid->count != right_sid->count) {
		return NTFS_OK;
	}
	for (i = 0; i < left_sid->count; i++) {
		if (left_sid->subauthorities[i] != right_sid->subauthorities[i]) {
			return NTFS_OK;
		}
	}
	*same = true;
	return NTFS_OK;
}

static enum ntfs_result
access_token_match(struct ntfs_dacl_work *work, const struct ntfs_sid *sid, bool deny,
    bool ownership, bool restricting, bool *match)
{
	const struct ntfs_access_token *token = work->token;
	uint32_t flags;
	size_t i;
	enum ntfs_result result;

	*match = false;
	if (restricting) {
		for (i = 0; i < token->restricting_count; i++) {
			result = access_compare_sid(work, sid, &token->restricting[i], match);
			if (result != NTFS_OK || *match) {
				return result;
			}
		}
		return NTFS_OK;
	}
	if (deny || !token->user_deny_only) {
		result = access_compare_sid(work, sid, &token->user, match);
		if (result != NTFS_OK || *match) {
			return result;
		}
	}
	for (i = 0; i < token->group_count; i++) {
		flags = token->groups[i].attributes;
		if ((flags & NTFS_GROUP_ENABLED) == 0 &&
		    (!deny || (flags & NTFS_GROUP_DENY_ONLY) == 0)) {
			continue;
		}
		if (ownership &&
		    (flags & (NTFS_GROUP_OWNER | NTFS_GROUP_ENABLED)) !=
			(NTFS_GROUP_OWNER | NTFS_GROUP_ENABLED)) {
			continue;
		}
		result = access_compare_sid(work, sid, &token->groups[i].sid, match);
		if (result != NTFS_OK || *match) {
			return result;
		}
	}
	return NTFS_OK;
}

/* Called only after the complete descriptor decoder has checked every span. */
static enum ntfs_result
access_next_ace(const uint8_t *bytes, size_t *position, struct ntfs_ace_info *ace)
{
	const struct ntfs_disk_ace *header = (const void *)(bytes + *position);
	enum ntfs_result result;

	result = ntfs_security_ace_decode(header, ntfs_u16(header->length), ace);
	if (result == NTFS_OK) {
		*position += ace->length;
	}
	return result;
}

static enum ntfs_result
access_validate_dacl(const uint8_t *bytes, const struct ntfs_acl_info *acl, bool *owner_rights)
{
	struct ntfs_ace_info ace;
	size_t position = acl->span.offset + sizeof(struct ntfs_disk_acl), i;
	enum ntfs_result result;

	*owner_rights = false;
	for (i = 0; i < acl->entries; i++) {
		result = access_next_ace(bytes, &position, &ace);
		if (result != NTFS_OK) {
			return result;
		}
		if ((ace.flags & NTFS_ACE_INHERIT_ONLY) != 0) {
			continue;
		}
		if ((ace.type != NTFS_ACE_ALLOW && ace.type != NTFS_ACE_DENY) ||
		    (ace.flags & ~APPLICABLE_ACE_FLAGS) != 0 ||
		    (ace.mask & ~NTFS_FILE_ALL_ACCESS) != 0) {
			/* Generic mapping belongs to the caller's request. A stored ACE
			 * needs concrete file rights; inventing its mapping can grant
			 * access the original descriptor did not specify. */
			return NTFS_UNSUPPORTED;
		}
		*owner_rights |= access_owner_rights_sid(&ace.trustee);
	}
	return NTFS_OK;
}

static enum ntfs_result
access_evaluate_dacl(const uint8_t *bytes, const struct ntfs_acl_info *acl,
    struct ntfs_dacl_work *work, uint32_t requested, bool owner, bool restricting, bool *allowed)
{
	struct ntfs_ace_info ace;
	size_t position = acl->span.offset + sizeof(struct ntfs_disk_acl), i;
	uint32_t remaining = requested, mask;
	bool match;
	enum ntfs_result result;

	*allowed = false;
	if (acl->state == NTFS_ACL_ABSENT || acl->state == NTFS_ACL_NULL) {
		*allowed = true;
		return NTFS_OK;
	}
	for (i = 0; i < acl->entries && remaining != 0; i++) {
		result = access_next_ace(bytes, &position, &ace);
		if (result != NTFS_OK) {
			return result;
		}
		if ((ace.flags & NTFS_ACE_INHERIT_ONLY) != 0) {
			continue;
		}
		mask = ace.mask;
		if ((mask & remaining) == 0) {
			continue;
		}
		if (access_owner_rights_sid(&ace.trustee)) {
			match = owner;
		} else {
			result = access_token_match(work, &ace.trustee, ace.type == NTFS_ACE_DENY,
			    false, restricting, &match);
			if (result != NTFS_OK) {
				return result;
			}
		}
		if (!match) {
			continue;
		}
		if (ace.type == NTFS_ACE_DENY) {
			return NTFS_OK;
		}
		remaining &= ~mask;
	}
	*allowed = remaining == 0;
	return NTFS_OK;
}

static enum ntfs_result
access_maximum_dacl(const uint8_t *bytes, const struct ntfs_acl_info *acl,
    struct ntfs_dacl_work *work, uint32_t implied, bool owner, bool restricting, uint32_t *granted)
{
	struct ntfs_ace_info ace;
	size_t position = acl->span.offset + sizeof(struct ntfs_disk_acl), i;
	uint32_t remaining = NTFS_FILE_ALL_ACCESS & ~implied, mask;
	bool match;
	enum ntfs_result result;

	*granted = implied;
	if (acl->state == NTFS_ACL_ABSENT || acl->state == NTFS_ACL_NULL) {
		*granted = NTFS_FILE_ALL_ACCESS;
		return NTFS_OK;
	}
	for (i = 0; i < acl->entries && remaining != 0; i++) {
		result = access_next_ace(bytes, &position, &ace);
		if (result != NTFS_OK) {
			return result;
		}
		if ((ace.flags & NTFS_ACE_INHERIT_ONLY) != 0) {
			continue;
		}
		mask = ace.mask & remaining;
		if (mask == 0) {
			continue;
		}
		if (access_owner_rights_sid(&ace.trustee)) {
			match = owner;
		} else {
			result = access_token_match(work, &ace.trustee, ace.type == NTFS_ACE_DENY,
			    false, restricting, &match);
			if (result != NTFS_OK) {
				return result;
			}
		}
		if (match) {
			/* Each concrete right is decided by its first applicable ACE.
			 * A later deny cannot revoke an earlier ordered allow. */
			if (ace.type == NTFS_ACE_ALLOW) {
				*granted |= mask;
			}
			remaining &= ~mask;
		}
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_dacl_evaluate_volume(struct ntfs_volume *volume, const void *buffer, size_t size,
    const struct ntfs_access_token *token, uint32_t desired, const struct ntfs_dacl_limits *limits,
    struct ntfs_dacl_decision *out)
{
	struct ntfs_security_info info;
	struct ntfs_dacl_limits defaults;
	struct ntfs_dacl_work work = {.token = token, .volume = volume};
	struct ntfs_dacl_decision decision = {0};
	uint32_t remaining, implied, granted = 0, restricted_granted = 0;
	bool owner, owner_rights, restricting_owner = false;
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (limits == NULL) {
		ntfs_dacl_default_limits(&defaults);
		limits = &defaults;
	}
	if (limits->max_sids == 0 || limits->max_sids > NTFS_ACCESS_MAX_SIDS ||
	    limits->max_sid_comparisons == 0 ||
	    limits->max_sid_comparisons > NTFS_ACCESS_MAX_COMPARISONS) {
		return NTFS_INVALID;
	}
	result = access_validate_token(token, limits);
	if (result != NTFS_OK) {
		return result;
	}
	decision.requested = ntfs_file_map_rights(desired);
	if ((decision.requested & ~(NTFS_FILE_ALL_ACCESS | NTFS_ACCESS_MAXIMUM_ALLOWED)) != 0) {
		return NTFS_UNSUPPORTED;
	}
	if (volume != NULL) {
		/* Descriptor scans are byte-bounded; SID comparisons share this scope
		 * independently of the evaluator's own comparison ceiling. */
		result = ntfs_work(volume, size + token->group_count + token->restricting_count);
		if (result != NTFS_OK) {
			return result;
		}
	}
	result = ntfs_security_decode(buffer, size, &info);
	if (result != NTFS_OK) {
		return result;
	}
	if (info.owner_span.length == 0 || info.group_span.length == 0) {
		return NTFS_CORRUPT;
	}
	result = access_validate_dacl(buffer, &info.dacl, &owner_rights);
	if (result != NTFS_OK) {
		return result;
	}
	/* AccessCheck denies an original zero-right request. This is different
	 * from a nonzero request satisfied entirely by implied owner rights.
	 * Keep complete descriptor and feature validation before this decision. */
	if (decision.requested == 0) {
		*out = decision;
		return NTFS_OK;
	}
	work.maximum = limits->max_sid_comparisons;
	result = access_token_match(&work, &info.owner, false, true, false, &owner);
	if (result != NTFS_OK) {
		return result;
	}
	if (owner && token->restricted) {
		/* Native ownership requires the owner in both token contexts.
		 * OWNER RIGHTS uses this same qualification in both DACL passes. */
		result = access_token_match(&work, &info.owner, false, true, true, &restricting_owner);
		if (result != NTFS_OK) {
			return result;
		}
		owner = restricting_owner;
	}
	implied = owner && !owner_rights ? OWNER_IMPLIED_ACCESS : 0;
	if ((decision.requested & NTFS_ACCESS_MAXIMUM_ALLOWED) != 0) {
		result = access_maximum_dacl(buffer, &info.dacl, &work, implied, owner, false, &granted);
		if (result == NTFS_OK && token->restricted) {
			result = access_maximum_dacl(
			    buffer, &info.dacl, &work, implied, owner, true, &restricted_granted);
			if (result == NTFS_OK) {
				granted &= restricted_granted;
			}
		}
		if (result != NTFS_OK) {
			return result;
		}
		remaining = decision.requested & ~NTFS_ACCESS_MAXIMUM_ALLOWED;
		decision.allowed = granted != 0 && (remaining & ~granted) == 0;
		decision.granted = decision.allowed ? granted : 0;
		decision.sid_comparisons = work.comparisons;
		*out = decision;
		return NTFS_OK;
	}
	remaining = decision.requested & ~implied;
	result = access_evaluate_dacl(
	    buffer, &info.dacl, &work, remaining, owner, false, &decision.allowed);
	if (result == NTFS_OK && decision.allowed && token->restricted) {
		result = access_evaluate_dacl(
		    buffer, &info.dacl, &work, remaining, owner, true, &decision.allowed);
	}
	if (result != NTFS_OK) {
		return result;
	}
	decision.granted = decision.allowed ? decision.requested : 0;
	decision.sid_comparisons = work.comparisons;
	*out = decision;
	return NTFS_OK;
}

enum ntfs_result
ntfs_dacl_evaluate(const void *buffer, size_t size, const struct ntfs_access_token *token,
    uint32_t desired, const struct ntfs_dacl_limits *limits, struct ntfs_dacl_decision *out)
{
	return ntfs_dacl_evaluate_volume(NULL, buffer, size, token, desired, limits, out);
}
