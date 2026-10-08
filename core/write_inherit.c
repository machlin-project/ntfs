/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_mutation_internal.h"

static enum ntfs_result
inheritance_append_ace(uint8_t *output, size_t *used, uint16_t *count, const uint8_t *original,
    const struct ntfs_ace_info *ace, uint8_t flags, const uint8_t *sid, size_t sid_bytes,
    bool effective)
{
	struct ntfs_disk_ace *header;
	size_t bytes = sizeof(*header) + sizeof(uint32_t) + sid_bytes;

	if (bytes > NTFS_MUTATION_SECURITY_BYTES - *used || bytes > UINT16_MAX ||
	    *count == UINT16_MAX) {
		return NTFS_NO_SPACE;
	}
	header = (void *)(output + *used);
	header->type = ace->type;
	header->flags = flags;
	ntfs_put_u16(header->length, (uint16_t)bytes);
	ntfs_put_u32(output + *used + sizeof(*header),
	    effective ? ntfs_file_map_rights(ace->mask) : ace->mask);
	ntfs_copy(output + *used + sizeof(*header) + sizeof(uint32_t), sid, sid_bytes);
	*used += bytes;
	(*count)++;
	(void)original;
	return NTFS_OK;
}

static enum ntfs_result
inheritance_inherit_acl(const uint8_t *parent, const struct ntfs_security_info *security,
    const struct ntfs_acl_info *acl, bool directory, uint8_t *output, size_t *used,
    uint32_t *offset)
{
	struct ntfs_disk_acl *header;
	struct ntfs_ace_info ace;
	const uint8_t *body, *sid;
	const struct ntfs_security_span *replacement;
	size_t position, index, sid_bytes, start;
	uint16_t count = 0;
	uint8_t flags, audit_flags, propagation;
	bool applies, propagates, creator;
	enum ntfs_result result;

	*offset = 0;
	if (acl->state == NTFS_ACL_ABSENT || acl->state == NTFS_ACL_NULL) {
		return NTFS_OK;
	}
	start = *used;
	if (sizeof(*header) > NTFS_MUTATION_SECURITY_BYTES - start) {
		return NTFS_NO_SPACE;
	}
	*used += sizeof(*header);
	position = acl->span.offset + sizeof(*header);
	for (index = 0; index < acl->entries; index++) {
		body = parent + position;
		result = ntfs_security_ace_decode(
		    body, ntfs_u16(((const struct ntfs_disk_ace *)body)->length), &ace);
		if (result != NTFS_OK) {
			return result;
		}
		position += ace.length;
		applies =
		    (ace.flags &
			(directory ? NTFS_ACE_CONTAINER_INHERIT : NTFS_ACE_OBJECT_INHERIT)) != 0;
		propagates = directory && (ace.flags & NTFS_ACE_NO_PROPAGATE) == 0 &&
		    (ace.flags & (NTFS_ACE_CONTAINER_INHERIT | NTFS_ACE_OBJECT_INHERIT)) != 0;
		if (!applies && !propagates) {
			continue;
		}
		if (ace.object || ace.opaque || ace.application_data ||
		    (ace.flags &
			~(NTFS_ACE_CONTAINER_INHERIT | NTFS_ACE_OBJECT_INHERIT |
			    NTFS_ACE_NO_PROPAGATE | NTFS_ACE_INHERIT_ONLY | NTFS_ACE_INHERITED |
			    NTFS_ACE_SUCCESSFUL_ACCESS | NTFS_ACE_FAILED_ACCESS)) != 0 ||
		    (ace.type != NTFS_ACE_ALLOW && ace.type != NTFS_ACE_DENY &&
			ace.type != NTFS_ACE_AUDIT && ace.type != NTFS_ACE_MANDATORY_LABEL)) {
			return NTFS_UNSUPPORTED;
		}
		creator = ace.trustee.authority == NTFS_MUTATION_CREATOR_AUTHORITY &&
		    ace.trustee.count == 1 &&
		    (ace.trustee.subauthorities[0] == NTFS_MUTATION_CREATOR_OWNER ||
			ace.trustee.subauthorities[0] == NTFS_MUTATION_CREATOR_GROUP);
		sid = body + ace.sid.offset;
		sid_bytes = ace.sid.length;
		audit_flags = ace.flags & (NTFS_ACE_SUCCESSFUL_ACCESS | NTFS_ACE_FAILED_ACCESS);
		propagation = ace.flags & (NTFS_ACE_CONTAINER_INHERIT | NTFS_ACE_OBJECT_INHERIT);
		if (applies && (creator || ntfs_file_map_rights(ace.mask) != ace.mask)) {
			if (creator) {
				replacement =
				    ace.trustee.subauthorities[0] == NTFS_MUTATION_CREATOR_OWNER
				    ? &security->owner_span
				    : &security->group_span;
				if (replacement->length == 0) {
					return NTFS_UNSUPPORTED;
				}
			} else {
				replacement = &ace.sid;
			}
			result = inheritance_append_ace(output, used, &count, body, &ace,
			    audit_flags | NTFS_ACE_INHERITED,
			    creator ? parent + replacement->offset : body + replacement->offset,
			    replacement->length, true);
			if (result != NTFS_OK) {
				return result;
			}
			if (!propagates) {
				continue;
			}
			flags =
			    audit_flags | propagation | NTFS_ACE_INHERIT_ONLY | NTFS_ACE_INHERITED;
			result = inheritance_append_ace(
			    output, used, &count, body, &ace, flags, sid, sid_bytes, false);
		} else {
			flags = audit_flags | NTFS_ACE_INHERITED;
			if (propagates) {
				flags |= propagation;
			}
			if (!applies) {
				flags |= NTFS_ACE_INHERIT_ONLY;
			}
			result = inheritance_append_ace(
			    output, used, &count, body, &ace, flags, sid, sid_bytes, applies);
		}
		if (result != NTFS_OK) {
			return result;
		}
	}
	header = (void *)(output + start);
	header->revision = NTFS_MUTATION_ACL_REVISION;
	ntfs_put_u16(header->length, (uint16_t)(*used - start));
	ntfs_put_u16(header->count, count);
	*offset = (uint32_t)start;
	return NTFS_OK;
}

static enum ntfs_result
inheritance_append_sid(uint8_t *output, size_t *used, const uint8_t *parent,
    const struct ntfs_security_span *sid, uint8_t *field)
{
	if (sid->length == 0) {
		return NTFS_OK;
	}
	if (sid->length > NTFS_MUTATION_SECURITY_BYTES - *used) {
		return NTFS_NO_SPACE;
	}
	ntfs_put_u32(field, (uint32_t)*used);
	ntfs_copy(output + *used, parent + sid->offset, sid->length);
	*used += sid->length;
	return NTFS_OK;
}

enum ntfs_result
ntfs_mutation_security_inherit(struct ntfs_write_mutation_plan *plan,
    struct ntfs_mutation_record *parent_record, bool directory, uint8_t **out, size_t *bytes)
{
	struct ntfs_node *node = NULL;
	struct ntfs_security *snapshot = NULL;
	struct ntfs_security_info security, checked;
	struct ntfs_disk_security_descriptor *header;
	uint8_t *parent = NULL, *output = NULL;
	size_t size = 0, copied, used;
	uint32_t offset;
	uint16_t control = NTFS_SD_SELF_RELATIVE;
	enum ntfs_result result;

	*out = NULL;
	*bytes = 0;
	result = ntfs_node_open(plan->volume, parent_record->reference, &node);
	if (result == NTFS_OK) {
		result = ntfs_security_open(node, &snapshot);
	}
	if (result != NTFS_OK) {
		goto done;
	}
	size = ntfs_security_size(snapshot);
	if (size > NTFS_MUTATION_SECURITY_BYTES) {
		result = NTFS_UNSUPPORTED;
		goto done;
	}
	parent = ntfs_mutation_allocate(plan, size);
	output = ntfs_mutation_allocate(plan, NTFS_MUTATION_SECURITY_BYTES);
	if (parent == NULL || output == NULL) {
		result = NTFS_NO_MEMORY;
		goto done;
	}
	result = ntfs_security_copy(snapshot, parent, size, &copied);
	if (result != NTFS_OK) {
		goto done;
	}
	ntfs_security_get_info(snapshot, &security);
	header = (void *)output;
	header->revision = NTFS_MUTATION_SECURITY_REVISION;
	used = sizeof(*header);
	result = inheritance_inherit_acl(
	    parent, &security, &security.dacl, directory, output, &used, &offset);
	ntfs_put_u32(header->dacl, offset);
	if (security.dacl.state != NTFS_ACL_ABSENT) {
		control |= NTFS_SD_DACL_PRESENT;
		if (security.dacl.state != NTFS_ACL_NULL) {
			control |= NTFS_SD_DACL_AUTO_INHERITED;
		}
	}
	if (result == NTFS_OK) {
		result = inheritance_inherit_acl(
		    parent, &security, &security.sacl, directory, output, &used, &offset);
		ntfs_put_u32(header->sacl, offset);
	}
	if (security.sacl.state != NTFS_ACL_ABSENT) {
		control |= NTFS_SD_SACL_PRESENT;
		if (security.sacl.state != NTFS_ACL_NULL) {
			control |= NTFS_SD_SACL_AUTO_INHERITED;
		}
	}
	if (result == NTFS_OK) {
		result = inheritance_append_sid(
		    output, &used, parent, &security.owner_span, header->owner);
	}
	if (result == NTFS_OK) {
		result = inheritance_append_sid(
		    output, &used, parent, &security.group_span, header->group);
	}
	ntfs_put_u16(header->control, control);
	if (result == NTFS_OK) {
		result = ntfs_security_decode(output, used, &checked);
	}
	if (result == NTFS_OK) {
		*out = output;
		*bytes = used;
		output = NULL;
	}

done:
	ntfs_mutation_release(plan, parent, size);
	ntfs_mutation_release(plan, output, NTFS_MUTATION_SECURITY_BYTES);
	ntfs_security_close(snapshot);
	ntfs_node_close(node);
	return result;
}
