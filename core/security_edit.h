/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#ifndef MACHLIN_NTFS_SECURITY_EDIT_H
#define MACHLIN_NTFS_SECURITY_EDIT_H
#include <ntfs/security.h>

struct ntfs_security_edit_input {
	const void *original, *dacl_source;
	size_t original_bytes, dacl_source_bytes;
};

/* Pure private self-relative descriptor storage editing. Both complete inputs
 * are validated by ntfs_security_decode. Replace exactly the DACL component and
 * DACL_PRESENT, DACL_DEFAULTED, DACL_AUTO_INHERIT_REQUEST, DACL_AUTO_INHERITED
 * and DACL_PROTECTED bits from dacl_source; preserve original owner/group/SACL,
 * resource-manager byte and every other control bit. No inheritance processing,
 * canonical ACE ordering, SID substitution or authorization is performed.
 * Absent, NULL, empty and populated ACLs retain their distinct stored states.
 * Accepted opaque ACE bodies and ACL free space are copied without interpretation.
 *
 * Output packs owner, group, SACL, DACL on DWORD boundaries. Component bytes are
 * exact; source gaps, trailing descriptor storage and shared offsets are not
 * retained. In particular, identical inputs need not produce identical storage.
 * Both inputs may share any immutable storage, including validated component
 * aliases admitted by the decoder. Output and size output must be disjoint from
 * the input structure, both complete input ranges and each other. Encode checks
 * the complete capacity range, not only the returned extent. All failures leave
 * both outputs unchanged. Only returned output bytes change on success.
 *
 * Inputs obey NTFS_SECURITY_MAX_BYTES. No allocation, callbacks, I/O, shared
 * security IDs, native admission or WAL ownership is supplied. Size and encode
 * perform the same validation; callers retain immutable inputs between calls.
 */
enum ntfs_result ntfs_security_edit_dacl_size(const struct ntfs_security_edit_input *, size_t *);
enum ntfs_result ntfs_security_edit_dacl_encode(
    const struct ntfs_security_edit_input *, void *, size_t, size_t *);

#endif
