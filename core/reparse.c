/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"

struct reparse_values {
	struct ntfs_reparse_info info;
	size_t substitute_offset, print_offset;
};

struct ntfs_reparse {
	struct ntfs_volume *volume;
	struct reparse_values values;
	uint8_t *bytes;
	size_t size;
};

static bool
valid_name(const uint8_t *path, size_t size, size_t offset, size_t length)
{
	size_t i;

	if (offset % NTFS_UTF16_UNIT_BYTES != 0 || length % NTFS_UTF16_UNIT_BYTES != 0 ||
	    !ntfs_bounds(offset, length, size)) {
		return false;
	}
	for (i = 0; i < length; i += NTFS_UTF16_UNIT_BYTES) {
		if (ntfs_u16(path + offset + i) == 0) {
			return false;
		}
	}
	return true;
}

static enum ntfs_result
decode_reparse(const void *buffer, size_t size, struct reparse_values *values)
{
	const struct ntfs_disk_reparse *header = buffer;
	const struct ntfs_disk_reparse_names *names;
	const struct ntfs_disk_reparse_symlink *symlink;
	const uint8_t *payload, *path;
	uint32_t tag;
	size_t header_size, path_size, substitute_length, print_length;

	ntfs_zero(values, sizeof(*values));
	if (size < sizeof(*header) || size > NTFS_REPARSE_MAX_BYTES) {
		return NTFS_CORRUPT;
	}
	values->info.tag = ntfs_u32(header->tag);
	/* MS-FSCC requires reserved tag bits and the common reserved field to be
	 * ignored on receipt. Preserve the original tag for diagnostics. */
	tag = values->info.tag & ~NTFS_REPARSE_RESERVED_BITS;
	if (tag <= NTFS_REPARSE_RESERVED_TAG_MAX ||
	    (tag & (NTFS_REPARSE_NAME_SURROGATE | NTFS_REPARSE_DIRECTORY)) ==
		(NTFS_REPARSE_NAME_SURROGATE | NTFS_REPARSE_DIRECTORY)) {
		return NTFS_CORRUPT;
	}
	if ((tag & NTFS_REPARSE_MICROSOFT) == 0) {
		/* The GUID envelope has a different length contract. Do not guess it. */
		return NTFS_UNSUPPORTED;
	}
	if (ntfs_u16(header->length) != size - sizeof(*header)) {
		/* Microsoft owners may also use a GUID envelope. Matching its size
		 * is only enough to report an unsupported candidate, not to decode it. */
		if (size >= sizeof(struct ntfs_disk_reparse_guid) &&
		    ntfs_u16(header->length) == size - sizeof(struct ntfs_disk_reparse_guid)) {
			return NTFS_UNSUPPORTED;
		}
		return NTFS_CORRUPT;
	}
	if (tag == NTFS_REPARSE_TAG_WOF) {
		values->info.kind = NTFS_REPARSE_WOF;
		return NTFS_OK;
	}
	if ((tag & ~NTFS_REPARSE_CLOUD_VARIANT_MASK) == NTFS_REPARSE_TAG_CLOUD) {
		values->info.kind = NTFS_REPARSE_CLOUD;
		return NTFS_OK;
	}
	if (tag != NTFS_REPARSE_TAG_SYMLINK && tag != NTFS_REPARSE_TAG_MOUNT_POINT) {
		return NTFS_OK;
	}
	payload = (const uint8_t *)buffer + sizeof(*header);
	header_size = tag == NTFS_REPARSE_TAG_SYMLINK ? sizeof(*symlink) : sizeof(*names);
	if (size - sizeof(*header) < header_size) {
		return NTFS_CORRUPT;
	}
	if (tag == NTFS_REPARSE_TAG_SYMLINK) {
		symlink = (const void *)payload;
		values->info.flags = ntfs_u32(symlink->flags);
		if ((values->info.flags & ~NTFS_REPARSE_SYMLINK_RELATIVE) != 0) {
			return NTFS_UNSUPPORTED;
		}
		values->info.kind = NTFS_REPARSE_SYMLINK;
	} else {
		values->info.kind = NTFS_REPARSE_MOUNT_POINT;
	}
	names = (const void *)payload;
	path = payload + header_size;
	path_size = size - sizeof(*header) - header_size;
	values->substitute_offset = ntfs_u16(names->substitute_offset);
	values->print_offset = ntfs_u16(names->print_offset);
	substitute_length = ntfs_u16(names->substitute_length);
	print_length = ntfs_u16(names->print_length);
	if (path_size % NTFS_UTF16_UNIT_BYTES != 0 || substitute_length == 0 ||
	    !valid_name(path, path_size, values->substitute_offset, substitute_length) ||
	    !valid_name(path, path_size, values->print_offset, print_length)) {
		return NTFS_CORRUPT;
	}
	values->info.substitute_length = substitute_length / NTFS_UTF16_UNIT_BYTES;
	values->info.print_length = print_length / NTFS_UTF16_UNIT_BYTES;
	values->substitute_offset += sizeof(*header) + header_size;
	values->print_offset += sizeof(*header) + header_size;
	return NTFS_OK;
}

enum ntfs_result
ntfs_reparse_decode(const void *buffer, size_t size, struct ntfs_reparse_info *info)
{
	struct reparse_values values;
	enum ntfs_result result;

	if (info == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(info, sizeof(*info));
	if (buffer == NULL) {
		return NTFS_INVALID;
	}
	result = decode_reparse(buffer, size, &values);
	if (result == NTFS_OK) {
		*info = values.info;
	}
	return result;
}

enum ntfs_result
ntfs_reparse_open(struct ntfs_node *node, struct ntfs_reparse **out)
{
	struct ntfs_volume *v;
	struct ntfs_stream *stream = NULL;
	struct ntfs_reparse *reparse;
	struct reparse_values values;
	struct ntfs_stat stat;
	uint8_t *bytes = NULL;
	size_t size = 0;
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	*out = NULL;
	if (node == NULL) {
		return NTFS_INVALID;
	}
	v = node->volume;
	if (v->children == UINT32_MAX) {
		return NTFS_RANGE;
	}
	result = ntfs_node_metadata(node, &stat);
	if (result != NTFS_OK) {
		return result;
	}
	if (!stat.reparse) {
		return NTFS_NOT_FOUND;
	}
	result = ntfs_attribute_open(node, NTFS_ATTRIBUTE_REPARSE_POINT, NULL, 0, &stream);
	if (result != NTFS_OK) {
		return result == NTFS_NOT_FOUND ? NTFS_CORRUPT : result;
	}
	if (stream->flags != 0 || stream->initialized != stream->size ||
	    stream->size < sizeof(struct ntfs_disk_reparse) ||
	    stream->size > NTFS_REPARSE_MAX_BYTES) {
		result = NTFS_CORRUPT;
		goto finish;
	}
	size = (size_t)stream->size;
	if (stream->resident) {
		bytes = stream->value;
		stream->value = NULL;
		stream->value_allocation = 0;
	} else {
		bytes = ntfs_alloc(v, size);
		if (bytes == NULL) {
			result = NTFS_NO_MEMORY;
			goto finish;
		}
		result = ntfs_stream_exact(stream, 0, bytes, size);
		if (result != NTFS_OK) {
			goto finish;
		}
	}
	result = decode_reparse(bytes, size, &values);
	if (result != NTFS_OK) {
		goto finish;
	}
	if (values.info.kind == NTFS_REPARSE_MOUNT_POINT && !stat.directory) {
		result = NTFS_CORRUPT;
		goto finish;
	}
	reparse = ntfs_alloc(v, sizeof(*reparse));
	if (reparse == NULL) {
		result = NTFS_NO_MEMORY;
		goto finish;
	}
	reparse->volume = v;
	reparse->values = values;
	reparse->bytes = bytes;
	reparse->size = size;
	bytes = NULL;
	v->children++;
	*out = reparse;
finish:
	ntfs_free(v, bytes, size);
	ntfs_stream_close(stream);
	return result;
}

void
ntfs_reparse_close(struct ntfs_reparse *reparse)
{
	struct ntfs_volume *v;

	if (reparse == NULL) {
		return;
	}
	v = reparse->volume;
	v->children--;
	ntfs_free(v, reparse->bytes, reparse->size);
	ntfs_free(v, reparse, sizeof(*reparse));
}

void
ntfs_reparse_get_info(const struct ntfs_reparse *reparse, struct ntfs_reparse_info *info)
{
	*info = reparse->values.info;
}

enum ntfs_result
ntfs_reparse_name(const struct ntfs_reparse *reparse, enum ntfs_reparse_name_type which,
    uint16_t *buffer, size_t capacity, size_t *length)
{
	size_t offset, count, i;

	if (length == NULL) {
		return NTFS_INVALID;
	}
	*length = 0;
	if (reparse == NULL || (capacity != 0 && buffer == NULL) ||
	    (which != NTFS_REPARSE_SUBSTITUTE_NAME && which != NTFS_REPARSE_PRINT_NAME)) {
		return NTFS_INVALID;
	}
	if (reparse->values.info.kind != NTFS_REPARSE_SYMLINK &&
	    reparse->values.info.kind != NTFS_REPARSE_MOUNT_POINT) {
		return NTFS_UNSUPPORTED;
	}
	if (which == NTFS_REPARSE_SUBSTITUTE_NAME) {
		offset = reparse->values.substitute_offset;
		count = reparse->values.info.substitute_length;
	} else {
		offset = reparse->values.print_offset;
		count = reparse->values.info.print_length;
	}
	*length = count;
	if (capacity < count) {
		return NTFS_RANGE;
	}
	for (i = 0; i < count; i++) {
		buffer[i] = ntfs_u16(reparse->bytes + offset + i * NTFS_UTF16_UNIT_BYTES);
	}
	return NTFS_OK;
}
