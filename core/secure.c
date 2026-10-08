/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "secure_internal.h"

static const uint16_t sds_name[] = {'$', 'S', 'D', 'S'};

static uint32_t ntfs_secure_descriptor_hash(const uint8_t *bytes, size_t size);
static enum ntfs_result ntfs_secure_open_file_descriptor(struct ntfs_node *node,
    struct ntfs_security **out, enum ntfs_result (*charge)(void *, uint64_t), void *context);

static uint32_t
ntfs_secure_descriptor_hash(const uint8_t *bytes, size_t size)
{
	uint32_t hash = 0;
	size_t position;

	/* The stored checksum rotates by three and adds each complete LE DWORD,
	 * with unsigned 32-bit wrap. It is a format check, not authentication. */
	for (position = 0; ntfs_bounds(position, sizeof(uint32_t), size);
	    position += sizeof(uint32_t)) {
		hash = (hash << NTFS_SECURITY_HASH_ROTATION) |
		    (hash >> (NTFS_SECURITY_HASH_BITS - NTFS_SECURITY_HASH_ROTATION));
		hash += ntfs_u32(bytes + position);
	}
	return hash;
}

enum ntfs_result
ntfs_secure_read_descriptor(struct ntfs_stream *store,
    const struct ntfs_disk_security_locator *locator, struct ntfs_security *snapshot,
    enum ntfs_result (*charge)(void *, uint64_t), void *context)
{
	struct ntfs_volume *volume = store->volume;
	struct ntfs_disk_security_locator primary, duplicate;
	uint64_t offset = ntfs_u64(locator->offset);
	uint8_t *compare = NULL;
	size_t position, length;
	enum ntfs_result result;

	result = ntfs_stream_exact(store, offset, &primary, sizeof(primary));
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_index_work(volume, charge, context, sizeof(primary));
	if (result != NTFS_OK) {
		return result;
	}
	if (!ntfs_equal(locator, &primary, sizeof(primary))) {
		return NTFS_CORRUPT;
	}
	snapshot->size = ntfs_u32(primary.length) - sizeof(primary);
	snapshot->bytes = ntfs_alloc(volume, snapshot->size);
	if (snapshot->bytes == NULL) {
		return NTFS_NO_MEMORY;
	}
	result =
	    ntfs_stream_exact(store, offset + sizeof(primary), snapshot->bytes, snapshot->size);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_index_work(volume, charge, context, snapshot->size);
	if (result != NTFS_OK) {
		return result;
	}
	if (ntfs_secure_descriptor_hash(snapshot->bytes, snapshot->size) !=
	    ntfs_u32(primary.hash)) {
		return NTFS_CORRUPT;
	}
	result = ntfs_index_work(volume, charge, context, snapshot->size);
	if (result == NTFS_OK) {
		result = ntfs_security_decode(snapshot->bytes, snapshot->size, &snapshot->info);
	}
	if (result != NTFS_OK) {
		return result;
	}
	offset += NTFS_SDS_BLOCK_BYTES;
	result = ntfs_stream_exact(store, offset, &duplicate, sizeof(duplicate));
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_index_work(volume, charge, context, sizeof(primary));
	if (result != NTFS_OK) {
		return result;
	}
	if (!ntfs_equal(&primary, &duplicate, sizeof(primary))) {
		return NTFS_CORRUPT;
	}
	compare = ntfs_alloc(volume, NTFS_SECURITY_COMPARE_BYTES);
	if (compare == NULL) {
		return NTFS_NO_MEMORY;
	}
	for (position = 0; position < snapshot->size; position += length) {
		length = snapshot->size - position;
		if (length > NTFS_SECURITY_COMPARE_BYTES) {
			length = NTFS_SECURITY_COMPARE_BYTES;
		}
		result = ntfs_index_work(volume, charge, context, length);
		if (result == NTFS_OK) {
			result = ntfs_stream_exact(
			    store, offset + sizeof(duplicate) + position, compare, length);
		}
		if (result != NTFS_OK) {
			break;
		}
		if (!ntfs_equal(snapshot->bytes + position, compare, length)) {
			result = NTFS_CORRUPT;
			break;
		}
	}
	ntfs_free(volume, compare, NTFS_SECURITY_COMPARE_BYTES);
	return result;
}

enum ntfs_result
ntfs_security_resolve_impl(
    struct ntfs_volume *volume, uint32_t security_id, struct ntfs_security **out)
{
	struct ntfs_node *node = NULL;
	struct ntfs_stream *store = NULL;
	struct ntfs_security *snapshot = NULL;
	struct ntfs_stat stat;
	struct ntfs_disk_security_locator sii, sdh;
	struct ntfs_secure_index_key key = {.id = security_id};
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	*out = NULL;
	if (volume == NULL || security_id == 0) {
		return NTFS_INVALID;
	}
	if (volume->children == UINT32_MAX) {
		return NTFS_RANGE;
	}
	result = ntfs_node_by_number(volume, NTFS_SECURE_RECORD, &node);
	if (result != NTFS_OK) {
		goto finish;
	}
	result = ntfs_node_metadata(node, &stat);
	if (result != NTFS_OK) {
		goto finish;
	}
	if (stat.directory || stat.reparse) {
		result = NTFS_CORRUPT;
		goto finish;
	}
	result = ntfs_attribute_open(
	    node, NTFS_ATTRIBUTE_DATA, sds_name, sizeof(sds_name) / sizeof(sds_name[0]), &store);
	if (result != NTFS_OK) {
		result = result == NTFS_NOT_FOUND ? NTFS_CORRUPT : result;
		goto finish;
	}
	if (store->resident || store->flags != 0 || store->initialized != store->size) {
		result = NTFS_CORRUPT;
		goto finish;
	}
	result = ntfs_secure_index_seek(node, false, key, store->size, &sii);
	if (result != NTFS_OK) {
		goto finish;
	}
	key.hash = ntfs_u32(sii.hash);
	result = ntfs_secure_index_seek(node, true, key, store->size, &sdh);
	if (result != NTFS_OK) {
		result = result == NTFS_NOT_FOUND ? NTFS_CORRUPT : result;
		goto finish;
	}
	if (!ntfs_equal(&sii, &sdh, sizeof(sii))) {
		result = NTFS_CORRUPT;
		goto finish;
	}
	if (volume->children == UINT32_MAX) {
		result = NTFS_RANGE;
		goto finish;
	}
	snapshot = ntfs_alloc(volume, sizeof(*snapshot));
	if (snapshot == NULL) {
		result = NTFS_NO_MEMORY;
		goto finish;
	}
	snapshot->volume = volume;
	snapshot->id = security_id;
	volume->children++;
	result = ntfs_secure_read_descriptor(store, &sii, snapshot, NULL, NULL);
finish:
	ntfs_stream_close(store);
	ntfs_node_close(node);
	if (result != NTFS_OK) {
		ntfs_security_close(snapshot);
		return result;
	}
	*out = snapshot;
	return NTFS_OK;
}

static enum ntfs_result
ntfs_secure_open_file_descriptor(struct ntfs_node *node, struct ntfs_security **out,
    enum ntfs_result (*charge)(void *, uint64_t), void *context)
{
	struct ntfs_volume *volume = node->volume;
	struct ntfs_stream *stream = NULL;
	struct ntfs_security *snapshot = NULL;
	enum ntfs_result result;

	if (volume->children == UINT32_MAX) {
		return NTFS_RANGE;
	}
	result = ntfs_attribute_open(node, NTFS_ATTR_SECURITY_DESCRIPTOR, NULL, 0, &stream);
	if (result != NTFS_OK) {
		return result;
	}
	if (stream->flags != 0 || stream->initialized != stream->size ||
	    stream->size < sizeof(struct ntfs_disk_security_descriptor)) {
		result = NTFS_CORRUPT;
		goto finish;
	}
	if (stream->size > NTFS_SECURITY_MAX_BYTES) {
		result = NTFS_RANGE;
		goto finish;
	}
	snapshot = ntfs_alloc(volume, sizeof(*snapshot));
	if (snapshot == NULL) {
		result = NTFS_NO_MEMORY;
		goto finish;
	}
	snapshot->volume = volume;
	snapshot->size = (size_t)stream->size;
	volume->children++;
	if (stream->resident) {
		snapshot->bytes = stream->value;
		stream->value = NULL;
		stream->value_allocation = 0;
	} else {
		snapshot->bytes = ntfs_alloc(volume, snapshot->size);
		if (snapshot->bytes == NULL) {
			result = NTFS_NO_MEMORY;
			goto finish;
		}
		result = ntfs_stream_exact(stream, 0, snapshot->bytes, snapshot->size);
		if (result != NTFS_OK) {
			goto finish;
		}
	}
	result = ntfs_index_work(volume, charge, context, snapshot->size);
	if (result == NTFS_OK) {
		result = ntfs_security_decode(snapshot->bytes, snapshot->size, &snapshot->info);
	}
finish:
	ntfs_stream_close(stream);
	if (result != NTFS_OK) {
		ntfs_security_close(snapshot);
		return result;
	}
	*out = snapshot;
	return NTFS_OK;
}

enum ntfs_result
ntfs_security_file_validate(struct ntfs_node *node, bool required,
    enum ntfs_result (*charge)(void *, uint64_t), void *context)
{
	struct ntfs_security *snapshot = NULL;
	enum ntfs_result result;

	result = ntfs_secure_open_file_descriptor(node, &snapshot, charge, context);
	ntfs_security_close(snapshot);
	if (result == NTFS_NOT_FOUND) {
		return required ? NTFS_CORRUPT : NTFS_OK;
	}
	return result;
}

enum ntfs_result
ntfs_security_open_impl(struct ntfs_node *node, struct ntfs_security **out)
{
	struct ntfs_stat stat;
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	*out = NULL;
	result = ntfs_node_metadata(node, &stat);
	if (result != NTFS_OK) {
		return result;
	}
	if (stat.security_id == 0) {
		result = ntfs_secure_open_file_descriptor(node, out, NULL, NULL);
		return result == NTFS_NOT_FOUND ? NTFS_CORRUPT : result;
	}
	result = ntfs_security_resolve(node->volume, stat.security_id, out);
	return result == NTFS_NOT_FOUND ? NTFS_CORRUPT : result;
}

void
ntfs_security_close(struct ntfs_security *snapshot)
{
	struct ntfs_volume *volume;

	if (snapshot == NULL) {
		return;
	}
	volume = snapshot->volume;
	ntfs_free(volume, snapshot->bytes, snapshot->size);
	volume->children--;
	ntfs_free(volume, snapshot, sizeof(*snapshot));
}

uint32_t
ntfs_security_id(const struct ntfs_security *snapshot)
{
	return snapshot == NULL ? 0 : snapshot->id;
}

size_t
ntfs_security_size(const struct ntfs_security *snapshot)
{
	return snapshot == NULL ? 0 : snapshot->size;
}

void
ntfs_security_get_info(const struct ntfs_security *snapshot, struct ntfs_security_info *out)
{
	if (out != NULL) {
		ntfs_zero(out, sizeof(*out));
		if (snapshot != NULL) {
			*out = snapshot->info;
		}
	}
}

enum ntfs_result
ntfs_security_copy_impl(
    const struct ntfs_security *snapshot, void *buffer, size_t capacity, size_t *size)
{
	enum ntfs_result result;

	if (size == NULL) {
		return NTFS_INVALID;
	}
	*size = 0;
	if (snapshot == NULL || (buffer == NULL && capacity != 0)) {
		return NTFS_INVALID;
	}
	*size = snapshot->size;
	if (buffer == NULL && capacity == 0) {
		return NTFS_OK;
	}
	if (capacity < snapshot->size) {
		return NTFS_RANGE;
	}
	result = ntfs_work(snapshot->volume, snapshot->size);
	if (result != NTFS_OK) {
		*size = 0;
		return result;
	}
	ntfs_copy(buffer, snapshot->bytes, snapshot->size);
	return NTFS_OK;
}

enum ntfs_result
ntfs_security_evaluate_dacl_impl(const struct ntfs_security *snapshot,
    const struct ntfs_access_token *token, uint32_t desired, const struct ntfs_dacl_limits *limits,
    struct ntfs_dacl_decision *out)
{
	if (snapshot == NULL) {
		if (out != NULL) {
			ntfs_zero(out, sizeof(*out));
		}
		return NTFS_INVALID;
	}
	return ntfs_dacl_evaluate_volume(
	    snapshot->volume, snapshot->bytes, snapshot->size, token, desired, limits, out);
}

struct ntfs_volume *
ntfs_security_volume(const struct ntfs_security *object)
{
	return object == NULL ? NULL : object->volume;
}
