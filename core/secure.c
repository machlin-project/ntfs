/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include <ntfs/access.h>

struct ntfs_security {
	struct ntfs_volume *volume;
	struct ntfs_security_info info;
	uint8_t *bytes;
	size_t size;
	uint32_t id;
};

struct secure_key {
	uint32_t hash, id;
};

struct secure_bounds {
	struct secure_key lower, upper;
	bool has_lower, has_upper;
};

struct secure_choice {
	struct secure_bounds bounds;
	struct ntfs_disk_security_locator locator;
	uint64_t vcn;
	bool found, child;
};

static const uint16_t sii_name[] = {'$', 'S', 'I', 'I'};
static const uint16_t sdh_name[] = {'$', 'S', 'D', 'H'};
static const uint16_t sds_name[] = {'$', 'S', 'D', 'S'};

static int
compare_key(struct secure_key a, struct secure_key b, bool by_hash)
{
	if (by_hash && a.hash != b.hash) {
		return a.hash < b.hash ? -1 : 1;
	}
	return a.id == b.id ? 0 : a.id < b.id ? -1 : 1;
}

static bool
valid_locator(const struct ntfs_disk_security_locator *locator, uint64_t store_size)
{
	uint64_t offset = ntfs_u64(locator->offset);
	uint32_t length = ntfs_u32(locator->length);

	/* Locators always name the primary half of a 512-KiB pair. Each whole
	 * entry and its duplicate must fit the initialized, immutable stream. */
	return ntfs_u32(locator->security_id) != 0 && offset % NTFS_SDS_ALIGNMENT == 0 &&
	    offset % NTFS_SDS_PAIR_BYTES < NTFS_SDS_BLOCK_BYTES &&
	    length >= sizeof(*locator) + sizeof(struct ntfs_disk_security_descriptor) &&
	    length <= NTFS_SDS_BLOCK_BYTES - offset % NTFS_SDS_BLOCK_BYTES &&
	    ntfs_bounds(offset, (uint64_t)NTFS_SDS_BLOCK_BYTES + length, store_size);
}

static enum ntfs_result
choose_entry(const uint8_t *bytes, size_t size, size_t header_offset, bool by_hash,
    struct secure_key target, const struct secure_bounds *bounds, uint64_t store_size,
    struct secure_choice *choice)
{
	const struct ntfs_disk_index_header *header;
	const struct ntfs_disk_view_entry *entry;
	const struct ntfs_disk_security_locator *locator;
	const struct ntfs_disk_security_hash_key *hash_key;
	struct secure_key key = {0}, previous = {0};
	size_t position, end, length, key_length, trailer, payload_end, data_offset;
	uint16_t flags;
	bool has_previous = false, selected = false, terminal = false, large;
	int order;

	ntfs_zero(choice, sizeof(*choice));
	if (!ntfs_bounds(header_offset, sizeof(*header), size)) {
		return NTFS_CORRUPT;
	}
	header = (const void *)(bytes + header_offset);
	position = ntfs_u32(header->entries_offset);
	end = ntfs_u32(header->used);
	if (position < sizeof(*header) || position % NTFS_WIRE_ALIGNMENT != 0 || end < position ||
	    end > ntfs_u32(header->allocated) ||
	    !ntfs_bounds(header_offset, ntfs_u32(header->allocated), size) ||
	    (header->flags & ~NTFS_INDEX_LARGE) != 0) {
		return NTFS_CORRUPT;
	}
	position += header_offset;
	end += header_offset;
	large = (header->flags & NTFS_INDEX_LARGE) != 0;
	while (position < end) {
		if (!ntfs_bounds(position, sizeof(*entry), end)) {
			return NTFS_CORRUPT;
		}
		entry = (const void *)(bytes + position);
		flags = ntfs_u16(entry->flags);
		length = ntfs_u16(entry->length);
		key_length = ntfs_u16(entry->key_length);
		trailer = (flags & NTFS_INDEX_CHILD) != 0 ? sizeof(uint64_t) : 0;
		if ((flags & ~(NTFS_INDEX_CHILD | NTFS_INDEX_END)) != 0 ||
		    ((flags & NTFS_INDEX_CHILD) != 0) != large ||
		    length < sizeof(*entry) + trailer || length % NTFS_WIRE_ALIGNMENT != 0 ||
		    !ntfs_bounds(position, length, end)) {
			return NTFS_CORRUPT;
		}
		payload_end = length - trailer;
		if ((flags & NTFS_INDEX_END) != 0) {
			if (key_length != 0 || ntfs_u16(entry->data_length) != 0 ||
			    position + length != end) {
				return NTFS_CORRUPT;
			}
			terminal = true;
			order = 1;
		} else {
			if (key_length != (by_hash ? sizeof(*hash_key) : sizeof(uint32_t)) ||
			    key_length > payload_end - sizeof(*entry)) {
				return NTFS_CORRUPT;
			}
			hash_key = (const void *)((const uint8_t *)entry + sizeof(*entry));
			key.hash = by_hash ? ntfs_u32(hash_key->hash) : 0;
			key.id = by_hash ? ntfs_u32(hash_key->security_id) : ntfs_u32(hash_key);
			data_offset = ntfs_u16(entry->data_offset);
			if (ntfs_u16(entry->data_length) != sizeof(*locator) ||
			    data_offset < sizeof(*entry) + key_length ||
			    !ntfs_bounds(data_offset, sizeof(*locator), payload_end)) {
				return NTFS_CORRUPT;
			}
			locator = (const void *)((const uint8_t *)entry + data_offset);
			if (!valid_locator(locator, store_size) ||
			    ntfs_u32(locator->security_id) != key.id ||
			    (by_hash && ntfs_u32(locator->hash) != key.hash) ||
			    (has_previous && compare_key(previous, key, by_hash) >= 0) ||
			    (bounds->has_lower && compare_key(bounds->lower, key, by_hash) >= 0) ||
			    (bounds->has_upper && compare_key(key, bounds->upper, by_hash) >= 0)) {
				return NTFS_CORRUPT;
			}
			order = compare_key(key, target, by_hash);
			if (order == 0) {
				choice->found = true;
				choice->locator = *locator;
			}
		}
		if (!selected && order >= 0) {
			selected = true;
			choice->child = large;
			choice->bounds = *bounds;
			if (has_previous) {
				choice->bounds.lower = previous;
				choice->bounds.has_lower = true;
			}
			if (!terminal) {
				choice->bounds.upper = key;
				choice->bounds.has_upper = true;
			}
			if (large) {
				choice->vcn = ntfs_u64((const uint8_t *)entry + payload_end);
			}
		}
		if (terminal) {
			break;
		}
		previous = key;
		has_previous = true;
		position += length;
	}
	return terminal && selected ? NTFS_OK : NTFS_CORRUPT;
}

static enum ntfs_result
index_seek(struct ntfs_node *node, bool by_hash, struct secure_key target, uint64_t store_size,
    struct ntfs_disk_security_locator *out)
{
	struct ntfs_volume *v = node->volume;
	struct ntfs_stream *root = NULL, *allocation = NULL, *bitmap = NULL;
	const struct ntfs_disk_index_root *header;
	const struct ntfs_disk_index_block *block;
	const uint16_t *name = by_hash ? sdh_name : sii_name;
	const uint8_t *bytes;
	uint8_t *buffer = NULL, allocated;
	struct secure_bounds bounds = {0};
	struct secure_choice choice;
	uint64_t visited[NTFS_SECURITY_INDEX_DEPTH], offset, bit;
	size_t size, header_offset;
	uint32_t block_size = 0, unit, depth = 0, i;
	enum ntfs_result result;

	result = ntfs_attribute_open(
	    node, NTFS_ATTR_INDEX_ROOT, name, sizeof(sii_name) / sizeof(sii_name[0]), &root);
	if (result != NTFS_OK) {
		result = result == NTFS_NOT_FOUND ? NTFS_CORRUPT : result;
		goto finish;
	}
	if (!root->resident || root->flags != 0 ||
	    root->size < sizeof(*header) + sizeof(struct ntfs_disk_index_header)) {
		result = NTFS_CORRUPT;
		goto finish;
	}
	header = (const void *)root->value;
	block_size = ntfs_u32(header->block_size);
	if (ntfs_u32(header->type) != NTFS_INDEX_VIEW_TYPE ||
	    ntfs_u32(header->collation) !=
		(by_hash ? NTFS_COLLATION_SECURITY_HASH : NTFS_COLLATION_ULONG)) {
		result = NTFS_UNSUPPORTED;
		goto finish;
	}
	if (block_size < v->info.sector_size || block_size > NTFS_MAX_INDEX_BYTES ||
	    (block_size & (block_size - 1u)) != 0) {
		result = NTFS_CORRUPT;
		goto finish;
	}
	unit = v->info.cluster_size <= block_size ? v->info.cluster_size : v->info.sector_size;
	bytes = root->value;
	size = (size_t)root->size;
	header_offset = sizeof(*header);
	for (;;) {
		result = ntfs_work(v, size);
		if (result != NTFS_OK) {
			goto finish;
		}
		result = choose_entry(
		    bytes, size, header_offset, by_hash, target, &bounds, store_size, &choice);
		if (result != NTFS_OK) {
			goto finish;
		}
		if (choice.found) {
			*out = choice.locator;
			goto finish;
		}
		if (!choice.child) {
			result = NTFS_NOT_FOUND;
			goto finish;
		}
		/* One block buffer and copied ancestor keys make memory independent
		 * of tree depth. A bounded path suffices for cycle checks on a seek. */
		for (i = 0; i < depth; i++) {
			if (visited[i] == choice.vcn) {
				result = NTFS_CORRUPT;
				goto finish;
			}
		}
		if (depth == NTFS_SECURITY_INDEX_DEPTH - 1 ||
		    depth == v->limits.max_directory_nodes) {
			result = NTFS_RANGE;
			goto finish;
		}
		if (choice.vcn > (uint64_t)INT64_MAX / unit) {
			result = NTFS_CORRUPT;
			goto finish;
		}
		offset = choice.vcn * unit;
		if (allocation == NULL) {
			result = ntfs_attribute_open(node, NTFS_ATTR_INDEX_ALLOCATION, name,
			    sizeof(sii_name) / sizeof(sii_name[0]), &allocation);
			if (result == NTFS_OK) {
				result = ntfs_attribute_open(node, NTFS_ATTR_BITMAP, name,
				    sizeof(sii_name) / sizeof(sii_name[0]), &bitmap);
			}
			if (result != NTFS_OK) {
				result = result == NTFS_NOT_FOUND ? NTFS_CORRUPT : result;
				goto finish;
			}
			if (allocation->resident || allocation->flags != 0 ||
			    allocation->initialized != allocation->size || bitmap->flags != 0 ||
			    bitmap->initialized != bitmap->size) {
				result = NTFS_CORRUPT;
				goto finish;
			}
			buffer = ntfs_alloc(v, block_size);
			if (buffer == NULL) {
				result = NTFS_NO_MEMORY;
				goto finish;
			}
		}
		if (offset % block_size != 0 ||
		    !ntfs_bounds(offset, block_size, allocation->size)) {
			result = NTFS_CORRUPT;
			goto finish;
		}
		bit = offset / block_size;
		if (!ntfs_bounds(bit / NTFS_BITS_PER_BYTE, sizeof(allocated), bitmap->size)) {
			result = NTFS_CORRUPT;
			goto finish;
		}
		result = ntfs_stream_exact(
		    bitmap, bit / NTFS_BITS_PER_BYTE, &allocated, sizeof(allocated));
		if (result != NTFS_OK) {
			goto finish;
		}
		if ((allocated & (1u << (bit % NTFS_BITS_PER_BYTE))) == 0) {
			result = NTFS_CORRUPT;
			goto finish;
		}
		visited[depth++] = choice.vcn;
		bounds = choice.bounds;
		result = ntfs_stream_exact(allocation, offset, buffer, block_size);
		if (result == NTFS_OK) {
			result = ntfs_fixup(buffer, block_size, "INDX");
		}
		if (result != NTFS_OK) {
			goto finish;
		}
		block = (const void *)buffer;
		if (ntfs_u64(block->vcn) != choice.vcn ||
		    ntfs_u16(block->mst.usa_offset) < sizeof(*block) ||
		    ntfs_u16(block->mst.usa_offset) +
			    (size_t)ntfs_u16(block->mst.usa_count) * NTFS_MST_WORD_BYTES >
			offsetof(struct ntfs_disk_index_block, header) +
			    (uint64_t)ntfs_u32(block->header.entries_offset)) {
			result = NTFS_CORRUPT;
			goto finish;
		}
		bytes = buffer;
		size = block_size;
		header_offset = offsetof(struct ntfs_disk_index_block, header);
	}
finish:
	ntfs_free(v, buffer, block_size);
	ntfs_stream_close(bitmap);
	ntfs_stream_close(allocation);
	ntfs_stream_close(root);
	return result;
}

static uint32_t
descriptor_hash(const uint8_t *bytes, size_t size)
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

static enum ntfs_result
read_descriptor(struct ntfs_stream *store, const struct ntfs_disk_security_locator *locator,
    struct ntfs_security *snapshot)
{
	struct ntfs_volume *v = store->volume;
	struct ntfs_disk_security_locator primary, duplicate;
	uint64_t offset = ntfs_u64(locator->offset);
	uint8_t *compare = NULL;
	size_t position, length;
	enum ntfs_result result;

	result = ntfs_stream_exact(store, offset, &primary, sizeof(primary));
	if (result != NTFS_OK) {
		return result;
	}
	if (!ntfs_equal(locator, &primary, sizeof(primary))) {
		return NTFS_CORRUPT;
	}
	snapshot->size = ntfs_u32(primary.length) - sizeof(primary);
	snapshot->bytes = ntfs_alloc(v, snapshot->size);
	if (snapshot->bytes == NULL) {
		return NTFS_NO_MEMORY;
	}
	result =
	    ntfs_stream_exact(store, offset + sizeof(primary), snapshot->bytes, snapshot->size);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_work(v, snapshot->size);
	if (result != NTFS_OK) {
		return result;
	}
	if (descriptor_hash(snapshot->bytes, snapshot->size) != ntfs_u32(primary.hash)) {
		return NTFS_CORRUPT;
	}
	result = ntfs_work(v, snapshot->size);
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
	if (!ntfs_equal(&primary, &duplicate, sizeof(primary))) {
		return NTFS_CORRUPT;
	}
	compare = ntfs_alloc(v, NTFS_SECURITY_COMPARE_BYTES);
	if (compare == NULL) {
		return NTFS_NO_MEMORY;
	}
	for (position = 0; position < snapshot->size; position += length) {
		length = snapshot->size - position;
		if (length > NTFS_SECURITY_COMPARE_BYTES) {
			length = NTFS_SECURITY_COMPARE_BYTES;
		}
		result = ntfs_stream_exact(
		    store, offset + sizeof(duplicate) + position, compare, length);
		if (result != NTFS_OK) {
			break;
		}
		if (!ntfs_equal(snapshot->bytes + position, compare, length)) {
			result = NTFS_CORRUPT;
			break;
		}
	}
	ntfs_free(v, compare, NTFS_SECURITY_COMPARE_BYTES);
	return result;
}

enum ntfs_result
ntfs_security_resolve_impl(struct ntfs_volume *v, uint32_t id, struct ntfs_security **out)
{
	struct ntfs_node *node = NULL;
	struct ntfs_stream *store = NULL;
	struct ntfs_security *snapshot = NULL;
	struct ntfs_stat stat;
	struct ntfs_disk_security_locator sii, sdh;
	struct secure_key key = {.id = id};
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	*out = NULL;
	if (v == NULL || id == 0) {
		return NTFS_INVALID;
	}
	if (v->children == UINT32_MAX) {
		return NTFS_RANGE;
	}
	result = ntfs_node_by_number(v, NTFS_SECURE_RECORD, &node);
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
	result = index_seek(node, false, key, store->size, &sii);
	if (result != NTFS_OK) {
		goto finish;
	}
	key.hash = ntfs_u32(sii.hash);
	result = index_seek(node, true, key, store->size, &sdh);
	if (result != NTFS_OK) {
		result = result == NTFS_NOT_FOUND ? NTFS_CORRUPT : result;
		goto finish;
	}
	if (!ntfs_equal(&sii, &sdh, sizeof(sii))) {
		result = NTFS_CORRUPT;
		goto finish;
	}
	if (v->children == UINT32_MAX) {
		result = NTFS_RANGE;
		goto finish;
	}
	snapshot = ntfs_alloc(v, sizeof(*snapshot));
	if (snapshot == NULL) {
		result = NTFS_NO_MEMORY;
		goto finish;
	}
	snapshot->volume = v;
	snapshot->id = id;
	v->children++;
	result = read_descriptor(store, &sii, snapshot);
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
open_file_descriptor(struct ntfs_node *node, struct ntfs_security **out)
{
	struct ntfs_volume *v = node->volume;
	struct ntfs_stream *stream = NULL;
	struct ntfs_security *snapshot = NULL;
	enum ntfs_result result;

	if (v->children == UINT32_MAX) {
		return NTFS_RANGE;
	}
	result = ntfs_attribute_open(node, NTFS_ATTR_SECURITY_DESCRIPTOR, NULL, 0, &stream);
	if (result != NTFS_OK) {
		return result == NTFS_NOT_FOUND ? NTFS_CORRUPT : result;
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
	snapshot = ntfs_alloc(v, sizeof(*snapshot));
	if (snapshot == NULL) {
		result = NTFS_NO_MEMORY;
		goto finish;
	}
	snapshot->volume = v;
	snapshot->size = (size_t)stream->size;
	v->children++;
	if (stream->resident) {
		snapshot->bytes = stream->value;
		stream->value = NULL;
		stream->value_allocation = 0;
	} else {
		snapshot->bytes = ntfs_alloc(v, snapshot->size);
		if (snapshot->bytes == NULL) {
			result = NTFS_NO_MEMORY;
			goto finish;
		}
		result = ntfs_stream_exact(stream, 0, snapshot->bytes, snapshot->size);
		if (result != NTFS_OK) {
			goto finish;
		}
	}
	result = ntfs_work(v, snapshot->size);
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
		return open_file_descriptor(node, out);
	}
	result = ntfs_security_resolve(node->volume, stat.security_id, out);
	return result == NTFS_NOT_FOUND ? NTFS_CORRUPT : result;
}

void
ntfs_security_close(struct ntfs_security *snapshot)
{
	struct ntfs_volume *v;

	if (snapshot == NULL) {
		return;
	}
	v = snapshot->volume;
	ntfs_free(v, snapshot->bytes, snapshot->size);
	v->children--;
	ntfs_free(v, snapshot, sizeof(*snapshot));
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
