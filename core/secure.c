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

struct secure_frame {
	uint8_t *bytes;
	size_t allocation, position, end;
	struct secure_bounds bounds;
	struct secure_key previous;
	bool has_previous, descended, owned;
};

struct secure_cursor {
	struct ntfs_volume *volume;
	struct ntfs_stream *root, *allocation, *bitmap;
	struct secure_frame frames[NTFS_SECURITY_INDEX_DEPTH];
	struct ntfs_index_visited visited;
	uint64_t store_size;
	uint32_t block_size, depth;
	bool by_hash;
	enum ntfs_result (*charge)(void *, uint64_t);
	void *context;
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
root_geometry(struct ntfs_stream *root, bool by_hash, uint32_t *block_size)
{
	const struct ntfs_disk_index_root *header;

	if (!root->resident || root->flags != 0 ||
	    root->size < sizeof(*header) + sizeof(struct ntfs_disk_index_header)) {
		return NTFS_CORRUPT;
	}
	header = (const void *)root->value;
	if (ntfs_u32(header->type) != NTFS_INDEX_VIEW_TYPE ||
	    ntfs_u32(header->collation) !=
		(by_hash ? NTFS_COLLATION_SECURITY_HASH : NTFS_COLLATION_ULONG)) {
		return NTFS_UNSUPPORTED;
	}
	*block_size = ntfs_u32(header->block_size);
	if (*block_size < root->volume->info.sector_size || *block_size > NTFS_MAX_INDEX_BYTES ||
	    (*block_size & (*block_size - 1u)) != 0) {
		return NTFS_CORRUPT;
	}
	return NTFS_OK;
}

static enum ntfs_result
index_seek(struct ntfs_node *node, bool by_hash, struct secure_key target, uint64_t store_size,
    struct ntfs_disk_security_locator *out)
{
	struct ntfs_volume *v = node->volume;
	struct ntfs_stream *root = NULL, *allocation = NULL, *bitmap = NULL;
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
	result = root_geometry(root, by_hash, &block_size);
	if (result != NTFS_OK) {
		goto finish;
	}
	unit = v->info.cluster_size <= block_size ? v->info.cluster_size : v->info.sector_size;
	bytes = root->value;
	size = (size_t)root->size;
	header_offset = sizeof(struct ntfs_disk_index_root);
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

static enum ntfs_result
cursor_frame(struct secure_cursor *cursor, struct secure_frame *frame, size_t header_offset)
{
	const struct ntfs_disk_index_header *header;
	struct secure_choice choice;
	struct secure_key target = {0};
	enum ntfs_result result;

	result =
	    ntfs_index_work(cursor->volume, cursor->charge, cursor->context, frame->allocation);
	if (result == NTFS_OK) {
		result = choose_entry(frame->bytes, frame->allocation, header_offset,
		    cursor->by_hash, target, &frame->bounds, cursor->store_size, &choice);
	}
	if (result != NTFS_OK) {
		return result;
	}
	header = (const void *)(frame->bytes + header_offset);
	frame->position = header_offset + ntfs_u32(header->entries_offset);
	frame->end = header_offset + ntfs_u32(header->used);
	return NTFS_OK;
}

static void
cursor_close(struct secure_cursor *cursor)
{
	struct ntfs_volume *volume;
	struct secure_frame *frame;

	if (cursor == NULL) {
		return;
	}
	volume = cursor->volume;
	while (cursor->depth != 0) {
		frame = &cursor->frames[--cursor->depth];
		if (frame->owned) {
			ntfs_free(volume, frame->bytes, frame->allocation);
		}
	}
	ntfs_free(volume, cursor->visited.values,
	    (size_t)cursor->visited.capacity * sizeof(*cursor->visited.values));
	ntfs_stream_close(cursor->bitmap);
	ntfs_stream_close(cursor->allocation);
	ntfs_stream_close(cursor->root);
	ntfs_free(volume, cursor, sizeof(*cursor));
}

static enum ntfs_result
cursor_open(struct ntfs_node *node, bool by_hash, uint64_t store_size,
    enum ntfs_result (*charge)(void *, uint64_t), void *context, struct secure_cursor **out)
{
	struct secure_cursor *cursor;
	const uint16_t *name = by_hash ? sdh_name : sii_name;
	const struct ntfs_disk_index_root *header;
	const struct ntfs_disk_index_header *node_header;
	struct secure_frame *frame;
	enum ntfs_result result;

	*out = NULL;
	cursor = ntfs_alloc(node->volume, sizeof(*cursor));
	if (cursor == NULL) {
		return NTFS_NO_MEMORY;
	}
	cursor->volume = node->volume;
	cursor->by_hash = by_hash;
	cursor->store_size = store_size;
	cursor->charge = charge;
	cursor->context = context;
	result = ntfs_attribute_open(node, NTFS_ATTR_INDEX_ROOT, name,
	    sizeof(sii_name) / sizeof(sii_name[0]), &cursor->root);
	if (result == NTFS_OK) {
		result = root_geometry(cursor->root, by_hash, &cursor->block_size);
	}
	if (result != NTFS_OK) {
		result = result == NTFS_NOT_FOUND ? NTFS_CORRUPT : result;
		goto finish;
	}
	result = ntfs_attribute_open(node, NTFS_ATTR_INDEX_ALLOCATION, name,
	    sizeof(sii_name) / sizeof(sii_name[0]), &cursor->allocation);
	if (result == NTFS_NOT_FOUND) {
		result = NTFS_OK;
	}
	if (result == NTFS_OK) {
		result = ntfs_attribute_open(node, NTFS_ATTR_BITMAP, name,
		    sizeof(sii_name) / sizeof(sii_name[0]), &cursor->bitmap);
		if (result == NTFS_NOT_FOUND) {
			result = NTFS_OK;
		}
	}
	if (result != NTFS_OK) {
		goto finish;
	}
	header = (const void *)cursor->root->value;
	node_header = (const void *)(cursor->root->value + sizeof(*header));
	if ((cursor->allocation != NULL &&
		(cursor->allocation->resident || cursor->allocation->flags != 0 ||
		    cursor->allocation->initialized != cursor->allocation->size ||
		    (cursor->allocation->size != 0 && cursor->bitmap == NULL))) ||
	    (cursor->bitmap != NULL &&
		(cursor->bitmap->flags != 0 ||
		    cursor->bitmap->initialized != cursor->bitmap->size)) ||
	    ((node_header->flags & NTFS_INDEX_LARGE) != 0 &&
		(cursor->allocation == NULL || cursor->bitmap == NULL))) {
		result = NTFS_CORRUPT;
		goto finish;
	}
	frame = &cursor->frames[0];
	frame->bytes = cursor->root->value;
	frame->allocation = (size_t)cursor->root->size;
	cursor->depth = 1;
	result = cursor_frame(cursor, frame, sizeof(*header));
finish:
	if (result != NTFS_OK) {
		cursor_close(cursor);
		return result;
	}
	*out = cursor;
	return NTFS_OK;
}

static struct secure_key
entry_key(const struct ntfs_disk_view_entry *entry, bool by_hash)
{
	const struct ntfs_disk_security_hash_key *key =
	    (const void *)((const uint8_t *)entry + sizeof(*entry));
	struct secure_key value = {0};

	value.id = by_hash ? ntfs_u32(key->security_id) : ntfs_u32(key);
	value.hash = by_hash ? ntfs_u32(key->hash) : 0;
	return value;
}

static enum ntfs_result
cursor_descend(struct secure_cursor *cursor, const struct ntfs_disk_view_entry *entry)
{
	struct ntfs_volume *volume = cursor->volume;
	const struct secure_frame *parent = &cursor->frames[cursor->depth - 1];
	struct secure_frame *frame;
	const struct ntfs_disk_index_block *block;
	uint64_t vcn, offset, bit;
	uint32_t unit;
	uint8_t allocated;
	enum ntfs_result result;

	if (cursor->depth == NTFS_SECURITY_INDEX_DEPTH) {
		return NTFS_RANGE;
	}
	unit = volume->info.cluster_size <= cursor->block_size ? volume->info.cluster_size
							       : volume->info.sector_size;
	vcn = ntfs_u64((const uint8_t *)entry + ntfs_u16(entry->length) - sizeof(vcn));
	if (vcn > (uint64_t)INT64_MAX / unit) {
		return NTFS_CORRUPT;
	}
	offset = vcn * unit;
	if (cursor->allocation == NULL || cursor->bitmap == NULL ||
	    offset % cursor->block_size != 0 ||
	    !ntfs_bounds(offset, cursor->block_size, cursor->allocation->size)) {
		return NTFS_CORRUPT;
	}
	bit = offset / cursor->block_size;
	if (!ntfs_bounds(bit / NTFS_BITS_PER_BYTE, sizeof(allocated), cursor->bitmap->size)) {
		return NTFS_CORRUPT;
	}
	result = ntfs_stream_exact(
	    cursor->bitmap, bit / NTFS_BITS_PER_BYTE, &allocated, sizeof(allocated));
	if (result != NTFS_OK) {
		return result;
	}
	if ((allocated & (1u << (bit % NTFS_BITS_PER_BYTE))) == 0) {
		return NTFS_CORRUPT;
	}
	result = ntfs_index_visit(volume, &cursor->visited, vcn, cursor->charge, cursor->context);
	if (result != NTFS_OK) {
		return result;
	}
	frame = &cursor->frames[cursor->depth];
	ntfs_zero(frame, sizeof(*frame));
	frame->allocation = cursor->block_size;
	frame->bytes = ntfs_alloc(volume, frame->allocation);
	if (frame->bytes == NULL) {
		return NTFS_NO_MEMORY;
	}
	frame->owned = true;
	frame->bounds = parent->bounds;
	if (parent->has_previous) {
		frame->bounds.lower = parent->previous;
		frame->bounds.has_lower = true;
	}
	if ((ntfs_u16(entry->flags) & NTFS_INDEX_END) == 0) {
		frame->bounds.upper = entry_key(entry, cursor->by_hash);
		frame->bounds.has_upper = true;
	}
	cursor->depth++;
	result = ntfs_stream_exact(cursor->allocation, offset, frame->bytes, frame->allocation);
	if (result == NTFS_OK) {
		result = ntfs_fixup(frame->bytes, frame->allocation, "INDX");
	}
	if (result != NTFS_OK) {
		return result;
	}
	block = (const void *)frame->bytes;
	if (ntfs_u64(block->vcn) != vcn || ntfs_u16(block->mst.usa_offset) < sizeof(*block) ||
	    ntfs_u16(block->mst.usa_offset) +
		    (size_t)ntfs_u16(block->mst.usa_count) * NTFS_MST_WORD_BYTES >
		offsetof(struct ntfs_disk_index_block, header) +
		    (uint64_t)ntfs_u32(block->header.entries_offset)) {
		return NTFS_CORRUPT;
	}
	return cursor_frame(cursor, frame, offsetof(struct ntfs_disk_index_block, header));
}

static enum ntfs_result
cursor_next(struct secure_cursor *cursor, struct ntfs_disk_security_locator *out)
{
	struct secure_frame *frame;
	const struct ntfs_disk_view_entry *entry;
	uint16_t flags;
	enum ntfs_result result;

	while (cursor->depth != 0) {
		result = ntfs_index_work(cursor->volume, cursor->charge, cursor->context, 1);
		if (result != NTFS_OK) {
			return result;
		}
		frame = &cursor->frames[cursor->depth - 1];
		entry = (const void *)(frame->bytes + frame->position);
		flags = ntfs_u16(entry->flags);
		if ((flags & NTFS_INDEX_CHILD) != 0 && !frame->descended) {
			frame->descended = true;
			result = cursor_descend(cursor, entry);
			if (result != NTFS_OK) {
				return result;
			}
			continue;
		}
		if ((flags & NTFS_INDEX_END) != 0) {
			if (frame->owned) {
				ntfs_free(cursor->volume, frame->bytes, frame->allocation);
			}
			cursor->depth--;
			continue;
		}
		ntfs_copy(out, (const uint8_t *)entry + ntfs_u16(entry->data_offset), sizeof(*out));
		frame->previous = entry_key(entry, cursor->by_hash);
		frame->has_previous = true;
		frame->descended = false;
		frame->position += ntfs_u16(entry->length);
		return NTFS_OK;
	}
	return NTFS_END;
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
    struct ntfs_security *snapshot, enum ntfs_result (*charge)(void *, uint64_t), void *context)
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
	result = ntfs_index_work(v, charge, context, sizeof(primary));
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
	result = ntfs_index_work(v, charge, context, snapshot->size);
	if (result != NTFS_OK) {
		return result;
	}
	if (descriptor_hash(snapshot->bytes, snapshot->size) != ntfs_u32(primary.hash)) {
		return NTFS_CORRUPT;
	}
	result = ntfs_index_work(v, charge, context, snapshot->size);
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
	result = ntfs_index_work(v, charge, context, sizeof(primary));
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
		result = ntfs_index_work(v, charge, context, length);
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
	ntfs_free(v, compare, NTFS_SECURITY_COMPARE_BYTES);
	return result;
}

void
ntfs_security_store_default_limits(struct ntfs_security_store_limits *limits)
{
	if (limits != NULL) {
		limits->max_descriptors = NTFS_SECURITY_STORE_DEFAULT_DESCRIPTORS;
	}
}

static void
store_subject(
    struct ntfs_security_store_report *report, const struct ntfs_disk_security_locator *locator)
{
	report->security_id = ntfs_u32(locator->security_id);
	report->hash = ntfs_u32(locator->hash);
	report->offset = ntfs_u64(locator->offset);
	report->cluster = 0;
}

static enum ntfs_result
find_locator(struct ntfs_volume *volume, const struct ntfs_disk_security_locator *locators,
    uint32_t count, uint32_t id, enum ntfs_result (*charge)(void *, uint64_t), void *context,
    const struct ntfs_disk_security_locator **out)
{
	uint32_t first = 0, end = count, middle, found;
	enum ntfs_result result;

	*out = NULL;
	while (first < end) {
		result = ntfs_index_work(volume, charge, context, 1);
		if (result != NTFS_OK) {
			return result;
		}
		middle = first + (end - first) / NTFS_VECTOR_GROWTH;
		found = ntfs_u32(locators[middle].security_id);
		if (found == id) {
			*out = &locators[middle];
			return NTFS_OK;
		}
		if (found < id) {
			first = middle + 1;
		} else {
			end = middle;
		}
	}
	return NTFS_NOT_FOUND;
}

static void
swap_locators(struct ntfs_disk_security_locator *left, struct ntfs_disk_security_locator *right)
{
	struct ntfs_disk_security_locator temporary = *left;

	*left = *right;
	*right = temporary;
}

static enum ntfs_result
sift_offsets(struct ntfs_volume *volume, struct ntfs_disk_security_locator *locators, uint32_t root,
    uint32_t count, enum ntfs_result (*charge)(void *, uint64_t), void *context)
{
	uint32_t child;
	enum ntfs_result result;

	while (root < count / NTFS_VECTOR_GROWTH) {
		result = ntfs_index_work(volume, charge, context, 1);
		if (result != NTFS_OK) {
			return result;
		}
		child = root * NTFS_VECTOR_GROWTH + 1;
		if (child + 1 < count &&
		    ntfs_u64(locators[child].offset) < ntfs_u64(locators[child + 1].offset)) {
			child++;
		}
		if (ntfs_u64(locators[root].offset) >= ntfs_u64(locators[child].offset)) {
			break;
		}
		swap_locators(&locators[root], &locators[child]);
		root = child;
	}
	return NTFS_OK;
}

static enum ntfs_result
sort_offsets(struct ntfs_volume *volume, struct ntfs_disk_security_locator *locators,
    uint32_t count, enum ntfs_result (*charge)(void *, uint64_t), void *context)
{
	uint32_t index;
	enum ntfs_result result;

	for (index = count / NTFS_VECTOR_GROWTH; index != 0; index--) {
		result = sift_offsets(volume, locators, index - 1, count, charge, context);
		if (result != NTFS_OK) {
			return result;
		}
	}
	for (index = count; index > 1; index--) {
		result = ntfs_index_work(volume, charge, context, 1);
		if (result != NTFS_OK) {
			return result;
		}
		swap_locators(&locators[0], &locators[index - 1]);
		result = sift_offsets(volume, locators, 0, index - 1, charge, context);
		if (result != NTFS_OK) {
			return result;
		}
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_security_store_validate_impl(struct ntfs_volume *volume,
    const struct ntfs_security_store_limits *limits, struct ntfs_security_store_report *report,
    enum ntfs_result (*charge)(void *, uint64_t), void *context,
    enum ntfs_result (*references)(void *, const struct ntfs_disk_security_locator *, uint32_t))
{
	struct ntfs_security_store_limits selected = {NTFS_SECURITY_STORE_DEFAULT_DESCRIPTORS};
	struct ntfs_node *node = NULL;
	struct ntfs_stream *store = NULL;
	struct secure_cursor *cursor = NULL;
	struct ntfs_disk_security_locator *locators = NULL, *replacement;
	const struct ntfs_disk_security_locator *found;
	struct ntfs_disk_security_locator locator;
	struct ntfs_security snapshot;
	struct ntfs_stat stat;
	uint32_t count = 0, capacity = 0, grown, index;
	uint64_t previous_end = 0;
	enum ntfs_result result;

	if (report == NULL) {
		return NTFS_INVALID;
	}
	if (limits != NULL) {
		selected = *limits;
	}
	ntfs_zero(report, sizeof(*report));
	report->result = NTFS_INVALID;
	if (volume == NULL || selected.max_descriptors == 0 ||
	    selected.max_descriptors > NTFS_SECURITY_STORE_MAX_DESCRIPTORS) {
		return NTFS_INVALID;
	}
	result = ntfs_node_by_number(volume, NTFS_SECURE_RECORD, &node);
	if (result == NTFS_OK) {
		report->reference = node->reference;
		result = ntfs_node_metadata(node, &stat);
	}
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
	report->stage = NTFS_SECURITY_STORE_SII;
	result = cursor_open(node, false, store->size, charge, context, &cursor);
	if (result != NTFS_OK) {
		goto finish;
	}
	while ((result = cursor_next(cursor, &locator)) == NTFS_OK) {
		store_subject(report, &locator);
		if (count == selected.max_descriptors) {
			report->descriptor_limit = true;
			result = NTFS_RANGE;
			goto finish;
		}
		if (count == capacity) {
			grown = capacity == 0 ? NTFS_CATALOG_INITIAL_CAPACITY
					      : capacity * NTFS_VECTOR_GROWTH;
			if (grown > selected.max_descriptors) {
				grown = selected.max_descriptors;
			}
			result = ntfs_index_work(
			    volume, charge, context, (uint64_t)count * sizeof(*locators));
			if (result != NTFS_OK) {
				goto finish;
			}
			replacement = ntfs_alloc(volume, (size_t)grown * sizeof(*replacement));
			if (replacement == NULL) {
				result = NTFS_NO_MEMORY;
				goto finish;
			}
			ntfs_copy(replacement, locators, (size_t)count * sizeof(*locators));
			ntfs_free(volume, locators, (size_t)capacity * sizeof(*locators));
			locators = replacement;
			capacity = grown;
		}
		locators[count++] = locator;
		report->sii_entries++;
	}
	if (result != NTFS_END) {
		goto finish;
	}
	report->sii_blocks = cursor->visited.count;
	report->stage = NTFS_SECURITY_STORE_SII_ALLOCATION;
	result = ntfs_index_check_allocation(volume, cursor->allocation, cursor->bitmap,
	    &cursor->visited, cursor->block_size, charge, context, &report->cluster);
	if (result != NTFS_OK) {
		goto finish;
	}
	cursor_close(cursor);
	cursor = NULL;
	report->stage = NTFS_SECURITY_STORE_SDH;
	report->security_id = 0;
	report->hash = 0;
	report->offset = 0;
	result = cursor_open(node, true, store->size, charge, context, &cursor);
	if (result != NTFS_OK) {
		goto finish;
	}
	while ((result = cursor_next(cursor, &locator)) == NTFS_OK) {
		store_subject(report, &locator);
		result = find_locator(volume, locators, count, ntfs_u32(locator.security_id),
		    charge, context, &found);
		if (result == NTFS_NOT_FOUND ||
		    (result == NTFS_OK && !ntfs_equal(found, &locator, sizeof(locator)))) {
			result = NTFS_CORRUPT;
		}
		if (result != NTFS_OK) {
			goto finish;
		}
		report->sdh_entries++;
	}
	if (result != NTFS_END || report->sdh_entries != count) {
		result = result == NTFS_END ? NTFS_CORRUPT : result;
		goto finish;
	}
	report->sdh_blocks = cursor->visited.count;
	report->stage = NTFS_SECURITY_STORE_SDH_ALLOCATION;
	result = ntfs_index_check_allocation(volume, cursor->allocation, cursor->bitmap,
	    &cursor->visited, cursor->block_size, charge, context, &report->cluster);
	if (result != NTFS_OK) {
		goto finish;
	}
	cursor_close(cursor);
	cursor = NULL;
	if (references != NULL) {
		result = references(context, locators, count);
		if (result != NTFS_OK) {
			goto finish;
		}
	}
	report->stage = NTFS_SECURITY_STORE_DESCRIPTORS;
	result = sort_offsets(volume, locators, count, charge, context);
	if (result != NTFS_OK) {
		goto finish;
	}
	for (index = 0; index < count; index++) {
		store_subject(report, &locators[index]);
		result = ntfs_index_work(volume, charge, context, sizeof(locator));
		if (result != NTFS_OK) {
			goto finish;
		}
		if (ntfs_u64(locators[index].offset) < previous_end) {
			result = NTFS_CORRUPT;
			goto finish;
		}
		previous_end = ntfs_u64(locators[index].offset) + ntfs_u32(locators[index].length);
	}
	for (index = 0; index < count; index++) {
		store_subject(report, &locators[index]);
		ntfs_zero(&snapshot, sizeof(snapshot));
		result = read_descriptor(store, &locators[index], &snapshot, charge, context);
		ntfs_free(volume, snapshot.bytes, snapshot.size);
		if (result != NTFS_OK) {
			goto finish;
		}
		report->descriptors++;
		report->descriptor_bytes += snapshot.size;
	}
	report->complete = true;
	report->stage = NTFS_SECURITY_STORE_FINISHED;
	report->security_id = 0;
	report->hash = 0;
	report->offset = 0;
	report->cluster = 0;
	result = NTFS_OK;
finish:
	if (cursor != NULL) {
		if (cursor->by_hash) {
			report->sdh_blocks = cursor->visited.count;
		} else {
			report->sii_blocks = cursor->visited.count;
		}
	}
	cursor_close(cursor);
	ntfs_free(volume, locators, (size_t)capacity * sizeof(*locators));
	ntfs_stream_close(store);
	ntfs_node_close(node);
	report->result = result;
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
	result = read_descriptor(store, &sii, snapshot, NULL, NULL);
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
