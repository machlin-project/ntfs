/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "secure_internal.h"

static const uint16_t sii_name[] = {'$', 'S', 'I', 'I'};
static const uint16_t sdh_name[] = {'$', 'S', 'D', 'H'};

static int ntfs_secure_compare_key(
    struct ntfs_secure_index_key a, struct ntfs_secure_index_key b, bool by_hash);
static bool ntfs_secure_valid_locator(
    const struct ntfs_disk_security_locator *locator, uint64_t store_size);
static enum ntfs_result ntfs_secure_choose_entry(const uint8_t *bytes, size_t size,
    size_t header_offset, bool by_hash, struct ntfs_secure_index_key target,
    const struct ntfs_secure_index_bounds *bounds, uint64_t store_size,
    struct ntfs_secure_index_choice *choice);
static enum ntfs_result ntfs_secure_root_geometry(
    struct ntfs_stream *root, bool by_hash, uint32_t *block_size);
static enum ntfs_result ntfs_secure_cursor_frame(struct ntfs_secure_index_cursor *cursor,
    struct ntfs_secure_index_frame *frame, size_t header_offset);
static struct ntfs_secure_index_key ntfs_secure_entry_key(
    const struct ntfs_disk_view_entry *entry, bool by_hash);
static enum ntfs_result ntfs_secure_cursor_descend(
    struct ntfs_secure_index_cursor *cursor, const struct ntfs_disk_view_entry *entry);

static int
ntfs_secure_compare_key(
    struct ntfs_secure_index_key left_key, struct ntfs_secure_index_key right_key, bool by_hash)
{
	if (by_hash && left_key.hash != right_key.hash) {
		return left_key.hash < right_key.hash ? -1 : 1;
	}
	return left_key.id == right_key.id ? 0 : left_key.id < right_key.id ? -1 : 1;
}

static bool
ntfs_secure_valid_locator(const struct ntfs_disk_security_locator *locator, uint64_t store_size)
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
ntfs_secure_choose_entry(const uint8_t *bytes, size_t size, size_t header_offset, bool by_hash,
    struct ntfs_secure_index_key target, const struct ntfs_secure_index_bounds *bounds,
    uint64_t store_size, struct ntfs_secure_index_choice *choice)
{
	const struct ntfs_disk_index_header *header;
	const struct ntfs_disk_view_entry *entry;
	const struct ntfs_disk_security_locator *locator;
	const struct ntfs_disk_security_hash_key *hash_key;
	struct ntfs_secure_index_key key = {0}, previous = {0};
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
			if (!ntfs_secure_valid_locator(locator, store_size) ||
			    ntfs_u32(locator->security_id) != key.id ||
			    (by_hash && ntfs_u32(locator->hash) != key.hash) ||
			    (has_previous &&
				ntfs_secure_compare_key(previous, key, by_hash) >= 0) ||
			    (bounds->has_lower &&
				ntfs_secure_compare_key(bounds->lower, key, by_hash) >= 0) ||
			    (bounds->has_upper &&
				ntfs_secure_compare_key(key, bounds->upper, by_hash) >= 0)) {
				return NTFS_CORRUPT;
			}
			order = ntfs_secure_compare_key(key, target, by_hash);
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
ntfs_secure_root_geometry(struct ntfs_stream *root, bool by_hash, uint32_t *block_size)
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

enum ntfs_result
ntfs_secure_index_seek(struct ntfs_node *node, bool by_hash, struct ntfs_secure_index_key target,
    uint64_t store_size, struct ntfs_disk_security_locator *out)
{
	struct ntfs_volume *volume = node->volume;
	struct ntfs_stream *root = NULL, *allocation = NULL, *bitmap = NULL;
	const struct ntfs_disk_index_block *block;
	const uint16_t *name = by_hash ? sdh_name : sii_name;
	const uint8_t *bytes;
	uint8_t *buffer = NULL, allocated;
	struct ntfs_secure_index_bounds bounds = {0};
	struct ntfs_secure_index_choice choice;
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
	result = ntfs_secure_root_geometry(root, by_hash, &block_size);
	if (result != NTFS_OK) {
		goto finish;
	}
	unit = volume->info.cluster_size <= block_size ? volume->info.cluster_size
						       : volume->info.sector_size;
	bytes = root->value;
	size = (size_t)root->size;
	header_offset = sizeof(struct ntfs_disk_index_root);
	for (;;) {
		result = ntfs_work(volume, size);
		if (result != NTFS_OK) {
			goto finish;
		}
		result = ntfs_secure_choose_entry(
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
		    depth == volume->limits.max_directory_nodes) {
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
			buffer = ntfs_alloc(volume, block_size);
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
	ntfs_free(volume, buffer, block_size);
	ntfs_stream_close(bitmap);
	ntfs_stream_close(allocation);
	ntfs_stream_close(root);
	return result;
}

static enum ntfs_result
ntfs_secure_cursor_frame(struct ntfs_secure_index_cursor *cursor,
    struct ntfs_secure_index_frame *frame, size_t header_offset)
{
	const struct ntfs_disk_index_header *header;
	struct ntfs_secure_index_choice choice;
	struct ntfs_secure_index_key target = {0};
	enum ntfs_result result;

	result =
	    ntfs_index_work(cursor->volume, cursor->charge, cursor->context, frame->allocation);
	if (result == NTFS_OK) {
		result = ntfs_secure_choose_entry(frame->bytes, frame->allocation, header_offset,
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

void
ntfs_secure_cursor_close(struct ntfs_secure_index_cursor *cursor)
{
	struct ntfs_volume *volume;
	struct ntfs_secure_index_frame *frame;

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

enum ntfs_result
ntfs_secure_cursor_open(struct ntfs_node *node, bool by_hash, uint64_t store_size,
    enum ntfs_result (*charge)(void *, uint64_t), void *context,
    struct ntfs_secure_index_cursor **out)
{
	struct ntfs_secure_index_cursor *cursor;
	const uint16_t *name = by_hash ? sdh_name : sii_name;
	const struct ntfs_disk_index_root *header;
	const struct ntfs_disk_index_header *node_header;
	struct ntfs_secure_index_frame *frame;
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
		result = ntfs_secure_root_geometry(cursor->root, by_hash, &cursor->block_size);
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
	result = ntfs_secure_cursor_frame(cursor, frame, sizeof(*header));
finish:
	if (result != NTFS_OK) {
		ntfs_secure_cursor_close(cursor);
		return result;
	}
	*out = cursor;
	return NTFS_OK;
}

static struct ntfs_secure_index_key
ntfs_secure_entry_key(const struct ntfs_disk_view_entry *entry, bool by_hash)
{
	const struct ntfs_disk_security_hash_key *key =
	    (const void *)((const uint8_t *)entry + sizeof(*entry));
	struct ntfs_secure_index_key value = {0};

	value.id = by_hash ? ntfs_u32(key->security_id) : ntfs_u32(key);
	value.hash = by_hash ? ntfs_u32(key->hash) : 0;
	return value;
}

static enum ntfs_result
ntfs_secure_cursor_descend(
    struct ntfs_secure_index_cursor *cursor, const struct ntfs_disk_view_entry *entry)
{
	struct ntfs_volume *volume = cursor->volume;
	const struct ntfs_secure_index_frame *parent = &cursor->frames[cursor->depth - 1];
	struct ntfs_secure_index_frame *frame;
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
		frame->bounds.upper = ntfs_secure_entry_key(entry, cursor->by_hash);
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
	return ntfs_secure_cursor_frame(
	    cursor, frame, offsetof(struct ntfs_disk_index_block, header));
}

enum ntfs_result
ntfs_secure_cursor_next(
    struct ntfs_secure_index_cursor *cursor, struct ntfs_disk_security_locator *out)
{
	struct ntfs_secure_index_frame *frame;
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
			result = ntfs_secure_cursor_descend(cursor, entry);
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
		frame->previous = ntfs_secure_entry_key(entry, cursor->by_hash);
		frame->has_previous = true;
		frame->descended = false;
		frame->position += ntfs_u16(entry->length);
		return NTFS_OK;
	}
	return NTFS_END;
}
