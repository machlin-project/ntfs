/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"

struct index_frame {
	uint8_t *bytes;
	size_t allocation, position, end;
	bool descended;
};

struct ntfs_directory {
	struct ntfs_volume *volume;
	struct ntfs_stream *allocation, *bitmap;
	uint64_t reference;
	struct index_frame stack[NTFS_DIRECTORY_DEPTH];
	uint32_t depth, visited_count, visited_capacity;
	uint64_t *visited;
	enum ntfs_result failure;
};

static const uint16_t index_name[] = {'$', 'I', '3', '0'};

static enum ntfs_result
entry_at(const struct index_frame *frame, const struct ntfs_disk_index_entry **out)
{
	const struct ntfs_disk_index_entry *entry;
	const struct ntfs_disk_filename *key;
	size_t length, key_length, trailer;
	uint16_t flags;

	if (!ntfs_bounds(frame->position, sizeof(*entry), frame->end)) {
		return NTFS_CORRUPT;
	}
	entry = (const void *)(frame->bytes + frame->position);
	length = ntfs_u16(entry->length);
	key_length = ntfs_u16(entry->key_length);
	flags = ntfs_u16(entry->flags);
	trailer = (flags & NTFS_INDEX_CHILD) != 0 ? sizeof(uint64_t) : 0;
	if ((flags & ~(NTFS_INDEX_CHILD | NTFS_INDEX_END)) != 0 || length % 8 != 0 ||
	    length < sizeof(*entry) + trailer ||
	    !ntfs_bounds(frame->position, length, frame->end) ||
	    key_length > length - sizeof(*entry) - trailer) {
		return NTFS_CORRUPT;
	}
	if ((flags & NTFS_INDEX_END) != 0) {
		if (key_length != 0 || frame->position + length != frame->end) {
			return NTFS_CORRUPT;
		}
	} else {
		if (key_length < sizeof(*key)) {
			return NTFS_CORRUPT;
		}
		key = (const void *)((const uint8_t *)entry + sizeof(*entry));
		if (key->length == 0 || key->name_namespace > 3 ||
		    sizeof(*key) + (size_t)key->length * 2 != key_length ||
		    ntfs_u64(entry->reference) >> NTFS_REFERENCE_SEQUENCE_SHIFT == 0) {
			return NTFS_CORRUPT;
		}
	}
	*out = entry;
	return NTFS_OK;
}

static enum ntfs_result
validate_frame(struct ntfs_directory *d, struct index_frame *f, size_t header_offset)
{
	const struct ntfs_disk_index_header *header;
	const struct ntfs_disk_index_entry *entry;
	const struct ntfs_disk_filename *key;
	struct index_frame scan;
	uint16_t previous[NTFS_NAME_MAX];
	size_t previous_length = 0, entries, used, allocated, i;
	enum ntfs_result result;
	bool terminal = false;

	if (!ntfs_bounds(header_offset, sizeof(*header), f->allocation)) {
		return NTFS_CORRUPT;
	}
	header = (const void *)(f->bytes + header_offset);
	entries = ntfs_u32(header->entries_offset);
	used = ntfs_u32(header->used);
	allocated = ntfs_u32(header->allocated);
	if (entries < sizeof(*header) || entries % 8 != 0 || used < entries || used > allocated ||
	    allocated > f->allocation - header_offset || (header->flags & ~NTFS_INDEX_LARGE) != 0) {
		return NTFS_CORRUPT;
	}
	f->position = header_offset + entries;
	f->end = header_offset + used;
	scan = *f;
	while (scan.position < scan.end) {
		result = entry_at(&scan, &entry);
		if (result != NTFS_OK) {
			return result;
		}
		if (((ntfs_u16(entry->flags) & NTFS_INDEX_CHILD) != 0) !=
		    ((header->flags & NTFS_INDEX_LARGE) != 0)) {
			return NTFS_CORRUPT;
		}
		if ((ntfs_u16(entry->flags) & NTFS_INDEX_END) != 0) {
			terminal = true;
			break;
		}
		key = (const void *)((const uint8_t *)entry + sizeof(*entry));
		if (ntfs_u64(key->parent) != d->reference) {
			return NTFS_CORRUPT;
		}
		if (previous_length != 0 &&
		    ntfs_name_compare(d->volume, previous, previous_length,
			(const uint8_t *)key + sizeof(*key), key->length) > 0) {
			return NTFS_CORRUPT;
		}
		previous_length = key->length;
		for (i = 0; i < previous_length; i++) {
			previous[i] = ntfs_u16((const uint8_t *)key + sizeof(*key) + i * 2);
		}
		scan.position += ntfs_u16(entry->length);
	}
	return terminal ? NTFS_OK : NTFS_CORRUPT;
}

static size_t
hash_vcn(uint64_t vcn, uint32_t capacity)
{
	return (size_t)((vcn * UINT64_C(11400714819323198485)) >> 32) & (capacity - 1u);
}

static enum ntfs_result
visit(struct ntfs_directory *d, uint64_t vcn)
{
	uint64_t *table;
	uint32_t capacity, i;
	size_t position;

	if (vcn == UINT64_MAX) {
		return NTFS_CORRUPT;
	}
	if (d->visited_count == d->volume->limits.max_directory_nodes) {
		return NTFS_RANGE;
	}
	if (d->visited_count * 2 >= d->visited_capacity) {
		capacity = d->visited_capacity == 0 ? 64 : d->visited_capacity * 2;
		table = ntfs_alloc(d->volume, (size_t)capacity * sizeof(*table));
		if (table == NULL) {
			return NTFS_NO_MEMORY;
		}
		for (i = 0; i < d->visited_capacity; i++) {
			if (d->visited[i] == 0) {
				continue;
			}
			position = hash_vcn(d->visited[i] - 1, capacity);
			while (table[position] != 0) {
				position = (position + 1) & (capacity - 1u);
			}
			table[position] = d->visited[i];
		}
		ntfs_free(d->volume, d->visited, (size_t)d->visited_capacity * sizeof(*table));
		d->visited = table;
		d->visited_capacity = capacity;
	}
	position = hash_vcn(vcn, d->visited_capacity);
	while (d->visited[position] != 0) {
		if (d->visited[position] == vcn + 1) {
			return NTFS_CORRUPT;
		}
		position = (position + 1) & (d->visited_capacity - 1u);
	}
	d->visited[position] = vcn + 1;
	d->visited_count++;
	return NTFS_OK;
}

static enum ntfs_result
descend(struct ntfs_directory *d, const struct ntfs_disk_index_entry *entry)
{
	struct ntfs_volume *v = d->volume;
	struct index_frame *f;
	const struct ntfs_disk_index_block *block;
	uint64_t vcn, offset, bit;
	uint32_t unit;
	uint8_t allocated;
	enum ntfs_result result;

	if (d->depth == NTFS_DIRECTORY_DEPTH) {
		return NTFS_RANGE;
	}
	if (d->allocation == NULL || d->bitmap == NULL) {
		return NTFS_CORRUPT;
	}
	vcn = ntfs_u64((const uint8_t *)entry + ntfs_u16(entry->length) - sizeof(uint64_t));
	unit =
	    v->info.cluster_size <= v->info.index_size ? v->info.cluster_size : v->info.sector_size;
	if (vcn > (uint64_t)INT64_MAX / unit) {
		return NTFS_CORRUPT;
	}
	offset = vcn * unit;
	if (offset % v->info.index_size != 0 ||
	    !ntfs_bounds(offset, v->info.index_size, d->allocation->size)) {
		return NTFS_CORRUPT;
	}
	bit = offset / v->info.index_size;
	result = ntfs_stream_exact(d->bitmap, bit / 8, &allocated, 1);
	if (result != NTFS_OK) {
		return result;
	}
	if ((allocated & (1u << (bit % 8))) == 0) {
		return NTFS_CORRUPT;
	}
	result = visit(d, vcn);
	if (result != NTFS_OK) {
		return result;
	}
	f = &d->stack[d->depth];
	ntfs_zero(f, sizeof(*f));
	f->allocation = v->info.index_size;
	f->bytes = ntfs_alloc(v, f->allocation);
	if (f->bytes == NULL) {
		return NTFS_NO_MEMORY;
	}
	d->depth++;
	result = ntfs_stream_exact(d->allocation, offset, f->bytes, f->allocation);
	if (result == NTFS_OK) {
		result = ntfs_fixup(f->bytes, f->allocation, "INDX");
	}
	if (result != NTFS_OK) {
		return result;
	}
	block = (const void *)f->bytes;
	if (ntfs_u64(block->vcn) != vcn || ntfs_u16(block->mst.usa_offset) < sizeof(*block) ||
	    ntfs_u16(block->mst.usa_offset) + (size_t)ntfs_u16(block->mst.usa_count) * 2 >
		offsetof(struct ntfs_disk_index_block, header) +
		    ntfs_u32(block->header.entries_offset)) {
		return NTFS_CORRUPT;
	}
	return validate_frame(d, f, offsetof(struct ntfs_disk_index_block, header));
}

enum ntfs_result
ntfs_directory_open(struct ntfs_node *node, struct ntfs_directory **out)
{
	struct ntfs_directory *d;
	struct ntfs_stream *root = NULL;
	const struct ntfs_disk_index_root *header;
	const struct ntfs_disk_record *record;
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	*out = NULL;
	if (node == NULL) {
		return NTFS_INVALID;
	}
	record = (const void *)node->record;
	if ((ntfs_u16(record->flags) & NTFS_RECORD_DIRECTORY) == 0) {
		return NTFS_NOT_DIRECTORY;
	}
	d = ntfs_alloc(node->volume, sizeof(*d));
	if (d == NULL) {
		return NTFS_NO_MEMORY;
	}
	d->volume = node->volume;
	d->reference = node->reference;
	d->volume->children++;
	result = ntfs_attribute_open(node, NTFS_ATTR_INDEX_ROOT, index_name, 4, &root);
	if (result != NTFS_OK) {
		goto finish;
	}
	if (!root->resident ||
	    root->size < sizeof(*header) + sizeof(struct ntfs_disk_index_header)) {
		result = NTFS_CORRUPT;
		goto finish;
	}
	header = (const void *)root->value;
	if (ntfs_u32(header->type) != NTFS_ATTR_FILENAME ||
	    ntfs_u32(header->collation) != NTFS_COLLATION_FILENAME ||
	    ntfs_u32(header->block_size) != d->volume->info.index_size) {
		result = NTFS_UNSUPPORTED;
		goto finish;
	}
	d->stack[0].bytes = root->value;
	d->stack[0].allocation = root->value_allocation;
	root->value = NULL;
	root->value_allocation = 0;
	d->depth = 1;
	result = validate_frame(d, &d->stack[0], sizeof(*header));
	if (result != NTFS_OK) {
		goto finish;
	}
	result =
	    ntfs_attribute_open(node, NTFS_ATTR_INDEX_ALLOCATION, index_name, 4, &d->allocation);
	if (result == NTFS_NOT_FOUND) {
		result = NTFS_OK;
	} else if (result == NTFS_OK) {
		result = ntfs_attribute_open(node, NTFS_ATTR_BITMAP, index_name, 4, &d->bitmap);
		if (result == NTFS_OK &&
		    (d->allocation->resident || d->allocation->flags != 0 ||
			d->allocation->initialized != d->allocation->size ||
			d->bitmap->flags != 0 || d->bitmap->initialized != d->bitmap->size)) {
			result = NTFS_CORRUPT;
		}
	}
finish:
	ntfs_stream_close(root);
	if (result != NTFS_OK) {
		ntfs_directory_close(d);
		return result;
	}
	*out = d;
	return NTFS_OK;
}

void
ntfs_directory_close(struct ntfs_directory *d)
{
	struct ntfs_volume *v;
	uint32_t i;

	if (d == NULL) {
		return;
	}
	v = d->volume;
	for (i = 0; i < d->depth; i++) {
		ntfs_free(v, d->stack[i].bytes, d->stack[i].allocation);
	}
	ntfs_free(v, d->visited, (size_t)d->visited_capacity * sizeof(*d->visited));
	ntfs_stream_close(d->allocation);
	ntfs_stream_close(d->bitmap);
	v->children--;
	ntfs_free(v, d, sizeof(*d));
}

enum ntfs_result
ntfs_directory_next(struct ntfs_directory *d, struct ntfs_dirent *out)
{
	struct index_frame *f;
	const struct ntfs_disk_index_entry *entry;
	const struct ntfs_disk_filename *key;
	enum ntfs_result result;
	uint16_t flags;
	size_t i;

	if (d == NULL || out == NULL) {
		return NTFS_INVALID;
	}
	if (d->failure != NTFS_OK) {
		return d->failure;
	}
	while (d->depth != 0) {
		f = &d->stack[d->depth - 1];
		result = entry_at(f, &entry);
		if (result != NTFS_OK) {
			d->failure = result;
			return result;
		}
		flags = ntfs_u16(entry->flags);
		if ((flags & NTFS_INDEX_CHILD) != 0 && !f->descended) {
			f->descended = true;
			result = descend(d, entry);
			if (result != NTFS_OK) {
				d->failure = result;
				return result;
			}
			continue;
		}
		if ((flags & NTFS_INDEX_END) != 0) {
			ntfs_free(d->volume, f->bytes, f->allocation);
			d->depth--;
			continue;
		}
		key = (const void *)((const uint8_t *)entry + sizeof(*entry));
		ntfs_zero(out, sizeof(*out));
		out->reference = ntfs_u64(entry->reference);
		out->parent_reference = ntfs_u64(key->parent);
		out->size = ntfs_u64(key->size);
		out->file_attributes = ntfs_u32(key->attributes);
		out->name_namespace = key->name_namespace;
		out->name_length = key->length;
		for (i = 0; i < key->length; i++) {
			out->name[i] = ntfs_u16((const uint8_t *)key + sizeof(*key) + i * 2);
		}
		f->position += ntfs_u16(entry->length);
		f->descended = false;
		return NTFS_OK;
	}
	return NTFS_END;
}

enum ntfs_result
ntfs_lookup_entry(struct ntfs_node *parent, const uint16_t *name, size_t length,
    struct ntfs_node **out, struct ntfs_dirent *found)
{
	struct ntfs_directory *d = NULL;
	struct index_frame *f;
	const struct ntfs_disk_index_entry *entry;
	const struct ntfs_disk_filename *key;
	uint64_t reference = 0;
	enum ntfs_result result;
	uint16_t flags;
	size_t i;
	int comparison;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	*out = NULL;
	if (parent == NULL || name == NULL || length == 0 || length > NTFS_NAME_MAX) {
		return NTFS_INVALID;
	}
	for (i = 0; i < length; i++) {
		if (name[i] == 0 || name[i] == '/') {
			return NTFS_INVALID;
		}
	}
	result = ntfs_directory_open(parent, &d);
	if (result != NTFS_OK) {
		return result;
	}
	for (;;) {
		f = &d->stack[d->depth - 1];
		result = entry_at(f, &entry);
		if (result != NTFS_OK) {
			break;
		}
		flags = ntfs_u16(entry->flags);
		comparison = -1;
		if ((flags & NTFS_INDEX_END) == 0) {
			key = (const void *)((const uint8_t *)entry + sizeof(*entry));
			comparison = ntfs_name_compare(parent->volume, name, length,
			    (const uint8_t *)key + sizeof(*key), key->length);
			if (comparison == 0) {
				reference = ntfs_u64(entry->reference);
				if (found != NULL) {
					ntfs_zero(found, sizeof(*found));
					found->reference = reference;
					found->parent_reference = ntfs_u64(key->parent);
					found->size = ntfs_u64(key->size);
					found->file_attributes = ntfs_u32(key->attributes);
					found->name_namespace = key->name_namespace;
					found->name_length = key->length;
					for (i = 0; i < key->length; i++) {
						found->name[i] = ntfs_u16(
						    (const uint8_t *)key + sizeof(*key) + i * 2);
					}
				}
				break;
			}
		}
		if (comparison < 0) {
			if ((flags & NTFS_INDEX_CHILD) == 0) {
				result = NTFS_NOT_FOUND;
				break;
			}
			result = descend(d, entry);
			if (result != NTFS_OK) {
				break;
			}
		} else {
			f->position += ntfs_u16(entry->length);
		}
	}
	ntfs_directory_close(d);
	if (result == NTFS_OK) {
		result = ntfs_node_open(parent->volume, reference, out);
	}
	return result;
}

enum ntfs_result
ntfs_lookup(struct ntfs_node *parent, const uint16_t *name, size_t length, struct ntfs_node **out)
{
	return ntfs_lookup_entry(parent, name, length, out, NULL);
}
