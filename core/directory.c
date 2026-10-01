/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"

struct index_frame {
	uint8_t *bytes;
	size_t allocation, position, end;
	const struct ntfs_disk_filename *lower, *upper, *previous;
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

static int
key_compare(struct ntfs_volume *v, const struct ntfs_disk_filename *left,
    const struct ntfs_disk_filename *right)
{
	const uint8_t *a = (const uint8_t *)left + sizeof(*left);
	const uint8_t *b = (const uint8_t *)right + sizeof(*right);
	size_t i, count = left->length < right->length ? left->length : right->length;
	uint16_t x, y;
	int sensitive = 0;

	/* Filename collation uses $UpCase first, then the original UTF-16 units
	 * to order names that differ only in case. Keep both comparisons. */
	for (i = 0; i < count; i++) {
		x = ntfs_u16(a + i * NTFS_UTF16_UNIT_BYTES);
		y = ntfs_u16(b + i * NTFS_UTF16_UNIT_BYTES);
		if (sensitive == 0 && x != y) {
			sensitive = x < y ? -1 : 1;
		}
		x = ntfs_u16(v->upcase + (size_t)x * NTFS_UTF16_UNIT_BYTES);
		y = ntfs_u16(v->upcase + (size_t)y * NTFS_UTF16_UNIT_BYTES);
		if (x != y) {
			return x < y ? -1 : 1;
		}
	}
	return left->length == right->length ? sensitive : left->length < right->length ? -1 : 1;
}

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
	if ((flags & ~(NTFS_INDEX_CHILD | NTFS_INDEX_END)) != 0 ||
	    length % NTFS_WIRE_ALIGNMENT != 0 || length < sizeof(*entry) + trailer ||
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
		if (key->length == 0 || key->name_namespace > NTFS_NAMESPACE_WIN32_DOS ||
		    sizeof(*key) + (size_t)key->length * NTFS_UTF16_UNIT_BYTES != key_length ||
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
	const struct ntfs_disk_filename *key, *previous = NULL;
	struct index_frame scan;
	size_t entries, used, allocated;
	enum ntfs_result result;
	bool terminal = false;

	if (!ntfs_bounds(header_offset, sizeof(*header), f->allocation)) {
		return NTFS_CORRUPT;
	}
	header = (const void *)(f->bytes + header_offset);
	entries = ntfs_u32(header->entries_offset);
	used = ntfs_u32(header->used);
	allocated = ntfs_u32(header->allocated);
	if (entries < sizeof(*header) || entries % NTFS_WIRE_ALIGNMENT != 0 || used < entries ||
	    used > allocated || allocated > f->allocation - header_offset ||
	    (header->flags & ~NTFS_INDEX_LARGE) != 0) {
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
		if ((previous != NULL && key_compare(d->volume, previous, key) >= 0) ||
		    (f->lower != NULL && key_compare(d->volume, f->lower, key) >= 0) ||
		    (f->upper != NULL && key_compare(d->volume, key, f->upper) >= 0)) {
			return NTFS_CORRUPT;
		}
		previous = key;
		scan.position += ntfs_u16(entry->length);
	}
	return terminal ? NTFS_OK : NTFS_CORRUPT;
}

static size_t
hash_vcn(uint64_t vcn, uint32_t capacity)
{
	return (size_t)((vcn * NTFS_VCN_HASH_MULTIPLIER) >> NTFS_VCN_HASH_SHIFT) & (capacity - 1u);
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
	if (d->visited_count * NTFS_VISITED_LOAD_DENOMINATOR >= d->visited_capacity) {
		capacity = d->visited_capacity == 0 ? NTFS_VISITED_INITIAL_CAPACITY
						    : d->visited_capacity * NTFS_VECTOR_GROWTH;
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
	const struct index_frame *parent;
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
	result =
	    ntfs_stream_exact(d->bitmap, bit / NTFS_BITS_PER_BYTE, &allocated, sizeof(allocated));
	if (result != NTFS_OK) {
		return result;
	}
	if ((allocated & (1u << (bit % NTFS_BITS_PER_BYTE))) == 0) {
		return NTFS_CORRUPT;
	}
	result = visit(d, vcn);
	if (result != NTFS_OK) {
		return result;
	}
	f = &d->stack[d->depth];
	ntfs_zero(f, sizeof(*f));
	parent = &d->stack[d->depth - 1];
	/* Bounds point into live ancestors, which outlive every child frame. */
	f->lower = parent->previous != NULL ? parent->previous : parent->lower;
	f->upper = (ntfs_u16(entry->flags) & NTFS_INDEX_END) != 0
	    ? parent->upper
	    : (const void *)((const uint8_t *)entry + sizeof(*entry));
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
	    ntfs_u16(block->mst.usa_offset) +
		    (size_t)ntfs_u16(block->mst.usa_count) * NTFS_MST_WORD_BYTES >
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
	if (node->volume->children == UINT32_MAX) {
		return NTFS_RANGE;
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
	result = ntfs_attribute_open(node, NTFS_ATTR_INDEX_ROOT, index_name,
	    sizeof(index_name) / sizeof(index_name[0]), &root);
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
	result = ntfs_attribute_open(node, NTFS_ATTR_INDEX_ALLOCATION, index_name,
	    sizeof(index_name) / sizeof(index_name[0]), &d->allocation);
	if (result == NTFS_NOT_FOUND) {
		result = NTFS_OK;
	} else if (result == NTFS_OK) {
		result = ntfs_attribute_open(node, NTFS_ATTR_BITMAP, index_name,
		    sizeof(index_name) / sizeof(index_name[0]), &d->bitmap);
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

static enum ntfs_result
next_entry(struct ntfs_directory *d, const struct ntfs_disk_index_entry **out)
{
	struct index_frame *f;
	const struct ntfs_disk_index_entry *entry;
	const struct ntfs_disk_filename *key;
	enum ntfs_result result;
	uint16_t flags;

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
		f->previous = key;
		f->position += ntfs_u16(entry->length);
		f->descended = false;
		*out = entry;
		return NTFS_OK;
	}
	return NTFS_END;
}

static void
copy_entry(const struct ntfs_disk_index_entry *entry, struct ntfs_dirent *out)
{
	const struct ntfs_disk_filename *key =
	    (const void *)((const uint8_t *)entry + sizeof(*entry));
	size_t i;

	ntfs_zero(out, sizeof(*out));
	out->reference = ntfs_u64(entry->reference);
	out->parent_reference = ntfs_u64(key->parent);
	out->size = ntfs_u64(key->size);
	out->file_attributes = ntfs_u32(key->attributes);
	out->name_namespace = key->name_namespace;
	out->name_length = key->length;
	for (i = 0; i < key->length; i++) {
		out->name[i] =
		    ntfs_u16((const uint8_t *)key + sizeof(*key) + i * NTFS_UTF16_UNIT_BYTES);
	}
}

enum ntfs_result
ntfs_directory_next(struct ntfs_directory *d, struct ntfs_dirent *out)
{
	const struct ntfs_disk_index_entry *entry;
	enum ntfs_result result;

	if (d == NULL || out == NULL) {
		return NTFS_INVALID;
	}
	result = next_entry(d, &entry);
	if (result == NTFS_OK) {
		copy_entry(entry, out);
	}
	return result;
}

static enum ntfs_result
seek_name(struct ntfs_directory *d, const uint16_t *name, size_t length)
{
	struct index_frame *f;
	const struct ntfs_disk_index_entry *entry;
	const struct ntfs_disk_filename *key;
	enum ntfs_result result;
	int comparison;

	for (;;) {
		f = &d->stack[d->depth - 1];
		result = entry_at(f, &entry);
		if (result != NTFS_OK) {
			return result;
		}
		comparison = -1;
		key = NULL;
		if ((ntfs_u16(entry->flags) & NTFS_INDEX_END) == 0) {
			key = (const void *)((const uint8_t *)entry + sizeof(*entry));
			comparison = ntfs_name_compare(d->volume, name, length,
			    (const uint8_t *)key + sizeof(*key), key->length);
		}
		if (comparison > 0) {
			f->previous = key;
			f->position += ntfs_u16(entry->length);
			continue;
		}
		if ((ntfs_u16(entry->flags) & NTFS_INDEX_CHILD) == 0) {
			return NTFS_OK;
		}
		f->descended = true;
		result = descend(d, entry);
		if (result != NTFS_OK) {
			return result;
		}
	}
}

enum ntfs_result
ntfs_lookup_entry(struct ntfs_node *parent, const uint16_t *name, size_t length,
    struct ntfs_node **out, struct ntfs_dirent *found)
{
	struct ntfs_directory *d = NULL;
	const struct ntfs_disk_index_entry *entry;
	const struct ntfs_disk_filename *key;
	uint64_t reference = 0;
	enum ntfs_result result;
	size_t i;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	*out = NULL;
	if (found != NULL) {
		ntfs_zero(found, sizeof(*found));
	}
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
	result = seek_name(d, name, length);
	if (result == NTFS_OK) {
		result = next_entry(d, &entry);
		if (result == NTFS_END) {
			result = NTFS_NOT_FOUND;
		} else if (result == NTFS_OK) {
			key = (const void *)((const uint8_t *)entry + sizeof(*entry));
			if (ntfs_name_compare(parent->volume, name, length,
				(const uint8_t *)key + sizeof(*key), key->length) != 0) {
				result = NTFS_NOT_FOUND;
			} else {
				reference = ntfs_u64(entry->reference);
				if (found != NULL) {
					copy_entry(entry, found);
				}
			}
		}
	}
	if (result == NTFS_OK) {
		/* Case-insensitive lookup cannot choose between distinct POSIX
		 * names that fold alike. The lower-bound cursor also catches a
		 * collision split across a separator and its neighboring child. */
		result = next_entry(d, &entry);
		if (result == NTFS_END) {
			result = NTFS_OK;
		} else if (result == NTFS_OK) {
			key = (const void *)((const uint8_t *)entry + sizeof(*entry));
			if (ntfs_name_compare(parent->volume, name, length,
				(const uint8_t *)key + sizeof(*key), key->length) == 0) {
				result = NTFS_UNSUPPORTED;
			}
		}
	}
	ntfs_directory_close(d);
	if (result == NTFS_OK) {
		result = ntfs_node_open(parent->volume, reference, out);
	}
	if (result != NTFS_OK && found != NULL) {
		ntfs_zero(found, sizeof(*found));
	}
	return result;
}

enum ntfs_result
ntfs_lookup(struct ntfs_node *parent, const uint16_t *name, size_t length, struct ntfs_node **out)
{
	return ntfs_lookup_entry(parent, name, length, out, NULL);
}
