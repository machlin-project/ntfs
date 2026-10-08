/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_directory_internal.h"

static uint16_t *
index_slot(const struct ntfs_mutation_index_tree *tree, uint64_t vcn)
{
	uint16_t *slots = ntfs_mutation_vector_slots(tree->nodes, tree->capacity);
	size_t position = ntfs_mutation_hash(vcn, tree->capacity);
	size_t mask = tree->capacity * NTFS_MUTATION_LOOKUP_SLOTS_PER_ENTRY - 1;

	while (slots[position] != 0 && tree->nodes[slots[position] - 1]->vcn != vcn) {
		position = (position + 1) & mask;
	}
	return &slots[position];
}

static struct ntfs_mutation_index_node *
index_node(const struct ntfs_mutation_index_tree *tree, uint64_t vcn)
{
	uint16_t slot;

	if (tree->capacity == 0) {
		return NULL;
	}
	slot = *index_slot(tree, vcn);
	return slot == 0 ? NULL : tree->nodes[slot - 1];
}

static enum ntfs_result
index_acquire(struct ntfs_write_mutation_plan *plan, struct ntfs_mutation_index_tree *tree,
    uint64_t vcn, struct ntfs_mutation_index_node **out)
{
	struct ntfs_mutation_index_node *node, **nodes;
	size_t capacity, index;

	*out = NULL;
	if (vcn == NTFS_MUTATION_INDEX_ROOT_VCN) {
		node = ntfs_mutation_allocate(plan, sizeof(*node));
		if (node == NULL) {
			return NTFS_NO_MEMORY;
		}
		tree->root = node;
	} else {
		node = index_node(tree, vcn);
		if (node != NULL) {
			if (node->live) {
				return NTFS_CORRUPT;
			}
		} else {
			if (tree->count == NTFS_MUTATION_MAX_REGIONS) {
				return NTFS_RANGE;
			}
			if (tree->count == tree->capacity) {
				capacity = tree->capacity == 0
				    ? NTFS_MUTATION_INITIAL_REGIONS
				    : tree->capacity * NTFS_VECTOR_GROWTH;
				nodes = ntfs_mutation_allocate(
				    plan, ntfs_mutation_vector_bytes(capacity));
				if (nodes == NULL) {
					return NTFS_NO_MEMORY;
				}
				ntfs_copy(nodes, tree->nodes, tree->count * sizeof(*nodes));
				ntfs_mutation_release(
				    plan, tree->nodes, ntfs_mutation_vector_bytes(tree->capacity));
				tree->nodes = nodes;
				tree->capacity = capacity;
				for (index = 0; index < tree->count; index++) {
					*index_slot(tree, tree->nodes[index]->vcn) =
					    (uint16_t)(index + 1);
				}
			}
			node = ntfs_mutation_allocate(plan, sizeof(*node));
			if (node == NULL) {
				return NTFS_NO_MEMORY;
			}
			node->vcn = vcn;
			tree->nodes[tree->count++] = node;
			*index_slot(tree, vcn) = (uint16_t)tree->count;
		}
	}
	node->vcn = vcn;
	node->live = true;
	node->dirty = true;
	node->child = false;
	node->used = ntfs_mutation_index_encode(node->entries, NULL, false, 0);
	*out = node;
	return NTFS_OK;
}

static enum ntfs_result
index_new(struct ntfs_write_mutation_plan *plan, struct ntfs_mutation_index_tree *tree,
    struct ntfs_mutation_index_node **out)
{
	struct ntfs_mutation_index_node *node;
	uint64_t vcn;

	for (vcn = 0; vcn <= tree->count; vcn++) {
		node = index_node(tree, vcn);
		if (node == NULL || !node->live) {
			return index_acquire(plan, tree, vcn, out);
		}
	}
	return NTFS_RANGE;
}

size_t
ntfs_mutation_index_encode(
    uint8_t *buffer, const struct ntfs_mutation_key *key, bool child, uint64_t vcn)
{
	struct ntfs_disk_index_entry *entry = (void *)buffer;
	size_t bytes = ntfs_mutation_align_bytes(sizeof(*entry) + (key == NULL ? 0 : key->bytes)) +
	    (child ? sizeof(uint64_t) : 0);

	ntfs_zero(buffer, bytes);
	ntfs_put_u16(entry->length, (uint16_t)bytes);
	ntfs_put_u16(
	    entry->flags, (key == NULL ? NTFS_INDEX_END : 0) | (child ? NTFS_INDEX_CHILD : 0));
	if (key != NULL) {
		ntfs_put_u64(entry->reference, key->reference);
		ntfs_put_u16(entry->key_length, key->bytes);
		ntfs_copy(buffer + sizeof(*entry), key->value, key->bytes);
	}
	if (child) {
		ntfs_put_u64(buffer + bytes - sizeof(uint64_t), vcn);
	}
	return bytes;
}

static struct ntfs_disk_index_entry *
index_entry(struct ntfs_mutation_index_node *node, size_t offset)
{
	return (void *)(node->entries + offset);
}

static uint64_t
index_child(const struct ntfs_mutation_index_node *node, size_t offset)
{
	const struct ntfs_disk_index_entry *entry = (const void *)(node->entries + offset);

	return ntfs_u64(node->entries + offset + ntfs_u16(entry->length) - sizeof(uint64_t));
}

static void
index_set_child(struct ntfs_mutation_index_node *node, size_t offset, uint64_t vcn)
{
	ntfs_put_u64(
	    node->entries + offset + ntfs_u16(index_entry(node, offset)->length) - sizeof(uint64_t),
	    vcn);
	node->dirty = true;
}

static void
index_key(const struct ntfs_mutation_index_node *node, size_t offset, struct ntfs_mutation_key *key)
{
	const struct ntfs_disk_index_entry *entry = (const void *)(node->entries + offset);

	key->reference = ntfs_u64(entry->reference);
	key->bytes = ntfs_u16(entry->key_length);
	ntfs_copy(key->value, entry + 1, key->bytes);
}

static void
index_replace(struct ntfs_mutation_index_node *node, size_t offset, size_t old,
    const struct ntfs_mutation_key *key, uint64_t child)
{
	size_t bytes = key == NULL
	    ? 0
	    : ntfs_mutation_align_bytes(sizeof(struct ntfs_disk_index_entry) + key->bytes) +
		(node->child ? sizeof(uint64_t) : 0);
	size_t tail = node->used - offset - old, index;

	if (bytes > old) {
		for (index = tail; index != 0; index--) {
			node->entries[offset + bytes + index - 1] =
			    node->entries[offset + old + index - 1];
		}
	} else {
		for (index = 0; index < tail; index++) {
			node->entries[offset + bytes + index] = node->entries[offset + old + index];
		}
	}
	if (key != NULL) {
		(void)ntfs_mutation_index_encode(node->entries + offset, key, node->child, child);
	}
	node->used = node->used - old + bytes;
	node->dirty = true;
}

size_t
ntfs_mutation_index_root_limit(const struct ntfs_mutation_record *record)
{
	const struct ntfs_disk_record *header = (const void *)record->bytes;
	struct ntfs_attr_view root;
	size_t available = NTFS_WRITE_RECORD_BYTES - ntfs_u32(header->used);
	size_t overhead = sizeof(struct ntfs_disk_attr) + sizeof(struct ntfs_disk_resident) +
	    NTFS_WRITE_MUTATION_TARGET_NAME_UNITS * NTFS_UTF16_UNIT_BYTES +
	    sizeof(struct ntfs_disk_index_root) + sizeof(struct ntfs_disk_index_header);

	if (ntfs_attr_find(record->bytes, sizeof(record->bytes), NTFS_ATTR_INDEX_ROOT,
		ntfs_mutation_index_name, NTFS_WRITE_MUTATION_TARGET_NAME_UNITS, UINT16_MAX,
		&root) == NTFS_OK) {
		available += root.length;
	}
	return available > overhead ? (available - overhead) & ~(size_t)(NTFS_WIRE_ALIGNMENT - 1)
				    : 0;
}

enum ntfs_result
ntfs_mutation_index_load(struct ntfs_write_mutation_plan *plan,
    struct ntfs_mutation_directory *directory, uint64_t vcn, const uint8_t *header_bytes,
    size_t bytes)
{
	const struct ntfs_disk_index_header *header = (const void *)header_bytes;
	struct ntfs_mutation_index_node *node;
	size_t first = ntfs_u32(header->entries_offset), end = ntfs_u32(header->used);
	enum ntfs_result result;

	if (directory->tree == NULL) {
		directory->tree = ntfs_mutation_allocate(plan, sizeof(*directory->tree));
		if (directory->tree == NULL) {
			return NTFS_NO_MEMORY;
		}
	}
	if (first > end || end > bytes || end - first > NTFS_MUTATION_INDEX_CONTENT_BYTES) {
		return NTFS_CORRUPT;
	}
	result = index_acquire(plan, directory->tree, vcn, &node);
	if (result == NTFS_OK) {
		node->child = (header->flags & NTFS_INDEX_LARGE) != 0;
		node->dirty = false;
		node->used = end - first;
		ntfs_copy(node->entries, header_bytes + first, node->used);
	}
	return result;
}

void
ntfs_mutation_index_close(
    struct ntfs_write_mutation_plan *plan, struct ntfs_mutation_index_tree *tree)
{
	size_t index;

	if (tree == NULL) {
		return;
	}
	for (index = 0; index < tree->count; index++) {
		ntfs_mutation_release(plan, tree->nodes[index], sizeof(*tree->nodes[index]));
	}
	ntfs_mutation_release(plan, tree->nodes, ntfs_mutation_vector_bytes(tree->capacity));
	ntfs_mutation_release(plan, tree->root, sizeof(*tree->root));
	ntfs_mutation_release(plan, tree, sizeof(*tree));
}

static enum ntfs_result
index_split(struct ntfs_write_mutation_plan *plan, struct ntfs_mutation_index_tree *tree,
    struct ntfs_mutation_index_node *node, struct ntfs_mutation_key *promoted, uint64_t *right_vcn)
{
	struct ntfs_mutation_index_node *right;
	size_t offset = 0, median = 0, length, after, left_bytes, right_bytes, best = SIZE_MAX,
	       difference;
	uint64_t child = 0;
	enum ntfs_result result;

	/* Variable-length keys split by encoded bytes. Both children retain a
	 * termination entry; the promoted key exists only in the parent. */
	while ((ntfs_u16(index_entry(node, offset)->flags) & NTFS_INDEX_END) == 0) {
		length = ntfs_u16(index_entry(node, offset)->length);
		left_bytes = offset + sizeof(struct ntfs_disk_index_entry) +
		    (node->child ? sizeof(uint64_t) : 0);
		right_bytes = node->used - offset - length;
		difference =
		    left_bytes < right_bytes ? right_bytes - left_bytes : left_bytes - right_bytes;
		if (left_bytes <= NTFS_MUTATION_INDEX_CONTENT_BYTES &&
		    right_bytes <= NTFS_MUTATION_INDEX_CONTENT_BYTES && difference < best) {
			median = offset;
			best = difference;
		}
		offset += length;
	}
	if (best == SIZE_MAX) {
		return NTFS_RANGE;
	}
	index_key(node, median, promoted);
	if (node->child) {
		child = index_child(node, median);
	}
	after = median + ntfs_u16(index_entry(node, median)->length);
	result = index_new(plan, tree, &right);
	if (result != NTFS_OK) {
		return result;
	}
	right->child = node->child;
	right->used = node->used - after;
	ntfs_copy(right->entries, node->entries + after, right->used);
	node->used =
	    median + ntfs_mutation_index_encode(node->entries + median, NULL, node->child, child);
	node->dirty = true;
	*right_vcn = right->vcn;
	return NTFS_OK;
}

static enum ntfs_result
index_extreme(struct ntfs_mutation_index_tree *tree, struct ntfs_mutation_index_node *node,
    bool last, struct ntfs_mutation_key *key, unsigned depth)
{
	struct ntfs_mutation_index_node *child;
	size_t offset, previous = SIZE_MAX;
	enum ntfs_result result;

	if (node == NULL || !node->live || depth == NTFS_DIRECTORY_DEPTH) {
		return NTFS_CORRUPT;
	}
	for (offset = 0; (ntfs_u16(index_entry(node, offset)->flags) & NTFS_INDEX_END) == 0;
	    offset += ntfs_u16(index_entry(node, offset)->length)) {
		if (!last) {
			break;
		}
		previous = offset;
	}
	if (node->child) {
		child = index_node(tree, index_child(node, offset));
		result = index_extreme(tree, child, last, key, depth + 1);
		if (result != NTFS_NOT_FOUND) {
			return result;
		}
	}
	if (last) {
		offset = previous;
	}
	if (offset == SIZE_MAX ||
	    (ntfs_u16(index_entry(node, offset)->flags) & NTFS_INDEX_END) != 0) {
		return NTFS_NOT_FOUND;
	}
	index_key(node, offset, key);
	return NTFS_OK;
}

static enum ntfs_result
index_balance(struct ntfs_mutation_index_tree *tree, struct ntfs_mutation_index_node *parent,
    size_t position, struct ntfs_mutation_key *separator, struct ntfs_mutation_key *donated)
{
	struct ntfs_mutation_index_node *left, *right;
	size_t offset = 0, previous = SIZE_MAX, next, end, bytes, donor;
	uint64_t child;

	if (!parent->child ||
	    parent->used == sizeof(struct ntfs_disk_index_entry) + sizeof(uint64_t)) {
		return NTFS_OK;
	}
	/* Prefer the right sibling; the rightmost child uses its left sibling. */
	while (offset < position) {
		previous = offset;
		offset += ntfs_u16(index_entry(parent, offset)->length);
	}
	if ((ntfs_u16(index_entry(parent, position)->flags) & NTFS_INDEX_END) != 0) {
		position = previous;
	}
	next = position + ntfs_u16(index_entry(parent, position)->length);
	left = index_node(tree, index_child(parent, position));
	right = index_node(tree, index_child(parent, next));
	if (left == NULL || right == NULL || !left->live || !right->live) {
		return NTFS_CORRUPT;
	}
	if (left->child != right->child) {
		/* Previously admitted trees may have unequal subtree heights. */
		return NTFS_OK;
	}
	index_key(parent, position, separator);
	end = sizeof(struct ntfs_disk_index_entry) + (left->child ? sizeof(uint64_t) : 0);
	bytes = ntfs_mutation_align_bytes(sizeof(struct ntfs_disk_index_entry) + separator->bytes) +
	    (left->child ? sizeof(uint64_t) : 0);
	if (left->used - end + bytes + right->used <= NTFS_MUTATION_INDEX_CONTENT_BYTES) {
		child = left->child ? index_child(left, left->used - end) : 0;
		left->used -= end;
		left->used += ntfs_mutation_index_encode(
		    left->entries + left->used, separator, left->child, child);
		ntfs_copy(left->entries + left->used, right->entries, right->used);
		left->used += right->used;
		left->dirty = true;
		right->live = false;
		index_replace(
		    parent, position, ntfs_u16(index_entry(parent, position)->length), NULL, 0);
		index_set_child(parent, position, left->vcn);
	} else if (left->used == end) {
		index_key(right, 0, donated);
		child = left->child ? index_child(left, 0) : 0;
		index_replace(left, 0, 0, separator, child);
		if (left->child) {
			index_set_child(left, bytes, index_child(right, 0));
		}
		index_replace(right, 0, ntfs_u16(index_entry(right, 0)->length), NULL, 0);
		index_replace(parent, position, ntfs_u16(index_entry(parent, position)->length),
		    donated, left->vcn);
	} else if (right->used == end) {
		for (donor = 0;
		    donor + ntfs_u16(index_entry(left, donor)->length) < left->used - end;
		    donor += ntfs_u16(index_entry(left, donor)->length)) {
		}
		index_key(left, donor, donated);
		child = left->child ? index_child(left, left->used - end) : 0;
		index_replace(right, 0, 0, separator, child);
		if (left->child) {
			child = index_child(left, donor);
			index_set_child(left, left->used - end, child);
		}
		index_replace(left, donor, ntfs_u16(index_entry(left, donor)->length), NULL, 0);
		index_replace(parent, position, ntfs_u16(index_entry(parent, position)->length),
		    donated, left->vcn);
	}
	return NTFS_OK;
}

static enum ntfs_result
index_retire_empty(
    struct ntfs_mutation_index_tree *tree, struct ntfs_mutation_index_node *node, unsigned depth)
{
	enum ntfs_result result;

	if (node == NULL || !node->live || depth == NTFS_DIRECTORY_DEPTH ||
	    (ntfs_u16(index_entry(node, 0)->flags) & NTFS_INDEX_END) == 0) {
		return NTFS_CORRUPT;
	}
	if (node->child) {
		result =
		    index_retire_empty(tree, index_node(tree, index_child(node, 0)), depth + 1);
		if (result != NTFS_OK) {
			return result;
		}
	}
	node->live = false;
	return NTFS_OK;
}

static enum ntfs_result
index_edit_node(struct ntfs_write_mutation_plan *plan, struct ntfs_mutation_index_tree *tree,
    struct ntfs_mutation_index_node *node, const struct ntfs_mutation_key *key, bool remove,
    struct ntfs_mutation_key *promoted, uint64_t *right, unsigned depth)
{
	struct ntfs_mutation_key candidate, replacement;
	struct ntfs_mutation_index_node *child;
	size_t offset, length, next;
	uint64_t vcn = 0, split = NTFS_MUTATION_INDEX_ROOT_VCN;
	int order = -1;
	enum ntfs_result result;

	*right = NTFS_MUTATION_INDEX_ROOT_VCN;
	if (node == NULL || !node->live || depth == NTFS_DIRECTORY_DEPTH) {
		return NTFS_CORRUPT;
	}
	for (offset = 0; (ntfs_u16(index_entry(node, offset)->flags) & NTFS_INDEX_END) == 0;
	    offset += ntfs_u16(index_entry(node, offset)->length)) {
		index_key(node, offset, &candidate);
		order = ntfs_mutation_key_compare(plan, key, &candidate);
		if (order <= 0) {
			break;
		}
	}
	if ((ntfs_u16(index_entry(node, offset)->flags) & NTFS_INDEX_END) != 0) {
		order = -1;
	}
	length = ntfs_u16(index_entry(node, offset)->length);
	if (node->child) {
		vcn = index_child(node, offset);
	}
	if (order == 0 && !remove) {
		index_replace(node, offset, length, key, vcn);
	} else if (order == 0 && !node->child) {
		index_replace(node, offset, length, NULL, 0);
	} else if (!node->child) {
		if (remove) {
			return NTFS_NOT_FOUND;
		}
		index_replace(node, offset, 0, key, 0);
	} else {
		child = index_node(tree, vcn);
		if (order == 0) {
			result = index_extreme(tree, child, true, &replacement, depth + 1);
			if (result == NTFS_NOT_FOUND) {
				next = offset + length;
				child = index_node(tree, index_child(node, next));
				result = index_extreme(tree, child, false, &replacement, depth + 1);
				if (result == NTFS_NOT_FOUND) {
					result = index_retire_empty(
					    tree, index_node(tree, vcn), depth + 1);
					if (result != NTFS_OK) {
						return result;
					}
					index_replace(node, offset, length, NULL, 0);
					return NTFS_OK;
				}
				if (result != NTFS_OK) {
					return result;
				}
				index_replace(node, offset, length, &replacement, vcn);
				offset += ntfs_u16(index_entry(node, offset)->length);
			} else if (result == NTFS_OK) {
				index_replace(node, offset, length, &replacement, vcn);
			} else {
				return result;
			}
		}
		result = index_edit_node(plan, tree, child, order == 0 ? &replacement : key, remove,
		    &candidate, &split, depth + 1);
		if (result != NTFS_OK) {
			return result;
		}
		if (split != NTFS_MUTATION_INDEX_ROOT_VCN) {
			index_replace(node, offset, 0, &candidate, child->vcn);
			index_set_child(
			    node, offset + ntfs_u16(index_entry(node, offset)->length), split);
		}
		if (remove) {
			/* The recursive edit and split insertion have consumed these keys;
			 * reuse this depth's two buffers for separator/donor balancing. */
			result = index_balance(tree, node, offset, &candidate, &replacement);
			if (result != NTFS_OK) {
				return result;
			}
		}
	}
	if (node != tree->root && node->used > NTFS_MUTATION_INDEX_CONTENT_BYTES) {
		return index_split(plan, tree, node, promoted, right);
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_mutation_index_fit_root(
    struct ntfs_write_mutation_plan *plan, struct ntfs_mutation_directory *directory, size_t limit)
{
	struct ntfs_mutation_index_tree *tree = directory->tree;
	struct ntfs_mutation_index_node *child;
	enum ntfs_result result;

	while (tree->root->child &&
	    tree->root->used == sizeof(struct ntfs_disk_index_entry) + sizeof(uint64_t)) {
		child = index_node(tree, index_child(tree->root, 0));
		if (child == NULL || !child->live) {
			return NTFS_CORRUPT;
		}
		if (child->used > limit) {
			break;
		}
		tree->root->used = child->used;
		tree->root->child = child->child;
		tree->root->dirty = true;
		ntfs_copy(tree->root->entries, child->entries, child->used);
		child->live = false;
	}
	if (tree->root->used > limit) {
		result = index_new(plan, tree, &child);
		if (result != NTFS_OK) {
			return result;
		}
		child->child = tree->root->child;
		child->used = tree->root->used;
		ntfs_copy(child->entries, tree->root->entries, child->used);
		tree->root->child = true;
		tree->root->used =
		    ntfs_mutation_index_encode(tree->root->entries, NULL, true, child->vcn);
		tree->root->dirty = true;
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_mutation_index_edit(struct ntfs_write_mutation_plan *plan,
    struct ntfs_mutation_directory *directory, const struct ntfs_mutation_key *key, bool remove)
{
	struct ntfs_mutation_index_tree *tree = directory->tree;
	struct ntfs_mutation_key promoted;
	uint64_t right;
	enum ntfs_result result;

	if (tree == NULL || tree->root == NULL) {
		return NTFS_CORRUPT;
	}
	result = index_edit_node(plan, tree, tree->root, key, remove, &promoted, &right, 0);
	if (result != NTFS_OK) {
		return result;
	}
	return ntfs_mutation_index_fit_root(
	    plan, directory, ntfs_mutation_index_root_limit(directory->record));
}
