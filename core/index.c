/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"

static size_t
index_hash_vcn(uint64_t vcn, uint32_t capacity)
{
	return (size_t)((vcn * NTFS_VCN_HASH_MULTIPLIER) >> NTFS_VCN_HASH_SHIFT) & (capacity - 1u);
}

enum ntfs_result
ntfs_index_work(struct ntfs_volume *volume, enum ntfs_result (*charge)(void *, uint64_t),
    void *context, uint64_t units)
{
	enum ntfs_result result = charge == NULL ? NTFS_OK : charge(context, units);

	return result == NTFS_OK ? ntfs_work(volume, units) : result;
}

enum ntfs_result
ntfs_index_visit(struct ntfs_volume *volume, struct ntfs_index_visited *visited, uint64_t vcn,
    enum ntfs_result (*charge)(void *, uint64_t), void *context)
{
	uint64_t *table;
	uint32_t capacity, i;
	size_t position;
	enum ntfs_result result;

	if (vcn == UINT64_MAX) {
		return NTFS_CORRUPT;
	}
	if (visited->count == volume->limits.max_directory_nodes) {
		return NTFS_RANGE;
	}
	if (visited->count * NTFS_VISITED_LOAD_DENOMINATOR >= visited->capacity) {
		capacity = visited->capacity == 0 ? NTFS_VISITED_INITIAL_CAPACITY
						  : visited->capacity * NTFS_VECTOR_GROWTH;
		table = ntfs_alloc(volume, (size_t)capacity * sizeof(*table));
		if (table == NULL) {
			return NTFS_NO_MEMORY;
		}
		for (i = 0; i < visited->capacity; i++) {
			result = ntfs_index_work(volume, charge, context, 1);
			if (result != NTFS_OK) {
				ntfs_free(volume, table, (size_t)capacity * sizeof(*table));
				return result;
			}
			if (visited->values[i] == 0) {
				continue;
			}
			position = index_hash_vcn(visited->values[i] - 1, capacity);
			while (table[position] != 0) {
				result = ntfs_index_work(volume, charge, context, 1);
				if (result != NTFS_OK) {
					ntfs_free(volume, table, (size_t)capacity * sizeof(*table));
					return result;
				}
				position = (position + 1) & (capacity - 1u);
			}
			table[position] = visited->values[i];
		}
		ntfs_free(volume, visited->values, (size_t)visited->capacity * sizeof(*table));
		visited->values = table;
		visited->capacity = capacity;
	}
	position = index_hash_vcn(vcn, visited->capacity);
	while (visited->values[position] != 0) {
		result = ntfs_index_work(volume, charge, context, 1);
		if (result != NTFS_OK) {
			return result;
		}
		if (visited->values[position] == vcn + 1) {
			return NTFS_CORRUPT;
		}
		position = (position + 1) & (visited->capacity - 1u);
	}
	visited->values[position] = vcn + 1;
	visited->count++;
	return NTFS_OK;
}

static enum ntfs_result
index_inventory_slot(struct ntfs_volume *volume, struct ntfs_stream *allocation,
    const struct ntfs_index_visited *visited, uint32_t block_size, uint64_t slot,
    enum ntfs_result (*charge)(void *, uint64_t), void *context, uint64_t *cluster)
{
	const struct ntfs_run *run;
	uint64_t offset, vcn, storage_vcn;
	uint32_t unit;
	size_t position;
	enum ntfs_result result;

	if (allocation == NULL || slot >= allocation->size / block_size) {
		return NTFS_CORRUPT;
	}
	/* The slot bound proves the multiplication fits the validated stream. */
	offset = slot * block_size;
	unit = volume->info.cluster_size <= block_size ? volume->info.cluster_size
						       : volume->info.sector_size;
	vcn = offset / unit;
	if (visited->capacity != 0) {
		position = index_hash_vcn(vcn, visited->capacity);
		while (visited->values[position] != 0) {
			result = ntfs_index_work(volume, charge, context, 1);
			if (result != NTFS_OK) {
				return result;
			}
			if (visited->values[position] == vcn + 1) {
				return NTFS_OK;
			}
			position = (position + 1) & (visited->capacity - 1u);
		}
	}
	storage_vcn = offset / volume->info.cluster_size;
	run = ntfs_run_find(allocation, storage_vcn);
	if (run != NULL && run->lcn != NTFS_HOLE) {
		*cluster = run->lcn + storage_vcn - run->vcn;
	}
	return NTFS_CORRUPT;
}

enum ntfs_result
ntfs_index_check_allocation(struct ntfs_volume *volume, struct ntfs_stream *allocation,
    struct ntfs_stream *bitmap, const struct ntfs_index_visited *visited, uint32_t block_size,
    enum ntfs_result (*charge)(void *, uint64_t), void *context, uint64_t *cluster)
{
	uint8_t bytes[NTFS_INDEX_BITMAP_SCAN_BYTES];
	uint64_t offset, slot, used = 0;
	size_t take, byte;
	unsigned bit;
	enum ntfs_result result;

	*cluster = 0;
	if (allocation != NULL && allocation->size % block_size != 0) {
		return NTFS_CORRUPT;
	}
	if (bitmap == NULL) {
		return visited->count == 0 ? NTFS_OK : NTFS_CORRUPT;
	}
	if (bitmap->flags != 0 || bitmap->initialized != bitmap->size) {
		return NTFS_CORRUPT;
	}
	for (offset = 0; offset < bitmap->size; offset += take) {
		take = bitmap->size - offset < sizeof(bytes) ? (size_t)(bitmap->size - offset)
							     : sizeof(bytes);
		result =
		    ntfs_index_work(volume, charge, context, (uint64_t)take * NTFS_BITS_PER_BYTE);
		if (result == NTFS_OK) {
			result = ntfs_stream_exact(bitmap, offset, bytes, take);
		}
		if (result != NTFS_OK) {
			return result;
		}
		for (byte = 0; byte < take; byte++) {
			if (offset + byte > UINT64_MAX / NTFS_BITS_PER_BYTE) {
				return NTFS_CORRUPT;
			}
			for (bit = 0; bit < NTFS_BITS_PER_BYTE; bit++) {
				if ((bytes[byte] & (1u << bit)) == 0) {
					continue;
				}
				slot = (offset + byte) * NTFS_BITS_PER_BYTE + bit;
				result = index_inventory_slot(volume, allocation, visited,
				    block_size, slot, charge, context, cluster);
				if (result != NTFS_OK) {
					return result;
				}
				used++;
			}
		}
	}
	return used == visited->count ? NTFS_OK : NTFS_CORRUPT;
}
