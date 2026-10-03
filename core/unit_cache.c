/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"

void
ntfs_unit_cache_initialize(struct ntfs_unit_cache *cache)
{
	ntfs_zero(cache, sizeof(*cache));
	cache->current = NTFS_UNIT_CACHE_EMPTY;
	cache->retained = NTFS_UNIT_CACHE_EMPTY;
}

bool
ntfs_unit_cache_reuse(struct ntfs_unit_cache *cache, uint8_t *required, uint64_t unit)
{
	uint64_t previous;

	if (cache->retained == NTFS_UNIT_CACHE_EMPTY || cache->retained != unit) {
		return false;
	}
	previous = cache->current;
	cache->current = cache->retained;
	cache->retained = previous;
	cache->output = cache->output == required ? cache->extra : required;
	return true;
}

uint8_t *
ntfs_unit_cache_prepare(
    struct ntfs_volume *volume, struct ntfs_unit_cache *cache, uint8_t *required, size_t size)
{
	if (cache->output == NULL) {
		cache->output = required;
	}
	/* Attempt the extra output once, only after a useful first fill. Refusal
	 * leaves the required decode path and its operation status intact. */
	if (cache->current != NTFS_UNIT_CACHE_EMPTY && !cache->attempted) {
		cache->attempted = true;
		cache->extra = ntfs_alloc_optional(volume, size);
	}
	if (cache->extra != NULL) {
		/* Replace only the older slot. A failed fill preserves the current one. */
		cache->retained = NTFS_UNIT_CACHE_EMPTY;
		return cache->output == required ? cache->extra : required;
	}
	cache->current = NTFS_UNIT_CACHE_EMPTY;
	return required;
}

void
ntfs_unit_cache_publish(struct ntfs_unit_cache *cache, uint64_t unit, uint8_t *output)
{
	if (cache->extra != NULL) {
		cache->retained = cache->current;
	}
	cache->current = unit;
	cache->output = output;
}

void
ntfs_unit_cache_release(struct ntfs_volume *volume, struct ntfs_unit_cache *cache, size_t size)
{
	ntfs_free(volume, cache->extra, size);
	ntfs_unit_cache_initialize(cache);
}
