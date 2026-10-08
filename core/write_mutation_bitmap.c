/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_mutation_internal.h"

static size_t
mutation_bitmap_pages(size_t bytes)
{
	return bytes / NTFS_MUTATION_BITMAP_PAGE_BYTES +
	    (bytes % NTFS_MUTATION_BITMAP_PAGE_BYTES != 0);
}

static void
mutation_bitmap_release_pages(struct ntfs_write_mutation_plan *plan,
    struct ntfs_mutation_bitmap_page **pages, size_t capacity)
{
	size_t index;

	for (index = 0; index < capacity; index++) {
		ntfs_mutation_release(plan, pages[index], sizeof(*pages[index]));
	}
	ntfs_mutation_release(plan, pages, capacity * sizeof(*pages));
}

enum ntfs_result
ntfs_mutation_bitmap_open(struct ntfs_write_mutation_plan *plan,
    struct ntfs_mutation_bitmap *bitmap, uint64_t number, uint32_t type)
{
	uint64_t required;
	enum ntfs_result result;

	bitmap->type = type;
	result = ntfs_mutation_record_get(plan, number, true, &bitmap->record);
	if (result == NTFS_OK) {
		result = ntfs_mutation_stream(plan, bitmap->record, type, NULL, 0, &bitmap->stream);
	}
	if (result != NTFS_OK) {
		return result;
	}
	if (bitmap->stream->size == 0 || bitmap->stream->size > NTFS_MUTATION_MAX_BITMAP_BYTES ||
	    bitmap->stream->initialized != bitmap->stream->size) {
		return NTFS_UNSUPPORTED;
	}
	required = number == NTFS_BITMAP_RECORD ? plan->info.cluster_count
						: plan->mft->initialized / NTFS_WRITE_RECORD_BYTES;
	if ((required + NTFS_BITS_PER_BYTE - 1u) / NTFS_BITS_PER_BYTE > bitmap->stream->size) {
		return NTFS_CORRUPT;
	}
	bitmap->bytes = (size_t)bitmap->stream->size;
	bitmap->original_bytes = bitmap->bytes;
	/* A one-page bitmap keeps its allocation-free lookup path. Larger maps
	 * read one page at a time and retain snapshots only for modified pages. */
	if (bitmap->bytes > NTFS_MUTATION_BITMAP_PAGE_BYTES) {
		return NTFS_OK;
	}
	bitmap->before = ntfs_mutation_allocate(plan, bitmap->bytes);
	bitmap->after = ntfs_mutation_allocate(plan, bitmap->bytes);
	if (bitmap->before == NULL || bitmap->after == NULL) {
		return NTFS_NO_MEMORY;
	}
	result = ntfs_mutation_stream_read(plan, bitmap->stream, 0, bitmap->before, bitmap->bytes);
	if (result == NTFS_OK) {
		ntfs_copy(bitmap->after, bitmap->before, bitmap->bytes);
	}
	return result;
}

enum ntfs_result
ntfs_mutation_bitmap_view(struct ntfs_write_mutation_plan *plan,
    struct ntfs_mutation_bitmap *bitmap, size_t offset, bool modify,
    struct ntfs_mutation_bitmap_view *view)
{
	struct ntfs_mutation_bitmap_page *page;
	size_t index, within, take, first, capacity, window, cursor, word;
	uint64_t occupied;
	uint8_t *memory;
	size_t wanted;
	enum ntfs_result result;

	*view = (struct ntfs_mutation_bitmap_view){0};
	if (offset >= bitmap->bytes) {
		return NTFS_RANGE;
	}
	if (bitmap->after != NULL) {
		view->before = bitmap->before == NULL ? NULL : bitmap->before + offset;
		view->after = bitmap->after + offset;
		view->bytes = bitmap->bytes - offset;
		return NTFS_OK;
	}
	index = offset / NTFS_MUTATION_BITMAP_PAGE_BYTES;
	within = offset % NTFS_MUTATION_BITMAP_PAGE_BYTES;
	first = offset - within;
	take = NTFS_MUTATION_BITMAP_PAGE_BYTES - within;
	if (take > bitmap->bytes - offset) {
		take = bitmap->bytes - offset;
	}
	page = index < bitmap->page_capacity ? bitmap->pages[index] : NULL;
	if (page == NULL) {
		window = bitmap->window_index;
		if (!bitmap->window_valid || first < window ||
		    first - window >= bitmap->window_bytes) {
			wanted = bitmap->window_valid && first == window + bitmap->window_bytes
			    ? NTFS_MUTATION_BITMAP_WINDOW_BYTES
			    : NTFS_MUTATION_BITMAP_PAGE_BYTES;
			if (bitmap->window_capacity < wanted) {
				memory = ntfs_mutation_allocate(plan, wanted);
				if (memory == NULL) {
					return NTFS_NO_MEMORY;
				}
				ntfs_mutation_release(
				    plan, bitmap->window, bitmap->window_capacity);
				bitmap->window = memory;
				bitmap->window_capacity = wanted;
			}
			window = first;
			/* A failed exact read may overwrite the window. Invalidate before
			 * I/O, including attempts to replace a previously valid page. */
			bitmap->window_valid = false;
			ntfs_zero(bitmap->window, wanted);
			if (window < bitmap->original_bytes) {
				capacity = bitmap->original_bytes - window;
				if (capacity > wanted) {
					capacity = wanted;
				}
				/* The owning stream is an immutable original-volume snapshot.
				 * Projected plan patches must never enter before bytes. */
				result = ntfs_stream_exact(
				    bitmap->stream, window, bitmap->window, capacity);
				if (result != NTFS_OK) {
					return result;
				}
				/* Only complete original pages are summarized. Original ownership
				 * cannot become reusable during this plan, even after retirement.
				 */
				for (cursor = 0;
				    cursor + NTFS_MUTATION_BITMAP_PAGE_BYTES <= capacity;
				    cursor += NTFS_MUTATION_BITMAP_PAGE_BYTES) {
					occupied = UINT64_MAX;
					for (word = 0; word < NTFS_MUTATION_BITMAP_PAGE_BYTES;
					    word += sizeof(uint64_t)) {
						occupied &=
						    ntfs_u64(bitmap->window + cursor + word);
					}
					if (occupied == UINT64_MAX) {
						ntfs_mutation_set_bit(bitmap->full_pages,
						    (window + cursor) /
							NTFS_MUTATION_BITMAP_PAGE_BYTES,
						    true);
					}
				}
			}
			bitmap->window_index = window;
			bitmap->window_bytes = wanted;
			bitmap->window_valid = true;
		}
		if (!modify) {
			*view = (struct ntfs_mutation_bitmap_view){
			    bitmap->window + first - window + within,
			    bitmap->window + first - window + within, take};
			return NTFS_OK;
		}
		if (bitmap->pages == NULL) {
			capacity = mutation_bitmap_pages(bitmap->bytes);
			bitmap->pages =
			    ntfs_mutation_allocate(plan, capacity * sizeof(*bitmap->pages));
			if (bitmap->pages == NULL) {
				return NTFS_NO_MEMORY;
			}
			bitmap->page_capacity = capacity;
		}
		page = ntfs_mutation_allocate(plan, sizeof(*page));
		if (page == NULL) {
			return NTFS_NO_MEMORY;
		}
		ntfs_copy(page->before, bitmap->window + first - window, sizeof(page->before));
		ntfs_copy(page->after, bitmap->window + first - window, sizeof(page->after));
		bitmap->pages[index] = page;
	}
	*view =
	    (struct ntfs_mutation_bitmap_view){page->before + within, page->after + within, take};
	return NTFS_OK;
}

enum ntfs_result
ntfs_mutation_bitmap_test(struct ntfs_write_mutation_plan *plan,
    struct ntfs_mutation_bitmap *bitmap, uint64_t bit, bool original, bool *out)
{
	struct ntfs_mutation_bitmap_view view;
	size_t bytes = original ? bitmap->original_bytes : bitmap->bytes;
	enum ntfs_result result;

	*out = false;
	if (bit / NTFS_BITS_PER_BYTE >= bytes) {
		return NTFS_OK;
	}
	result = ntfs_mutation_bitmap_view(
	    plan, bitmap, (size_t)(bit / NTFS_BITS_PER_BYTE), false, &view);
	if (result == NTFS_OK) {
		*out = ntfs_mutation_bit(
		    original ? view.before : view.after, 1, bit % NTFS_BITS_PER_BYTE);
	}
	return result;
}

enum ntfs_result
ntfs_mutation_bitmap_set(struct ntfs_write_mutation_plan *plan, struct ntfs_mutation_bitmap *bitmap,
    uint64_t bit, bool value)
{
	struct ntfs_mutation_bitmap_view view;
	enum ntfs_result result;

	if (bit / NTFS_BITS_PER_BYTE >= bitmap->bytes) {
		return NTFS_RANGE;
	}
	result = ntfs_mutation_bitmap_view(
	    plan, bitmap, (size_t)(bit / NTFS_BITS_PER_BYTE), true, &view);
	if (result == NTFS_OK) {
		ntfs_mutation_set_bit(view.after, bit % NTFS_BITS_PER_BYTE, value);
	}
	return result;
}

enum ntfs_result
ntfs_mutation_bitmap_grow(
    struct ntfs_write_mutation_plan *plan, struct ntfs_mutation_bitmap *bitmap, size_t bytes)
{
	struct ntfs_mutation_bitmap_page **pages;
	uint8_t *before, *after;
	size_t capacity, index, offset, take;

	if (bytes <= bitmap->bytes) {
		return NTFS_OK;
	}
	if (bytes > NTFS_MUTATION_MAX_BITMAP_BYTES) {
		return NTFS_RANGE;
	}
	if (bitmap->after != NULL && bytes <= NTFS_MUTATION_BITMAP_PAGE_BYTES) {
		before = ntfs_mutation_allocate(plan, bytes);
		after = ntfs_mutation_allocate(plan, bytes);
		if (before == NULL || after == NULL) {
			ntfs_mutation_release(plan, before, bytes);
			ntfs_mutation_release(plan, after, bytes);
			return NTFS_NO_MEMORY;
		}
		ntfs_copy(before, bitmap->before, bitmap->bytes);
		ntfs_copy(after, bitmap->after, bitmap->bytes);
		ntfs_mutation_release(plan, bitmap->before, bitmap->bytes);
		ntfs_mutation_release(plan, bitmap->after, bitmap->bytes);
		bitmap->before = before;
		bitmap->after = after;
		bitmap->bytes = bytes;
		return NTFS_OK;
	}
	capacity = mutation_bitmap_pages(bytes);
	if (bitmap->after != NULL) {
		/* Publish the representation change only after all snapshots exist.
		 * Unchanged pages can subsequently be read from the original stream. */
		pages = ntfs_mutation_allocate(plan, capacity * sizeof(*pages));
		if (pages == NULL) {
			return NTFS_NO_MEMORY;
		}
		for (offset = 0; offset < bitmap->bytes; offset += take) {
			take = bitmap->bytes - offset;
			if (take > NTFS_MUTATION_BITMAP_PAGE_BYTES) {
				take = NTFS_MUTATION_BITMAP_PAGE_BYTES;
			}
			if (ntfs_equal(bitmap->before + offset, bitmap->after + offset, take)) {
				continue;
			}
			index = offset / NTFS_MUTATION_BITMAP_PAGE_BYTES;
			pages[index] = ntfs_mutation_allocate(plan, sizeof(*pages[index]));
			if (pages[index] == NULL) {
				mutation_bitmap_release_pages(plan, pages, capacity);
				return NTFS_NO_MEMORY;
			}
			ntfs_copy(pages[index]->before, bitmap->before + offset, take);
			ntfs_copy(pages[index]->after, bitmap->after + offset, take);
		}
		ntfs_mutation_release(plan, bitmap->before, bitmap->bytes);
		ntfs_mutation_release(plan, bitmap->after, bitmap->bytes);
		bitmap->before = bitmap->after = NULL;
		bitmap->pages = pages;
		bitmap->page_capacity = capacity;
	} else if (bitmap->pages != NULL && capacity > bitmap->page_capacity) {
		pages = ntfs_mutation_allocate(plan, capacity * sizeof(*pages));
		if (pages == NULL) {
			return NTFS_NO_MEMORY;
		}
		ntfs_copy(pages, bitmap->pages, bitmap->page_capacity * sizeof(*pages));
		ntfs_mutation_release(plan, bitmap->pages, bitmap->page_capacity * sizeof(*pages));
		bitmap->pages = pages;
		bitmap->page_capacity = capacity;
	}
	bitmap->bytes = bytes;
	return NTFS_OK;
}

static bool
mutation_bitmap_page_changed(const struct ntfs_mutation_bitmap *bitmap, size_t offset, size_t take)
{
	const struct ntfs_mutation_bitmap_page *page;
	size_t index;

	if (bitmap->after != NULL) {
		return !ntfs_equal(bitmap->before + offset, bitmap->after + offset, take);
	}
	index = offset / NTFS_MUTATION_BITMAP_PAGE_BYTES;
	page = index < bitmap->page_capacity ? bitmap->pages[index] : NULL;
	return page != NULL && !ntfs_equal(page->before, page->after, take);
}

enum ntfs_result
ntfs_mutation_bitmap_flush(
    struct ntfs_write_mutation_plan *plan, struct ntfs_mutation_bitmap *bitmap)
{
	struct ntfs_run *runs = NULL;
	struct ntfs_stream *stream = NULL;
	struct ntfs_mutation_bitmap_view view;
	uint64_t clusters;
	size_t count = 0, offset, take;
	bool changed = bitmap->bytes != bitmap->original_bytes;
	enum ntfs_result result;

	for (offset = 0; !changed && offset < bitmap->bytes; offset += take) {
		take = bitmap->bytes - offset < NTFS_MUTATION_BITMAP_PAGE_BYTES
		    ? bitmap->bytes - offset
		    : NTFS_MUTATION_BITMAP_PAGE_BYTES;
		changed = mutation_bitmap_page_changed(bitmap, offset, take);
	}
	if (!changed) {
		return NTFS_OK;
	}
	if (bitmap->stream->resident && bitmap->after != NULL) {
		result = ntfs_mutation_resident(
		    plan, bitmap->record, bitmap->type, NULL, 0, bitmap->after, bitmap->bytes, 0);
		if (result != NTFS_NO_SPACE) {
			return result;
		}
	}
	/* A bit update does not resize or re-encode its owning bitmap stream. */
	result = NTFS_OK;
	if (bitmap->stream->resident || bitmap->bytes != bitmap->original_bytes) {
		clusters = bitmap->bytes / NTFS_WRITE_CLUSTER_BYTES +
		    (bitmap->bytes % NTFS_WRITE_CLUSTER_BYTES != 0);
		result = ntfs_mutation_resize_runs(plan, bitmap->stream, clusters, &runs, &count);
		if (result == NTFS_OK) {
			result = ntfs_mutation_nonresident(plan, bitmap->record, bitmap->type, NULL,
			    0, runs, count, bitmap->bytes, bitmap->bytes, 0);
		}
	}
	if (result == NTFS_OK) {
		result = ntfs_mutation_stream(plan, bitmap->record, bitmap->type, NULL, 0, &stream);
	}
	for (offset = 0; result == NTFS_OK && offset < bitmap->bytes; offset += take) {
		take = bitmap->bytes - offset < NTFS_MUTATION_BITMAP_PAGE_BYTES
		    ? bitmap->bytes - offset
		    : NTFS_MUTATION_BITMAP_PAGE_BYTES;
		if (bitmap->stream->resident || offset + take > bitmap->original_bytes ||
		    mutation_bitmap_page_changed(bitmap, offset, take)) {
			result = ntfs_mutation_bitmap_view(plan, bitmap, offset, false, &view);
			if (result == NTFS_OK) {
				result = ntfs_mutation_stream_write(plan, bitmap->record,
				    bitmap->type, NULL, 0, stream, offset, view.after, take,
				    NTFS_WRITE_MUTATION_BITMAP);
			}
		}
	}
	ntfs_stream_close(stream);
	ntfs_mutation_release(plan, runs, NTFS_MUTATION_MAX_RUNS * sizeof(*runs));
	return result;
}

void
ntfs_mutation_bitmap_close(
    struct ntfs_write_mutation_plan *plan, struct ntfs_mutation_bitmap *bitmap)
{
	ntfs_stream_close(bitmap->stream);
	ntfs_mutation_release(plan, bitmap->before, bitmap->bytes);
	ntfs_mutation_release(plan, bitmap->after, bitmap->bytes);
	mutation_bitmap_release_pages(plan, bitmap->pages, bitmap->page_capacity);
	ntfs_mutation_release(plan, bitmap->window, bitmap->window_capacity);
	*bitmap = (struct ntfs_mutation_bitmap){0};
}
