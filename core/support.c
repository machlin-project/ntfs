/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"

uint16_t
ntfs_u16(const void *p)
{
	const uint8_t *b = p;
	return (uint16_t)(b[0] | (uint16_t)b[1] << 8);
}

uint32_t
ntfs_u32(const void *p)
{
	const uint8_t *b = p;
	return (uint32_t)ntfs_u16(b) | (uint32_t)ntfs_u16(b + 2) << 16;
}

uint64_t
ntfs_u64(const void *p)
{
	const uint8_t *b = p;
	return (uint64_t)ntfs_u32(b) | (uint64_t)ntfs_u32(b + 4) << 32;
}

void
ntfs_copy(void *to, const void *from, size_t n)
{
	uint8_t *d = to;
	const uint8_t *s = from;
	size_t i;
	for (i = 0; i < n; i++) {
		d[i] = s[i];
	}
}

void
ntfs_zero(void *to, size_t n)
{
	uint8_t *d = to;
	size_t i;
	for (i = 0; i < n; i++) {
		d[i] = 0;
	}
}

bool
ntfs_equal(const void *a, const void *b, size_t n)
{
	const uint8_t *x = a, *y = b;
	size_t i;
	for (i = 0; i < n; i++) {
		if (x[i] != y[i]) {
			return false;
		}
	}
	return true;
}

bool
ntfs_bounds(uint64_t offset, uint64_t length, uint64_t size)
{
	return offset <= size && length <= size - offset;
}

void *
ntfs_alloc(struct ntfs_volume *v, size_t n)
{
	void *p;
	if (n == 0) {
		return NULL;
	}
	p = v->env.allocate(v->env.context, n);
	if (p != NULL) {
		ntfs_zero(p, n);
	}
	return p;
}

void
ntfs_free(struct ntfs_volume *v, void *p, size_t n)
{
	if (p != NULL) {
		v->env.release(v->env.context, p, n);
	}
}

enum ntfs_result
ntfs_io(struct ntfs_volume *v, uint64_t offset, void *buffer, size_t size)
{
	if (!ntfs_bounds(offset, size, v->info.size_bytes)) {
		return NTFS_CORRUPT;
	}
	if (size == 0) {
		return NTFS_OK;
	}
	v->stats.read_calls++;
	v->stats.read_bytes += size;
	return v->env.read(v->env.context, offset, buffer, size);
}

void
ntfs_default_limits(struct ntfs_limits *l)
{
	l->max_runs = 65536;
	l->max_attribute_list = 1048576;
	l->record_cache_entries = 64;
	l->max_directory_nodes = 65536;
}

const char *
ntfs_result_string(enum ntfs_result r)
{
	static const char *const names[] = {"success", "not NTFS", "corrupt metadata",
	    "unsupported format", "I/O error", "out of memory", "not found", "not a directory",
	    "is a directory", "invalid argument", "stale file reference", "resource limit",
	    "read-only filesystem", "volume requires Windows recovery", "end of directory",
	    "objects still open"};
	return (unsigned)r < sizeof(names) / sizeof(names[0]) ? names[r] : "unknown error";
}

void
ntfs_decode_time(uint64_t ticks, struct ntfs_time *out)
{
	uint64_t delta;

	if (ticks >= NTFS_TIME_EPOCH) {
		delta = ticks - NTFS_TIME_EPOCH;
		out->seconds = (int64_t)(delta / NTFS_TIME_TICKS);
		out->nanoseconds = (uint32_t)(delta % NTFS_TIME_TICKS) * 100;
	} else {
		delta = NTFS_TIME_EPOCH - ticks;
		out->seconds = -(int64_t)(delta / NTFS_TIME_TICKS);
		out->nanoseconds = 0;
		if (delta % NTFS_TIME_TICKS != 0) {
			out->seconds--;
			out->nanoseconds =
			    (uint32_t)(NTFS_TIME_TICKS - delta % NTFS_TIME_TICKS) * 100;
		}
	}
}
