/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"

uint16_t
ntfs_u16(const void *input)
{
	const uint8_t *bytes = input;

	return (uint16_t)(bytes[0] | (uint16_t)bytes[1] << NTFS_BITS_PER_BYTE);
}

uint32_t
ntfs_u32(const void *input)
{
	const uint8_t *bytes = input;

	return (uint32_t)ntfs_u16(bytes) |
	    (uint32_t)ntfs_u16(bytes + sizeof(uint16_t)) << (sizeof(uint16_t) * NTFS_BITS_PER_BYTE);
}

uint64_t
ntfs_u64(const void *input)
{
	const uint8_t *bytes = input;

	return (uint64_t)ntfs_u32(bytes) |
	    (uint64_t)ntfs_u32(bytes + sizeof(uint32_t)) << (sizeof(uint32_t) * NTFS_BITS_PER_BYTE);
}

void
ntfs_put_u16(void *output, uint16_t value)
{
	uint8_t *bytes = output;

	bytes[0] = (uint8_t)value;
	bytes[1] = (uint8_t)(value >> NTFS_BITS_PER_BYTE);
}

void
ntfs_put_u32(void *output, uint32_t value)
{
	uint8_t *bytes = output;

	ntfs_put_u16(bytes, (uint16_t)value);
	ntfs_put_u16(
	    bytes + sizeof(uint16_t), (uint16_t)(value >> (sizeof(uint16_t) * NTFS_BITS_PER_BYTE)));
}

void
ntfs_put_u64(void *output, uint64_t value)
{
	uint8_t *bytes = output;

	ntfs_put_u32(bytes, (uint32_t)value);
	ntfs_put_u32(
	    bytes + sizeof(uint32_t), (uint32_t)(value >> (sizeof(uint32_t) * NTFS_BITS_PER_BYTE)));
}

void
ntfs_copy(void *destination, const void *source, size_t bytes)
{
	uint8_t *destination_bytes = destination;
	const uint8_t *source_bytes = source;
	size_t i;

	for (i = 0; i < bytes; i++) {
		destination_bytes[i] = source_bytes[i];
	}
}

void
ntfs_zero(void *destination, size_t bytes)
{
	uint8_t *destination_bytes = destination;
	size_t i;

	for (i = 0; i < bytes; i++) {
		destination_bytes[i] = 0;
	}
}

bool
ntfs_equal(const void *left, const void *right, size_t bytes)
{
	const uint8_t *left_bytes = left, *right_bytes = right;
	size_t i;

	for (i = 0; i < bytes; i++) {
		if (left_bytes[i] != right_bytes[i]) {
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

static void *
volume_allocate(struct ntfs_volume *volume, size_t bytes, bool optional)
{
	void *allocation;

	if (bytes == 0 || !ntfs_operation_allocate(volume, bytes, optional)) {
		return NULL;
	}
	allocation = volume->env.allocate(volume->env.context, bytes);
	if (allocation != NULL) {
		ntfs_operation_allocated(volume, bytes);
		ntfs_zero(allocation, bytes);
	}
	return allocation;
}

void *
ntfs_alloc(struct ntfs_volume *volume, size_t bytes)
{
	return volume_allocate(volume, bytes, false);
}

void *
ntfs_alloc_optional(struct ntfs_volume *volume, size_t bytes)
{
	return volume_allocate(volume, bytes, true);
}

void
ntfs_free(struct ntfs_volume *volume, void *allocation, size_t bytes)
{
	if (allocation != NULL) {
		volume->live_bytes -= bytes;
		volume->env.release(volume->env.context, allocation, bytes);
	}
}

enum ntfs_result
ntfs_io(struct ntfs_volume *volume, uint64_t offset, void *buffer, size_t size)
{
	enum ntfs_result result;

	if (!ntfs_bounds(offset, size, volume->info.size_bytes)) {
		return NTFS_CORRUPT;
	}
	if (size == 0) {
		return NTFS_OK;
	}
	result = ntfs_operation_read(volume, size);
	if (result != NTFS_OK) {
		return result;
	}
	volume->stats.read_calls++;
	volume->stats.read_bytes += size;
	return volume->env.read(volume->env.context, offset, buffer, size);
}

void
ntfs_default_limits(struct ntfs_limits *limits)
{
	limits->max_runs = NTFS_DEFAULT_MAX_RUNS;
	limits->max_attribute_list = NTFS_DEFAULT_MAX_ATTRIBUTE_LIST;
	limits->record_cache_entries = NTFS_DEFAULT_RECORD_CACHE_ENTRIES;
	limits->max_directory_nodes = NTFS_DEFAULT_MAX_DIRECTORY_NODES;
	limits->max_live_bytes = NTFS_DEFAULT_MAX_LIVE_BYTES;
	ntfs_operation_default_limits(&limits->operation);
}

const char *
ntfs_result_string(enum ntfs_result result)
{
	static const char *const names[] = {"success", "not NTFS", "corrupt metadata",
	    "unsupported format", "I/O error", "out of memory", "not found", "not a directory",
	    "is a directory", "invalid argument", "stale file reference", "resource limit",
	    "read-only filesystem", "volume requires Windows recovery", "end of directory",
	    "objects still open", "too many symbolic links", "insufficient free space",
	    "name already exists", "directory is not empty"};
	return (unsigned)result < sizeof(names) / sizeof(names[0]) ? names[result]
								   : "unknown error";
}

void
ntfs_decode_time(uint64_t ticks, struct ntfs_time *out)
{
	uint64_t delta;

	if (ticks >= NTFS_TIME_EPOCH) {
		delta = ticks - NTFS_TIME_EPOCH;
		out->seconds = (int64_t)(delta / NTFS_TIME_TICKS);
		out->nanoseconds =
		    (uint32_t)(delta % NTFS_TIME_TICKS) * NTFS_TIME_NANOSECONDS_PER_TICK;
	} else {
		delta = NTFS_TIME_EPOCH - ticks;
		out->seconds = -(int64_t)(delta / NTFS_TIME_TICKS);
		out->nanoseconds = 0;
		if (delta % NTFS_TIME_TICKS != 0) {
			out->seconds--;
			out->nanoseconds = (uint32_t)(NTFS_TIME_TICKS - delta % NTFS_TIME_TICKS) *
			    NTFS_TIME_NANOSECONDS_PER_TICK;
		}
	}
}
