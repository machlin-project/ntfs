/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "validate_internal.h"

static int ntfs_validation_compare_runs(
    struct ntfs_validation_context *validation, const void *a, const void *b);
static enum ntfs_result ntfs_validation_compare_mirror_record(
    struct ntfs_validation_context *validation, uint8_t *primary, uint8_t *mirror, bool allocated);

static int
ntfs_validation_compare_runs(
    struct ntfs_validation_context *validation, const void *left_input, const void *right_input)
{
	const struct ntfs_validation_run *left = left_input, *right = right_input;

	(void)validation;
	if (left->first != right->first) {
		return left->first < right->first ? -1 : 1;
	}
	return left->end < right->end ? -1 : left->end != right->end;
}

enum ntfs_result
ntfs_validation_scan_allocation(struct ntfs_validation_context *validation)
{
	struct ntfs_node *node = NULL;
	struct ntfs_stream *bitmap = NULL;
	uint8_t *bytes = NULL;
	const struct ntfs_validation_run *run;
	uint64_t count = validation->volume->info.cluster_count, bitmap_size, offset, cluster;
	uint32_t i, current = 0;
	size_t take, byte;
	unsigned bit;
	bool allocated, claimed;
	enum ntfs_result result;

	validation->report->stage = NTFS_VALIDATION_ALLOCATION;
	validation->report->reference = 0;
	validation->report->related_reference = 0;
	validation->report->attribute_type = NTFS_ATTRIBUTE_DATA;
	result = ntfs_validation_sort(validation, validation->runs, sizeof(*validation->runs),
	    validation->run_count, ntfs_validation_compare_runs);
	if (result != NTFS_OK) {
		return result;
	}
	for (i = 1; i < validation->run_count; i++) {
		if (validation->runs[i - 1].end > validation->runs[i].first) {
			validation->report->reference = validation->runs[i].reference;
			validation->report->record_number =
			    validation->runs[i].reference & NTFS_REFERENCE_RECORD_MASK;
			validation->report->related_reference = validation->runs[i - 1].reference;
			validation->report->attribute_type = validation->runs[i].type;
			validation->report->cluster = validation->runs[i].first;
			return NTFS_CORRUPT;
		}
	}
	bitmap_size = (count + NTFS_BITS_PER_BYTE - 1) / NTFS_BITS_PER_BYTE;
	validation->report->record_number = NTFS_BITMAP_RECORD;
	result = ntfs_node_by_number(validation->volume, NTFS_BITMAP_RECORD, &node);
	if (result == NTFS_OK) {
		result = ntfs_attribute_open(node, NTFS_ATTRIBUTE_DATA, NULL, 0, &bitmap);
	}
	if (result != NTFS_OK) {
		goto finish;
	}
	if (bitmap->flags != 0 || bitmap->size < bitmap_size || bitmap->initialized < bitmap_size) {
		result = NTFS_CORRUPT;
		goto finish;
	}
	bytes = ntfs_validation_allocate(validation, NTFS_BITMAP_SCAN_BYTES);
	if (bytes == NULL) {
		result = NTFS_NO_MEMORY;
		goto finish;
	}
	for (offset = 0; offset < bitmap_size; offset += take) {
		take = bitmap_size - offset < NTFS_BITMAP_SCAN_BYTES
		    ? (size_t)(bitmap_size - offset)
		    : NTFS_BITMAP_SCAN_BYTES;
		result = ntfs_validation_charge(validation, (uint64_t)take * NTFS_BITS_PER_BYTE);
		if (result == NTFS_OK) {
			result = ntfs_stream_exact(bitmap, offset, bytes, take);
		}
		if (result != NTFS_OK) {
			break;
		}
		for (byte = 0; byte < take; byte++) {
			for (bit = 0; bit < NTFS_BITS_PER_BYTE; bit++) {
				cluster = (offset + byte) * NTFS_BITS_PER_BYTE + bit;
				if (cluster >= count) {
					break;
				}
				while (current < validation->run_count &&
				    validation->runs[current].end <= cluster) {
					current++;
				}
				run = current < validation->run_count ? &validation->runs[current]
								      : NULL;
				claimed = run != NULL && run->first <= cluster;
				allocated = (bytes[byte] & (1u << bit)) != 0;
				if (allocated) {
					validation->report->allocated_clusters++;
					if (!claimed) {
						validation->report->unclaimed_clusters++;
						validation->report->cluster = cluster;
					}
				} else if (claimed) {
					validation->report->reference = run->reference;
					validation->report->record_number =
					    run->reference & NTFS_REFERENCE_RECORD_MASK;
					validation->report->attribute_type = run->type;
					validation->report->cluster = cluster;
					result = NTFS_CORRUPT;
					goto finish;
				}
			}
		}
	}
	if (result == NTFS_OK && validation->report->unclaimed_clusters != 0) {
		result = NTFS_CORRUPT;
	}
finish:
	ntfs_validation_release(validation, bytes, NTFS_BITMAP_SCAN_BYTES);
	ntfs_stream_close(bitmap);
	ntfs_node_close(node);
	return result;
}

static enum ntfs_result
ntfs_validation_compare_mirror_record(
    struct ntfs_validation_context *validation, uint8_t *primary, uint8_t *mirror, bool allocated)
{
	const struct ntfs_disk_record *header = (const void *)primary;
	size_t size = validation->volume->info.record_size, used, usa_start, usa_end;
	enum ntfs_result result;

	result = ntfs_validation_charge(validation, size);
	if (result != NTFS_OK) {
		return result;
	}
	if (!allocated) {
		/* Unallocated slots are opaque to the record inventory. Require an
		 * exact replica rather than interpreting stale free-record contents. */
		return ntfs_equal(primary, mirror, size) ? NTFS_OK : NTFS_CORRUPT;
	}
	result = ntfs_record_validate(primary, size);
	if (result == NTFS_OK) {
		result = ntfs_validation_charge(validation, size);
	}
	if (result == NTFS_OK) {
		result = ntfs_record_validate(mirror, size);
	}
	if (result != NTFS_OK) {
		return result;
	}
	used = ntfs_u32(header->used);
	usa_start = ntfs_u16(header->mst.usa_offset);
	usa_end = usa_start + (size_t)ntfs_u16(header->mst.usa_count) * NTFS_MST_WORD_BYTES;
	result = ntfs_validation_charge(validation, used);
	if (result != NTFS_OK) {
		return result;
	}
	/* Both copies have passed MST restoration. Compare the used logical body,
	 * including USA geometry in the header, but not protection counters/saved
	 * slack tails or bytes beyond the record's declared used span. */
	return ntfs_equal(primary, mirror, usa_start) &&
		ntfs_equal(primary + usa_end, mirror + usa_end, used - usa_end)
	    ? NTFS_OK
	    : NTFS_CORRUPT;
}

enum ntfs_result
ntfs_validation_scan_boot(struct ntfs_validation_context *validation)
{
	struct ntfs_volume *volume = validation->volume;
	struct ntfs_node *owner = NULL;
	struct ntfs_stream *boot = NULL;
	const struct ntfs_disk_record *header;
	uint8_t *primary = NULL, *copy = NULL;
	uint64_t backup = volume->info.size_bytes;
	size_t sector = volume->info.sector_size;
	enum ntfs_result result;

	validation->report->stage = NTFS_VALIDATION_BOOT;
	validation->report->record_number = NTFS_BOOT_RECORD;
	validation->report->reference = 0;
	validation->report->related_reference = 0;
	validation->report->attribute_type = NTFS_ATTRIBUTE_DATA;
	validation->report->cluster = 0;
	result = ntfs_node_by_number(volume, NTFS_BOOT_RECORD, &owner);
	if (result == NTFS_NOT_FOUND) {
		result = NTFS_CORRUPT;
	}
	if (result != NTFS_OK) {
		goto finish;
	}
	validation->report->reference = owner->reference;
	header = (const void *)owner->record;
	if (ntfs_u64(header->base_reference) != 0) {
		result = NTFS_CORRUPT;
		goto finish;
	}
	if (ntfs_u16(header->flags) != NTFS_RECORD_IN_USE) {
		result = NTFS_UNSUPPORTED;
		goto finish;
	}
	result = ntfs_stream_open(owner, NULL, 0, &boot);
	if (result == NTFS_NOT_FOUND) {
		result = NTFS_CORRUPT;
	}
	if (result != NTFS_OK) {
		goto finish;
	}
	if (boot->resident || boot->size < sector || boot->initialized < sector ||
	    boot->run_count == 0 || boot->runs[0].lcn != 0) {
		result = NTFS_CORRUPT;
		goto finish;
	}
	if (boot->flags != 0) {
		result = NTFS_UNSUPPORTED;
		goto finish;
	}
	/* The supported NTFS 3.x profile reserves a sector after the boot-declared
	 * data span. Its
	 * device-relative position does not move when a larger resource is supplied.
	 * It lies outside mounted stream I/O, so this private diagnostic checks the
	 * backing bounds and charges its exact callback directly to its own owner. */
	validation->report->cluster = backup / volume->info.cluster_size;
	if (!ntfs_bounds(backup, sector, validation->source.size_bytes)) {
		result = NTFS_CORRUPT;
		goto finish;
	}
	primary = ntfs_validation_allocate(validation, sector);
	copy = ntfs_validation_allocate(validation, sector);
	if (primary == NULL || copy == NULL) {
		result = NTFS_NO_MEMORY;
		goto finish;
	}
	validation->report->cluster = 0;
	result = ntfs_stream_exact(boot, 0, primary, sector);
	if (result == NTFS_OK) {
		validation->report->cluster = backup / volume->info.cluster_size;
		result = ntfs_validation_read(validation, backup, copy, sector);
	}
	if (result == NTFS_OK) {
		result = ntfs_validation_charge(validation, sector);
	}
	if (result == NTFS_OK && !ntfs_equal(primary, copy, sector)) {
		result = NTFS_CORRUPT;
	}
finish:
	ntfs_validation_release(validation, copy, sector);
	ntfs_validation_release(validation, primary, sector);
	ntfs_stream_close(boot);
	ntfs_node_close(owner);
	return result;
}

enum ntfs_result
ntfs_validation_scan_mirror(struct ntfs_validation_context *validation)
{
	struct ntfs_volume *volume = validation->volume;
	struct ntfs_node *owner = NULL;
	struct ntfs_stream *mirror = NULL;
	const struct ntfs_disk_record *header;
	const struct ntfs_run *run;
	uint8_t *primary = NULL, *copy = NULL;
	uint64_t required = (uint64_t)NTFS_MFT_MIRROR_REQUIRED_RECORDS * volume->info.record_size;
	uint64_t maximum, offset;
	uint32_t i;
	enum ntfs_result result;

	validation->report->stage = NTFS_VALIDATION_MIRROR;
	validation->report->record_number = NTFS_MFT_MIRROR_RECORD;
	validation->report->reference = 0;
	validation->report->related_reference = 0;
	validation->report->attribute_type = NTFS_ATTRIBUTE_DATA;
	validation->report->cluster = volume->mirror_lcn;
	result = ntfs_node_by_number(volume, NTFS_MFT_MIRROR_RECORD, &owner);
	if (result == NTFS_NOT_FOUND) {
		result = NTFS_CORRUPT;
	}
	if (result != NTFS_OK) {
		goto finish;
	}
	validation->report->reference = owner->reference;
	header = (const void *)owner->record;
	if (ntfs_u64(header->base_reference) != 0) {
		result = NTFS_CORRUPT;
		goto finish;
	}
	if (ntfs_u16(header->flags) != NTFS_RECORD_IN_USE) {
		result = NTFS_UNSUPPORTED;
		goto finish;
	}
	result = ntfs_stream_open(owner, NULL, 0, &mirror);
	if (result == NTFS_NOT_FOUND) {
		result = NTFS_CORRUPT;
	}
	if (result != NTFS_OK) {
		goto finish;
	}
	validation->report->mirror_record_slots = mirror->size / volume->info.record_size;
	maximum = required > volume->info.cluster_size ? required : volume->info.cluster_size;
	if (mirror->resident || mirror->size < required || mirror->initialized < required ||
	    mirror->size % volume->info.record_size != 0 || mirror->run_count == 0 ||
	    mirror->runs[0].lcn != volume->mirror_lcn ||
	    validation->report->record_slots < NTFS_MFT_MIRROR_REQUIRED_RECORDS) {
		result = NTFS_CORRUPT;
		goto finish;
	}
	if (mirror->flags != 0 || mirror->size > maximum) {
		result = NTFS_UNSUPPORTED;
		goto finish;
	}
	validation->report->mirror_unchecked_records =
	    validation->report->mirror_record_slots - NTFS_MFT_MIRROR_REQUIRED_RECORDS;
	primary = ntfs_validation_allocate(validation, volume->info.record_size);
	copy = ntfs_validation_allocate(validation, volume->info.record_size);
	if (primary == NULL || copy == NULL) {
		result = NTFS_NO_MEMORY;
		goto finish;
	}
	for (i = 0; i < NTFS_MFT_MIRROR_REQUIRED_RECORDS; i++) {
		offset = (uint64_t)i * volume->info.record_size;
		validation->report->record_number = i;
		validation->report->reference = validation->records[i].reference;
		validation->report->related_reference = owner->reference;
		run = ntfs_run_find(mirror, offset / volume->info.cluster_size);
		if (run == NULL || run->lcn == NTFS_HOLE) {
			result = NTFS_CORRUPT;
			break;
		}
		validation->report->cluster =
		    run->lcn + offset / volume->info.cluster_size - run->vcn;
		result = ntfs_stream_exact(volume->mft, offset, primary, volume->info.record_size);
		if (result == NTFS_OK) {
			result = ntfs_stream_exact(mirror, offset, copy, volume->info.record_size);
		}
		if (result == NTFS_OK) {
			result = ntfs_validation_compare_mirror_record(
			    validation, primary, copy, validation->records[i].reference != 0);
		}
		if (result != NTFS_OK) {
			break;
		}
		validation->report->mirror_records_compared++;
	}
finish:
	ntfs_validation_release(validation, copy, volume->info.record_size);
	ntfs_validation_release(validation, primary, volume->info.record_size);
	ntfs_stream_close(mirror);
	ntfs_node_close(owner);
	return result;
}
