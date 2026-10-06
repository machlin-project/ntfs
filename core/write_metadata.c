/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_internal.h"
#include <ntfs/record.h>

static bool
separate(const void *left, size_t left_bytes, const void *right, size_t right_bytes)
{
	uintptr_t a = (uintptr_t)left, b = (uintptr_t)right;

	if (left_bytes > UINTPTR_MAX - a || right_bytes > UINTPTR_MAX - b) {
		return false;
	}
	return a + left_bytes <= b || b + right_bytes <= a;
}

static enum ntfs_result
prepare(struct ntfs_node *node, uint64_t filetime, uint64_t lsn, struct ntfs_write_file_plan *out)
{
	struct ntfs_volume *volume = node->volume;
	struct ntfs_node *mft = NULL;
	struct ntfs_stream *stream = NULL;
	const struct ntfs_disk_record *header = (const void *)node->record;
	const struct ntfs_disk_record_extension *extension;
	struct ntfs_disk_record *after_header;
	struct ntfs_disk_standard *after_standard;
	struct ntfs_attr_view standard, listed;
	struct ntfs_stat stat;
	const struct ntfs_run *run;
	const uint8_t *body;
	uint64_t record_position, vcn, lcn, physical;
	size_t bytes, attribute_offset, value_offset;
	uint32_t used;
	enum ntfs_result result;

	if (filetime > INT64_MAX || lsn == 0) {
		return NTFS_INVALID;
	}
	if (volume->info.sector_size != NTFS_WRITE_SECTOR_BYTES ||
	    volume->info.cluster_size != NTFS_WRITE_CLUSTER_BYTES ||
	    volume->info.record_size != NTFS_WRITE_RECORD_BYTES ||
	    volume->info.major_version != NTFS_VOLUME_MAJOR_VERSION ||
	    volume->info.minor_version != NTFS_VOLUME_MAX_MINOR_VERSION) {
		return NTFS_UNSUPPORTED;
	}
	result = ntfs_node_stat(node, &stat);
	if (result != NTFS_OK) {
		return result;
	}
	if ((stat.reference & NTFS_REFERENCE_RECORD_MASK) < NTFS_FIRST_USER_RECORD ||
	    stat.directory || stat.reparse ||
	    (stat.file_attributes &
		(NTFS_FILE_READ_ONLY | NTFS_FILE_SYSTEM | NTFS_FILE_COMPRESSED |
		    NTFS_FILE_ENCRYPTED | NTFS_FILE_SPARSE)) != 0 ||
	    ntfs_u16(header->flags) != NTFS_RECORD_IN_USE ||
	    ntfs_u16(header->mst.usa_offset) !=
		sizeof(*header) + sizeof(struct ntfs_disk_record_extension) ||
	    ntfs_u16(header->mst.usa_count) != NTFS_WRITE_RECORD_BYTES / NTFS_MST_STRIDE + 1) {
		return NTFS_UNSUPPORTED;
	}
	if (lsn <= ntfs_u64(header->lsn)) {
		return NTFS_STALE;
	}
	used = ntfs_u32(header->used);
	extension = (const void *)(node->record + sizeof(*header));
	if (used > NTFS_WRITE_RECORD_BYTES || used % NTFS_WIRE_ALIGNMENT != 0 ||
	    ntfs_u32(extension->record_number) != (stat.reference & NTFS_REFERENCE_RECORD_MASK)) {
		return NTFS_CORRUPT;
	}
	result = ntfs_attr_find(
	    node->record, NTFS_WRITE_RECORD_BYTES, NTFS_ATTR_LIST, NULL, 0, UINT16_MAX, &listed);
	if (result != NTFS_NOT_FOUND) {
		return result == NTFS_OK ? NTFS_UNSUPPORTED : result;
	}
	result = ntfs_attr_find(node->record, NTFS_WRITE_RECORD_BYTES, NTFS_ATTR_STANDARD, NULL, 0,
	    UINT16_MAX, &standard);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_attr_value(&standard, &body, &bytes);
	if (result != NTFS_OK || standard.flags != 0 || bytes != NTFS_WRITE_STANDARD_BYTES) {
		return result == NTFS_OK ? NTFS_UNSUPPORTED : result;
	}
	result = ntfs_stream_open(node, NULL, 0, &stream);
	if (result != NTFS_OK) {
		return result;
	}
	if (stream->resident || stream->metadata_only || stream->wof != NULL ||
	    stream->flags != 0 || stream->compression_unit != 0) {
		ntfs_stream_close(stream);
		return NTFS_UNSUPPORTED;
	}
	ntfs_stream_close(stream);
	attribute_offset = (size_t)(standard.bytes - node->record);
	value_offset = (size_t)(body - standard.bytes);
	if (!ntfs_bounds(attribute_offset, standard.length, used) ||
	    !ntfs_bounds(value_offset, bytes, standard.length)) {
		return NTFS_CORRUPT;
	}
	record_position =
	    (stat.reference & NTFS_REFERENCE_RECORD_MASK) * (uint64_t)NTFS_WRITE_RECORD_BYTES;
	if (!ntfs_bounds(record_position, NTFS_WRITE_RECORD_BYTES, volume->mft->initialized)) {
		return NTFS_CORRUPT;
	}
	vcn = record_position / NTFS_WRITE_CLUSTER_BYTES;
	run = ntfs_run_find(volume->mft, vcn);
	if (run == NULL || run->lcn == NTFS_HOLE || vcn < run->vcn ||
	    vcn - run->vcn >= run->length || run->lcn > UINT64_MAX - (vcn - run->vcn)) {
		return NTFS_CORRUPT;
	}
	lcn = run->lcn + vcn - run->vcn;
	if (lcn >= volume->info.cluster_count || lcn > UINT64_MAX / NTFS_WRITE_CLUSTER_BYTES) {
		return NTFS_CORRUPT;
	}
	physical = lcn * NTFS_WRITE_CLUSTER_BYTES;
	if (!ntfs_bounds(physical, NTFS_WRITE_CLUSTER_BYTES, volume->info.size_bytes)) {
		return NTFS_CORRUPT;
	}
	result = ntfs_node_by_number(volume, NTFS_MFT_RECORD, &mft);
	if (result != NTFS_OK) {
		return result;
	}
	if (mft->reference != UINT64_C(1) << NTFS_REFERENCE_SEQUENCE_SHIFT) {
		ntfs_node_close(mft);
		return NTFS_UNSUPPORTED;
	}
	result = ntfs_work(volume, sizeof(*out));
	if (result != NTFS_OK) {
		ntfs_node_close(mft);
		return result;
	}
	out->reference = stat.reference;
	out->mft_reference = mft->reference;
	ntfs_node_close(mft);
	out->target_vcn = vcn;
	out->target_lcn = lcn;
	out->cluster_physical = physical;
	out->cluster_index =
	    (uint16_t)(record_position % NTFS_WRITE_CLUSTER_BYTES / NTFS_WRITE_SECTOR_BYTES);
	out->record_offset = (uint16_t)attribute_offset;
	out->attribute_offset =
	    (uint16_t)(value_offset + offsetof(struct ntfs_disk_standard, modified));
	out->change_bytes =
	    NTFS_WRITE_STANDARD_BYTES - offsetof(struct ntfs_disk_standard, modified);
	out->snapshot_bytes = (uint16_t)used;
	ntfs_copy(out->before, node->record, NTFS_WRITE_RECORD_BYTES);
	ntfs_copy(out->after, node->record, NTFS_WRITE_RECORD_BYTES);
	after_header = (void *)out->after;
	after_standard = (void *)(out->after + attribute_offset + value_offset);
	ntfs_put_u64(after_header->lsn, lsn);
	ntfs_put_u64(after_standard->modified, filetime);
	ntfs_put_u64(after_standard->changed, filetime);
	ntfs_put_u32(
	    after_standard->attributes, ntfs_u32(after_standard->attributes) | NTFS_FILE_ARCHIVE);
	return ntfs_record_protect(out->after, NTFS_WRITE_RECORD_BYTES, out->protected_after,
	    sizeof(out->protected_after));
}

enum ntfs_result
ntfs_write_prepare_metadata(
    struct ntfs_node *node, uint64_t filetime, uint64_t lsn, struct ntfs_write_file_plan *out)
{
	enum ntfs_result result;

	if (node == NULL || out == NULL || !separate(node, sizeof(*node), out, sizeof(*out)) ||
	    !separate(node->volume, sizeof(*node->volume), out, sizeof(*out)) ||
	    !separate(node->record, node->volume->info.record_size, out, sizeof(*out))) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	result = ntfs_operation_enter(node->volume);
	if (result == NTFS_OK) {
		result = prepare(node, filetime, lsn, out);
		ntfs_operation_leave(node->volume);
	}
	if (result != NTFS_OK) {
		ntfs_zero(out, sizeof(*out));
	}
	return result;
}
