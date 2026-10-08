/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"

enum ntfs_result
ntfs_node_by_number(struct ntfs_volume *volume, uint64_t number, struct ntfs_node **out)
{
	struct ntfs_node *node;
	const struct ntfs_disk_record *header;
	enum ntfs_result result;

	*out = NULL;
	if (volume->children == UINT32_MAX) {
		return NTFS_RANGE;
	}
	node = ntfs_alloc(volume, sizeof(*node));
	if (node == NULL) {
		return NTFS_NO_MEMORY;
	}
	node->volume = volume;
	result = ntfs_record_read(volume, number, &node->record);
	if (result != NTFS_OK) {
		ntfs_free(volume, node, sizeof(*node));
		return result;
	}
	header = (const void *)node->record;
	if (ntfs_u64(header->base_reference) != 0) {
		ntfs_free(volume, node->record, volume->info.record_size);
		ntfs_free(volume, node, sizeof(*node));
		return NTFS_CORRUPT;
	}
	node->reference =
	    number | (uint64_t)ntfs_u16(header->sequence) << NTFS_REFERENCE_SEQUENCE_SHIFT;
	volume->children++;
	*out = node;
	return NTFS_OK;
}

enum ntfs_result
ntfs_node_open_impl(struct ntfs_volume *volume, uint64_t reference, struct ntfs_node **out)
{
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	*out = NULL;
	if (volume == NULL || reference >> NTFS_REFERENCE_SEQUENCE_SHIFT == 0) {
		return NTFS_INVALID;
	}
	result = ntfs_node_by_number(volume, reference & NTFS_REFERENCE_RECORD_MASK, out);
	if (result == NTFS_OK && (*out)->reference != reference) {
		ntfs_node_close(*out);
		*out = NULL;
		return NTFS_STALE;
	}
	return result;
}

enum ntfs_result
ntfs_root_impl(struct ntfs_volume *volume, struct ntfs_node **out)
{
	if (volume == NULL || out == NULL) {
		return NTFS_INVALID;
	}
	return ntfs_node_by_number(volume, NTFS_ROOT_RECORD, out);
}

void
ntfs_node_close(struct ntfs_node *node)
{
	struct ntfs_volume *volume;

	if (node == NULL) {
		return;
	}
	volume = node->volume;
	volume->children--;
	ntfs_free(volume, node->record, volume->info.record_size);
	ntfs_free(volume, node, sizeof(*node));
}

enum ntfs_result
ntfs_node_metadata_impl(struct ntfs_node *node, struct ntfs_stat *stat)
{
	struct ntfs_volume *volume;
	struct ntfs_stat *cached = NULL;
	const struct ntfs_disk_record *record_header;
	const struct ntfs_disk_standard *standard_information;
	const struct ntfs_disk_standard_policy *policy;
	const struct ntfs_disk_standard_extension *extended;
	struct ntfs_attr_view attribute_view;
	const uint8_t *value;
	size_t length;
	uint32_t cache_index;
	bool reparse_present;
	enum ntfs_result result;

	if (node == NULL || stat == NULL) {
		return NTFS_INVALID;
	}
	result = ntfs_work(
	    node->volume, node->metadata_verified ? sizeof(*stat) : node->volume->info.record_size);
	if (result != NTFS_OK) {
		return result;
	}
	if (node->metadata_verified) {
		*stat = node->metadata;
		return NTFS_OK;
	}
	volume = node->volume;
	record_header = (const void *)node->record;
	if (volume->cache != NULL) {
		/* Direct mapping bounds lookup without scanning the record cache.
		 * Raw record and filename-count replacement use independent keys. */
		cache_index = (node->reference & NTFS_REFERENCE_RECORD_MASK) %
		    volume->limits.record_cache_entries;
		cached = &volume->cache[cache_index].metadata;
		result = ntfs_work(volume, sizeof(*cached));
		if (result != NTFS_OK) {
			return result;
		}
		if (cached->reference == node->reference) {
			if (cached->links != ntfs_u16(record_header->links) ||
			    cached->directory !=
				((ntfs_u16(record_header->flags) & NTFS_RECORD_DIRECTORY) != 0)) {
				return NTFS_CORRUPT;
			}
			*stat = *cached;
			goto verified;
		}
		/* Reserve publication work before cold I/O; failures publish nothing. */
		result = ntfs_work(volume, sizeof(*cached));
		if (result != NTFS_OK) {
			return result;
		}
	}
	ntfs_zero(stat, sizeof(*stat));
	stat->reference = node->reference;
	stat->links = ntfs_u16(record_header->links);
	stat->directory = (ntfs_u16(record_header->flags) & NTFS_RECORD_DIRECTORY) != 0;
	result = ntfs_attr_find(node->record, node->volume->info.record_size, NTFS_ATTR_STANDARD,
	    NULL, 0, UINT16_MAX, &attribute_view);
	if (result != NTFS_OK) {
		return result == NTFS_NOT_FOUND ? NTFS_CORRUPT : result;
	}
	result = ntfs_attr_value(&attribute_view, &value, &length);
	if (result != NTFS_OK || attribute_view.flags != 0 ||
	    length < sizeof(*standard_information) ||
	    (length > sizeof(*standard_information) &&
		length < sizeof(*standard_information) + sizeof(*extended))) {
		return NTFS_CORRUPT;
	}
	standard_information = (const void *)value;
	/* Modern Windows uses the low version byte as the directory case flag
	 * when version numbering is disabled. The remaining bytes are storage
	 * hints, not case flags. Legacy version numbers do not select this policy. */
	if (stat->directory && ntfs_u32(standard_information->max_versions) == 0) {
		policy = (const void *)standard_information->version;
		if (policy->directory_flags != NTFS_STANDARD_DIRECTORY_CASE_INSENSITIVE &&
		    policy->directory_flags != NTFS_STANDARD_DIRECTORY_CASE_SENSITIVE) {
			return NTFS_UNSUPPORTED;
		}
		stat->case_sensitive =
		    policy->directory_flags == NTFS_STANDARD_DIRECTORY_CASE_SENSITIVE;
	}
	stat->file_attributes = ntfs_u32(standard_information->attributes);
	stat->reparse = (stat->file_attributes & NTFS_FILE_REPARSE) != 0;
	ntfs_decode_time(ntfs_u64(standard_information->created), &stat->created);
	ntfs_decode_time(ntfs_u64(standard_information->modified), &stat->modified);
	ntfs_decode_time(ntfs_u64(standard_information->changed), &stat->changed);
	ntfs_decode_time(ntfs_u64(standard_information->accessed), &stat->accessed);
	if (length >= sizeof(*standard_information) + sizeof(*extended)) {
		extended = (const void *)(value + sizeof(*standard_information));
		stat->security_id = ntfs_u32(extended->security_id);
	}
	if (!stat->reparse) {
		/* A cleared standard-information flag cannot turn filter-owned data
		 * into an ordinary file. This also searches attribute-list extensions. */
		result = ntfs_attribute_type_present(
		    node, NTFS_ATTRIBUTE_REPARSE_POINT, &reparse_present);
		if (result != NTFS_OK) {
			return result;
		}
		if (reparse_present) {
			return NTFS_CORRUPT;
		}
	}
	if (cached != NULL) {
		*cached = *stat;
	}
verified:
	node->metadata = *stat;
	node->metadata_verified = true;
	return NTFS_OK;
}

enum ntfs_result
ntfs_node_stat_impl(struct ntfs_node *node, struct ntfs_stat *stat)
{
	enum ntfs_result result;

	result = ntfs_node_metadata(node, stat);
	if (result != NTFS_OK) {
		return result;
	}
	if (stat->reparse) {
		result = ntfs_wof_sizes(node, &stat->size, &stat->allocated_size);
		return result == NTFS_NOT_FOUND ? NTFS_OK : result;
	}
	if (stat->directory) {
		return NTFS_OK;
	}
	/* NTFS sizes describe the unnamed stream independently of our ability
	 * to decrypt or decode its content. Validate its complete mapping first. */
	return ntfs_attribute_sizes(node, &stat->size, &stat->allocated_size);
}
