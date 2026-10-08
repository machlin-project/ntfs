/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"

/* Public owning boundaries share one active execution budget. Cleanup and
 * fixed-size immutable getters require no admission or new resources. */

enum ntfs_result
ntfs_count_free_clusters(struct ntfs_volume *volume, uint64_t *out)
{
	struct ntfs_volume *owner = volume;
	enum ntfs_result result;

	if (out != NULL) {
		*out = 0;
	}
	if (out == NULL) {
		return NTFS_INVALID;
	}
	result = ntfs_operation_enter(owner);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_count_free_clusters_impl(volume, out);
	ntfs_operation_leave(owner);
	return result;
}

enum ntfs_result
ntfs_node_open(struct ntfs_volume *volume, uint64_t reference, struct ntfs_node **out)
{
	struct ntfs_volume *owner = volume;
	enum ntfs_result result;

	if (out != NULL) {
		*out = NULL;
	}
	if (out == NULL) {
		return NTFS_INVALID;
	}
	result = ntfs_operation_enter(owner);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_node_open_impl(volume, reference, out);
	ntfs_operation_leave(owner);
	return result;
}

enum ntfs_result
ntfs_root(struct ntfs_volume *volume, struct ntfs_node **out)
{
	struct ntfs_volume *owner = volume;
	enum ntfs_result result;

	if (out != NULL) {
		*out = NULL;
	}
	if (out == NULL) {
		return NTFS_INVALID;
	}
	result = ntfs_operation_enter(owner);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_root_impl(volume, out);
	ntfs_operation_leave(owner);
	return result;
}

enum ntfs_result
ntfs_node_metadata(struct ntfs_node *node, struct ntfs_stat *out)
{
	struct ntfs_volume *owner = node == NULL ? NULL : node->volume;
	enum ntfs_result result;

	if (out != NULL) {
		ntfs_zero(out, sizeof(*out));
	}
	if (out == NULL) {
		return NTFS_INVALID;
	}
	result = ntfs_operation_enter(owner);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_node_metadata_impl(node, out);
	if (result != NTFS_OK) {
		ntfs_zero(out, sizeof(*out));
	}
	ntfs_operation_leave(owner);
	return result;
}

enum ntfs_result
ntfs_node_stat(struct ntfs_node *node, struct ntfs_stat *out)
{
	struct ntfs_volume *owner = node == NULL ? NULL : node->volume;
	enum ntfs_result result;

	if (out != NULL) {
		ntfs_zero(out, sizeof(*out));
	}
	if (out == NULL) {
		return NTFS_INVALID;
	}
	result = ntfs_operation_enter(owner);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_node_stat_impl(node, out);
	if (result != NTFS_OK) {
		ntfs_zero(out, sizeof(*out));
	}
	ntfs_operation_leave(owner);
	return result;
}

enum ntfs_result
ntfs_node_link_counts(struct ntfs_node *node, struct ntfs_link_counts *out)
{
	struct ntfs_volume *owner = node == NULL ? NULL : node->volume;
	enum ntfs_result result;

	if (out != NULL) {
		ntfs_zero(out, sizeof(*out));
	}
	if (out == NULL) {
		return NTFS_INVALID;
	}
	result = ntfs_operation_enter(owner);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_node_link_counts_impl(node, out);
	if (result != NTFS_OK) {
		ntfs_zero(out, sizeof(*out));
	}
	ntfs_operation_leave(owner);
	return result;
}

enum ntfs_result
ntfs_stream_open(
    struct ntfs_node *node, const uint16_t *name, size_t length, struct ntfs_stream **out)
{
	struct ntfs_volume *owner = node == NULL ? NULL : node->volume;
	enum ntfs_result result;

	if (out != NULL) {
		*out = NULL;
	}
	if (out == NULL) {
		return NTFS_INVALID;
	}
	result = ntfs_operation_enter(owner);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_stream_open_impl(node, name, length, out);
	ntfs_operation_leave(owner);
	return result;
}

enum ntfs_result
ntfs_stream_read(
    struct ntfs_stream *stream, uint64_t offset, void *bytes, size_t length, size_t *out)
{
	struct ntfs_volume *owner = stream == NULL ? NULL : stream->volume;
	enum ntfs_result result;

	if (out != NULL) {
		*out = 0;
	}
	if (out == NULL) {
		return NTFS_INVALID;
	}
	result = ntfs_operation_enter(owner);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_stream_read_impl(stream, offset, bytes, length, out);
	ntfs_operation_leave(owner);
	return result;
}

enum ntfs_result
ntfs_directory_open(struct ntfs_node *node, struct ntfs_directory **out)
{
	struct ntfs_volume *owner = node == NULL ? NULL : node->volume;
	enum ntfs_result result;

	if (out != NULL) {
		*out = NULL;
	}
	if (out == NULL) {
		return NTFS_INVALID;
	}
	result = ntfs_operation_enter(owner);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_directory_open_impl(node, out);
	ntfs_operation_leave(owner);
	return result;
}

enum ntfs_result
ntfs_directory_next(struct ntfs_directory *directory, struct ntfs_dirent *out)
{
	struct ntfs_volume *owner = ntfs_directory_volume(directory);
	enum ntfs_result result;

	if (out != NULL) {
		ntfs_zero(out, sizeof(*out));
	}
	if (out == NULL) {
		return NTFS_INVALID;
	}
	result = ntfs_operation_enter(owner);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_directory_next_impl(directory, out);
	ntfs_operation_leave(owner);
	return result;
}

enum ntfs_result
ntfs_lookup_entry(struct ntfs_node *node, const uint16_t *name, size_t length,
    struct ntfs_node **out, struct ntfs_dirent *entry)
{
	struct ntfs_volume *owner = node == NULL ? NULL : node->volume;
	enum ntfs_result result;

	if (out != NULL) {
		*out = NULL;
	}
	if (entry != NULL) {
		ntfs_zero(entry, sizeof(*entry));
	}
	if (out == NULL) {
		return NTFS_INVALID;
	}
	result = ntfs_operation_enter(owner);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_lookup_entry_impl(node, name, length, out, entry);
	ntfs_operation_leave(owner);
	return result;
}

enum ntfs_result
ntfs_lookup(struct ntfs_node *node, const uint16_t *name, size_t length, struct ntfs_node **out)
{
	struct ntfs_volume *owner = node == NULL ? NULL : node->volume;
	enum ntfs_result result;

	if (out != NULL) {
		*out = NULL;
	}
	if (out == NULL) {
		return NTFS_INVALID;
	}
	result = ntfs_operation_enter(owner);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_lookup_impl(node, name, length, out);
	ntfs_operation_leave(owner);
	return result;
}

enum ntfs_result
ntfs_stream_catalog_open(struct ntfs_node *node, uint32_t maximum, struct ntfs_stream_catalog **out)
{
	struct ntfs_volume *owner = node == NULL ? NULL : node->volume;
	enum ntfs_result result;

	if (out != NULL) {
		*out = NULL;
	}
	if (out == NULL) {
		return NTFS_INVALID;
	}
	result = ntfs_operation_enter(owner);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_stream_catalog_open_impl(node, maximum, out);
	ntfs_operation_leave(owner);
	return result;
}

enum ntfs_result
ntfs_stream_catalog_entry(
    const struct ntfs_stream_catalog *catalog, uint32_t index, struct ntfs_stream_name *out)
{
	struct ntfs_volume *owner = ntfs_catalog_volume(catalog);
	enum ntfs_result result;

	if (out != NULL) {
		ntfs_zero(out, sizeof(*out));
	}
	if (out == NULL) {
		return NTFS_INVALID;
	}
	result = ntfs_operation_enter(owner);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_stream_catalog_entry_impl(catalog, index, out);
	ntfs_operation_leave(owner);
	return result;
}

enum ntfs_result
ntfs_reparse_open(struct ntfs_node *node, struct ntfs_reparse **out)
{
	struct ntfs_volume *owner = node == NULL ? NULL : node->volume;
	enum ntfs_result result;

	if (out != NULL) {
		*out = NULL;
	}
	if (out == NULL) {
		return NTFS_INVALID;
	}
	result = ntfs_operation_enter(owner);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_reparse_open_impl(node, out);
	ntfs_operation_leave(owner);
	return result;
}

enum ntfs_result
ntfs_reparse_bytes(const struct ntfs_reparse *snapshot, void *bytes, size_t capacity, size_t *out)
{
	struct ntfs_volume *owner = ntfs_reparse_volume(snapshot);
	enum ntfs_result result;

	if (out != NULL) {
		*out = 0;
	}
	if (out == NULL) {
		return NTFS_INVALID;
	}
	result = ntfs_operation_enter(owner);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_reparse_bytes_impl(snapshot, bytes, capacity, out);
	ntfs_operation_leave(owner);
	return result;
}

enum ntfs_result
ntfs_reparse_name(const struct ntfs_reparse *snapshot, enum ntfs_reparse_name_type type,
    uint16_t *units, size_t capacity, size_t *out)
{
	struct ntfs_volume *owner = ntfs_reparse_volume(snapshot);
	enum ntfs_result result;

	if (out != NULL) {
		*out = 0;
	}
	if (out == NULL) {
		return NTFS_INVALID;
	}
	result = ntfs_operation_enter(owner);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_reparse_name_impl(snapshot, type, units, capacity, out);
	ntfs_operation_leave(owner);
	return result;
}

enum ntfs_result
ntfs_security_resolve(struct ntfs_volume *volume, uint32_t security_id, struct ntfs_security **out)
{
	struct ntfs_volume *owner = volume;
	enum ntfs_result result;

	if (out != NULL) {
		*out = NULL;
	}
	if (out == NULL) {
		return NTFS_INVALID;
	}
	result = ntfs_operation_enter(owner);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_security_resolve_impl(volume, security_id, out);
	ntfs_operation_leave(owner);
	return result;
}

enum ntfs_result
ntfs_security_open(struct ntfs_node *node, struct ntfs_security **out)
{
	struct ntfs_volume *owner = node == NULL ? NULL : node->volume;
	enum ntfs_result result;

	if (out != NULL) {
		*out = NULL;
	}
	if (out == NULL) {
		return NTFS_INVALID;
	}
	result = ntfs_operation_enter(owner);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_security_open_impl(node, out);
	ntfs_operation_leave(owner);
	return result;
}

enum ntfs_result
ntfs_security_copy(const struct ntfs_security *snapshot, void *bytes, size_t capacity, size_t *out)
{
	struct ntfs_volume *owner = ntfs_security_volume(snapshot);
	enum ntfs_result result;

	if (out != NULL) {
		*out = 0;
	}
	if (out == NULL) {
		return NTFS_INVALID;
	}
	result = ntfs_operation_enter(owner);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_security_copy_impl(snapshot, bytes, capacity, out);
	ntfs_operation_leave(owner);
	return result;
}

enum ntfs_result
ntfs_security_store_validate(struct ntfs_volume *volume,
    const struct ntfs_security_store_limits *limits, struct ntfs_security_store_report *report)
{
	enum ntfs_result result;

	if (report == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(report, sizeof(*report));
	report->result = NTFS_INVALID;
	if (volume == NULL ||
	    (limits != NULL &&
		(limits->max_descriptors == 0 ||
		    limits->max_descriptors > NTFS_SECURITY_STORE_MAX_DESCRIPTORS))) {
		return NTFS_INVALID;
	}
	result = ntfs_operation_enter(volume);
	if (result != NTFS_OK) {
		report->result = result;
		return result;
	}
	result = ntfs_security_store_validate_impl(volume, limits, report, NULL, NULL, NULL);
	ntfs_operation_leave(volume);
	return result;
}

enum ntfs_result
ntfs_security_evaluate_dacl(const struct ntfs_security *snapshot,
    const struct ntfs_access_token *token, uint32_t desired, const struct ntfs_dacl_limits *limits,
    struct ntfs_dacl_decision *out)
{
	struct ntfs_volume *owner = ntfs_security_volume(snapshot);
	enum ntfs_result result;

	if (out != NULL) {
		ntfs_zero(out, sizeof(*out));
	}
	if (out == NULL) {
		return NTFS_INVALID;
	}
	result = ntfs_operation_enter(owner);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_security_evaluate_dacl_impl(snapshot, token, desired, limits, out);
	ntfs_operation_leave(owner);
	return result;
}

enum ntfs_result
ntfs_logfile_open_volume(struct ntfs_volume *volume, const struct ntfs_logfile_limits *limits,
    struct ntfs_logfile_report *report, struct ntfs_logfile **out)
{
	struct ntfs_volume *owner = volume;
	enum ntfs_result result;

	if (out != NULL) {
		*out = NULL;
	}
	if (report != NULL) {
		ntfs_zero(report, sizeof(*report));
		report->selected_probe = NTFS_LOGFILE_NO_PROBE;
	}
	if (out == NULL) {
		return NTFS_INVALID;
	}
	result = ntfs_operation_enter(owner);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_logfile_open_volume_impl(volume, limits, report, out);
	ntfs_operation_leave(owner);
	return result;
}
