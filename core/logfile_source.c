/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "logfile_source_internal.h"

static bool ntfs_logfile_valid_limits(const struct ntfs_logfile_limits *limits);
static bool ntfs_logfile_same_geometry(
    const struct ntfs_logfile_restart *a, const struct ntfs_logfile_restart *b);
static enum ntfs_result ntfs_logfile_probe_restart(
    struct ntfs_logfile *source, struct ntfs_logfile_probe *probe);
static enum ntfs_result ntfs_logfile_retained_hint_difference(const struct ntfs_logfile_restart *a,
    const uint8_t *left, const struct ntfs_logfile_restart *b, const uint8_t *right);
static enum ntfs_result ntfs_logfile_discover(struct ntfs_logfile *source, bool retained_roots);
static enum ntfs_result ntfs_logfile_volume_read(
    void *context, uint64_t offset, void *bytes, size_t size);
static void *ntfs_logfile_volume_allocate(void *context, size_t size);
static void ntfs_logfile_volume_release(void *context, void *bytes, size_t size);
static void *ntfs_logfile_recovery_volume_allocate(void *context, size_t size);
static void ntfs_logfile_recovery_volume_release(void *context, void *bytes, size_t size);
static enum ntfs_result ntfs_logfile_acquire_volume(struct ntfs_volume *volume,
    const struct ntfs_logfile_limits *limits, struct ntfs_logfile_report *report,
    struct ntfs_logfile **out, bool retained_roots);
static enum ntfs_result ntfs_logfile_source_open(const struct ntfs_environment *environment,
    const struct ntfs_logfile_limits *requested, struct ntfs_logfile_report *report,
    struct ntfs_logfile **out, bool retained_roots);

void
ntfs_logfile_default_limits(struct ntfs_logfile_limits *limits)
{
	if (limits != NULL) {
		*limits = (struct ntfs_logfile_limits){NTFS_LOGFILE_MAX_PAGE_BYTES,
		    NTFS_LOGFILE_DEFAULT_READ_CALLS, NTFS_LOGFILE_DEFAULT_READ_BYTES};
	}
}

static bool
ntfs_logfile_valid_limits(const struct ntfs_logfile_limits *limits)
{
	return limits->max_page_bytes >= NTFS_MST_STRIDE &&
	    limits->max_page_bytes <= NTFS_LOGFILE_MAX_PAGE_BYTES &&
	    (limits->max_page_bytes & (limits->max_page_bytes - 1u)) == 0 &&
	    limits->max_read_calls != 0 && limits->max_read_bytes != 0;
}

enum ntfs_result
ntfs_logfile_source_read(struct ntfs_logfile *source, uint64_t offset, void *buffer, size_t size,
    struct ntfs_logfile_report *work)
{
	enum ntfs_result result;

	if (!ntfs_bounds(offset, size, source->environment.size_bytes)) {
		return NTFS_NOT_FOUND;
	}
	if (work->read_calls >= source->limits.max_read_calls ||
	    size > source->limits.max_read_bytes - work->read_bytes) {
		return NTFS_RANGE;
	}
	work->read_calls++;
	work->read_bytes += size;
	result = source->environment.read(source->environment.context, offset, buffer, size);
	source->backend_failed = result != NTFS_OK;
	return result;
}

static bool
ntfs_logfile_same_geometry(
    const struct ntfs_logfile_restart *a, const struct ntfs_logfile_restart *b)
{
	return a->major == b->major && a->minor == b->minor &&
	    a->system_page_bytes == b->system_page_bytes &&
	    a->log_page_bytes == b->log_page_bytes && a->file_bytes == b->file_bytes &&
	    a->usable_bytes == b->usable_bytes && a->circular_offset == b->circular_offset &&
	    a->sequence_bits == b->sequence_bits &&
	    a->record_header_bytes == b->record_header_bytes &&
	    a->page_data_offset == b->page_data_offset;
}

static enum ntfs_result
ntfs_logfile_probe_restart(struct ntfs_logfile *source, struct ntfs_logfile_probe *probe)
{
	struct ntfs_disk_log_restart_page prefix;
	const struct ntfs_disk_log_restart_page *header;
	enum ntfs_result result;

	result = ntfs_logfile_source_read(
	    source, probe->offset, &prefix, sizeof(prefix), &source->report);
	if (result != NTFS_OK) {
		return result;
	}
	if (!ntfs_equal(prefix.mst.magic, "RSTR", sizeof(prefix.mst.magic)) &&
	    !ntfs_equal(prefix.mst.magic, "CHKD", sizeof(prefix.mst.magic))) {
		return NTFS_NOT_FOUND;
	}
	probe->page_bytes = ntfs_u32(prefix.system_page_bytes);
	/* Do not presume the integrity scheme or layout of another version. */
	if (ntfs_equal(prefix.mst.magic, "CHKD", sizeof(prefix.mst.magic)) ||
	    !((ntfs_u16(prefix.major) == NTFS_LFS_MAJOR_LEGACY &&
		  ntfs_u16(prefix.minor) == NTFS_LFS_MINOR_LEGACY) ||
		(ntfs_u16(prefix.major) == NTFS_LFS_MAJOR_FAST &&
		    ntfs_u16(prefix.minor) == NTFS_LFS_MINOR_FAST))) {
		return NTFS_UNSUPPORTED;
	}
	if (probe->page_bytes < NTFS_MST_STRIDE ||
	    (probe->page_bytes & (probe->page_bytes - 1u)) != 0 ||
	    (probe->offset != 0 && probe->offset != probe->page_bytes)) {
		return NTFS_CORRUPT;
	}
	if (probe->page_bytes > NTFS_LOGFILE_MAX_PAGE_BYTES) {
		return NTFS_UNSUPPORTED;
	}
	if (probe->page_bytes > source->limits.max_page_bytes) {
		return NTFS_RANGE;
	}
	result = ntfs_logfile_source_read(
	    source, probe->offset, source->raw, probe->page_bytes, &source->report);
	if (result != NTFS_OK) {
		return result;
	}
	header = (const void *)source->raw;
	if (!ntfs_equal(header, &prefix, sizeof(prefix))) {
		return NTFS_CORRUPT;
	}
	result = ntfs_logfile_restart_decode(source->raw, probe->page_bytes,
	    source->environment.size_bytes, source->scratch, source->limits.max_page_bytes,
	    &probe->restart);
	if (result == NTFS_OK && probe->restart.log_page_bytes > source->limits.max_page_bytes) {
		ntfs_zero(&probe->restart, sizeof(probe->restart));
		return NTFS_RANGE;
	}
	return result;
}

static enum ntfs_result
ntfs_logfile_retained_hint_difference(const struct ntfs_logfile_restart *a, const uint8_t *left,
    const struct ntfs_logfile_restart *b, const uint8_t *right)
{
	size_t flags = offsetof(struct ntfs_disk_log_restart_area, flags);
	size_t end = flags + sizeof(((struct ntfs_disk_log_restart_area *)0)->flags);

	if (a->major != NTFS_LFS_MAJOR_LEGACY || a->minor != NTFS_LFS_MINOR_LEGACY ||
	    a->system_page_bytes != NTFS_LFS_FAST_PAGE_BYTES ||
	    a->log_page_bytes != NTFS_LFS_FAST_PAGE_BYTES ||
	    a->record_header_bytes != sizeof(struct ntfs_disk_log_record) ||
	    a->page_data_offset != sizeof(struct ntfs_disk_log_fast_page) || a->client_count != 1 ||
	    a->in_use_head != 0 || a->free_head != NTFS_LOGFILE_NO_CLIENT ||
	    b->client_count != a->client_count || b->in_use_head != a->in_use_head ||
	    b->free_head != a->free_head || a->area.length != b->area.length ||
	    a->area.length < end || a->flags == b->flags ||
	    (a->flags != 0 && a->flags != NTFS_LOGFILE_RESTART_CLEAN) ||
	    (b->flags != 0 && b->flags != NTFS_LOGFILE_RESTART_CLEAN)) {
		return NTFS_UNSUPPORTED;
	}
	return ntfs_equal(left + a->area.offset, right + b->area.offset, flags) &&
		ntfs_equal(
		    left + a->area.offset + end, right + b->area.offset + end, a->area.length - end)
	    ? NTFS_OK
	    : NTFS_UNSUPPORTED;
}

static enum ntfs_result
ntfs_logfile_discover(struct ntfs_logfile *source, bool retained_roots)
{
	struct ntfs_logfile_probe *probe;
	struct ntfs_logfile_restart *selected = &source->restart;
	uint64_t offset = 0;
	uint16_t index;
	bool unsupported = false, conflict = false, select_dirty;
	enum ntfs_result result;

	for (index = 0; index < NTFS_LOGFILE_RESTART_PROBES; index++) {
		probe = &source->report.probes[index];
		probe->offset = offset;
		probe->result = ntfs_logfile_probe_restart(source, probe);
		source->report.probe_count++;
		result = probe->result;
		if (source->backend_failed || result == NTFS_RANGE ||
		    (result != NTFS_OK && result != NTFS_CORRUPT && result != NTFS_UNSUPPORTED &&
			result != NTFS_NOT_FOUND)) {
			return result;
		}
		unsupported |= result == NTFS_UNSUPPORTED;
		if (result == NTFS_OK) {
			select_dirty = false;
			if (source->report.selected_probe == NTFS_LOGFILE_NO_PROBE) {
				source->report.selection = NTFS_LOGFILE_SINGLE_COPY;
			} else if (!ntfs_logfile_same_geometry(selected, &probe->restart)) {
				conflict = true;
			} else if (selected->current_lsn == probe->restart.current_lsn) {
				if (selected->area.length != probe->restart.area.length ||
				    !ntfs_equal(source->selected + selected->area.offset,
					source->scratch + probe->restart.area.offset,
					selected->area.length)) {
					if (retained_roots &&
					    ntfs_logfile_retained_hint_difference(selected,
						source->selected, &probe->restart,
						source->scratch) == NTFS_OK) {
						/* Retain the observable copy conflict and select an
						 * actual dirty snapshot; no source flag is altered.
						 */
						source->report.selection = NTFS_LOGFILE_CONFLICT;
						select_dirty = probe->restart.flags == 0;
					} else {
						conflict = true;
					}
				} else {
					source->report.selection = NTFS_LOGFILE_EQUAL_COPIES;
				}
			} else {
				source->report.selection = NTFS_LOGFILE_NEWER_COPY;
			}
			if (source->report.selected_probe == NTFS_LOGFILE_NO_PROBE ||
			    (!conflict &&
				(probe->restart.current_lsn > selected->current_lsn ||
				    select_dirty))) {
				*selected = probe->restart;
				source->report.selected_probe = index;
				ntfs_copy(source->selected, source->scratch, probe->page_bytes);
			}
		}
		offset = offset == 0 ? NTFS_MST_STRIDE : offset * 2u;
	}
	source->report.scan_complete = true;
	if (conflict) {
		source->report.selection = NTFS_LOGFILE_CONFLICT;
		return NTFS_UNSUPPORTED;
	}
	if (unsupported) {
		return NTFS_UNSUPPORTED;
	}
	return source->report.selected_probe == NTFS_LOGFILE_NO_PROBE ? NTFS_CORRUPT : NTFS_OK;
}

void
ntfs_logfile_close(struct ntfs_logfile *source)
{
	struct ntfs_stream *backing;

	if (source != NULL) {
		backing = source->backing;
		ntfs_logfile_clear_page_index(source);
		if (source->raw != NULL) {
			source->environment.release(source->environment.context, source->raw,
			    source->limits.max_page_bytes);
		}
		if (source->scratch != NULL) {
			source->environment.release(source->environment.context, source->scratch,
			    source->limits.max_page_bytes);
		}
		if (source->selected != NULL) {
			source->environment.release(source->environment.context, source->selected,
			    source->limits.max_page_bytes);
		}
		source->environment.release(source->environment.context, source, sizeof(*source));
		ntfs_stream_close(backing);
	}
}

static enum ntfs_result
ntfs_logfile_volume_read(void *context, uint64_t offset, void *bytes, size_t size)
{
	return ntfs_stream_exact(context, offset, bytes, size);
}

static void *
ntfs_logfile_volume_allocate(void *context, size_t size)
{
	struct ntfs_stream *stream = context;

	return ntfs_alloc(stream->volume, size);
}

static void
ntfs_logfile_volume_release(void *context, void *bytes, size_t size)
{
	struct ntfs_stream *stream = context;

	ntfs_free(stream->volume, bytes, size);
}

static void *
ntfs_logfile_recovery_volume_allocate(void *context, size_t size)
{
	return ntfs_alloc(context, size);
}

static void
ntfs_logfile_recovery_volume_release(void *context, void *bytes, size_t size)
{
	ntfs_free(context, bytes, size);
}

static enum ntfs_result
ntfs_logfile_acquire_volume(struct ntfs_volume *volume, const struct ntfs_logfile_limits *limits,
    struct ntfs_logfile_report *report, struct ntfs_logfile **out, bool retained_roots)
{
	struct ntfs_node *node = NULL;
	struct ntfs_stream *stream = NULL;
	struct ntfs_stat metadata;
	struct ntfs_environment environment;
	struct ntfs_logfile_limits policy;
	const struct ntfs_disk_record *header;
	enum ntfs_result result;

	if (report != NULL) {
		ntfs_zero(report, sizeof(*report));
		report->selected_probe = NTFS_LOGFILE_NO_PROBE;
	}
	if (out == NULL) {
		return NTFS_INVALID;
	}
	*out = NULL;
	if (volume == NULL) {
		return NTFS_INVALID;
	}
	ntfs_logfile_default_limits(&policy);
	if (limits != NULL) {
		policy = *limits;
	}
	if (!ntfs_logfile_valid_limits(&policy)) {
		return NTFS_INVALID;
	}
	result = ntfs_node_by_number(volume, NTFS_LOGFILE_RECORD, &node);
	if (result != NTFS_OK) {
		return result;
	}
	header = (const void *)node->record;
	result = ntfs_node_metadata(node, &metadata);
	if (result != NTFS_OK) {
		goto done;
	}
	if (metadata.directory || metadata.reparse ||
	    (ntfs_u16(header->flags) & (NTFS_RECORD_VIEW_INDEX | NTFS_RECORD_UNINTERPRETED)) != 0 ||
	    (metadata.file_attributes &
		(NTFS_FILE_SPARSE | NTFS_FILE_COMPRESSED | NTFS_FILE_ENCRYPTED)) != 0) {
		result = NTFS_UNSUPPORTED;
		goto done;
	}
	result = ntfs_stream_open(node, NULL, 0, &stream);
	if (result != NTFS_OK) {
		goto done;
	}
	if (stream->flags != 0 || stream->initialized != stream->size) {
		result = NTFS_UNSUPPORTED;
		goto done;
	}
	ntfs_node_close(node);
	node = NULL;
	environment = (struct ntfs_environment){NTFS_API_VERSION, stream, stream->size,
	    ntfs_logfile_volume_read, ntfs_logfile_volume_allocate, ntfs_logfile_volume_release};
	result = ntfs_logfile_source_open(&environment, &policy, report, out, retained_roots);
	if (result == NTFS_OK) {
		(*out)->backing = stream;
		stream = NULL;
	}
done:
	ntfs_node_close(node);
	ntfs_stream_close(stream);
	return result;
}

enum ntfs_result
ntfs_logfile_open_volume_impl(struct ntfs_volume *volume, const struct ntfs_logfile_limits *limits,
    struct ntfs_logfile_report *report, struct ntfs_logfile **out)
{
	return ntfs_logfile_acquire_volume(volume, limits, report, out, false);
}

enum ntfs_result
ntfs_logfile_open_volume_retained_impl(struct ntfs_volume *volume,
    const struct ntfs_logfile_limits *limits, struct ntfs_logfile_report *report,
    struct ntfs_logfile **out)
{
	return ntfs_logfile_acquire_volume(volume, limits, report, out, true);
}

static enum ntfs_result
ntfs_logfile_source_open(const struct ntfs_environment *environment,
    const struct ntfs_logfile_limits *requested, struct ntfs_logfile_report *report,
    struct ntfs_logfile **out, bool retained_roots)
{
	struct ntfs_logfile_limits limits;
	struct ntfs_logfile *source;
	enum ntfs_result result;

	if (report != NULL) {
		ntfs_zero(report, sizeof(*report));
		report->selected_probe = NTFS_LOGFILE_NO_PROBE;
	}
	if (out == NULL) {
		return NTFS_INVALID;
	}
	*out = NULL;
	ntfs_logfile_default_limits(&limits);
	if (requested != NULL) {
		limits = *requested;
	}
	if (environment == NULL || environment->api_version != NTFS_API_VERSION ||
	    environment->read == NULL || environment->allocate == NULL ||
	    environment->release == NULL || !ntfs_logfile_valid_limits(&limits)) {
		return NTFS_INVALID;
	}
	if (environment->size_bytes > NTFS_LOGFILE_MAX_FILE_BYTES) {
		return NTFS_RANGE;
	}
	if (environment->size_bytes < sizeof(struct ntfs_disk_log_restart_page)) {
		return NTFS_CORRUPT;
	}
	source = environment->allocate(environment->context, sizeof(*source));
	if (source == NULL) {
		return NTFS_NO_MEMORY;
	}
	ntfs_zero(source, sizeof(*source));
	source->environment = *environment;
	source->limits = limits;
	source->report.selected_probe = NTFS_LOGFILE_NO_PROBE;
	source->raw = environment->allocate(environment->context, limits.max_page_bytes);
	source->scratch = environment->allocate(environment->context, limits.max_page_bytes);
	source->selected = environment->allocate(environment->context, limits.max_page_bytes);
	if (source->raw == NULL || source->scratch == NULL || source->selected == NULL) {
		result = NTFS_NO_MEMORY;
	} else {
		result = ntfs_logfile_discover(source, retained_roots);
	}
	if (result != NTFS_OK) {
		source->report.selected_probe = NTFS_LOGFILE_NO_PROBE;
		if (source->report.selection != NTFS_LOGFILE_CONFLICT) {
			source->report.selection = NTFS_LOGFILE_UNSELECTED;
		}
	}
	if (report != NULL) {
		*report = source->report;
	}
	if (result != NTFS_OK) {
		ntfs_logfile_close(source);
		return result;
	}
	*out = source;
	return NTFS_OK;
}

enum ntfs_result
ntfs_logfile_open(const struct ntfs_environment *environment,
    const struct ntfs_logfile_limits *requested, struct ntfs_logfile_report *report,
    struct ntfs_logfile **out)
{
	return ntfs_logfile_source_open(environment, requested, report, out, false);
}

enum ntfs_result
ntfs_logfile_get_restart(const struct ntfs_logfile *source, struct ntfs_logfile_restart *out)
{
	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (source == NULL) {
		return NTFS_INVALID;
	}
	*out = source->restart;
	return NTFS_OK;
}

enum ntfs_result
ntfs_logfile_environment(const struct ntfs_logfile *source, struct ntfs_environment *out,
    struct ntfs_logfile_limits *limits, struct ntfs_volume **backing)
{
	if (out == NULL || backing == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	*backing = NULL;
	if (source == NULL) {
		return NTFS_INVALID;
	}
	*out = source->environment;
	/* Recovery queries need only owned bytes. Do not retain a source read
	 * callback or a stream context which source close would destroy. */
	out->read = NULL;
	if (source->backing != NULL) {
		*backing = source->backing->volume;
		out->context = *backing;
		out->allocate = ntfs_logfile_recovery_volume_allocate;
		out->release = ntfs_logfile_recovery_volume_release;
	}
	if (limits != NULL) {
		*limits = source->limits;
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_logfile_get_client(
    const struct ntfs_logfile *source, uint16_t index, struct ntfs_logfile_client *out)
{
	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (source == NULL) {
		return NTFS_INVALID;
	}
	if (index >= source->restart.client_count) {
		return NTFS_END;
	}
	return ntfs_logfile_client_decode(source->selected + source->restart.clients.offset +
		(size_t)index * sizeof(struct ntfs_disk_log_client),
	    sizeof(struct ntfs_disk_log_client), out);
}

enum ntfs_result
ntfs_logfile_get_active_client(const struct ntfs_logfile *source, uint16_t index, uint16_t sequence,
    struct ntfs_logfile_client *out)
{
	const struct ntfs_disk_log_client *entry;
	uint16_t cursor, visited;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (source == NULL) {
		return NTFS_INVALID;
	}
	if (index >= source->restart.client_count) {
		return NTFS_STALE;
	}
	entry = (const void *)(source->selected + source->restart.clients.offset +
	    (size_t)index * sizeof(*entry));
	if (ntfs_u16(entry->sequence) != sequence) {
		return NTFS_STALE;
	}
	cursor = source->restart.in_use_head;
	for (visited = 0;
	    cursor != NTFS_LOGFILE_NO_CLIENT && visited < source->restart.client_count; visited++) {
		if (cursor >= source->restart.client_count) {
			return NTFS_CORRUPT;
		}
		if (cursor == index) {
			return ntfs_logfile_get_client(source, index, out);
		}
		entry = (const void *)(source->selected + source->restart.clients.offset +
		    (size_t)cursor * sizeof(*entry));
		cursor = ntfs_u16(entry->next);
	}
	return cursor == NTFS_LOGFILE_NO_CLIENT ? NTFS_STALE : NTFS_CORRUPT;
}

bool
ntfs_logfile_is_ntfs_client(const struct ntfs_logfile_client *client)
{
	static const uint16_t client_name[] = {'N', 'T', 'F', 'S'};

	return client->name_length == sizeof(client_name) / sizeof(client_name[0]) &&
	    ntfs_equal(client->name, client_name, sizeof(client_name));
}

enum ntfs_result
ntfs_logfile_decode_client_restart_record(const struct ntfs_logfile *source, const void *input,
    size_t size, struct ntfs_logfile_client_restart *out)
{
	struct ntfs_logfile_record record;
	struct ntfs_logfile_client client;
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (source == NULL) {
		return NTFS_INVALID;
	}
	result =
	    ntfs_logfile_record_decode(input, size, source->restart.record_header_bytes, &record);
	if (result != NTFS_OK) {
		return result;
	}
	if (record.type != NTFS_LOGFILE_RECORD_RESTART) {
		return NTFS_UNSUPPORTED;
	}
	result = ntfs_logfile_get_active_client(
	    source, record.client_index, record.client_sequence, &client);
	if (result != NTFS_OK) {
		return result;
	}
	if (!ntfs_logfile_is_ntfs_client(&client)) {
		return NTFS_UNSUPPORTED;
	}
	if (client.restart_lsn == 0 || record.lsn != client.restart_lsn) {
		return NTFS_STALE;
	}
	return ntfs_logfile_client_restart_decode(
	    (const uint8_t *)input + record.data.offset, record.data.length, out);
}
