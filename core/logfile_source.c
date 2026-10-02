/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include <ntfs/logfile.h>

struct ntfs_logfile {
	struct ntfs_environment environment;
	struct ntfs_logfile_limits limits;
	struct ntfs_logfile_report report;
	struct ntfs_logfile_restart restart;
	uint8_t *raw, *scratch, *selected;
	bool backend_failed;
	struct ntfs_stream *backing;
};

void
ntfs_logfile_default_limits(struct ntfs_logfile_limits *limits)
{
	if (limits != NULL) {
		*limits = (struct ntfs_logfile_limits){NTFS_LOGFILE_MAX_PAGE_BYTES,
		    NTFS_LOGFILE_DEFAULT_READ_CALLS, NTFS_LOGFILE_DEFAULT_READ_BYTES};
	}
}

static bool
valid_limits(const struct ntfs_logfile_limits *limits)
{
	return limits->max_page_bytes >= NTFS_MST_STRIDE &&
	    limits->max_page_bytes <= NTFS_LOGFILE_MAX_PAGE_BYTES &&
	    (limits->max_page_bytes & (limits->max_page_bytes - 1u)) == 0 &&
	    limits->max_read_calls != 0 && limits->max_read_bytes != 0;
}

static enum ntfs_result
source_read(struct ntfs_logfile *source, uint64_t offset, void *buffer, size_t size,
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
same_geometry(const struct ntfs_logfile_restart *a, const struct ntfs_logfile_restart *b)
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
probe_restart(struct ntfs_logfile *source, struct ntfs_logfile_probe *probe)
{
	struct ntfs_disk_log_restart_page prefix;
	const struct ntfs_disk_log_restart_page *header;
	enum ntfs_result result;

	result = source_read(source, probe->offset, &prefix, sizeof(prefix), &source->report);
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
	result =
	    source_read(source, probe->offset, source->raw, probe->page_bytes, &source->report);
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
discover(struct ntfs_logfile *source)
{
	struct ntfs_logfile_probe *probe;
	struct ntfs_logfile_restart *selected = &source->restart;
	uint64_t offset = 0;
	uint16_t index;
	bool unsupported = false, conflict = false;
	enum ntfs_result result;

	for (index = 0; index < NTFS_LOGFILE_RESTART_PROBES; index++) {
		probe = &source->report.probes[index];
		probe->offset = offset;
		probe->result = probe_restart(source, probe);
		source->report.probe_count++;
		result = probe->result;
		if (source->backend_failed || result == NTFS_RANGE ||
		    (result != NTFS_OK && result != NTFS_CORRUPT && result != NTFS_UNSUPPORTED &&
			result != NTFS_NOT_FOUND)) {
			return result;
		}
		unsupported |= result == NTFS_UNSUPPORTED;
		if (result == NTFS_OK) {
			if (source->report.selected_probe == NTFS_LOGFILE_NO_PROBE) {
				source->report.selection = NTFS_LOGFILE_SINGLE_COPY;
			} else if (!same_geometry(selected, &probe->restart)) {
				conflict = true;
			} else if (selected->current_lsn == probe->restart.current_lsn) {
				if (selected->area.length != probe->restart.area.length ||
				    !ntfs_equal(source->selected + selected->area.offset,
					source->scratch + probe->restart.area.offset,
					selected->area.length)) {
					conflict = true;
				} else {
					source->report.selection = NTFS_LOGFILE_EQUAL_COPIES;
				}
			} else {
				source->report.selection = NTFS_LOGFILE_NEWER_COPY;
			}
			if (source->report.selected_probe == NTFS_LOGFILE_NO_PROBE ||
			    (!conflict && probe->restart.current_lsn > selected->current_lsn)) {
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
volume_read(void *context, uint64_t offset, void *bytes, size_t size)
{
	return ntfs_stream_exact(context, offset, bytes, size);
}

static void *
volume_allocate(void *context, size_t size)
{
	struct ntfs_stream *stream = context;

	return stream->volume->env.allocate(stream->volume->env.context, size);
}

static void
volume_release(void *context, void *bytes, size_t size)
{
	struct ntfs_stream *stream = context;

	stream->volume->env.release(stream->volume->env.context, bytes, size);
}

enum ntfs_result
ntfs_logfile_open_volume(struct ntfs_volume *volume, const struct ntfs_logfile_limits *limits,
    struct ntfs_logfile_report *report, struct ntfs_logfile **out)
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
	if (!valid_limits(&policy)) {
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
	environment = (struct ntfs_environment){
	    NTFS_API_VERSION, stream, stream->size, volume_read, volume_allocate, volume_release};
	result = ntfs_logfile_open(&environment, &policy, report, out);
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
ntfs_logfile_open(const struct ntfs_environment *environment,
    const struct ntfs_logfile_limits *requested, struct ntfs_logfile_report *report,
    struct ntfs_logfile **out)
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
	    environment->release == NULL || !valid_limits(&limits)) {
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
		result = discover(source);
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

enum ntfs_result
ntfs_logfile_decode_client_restart_record(const struct ntfs_logfile *source, const void *input,
    size_t size, struct ntfs_logfile_client_restart *out)
{
	static const uint16_t client_name[] = {'N', 'T', 'F', 'S'};
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
	if (client.name_length != sizeof(client_name) / sizeof(client_name[0]) ||
	    !ntfs_equal(client.name, client_name, sizeof(client_name))) {
		return NTFS_UNSUPPORTED;
	}
	if (client.restart_lsn == 0 || record.lsn != client.restart_lsn) {
		return NTFS_STALE;
	}
	return ntfs_logfile_client_restart_decode(
	    (const uint8_t *)input + record.data.offset, record.data.length, out);
}

static enum ntfs_result
load_page(struct ntfs_logfile *source, uint64_t offset, struct ntfs_logfile_report *work,
    struct ntfs_logfile_page_view *out)
{
	struct ntfs_logfile_page_view view = {0};
	const struct ntfs_logfile_restart *restart = &source->restart;
	enum ntfs_result result;

	if (offset % restart->log_page_bytes != 0 ||
	    offset < (uint64_t)NTFS_LFS_RESTART_PAGES * restart->system_page_bytes ||
	    !ntfs_bounds(offset, restart->log_page_bytes, restart->usable_bytes)) {
		return NTFS_INVALID;
	}
	result = source_read(source, offset, source->raw, restart->log_page_bytes, work);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_logfile_page_decode(source->raw, restart->log_page_bytes, restart,
	    source->scratch, source->limits.max_page_bytes, &view.page);
	if (result != NTFS_OK) {
		return result;
	}
	view.offset = offset;
	view.storage = offset >= restart->circular_offset ? NTFS_LOGFILE_CIRCULAR
	    : restart->major == NTFS_LFS_MAJOR_FAST	  ? NTFS_LOGFILE_FAST_STORAGE
							  : NTFS_LOGFILE_LEGACY_TAIL;
	*out = view;
	return NTFS_OK;
}

enum ntfs_result
ntfs_logfile_read_page(struct ntfs_logfile *source, uint64_t offset, void *bytes, size_t capacity,
    struct ntfs_logfile_page_view *out)
{
	struct ntfs_logfile_report work = {0};
	struct ntfs_logfile_page_view view;
	const struct ntfs_logfile_restart *restart;
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (source == NULL || bytes == NULL) {
		return NTFS_INVALID;
	}
	restart = &source->restart;
	if (offset % restart->log_page_bytes != 0 ||
	    offset < (uint64_t)NTFS_LFS_RESTART_PAGES * restart->system_page_bytes ||
	    !ntfs_bounds(offset, restart->log_page_bytes, restart->usable_bytes)) {
		return NTFS_INVALID;
	}
	if (capacity < restart->log_page_bytes) {
		return NTFS_RANGE;
	}
	result = load_page(source, offset, &work, &view);
	if (result == NTFS_OK) {
		ntfs_copy(bytes, source->scratch, restart->log_page_bytes);
		*out = view;
	}
	return result;
}

enum ntfs_result
ntfs_logfile_read_circular_record(struct ntfs_logfile *source, uint64_t requested_lsn, void *bytes,
    size_t capacity, struct ntfs_logfile_record_view *out)
{
	struct ntfs_logfile_report work = {0};
	struct ntfs_logfile_record_view view = {0};
	struct ntfs_logfile_page_view page;
	struct ntfs_logfile_lsn location, linked;
	const struct ntfs_logfile_restart *restart;
	const struct ntfs_disk_log_record *header;
	uint8_t *staged;
	uint64_t total, unique_capacity, offset;
	size_t copied, amount, record_offset;
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (source == NULL || bytes == NULL) {
		return NTFS_INVALID;
	}
	restart = &source->restart;
	result = ntfs_logfile_lsn_decode(restart, requested_lsn, &location);
	if (result != NTFS_OK) {
		return result;
	}
	if (capacity < restart->record_header_bytes) {
		return NTFS_RANGE;
	}
	result = load_page(source, location.page_offset, &work, &page);
	if (result != NTFS_OK) {
		return result;
	}
	header = (const void *)(source->scratch + location.record_offset);
	if (ntfs_u64(header->lsn) != requested_lsn) {
		return NTFS_STALE;
	}
	total = (uint64_t)restart->record_header_bytes + ntfs_u32(header->data_bytes);
	unique_capacity = (restart->usable_bytes - restart->circular_offset) /
		restart->log_page_bytes * (restart->log_page_bytes - restart->page_data_offset) -
	    (location.record_offset - restart->page_data_offset);
	if (total > NTFS_LOGFILE_MAX_RECORD_BYTES || total > capacity || total > unique_capacity) {
		return NTFS_RANGE;
	}
	staged = source->environment.allocate(source->environment.context, (size_t)total);
	if (staged == NULL) {
		return NTFS_NO_MEMORY;
	}
	offset = location.page_offset;
	record_offset = location.record_offset;
	copied = 0;
	view.first_page_offset = offset;
	for (;;) {
		amount = restart->log_page_bytes - record_offset;
		if (amount > total - copied) {
			amount = (size_t)total - copied;
		}
		ntfs_copy(staged + copied, source->scratch + record_offset, amount);
		copied += amount;
		view.pages_read++;
		view.last_page_offset = offset;
		if (copied == total) {
			break;
		}
		offset += restart->log_page_bytes;
		if (offset == restart->usable_bytes) {
			offset = restart->circular_offset;
			view.wrapped = true;
		}
		if (offset == location.page_offset) {
			result = NTFS_RANGE;
			goto done;
		}
		result = load_page(source, offset, &work, &page);
		if (result != NTFS_OK) {
			goto done;
		}
		record_offset = restart->page_data_offset;
	}
	result = ntfs_logfile_record_decode(
	    staged, (size_t)total, restart->record_header_bytes, &view.record);
	if (result == NTFS_OK &&
	    ((view.record.previous_lsn != 0 &&
		 ntfs_logfile_lsn_decode(restart, view.record.previous_lsn, &linked) != NTFS_OK) ||
		(view.record.undo_next_lsn != 0 &&
		    ntfs_logfile_lsn_decode(restart, view.record.undo_next_lsn, &linked) !=
			NTFS_OK))) {
		result = NTFS_CORRUPT;
	}
	if (result == NTFS_OK) {
		view.bytes = (uint32_t)total;
		view.read_calls = work.read_calls;
		view.read_bytes = work.read_bytes;
		ntfs_copy(bytes, staged, (size_t)total);
		*out = view;
	}
done:
	source->environment.release(source->environment.context, staged, (size_t)total);
	return result;
}
