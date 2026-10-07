/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include "logfile_internal.h"
#include "logfile_tables_disk.h"

struct indexed_page_entry {
	struct ntfs_logfile_indexed_page page;
	struct ntfs_logfile_page_view circular;
	uint64_t equal_candidates;
	uint32_t retained_target;
	bool blocked;
};

struct page_index {
	struct ntfs_logfile_page_index_report report;
	struct ntfs_logfile_page_view copies[NTFS_LOGFILE_FAST_COPY_PAGES];
	uint64_t copy_targets[NTFS_LOGFILE_FAST_COPY_PAGES];
	uint64_t unrouted_lsn;
	size_t allocation_bytes;
	bool unrouted_undated;
	struct indexed_page_entry entries[];
};

struct index_builder {
	struct page_index *index;
	const struct ntfs_logfile_restart *restart;
	uint64_t first_offset;
	uint32_t copy_pages;
	struct ntfs_logfile *source;
	bool admit_uncompleted_legacy_copies;
};

struct ntfs_logfile {
	struct ntfs_environment environment;
	struct ntfs_logfile_limits limits;
	struct ntfs_logfile_report report;
	struct ntfs_logfile_restart restart;
	uint8_t *raw, *scratch, *selected;
	bool backend_failed;
	struct ntfs_stream *backing;
	struct page_index *page_index;
};

struct legacy_copies {
	struct ntfs_logfile_page_view pages[NTFS_LFS_LEGACY_TAIL_PAGES];
	bool available[NTFS_LFS_LEGACY_TAIL_PAGES];
	uint8_t *comparison;
};

struct fast_copies {
	struct ntfs_logfile_page_view pages[NTFS_LOGFILE_FAST_COPY_PAGES];
	uint32_t targets[NTFS_LOGFILE_FAST_COPY_PAGES];
	bool available[NTFS_LOGFILE_FAST_COPY_PAGES];
	uint8_t *comparison;
};

struct record_copies {
	struct legacy_copies *legacy;
	struct fast_copies *fast;
	const struct ntfs_logfile_checkpoint_capture_limits *capture_limits;
	bool indexed, history;
};

struct record_ending {
	struct ntfs_logfile_page_view page;
	uint64_t offset;
	size_t end_offset;
};

enum {
	NTFS_LOGFILE_FAST_METADATA_BYTES = 2 * 1024,
	NTFS_LOGFILE_INDEX_METADATA_BYTES = 4 * 1024,
	NTFS_LOGFILE_PREFIX_PAIR_READS = 2
};

_Static_assert(
    sizeof(struct fast_copies) <= NTFS_LOGFILE_FAST_METADATA_BYTES, "fast-copy metadata policy");
_Static_assert(NTFS_LOGFILE_MAX_FILE_BYTES / NTFS_MST_STRIDE <= UINT32_MAX,
    "physical inventory counter capacity");
_Static_assert(sizeof(struct page_index) == offsetof(struct page_index, entries),
    "page-index flexible-array placement");
_Static_assert(sizeof(struct page_index) <= NTFS_LOGFILE_INDEX_METADATA_BYTES,
    "page-index fixed metadata policy");
_Static_assert(NTFS_LOGFILE_FAST_COPY_PAGES < sizeof(uint64_t) * NTFS_BITS_PER_BYTE,
    "copy slots and circular candidate fit the index mask");
_Static_assert(sizeof(struct ntfs_disk_log_fast_page) ==
	NTFS_LFS_FAST_USA_WORDS * sizeof(uint16_t) + sizeof(struct ntfs_disk_log_page) +
	    sizeof(uint16_t) + sizeof(uint32_t),
    "fast-page prefix layout");

static enum ntfs_result source_open(const struct ntfs_environment *,
    const struct ntfs_logfile_limits *, struct ntfs_logfile_report *, struct ntfs_logfile **,
    bool retained_roots);

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
retained_hint_difference(const struct ntfs_logfile_restart *a, const uint8_t *left,
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
discover(struct ntfs_logfile *source, bool retained_roots)
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
			select_dirty = false;
			if (source->report.selected_probe == NTFS_LOGFILE_NO_PROBE) {
				source->report.selection = NTFS_LOGFILE_SINGLE_COPY;
			} else if (!same_geometry(selected, &probe->restart)) {
				conflict = true;
			} else if (selected->current_lsn == probe->restart.current_lsn) {
				if (selected->area.length != probe->restart.area.length ||
				    !ntfs_equal(source->selected + selected->area.offset,
					source->scratch + probe->restart.area.offset,
					selected->area.length)) {
					if (retained_roots &&
					    retained_hint_difference(selected, source->selected,
						&probe->restart, source->scratch) == NTFS_OK) {
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
volume_read(void *context, uint64_t offset, void *bytes, size_t size)
{
	return ntfs_stream_exact(context, offset, bytes, size);
}

static void *
volume_allocate(void *context, size_t size)
{
	struct ntfs_stream *stream = context;

	return ntfs_alloc(stream->volume, size);
}

static void
volume_release(void *context, void *bytes, size_t size)
{
	struct ntfs_stream *stream = context;

	ntfs_free(stream->volume, bytes, size);
}

static void *
recovery_volume_allocate(void *context, size_t size)
{
	return ntfs_alloc(context, size);
}

static void
recovery_volume_release(void *context, void *bytes, size_t size)
{
	ntfs_free(context, bytes, size);
}

static enum ntfs_result
open_volume(struct ntfs_volume *volume, const struct ntfs_logfile_limits *limits,
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
	result = source_open(&environment, &policy, report, out, retained_roots);
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
	return open_volume(volume, limits, report, out, false);
}

enum ntfs_result
ntfs_logfile_open_volume_retained_impl(struct ntfs_volume *volume,
    const struct ntfs_logfile_limits *limits, struct ntfs_logfile_report *report,
    struct ntfs_logfile **out)
{
	return open_volume(volume, limits, report, out, true);
}

static enum ntfs_result
source_open(const struct ntfs_environment *environment, const struct ntfs_logfile_limits *requested,
    struct ntfs_logfile_report *report, struct ntfs_logfile **out, bool retained_roots)
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
		result = discover(source, retained_roots);
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
	return source_open(environment, requested, report, out, false);
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
		out->allocate = recovery_volume_allocate;
		out->release = recovery_volume_release;
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

static bool
is_ntfs_client(const struct ntfs_logfile_client *client)
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
	if (!is_ntfs_client(&client)) {
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

static bool
same_written_prefix(const struct ntfs_logfile_restart *restart, const struct ntfs_logfile_page *a,
    const uint8_t *a_bytes, const struct ntfs_logfile_page *b, const uint8_t *b_bytes)
{
	return a->flags == b->flags && a->next_record_offset == b->next_record_offset &&
	    a->next_record_offset >= restart->page_data_offset &&
	    ntfs_equal(a_bytes + restart->page_data_offset, b_bytes + restart->page_data_offset,
		a->next_record_offset - restart->page_data_offset);
}

static enum ntfs_result
scan_legacy_copies(
    struct ntfs_logfile *source, struct ntfs_logfile_report *work, struct legacy_copies *copies)
{
	const struct ntfs_logfile_restart *restart = &source->restart;
	struct ntfs_logfile_page_view *page;
	uint64_t offset;
	unsigned index;
	enum ntfs_result result;

	for (index = 0; index < NTFS_LFS_LEGACY_TAIL_PAGES; index++) {
		page = &copies->pages[index];
		offset = (uint64_t)NTFS_LFS_RESTART_PAGES * restart->system_page_bytes +
		    (uint64_t)index * restart->log_page_bytes;
		result = load_page(source, offset, work, page);
		if (source->backend_failed ||
		    (result != NTFS_OK && result != NTFS_CORRUPT && result != NTFS_NOT_FOUND)) {
			return result;
		}
		if (result != NTFS_OK || page->page.copy_value < restart->circular_offset ||
		    page->page.copy_value % restart->log_page_bytes != 0 ||
		    !ntfs_bounds(
			page->page.copy_value, restart->log_page_bytes, restart->usable_bytes)) {
			continue;
		}
		if ((page->page.flags &
			~(NTFS_LOGFILE_PAGE_RECORD_END | NTFS_LOGFILE_PAGE_CLIENT_RESTART)) != 0) {
			return NTFS_UNSUPPORTED;
		}
		copies->available[index] = true;
		if (index == 0) {
			ntfs_copy(copies->comparison, source->scratch, restart->log_page_bytes);
		} else if (copies->available[0] &&
		    copies->pages[0].page.copy_value == page->page.copy_value &&
		    copies->pages[0].page.last_end_lsn == page->page.last_end_lsn &&
		    !same_written_prefix(restart, &copies->pages[0].page, copies->comparison,
			&page->page, source->scratch)) {
			return NTFS_UNSUPPORTED;
		}
	}
	return NTFS_OK;
}

static enum ntfs_result
load_legacy_page(struct ntfs_logfile *source, uint64_t offset, struct ntfs_logfile_report *work,
    struct legacy_copies *copies, struct ntfs_logfile_page_view *out)
{
	const struct ntfs_logfile_restart *restart = &source->restart;
	const struct ntfs_logfile_page_view *candidate = NULL;
	struct ntfs_logfile_page_view circular = {0}, tail = {0};
	enum ntfs_result circular_result, result;
	unsigned index;

	for (index = 0; index < NTFS_LFS_LEGACY_TAIL_PAGES; index++) {
		if (copies->available[index] && copies->pages[index].page.copy_value == offset &&
		    (candidate == NULL ||
			copies->pages[index].page.last_end_lsn > candidate->page.last_end_lsn)) {
			candidate = &copies->pages[index];
		}
	}
	circular_result = load_page(source, offset, work, &circular);
	if (source->backend_failed ||
	    (circular_result != NTFS_OK && circular_result != NTFS_CORRUPT &&
		circular_result != NTFS_NOT_FOUND)) {
		return circular_result;
	}
	if (circular_result == NTFS_OK &&
	    (circular.page.flags &
		~(NTFS_LOGFILE_PAGE_RECORD_END | NTFS_LOGFILE_PAGE_CLIENT_RESTART)) != 0) {
		return NTFS_UNSUPPORTED;
	}
	if (candidate == NULL ||
	    (circular_result == NTFS_OK &&
		circular.page.last_end_lsn > candidate->page.last_end_lsn)) {
		if (circular_result == NTFS_OK) {
			*out = circular;
		}
		return circular_result;
	}
	if (candidate->page.last_end_lsn == 0 ||
	    (candidate->page.flags & NTFS_LOGFILE_PAGE_RECORD_END) == 0 ||
	    candidate->page.next_record_offset < restart->page_data_offset) {
		return NTFS_UNSUPPORTED;
	}
	if (circular_result == NTFS_OK) {
		ntfs_copy(copies->comparison, source->scratch, restart->log_page_bytes);
	}
	result = load_page(source, candidate->offset, work, &tail);
	if (result != NTFS_OK) {
		return result;
	}
	if (tail.page.copy_value != candidate->page.copy_value ||
	    tail.page.last_end_lsn != candidate->page.last_end_lsn ||
	    tail.page.flags != candidate->page.flags ||
	    tail.page.next_record_offset != candidate->page.next_record_offset) {
		return NTFS_STALE;
	}
	if (circular_result == NTFS_OK && circular.page.last_end_lsn == tail.page.last_end_lsn &&
	    !same_written_prefix(
		restart, &circular.page, copies->comparison, &tail.page, source->scratch)) {
		return NTFS_UNSUPPORTED;
	}
	*out = tail;
	return NTFS_OK;
}

static enum ntfs_result
fast_target(struct ntfs_logfile *source, uint32_t *target)
{
	const struct ntfs_disk_log_fast_page *header = (const void *)source->scratch;
	uint32_t usa_end;

	usa_end = ntfs_u16(header->common.mst.usa_offset) +
	    (uint32_t)ntfs_u16(header->common.mst.usa_count) * NTFS_MST_WORD_BYTES;
	if (usa_end > offsetof(struct ntfs_disk_log_fast_page, file_offset)) {
		return NTFS_UNSUPPORTED;
	}
	*target = ntfs_u32(header->file_offset);
	return NTFS_OK;
}

static enum ntfs_result
observe_target(struct ntfs_logfile *source, struct ntfs_logfile_page_observation *observation)
{
	const struct ntfs_logfile_restart *restart = &source->restart;
	const struct ntfs_logfile_page *page = &observation->page;
	struct ntfs_logfile_lsn location;
	uint64_t target;
	uint32_t fast_offset, known_flags;
	enum ntfs_result result;

	known_flags = NTFS_LOGFILE_PAGE_RECORD_END | NTFS_LOGFILE_PAGE_CLIENT_RESTART;
	if ((page->flags & ~known_flags) != 0) {
		return NTFS_UNSUPPORTED;
	}
	if (observation->storage == NTFS_LOGFILE_LEGACY_TAIL) {
		target = page->copy_value;
	} else if (observation->storage == NTFS_LOGFILE_FAST_STORAGE) {
		if (restart->system_page_bytes != NTFS_LFS_FAST_PAGE_BYTES ||
		    restart->log_page_bytes != NTFS_LFS_FAST_PAGE_BYTES ||
		    restart->page_data_offset < sizeof(struct ntfs_disk_log_fast_page)) {
			return NTFS_UNSUPPORTED;
		}
		result = fast_target(source, &fast_offset);
		if (result != NTFS_OK) {
			return result;
		}
		target = fast_offset;
	} else {
		target = observation->offset;
	}
	observation->target_offset = target;
	if (target < restart->circular_offset || target % restart->log_page_bytes != 0 ||
	    !ntfs_bounds(target, restart->log_page_bytes, restart->usable_bytes)) {
		return NTFS_CORRUPT;
	}
	if (observation->storage != NTFS_LOGFILE_LEGACY_TAIL) {
		result = ntfs_logfile_lsn_decode(restart, page->copy_value, &location);
		if (result != NTFS_OK) {
			return result;
		}
		if (page->copy_value < page->last_end_lsn) {
			return NTFS_CORRUPT;
		}
	}
	return NTFS_OK;
}

enum ntfs_result
ntfs_logfile_visit_pages(struct ntfs_logfile *source, ntfs_logfile_page_visitor visitor,
    void *context, struct ntfs_logfile_inventory *out)
{
	struct ntfs_logfile_report work = {0};
	struct ntfs_logfile_page_observation observation;
	struct ntfs_logfile_page_view page = {0};
	const struct ntfs_logfile_restart *restart;
	const struct ntfs_disk_mst *header;
	uint64_t offset, total_bytes, epoch;
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (source == NULL) {
		return NTFS_INVALID;
	}
	restart = &source->restart;
	header = (const void *)source->raw;
	offset = (uint64_t)NTFS_LFS_RESTART_PAGES * restart->system_page_bytes;
	total_bytes = restart->usable_bytes - offset;
	out->next_offset = offset;
	out->total_pages = (uint32_t)(total_bytes / restart->log_page_bytes);
	if (out->total_pages > source->limits.max_read_calls ||
	    total_bytes > source->limits.max_read_bytes) {
		return NTFS_RANGE;
	}
	while (offset < restart->usable_bytes) {
		ntfs_zero(&observation, sizeof(observation));
		observation.offset = offset;
		observation.storage = offset >= restart->circular_offset ? NTFS_LOGFILE_CIRCULAR
		    : restart->major == NTFS_LFS_MAJOR_FAST		 ? NTFS_LOGFILE_FAST_STORAGE
									 : NTFS_LOGFILE_LEGACY_TAIL;
		observation.target_result = NTFS_INVALID;
		result = load_page(source, offset, &work, &page);
		out->read_calls = work.read_calls;
		out->read_bytes = work.read_bytes;
		if (source->backend_failed ||
		    (result != NTFS_OK && result != NTFS_CORRUPT && result != NTFS_NOT_FOUND)) {
			return result;
		}
		if (result == NTFS_CORRUPT &&
		    !ntfs_equal(header->magic, "RCRD", sizeof(header->magic))) {
			result = NTFS_NOT_FOUND;
		}
		observation.result = result;
		out->examined_pages++;
		if (result == NTFS_OK) {
			observation.page = page.page;
			out->decoded_pages++;
			observation.target_result = observe_target(source, &observation);
			if (observation.target_result == NTFS_UNSUPPORTED) {
				out->unsupported_targets++;
			} else if (observation.target_result != NTFS_OK) {
				out->invalid_targets++;
			} else {
				epoch = observation.storage == NTFS_LOGFILE_LEGACY_TAIL
				    ? observation.page.last_end_lsn
				    : observation.page.copy_value;
				if (epoch > out->max_observed_epoch_lsn) {
					out->max_observed_epoch_lsn = epoch;
				}
				if ((observation.page.flags & NTFS_LOGFILE_PAGE_RECORD_END) != 0 &&
				    observation.page.last_end_lsn > out->max_observed_end_lsn) {
					out->max_observed_end_lsn = observation.page.last_end_lsn;
				}
			}
		} else if (result == NTFS_NOT_FOUND) {
			out->missing_pages++;
		} else {
			out->corrupt_pages++;
		}
		if (visitor != NULL) {
			result = visitor(context, &observation);
			if (result != NTFS_OK) {
				return result;
			}
		}
		out->visited_pages++;
		offset += restart->log_page_bytes;
		out->next_offset = offset;
	}
	out->complete = true;
	return NTFS_OK;
}

static uint64_t
index_epoch(const struct ntfs_logfile_restart *restart, const struct ntfs_logfile_page *page)
{
	return restart->major == NTFS_LFS_MAJOR_LEGACY ? page->last_end_lsn : page->copy_value;
}

static bool
same_page_metadata(const struct ntfs_logfile_page_view *a, const struct ntfs_logfile_page_view *b)
{
	return a->offset == b->offset && a->storage == b->storage &&
	    a->page.copy_value == b->page.copy_value &&
	    a->page.last_end_lsn == b->page.last_end_lsn && a->page.flags == b->page.flags &&
	    a->page.page_count == b->page.page_count &&
	    a->page.page_position == b->page.page_position &&
	    a->page.next_record_offset == b->page.next_record_offset;
}

static uint32_t
retained_fast_target(
    struct ntfs_logfile *source, const struct ntfs_logfile_page_observation *observation)
{
	const struct ntfs_logfile_restart *restart = &source->restart;
	const struct ntfs_disk_log_fast_page *header = (const void *)source->scratch;
	struct ntfs_logfile_lsn started, ended;
	uint64_t fast_circular;
	uint32_t target;

	/* A clean Windows downgrade can retain a protected completed restart page
	 * inside the former fast area. This only nominates a duplicate: a separate
	 * exact comparison against its selected home is required before history
	 * can omit it. Other layouts and spanning transfers retain normal checks. */
	fast_circular = (uint64_t)(NTFS_LFS_RESTART_PAGES + NTFS_LOGFILE_FAST_COPY_PAGES) *
	    NTFS_LFS_FAST_PAGE_BYTES;
	if (restart->major != NTFS_LFS_MAJOR_LEGACY ||
	    restart->system_page_bytes != NTFS_LFS_FAST_PAGE_BYTES ||
	    restart->log_page_bytes != NTFS_LFS_FAST_PAGE_BYTES ||
	    restart->page_data_offset < sizeof(*header) ||
	    observation->storage != NTFS_LOGFILE_CIRCULAR || observation->result != NTFS_OK ||
	    observation->target_result != NTFS_OK || observation->offset >= fast_circular ||
	    observation->page.flags !=
		(NTFS_LOGFILE_PAGE_RECORD_END | NTFS_LOGFILE_PAGE_CLIENT_RESTART) ||
	    observation->page.page_count != 1 || observation->page.page_position != 1 ||
	    ntfs_u16(header->common.mst.usa_offset) != sizeof(header->common) ||
	    ntfs_u16(header->common.mst.usa_count) != NTFS_LFS_FAST_USA_WORDS ||
	    observation->page.next_record_offset <= restart->page_data_offset) {
		return 0;
	}
	target = ntfs_u32(header->file_offset);
	if (target < fast_circular || target % restart->log_page_bytes != 0 ||
	    !ntfs_bounds(target, restart->log_page_bytes, restart->usable_bytes) ||
	    ntfs_logfile_lsn_decode(restart, observation->page.copy_value, &started) != NTFS_OK ||
	    ntfs_logfile_lsn_decode(restart, observation->page.last_end_lsn, &ended) != NTFS_OK ||
	    started.page_offset != target || ended.page_offset != target) {
		return 0;
	}
	return target;
}

static bool
index_uncompleted_copy(
    const struct index_builder *builder, const struct ntfs_logfile_page_view *view)
{
	const struct ntfs_logfile_restart *restart = builder->restart;
	const struct ntfs_logfile_page *page = &view->page;

	return builder->admit_uncompleted_legacy_copies &&
	    restart->major == NTFS_LFS_MAJOR_LEGACY && restart->minor == NTFS_LFS_MINOR_LEGACY &&
	    restart->system_page_bytes == NTFS_LFS_FAST_PAGE_BYTES &&
	    restart->log_page_bytes == NTFS_LFS_FAST_PAGE_BYTES &&
	    restart->record_header_bytes == sizeof(struct ntfs_disk_log_record) &&
	    restart->page_data_offset == sizeof(struct ntfs_disk_log_fast_page) &&
	    view->storage == NTFS_LOGFILE_LEGACY_TAIL && page->flags == 0 &&
	    page->last_end_lsn == 0 && page->next_record_offset == restart->page_data_offset &&
	    page->page_count == 1 && page->page_position == 1;
}

static enum ntfs_result
index_collect(void *context, const struct ntfs_logfile_page_observation *observation)
{
	struct index_builder *builder = context;
	struct page_index *index = builder->index;
	const struct ntfs_logfile_restart *restart = builder->restart;
	struct indexed_page_entry *entry;
	struct ntfs_logfile_page_view view = {0};
	struct ntfs_logfile_lsn location;
	uint64_t target, epoch, bit;
	uint32_t slot;
	enum ntfs_result result;

	result = observation->result == NTFS_OK ? observation->target_result : observation->result;
	/* A legacy circular continuation can have no last-start witness. Its
	 * protected physical address and last-end epoch remain observable; this
	 * exception never routes a tail or qualifies continuation provenance. */
	if (restart->major == NTFS_LFS_MAJOR_LEGACY &&
	    observation->storage == NTFS_LOGFILE_CIRCULAR && observation->result == NTFS_OK &&
	    result == NTFS_NOT_FOUND && observation->page.copy_value == 0) {
		result = NTFS_OK;
	}
	if (observation->storage != NTFS_LOGFILE_CIRCULAR) {
		if (result != NTFS_OK) {
			index->report.unrouted_copies += observation->result != NTFS_NOT_FOUND;
			index->report.unsupported_copies += result == NTFS_UNSUPPORTED;
			if (observation->result == NTFS_OK) {
				epoch = observation->page.last_end_lsn;
				if (observation->storage == NTFS_LOGFILE_FAST_STORAGE &&
				    ntfs_logfile_lsn_decode(restart, observation->page.copy_value,
					&location) == NTFS_OK &&
				    observation->page.copy_value > epoch) {
					epoch = observation->page.copy_value;
				}
				if (epoch > index->unrouted_lsn) {
					index->unrouted_lsn = epoch;
				}
				if (epoch == 0 &&
				    ((observation->page.flags & NTFS_LOGFILE_PAGE_RECORD_END) !=
					    0 ||
					observation->page.next_record_offset >
					    restart->page_data_offset)) {
					index->unrouted_undated = true;
				}
			}
			return NTFS_OK;
		}
		slot = (uint32_t)((observation->offset - builder->first_offset) /
		    restart->log_page_bytes);
		target = observation->target_offset;
	} else {
		slot = builder->copy_pages;
		target = observation->offset;
	}
	entry = &index->entries[(target - restart->circular_offset) / restart->log_page_bytes];
	if (observation->storage == NTFS_LOGFILE_CIRCULAR && observation->result == NTFS_OK) {
		entry->circular.offset = observation->offset;
		entry->circular.storage = observation->storage;
		entry->circular.page = observation->page;
		entry->retained_target = retained_fast_target(builder->source, observation);
	}
	if (result != NTFS_OK) {
		if (result == NTFS_UNSUPPORTED) {
			entry->blocked = true;
			entry->page.result = NTFS_UNSUPPORTED;
		} else if (entry->equal_candidates == 0) {
			entry->page.result = result;
		}
		return NTFS_OK;
	}
	view.offset = observation->offset;
	view.storage = observation->storage;
	view.page = observation->page;
	if (observation->storage != NTFS_LOGFILE_CIRCULAR) {
		index->copies[slot] = view;
		index->copy_targets[slot] = target;
	} else {
		entry->circular = view;
	}
	epoch = index_epoch(restart, &observation->page);
	bit = UINT64_C(1) << slot;
	if (entry->equal_candidates == 0 || epoch > entry->page.epoch_lsn) {
		entry->page.selected = view;
		entry->page.epoch_lsn = epoch;
		entry->page.result = NTFS_OK;
		entry->equal_candidates = bit;
	} else if (epoch == entry->page.epoch_lsn) {
		entry->equal_candidates |= bit;
	}
	return NTFS_OK;
}

static enum ntfs_result
index_reload(struct ntfs_logfile *source, const struct ntfs_logfile_page_view *expected,
    uint64_t target, struct ntfs_logfile_report *work, struct ntfs_logfile_page_view *out)
{
	struct ntfs_logfile_page_observation observation = {0};
	enum ntfs_result result;

	result = load_page(source, expected->offset, work, out);
	if (result != NTFS_OK) {
		return result;
	}
	if (!same_page_metadata(expected, out)) {
		return NTFS_STALE;
	}
	observation.offset = out->offset;
	observation.storage = out->storage;
	observation.page = out->page;
	result = observe_target(source, &observation);
	if (source->restart.major == NTFS_LFS_MAJOR_LEGACY &&
	    out->storage == NTFS_LOGFILE_CIRCULAR && result == NTFS_NOT_FOUND &&
	    out->page.copy_value == 0) {
		result = NTFS_OK;
	}
	if (result != NTFS_OK) {
		return result;
	}
	return observation.target_offset == target ? NTFS_OK : NTFS_STALE;
}

static enum ntfs_result
index_compare(struct ntfs_logfile *source, struct index_builder *builder,
    struct indexed_page_entry *entry, struct ntfs_logfile_report *work, uint8_t *comparison)
{
	const struct ntfs_logfile_restart *restart = builder->restart;
	struct ntfs_logfile_page_view canonical, duplicate, expected;
	uint64_t bit, offset;
	uint32_t slot;
	bool loaded = false;
	enum ntfs_result result;

	if (entry->blocked) {
		entry->page.result = NTFS_UNSUPPORTED;
	}
	if (entry->page.result != NTFS_OK) {
		return NTFS_OK;
	}
	/* The experimental serializer persists every segment separately. A copy
	 * without a complete prefix can supersede a torn uncompleted home, but it
	 * cannot supply an endpoint or complete-prefix comparison authority. The
	 * private recovery owner must bind the whole retained history independently. */
	if (index_uncompleted_copy(builder, &entry->page.selected)) {
		return NTFS_OK;
	}
	if (entry->page.selected.storage != NTFS_LOGFILE_CIRCULAR &&
	    ((entry->page.selected.page.flags & NTFS_LOGFILE_PAGE_RECORD_END) == 0 ||
		entry->page.selected.page.last_end_lsn == 0 ||
		entry->page.selected.page.next_record_offset < restart->page_data_offset)) {
		entry->page.result = NTFS_UNSUPPORTED;
		return NTFS_OK;
	}
	if ((entry->equal_candidates & (entry->equal_candidates - 1u)) == 0) {
		return NTFS_OK;
	}
	for (slot = 0; slot <= builder->copy_pages; slot++) {
		bit = UINT64_C(1) << slot;
		if ((entry->equal_candidates & bit) == 0) {
			continue;
		}
		offset = slot == builder->copy_pages
		    ? entry->page.target_offset
		    : builder->first_offset + (uint64_t)slot * restart->log_page_bytes;
		if (offset == entry->page.selected.offset) {
			continue;
		}
		if (!loaded) {
			result = index_reload(source, &entry->page.selected,
			    entry->page.target_offset, work, &canonical);
			if (result != NTFS_OK) {
				return result;
			}
			ntfs_copy(comparison, source->scratch, restart->log_page_bytes);
			loaded = true;
		}
		expected =
		    slot == builder->copy_pages ? entry->circular : builder->index->copies[slot];
		result =
		    index_reload(source, &expected, entry->page.target_offset, work, &duplicate);
		if (result != NTFS_OK) {
			return result;
		}
		if (index_epoch(restart, &duplicate.page) != entry->page.epoch_lsn) {
			return NTFS_STALE;
		}
		builder->index->report.compared_prefixes++;
		if (duplicate.page.last_end_lsn != canonical.page.last_end_lsn ||
		    !same_written_prefix(
			restart, &canonical.page, comparison, &duplicate.page, source->scratch)) {
			entry->page.result = NTFS_UNSUPPORTED;
			entry->page.prefix_conflict = true;
		}
	}
	return NTFS_OK;
}

static enum ntfs_result
index_compare_retained(struct ntfs_logfile *source, struct indexed_page_entry *entry,
    struct page_index *index, struct ntfs_logfile_report *work, uint8_t *comparison)
{
	const struct ntfs_logfile_restart *restart = &source->restart;
	const struct indexed_page_entry *home;
	struct ntfs_logfile_page_view retained, selected;
	struct ntfs_logfile_page_observation observation = {0};
	enum ntfs_result result;

	if (entry->retained_target == 0 || entry->page.result != NTFS_OK ||
	    entry->page.selected.offset != entry->circular.offset) {
		return NTFS_OK;
	}
	home = &index->entries[(entry->retained_target - restart->circular_offset) /
	    restart->log_page_bytes];
	if (home->page.result != NTFS_OK || home->page.epoch_lsn != entry->page.epoch_lsn ||
	    home->page.selected.page.page_count != 1 ||
	    home->page.selected.page.page_position != 1 ||
	    home->page.selected.page.flags != entry->circular.page.flags ||
	    home->page.selected.page.last_end_lsn != entry->circular.page.last_end_lsn) {
		return NTFS_OK;
	}
	result = index_reload(source, &entry->circular, entry->page.target_offset, work, &retained);
	if (result != NTFS_OK) {
		return result;
	}
	observation.offset = retained.offset;
	observation.storage = retained.storage;
	observation.result = NTFS_OK;
	observation.target_result = NTFS_OK;
	observation.page = retained.page;
	if (retained_fast_target(source, &observation) != entry->retained_target) {
		return NTFS_STALE;
	}
	ntfs_copy(comparison, source->scratch, restart->log_page_bytes);
	result =
	    index_reload(source, &home->page.selected, home->page.target_offset, work, &selected);
	if (result != NTFS_OK) {
		return result;
	}
	index->report.compared_prefixes++;
	if (!same_written_prefix(
		restart, &retained.page, comparison, &selected.page, source->scratch)) {
		entry->page.result = NTFS_UNSUPPORTED;
		entry->page.prefix_conflict = true;
	} else {
		entry->page.retained_fast_copy = true;
	}
	return NTFS_OK;
}

void
ntfs_logfile_clear_page_index(struct ntfs_logfile *source)
{
	struct page_index *index;

	if (source != NULL && source->page_index != NULL) {
		index = source->page_index;
		source->page_index = NULL;
		source->environment.release(
		    source->environment.context, index, index->allocation_bytes);
	}
}

static enum ntfs_result
prepare_page_index(struct ntfs_logfile *source, uint64_t max_bytes,
    struct ntfs_logfile_page_index_report *out, bool admit_uncompleted_legacy_copies)
{
	struct ntfs_logfile_report work = {0};
	struct index_builder builder;
	struct page_index *index;
	struct indexed_page_entry *entry;
	const struct ntfs_logfile_restart *restart;
	uint8_t *comparison;
	uint64_t storage_pages, maximum_reads, required_bytes;
	uint32_t copies, targets, ordinal, retained_candidates = 0;
	bool existing_conflict;
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (source == NULL || max_bytes == 0) {
		return NTFS_INVALID;
	}
	if (source->page_index != NULL) {
		return NTFS_BUSY;
	}
	restart = &source->restart;
	if (restart->major == NTFS_LFS_MAJOR_FAST &&
	    (restart->system_page_bytes != NTFS_LFS_FAST_PAGE_BYTES ||
		restart->log_page_bytes != NTFS_LFS_FAST_PAGE_BYTES ||
		restart->page_data_offset < sizeof(struct ntfs_disk_log_fast_page))) {
		return NTFS_UNSUPPORTED;
	}
	copies = restart->major == NTFS_LFS_MAJOR_FAST ? NTFS_LOGFILE_FAST_COPY_PAGES
						       : NTFS_LFS_LEGACY_TAIL_PAGES;
	targets = (uint32_t)((restart->usable_bytes - restart->circular_offset) /
	    restart->log_page_bytes);
	storage_pages = (uint64_t)targets + copies;
	maximum_reads = storage_pages + (uint64_t)NTFS_LOGFILE_PREFIX_PAIR_READS * copies;
	required_bytes =
	    sizeof(*index) + (uint64_t)targets * sizeof(*entry) + restart->log_page_bytes;
	out->required_bytes = required_bytes;
	out->indexed_targets = targets;
	if (required_bytes > max_bytes || required_bytes > SIZE_MAX ||
	    maximum_reads > source->limits.max_read_calls ||
	    maximum_reads * restart->log_page_bytes > source->limits.max_read_bytes) {
		return NTFS_RANGE;
	}
	index = source->environment.allocate(source->environment.context, (size_t)required_bytes);
	if (index == NULL) {
		return NTFS_NO_MEMORY;
	}
	ntfs_zero(index, (size_t)required_bytes);
	index->allocation_bytes = (size_t)required_bytes;
	index->report = *out;
	for (ordinal = 0; ordinal < targets; ordinal++) {
		entry = &index->entries[ordinal];
		entry->page.target_offset =
		    restart->circular_offset + (uint64_t)ordinal * restart->log_page_bytes;
		entry->page.result = NTFS_NOT_FOUND;
	}
	builder = (struct index_builder){index, restart,
	    (uint64_t)NTFS_LFS_RESTART_PAGES * restart->system_page_bytes, copies, source,
	    admit_uncompleted_legacy_copies};
	comparison = (uint8_t *)(index->entries + targets);
	result =
	    ntfs_logfile_visit_pages(source, index_collect, &builder, &index->report.inventory);
	work.read_calls = index->report.inventory.read_calls;
	work.read_bytes = index->report.inventory.read_bytes;
	if (result == NTFS_OK) {
		for (ordinal = 0; ordinal < targets; ordinal++) {
			retained_candidates += index->entries[ordinal].retained_target != 0;
		}
		/* Candidate routing is untrusted until comparison. Reserve every pair
		 * before any comparison read, under the original whole-operation cap. */
		maximum_reads += (uint64_t)NTFS_LOGFILE_PREFIX_PAIR_READS * retained_candidates;
		if (maximum_reads > source->limits.max_read_calls ||
		    maximum_reads * restart->log_page_bytes > source->limits.max_read_bytes) {
			result = NTFS_RANGE;
		}
	}
	if (result == NTFS_OK) {
		for (ordinal = 0; ordinal < targets; ordinal++) {
			entry = &index->entries[ordinal];
			result = index_compare(source, &builder, entry, &work, comparison);
			if (result != NTFS_OK) {
				break;
			}
			index->report.selected_pages += entry->page.result == NTFS_OK;
			index->report.missing_targets += entry->page.result == NTFS_NOT_FOUND;
			index->report.corrupt_targets += entry->page.result == NTFS_CORRUPT;
			index->report.unsupported_targets += entry->page.result == NTFS_UNSUPPORTED;
			index->report.prefix_conflicts += entry->page.prefix_conflict;
		}
	}
	if (result == NTFS_OK) {
		for (ordinal = 0; ordinal < targets; ordinal++) {
			entry = &index->entries[ordinal];
			existing_conflict = entry->page.prefix_conflict;
			result = index_compare_retained(source, entry, index, &work, comparison);
			if (result != NTFS_OK) {
				break;
			}
			if (!existing_conflict && entry->page.prefix_conflict) {
				index->report.selected_pages--;
				index->report.unsupported_targets++;
				index->report.prefix_conflicts++;
			}
		}
	}
	index->report.read_calls = work.read_calls;
	index->report.read_bytes = work.read_bytes;
	if (result == NTFS_OK) {
		index->report.published = true;
		index->report.retained_bytes = required_bytes;
		source->page_index = index;
	}
	*out = index->report;
	if (result != NTFS_OK) {
		source->environment.release(
		    source->environment.context, index, index->allocation_bytes);
	}
	return result;
}

enum ntfs_result
ntfs_logfile_prepare_page_index(
    struct ntfs_logfile *source, uint64_t max_bytes, struct ntfs_logfile_page_index_report *out)
{
	return prepare_page_index(source, max_bytes, out, false);
}

enum ntfs_result
ntfs_logfile_prepare_write_page_index(
    struct ntfs_logfile *source, uint64_t max_bytes, struct ntfs_logfile_page_index_report *out)
{
	return prepare_page_index(source, max_bytes, out, true);
}

enum ntfs_result
ntfs_logfile_get_page_index_report(
    const struct ntfs_logfile *source, struct ntfs_logfile_page_index_report *out)
{
	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (source == NULL) {
		return NTFS_INVALID;
	}
	if (source->page_index == NULL) {
		return NTFS_NOT_FOUND;
	}
	*out = source->page_index->report;
	return NTFS_OK;
}

enum ntfs_result
ntfs_logfile_get_indexed_page(
    const struct ntfs_logfile *source, uint64_t offset, struct ntfs_logfile_indexed_page *out)
{
	const struct ntfs_logfile_restart *restart;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (source == NULL) {
		return NTFS_INVALID;
	}
	restart = &source->restart;
	if (offset < restart->circular_offset || offset % restart->log_page_bytes != 0 ||
	    !ntfs_bounds(offset, restart->log_page_bytes, restart->usable_bytes)) {
		return NTFS_INVALID;
	}
	if (source->page_index == NULL) {
		return NTFS_NOT_FOUND;
	}
	*out = source->page_index
		   ->entries[(offset - restart->circular_offset) / restart->log_page_bytes]
		   .page;
	return NTFS_OK;
}

static enum ntfs_result
load_indexed_page(struct ntfs_logfile *source, uint64_t offset, struct ntfs_logfile_report *work,
    struct ntfs_logfile_page_view *out)
{
	struct ntfs_logfile_indexed_page indexed;
	enum ntfs_result result;

	if (source->page_index != NULL && source->page_index->report.unsupported_copies != 0) {
		return NTFS_UNSUPPORTED;
	}
	result = ntfs_logfile_get_indexed_page(source, offset, &indexed);
	if (result != NTFS_OK) {
		return result;
	}
	if (indexed.result != NTFS_OK) {
		return indexed.result;
	}
	return index_reload(source, &indexed.selected, offset, work, out);
}

static enum ntfs_result
scan_fast_copies(
    struct ntfs_logfile *source, struct ntfs_logfile_report *work, struct fast_copies *copies)
{
	const struct ntfs_logfile_restart *restart = &source->restart;
	struct ntfs_logfile_page_view *page;
	struct ntfs_logfile_lsn location;
	uint64_t offset;
	uint32_t target;
	unsigned index;
	enum ntfs_result result;

	for (index = 0; index < NTFS_LOGFILE_FAST_COPY_PAGES; index++) {
		page = &copies->pages[index];
		offset = (uint64_t)NTFS_LFS_RESTART_PAGES * restart->system_page_bytes +
		    (uint64_t)index * restart->log_page_bytes;
		result = load_page(source, offset, work, page);
		if (source->backend_failed ||
		    (result != NTFS_OK && result != NTFS_CORRUPT && result != NTFS_NOT_FOUND)) {
			return result;
		}
		if (result != NTFS_OK) {
			continue;
		}
		result = fast_target(source, &target);
		if (result != NTFS_OK) {
			return result;
		}
		if (target < restart->circular_offset || target % restart->log_page_bytes != 0 ||
		    !ntfs_bounds(target, restart->log_page_bytes, restart->usable_bytes) ||
		    ntfs_logfile_lsn_decode(restart, page->page.copy_value, &location) != NTFS_OK ||
		    page->page.copy_value < page->page.last_end_lsn) {
			continue;
		}
		if ((page->page.flags &
			~(NTFS_LOGFILE_PAGE_RECORD_END | NTFS_LOGFILE_PAGE_CLIENT_RESTART)) != 0) {
			return NTFS_UNSUPPORTED;
		}
		copies->targets[index] = target;
		copies->available[index] = true;
	}
	return NTFS_OK;
}

static enum ntfs_result
reload_fast_copy(struct ntfs_logfile *source, struct ntfs_logfile_report *work,
    const struct fast_copies *copies, unsigned index, struct ntfs_logfile_page_view *out)
{
	uint32_t target;
	enum ntfs_result result;

	result = load_page(source, copies->pages[index].offset, work, out);
	if (result != NTFS_OK) {
		return result;
	}
	result = fast_target(source, &target);
	if (result != NTFS_OK) {
		return result;
	}
	if (target != copies->targets[index] ||
	    out->page.copy_value != copies->pages[index].page.copy_value ||
	    out->page.last_end_lsn != copies->pages[index].page.last_end_lsn ||
	    out->page.flags != copies->pages[index].page.flags ||
	    out->page.page_count != copies->pages[index].page.page_count ||
	    out->page.page_position != copies->pages[index].page.page_position ||
	    out->page.next_record_offset != copies->pages[index].page.next_record_offset) {
		return NTFS_STALE;
	}
	return NTFS_OK;
}

static bool
same_fast_prefix(const struct ntfs_logfile_restart *restart, const struct ntfs_logfile_page *a,
    const uint8_t *a_bytes, const struct ntfs_logfile_page *b, const uint8_t *b_bytes)
{
	return a->last_end_lsn == b->last_end_lsn &&
	    same_written_prefix(restart, a, a_bytes, b, b_bytes);
}

static enum ntfs_result
load_fast_page(struct ntfs_logfile *source, uint64_t offset, struct ntfs_logfile_report *work,
    struct fast_copies *copies, struct ntfs_logfile_page_view *out)
{
	const struct ntfs_logfile_restart *restart = &source->restart;
	const struct ntfs_logfile_page_view *candidate;
	struct ntfs_logfile_page_view circular = {0}, selected = {0}, duplicate = {0};
	struct ntfs_logfile_lsn location;
	enum ntfs_result circular_result, result;
	unsigned index, chosen = NTFS_LOGFILE_FAST_COPY_PAGES;

	for (index = 0; index < NTFS_LOGFILE_FAST_COPY_PAGES; index++) {
		if (copies->available[index] && copies->targets[index] == offset &&
		    (chosen == NTFS_LOGFILE_FAST_COPY_PAGES ||
			copies->pages[index].page.copy_value >
			    copies->pages[chosen].page.copy_value)) {
			chosen = index;
		}
	}
	circular_result = load_page(source, offset, work, &circular);
	if (source->backend_failed ||
	    (circular_result != NTFS_OK && circular_result != NTFS_CORRUPT &&
		circular_result != NTFS_NOT_FOUND)) {
		return circular_result;
	}
	if (circular_result == NTFS_OK &&
	    (circular.page.flags &
		~(NTFS_LOGFILE_PAGE_RECORD_END | NTFS_LOGFILE_PAGE_CLIENT_RESTART)) != 0) {
		return NTFS_UNSUPPORTED;
	}
	if (circular_result == NTFS_OK &&
	    (ntfs_logfile_lsn_decode(restart, circular.page.copy_value, &location) != NTFS_OK ||
		circular.page.copy_value < circular.page.last_end_lsn)) {
		circular_result = NTFS_CORRUPT;
	}
	if (chosen == NTFS_LOGFILE_FAST_COPY_PAGES ||
	    (circular_result == NTFS_OK &&
		circular.page.copy_value > copies->pages[chosen].page.copy_value)) {
		if (circular_result == NTFS_OK) {
			*out = circular;
		}
		return circular_result;
	}
	candidate = &copies->pages[chosen];
	if (candidate->page.last_end_lsn == 0 ||
	    (candidate->page.flags & NTFS_LOGFILE_PAGE_RECORD_END) == 0 ||
	    candidate->page.next_record_offset < restart->page_data_offset) {
		return NTFS_UNSUPPORTED;
	}
	if (circular_result == NTFS_OK) {
		ntfs_copy(copies->comparison, source->scratch, restart->log_page_bytes);
	}
	result = reload_fast_copy(source, work, copies, chosen, &selected);
	if (result != NTFS_OK) {
		return result;
	}
	if (circular_result == NTFS_OK && circular.page.copy_value == selected.page.copy_value &&
	    !same_fast_prefix(
		restart, &circular.page, copies->comparison, &selected.page, source->scratch)) {
		return NTFS_UNSUPPORTED;
	}
	ntfs_copy(copies->comparison, source->scratch, restart->log_page_bytes);
	for (index = 0; index < NTFS_LOGFILE_FAST_COPY_PAGES; index++) {
		if (index == chosen || !copies->available[index] ||
		    copies->targets[index] != offset ||
		    copies->pages[index].page.copy_value != selected.page.copy_value) {
			continue;
		}
		result = reload_fast_copy(source, work, copies, index, &duplicate);
		if (result != NTFS_OK) {
			return result;
		}
		if (!same_fast_prefix(restart, &selected.page, copies->comparison, &duplicate.page,
			source->scratch)) {
			return NTFS_UNSUPPORTED;
		}
	}
	ntfs_copy(source->scratch, copies->comparison, restart->log_page_bytes);
	*out = selected;
	return NTFS_OK;
}

static enum ntfs_result
load_history_page(struct ntfs_logfile *source, uint64_t offset, uint64_t lsn,
    struct ntfs_logfile_report *work, struct ntfs_logfile_page_view *out)
{
	const struct ntfs_logfile_restart *restart = &source->restart;
	const struct indexed_page_entry *entry;
	const struct ntfs_logfile_page_view *selected;

	entry = &source->page_index
		     ->entries[(offset - restart->circular_offset) / restart->log_page_bytes];
	if (entry->blocked || entry->page.prefix_conflict ||
	    (entry->page.result == NTFS_UNSUPPORTED &&
		(entry->equal_candidates & (entry->equal_candidates - 1u)) != 0)) {
		return NTFS_UNSUPPORTED;
	}
	if (entry->page.result != NTFS_OK &&
	    !(entry->page.result == NTFS_UNSUPPORTED &&
		entry->page.selected.storage != NTFS_LOGFILE_CIRCULAR &&
		entry->page.selected.offset != 0)) {
		return entry->page.result;
	}
	selected = &entry->page.selected;
	/* A legacy tail preserves the completed prefix. A matching protected
	 * circular page can additionally contain the new spanning record beyond
	 * that prefix. Equal-end prefix agreement was checked by preparation. */
	if (selected->storage == NTFS_LOGFILE_LEGACY_TAIL && selected->page.last_end_lsn < lsn &&
	    entry->circular.offset != 0 &&
	    entry->circular.page.last_end_lsn == selected->page.last_end_lsn &&
	    (entry->circular.page.copy_value == lsn || entry->circular.page.copy_value == 0)) {
		selected = &entry->circular;
	}
	return index_reload(source, selected, offset, work, out);
}

static enum ntfs_result
load_record_page(struct ntfs_logfile *source, uint64_t offset, uint64_t lsn,
    struct ntfs_logfile_report *work, const struct record_copies *copies,
    struct ntfs_logfile_page_view *out)
{
	const struct ntfs_logfile_checkpoint_capture_limits *limits;

	if (copies == NULL) {
		return load_page(source, offset, work, out);
	}
	limits = copies->capture_limits;
	if (limits != NULL &&
	    (work->read_calls >= limits->max_read_calls ||
		work->read_bytes > limits->max_read_bytes ||
		source->restart.log_page_bytes > limits->max_read_bytes - work->read_bytes)) {
		return NTFS_RANGE;
	}
	if (copies->indexed) {
		if (copies->history) {
			return load_history_page(source, offset, lsn, work, out);
		}
		return load_indexed_page(source, offset, work, out);
	}
	if (copies->legacy != NULL) {
		return load_legacy_page(source, offset, work, copies->legacy, out);
	}
	return load_fast_page(source, offset, work, copies->fast, out);
}

static enum ntfs_result
assemble_record(struct ntfs_logfile *source, uint64_t requested_lsn, void *bytes, size_t capacity,
    struct ntfs_logfile_record_view *out, struct ntfs_logfile_report *work,
    const struct record_copies *copies, struct record_ending *ending)
{
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
	if (ending != NULL) {
		ntfs_zero(ending, sizeof(*ending));
	}
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
	result = load_record_page(source, location.page_offset, requested_lsn, work, copies, &page);
	if (result != NTFS_OK) {
		return result;
	}
	if (ending != NULL && page.storage != NTFS_LOGFILE_LEGACY_TAIL &&
	    page.page.copy_value == 0) {
		return NTFS_STALE;
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
		if (ending != NULL) {
			/* Continuation framing follows the record's byte extent, never an
			 * I/O transfer's count/position. A full continuation contains no
			 * other starts or ends; the first partial record leaves its free
			 * boundary at its own header. */
			if (page.storage != NTFS_LOGFILE_LEGACY_TAIL && page.page.copy_value != 0 &&
			    (page.page.copy_value < requested_lsn ||
				(copied + amount < total &&
				    page.page.copy_value != requested_lsn))) {
				result = NTFS_STALE;
				goto done;
			}
			if (copied + amount < total &&
			    (page.page.next_record_offset != record_offset ||
				(copied != 0 &&
				    ((page.page.flags & NTFS_LOGFILE_PAGE_RECORD_END) != 0 ||
					page.page.last_end_lsn != 0)))) {
				result = NTFS_CORRUPT;
				goto done;
			}
		}
		/* A spanning record starts beyond the last completed prefix. Only its
		 * ending circular segment, and every selected completed tail segment,
		 * must fit the page's declared written prefix. */
		if (copies != NULL &&
		    ((ending == NULL && page.storage != NTFS_LOGFILE_CIRCULAR) ||
			copied + amount == total) &&
		    !ntfs_bounds(record_offset, amount, page.page.next_record_offset)) {
			result = NTFS_CORRUPT;
			goto done;
		}
		ntfs_copy(staged + copied, source->scratch + record_offset, amount);
		copied += amount;
		view.pages_read++;
		view.copy_pages_read += page.storage != NTFS_LOGFILE_CIRCULAR;
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
		result = load_record_page(source, offset, requested_lsn, work, copies, &page);
		if (result != NTFS_OK) {
			goto done;
		}
		record_offset = restart->page_data_offset;
	}
	if (copies != NULL &&
	    ((page.page.flags & NTFS_LOGFILE_PAGE_RECORD_END) == 0 ||
		page.page.last_end_lsn < requested_lsn)) {
		result = NTFS_STALE;
		goto done;
	}
	result = ntfs_logfile_record_decode(
	    staged, (size_t)total, restart->record_header_bytes, &view.record);
	if (result == NTFS_OK && ending != NULL && view.pages_read > 1 &&
	    (view.record.flags & NTFS_LOGFILE_RECORD_MULTI_PAGE) == 0) {
		result = NTFS_CORRUPT;
	}
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
		view.read_calls = work->read_calls;
		view.read_bytes = work->read_bytes;
		ntfs_copy(bytes, staged, (size_t)total);
		*out = view;
		if (ending != NULL) {
			ending->page = page;
			ending->offset = offset;
			ending->end_offset = record_offset + amount;
		}
	}
done:
	source->environment.release(source->environment.context, staged, (size_t)total);
	return result;
}

enum ntfs_result
ntfs_logfile_read_circular_record(struct ntfs_logfile *source, uint64_t requested_lsn, void *bytes,
    size_t capacity, struct ntfs_logfile_record_view *out)
{
	struct ntfs_logfile_report work = {0};

	return assemble_record(source, requested_lsn, bytes, capacity, out, &work, NULL, NULL);
}

enum ntfs_result
ntfs_logfile_read_indexed_record(struct ntfs_logfile *source, uint64_t requested_lsn, void *bytes,
    size_t capacity, struct ntfs_logfile_record_view *out)
{
	struct ntfs_logfile_report work = {0};
	struct record_copies route = {.indexed = true};

	return assemble_record(source, requested_lsn, bytes, capacity, out, &work, &route, NULL);
}

static enum ntfs_result
capture_packet(struct ntfs_logfile *source, uint64_t lsn, uint8_t *workspace, size_t capacity,
    struct ntfs_logfile_span *span, struct ntfs_logfile_report *work,
    const struct ntfs_logfile_checkpoint_capture_limits *limits,
    struct ntfs_logfile_checkpoint_capture_report *report)
{
	struct ntfs_logfile_record_view view;
	struct record_ending ending;
	struct record_copies route = {.capture_limits = limits, .indexed = true};
	enum ntfs_result result;

	report->requested_lsn = lsn;
	result = assemble_record(source, lsn, workspace + report->record_bytes,
	    capacity - report->record_bytes, &view, work, &route, &ending);
	report->read_calls = work->read_calls;
	report->read_bytes = work->read_bytes;
	if (result == NTFS_OK) {
		*span = (struct ntfs_logfile_span){report->record_bytes, view.bytes};
		report->record_bytes += view.bytes;
		report->acquired_records++;
		report->copy_pages_read += view.copy_pages_read;
	}
	return result;
}

enum ntfs_result
ntfs_logfile_capture_checkpoint(struct ntfs_logfile *source, uint16_t index, uint16_t sequence,
    const struct ntfs_logfile_checkpoint_capture_limits *limits, void *workspace, size_t capacity,
    void *names, size_t name_capacity, struct ntfs_logfile_checkpoint_capture *out,
    struct ntfs_logfile_checkpoint_capture_report *report)
{
	struct ntfs_logfile_checkpoint_capture value = {0};
	struct ntfs_logfile_checkpoint_dump dumps[NTFS_LOGFILE_CHECKPOINT_KINDS] = {0};
	struct ntfs_logfile_table_reference anchors[NTFS_LOGFILE_CHECKPOINT_KINDS];
	struct ntfs_logfile_report work = {0};
	struct ntfs_logfile_checkpoint_capture_limits admitted;
	const struct ntfs_logfile_checkpoint_capture_limits *budget = NULL;
	uint8_t *bytes = workspace;
	uint32_t kind, previous;
	enum ntfs_result result;

	_Static_assert(
	    NTFS_LOGFILE_CHECKPOINT_MAX_BYTES <= UINT32_MAX, "checkpoint workspace span capacity");
	if (out != NULL) {
		ntfs_zero(out, sizeof(*out));
	}
	if (report != NULL) {
		ntfs_zero(report, sizeof(*report));
	}
	if (out == NULL || report == NULL || source == NULL || workspace == NULL) {
		return NTFS_INVALID;
	}
	if (limits != NULL) {
		admitted = *limits;
		if (admitted.max_read_calls == 0 || admitted.max_read_bytes == 0) {
			return NTFS_INVALID;
		}
		budget = &admitted;
	}
	result = ntfs_logfile_get_active_client(source, index, sequence, &value.client);
	if (result != NTFS_OK) {
		return result;
	}
	if (!is_ntfs_client(&value.client)) {
		return NTFS_UNSUPPORTED;
	}
	report->checkpoint_lsn = value.client.restart_lsn;
	if (value.client.restart_lsn == 0) {
		return NTFS_NOT_FOUND;
	}
	result = capture_packet(source, value.client.restart_lsn, bytes, capacity,
	    &value.checkpoint, &work, budget, report);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_logfile_decode_client_restart_record(
	    source, bytes, value.checkpoint.length, &value.restart);
	if (result != NTFS_OK) {
		return result;
	}
	/* Admit the complete anchor set before any table read. This also prevents
	 * one packet being assigned two table roles by a forged restart payload. */
	for (kind = 0; kind < NTFS_LOGFILE_CHECKPOINT_KINDS; kind++) {
		result = ntfs_logfile_checkpoint_anchor(&source->restart, &value.restart,
		    value.client.restart_lsn, (enum ntfs_logfile_checkpoint_kind)kind,
		    &anchors[kind]);
		if (result == NTFS_NOT_FOUND) {
			continue;
		}
		if (result != NTFS_OK) {
			return result;
		}
		for (previous = 0; previous < kind; previous++) {
			if (anchors[previous].lsn == anchors[kind].lsn) {
				return NTFS_CORRUPT;
			}
		}
	}
	for (kind = 0; kind < NTFS_LOGFILE_CHECKPOINT_KINDS; kind++) {
		if (anchors[kind].lsn == 0) {
			continue;
		}
		result = capture_packet(source, anchors[kind].lsn, bytes, capacity,
		    &value.dumps[kind], &work, budget, report);
		if (result != NTFS_OK) {
			return result;
		}
		dumps[kind] = (struct ntfs_logfile_checkpoint_dump){
		    bytes + value.dumps[kind].offset, value.dumps[kind].length};
	}
	result = ntfs_logfile_checkpoint_decode(
	    source, bytes, value.checkpoint.length, dumps, names, name_capacity, &value.snapshot);
	if (result != NTFS_OK) {
		return result;
	}
	value.client_index = index;
	value.client_sequence = sequence;
	value.bytes = report->record_bytes;
	*out = value;
	report->complete = true;
	return NTFS_OK;
}

struct transaction_links {
	uint64_t lsn, undo_next_lsn;
};

static enum ntfs_result
transaction_link(const struct ntfs_logfile *source, uint64_t lsn, uint64_t current, uint64_t oldest)
{
	struct ntfs_logfile_lsn location;

	if (lsn == 0) {
		return NTFS_OK;
	}
	if (lsn >= current) {
		return NTFS_CORRUPT;
	}
	if (lsn < oldest) {
		return NTFS_STALE;
	}
	return ntfs_logfile_lsn_decode(&source->restart, lsn, &location) == NTFS_OK ? NTFS_OK
										    : NTFS_CORRUPT;
}

static bool
transaction_contains(const uint8_t *links, uint32_t count, uint64_t lsn)
{
	struct transaction_links link;
	uint32_t first = 0, last = count, middle;

	while (first < last) {
		middle = first + (last - first) / 2;
		ntfs_copy(&link, links + (size_t)middle * sizeof(link), sizeof(link));
		if (link.lsn == lsn) {
			return true;
		}
		if (link.lsn > lsn) {
			first = middle + 1;
		} else {
			last = middle;
		}
	}
	return false;
}

enum ntfs_result
ntfs_logfile_visit_transaction(struct ntfs_logfile *source, uint16_t index, uint16_t sequence,
    uint32_t transaction, uint64_t root_lsn, const struct ntfs_logfile_transaction_limits *limits,
    void *workspace, size_t capacity, void *link_workspace, size_t link_capacity,
    ntfs_logfile_record_visitor visitor, void *context,
    struct ntfs_logfile_transaction_report *report)
{
	struct ntfs_logfile_transaction_limits admitted;
	struct ntfs_logfile_checkpoint_capture_limits budget;
	struct record_copies route = {.capture_limits = &budget, .indexed = true};
	struct ntfs_logfile_report work = {0};
	struct ntfs_logfile_record_view view;
	struct ntfs_logfile_client client;
	struct ntfs_logfile_update update;
	struct ntfs_logfile_lsn location;
	struct transaction_links link;
	struct record_ending ending;
	uint8_t *links = link_workspace;
	uint64_t lsn;
	uint32_t item;
	enum ntfs_result result;

	_Static_assert(sizeof(link) == 2 * sizeof(uint64_t), "transaction link workspace");
	if (report != NULL) {
		ntfs_zero(report, sizeof(*report));
	}
	if (report == NULL || source == NULL || workspace == NULL || links == NULL ||
	    visitor == NULL || transaction == 0 || root_lsn == 0) {
		return NTFS_INVALID;
	}
	admitted = limits != NULL
	    ? *limits
	    : (struct ntfs_logfile_transaction_limits){NTFS_LOGFILE_TRANSACTION_MAX_RECORDS,
		  source->limits.max_read_calls, source->limits.max_read_bytes};
	if (admitted.max_records == 0 || admitted.max_read_calls == 0 ||
	    admitted.max_read_bytes == 0) {
		return NTFS_INVALID;
	}
	if (admitted.max_records > NTFS_LOGFILE_TRANSACTION_MAX_RECORDS ||
	    link_capacity / sizeof(link) < admitted.max_records) {
		return NTFS_RANGE;
	}
	budget = (struct ntfs_logfile_checkpoint_capture_limits){
	    admitted.max_read_calls, admitted.max_read_bytes};
	result = ntfs_logfile_get_active_client(source, index, sequence, &client);
	if (result != NTFS_OK) {
		return result;
	}
	if (!is_ntfs_client(&client) || client.oldest_lsn == 0) {
		return NTFS_UNSUPPORTED;
	}
	if (ntfs_logfile_lsn_decode(&source->restart, client.oldest_lsn, &location) != NTFS_OK ||
	    ntfs_logfile_lsn_decode(&source->restart, root_lsn, &location) != NTFS_OK) {
		return NTFS_CORRUPT;
	}
	if (root_lsn < client.oldest_lsn) {
		return NTFS_STALE;
	}
	report->root_lsn = root_lsn;
	report->transaction = transaction;
	report->next_lsn = root_lsn;
	lsn = root_lsn;
	while (lsn != 0) {
		if (report->examined_records == admitted.max_records) {
			return NTFS_RANGE;
		}
		result = assemble_record(
		    source, lsn, workspace, capacity, &view, &work, &route, &ending);
		report->read_calls = work.read_calls;
		report->read_bytes = work.read_bytes;
		if (result != NTFS_OK) {
			return result;
		}
		report->examined_records++;
		report->copy_pages_read += view.copy_pages_read;
		if (view.record.client_index != index || view.record.client_sequence != sequence ||
		    view.record.transaction != transaction) {
			return NTFS_STALE;
		}
		if (view.record.type != NTFS_LOGFILE_RECORD_UPDATE ||
		    (view.record.flags &
			(NTFS_LOGFILE_RECORD_ADDING | NTFS_LOGFILE_RECORD_DELETING)) != 0) {
			return NTFS_UNSUPPORTED;
		}
		result = transaction_link(source, view.record.previous_lsn, lsn, client.oldest_lsn);
		if (result == NTFS_OK) {
			result = transaction_link(
			    source, view.record.undo_next_lsn, lsn, client.oldest_lsn);
		}
		if (result != NTFS_OK) {
			return result;
		}
		result = ntfs_logfile_update_decode((uint8_t *)workspace + view.record.data.offset,
		    view.record.data.length, &update);
		if (result != NTFS_OK) {
			return result;
		}
		if (report->control_lsn == 0 &&
		    (update.redo_operation == NTFS_LOG_OP_PREPARE_TRANSACTION ||
			update.redo_operation == NTFS_LOG_OP_COMMIT_TRANSACTION ||
			update.redo_operation == NTFS_LOG_OP_FORGET_TRANSACTION)) {
			report->control_lsn = lsn;
			report->control_operation = update.redo_operation;
		}
		link = (struct transaction_links){lsn, view.record.undo_next_lsn};
		ntfs_copy(
		    links + (size_t)report->visited_records * sizeof(link), &link, sizeof(link));
		result = visitor(context, &view, workspace);
		if (result != NTFS_OK) {
			return result;
		}
		report->last_lsn = lsn;
		report->record_bytes += view.bytes;
		report->visited_records++;
		lsn = view.record.previous_lsn;
		report->next_lsn = lsn;
	}
	for (item = 0; item < report->visited_records; item++) {
		ntfs_copy(&link, links + (size_t)item * sizeof(link), sizeof(link));
		if (link.undo_next_lsn != 0) {
			if (!transaction_contains(
				links, report->visited_records, link.undo_next_lsn)) {
				return NTFS_CORRUPT;
			}
			report->undo_references++;
		}
	}
	report->complete = true;
	return NTFS_OK;
}

static enum ntfs_result
checkpoint_transaction_seed(const struct ntfs_logfile *source,
    const struct ntfs_logfile_transaction *seed, uint64_t table_lsn, uint64_t oldest)
{
	struct ntfs_logfile_lsn location;

	if (seed->first_lsn == 0 || seed->previous_lsn == 0) {
		return seed->state == NTFS_LOGFILE_TRANSACTION_UNINITIALIZED &&
			seed->first_lsn == 0 && seed->previous_lsn == 0 &&
			seed->undo_next_lsn == 0 && seed->undo_records == 0 && seed->undo_bytes == 0
		    ? NTFS_OK
		    : NTFS_UNSUPPORTED;
	}
	if (seed->first_lsn > seed->previous_lsn || seed->previous_lsn >= table_lsn ||
	    seed->undo_next_lsn > seed->previous_lsn ||
	    (seed->undo_next_lsn != 0 && seed->undo_next_lsn < seed->first_lsn)) {
		return NTFS_CORRUPT;
	}
	if (ntfs_logfile_lsn_decode(&source->restart, seed->first_lsn, &location) != NTFS_OK ||
	    ntfs_logfile_lsn_decode(&source->restart, seed->previous_lsn, &location) != NTFS_OK ||
	    (seed->undo_next_lsn != 0 &&
		ntfs_logfile_lsn_decode(&source->restart, seed->undo_next_lsn, &location) !=
		    NTFS_OK)) {
		return NTFS_CORRUPT;
	}
	if (oldest == 0) {
		return NTFS_UNSUPPORTED;
	}
	return seed->first_lsn < oldest ? NTFS_STALE : NTFS_OK;
}

static enum ntfs_result
checkpoint_transaction_packet(
    void *context, const struct ntfs_logfile_record_view *view, const void *bytes)
{
	(void)context;
	(void)view;
	(void)bytes;
	return NTFS_OK;
}

enum ntfs_result
ntfs_logfile_visit_checkpoint_transactions(struct ntfs_logfile *source, uint16_t index,
    uint16_t sequence, const struct ntfs_logfile_checkpoint_transaction_limits *limits,
    const struct ntfs_logfile_checkpoint_transaction_workspace *workspace,
    ntfs_logfile_checkpoint_transaction_visitor visitor, void *context,
    struct ntfs_logfile_checkpoint_transaction_report *report)
{
	struct ntfs_logfile_checkpoint_capture capture;
	struct ntfs_logfile_checkpoint_transaction_view view;
	struct ntfs_logfile_checkpoint_transaction_limits admitted;
	struct ntfs_logfile_checkpoint_transaction_workspace buffers;
	struct ntfs_logfile_checkpoint_capture_limits budget;
	struct ntfs_logfile_transaction_limits chain_limits;
	const struct ntfs_logfile_checkpoint_table *table;
	const uint8_t *body;
	uint32_t item, key, nonempty = 0;
	enum ntfs_result result;

	if (report != NULL) {
		ntfs_zero(report, sizeof(*report));
	}
	if (source == NULL || workspace == NULL || report == NULL || visitor == NULL) {
		return NTFS_INVALID;
	}
	buffers = *workspace;
	admitted = limits != NULL
	    ? *limits
	    : (struct ntfs_logfile_checkpoint_transaction_limits){
		  NTFS_LOGFILE_TRANSACTION_MAX_RECORDS, NTFS_LOGFILE_TRANSACTION_MAX_RECORDS,
		  source->limits.max_read_calls, source->limits.max_read_bytes};
	if (buffers.checkpoint_records == NULL || buffers.record == NULL || buffers.links == NULL ||
	    admitted.max_transactions == 0 || admitted.max_records == 0 ||
	    admitted.max_read_calls == 0 || admitted.max_read_bytes == 0) {
		return NTFS_INVALID;
	}
	if (admitted.max_transactions > NTFS_LOGFILE_TRANSACTION_MAX_RECORDS ||
	    admitted.max_records > NTFS_LOGFILE_TRANSACTION_MAX_RECORDS ||
	    buffers.link_capacity / sizeof(struct transaction_links) < admitted.max_records) {
		return NTFS_RANGE;
	}
	budget.max_read_calls = admitted.max_read_calls < source->limits.max_read_calls
	    ? admitted.max_read_calls
	    : source->limits.max_read_calls;
	budget.max_read_bytes = admitted.max_read_bytes < source->limits.max_read_bytes
	    ? admitted.max_read_bytes
	    : source->limits.max_read_bytes;
	result = ntfs_logfile_capture_checkpoint(source, index, sequence, &budget,
	    buffers.checkpoint_records, buffers.checkpoint_capacity, buffers.names,
	    buffers.name_capacity, &capture, &report->checkpoint);
	report->read_calls = report->checkpoint.read_calls;
	report->read_bytes = report->checkpoint.read_bytes;
	report->record_bytes = report->checkpoint.record_bytes;
	report->copy_pages_read = report->checkpoint.copy_pages_read;
	if (result != NTFS_OK) {
		return result;
	}
	if ((capture.snapshot.present_mask & (1u << NTFS_LOGFILE_CHECKPOINT_TRANSACTIONS)) == 0) {
		return NTFS_NOT_FOUND;
	}
	table = &capture.snapshot.tables[NTFS_LOGFILE_CHECKPOINT_TRANSACTIONS];
	body = (const uint8_t *)buffers.checkpoint_records +
	    capture.dumps[NTFS_LOGFILE_CHECKPOINT_TRANSACTIONS].offset + table->body.offset;
	report->table_lsn = table->table_lsn;
	report->allocated_transactions = table->table.allocated_count;
	if (table->table.allocated_count > admitted.max_transactions) {
		return NTFS_RANGE;
	}
	/* A bad later seed must not expose any earlier transaction to the visitor. */
	for (item = 0; item < table->table.entry_count; item++) {
		key = table->table.entries.offset + item * table->table.entry_bytes;
		result = ntfs_logfile_transaction_decode(
		    body + key, table->table.entry_bytes, &view.snapshot);
		if (result == NTFS_NOT_FOUND) {
			continue;
		}
		report->requested_transaction = key;
		if (result != NTFS_OK) {
			return result;
		}
		result = checkpoint_transaction_seed(
		    source, &view.snapshot, table->table_lsn, capture.client.oldest_lsn);
		if (result != NTFS_OK) {
			return result;
		}
		if (view.snapshot.previous_lsn != 0) {
			nonempty++;
		}
	}
	report->requested_transaction = 0;
	if (nonempty > admitted.max_records) {
		return NTFS_RANGE;
	}
	for (item = 0; item < table->table.entry_count; item++) {
		key = table->table.entries.offset + item * table->table.entry_bytes;
		ntfs_zero(&view, sizeof(view));
		result = ntfs_logfile_transaction_decode(
		    body + key, table->table.entry_bytes, &view.snapshot);
		if (result == NTFS_NOT_FOUND) {
			continue;
		}
		if (result != NTFS_OK) {
			return result;
		}
		view.key = key;
		report->requested_transaction = key;
		if (view.snapshot.previous_lsn != 0) {
			if (report->read_calls == budget.max_read_calls ||
			    report->read_bytes == budget.max_read_bytes ||
			    report->examined_records == admitted.max_records) {
				return NTFS_RANGE;
			}
			chain_limits = (struct ntfs_logfile_transaction_limits){
			    admitted.max_records - report->examined_records,
			    budget.max_read_calls - report->read_calls,
			    budget.max_read_bytes - report->read_bytes};
			result = ntfs_logfile_visit_transaction(source, index, sequence, key,
			    view.snapshot.previous_lsn, &chain_limits, buffers.record,
			    buffers.record_capacity, buffers.links, buffers.link_capacity,
			    checkpoint_transaction_packet, NULL, &view.chain);
			report->read_calls += view.chain.read_calls;
			report->read_bytes += view.chain.read_bytes;
			report->record_bytes += view.chain.record_bytes;
			report->copy_pages_read += view.chain.copy_pages_read;
			report->examined_records += view.chain.examined_records;
			report->checked_records += view.chain.visited_records;
			if (result != NTFS_OK) {
				return result;
			}
			if (view.chain.last_lsn != view.snapshot.first_lsn ||
			    (view.snapshot.undo_next_lsn != 0 &&
				!transaction_contains(buffers.links, view.chain.visited_records,
				    view.snapshot.undo_next_lsn))) {
				return NTFS_CORRUPT;
			}
		} else {
			view.chain.transaction = key;
			view.chain.complete = true;
		}
		report->verified_transactions++;
		result = visitor(context, &view);
		if (result != NTFS_OK) {
			return result;
		}
		report->visited_transactions++;
	}
	report->complete = true;
	return NTFS_OK;
}

static enum ntfs_result
history_bounds(struct ntfs_logfile *source, uint64_t first, struct ntfs_logfile_history_report *out,
    uint64_t *end_target)
{
	const struct ntfs_logfile_restart *restart = &source->restart;
	const struct page_index *index = source->page_index;
	const struct indexed_page_entry *entry;
	const struct ntfs_logfile_page_view *view;
	struct ntfs_logfile_lsn beginning, end, started;
	uint32_t ordinal, slot;
	uint64_t completed, candidate;
	bool duplicate = false;
	enum ntfs_result result;

	result = ntfs_logfile_lsn_decode(restart, first, &beginning);
	if (result != NTFS_OK) {
		return result;
	}
	if (index == NULL) {
		return NTFS_NOT_FOUND;
	}
	if (index->report.unsupported_copies != 0 || index->unrouted_undated ||
	    index->unrouted_lsn >= first) {
		return NTFS_UNSUPPORTED;
	}
	for (ordinal = 0; ordinal < index->report.indexed_targets; ordinal++) {
		entry = &index->entries[ordinal];
		if (entry->page.retained_fast_copy) {
			continue;
		}
		if (entry->blocked || entry->page.prefix_conflict ||
		    (entry->page.result == NTFS_UNSUPPORTED &&
			(entry->equal_candidates & (entry->equal_candidates - 1u)) != 0)) {
			return NTFS_UNSUPPORTED;
		}
		if (entry->page.result == NTFS_CORRUPT) {
			return NTFS_CORRUPT;
		}
		if (entry->page.result != NTFS_OK &&
		    !(entry->page.result == NTFS_UNSUPPORTED && entry->page.selected.offset != 0 &&
			entry->page.selected.storage != NTFS_LOGFILE_CIRCULAR)) {
			continue;
		}
		view = &entry->page.selected;
		completed = (view->page.flags & NTFS_LOGFILE_PAGE_RECORD_END) != 0
		    ? view->page.last_end_lsn
		    : 0;
		/* A newer partial page may replace obsolete records, but cannot
		 * erase a completed record in the requested retained interval. */
		if (entry->circular.offset != 0 &&
		    (entry->circular.page.flags & NTFS_LOGFILE_PAGE_RECORD_END) != 0 &&
		    entry->circular.page.last_end_lsn >= first &&
		    entry->circular.page.last_end_lsn > completed) {
			return NTFS_STALE;
		}
		if (completed > out->candidate_end_lsn) {
			out->candidate_end_lsn = completed;
			*end_target = entry->page.target_offset;
			duplicate = false;
		} else if (completed >= first && completed == out->candidate_end_lsn) {
			duplicate = true;
		}
		view = restart->major == NTFS_LFS_MAJOR_LEGACY ? &entry->circular
							       : &entry->page.selected;
		if (view->offset != 0 && view->page.copy_value > out->observed_start_lsn &&
		    ntfs_logfile_lsn_decode(restart, view->page.copy_value, &started) == NTFS_OK) {
			out->observed_start_lsn = view->page.copy_value;
		}
	}
	/* Copy targets come from their declared routing fields. A continuation's
	 * last-start LSN can name a different page. Keep this pass linear in the
	 * fixed copy count, rather than rechecking every slot for every target. */
	for (slot = 0; slot < NTFS_LOGFILE_FAST_COPY_PAGES; slot++) {
		view = &index->copies[slot];
		candidate = view->page.last_end_lsn;
		if (view->offset == 0 || (view->page.flags & NTFS_LOGFILE_PAGE_RECORD_END) == 0 ||
		    candidate < first) {
			continue;
		}
		entry = &index->entries[(index->copy_targets[slot] - restart->circular_offset) /
		    restart->log_page_bytes];
		completed = (entry->page.selected.page.flags & NTFS_LOGFILE_PAGE_RECORD_END) != 0
		    ? entry->page.selected.page.last_end_lsn
		    : 0;
		if (candidate > completed) {
			return NTFS_STALE;
		}
	}
	if (out->candidate_end_lsn == 0 || out->candidate_end_lsn < first) {
		return NTFS_NOT_FOUND;
	}
	if (duplicate) {
		return NTFS_CORRUPT;
	}
	result = ntfs_logfile_lsn_decode(restart, out->candidate_end_lsn, &end);
	if (result != NTFS_OK) {
		return result;
	}
	if (end.sequence < beginning.sequence || end.sequence - beginning.sequence > 1 ||
	    (end.sequence == beginning.sequence && end.file_offset < beginning.file_offset) ||
	    (end.sequence != beginning.sequence && end.page_offset >= beginning.page_offset)) {
		return NTFS_STALE;
	}
	return NTFS_OK;
}

static enum ntfs_result
history_next_lsn(const struct ntfs_logfile_restart *restart, uint64_t current,
    const struct ntfs_logfile_record_view *record, const struct record_ending *ending,
    bool next_page, uint64_t *out)
{
	struct ntfs_logfile_lsn location;
	uint64_t sequence, offset, record_offset, maximum_sequence;
	uint32_t offset_bits;
	enum ntfs_result result;

	result = ntfs_logfile_lsn_decode(restart, current, &location);
	if (result != NTFS_OK) {
		return result;
	}
	offset_bits = NTFS_LFS_LSN_BITS - restart->sequence_bits;
	maximum_sequence = UINT64_MAX >> offset_bits;
	sequence = location.sequence;
	if (record->wrapped) {
		if (sequence == maximum_sequence) {
			return NTFS_RANGE;
		}
		sequence++;
	}
	offset = ending->offset;
	record_offset =
	    (ending->end_offset + NTFS_WIRE_ALIGNMENT - 1) & ~(uint64_t)(NTFS_WIRE_ALIGNMENT - 1);
	if (next_page ||
	    !ntfs_bounds(record_offset, restart->record_header_bytes, restart->log_page_bytes)) {
		offset += restart->log_page_bytes;
		if (offset == restart->usable_bytes) {
			offset = restart->circular_offset;
			if (sequence == maximum_sequence) {
				return NTFS_RANGE;
			}
			sequence++;
		}
		record_offset = restart->page_data_offset;
	}
	*out = (sequence << offset_bits) | ((offset + record_offset) >> NTFS_LFS_LSN_OFFSET_SHIFT);
	return *out > current ? NTFS_OK : NTFS_CORRUPT;
}

static enum ntfs_result
history_tail(struct ntfs_logfile *source, const struct ntfs_logfile_record_view *last,
    const struct record_ending *ending, struct ntfs_logfile_report *work,
    const struct ntfs_logfile_checkpoint_capture_limits *limits,
    struct ntfs_logfile_history_report *out)
{
	const struct ntfs_logfile_restart *restart = &source->restart;
	const struct indexed_page_entry *entry;
	const struct ntfs_logfile_page_view *expected;
	struct ntfs_logfile_page_view page;
	struct ntfs_logfile_record record;
	struct ntfs_logfile_lsn location, linked;
	uint64_t adjacent;
	uint32_t bytes;
	enum ntfs_result result;

	if (out->observed_start_lsn <= out->candidate_end_lsn) {
		return NTFS_OK;
	}
	out->tail_lsn = out->observed_start_lsn;
	result = ntfs_logfile_lsn_decode(restart, out->tail_lsn, &location);
	if (result != NTFS_OK) {
		return result;
	}
	if (out->tail_lsn != out->next_lsn) {
		result = history_next_lsn(restart, last->record.lsn, last, ending, true, &adjacent);
		if (result != NTFS_OK) {
			return result;
		}
		if (out->tail_lsn != adjacent) {
			return NTFS_STALE;
		}
	}
	entry = &source->page_index->entries[(location.page_offset - restart->circular_offset) /
	    restart->log_page_bytes];
	expected =
	    restart->major == NTFS_LFS_MAJOR_LEGACY ? &entry->circular : &entry->page.selected;
	if (expected->offset == 0 || expected->page.copy_value != out->tail_lsn) {
		return NTFS_STALE;
	}
	if (limits != NULL &&
	    (work->read_calls >= limits->max_read_calls ||
		work->read_bytes > limits->max_read_bytes ||
		restart->log_page_bytes > limits->max_read_bytes - work->read_bytes)) {
		return NTFS_RANGE;
	}
	result = index_reload(source, expected, location.page_offset, work, &page);
	if (result != NTFS_OK) {
		return result;
	}
	if (page.page.next_record_offset != location.record_offset ||
	    page.page.last_end_lsn > out->candidate_end_lsn) {
		return NTFS_CORRUPT;
	}
	result = ntfs_logfile_record_prefix(source->scratch + location.record_offset,
	    restart->log_page_bytes - location.record_offset, restart->record_header_bytes, &record,
	    &bytes);
	if (result != NTFS_OK) {
		return result;
	}
	if (record.lsn != out->tail_lsn) {
		return NTFS_STALE;
	}
	if ((record.flags & NTFS_LOGFILE_RECORD_MULTI_PAGE) == 0 ||
	    bytes <= restart->log_page_bytes - location.record_offset ||
	    (record.previous_lsn != 0 &&
		ntfs_logfile_lsn_decode(restart, record.previous_lsn, &linked) != NTFS_OK) ||
	    (record.undo_next_lsn != 0 &&
		ntfs_logfile_lsn_decode(restart, record.undo_next_lsn, &linked) != NTFS_OK)) {
		return NTFS_CORRUPT;
	}
	out->tail_verified = true;
	out->next_lsn = out->tail_lsn;
	return NTFS_OK;
}

enum ntfs_result
ntfs_logfile_visit_records_limited(struct ntfs_logfile *source, uint64_t first,
    uint32_t max_records, const struct ntfs_logfile_checkpoint_capture_limits *limits,
    void *workspace, size_t capacity, ntfs_logfile_record_visitor visitor, void *context,
    struct ntfs_logfile_history_report *out)
{
	struct record_copies route = {.indexed = true, .history = true};
	struct ntfs_logfile_checkpoint_capture_limits admitted;
	struct ntfs_logfile_report work = {0};
	struct ntfs_logfile_record_view record;
	struct record_ending ending;
	struct ntfs_logfile_lsn location, beginning;
	struct ntfs_logfile_lsn started;
	const struct ntfs_logfile_restart *restart;
	const struct indexed_page_entry *entry;
	uint64_t current, end_target, before_bytes, aligned, ending_sequence, last_start;
	uint32_t before_calls;
	bool pending_start;
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (source == NULL || workspace == NULL || max_records == 0) {
		return NTFS_INVALID;
	}
	if (limits != NULL) {
		admitted = *limits;
		if (admitted.max_read_calls == 0 || admitted.max_read_bytes == 0) {
			return NTFS_INVALID;
		}
		route.capture_limits = &admitted;
	}
	restart = &source->restart;
	if (capacity < restart->record_header_bytes) {
		return NTFS_RANGE;
	}
	out->first_lsn = first;
	out->next_lsn = first;
	result = history_bounds(source, first, out, &end_target);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_logfile_lsn_decode(restart, first, &beginning);
	if (result != NTFS_OK) {
		return result;
	}
	current = first;
	for (;;) {
		if (out->examined_records == max_records) {
			result = NTFS_RANGE;
			break;
		}
		before_calls = work.read_calls;
		before_bytes = work.read_bytes;
		result = assemble_record(
		    source, current, workspace, capacity, &record, &work, &route, &ending);
		if (result != NTFS_OK) {
			break;
		}
		record.read_calls -= before_calls;
		record.read_bytes -= before_bytes;
		aligned = (ending.end_offset + NTFS_WIRE_ALIGNMENT - 1) &
		    ~(uint64_t)(NTFS_WIRE_ALIGNMENT - 1);
		if (ending.page.page.last_end_lsn > out->candidate_end_lsn ||
		    aligned > ending.page.page.next_record_offset) {
			result = NTFS_CORRUPT;
			break;
		}
		result = ntfs_logfile_lsn_decode(restart, current, &location);
		if (result != NTFS_OK) {
			break;
		}
		ending_sequence = location.sequence + (record.wrapped ? 1u : 0u);
		if (ending_sequence - beginning.sequence > 1 ||
		    (ending_sequence != beginning.sequence &&
			ending.offset >= beginning.page_offset)) {
			result = NTFS_STALE;
			break;
		}
		if (current == out->candidate_end_lsn &&
		    (ending.offset != end_target || ending.page.page.last_end_lsn != current ||
			aligned != ending.page.page.next_record_offset)) {
			result = NTFS_CORRUPT;
			break;
		}
		out->examined_records++;
		out->last_lsn = current;
		out->record_bytes += record.bytes;
		out->copy_pages_read += record.copy_pages_read;
		out->wrapped |= record.wrapped;
		if (visitor != NULL) {
			result = visitor(context, &record, workspace);
			if (result != NTFS_OK) {
				break;
			}
		}
		out->visited_records++;
		if (current == out->candidate_end_lsn) {
			out->endpoint_verified = true;
			out->completed_end_lsn = current;
			result = history_next_lsn(
			    restart, current, &record, &ending, false, &out->next_lsn);
			if (result == NTFS_OK) {
				result = history_tail(
				    source, &record, &ending, &work, route.capture_limits, out);
			}
			out->complete = result == NTFS_OK;
			break;
		}
		/* A completed prefix can end at the next spanning record's header.
		 * Only a matching last-start witness keeps that boundary on this page;
		 * otherwise the closed prefix advances to the next physical payload. */
		last_start = ending.page.page.copy_value;
		if (restart->major == NTFS_LFS_MAJOR_LEGACY) {
			entry = &source->page_index
				     ->entries[(ending.offset - restart->circular_offset) /
					 restart->log_page_bytes];
			last_start = entry->circular.page.copy_value;
		}
		pending_start = last_start > current &&
		    ntfs_logfile_lsn_decode(restart, last_start, &started) == NTFS_OK &&
		    started.file_offset == ending.offset + aligned;
		result = history_next_lsn(restart, current, &record, &ending,
		    aligned == ending.page.page.next_record_offset && !pending_start,
		    &out->next_lsn);
		if (result != NTFS_OK) {
			break;
		}
		current = out->next_lsn;
		result = ntfs_logfile_lsn_decode(restart, current, &location);
		if (result != NTFS_OK) {
			break;
		}
		if (current > out->candidate_end_lsn ||
		    location.sequence - beginning.sequence > 1 ||
		    (location.sequence != beginning.sequence &&
			location.page_offset >= beginning.page_offset)) {
			result = NTFS_STALE;
			break;
		}
		out->wrapped |= location.sequence != beginning.sequence;
	}
	out->read_calls = work.read_calls;
	out->read_bytes = work.read_bytes;
	return result;
}

enum ntfs_result
ntfs_logfile_visit_records(struct ntfs_logfile *source, uint64_t first, uint32_t max_records,
    void *workspace, size_t capacity, ntfs_logfile_record_visitor visitor, void *context,
    struct ntfs_logfile_history_report *out)
{
	return ntfs_logfile_visit_records_limited(
	    source, first, max_records, NULL, workspace, capacity, visitor, context, out);
}

enum ntfs_result
ntfs_logfile_read_legacy_record(struct ntfs_logfile *source, uint64_t requested_lsn, void *bytes,
    size_t capacity, struct ntfs_logfile_record_view *out)
{
	struct legacy_copies copies = {0};
	struct record_copies route = {.legacy = &copies};
	struct ntfs_logfile_report work = {0};
	struct ntfs_logfile_lsn location;
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (source == NULL || bytes == NULL) {
		return NTFS_INVALID;
	}
	if (source->restart.major != NTFS_LFS_MAJOR_LEGACY) {
		return NTFS_UNSUPPORTED;
	}
	result = ntfs_logfile_lsn_decode(&source->restart, requested_lsn, &location);
	if (result != NTFS_OK) {
		return result;
	}
	if (capacity < source->restart.record_header_bytes) {
		return NTFS_RANGE;
	}
	copies.comparison = source->environment.allocate(
	    source->environment.context, source->restart.log_page_bytes);
	if (copies.comparison == NULL) {
		return NTFS_NO_MEMORY;
	}
	result = scan_legacy_copies(source, &work, &copies);
	if (result == NTFS_OK) {
		result = assemble_record(
		    source, requested_lsn, bytes, capacity, out, &work, &route, NULL);
	}
	source->environment.release(
	    source->environment.context, copies.comparison, source->restart.log_page_bytes);
	return result;
}

enum ntfs_result
ntfs_logfile_read_fast_record(struct ntfs_logfile *source, uint64_t requested_lsn, void *bytes,
    size_t capacity, struct ntfs_logfile_record_view *out)
{
	struct ntfs_logfile_report work = {0};
	struct ntfs_logfile_lsn location;
	struct record_copies route;
	const struct ntfs_logfile_restart *restart;
	struct fast_copies *copies;
	size_t workspace_bytes;
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(out, sizeof(*out));
	if (source == NULL || bytes == NULL) {
		return NTFS_INVALID;
	}
	restart = &source->restart;
	if (restart->major != NTFS_LFS_MAJOR_FAST ||
	    restart->system_page_bytes != NTFS_LFS_FAST_PAGE_BYTES ||
	    restart->log_page_bytes != NTFS_LFS_FAST_PAGE_BYTES ||
	    restart->page_data_offset < sizeof(struct ntfs_disk_log_fast_page)) {
		return NTFS_UNSUPPORTED;
	}
	result = ntfs_logfile_lsn_decode(restart, requested_lsn, &location);
	if (result != NTFS_OK) {
		return result;
	}
	if (capacity < restart->record_header_bytes ||
	    source->limits.max_read_calls <= NTFS_LOGFILE_FAST_COPY_PAGES ||
	    source->limits.max_read_bytes <
		(uint64_t)(NTFS_LOGFILE_FAST_COPY_PAGES + 1) * restart->log_page_bytes) {
		return NTFS_RANGE;
	}
	workspace_bytes = sizeof(*copies) + restart->log_page_bytes;
	copies = source->environment.allocate(source->environment.context, workspace_bytes);
	if (copies == NULL) {
		return NTFS_NO_MEMORY;
	}
	ntfs_zero(copies, sizeof(*copies));
	copies->comparison = (uint8_t *)(copies + 1);
	route = (struct record_copies){.fast = copies};
	result = scan_fast_copies(source, &work, copies);
	if (result == NTFS_OK) {
		result = assemble_record(
		    source, requested_lsn, bytes, capacity, out, &work, &route, NULL);
	}
	source->environment.release(source->environment.context, copies, workspace_bytes);
	return result;
}
