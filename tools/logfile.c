/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/logfile.h>
#include <ntfs/logfile_tables.h>
#include <ntfs/checkpoint.h>
#include "image.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum { LOGFILE_DIAGNOSTIC_VERSION = 1, LOGFILE_ARGUMENT_ERROR = 2 };

enum { LOGFILE_INVENTORY_READ_CALLS = 4096, LOGFILE_INVENTORY_READ_BYTES = 16 * 1024 * 1024 };

static bool
number(const char *text, uint64_t maximum, uint64_t *out)
{
	uint64_t value = 0;
	unsigned digit;

	if (*text == '\0') {
		return false;
	}
	while (*text != '\0') {
		if (*text < '0' || *text > '9') {
			return false;
		}
		digit = (unsigned)(*text++ - '0');
		if (digit > maximum || value > (maximum - digit) / 10u) {
			return false;
		}
		value = value * 10u + digit;
	}
	*out = value;
	return true;
}

static uint8_t *
read_packet(const char *path, size_t maximum, size_t *size)
{
	struct stat info;
	uint8_t *bytes = NULL, extra;
	size_t position = 0;
	ssize_t got;
	int fd;

	fd = open(path, O_RDONLY | O_NONBLOCK);
	if (fd < 0) {
		return NULL;
	}
	if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size <= 0 ||
	    (uint64_t)info.st_size > maximum) {
		goto done;
	}
	*size = (size_t)info.st_size;
	bytes = malloc(*size);
	if (bytes == NULL) {
		goto done;
	}
	while (position < *size) {
		got = read(fd, bytes + position, *size - position);
		if (got < 0 && errno == EINTR) {
			continue;
		}
		if (got <= 0) {
			goto invalid;
		}
		position += (size_t)got;
	}
	do {
		got = read(fd, &extra, sizeof(extra));
	} while (got < 0 && errno == EINTR);
	if (got != 0) {
		goto invalid;
	}
	goto done;
invalid:
	free(bytes);
	bytes = NULL;
done:
	close(fd);
	return bytes;
}

static void
span(const char *name, struct ntfs_logfile_span value)
{
	printf(",\"%s\":{\"offset\":%" PRIu32 ",\"length\":%" PRIu32 "}", name, value.offset,
	    value.length);
}

static void
restart_fields(const struct ntfs_logfile_restart *r, bool comma)
{
	printf("%s\"major\":%u,\"minor\":%u,\"flags\":%u,\"clean_hint\":%s,"
	       "\"system_page_bytes\":%" PRIu32 ",\"log_page_bytes\":%" PRIu32
	       ",\"file_bytes\":%" PRIu64 ",\"usable_bytes\":%" PRIu64
	       ",\"circular_offset\":%" PRIu64 ",\"current_lsn\":%" PRIu64
	       ",\"sequence_bits\":%" PRIu32 ",\"last_data_bytes\":%" PRIu32
	       ",\"open_count\":%" PRIu32 ",\"record_header_bytes\":%u,\"page_data_offset\":%u,"
	       "\"free_head\":%u,\"in_use_head\":%u,\"client_count\":%u",
	    comma ? "," : "", r->major, r->minor, r->flags, r->clean_hint ? "true" : "false",
	    r->system_page_bytes, r->log_page_bytes, r->file_bytes, r->usable_bytes,
	    r->circular_offset, r->current_lsn, r->sequence_bits, r->last_data_bytes, r->open_count,
	    r->record_header_bytes, r->page_data_offset, r->free_head, r->in_use_head,
	    r->client_count);
	span("area", r->area);
	span("clients", r->clients);
}

static void
client_restart_fields(const struct ntfs_logfile_client_restart *value)
{
	printf(",\"major\":%" PRIu32 ",\"minor\":%" PRIu32 ",\"analysis_lsn\":%" PRIu64,
	    value->major, value->minor, value->analysis_lsn);
	printf(",\"open_attributes\":{\"lsn\":%" PRIu64 ",\"bytes\":%" PRIu32 "}",
	    value->open_attributes.lsn, value->open_attributes.bytes);
	printf(",\"attribute_names\":{\"lsn\":%" PRIu64 ",\"bytes\":%" PRIu32 "}",
	    value->attribute_names.lsn, value->attribute_names.bytes);
	printf(",\"dirty_pages\":{\"lsn\":%" PRIu64 ",\"bytes\":%" PRIu32 "}",
	    value->dirty_pages.lsn, value->dirty_pages.bytes);
	printf(",\"transactions\":{\"lsn\":%" PRIu64 ",\"bytes\":%" PRIu32 "}",
	    value->transactions.lsn, value->transactions.bytes);
	span("extension", value->extension);
}

static void
client_fields(const struct ntfs_logfile_client *client, bool comma)
{
	size_t j;

	printf("%s{\"oldest_lsn\":%" PRIu64 ",\"restart_lsn\":%" PRIu64
	       ",\"previous\":%u,\"next\":%u,\"sequence\":%u,\"name_utf16\":[",
	    comma ? "," : "", client->oldest_lsn, client->restart_lsn, client->previous,
	    client->next, client->sequence);
	for (j = 0; j < client->name_length; j++) {
		printf("%s%u", j == 0 ? "" : ",", client->name[j]);
	}
	printf("]}");
}

static void
record_fields(const struct ntfs_logfile_record *record, bool comma)
{
	printf("%s\"lsn\":%" PRIu64 ",\"previous_lsn\":%" PRIu64 ",\"undo_next_lsn\":%" PRIu64
	       ",\"type\":%" PRIu32 ",\"transaction\":%" PRIu32 ",\"client_sequence\":%u,"
	       "\"client_index\":%u,\"flags\":%u",
	    comma ? "," : "", record->lsn, record->previous_lsn, record->undo_next_lsn,
	    record->type, record->transaction, record->client_sequence, record->client_index,
	    record->flags);
	span("data", record->data);
}

static void
restart(const struct ntfs_logfile_restart *r, const uint8_t *scratch)
{
	struct ntfs_logfile_client client;
	size_t i, client_bytes;

	restart_fields(r, true);
	printf(",\"client_records\":[");
	client_bytes = r->client_count == 0 ? 0 : r->clients.length / r->client_count;
	for (i = 0; i < r->client_count; i++) {
		if (ntfs_logfile_client_decode(scratch + r->clients.offset + i * client_bytes,
			client_bytes, &client) != NTFS_OK) {
			/* Only successfully decoded restart snapshots reach this path. */
			abort();
		}
		client_fields(&client, i != 0);
	}
	printf("]");
}

static int
journal(const char *path, bool volume_source)
{
	struct ntfs_image image;
	struct ntfs_volume *volume = NULL;
	struct ntfs_logfile *source = NULL;
	struct ntfs_logfile_report report = {0};
	struct ntfs_logfile_restart r;
	struct ntfs_logfile_client client;
	const struct ntfs_logfile_probe *probe;
	uint16_t i;
	enum ntfs_result result;

	if (ntfs_image_open(path, &image) != 0) {
		fprintf(stderr, "Cannot open read-only regular-file source\n");
		return LOGFILE_ARGUMENT_ERROR;
	}
	report.selected_probe = NTFS_LOGFILE_NO_PROBE;
	if (volume_source) {
		result = ntfs_mount(&image.environment, NULL, &volume);
		if (result == NTFS_OK) {
			result = ntfs_logfile_open_volume(volume, NULL, &report, &source);
		}
	} else {
		result = ntfs_logfile_open(&image.environment, NULL, &report, &source);
	}
	printf("{\"schema_version\":%u,\"scope\":\"%s\",\"code\":%d,\"result\":\"%s\","
	       "\"recovery_qualified\":false,\"scan_complete\":%s,\"selection\":%d,\"selected_"
	       "probe\":",
	    LOGFILE_DIAGNOSTIC_VERSION, volume_source ? "volume-journal" : "journal", (int)result,
	    ntfs_result_string(result), report.scan_complete ? "true" : "false",
	    (int)report.selection);
	if (report.selected_probe == NTFS_LOGFILE_NO_PROBE) {
		printf("null");
	} else {
		printf("%u", report.selected_probe);
	}
	printf(",\"read_calls\":%" PRIu32 ",\"read_bytes\":%" PRIu64 ",\"probes\":[",
	    report.read_calls, report.read_bytes);
	for (i = 0; i < report.probe_count; i++) {
		probe = &report.probes[i];
		printf("%s{\"offset\":%" PRIu64 ",\"page_bytes\":%" PRIu32
		       ",\"code\":%d,\"current_lsn\":%" PRIu64 "}",
		    i == 0 ? "" : ",", probe->offset, probe->page_bytes, (int)probe->result,
		    probe->restart.current_lsn);
	}
	printf("],\"selected_restart\":");
	if (result == NTFS_OK) {
		if (ntfs_logfile_get_restart(source, &r) != NTFS_OK) {
			abort();
		}
		printf("{");
		restart_fields(&r, false);
		printf(",\"client_records\":[");
		for (i = 0; i < r.client_count; i++) {
			if (ntfs_logfile_get_client(source, i, &client) != NTFS_OK) {
				abort();
			}
			client_fields(&client, i != 0);
		}
		printf("]}");
	} else {
		printf("null");
	}
	printf("}\n");
	ntfs_logfile_close(source);
	if (ntfs_unmount(volume) != NTFS_OK) {
		abort();
	}
	ntfs_image_close(&image);
	return result == NTFS_OK ? 0 : 1;
}

static enum ntfs_result
inventory_page(void *context, const struct ntfs_logfile_page_observation *observation)
{
	const struct ntfs_logfile_page *page = &observation->page;
	bool *first = context;

	printf("%s{\"offset\":%" PRIu64 ",\"storage\":%d,\"code\":%d,\"target_code\":%d,"
	       "\"target_offset\":%" PRIu64 ",\"page\":",
	    *first ? "" : ",", observation->offset, (int)observation->storage,
	    (int)observation->result, (int)observation->target_result, observation->target_offset);
	*first = false;
	if (observation->result != NTFS_OK) {
		printf("null}");
	} else {
		printf("{\"copy_value\":%" PRIu64 ",\"last_end_lsn\":%" PRIu64 ",\"flags\":%" PRIu32
		       ",\"page_count\":%u,\"page_position\":%u,"
		       "\"next_record_offset\":%u}}",
		    page->copy_value, page->last_end_lsn, page->flags, page->page_count,
		    page->page_position, page->next_record_offset);
	}
	return ferror(stdout) ? NTFS_IO : NTFS_OK;
}

static int
journal_pages(const char *path)
{
	struct ntfs_image image;
	struct ntfs_logfile *source = NULL;
	struct ntfs_logfile_limits limits;
	struct ntfs_logfile_inventory inventory = {0};
	struct ntfs_logfile_restart restart = {0};
	bool first = true;
	enum ntfs_result result;

	if (ntfs_image_open(path, &image) != 0) {
		fprintf(stderr, "Cannot open read-only regular-file source\n");
		return LOGFILE_ARGUMENT_ERROR;
	}
	ntfs_logfile_default_limits(&limits);
	limits.max_read_calls = LOGFILE_INVENTORY_READ_CALLS;
	limits.max_read_bytes = LOGFILE_INVENTORY_READ_BYTES;
	result = ntfs_logfile_open(&image.environment, &limits, NULL, &source);
	printf("{\"schema_version\":%u,\"scope\":\"pages\",\"history_qualified\":false,"
	       "\"recovery_qualified\":false,\"pages\":[",
	    LOGFILE_DIAGNOSTIC_VERSION);
	if (result == NTFS_OK) {
		if (ntfs_logfile_get_restart(source, &restart) != NTFS_OK) {
			abort();
		}
		result = ntfs_logfile_visit_pages(source, inventory_page, &first, &inventory);
	}
	printf("],\"code\":%d,\"result\":\"%s\",\"restart_current_lsn\":%" PRIu64
	       ",\"inventory\":{\"complete\":%s,\"total_pages\":%" PRIu32
	       ",\"examined_pages\":%" PRIu32 ",\"visited_pages\":%" PRIu32
	       ",\"decoded_pages\":%" PRIu32 ",\"missing_pages\":%" PRIu32
	       ",\"corrupt_pages\":%" PRIu32 ",\"invalid_targets\":%" PRIu32
	       ",\"unsupported_targets\":%" PRIu32 ",\"read_calls\":%" PRIu32
	       ",\"read_bytes\":%" PRIu64 ",\"next_offset\":%" PRIu64
	       ",\"max_observed_epoch_lsn\":%" PRIu64 ",\"max_observed_end_lsn\":%" PRIu64 "}}\n",
	    (int)result, ntfs_result_string(result), restart.current_lsn,
	    inventory.complete ? "true" : "false", inventory.total_pages, inventory.examined_pages,
	    inventory.visited_pages, inventory.decoded_pages, inventory.missing_pages,
	    inventory.corrupt_pages, inventory.invalid_targets, inventory.unsupported_targets,
	    inventory.read_calls, inventory.read_bytes, inventory.next_offset,
	    inventory.max_observed_epoch_lsn, inventory.max_observed_end_lsn);
	ntfs_logfile_close(source);
	ntfs_image_close(&image);
	return result == NTFS_OK && !ferror(stdout) ? 0 : 1;
}

static int
circular_record(const char *path, uint64_t lsn, bool legacy_copies, bool fast_copies)
{
	struct ntfs_image image;
	struct ntfs_logfile *source = NULL;
	struct ntfs_logfile_record_view view;
	struct ntfs_logfile_limits limits;
	uint8_t *bytes = NULL;
	size_t i;
	enum ntfs_result result;

	if (ntfs_image_open(path, &image) != 0) {
		fprintf(stderr, "Cannot open read-only regular-file source\n");
		return LOGFILE_ARGUMENT_ERROR;
	}
	ntfs_logfile_default_limits(&limits);
	if (fast_copies) {
		/* One full slot scan plus the normal record budget and an equal-copy
		 * comparison. The core never raises caller credits internally. */
		limits.max_read_calls += NTFS_LOGFILE_FAST_COPY_PAGES + 1;
		limits.max_read_bytes *= 2;
	}
	result = ntfs_logfile_open(&image.environment, &limits, NULL, &source);
	if (result == NTFS_OK) {
		bytes = malloc(NTFS_LOGFILE_MAX_RECORD_BYTES);
		if (bytes == NULL) {
			result = NTFS_NO_MEMORY;
		} else if (fast_copies) {
			result = ntfs_logfile_read_fast_record(
			    source, lsn, bytes, NTFS_LOGFILE_MAX_RECORD_BYTES, &view);
		} else if (legacy_copies) {
			result = ntfs_logfile_read_legacy_record(
			    source, lsn, bytes, NTFS_LOGFILE_MAX_RECORD_BYTES, &view);
		} else {
			result = ntfs_logfile_read_circular_record(
			    source, lsn, bytes, NTFS_LOGFILE_MAX_RECORD_BYTES, &view);
		}
	}
	printf("{\"schema_version\":%u,\"scope\":\"%s\",\"code\":%d,"
	       "\"result\":\"%s\",\"recovery_qualified\":false,\"requested_lsn\":%" PRIu64
	       ",\"record\":",
	    LOGFILE_DIAGNOSTIC_VERSION,
	    fast_copies		? "fast-record"
		: legacy_copies ? "legacy-record"
				: "circular-record",
	    (int)result, ntfs_result_string(result), lsn);
	if (result == NTFS_OK) {
		printf("{");
		record_fields(&view.record, false);
		printf("},\"assembly\":{\"first_page_offset\":%" PRIu64
		       ",\"last_page_offset\":%" PRIu64 ",\"bytes\":%" PRIu32
		       ",\"pages_read\":%" PRIu32 ",\"copy_pages_read\":%" PRIu32
		       ",\"read_calls\":%" PRIu32 ",\"read_bytes\":%" PRIu64
		       ",\"wrapped\":%s},\"bytes_hex\":\"",
		    view.first_page_offset, view.last_page_offset, view.bytes, view.pages_read,
		    view.copy_pages_read, view.read_calls, view.read_bytes,
		    view.wrapped ? "true" : "false");
		for (i = 0; i < view.bytes; i++) {
			printf("%02x", (unsigned)bytes[i]);
		}
		printf("\"");
	} else {
		printf("null,\"assembly\":null,\"bytes_hex\":null");
	}
	printf("}\n");
	free(bytes);
	ntfs_logfile_close(source);
	ntfs_image_close(&image);
	return result == NTFS_OK ? 0 : 1;
}

static int
active_client(const char *path, uint16_t index, uint16_t sequence)
{
	struct ntfs_image image;
	struct ntfs_logfile *source = NULL;
	struct ntfs_logfile_client client;
	enum ntfs_result result;

	if (ntfs_image_open(path, &image) != 0) {
		fprintf(stderr, "Cannot open read-only regular-file source\n");
		return LOGFILE_ARGUMENT_ERROR;
	}
	result = ntfs_logfile_open(&image.environment, NULL, NULL, &source);
	if (result == NTFS_OK) {
		result = ntfs_logfile_get_active_client(source, index, sequence, &client);
	}
	printf("{\"schema_version\":%u,\"scope\":\"active-client\",\"code\":%d,"
	       "\"result\":\"%s\",\"recovery_qualified\":false,\"index\":%u,"
	       "\"sequence\":%u,\"client\":",
	    LOGFILE_DIAGNOSTIC_VERSION, (int)result, ntfs_result_string(result), index, sequence);
	if (result == NTFS_OK) {
		client_fields(&client, false);
	} else {
		printf("null");
	}
	printf("}\n");
	ntfs_logfile_close(source);
	ntfs_image_close(&image);
	return result == NTFS_OK ? 0 : 1;
}

static int
client_restart_record(const char *path, const char *packet_path)
{
	struct ntfs_image image;
	struct ntfs_logfile *source = NULL;
	struct ntfs_logfile_client_restart value = {0};
	uint8_t *bytes;
	size_t size;
	enum ntfs_result result;

	bytes = read_packet(packet_path, NTFS_LOGFILE_MAX_RECORD_BYTES, &size);
	if (bytes == NULL) {
		fprintf(stderr, "Cannot read bounded regular-file packet\n");
		return LOGFILE_ARGUMENT_ERROR;
	}
	if (ntfs_image_open(path, &image) != 0) {
		free(bytes);
		fprintf(stderr, "Cannot open read-only regular-file source\n");
		return LOGFILE_ARGUMENT_ERROR;
	}
	result = ntfs_logfile_open(&image.environment, NULL, NULL, &source);
	if (result == NTFS_OK) {
		result = ntfs_logfile_decode_client_restart_record(source, bytes, size, &value);
	}
	printf("{\"schema_version\":%u,\"scope\":\"client-restart-record\",\"code\":%d,"
	       "\"result\":\"%s\",\"recovery_qualified\":false",
	    LOGFILE_DIAGNOSTIC_VERSION, (int)result, ntfs_result_string(result));
	client_restart_fields(&value);
	printf("}\n");
	free(bytes);
	ntfs_logfile_close(source);
	ntfs_image_close(&image);
	return result == NTFS_OK ? 0 : 1;
}

static void
checkpoint_fields(const struct ntfs_logfile_checkpoint_table *value)
{
	printf("\"kind\":%u,\"client_major\":%" PRIu32 ",\"client_minor\":%" PRIu32
	       ",\"checkpoint_lsn\":%" PRIu64 ",\"table_lsn\":%" PRIu64,
	    (unsigned)value->kind, value->client_major, value->client_minor, value->checkpoint_lsn,
	    value->table_lsn);
	span("body", value->body);
	printf(",\"table\":{\"entry_bytes\":%u,\"entry_count\":%u,\"allocated_count\":%u,"
	       "\"free_goal\":%" PRIu32 ",\"first_free\":%" PRIu32 ",\"last_free\":%" PRIu32,
	    value->table.entry_bytes, value->table.entry_count, value->table.allocated_count,
	    value->table.free_goal, value->table.first_free, value->table.last_free);
	span("entries", value->table.entries);
	printf("},\"names\":{\"entry_count\":%" PRIu32, value->names.entry_count);
	span("entries", value->names.entries);
	printf("}");
}

static int
checkpoint_table(
    const char *path, const char *checkpoint_path, const char *kind_name, const char *table_path)
{
	static const char *const kinds[] = {
	    "open-attributes", "attribute-names", "dirty-pages", "transactions"};
	struct ntfs_image image;
	struct ntfs_logfile *source = NULL;
	struct ntfs_logfile_checkpoint_table value = {0};
	uint8_t *checkpoint, *table = NULL;
	size_t checkpoint_bytes, table_bytes = 0, kind;
	enum ntfs_result result;

	for (kind = 0; kind < sizeof(kinds) / sizeof(kinds[0]); kind++) {
		if (strcmp(kind_name, kinds[kind]) == 0) {
			break;
		}
	}
	if (kind == sizeof(kinds) / sizeof(kinds[0])) {
		fprintf(stderr, "Unknown checkpoint table kind\n");
		return LOGFILE_ARGUMENT_ERROR;
	}
	checkpoint = read_packet(checkpoint_path, NTFS_LOGFILE_MAX_RECORD_BYTES, &checkpoint_bytes);
	if (checkpoint == NULL) {
		fprintf(stderr, "Cannot read bounded checkpoint record\n");
		return LOGFILE_ARGUMENT_ERROR;
	}
	if (strcmp(table_path, "-") != 0) {
		table = read_packet(table_path, NTFS_LOGFILE_MAX_RECORD_BYTES, &table_bytes);
		if (table == NULL) {
			free(checkpoint);
			fprintf(stderr, "Cannot read bounded table record\n");
			return LOGFILE_ARGUMENT_ERROR;
		}
	}
	if (ntfs_image_open(path, &image) != 0) {
		free(table);
		free(checkpoint);
		fprintf(stderr, "Cannot open read-only regular-file source\n");
		return LOGFILE_ARGUMENT_ERROR;
	}
	result = ntfs_logfile_open(&image.environment, NULL, NULL, &source);
	if (result == NTFS_OK) {
		result = ntfs_logfile_checkpoint_table_decode(source,
		    (enum ntfs_logfile_checkpoint_kind)kind, checkpoint, checkpoint_bytes, table,
		    table_bytes, &value);
	}
	printf("{\"schema_version\":%u,\"scope\":\"checkpoint-table\",\"code\":%d,"
	       "\"result\":\"%s\",\"recovery_qualified\":false,\"requested_kind\":\"%s\",",
	    LOGFILE_DIAGNOSTIC_VERSION, (int)result, ntfs_result_string(result), kind_name);
	checkpoint_fields(&value);
	printf("}\n");
	free(table);
	free(checkpoint);
	ntfs_logfile_close(source);
	ntfs_image_close(&image);
	return result == NTFS_OK ? 0 : 1;
}

enum {
	LOGFILE_SNAPSHOT_SOURCE_ARGUMENT = 2,
	LOGFILE_SNAPSHOT_CHECKPOINT_ARGUMENT = LOGFILE_SNAPSHOT_SOURCE_ARGUMENT + 1,
	LOGFILE_SNAPSHOT_DUMPS_ARGUMENT = LOGFILE_SNAPSHOT_CHECKPOINT_ARGUMENT + 1,
	LOGFILE_SNAPSHOT_WORKSPACE_ARGUMENT =
	    LOGFILE_SNAPSHOT_DUMPS_ARGUMENT + NTFS_LOGFILE_CHECKPOINT_KINDS,
	LOGFILE_SNAPSHOT_ARGUMENTS = LOGFILE_SNAPSHOT_WORKSPACE_ARGUMENT + 1
};

static int
checkpoint_snapshot(char **argv)
{
	struct ntfs_image image;
	struct ntfs_logfile *source = NULL;
	struct ntfs_logfile_checkpoint_snapshot value = {0};
	struct ntfs_logfile_checkpoint_dump dumps[NTFS_LOGFILE_CHECKPOINT_KINDS] = {0};
	uint8_t *checkpoint = NULL, *workspace = NULL,
		*packets[NTFS_LOGFILE_CHECKPOINT_KINDS] = {0};
	size_t checkpoint_bytes, kind;
	uint64_t capacity = 0;
	bool null_workspace, opened = false;
	enum ntfs_result result;
	int status = LOGFILE_ARGUMENT_ERROR;

	null_workspace = strcmp(argv[LOGFILE_SNAPSHOT_WORKSPACE_ARGUMENT], "-") == 0;
	if (!null_workspace &&
	    !number(argv[LOGFILE_SNAPSHOT_WORKSPACE_ARGUMENT],
		NTFS_LOGFILE_CHECKPOINT_NAME_WORKSPACE_BYTES, &capacity)) {
		fprintf(stderr, "Invalid checkpoint name workspace capacity\n");
		goto done;
	}
	checkpoint = read_packet(argv[LOGFILE_SNAPSHOT_CHECKPOINT_ARGUMENT],
	    NTFS_LOGFILE_MAX_RECORD_BYTES, &checkpoint_bytes);
	if (checkpoint == NULL) {
		fprintf(stderr, "Cannot read bounded checkpoint record\n");
		goto done;
	}
	for (kind = 0; kind < NTFS_LOGFILE_CHECKPOINT_KINDS; kind++) {
		if (strcmp(argv[LOGFILE_SNAPSHOT_DUMPS_ARGUMENT + kind], "-") != 0) {
			packets[kind] = read_packet(argv[LOGFILE_SNAPSHOT_DUMPS_ARGUMENT + kind],
			    NTFS_LOGFILE_MAX_RECORD_BYTES, &dumps[kind].bytes);
			if (packets[kind] == NULL) {
				fprintf(stderr, "Cannot read bounded checkpoint dump\n");
				goto done;
			}
			dumps[kind].data = packets[kind];
		}
	}
	if (!null_workspace) {
		workspace = malloc(capacity == 0 ? 1 : (size_t)capacity);
		if (workspace == NULL) {
			goto done;
		}
	}
	if (ntfs_image_open(argv[LOGFILE_SNAPSHOT_SOURCE_ARGUMENT], &image) != 0) {
		fprintf(stderr, "Cannot open read-only regular-file source\n");
		goto done;
	}
	opened = true;
	result = ntfs_logfile_open(&image.environment, NULL, NULL, &source);
	if (result == NTFS_OK) {
		result = ntfs_logfile_checkpoint_decode(source, checkpoint, checkpoint_bytes, dumps,
		    workspace, (size_t)capacity, &value);
	}
	printf("{\"schema_version\":%u,\"scope\":\"checkpoint-snapshot\",\"code\":%d,"
	       "\"result\":\"%s\",\"recovery_qualified\":false,\"present_mask\":%" PRIu32
	       ",\"client_major\":%" PRIu32 ",\"client_minor\":%" PRIu32
	       ",\"checkpoint_lsn\":%" PRIu64 ",\"named_attributes\":%" PRIu32
	       ",\"dirty_pages\":%" PRIu32 ",\"tables\":[",
	    LOGFILE_DIAGNOSTIC_VERSION, (int)result, ntfs_result_string(result), value.present_mask,
	    value.client_major, value.client_minor, value.checkpoint_lsn, value.named_attributes,
	    value.dirty_pages);
	for (kind = 0; kind < NTFS_LOGFILE_CHECKPOINT_KINDS; kind++) {
		printf("%s{", kind == 0 ? "" : ",");
		checkpoint_fields(&value.tables[kind]);
		printf("}");
	}
	printf("]}\n");
	status = result == NTFS_OK ? 0 : 1;
done:
	ntfs_logfile_close(source);
	if (opened) {
		ntfs_image_close(&image);
	}
	for (kind = 0; kind < NTFS_LOGFILE_CHECKPOINT_KINDS; kind++) {
		free(packets[kind]);
	}
	free(workspace);
	free(checkpoint);
	return status;
}

int
main(int argc, char **argv)
{
	struct ntfs_logfile_restart configuration, r = {0};
	struct ntfs_logfile_page p = {0};
	struct ntfs_logfile_record record = {0};
	struct ntfs_logfile_update update = {0};
	struct ntfs_logfile_client_restart client_restart = {0};
	struct ntfs_logfile_attribute_name attribute_name = {0};
	struct ntfs_logfile_attribute_names attribute_names = {0};
	uint8_t *bytes = NULL, *scratch = NULL, *restart_bytes = NULL, *restart_scratch = NULL;
	size_t size, restart_size, maximum;
	uint64_t argument = 0, sequence;
	enum ntfs_result result;
	bool is_restart, is_page, is_record, is_update, is_client_restart;
	bool is_attribute_name, is_attribute_names;
	int status = LOGFILE_ARGUMENT_ERROR;

	if (argc < 3) {
		goto usage;
	}
	if (strcmp(argv[1], "checkpoint-snapshot") == 0) {
		if (argc != LOGFILE_SNAPSHOT_ARGUMENTS) {
			goto usage;
		}
		return checkpoint_snapshot(argv);
	}
	if (strcmp(argv[1], "checkpoint-table") == 0) {
		if (argc != 6) {
			goto usage;
		}
		return checkpoint_table(argv[2], argv[3], argv[4], argv[5]);
	}
	if (argc == 3 &&
	    (strcmp(argv[1], "journal") == 0 || strcmp(argv[1], "volume-journal") == 0)) {
		return journal(argv[2], strcmp(argv[1], "volume-journal") == 0);
	}
	if (argc == 3 && strcmp(argv[1], "pages") == 0) {
		return journal_pages(argv[2]);
	}
	if (strcmp(argv[1], "circular-record") == 0 || strcmp(argv[1], "legacy-record") == 0 ||
	    strcmp(argv[1], "fast-record") == 0) {
		if (argc != 4 || !number(argv[3], UINT64_MAX, &argument)) {
			goto usage;
		}
		return circular_record(argv[2], argument, strcmp(argv[1], "legacy-record") == 0,
		    strcmp(argv[1], "fast-record") == 0);
	}
	if (strcmp(argv[1], "active-client") == 0) {
		if (argc != 5 || !number(argv[3], UINT16_MAX, &argument) ||
		    !number(argv[4], UINT16_MAX, &sequence)) {
			goto usage;
		}
		return active_client(argv[2], (uint16_t)argument, (uint16_t)sequence);
	}
	if (strcmp(argv[1], "client-restart-record") == 0) {
		if (argc != 4) {
			goto usage;
		}
		return client_restart_record(argv[2], argv[3]);
	}
	is_restart = strcmp(argv[1], "restart") == 0;
	is_page = strcmp(argv[1], "page") == 0;
	is_record = strcmp(argv[1], "record") == 0;
	is_update = strcmp(argv[1], "update") == 0;
	is_client_restart = strcmp(argv[1], "client-restart") == 0;
	is_attribute_name = strcmp(argv[1], "attribute-name") == 0;
	is_attribute_names = strcmp(argv[1], "attribute-names") == 0;
	if ((is_restart && argc == 4) || (is_page && argc == 5)) {
		if (!number(argv[argc - 1], NTFS_LOGFILE_MAX_FILE_BYTES, &argument)) {
			goto usage;
		}
	} else if (is_record && argc == 4) {
		if (!number(argv[3], UINT16_MAX, &argument)) {
			goto usage;
		}
	} else if ((!is_update && !is_client_restart && !is_attribute_name &&
		       !is_attribute_names) ||
	    argc != 3) {
		goto usage;
	}
	maximum =
	    is_restart || is_page ? NTFS_LOGFILE_MAX_PAGE_BYTES : NTFS_LOGFILE_MAX_RECORD_BYTES;
	bytes = read_packet(argv[2], maximum, &size);
	if (bytes == NULL) {
		fprintf(stderr, "Cannot read bounded regular-file packet\n");
		goto done;
	}
	if (is_restart || is_page) {
		scratch = malloc(size);
		if (scratch == NULL) {
			goto done;
		}
	}
	if (is_page) {
		restart_bytes = read_packet(argv[3], NTFS_LOGFILE_MAX_PAGE_BYTES, &restart_size);
		if (restart_bytes == NULL) {
			goto done;
		}
		restart_scratch = malloc(restart_size);
		if (restart_scratch == NULL) {
			goto done;
		}
		result = ntfs_logfile_restart_decode(restart_bytes, restart_size, argument,
		    restart_scratch, restart_size, &configuration);
		if (result != NTFS_OK) {
			fprintf(stderr, "Restart configuration: %s\n", ntfs_result_string(result));
			goto done;
		}
		result = ntfs_logfile_page_decode(bytes, size, &configuration, scratch, size, &p);
	} else if (is_restart) {
		result = ntfs_logfile_restart_decode(bytes, size, argument, scratch, size, &r);
	} else if (is_record) {
		result = ntfs_logfile_record_decode(bytes, size, (uint16_t)argument, &record);
	} else if (is_client_restart) {
		result = ntfs_logfile_client_restart_decode(bytes, size, &client_restart);
	} else if (is_attribute_name) {
		result = ntfs_logfile_attribute_name_decode(bytes, size, &attribute_name);
	} else if (is_attribute_names) {
		result = ntfs_logfile_attribute_names_decode(bytes, size, &attribute_names);
	} else {
		result = ntfs_logfile_update_decode(bytes, size, &update);
	}
	printf("{\"schema_version\":%u,\"scope\":\"%s\",\"code\":%d,\"result\":\"%s\","
	       "\"recovery_qualified\":false",
	    LOGFILE_DIAGNOSTIC_VERSION, argv[1], (int)result, ntfs_result_string(result));
	if (is_restart) {
		restart(&r, scratch);
	} else if (is_page) {
		printf(",\"copy_value\":%" PRIu64 ",\"last_end_lsn\":%" PRIu64 ",\"flags\":%" PRIu32
		       ",\"page_count\":%u,\"page_position\":%u,"
		       "\"next_record_offset\":%u",
		    p.copy_value, p.last_end_lsn, p.flags, p.page_count, p.page_position,
		    p.next_record_offset);
	} else if (is_record) {
		record_fields(&record, true);
	} else if (is_client_restart) {
		client_restart_fields(&client_restart);
	} else if (is_attribute_name) {
		printf(",\"target_attribute\":%u,\"name_units\":%u,\"bytes\":%" PRIu32,
		    attribute_name.target_attribute, attribute_name.name_units,
		    attribute_name.bytes);
		span("name", attribute_name.name);
	} else if (is_attribute_names) {
		printf(",\"entry_count\":%" PRIu32, attribute_names.entry_count);
		span("entries", attribute_names.entries);
	} else {
		printf(",\"redo_operation\":%u,\"undo_operation\":%u,\"target_attribute\":%u,"
		       "\"lcn_count\":%u,\"record_offset\":%u,\"attribute_offset\":%u,"
		       "\"cluster_index\":%u,\"attribute_flags\":%u,\"target_vcn\":%" PRIu64,
		    update.redo_operation, update.undo_operation, update.target_attribute,
		    update.lcn_count, update.record_offset, update.attribute_offset,
		    update.cluster_index, update.attribute_flags, update.target_vcn);
		span("redo", update.redo);
		span("undo", update.undo);
		span("lcns", update.lcns);
	}
	printf("}\n");
	status = result == NTFS_OK ? 0 : 1;
	goto done;
usage:
	fprintf(stderr,
	    "Usage: ntfs-logfile restart PAGE FILE_BYTES\n"
	    "       ntfs-logfile page PAGE RESTART_PAGE FILE_BYTES\n"
	    "       ntfs-logfile record PACKET HEADER_BYTES\n"
	    "       ntfs-logfile update CLIENT_PACKET\n"
	    "       ntfs-logfile attribute-name ENTRY_PACKET\n"
	    "       ntfs-logfile attribute-names NAMES_PACKET\n"
	    "       ntfs-logfile client-restart CLIENT_PACKET\n"
	    "       ntfs-logfile client-restart-record LOGICAL_JOURNAL_FILE ASSEMBLED_RECORD\n"
	    "       ntfs-logfile checkpoint-table JOURNAL CHECKPOINT_RECORD KIND TABLE_RECORD|-\n"
	    "       ntfs-logfile checkpoint-snapshot JOURNAL CHECKPOINT OPEN|- NAMES|- DIRTY|- "
	    "TX|- WORKSPACE_BYTES|-\n"
	    "       ntfs-logfile journal LOGICAL_JOURNAL_FILE\n"
	    "       ntfs-logfile pages LOGICAL_JOURNAL_FILE\n"
	    "       ntfs-logfile volume-journal NTFS_IMAGE_FILE\n"
	    "       ntfs-logfile circular-record LOGICAL_JOURNAL_FILE DECIMAL_LSN\n"
	    "       ntfs-logfile legacy-record LOGICAL_JOURNAL_FILE DECIMAL_LSN\n"
	    "       ntfs-logfile fast-record LOGICAL_JOURNAL_FILE DECIMAL_LSN\n"
	    "       ntfs-logfile active-client LOGICAL_JOURNAL_FILE INDEX SEQUENCE\n");
done:
	free(restart_scratch);
	free(restart_bytes);
	free(scratch);
	free(bytes);
	return status;
}
