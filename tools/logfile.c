/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/logfile.h>
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

static int
circular_record(const char *path, uint64_t lsn)
{
	struct ntfs_image image;
	struct ntfs_logfile *source = NULL;
	struct ntfs_logfile_record_view view;
	uint8_t *bytes = NULL;
	size_t i;
	enum ntfs_result result;

	if (ntfs_image_open(path, &image) != 0) {
		fprintf(stderr, "Cannot open read-only regular-file source\n");
		return LOGFILE_ARGUMENT_ERROR;
	}
	result = ntfs_logfile_open(&image.environment, NULL, NULL, &source);
	if (result == NTFS_OK) {
		bytes = malloc(NTFS_LOGFILE_MAX_RECORD_BYTES);
		result = bytes == NULL ? NTFS_NO_MEMORY
				       : ntfs_logfile_read_circular_record(source, lsn, bytes,
					     NTFS_LOGFILE_MAX_RECORD_BYTES, &view);
	}
	printf("{\"schema_version\":%u,\"scope\":\"circular-record\",\"code\":%d,"
	       "\"result\":\"%s\",\"recovery_qualified\":false,\"requested_lsn\":%" PRIu64
	       ",\"record\":",
	    LOGFILE_DIAGNOSTIC_VERSION, (int)result, ntfs_result_string(result), lsn);
	if (result == NTFS_OK) {
		printf("{");
		record_fields(&view.record, false);
		printf("},\"assembly\":{\"first_page_offset\":%" PRIu64
		       ",\"last_page_offset\":%" PRIu64 ",\"bytes\":%" PRIu32
		       ",\"pages_read\":%" PRIu32 ",\"read_calls\":%" PRIu32
		       ",\"read_bytes\":%" PRIu64 ",\"wrapped\":%s},\"bytes_hex\":\"",
		    view.first_page_offset, view.last_page_offset, view.bytes, view.pages_read,
		    view.read_calls, view.read_bytes, view.wrapped ? "true" : "false");
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

int
main(int argc, char **argv)
{
	struct ntfs_logfile_restart configuration, r = {0};
	struct ntfs_logfile_page p = {0};
	struct ntfs_logfile_record record = {0};
	struct ntfs_logfile_update update = {0};
	struct ntfs_logfile_client_restart client_restart = {0};
	uint8_t *bytes = NULL, *scratch = NULL, *restart_bytes = NULL, *restart_scratch = NULL;
	size_t size, restart_size, maximum;
	uint64_t argument = 0, sequence;
	enum ntfs_result result;
	bool is_restart, is_page, is_record, is_update, is_client_restart;
	int status = LOGFILE_ARGUMENT_ERROR;

	if (argc < 3) {
		goto usage;
	}
	if (argc == 3 &&
	    (strcmp(argv[1], "journal") == 0 || strcmp(argv[1], "volume-journal") == 0)) {
		return journal(argv[2], strcmp(argv[1], "volume-journal") == 0);
	}
	if (strcmp(argv[1], "circular-record") == 0) {
		if (argc != 4 || !number(argv[3], UINT64_MAX, &argument)) {
			goto usage;
		}
		return circular_record(argv[2], argument);
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
	if ((is_restart && argc == 4) || (is_page && argc == 5)) {
		if (!number(argv[argc - 1], NTFS_LOGFILE_MAX_FILE_BYTES, &argument)) {
			goto usage;
		}
	} else if (is_record && argc == 4) {
		if (!number(argv[3], UINT16_MAX, &argument)) {
			goto usage;
		}
	} else if ((!is_update && !is_client_restart) || argc != 3) {
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
	    "       ntfs-logfile client-restart CLIENT_PACKET\n"
	    "       ntfs-logfile client-restart-record LOGICAL_JOURNAL_FILE ASSEMBLED_RECORD\n"
	    "       ntfs-logfile journal LOGICAL_JOURNAL_FILE\n"
	    "       ntfs-logfile volume-journal NTFS_IMAGE_FILE\n"
	    "       ntfs-logfile circular-record LOGICAL_JOURNAL_FILE DECIMAL_LSN\n"
	    "       ntfs-logfile active-client LOGICAL_JOURNAL_FILE INDEX SEQUENCE\n");
done:
	free(restart_scratch);
	free(restart_bytes);
	free(scratch);
	free(bytes);
	return status;
}
