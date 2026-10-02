/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/validate.h>
#include "image.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { DECIMAL_RADIX = 10, OPTION_PAIR = 2 };

static bool
number(const char *text, uint64_t *value)
{
	char *end;
	size_t i;
	unsigned long long parsed;

	if (text[0] == 0) {
		return false;
	}
	for (i = 0; text[i] != 0; i++) {
		if (text[i] < '0' || text[i] > '9') {
			return false;
		}
	}
	errno = 0;
	parsed = strtoull(text, &end, DECIMAL_RADIX);
	if (errno != 0 || *end != 0 || parsed == 0 || parsed > UINT64_MAX) {
		return false;
	}
	*value = (uint64_t)parsed;
	return true;
}

static void
print_report(const struct ntfs_validation_report *r)
{
	printf("{\"result\":\"%s\",\"complete\":%s,\"stage\":%u,\"exhausted\":%u,"
	       "\"record_number\":\"%" PRIu64 "\","
	       "\"reference\":\"%016" PRIx64 "\",\"related_reference\":\"%016" PRIx64 "\","
	       "\"attribute_type\":%u,\"cluster\":\"%" PRIu64 "\","
	       "\"record_slots\":\"%" PRIu64 "\",\"records_scanned\":\"%" PRIu64 "\","
	       "\"base_records\":\"%" PRIu64 "\",\"extension_records\":\"%" PRIu64 "\","
	       "\"attributes\":\"%" PRIu64 "\",\"streams\":\"%" PRIu64 "\","
	       "\"physical_runs\":\"%" PRIu64 "\",\"claimed_clusters\":\"%" PRIu64 "\","
	       "\"filename_attributes\":\"%" PRIu64 "\",\"index_entries\":\"%" PRIu64 "\","
	       "\"directories\":\"%" PRIu64 "\",\"deferred_dos_link_counts\":\"%" PRIu64 "\","
	       "\"allocated_clusters\":\"%" PRIu64 "\",\"unclaimed_clusters\":\"%" PRIu64 "\","
	       "\"read_calls\":\"%" PRIu64 "\",\"read_bytes\":\"%" PRIu64 "\","
	       "\"allocation_calls\":\"%" PRIu64 "\",\"work_units\":\"%" PRIu64 "\","
	       "\"peak_memory_bytes\":\"%" PRIu64 "\"}\n",
	    ntfs_result_string(r->result), r->complete ? "true" : "false", (unsigned)r->stage,
	    (unsigned)r->exhausted, r->record_number, r->reference, r->related_reference,
	    r->attribute_type, r->cluster, r->record_slots, r->records_scanned, r->base_records,
	    r->extension_records, r->attributes, r->streams, r->physical_runs, r->claimed_clusters,
	    r->filename_attributes, r->index_entries, r->directories, r->deferred_dos_link_counts,
	    r->allocated_clusters, r->unclaimed_clusters, r->read_calls, r->read_bytes,
	    r->allocation_calls, r->work_units, (uint64_t)r->peak_memory_bytes);
}

int
main(int argc, char **argv)
{
	struct ntfs_validation_limits limits;
	struct ntfs_validation_report report;
	struct ntfs_image image;
	uint64_t value;
	int i, error;
	enum ntfs_result result;

	if (argc < 2 || (argc - OPTION_PAIR) % OPTION_PAIR != 0) {
		fprintf(stderr,
		    "Usage: ntfs-validate IMAGE "
		    "[--max-{records,runs,links,memory-bytes,read-calls,read-bytes,work-units} "
		    "N]\n");
		return 2;
	}
	ntfs_validation_default_limits(&limits);
	for (i = OPTION_PAIR; i < argc; i += OPTION_PAIR) {
		if (!number(argv[i + 1], &value)) {
			fprintf(stderr, "Invalid positive validation budget\n");
			return 2;
		}
		if (strcmp(argv[i], "--max-records") == 0 && value <= UINT32_MAX) {
			limits.max_records = (uint32_t)value;
		} else if (strcmp(argv[i], "--max-runs") == 0 && value <= UINT32_MAX) {
			limits.max_runs = (uint32_t)value;
		} else if (strcmp(argv[i], "--max-links") == 0 && value <= UINT32_MAX) {
			limits.max_links = (uint32_t)value;
		} else if (strcmp(argv[i], "--max-memory-bytes") == 0 && value <= SIZE_MAX) {
			limits.max_memory_bytes = (size_t)value;
		} else if (strcmp(argv[i], "--max-read-calls") == 0) {
			limits.max_read_calls = value;
		} else if (strcmp(argv[i], "--max-read-bytes") == 0) {
			limits.max_read_bytes = value;
		} else if (strcmp(argv[i], "--max-work-units") == 0) {
			limits.max_work_units = value;
		} else {
			fprintf(stderr, "Unknown or oversized validation budget\n");
			return 2;
		}
	}
	error = ntfs_image_open(argv[1], &image);
	if (error != 0) {
		fprintf(stderr, "image: %s\n", strerror(error));
		return 2;
	}
	result = ntfs_validate(&image.environment, NULL, &limits, &report);
	ntfs_image_close(&image);
	print_report(&report);
	return result == NTFS_OK && report.complete ? 0 : 1;
}
