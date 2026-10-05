/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "overwrite_image.h"
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool
parse_offset(const char *text, uint64_t *offset)
{
	unsigned digit;

	*offset = 0;
	if (*text == 0) {
		return false;
	}
	while (*text != 0) {
		if (*text < '0' || *text > '9') {
			return false;
		}
		digit = (unsigned)(*text++ - '0');
		if (*offset > (UINT64_MAX - digit) / 10) {
			return false;
		}
		*offset = *offset * 10 + digit;
	}
	return true;
}

int
main(int argc, char **argv)
{
	struct ntfs_overwrite_image image;
	struct ntfs_overwrite *owner = NULL;
	struct ntfs_overwrite_admission admission = {0};
	struct ntfs_overwrite_report report = {0};
	uint16_t path[NTFS_OVERWRITE_MAX_PATH_UNITS];
	uint8_t *data;
	FILE *input;
	struct stat input_status;
	size_t units, bytes;
	uint64_t offset, reference = 0;
	int error, extra, input_fd;
	enum ntfs_result result;

	if (argc != 5 || !parse_offset(argv[3], &offset)) {
		fprintf(stderr, "usage: ntfs-overwrite PRIVATE_IMAGE /PATH OFFSET INPUT\n");
		return 2;
	}
	result = ntfs_utf8_to_utf16(
	    argv[2], strlen(argv[2]), path, NTFS_OVERWRITE_MAX_PATH_UNITS, &units);
	if (result != NTFS_OK) {
		fprintf(stderr, "invalid UTF-8 path\n");
		return 2;
	}
	input_fd = open(argv[4], O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (input_fd < 0) {
		fprintf(stderr, "cannot open overwrite input\n");
		return 2;
	}
	if (fstat(input_fd, &input_status) != 0 || !S_ISREG(input_status.st_mode) ||
	    input_status.st_size < 0 || input_status.st_size > NTFS_OVERWRITE_MAX_BYTES) {
		close(input_fd);
		fprintf(stderr, "bounded regular overwrite input required\n");
		return 2;
	}
	input = fdopen(input_fd, "rb");
	if (input == NULL) {
		close(input_fd);
		return 2;
	}
	data = malloc(NTFS_OVERWRITE_MAX_BYTES);
	if (data == NULL) {
		fclose(input);
		return 2;
	}
	bytes = fread(data, 1, NTFS_OVERWRITE_MAX_BYTES, input);
	extra = fgetc(input);
	error = ferror(input);
	fclose(input);
	if (error != 0 || extra != EOF) {
		fprintf(stderr, "input exceeds bounded overwrite capacity or failed reading\n");
		free(data);
		return 2;
	}
	error = ntfs_overwrite_image_open(argv[1], &image);
	if (error != 0) {
		fprintf(stderr, "private writable regular image required: %s\n", strerror(error));
		free(data);
		return 2;
	}
	result = ntfs_overwrite_open(&image.environment, &admission, &owner);
	if (result == NTFS_OK) {
		result = ntfs_overwrite_resolve(owner, path, units, &reference);
	}
	if (result == NTFS_OK) {
		result = ntfs_overwrite_range(owner, reference, offset, data, bytes, &report);
	}
	printf("{\"scope\":\"metadata-preserving-overwrite\",\"code\":%d,\"result\":\"%s\","
	       "\"reference\":\"%016" PRIx64 "\",\"validation_complete\":%s,"
	       "\"quiescent\":%s,\"admission_persisted\":%s,\"requested_bytes\":%" PRIu64
	       ",\"completed_bytes\":%" PRIu64 ",\"physical_bytes\":%" PRIu64 ",\"writes\":%" PRIu32
	       ",\"persisted\":%s,\"poisoned\":%s}\n",
	    (int)result, ntfs_result_string(result), reference,
	    admission.validation.complete ? "true" : "false",
	    admission.quiescent ? "true" : "false",
	    admission.persistence_succeeded ? "true" : "false", report.requested_bytes,
	    report.completed_bytes, report.physical_bytes, report.writes,
	    report.persisted ? "true" : "false", report.poisoned ? "true" : "false");
	ntfs_overwrite_close(owner);
	ntfs_overwrite_image_close(&image);
	free(data);
	return result == NTFS_OK ? 0 : 1;
}
