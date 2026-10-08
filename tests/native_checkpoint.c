/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_checkpoint.h"
#include "write_batch_recover.h"
#include "image_fault.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { RECOVERY_TRACE_EVENTS = 4096 };

static size_t
number(const char *text)
{
	char *end;
	unsigned long long value;

	errno = 0;
	value = strtoull(text, &end, 10);
	assert(errno == 0 && end != text && *end == '\0' && text[0] != '-' && value <= SIZE_MAX);
	return (size_t)value;
}

int
main(int argc, char **argv)
{
	struct ntfs_image_fault *fault;
	struct ntfs_write_checkpoint *checkpoint = NULL;
	struct ntfs_write_batch_recovery *recovery = NULL;
	struct ntfs_write_checkpoint_report checkpoint_report = {0};
	struct ntfs_write_recovery_report recovery_report = {0};
	const char *trace;
	size_t failed_write = 0, failed_barrier = 0, prefix = 0, publications = 0;
	bool recover, poisoned = false;
	int opened;
	enum ntfs_result result;

	assert(argc == 4 || argc == 7);
	recover = strcmp(argv[1], "--recover") == 0 || strcmp(argv[1], "--interrupt-recover") == 0;
	assert(recover || strcmp(argv[1], "--image") == 0 ||
	    strcmp(argv[1], "--interrupt-image") == 0);
	trace = argv[argc - 1];
	if (argc == 7) {
		assert(strcmp(argv[1], "--interrupt-image") == 0 ||
		    strcmp(argv[1], "--interrupt-recover") == 0);
		failed_write = number(argv[3]);
		prefix = number(argv[4]);
		failed_barrier = number(argv[5]);
	}
	fault = calloc(1, sizeof(*fault));
	assert(fault != NULL);
	opened = ntfs_image_fault_open_bounded(argv[2], failed_write, prefix, failed_barrier,
	    RECOVERY_TRACE_EVENTS, NTFS_WRITE_CLUSTER_BYTES, fault);
	if (opened != 0) {
		fprintf(stderr, "private checkpoint/recovery image open failed: %d\n", opened);
		free(fault);
		return 2;
	}
	result = fault->environment.claim(fault->environment.reader.context);
	if (result == NTFS_OK) {
		result = recover ? ntfs_write_batch_recover_prepare(&fault->environment, &recovery)
				 : ntfs_write_checkpoint_prepare(&fault->environment, &checkpoint);
	}
	if (result == NTFS_OK) {
		publications = recover ? ntfs_write_batch_recovery_count(recovery)
				       : ntfs_write_checkpoint_count(checkpoint);
		fault->enabled = true;
		result = recover
		    ? ntfs_write_batch_recover_execute(recovery, &poisoned, &recovery_report)
		    : ntfs_write_checkpoint_execute(checkpoint, &poisoned, &checkpoint_report);
	}
	printf("{\"result\":%u,\"recovery\":%s,\"prepared_publications\":%zu,"
	       "\"writes\":%u,\"barriers\":%u,\"physical_bytes\":%llu,"
	       "\"homes_persisted\":%s,\"completed\":%s,\"poisoned\":%s}\n",
	    result, recover ? "true" : "false", publications,
	    recover ? recovery_report.writes : checkpoint_report.writes,
	    recover ? recovery_report.barriers : checkpoint_report.barriers,
	    (unsigned long long)(recover ? recovery_report.physical_bytes
					 : checkpoint_report.physical_bytes),
	    (recover ? recovery_report.homes_persisted : checkpoint_report.homes_persisted)
		? "true"
		: "false",
	    (recover ? recovery_report.completed : checkpoint_report.completed) ? "true" : "false",
	    poisoned ? "true" : "false");
	ntfs_write_checkpoint_close(checkpoint);
	ntfs_write_batch_recovery_close(recovery);
	assert(ntfs_image_fault_dump(fault, trace) == 0);
	ntfs_image_fault_close(fault);
	free(fault);
	return result == NTFS_OK ? 0 : 1;
}
