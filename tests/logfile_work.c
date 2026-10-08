/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "logfile_source_internal.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

enum { TEST_VOLUME_BYTES = 32, TEST_READ_BYTES = 4, TEST_READ_CALLS = 2 };

struct test_source {
	unsigned calls;
	enum ntfs_result result;
};

static enum ntfs_result
read_source(void *context, uint64_t offset, void *output, size_t bytes)
{
	struct test_source *source = context;

	assert(offset <= TEST_VOLUME_BYTES && bytes <= TEST_VOLUME_BYTES - offset);
	source->calls++;
	if (source->result == NTFS_OK) {
		memset(output, 'L', bytes);
	}
	return source->result;
}

int
main(void)
{
	struct test_source backend = {0, NTFS_OK};
	struct ntfs_logfile source = {0};
	struct ntfs_logfile_io_work work = {0};
	uint8_t output[TEST_READ_BYTES] = {0};
	unsigned calls;

	source.environment.context = &backend;
	source.environment.size_bytes = TEST_VOLUME_BYTES;
	source.environment.read = read_source;
	source.limits.max_read_calls = TEST_READ_CALLS;
	source.limits.max_read_bytes = TEST_READ_BYTES * TEST_READ_CALLS;
	assert(ntfs_logfile_source_read(&source, 0, output, sizeof(output), &work) == NTFS_OK);
	assert(ntfs_logfile_source_read(&source, TEST_READ_BYTES, output, sizeof(output), &work) ==
	    NTFS_OK);
	assert(work.read_calls == TEST_READ_CALLS && work.read_bytes == TEST_READ_BYTES * TEST_READ_CALLS);
	assert(backend.calls == TEST_READ_CALLS);
	assert(ntfs_logfile_source_read(&source, 0, output, sizeof(output), &work) == NTFS_RANGE);
	assert(work.read_calls == TEST_READ_CALLS && backend.calls == TEST_READ_CALLS);
	work = (struct ntfs_logfile_io_work){.read_bytes = TEST_READ_BYTES * TEST_READ_CALLS - 1};
	assert(ntfs_logfile_source_read(&source, 0, output, sizeof(output), &work) == NTFS_RANGE);
	assert(work.read_calls == 0 && work.read_bytes == TEST_READ_BYTES * TEST_READ_CALLS - 1);
	work.read_bytes = UINT64_MAX;
	source.limits.max_read_bytes = UINT64_MAX - 1;
	assert(ntfs_logfile_source_read(&source, 0, output, sizeof(output), &work) == NTFS_RANGE);
	assert(work.read_calls == 0 && work.read_bytes == UINT64_MAX);
	work = (struct ntfs_logfile_io_work){0};
	calls = backend.calls;
	assert(ntfs_logfile_source_read(&source, TEST_VOLUME_BYTES, output, sizeof(output), &work) ==
	    NTFS_NOT_FOUND);
	assert(work.read_calls == 0 && work.read_bytes == 0 && backend.calls == calls);
	backend.result = NTFS_IO;
	assert(ntfs_logfile_source_read(&source, 0, output, sizeof(output), &work) == NTFS_IO);
	assert(work.read_calls == 1 && work.read_bytes == sizeof(output) && source.backend_failed);
	backend.result = NTFS_OK;
	assert(ntfs_logfile_source_read(&source, 0, output, sizeof(output), &work) == NTFS_OK);
	assert(work.read_calls == 2 && work.read_bytes == 2 * sizeof(output) && !source.backend_failed);
	puts("bounded journal I/O credits, exact failure charges and overflow refusals pass");
	return 0;
}
