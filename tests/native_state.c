/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_batch_history.h"
#include "internal.h"
#include "image.h"
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

enum { FIRST_ORDINARY_RECORD = 24, DECIMAL_RADIX = 10 };

static uint64_t
allocated_bits(struct ntfs_node *node, uint32_t type, const uint16_t *name, size_t units,
    uint64_t count, uint64_t first, uint64_t *reserved)
{
	struct ntfs_stream *stream = NULL;
	uint8_t *bits;
	uint64_t bit, allocated = 0;

	assert(ntfs_attribute_open(node, type, name, units, &stream) == NTFS_OK);
	assert(stream->size <= SIZE_MAX &&
	    (count + NTFS_BITS_PER_BYTE - 1) / NTFS_BITS_PER_BYTE <= stream->size);
	bits = malloc((size_t)stream->size);
	assert(bits != NULL && ntfs_stream_exact(stream, 0, bits, (size_t)stream->size) == NTFS_OK);
	*reserved = 0;
	for (bit = first; bit < count; bit++) {
		if ((bits[bit / NTFS_BITS_PER_BYTE] & (1u << (bit % NTFS_BITS_PER_BYTE))) != 0) {
			allocated++;
			if (bit >= NTFS_FIRST_USER_RECORD && bit < FIRST_ORDINARY_RECORD) {
				*reserved |= UINT64_C(1) << (bit - NTFS_FIRST_USER_RECORD);
			}
		}
	}
	free(bits);
	ntfs_stream_close(stream);
	return allocated;
}

int
main(int argc, char **argv)
{
	struct ntfs_image image;
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *mft = NULL, *directory = NULL;
	struct ntfs_stream *index = NULL;
	struct ntfs_write_batch_history history;
	struct ntfs_logfile_lsn end, floor;
	char *tail;
	const uint16_t index_name[] = {'$', 'I', '3', '0'};
	uint64_t reference, records, allocated, ordinary, reserved, unused;
	uint64_t index_bytes = 0, blocks = 0, index_allocated = 0;
	size_t run;
	enum ntfs_result result;

	assert(argc == 3);
	errno = 0;
	reference = strtoull(argv[2], &tail, DECIMAL_RADIX);
	assert(errno == 0 && tail != argv[2] && *tail == '\0' && argv[2][0] != '-');
	assert(ntfs_image_open(argv[1], &image) == 0);
	assert(ntfs_write_batch_history_prepare(&image.environment, &history) == NTFS_OK);
	assert(history.history.complete && history.history.endpoint_verified &&
	    history.history.tail_lsn == 0);
	assert(ntfs_logfile_lsn_decode(&history.origin, history.history.completed_end_lsn, &end) ==
	    NTFS_OK);
	assert(
	    ntfs_logfile_lsn_decode(&history.origin, history.client.oldest_lsn, &floor) == NTFS_OK);
	assert(ntfs_mount(&image.environment, NULL, &volume) == NTFS_OK);
	assert(ntfs_node_by_number(volume, NTFS_MFT_RECORD, &mft) == NTFS_OK);
	records = volume->mft->initialized / volume->info.record_size;
	allocated = allocated_bits(mft, NTFS_ATTR_BITMAP, NULL, 0, records, 0, &reserved);
	ordinary =
	    allocated_bits(mft, NTFS_ATTR_BITMAP, NULL, 0, records, FIRST_ORDINARY_RECORD, &unused);
	assert(ntfs_node_open(volume, reference, &directory) == NTFS_OK);
	result = ntfs_attribute_open(directory, NTFS_ATTR_INDEX_ALLOCATION, index_name,
	    sizeof(index_name) / sizeof(*index_name), &index);
	assert(result == NTFS_OK || result == NTFS_NOT_FOUND);
	if (result == NTFS_OK) {
		index_bytes = index->allocated;
		blocks = index->size / volume->info.index_size;
		index_allocated = allocated_bits(directory, NTFS_ATTR_BITMAP, index_name,
		    sizeof(index_name) / sizeof(*index_name), blocks, 0, &unused);
	}
	printf("{\"mftInitializedBytes\":\"%" PRIu64 "\",\"mftAllocatedBytes\":\"%" PRIu64
	       "\",\"mftRecords\":%" PRIu64 ",\"mftAllocatedRecords\":%" PRIu64
	       ",\"mftFreeOrdinaryRecords\":%" PRIu64 ",\"mftReservedAllocationMask\":%" PRIu64
	       ",\"mftRuns\":[",
	    volume->mft->initialized, volume->mft->allocated, records, allocated,
	    records - FIRST_ORDINARY_RECORD - ordinary, reserved);
	for (run = 0; run < volume->mft->run_count; run++) {
		printf("%s{\"vcn\":\"%" PRIu64 "\",\"lcn\":\"%" PRIu64 "\",\"clusters\":\"%" PRIu64
		       "\"}",
		    run == 0 ? "" : ",", volume->mft->runs[run].vcn, volume->mft->runs[run].lcn,
		    volume->mft->runs[run].length);
	}
	printf("],\"directoryReference\":\"%" PRIu64
	       "\",\"directoryIndexAllocatedBytes\":\"%" PRIu64
	       "\",\"directoryIndexBlocks\":%" PRIu64 ",\"directoryLiveIndexBlocks\":%" PRIu64
	       ",\"logFileBytes\":\"%" PRIu64 "\",\"completedLsn\":\"%" PRIu64
	       "\",\"completedSequence\":\"%" PRIu64 "\",\"completedOffset\":\"%" PRIu64
	       "\",\"oldestLsn\":\"%" PRIu64 "\",\"oldestSequence\":\"%" PRIu64
	       "\",\"oldestOffset\":\"%" PRIu64 "\",\"settled\":true}\n",
	    reference, index_bytes, blocks, index_allocated, history.origin.file_bytes,
	    history.history.completed_end_lsn, end.sequence, end.file_offset,
	    history.client.oldest_lsn, floor.sequence, floor.file_offset);
	ntfs_stream_close(index);
	ntfs_node_close(directory);
	ntfs_node_close(mft);
	assert(ntfs_unmount(volume) == NTFS_OK);
	ntfs_image_close(&image);
	return 0;
}
