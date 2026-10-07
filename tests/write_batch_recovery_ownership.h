/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
/* A syntactically valid FILE snapshot must not turn originally unused storage
 * into an owned predecessor. Author the false claim independently of the
 * mutation compiler, whose normal output already preserves this distinction. */

static void
recovery_unowned_file(
    const char *directory, const char *image_name, enum test_profile profile, bool initialized)
{
	struct recovery_case *source;
	struct test_case *test;
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *mft = NULL;
	struct ntfs_stream *bitmap = NULL;
	struct ntfs_write_batch_recovery *owner = NULL;
	struct ntfs_logfile_update original, replacement;
	struct ntfs_logfile_update_input snapshot = {0};
	struct ntfs_disk_log_record *record;
	struct ntfs_disk_log_page *page;
	const struct ntfs_write_mutation_region *region = NULL;
	const struct ntfs_write_batch_publication *step;
	const uint8_t *logical_file = NULL;
	uint8_t *logical, *encoded, *input, *before_file, bit;
	uint64_t logical_offset = 0, number;
	size_t index, publication, offset = 0, winner, payload_bytes, next;
	uint32_t measured;
	char *path;
	FILE *file;
	int count;
	enum ntfs_result result;

	source = recovery_source(directory, image_name, NTFS_WRITE_CREATE_FILE, profile);
	test = source->test;
	recovery_state(source, 0, 0, false);
	assert(ntfs_mount(&test->backend.reader, NULL, &volume) == NTFS_OK);
	assert(ntfs_node_by_number(volume, NTFS_MFT_RECORD, &mft) == NTFS_OK);
	assert(ntfs_attribute_open(mft, NTFS_ATTR_BITMAP, NULL, 0, &bitmap) == NTFS_OK);
	for (index = 0; index + 1 < source->oracle->steps; index++) {
		assert(ntfs_logfile_update_decode(source->oracle->step[index].payload,
			   source->oracle->step[index].bytes, &original) == NTFS_OK);
		if (original.redo_operation != NTFS_LOG_OP_NOOP ||
		    original.undo_operation != NTFS_LOG_OP_DEALLOCATE_FILE_RECORD) {
			continue;
		}
		offset = (size_t)original.cluster_index * NTFS_MST_STRIDE;
		region = &test->region[source->oracle->step[index].region];
		logical_offset = region->target.logical_offset + offset;
		if (ntfs_bounds(logical_offset, NTFS_WRITE_RECORD_BYTES,
			volume->mft->initialized) != initialized) {
			continue;
		}
		assert(ntfs_logfile_update_decode(source->oracle->step[index + 1].payload,
			   source->oracle->step[index + 1].bytes, &replacement) == NTFS_OK &&
		    replacement.redo_operation == NTFS_LOG_OP_INITIALIZE_FILE_RECORD &&
		    replacement.undo_operation == NTFS_LOG_OP_NOOP &&
		    replacement.cluster_index == original.cluster_index);
		logical_file = source->oracle->step[index + 1].payload + replacement.redo.offset;
		break;
	}
	assert(index + 1 < source->oracle->steps && logical_file != NULL && region != NULL);
	number = logical_offset / NTFS_WRITE_RECORD_BYTES;
	if (initialized) {
		assert(ntfs_stream_exact(bitmap, number / NTFS_BITS_PER_BYTE, &bit, sizeof(bit)) ==
			NTFS_OK &&
		    (bit & (1u << (number % NTFS_BITS_PER_BYTE))) == 0);
	} else {
		assert(ntfs_bounds(logical_offset, NTFS_WRITE_RECORD_BYTES,
		    volume->mft->clusters * (uint64_t)NTFS_WRITE_CLUSTER_BYTES));
	}
	ntfs_stream_close(bitmap);
	ntfs_node_close(mft);
	assert(ntfs_unmount(volume) == NTFS_OK && test->device.live == 0);
	logical = malloc(NTFS_WRITE_CLUSTER_BYTES);
	encoded = malloc(NTFS_WRITE_CLUSTER_BYTES);
	input = malloc(test->device.bytes);
	before_file = malloc(NTFS_WRITE_RECORD_BYTES);
	path = malloc(TEST_PATH_BYTES);
	assert(logical != NULL && encoded != NULL && input != NULL && before_file != NULL &&
	    path != NULL);
	memcpy(before_file, logical_file, NTFS_WRITE_RECORD_BYTES);
	ntfs_put_u16(((struct ntfs_disk_record *)(void *)before_file)->flags, 0);
	for (winner = 0; winner < 2; winner++) {
		recovery_state(source, source->commit + winner, 0, false);
		for (publication = 0; publication < source->commit; publication++) {
			step = &source->publication[publication];
			if (step->stage != NTFS_WRITE_EXECUTION_PREPARE_HOME) {
				continue;
			}
			memcpy(logical, step->image, NTFS_WRITE_CLUSTER_BYTES);
			assert(ntfs_fixup(logical, NTFS_WRITE_CLUSTER_BYTES, "RCRD") == NTFS_OK);
			record = (void *)(logical + source->oracle->restart.page_data_offset);
			if (ntfs_u32(record->transaction) != NTFS_WRITE_TRANSACTION_KEY ||
			    (ntfs_u16(record->flags) & NTFS_LOGFILE_RECORD_MULTI_PAGE) != 0) {
				continue;
			}
			assert(ntfs_logfile_update_decode((uint8_t *)record + sizeof(*record),
				   ntfs_u32(record->data_bytes), &replacement) == NTFS_OK);
			if (replacement.redo_operation == NTFS_LOG_OP_NOOP &&
			    replacement.undo_operation == NTFS_LOG_OP_DEALLOCATE_FILE_RECORD &&
			    replacement.target_vcn == original.target_vcn &&
			    replacement.cluster_index == original.cluster_index &&
			    replacement.target_attribute == original.target_attribute) {
				break;
			}
		}
		assert(publication < source->commit);
		step = &source->publication[publication];
		snapshot.redo_operation = snapshot.undo_operation =
		    NTFS_LOG_OP_INITIALIZE_FILE_RECORD;
		snapshot.target_attribute = original.target_attribute;
		snapshot.target_vcn = original.target_vcn;
		snapshot.cluster_index = original.cluster_index;
		snapshot.attribute_flags = original.attribute_flags;
		snapshot.lcns = (struct ntfs_logfile_buffer){
		    source->oracle->step[index].payload + original.lcns.offset,
		    original.lcns.length};
		snapshot.redo = snapshot.undo =
		    (struct ntfs_logfile_buffer){before_file, NTFS_WRITE_RECORD_BYTES};
		assert(ntfs_logfile_update_measure(&snapshot, &measured) == NTFS_OK);
		payload_bytes = NTFS_WRITE_CLUSTER_BYTES -
		    source->oracle->restart.page_data_offset - sizeof(*record);
		assert(ntfs_logfile_update_encode(&snapshot, (uint8_t *)record + sizeof(*record),
			   payload_bytes) == NTFS_OK);
		ntfs_put_u32(record->data_bytes, measured);
		ntfs_put_u16(record->flags, NTFS_LOGFILE_RECORD_ADDING);
		page = (void *)logical;
		next = source->oracle->restart.page_data_offset + sizeof(*record) + measured;
		next = (next + NTFS_WIRE_ALIGNMENT - 1) & ~(size_t)(NTFS_WIRE_ALIGNMENT - 1);
		assert(next <= NTFS_WRITE_CLUSTER_BYTES);
		ntfs_put_u16(page->next_record_offset, (uint16_t)next);
		assert(ntfs_record_protect(logical, NTFS_WRITE_CLUSTER_BYTES, encoded,
			   NTFS_WRITE_CLUSTER_BYTES) == NTFS_OK);
		memcpy(test->device.visible + step->physical, encoded, NTFS_WRITE_CLUSTER_BYTES);
		/* The false predecessor is complete and matches its logged snapshot.
		 * Its original allocation/initialization still proves it was unused. */
		assert(ntfs_record_protect(before_file, NTFS_WRITE_RECORD_BYTES, encoded,
			   NTFS_WRITE_CLUSTER_BYTES) == NTFS_OK);
		memcpy(test->device.visible + region->physical + offset, encoded,
		    NTFS_WRITE_RECORD_BYTES);
		memcpy(test->device.durable, test->device.visible, test->device.bytes);
		validate(test);
		memcpy(input, test->device.visible, test->device.bytes);
		owner = (void *)(uintptr_t)1;
		result = ntfs_write_batch_recover_prepare(&test->backend, &owner);
		if (result == NTFS_OK) {
			fprintf(stderr,
			    "unused FILE snapshot incorrectly admitted: %s, winner=%zu\n",
			    initialized ? "bitmap-clear initialized slot"
					: "uninitialized allocated tail",
			    winner);
			count = snprintf(path, TEST_PATH_BYTES, "%s/unowned-file-%u-%zu.img",
			    recovery_output, initialized, winner);
			assert(count > 0 && count < TEST_PATH_BYTES);
			file = fopen(path, "wbx");
			assert(file != NULL &&
			    fwrite(input, 1, test->device.bytes, file) == test->device.bytes &&
			    fclose(file) == 0);
			fprintf(stderr, "retained false predecessor input: %s\n", path);
		}
		assert(result == NTFS_STALE && owner == NULL && test->device.live == 0 &&
		    test->device.writes == 0 && test->device.barriers == 0 &&
		    memcmp(input, test->device.visible, test->device.bytes) == 0 &&
		    memcmp(input, test->device.durable, test->device.bytes) == 0);
	}
	free(path);
	free(input);
	free(before_file);
	free(encoded);
	free(logical);
	recovery_source_close(source);
	printf("PASS: complete false FILE predecessor refuses for both loser/winner: %s\n",
	    initialized ? "bitmap-clear initialized slot" : "uninitialized allocated MFT tail");
}

static void
batch_recovery_ownership_tests(const char *directory, const char *output)
{
	recovery_output_begin(output);
	recovery_unowned_file(directory, "source.img", TEST_DEFAULT, true);
	recovery_unowned_file(directory, "large-unused-mft-tail-stale.img", TEST_MFT_GROWTH, false);
	free(recovery_output);
}
