/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
/* Shared complete-operation fixture, device and independent metadata/content
 * oracles live in write_batch_execute.c. This suite gets only crash bytes after
 * every original C planner/program/executor has been closed. */

struct recovery_case {
	struct test_case *test;
	struct journal_oracle *oracle;
	struct ntfs_write_batch_publication *publication;
	uint8_t *frames, *committed;
	size_t count, commit;
};

#include "write_batch_recovery_journal.h"

static char *recovery_output;

static struct recovery_case *
recovery_source(const char *directory, const char *image, enum ntfs_write_mutation_kind kind,
    enum test_profile profile)
{
	struct recovery_case *source;
	struct ntfs_write_batch_execution *writer = NULL;
	const struct ntfs_write_batch_publication *step;
	size_t index;

	source = calloc(1, sizeof(*source));
	assert(source != NULL);
	source->test = prepare_profile(directory, image, kind, profile);
	source->oracle = journal_capture(source->test);
	assert(ntfs_write_batch_execute_prepare(
		   &source->test->backend, source->test->program, &writer) == NTFS_OK);
	source->count = ntfs_write_batch_execution_count(writer);
	source->publication = calloc(source->count, sizeof(*source->publication));
	source->frames = malloc(source->count * NTFS_WRITE_CLUSTER_BYTES);
	source->committed = malloc(source->test->device.bytes);
	assert(source->publication != NULL && source->frames != NULL && source->committed != NULL);
	memcpy(source->committed, source->test->before, source->test->device.bytes);
	for (index = 0; index < source->count; index++) {
		step = ntfs_write_batch_execution_get(writer, index);
		source->publication[index] = *step;
		memcpy(source->frames + index * NTFS_WRITE_CLUSTER_BYTES, step->image,
		    NTFS_WRITE_CLUSTER_BYTES);
		source->publication[index].image =
		    source->frames + index * NTFS_WRITE_CLUSTER_BYTES;
		memcpy(source->committed + step->physical, step->image, NTFS_WRITE_CLUSTER_BYTES);
		if (step->stage == NTFS_WRITE_EXECUTION_COMMIT_COPY) {
			source->commit = index;
		}
	}
	assert(source->commit > 0);
	ntfs_write_batch_execution_close(writer);
	ntfs_write_program_close(source->test->program);
	ntfs_write_mutation_plan_close(source->test->plan);
	source->test->program = NULL;
	source->test->plan = NULL;
	assert(source->test->device.live == 0);
	return source;
}

static void
recovery_source_close(struct recovery_case *source)
{
	recovery_journal_close(source->oracle);
	finish(source->test);
	free(source->committed);
	free(source->frames);
	free(source->publication);
	free(source);
}

static void
recovery_state(struct recovery_case *source, size_t complete, size_t partial, bool suffix)
{
	struct device *device = &source->test->device;
	const struct ntfs_write_batch_publication *step;
	size_t index;

	assert(complete <= source->count && partial <= NTFS_WRITE_CLUSTER_BYTES);
	memcpy(device->visible, source->test->before, device->bytes);
	for (index = 0; index < complete; index++) {
		step = &source->publication[index];
		memcpy(device->visible + step->physical, step->image, NTFS_WRITE_CLUSTER_BYTES);
	}
	if (complete < source->count && partial != 0) {
		step = &source->publication[complete];
		if (suffix) {
			memcpy(
			    device->visible + step->physical + NTFS_WRITE_CLUSTER_BYTES - partial,
			    step->image + NTFS_WRITE_CLUSTER_BYTES - partial, partial);
		} else {
			memcpy(device->visible + step->physical, step->image, partial);
		}
	}
	memcpy(device->durable, device->visible, device->bytes);
	device->writes = device->barriers = device->reads = device->allocations = 0;
	device->fail_write = device->fail_barrier = device->fail_read = device->fail_allocation = 0;
	device->overreport = device->short_success = device->persist_on_failure = false;
}

static enum ntfs_result
recovery_execute(struct test_case *test, struct ntfs_write_batch_recovery *owner, bool *poisoned,
    struct ntfs_write_recovery_report *report)
{
	enum ntfs_result result;

	test->device.recovering = owner;
	test->device.executing = true;
	result = ntfs_write_batch_recover_execute(owner, poisoned, report);
	test->device.executing = false;
	test->device.recovering = NULL;
	return result;
}

static void
recovery_metadata(struct recovery_case *source, bool committed)
{
	struct test_case *test = source->test;
	const struct ntfs_write_mutation_region *region;
	size_t index;

	validate(test);
	for (index = 0; index < test->regions; index++) {
		region = &test->region[index];
		if (committed) {
			same_metadata(region, test->before + region->physical,
			    source->committed + region->physical,
			    test->device.visible + region->physical);
		} else if (region->kind != NTFS_WRITE_MUTATION_DATA) {
			/* Under this executor's ordering, a loser has published no metadata.
			 * Recovery must preserve every old allocation and namespace byte. */
			assert(memcmp(test->before + region->physical,
				   test->device.visible + region->physical, region->bytes) == 0);
		}
	}
	if (committed) {
		requested_file_check(test);
	}
}

static void
recovery_check(struct recovery_case *source, bool committed)
{
	struct test_case *test = source->test;
	struct ntfs_write_batch_recovery *owner = NULL;
	struct ntfs_write_recovery_report report;
	uint8_t *input;
	size_t reads, allocations, writes, barriers;
	bool poisoned = false;
	enum ntfs_result result;

	input = malloc(test->device.bytes);
	assert(input != NULL);
	memcpy(input, test->device.visible, test->device.bytes);
	writes = test->device.writes;
	barriers = test->device.barriers;
	result = ntfs_write_batch_recover_prepare(&test->backend, &owner);
	if (result != NTFS_OK) {
		char path[TEST_PATH_BYTES];
		FILE *file;
		int count;

		fprintf(stderr, "fresh recovery prepare: %s; expected %s\n",
		    ntfs_result_string(result), committed ? "committed" : "old");
		count = snprintf(path, sizeof(path), "%s/refused.img", recovery_output);
		assert(count > 0 && (size_t)count < sizeof(path));
		file = fopen(path, "wbx");
		assert(file != NULL &&
		    fwrite(input, 1, test->device.bytes, file) == test->device.bytes &&
		    fclose(file) == 0);
		fprintf(stderr, "retained failed recovery input: %s\n", path);
	}
	assert(result == NTFS_OK && owner != NULL && test->device.writes == writes &&
	    test->device.barriers == barriers &&
	    memcmp(input, test->device.visible, test->device.bytes) == 0);
	reads = test->device.reads;
	allocations = test->device.allocations;
	assert(recovery_execute(test, owner, &poisoned, &report) == NTFS_OK && !poisoned &&
	    report.completed && report.homes_persisted && test->device.reads == reads &&
	    test->device.allocations == allocations);
	assert(recovery_execute(test, owner, &poisoned, &report) == NTFS_INVALID);
	ntfs_write_batch_recovery_close(owner);
	assert(test->device.live == 0);
	recovery_metadata(source, committed);
	recovery_journal_check(source, committed);
	assert(memcmp(test->device.visible, test->device.durable, test->device.bytes) == 0);
	free(input);
}

static void
recovery_posix_case(const char *directory, unsigned ordinal, const char *image_name,
    enum ntfs_write_mutation_kind kind, enum test_profile profile)
{
	struct recovery_case *source;
	struct test_case *test;
	struct ntfs_overwrite_image image;
	struct ntfs_write_batch_recovery *owner = NULL;
	struct ntfs_write_recovery_report report;
	const struct ntfs_write_batch_recovery_publication *step;
	uint8_t *expected;
	char *path;
	FILE *file;
	size_t committed, pass, index, publications, first_publications = 0;
	int count;
	bool poisoned;

	source = recovery_source(directory, image_name, kind, profile);
	test = source->test;
	path = malloc(TEST_PATH_BYTES);
	expected = malloc(test->device.bytes);
	assert(path != NULL && expected != NULL);
	for (committed = 0; committed < 2; committed++) {
		recovery_state(source, source->commit + committed, 0, false);
		memcpy(expected, test->device.visible, test->device.bytes);
		count = snprintf(path, TEST_PATH_BYTES, "%s/recovery-%u-%s.img", recovery_output,
		    ordinal, committed ? "committed" : "old");
		assert(count > 0 && count < TEST_PATH_BYTES);
		file = fopen(path, "wbx");
		assert(file != NULL &&
		    fwrite(expected, 1, test->device.bytes, file) == test->device.bytes &&
		    fclose(file) == 0);
		for (pass = 0; pass < 2; pass++) {
			assert(ntfs_overwrite_image_open(path, &image) == 0);
			assert(
			    image.environment.claim(image.environment.reader.context) == NTFS_OK);
			assert(ntfs_write_batch_recover_prepare(&image.environment, &owner) ==
			    NTFS_OK);
			publications = ntfs_write_batch_recovery_count(owner);
			if (pass == 0) {
				assert(publications != 0);
				first_publications = publications;
			} else {
				assert(publications == 0);
			}
			for (index = 0; index < publications; index++) {
				step = ntfs_write_batch_recovery_get(owner, index);
				assert(step != NULL && step->physical <= test->device.bytes &&
				    NTFS_WRITE_CLUSTER_BYTES <=
					test->device.bytes - step->physical);
				memcpy(expected + step->physical, step->image,
				    NTFS_WRITE_CLUSTER_BYTES);
			}
			poisoned = false;
			assert(ntfs_write_batch_recover_execute(owner, &poisoned, &report) ==
				NTFS_OK &&
			    !poisoned && report.completed && report.homes_persisted &&
			    report.writes == publications &&
			    report.physical_bytes == publications * NTFS_WRITE_CLUSTER_BYTES &&
			    report.barriers == (publications == 0 ? 1 : publications));
			ntfs_write_batch_recovery_close(owner);
			ntfs_overwrite_image_close(&image);
			/* Read the complete actual postimage after both owners have closed. */
			file = fopen(path, "rb");
			assert(file != NULL &&
			    fread(test->device.visible, 1, test->device.bytes, file) ==
				test->device.bytes &&
			    fgetc(file) == EOF && fclose(file) == 0);
			assert(memcmp(expected, test->device.visible, test->device.bytes) == 0);
			recovery_metadata(source, committed != 0);
			recovery_journal_check(source, committed != 0);
			assert(test->device.live == 0);
		}
		printf("PASS: actual fresh regular-image recovery and zero-rewrite second reopen: "
		       "%s (%zu writes/%zu barriers)\n",
		    path, first_publications, first_publications);
	}
	free(expected);
	free(path);
	recovery_source_close(source);
}

static void
recovery_posix_images(const char *directory)
{
	recovery_posix_case(directory, 0, "source.img", NTFS_WRITE_CREATE_FILE, TEST_DEFAULT);
	recovery_posix_case(directory, 1, "source.img", NTFS_WRITE_GROWING_RANGE, TEST_DEFAULT);
	recovery_posix_case(
	    directory, 2, "large-source.img", NTFS_WRITE_CREATE_FILE, TEST_MFT_GROWTH);
}

static void
recovery_profiles(const char *directory)
{
	static const struct {
		enum ntfs_write_mutation_kind kind;
		enum test_profile profile;
		const char *image;
	} profiles[] = {{NTFS_WRITE_CREATE_FILE, TEST_DEFAULT, "source.img"},
	    {NTFS_WRITE_CREATE_DIRECTORY, TEST_DEFAULT, "source.img"},
	    {NTFS_WRITE_RESIZE_FILE, TEST_DEFAULT, "source.img"},
	    {NTFS_WRITE_GROWING_RANGE, TEST_PAGE_ALIGNMENT, "source.img"},
	    {NTFS_WRITE_REMOVE_FILE, TEST_DEFAULT, "source.img"},
	    {NTFS_WRITE_RENAME, TEST_DEFAULT, "source.img"},
	    {NTFS_WRITE_RESIZE_FILE, TEST_SHRINK, "source.img"},
	    {NTFS_WRITE_RESIZE_FILE, TEST_RESIDENT_GROWTH, "source.img"},
	    {NTFS_WRITE_REMOVE_DIRECTORY, TEST_EMPTY_DIRECTORY, "source.img"},
	    {NTFS_WRITE_CREATE_FILE, TEST_MFT_GROWTH, "large-source.img"},
	    {NTFS_WRITE_CREATE_FILE, TEST_DEFAULT, "unused-index-torn.img"},
	    {NTFS_WRITE_CREATE_FILE, TEST_DEFAULT, "unused-index-stale.img"},
	    {NTFS_WRITE_CREATE_FILE, TEST_MFT_GROWTH, "large-unused-file-torn.img"},
	    {NTFS_WRITE_CREATE_FILE, TEST_MFT_GROWTH, "large-unused-file-stale.img"},
	    {NTFS_WRITE_CREATE_FILE, TEST_MFT_GROWTH, "large-unused-mft-tail-torn.img"},
	    {NTFS_WRITE_CREATE_FILE, TEST_MFT_GROWTH, "large-unused-mft-tail-stale.img"}};
	struct recovery_case *source;
	size_t index;

	for (index = 0; index < sizeof(profiles) / sizeof(profiles[0]); index++) {
		fprintf(stderr, "fresh recovery profile %zu: %s\n", index, profiles[index].image);
		source = recovery_source(directory, profiles[index].image, profiles[index].kind,
		    profiles[index].profile);
		recovery_state(source, source->commit + 1, 0, false);
		fprintf(stderr, "committed first owner\n");
		recovery_check(source, true);
		/* A second fresh owner sees completed homes and performs no rewrite. */
		source->test->device.writes = source->test->device.barriers = 0;
		fprintf(stderr, "committed second owner\n");
		recovery_check(source, true);
		assert(source->test->device.writes == 0);
		recovery_state(source, source->commit, 0, false);
		fprintf(stderr, "loser first owner\n");
		recovery_check(source, false);
		source->test->device.writes = source->test->device.barriers = 0;
		fprintf(stderr, "loser second owner\n");
		recovery_check(source, false);
		assert(source->test->device.writes == 0);
		printf("PASS: fresh complete/loser recovery kind %u/profile %u on %s\n",
		    profiles[index].kind, profiles[index].profile, profiles[index].image);
		recovery_source_close(source);
	}
}

static void
recovery_writer_states(const char *directory, enum ntfs_write_mutation_kind kind,
    enum test_profile profile, const char *image)
{
	struct recovery_case *source;
	size_t index, partial, direction, cases = 0;
	bool committed;

	source = recovery_source(directory, image, kind, profile);
	for (index = 0; index <= source->count; index++) {
		for (partial = 0; partial < NTFS_WRITE_CLUSTER_BYTES;
		    partial += NTFS_WRITE_SECTOR_BYTES) {
			if (index == source->count && partial != 0) {
				break;
			}
			for (direction = 0; direction < (partial == 0 ? 1u : 2u); direction++) {
				committed = index > source->commit;
				recovery_state(source, index, partial, direction != 0);
				fprintf(stderr,
				    "recovery case kind=%u profile=%u publication=%zu "
				    "partial=%zu suffix=%zu\n",
				    kind, profile, index, partial, direction);
				recovery_check(source, committed);
				cases++;
			}
		}
	}
	printf("PASS: %zu whole/prefix/suffix writer states recover to %s metadata\n", cases,
	    "the old or committed complete");
	recovery_source_close(source);
}

static void
recovery_reader_policy(const char *directory)
{
	struct recovery_case *source;
	struct test_case *test;
	struct ntfs_volume *volume = NULL;
	struct ntfs_logfile *log;
	struct ntfs_logfile_client client;
	struct ntfs_logfile_history_report history;
	struct ntfs_logfile_page_index_report index;
	const struct ntfs_run *run;
	uint8_t record[NTFS_WRITE_BATCH_MAX_PACKET_BYTES];
	uint64_t root_vcn, physical;
	size_t publication, partial;

	source = recovery_source(directory, "source.img", NTFS_WRITE_CREATE_FILE, TEST_DEFAULT);
	test = source->test;
	recovery_state(source, source->commit, 0, false);
	log = journal_open(test, &volume);
	assert(ntfs_logfile_get_client(log, 0, &client) == NTFS_OK);
	assert(ntfs_logfile_get_page_index_report(log, &index) == NTFS_OK &&
	    index.unsupported_targets != 0);
	assert(ntfs_logfile_visit_records(log, client.oldest_lsn, NTFS_WRITE_BATCH_MAX_PACKETS,
		   record, sizeof(record), NULL, NULL, &history) == NTFS_UNSUPPORTED);
	ntfs_logfile_close(log);
	assert(ntfs_unmount(volume) == NTFS_OK);
	volume = NULL;
	recovery_check(source, false);

	recovery_state(source, 0, 0, false);
	assert(ntfs_mount(&test->backend.reader, NULL, &volume) == NTFS_OK);
	root_vcn = (uint64_t)NTFS_ROOT_RECORD * NTFS_WRITE_RECORD_BYTES / NTFS_WRITE_CLUSTER_BYTES;
	run = ntfs_run_find(volume->mft, root_vcn);
	assert(run != NULL && run->lcn != NTFS_HOLE && root_vcn >= run->vcn &&
	    root_vcn - run->vcn < run->length);
	physical = (run->lcn + root_vcn - run->vcn) * NTFS_WRITE_CLUSTER_BYTES;
	assert(ntfs_unmount(volume) == NTFS_OK);
	volume = NULL;
	for (publication = source->commit + 1; publication < source->count; publication++) {
		if (source->publication[publication].stage == NTFS_WRITE_EXECUTION_METADATA_HOME &&
		    source->publication[publication].physical == physical) {
			break;
		}
	}
	assert(publication < source->count);
	partial = ((size_t)NTFS_ROOT_RECORD * NTFS_WRITE_RECORD_BYTES) % NTFS_WRITE_CLUSTER_BYTES +
	    NTFS_WRITE_SECTOR_BYTES;
	recovery_state(source, publication, partial, false);
	assert(ntfs_mount(&test->backend.reader, NULL, &volume) == NTFS_CORRUPT && volume == NULL &&
	    test->device.live == 0);
	recovery_check(source, true);
	recovery_source_close(source);
	puts("PASS: public history still refuses uncompleted tail copies and public mount "
	     "still refuses a torn root; private journal recovery validates both complete views");
}

#include "write_batch_recovery_faults.h"

static void
recovery_output_begin(const char *output)
{
	int count;

	recovery_output = malloc(TEST_PATH_BYTES);
	assert(recovery_output != NULL);
	count =
	    snprintf(recovery_output, TEST_PATH_BYTES, "%s/write-batch-recovery-XXXXXX", output);
	assert(count > 0 && count < TEST_PATH_BYTES && mkdtemp(recovery_output) != NULL);
}

#include "write_batch_recovery_ownership.h"

static void
batch_recovery_tests(const char *directory, const char *output)
{
	recovery_output_begin(output);

	recovery_tail_admission(directory);
	recovery_reader_policy(directory);
	recovery_posix_images(directory);
	recovery_profiles(directory);
	recovery_writer_states(directory, NTFS_WRITE_CREATE_FILE, TEST_DEFAULT, "source.img");
	recovery_writer_states(directory, NTFS_WRITE_GROWING_RANGE, TEST_DEFAULT, "source.img");
	recovery_writer_states(
	    directory, NTFS_WRITE_CREATE_FILE, TEST_MFT_GROWTH, "large-source.img");
	free(recovery_output);
}

static void
batch_recovery_callback_tests(const char *directory, const char *output)
{
	recovery_output_begin(output);

	recovery_admission(directory);
	recovery_callback_faults(
	    directory, NTFS_WRITE_CREATE_FILE, TEST_DEFAULT, "source.img", true);
	recovery_callback_faults(
	    directory, NTFS_WRITE_GROWING_RANGE, TEST_DEFAULT, "source.img", false);
	recovery_callback_faults(
	    directory, NTFS_WRITE_CREATE_FILE, TEST_MFT_GROWTH, "large-source.img", false);
	free(recovery_output);
}
