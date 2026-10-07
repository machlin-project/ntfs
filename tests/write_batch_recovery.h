/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
/* Shared complete-operation fixture, device and independent metadata/content
 * oracles live in write_batch_execute.c. This suite gets only crash bytes after
 * every original C planner/program/executor has been closed. */

struct recovery_case {
	struct test_case *test;
	struct journal_oracle *oracle;
	struct ntfs_write_batch_publication *publication;
	uint8_t *frames, *committed;
	uint64_t reference, previous_reference;
	size_t count, commit;
	size_t state_complete, state_partial;
	bool state_suffix;
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
	enum ntfs_result result;

	source = calloc(1, sizeof(*source));
	assert(source != NULL);
	source->test = prepare_profile(directory, image, kind, profile);
	source->reference = ntfs_write_mutation_plan_reference(source->test->plan);
	source->oracle = journal_capture(source->test);
	result = ntfs_write_batch_execute_prepare(
	    &source->test->backend, source->test->program, &writer);
	if (result != NTFS_OK) {
		fprintf(stderr, "fresh next execution prepare on %s: %s\n", image,
		    ntfs_result_string(result));
	}
	assert(result == NTFS_OK);
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
	source->state_complete = complete;
	source->state_partial = partial;
	source->state_suffix = suffix;
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
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *node = NULL;
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
	if (source->previous_reference != 0) {
		/* The reused slot names a new object. The deleted identity may never
		 * resolve to it, including across every recovery reopen. */
		assert(ntfs_mount(&test->backend.reader, NULL, &volume) == NTFS_OK);
		assert(ntfs_node_open(volume, source->reference, &node) ==
		    (committed ? NTFS_OK : NTFS_NOT_FOUND));
		ntfs_node_close(node);
		node = NULL;
		assert(ntfs_node_open(volume, source->previous_reference, &node) ==
		    (committed ? NTFS_STALE : NTFS_NOT_FOUND));
		assert(node == NULL && ntfs_unmount(volume) == NTFS_OK);
	}
}

static void
recovery_preserved_bytes(struct recovery_case *source, const uint8_t *input)
{
	struct test_case *test = source->test;
	struct ntfs_volume *volume = NULL;
	struct ntfs_node *node = NULL;
	struct ntfs_stream *log = NULL;
	const struct ntfs_write_mutation_region *region;
	const struct ntfs_run *run;
	size_t physical, index, bytes;
	bool managed;

	assert(ntfs_mount(&test->backend.reader, NULL, &volume) == NTFS_OK);
	assert(ntfs_node_by_number(volume, NTFS_LOGFILE_RECORD, &node) == NTFS_OK);
	assert(ntfs_stream_open(node, NULL, 0, &log) == NTFS_OK);
	for (physical = 0; physical < test->device.bytes; physical += NTFS_WRITE_CLUSTER_BYTES) {
		bytes = test->device.bytes - physical < NTFS_WRITE_CLUSTER_BYTES
		    ? test->device.bytes - physical
		    : NTFS_WRITE_CLUSTER_BYTES;
		managed = false;
		for (index = 0; index < log->run_count; index++) {
			run = &log->runs[index];
			assert(run->lcn != NTFS_HOLE);
			if (physical / NTFS_WRITE_CLUSTER_BYTES >= run->lcn &&
			    physical / NTFS_WRITE_CLUSTER_BYTES - run->lcn < run->length) {
				managed = true;
				break;
			}
		}
		for (index = 0; !managed && index < test->regions; index++) {
			region = &test->region[index];
			managed = region->kind != NTFS_WRITE_MUTATION_DATA &&
			    region->physical == physical;
		}
		if (!managed) {
			assert(
			    memcmp(input + physical, test->device.visible + physical, bytes) == 0);
		}
	}
	ntfs_stream_close(log);
	ntfs_node_close(node);
	assert(ntfs_unmount(volume) == NTFS_OK);
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
		fprintf(stderr, "writer prefix: %zu/%zu publications; partial %zu %s; commit %zu\n",
		    source->state_complete, source->count, source->state_partial,
		    source->state_suffix ? "suffix" : "prefix", source->commit);
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
	recovery_preserved_bytes(source, input);
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

static void
recovery_qualified_refusals(const char *directory)
{
	static const struct {
		const char *image;
		enum ntfs_result expected;
	} cases[] = {{"prepared-no-home.img", NTFS_BUSY}, {"committed-no-home.img", NTFS_BUSY},
	    {"followup-wrong-previous-file.img", NTFS_CORRUPT},
	    {"qualified-copy-torn-home.img", NTFS_CORRUPT}};
	struct test_case *test;
	struct ntfs_write_batch_recovery *owner;
	size_t index;
	enum ntfs_result result;

	for (index = 0; index < sizeof(cases) / sizeof(cases[0]); index++) {
		test = prepare_profile(
		    directory, cases[index].image, NTFS_WRITE_CREATE_FILE, TEST_DEFAULT);
		ntfs_write_program_close(test->program);
		ntfs_write_mutation_plan_close(test->plan);
		test->program = NULL;
		test->plan = NULL;
		assert(test->device.live == 0);
		owner = (void *)(uintptr_t)1;
		result = ntfs_write_batch_recover_prepare(&test->backend, &owner);
		if (result != cases[index].expected) {
			fprintf(stderr, "qualified predecessor refusal %s: actual=%s expected=%s\n",
			    cases[index].image, ntfs_result_string(result),
			    ntfs_result_string(cases[index].expected));
		}
		assert(result == cases[index].expected && owner == NULL && test->device.live == 0 &&
		    test->device.writes == 0 && test->device.barriers == 0 &&
		    memcmp(test->before, test->device.visible, test->device.bytes) == 0 &&
		    memcmp(test->before, test->device.durable, test->device.bytes) == 0);
		finish(test);
	}
	puts("PASS: pending/unsettled/broken qualified predecessors and an unproved circular "
	     "home refuse without writes, leaks or an owner");
}

static void
batch_recovery_history_tests(const char *directory, const char *output)
{
	static const struct {
		const char *name;
		size_t lifetimes;
	} images[] = {{"committed-clean-original-root.img", 1},
	    {"followup-clean-original-root.img", 2}, {"compensated-clean-original-root.img", 1}};

	static const enum ntfs_write_mutation_kind kinds[] = {NTFS_WRITE_CREATE_FILE,
	    NTFS_WRITE_RESIZE_FILE, NTFS_WRITE_RENAME, NTFS_WRITE_REMOVE_FILE};
	struct recovery_case *source;
	size_t image, kind, index, states = 0;

	recovery_output_begin(output);
	recovery_qualified_refusals(directory);
	for (image = 0; image < sizeof(images) / sizeof(images[0]); image++) {
		for (kind = 0; kind < sizeof(kinds) / sizeof(kinds[0]); kind++) {
			source = recovery_source(directory, images[image].name, kinds[kind],
			    kinds[kind] == NTFS_WRITE_RESIZE_FILE ? TEST_SHRINK : TEST_DEFAULT);
			for (index = 0; index <= source->count; index++) {
				recovery_state(source, index, 0, false);
				recovery_check(source, index > source->commit);
				states++;
				/* A fresh second owner must retain all preceding lifetimes
				 * and perform no additional rewrite. */
				source->test->device.writes = source->test->device.barriers = 0;
				recovery_check(source, index > source->commit);
				assert(source->test->device.writes == 0);
			}
			printf("PASS: %zu fresh mixed-history states after %zu qualified "
			       "lifetimes for mutation %u\n",
			    source->count + 1, images[image].lifetimes, kinds[kind]);
			recovery_source_close(source);
		}
	}
	printf("PASS: %zu mixed-history interruption states and zero-rewrite second "
	       "reopens from independently authored qualified predecessors\n",
	    states);
	free(recovery_output);
}

struct recovery_sequence_step {
	enum ntfs_write_mutation_kind kind;
	enum test_profile profile;
};

static void
recovery_free_initialization_guards(void)
{
	struct ntfs_write_batch_recovery *owner, *history;
	struct ntfs_batch_recovery_home *home;
	struct ntfs_batch_recovery_projection *projection;
	struct ntfs_disk_record *record;
	uint8_t slot = 1u << 1;
	uint16_t sequence = 7;

	owner = calloc(1, sizeof(*owner));
	history = calloc(1, sizeof(*history));
	home = calloc(1, sizeof(*home));
	projection = calloc(1, sizeof(*projection));
	assert(owner != NULL && history != NULL && home != NULL && projection != NULL);
	owner->historical = owner->committed = true;
	owner->history_owner = history;
	history->projection = projection;
	history->projections = 1;
	projection->physical = home->physical = TEST_WRITE_OFFSET * NTFS_WRITE_CLUSTER_BYTES;
	projection->unknown_slots = slot;
	projection->next_sequence[1] = sequence;
	home->kind = NTFS_WRITE_MUTATION_FILE;
	home->slots = home->new_slots = slot;
	record = (void *)(home->after + NTFS_WRITE_RECORD_BYTES);
	ntfs_put_u16(record->sequence, sequence);
	assert(ntfs_batch_recovery_history_home_admit(owner, home) == NTFS_OK &&
	    home->historical_free_slots == slot);
	home->historical_free_slots = 0;
	ntfs_put_u16(record->sequence, (uint16_t)(sequence + 1u));
	assert(ntfs_batch_recovery_history_home_admit(owner, home) == NTFS_STALE &&
	    home->historical_free_slots == 0);
	ntfs_put_u16(record->sequence, sequence);
	ntfs_put_u16(record->flags, NTFS_RECORD_IN_USE);
	assert(ntfs_batch_recovery_history_home_admit(owner, home) == NTFS_STALE &&
	    home->historical_free_slots == 0);
	ntfs_put_u16(record->flags, 0);
	projection->unowned_cluster = true;
	assert(ntfs_batch_recovery_history_home_admit(owner, home) == NTFS_UNSUPPORTED &&
	    home->historical_free_slots == 0);
	projection->unowned_cluster = false;
	owner->committed = false;
	assert(ntfs_batch_recovery_history_home_admit(owner, home) == NTFS_UNSUPPORTED &&
	    home->historical_free_slots == 0);
	free(projection);
	free(home);
	free(history);
	free(owner);
	puts("PASS: a retained free initialization binds its generation; live, mismatched, "
	     "unowned and uncommitted states refuse");
}

static void
recovery_historical_after_guards(void)
{
	struct ntfs_write_batch_recovery *owner;
	struct ntfs_batch_recovery_home *home;
	size_t slot;

	owner = calloc(1, sizeof(*owner));
	home = calloc(1, sizeof(*home));
	assert(owner != NULL && home != NULL);
	owner->home = home;
	owner->homes = 1;
	owner->historical = owner->committed = true;
	home->kind = NTFS_WRITE_MUTATION_FILE;
	home->slots = 1;
	memset(home->source, TEST_PATTERN, sizeof(home->source));
	memcpy(home->after, home->source, sizeof(home->after));
	assert(ntfs_batch_recovery_historical_after_admit(owner) == NTFS_OK);
	for (slot = 0; slot < TEST_FILE_SLOTS; slot++) {
		home->after[slot * NTFS_WRITE_RECORD_BYTES] ^= TEST_PATTERN;
		assert(ntfs_batch_recovery_historical_after_admit(owner) == NTFS_STALE);
		home->after[slot * NTFS_WRITE_RECORD_BYTES] ^= TEST_PATTERN;
	}
	home->after[0] ^= TEST_PATTERN;
	home->historical_free_slots = 1;
	assert(ntfs_batch_recovery_historical_after_admit(owner) == NTFS_OK);
	home->slots = 0;
	assert(ntfs_batch_recovery_historical_after_admit(owner) == NTFS_CORRUPT);
	home->slots = 1;
	home->kind = NTFS_WRITE_MUTATION_INDEX;
	assert(ntfs_batch_recovery_historical_after_admit(owner) == NTFS_CORRUPT);
	home->historical_free_slots = 0;
	assert(ntfs_batch_recovery_historical_after_admit(owner) == NTFS_STALE);
	home->after[0] ^= TEST_PATTERN;
	assert(ntfs_batch_recovery_historical_after_admit(owner) == NTFS_OK);
	home->kind = NTFS_WRITE_MUTATION_BITMAP;
	home->after[NTFS_WRITE_CLUSTER_BYTES - 1] ^= TEST_PATTERN;
	assert(ntfs_batch_recovery_historical_after_admit(owner) == NTFS_STALE);
	home->after[NTFS_WRITE_CLUSTER_BYTES - 1] ^= TEST_PATTERN;
	assert(ntfs_batch_recovery_historical_after_admit(owner) == NTFS_OK);
	owner->committed = false;
	assert(ntfs_batch_recovery_historical_after_admit(owner) == NTFS_INVALID);
	owner->committed = true;
	owner->historical = false;
	assert(ntfs_batch_recovery_historical_after_admit(owner) == NTFS_INVALID);
	free(home);
	free(owner);
	puts("PASS: historical after reuse requires whole-home equality, including unchanged "
	     "FILE siblings, INDX and bitmap bytes; only proved free slots are excluded");
}

static void
batch_recovery_growth_tests(const char *directory, const char *output)
{
	static const enum test_profile profiles[] = {
	    TEST_MFT_GROWTH, TEST_DEFAULT, TEST_RENAMED_FILE};
	struct recovery_case *source;
	const struct ntfs_write_batch_publication *publication;
	struct ntfs_write_batch_recovery *owner;
	struct ntfs_volume *volume = NULL;
	const char *input_directory = directory, *input_name = "large-source.img";
	char name[TEST_PATH_BYTES], predecessor_name[TEST_PATH_BYTES], path[TEST_PATH_BYTES];
	FILE *file;
	uint64_t references[sizeof(profiles) / sizeof(profiles[0])];
	uint64_t grown_initialized = 0;
	size_t step, index;
	int length;

	recovery_output_begin(output);
	for (step = 0; step < sizeof(profiles) / sizeof(profiles[0]); step++) {
		source = recovery_source(
		    input_directory, input_name, NTFS_WRITE_CREATE_FILE, profiles[step]);
		references[step] = source->reference;
		if (step != 0) {
			assert(references[step] == references[0] + step);
		}
		recovery_state(source, source->count, 0, false);
		recovery_check(source, true);
		assert(source->test->device.writes == 0 && source->test->device.barriers == 1);
		assert(ntfs_mount(&source->test->backend.reader, NULL, &volume) == NTFS_OK);
		if (step == 0) {
			grown_initialized = volume->mft->initialized;
		} else {
			assert(volume->mft->initialized == grown_initialized);
		}
		assert(ntfs_unmount(volume) == NTFS_OK && source->test->device.live == 0);
		volume = NULL;
		/* Each next source is a complete reopened ordinary image. No direct
		 * projected seeding or checkpoint hides the retained initialization. */
		length = snprintf(name, sizeof(name), "growth-successor-%zu.img", step);
		assert(length > 0 && (size_t)length < sizeof(name));
		posix_case(input_directory, recovery_output, name, input_name,
		    NTFS_WRITE_CREATE_FILE, profiles[step]);
		length = snprintf(path, sizeof(path), "%s/%s", recovery_output, name);
		assert(length > 0 && (size_t)length < sizeof(path));
		file = fopen(path, "rb");
		assert(file != NULL &&
		    fread(source->test->device.visible, 1, source->test->device.bytes, file) ==
			source->test->device.bytes &&
		    fgetc(file) == EOF && fclose(file) == 0);
		assert(memcmp(source->test->device.visible, source->committed,
			   source->test->device.bytes) == 0);
		if (step != 0) {
			/* The retained growth's free FILE is meaningful even if a later
			 * initializer tears or its commit is delivered before its home. */
			for (index = source->commit; index < source->count; index++) {
				publication = &source->publication[index];
				if (publication->stage != NTFS_WRITE_EXECUTION_METADATA_HOME) {
					continue;
				}
				recovery_state(source, index, NTFS_WRITE_SECTOR_BYTES, false);
				recovery_check(source, true);
			}
		}
		owner = NULL;
		recovery_state(source, source->count, 0, false);
		assert(
		    ntfs_write_batch_recover_prepare(&source->test->backend, &owner) == NTFS_OK &&
		    ntfs_write_batch_recovery_count(owner) == 0);
		ntfs_write_batch_recovery_close(owner);
		recovery_source_close(source);
		input_directory = recovery_output;
		memcpy(predecessor_name, name, strlen(name) + 1);
		input_name = predecessor_name;
	}
	recovery_free_initialization_guards();
	free(recovery_output);
	puts("PASS: retained MFT growth admits two free sibling initializations, torn "
	     "metadata recovery and zero-rewrite reopens without an intervening checkpoint");
}

static void
recovery_sequence_case(const char *directory, unsigned ordinal, const char *image_name,
    const struct recovery_sequence_step *steps, size_t count, bool generation_reuse)
{
	struct recovery_case *source;
	const char *input_directory = directory, *input_name = image_name;
	char path[TEST_PATH_BYTES], name[TEST_PATH_BYTES], predecessor_name[TEST_PATH_BYTES];
	FILE *file;
	uint64_t first_reference = 0;
	uint16_t generation;
	size_t step, publication, partial, direction, states = 0;
	int length;

	for (step = 0; step < count; step++) {
		fprintf(stderr, "sequence %u lifetime %zu kind %u/profile %u\n", ordinal, step + 1,
		    steps[step].kind, steps[step].profile);
		source = recovery_source(
		    input_directory, input_name, steps[step].kind, steps[step].profile);
		if (generation_reuse && steps[step].kind == NTFS_WRITE_CREATE_FILE) {
			if (first_reference == 0) {
				first_reference = source->reference;
			} else {
				generation =
				    (uint16_t)(first_reference >> NTFS_REFERENCE_SEQUENCE_SHIFT);
				generation = (uint16_t)(generation + 1u);
				assert((source->reference & NTFS_REFERENCE_RECORD_MASK) ==
					(first_reference & NTFS_REFERENCE_RECORD_MASK) &&
				    source->reference >> NTFS_REFERENCE_SEQUENCE_SHIFT ==
					(generation == 0 ? 1 : generation));
				source->previous_reference = first_reference;
			}
		}
		for (publication = 0; publication <= source->count; publication++) {
			for (partial = 0; partial < NTFS_WRITE_CLUSTER_BYTES;
			    partial += NTFS_WRITE_SECTOR_BYTES) {
				if (partial != 0 &&
				    (!generation_reuse || step + 1 != count ||
					publication == source->count)) {
					break;
				}
				for (direction = 0; direction < (partial == 0 ? 1u : 2u);
				    direction++) {
					recovery_state(
					    source, publication, partial, direction != 0);
					recovery_check(source, publication > source->commit);
					states++;
					source->test->device.writes =
					    source->test->device.barriers = 0;
					recovery_check(source, publication > source->commit);
					assert(source->test->device.writes == 0);
				}
			}
		}
		length = snprintf(name, sizeof(name), "sequence-%u-%zu.img", ordinal, step);
		assert(length > 0 && (size_t)length < sizeof(name));
		length = snprintf(path, sizeof(path), "%s/%s", recovery_output, name);
		assert(length > 0 && (size_t)length < sizeof(path));
		/* Execute this operation through the actual ordinary-file backend,
		 * close it, and use only that reopened file as the next predecessor. */
		posix_case(input_directory, recovery_output, name, input_name, steps[step].kind,
		    steps[step].profile);
		file = fopen(path, "rb");
		assert(file != NULL &&
		    fread(source->test->device.visible, 1, source->test->device.bytes, file) ==
			source->test->device.bytes &&
		    fgetc(file) == EOF && fclose(file) == 0);
		assert(memcmp(source->test->device.visible, source->committed,
			   source->test->device.bytes) == 0);
		recovery_source_close(source);
		input_directory = recovery_output;
		memcpy(predecessor_name, name, strlen(name) + 1);
		input_name = predecessor_name;
	}
	printf("PASS: sequence %u: %zu ordinary lifetimes/%zu interruption states, "
	       "all unrelated bytes preserved and zero-rewrite second reopens\n",
	    ordinal, count, states);
}

static void
recovery_reopen_cases(const char *directory)
{
	static const struct recovery_sequence_step steps[] = {
	    {NTFS_WRITE_CREATE_FILE, TEST_DEFAULT}, {NTFS_WRITE_RENAME, TEST_RENAMED_FILE}};
	static const char *images[] = {"compensated-source.img", "opened-only-source.img",
	    "twice-opened-source.img", "compensated-wrapped-source.img"};
	struct recovery_case *source;
	const struct ntfs_write_batch_publication *publication;
	struct ntfs_disk_log_record *record;
	struct ntfs_logfile_update update;
	uint8_t *logical;
	char path[TEST_PATH_BYTES];
	FILE *file;
	size_t index, complete, count;
	int length;

	logical = malloc(NTFS_WRITE_CLUSTER_BYTES);
	assert(logical != NULL);
	for (index = 0; index < sizeof(images) / sizeof(images[0]); index++) {
		source = recovery_source(index == 2 ? recovery_output : directory,
		    index == 2	     ? images[1]
			: index == 3 ? "large-reuse-wrapped.img"
				     : "large-source.img",
		    NTFS_WRITE_CREATE_FILE, TEST_DEFAULT);
		complete = source->commit;
		if (index == 1 || index == 2) {
			for (count = 0; count < source->commit; count++) {
				publication = &source->publication[count];
				if (publication->stage != NTFS_WRITE_EXECUTION_PREPARE_HOME) {
					continue;
				}
				memcpy(logical, publication->image, NTFS_WRITE_CLUSTER_BYTES);
				assert(ntfs_fixup(logical, NTFS_WRITE_CLUSTER_BYTES, "RCRD") ==
				    NTFS_OK);
				record =
				    (void *)(logical + source->oracle->restart.page_data_offset);
				assert(
				    ntfs_logfile_update_decode((uint8_t *)record + sizeof(*record),
					ntfs_u32(record->data_bytes), &update) == NTFS_OK);
				assert(update.redo_operation ==
				    NTFS_LOG_OP_OPEN_NONRESIDENT_ATTRIBUTE);
				complete = count + 1;
				break;
			}
			assert(count < source->commit);
		}
		recovery_state(source, complete, 0, false);
		recovery_check(source, false);
		source->test->device.writes = source->test->device.barriers = 0;
		recovery_check(source, false);
		assert(source->test->device.writes == 0);
		length = snprintf(path, sizeof(path), "%s/%s", recovery_output, images[index]);
		assert(length > 0 && (size_t)length < sizeof(path));
		file = fopen(path, "wbx");
		assert(file != NULL &&
		    fwrite(source->test->device.visible, 1, source->test->device.bytes, file) ==
			source->test->device.bytes &&
		    fclose(file) == 0);
		recovery_source_close(source);
		recovery_sequence_case(recovery_output, (unsigned)(5 + index), images[index], steps,
		    sizeof(steps) / sizeof(steps[0]), false);
		if (index == 0) {
			recovery_compensated_generation_refusal(
			    recovery_output, "sequence-5-0.img");
		}
	}
	free(logical);
	puts("PASS: actual operations continue after fresh compensated and one/two "
	     "opened-attribute-only recovered prefixes, including a free wrapped generation");
}

static void
batch_recovery_reopen_tests(const char *directory, const char *output)
{
	recovery_output_begin(output);
	recovery_reopen_cases(directory);
	free(recovery_output);
}

static void
batch_recovery_sequence_tests(const char *directory, const char *output, bool reuse_only)
{
	static const struct recovery_sequence_step namespace_steps[] = {
	    {NTFS_WRITE_CREATE_FILE, TEST_DEFAULT}, {NTFS_WRITE_GROWING_RANGE, TEST_DEFAULT},
	    {NTFS_WRITE_RESIZE_FILE, TEST_SHRINK}, {NTFS_WRITE_RENAME, TEST_RENAMED_FILE},
	    {NTFS_WRITE_REMOVE_FILE, TEST_RENAMED_FILE},
	    {NTFS_WRITE_REMOVE_FILE, TEST_CREATED_FILE}};
	static const struct recovery_sequence_step directory_steps[] = {
	    {NTFS_WRITE_CREATE_DIRECTORY, TEST_DEFAULT}, {NTFS_WRITE_RENAME, TEST_RENAMED_FILE},
	    {NTFS_WRITE_REMOVE_DIRECTORY, TEST_DEFAULT}};
	static const struct recovery_sequence_step reuse_steps[] = {
	    {NTFS_WRITE_CREATE_FILE, TEST_DEFAULT}, {NTFS_WRITE_REMOVE_FILE, TEST_CREATED_FILE},
	    {NTFS_WRITE_CREATE_FILE, TEST_DEFAULT}};
	static const struct recovery_sequence_step distinct_steps[] = {
	    {NTFS_WRITE_CREATE_FILE, TEST_DEFAULT}, {NTFS_WRITE_CREATE_FILE, TEST_RENAMED_FILE},
	    {NTFS_WRITE_REMOVE_FILE, TEST_CREATED_FILE}};

	recovery_historical_after_guards();
	if (!reuse_only) {
		batch_recovery_growth_tests(directory, output);
	}
	recovery_output_begin(output);
	if (!reuse_only) {
		recovery_sequence_case(directory, 0, "large-source.img", namespace_steps,
		    sizeof(namespace_steps) / sizeof(namespace_steps[0]), false);
		recovery_sequence_case(directory, 1, "large-source.img", directory_steps,
		    sizeof(directory_steps) / sizeof(directory_steps[0]), false);
		recovery_sequence_case(directory, 2, "large-source.img", distinct_steps,
		    sizeof(distinct_steps) / sizeof(distinct_steps[0]), false);
	}
	recovery_sequence_case(directory, 3, "large-source.img", reuse_steps,
	    sizeof(reuse_steps) / sizeof(reuse_steps[0]), true);
	recovery_sequence_case(directory, 4, "large-reuse-wrapped.img", reuse_steps,
	    sizeof(reuse_steps) / sizeof(reuse_steps[0]), true);
	if (!reuse_only) {
		recovery_callback_faults(recovery_output, NTFS_WRITE_CREATE_FILE, TEST_DEFAULT,
		    "sequence-3-1.img", true);
		recovery_posix_case(
		    recovery_output, 3, "sequence-3-1.img", NTFS_WRITE_CREATE_FILE, TEST_DEFAULT);
		recovery_reopen_cases(directory);
	}
	free(recovery_output);
}
