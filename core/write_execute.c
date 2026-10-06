/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_internal.h"

enum {
	FRAME_DIRTY_FIRST,
	FRAME_DIRTY_SECOND,
	FRAME_PREPARE_COPY,
	FRAME_PREPARE_HOME,
	FRAME_COMMIT_COPY,
	FRAME_COMMIT_HOME,
	FRAME_CLEAN_FIRST,
	FRAME_CLEAN_SECOND
};

static bool
separate(const void *a, size_t a_bytes, const void *b, size_t b_bytes)
{
	uintptr_t left = (uintptr_t)a, right = (uintptr_t)b;

	return (a != NULL || a_bytes == 0) && (b != NULL || b_bytes == 0) &&
	    a_bytes <= UINTPTR_MAX - left && b_bytes <= UINTPTR_MAX - right &&
	    (a_bytes == 0 || b_bytes == 0 || left + a_bytes <= right || right + b_bytes <= left);
}

static bool
physical_separate(uint64_t a, uint64_t a_bytes, uint64_t b, uint64_t b_bytes)
{
	return a_bytes <= UINT64_MAX - a && b_bytes <= UINT64_MAX - b &&
	    (a + a_bytes <= b || b + b_bytes <= a);
}

static enum ntfs_result
admit(const struct ntfs_overwrite_environment *backend,
    const struct ntfs_write_execution_input *input, struct ntfs_write_execution_workspace *work)
{
	const struct ntfs_write_data_span *span;
	const struct ntfs_write_file_plan *file;
	uint64_t total = 0;
	size_t index, previous;
	uint32_t alignment;

	if (backend == NULL || input == NULL || work == NULL || input->file == NULL ||
	    input->journal == NULL || input->spans > NTFS_WRITE_EXECUTE_MAX_SPANS ||
	    !separate(backend, sizeof(*backend), work, sizeof(*work)) ||
	    !separate(input, sizeof(*input), work, sizeof(*work)) ||
	    !separate(input->file, sizeof(*input->file), work, sizeof(*work)) ||
	    !separate(input->journal, sizeof(*input->journal), work, sizeof(*work)) ||
	    !separate(input->data, input->spans * sizeof(*input->data), work, sizeof(*work))) {
		return NTFS_INVALID;
	}
	alignment = backend->alignment;
	if (backend->api_version != NTFS_OVERWRITE_API_VERSION ||
	    backend->reader.api_version != NTFS_API_VERSION || backend->reader.read == NULL ||
	    backend->write == NULL || backend->persist == NULL ||
	    alignment < NTFS_WRITE_SECTOR_BYTES || alignment > NTFS_WRITE_CLUSTER_BYTES ||
	    (alignment & (alignment - 1u)) != 0 || (uintptr_t)work % alignment != 0) {
		return NTFS_INVALID;
	}
	file = input->file;
	if (file->cluster_physical % NTFS_WRITE_CLUSTER_BYTES != 0 ||
	    !ntfs_bounds(
		file->cluster_physical, NTFS_WRITE_CLUSTER_BYTES, backend->reader.size_bytes) ||
	    file->cluster_index % (NTFS_WRITE_RECORD_BYTES / NTFS_WRITE_SECTOR_BYTES) != 0 ||
	    !ntfs_bounds((size_t)file->cluster_index * NTFS_WRITE_SECTOR_BYTES,
		NTFS_WRITE_RECORD_BYTES, NTFS_WRITE_CLUSTER_BYTES) ||
	    ntfs_u64(((const struct ntfs_disk_record *)file->after)->lsn) !=
		input->journal->reservation.update_lsn) {
		return NTFS_INVALID;
	}
	for (index = 0; index < NTFS_WRITE_EXECUTE_LOG_LOCATIONS; index++) {
		if (input->physical[index] % NTFS_WRITE_CLUSTER_BYTES != 0 ||
		    !ntfs_bounds(input->physical[index], NTFS_WRITE_CLUSTER_BYTES,
			backend->reader.size_bytes) ||
		    !physical_separate(input->physical[index], NTFS_WRITE_CLUSTER_BYTES,
			file->cluster_physical, NTFS_WRITE_CLUSTER_BYTES)) {
			return NTFS_INVALID;
		}
		for (previous = 0; previous < index; previous++) {
			if (!physical_separate(input->physical[index], NTFS_WRITE_CLUSTER_BYTES,
				input->physical[previous], NTFS_WRITE_CLUSTER_BYTES)) {
				return NTFS_INVALID;
			}
		}
	}
	for (index = 0; index < NTFS_LFS_RESTART_PAGES; index++) {
		if (!separate(
			input->restart[index], NTFS_WRITE_CLUSTER_BYTES, work, sizeof(*work))) {
			return NTFS_INVALID;
		}
	}
	for (index = 0; index < input->spans; index++) {
		span = &input->data[index];
		if (span->bytes == 0 || span->bytes > NTFS_WRITE_EXECUTE_MAX_DATA_BYTES - total ||
		    span->physical % alignment != 0 || span->bytes % alignment != 0 ||
		    (uintptr_t)span->image % alignment != 0 ||
		    !ntfs_bounds(span->physical, span->bytes, backend->reader.size_bytes) ||
		    !separate(span->image, span->bytes, work, sizeof(*work)) ||
		    !physical_separate(span->physical, span->bytes, file->cluster_physical,
			NTFS_WRITE_CLUSTER_BYTES)) {
			return NTFS_INVALID;
		}
		for (previous = 0; previous < NTFS_WRITE_EXECUTE_LOG_LOCATIONS; previous++) {
			if (!physical_separate(span->physical, span->bytes,
				input->physical[previous], NTFS_WRITE_CLUSTER_BYTES)) {
				return NTFS_INVALID;
			}
		}
		for (previous = 0; previous < index; previous++) {
			if (!physical_separate(span->physical, span->bytes,
				input->data[previous].physical, input->data[previous].bytes)) {
				return NTFS_INVALID;
			}
		}
		total += span->bytes;
	}
	return NTFS_OK;
}

static enum ntfs_result
prepare(const struct ntfs_overwrite_environment *backend,
    const struct ntfs_write_execution_input *input, struct ntfs_write_execution_workspace *work)
{
	const struct ntfs_write_journal_plan *journal = input->journal;
	const struct ntfs_write_file_plan *file = input->file;
	const void *desired[NTFS_WRITE_EXECUTE_LOG_LOCATIONS];
	const size_t frames[NTFS_WRITE_EXECUTE_LOG_LOCATIONS] = {FRAME_DIRTY_FIRST,
	    FRAME_DIRTY_SECOND, FRAME_PREPARE_HOME, FRAME_COMMIT_HOME, FRAME_PREPARE_COPY,
	    FRAME_COMMIT_COPY};
	size_t index, offset, first, end;
	enum ntfs_result result;

	desired[NTFS_WRITE_EXECUTE_RESTART_FIRST] = journal->dirty_restart[0];
	desired[NTFS_WRITE_EXECUTE_RESTART_SECOND] = journal->dirty_restart[1];
	desired[NTFS_WRITE_EXECUTE_PREPARE_HOME] = journal->prepare;
	desired[NTFS_WRITE_EXECUTE_COMMIT_HOME] = journal->commit;
	desired[NTFS_WRITE_EXECUTE_PREPARE_COPY] = journal->prepare_copy;
	desired[NTFS_WRITE_EXECUTE_COMMIT_COPY] = journal->commit_copy;
	for (index = 0; index < NTFS_WRITE_EXECUTE_LOG_LOCATIONS; index++) {
		result = backend->reader.read(backend->reader.context, input->physical[index],
		    work->before, sizeof(work->before));
		if (result != NTFS_OK) {
			return result;
		}
		if (index < NTFS_LFS_RESTART_PAGES &&
		    !ntfs_equal(work->before, input->restart[index], sizeof(work->before))) {
			return NTFS_STALE;
		}
		ntfs_copy(work->frame[frames[index]], desired[index], NTFS_WRITE_CLUSTER_BYTES);
		result = ntfs_write_guard_frame(
		    work->before, sizeof(work->before), work->frame[frames[index]], &work->guard);
		if (result != NTFS_OK) {
			return result;
		}
	}
	for (index = 0; index < NTFS_LFS_RESTART_PAGES; index++) {
		ntfs_copy(work->frame[FRAME_CLEAN_FIRST + index], journal->retained_restart[index],
		    NTFS_WRITE_CLUSTER_BYTES);
		result = ntfs_write_guard_frame(work->frame[FRAME_DIRTY_FIRST + index],
		    NTFS_WRITE_CLUSTER_BYTES, work->frame[FRAME_CLEAN_FIRST + index], &work->guard);
		if (result != NTFS_OK) {
			return result;
		}
	}
	result = backend->reader.read(
	    backend->reader.context, file->cluster_physical, work->home, sizeof(work->home));
	if (result != NTFS_OK) {
		return result;
	}
	offset = (size_t)file->cluster_index * NTFS_WRITE_SECTOR_BYTES;
	ntfs_copy(work->before, work->home + offset, NTFS_WRITE_RECORD_BYTES);
	ntfs_copy(work->guard.restored, work->before, NTFS_WRITE_RECORD_BYTES);
	result = ntfs_fixup(work->guard.restored, NTFS_WRITE_RECORD_BYTES, "FILE");
	if (result != NTFS_OK) {
		return result;
	}
	if (!ntfs_equal(work->guard.restored, file->before, NTFS_WRITE_RECORD_BYTES)) {
		return NTFS_STALE;
	}
	ntfs_copy(work->guard.restored, file->protected_after, NTFS_WRITE_RECORD_BYTES);
	result = ntfs_fixup(work->guard.restored, NTFS_WRITE_RECORD_BYTES, "FILE");
	if (result != NTFS_OK) {
		return result;
	}
	first = ntfs_u16(((const struct ntfs_disk_record *)file->after)->mst.usa_offset);
	end = first +
	    (size_t)ntfs_u16(((const struct ntfs_disk_record *)file->after)->mst.usa_count) *
		sizeof(uint16_t);
	if (end > NTFS_WRITE_RECORD_BYTES ||
	    !ntfs_equal(work->guard.restored, file->after, first) ||
	    !ntfs_equal(
		work->guard.restored + end, file->after + end, NTFS_WRITE_RECORD_BYTES - end)) {
		return NTFS_CORRUPT;
	}
	ntfs_copy(work->home + offset, file->protected_after, NTFS_WRITE_RECORD_BYTES);
	result = ntfs_write_guard_frame(
	    work->before, NTFS_WRITE_RECORD_BYTES, work->home + offset, &work->guard);
	if (result != NTFS_OK) {
		return result;
	}
	work->backend = *backend;
	ntfs_copy(work->physical, input->physical, sizeof(work->physical));
	work->home_physical = file->cluster_physical;
	work->spans = input->spans;
	ntfs_copy(work->data, input->data, input->spans * sizeof(*input->data));
	work->prepared = true;
	return NTFS_OK;
}

enum ntfs_result
ntfs_write_execute_prepare(const struct ntfs_overwrite_environment *backend,
    const struct ntfs_write_execution_input *input, struct ntfs_write_execution_workspace *work)
{
	enum ntfs_result result;

	result = admit(backend, input, work);
	if (result != NTFS_OK) {
		return result;
	}
	ntfs_zero(work, sizeof(*work));
	result = prepare(backend, input, work);
	if (result != NTFS_OK) {
		ntfs_zero(work, sizeof(*work));
	}
	return result;
}

static enum ntfs_result
write_exact(struct ntfs_write_execution_workspace *work, uint64_t physical, const void *image,
    size_t bytes, bool *poisoned, struct ntfs_write_execution_report *report)
{
	size_t transferred = 0;
	enum ntfs_result result;

	report->writes++;
	result =
	    work->backend.write(work->backend.reader.context, physical, image, bytes, &transferred);
	if (transferred <= bytes) {
		report->physical_bytes += transferred;
	}
	if (result != NTFS_OK || transferred != bytes) {
		*poisoned = true;
		return NTFS_IO;
	}
	return NTFS_OK;
}

static enum ntfs_result
persist(struct ntfs_write_execution_workspace *work, enum ntfs_write_execution_stage stage,
    bool *poisoned, struct ntfs_write_execution_report *report)
{
	enum ntfs_result result;

	report->barriers++;
	result = work->backend.persist(work->backend.reader.context);
	if (result != NTFS_OK) {
		*poisoned = true;
		return NTFS_IO;
	}
	report->durable_stage = stage;
	return NTFS_OK;
}

static enum ntfs_result
publish(struct ntfs_write_execution_workspace *work, uint64_t physical, const void *image,
    enum ntfs_write_execution_stage stage, bool *poisoned,
    struct ntfs_write_execution_report *report)
{
	enum ntfs_result result;

	result = write_exact(work, physical, image, NTFS_WRITE_CLUSTER_BYTES, poisoned, report);
	if (result == NTFS_OK) {
		result = persist(work, stage, poisoned, report);
	}
	return result;
}

enum ntfs_result
ntfs_write_execute(struct ntfs_write_execution_workspace *work, bool *poisoned,
    struct ntfs_write_execution_report *report)
{
	const size_t frame_location[NTFS_WRITE_EXECUTE_FRAMES] = {NTFS_WRITE_EXECUTE_RESTART_FIRST,
	    NTFS_WRITE_EXECUTE_RESTART_SECOND, NTFS_WRITE_EXECUTE_PREPARE_COPY,
	    NTFS_WRITE_EXECUTE_PREPARE_HOME, NTFS_WRITE_EXECUTE_COMMIT_COPY,
	    NTFS_WRITE_EXECUTE_COMMIT_HOME, NTFS_WRITE_EXECUTE_RESTART_FIRST,
	    NTFS_WRITE_EXECUTE_RESTART_SECOND};

	const enum ntfs_write_execution_stage stage[NTFS_WRITE_EXECUTE_FRAMES] = {
	    NTFS_WRITE_EXECUTION_DIRTY_FIRST, NTFS_WRITE_EXECUTION_DIRTY_SECOND,
	    NTFS_WRITE_EXECUTION_PREPARE_COPY, NTFS_WRITE_EXECUTION_PREPARE_HOME,
	    NTFS_WRITE_EXECUTION_COMMIT_COPY, NTFS_WRITE_EXECUTION_COMMIT_HOME,
	    NTFS_WRITE_EXECUTION_CLEAN_FIRST, NTFS_WRITE_EXECUTION_CLEAN_SECOND};

	size_t index, span;
	enum ntfs_result result = NTFS_OK;

	if (work == NULL || poisoned == NULL || report == NULL ||
	    !separate(work, sizeof(*work), poisoned, sizeof(*poisoned)) ||
	    !separate(work, sizeof(*work), report, sizeof(*report)) ||
	    !separate(poisoned, sizeof(*poisoned), report, sizeof(*report))) {
		return NTFS_INVALID;
	}
	if (work->spans > NTFS_WRITE_EXECUTE_MAX_SPANS) {
		return NTFS_INVALID;
	}
	for (span = 0; span < work->spans; span++) {
		if (!separate(work->data[span].image, work->data[span].bytes, poisoned,
			sizeof(*poisoned)) ||
		    !separate(
			work->data[span].image, work->data[span].bytes, report, sizeof(*report))) {
			return NTFS_INVALID;
		}
	}
	ntfs_zero(report, sizeof(*report));
	if (*poisoned) {
		report->poisoned = true;
		return NTFS_IO;
	}
	if (!work->prepared) {
		return NTFS_INVALID;
	}
	/* A prepared physical image is consumed once, including uncertain failure. */
	work->prepared = false;
	for (index = 0; index < NTFS_WRITE_EXECUTE_FRAMES; index++) {
		if (index == FRAME_COMMIT_COPY && work->spans != 0) {
			for (span = 0; span < work->spans; span++) {
				result = write_exact(work, work->data[span].physical,
				    work->data[span].image, work->data[span].bytes, poisoned,
				    report);
				if (result != NTFS_OK) {
					goto done;
				}
				report->data_bytes += work->data[span].bytes;
			}
			result = persist(work, NTFS_WRITE_EXECUTION_DATA, poisoned, report);
			if (result != NTFS_OK) {
				goto done;
			}
			report->data_persisted = true;
		}
		if (index == FRAME_CLEAN_FIRST) {
			result = publish(work, work->home_physical, work->home,
			    NTFS_WRITE_EXECUTION_FILE_HOME, poisoned, report);
			if (result != NTFS_OK) {
				goto done;
			}
		}
		result = publish(work, work->physical[frame_location[index]], work->frame[index],
		    stage[index], poisoned, report);
		if (result != NTFS_OK) {
			goto done;
		}
		if (index == FRAME_COMMIT_COPY) {
			report->commit_persisted = true;
		}
	}
	report->completed = true;

done:
	report->poisoned = *poisoned;
	return result;
}
