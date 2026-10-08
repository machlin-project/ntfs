/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "pointer_range.h"
#include "write_owner_internal.h"
#include "write_batch_execute.h"
#include "write_batch_recover.h"

struct ntfs_write_mutation_projection {
	struct ntfs_overwrite_environment source;
	const struct ntfs_write_batch_recovery *recovery;
	const struct ntfs_write_checkpoint *checkpoint;
	uint64_t work;
};

static void *
projection_allocate(void *context, size_t bytes)
{
	struct ntfs_write_mutation_projection *view = context;

	return view->source.reader.allocate(view->source.reader.context, bytes);
}

static void
projection_release(void *context, void *memory, size_t bytes)
{
	struct ntfs_write_mutation_projection *view = context;

	view->source.reader.release(view->source.reader.context, memory, bytes);
}

static enum ntfs_result
projection_read(void *context, uint64_t offset, void *output, size_t bytes)
{
	struct ntfs_write_mutation_projection *view = context;
	const struct ntfs_write_batch_recovery_publication *recovery;
	const struct ntfs_write_checkpoint_publication *checkpoint;
	const uint8_t *image;
	uint64_t physical, first, end;
	size_t index, count;
	enum ntfs_result result;

	if (!ntfs_bounds(offset, bytes, view->source.reader.size_bytes)) {
		return NTFS_RANGE;
	}
	count = view->recovery != NULL ? ntfs_write_batch_recovery_count(view->recovery)
				       : ntfs_write_checkpoint_count(view->checkpoint);
	if (count > NTFS_DEFAULT_OPERATION_WORK - view->work) {
		return NTFS_RANGE;
	}
	view->work += count;
	result = view->source.reader.read(view->source.reader.context, offset, output, bytes);
	if (result != NTFS_OK) {
		return result;
	}
	for (index = 0; index < count; index++) {
		if (view->recovery != NULL) {
			recovery = ntfs_write_batch_recovery_get(view->recovery, index);
			if (recovery == NULL) {
				return NTFS_CORRUPT;
			}
			physical = recovery->physical;
			image = recovery->image;
		} else {
			checkpoint = ntfs_write_checkpoint_get(view->checkpoint, index);
			if (checkpoint == NULL) {
				return NTFS_CORRUPT;
			}
			physical = checkpoint->physical;
			image = checkpoint->image;
		}
		if (!ntfs_bounds(
			physical, NTFS_WRITE_CLUSTER_BYTES, view->source.reader.size_bytes)) {
			return NTFS_CORRUPT;
		}
		first = offset > physical ? offset : physical;
		end = offset + bytes < physical + NTFS_WRITE_CLUSTER_BYTES
		    ? offset + bytes
		    : physical + NTFS_WRITE_CLUSTER_BYTES;
		if (first < end) {
			ntfs_copy((uint8_t *)output + first - offset, image + first - physical,
			    (size_t)(end - first));
		}
	}
	return NTFS_OK;
}

static enum ntfs_result
projection_write(void *context, uint64_t offset, const void *image, size_t bytes, size_t *actual)
{
	struct ntfs_write_mutation_projection *view = context;

	return view->source.write(view->source.reader.context, offset, image, bytes, actual);
}

static enum ntfs_result
projection_persist(void *context)
{
	struct ntfs_write_mutation_projection *view = context;

	return view->source.persist(view->source.reader.context);
}

static struct ntfs_overwrite_environment
projection_backend(struct ntfs_write_mutation_projection *view)
{
	struct ntfs_overwrite_environment backend = view->source;

	backend.reader.context = view;
	backend.reader.read = projection_read;
	backend.reader.allocate = projection_allocate;
	backend.reader.release = projection_release;
	backend.write = projection_write;
	backend.persist = projection_persist;
	return backend;
}

static enum ntfs_result
mutation_owner_check_policy(
    const struct ntfs_environment *reader, uint32_t alignment, struct ntfs_info *info)
{
	struct ntfs_volume *volume = NULL;
	enum ntfs_result result, closed;

	result = ntfs_mount(reader, NULL, &volume);
	if (result != NTFS_OK) {
		return result;
	}
	ntfs_get_info(volume, info);
	if (info->sector_size != NTFS_WRITE_SECTOR_BYTES ||
	    info->cluster_size != NTFS_WRITE_CLUSTER_BYTES ||
	    info->record_size != NTFS_WRITE_RECORD_BYTES || alignment > info->cluster_size) {
		result = NTFS_UNSUPPORTED;
	} else {
		result = ntfs_write_owner_check_hibernation(volume);
	}
	if (result == NTFS_OK) {
		result = ntfs_write_owner_check_change_journal(volume);
	}
	closed = ntfs_unmount(volume);
	return closed == NTFS_OK ? result : closed;
}

enum ntfs_result
ntfs_write_mutation_owner_open(const struct ntfs_overwrite_environment *environment,
    struct ntfs_overwrite_admission *admission, struct ntfs_write_recovery_report *report,
    struct ntfs_overwrite **out)
{
	struct ntfs_overwrite *owner = NULL;
	struct ntfs_write_batch_recovery *recovery = NULL;
	struct ntfs_write_mutation_projection view = {0};
	struct ntfs_overwrite_environment backend, projected;
	enum ntfs_result result;

	if (environment == NULL || admission == NULL || report == NULL || out == NULL ||
	    !ntfs_pointer_ranges_separate(
		environment, sizeof(*environment), admission, sizeof(*admission)) ||
	    !ntfs_pointer_ranges_separate(
		environment, sizeof(*environment), report, sizeof(*report)) ||
	    !ntfs_pointer_ranges_separate(environment, sizeof(*environment), out, sizeof(*out)) ||
	    !ntfs_pointer_ranges_separate(admission, sizeof(*admission), report, sizeof(*report)) ||
	    !ntfs_pointer_ranges_separate(admission, sizeof(*admission), out, sizeof(*out)) ||
	    !ntfs_pointer_ranges_separate(report, sizeof(*report), out, sizeof(*out))) {
		return NTFS_INVALID;
	}
	*out = NULL;
	ntfs_zero(admission, sizeof(*admission));
	ntfs_zero(report, sizeof(*report));
	result = ntfs_write_owner_claim(environment, &owner);
	if (result != NTFS_OK) {
		return result;
	}
	admission->claimed = true;
	backend = ntfs_write_owner_backend(owner);
	result = ntfs_write_batch_recover_prepare(&backend, &recovery);
	if (result != NTFS_OK) {
		goto done;
	}
	view.source = backend;
	view.recovery = recovery;
	projected = projection_backend(&view);
	result = ntfs_validate(&projected.reader, NULL, NULL, &admission->validation);
	if (result == NTFS_OK) {
		result = mutation_owner_check_policy(
		    &projected.reader, backend.alignment, &admission->info);
	}
	if (result == NTFS_OK) {
		result = ntfs_write_batch_recover_execute(recovery, &owner->poisoned, report);
		admission->quiescent = result == NTFS_OK && report->homes_persisted;
		admission->persistence_succeeded = result == NTFS_OK && report->completed;
	}
done:
	ntfs_write_batch_recovery_close(recovery);
	if (result != NTFS_OK) {
		ntfs_overwrite_close(owner);
		return result;
	}
	owner->info = admission->info;
	owner->mutations = true;
	*out = owner;
	return NTFS_OK;
}

static bool
mutation_owner_name_output_separate(const struct ntfs_overwrite *owner,
    const struct ntfs_write_name *name, const struct ntfs_write_mutation_report *report)
{
	return name != NULL &&
	    ntfs_pointer_ranges_separate(name, sizeof(*name), report, sizeof(*report)) &&
	    ntfs_pointer_ranges_separate(name, sizeof(*name), owner, sizeof(*owner));
}

struct ntfs_write_mutation_execution {
	struct ntfs_overwrite *owner;
	struct ntfs_overwrite_environment backend;
	struct ntfs_write_mutation_projection projection;
	struct ntfs_write_batch_execution *execution;
	struct ntfs_write_checkpoint *checkpoint;
	struct ntfs_write_mutation_preview preview;
	bool noop, attempted;
};

static enum ntfs_result
mutation_owner_read_item(
    struct ntfs_volume *volume, uint64_t reference, struct ntfs_write_mutation_item *out)
{
	struct ntfs_node *node = NULL;
	struct ntfs_write_mutation_item item = {0};
	enum ntfs_result result;

	result = ntfs_node_open(volume, reference, &node);
	if (result == NTFS_OK) {
		result = ntfs_node_stat(node, &item.stat);
	}
	if (result == NTFS_OK && item.stat.reparse) {
		result = NTFS_UNSUPPORTED;
	}
	if (result == NTFS_OK) {
		result = ntfs_node_link_counts(node, &item.links);
	}
	ntfs_node_close(node);
	if (result == NTFS_OK) {
		*out = item;
	}
	return result;
}

static enum ntfs_result
mutation_owner_find_over_item(struct ntfs_volume *volume, const struct ntfs_write_name *name,
    struct ntfs_write_mutation_item *out)
{
	struct ntfs_node *parent = NULL, *node = NULL;
	struct ntfs_stat stat;
	enum ntfs_result result;

	result = ntfs_node_open(volume, name->parent_reference, &parent);
	if (result == NTFS_OK) {
		result = ntfs_lookup(parent, name->units, name->count, &node);
	}
	if (result == NTFS_OK) {
		result = ntfs_node_metadata(node, &stat);
	}
	ntfs_node_close(node);
	ntfs_node_close(parent);
	return result == NTFS_OK ? mutation_owner_read_item(volume, stat.reference, out) : result;
}

static enum ntfs_result
mutation_owner_read_retirement(
    struct ntfs_volume *volume, struct ntfs_write_mutation_item *item, bool *exists)
{
	enum ntfs_result result;

	result = mutation_owner_read_item(volume, item->stat.reference, item);
	if (result == NTFS_OK) {
		*exists = true;
		return NTFS_OK;
	}
	if ((result != NTFS_NOT_FOUND && result != NTFS_STALE) || item->stat.links != 1 ||
	    item->links.physical_names != 1 || item->links.primary_names != 1 ||
	    item->links.dos_aliases != 0) {
		return result == NTFS_NOT_FOUND || result == NTFS_STALE ? NTFS_CORRUPT : result;
	}
	/* A free FILE's retained header is not a live native inode. Keep the old
	 * identity/sizes in the reply, independently of its advanced free generation. */
	item->stat.links = 0;
	ntfs_zero(&item->links, sizeof(item->links));
	*exists = false;
	return NTFS_OK;
}

static enum ntfs_result
mutation_owner_prepare_preview(struct ntfs_write_mutation_execution *prepared,
    const struct ntfs_write_mutation_request *request, const struct ntfs_write_mutation_plan *plan)
{
	struct ntfs_write_mutation_preview *preview = &prepared->preview;
	struct ntfs_environment projected;
	struct ntfs_volume *volume = NULL;
	uint64_t reference = ntfs_write_mutation_plan_reference(plan);
	bool removing;
	enum ntfs_result result = NTFS_OK, closed;

	preview->kind = request->kind;
	preview->requested_bytes =
	    request->kind == NTFS_WRITE_RESIZE_FILE ? request->size : request->bytes;
	removing =
	    request->kind == NTFS_WRITE_REMOVE_FILE || request->kind == NTFS_WRITE_REMOVE_DIRECTORY;
	if (removing || request->kind == NTFS_WRITE_RENAME) {
		result = ntfs_mount(&prepared->backend.reader, NULL, &volume);
		if (result == NTFS_OK && removing) {
			result = mutation_owner_read_item(volume, reference, &preview->item);
		}
		if (result == NTFS_OK && request->kind == NTFS_WRITE_RENAME) {
			result = mutation_owner_find_over_item(
			    volume, &request->destination, &preview->over_item);
			if (result == NTFS_NOT_FOUND) {
				result = NTFS_OK;
			} else if (result == NTFS_OK) {
				preview->over_item_present =
				    preview->over_item.stat.reference != reference;
			}
		}
		closed = ntfs_unmount(volume);
		volume = NULL;
		if (closed != NTFS_OK) {
			result = closed;
		}
	}
	if (result == NTFS_OK) {
		result = ntfs_write_mutation_plan_view(plan, &projected);
	}
	if (result == NTFS_OK) {
		result = ntfs_mount(&projected, NULL, &volume);
	}
	if (result == NTFS_OK) {
		if (removing) {
			result = mutation_owner_read_retirement(
			    volume, &preview->item, &preview->item_exists);
		} else {
			result = mutation_owner_read_item(volume, reference, &preview->item);
			preview->item_exists = result == NTFS_OK;
		}
	}
	if (result == NTFS_OK && preview->over_item_present) {
		result = mutation_owner_read_retirement(
		    volume, &preview->over_item, &preview->over_item_exists);
	}
	if (result == NTFS_OK && request->kind != NTFS_WRITE_RESIZE_FILE &&
	    request->kind != NTFS_WRITE_GROWING_RANGE) {
		result = mutation_owner_read_item(
		    volume, request->source.parent_reference, &preview->source_directory);
		preview->source_directory_present = result == NTFS_OK;
	}
	if (result == NTFS_OK && request->kind == NTFS_WRITE_RENAME) {
		result = mutation_owner_read_item(
		    volume, request->destination.parent_reference, &preview->destination_directory);
		preview->destination_directory_present = result == NTFS_OK;
	}
	if (result == NTFS_OK) {
		result = ntfs_count_free_clusters(volume, &preview->free_clusters);
	}
	if (volume != NULL) {
		closed = ntfs_unmount(volume);
		if (closed != NTFS_OK) {
			result = closed;
		}
	}
	return result;
}

void
ntfs_write_mutation_execution_close(struct ntfs_write_mutation_execution *prepared)
{
	struct ntfs_overwrite *owner;
	bool closing;

	if (prepared == NULL) {
		return;
	}
	owner = prepared->owner;
	ntfs_write_batch_execution_close(prepared->execution);
	ntfs_write_checkpoint_close(prepared->checkpoint);
	closing = owner->closing;
	owner->mutation = NULL;
	owner->reader.release(owner->reader.context, prepared, sizeof(*prepared));
	if (closing) {
		ntfs_overwrite_close(owner);
	}
}

enum ntfs_result
ntfs_write_mutation_execution_prepare(struct ntfs_overwrite *owner,
    const struct ntfs_write_mutation_request *request, struct ntfs_write_mutation_execution **out)
{
	struct ntfs_write_mutation_execution *prepared;
	struct ntfs_write_mutation_plan *plan = NULL;
	struct ntfs_write_program *program = NULL;
	struct ntfs_overwrite_environment projected;
	struct ntfs_info info;
	enum ntfs_result result;

	if (owner == NULL || request == NULL || out == NULL ||
	    !ntfs_pointer_ranges_separate(owner, sizeof(*owner), out, sizeof(*out)) ||
	    !ntfs_pointer_ranges_separate(request, sizeof(*request), out, sizeof(*out)) ||
	    !ntfs_pointer_ranges_separate(request, sizeof(*request), owner, sizeof(*owner))) {
		return NTFS_INVALID;
	}
	if (request->source.count > NTFS_NAME_MAX || request->destination.count > NTFS_NAME_MAX) {
		return NTFS_RANGE;
	}
	if (!ntfs_pointer_ranges_separate(request->data, request->bytes, out, sizeof(*out)) ||
	    !ntfs_pointer_ranges_separate(request->data, request->bytes, owner, sizeof(*owner)) ||
	    !ntfs_pointer_ranges_separate(request->source.units,
		request->source.count * sizeof(*request->source.units), out, sizeof(*out)) ||
	    !ntfs_pointer_ranges_separate(request->destination.units,
		request->destination.count * sizeof(*request->destination.units), out,
		sizeof(*out)) ||
	    !ntfs_pointer_ranges_separate(request->source.units,
		request->source.count * sizeof(*request->source.units), owner, sizeof(*owner)) ||
	    !ntfs_pointer_ranges_separate(request->destination.units,
		request->destination.count * sizeof(*request->destination.units), owner,
		sizeof(*owner)) ||
	    (owner->mutation != NULL &&
		!ntfs_pointer_ranges_separate(
		    owner->mutation, sizeof(*owner->mutation), out, sizeof(*out)))) {
		return NTFS_INVALID;
	}
	*out = NULL;
	if (owner->poisoned) {
		return NTFS_IO;
	}
	if (owner->closing) {
		return NTFS_STALE;
	}
	if (!owner->mutations) {
		return NTFS_UNSUPPORTED;
	}
	if (owner->mutation != NULL) {
		return NTFS_BUSY;
	}
	if (!ntfs_write_mutation_request_valid(request)) {
		return NTFS_INVALID;
	}
	/* SI-only storage preparation has no native later-setter/cache contract.
	 * Keep execution closed even if the generic FILE compiler accepts its bytes. */
	if (request->kind == NTFS_WRITE_SET_TIMES) {
		return NTFS_UNSUPPORTED;
	}
	prepared = owner->reader.allocate(owner->reader.context, sizeof(*prepared));
	if (prepared == NULL) {
		return NTFS_NO_MEMORY;
	}
	ntfs_zero(prepared, sizeof(*prepared));
	prepared->owner = owner;
	owner->mutation = prepared;
	ntfs_write_owner_begin(owner);
	prepared->backend = ntfs_write_owner_backend(owner);
	result = mutation_owner_check_policy(
	    &prepared->backend.reader, prepared->backend.alignment, &info);
	if (result == NTFS_OK) {
		result = ntfs_write_mutation_prepare(&prepared->backend.reader, request, &plan);
	}
	if (result == NTFS_OK) {
		result = mutation_owner_prepare_preview(prepared, request, plan);
		prepared->noop = ntfs_write_mutation_plan_count(plan) == 0;
	}
	if (result == NTFS_OK && !prepared->noop) {
		result = ntfs_write_program_prepare(&prepared->backend.reader, plan, &program);
	}
	ntfs_write_mutation_plan_close(plan);
	if (result != NTFS_OK) {
		goto done;
	}
	if (!prepared->noop) {
		result = ntfs_write_batch_execute_prepare(
		    &prepared->backend, program, &prepared->execution);
	}
	if (result == NTFS_NO_SPACE) {
		/* Reserve both operations against one unchanged claimed source. Rebinding
		 * on the complete private checkpoint view may fail, but never writes. */
		result = ntfs_write_checkpoint_prepare(&prepared->backend, &prepared->checkpoint);
		if (result == NTFS_BUSY) {
			result = NTFS_NO_SPACE;
		} else if (result == NTFS_OK) {
			prepared->projection.source = prepared->backend;
			prepared->projection.checkpoint = prepared->checkpoint;
			projected = projection_backend(&prepared->projection);
			result = ntfs_write_batch_execute_prepare(
			    &projected, program, &prepared->execution);
			prepared->preview.checkpoint_required = result == NTFS_OK;
		}
	}
done:
	ntfs_write_program_close(program);
	if (result != NTFS_OK) {
		ntfs_write_mutation_execution_close(prepared);
		return result;
	}
	*out = prepared;
	return NTFS_OK;
}

const struct ntfs_write_mutation_preview *
ntfs_write_mutation_execution_preview(const struct ntfs_write_mutation_execution *prepared)
{
	return prepared == NULL ? NULL : &prepared->preview;
}

enum ntfs_result
ntfs_write_mutation_execution_execute(
    struct ntfs_write_mutation_execution *prepared, struct ntfs_write_mutation_report *report)
{
	struct ntfs_overwrite *owner;
	enum ntfs_result result;

	if (prepared == NULL || report == NULL ||
	    !ntfs_pointer_ranges_separate(prepared, sizeof(*prepared), report, sizeof(*report)) ||
	    !ntfs_pointer_ranges_separate(
		prepared->owner, sizeof(*prepared->owner), report, sizeof(*report))) {
		return NTFS_INVALID;
	}
	owner = prepared->owner;
	ntfs_zero(report, sizeof(*report));
	report->reference = prepared->preview.item.stat.reference;
	report->requested_bytes = prepared->preview.requested_bytes;
	if (owner->poisoned) {
		report->execution.poisoned = true;
		return NTFS_IO;
	}
	if (owner->closing || prepared->attempted) {
		return NTFS_STALE;
	}
	prepared->attempted = true;
	if (prepared->noop) {
		report->execution.completed = true;
		report->completed_bytes = report->requested_bytes;
		return NTFS_OK;
	}
	report->initial_persistence_attempted = true;
	if (prepared->checkpoint != NULL) {
		result = ntfs_write_checkpoint_execute(
		    prepared->checkpoint, &owner->poisoned, &report->checkpoint);
		report->initial_persistence_succeeded = report->checkpoint.homes_persisted;
		report->checkpointed = result == NTFS_OK && report->checkpoint.completed;
	} else {
		result = prepared->backend.persist(prepared->backend.reader.context);
		report->initial_persistence_succeeded = result == NTFS_OK;
		if (result != NTFS_OK) {
			owner->poisoned = true;
			result = NTFS_IO;
		}
	}
	if (result == NTFS_OK) {
		result = ntfs_write_batch_execute(
		    prepared->execution, &owner->poisoned, &report->execution);
	}
	if (result == NTFS_OK) {
		report->completed_bytes = report->requested_bytes;
	}
	report->execution.poisoned = owner->poisoned;
	return result;
}

static enum ntfs_result
mutation_owner_execute_request(struct ntfs_overwrite *owner,
    const struct ntfs_write_mutation_request *request, struct ntfs_write_mutation_report *report)
{
	struct ntfs_write_mutation_execution *prepared = NULL;
	enum ntfs_result result;

	if (owner == NULL || report == NULL ||
	    !ntfs_pointer_ranges_separate(owner, sizeof(*owner), report, sizeof(*report)) ||
	    !ntfs_pointer_ranges_separate(request->data, request->bytes, report, sizeof(*report)) ||
	    request->source.count > NTFS_NAME_MAX || request->destination.count > NTFS_NAME_MAX ||
	    !ntfs_pointer_ranges_separate(request->source.units,
		request->source.count * sizeof(*request->source.units), report, sizeof(*report)) ||
	    !ntfs_pointer_ranges_separate(request->destination.units,
		request->destination.count * sizeof(*request->destination.units), report,
		sizeof(*report))) {
		return NTFS_INVALID;
	}
	ntfs_zero(report, sizeof(*report));
	result = ntfs_write_mutation_execution_prepare(owner, request, &prepared);
	if (result == NTFS_OK) {
		result = ntfs_write_mutation_execution_execute(prepared, report);
	}
	report->execution.poisoned = owner->poisoned;
	ntfs_write_mutation_execution_close(prepared);
	return result;
}

enum ntfs_result
ntfs_write_create_file(struct ntfs_overwrite *owner, const struct ntfs_write_name *name,
    uint64_t filetime, struct ntfs_write_mutation_report *report)
{
	struct ntfs_write_mutation_request request = {0};

	if (!mutation_owner_name_output_separate(owner, name, report)) {
		return NTFS_INVALID;
	}
	request.kind = NTFS_WRITE_CREATE_FILE;
	request.source = *name;
	request.filetime = filetime;
	return mutation_owner_execute_request(owner, &request, report);
}

enum ntfs_result
ntfs_write_create_directory(struct ntfs_overwrite *owner, const struct ntfs_write_name *name,
    uint64_t filetime, struct ntfs_write_mutation_report *report)
{
	struct ntfs_write_mutation_request request = {0};

	if (!mutation_owner_name_output_separate(owner, name, report)) {
		return NTFS_INVALID;
	}
	request.kind = NTFS_WRITE_CREATE_DIRECTORY;
	request.source = *name;
	request.filetime = filetime;
	return mutation_owner_execute_request(owner, &request, report);
}

enum ntfs_result
ntfs_write_resize_file(struct ntfs_overwrite *owner, uint64_t reference, uint64_t bytes,
    uint64_t filetime, struct ntfs_write_mutation_report *report)
{
	struct ntfs_write_mutation_request request = {0};

	request.kind = NTFS_WRITE_RESIZE_FILE;
	request.reference = reference;
	request.size = bytes;
	request.filetime = filetime;
	return mutation_owner_execute_request(owner, &request, report);
}

enum ntfs_result
ntfs_write_growing_range(struct ntfs_overwrite *owner, uint64_t reference, uint64_t offset,
    const void *data, size_t bytes, uint64_t filetime, struct ntfs_write_mutation_report *report)
{
	struct ntfs_write_mutation_request request = {0};

	request.kind = NTFS_WRITE_GROWING_RANGE;
	request.reference = reference;
	request.offset = offset;
	request.data = data;
	request.bytes = bytes;
	request.filetime = filetime;
	return mutation_owner_execute_request(owner, &request, report);
}

enum ntfs_result
ntfs_write_remove_file(struct ntfs_overwrite *owner, const struct ntfs_write_name *name,
    uint64_t filetime, struct ntfs_write_mutation_report *report)
{
	struct ntfs_write_mutation_request request = {0};

	if (!mutation_owner_name_output_separate(owner, name, report)) {
		return NTFS_INVALID;
	}
	request.kind = NTFS_WRITE_REMOVE_FILE;
	request.source = *name;
	request.filetime = filetime;
	return mutation_owner_execute_request(owner, &request, report);
}

enum ntfs_result
ntfs_write_remove_directory(struct ntfs_overwrite *owner, const struct ntfs_write_name *name,
    uint64_t filetime, struct ntfs_write_mutation_report *report)
{
	struct ntfs_write_mutation_request request = {0};

	if (!mutation_owner_name_output_separate(owner, name, report)) {
		return NTFS_INVALID;
	}
	request.kind = NTFS_WRITE_REMOVE_DIRECTORY;
	request.source = *name;
	request.filetime = filetime;
	return mutation_owner_execute_request(owner, &request, report);
}

enum ntfs_result
ntfs_write_rename(struct ntfs_overwrite *owner, const struct ntfs_write_name *source,
    const struct ntfs_write_name *destination, bool replace, uint64_t filetime,
    struct ntfs_write_mutation_report *report)
{
	struct ntfs_write_mutation_request request = {0};

	if (!mutation_owner_name_output_separate(owner, source, report) ||
	    !mutation_owner_name_output_separate(owner, destination, report)) {
		return NTFS_INVALID;
	}
	request.kind = NTFS_WRITE_RENAME;
	request.source = *source;
	request.destination = *destination;
	request.replace = replace;
	request.filetime = filetime;
	return mutation_owner_execute_request(owner, &request, report);
}
