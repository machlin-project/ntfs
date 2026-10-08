/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_sparse.h"
#include "pointer_range.h"

struct ntfs_write_sparse_plan {
	struct ntfs_environment environment;
	size_t allocation;
	struct ntfs_write_sparse_view view;
	struct ntfs_run storage[];
};

static enum ntfs_result
sparse_input_validate(const struct ntfs_write_sparse_input *input)
{
	const struct ntfs_run *run, *prior;
	uint64_t next = 0, logical_bytes;
	size_t index, other;

	if (input->count > NTFS_WRITE_SPARSE_MAX_RUNS) {
		return NTFS_RANGE;
	}
	if (!ntfs_pointer_range_valid(input->runs, input->count * sizeof(*input->runs))) {
		return NTFS_INVALID;
	}
	if (input->cluster_bytes < NTFS_MST_STRIDE ||
	    input->cluster_bytes > NTFS_MAX_CLUSTER_BYTES ||
	    (input->cluster_bytes & (input->cluster_bytes - 1u)) != 0) {
		return NTFS_UNSUPPORTED;
	}
	if (input->volume_clusters == 0 ||
	    input->volume_clusters > (uint64_t)INT64_MAX / input->cluster_bytes ||
	    input->logical_clusters > (uint64_t)INT64_MAX / input->cluster_bytes) {
		return NTFS_RANGE;
	}
	logical_bytes = input->logical_clusters * input->cluster_bytes;
	if (!ntfs_bounds(input->offset, input->bytes, logical_bytes)) {
		return NTFS_RANGE;
	}
	for (index = 0; index < input->count; index++) {
		run = &input->runs[index];
		if (run->vcn != next || run->length == 0 ||
		    !ntfs_bounds(run->vcn, run->length, input->logical_clusters)) {
			return NTFS_CORRUPT;
		}
		next += run->length;
		if (run->lcn == NTFS_HOLE) {
			continue;
		}
		if (!ntfs_bounds(run->lcn, run->length, input->volume_clusters)) {
			return NTFS_CORRUPT;
		}
		/* At most MAX_RUNS*(MAX_RUNS-1)/2 original-ownership comparisons. */
		for (other = 0; other < index; other++) {
			prior = &input->runs[other];
			if (prior->lcn != NTFS_HOLE && run->lcn < prior->lcn + prior->length &&
			    prior->lcn < run->lcn + run->length) {
				return NTFS_CORRUPT;
			}
		}
	}
	return next == input->logical_clusters ? NTFS_OK : NTFS_CORRUPT;
}

static void
sparse_append(struct ntfs_run *runs, size_t *count, uint64_t vcn, uint64_t length, uint64_t lcn)
{
	struct ntfs_run *last;

	if (length == 0) {
		return;
	}
	if (*count != 0) {
		last = &runs[*count - 1u];
		if (last->vcn + last->length == vcn &&
		    ((last->lcn == NTFS_HOLE && lcn == NTFS_HOLE) ||
			(last->lcn != NTFS_HOLE && lcn != NTFS_HOLE &&
			    last->lcn + last->length == lcn))) {
			last->length += length;
			return;
		}
	}
	runs[(*count)++] = (struct ntfs_run){vcn, length, lcn};
}

static void
sparse_zero_span(struct ntfs_write_sparse_plan *plan, const struct ntfs_write_sparse_input *input,
    uint64_t offset, uint64_t bytes)
{
	const struct ntfs_run *run;
	struct ntfs_write_sparse_zero *zero;
	uint64_t vcn = offset / input->cluster_bytes;
	size_t index;

	if (bytes == 0) {
		return;
	}
	for (index = 0; index < input->count; index++) {
		run = &input->runs[index];
		if (vcn >= run->vcn && vcn - run->vcn < run->length) {
			if (run->lcn != NTFS_HOLE) {
				zero = &plan->view.zero[plan->view.zero_count++];
				zero->physical =
				    (run->lcn + vcn - run->vcn) * input->cluster_bytes +
				    offset % input->cluster_bytes;
				zero->bytes = bytes;
			}
			return;
		}
	}
}

enum ntfs_result
ntfs_write_sparse_prepare(const struct ntfs_environment *environment,
    const struct ntfs_write_sparse_input *input, struct ntfs_write_sparse_plan **out)
{
	struct ntfs_write_sparse_plan *plan;
	struct ntfs_run *before, *after, *retired;
	const struct ntfs_run *run;
	uint64_t end, first, last, left, right, head_end, tail_first, lcn;
	size_t index, allocation, capacity;
	enum ntfs_result result;

	if (!ntfs_pointer_range_valid(out, sizeof(*out)) ||
	    !ntfs_pointer_range_valid(environment, sizeof(*environment)) ||
	    !ntfs_pointer_range_valid(input, sizeof(*input)) ||
	    !ntfs_pointer_ranges_separate(environment, sizeof(*environment), out, sizeof(*out)) ||
	    !ntfs_pointer_ranges_separate(input, sizeof(*input), out, sizeof(*out))) {
		return NTFS_INVALID;
	}
	if (input->count > NTFS_WRITE_SPARSE_MAX_RUNS) {
		return NTFS_RANGE;
	}
	if (!ntfs_pointer_ranges_separate(
		input->runs, input->count * sizeof(*input->runs), out, sizeof(*out))) {
		return NTFS_INVALID;
	}
	*out = NULL;
	if (environment->api_version != NTFS_API_VERSION || environment->allocate == NULL ||
	    environment->release == NULL) {
		return NTFS_INVALID;
	}
	result = sparse_input_validate(input);
	if (result != NTFS_OK) {
		return result;
	}
	/* Splitting one interval adds at most two projected run boundaries. */
	capacity = input->count * 3 + 2;
	allocation = sizeof(*plan) + capacity * sizeof(*before);
	plan = environment->allocate(environment->context, allocation);
	if (plan == NULL) {
		return NTFS_NO_MEMORY;
	}
	ntfs_zero(plan, allocation);
	plan->environment = *environment;
	plan->allocation = allocation;
	before = plan->storage;
	after = before + input->count;
	retired = after + input->count + 2;
	plan->view.before = before;
	plan->view.after = after;
	plan->view.retired = retired;
	plan->view.before_count = input->count;
	ntfs_copy(before, input->runs, input->count * sizeof(*before));
	if (input->bytes == 0) {
		ntfs_copy(after, before, input->count * sizeof(*after));
		plan->view.after_count = input->count;
		*out = plan;
		return NTFS_OK;
	}
	end = input->offset + input->bytes;
	first = input->offset / input->cluster_bytes +
	    (input->offset % input->cluster_bytes != 0 ? 1u : 0u);
	last = end / input->cluster_bytes;
	for (index = 0; index < input->count; index++) {
		run = &before[index];
		left = run->vcn > first ? run->vcn : first;
		right = run->vcn + run->length < last ? run->vcn + run->length : last;
		if (left >= right) {
			sparse_append(
			    after, &plan->view.after_count, run->vcn, run->length, run->lcn);
			continue;
		}
		sparse_append(after, &plan->view.after_count, run->vcn, left - run->vcn, run->lcn);
		sparse_append(after, &plan->view.after_count, left, right - left, NTFS_HOLE);
		lcn = run->lcn == NTFS_HOLE ? NTFS_HOLE : run->lcn + left - run->vcn;
		if (lcn != NTFS_HOLE) {
			sparse_append(retired, &plan->view.retired_count, left, right - left, lcn);
		}
		lcn = run->lcn == NTFS_HOLE ? NTFS_HOLE : run->lcn + right - run->vcn;
		sparse_append(
		    after, &plan->view.after_count, right, run->vcn + run->length - right, lcn);
	}
	if (input->bytes != 0) {
		head_end = input->offset;
		if (input->offset % input->cluster_bytes != 0) {
			head_end = first * input->cluster_bytes;
			if (head_end > end) {
				head_end = end;
			}
			sparse_zero_span(plan, input, input->offset, head_end - input->offset);
		}
		tail_first = last * input->cluster_bytes;
		if (end % input->cluster_bytes != 0 && tail_first >= head_end) {
			sparse_zero_span(plan, input, tail_first, end - tail_first);
		}
	}
	*out = plan;
	return NTFS_OK;
}

const struct ntfs_write_sparse_view *
ntfs_write_sparse_plan_view(const struct ntfs_write_sparse_plan *plan)
{
	return plan == NULL ? NULL : &plan->view;
}

void
ntfs_write_sparse_plan_close(struct ntfs_write_sparse_plan *plan)
{
	struct ntfs_environment environment;
	size_t bytes;

	if (plan == NULL) {
		return;
	}
	environment = plan->environment;
	bytes = plan->allocation;
	environment.release(environment.context, plan, bytes);
}
