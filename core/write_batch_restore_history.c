/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_batch_recover_internal.h"

void
ntfs_batch_recovery_lifetime_select(
    struct ntfs_write_batch_recovery *owner, const struct ntfs_batch_recovery_lifetime *lifetime)
{
	owner->target = lifetime->target;
	owner->targets = lifetime->targets;
	owner->target_capacity = lifetime->target_capacity;
	owner->first_update = lifetime->first_update;
	owner->updates = lifetime->updates;
	owner->compensations = lifetime->compensations;
	owner->remaining_undo = lifetime->remaining_undo;
	owner->committed = lifetime->committed;
	owner->compensated = lifetime->compensated;
}

enum ntfs_result
ntfs_batch_recovery_history_home_admit(
    const struct ntfs_write_batch_recovery *owner, struct ntfs_batch_recovery_home *home)
{
	const struct ntfs_write_batch_recovery *history = owner->history_owner;
	const struct ntfs_batch_recovery_projection *projection;
	const struct ntfs_disk_record *before, *after;
	uint8_t unknown;
	uint16_t sequence;
	size_t index, slot, offset;

	if (!owner->historical || history == NULL) {
		return NTFS_OK;
	}
	for (index = 0; index < history->projections; index++) {
		projection = &history->projection[index];
		if (projection->physical != home->physical) {
			continue;
		}
		/* A later initialization does not retain old unowned bytes. An exact
		 * prior retirement can nevertheless prove this FILE generation: its
		 * full old snapshot, header inverse, original set MFT bit and settled
		 * clear bit bind the free state consumed by the later initializer.
		 * Private placeholders never become an alleged physical before image. */
		if (projection->unowned_cluster || projection->unknown_index ||
		    (projection->unknown_slots != 0 && home->kind != NTFS_WRITE_MUTATION_FILE)) {
			return NTFS_UNSUPPORTED;
		}
		unknown = home->slots & projection->unknown_slots;
		if (unknown == 0) {
			continue;
		}
		if (owner->compensated && (home->new_slots & unknown) == unknown &&
		    (home->old_slots & unknown) == 0) {
			/* A fully compensated initializer published no metadata. Its
			 * original free state is the same state consumed by the later
			 * initializer, whose generation must agree. Unknown free bytes
			 * remain unknown while walking further backwards. */
			for (slot = 0; slot < NTFS_BATCH_RECOVERY_FILE_SLOTS; slot++) {
				if ((unknown & (1u << slot)) == 0) {
					continue;
				}
				after =
				    (const void *)(home->after + slot * NTFS_WRITE_RECORD_BYTES);
				if (ntfs_u16(after->sequence) != projection->next_sequence[slot]) {
					return NTFS_STALE;
				}
			}
			continue;
		}
		if (!owner->committed || (home->old_slots & unknown) != unknown ||
		    (home->new_slots & unknown) != 0) {
			return NTFS_UNSUPPORTED;
		}
		for (slot = 0; slot < NTFS_BATCH_RECOVERY_FILE_SLOTS; slot++) {
			if ((unknown & (1u << slot)) == 0) {
				continue;
			}
			offset = slot * NTFS_WRITE_RECORD_BYTES;
			before = (const void *)(home->before + offset);
			after = (const void *)(home->after + offset);
			sequence = (uint16_t)(ntfs_u16(before->sequence) + 1u);
			if (sequence == 0) {
				sequence = 1;
			}
			if ((ntfs_u16(before->flags) & NTFS_RECORD_IN_USE) == 0 ||
			    ntfs_u16(after->flags) != 0 || ntfs_u16(after->sequence) != sequence ||
			    sequence != projection->next_sequence[slot]) {
				return NTFS_STALE;
			}
		}
		home->historical_free_slots |= unknown;
	}
	return NTFS_OK;
}

static enum ntfs_result
recovery_projection_append(
    struct ntfs_write_batch_recovery *owner, const struct ntfs_write_batch_recovery *source)
{
	struct ntfs_batch_recovery_projection *entries, *projection;
	const struct ntfs_batch_recovery_home *home;
	const struct ntfs_disk_record *initialized;
	size_t index, other, capacity, slot;

	for (index = 0; index < source->homes; index++) {
		home = &source->home[index];
		for (other = 0; other < owner->projections; other++) {
			if (owner->projection[other].physical == home->physical) {
				break;
			}
		}
		if (other == owner->projections) {
			if (owner->projections == NTFS_WRITE_BATCH_MAX_PACKETS) {
				return NTFS_RANGE;
			}
			if (owner->projections == owner->projection_capacity) {
				capacity = owner->projection_capacity == 0
				    ? NTFS_BATCH_RECOVERY_INITIAL_PACKETS
				    : owner->projection_capacity * NTFS_VECTOR_GROWTH;
				if (capacity > NTFS_WRITE_BATCH_MAX_PACKETS) {
					capacity = NTFS_WRITE_BATCH_MAX_PACKETS;
				}
				entries = ntfs_batch_recovery_allocate(
				    owner, capacity * sizeof(*entries));
				if (entries == NULL) {
					return NTFS_NO_MEMORY;
				}
				ntfs_copy(entries, owner->projection,
				    owner->projections * sizeof(*entries));
				ntfs_batch_recovery_release(owner, owner->projection,
				    owner->projection_capacity * sizeof(*entries));
				owner->projection = entries;
				owner->projection_capacity = capacity;
			}
			owner->projections++;
		}
		projection = &owner->projection[other];
		projection->physical = home->physical;
		ntfs_copy(projection->before, home->before, sizeof(projection->before));
		projection->unknown_slots &= (uint8_t)~home->historical_free_slots;
		if (source->committed) {
			if ((home->new_slots & home->slots) != home->new_slots) {
				return NTFS_CORRUPT;
			}
			projection->unknown_slots |= home->new_slots;
			for (slot = 0; slot < NTFS_BATCH_RECOVERY_FILE_SLOTS; slot++) {
				if ((home->new_slots & (1u << slot)) != 0) {
					initialized = (const void *)(home->after +
					    slot * NTFS_WRITE_RECORD_BYTES);
					projection->next_sequence[slot] =
					    ntfs_u16(initialized->sequence);
				} else if ((home->historical_free_slots & (1u << slot)) != 0) {
					projection->next_sequence[slot] = 0;
				}
			}
			projection->unknown_index |=
			    home->kind == NTFS_WRITE_MUTATION_INDEX && !home->old_index;
			projection->unowned_cluster |= home->unowned_cluster;
		}
	}
	return NTFS_OK;
}

static enum ntfs_result
recovery_prior_lifetime(struct ntfs_write_batch_recovery *owner,
    const struct ntfs_batch_recovery_lifetime *lifetime, struct ntfs_batch_recovery_workspace *work)
{
	struct ntfs_write_batch_recovery *prior;
	enum ntfs_result result;

	if (lifetime->updates != 0 && !lifetime->committed && !lifetime->compensated) {
		return NTFS_BUSY;
	}
	prior = ntfs_batch_recovery_allocate(owner, sizeof(*prior));
	if (prior == NULL) {
		return NTFS_NO_MEMORY;
	}
	/* This source is an explicit private historical projection, not fabricated
	 * crash media or a shortened physical endpoint. All actual I/O and memory
	 * continue through the root owner's aggregate governors. */
	prior->backend = owner->backend;
	prior->backend.reader = owner->reader;
	prior->reader = (struct ntfs_environment){NTFS_API_VERSION, prior, owner->reader.size_bytes,
	    ntfs_batch_recovery_overlay_read, ntfs_batch_recovery_allocate,
	    ntfs_batch_recovery_release};
	prior->info = owner->info;
	prior->mft_lcn = owner->mft_lcn;
	prior->mirror_lcn = owner->mirror_lcn;
	prior->selected = owner->selected;
	prior->origin = owner->origin;
	prior->client = owner->client;
	prior->history = owner->history;
	prior->packet = owner->packet;
	prior->packets = owner->packets;
	prior->ordinary_first = NTFS_BATCH_RECOVERY_ORIGIN_PACKETS;
	prior->history_owner = owner;
	prior->historical = true;
	ntfs_batch_recovery_lifetime_select(prior, lifetime);
	result = ntfs_batch_recovery_restore(prior, work);
	if (result == NTFS_OK) {
		result = recovery_projection_append(owner, prior);
	}
	/* Packet and target arrays are borrowed from the complete owning history.
	 * Only this lifetime's metadata workspace belongs to the private child. */
	ntfs_batch_recovery_release(
	    prior, prior->home, prior->home_capacity * sizeof(*prior->home));
	ntfs_batch_recovery_release(owner, prior, sizeof(*prior));
	return result;
}

enum ntfs_result
ntfs_batch_recovery_restore_history(
    struct ntfs_write_batch_recovery *owner, struct ntfs_batch_recovery_workspace *work)
{
	struct ntfs_volume *volume = NULL;
	struct ntfs_limits limits;
	size_t lifetime;
	enum ntfs_result result;

	if (owner->lifetimes <= 1) {
		return NTFS_OK;
	}
	result = recovery_projection_append(owner, owner);
	if (result != NTFS_OK) {
		return result;
	}
	owner->view = NTFS_BATCH_RECOVERY_HISTORY;
	for (lifetime = owner->lifetimes - 1; lifetime > 0; lifetime--) {
		result = recovery_prior_lifetime(owner, &owner->lifetime[lifetime - 1], work);
		if (result != NTFS_OK) {
			goto done;
		}
	}
	ntfs_default_limits(&limits);
	limits.record_cache_entries = 0;
	result = ntfs_mount(&owner->reader, &limits, &volume);
	if (result == NTFS_OK) {
		result = ntfs_batch_recovery_qualified_validate(owner, volume, work);
	}
done:
	if (volume != NULL) {
		ntfs_unmount(volume);
	}
	owner->view = NTFS_BATCH_RECOVERY_SOURCE;
	ntfs_batch_recovery_release(
	    owner, owner->projection, owner->projection_capacity * sizeof(*owner->projection));
	owner->projection = NULL;
	owner->projections = owner->projection_capacity = 0;
	return result;
}
