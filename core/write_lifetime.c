/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_lifetime.h"
#include "internal.h"
#include "pointer_range.h"

struct lifetime_object {
	uint64_t reference;
	uint32_t names;
	size_t opens, mappings;
	enum ntfs_write_lifetime_state state;
	bool used, pending;
};

struct lifetime_pending {
	struct ntfs_write_lifetime_ticket ticket;
	size_t source, victim;
	bool started;
};

/* A common slot supplies the alignment of each table without unchecked padding
 * arithmetic or allocations after construction. Each table has one member type. */
union lifetime_slot {
	struct lifetime_object object;
	struct ntfs_write_lifetime_token lease;
	struct lifetime_pending pending;
};

struct ntfs_write_lifetime {
	struct ntfs_environment environment;
	struct ntfs_write_lifetime_limits limits;
	uint64_t epoch, issued;
	size_t allocation;
	bool draining, poisoned;
	union lifetime_slot storage[];
};

static struct lifetime_object *
lifetime_object(struct ntfs_write_lifetime *owner, size_t index)
{
	return &owner->storage[index].object;
}

static const struct lifetime_object *
lifetime_object_const(const struct ntfs_write_lifetime *owner, size_t index)
{
	return &owner->storage[index].object;
}

static struct ntfs_write_lifetime_token *
lifetime_lease(struct ntfs_write_lifetime *owner, size_t index)
{
	return &owner->storage[owner->limits.objects + index].lease;
}

static const struct ntfs_write_lifetime_token *
lifetime_lease_const(const struct ntfs_write_lifetime *owner, size_t index)
{
	return &owner->storage[owner->limits.objects + index].lease;
}

static struct lifetime_pending *
lifetime_pending(struct ntfs_write_lifetime *owner, size_t index)
{
	return &owner->storage[owner->limits.objects + owner->limits.leases + index].pending;
}

static bool
lifetime_output(const struct ntfs_write_lifetime *owner, const void *out, size_t bytes)
{
	return owner != NULL && out != NULL &&
	    ntfs_pointer_ranges_separate(owner, owner->allocation, out, bytes);
}

static enum ntfs_result
lifetime_admit(const struct ntfs_write_lifetime *owner)
{
	if (owner == NULL) {
		return NTFS_INVALID;
	}
	return owner->poisoned ? NTFS_IO : owner->draining ? NTFS_STALE : NTFS_OK;
}

static enum ntfs_result
lifetime_find(const struct ntfs_write_lifetime *owner, uint64_t reference, size_t *slot)
{
	const struct lifetime_object *object;
	size_t index;

	for (index = 0; index < owner->limits.objects; index++) {
		object = lifetime_object_const(owner, index);
		if (object->used && (object->reference & NTFS_REFERENCE_RECORD_MASK) ==
		    (reference & NTFS_REFERENCE_RECORD_MASK)) {
			if (object->reference != reference) {
				return NTFS_STALE;
			}
			*slot = index;
			return NTFS_OK;
		}
	}
	return NTFS_NOT_FOUND;
}

static bool
lifetime_kind(enum ntfs_write_lifetime_kind kind)
{
	return kind == NTFS_WRITE_LIFETIME_OPEN || kind == NTFS_WRITE_LIFETIME_MAPPING;
}

static enum ntfs_result
lifetime_token(const struct ntfs_write_lifetime *owner, struct ntfs_write_lifetime_token token,
    size_t *slot)
{
	const struct ntfs_write_lifetime_token *held;
	size_t index;

	if (owner == NULL) {
		return NTFS_INVALID;
	}
	if (token.owner != owner || token.epoch != owner->epoch || token.serial == 0) {
		return NTFS_STALE;
	}
	for (index = 0; index < owner->limits.leases; index++) {
		held = lifetime_lease_const(owner, index);
		if (held->serial == token.serial && held->reference == token.reference &&
		    held->kind == token.kind) {
			*slot = index;
			return NTFS_OK;
		}
	}
	return NTFS_STALE;
}

static enum ntfs_result
lifetime_ticket(struct ntfs_write_lifetime *owner, struct ntfs_write_lifetime_ticket ticket,
    struct lifetime_pending **out)
{
	struct lifetime_pending *pending;
	size_t index;

	if (owner == NULL) {
		return NTFS_INVALID;
	}
	if (ticket.owner != owner || ticket.epoch != owner->epoch || ticket.serial == 0) {
		return NTFS_STALE;
	}
	for (index = 0; index < owner->limits.pending; index++) {
		pending = lifetime_pending(owner, index);
		if (pending->ticket.serial == ticket.serial &&
		    pending->ticket.source == ticket.source &&
		    pending->ticket.victim == ticket.victim &&
		    pending->ticket.operation == ticket.operation) {
			*out = pending;
			return NTFS_OK;
		}
	}
	return NTFS_STALE;
}

enum ntfs_result
ntfs_write_lifetime_create(const struct ntfs_environment *environment, uint64_t epoch,
    const struct ntfs_write_lifetime_limits *limits, struct ntfs_write_lifetime **out)
{
	struct ntfs_write_lifetime *owner;
	size_t slots, allocation;

	if (environment == NULL || limits == NULL || out == NULL ||
	    !ntfs_pointer_ranges_separate(environment, sizeof(*environment), out, sizeof(*out)) ||
	    !ntfs_pointer_ranges_separate(limits, sizeof(*limits), out, sizeof(*out))) {
		return NTFS_INVALID;
	}
	*out = NULL;
	if (environment->api_version != NTFS_API_VERSION || environment->allocate == NULL ||
	    environment->release == NULL || epoch == 0) {
		return NTFS_INVALID;
	}
	if (limits->objects == 0 || limits->objects > NTFS_WRITE_LIFETIME_MAX_OBJECTS ||
	    limits->leases == 0 || limits->leases > NTFS_WRITE_LIFETIME_MAX_LEASES ||
	    limits->pending == 0 || limits->pending > NTFS_WRITE_LIFETIME_MAX_PENDING ||
	    limits->issued == 0) {
		return NTFS_RANGE;
	}
	slots = limits->objects + limits->leases + limits->pending;
	if (slots > (SIZE_MAX - sizeof(*owner)) / sizeof(*owner->storage)) {
		return NTFS_RANGE;
	}
	allocation = sizeof(*owner) + slots * sizeof(*owner->storage);
	owner = environment->allocate(environment->context, allocation);
	if (owner == NULL) {
		return NTFS_NO_MEMORY;
	}
	ntfs_zero(owner, allocation);
	owner->environment = *environment;
	owner->limits = *limits;
	owner->epoch = epoch;
	owner->allocation = allocation;
	*out = owner;
	return NTFS_OK;
}

enum ntfs_result
ntfs_write_lifetime_track(struct ntfs_write_lifetime *owner, uint64_t reference, uint32_t names)
{
	struct lifetime_object *object;
	size_t index, empty;
	uint64_t sequence = reference >> NTFS_REFERENCE_SEQUENCE_SHIFT;
	enum ntfs_result result = lifetime_admit(owner);

	if (result != NTFS_OK) {
		return result;
	}
	if (sequence == 0 || (reference & NTFS_REFERENCE_RECORD_MASK) < NTFS_FIRST_USER_RECORD ||
	    names == 0) {
		return NTFS_INVALID;
	}
	empty = owner->limits.objects;
	for (index = 0; index < owner->limits.objects; index++) {
		object = lifetime_object(owner, index);
		if (!object->used) {
			if (empty == owner->limits.objects) {
				empty = index;
			}
			continue;
		}
		if ((object->reference & NTFS_REFERENCE_RECORD_MASK) !=
		    (reference & NTFS_REFERENCE_RECORD_MASK)) {
			continue;
		}
		if (object->state != NTFS_WRITE_LIFETIME_RETIRED) {
			return object->reference == reference ? NTFS_EXISTS : NTFS_STALE;
		}
		if ((object->reference >> NTFS_REFERENCE_SEQUENCE_SHIFT) == UINT16_MAX) {
			return NTFS_UNSUPPORTED;
		}
		if (sequence != (object->reference >> NTFS_REFERENCE_SEQUENCE_SHIFT) + 1u) {
			return NTFS_STALE;
		}
		empty = index;
		break;
	}
	if (empty == owner->limits.objects) {
		return NTFS_NO_SPACE;
	}
	object = lifetime_object(owner, empty);
	*object = (struct lifetime_object){.reference = reference,
	    .names = names, .state = NTFS_WRITE_LIFETIME_ATTACHED, .used = true};
	return NTFS_OK;
}

static enum ntfs_result
lifetime_issue(struct ntfs_write_lifetime *owner, size_t slot, enum ntfs_write_lifetime_kind kind,
    struct ntfs_write_lifetime_token *out)
{
	struct lifetime_object *object = lifetime_object(owner, slot);
	struct ntfs_write_lifetime_token *lease;
	size_t index;

	if (object->pending) {
		return NTFS_BUSY;
	}
	if (owner->issued == owner->limits.issued) {
		return NTFS_RANGE;
	}
	for (index = 0; index < owner->limits.leases; index++) {
		lease = lifetime_lease(owner, index);
		if (lease->serial != 0) {
			continue;
		}
		*lease = (struct ntfs_write_lifetime_token){owner, owner->epoch, ++owner->issued,
		    object->reference, kind};
		if (kind == NTFS_WRITE_LIFETIME_OPEN) {
			object->opens++;
		} else {
			object->mappings++;
		}
		*out = *lease;
		return NTFS_OK;
	}
	return NTFS_NO_SPACE;
}

enum ntfs_result
ntfs_write_lifetime_acquire(struct ntfs_write_lifetime *owner, uint64_t reference,
    enum ntfs_write_lifetime_kind kind, struct ntfs_write_lifetime_token *out)
{
	size_t slot;
	enum ntfs_result result;

	if (!lifetime_output(owner, out, sizeof(*out)) || !lifetime_kind(kind)) {
		return NTFS_INVALID;
	}
	result = lifetime_admit(owner);
	if (result == NTFS_OK) {
		result = lifetime_find(owner, reference, &slot);
	}
	if (result != NTFS_OK) {
		return result;
	}
	if (lifetime_object(owner, slot)->state != NTFS_WRITE_LIFETIME_ATTACHED) {
		return NTFS_NOT_FOUND;
	}
	return lifetime_issue(owner, slot, kind, out);
}

enum ntfs_result
ntfs_write_lifetime_retain(struct ntfs_write_lifetime *owner, struct ntfs_write_lifetime_token token,
    enum ntfs_write_lifetime_kind kind, struct ntfs_write_lifetime_token *out)
{
	size_t lease, slot;
	enum ntfs_result result;

	if (!lifetime_output(owner, out, sizeof(*out)) || !lifetime_kind(kind)) {
		return NTFS_INVALID;
	}
	result = lifetime_admit(owner);
	if (result == NTFS_OK) {
		result = lifetime_token(owner, token, &lease);
	}
	if (result == NTFS_OK) {
		result = lifetime_find(owner, token.reference, &slot);
	}
	if (result != NTFS_OK) {
		return result;
	}
	return lifetime_issue(owner, slot, kind, out);
}

enum ntfs_result
ntfs_write_lifetime_access(const struct ntfs_write_lifetime *owner,
    struct ntfs_write_lifetime_token token)
{
	size_t lease, slot;
	enum ntfs_result result = lifetime_admit(owner);

	if (result == NTFS_OK) {
		result = lifetime_token(owner, token, &lease);
	}
	if (result == NTFS_OK) {
		result = lifetime_find(owner, token.reference, &slot);
	}
	if (result != NTFS_OK) {
		return result;
	}
	return lifetime_object_const(owner, slot)->pending ? NTFS_BUSY : NTFS_OK;
}

enum ntfs_result
ntfs_write_lifetime_release(struct ntfs_write_lifetime *owner, struct ntfs_write_lifetime_token token)
{
	struct lifetime_object *object;
	size_t lease, slot;
	enum ntfs_result result = lifetime_token(owner, token, &lease);

	if (result == NTFS_OK) {
		result = lifetime_find(owner, token.reference, &slot);
	}
	if (result != NTFS_OK) {
		return result;
	}
	object = lifetime_object(owner, slot);
	if (token.kind == NTFS_WRITE_LIFETIME_OPEN) {
		object->opens--;
	} else {
		object->mappings--;
	}
	ntfs_zero(lifetime_lease(owner, lease), sizeof(*lifetime_lease(owner, lease)));
	return NTFS_OK;
}

enum ntfs_result
ntfs_write_lifetime_inspect(const struct ntfs_write_lifetime *owner, uint64_t reference,
    struct ntfs_write_lifetime_view *out)
{
	const struct lifetime_object *object;
	size_t slot;
	enum ntfs_result result;

	if (!lifetime_output(owner, out, sizeof(*out))) {
		return NTFS_INVALID;
	}
	result = lifetime_find(owner, reference, &slot);
	if (result != NTFS_OK) {
		return result;
	}
	object = lifetime_object_const(owner, slot);
	*out = (struct ntfs_write_lifetime_view){.state = object->state,
	    .names = object->names, .opens = object->opens, .mappings = object->mappings,
	    .pending = object->pending,
	    .eligible = object->state == NTFS_WRITE_LIFETIME_DETACHED && object->opens == 0 &&
		object->mappings == 0 && !object->pending && !owner->draining && !owner->poisoned,
	    .draining = owner->draining, .poisoned = owner->poisoned};
	return NTFS_OK;
}

enum ntfs_result
ntfs_write_lifetime_prepare(struct ntfs_write_lifetime *owner,
    enum ntfs_write_lifetime_operation operation, uint64_t source, uint64_t victim,
    struct ntfs_write_lifetime_ticket *out)
{
	struct lifetime_object *object, *other = NULL;
	struct lifetime_pending *pending;
	size_t slot, source_slot = 0, index;
	enum ntfs_result result;

	if (!lifetime_output(owner, out, sizeof(*out))) {
		return NTFS_INVALID;
	}
	if (operation != NTFS_WRITE_LIFETIME_UNLINK && operation != NTFS_WRITE_LIFETIME_REPLACE &&
	    operation != NTFS_WRITE_LIFETIME_RETIRE) {
		return NTFS_INVALID;
	}
	if ((operation == NTFS_WRITE_LIFETIME_REPLACE && source == victim) ||
	    (operation != NTFS_WRITE_LIFETIME_REPLACE && source != 0)) {
		return NTFS_INVALID;
	}
	result = lifetime_admit(owner);
	if (result == NTFS_OK) {
		result = lifetime_find(owner, victim, &slot);
	}
	if (result == NTFS_OK && operation == NTFS_WRITE_LIFETIME_REPLACE) {
		result = lifetime_find(owner, source, &source_slot);
		if (result == NTFS_OK) {
			other = lifetime_object(owner, source_slot);
		}
	}
	if (result != NTFS_OK) {
		return result;
	}
	object = lifetime_object(owner, slot);
	if (object->pending || (other != NULL && other->pending)) {
		return NTFS_BUSY;
	}
	if (operation == NTFS_WRITE_LIFETIME_RETIRE) {
		if (object->state != NTFS_WRITE_LIFETIME_DETACHED || object->opens != 0 ||
		    object->mappings != 0) {
			return NTFS_BUSY;
		}
	} else if (object->state != NTFS_WRITE_LIFETIME_ATTACHED ||
	    (other != NULL && other->state != NTFS_WRITE_LIFETIME_ATTACHED)) {
		return NTFS_NOT_FOUND;
	}
	if (owner->issued == owner->limits.issued) {
		return NTFS_RANGE;
	}
	for (index = 0; index < owner->limits.pending; index++) {
		pending = lifetime_pending(owner, index);
		if (pending->ticket.serial != 0) {
			continue;
		}
		pending->ticket = (struct ntfs_write_lifetime_ticket){owner, owner->epoch,
		    ++owner->issued, source, victim, operation};
		pending->source = source_slot;
		pending->victim = slot;
		pending->started = false;
		object->pending = true;
		if (other != NULL) {
			other->pending = true;
		}
		*out = pending->ticket;
		return NTFS_OK;
	}
	return NTFS_NO_SPACE;
}

enum ntfs_result
ntfs_write_lifetime_start(struct ntfs_write_lifetime *owner, struct ntfs_write_lifetime_ticket ticket)
{
	struct lifetime_pending *pending;
	enum ntfs_result result = lifetime_admit(owner);

	if (result == NTFS_OK) {
		result = lifetime_ticket(owner, ticket, &pending);
	}
	if (result != NTFS_OK) {
		return result;
	}
	if (pending->started) {
		return NTFS_BUSY;
	}
	pending->started = true;
	return NTFS_OK;
}

enum ntfs_result
ntfs_write_lifetime_finish(struct ntfs_write_lifetime *owner, struct ntfs_write_lifetime_ticket ticket,
    enum ntfs_write_lifetime_outcome outcome)
{
	struct lifetime_pending *pending;
	struct lifetime_object *object;
	enum ntfs_result result;

	if (outcome != NTFS_WRITE_LIFETIME_ABORTED && outcome != NTFS_WRITE_LIFETIME_COMMITTED &&
	    outcome != NTFS_WRITE_LIFETIME_UNCERTAIN) {
		return NTFS_INVALID;
	}
	result = lifetime_ticket(owner, ticket, &pending);
	if (result != NTFS_OK) {
		return result;
	}
	if (!pending->started && outcome != NTFS_WRITE_LIFETIME_ABORTED) {
		return NTFS_INVALID;
	}
	object = lifetime_object(owner, pending->victim);
	if (outcome == NTFS_WRITE_LIFETIME_COMMITTED) {
		if (ticket.operation == NTFS_WRITE_LIFETIME_RETIRE) {
			object->state = NTFS_WRITE_LIFETIME_RETIRED;
		} else {
			object->names--;
			if (object->names == 0) {
				object->state = NTFS_WRITE_LIFETIME_DETACHED;
			}
		}
	} else if (outcome == NTFS_WRITE_LIFETIME_UNCERTAIN) {
		owner->poisoned = true;
	}
	object->pending = false;
	if (ticket.operation == NTFS_WRITE_LIFETIME_REPLACE) {
		lifetime_object(owner, pending->source)->pending = false;
	}
	ntfs_zero(pending, sizeof(*pending));
	return NTFS_OK;
}

void
ntfs_write_lifetime_drain(struct ntfs_write_lifetime *owner)
{
	if (owner != NULL) {
		owner->draining = true;
	}
}

void
ntfs_write_lifetime_poison(struct ntfs_write_lifetime *owner)
{
	if (owner != NULL) {
		owner->poisoned = true;
	}
}

enum ntfs_result
ntfs_write_lifetime_close(struct ntfs_write_lifetime *owner)
{
	struct ntfs_environment environment;
	size_t index, allocation;

	if (owner == NULL) {
		return NTFS_OK;
	}
	if (!owner->draining && !owner->poisoned) {
		return NTFS_BUSY;
	}
	for (index = 0; index < owner->limits.leases; index++) {
		if (lifetime_lease(owner, index)->serial != 0) {
			return NTFS_BUSY;
		}
	}
	for (index = 0; index < owner->limits.pending; index++) {
		if (lifetime_pending(owner, index)->ticket.serial != 0) {
			return NTFS_BUSY;
		}
	}
	environment = owner->environment;
	allocation = owner->allocation;
	environment.release(environment.context, owner, allocation);
	return NTFS_OK;
}
