/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "write_lifetime.h"
#include "fuzz_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_SOURCE_RECORD = 24,
	TEST_VICTIM_RECORD = 25,
	TEST_OTHER_RECORD = 26,
	TEST_NAMES = 4,
	TEST_TOKENS = 16,
	TEST_OBJECTS = 3,
	TEST_EPOCH = 7,
	TEST_SERIAL_BUDGET = 1000
};

struct oracle {
	struct fuzz_device device;
	struct ntfs_write_lifetime *owner;
	uint64_t names[TEST_NAMES], objects[TEST_OBJECTS];
	bool allocated[TEST_OBJECTS], pending[TEST_OBJECTS], draining, poisoned;
	struct ntfs_write_lifetime_token tokens[TEST_TOKENS];
};

static size_t assertions, scenarios;

static uint64_t
reference(uint64_t record, uint16_t sequence)
{
	return record | (uint64_t)sequence << NTFS_REFERENCE_SEQUENCE_SHIFT;
}

static void
oracle_check(struct oracle *oracle)
{
	struct ntfs_write_lifetime_view view;
	size_t object, name, held, opens, mappings;
	uint32_t names;
	enum ntfs_write_lifetime_state state;

	for (object = 0; object < TEST_OBJECTS; object++) {
		if (oracle->objects[object] == 0) {
			continue;
		}
		names = 0;
		opens = 0;
		mappings = 0;
		/* Independent reachability oracle: reconstruct both counts from actual
		 * named edges and a set of live value tokens, never from C counters. */
		for (name = 0; name < TEST_NAMES; name++) {
			if (oracle->names[name] == oracle->objects[object]) {
				names++;
			}
		}
		for (held = 0; held < TEST_TOKENS; held++) {
			if (oracle->tokens[held].serial == 0 ||
			    oracle->tokens[held].reference != oracle->objects[object]) {
				continue;
			}
			if (oracle->tokens[held].kind == NTFS_WRITE_LIFETIME_OPEN) {
				opens++;
			} else {
				mappings++;
			}
		}
		state = !oracle->allocated[object] ? NTFS_WRITE_LIFETIME_RETIRED
		    : names != 0		   ? NTFS_WRITE_LIFETIME_ATTACHED
						   : NTFS_WRITE_LIFETIME_DETACHED;
		assert(ntfs_write_lifetime_inspect(oracle->owner, oracle->objects[object], &view) ==
		    NTFS_OK);
		assert(view.state == state && view.names == names && view.opens == opens &&
		    view.mappings == mappings && view.pending == oracle->pending[object]);
		assert(view.draining == oracle->draining && view.poisoned == oracle->poisoned);
		assert(view.eligible ==
		    (oracle->allocated[object] && names == 0 && opens == 0 && mappings == 0 &&
			!oracle->pending[object] && !oracle->draining && !oracle->poisoned));
		assert(oracle->allocated[object] || (names == 0 && opens == 0 && mappings == 0));
		assertions++;
	}
	assert(oracle->device.allocations == 1 && oracle->device.reads == 0);
}

static void
oracle_open(struct oracle *oracle, size_t source_names, size_t victim_names)
{
	struct ntfs_environment environment = fuzz_environment(&oracle->device);
	const struct ntfs_write_lifetime_limits limits = {
	    TEST_OBJECTS, TEST_TOKENS, TEST_OBJECTS, TEST_SERIAL_BUDGET};

	environment.read = NULL;
	assert(ntfs_write_lifetime_create(&environment, TEST_EPOCH, &limits, &oracle->owner) ==
	    NTFS_OK);
	oracle->objects[0] = reference(TEST_SOURCE_RECORD, 1);
	oracle->objects[1] = reference(TEST_VICTIM_RECORD, 1);
	oracle->allocated[0] = true;
	oracle->allocated[1] = true;
	oracle->names[0] = oracle->objects[0];
	oracle->names[1] = source_names == 2 ? oracle->objects[0] : 0;
	oracle->names[2] = oracle->objects[1];
	oracle->names[3] = victim_names == 2 ? oracle->objects[1] : 0;
	assert(ntfs_write_lifetime_track(
		   oracle->owner, oracle->objects[0], (uint32_t)source_names) == NTFS_OK);
	assert(ntfs_write_lifetime_track(
		   oracle->owner, oracle->objects[1], (uint32_t)victim_names) == NTFS_OK);
	oracle_check(oracle);
}

static void
oracle_acquire(
    struct oracle *oracle, size_t slot, size_t object, enum ntfs_write_lifetime_kind kind)
{
	assert(oracle->tokens[slot].serial == 0);
	assert(ntfs_write_lifetime_acquire(
		   oracle->owner, oracle->objects[object], kind, &oracle->tokens[slot]) == NTFS_OK);
	assert(oracle->tokens[slot].reference == oracle->objects[object]);
	oracle_check(oracle);
}

static void
oracle_release(struct oracle *oracle, size_t slot)
{
	struct ntfs_write_lifetime_token old = oracle->tokens[slot];

	assert(old.serial != 0);
	assert(ntfs_write_lifetime_release(oracle->owner, old) == NTFS_OK);
	memset(&oracle->tokens[slot], 0, sizeof(oracle->tokens[slot]));
	oracle_check(oracle);
	assert(ntfs_write_lifetime_release(oracle->owner, old) == NTFS_STALE);
	oracle_check(oracle);
}

static void
oracle_close(struct oracle *oracle)
{
	size_t index;

	ntfs_write_lifetime_drain(oracle->owner);
	ntfs_write_lifetime_drain(oracle->owner);
	oracle->draining = true;
	oracle_check(oracle);
	for (index = 0; index < TEST_TOKENS; index++) {
		if (oracle->tokens[index].serial != 0) {
			assert(ntfs_write_lifetime_close(oracle->owner) == NTFS_BUSY);
			oracle_release(oracle, index);
		}
	}
	assert(ntfs_write_lifetime_close(oracle->owner) == NTFS_OK);
	assert(oracle->device.memory == 0 && oracle->device.reads == 0);
	scenarios++;
}

static void
oracle_remove_last(struct oracle *oracle, size_t name, size_t object)
{
	struct ntfs_write_lifetime_ticket ticket;

	assert(ntfs_write_lifetime_prepare(oracle->owner, NTFS_WRITE_LIFETIME_UNLINK, 0,
		   oracle->objects[object], &ticket) == NTFS_OK);
	oracle->pending[object] = true;
	oracle_check(oracle);
	assert(ntfs_write_lifetime_start(oracle->owner, ticket) == NTFS_OK);
	assert(ntfs_write_lifetime_finish(oracle->owner, ticket, NTFS_WRITE_LIFETIME_COMMITTED) ==
	    NTFS_OK);
	oracle->names[name] = 0;
	oracle->pending[object] = false;
	oracle_check(oracle);
}

static void
retire_and_reuse(struct oracle *oracle)
{
	struct ntfs_write_lifetime_ticket ticket;
	struct ntfs_write_lifetime_token absent = {0};
	struct ntfs_write_lifetime_view before, after;
	uint64_t old = oracle->objects[1], next = reference(TEST_VICTIM_RECORD, 2);
	size_t name;

	assert(ntfs_write_lifetime_acquire(oracle->owner, old, NTFS_WRITE_LIFETIME_OPEN, &absent) ==
	    NTFS_NOT_FOUND);
	assert(absent.serial == 0);
	assert(ntfs_write_lifetime_track(oracle->owner, next, 1) == NTFS_STALE);
	assert(ntfs_write_lifetime_inspect(oracle->owner, old, &before) == NTFS_OK);
	assert(before.eligible);
	assert(ntfs_write_lifetime_prepare(
		   oracle->owner, NTFS_WRITE_LIFETIME_RETIRE, 0, old, &ticket) == NTFS_OK);
	oracle->pending[1] = true;
	oracle_check(oracle);
	assert(ntfs_write_lifetime_finish(oracle->owner, ticket, NTFS_WRITE_LIFETIME_ABORTED) ==
	    NTFS_OK);
	oracle->pending[1] = false;
	oracle_check(oracle);
	assert(ntfs_write_lifetime_inspect(oracle->owner, old, &after) == NTFS_OK);
	assert(after.eligible && after.state == before.state && after.names == before.names);
	assert(ntfs_write_lifetime_prepare(
		   oracle->owner, NTFS_WRITE_LIFETIME_RETIRE, 0, old, &ticket) == NTFS_OK);
	oracle->pending[1] = true;
	assert(ntfs_write_lifetime_start(oracle->owner, ticket) == NTFS_OK);
	assert(ntfs_write_lifetime_track(oracle->owner, next, 1) == NTFS_STALE);
	assert(ntfs_write_lifetime_finish(oracle->owner, ticket, NTFS_WRITE_LIFETIME_COMMITTED) ==
	    NTFS_OK);
	oracle->pending[1] = false;
	oracle->allocated[1] = false;
	oracle_check(oracle);
	assert(ntfs_write_lifetime_track(oracle->owner, old, 1) == NTFS_STALE);
	assert(ntfs_write_lifetime_track(oracle->owner, reference(TEST_VICTIM_RECORD, 3), 1) ==
	    NTFS_STALE);
	assert(ntfs_write_lifetime_track(oracle->owner, next, 1) == NTFS_OK);
	oracle->objects[1] = next;
	for (name = 0; name < TEST_NAMES; name++) {
		if (oracle->names[name] == 0) {
			break;
		}
	}
	assert(name < TEST_NAMES);
	oracle->names[name] = next;
	oracle->allocated[1] = true;
	oracle_check(oracle);
	assert(ntfs_write_lifetime_inspect(oracle->owner, old, &after) == NTFS_STALE);
	assert(ntfs_write_lifetime_acquire(oracle->owner, old, NTFS_WRITE_LIFETIME_OPEN, &absent) ==
	    NTFS_STALE);
	assert(ntfs_write_lifetime_finish(oracle->owner, ticket, NTFS_WRITE_LIFETIME_COMMITTED) ==
	    NTFS_STALE);
	oracle_acquire(oracle, TEST_TOKENS - 1, 1, NTFS_WRITE_LIFETIME_MAPPING);
}

static void
lifecycle_case(size_t source_names, size_t victim_names, size_t opens, size_t mappings,
    bool replace, enum ntfs_write_lifetime_outcome outcome, size_t drain_phase, bool release_early)
{
	struct oracle oracle = {0};
	struct ntfs_write_lifetime_ticket ticket, sentinel = {0};
	struct ntfs_write_lifetime_token token = {0}, stale = {0};
	size_t index, first = 1, held = opens + mappings;
	uint64_t source, victim;
	enum ntfs_result closed;

	oracle_open(&oracle, source_names, victim_names);
	source = oracle.objects[0];
	victim = oracle.objects[1];
	oracle_acquire(&oracle, 0, 0, NTFS_WRITE_LIFETIME_OPEN);
	for (index = 0; index < held; index++) {
		oracle_acquire(&oracle, index + first, 1,
		    index < opens ? NTFS_WRITE_LIFETIME_OPEN : NTFS_WRITE_LIFETIME_MAPPING);
	}
	assert(ntfs_write_lifetime_prepare(oracle.owner,
		   replace ? NTFS_WRITE_LIFETIME_REPLACE : NTFS_WRITE_LIFETIME_UNLINK,
		   replace ? source : 0, victim, &ticket) == NTFS_OK);
	oracle.pending[0] = replace;
	oracle.pending[1] = true;
	oracle_check(&oracle);
	assert(ntfs_write_lifetime_finish(oracle.owner, ticket, NTFS_WRITE_LIFETIME_COMMITTED) ==
	    NTFS_INVALID);
	assert(ntfs_write_lifetime_finish(oracle.owner, ticket, NTFS_WRITE_LIFETIME_UNCERTAIN) ==
	    NTFS_INVALID);
	assert(ntfs_write_lifetime_prepare(
		   oracle.owner, NTFS_WRITE_LIFETIME_RETIRE, 0, victim, &sentinel) == NTFS_BUSY);
	assert(sentinel.serial == 0);
	assert(ntfs_write_lifetime_acquire(
		   oracle.owner, victim, NTFS_WRITE_LIFETIME_OPEN, &token) == NTFS_BUSY);
	assert(token.serial == 0);
	assert(ntfs_write_lifetime_access(oracle.owner, oracle.tokens[0]) ==
	    (replace ? NTFS_BUSY : NTFS_OK));
	if (held != 0) {
		stale = oracle.tokens[first];
		assert(ntfs_write_lifetime_retain(oracle.owner, oracle.tokens[first],
			   NTFS_WRITE_LIFETIME_MAPPING, &token) == NTFS_BUSY);
		if (release_early) {
			oracle_release(&oracle, first++);
			held--;
		}
	}
	if (drain_phase == 1) {
		ntfs_write_lifetime_drain(oracle.owner);
		oracle.draining = true;
		assert(ntfs_write_lifetime_start(oracle.owner, ticket) == NTFS_STALE);
		outcome = NTFS_WRITE_LIFETIME_ABORTED;
	} else {
		assert(ntfs_write_lifetime_start(oracle.owner, ticket) == NTFS_OK);
		assert(ntfs_write_lifetime_start(oracle.owner, ticket) == NTFS_BUSY);
		if (drain_phase == 2) {
			ntfs_write_lifetime_drain(oracle.owner);
			oracle.draining = true;
		}
	}
	assert(ntfs_write_lifetime_close(oracle.owner) == NTFS_BUSY);
	assert(ntfs_write_lifetime_finish(oracle.owner, ticket, outcome) == NTFS_OK);
	oracle.pending[0] = false;
	oracle.pending[1] = false;
	if (outcome == NTFS_WRITE_LIFETIME_COMMITTED) {
		oracle.names[2] = replace ? source : 0;
		if (replace) {
			oracle.names[0] = 0;
		}
	} else if (outcome == NTFS_WRITE_LIFETIME_UNCERTAIN) {
		oracle.poisoned = true;
	}
	oracle_check(&oracle);
	assert(ntfs_write_lifetime_finish(oracle.owner, ticket, outcome) == NTFS_STALE);
	if (oracle.poisoned || oracle.draining) {
		closed = oracle.poisoned ? NTFS_IO : NTFS_STALE;
		assert(ntfs_write_lifetime_access(oracle.owner, oracle.tokens[0]) == closed);
		assert(ntfs_write_lifetime_acquire(
			   oracle.owner, source, NTFS_WRITE_LIFETIME_OPEN, &token) == closed);
		assert(ntfs_write_lifetime_prepare(oracle.owner, NTFS_WRITE_LIFETIME_UNLINK, 0,
			   source, &sentinel) == closed);
		assert(ntfs_write_lifetime_track(
			   oracle.owner, reference(TEST_OTHER_RECORD, 1), 1) == closed);
		oracle_close(&oracle);
		return;
	}
	if (outcome == NTFS_WRITE_LIFETIME_ABORTED) {
		assert(ntfs_write_lifetime_access(oracle.owner, oracle.tokens[0]) == NTFS_OK);
		oracle_close(&oracle);
		return;
	}
	if (victim_names == 2) {
		oracle_remove_last(&oracle, 3, 1);
	}
	if (held != 0) {
		assert(ntfs_write_lifetime_access(oracle.owner, oracle.tokens[first]) == NTFS_OK);
		assert(
		    ntfs_write_lifetime_retain(oracle.owner, oracle.tokens[first],
			NTFS_WRITE_LIFETIME_MAPPING, &oracle.tokens[TEST_TOKENS - 2]) == NTFS_OK);
		oracle_check(&oracle);
		assert(ntfs_write_lifetime_prepare(oracle.owner, NTFS_WRITE_LIFETIME_RETIRE, 0,
			   victim, &sentinel) == NTFS_BUSY);
		for (index = 0; index < held; index++) {
			oracle_release(&oracle, first + index);
		}
		/* The descriptor set is empty here; its derived mapping alone must keep
		 * detached storage allocated and retirement unavailable. */
		assert(ntfs_write_lifetime_prepare(oracle.owner, NTFS_WRITE_LIFETIME_RETIRE, 0,
			   victim, &sentinel) == NTFS_BUSY);
		oracle_release(&oracle, TEST_TOKENS - 2);
	}
	retire_and_reuse(&oracle);
	if (stale.serial != 0) {
		assert(ntfs_write_lifetime_release(oracle.owner, stale) == NTFS_STALE);
		assert(ntfs_write_lifetime_retain(
			   oracle.owner, stale, NTFS_WRITE_LIFETIME_OPEN, &token) == NTFS_STALE);
		oracle_check(&oracle);
	}
	oracle_close(&oracle);
}

static void
lifecycle_matrix(void)
{
	size_t source_names, victim_names, opens, mappings, replace, outcome, drain, early;

	for (source_names = 1; source_names <= 2; source_names++) {
		for (victim_names = 1; victim_names <= 2; victim_names++) {
			for (opens = 0; opens <= 2; opens++) {
				for (mappings = 0; mappings <= 2; mappings++) {
					for (replace = 0; replace <= 1; replace++) {
						for (outcome = NTFS_WRITE_LIFETIME_ABORTED;
						    outcome <= NTFS_WRITE_LIFETIME_UNCERTAIN;
						    outcome++) {
							for (drain = 0; drain <= 2; drain++) {
								for (early = 0; early <= 1;
								    early++) {
									lifecycle_case(source_names,
									    victim_names, opens,
									    mappings, replace != 0,
									    (enum ntfs_write_lifetime_outcome)
										outcome,
									    drain, early != 0);
								}
							}
						}
					}
				}
			}
		}
	}
}

static void
failure_and_identity(void)
{
	struct oracle oracle = {0}, foreign = {0};
	struct ntfs_write_lifetime_token changed, output, original;
	struct ntfs_write_lifetime_ticket ticket, wrong, second;
	struct ntfs_write_lifetime_view view, saved;
	uint64_t source, victim;
	size_t index;

	oracle_open(&oracle, 1, 1);
	oracle_open(&foreign, 1, 1);
	source = oracle.objects[0];
	victim = oracle.objects[1];
	oracle_acquire(&oracle, 0, 0, NTFS_WRITE_LIFETIME_OPEN);
	original = oracle.tokens[0];
	memset(&output, 0xa5, sizeof(output));
	for (index = 0; index < 5; index++) {
		changed = original;
		if (index == 0) {
			changed.owner = foreign.owner;
		} else if (index == 1) {
			changed.epoch++;
		} else if (index == 2) {
			changed.reference = victim;
		} else if (index == 3) {
			changed.serial++;
		} else {
			changed.kind = NTFS_WRITE_LIFETIME_MAPPING;
		}
		assert(ntfs_write_lifetime_release(oracle.owner, changed) == NTFS_STALE);
		assert(ntfs_write_lifetime_access(oracle.owner, changed) == NTFS_STALE);
		oracle_check(&oracle);
	}
	assert(ntfs_write_lifetime_release(foreign.owner, original) == NTFS_STALE);
	assert(ntfs_write_lifetime_track(oracle.owner, source, 1) == NTFS_EXISTS);
	assert(ntfs_write_lifetime_track(oracle.owner, reference(TEST_SOURCE_RECORD, 2), 1) ==
	    NTFS_STALE);
	assert(ntfs_write_lifetime_track(oracle.owner, TEST_SOURCE_RECORD, 1) == NTFS_INVALID);
	assert(ntfs_write_lifetime_track(oracle.owner, reference(NTFS_ROOT_RECORD, 1), 1) ==
	    NTFS_INVALID);
	assert(ntfs_write_lifetime_track(oracle.owner, source, 0) == NTFS_INVALID);
	assert(ntfs_write_lifetime_acquire(oracle.owner, source, (enum ntfs_write_lifetime_kind)2,
		   &output) == NTFS_INVALID);
	assert(ntfs_write_lifetime_acquire(oracle.owner, reference(TEST_OTHER_RECORD, 1),
		   NTFS_WRITE_LIFETIME_OPEN, &output) == NTFS_NOT_FOUND);
	assert(ntfs_write_lifetime_acquire(oracle.owner, source, NTFS_WRITE_LIFETIME_OPEN,
		   (void *)oracle.owner) == NTFS_INVALID);
	assert(ntfs_write_lifetime_inspect(oracle.owner, source, (void *)oracle.owner) ==
	    NTFS_INVALID);
	assert(ntfs_write_lifetime_prepare(oracle.owner, NTFS_WRITE_LIFETIME_REPLACE, source,
		   source, &ticket) == NTFS_INVALID);
	assert(ntfs_write_lifetime_prepare(oracle.owner, NTFS_WRITE_LIFETIME_UNLINK, source, victim,
		   &ticket) == NTFS_INVALID);
	assert(ntfs_write_lifetime_prepare(oracle.owner, (enum ntfs_write_lifetime_operation)3, 0,
		   victim, &ticket) == NTFS_INVALID);
	assert(ntfs_write_lifetime_prepare(
		   oracle.owner, NTFS_WRITE_LIFETIME_RETIRE, 0, victim, &ticket) == NTFS_BUSY);
	oracle_check(&oracle);
	assert(ntfs_write_lifetime_prepare(
		   oracle.owner, NTFS_WRITE_LIFETIME_REPLACE, source, victim, &ticket) == NTFS_OK);
	oracle.pending[0] = true;
	oracle.pending[1] = true;
	for (index = 0; index < 6; index++) {
		wrong = ticket;
		if (index == 0) {
			wrong.owner = foreign.owner;
		} else if (index == 1) {
			wrong.epoch++;
		} else if (index == 2) {
			wrong.source = victim;
		} else if (index == 3) {
			wrong.victim = source;
		} else if (index == 4) {
			wrong.serial++;
		} else {
			wrong.operation = NTFS_WRITE_LIFETIME_UNLINK;
		}
		assert(ntfs_write_lifetime_start(oracle.owner, wrong) == NTFS_STALE);
		assert(ntfs_write_lifetime_finish(
			   oracle.owner, wrong, NTFS_WRITE_LIFETIME_ABORTED) == NTFS_STALE);
		oracle_check(&oracle);
	}
	assert(ntfs_write_lifetime_prepare(
		   oracle.owner, NTFS_WRITE_LIFETIME_UNLINK, 0, source, &second) == NTFS_BUSY);
	assert(ntfs_write_lifetime_finish(
		   oracle.owner, ticket, (enum ntfs_write_lifetime_outcome)3) == NTFS_INVALID);
	assert(ntfs_write_lifetime_finish(oracle.owner, ticket, NTFS_WRITE_LIFETIME_ABORTED) ==
	    NTFS_OK);
	oracle.pending[0] = false;
	oracle.pending[1] = false;
	assert(ntfs_write_lifetime_inspect(oracle.owner, source, &view) == NTFS_OK);
	saved = view;
	assert(ntfs_write_lifetime_inspect(oracle.owner, reference(TEST_SOURCE_RECORD, 2), &view) ==
	    NTFS_STALE);
	assert(memcmp(&view, &saved, sizeof(view)) == 0);
	/* New epoch rejects an otherwise exactly matching token at the same current
	 * owner pointer. Actual allocator address reuse is covered separately. */
	changed = original;
	changed.epoch = TEST_EPOCH - 1;
	assert(ntfs_write_lifetime_release(oracle.owner, changed) == NTFS_STALE);
	ntfs_write_lifetime_poison(oracle.owner);
	ntfs_write_lifetime_poison(oracle.owner);
	oracle.poisoned = true;
	oracle_check(&oracle);
	oracle_close(&oracle);
	oracle_close(&foreign);
}

static void
limits_and_allocation(void)
{
	struct fuzz_device device = {0};
	struct ntfs_environment environment = fuzz_environment(&device), invalid;
	struct ntfs_write_lifetime_limits limits = {1, 1, 1, 3}, bad;
	struct ntfs_write_lifetime *owner;
	struct ntfs_write_lifetime_token token, before, output;
	struct ntfs_write_lifetime_ticket ticket, ticket_before, other;
	struct ntfs_write_lifetime_view view;
	uint64_t ref = reference(TEST_SOURCE_RECORD, UINT16_MAX);
	size_t index, calls;

	for (index = 0; index < 8; index++) {
		bad = limits;
		if (index == 0) {
			bad.objects = 0;
		} else if (index == 1) {
			bad.objects = SIZE_MAX;
		} else if (index == 2) {
			bad.leases = 0;
		} else if (index == 3) {
			bad.leases = SIZE_MAX;
		} else if (index == 4) {
			bad.pending = 0;
		} else if (index == 5) {
			bad.pending = SIZE_MAX;
		} else if (index == 6) {
			bad.issued = 0;
		} else {
			bad.objects = NTFS_WRITE_LIFETIME_MAX_OBJECTS + 1u;
		}
		owner = (void *)(uintptr_t)1;
		assert(ntfs_write_lifetime_create(&environment, TEST_EPOCH, &bad, &owner) ==
		    NTFS_RANGE);
		assert(owner == NULL && device.allocations == 0);
	}
	for (index = 0; index < 4; index++) {
		invalid = environment;
		if (index == 0) {
			invalid.api_version++;
		} else if (index == 1) {
			invalid.allocate = NULL;
		} else if (index == 2) {
			invalid.release = NULL;
		}
		owner = (void *)(uintptr_t)1;
		assert(ntfs_write_lifetime_create(
			   &invalid, index == 3 ? 0 : TEST_EPOCH, &limits, &owner) == NTFS_INVALID);
		assert(owner == NULL && device.allocations == 0);
	}
	owner = (void *)(uintptr_t)1;
	assert(ntfs_write_lifetime_create(NULL, TEST_EPOCH, &limits, &owner) == NTFS_INVALID);
	assert(owner == (void *)(uintptr_t)1);
	assert(ntfs_write_lifetime_create(&environment, TEST_EPOCH, &limits, (void *)&limits) ==
	    NTFS_INVALID);
	assert(ntfs_write_lifetime_create(&environment, TEST_EPOCH, &limits,
		   (void *)(UINTPTR_MAX - sizeof(owner) + 1u)) == NTFS_INVALID);
	device.fail_allocation = 1;
	assert(ntfs_write_lifetime_create(&environment, TEST_EPOCH, &limits, &owner) ==
	    NTFS_NO_MEMORY);
	assert(owner == NULL && device.memory == 0 && device.reads == 0);
	device.fail_allocation = 0;
	limits.issued = TEST_SERIAL_BUDGET;
	assert(ntfs_write_lifetime_create(&environment, TEST_EPOCH, &limits, &owner) == NTFS_OK);
	assert(ntfs_write_lifetime_track(owner, ref, UINT32_MAX) == NTFS_OK);
	assert(
	    ntfs_write_lifetime_inspect(owner, ref, &view) == NTFS_OK && view.names == UINT32_MAX);
	assert(ntfs_write_lifetime_prepare(owner, NTFS_WRITE_LIFETIME_UNLINK, 0, ref, &ticket) ==
	    NTFS_OK);
	assert(ntfs_write_lifetime_start(owner, ticket) == NTFS_OK);
	assert(ntfs_write_lifetime_finish(owner, ticket, NTFS_WRITE_LIFETIME_COMMITTED) == NTFS_OK);
	assert(ntfs_write_lifetime_inspect(owner, ref, &view) == NTFS_OK &&
	    view.names == UINT32_MAX - 1u);
	ntfs_write_lifetime_drain(owner);
	assert(ntfs_write_lifetime_close(owner) == NTFS_OK);
	limits.issued = 3;
	assert(ntfs_write_lifetime_create(&environment, TEST_EPOCH, &limits, &owner) == NTFS_OK);
	assert(ntfs_write_lifetime_track(owner, ref, 1) == NTFS_OK);
	assert(
	    ntfs_write_lifetime_track(owner, reference(TEST_OTHER_RECORD, 1), 1) == NTFS_NO_SPACE);
	assert(
	    ntfs_write_lifetime_acquire(owner, ref, NTFS_WRITE_LIFETIME_OPEN, &token) == NTFS_OK);
	memset(&output, 0xa5, sizeof(output));
	before = output;
	assert(ntfs_write_lifetime_acquire(owner, ref, NTFS_WRITE_LIFETIME_MAPPING, &output) ==
	    NTFS_NO_SPACE);
	assert(memcmp(&output, &before, sizeof(output)) == 0);
	assert(ntfs_write_lifetime_retain(owner, token, NTFS_WRITE_LIFETIME_MAPPING, &output) ==
	    NTFS_NO_SPACE);
	assert(memcmp(&output, &before, sizeof(output)) == 0);
	assert(ntfs_write_lifetime_release(owner, token) == NTFS_OK);
	assert(ntfs_write_lifetime_prepare(owner, NTFS_WRITE_LIFETIME_UNLINK, 0, ref, &ticket) ==
	    NTFS_OK);
	assert(ntfs_write_lifetime_start(owner, ticket) == NTFS_OK);
	assert(ntfs_write_lifetime_finish(owner, ticket, NTFS_WRITE_LIFETIME_COMMITTED) == NTFS_OK);
	assert(ntfs_write_lifetime_prepare(owner, NTFS_WRITE_LIFETIME_RETIRE, 0, ref, &ticket) ==
	    NTFS_OK);
	assert(ntfs_write_lifetime_start(owner, ticket) == NTFS_OK);
	assert(ntfs_write_lifetime_finish(owner, ticket, NTFS_WRITE_LIFETIME_COMMITTED) == NTFS_OK);
	assert(ntfs_write_lifetime_track(owner, reference(TEST_SOURCE_RECORD, 1), 1) ==
	    NTFS_UNSUPPORTED);
	ntfs_write_lifetime_drain(owner);
	assert(ntfs_write_lifetime_close(owner) == NTFS_OK);
	assert(device.memory == 0);
	/* A small serial budget reaches the exact production exhaustion branch;
	 * releases/aborts never recycle identifiers or consume another budget. */
	limits.objects = 2;
	limits.issued = 2;
	ref = reference(TEST_SOURCE_RECORD, 1);
	assert(ntfs_write_lifetime_create(&environment, TEST_EPOCH, &limits, &owner) == NTFS_OK);
	assert(ntfs_write_lifetime_track(owner, ref, 1) == NTFS_OK);
	assert(ntfs_write_lifetime_track(owner, reference(TEST_OTHER_RECORD, 1), 1) == NTFS_OK);
	assert(ntfs_write_lifetime_prepare(owner, NTFS_WRITE_LIFETIME_UNLINK, 0, ref, &ticket) ==
	    NTFS_OK);
	memset(&other, 0xa5, sizeof(other));
	ticket_before = other;
	assert(ntfs_write_lifetime_prepare(owner, NTFS_WRITE_LIFETIME_UNLINK, 0,
		   reference(TEST_OTHER_RECORD, 1), &other) == NTFS_NO_SPACE);
	assert(memcmp(&other, &ticket_before, sizeof(other)) == 0);
	assert(
	    ntfs_write_lifetime_inspect(owner, reference(TEST_OTHER_RECORD, 1), &view) == NTFS_OK);
	assert(!view.pending && view.names == 1);
	assert(ntfs_write_lifetime_finish(owner, ticket, NTFS_WRITE_LIFETIME_ABORTED) == NTFS_OK);
	assert(
	    ntfs_write_lifetime_acquire(owner, ref, NTFS_WRITE_LIFETIME_OPEN, &token) == NTFS_OK);
	assert(ntfs_write_lifetime_release(owner, token) == NTFS_OK);
	calls = device.allocations;
	assert(ntfs_write_lifetime_acquire(owner, ref, NTFS_WRITE_LIFETIME_OPEN, &output) ==
	    NTFS_RANGE);
	assert(memcmp(&output, &before, sizeof(output)) == 0);
	assert(ntfs_write_lifetime_prepare(owner, NTFS_WRITE_LIFETIME_UNLINK, 0, ref, &other) ==
	    NTFS_RANGE);
	assert(memcmp(&other, &ticket_before, sizeof(other)) == 0);
	assert(ntfs_write_lifetime_inspect(owner, ref, &view) == NTFS_OK && !view.pending);
	assert(device.allocations == calls && device.reads == 0);
	ntfs_write_lifetime_drain(owner);
	assert(ntfs_write_lifetime_close(owner) == NTFS_OK);
	assert(device.memory == 0);
	assert(ntfs_write_lifetime_close(NULL) == NTFS_OK);
}

static void
maximum_tables_and_parallel_completion(void)
{
	struct fuzz_device device = {0};
	struct ntfs_environment environment = fuzz_environment(&device);
	const struct ntfs_write_lifetime_limits limits = {NTFS_WRITE_LIFETIME_MAX_OBJECTS,
	    NTFS_WRITE_LIFETIME_MAX_LEASES, NTFS_WRITE_LIFETIME_MAX_PENDING, UINT64_MAX};
	struct ntfs_write_lifetime *owner;
	struct ntfs_write_lifetime_token *tokens, output = {0};
	struct ntfs_write_lifetime_ticket tickets[NTFS_WRITE_LIFETIME_MAX_PENDING],
	    output_ticket = {0};
	struct ntfs_write_lifetime_view view;
	size_t index, allocations, expected_opens, expected_mappings;
	uint64_t ref = reference(TEST_SOURCE_RECORD, 1), other;

	tokens = calloc(NTFS_WRITE_LIFETIME_MAX_LEASES, sizeof(*tokens));
	assert(tokens != NULL);
	assert(ntfs_write_lifetime_create(&environment, UINT64_MAX, &limits, &owner) == NTFS_OK);
	for (index = 0; index < NTFS_WRITE_LIFETIME_MAX_OBJECTS; index++) {
		assert(ntfs_write_lifetime_track(
			   owner, reference(TEST_SOURCE_RECORD + index, 1), 1) == NTFS_OK);
	}
	assert(ntfs_write_lifetime_track(owner,
		   reference(TEST_SOURCE_RECORD + NTFS_WRITE_LIFETIME_MAX_OBJECTS, 1),
		   1) == NTFS_NO_SPACE);
	for (index = 0; index < NTFS_WRITE_LIFETIME_MAX_LEASES; index++) {
		assert(ntfs_write_lifetime_acquire(owner, ref,
			   index % 2 == 0 ? NTFS_WRITE_LIFETIME_OPEN : NTFS_WRITE_LIFETIME_MAPPING,
			   &tokens[index]) == NTFS_OK);
	}
	assert(ntfs_write_lifetime_acquire(owner, ref, NTFS_WRITE_LIFETIME_OPEN, &output) ==
	    NTFS_NO_SPACE);
	assert(output.serial == 0);
	assert(ntfs_write_lifetime_inspect(owner, ref, &view) == NTFS_OK);
	expected_opens = NTFS_WRITE_LIFETIME_MAX_LEASES / 2;
	expected_mappings = NTFS_WRITE_LIFETIME_MAX_LEASES / 2;
	assert(view.opens == expected_opens && view.mappings == expected_mappings);
	for (index = 0; index < NTFS_WRITE_LIFETIME_MAX_PENDING; index++) {
		other = reference(TEST_SOURCE_RECORD + index + 1, 1);
		assert(ntfs_write_lifetime_prepare(owner, NTFS_WRITE_LIFETIME_UNLINK, 0, other,
			   &tickets[index]) == NTFS_OK);
		assert(ntfs_write_lifetime_start(owner, tickets[index]) == NTFS_OK);
	}
	other = reference(TEST_SOURCE_RECORD + NTFS_WRITE_LIFETIME_MAX_PENDING + 1, 1);
	assert(ntfs_write_lifetime_prepare(
		   owner, NTFS_WRITE_LIFETIME_UNLINK, 0, other, &output_ticket) == NTFS_NO_SPACE);
	assert(output_ticket.serial == 0);
	assert(ntfs_write_lifetime_inspect(owner, other, &view) == NTFS_OK && !view.pending);
	assert(ntfs_write_lifetime_finish(owner, tickets[0], NTFS_WRITE_LIFETIME_UNCERTAIN) ==
	    NTFS_OK);
	for (index = 1; index < NTFS_WRITE_LIFETIME_MAX_PENDING; index++) {
		/* An unrelated operation had already crossed start before the uncertain
		 * outcome. A known durable endpoint must still be recorded during poison. */
		assert(ntfs_write_lifetime_finish(
			   owner, tickets[index], NTFS_WRITE_LIFETIME_COMMITTED) == NTFS_OK);
		assert(ntfs_write_lifetime_inspect(owner, tickets[index].victim, &view) == NTFS_OK);
		assert(view.state == NTFS_WRITE_LIFETIME_DETACHED && view.names == 0 &&
		    view.poisoned && !view.pending && !view.eligible);
		assert(ntfs_write_lifetime_prepare(owner, NTFS_WRITE_LIFETIME_RETIRE, 0,
			   tickets[index].victim, &output_ticket) == NTFS_IO);
	}
	assert(ntfs_write_lifetime_track(owner, reference(TEST_SOURCE_RECORD, 2), 1) == NTFS_IO);
	allocations = device.allocations;
	for (index = 0; index < NTFS_WRITE_LIFETIME_MAX_LEASES; index++) {
		assert(ntfs_write_lifetime_close(owner) == NTFS_BUSY);
		assert(ntfs_write_lifetime_release(owner, tokens[index]) == NTFS_OK);
		if (tokens[index].kind == NTFS_WRITE_LIFETIME_OPEN) {
			expected_opens--;
		} else {
			expected_mappings--;
		}
		assert(ntfs_write_lifetime_inspect(owner, ref, &view) == NTFS_OK);
		assert(view.opens == expected_opens && view.mappings == expected_mappings);
	}
	assert(ntfs_write_lifetime_close(owner) == NTFS_OK);
	assert(device.allocations == allocations && device.memory == 0 && device.reads == 0);
	free(tokens);
}

struct fixed_allocator {
	void *bytes;
	size_t capacity, live;
};

static void *
fixed_allocate(void *opaque, size_t bytes)
{
	struct fixed_allocator *allocator = opaque;

	assert(allocator->live == 0 && bytes <= allocator->capacity);
	allocator->live = bytes;
	return allocator->bytes;
}

static void
fixed_release(void *opaque, void *bytes, size_t size)
{
	struct fixed_allocator *allocator = opaque;

	assert(bytes == allocator->bytes && size == allocator->live);
	allocator->live = 0;
}

static void
same_address_new_epoch(void)
{
	struct fixed_allocator allocator = {0};
	struct ntfs_environment environment = {.api_version = NTFS_API_VERSION,
	    .context = &allocator,
	    .allocate = fixed_allocate,
	    .release = fixed_release};
	const struct ntfs_write_lifetime_limits limits = {1, 1, 1, UINT64_MAX};
	struct ntfs_write_lifetime *owner, *former;
	struct ntfs_write_lifetime_token old, current;
	struct ntfs_write_lifetime_ticket old_ticket, current_ticket;
	struct ntfs_write_lifetime_view view;
	uint64_t ref = reference(TEST_SOURCE_RECORD, 1);

	allocator.capacity = 4096;
	allocator.bytes = malloc(allocator.capacity);
	assert(allocator.bytes != NULL);
	assert(ntfs_write_lifetime_create(&environment, TEST_EPOCH, &limits, &owner) == NTFS_OK);
	former = owner;
	assert(ntfs_write_lifetime_track(owner, ref, 1) == NTFS_OK);
	assert(ntfs_write_lifetime_acquire(owner, ref, NTFS_WRITE_LIFETIME_OPEN, &old) == NTFS_OK);
	assert(ntfs_write_lifetime_release(owner, old) == NTFS_OK);
	assert(ntfs_write_lifetime_prepare(
		   owner, NTFS_WRITE_LIFETIME_UNLINK, 0, ref, &old_ticket) == NTFS_OK);
	assert(
	    ntfs_write_lifetime_finish(owner, old_ticket, NTFS_WRITE_LIFETIME_ABORTED) == NTFS_OK);
	ntfs_write_lifetime_drain(owner);
	assert(ntfs_write_lifetime_close(owner) == NTFS_OK);
	assert(
	    ntfs_write_lifetime_create(&environment, TEST_EPOCH + 1, &limits, &owner) == NTFS_OK);
	assert(owner == former);
	assert(ntfs_write_lifetime_track(owner, ref, 1) == NTFS_OK);
	assert(
	    ntfs_write_lifetime_acquire(owner, ref, NTFS_WRITE_LIFETIME_OPEN, &current) == NTFS_OK);
	assert(old.serial == current.serial && old.owner == current.owner);
	assert(ntfs_write_lifetime_release(owner, old) == NTFS_STALE);
	assert(ntfs_write_lifetime_access(owner, current) == NTFS_OK);
	assert(ntfs_write_lifetime_release(owner, current) == NTFS_OK);
	assert(ntfs_write_lifetime_prepare(
		   owner, NTFS_WRITE_LIFETIME_UNLINK, 0, ref, &current_ticket) == NTFS_OK);
	assert(old_ticket.serial == current_ticket.serial);
	assert(ntfs_write_lifetime_finish(owner, old_ticket, NTFS_WRITE_LIFETIME_ABORTED) ==
	    NTFS_STALE);
	assert(ntfs_write_lifetime_inspect(owner, ref, &view) == NTFS_OK && view.pending);
	assert(ntfs_write_lifetime_start(owner, current_ticket) == NTFS_OK);
	ntfs_write_lifetime_poison(owner);
	assert(ntfs_write_lifetime_close(owner) == NTFS_BUSY);
	assert(ntfs_write_lifetime_finish(owner, current_ticket, NTFS_WRITE_LIFETIME_UNCERTAIN) ==
	    NTFS_OK);
	assert(ntfs_write_lifetime_inspect(owner, ref, &view) == NTFS_OK && view.poisoned &&
	    !view.pending && !view.eligible);
	assert(ntfs_write_lifetime_close(owner) == NTFS_OK);
	assert(allocator.live == 0);
	free(allocator.bytes);
}

int
main(void)
{
	lifecycle_matrix();
	failure_and_identity();
	limits_and_allocation();
	maximum_tables_and_parallel_completion();
	same_address_new_epoch();
	printf("write lifetime: %zu lifecycle scenarios, %zu independent reachability checks\n",
	    scenarios, assertions);
	return 0;
}
