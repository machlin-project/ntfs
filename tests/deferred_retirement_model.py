#!/usr/bin/env python3
"""Explore a portable deferred-retirement owner, without inventing NTFS orphan bytes.

Durable old/new decisions and the orphan witness are explicit abstract inputs.
This model does not establish physical WAL ordering or enable driver operations.
"""
from collections import deque
from dataclasses import dataclass, replace
from itertools import product

MAX_GENERATION = 2  # Finite exploration bound, not an NTFS generation policy.
MAX_EPOCH = 2
MAX_ISSUED = 2
MAX_OPEN = 2
MAX_MAPPING = 1
PREPARED, WAL_DURABLE, METADATA_VISIBLE, COMMITTED = range(4)


@dataclass(frozen=True, order=True)
class Reference:
    slot: int
    generation: int


@dataclass(frozen=True, order=True)
class Token:
    epoch: int
    serial: int
    reference: Reference
    mapping: bool


@dataclass(frozen=True)
class Disk:
    generations: tuple[int, ...]
    allocated: tuple[bool, ...]
    names: tuple[Reference | None, ...]
    orphans: frozenset[Reference] = frozenset()


@dataclass(frozen=True)
class Pending:
    operation: str
    before: Disk
    after: Disk
    phase: int = PREPARED


@dataclass(frozen=True)
class Owner:
    disk: Disk
    counts: tuple[int, ...]
    tokens: tuple[Token, ...] = ()
    epoch: int = 1
    issued: int = 0
    draining: bool = False
    poisoned: bool = False
    pending: Pending | None = None


def initial(slots=1):
    references = tuple(Reference(slot, 1) for slot in range(slots))
    return Owner(Disk((1,) * slots, (True,) * slots, references), (0,) * slots)


def acquire(owner, name, mapping):
    """Issue a distinct lease; new acquisition never uses an unlinked FILE slot."""
    if owner.draining or owner.poisoned or owner.pending is not None or owner.issued == MAX_ISSUED:
        return None
    reference = owner.disk.names[name]
    if reference is None:
        return None
    ceiling = MAX_MAPPING if mapping else MAX_OPEN
    if sum(token.mapping == mapping for token in owner.tokens) == ceiling:
        return None
    counts = list(owner.counts)
    counts[reference.slot] += 1
    token = Token(owner.epoch, owner.issued + 1, reference, mapping)
    return replace(owner, counts=tuple(counts), tokens=owner.tokens + (token,),
                   issued=owner.issued + 1)


def release(owner, token):
    """Exact token validation precedes a reference-counter change."""
    if token.epoch != owner.epoch or token not in owner.tokens:
        return None
    reference = token.reference
    if (not owner.disk.allocated[reference.slot]
            or owner.disk.generations[reference.slot] != reference.generation):
        return None
    counts = list(owner.counts)
    counts[reference.slot] -= 1
    return replace(owner, counts=tuple(counts),
                   tokens=tuple(held for held in owner.tokens if held != token))


def prepare(owner, operation, source=0, destination=0):
    if owner.draining or owner.poisoned or owner.pending is not None:
        return None
    disk = owner.disk
    names = list(disk.names)
    allocated = list(disk.allocated)
    generations = list(disk.generations)
    orphans = set(disk.orphans)
    if operation in ('unlink', 'replace'):
        victim = names[destination if operation == 'replace' else source]
        if victim is None:
            return None
        if operation == 'replace':
            if source == destination or names[source] is None:
                return None
            names[destination], names[source] = names[source], None
        else:
            names[source] = None
        if victim not in names:
            orphans.add(victim)
    elif operation == 'retire':
        reference = Reference(source, generations[source])
        if (reference not in orphans or reference in names or owner.counts[source] != 0
                or not allocated[source]):
            return None
        allocated[source] = False
        orphans.remove(reference)
    elif operation == 'create':
        if (names[destination] is not None or allocated[source]
                or owner.counts[source] != 0 or generations[source] == MAX_GENERATION):
            return None
        generations[source] += 1
        allocated[source] = True
        names[destination] = Reference(source, generations[source])
    else:
        raise AssertionError(operation)
    after = Disk(tuple(generations), tuple(allocated), tuple(names), frozenset(orphans))
    return replace(owner, pending=Pending(operation, disk, after))


def advance(owner):
    pending = owner.pending
    if pending is None or owner.draining or owner.poisoned:
        return None
    if pending.phase == COMMITTED:
        return replace(owner, pending=None)
    phase = pending.phase + 1
    # METADATA_VISIBLE is an uncommitted physical projection. The old/new
    # journal decision remains old until COMMITTED; callbacks stay excluded.
    return replace(owner, pending=replace(pending, phase=phase),
                   disk=pending.after if phase == COMMITTED else pending.before)


def abandon(owner):
    if owner.pending is None or owner.pending.phase != PREPARED:
        return None
    return replace(owner, pending=None)


def crash(owner):
    if owner.epoch == MAX_EPOCH:
        return None
    # The abstract durable decision supplies the complete recoverable disk.
    # Former-owner handles are revoked before any orphan retirement is allowed.
    return Owner(owner.disk, (0,) * len(owner.counts), epoch=owner.epoch + 1)


def oracle(owner):
    """Reconstruct object reachability independently of cached owner counts."""
    disk = owner.disk
    assert len(disk.generations) == len(disk.allocated) == len(owner.counts)
    objects = {Reference(slot, generation) for slot, generation in enumerate(disk.generations)
               if disk.allocated[slot]}
    edges = [reference for reference in disk.names if reference is not None]
    leases = [token.reference for token in owner.tokens]
    assert set(edges) <= objects
    assert set(leases) <= objects, 'reachable storage was freed or reused'
    assert disk.orphans <= objects, 'orphan witness lost its original allocation'
    assert not set(edges) & disk.orphans, 'linked object cannot be a detached orphan'
    assert objects == set(edges) | disk.orphans, 'unreachable storage has no recovery witness'
    assert len(set(owner.tokens)) == len(owner.tokens)
    assert all(token.epoch == owner.epoch and 0 < token.serial <= owner.issued
               for token in owner.tokens)
    reconstructed = tuple(sum(reference.slot == slot for reference in leases)
                          for slot in range(len(owner.counts)))
    assert reconstructed == owner.counts, 'cached count differs from retained identities'
    assert sum(token.mapping for token in owner.tokens) <= MAX_MAPPING
    assert sum(not token.mapping for token in owner.tokens) <= MAX_OPEN
    pending = owner.pending
    if pending is not None:
        assert disk == (pending.after if pending.phase == COMMITTED else pending.before)
        if pending.operation in ('unlink', 'replace'):
            assert pending.before.allocated == pending.after.allocated
            assert pending.before.generations == pending.after.generations
        if pending.operation == 'retire':
            removed = {slot for slot, value in enumerate(pending.before.allocated)
                       if value and not pending.after.allocated[slot]}
            assert len(removed) == 1 and all(owner.counts[slot] == 0 for slot in removed)
            assert pending.before.names == pending.after.names


def successors(owner):
    for name in range(len(owner.disk.names)):
        for mapping in (False, True):
            yield acquire(owner, name, mapping)
        yield prepare(owner, 'unlink', name)
        for slot in range(len(owner.counts)):
            yield prepare(owner, 'create', slot, name)
        for destination in range(len(owner.disk.names)):
            yield prepare(owner, 'replace', name, destination)
    for slot in range(len(owner.counts)):
        yield prepare(owner, 'retire', slot)
    for token in owner.tokens:
        released = release(owner, token)
        assert released is not None
        assert release(released, token) is None, 'duplicate release changed a live counter'
        assert release(owner, replace(token, epoch=owner.epoch + 1)) is None
        assert release(owner, replace(token, reference=replace(
            token.reference, generation=token.reference.generation + 1))) is None
        yield released
    yield advance(owner)
    yield abandon(owner)
    yield crash(owner)
    if (owner.pending is not None and owner.pending.phase != PREPARED
            and not owner.poisoned):
        yield replace(owner, poisoned=True)
    if not owner.draining:
        yield replace(owner, draining=True)


def explore():
    """Exhaust every reachable state within the stated one-slot finite bounds."""
    start = initial()
    visited = {start}
    queue = deque([start])
    transitions = 0
    while queue:
        owner = queue.popleft()
        oracle(owner)
        if owner.draining or owner.poisoned:
            assert acquire(owner, 0, False) is None and prepare(owner, 'unlink') is None
            assert advance(owner) is None
        if owner.pending is not None and owner.pending.phase == PREPARED:
            assert abandon(owner).disk == owner.disk
        recovered = crash(owner)
        if recovered is not None:
            assert recovered.disk == owner.disk and not recovered.tokens
            for token in owner.tokens:
                assert release(recovered, token) is None
        for candidate in successors(owner):
            if candidate is None:
                continue
            oracle(candidate)
            transitions += 1
            if candidate not in visited:
                visited.add(candidate)
                queue.append(candidate)
    assert any(owner.disk.generations == (MAX_GENERATION,) for owner in visited)
    assert any(owner.draining and owner.tokens and owner.disk.orphans for owner in visited)
    assert any(owner.epoch == MAX_EPOCH and owner.disk.orphans for owner in visited)
    assert any(owner.poisoned and owner.tokens for owner in visited)
    return len(visited), transitions


def settle(owner):
    assert owner is not None and owner.pending is not None
    while owner.pending is not None:
        owner = advance(owner)
        assert owner is not None
        oracle(owner)
    return owner


def replacement_cuts():
    cases = 0
    for holds_open, holds_mapping, phase in product((False, True), (False, True), range(5)):
        owner = initial(2)
        if holds_open:
            owner = acquire(owner, 1, False)
        if holds_mapping:
            owner = acquire(owner, 1, True)
        assert owner is not None
        victim = owner.disk.names[1]
        source = owner.disk.names[0]
        tokens = owner.tokens
        before = owner.disk
        owner = prepare(owner, 'replace', 0, 1)
        for _ in range(phase):
            owner = advance(owner)
            assert owner is not None
        oracle(owner)
        recovered = crash(owner)
        oracle(recovered)
        if phase < COMMITTED:
            assert recovered.disk == before
        else:
            assert recovered.disk.names == (None, source)
            assert victim in recovered.disk.orphans and recovered.disk.allocated[victim.slot]
            retired = settle(prepare(recovered, 'retire', victim.slot))
            recreated = settle(prepare(retired, 'create', victim.slot, 0))
            assert recreated.disk.names[0] == Reference(victim.slot, victim.generation + 1)
            for token in tokens:
                assert release(recreated, token) is None
        if phase == 4:
            if tokens:
                assert prepare(owner, 'retire', victim.slot) is None
            for token in tokens:
                owner = release(owner, token)
                oracle(owner)
            retired = settle(prepare(owner, 'retire', victim.slot))
            assert not retired.disk.allocated[victim.slot]
        cases += 1
    return cases


def stale_generation_release():
    owner = acquire(initial(), 0, False)
    old_token = owner.tokens[0]
    owner = release(owner, old_token)
    owner = settle(prepare(owner, 'unlink'))
    owner = settle(prepare(owner, 'retire'))
    owner = settle(prepare(owner, 'create'))
    owner = acquire(owner, 0, False)
    assert owner is not None and owner.tokens[0].reference.generation == 2
    assert release(owner, old_token) is None
    oracle(owner)
    return owner


def unsafe_counterexamples():
    examples = []
    held = acquire(initial(), 0, False)
    detached = settle(prepare(held, 'unlink'))
    examples.append(replace(detached, disk=replace(detached.disk, allocated=(False,))))
    examples.append(replace(detached, disk=replace(detached.disk, orphans=frozenset())))
    reused = stale_generation_release()
    examples.append(replace(reused, counts=(0,)))
    examples.append(replace(held, disk=replace(held.disk, generations=(2,))))
    victim = acquire(initial(2), 1, True)
    replaced = settle(prepare(victim, 'replace', 0, 1))
    examples.append(replace(replaced, disk=replace(replaced.disk, allocated=(True, False))))
    for unsafe in examples:
        try:
            oracle(unsafe)
        except AssertionError:
            continue
        raise AssertionError('unsafe retirement escaped the independent reachability oracle')
    return len(examples)


if __name__ == '__main__':
    states, transitions = explore()
    cuts = replacement_cuts()
    stale_generation_release()
    unsafe = unsafe_counterexamples()
    print(f'deferred retirement: {states} states, {transitions} transitions, '
          f'{cuts} replacement cuts, {unsafe} unsafe counterexamples')
    print('Abstract lifetime/durability model only; no NTFS orphan format, media writes, '
          'Windows recovery or FSKit admission is qualified.')
