# Deferred retirement: portable ownership contract

Open unlink and replacement of an opened victim are still refused by the C/native
ordinary mutation route. This contract separates an implementable ownership model
from the unresolved on-disk orphan and native lifetime protocols. It does not add
a disk field, relax validation or enable either operation.

## Identity and reachability

An object is identified by its complete sequence-bearing FILE reference within
one owner epoch. Namespace edges, open handles, mappings and a pending prepared
mutation are separate kinds of reachability. An open or mapping token retains
that exact identity and epoch; it cannot silently follow a reused record number.
A stale, duplicate or foreign-owner release does not decrement another token.

Removing the last name detaches the object from its namespace. It does not free
the FILE slot, clusters, stream mappings, security references or provider state
while any existing handle or mapping still reaches that generation. An existing
authorized token continues to refer to the detached object; a fresh name lookup
cannot acquire it. Replacing a victim moves the source edge and detaches the
victim in the same namespace transaction. Source and victim ownership stay
distinct even when their size, names or cached native attributes coincide.

## Preparation, publication and retirement

1. Under the owning operation serialization, resolve complete source/victim
   generations and namespace edges. Prove storage ownership and acquire an
   independent snapshot of every held handle/mapping lifetime.
2. Prepare the entire detach/replace metadata change, recovery material, bounded
   orphan witness and native reply before any write. A preparation can be abandoned
   without a namespace, allocation, counter or durable-state change.
3. Publish the namespace change through a qualified WAL/recovery contract. It
   must recover as the complete old or committed namespace. An uncertain transfer
   poisons the owner; no in-memory success or final free may be fabricated.
4. After committed detachment, retain all physical allocation while any token
   remains. Further reads/writes must use the same owning generation and the
   detached-object authority, not reopen through the now-missing name.
5. Last-reference release makes the object eligible for a separate bounded
   retirement preparation. Eligibility is not permission to clear a bitmap.
   Recheck generation, epoch, zero reachability and absence of pending work under
   the same owner before reserving every free/FILE/journal update.
6. Only durable completed retirement makes a record/cluster reusable. New FILE
   initialization advances its generation. Generation wrap remains an explicit
   unresolved policy/native gate; a small model counter is not a disk rule.

Native callbacks that arrive during reply construction, drain, reclamation or
revocation cannot bypass steps 2–6. A reference acquired after a proposed
last-release invalidates its preparation before the first write. Holding only an
FSItem object does not establish all kernel open/mapping lifetime facts.

## Crash and teardown boundary

A crash invalidates volatile handles and mappings from the former owner epoch.
Their later simulated release must be stale in the new epoch. Recovery must first
establish whether each namespace transaction committed and whether allocation
retirement committed. It cannot infer an orphan from an arbitrary unreferenced
FILE body, a clear directory entry, a matching signature or a zero link count.

A committed detached object needs a durable, independently identifiable recovery
witness that binds its full generation, storage and owning transaction. That is
an abstract requirement here. No NTFS orphan-list field, deletion marker, native
transaction family or special system index is assumed. Until an independently
specified mechanism and its Windows behavior are known, automatic cleanup and
media publication remain unavailable.

Unmount/drain closes new acquisition first. Ordinary release and cleanup remain
safe for retained tokens; freeing storage still requires the durable protocol.
Forced invalidation revokes access and releases volatile resources after admitted
I/O completes. It must not report an unperformed durable retirement as success.

## Executable model scope and independent checks

[The executable model](../tests/deferred_retirement_model.py) keeps the algorithm's
cached reference counters separate from an oracle that reconstructs reachability
from namespace edges and retained token identities. It exhausts one-slot states
within explicit generation/epoch/lease bounds and separately enumerates two-object
replacement cuts. Events include open, map, duplicate/stale release, detach,
replacement, abort, every abstract publication cut, last release, retire,
crash/recover, drain and reuse. Every transition is checked, not just terminal states.

Required invariants are no reuse while reachable, exact old/committed namespaces,
unchanged durable bytes on abandoned preparation, retained allocation until
completed retirement, generation/epoch isolation, bounded references/preparations,
and no successful acquisition during drain. Deliberately unsafe counterexamples
should show that unlink-time freeing, record-number-only identity and stale
release acceptance violate these invariants. Abstract atomic durable decisions
do not replace sector-transfer or actual C WAL/recovery tests.

The owning implementation still needs a C lifetime component, adapter-to-kernel
open/mapping/reclaim integration, complete detached-object read/write support,
native orphan/logging evidence and fresh-media interruption recovery. See
[the capability map](PORTABLE-FEATURES.md), [WRITES](WRITES.md) and
[LIFECYCLE](LIFECYCLE.md).
