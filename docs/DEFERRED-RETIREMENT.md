# Deferred retirement: portable ownership contract

Open unlink and replacement of an opened victim are still refused by the C/native
ordinary mutation route. This contract separates a private C lifetime owner and
independent ownership model from unresolved on-disk orphan and native lifetime
protocols. It does not add a disk field, relax validation or enable either
operation.

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

The private C lifetime component described below now owns the volatile boundary.
The complete owning implementation still needs adapter-to-kernel open/mapping/
reclaim integration, detached-object read/write support, native orphan/logging
evidence and fresh-media interruption recovery. See
[the capability map](PORTABLE-FEATURES.md), [WRITES](WRITES.md) and
[LIFECYCLE](LIFECYCLE.md).

## Private C lifetime owner

[`core/write_lifetime.c`](../core/write_lifetime.c) and its
[private header](../core/write_lifetime.h) implement the volatile part of this
contract. They deliberately do not replace the existing
[`write_retirement.c`](../core/write_retirement.c) compiler, which owns native
closed-FILE deallocation packets. No existing mutation, CLI or FSKit admission
calls the new lifetime component.

A caller-supplied `ntfs_environment` owns one bounded allocation. It retains up
to 256 record identities, 4,096 open/mapping leases and 32 simultaneous prepared
operations, selected downward by explicit limits. Construction makes one
allocation; every later operation, including publication and teardown, allocates
nothing. No read/write callback occurs. Tables are scanned only within their
configured caps. The caller supplies the existing writer's serialization and
accounted allocator; the component creates neither a lock nor a second I/O owner.

Each binding contains the full sequence-bearing reference and a count of logical
namespace edges, distinct from physical FILE_NAME/DOS-alias counts. Each issued
lease/ticket additionally carries the owner identity, a nonzero owner epoch and
an unrecycled serial. The epoch must never repeat while an earlier token could
survive, even if an allocator reuses the owner address. Serial exhaustion refuses
with RANGE before mutation. Released leases and aborted tickets do not recycle
serials. A record table slot remains reserved through retirement, so forgotten
history cannot accidentally admit another generation.

Namespace acquisition requires an attached object. A held authorized lease can
derive another open or mapping lease after detachment, including a mapping that
outlives every descriptor. Fresh namespace acquisition cannot. Access/release
checks the exact token; changing its generation, kind, serial, epoch or owner is
STALE. This is lifetime admission, not an NTFS read/write implementation or a
security authorization decision. The caller must retain the lease through the
whole native I/O and serialize access with release.

`prepare` reserves an unlink, replacement or retirement ticket. Unlink removes
one victim edge on committed completion; replacement pins both exact generations,
removes one victim edge and preserves the source's total edge count. Exact
source/destination name selection and atomic namespace publication remain the
external mutation owner's responsibility. Both pinned objects refuse new leases,
derivation and access until completion; releases remain available. Independent
objects can have separately bounded pending work. A retirement ticket requires a
detached object with no leases or pending work. Eligibility itself never frees a
cluster, FILE record, stream, security reference or cache.

`start` is a separate one-shot transition before the first possible transfer.
Drain/poison prevents starting a prepared ticket. A prepared ticket can only be
aborted. A started ticket finishes with one of three explicit caller assertions:

- ABORTED: independently proved unchanged media, including any necessary recovery;
  an I/O error alone is insufficient.
- COMMITTED: the complete operation has reached its independently established
  durable endpoint.
- UNCERTAIN: publication cannot be proved; all access/acquisition/reuse is poisoned.

The helper cannot establish those durability assertions and grants no authority
to make them. Completion remains available during drain/poison to consume pins
held by an already-started operation. Uncertain completion consumes its volatile
ticket but leaves the owner's namespace counters informational only: fresh-media
recovery must reconstruct a new epoch rather than trust that snapshot.

Only committed retirement marks the volatile object retired. Rebinding permits
exactly the next FILE sequence; UINT16_MAX wrap is refused rather than inventing
a stale-handle policy. This conservative lifetime policy does not change the
existing physical compiler's separate sequence encoding. The external allocator
must still prove durable retirement and complete reinitialization before calling
`track`. Closed/reused generations cannot be reached by old leases or tickets.

Drain and poison are terminal, idempotent and never revoke storage behind a held
lease or unfinished ticket. Teardown returns BUSY until every lease has been
released and every ticket completed or aborted. Successful close frees only the
volatile allocation, including when detached objects remain: it is not a disk
cleanup result. The allocator context and active I/O ownership must outlive close.

### Independent C checks

[`tests/write_lifetime.c`](../tests/write_lifetime.c) reconstructs expected name
counts from explicit namespace edges and expected open/mapping counts from a
separate retained-token set after each transition. Its matrix covers source/victim
multiple names, no/one/multiple opens and mappings, unlink/replacement, every
abstract completion outcome, drain before/after start, and release while prepared.
Further cases cover mapping derivation after detachment, last-mapping release,
retirement abort, committed retirement and exact successor reuse, duplicate or
altered token/ticket rejection, foreign owners, allocator address reuse in a new
epoch, failed allocation, table exhaustion, maximum name count, generation wrap,
serial exhaustion and unchanged failure outputs. Maximum-capacity checks retain
256 objects, 4,096 leases and 32 simultaneously started tickets. After one ticket
finishes uncertain, independently committed peers can finish without reopening
access or retirement eligibility. These are volatile C contracts; the separate
Python model retains its abstract crash/recovery exploration.

The focused local GCC run passes 1,298 lifecycle scenarios and 36,968 independent
reachability checks with fatal ASan/UBSan. Both the ordinary freestanding and
`NTFS_NO_SIMD`/general-register-only objects meet the 2-KiB frame limit. The first
leak-sanitizer attempt terminates at the sandbox's LSan-under-ptrace restriction;
its original failure is retained separately from the passing no-LSan supplement.
Exact callback allocation/release balance remains asserted. Clang and clang-format
are unavailable in that local environment, so this result does not claim those
gates or any native lifecycle, filesystem persistence, or full-suite acceptance.

### Remaining coupled implementation

The next owning integration must supply all of the following before enabling
open unlink or opened-victim replacement:

1. FSKit/kernel open, mapping, in-flight I/O and reclaim events mapped to exact
   leases under the existing publication/operation serialization. An FSItem count
   is not sufficient evidence of those lifetimes.
2. Detached-object read/write ownership that survives namespace loss and immutable
   view replacement without reopening through a deleted name.
3. Complete detachment/replacement metadata, storage retention and redo/undo,
   together with an independently specified native durable detached-object witness.
   No orphan field, zero-link inference or recovery transaction is invented here.
4. A separate complete final-retirement operation coupled to allocation, FILE,
   security/provider state and the existing packet/compiler/recovery owner, with
   interruption proofs and fresh-epoch reconstruction from the actual media.
5. A policy and native test for FILE generation wrap, followed by installed
   mmap/teardown/reclaim qualification and Windows recovery/chkdsk evidence.

Missing native witness/lifetime observations block those dependent transitions;
they do not block this bounded C resource and lifetime implementation. Existing
open-victim refusal remains unchanged.
