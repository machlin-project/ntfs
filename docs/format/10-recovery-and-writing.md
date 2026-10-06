# 10 · Recovery and writing

[Reference index](README.md) · [Previous](09-logfile.md) · [Next](11-worked-examples.md)

Updating an NTFS metadata object means preparing a native journal program whose
redo/undo and physical targets match the eventual home images. Correct final
bytes are necessary, but interruption must also leave enough proved information
to recover a consistent state.

This chapter describes the design boundary and the currently qualified ordinary
overwrite family. It does not claim generic replay for every native update.
The authoritative contracts are [WRITES.md](../WRITES.md) and
[NATIVE-WRITE-JOURNAL.md](../NATIVE-WRITE-JOURNAL.md).

## Write-ahead logging

The recovery journal records metadata updates before those updates can require
redo or undo at their home location. The general native architecture has analysis,
redo and undo phases, described by
[original NTFS recovery research](https://flatcap.github.io/linux-ntfs/ntfs/files/logfile.html)
and [Suhanov's LFS research](https://dfir.ru/2019/02/16/how-the-logfile-works/).
That architecture does not supply missing operation-specific execution semantics.

| Phase | Required owning decision |
| --- | --- |
| Analysis | Reconstruct selected client, checkpoint, open attributes, dirty targets and transaction lifetimes. |
| Redo | Reapply qualified logged changes that may not have reached durable homes. |
| Undo | Compensate qualified unfinished transactions while preserving a recoverable undo history. |
| Publication | Expose complete homes and a consistent journal state only after actual persistence. |

A raw Commit or Forget opcode is not enough to classify an arbitrary lifetime.
Our confirmed family requires its exact preceding packets, links, metadata and
native observed terminal marker. Unknown or incomplete families refuse.

## Prepare everything before mutation

The exclusive owner proves:

1. Resource authorization and exclusion of competing readers/mutators.
2. Supported clean/recoverable volume features and complete retained history.
3. Exact sequence-bearing object identity and permitted operation.
4. Every affected FILE/INDX/bitmap image and physical target, including before bytes.
5. Native redo/undo, links, ring capacity, transfer alignment and predecessor guards.
6. Whole reconstructed-volume validity through a fresh immutable overlay.
7. Complete output/report storage and teardown of all old immutable children.

Preparation errors leave disk bytes unchanged. An execution path that can still
discover a missing allocation or read after its first write has not met this
contract. Old caches and nodes cannot survive into a mutable epoch and then be
silently treated as fresh objects.

## Qualified ordinary overwrite sequence

The current native family binds `$MFT::$DATA` through OpenNonresidentAttribute,
retains a restored FILE reconstruction snapshot, logs SI redo/undo and, for
resident DATA, a separate resident-value update. Its qualified Forget/Compensation
terminal form is observed and bound as a whole family.

![Current retained-root writer ordering and true persistence boundaries](diagrams/write-order.svg)

[Diagram source](diagrams/write-order.mmd)

The actual sequence is dirty RSTR copies; prepare copy and home; initialized DATA
when applicable; commit copy and home; complete protected FILE home; retained
clean RSTR copies. Every metadata publication has a true persistence barrier.
The initialized DATA portion persists before the durable commit decision.
Resident DATA is instead carried by FILE metadata logging.

The sequence retains the original owning checkpoint and client roots. It does not
publish a new empty checkpoint, wrap the ring or discard retained history. Its
current bounded family-count limit is an admission limit, not completed journal
reuse. Those extensions belong to the active ordinary mutation batch.

## Failure model

| Boundary | Contract |
| --- | --- |
| Read/allocation/preflight refusal | No physical mutation; retry is allowed. |
| Exact successful write | Requested bytes were transferred; persistence still requires a barrier. |
| Successful true persistence barrier | The preceding qualified publication has crossed volatile caches. |
| Failed or short attempted transfer | Any requested bytes may have changed; permanently poison this owner. |
| Failed persistence | Durable state is uncertain; permanently poison this owner. |
| Fresh recovery owner | Reacquire and prove the native history; do not reuse stale in-memory decisions. |

On the image transport, `F_FULLFSYNC` is mandatory; a cache-only flush is not a
fallback. Close releases ownership without inventing a successful durability
result. Failed callbacks reporting zero bytes still represent uncertain attempted
I/O under this contract.

Metadata recovery and user-data atomicity are separate. An interrupted
initialized overwrite can expose some changed user DATA even when metadata takes
the old state. Newly exposed or newly allocated bytes must still obey VDL/zero
and ownership rules. Tests must specify which visible bytes are allowed rather
than demand byte identity of every unallocated cluster.

## Losers and compensation

A loser receives qualified native compensation before its FILE undo is published.
Compensation redo contains the original update's undo bytes and follows the
proved undo chain. Resident DATA and SI have ordered compensation updates.
The final marker closes that exact lifetime.

Interrupted recovery is itself recoverable. Reopening a compensated or completed
family must select its settled home state without reapplying an incompatible
transition. Tail-copy-backed log homes are restored before reusing the copy slot.
The full reconstructed volume is validated before any recovery transfer.

## Allocation and namespace batch

The active extension prepares connected changes to FILE records, mapping pairs,
volume/MFT/index bitmaps and complete `$I30` trees. The expected old or committed
metadata state must include allocation, names, sizes, generation reuse and
inherited security together.

Its local pure planner currently covers create/remove/rename, grow/shrink,
resident conversion, fragmentation, ENOSPC, MFT/index growth and reused slots.
Projection of those regions into test memory is a **planning test**. It supplies
neither a native WAL program nor real durability or recovery.

### Keep the logical owner with each physical region

The planner records each cluster's sequence-bearing owning FILE reference,
attribute type, original attribute name and logical stream byte offset. These
values are retained where the mutation owner already knows the checked mapping.
The later journal owner must not infer them from a coarse region kind or scan
the whole volume to guess a physical cluster's role.

![Logical mutation ownership remains bound to physical before/after regions](diagrams/mutation-targets.svg)

[Diagram source](diagrams/mutation-targets.mmd)

| Planned region | Logical target |
| --- | --- |
| FILE cluster | `$MFT::$DATA` at the corresponding logical cluster offset; several FILE records can share one cluster. |
| MFTMirr cluster | Replica of that logical MFT prefix, explicitly marked as a mirror; it needs its own actual predecessor protection. |
| INDX cluster | Its directory's named `$INDEX_ALLOCATION:$I30` at that buffer's stream offset. |
| Bitmap cluster | `$Bitmap::$DATA`, `$MFT::$BITMAP`, or that directory's named `$BITMAP:$I30`; these are different targets. |
| User DATA cluster | Its ordinary file's unnamed DATA and stream offset; initialized/zero-gap ordering remains separate from metadata rollback. |

Conflicting owners, logical offsets or region kinds at one physical cluster
refuse preparation. The complete projected-volume tests compare every retained
target with the checked resulting stream map and preserve targets across every
read/allocation failure and retry. A target descriptor is addressing evidence;
it does not assign an NTFS redo/undo opcode to the region.

For bitmap regions, a separate pure compiler now prepares exact native set/clear
pairs. The connected planning scenario applies every program forward to the
complete planned cluster and inversely to its exact predecessor, including MFT
and index growth and volume allocation/free. This checks that the bitmap program
matches the owning mutation; it does not decide when an allocation becomes durable.
The experimental whole-operation composition is described below. See
[bitmap range units and wire forms](09-logfile.md#bitmap-ranges-two-dwords-measured-in-bits).

FILE retirement now also has a separate pure native program. Its before-snapshot
and 24-byte header inverse agree with every retired slot in the connected private
mutation scenarios, without additional reads. Generation, flags, retained links,
attribute bodies and unrelated bytes are checked through forward and inverse
application. This covers one operation family within those scenarios; parent
FILE updates, index changes and bitmap programs still require qualified owning
recovery. The five exact native packet/home-LSN matches
establish a header transition, not executed Windows rollback of our program.
See [the retirement inverse](09-logfile.md#file-retirement-a-header-inverse).

### Prepare one complete operation and its inverse prefixes

The new private compiler retains every changed region and distinct attribute
identity, assembles all metadata updates and prepares complete LFS pages. It also
binds the original program's packets before producing compensation for a complete
metadata prefix. Copied pages survive program closure; exact packet reconstruction
checks every protected sector before changing caller output.

Original ownership accompanies every copied region. The planner binds FILE
predecessors to the unchanged MFT initialization/map and INDX predecessors to the
unchanged parent/map/index bitmap. The complete program cannot infer an inverse
from stale or malformed signatures in unused storage. An independent immutable
source view checks those claims across growth, removal and inverse prefixes,
including a mapped index buffer whose bitmap bit is clear.

The [experimental opcode composition](09-logfile.md#experimental-complete-image-composition)
uses whole FILE/INDX images with bitmap and retirement primitives. Local tests
compare the resulting complete metadata, its reverse inverse and representative
incomplete prefixes against the independently checked ordinary mutation. They
exercise failed allocations, exact retries, client/history mismatches and damaged
page protection. The generated opens and inverse links are real prepared bytes;
they have not been accepted as an executed native transaction.

![Private complete-operation preparation and its separate native execution gate](diagrams/mutation-program.svg)

[Diagram source](diagrams/mutation-program.mmd)

DATA remains separate initialization work. Mirrors retain their actual independent
physical predecessor protection while sharing the primary MFT journal target.
No device transfer, owning current-history proof, clean-checkpoint advancement or
FSKit mutation callback is added by this compiler. Full native image substitution
and newly exposed/free storage still require Windows replay/rollback
qualification of the retained ownership rules before executable admission.

General execution must bind all regions to qualified native operations, close
immutable owners, preserve open-unlink lifetime, and recover every transfer/barrier
prefix. Those requirements remain open alongside FSKit callback integration.

## Checkpoint advancement and ring reuse

![A retained floor cannot move until homes and a new owning checkpoint are durable](diagrams/checkpoint.svg)

[Diagram source](diagrams/checkpoint.mmd)

The floor protects every log record still needed by checkpoint, redo or undo,
including its containing page's prefix. It is not simply the numerically smallest
visible LSN or the current record's page. A newer checkpoint cannot discard live
undo obligations or dirty-home provenance.

A separately observed byte-level checkpoint hypothesis is not current C/product
admission. An earlier empty-checkpoint protocol caused native repair demand and
remains disqualified. Product advancement needs complete C framing, interrupted
publication tests, sustained reuse/wrap and one connected native acceptance batch.
Clearing flags or introducing a private journal cannot substitute for this gate.

## Implementation and evidence

- Family preparation: [write_transaction.c](../../core/write_transaction.c).
- Native encoding/compensation: [write_journal.c](../../core/write_journal.c).
- Ordinary private regions and logical targets: [write_mutation.h](../../core/write_mutation.h),
  [write_mutation.c](../../core/write_mutation.c),
  [stream binding](../../core/write_record.c) and
  [projected mapping/fault tests](../../tests/write_mutation.c).
- Bitmap native update preparation and private inverse application:
  [write_bitmap.c](../../core/write_bitmap.c), [contract](../../core/write_bitmap.h)
  and [independent goldens](../../tests/write_bitmap_fixtures.py).
- Experimental complete metadata/OAT/compensation preparation:
  [write_program.c](../../core/write_program.c), [contract](../../core/write_program.h)
  and [connected private prefix tests](../../tests/write_mutation.c).
- Physical preflight and execution: [write_execute.c](../../core/write_execute.c).
- Bound family replay: [write_replay.c](../../core/write_replay.c).
- Complete retained family history: [write_history.c](../../core/write_history.c).
- Fresh overlay validation: [write_overlay.c](../../core/write_overlay.c).
- Owning recovery: [write_recover.c](../../core/write_recover.c).
- Transfer/barrier fault tests: [write_execute.c](../../tests/write_execute.c).

Actual installed initialized and unchanged-size resident overwrites, offline
interruption recovery and independent Windows checks have qualified evidence.
Allocation/namespace/general checkpoint recovery and hardware power cuts do not
inherit that evidence. [ACCEPTANCE.md](../ACCEPTANCE.md) records the distinction.
