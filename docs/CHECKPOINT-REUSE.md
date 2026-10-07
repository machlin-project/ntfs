# Experimental settled checkpoint and journal reuse

This is the next connected implementation/test contract after retained ordinary
history. It does not expand the installed image owner's capabilities.
[WRITES.md](WRITES.md) retains the native acceptance gate, and
[the format reference](format/10-recovery-and-writing.md#checkpoint-advancement-and-ring-reuse)
separates format relationships from accepted product behavior.

The original Windows captures include empty client checkpoints whose analysis
anchor is a settled `ForgetTransaction`. Five independently prepared publication
states pass the narrower byte-level native observation recorded in
[NATIVE-WRITE-JOURNAL.md](NATIVE-WRITE-JOURNAL.md). They are not an executed C
checkpoint, interrupted recovery or circular-wrap qualification. The previously
failing checkpoint that introduced another bootstrap Noop remains disqualified.

## Input ownership

One exclusively claimed regular-image backend supplies exact immutable reads,
accounted allocation and real persistence. Preparation must acquire the complete
current retained history, prove every transaction settled and close all immutable
children. No live redo/undo, unfinished compensation, unresolved tail, torn sole
copy or unproved metadata home can be dropped. The actual final settled Forget
packet becomes the new analysis anchor; no transaction completion is invented.
An attribute-open-only suffix cannot serve as this anchor.

The private empty-origin binder accepts only the existing bootstrap/empty pair or
the exact single-client settled-Forget/empty pair. The latter retains the actual
Forget LSN, deleting flag, transaction identity, empty compensation inverse and
zero undo root. The qualified marker retains its MFT key/flag pair; an ordinary
complete-operation marker has the exact zero-target/zero-flag pair. Crossed pairs
and other keys/flags are refused. Its previous LSN precedes the new floor; the selected checkpoint
has no live tables. Client identity, restart geometry, opaque empty extension and
both analysis-anchor fields remain exact. The qualified overwrite owner's origin
admission is unchanged until its own continuation/wrap tests pass.

## Publication and restart roots

The [private checkpoint owner](../core/write_checkpoint.c) reserves a free circular page under the old floor,
encodes one empty restart packet and guards every output against its actual
physical predecessor. All aligned output, work and recovery reservations precede
the first transfer. A persistence barrier first establishes the proved settled
journal/metadata homes. The implemented experimental order then publishes dirty old roots, the
checkpoint tail copy and home, dirty advanced roots and clean advanced roots.
Every transfer has its owning barrier. The floor advances only after the complete
checkpoint and settled homes are durable; subsequent ordinary operations cannot
reuse the dropped interval until both advanced roots are complete and clean.

Fresh recovery must bind actual media at every transition. Before a complete new
checkpoint, the old origin remains authoritative. A complete unpublished
checkpoint needs an exact settled-prefix and anchor proof before publication.
If roots disagree across advancement, use the still-retained old root/history to
prove that exact transition; a numerically greater CurrentLsn alone is insufficient.
No private projected root is alleged to be physical source evidence. Torn copies,
lost publication barriers and an interrupted recovery are tested independently.

The [fresh recovery component](../core/write_checkpoint_recover.c) retains the
complete actual packet inventory, including a pending checkpoint. It separates
that packet from operation analysis without truncating the physical endpoint.
When both valid roots span advancement, their complete restored bytes must agree
except for CurrentLsn, last-data length, clean flag and the client's oldest/restart
LSNs; only their USA arrays are transport differences. An explicitly private old-root
view permits acquisition of the still-retained old history. That history must
prove the actual final Forget, complete empty checkpoint and all settled homes
before recovery can finish the transition. Required older log-home repairs,
live undo or contradictory valid roots refuse advancement.

An invalid/torn restart copy may be bypassed using its surviving root and complete
actual history. A structurally valid contradictory newer floor is different and
fails its exact transition proof. New-origin Forget and checkpoint packets must
already have exact complete circular homes: a sole copy cannot authorize another
operation which will overwrite that slot. Recovery of a pending checkpoint can
repair its home from the proved complete copy before advancing the old floor.

Execution consumes the prepared owner once, performs no reads/allocation and
poisons the transport after uncertain writes or barriers. Preparation failures
leave the whole image unchanged. No clean hint substitutes for owning-history,
home or generation proof.

## Test batch before native acceptance

Independent fixtures first cover settled Forget origins, dirty/clean copies,
an origin crossing the circular end and explicit live-undo/client/anchor refusals.
The existing implementation must produce the expected refusal before its admission
changes. Full page/root byte oracles then cover checkpoint construction and exact
predecessor USA protection; they are authored separately from the C serializer.

Connected interruption checks reopen only captured media after every transfer,
sector prefix/suffix and persistence failure, and after interrupted recovery.
Recovery must retain all user bytes and reach a complete old or new origin; a
second fresh reopen must require zero rewrites. Allocation/read refusals retain
exact retry and accounting. Actual POSIX transfers/F_FULLFSYNC, close and whole-file
reopen remain separate from modeled persistence inputs.

Sustained mixed operations run beyond both the retained-packet ceiling and the
physical ring capacity, with fresh owners between operations. They must preserve
FILE generations, allocation/index ownership, names, contents, zero exposure and
exact inverse provenance while reusing the journal. Sequence exhaustion, insufficient
space for checkpoint plus recovery, unknown native families and unsupported storage
reuse fail before mutation.

The ordinary executor reserves both physical pages and retained-record credits.
The maximum loser includes the preceding actual history, every forward update,
its inverses and terminal Forget, plus the next checkpoint. Reserving forward pages
alone is insufficient even when the operation itself fits. The acquisition owner's
4,096-packet ceiling is not an NTFS wire-format limit.

## Focused local evidence

Independent [origin fixtures](../tests/write_checkpoint_fixtures.py) pass 29
profiles: eight clean/dirty linear/wrapped origins and 21 explicit refusals.
Fifteen forward-fitting physical-space profiles pass; nine require refusal because
full recovery/checkpoint reservation will not fit, while six are admitted before
any write. The original qualified overwrite origin policy is unchanged.

[Whole-page publication fixtures](../tests/write_checkpoint_execute_fixtures.py)
and [execution checks](../tests/write_checkpoint_execute.c) pass four settled
committed/compensated families at 512- and 4,096-byte transfer alignments. Their
independently authored complete postimages agree byte-for-byte. Execution uses
eight writes and nine barriers without reads/allocation; fresh recovery requires
zero rewrites. All 2,861 allocation/read refusals across the four preparations
preserve the whole image, close partial ownership and retry to the same output.
Fifty-seven independently authored checkpoint/recovery ownership refusals also pass.

[Interruption checks](../tests/write_checkpoint_interrupt.c) pass 912 writer
transfer/barrier states and 1,264 interrupted-recovery transfer/barrier states across
linear/wrapped qualified and ordinary inputs. All user bytes remain unchanged;
only an exact complete old/new origin is admitted, and second fresh recovery
requires zero rewrites. These are modeled persistence states, not hardware cuts or
native Windows acceptance. The existing mixed-history suite remains passing.

All 5,262 pending-recovery allocation/read faults across copy-only and mixed-root
inputs preserve the complete image and retry to identical publication bytes.
The [sustained sequence](../tests/write_checkpoint_sequence.c) passes 640 modeled
create/grow/shrink/rename/remove operations on each of the small and enlarged rings:
5,632 new packets in each run, 256/128 checkpoints and 119/27 circular wraps.
Names, complete file data, initialized zero gaps, reused FILE generations and all
unowned bytes are checked after every operation, with zero-rewrite fresh recovery.
The complete actual POSIX run passes the same 640 operations and 5,632 packets,
256 checkpoints and 119 wraps. It uses real F_FULLFSYNC, closes and reopens the
ordinary backing file between operations, checks the complete reopened image and
retains its final postimage. This result is separate from the earlier ten-operation
smoke and the modeled persistence inputs.

Focused reports are retained under `artifacts/overwrite/checkpoint-reuse-*`.
The initial refusal fixture used an invalid floor before the page data area;
the surviving old root safely recovered it. Its corrected contradictory but
structurally valid floor uses the actual old checkpoint LSN. Both runs remain
retained. Earlier intended implementation refusals and fixture/setup mistakes
are kept separate from passing evidence.

The connected unit passes all 196 suites with assertions and fatal ASan/UBSan,
selected-Xcode style and 128 freestanding checks across 64 core sources. Strict
Release compilation then identified an implicit successful-producer dependency
in checkpoint mapping. Explicit error returns preserve the same ordered mapper,
read and publication calls; the three affected byte/fault/refusal suites pass
again. All 128 strict Release checks, both modified freestanding checks and 23
standalone writer headers pass. The earlier compiler refusal remains retained.
The actual unsigned universal Release app, both extension copies and core archive
also build successfully. Required module compilation commands and archive members
are checked for both architectures; this is build evidence, with no installation
or native admission change.

The local closing reports are `checkpoint-reuse-final-local-20261007/` and
`checkpoint-reuse-release-closure-20261007/` under `artifacts/overwrite/`.
Actual macOS/Windows operation, recovery, read-only chkdsk and original-event
acceptance remain the next connected native gate. Local origin admission or a
successful app build does not close that gate.

An additional actual C checkpoint on a private clone of the immutable Windows
resident-complete export passes all eight independently authored publication
frames, complete postimage comparison and fresh zero-write C recovery. The first
comparison used the older experiment's fixed USA seed and differed only in USA
storage and protected sector tails. A new independent oracle derives the exact
markers from each actual predecessor and fresh page; all logical fields and full
bytes agree without a C change or another writer invocation. Both comparisons
remain retained under `checkpoint-reuse-native-calibration-20261007/` and
`checkpoint-reuse-native-exact-oracle-20261007/`. This is offline execution on
native source bytes; the new postimage has not yet been recovered by Windows.
