# Transaction ownership and durability reference model

`tests/transaction_model.py` is an executable architecture model on in-memory
cells. `tests/recovery_model.py` explores its failure boundaries against separately
authored native NTFS endpoints. Neither module is imported by the core or FSKit.
The public read environment still has no write callback. This model supplies a
tested foundation for the transaction work in [WRITES.md](WRITES.md); native
NTFS recovery and writable product acceptance remain separate requirements.

## Ownership and reservation

One exclusive owner admits one transaction and finishes log retirement before
admitting another. Recovery requires a cold, unclaimed device without volatile
cells. Pending writes, residual log cells or uncertain I/O prevent a new owner.
This is an externally serialized reference contract, not a concurrency algorithm.

A plan contains immutable complete before/after pages and separately owned
initialized user data. All page, private-byte and abstract log-fragment credits
fit before simulated allocation. Reservations follow a named object-domain order
and then physical address. Stale snapshots, overlaps, mutable plans and invalid
geometry are refused before I/O. Every injected private-allocation failure releases
credits and reservations and permits a fresh attempt. Private-byte counters are
logical model charges; they do not measure Python memory or native RSS.

The model caps private snapshots at 4 MiB, log fragments at 4,096 and pages at 256.
These small exploration policies are independent of native format limits and the
read-only operation governor. Immutable complete FILE/INDX records are supplied
with newly authored update-sequence fixups; home writes select private sectors
from those complete records.

## Persistence and publication

The reference protocol uses the following order:

1. Initialize newly referenced data and persist it.
2. Persist complete before/after update evidence before any affected home write.
3. Persist commit membership before publishing the complete committed live view.
4. Persist the resulting home metadata, or restore before-images for an abort.
5. Persist a checkpoint, retire the other log evidence and persist that retirement.
6. Retire the checkpoint only after the other evidence is durably absent.

The simulator permits arbitrary eviction of pending sectors on a crash. An
attempted write or persistence barrier can fail after a zero, partial or complete
transfer. The owner becomes permanently uncertain, rejects reads and further
transactions and releases memory/reservations on close without issuing device I/O.
Successful acknowledgement requires a recoverable durable commit; a failure
after commit does not imply that the transaction was aborted.
Power-cut enumeration selects complete cell versions; byte-prefix tearing is
injected on failed calls. Arbitrary byte tear patterns and actual hardware sector
atomicity require separate native qualification.

The committed live view is separate from dirty home sectors. The profiles cover
deferred home writes, uncommitted home writes followed by commit, and an abort
which restores those uncommitted writes. Unreferenced initialized data can remain
in free storage after an abort; it cannot become referenced before initialization.

## Abstract history and replay

Log fragments contain typed immutable observations and an intact/torn flag.
They are not serialized journal bytes or a private on-disk journal. Fragment
counts charge identities, membership and snapshots in the model, not an NTFS
wire layout. A future independently qualified decoder must establish completeness
and integrity before supplying equivalent observations to a native algorithm.

History geometry, identity, membership and aggregate bounds are checked before
recovery I/O. A complete commit requires every listed update. Incomplete/torn
well-formed records are not complete evidence. Conflicting fragment observations,
invalid membership, overlapping updates and interleaved transactions are refused.
One serialized history is redone from complete after-images or undone from
complete before-images. Successful replay is idempotent. Interrupted replay is
restarted from a fresh cold device.

A durable checkpoint is an authoritative promise of already durable home pages
within this abstract protocol. During partial retirement, recovery retains that
exact marker while deleting remaining evidence. Replacing it with membership
derived from a shortened remaining log could erase the skip evidence. A malformed
or premature native checkpoint cannot acquire this promise from parser success.

## Independent native byte oracles

`tests/recovery_fixtures.py` imports no transaction-model types. It authors two
complete 8-MiB NTFS images using the existing independent named-wire fixture
author: a resident `hello.txt` before state and a renamed `renamed.txt` backed by
one initialized nonresident cluster after state. The transaction affects a
complete file record, the volume-bitmap file record and one complete directory
index block, with new FILE/INDX update-sequence fixups.

Every explored state must recover to all original or all resulting metadata
bytes. An acknowledged commit must select the resulting endpoint with its exact
initialized data. No mixed record, bitmap or directory outcome is accepted.
Representative recovered states are materialized as regular-file images and
checked by the actual read-only consistency diagnostic and exact content reader.
The images are hashed before and after those readers. Retained JSON reports
distinguish native image readability from unqualified native journal recovery.

All persistence subsets are explored for bounded home/control pending sets.
Larger abstract update-body sets use individual fragments, complements and
prefixes/suffixes; their complete powerset is not claimed. Sector-prefix failures
cover zero, one byte, half a sector, one byte below full and full transfer. The
explorer has a hard state ceiling and bounded child-tool output/deadlines.

Negative witnesses deliberately violate WAL, acknowledgement, initialization
and checkpoint order. The independent endpoint oracle must reject each. A torn
native FILE record from the WAL witness must also fail the actual consistency
diagnostic. This checks that the oracle can distinguish broken ordering from
successful recovery.

The retained final run passes 49,855 crash/fault states, including 1,205 interrupted
recovery states, 22 ownership contracts and 14 history refusals. All 47 representative
native images pass complete diagnostic/content checks; four unsafe-order witnesses
are detected, including a native corrupt-metadata verdict. All 62 sanitized-build
suites and style pass. ACCEPTANCE.md retains exact reports/logs, independent actual
image/tool review and the two corrected initial harness failures.

## Remaining native contract

This serialized full-snapshot model does not implement LFS written/current-history
selection, tail/fast-page routing, native NTFS opcodes/targets, checkpoint tables,
compensation records, LSN chains or interleaved transaction analysis. It does not
qualify a real device barrier, atomic sector behavior, writable device ownership,
hibernation/Fast Startup detection or FSKit mutation/lifecycle behavior.

Further work must retain the complete scope in WRITES.md and CORE-QUALIFICATION.md:
native journal/recovery ownership, concurrent mutations, attribute-list/B-tree
growth, security references, ENOSPC/log growth, device loss, open-unlinked objects,
mmap/truncation/cancellation, independent Windows replay and chkdsk, and actual
durability through every volatile cache. The model is original repository work;
it imports no external filesystem or recovery implementation.
