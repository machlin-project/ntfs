# Owned native recovery inputs

`ntfs/recovery.h` prepares an immutable, bounded NTFS-client history for the
separate recovery engine. It does not execute redo/undo, write a device or admit
a writable mount. The read environment retains API version 2 and no write callback.

## Ownership and complete publication

`ntfs_recovery_open` requires a prepared journal page index and external
serialization of the immutable source. It acquires the selected client's stored
checkpoint internally, including every referenced dump, then retains exact
unpadded records from that client's retained oldest LSN through the independently
framed completed endpoint. Restart-time CurrentLsn is not used as that endpoint.
The analysis LSN must name an exact retained packet between oldest and the stored
client restart. The checkpoint and each dump must match a retained packet byte
for byte. A caller-supplied checkpoint projection cannot replace these checks.

Every retained record must have the selected client index and sequence. Unknown
record types/flags refuse. The observed checkpoint-dump flag is admitted only on
the selected exact dump anchors, with no undo action/data or LCN vector; complete
packet binding still precedes publication. Its meaning for ordinary updates is
not inferred. An unfinished successor remains an explicit UNSUPPORTED result;
continuation freshness still requires original Windows qualification.

Only a complete successful open publishes an owner. Failed opens return NULL,
retain precise partial reports and free all private allocations. Getters expose
immutable owned packet bytes and value snapshots without I/O or allocation. The
owner survives source close. A volume-backed source supplies a separate counted
volume child and governed allocation context, avoiding a dangling temporary stream
allocator. Unmount returns BUSY until the recovery-input owner closes. Close frees
private storage and issues no reads or writes.

## Transaction lifetimes and checkpoint roots

Physical transaction keys are offsets into the native 40-byte transaction table,
beginning after its named 24-byte header. A bounded direct slot map distinguishes
each serialized lifetime. Each retained previous LSN must name the same lifetime's
immediately preceding update. A reused key with previous zero starts a new lifetime
only after Forget. Undo-next references must name an earlier record in that exact
lifetime, never a reused key's earlier lifetime or another transaction.

A retained prefix may begin before oldest only if it ends in Forget. Such a prefix
is reported incomplete and cannot supply undo authority. A still-live incomplete
prefix returns STALE. Independent checkpoint observations do not enter transaction
chains, even when their LFS header contains a transaction key and previous link.

Prepare, Commit and Forget advance observed lifetimes. Control records require
empty redo/undo bodies, no target/vector fields and a known Noop or Compensation
undo marker. Ordinary Windows Forget may occur without Commit; its Compensation
marker is retained without executing compensation or inferring an undo result.
These observed terminal states are not durable recovery decisions.

Every allocated checkpoint transaction key binds to its exact stored previous
root, first LSN and undo membership in this same retained history. Roots precede
the transaction dump. An allocated empty seed must have the uninitialized state
and zero LSN/undo credits. Raw table states and credits remain in the immutable
checkpoint; they are not converted into a replay plan.

## Bounds and evidence

Positive limits are copied before callbacks. Policies cap complete records at
4,096 and retained history at 16 MiB. Capture, history and successor probing share
one call/byte ceiling clamped to the source policy. Preparation/discovery remain
separate reported operations. All fixed storage is reserved before packet I/O:
checkpoint arena, history arena, record/lifetime catalogs, slot map, name scratch
and staging plus private assembly headroom. Reservation/retention reports describe
requested bytes, not process RSS; a backing volume's aggregate memory governor
also applies.

Original fixtures independently declare complete packet bytes and lifetime
outcomes, including LFS 1.1/2.0, both client payload versions, extended record
headers, interleaving, reused keys, checkpoint seeds, truncated prefixes, exact
copy bindings and malformed links/control fields. Fault tests fail every selected
allocation/read before retry, verify copied budgets, exact/short credits, immutable
inputs and source-close lifetime. A volume fixture verifies BUSY lifetime and
aggregate memory refusal before packet reads. Whole-source fuzz inputs exercise
the same composition and deterministic results without publishing partial owners.

The frozen original Windows Recovery journal supplies four exact packets with
their original client/checkpoint owner. The admitted bound dump flag permits this
input snapshot; it contains no transaction lifetime. This is native byte/ownership
evidence, not a positive native transaction or recovery witness. Review generated
reports under `artifacts/recovery-history/`; test and product stages remain distinct.

The diagnostic is
`ntfs-logfile recovery-inputs LOGICAL_JOURNAL_FILE CLIENT_INDEX CLIENT_SEQUENCE`.
It reports preparation, checkpoint/history credits, owned packets and observed
lifetimes separately, with `recovery_qualified` and `writes_enabled` false.

## Remaining execution contract

Native OAT/dirty-page evolution, volume/stream target resolution, compensation
execution, redo/undo decisions, modern journal placement, restart publication,
real persistence barriers and owner poisoning still belong to the separate native
recovery/writable owner. Positive original Windows histories and interrupted
Windows/chkdsk roundtrips are required under [WRITES.md](WRITES.md). Parser success
or this owner cannot bypass that contract.
