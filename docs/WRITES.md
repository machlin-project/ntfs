# Writable ownership and recovery contract

The unchanged-size resident continuation now has a private DATA redo/undo packet
after the standard-information update, with two ordered compensation packets
for a loser. It changes no attribute length or namespace/storage allocation.
Full independent FILE/page/image oracles and all 176 sanitized suites pass.
All 91 actual writer states and all 264 interrupted-recovery states pass
offline/native Windows recovery and original event review. Installed resident
syscalls, fresh saved-URL remount and the exact FSKit Windows postimage now pass,
including original healthy-event review. All 80 native FSKit component groups
pass with zero SKIPs; installed acceptance is separately established.
See the current continuation in [ACCEPTANCE.md](ACCEPTANCE.md).

## Ordinary mutation implementation batch

The next implementation unit combines storage allocation, file-size changes,
namespace mutation and journal reuse. These are required behavior, not current
acceptance. The existing signed resident image build remains an independent
checkpoint while this unit is developed.

The unit now has experimental complete-operation physical preparation/execution
alongside the private mutation and journal programs. Original settled history,
actual predecessor protection and aligned publication lifetime pass local checks,
including three actual regular-image persistence/reopen cases. The existing
bounded recovery parser does not accept these new families. A separate experimental
owner now acquires only reopened media, reconstructs the original/projected metadata,
recovers torn MFT bootstrap and continues interrupted compensation. Admission retains
the exact quiet origin, a settled qualified prefix and several ordinary groups.
Private backward views prove previous ownership and FILE generation reuse;
only the final transaction may require recovery. Completed compensation and
attribute-open-only prefixes can precede another operation without a fabricated
completion marker. The selected ordinary composition now passes independent
native Windows review of 28 distinct operation/recovery states. The one stopped
INDX fault is attributed to exact original sector bytes and event fields; only
the seven unattempted candidates execute afterward. Native creation inheritance,
MFT pressure and sustained ring reuse still precede write-owner and general
FSKit admission; see the current
[batch evidence](ACCEPTANCE.md#ordinary-mutation-planning-and-complete-lfs-placement).

One exclusive C owner must prepare all affected FILE/INDX images, mapping pairs,
volume/MFT/index bitmaps and native redo/undo before mutation. New immutable views
must observe one complete operation. Preparation failures, collisions and ENOSPC
leave the whole image unchanged. Attempted transfer or persistence failures poison
the owner; recovery must choose the complete old or committed metadata state,
including allocation and namespace. Allocation cannot publish uninitialized bytes
or recycle storage still referenced by an object. MFT reference generations must
reject stale references after reuse. Existing named streams and security remain
intact; creation must implement and test its inherited security contract.

Tests precede implementation of the complete unit. A shared mixed scenario creates
files and directories, writes past EOF, changes resident storage into nonresident
storage, grows through fragmented space, shrinks and clears newly exposed bytes,
moves and replaces names, unlinks objects and reuses their storage. A larger
directory scenario forces index splits and MFT growth. Failure cases cover full
space, name collisions, nonempty directories, stale references, read/allocation
refusal, every transfer/barrier and interrupted recovery. Sustained mixed operations
must reuse the journal beyond the previous retained-history limit; circular wrap
must preserve its qualified LSN and checkpoint semantics.

Development uses compilation and focused C tests for the affected contracts. One
full sanitized core/component regression closes the implementation unit. Only then
does one prepared installed macOS/Windows acceptance batch exercise the complete
scenario, native cache/mmap behavior and recovery inputs. No new feature receives
an individual VM cycle before that local boundary. Block-device admission,
encoded/named-stream mutation and general Windows ACL mutation are separate
contracts and do not become supported through this batch.

## Refactoring after the next verified commit

The next coherent, tested feature checkpoint is followed by a separate driver
refactoring plan. A checkpoint commit does not complete the full write objective.
First review module responsibilities, duplicated code and inconsistent conventions
across the C core and FSKit owner; record the proposed changes before making them.
The review includes naming, declaration/formatting rules, memory ownership, cleanup,
error publication and mutation/recovery interfaces.

The verified local checkpoint now has a concrete
[driver refactoring plan](REFACTORING.md), including the initial review findings,
ordered cleanup commits and their verification boundary.

Implement the agreed cleanup in focused behavior-preserving commits. Keep format
interpretation, write ordering, authorization and accepted capabilities unchanged
within each cleanup commit. Reuse the independent byte, fault, lifetime and recovery
oracles; run the complete regression at the resulting refactoring boundary. Native
checks remain required for changes affecting platform lifecycle or persistence.
Functional writing and recovery gaps retain their original acceptance requirements.

The [native ordinary-file journal](NATIVE-WRITE-JOURNAL.md) qualifies the bounded
MFT binding, full FILE snapshot, timestamp/archive update, native redo and
compensation family. Actual source-clone `pwrite`/`F_FULLFSYNC`, whole-image
comparison and idempotent reopen pass. All 110 actual writer interruption states
and 264 interrupted-recovery fault/complete states pass native Windows VHD
recovery. Independent original-event review binds 264 healthy events and 154
exactly predicted USA warnings; no unrelated warning or repair is admitted.
An earlier empty-checkpoint publication requested repair and remains disqualified;
the accepted writer preserves original client roots.

The installed FSKit image owner now passes authenticated owner `pwrite`/`fsync`,
shared-mapping mutation after descriptor close, observer/prefaulted-mapping
coherence, ordinary unmount and two fresh same-saved-URL CLI mounts. Authenticated
root and nobody are each denied three open modes. The actual exported postimage
passes independent Windows exact file/ADS/time/File ID/ACL, read-only chkdsk,
clean-state and matching healthy-event checks. ACCEPTANCE.md owns the reports.
These tests qualify existing initialized ordinary-file overwriting on authorized
offline images, not allocation, resize, resident/encoded/named-stream or namespace
mutation, general native history, ring wrap/growth or block-device writing.
Hardware power cuts and broad product stress remain untested.

The image transport retains the original security-scoped URL and backing native
owner, supplies mandatory `F_FULLFSYNC` and requires caller exclusion of
uncooperative access/mappings. Counted immutable reader leases exclude mutation;
replacement, resize, scope revocation, short/uncertain I/O or failed persistence
fail closed. The volume closes every immutable child/cache before writing and
lazily rebinds stable sequence-bearing FSItems to fresh views. Retryable allocation
refusal never reports stale data or hides durable completion. Unmount/invalidation
drain mutation before releasing the owner. Complete native replies are prepared
before mutation, and contextless I/O requires retained admitted open rights.
Ordinary vnode presentation grants no data or namespace access. Metadata
confidentiality across native attribute caches is not claimed.

Current FSKit components pass 59 host groups with thirteen runtime SKIPs and all
76 native groups with zero SKIPs and 871 unchanged inputs. Explicit image policy
refuses unknown/conflicting options before acquiring scope, and probing performs
only immutable reads. Recovery precedes publication; exact-URL unload drains
mutation. The immutable read environment has no write method and public block
resources retain read-only extraction. The separate public data-only overwrite
owner preserves all metadata; the timestamped journal owner supplies the complete
installed image operation. Existing source-build/component results remain
separate from the mounted and native Windows acceptance above.

The [recovery-input owner](RECOVERY-INPUTS.md) now internally binds the owning
checkpoint and complete retained oldest-to-endpoint packet interval, distinguishing
transaction lifetimes and verifying checkpoint roots. It survives source close and
retains volume memory/lifetime accounting. This prepares checked native inputs;
OAT/dirty evolution, compensation, replay, native persistence and Windows recovery
qualification still precede writable admission.

Read-only mount admission also retains refusal for every nonzero volume-information
flag. DIRTY now identifies the actual dirty bit; other unsupported flags return
UNSUPPORTED and do not establish a Windows repair requirement. Unsupported versions
still take precedence. This error distinction neither admits the observed Windows
Recovery volume nor satisfies writable ownership or native recovery qualification.

Private logical LFS/update packet encoding, common-header LFS 1.1 RCRD page encoding,
USA output, native restart-table/entry
framing, composed selected-client checkpoint-dump binding and complete name/dirty
target membership are implemented;
[WRITE-FOUNDATIONS.md](WRITE-FOUNDATIONS.md) defines their exact admission and
publication contracts. They add no device-write capability. Current physical
history, complete checkpoint ownership/analysis and native durability acceptance
remain prerequisites for the writable owner and mutations below.

Logical packet measurement now prepares exact buffer reservations and wire-width
admission. Canonical private serialization preserves opaque operations/targets and
borrowed content while clearing only reserved storage/padding. These helpers do not
resolve native addresses, select live history, plan pages/flags or commit an NTFS
transaction. Their exact-byte/native-input checks cannot enable a writable owner.
The page serializer now supplies canonical private headers and protected sector tails
using caller workspace. The separate LFS 2.0 serializer requires the supported
4-KiB prefix and preserves its opaque DWORD target. Both serializers preserve
opaque LSN/copy fields and the complete borrowed body, rejecting other layouts
and unknown flags. They do not choose page placement,
live history, transfers, flush ordering or a durable native journal publication.

Completed LFS 1.1 observation also admits final circular bytes only inside the
declared written prefix while allowing earlier unfinished segments beyond their
NextRecordOffset. Separate-transfer and wrap cases preserve the native distinction
between I/O transfers and records. This closes an ending-prefix framing gap; it
does not establish the complete current history or continuation provenance.
The separate supported LFS 2.0 observer now examines all 32 fast slots and compares
completed copies per target under shared credits. Its conservative conflict,
prefix, fault and quota checks have synthetic qualification. Three unmodified
Windows Recovery packets also pass fast-copy byte observation and selected-client
checkpoint binding/membership with their original owner. This confirms that native
snapshot profile, not the whole current history or Windows continuation ownership;
LOGFILE.md and ACCEPTANCE.md define the narrower contract and acquisition limits.

An optional retained target index now compares all equally newest written prefixes,
retains unresolved-copy evidence and supports exact indexed acquisition without
repeating slot scans. Preparation/reload/fault checks do not select an authoritative
current endpoint, active window or continuation owner. Those boundaries and subsequent
native analysis remain required before recovery can advance this write gate. The
original read environment has no write capability.

A bounded ordered selected-record visitor now verifies complete framing from a caller's
exact LSN through a selected completed endpoint and verifies an observed unfinished
successor header separately. It preserves one whole-operation I/O budget and explicit
partial/refusal evidence. Synthetic window, footer, wrap and failure checks do not
choose the owning client's analysis lower bound, establish native continuation
freshness, reconstruct live transaction state or qualify replay/durability. These
remaining contracts still precede a writable owner and every mutation below.

Clean Windows dismounts supply original LFS 1.1 pages with the known client-restart
flag, including a restart prefix retained in the former LFS 2.0 fast area. The
index qualifies only protected, completed, single-page restart duplicates whose
DWORD target and start/end LSN geometry agree. A separate exact comparison against
the resolved home prefix precedes duplicate exclusion from endpoint selection.
Physical inventory remains visible; missing homes, conflicting bytes, other targets
and transfers do not receive this exception. Candidate comparison pairs reserve
aggregate read credits after the complete inventory and before comparison I/O.
Both unchanged Windows captures now publish their exact two-packet clean interval
and owning checkpoint. The bootstrap Noop remains an observed active transaction
epoch; this evidence does not authorize replay or writes.

Complete physical page inventory is now implemented under explicit whole-scan
credits, without allocation or source mutation. All copy slots and circular pages
remain observable, including structural errors and unsupported targets; backend
errors terminate exactly. The original Windows journal's complete metadata scan
and four-packet selected-page window pass independent byte comparison. Neither
the maximum observed header LSN nor RSTR CurrentLsn is an authoritative current
endpoint. Full competing-copy resolution, ordered continuity, continuation
ownership and native transaction analysis remain required before recovery.

An explicit transaction-chain visitor now checks the selected client's retained
previous-LSN chain, packet identity, update spans and undo-next membership before
marking the chain complete. Copied whole-operation limits and caller-owned link
scratch bound reads and verification work. It observes raw control markers without
choosing redo/undo state; callbacks must retain partial analysis privately. This
closes a chain-binding primitive, not checkpoint analysis, native recovery or the
write gate. Original Windows transaction and interrupted-recovery witnesses remain
required. See LOGFILE.md for the exact contract.

Checkpoint transaction traversal now acquires the owning checkpoint internally
and binds allocated physical table keys to complete previous chains, stored first
LSNs and undo-root membership. All seeds are admitted before chain callbacks;
checkpoint and chains share aggregate I/O/record ceilings. Empty and absent tables
remain distinct. This adds checked inputs for later analysis, without advancing
native state through post-checkpoint records or deciding redo/undo actions. The
unchanged original Recovery journal has no transaction anchor. Positive native
transaction histories, continuation ownership and interrupted Windows recovery
remain required before enabling writes.

The next implementation and acceptance sequence is:

1. Qualify the private bounded history owner, executed redo/compensation and
   tail-copy/retained-root publication against Windows at every intermediate
   state. It owns an exact quiet origin and at most 64 complete transaction
   families, independently of RSTR CurrentLsn. Unknown families, checkpoint
   advancement, circular wrap, growth and `$UsnJrnl` remain refused. This does not
   replace complete arbitrary native checkpoint/current-history analysis.
2. Provide the FSKit owner with an authorized exclusive transport, real persistence,
   serialized mutation and coherent immutable-view replacement. The private C
   writer already reserves work, validates complete reconstructed metadata before
   mutation, closes read owners and poisons uncertain I/O. Keep product mutation
   admission closed until its native recovery and persistence gates pass.
3. Qualify bounded writes to existing initialized file ranges without allocation
   or size changes, with explicit partial-write and fsync semantics. Interrupt
   writes/barriers and verify recovery, metadata and data against Windows/chkdsk.
   Private timestamped writes and executed interrupted recovery now pass actual
   image I/O and injected failure checks. Actual power interruption, the new
   Windows publication sequence and FSKit acceptance remain open.
4. Expand to allocation, resize, creation, deletion and rename, with dedicated
   namespace/security/lifetime and crash tests for each mutation family.

Portable history/table decoders, transaction planning and injected failure models
can be implemented without a VM. Synthetic evidence cannot replace native NTFS
history acquisition, Windows recovery roundtrips or actual device durability checks.

A writable owner must exclusively claim the device, reject Windows hibernation
and Fast Startup state, validate volume/log versions and process native NTFS
$LogFile restart areas and redo/undo records. $UsnJrnl is a change journal, not a
replacement for $LogFile. An incompatible private journal would not give Windows
a recovery contract and must not be presented as native NTFS write support.

The read-only primitives in LOGFILE.md now validate bounded restart/client/page/
LSN/record framing, empty/nonempty-LCN update spans and lossless name-dump framing.
They neither choose a complete
post-crash journal history nor execute recovery. Clean hints and structural parser
success never satisfy writable ownership or permit a dirty mount. The separate
logical-source owner selects only compatible supported restart copies, retaining
bounded conflicts and backend error evidence; physical page reading does not
establish a post-crash journal history. Counted read-only stream binding is now
implemented without admitting dirty mounts. Physical wrapped-record assembly now
has bounded exact-byte/read/fault checks, but does not establish written/current
history or qualify continuation provenance. Native journal admission/drain,
complete qualified tail/fast-copy history, active circular history, native client checkpoints,
transaction analysis and native crash/durability qualification remain required.
An executable in-memory reference model now exercises serialized ownership,
WAL/commit/home/checkpoint ordering, partial writes and interrupted replay; see
[RECOVERY-MODEL.md](RECOVERY-MODEL.md). Its typed history is not an NTFS journal
format. Native transaction/recovery integration and broader crash/durability
qualification remain required.

Selected-client checkpoint acquisition now captures the stored restart and all
referenced dumps in caller-owned immutable record storage. Identity and the whole
anchor set precede table reads; all packet reads share one operation budget and
optional tighter call/byte ceilings. Complete binding, entry/free topology and
cross-table membership precede publication. Failure retains acquisition evidence
without publishing a partial snapshot; successful value-only views survive source
close with their caller-owned bytes. This supplies recovery analysis inputs, not
current-history liveness, transaction semantics, continuation freshness or native
recovery/durability acceptance. The read environment still has no write method.
The independent client restart decoder observes only the 64-byte common prefix
for client formats 0.0/1.0. Its raw analysis/table LSNs and byte counts authorize
no table reads, transaction state or recovery; containing-record ownership,
selected current history, complete checkpoint tables and optional extensions
must be qualified separately.
Selected-client record binding now checks the exact assembled framing, RESTART
type, active index/sequence, exact NTFS client name and stored restart LSN before
prefix interpretation. This cached snapshot match establishes no native page
provenance or current written history and cannot advance writable qualification.
The composed checkpoint decoder also checks the exact table anchor, dump identity,
action/body length, complete free topology and every allocated versioned entry.
Original historical packets pass under explicit synthetic selected-owner
projections; unchanged original owners refuse those old checkpoints. The full
snapshot now checks distinct dump LSNs and name/dirty targets against allocated
physical OAT keys. Stored self-references never replace those keys. Volume references,
current page/copy history and native analysis remain required.

The future product transaction module owns private snapshots, MFT/$Bitmap reservations,
attribute-list growth, directory B-tree changes, $Secure references and rollback.
Define lock ordering and credits before allocation. All referenced data must be
initialized before metadata publication. FILE/INDX sector fixups must be generated
from a complete private record; no in-place partial metadata edits are allowed.

Commit requires a real device persistence primitive through every volatile cache,
write-ahead log ordering, durable commit publication, recoverable home writes and
checkpoint advancement. FSKit callback completion or metadataFlush alone must not
be called a persistence barrier. An uncertain I/O or barrier failure poisons the
writable owner and retains recovery evidence. Licensing cannot prevent safe flush
or unmount, nor change the bytes committed by a transaction.

Acceptance must interrupt every boundary and each sector of metadata writes;
compare replay by this implementation and Windows, run independent chkdsk, and
verify user data, allocation, links, security IDs and rename atomicity. Cover ENOSPC,
failed log growth, device loss, duplicate names, open-unlinked lifetime, mmap,
concurrent truncation and cancellation. Failed recovery stays failed, never
"repaired" by clearing the dirty flag. NTFS-3G comparison is useful but cannot
replace Windows roundtrips and native recovery verification.
