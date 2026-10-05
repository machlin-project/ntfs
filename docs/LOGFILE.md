# Read-only log diagnostics

`ntfs/logfile.h` provides independent byte decoders for the common LFS 1.1/2.0
restart prefix/area, complete client lists, LSN geometry, protected record pages,
exact logical LFS records, NTFS update payloads with empty or nonempty LCN vectors and
the NTFS client's 64-byte common restart prefix for client formats 0.0/1.0.
These byte primitives do not allocate, access a device, mutate input or provide
a write capability.
The ordinary mount and FSKit mutation contracts are unchanged. A successfully
decoded restart page or its clean hint does not authorize mounting dirty media.

The separate logical-source owner now reads bounded restart candidates and selects
compatible redundant copies with conflict reports. These are foundations for
journal inspection. A physical circular-record observer now assembles exact
bytes across adjacent protected pages and one wrap. It does not route legacy
tail/modern fast-page copies, validate the active circular history or interpret NTFS
checkpoint tables. Active restart-snapshot identity now has a bounded pair
lookup and the client restart prefix has a separate decoder; record liveness,
complete native client payload interpretation, transaction analysis,
redo/undo execution and Windows recovery acceptance remain separate work.
LFS version numbers do not establish the NTFS client's payload version.
An already assembled client restart record can now be bound to selected active
snapshot identity before common-prefix decoding. This does not establish its
physical/current-history provenance.
Separate completed-copy observers route legacy tails and modern fast slots with
the contracts below. They do not select an entire current journal history.
The same owner also inventories complete physical storage under explicit scan
credits, retaining every common/target result. An optional bounded retained index
resolves competing written prefixes per target and supports exact record reads
without repeating copy scans; it does not qualify current history.

Separate [native checkpoint framing](WRITE-FOUNDATIONS.md) now checks complete
restart-table free topology and client-versioned open-attribute/dirty-page plus
transaction entries, plus lossless byte-counted attribute-name entries and complete
name dumps. Composed decoders bind exact dump records to a selected-client
restart snapshot, check every allocated entry and validate name/dirty targets
against physical allocated OAT keys. Volume references and qualified current
history remain separate. These decoders do not advance native
replay or writable admission.

The separate [recovery-input owner](RECOVERY-INPUTS.md) now composes the stored
selected checkpoint and retained oldest-to-endpoint packet interval, distinguishes
serialized transaction lifetimes and verifies checkpoint roots. It adds owned
preparation for recovery execution without granting read-write access or replay
authority.

## Bounded selected transaction chain

`ntfs_logfile_visit_transaction` walks an explicit nonzero transaction/root LSN,
newest first, through its stored previous-LSN links. Admission requires a prepared
immutable index, active exact client index/sequence, NTFS client name and retained
nonzero oldest LSN. Every complete packet must be UPDATE, bind the same client and
transaction, decode its update spans and have strictly older, geometrically valid
previous/undo-next links within the retained lower bound. Client lifecycle flags
refuse. After reaching a zero previous link, every nonzero undo-next link must name
a record in that same chain. Reused transaction IDs and unrelated earlier branches
cannot satisfy this membership check.

The caller supplies record and link scratch. At most 4096 records are admitted;
two uint64_t values per admitted record are reserved before I/O, at most 64 KiB.
Scratch accepts byte alignment. The decreasing chain permits binary membership
search without extra reads, giving O(records log records) bounded work. One staging
allocation exists per packet, with no retained allocation. All packet reads use
one operation budget; copied positive limits may tighten, never raise source I/O
ceilings. Discovery/index preparation remains separate. NULL limits inherit those
ceilings and the record policy cap.

Visitors receive borrowed exact packets before final undo membership is known;
retain analysis privately until complete success. They must not reenter the source
or alter private workspaces. Each view's pages/copy counts cover its packet, while
read calls/bytes are cumulative across the operation. Callback errors propagate
exactly. Reports distinguish attempted reads, examined packets, accepted callbacks,
the next unwalked LSN and verified undo references. Source bytes remain immutable;
failure may alter private scratch and never marks the chain complete. A raw most
recent Prepare/Commit/Forget marker is observed, without deciding recovery state.

The diagnostic is
`ntfs-logfile transaction-records LOGICAL_JOURNAL_FILE INDEX SEQUENCE TRANSACTION ROOT_LSN`.
It reports preparation separately, exact packets and complete/partial chain evidence.
This is selected transaction binding, not checkpoint analysis, live OAT/dirty state,
current continuation freshness, redo/undo execution or writable admission. No
positive Windows transaction chain is qualified by the small Recovery checkpoint,
whose observed packets have transaction zero.

## Checkpoint transaction roots and chains

`ntfs_logfile_visit_checkpoint_transactions` acquires the complete selected
checkpoint itself, then uses each allocated transaction entry's physical
table-relative byte offset as the packet transaction key. It does not accept
caller-projected table views. Every seed is admitted before chain I/O or a
callback: first/previous LSNs must be nonzero, retained, geometrically valid and
ordered before the transaction dump; a nonzero undo root lies in that interval.
An empty UNINITIALIZED entry requires zero links and credits. Other incomplete
link combinations refuse. Free entries remain opaque.

Each nonempty seed walks the complete previous-LSN chain through zero, preserving
exact selected-client/key binding and every packet's undo-next membership. The
oldest packet must equal the stored first LSN, and the stored undo root must be a
member of this same chain. Raw state, undo credits and control markers remain
observations. They do not establish winners, losers or native recovery actions.

Positive copied limits cap allocated transactions and the aggregate examined
chain records at 4096 each by default. One read-call/byte budget covers the entire
checkpoint acquisition and every chain; neither explicit nor inherited limits
raise the source ceiling. Record credits are never reset per transaction. The
caller supplies disjoint private checkpoint/name/record/link workspaces; links
reserve two uint64_t values per admitted chain record before any I/O, at most
64 KiB, and are reused between chains. Byte alignment is accepted. The API header
defines capacities, lifetimes and exact partial counters.

A callback receives a borrowed seed and its fully bound chain report. A later
transaction can still fail, so keep all analysis private until the outer report
is complete. Callback failures propagate exactly. A present empty transaction
table completes without chain reads; an absent anchor returns NOT_FOUND after
checkpoint acquisition. The regular-file diagnostic is
`ntfs-logfile checkpoint-transactions LOGICAL_JOURNAL_FILE INDEX SEQUENCE`.
Preparation is reported separately; tool ceilings are 8192 reads/16 MiB, with
4096 transactions/aggregate records and a 1-MiB retained index.

This qualifies bounded checkpoint-root binding. It does not process records after
the checkpoint, choose current continuation ownership, reconstruct live native
OAT/dirty/transaction state, execute redo/undo or admit writes. The original
Recovery observation has no transaction-table anchor; synthetic positive cases
cannot supply that missing native witness.

## Selected-checkpoint dump binding

`ntfs/checkpoint.h` exposes `ntfs_logfile_checkpoint_table_decode`. It accepts an
immutable selected journal owner, one exact assembled client RESTART record, a
named table kind and one exact assembled dump record. The cached restart binder
first checks the active NTFS client index/sequence, stored restart LSN and exact
common framing. Its zero/zero anchor returns NOT_FOUND without inspecting the
table pointer or size; inconsistent fields are CORRUPT. A present anchor must
address the selected circular geometry and precede the checkpoint.

The dump must match that anchor LSN and client identity, have UPDATE type and the
matching dump opcode. Nonzero previous/undo-next links must address the selected
geometry. The update requires an empty LCN vector, no undo operation/data and an
exact advertised redo-body length. Identity/LSN mismatches return STALE; unsupported
action or entry-layout families return UNSUPPORTED. Underlying framing failures
retain their decoder result. Complete restart-table free topology and every
allocated versioned entry are checked before publishing a result; stale free
payloads stay opaque. A name dump requires the exact whole-list terminator.

The output includes the client version, checkpoint/table LSNs, a body span relative
to the supplied complete table record and typed metadata with spans relative to
that body. Caller-owned buffers outlive these borrowed spans. Decoding performs no
I/O or allocation, accepts byte alignment, keeps disjoint inputs immutable and
zeros the output on every error. Native admission remains necessary before cached
use. This establishes snapshot identity and packet framing, without current written
page/continuation provenance, cross-table target membership, volume bounds,
transaction analysis or recovery.

The independent author supplies 147 cases across client 0/1, ordinary/extended
record headers, absent/inconsistent/future anchors, foreign identities, every
selected prefix truncation, action/body mismatches, complete free topology, stale
free entries, names and a maximum redo-length-fitting OAT. Core and CLI compare
exact numeric oracles; guarded aligned/unaligned calls arm the next read/allocation
failure and prove no callback occurs. The composed fuzz envelope has named lengths
for a logical source and both exact records. Structured mutations separately reach
restart pages, client fields, the dump envelope and complete table bodies; generic
mutations still damage all gates. Three fault variants produce 441 binding seeds.

Original historical observation acquired ten nonempty RESTART records and their
26 exact open-attribute/name/dirty-page dumps. All old checkpoints are STALE under
their unchanged original selected owner. Three original current checkpoints have
twelve absent anchors. Positive binding uses ten explicitly synthetic owner
projections: the selected original restart page is copied to both slots, four named
LSN/length fields change and USA is resealed. Every byte after those two restart
pages, including the historical records, stays exact. Those projections pass
26 present and fourteen absent bindings. They provide no original current nonempty
checkpoint, authoring-OS, native recovery, Windows or writable qualification.
Evidence is `artifacts/checkpoint-binding/native/` and
`artifacts/historical-checkpoint-observation/restart-assembled/`.

## Complete checkpoint target membership

`ntfs_logfile_checkpoint_decode` composes all four dump bindings from one exact
selected-client RESTART record and publishes one borrowed snapshot. Every present
anchor must have a distinct LSN. Name entries and allocated dirty-page entries
must address an allocated open-attribute entry by its physical table-relative
byte key. Client-0's opaque stored self-reference is never substituted. Several
dirty entries may share a target. Supported snapshots refuse two name entries
for one target with CORRUPT; identical names on different targets and unnamed open
entries remain valid. Nonempty names/dirty entries require a present OAT with
allocated targets. Free dirty payloads stay opaque.

Key lookup is constant work over checked fixed-stride storage. The full walk is
linear in supplied table/name bytes; duplicate-name checking uses one caller-owned
bit per OAT entry. Required scratch is ceil(entry_count / 8), at most 8 KiB. A NULL
required workspace returns INVALID; short storage returns RANGE before scratch
access. An empty name list needs no workspace. Admitted scratch may change on
failure; bytes beyond its required prefix remain untouched. All source/record bytes
remain immutable and errors leave the complete output zero, without I/O/allocation.
The presence mask distinguishes absent zero views; table spans retain the same
record/body provenance and externally serialized caller lifetime as the single-dump
API. Inputs, mutable workspace and output are disjoint and accept byte alignment.

Membership does not validate MFT sequences/types, volume geometry, physical LCNs,
stored LSN/transaction semantics or current page/continuation provenance. It cannot
authorize analysis, replay or a writable mount. Independent historical observation
finds all name/dirty targets allocated and name targets unique in ten original
old checkpoints; their positive selected-owner qualification remains explicitly
synthetic, with stale refusal under unchanged original current owners.

The independent author supplies 136 graphs across four client/header owners,
every table-presence mask, free/interior/header/out-of-range keys, duplicate names,
repeated dirty targets, missing OATs, colliding LSNs and exact/short/NULL scratch.
Guarded core tests compare thirty numeric fields, the independent workspace oracle,
aligned/unaligned immutable packets, repeat calls and armed no-callback counters.
CLI reports compare the same numeric oracles. A composed fuzz wrapper preserves
named source/checkpoint/four-dump lengths and separately mutates the source, client,
record envelope and table bodies; 408 seeds cover three fault variants per graph.

Native C/CLI qualification passes ten projected nonempty graphs, ten historical
STALE cases under unchanged original owners and three original current empty
snapshots. All 23 checkpoint files and 26 unique dumps compare directly to retained
originals. The thirteen copied sources match their preceding qualification inputs;
every projected journal byte after its two restart pages matches its original.
Evidence is artifacts/checkpoint-snapshot/{initial,native,final}/ and review.json.
These cases establish membership, without original current nonempty history or
Windows/recovery/writing qualification.

## Complete selected checkpoint acquisition

`ntfs_logfile_capture_checkpoint` acquires the active NTFS client's stored restart
and all referenced table packets through the prepared target index. The caller
supplies the exact client index/sequence, one record workspace and independent
name scratch. Free/stale identities and other client names refuse before reads;
an absent stored restart returns NOT_FOUND. Caller-supplied restart/table packet
projections are not inputs to this acquisition API.

One operation counter covers every selected page for the restart and all dumps.
Optional positive capture limits are copied at admission and impose a further
call/byte ceiling beneath the source's unchanged limits. Index preparation and
source discovery remain separate operations. All anchor pairs, circular geometry,
ordering before the checkpoint and distinct dump LSNs are checked after restart
binding and before any table read. Actual spanning records require MULTI_PAGE;
byte extents, intermediate page boundaries and the completed ending witness must
agree. Indexed copy/continuation admission retains its existing limitations.

The operation stages one exact bounded packet at a time, copying it into the
workspace only after successful assembly. The restart is first; present dumps
follow in checkpoint-kind order without alignment padding. The complete binding,
free topology, allocated entries and cross-table name/dirty membership must pass
before the value-only capture is published. Errors zero the capture. The separate
report retains the requested packet LSN, attempted reads and successful packet
counts/bytes; its complete flag describes acquisition and binding alone.

There are at most five packet acquisitions, at most 5 MiB of caller record storage
used and at most one 1-MiB private staging allocation at a time. Short remaining
record capacity returns RANGE. Name scratch retains the existing exact needed
prefix contract. Workspaces can change on error; untouched capacity stays intact.
All inputs/output/workspaces require disjoint, externally serialized lifetime.
Successful record bytes and capture metadata contain no source-owned pointers
and remain usable after source close while the caller retains them. Body spans
are still relative to the corresponding dump packet; the client extension span
is relative to the checkpoint payload. Opaque extensions and raw analysis/LSN
values are preserved.

The diagnostic is `ntfs-logfile checkpoint-capture LOGICAL_JOURNAL_FILE INDEX
SEQUENCE`, with bounded index/I/O policies and exact concatenated packet bytes.
Original fixtures currently cover 144 acquisition/refusal profiles, including
both client versions, all table-presence masks, both legacy slots/all 32 fast slots,
extended headers/payloads, invalid identities/anchors/membership, a large OAT,
the exact 1-MiB record limit and a wrapped checkpoint. Their 78 complete profiles
have 310 independently authored exact packet oracles. Read/allocation failure
sweeps, aggregate call/byte limits, short workspaces, unaligned guards, immutable
media and source-independent snapshot lifetime are separate executable checks.

This supplies an owned checkpoint input snapshot. It does not choose the current
client history or analysis lower bound, establish continuation freshness, validate
volume references/LCNs or reconstruct transaction state. Native analysis,
redo/undo recovery, persistence and writable admission remain separate gates.

## Empty LCN vectors and attribute-name packets

The stored NTFS update prefix reserves one LCN slot even when its declared count
is zero. The fixed fields occupy 32 bytes and this stored prefix occupies 40 bytes;
redo/undo offsets are absolute offsets from the client payload start. The unused
slot is opaque capacity, excluded from the returned empty vector. Nonzero bytes
there never become a physical address or require canonical zero padding. Compact
or truncated forms lacking that storage return CORRUPT. Empty data spans may use
offset zero; nonempty spans must begin after the complete stored prefix and satisfy
the existing alignment/bounds checks. Extra unused capacity remains uninterpreted.

This resolves the former address-base uncertainty for the observed subset of
original NIST LFS 1.1 packets. All 33 successfully assembled historical open/table/
name/dirty-page payloads use the 40-byte stored prefix and pass exact raw-field/span
comparison. Every reserved slot is nonzero, with twelve distinct values. Three
selected analysis payloads also decode with empty LCN/redo/undo spans; their
additional sixteen bytes remain opaque. One historical dirty-page candidate still
fails physical record assembly and remains a recorded refusal. These are historical
framing observations with unestablished authoring OS, not qualified current tables,
Windows acceptance or replay.

`ntfs_logfile_attribute_name_decode` interprets a four-byte target/byte-length
header, the declared lossless UTF-16LE name and a required zero UTF-16 terminator.
It returns the consumed entry size and a borrowed span excluding the terminator.
No alignment padding follows an entry. Unpaired surrogates and embedded zero units
remain exact stored units. A zero target/zero length header returns END with zero
output; this single-entry primitive leaves following bytes to its caller.

`ntfs_logfile_attribute_names_decode` requires the complete exact dump through its
final four-byte zero header. Missing/truncated endings, odd byte lengths, nonzero
string terminators and trailing bytes return CORRUPT. Both primitives allocate/read
nothing, accept unaligned immutable input and zero output on error. The 1-MiB
record cap bounds the whole linear traversal with constant scratch storage. Returned
target offsets, duplicate membership and attribute ownership still need cross-table
validation. A successful dump establishes no current checkpoint binding.

Independent fixtures cover 91 entry/dump packets, maximum name and packet lengths,
174,762 minimum-size entries, unpaired/embedded-zero units, every selected prefix
truncation, opaque following capacity and exact EOF. The original raw-byte name
observations use 18/32/46-byte dumps of one/two/three unpadded entries. Standalone
commands are `attribute-name ENTRY_PACKET` and `attribute-names NAMES_PACKET`;
their borrowed-span reports carry `recovery_qualified:false`.

The existing table/entry primitives also pass 288 vectors of exact original bytes
from 24 historical packets: fifteen complete OAT/dirty-page tables, 81 allocated or
free open entries and 192 allocated or free dirty entries. Every declared free chain
matches the original topology and every exposed field matches an independent
numeric oracle. Observed client-0 OAT storage uses 44-byte physical entries, while
its opaque stored self-reference advances by a different stride. Name/dirty targets
refer to physical table keys in this observed subset; a self-reference is not a
replacement lookup key. Current checkpoint binding and broader version semantics
remain unqualified. All original packet hashes remain unchanged.

## Logical source ownership and copy reports

`ntfs_logfile_open` takes an immutable logical `$LogFile` byte environment, not a
volume/block-device environment. Its exact read/allocate/release callbacks and
context stay alive until `ntfs_logfile_close`; the caller serializes operations.
An exported regular file can supply this source without mounting an NTFS volume.
`ntfs_logfile_open_volume` instead binds the fixed MFT record 2's unnamed DATA
stream in an already mounted immutable core volume. It uses the usual complete
mapping/list/extension sequence and base-ownership checks. The temporary node
closes before logical-source discovery; a counted public backing stream keeps
the volume BUSY until the journal owner closes. Each independently opened owner
has its own stream. Close releases the journal buffers/object before releasing
that callback context's stream. Native admission/drain integration remains
separate work. No dirty-mount or write policy changes.

Automatic binding supports ordinary fully initialized, unencoded storage. It
explicitly refuses directory, reparse, view/uninterpreted record, encoded/sparse
standard-information or stream flags, and partial initialized-length forms.
This is a bounded system-file policy, not a claim to decode those forms. Invalid
owner arguments/limits fail before metadata reads. Binding errors release the
temporary node and stream and leave the source NULL; pre-discovery failures have
an empty report. Logical read credits/reporting begin after stream construction.
Metadata/run limits and actual physical resource reads retain their own counters:
one logical restart-page read may span multiple physical extents.

Discovery probes offset zero and each possible second-copy position for supported
512-byte through 64-KiB system pages. It therefore finds a valid second copy even
when the first prefix or USA is damaged. A nonzero candidate must claim its own
offset as its system-page size. Full pages have the same checked byte/USA/client
contract as the independent restart primitive. All candidate positions are
examined before publication; resource exhaustion cannot silently make an early
candidate authoritative. Unknown-version/CHKD candidates refuse automatic
selection. Every backend error aborts discovery with its original result, even
when that result is also used for a structural decoder error.

Compatible copies must agree on LFS version, system/log page sizes, declared and
usable file geometry, LSN bit width and record header/data offsets. Increasing
numeric current LSNs select the newer compatible copy. Equal-LSN copies require
identical declared restored restart-area bytes; differing USA protection words
are outside that comparison. Incompatible geometry or divergent equal-LSN bytes
produce CONFLICT and UNSUPPORTED. This conservative refusal does not label every
such native transition corrupt: original Windows lifecycle/resize/version-change
observations are still needed. One good supported copy can be selected beside
missing or structurally bad storage, with SINGLE_COPY visible in the report.

Opening allocates one object and three `max_page_bytes` buffers, with no
journal-sized allocation. Optional retained indexing has a separate explicit
memory bound described below. Defaults are 64-KiB pages and 32 read calls/256 KiB per
operation; discovery has nine candidates and at most 18 exact reads. Both system
and log-page sizes must fit the buffer policy. Read credit is reserved before a
callback, including a failed or partial callback. On failure the owner output is
NULL and all allocations are released. The optional report retains bounded
partial candidate/status/read evidence, clears its selected index and never
publishes a selected snapshot. `scan_complete` means candidate probing finished,
not that a journal history or recovery operation is qualified.

Selected restart/client queries copy immutable snapshots with no allocation/I/O
and preserve original UTF-16 units. Physical page reading checks aligned file
bounds after both restart pages and labels legacy tail, fast storage or circular
storage. It stages the exact read and USA/geometry checks privately, then copies
the restored page to the caller only on success. Every error leaves caller bytes
unchanged and its view zero; failed fills are retryable. This operation does not
route copy-union targets, establish a page's active history or assemble records.

`ntfs_logfile_get_client` retains every stored client entry, including free
entries with old opaque LSNs. `ntfs_logfile_get_active_client` additionally
requires both the requested sequence and membership in the selected active
chain. Absent, free or mismatched entries return STALE with zero output. Sequence
zero and the full 16-bit maximum are compared as stored values. The validated
immutable owner bounds traversal by client count (at most 407 with current page
limits); no additional allocation, callback or read credit is consumed. Raw and
active snapshots preserve complete UTF-16 names. The pair identifies an entry
in that selected restart snapshot; it does not establish a record's lifetime,
written/current page history or the NTFS client's payload version. Future native
admission must still gate cached use after resource revocation.

## Complete physical page inventory

`ntfs_logfile_visit_pages` visits every complete record-storage page after both
restart pages through the selected `usable_bytes`, in ascending physical offset.
This includes both LFS 1.1 tail slots or all 32 LFS 2.0 fast slots, then the
circular area. Capacity beyond selected geometry and a declared partial last
page are excluded. Cached restart/client state is unchanged.

The exact total read count and bytes must fit the source's operation limits
before any read or visitor call. There is one exact read per page and no new
allocation; the existing raw/scratch buffers are reused. The ordinary 32-read
default cannot cover the supported minimum storage geometry. Callers must supply
explicit whole-scan credits; the API never enlarges them automatically. Failed
reads consume their reserved credits and abort with the backend's exact result,
even if that result is also a structural status or the callback filled a complete
valid page. Failed-read bytes never reach the visitor.

Each transient metadata observation reports physical offset, storage kind,
common-page decode result and a separate target result. Missing RCRD signatures
are NOT_FOUND; present but torn/malformed RCRD pages are CORRUPT. Structural
failures remain visible and do not terminate coverage. Successful common headers
stay visible when routing is invalid or unsupported. An unavailable common
decode leaves target_result INVALID. Unknown flags or modern layouts retain an
UNSUPPORTED target result rather than becoming current history.

Known targets must be aligned complete pages inside the circular area. Legacy
tails use the common copy field as a file offset; modern fast pages use the
qualified DWORD field after the common header/USA capacity/padding. Circular pages
target their own physical offset. Circular/modern last-start LSNs require selected
LSN geometry and cannot precede last-end LSN. The LSN's addressed page is not
required to equal this target: continuation ownership remains unqualified.

`max_observed_epoch_lsn` uses last-end LSN for legacy tails and last-start LSN
elsewhere. `max_observed_end_lsn` includes only record-end-marked pages. Both
maxima exclude invalid/unsupported routing and describe observed headers only.
They do not resolve competing copies, prove completed record bytes or select a
journal tail. In particular, RSTR CurrentLsn describes the latest LSN when that
restart area was written; it cannot bound later post-crash records. See the
[original LFS research](https://dfir.ru/2019/02/16/how-the-logfile-works/).

The optional synchronous visitor borrows one const metadata object until return.
It must not reenter/close this owner or mutate the source. Its non-OK result
terminates with that exact status. Partial summary counters remain available:
examined includes a visitor-rejected page, visited excludes it, and `next_offset`
is the first page whose visit has not succeeded. Retry starts at the first storage
page; this is not a resume cursor. NULL visitor collects only the summary.
`complete` requires every physical page and visitor to finish successfully. It
means coverage, including structural failures, without a history/recovery claim.

The regular-file diagnostic is `ntfs-logfile pages LOGICAL_JOURNAL_FILE`. It supplies
4,096 read calls/16 MiB explicitly, emits ordered metadata and the exact summary,
and always reports history_qualified and recovery_qualified false. This bounded
tool neither mounts flagged media nor writes to its source.

Sixty original graphs and 14,729 ordered rows cover all fast slots with LSNs later
than RSTR CurrentLsn, legacy 512-byte/4-KiB/64-KiB pages, missing/torn headers,
unknown flags/layouts, USA/target boundaries, conflicting epochs and unused
capacity. Seven backend statuses at every read position, partial and full-valid
failed fills, visitor stops, retry and exact/short credits pass. Virtual 4-GiB
geometry refuses before reads/allocation. The frozen native Windows journal's
1,170 rows also agree with independent protected source-byte review; its four
complete selected-page packets do not supply a later-than-restart native history.

## Retained target index and exact acquisition

`ntfs_logfile_prepare_page_index` is an explicit optional operation on the immutable
owner. Its positive `max_bytes` bounds one private allocation containing fixed copy
metadata, one entry per complete circular target and one log-page comparison buffer.
This retains metadata rather than the journal's data pages. Required bytes are
measurable on a too-small positive bound. The complete physical scan plus at most
two comparison reads per copy slot must fit the source's read-call/byte credits
before allocation or I/O. Defaults refuse rather than silently increasing limits.

The index chooses the greatest candidate epoch separately for each target. Legacy
tail and circular epochs both use last-end LSN; modern epochs use last-start LSN.
This deliberately differs from the physical inventory's observation-only maximum.
Protected legacy circular continuation pages may have a zero last-start field;
their physical address and last-end remain observable. This establishes no
continuation provenance. Modern fast indexing retains the qualified 4-KiB layout,
including the nonoverlapping DWORD target; unsupported profiles refuse before work.
RSTR CurrentLsn is not used as a ceiling for candidate epochs.

Every equally newest candidate must agree on flags, last-end LSN, NextRecordOffset
and all restored bytes between page_data_offset and NextRecordOffset. USA words,
transfer metadata and unused capacity can differ. The lowest physical offset is
the deterministic canonical candidate. Each compared page is reloaded and its
cached header/target rechecked. A disagreement retains an UNSUPPORTED target and
explicit prefix-conflict evidence. Remaining peers are still read, so a later
backend failure remains visible instead of being hidden by that conflict.
Unknown circular flags block their known target. A chosen copy must have a completed
nonempty prefix; there is no fallback to an older epoch when the newest is unresolved.

One complete preparation can publish missing/corrupt/unsupported target entries.
Unroutable copy evidence stays in separate counters. Unknown copy flags/layouts
also prevent indexed record acquisition globally because their target is unqualified.
Backend, revalidation or allocation failures publish no index, release all temporary
storage and permit a full retry. A second successful-owner preparation returns BUSY
without callbacks. Cached page/report queries require no allocation or I/O;
their function result is separate from each target's retained structural result.
Explicit clear and owner close release the exact retained allocation while cached
restart/client snapshots remain unchanged.

`ntfs_logfile_read_indexed_record` uses this prepared selection with the existing
exact record assembler. It rechecks each selected protected page and target under
one fresh operation budget, with one physical read per successful segment. It
preserves exact unpadded bytes, logical circular offsets, one-wrap bounds and final
written-prefix/RecordEnd evidence. Every failure leaves caller bytes unchanged and
the record view zero. It does not add a continuation-ownership or current-history claim.

The regular-file CLI commands are `ntfs-logfile index LOGICAL_JOURNAL_FILE` and
`ntfs-logfile indexed-record LOGICAL_JOURNAL_FILE DECIMAL_LSN`. Both explicitly
use the named 1-MiB index-memory and 4,096-read/16-MiB policies. JSON keeps
history_qualified and recovery_qualified false and reports preparation separately
from record reads. Large sources can legitimately refuse these diagnostic policies.

Seventy-one original graphs cover seventy published indices and one unsupported
profile refusal, with 14,922 exact ordered target rows. Equal copies, all-slot groups,
independent targets, complete prefix conflicts, newer epochs replacing old conflicts,
future epochs, legacy ordering and unsupported/unrouted evidence pass. The original
109 packet cases preserve 75 complete-byte successes and 34 explicit refusals.
Four whole-operation fault graphs exercise 13,398 partial/full-valid failed reads
under seven backend statuses, including failures after a discovered prefix conflict;
1,582 selected-record read faults and allocation failures also preserve atomic output
and retry. Twenty comparison-header and seven selected-reader header/target changes
refuse STALE. Exact/short/default read bounds, measured memory boundaries, cached
queries, clear/close/BUSY behavior and virtual 4-GiB preflight pass.

The frozen Windows journal's 1,138 target decisions match independently restored
source bytes: 34 selected pages, 1,104 missing targets, nine equal-prefix comparisons
and one visible unrouted copy. Preparation performs 1,188 reads/4,866,048 bytes and
retains 160,552 bytes on the preceding index-only build. All four original packets then
need one selected-page read apiece. This measures acquisition counts and retained
memory, not installed throughput, a clean guest flush or an active-window proof.

Use the selected-record visitor below for bounded framing from an explicit anchor.
Native active-window and continuation ownership still require the selected client's
checkpoint/analysis bounds. Complete checkpoint tables, subsequent transaction analysis
and volume references remain prerequisites for WRITES.md's recovery gate. Matched
cold/hot timing and broader memory pressure measurements remain a separate task.

## Bounded selected-record interval

`ntfs_logfile_visit_records` requires a prepared index, a positive record limit,
disjoint caller workspace and a report. The caller supplies an exact first LSN;
the owning NTFS client must eventually choose its retained analysis lower bound.
The maximum selected RecordEnd/last-end LSN is only an endpoint candidate. The
visitor verifies actual complete headers and declared bodies in order through that
candidate, with checked alignment, adjacent physical payloads, monotonic LSN geometry,
at most one ring wrap and no logical-page revisit. The final record must end on the
candidate's declared target and exactly at its NextRecordOffset. RSTR CurrentLsn
does not restrict the interval. Competing maximum ends, prefix conflicts, unsupported
pages, undated/recent unroutable copies and discarded retained completion tags refuse.
An unroutable copy dated only by an older valid completion tag remains diagnostic
evidence outside the requested framing interval; this is not native liveness proof.

NextRecordOffset can identify the beginning of a spanning record, rather than its
end. A matching last-start witness keeps the next boundary on the same page; a
closed prefix advances to the next physical payload. Full continuation fragments
have no intervening record starts or ends. The declared record byte extent controls
assembly, while transfer count/position never delimit it. A matching legacy circular
page can supply spanning bytes beyond a completed tail prefix whose equality was
already checked. A single incomplete modern copy can supply such framing; unresolved
equal incomplete peers refuse. Modern zero-start continuation ownership remains
unqualified and is not admitted by this path. Legacy zero-start segments provide
framing evidence, without establishing their native freshness or ownership.

A greatest observed last-start LSN beyond the completed candidate must identify its
immediate successor on the same or next physical payload. Its exact complete header,
declared spanning length, links and free boundary are checked separately. The body
remains incomplete; the visitor never receives that tail as a complete packet.
Legacy tail-only pages may have no observed start LSN because their common field
is a physical target. An exhausted sequence cannot invent a representable successor.

Each record uses one bounded private staging allocation and publishes exact unpadded
bytes into the transient caller workspace after assembly. All record and optional
tail reads share one operation budget; it never resets per record. Visitor read
counters describe that packet's successful physical segments. Report read counters
also retain failed attempts and optional tail-header reads; copy_pages_read counts
completed assembled packets. A callback failure counts the examined packet but
does not advance visited_records. A record/quota/read/allocation/footer failure
preserves partial evidence; no report is a resume cursor. Workspace is temporary
and can contain a prior packet even on failure. Only complete means that the entire
requested selected framing interval and its optional observed tail finished. Consumer
analysis must retain its own private state until this result is accepted. This API
does not qualify client ownership, current native history, transaction semantics,
replay, clean guest flushes or device durability, and cannot enable writes.

The regular-file CLI is `ntfs-logfile records LOGICAL_JOURNAL_FILE DECIMAL_FIRST_LSN`.
It explicitly caps index memory at 1 MiB, the walk at 4,096 records and I/O at
4,096 calls/16 MiB, with one 1-MiB record workspace. JSON preserves complete emitted
packets and partial reports while history_qualified/recovery_qualified remain false.

The original 123 windows contain 65 complete results and 58 refusals, with 861 exact
emitted packet oracles. They cover all copy slots, multiple records per page,
extended headers, padding and closed-prefix gaps, independent transfers, spanning
records, wrap, partial headers, routing/completion regressions, duplicate ends,
unknown flags, exact/excess record cap, maximum pages and sequence ceiling. Direct
core checks also fail every read/allocation in three distinct successful windows,
retry the same owner, stop visitors and exercise clear/index lifetime. A 600-record
source prepares within the physical-page budget, then refuses when the shared call
or byte credits run out; per-record budget resets are not accepted.

## Physical circular-record observation

`ntfs_logfile_read_circular_record` locates a complete first header through the
selected restart geometry and the caller's LSN. A different stored header LSN
returns STALE. The declared header/client length controls assembly: subsequent
physical pages contribute bytes beginning at `page_data_offset`, without another
record header. USA restoration precedes every copy, including a header or payload
intersecting a protected sector tail. Extended header bytes remain exact and
opaque. Final alignment padding is excluded from the returned record bytes.

Assembly can move from the last usable page to the first circular page once;
it never revisits a physical page. The unique payload capacity, caller capacity
and named 1-MiB record cap are checked before allocation. A single ephemeral
allocation stages the exact record while one shared read budget covers every
page; it is released on every path. Defaults remain 32 calls/256 KiB per
operation. Some complete records need explicitly larger byte credits: the
direct core test accepts an exact 1-MiB record with adequate custom credits,
while default credits refuse that same source. Errors leave caller bytes
unchanged and the record view zero, including partial reads and a failed later
page. Successful views retain first/last physical offsets, wrap state, page and
logical read counts, and decoded common record metadata. Nonzero previous/undo
LSNs must also fit the selected circular geometry.

This API observes physical framing. It does not use `copy_value`,
`next_record_offset` or `last_end_lsn` to establish written/current history,
select tail/fast copies or prove that continuation pages belong to a post-crash
record. Transfer counts/positions are separate from record segmentation, and
the known record flags remain metadata. Active client identity, checkpoint
tables and transaction interpretation remain separate. Do not use this
observation as an authoritative recovery input.

## Completed legacy tail-copy record observation

`ntfs_logfile_read_legacy_record` adds immutable LFS 1.1 copy routing to the same
exact staged-record assembly. Both tail slots are read before selecting a matching
circular target by increasing `last_end_lsn`. Targets must be aligned complete
pages in the selected circular geometry. A torn or malformed copy is unavailable;
an actual backend error aborts with its original result, including errors that share
a decoder's structural status. There is no preference for the first or second slot.

Equal-epoch copies must have the same flags, next-record boundary and restored
declared written prefix. USA words, transfer counts/positions and unused capacity
are outside that comparison. A newer valid circular page wins; divergent equal
circular/tail prefixes refuse. The selected tail is reread with snapshot header
checks, and every consumed tail byte must fit its declared written prefix.
The ending circular segment must also fit NextRecordOffset; violations are CORRUPT.
Earlier circular segments may extend beyond it: an unfinished record can leave that
field at its own start. Page transfer counts/positions cannot substitute for record
segmentation or continuation provenance.
Unknown page flags, a matching tail without a completed written prefix and modern
LFS 2.0 routing return UNSUPPORTED. A finished record additionally requires a
record-end page whose last-end LSN covers the requested record.

Returned first/last offsets remain logical circular addresses; `copy_pages_read`
counts segments read from tail storage. The shared read credits include the
two-slot scan, every circular observation and every selected-tail reread. One
temporary actual-log-page allocation holds a comparison prefix in addition to the
exact staged record; both release on every path. Cached selected restart/client
bytes remain intact. Errors preserve every caller byte and zero the view.

This is completed-copy observation, not a proof of the entire current history or
continuation provenance. It does not bind checkpoint tables or authorize recovery.
Full fast-page routing and native current-history/analysis remain prerequisites in
[WRITES.md](WRITES.md). The original format notes describe legacy tail copies as
backups that can retain bytes not yet moved to the regular area; see the
[original LFS research](https://dfir.ru/2019/02/16/how-the-logfile-works/).

The independent legacy author now supplies 37 exact C/CLI cases. Ending-prefix
checks include zero/short boundaries, exact/unaligned endings, ten-page records
whose pages belong to separate transfers, wrap and missing completion witnesses.
Six new negative packets reproduced success in the preceding accepted CLI and now
refuse with CORRUPT. Four retained historical completed two-page records preserve
their original bytes; one unfinished native ending page remains STALE. Six original
checkpoint/analysis records are unchanged. The raw circular observation can inspect
bytes that the completed-record observation refuses; neither proves current history.
Current acceptance and main-reviewed artifacts are recorded in ACCEPTANCE.md.

## Completed modern fast-copy record observation

`ntfs_logfile_read_fast_record` observes a completed record in the supported LFS 2.0
profile: 4-KiB system/log pages with the DWORD circular target after the common
header, nine-word USA capacity and word padding. Named wire fields derive its
position; larger declared data and record headers remain supported. A USA array
overlapping that target refuses with UNSUPPORTED. Other page profiles also refuse.

All 32 slots are examined before selecting the latest valid matching copy by its
common last-start LSN. Slot order and transfer count do not select an epoch. Torn
or malformed pages and invalid targets/epochs are unavailable; actual backend
errors retain their exact result. Valid unknown page flags refuse. The observed
client-restart page marker is admitted as framing, not interpreted as NTFS recovery.
A newer valid circular page wins. Equal latest fast/fast or fast/circular epochs
require identical last-end LSN, flags, NextRecordOffset and complete restored
written prefix. USA, transfer fields and unused capacity do not affect that
comparison. Conflicts or an unresolved newest matching copy refuse with UNSUPPORTED.
Selected copies are reread with semantic header/target checks; an observed change
returns STALE, without comparing C structure padding.

Every selected fast segment and the ending circular segment must fit the declared
written prefix. The ending record-end/last-end witness remains required. Earlier
unfinished circular segments can extend beyond NextRecordOffset, as in the legacy
observer; unfinished fast segments are not assembled. Logical first/last offsets
remain circular addresses, and copy_pages_read counts segments supplied by fast
storage. No transfer counter establishes continuation provenance.

One allocation holds at most 2 KiB of slot metadata plus one log page; assembly
separately stages only the exact record. All reads, duplicate comparisons and
continuations share the caller's limits. At least 33 reads/132 KiB are admitted
before allocation or I/O; ordinary 32-read defaults therefore return RANGE. The
CLI's explicit 65-read/512-KiB policy does not silently enlarge the core defaults.
Errors preserve caller bytes, clear the view and release temporary storage.

Seventy-two original graph cases include every slot, latest/equal/conflicting
epochs, torn storage, USA boundaries, extended headers, unknown layouts/flags,
written-prefix limits, two transfers and circular wrap. C also checks all read
positions with five distinct partial backend failures, both temporary allocation
failures, exact/short credits, zero-I/O default refusal and seven successful-read
header changes followed by fresh retries. Whole record goldens, immutable sources
and 104 new fuzz envelopes have separate main review; all 2,378 prior inputs remain
unchanged. ACCEPTANCE.md records full host evidence.

This is per-target completed-copy observation. It does not establish the complete
current circular history, client/table liveness, continuation ownership or native
recovery. Its 72 graph cases are synthetic. A separate unmodified Windows Recovery
journal now supplies three complete native packets through one newer fast copy:
the selected current restart, open-attributes dump and names dump. Direct main
comparison with independently restored source bytes and selected-owner snapshot
membership pass. This confirms that observed wire profile and per-target route;
it does not establish full post-crash history or durability. ACCEPTANCE.md records
the frozen acquisition, volume-admission refusal and remaining WRITES.md gates.

## NTFS client restart common prefix

`ntfs_logfile_client_restart_decode` observes the 64-byte common prefix of an
already acquired complete NTFS client restart payload. This is distinct from
the LFS restart-page area and has its own major/minor fields. Client 0.0/1.0 are
accepted; other versions return UNSUPPORTED with zero output. The decoder accepts
byte-aligned immutable input, performs no allocation or I/O, refuses payloads
larger than the named 1-MiB record cap and reports shorter common prefixes as
CORRUPT. Input and output must be disjoint. Named fields are published into a
zeroed output only after all prefix gates; padding and every error output stay
zero.

It retains the raw analysis LSN and four LSN/byte-count pairs: open attributes,
attribute names, dirty pages and transactions. Zero or maximum fields are
observations, not a presence or range decision; the decoder deliberately preserves
even apparently inconsistent pairs. They do not authorize reads, allocation,
table traversal or recovery. The caller must separately qualify the containing
LFS record, selected active client, written/current history, table geometry and
ownership. Optional data after the common prefix is an opaque relative span,
including a one-byte tail or a bounded maximum-size tail. A successful prefix
decode makes no claim that an optional extension is complete or valid. No USN,
table contents or extension version semantics are inferred.

`ntfs_logfile_decode_client_restart_record` takes the immutable selected owner
and an exact already assembled LFS record. It uses the selected record-header
length, including opaque extended header bytes, then requires RESTART type,
selected active index/sequence, the exact four UTF-16 units `NTFS` and equality
with that client's nonzero stored restart LSN. These gates precede payload
interpretation. Absent/free/mismatched identity or LSN returns STALE; a different
known record type or client name returns UNSUPPORTED. Common-record framing and
prefix errors retain their decoder result, including a corrupt sentinel client
index. All errors zero output; neither source/record bytes nor cached state change.

Binding is bounded by the cached client count and allocates/reads nothing. Its
1-MiB cap covers the entire LFS record, so the allowed client payload is smaller
than the standalone payload cap by the selected header length. The returned
extension span remains relative to client payload bytes. The supplied bytes must
still have independently qualified page integrity and continuation/current-history
provenance before recovery use. A snapshot match does not prove registration
lifetime or a complete checkpoint. Native admission remains necessary for cached
queries after revocation; no FSKit journal owner is introduced here.

## Byte and resource contract

The immutable input, output structure and caller-owned scratch must be disjoint.
Page decoding needs scratch equal to the page size, with byte alignment. Only
successful scratch is publishable: restoration may change it before a later
structural error. All output structures are zero on failure. Restored scratch
retains the original USA/header bytes with sector tails replaced; it cannot be
passed back as an original protected page.

Named byte-array wire structures define every field in `core/disk.h`. The common
restart prefix is 30 bytes; the next word belongs to the USA rather than a falsely
required 32-byte header. The existing atomic USA verifier uses its fixed 512-byte
stride independently of a device's logical sector size. Every tail is checked
before restoration, and the array must fit before the declared area/data offset.
Unknown versions are rejected before assuming their integrity mechanism.

The parser caps each page at 64 KiB and each logical record at 1 MiB. The observed
file-size ceiling is 4 GiB; decoding does not allocate a journal-sized buffer.
Page powers of two, declared/available/usable lengths, restart/client spans,
header alignment and minimum usable geometry are checked. LSN offset/sequence
widths cannot produce an undefined shift or overflowing byte conversion. Offset
widths may reserve more than the minimum file-address bits, as documented by the
original format research. Nonzero LSNs must address a complete record header in
the circular area, outside restart/tail/fast-page storage and page headers.

Both free and active client chains must cover their bounded array exactly once,
with consistent backward links. A 52-byte visited bitmap prevents cycles and
duplicate membership without allocation; the 64-KiB fixture holds 407 clients.
Active client LSNs undergo geometry/current-LSN checks. Free records may retain
stale LSNs from a former client lifetime. Names preserve up to 64 UTF-16 units,
including unpaired surrogates. Traversal is linear in the bounded client count.
Raw flags and page copy-union values remain visible without inventing a recovery
decision from them. Page transfer positions are distinct from record segmentation.

Logical LFS decoding requires the exact assembled header/client length, excluding
trailing alignment padding. It retains transaction/client identifiers, previous
and undo-next LSNs, known record flags and opaque client bytes. A qualified
history reader must first establish which pages belong to that record. The NTFS update decoder
checks the complete LCN vector and aligned, bounded redo/undo spans; the spans may
share bytes. Target identifiers, operation codes and LCN values are metadata,
never physical write addresses.

Published NTFS update notes describe a reserved first LCN slot, while the
NTFS-3G recovery utility uses a different offset base when no LCN follows. The
current update decoder explicitly returns UNSUPPORTED for that variant as soon
as its shared prefix through the LCN count is available. It does not presume a
full target-VCN layout for shorter packets. The LFS record decoder still preserves
the original client payload. Do not resolve this
disagreement by silently choosing an offset formula; obtain original Windows
packets and independent observations. Checkpoint table bodies and optional client
restart extensions remain opaque, and unknown LFS record types/flags, CHKD and other page versions are
unsupported. Erased/missing restart storage is not treated as a valid clean page.

## Diagnostic and qualification workflow

The packet modes of `ntfs-logfile` read bounded regular files opened read-only. They decode an
exported restart page, record page with an independent restart configuration,
already assembled LFS record, NTFS update payload or client restart common prefix.
They do not mount an image
or report the journal/volume as consistent. Successful JSON reports retain
`recovery_qualified: false`; a decoder error exits one with zero metadata, while
transport/argument/configuration failures exit two. The `journal` mode uses exact
bounded reads from a regular-file logical source rather than loading the entire
export. JSON retains every candidate result, read accounting, selection and the
selected lossless restart/client metadata, or NULL selected metadata on failure.
`volume-journal` reads an NTFS regular-file image through the portable core's
ordinary read-only mount and counted stream binding. It closes the journal,
then the core volume, then the image; it does not perform a native mount. A
mount/binding failure still produces a bounded report with no selected metadata.
Ordinary dirty-media rejection remains in force, and every mode retains
`recovery_qualified: false`.
`circular-record` takes an exported logical source and a decimal LSN. Its JSON
retains exact assembled bytes as `bytes_hex`, common record metadata and physical
assembly/read accounting; record, assembly and bytes are NULL on error. It uses
default credits and reports only the physical observation described above.
`active-client` takes an exported logical source and decimal index/sequence
values. It reports the selected active entry or NULL with its lookup error;
it does not read record content or change any recovery qualification.
`client-restart-record` takes an exported logical journal and an already assembled
record packet. Discovery selects the cached snapshot; binding makes no further
source reads or allocations. Its JSON has the same prefix fields and zero-error
contract as `client-restart`, with its own scope and `recovery_qualified: false`.
Both inputs are opened read-only and remain unchanged. Packet and source transport
errors exit two; discovery/binding/decoder reports exit zero or one as usual.
`checkpoint-table JOURNAL CHECKPOINT_RECORD KIND TABLE_RECORD|-` reports the
composed cached binding, body span and complete typed table/name metadata. KIND is
`open-attributes`, `attribute-names`, `dirty-pages` or `transactions`; `-` supplies
no dump for an absent anchor. The report preserves the requested kind separately
from its zero-on-error decoded fields and keeps `recovery_qualified: false`.
Input files remain read-only; malformed transport arguments exit two.

```sh
.build/ntfs-logfile restart EXPORTED_RESTART_PAGE LOGICAL_LOGFILE_BYTES
.build/ntfs-logfile page EXPORTED_RECORD_PAGE EXPORTED_RESTART_PAGE LOGICAL_LOGFILE_BYTES
.build/ntfs-logfile record ASSEMBLED_RECORD RECORD_HEADER_BYTES
.build/ntfs-logfile update NTFS_CLIENT_PACKET
.build/ntfs-logfile client-restart NTFS_CLIENT_RESTART_PACKET
.build/ntfs-logfile client-restart-record EXPORTED_LOGICAL_LOGFILE ASSEMBLED_RESTART_RECORD
.build/ntfs-logfile journal EXPORTED_LOGICAL_LOGFILE
.build/ntfs-logfile volume-journal NTFS_IMAGE_FILE
.build/ntfs-logfile circular-record EXPORTED_LOGICAL_LOGFILE DECIMAL_LSN
.build/ntfs-logfile active-client EXPORTED_LOGICAL_LOGFILE INDEX SEQUENCE
python3 scripts/fuzz.py --target logfile --seconds 60 --compiler /opt/homebrew/opt/llvm/bin/clang --output artifacts/fuzz-logfile-next
```

`tests/logfile_fixtures.py` authors named fields, independent expected metadata
and restored-byte oracles without importing the parser. Direct sanitized checks
cover error-output and buffer guards, exact restored bytes, all baseline restart
truncations, caller geometry and scratch equality/exhaustion. The CLI checks
every original expected field, transport errors and unchanged packet hashes.
The dedicated fuzz target exercises restart/client/page/record/update/LSN
contracts. Its custom mutator restores and reseals valid USA pages while changing
inner bytes; ordinary mutation also reaches damaged framing and envelopes. Fuzz
process RSS includes sanitizer/corpus overhead, independently of decoder storage.
Actual run counts and retained logs belong in ACCEPTANCE.md and generated reports.

Whole-source fixtures also cover copy selection/conflicts, small/mixed/maximum
pages, unknown versions, cached lossless clients, physical page bytes and torn
record-page rejection. Allocator/exact/partial-backend errors, distinct backend
result codes and page/read-credit boundaries retain separate checks. Source fuzz
repeats reports/snapshots/physical reads, checks allocation/read caps and exact
release accounting, and can restore/reseal either restart copy while directing
mutations into the checked declared restart area. The 2-MiB test envelope now
includes every source fixture, including ordinary 4-KiB system/log pages and
1-MiB files with maximum restart/mixed record-page sizes. Fuzz input/RSS is
independent of the owner's bounded three-page allocation and I/O credits.

`tests/logfile_record_fixtures.py` independently authors protected physical
fragments, exact unpadded record bytes and report metadata. Its 30 source
verdicts cover empty clients, extended headers/page prefixes, header-at-end,
two/three/four-page and wrapped records, mixed/ordinary/64-KiB pages, stale
headers, linked-LSN geometry, unknown framing, missing/torn continuations,
tail-only storage, ring revisit and record/credit boundaries. The direct suite
checks 14 allocation/40 partial-read failure positions, unchanged caller/source
bytes, retry, shared credits and exact-cap custom-policy success. Bound-volume
tests also compare independent record bytes and fail/retry the backing-stream
read and staging allocation. CLI reports compare both exact metadata and bytes.

Circular-record fuzz mode retains its requested LSN in the independent envelope
and separate read/allocation/budget controls. Resealed mutations target a record
header and nearby continuations as well as either restart copy; generic mutations
also reach damaged protection and arbitrary storage. All authored logfile seeds
execute in bounded fixed-file batches before exploration. Twenty-eight record
sources and six fault/control seeds fit the unchanged 2-MiB envelope. Two complete
4-MiB sources (maximum pages and exact-cap record) are explicitly excluded in
`logfile-record-selection.json` and the campaign report; both remain in direct
C/CLI tests. No seed is silently truncated.

`tests/logfile_client_fixtures.py` independently authors seven selected snapshots
and 858 raw/active pair expectations. Chains include empty/all-free, mixed
non-numeric active/free order, LFS 2.0 and the 407-client page bound; free entries
retain old out-of-geometry LSNs. Every client retains a full-length unpaired
UTF-16 name. Direct checks arm backend/allocation failures, compare all metadata
and prove zero cached I/O/allocation with exact source cleanup. The CLI samples
42 exact reports and argument/discovery/transport errors. Source fuzz checks
deterministic active lookup, mismatched sequences and zero errors, adding all
seven complete sources inside the existing envelope. Bound-volume cached tests
also compare active metadata and mismatched-sequence results without I/O.

`tests/logfile_checkpoint_fixtures.py` independently authors 77 common-prefix
verdicts from named wire fields: both client versions, distinct and maximum raw
LSN/count pairs, opaque/extended/exact-cap tails, unknown versions, every shorter
prefix and an over-cap payload. The direct suite checks both aligned and
unaligned input, exact zero padding/error outputs, input/output guards and
immutable bytes. The CLI compares 75 exact JSON reports and two packet-transport
rejections, arguments and unchanged hashes. All 77 complete payloads have fuzz
seeds inside the unchanged 2-MiB envelope. Structured mutations focus on declared
prefix fields, usually preserving the client version gate, while generic
mutations also reach version, truncation and framing errors.

`tests/logfile_restart_record_fixtures.py` independently authors 165 source/record
verdicts and exact prefix oracles. They cover both client versions, zero/maximum
sequence, non-numeric/maximum active chains, newer second selection, LFS 2.0,
extended headers, absent/free/foreign/stale clients, gate precedence, raw boundary
pairs, all shorter headers/prefixes, opaque tails and the complete-record cap.
The direct suite checks both input alignments, guards, zero outputs/padding and
immutable source/record bytes. Armed next-read/next-allocation failures plus exact
counters prove that cached binding performs neither callback, including failure
paths; owner close releases every allocation. The CLI compares 161 exact reports
and four transport checks plus arguments and original source/packet hashes.
All 165 complete source/record pairs fit the unchanged 2-MiB fuzz envelope.
Their separate mode checks deterministic binding/error outputs and guards,
reseals selected restart-copy mutations, and directs record/payload mutations
into context fields or the common prefix while usually preserving identity.

Independent volume layouts place the original logical journal bytes in
contiguous/fragmented runs and resident/nonresident attribute lists. They cover
mixed/maximum restart pages, ordinary 4-KiB log pages, fast storage, torn copies,
conflicts, stale sequence/base ownership, continuation gaps and unsupported
system-file forms. Exact page/report oracles are retained independently of the
core; failed physical reads may fill a prefix before returning an error. Fault
sweeps check every binding allocation/read position in selected layouts, retries,
exact release accounting and BUSY ownership, including two simultaneous owners.
These focused metadata images are not a Windows-authored complete system-file
namespace or whole-volume consistency oracle.

The image fuzz target now opens counted journal owners on mounted volumes and
checks cached clients, staged circular/tail pages, error guards and teardown.
Its seed author uses genuine 1-MiB physical geometry for bounded corpus storage;
larger journal layouts that cannot fit have explicit manifest skips and remain
in the full component/source suites. It does not truncate an 8-MiB volume or
treat a geometry skip as a passed layout. Separate logical-source fuzz retains
all of its original 1-MiB journals under the 2-MiB envelope.

Next work must integrate native journal admission/drain ownership, qualify complete
tail/fast-copy history and validate written/current circular history and continuation provenance,
then qualify client sequence lifetimes and interpret complete NTFS checkpoint
tables/extensions beyond the common prefix. Compare original
Windows 1.1/2.0 packets, including LCN-less records and interrupted writes. Add
transaction/crash/durability simulation under WRITES.md before any writable
environment, and retain native recovery/Windows roundtrips as separate acceptance.

## Format provenance

The implementation and fixture authors are repository-owned. Field/geometry
facts were consulted in [NTFS-3G's original log layout header](https://github.com/tuxera/ntfs-3g/blob/2022.10.3/include/ntfs-3g/logfile.h),
[original Linux-NTFS log notes](https://flatcap.github.io/linux-ntfs/ntfs/files/logfile.html),
[original libfsntfs research](https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20%28NTFS%29.asciidoc)
and [Maxim Suhanov's original LFS research](https://dfir.ru/2019/02/16/how-the-logfile-works/).
The common NTFS client restart prefix was cross-checked against the declarative
`NTFS_RESTART` field layout in [Linux v6.12's NTFS log source](https://github.com/torvalds/linux/blob/v6.12/fs/ntfs3/fslog.c)
and the named payload fields in [Suhanov's original parser](https://github.com/msuhanov/dfir_ntfs/blob/master/dfir_ntfs/LogFile.py).
Only layout facts were used for this original prefix decoder and independent
fixture author; no foreign parser, table/replay or recovery algorithm was imported.
The selected-client record binder reuses the repository's original record,
active-snapshot and prefix contracts. Its gate ordering, complete source/record
fixtures and cached fault/counter checks are original; no foreign registration,
binding or recovery algorithm was imported.
The short offset-base helpers in the separately retained NTFS-3G recovery utility
were inspected only to establish the conflicting LCN-less format fact; no replay,
parser or filesystem algorithm was imported. This is not source-isolated
clean-room work. PROVENANCE.md retains the proprietary/dependency boundary.
