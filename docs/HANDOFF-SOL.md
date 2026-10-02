# Handoff to Sol

Work in `/Users/darekhta/Development/machlin/ntfs`, branch `development`.
Read AGENTS.md, README.md, ARCHITECTURE.md, ACCEPTANCE.md, PROVENANCE.md and WRITES.md.
This is an independent proprietary FSKit product. No kernel adapter or LXNU
changes are included. Publishing source, choosing a public license and enabling
writes are separate decisions.

## Meaning of the requested 60%

The request was to establish roughly 60% of a driver and hand off the remainder.
There was no existing NTFS backlog or effort estimate from which a measured
percentage could be calculated. This delivery establishes six engineering
baselines: repository/process, validated disk decoding, MFT/attributes, stream
reading, indexed namespace and the FSKit app/adapter. This is a concrete partial
driver; it is not evidence that 60% of the total effort or commercial readiness
has been achieved. Writes, native recovery and qualification may dominate the
remaining effort. Use the acceptance matrix rather than a line-count percentage.

## What to preserve

- Freestanding core with explicit allocation/read callbacks and a separate
  proprietary licensing boundary. There is no disk write capability.
- Immutable resource lifetime, counted children, bounded runs/attribute lists/
  directory depth, atomic fixup verification and sequence-checked references.
- Incremental MFT bootstrap through resident/nonresident attribute lists. Only
  already mapped MFT runs may locate the next extension; the fixtures erase the
  original contiguous MFT to catch accidental physical-address assumptions.
- Strict index ordering and inherited key bounds, plus explicit rejection of
  ambiguous folded names across both leaf and separator/child boundaries.
- $UpCase-based lookup, stored-name return, sparse/VDL zeroing, ADS and LZNT1
  handling, including fragmented and partial final compression units.
- Bounded reparse snapshots with independent node lifetime, lossless UTF-16 link
  names and opaque tag classification. Preserve rejection of unsupported provider
  data and all reparse-directory traversal, including attributes whose
  standard-information flag was cleared. Tag classification alone does not decode
  content; known file-provider XPRESS/LZX uses the separately validated owning stream.
- Independent stream flags: an unencrypted ADS remains readable beside an
  encrypted default stream. Exact UTF-16 stream-name matching is documented.
- Complete regular-file size metadata is independent of content decoding. Private
  metadata-only descriptions validate all extents and cannot be read. Preserve
  strict public stream checks and truthful native attributes without exposing
  ciphertext or invented zero sizes.
- Named format constants, wire structures and separate resource budgets. Keep
  fixture offsets and geometry explicit; avoid unexplained numeric values.
- Complete separate legacy/modern FSKit protocol classes. Their read completion
  signatures differ; do not advertise both protocol families on one class.
- A retained resource owner through C callbacks, synchronized operation admission,
  canonical FSItem identities, replayable directory cookies, explicit EROFS for
  every implemented mutation and invalidation of all children before release.
  Resource revocation permanently fails admission, including cached stream reads;
  reclaim and teardown must still release children without device I/O.
- Separate component/build/mount evidence. NTFS-3G reverse-engineered format facts
  are valid engineering references; copying GPL implementation into this closed
  product is not part of the implementation plan.
- Safe build environments. Meson records environment variables in reports. Run
  `make test` through the allowlisted launcher; never dump ambient environments
  or unfiltered legacy Meson logs. Inspect selected test result fields.

## Reproduce local evidence

```sh
make test
make check-style
python3 scripts/check_core.py
make fskit
python3 scripts/test_fskit.py
python3 scripts/bootstrap_test_tools.py
python3 tests/interoperability.py --output artifacts/interoperability-next
python3 scripts/fuzz.py --seconds 60
python3 scripts/build.py .build-release --release
.build-release/ntfs-benchmark artifacts/interoperability-next/ntfs-s512-c4096.img large.bin
```

The interoperability runner refuses to overwrite its image files; choose a new
ignored output directory for a new execution. If Xcode omits libFuzzer, add
`--compiler /opt/homebrew/opt/llvm/bin/clang` to the fuzz command; see DEVELOPMENT.md.
Routine prepared runs belong to
Luna (`gpt-6-luna`); diagnosis, implementation and acceptance belong to the current
main task owner. FSKit VM preparation belongs to Sol (`gpt-6.1-sol`); one agent
owns a VM at a time. Give workers absolute directories and bounded tasks.

## Native lifecycle continuation

Unmount now closes admission using a separate short-held lock before waiting for
the serialized operation. It closes stream/catalog/cursor caches while preserving
nodes and FSItem identity for reclamation. Mount can reopen a drained immutable
owner; deactivation/invalidation is terminal. Concurrent unmount requests cannot
reopen admission before all have drained. Replies run outside the operation
monitor, and a delayed read reports zero bytes on failure after closed admission
or permanent resource revocation.

Eight semaphore-gated read scenarios, overlapping teardown, exact completion
counts, all transient cache kinds and interleaved enumeration passed under
ASan/UBSan, along with the existing namespace fault/budget checks. Style and the
current unsigned app/extension also passed. Three modern-runtime SKIPs remain.
See LIFECYCLE.md and `artifacts/plan-lifecycle-{component-reviewed,style,app-build}.log`.
The subsequent ownership continuation uses weak canonical indexing and each
item's retained volume. macOS 27 reclaim executes cleanup only through the native
eligibility API; older runtimes wait for the last FSItem reference. A separate
publication lock covers activation/lookup replies against reclaim/teardown while
replies remain outside the core monitor. Five modeled eligibility/ownership/
publication cases, all existing legacy checks, style and the unsigned current
app passed under `artifacts/plan-reclaim-{component-reviewed,style,app-build}.log`.
The model proves adapter cleanup ordering, not the real framework/kernel counts.
Do not claim interruption of a native synchronous read, task cancellation,
native reclaim-count qualification or installed lifetime/scheduling from this
component checkpoint. A callback that never returns still prevents draining;
buffers must remain owned until it does. The portable core is unchanged.

The directory-view continuation now adds names-only virtual current/parent
entries, checked numeric parent ownership without retaining parent FSItems,
separate cookie views and native invalid-cookie errors. Stored alias ordinals
remain unchanged. Parent release/remount, corrupt edges, root/nested/empty pages,
interleaved buffers, scan bounds, exactly-once replies and post-packer revocation
passed, including all 12 allocation/four read failure positions in the nested
operation. All 31 sanitized core suites, component, style and the unsigned app
passed under `artifacts/plan-enumeration-{core-tests,component-accepted,style,app-build}.log`.
Four modern-runtime checks explicitly SKIP. LIFECYCLE.md records the exact
contract and evidence boundaries; neither protocol has installed acceptance.

The subsequent metadata/content continuation passes all 32 sanitized core suites,
both freestanding targets, FSKit component, style and the unsigned app/extension.
Regular-file stat validates complete unnamed-stream mappings without requiring a
content decoder or copying resident payloads. EFS-flagged, unknown-compression,
unsupported-unit and empty encrypted metadata retain truthful sizes, including
resident/nonresident attribute-list storage. The core suite checks 18 verdicts
and all 29 allocation/four read failure positions with retry and exact cleanup.
Strict data opening is unchanged; metadata-only descriptions reject every read.

Six legacy FSKit storage variants retain requested attributes and readable
independent ADS while default reads return ENOTSUP, zero bytes and unchanged
buffers. Ten explicit metadata/reparse failures preserve the failed entry on
retry; names-only pages retain the inventory. Remount, permanent revocation and
exactly-once callbacks pass without default-content I/O. Five modern checks
explicitly SKIP: lifecycle, enumeration, content metadata and two case-policy
checks. Logs use `artifacts/plan-stat-{core-accepted,component-reviewed,style-reviewed,app-build}.log`
and `artifacts/plan-stat-freestanding.log`. Bounded mapping-pair and attribute-list
campaigns pass under `artifacts/fuzz-stat-{mapping,list}/`; see ACCEPTANCE.md for
counts and the retained fixture-collision failure. No installed mount,
Windows-authored EFS/compression or decryption acceptance is established.

The native-link continuation now projects a bounded single-edge symlink/junction
subset. Read LINK-POLICY.md before changing it. Explicit drive/GUID task options
bind only to this mounted owner, and numeric ancestry avoids host mount-path
assumptions or retained parent FSItems. Target translation uses the stored
substitute name, per-directory case policy and existing filename aliases, with
one shared raw-entry scan budget. Native type/size reflects emitted target bytes;
original wire packets and physical reparse allocation remain available separately.
Unmount closes counted snapshots while preserving immutable native targets;
raw xattrs reopen after admission. Intermediate reparse chains, multiply linked
reparse objects and cross-volume targets remain explicit unsupported contracts.

All 32 sanitized suites, both freestanding targets, component, style and the
current unsigned app passed. Forty-seven legacy path/storage verdicts and four
fault sweeps (32/eight, eight/three, 36/six and three/zero allocation/read positions)
pass with retry, exactly-once replies and cleanup. Names-only classification now
uses checked metadata without resolving a target; the existing nested operation
passes 33 allocation/13 read fault positions. Six modern checks explicitly SKIP:
lifecycle, enumeration, content metadata, link projection and two case-policy
checks. Evidence uses `artifacts/plan-links-{core-reviewed,component-reviewed,freestanding,style,app-build}.log`.
Image/reparse campaigns also pass under `artifacts/fuzz-native-links-{image,reparse}/`;
counts and the near-cap image-process RSS are recorded in ACCEPTANCE.md. The
Foundation translator itself has component evidence, not this core fuzz coverage.
No installed mount, Windows target acquisition or macOS 27 runtime ran.
Final naming/comment checks use `artifacts/plan-links-{core,component,style,app}-final.log`;
all 47 regenerated images and their expectation manifest remained byte-identical
(`artifacts/plan-links-fixture-final.log`). Those edits preserve the fuzz inputs.

Continue complete reparse resolution, provider content and explicit unknown/
malformed metadata behavior. The packer's nullable argument is not evidence that requested
attributes may be omitted. Preserve truthful metadata and stable continuation,
without hiding objects or inventing ordinary-file sizes. Backend dot lookup and
parent resolution remain separate from virtual enumeration. Bounded checkpoints,
native scheduling and buffer lifetime also remain open.

## Selected-client restart-record handoff checkpoint

`ntfs_logfile_decode_client_restart_record` binds an exact already assembled
record to the immutable selected snapshot before prefix decoding. It uses the
selected extended/common header length and requires RESTART type, active
index/sequence, exact UTF-16 `NTFS` name and equality with the client's nonzero
stored restart LSN. Stale/free/absent identity or LSN returns STALE; foreign
name/type is UNSUPPORTED. Framing/payload errors retain their decoder result.
Errors zero output, source/record bytes stay immutable, and the cached operation
allocates/reads nothing. Its complete-record 1-MiB cap includes header bytes;
extension spans remain relative to client payload bytes. The standalone
`client-restart-record LOGICAL_JOURNAL_FILE ASSEMBLED_RECORD` retains
`recovery_qualified: false`.

Independent fixtures supply 165 aligned/unaligned verdicts across 19 snapshots
and 161 exact CLI reports/four transports. They include maximum/non-numeric
active chains, sequence/name/LSN boundaries, newer second selection, raw prefix
fields, extended headers, every shorter header/prefix and whole-record limits.
Armed next-read/allocation failures and exact counters prove no cached callbacks
on success or failure; close releases all source memory. Numeric oracle-list
indexing was replaced with a named payload key; all 265 authored fixture files
remain byte-identical and three focused suites pass in
`artifacts/plan-logrestart-record-fixture-reviewed.log`.

All 59 sanitized core suites, style, 18 component PASS groups/seven explicit
runtime SKIPs and the unsigned Release app pass under
`artifacts/plan-logrestart-record-*-final.log`. Both app architectures compile
the changed source owner. The unchanged product passed both freestanding
2-KiB targets in the retained initial build/eight-focused-suite/frame logs.
The campaign fixed-replays all 414 authored seeds, including all 165 complete
new source/record pairs, then passes 101,694 executions/61 seconds, coverage
1,065/features 2,687, peak RSS 529 MiB and exit zero under
`artifacts/fuzz-logrestart-record-final/report.json`. Existing complete over-cap
record sources remain explicit campaign exclusions and full C/CLI tests.

This proves selected-snapshot binding, not physical/current-history provenance,
registration lifetime, complete checkpoint tables/extensions or native recovery.
No FSKit journal admission/drain owner, dirty mount or write capability was added.
Continue those full contracts under CORE-QUALIFICATION.md and WRITES.md. No VM,
installation or Windows journal was used.

## NTFS client restart-prefix handoff checkpoint

`ntfs_logfile_client_restart_decode` now retains the common 64-byte prefix for
client formats 0.0/1.0: major/minor, analysis LSN and four table LSN/byte-count
pairs. These client versions are independent of LFS page versions. Unknown
versions return UNSUPPORTED; short prefixes return CORRUPT and over-cap payloads
return RANGE. Input stays immutable, all error outputs/padding stay zero, and
there is no allocation or I/O. Fields publish individually into zeroed output.

Raw zero/max or inconsistent LSN/count pairs remain observable, authorizing no
table read, allocation or recovery. Additional bytes are an opaque relative
span; even a successful prefix does not validate extension completeness.
Containing-record ownership, selected active client/current history, native
sequence lifetimes, complete checkpoint tables/extensions and Windows recovery
remain separate qualification. The standalone `client-restart` diagnostic retains
`recovery_qualified: false` and cannot change the ordinary dirty-mount policy.

The original fixture author supplies 77 verdicts, both aligned/unaligned direct
checks and 75 exact CLI reports/two transport rejections. All 56 sanitized core
suites, style, both freestanding 2-KiB targets, 18 component PASS groups/seven
explicit runtime SKIPs and the unsigned Release app pass under
`artifacts/plan-logcheckpoint-*-final.log`. Both app architectures compile the
changed logfile source. Initial build/eight focused suites/frame evidence remains
under `artifacts/plan-logcheckpoint-*-initial.log`.

The campaign fixed-replays all 249 authored seeds, including all 77 new payloads,
then completes 103,509 executions/61 seconds, coverage 1,033/features 2,677,
peak RSS 520 MiB and exit zero in `artifacts/fuzz-logcheckpoint-final/report.json`.
Both existing over-cap complete record sources remain explicit campaign skips
and full direct C/CLI tests. No VM, installation or Windows journal was used.
The declarative prefix facts/proprietary boundary are retained in LOGFILE.md and
PROVENANCE.md; no foreign parser or recovery algorithm was imported.

Continue full checkpoint-table/extension and current-history ownership work
under CORE-QUALIFICATION.md and WRITES.md. This common-prefix decoder is a
foundation, not complete journal recovery or completion of the no-VM plan.
The current committed decoder also passes the eight-product Release/O3 byte
comparison under `artifacts/reproducibility-logcheckpoint/`; its command log is
`artifacts/plan-logcheckpoint-reproducibility.log`. This is local ordinary-build
evidence, with the separate scope limits below.

## Portable Release reproducibility checkpoint

`scripts/check_reproducible.py --output artifacts/reproducibility-next` creates
two ordinary isolated Meson Release/O3 builds with the same selected toolchain.
It requires committed compiled sources and an unchanged Git revision, verifies
selected options, compares all bytes of two core/backend archives and six CLI
products, and retains per-artifact hashes plus bounded combined diagnostics.
Build errors, timeout and log exhaustion fail; cleanup kills only the process
group owned by that build. It does not rewrite timestamps or normalize products.

The local arm64 check passes all eight products under
`artifacts/reproducibility-accepted/`; launcher/style logs are
`artifacts/plan-reproducibility*.log`. An earlier ordinary-build probe independently
matches them under `artifacts/reproducibility-probe/`. Prepared CI calls the checker
on its macOS/Linux matrix and retains reports/logs. It has not run remotely.
This establishes repeat builds in distinct directories of one checkout, not
relocated-source, cross-toolchain or FSKit app/signing reproducibility. That run
predates the client restart-prefix change above; later compiled source needs a
new comparison.

## FSKit resource I/O handoff checkpoint

`NTFSResource` now transfers a fragment directly into caller storage only when
its disk offset, caller address and complete transfer length satisfy physical
alignment. Other fragments retain the aligned private window, including partial
final sectors. All callbacks remain synchronous and capped at 1 MiB; the fixed
window, 64-MiB core allocation cap and volume serialization remain. Full device
completion and resource availability are required before success. Error paths
may change requested caller bytes, which native handlers discard while replying
with error/zero completed bytes. Outstanding buffer ownership survives through
read completion and teardown drain.

Final component/style/tool/unsigned Release app evidence is under
`artifacts/plan-resource-*-final-fixed.log`: 18 PASS groups/seven explicit macOS-27
runtime SKIPs, 120 resource geometry/fault verdicts at alignments 512/4096/65536,
16 gated direct/window lifecycle cases, four affected tool contracts and actual
resource compilation for both app architectures. The lifecycle double owns raw
aligned storage; `NSMutableData` may rehome a no-copy allocation and break a
test's alignment assumption. Earlier failure/diagnostic logs are retained, and
that test correction did not alter the measured product. Core code is unchanged;
the preceding active-client checkpoint was then the latest full core/frame run.

`scripts/benchmark_fskit_resource.py` builds the real resource at `-O2` over an
original immutable memory reader. It retains the binary, bounds tool execution,
checks source/binary hashes and byte/guard oracles, and alternates reference/current
executions. Reports retain all timings and callback destinations under
`artifacts/fskit-resource-{baseline,direct,offset-repeat}/`: 85 baseline runs,
170 matched runs and 20 longer offset-4-KiB repeats. Aligned 64-KiB/1-MiB wall and
CPU medians fall about 47%/49%, with unchanged calls/bytes and zero inferred bounce
copy; multi-window improvement is about 54%. The longer fallback repeat has
matching median request percentiles and no sustained timing difference.

Use PERFORMANCE.md's measurement commands for the next comparison. Measure real
caller alignment frequency, native transport/buffer lifetime, physical-device
throughput and independent-driver behavior separately. This optimization closes
one measured I/O item; Windows/journal/security/native acceptance and the rest of
CORE-QUALIFICATION.md remain open. No VM, driver installation or Windows run was
used for this checkpoint.

## Selected active-client handoff checkpoint

`ntfs_logfile_get_active_client` resolves an index/sequence pair only in the
selected immutable restart snapshot's active chain. Preserve STALE/zero output
for absent, free or mismatched entries, full field-width sequence comparison,
bounded traversal and no I/O/allocation. `ntfs_logfile_get_client` still retains
raw/free metadata, including old LSNs. Matching an active pair does not qualify
record liveness, written/current history or native client payloads. A future
native journal adapter must apply admission/revocation before cached access.

Seven independent snapshots check 858 raw/active pair queries and 42 exact CLI
reports, including empty/all-free/non-numeric mixed chains, LFS 2.0, the 407-client
bound and full-length unpaired names. Armed failures prove no cached I/O or
allocation; counted volume snapshots retain the same checks. The `active-client`
diagnostic reads exported regular files. All seven whole sources fit the existing
fuzz envelope, which additionally checks active metadata and mismatched sequences.
Actual full-suite/app/fuzz evidence belongs in ACCEPTANCE.md.

All 53 sanitized core suites, style, 17 component PASS/seven runtime SKIPs and
the unsigned app pass under `artifacts/plan-logclients-*-final.log`. The initial
build/nine focused suites and both frame-limited freestanding targets pass under
`artifacts/plan-logclients-*-initial.log`. The campaign replays all 172 seeds and
passes 91,838 executions/61 seconds at peak RSS 515 MiB under
`artifacts/fuzz-logclients-final/report.json`. Both app architectures compile the
changed owner. No native mount or Windows journal ran.

Continue tail/fast-copy routing, written/current record selection and native
checkpoint/table/transaction contracts under the complete no-VM scope in
CORE-QUALIFICATION.md. This lookup does not close those rows or measured
optimization/native qualification.

## Physical circular-record handoff checkpoint

`ntfs_logfile_read_circular_record` now joins exact physical record bytes by LSN
through adjacent protected pages and at most one wrap. Preserve the disjoint
caller/source/output contract, shared operation read credits, no-page-revisit
bound, one exact-size ephemeral staging allocation and unchanged caller bytes/
zero view on error. Nonzero previous/undo LSNs undergo selected geometry checks.
Only the first fragment has a record header; continuation bytes begin at the
restart data offset. Extended header bytes and restored sector tails remain
exact; final alignment padding is excluded.

This is a physical diagnostic observation. It does not establish written/current
history from page copy/last-end/next-offset metadata, route tail/fast copies,
resolve active client identity or qualify recovery. Do not silently promote it
to an authoritative transaction input. The `circular-record` CLI reads an
exported logical regular file and emits exact hex bytes plus record/physical-read
metadata under the same boundary. Bound-volume tests also exercise this API
through counted streams, partial resource reads and staging-allocation retry.

Independent fixtures retain 30 source verdicts and unpadded byte oracles,
including mixed/ordinary/maximum pages and the exact 1-MiB record cap with
explicitly adequate custom credits. Default credits intentionally refuse that
large record. The logfile fuzz envelope retains 28 record sources and six
fault/control seeds; two complete 4-MiB sources exceed its 2-MiB cap and remain
in direct C/CLI checks. The selection manifest and campaign report list those
exclusions without truncating either source. Fixed-file batches execute every
authored logfile seed before exploration. Actual results belong in ACCEPTANCE.md.

All 50 sanitized core suites, both frame-limited freestanding targets, style,
17 component PASS/seven runtime SKIPs and the unsigned app pass under
`artifacts/plan-logrecords-*-final.log`. Record tests pass 30 verdicts/exact CLI
reports and 14 allocation/40 partial-read faults. The campaign replays all 165
seeds and passes 103,760 executions/61 seconds at peak RSS 537 MiB under
`artifacts/fuzz-logrecords-final/report.json`. Both app architectures compile
the changed source owner. No native mount or Windows journal ran.

Continue copy routing and written/current circular-history validation, followed
by native client checkpoints/tables and transaction/crash/durability contracts.
The complete agreed no-VM and separate measured optimization scope remains in
CORE-QUALIFICATION.md. Native ownership, Windows packets and installed recovery
remain separate acceptance.

## NTFS-backed journal handoff checkpoint

`ntfs_logfile_open_volume` now binds MFT record 2's unnamed ordinary initialized
stream through the existing extent/list/sequence/base-owner checks. It closes the
temporary source node, retains one counted stream per journal owner and releases
the journal buffers/object before that callback context. Preserve BUSY unmount
and the same serialized immutable-volume contract. Directory/reparse/view,
encoded/sparse and partial initialized-length forms refuse binding explicitly;
SI flags and actual stream flags are checked separately. Invalid owner policy
fails before metadata I/O. Logical report credits begin after stream construction,
separately from physical I/O and existing metadata/run budgets.

All 46 sanitized core suites, both frame-limited freestanding targets, style,
17 component PASS/seven runtime SKIPs and the unsigned arm64/x86_64 app pass under
`artifacts/plan-logvolume-*-final.log`. Independent volume fixtures pass 24 exact
verdicts/reports, unchanged-image checks, 54 allocation/58 physical-read faults
with retry and two simultaneous owner lifetimes. The CLI's `volume-journal`
mode uses only a portable read-only core mount of a regular file. It does not
authorize dirty mounts or report a qualified journal history.

The image target adds 22 small volume seeds and explicitly skips two physical
layouts that cannot fit its authored 1-MiB geometry; all 24 remain in direct
tests. Fixed-file replay executes all 282 original image seeds at peak RSS
348 MiB. The first single-process campaign's corpus OOM remains recorded; the
retained input passes 2,000 fixed repeats at 337 MiB. Child-process exploration
then passes 55,049 executions/70-second supervisor interval, no OOM/timeout/crash,
with a per-process cap that is not an actual aggregate memory measurement.
All-source in-process fuzz passes 116,814 executions/61 seconds at peak RSS
474 MiB. ACCEPTANCE.md retains exact logs/reports and the corrected author
expectation for foreign extension ownership; do not erase either failed run.

Next qualify routed tail/fast copies and current circular history, then client
sequence/checkpoint/table interpretation and the
transaction/crash/durability model. Native journal admission/drain integration,
Windows lifecycle/version-transition packets and installed recovery/roundtrips
remain separate acceptance. FSKit maintenance remains unimplemented; fresh ext4
history adds unary-load/task-refusal requirements in FSKIT-EXT4-LESSONS.md without
adding maintenance or writable capabilities to this driver.

## Logical log source handoff checkpoint

LOGFILE.md and `ntfs/logfile.h` now define `ntfs_logfile_open` over a logical,
immutable exported journal environment. Do not pass a physical volume environment.
Keep its context/callbacks alive through close and serialize operations. Discovery
probes all nine candidate offsets with page/read caps, selects compatible newer/
equal restart areas and refuses ambiguous or unknown-version copies. Failure
leaves no owner/selected snapshot but retains bounded partial report evidence.
Cached restart/client queries have no I/O/allocation; physical page reads stage
complete integrity checks before copying caller bytes. Tail/fast labels do not
route a complete circular history or authorize recovery.

All 43 sanitized core suites and style pass under `artifacts/plan-logsource-*-final.log`.
Product C, both 2-KiB-frame targets, component 17 PASS/seven runtime SKIPs and the
current unsigned arm64/x86_64 app pass under the corresponding reviewed logs.
The 22 independent source verdicts/reports cover copy/current-LSN conflicts,
different USA words, damaged/missing first copies, unknown/CHKD versions,
lossless clients, ordinary/mixed/maximum pages, exact tail/fast/circular bytes,
partial I/O, original backend error codes, allocator/read faults and budgets.
`ntfs-logfile journal EXPORTED_LOGICAL_LOGFILE` emits candidate/read/selection
evidence without mounting media; every report retains `recovery_qualified: false`.

The final 2-MiB fuzz envelope includes all 22 sources, including three 1-MiB
files; 131 combined seeds are unique. The campaign completes 108,449 runs in
61 seconds, coverage 819/features 1,856 and peak RSS 526 MiB, exit zero without a
reported finding. Its report is `artifacts/fuzz-logsource-final/report.json`.
The initial 128-KiB campaign is separate and excluded two large source fixtures;
source fuzz now includes ordinary 4-KiB pages and directs resealed mutations into
declared restart-area bytes. Process RSS is not retained core memory. The initial
enum spelling compile failure and corrected/final evidence remain separate.

The subsequent checkpoint above adds counted NTFS-stream/volume lifetime.
Continue with native source lifetime, legacy tail/
modern fast-page routing, current circular history, wrapped assembly, client
sequence resolution and NTFS checkpoint/tables. Then complete transaction/crash/
durability simulation under WRITES.md. Original Windows packets and lifecycle/
resize/version-transition qualification, native replay/roundtrips and full release
acceptance remain required. CORE-QUALIFICATION.md retains the complete scope.

## Read-only log primitive handoff checkpoint

Read LOGFILE.md and `ntfs/logfile.h`. The original allocation-free primitives
decode LFS 1.1/2.0 common restart areas/client lists, LSN geometry, USA-protected
record pages, exact already assembled LFS records and NTFS update spans with a
nonempty LCN vector. A caller owns immutable input and bounded private page
scratch; every error zeroes its output. Complete client membership/backlinks and
active-LSN checks, lossless names, copy-union metadata and shared redo/undo bytes
retain their separate contracts. A clean hint cannot authorize a dirty mount.

All 40 sanitized core suites, arm64/x86_64 freestanding compilation with the
2-KiB frame limit, style, the 17-PASS/seven-SKIP component and current unsigned
app/extension pass under `artifacts/plan-logfile-*-accepted.log`. The new suites
have 109 independently authored buffer verdicts and 110 exact diagnostic/argument
contracts, restored-byte/input/scratch/output guards and baseline truncations.
The separate USA-preserving fuzz target completes 126,853 executions in 61 seconds,
coverage 343/features 1,079 and peak RSS 488 MiB without a reported finding;
its report is `artifacts/fuzz-logfile-accepted/report.json`. No installed or Windows
log acceptance ran, and raw decoder scratch is distinct from process RSS.

`ntfs-logfile` inspects bounded exported packets without mounting media. LFS
client-restart bodies remain opaque. LCN-less update offsets have conflicting
published bases and are explicitly unsupported pending original Windows bytes;
the enclosing LFS decoder still preserves their client payload. Keep the format
provenance and this rejection rather than guessing a writable target.

The newer logical-source checkpoint adds bounded source ownership/reads and
restart conflict/selection. Continue with legacy tail/modern fast-page routing,
wrapped multi-page assembly, client sequence resolution and native NTFS
checkpoint/tables. Then implement the transaction/
crash/durability simulator under WRITES.md, keeping native replay/Windows roundtrips
and write enablement as separate acceptance. The full remaining functional and
measured optimization scope stays in CORE-QUALIFICATION.md; this is a checkpoint.

## FSKit pressure handoff checkpoint

READ-CACHE-POLICY.md defines the independent observer and lazy disposable-cache
policy informed by ext4 history. WARN/CRITICAL outrank coalesced NORMAL. Failed
observation disables retention; remount preserves the last observed level. Source
callbacks never wait for core I/O or scan dormant items; distinct observation
identities reject callbacks from canceled intervals. Access/completion cleanup
releases stream/catalog/raw-reparse state after consumers finish, preserving node,
canonical item, native target, ancestry, cursor, pending entry and scan budget.

The sanitized component passes 17 PASS groups with seven explicit macOS-27 SKIPs.
Current unsigned app/extension and style pass. Measured core-byte release is
135,632/18,816/79,436 for the tested LZNT1/XPRESS4K/LZX32K scenarios with record
caching disabled. Notification during a gated read, 11 allocation/two read cold
LZX reopen faults, catalog allocation failure/retry, copied bytes/ADS, interleaved
full/empty pages, link identity, permanent revocation and elevated remount pass.
Evidence uses `artifacts/plan-pressure-component-final.log`, `plan-pressure-style-final.log`
and `plan-pressure-app-reviewed.log`. The
initial failed link fixture is retained separately; it escaped the explicit
owning root and was replaced by the existing supported native-link manifest's
independent target/wire expectations. Full escape rejection remains tested.

No portable C source changed; its preceding 37-suite/frame/fuzz evidence remains.
Native Dispatch receipt on both supported runtime families, aggregate allocation/
RSS stress, kernel-held mappings and native reclaim remain required. Do not infer
receipt from a pressure utility's exit status. The complete no-VM scope remains
in CORE-QUALIFICATION.md; security, recovery and measured optimization stay open.

## Core WOF handoff checkpoint

WOF file-provider XPRESS4K/8K/16K and LZX32K use the public stream API; read WOF.md for
format provenance and the provider contract. Complete sparse unnamed/backing
extents and the entire paged chunk table are checked before a readable stream is
published. Streams survive source nodes and own one counted volume child. One
private decoded unit, input/scratch allocation and 4-KiB table page remain bounded;
failed fills invalidate cache tags before I/O and retry without publishing failed
unit bytes. Placeholder VDL does not zero provider content. Provider stat validates
storage independently of the table/codec, retaining truthful encrypted metadata
and readable plaintext ADS. FSKit classifies known providers as ordinary files,
keeps original-wire metadata/full stream manifests and hides the backing alias.

All 37 sanitized suites, both freestanding targets, style, legacy component and
current unsigned app passed. The file suite checks 37 verdicts and 376 allocation/
101 read fault positions across selected stat/open/cold-read operations. Twenty-three
legacy provider scenarios check content/attributes/ADS/raw metadata, page changes,
remount/revocation, late-unit zero-count errors and exactly-once replies. Standalone
XPRESS retains 87 content/11 invalid vectors; LZX adds 140 content/31 invalid
vectors and a 4,940-byte caller-scratch contract. WIM-variant block headers,
repeated queues, tree deltas, aligned offsets and CALL conversion are distinct
from CAB/Delta stream grammar. Equal-size raw provider chunks bypass conversion.
The external wimlib comparison passes 192 captured packets and 139 nonempty
synthetic decodes; 168 compressor refusals remain raw fallbacks. No Windows codec ran.

Six modern checks explicitly SKIP. The WOF campaign completed 1,122,244 executions
and the image campaign 45,986, each in 61 seconds without a reported finding.
Peak RSS was 466/982 MiB respectively including corpus/sanitizer overhead;
image runner memory approaches its separate cap. ACCEPTANCE.md records exact
scope and retained failures. Current evidence uses `artifacts/plan-lzx-*.log`,
`artifacts/lzx-oracle-checked-2/` and `artifacts/fuzz-lzx-{wof,image}/`.
The preceding XPRESS checkpoint remains under `artifacts/plan-wof-files-*.log`.
No Windows/installed provider operation ran.

The final named-constant fixture review preserves 484 codec files, 148 full-image
files, 148 compact-image files and all 360 external oracle level/payload pairs;
see `artifacts/lzx-fixture-review/report.json`. No product source changed after
the successful final checks.

Read FSKIT-EXT4-LESSONS.md alongside the sibling's FSKIT.md and its Git fix history.
Modern NTFS result handlers now reject absent successful results with EIO while
preserving operation errors; initial revoked acquisition rejects before geometry.
The shared boundary component passes locally. Runtime result-constructor failures,
native reclamation, installed pressure delivery/stress and distribution discovery still
need their explicit evidence; ext4's mounted passes do not qualify this driver.

Continue provider-specific native fault/interleaving and hard-link expansion, Windows
codec/format observations, installed owning authorization and measured provider
profiles. Preserve the full no-VM scope in CORE-QUALIFICATION.md; this checkpoint
does not close security, recovery, optimizations or Windows/native acceptance.
The older checkpoints below remain historical evidence.

The core is ready for the next integration and compatibility work. Eleven sanitized
suites cover the standard and NTFS 3.0 images, two fragmented MFT bootstrap
layouts, a nested index, byte-level image contracts, stream boundaries, decoder
vectors, bounded mutations and build-environment isolation. Allocation/read fault sweeps run on
all five filesystem layouts and verify release accounting. The stream suite
checks mixed compression units, cache retry after failed reads, zero-I/O sparse
reads across 4 GiB, initialized-data boundaries, EOF and source-node lifetime.
Decoder vectors exercise every length/displacement split transition.

The core continuation adds `ntfs_reparse_decode/open/get_info/name/close` and the
inspector's `reparse` command. It reads Microsoft symlink and mount-point metadata
through resident, fragmented and attribute-list storage, with original tags and
lossless host-endian UTF-16 targets. Every output range is checked before copying.
WOF/cloud and unknown Microsoft payloads remain opaque; GUID framing is rejected
as UNSUPPORTED, including Microsoft-tagged candidates. The metadata snapshot has
no path-following behavior. Ordinary reads/traversal remain fail-closed.
Twenty-six image contracts plus decoder vectors and 45 allocation/six I/O
failure positions passed. The direct FSKit component and four-geometry NTFS-3G
oracle also passed after adding the core guards. See ACCEPTANCE.md for retained
fuzz evidence and limits. No Windows-authored reparse corpus has been tested.

The stream catalog and both FSKit xattr protocol paths are implemented. The
catalog preserves exact names, including unpaired UTF-16 and unsupported stream
encodings, while data opening remains independently validated. The adapter uses
short ordinal aliases and a lossless reverse manifest, with a 1,024-entry item cap
and bounded responses. Reclaim/unmount closes catalogs; revocation gates cached
operations. All 23 core suites, expanded adapter tests and the current unsigned
app passed, followed by a bounded image fuzz campaign and four independent
NTFS-3G image geometries with byte and stream-inventory comparisons. Follow
NATIVE-NAMESPACE.md for format and limits. This catalog checkpoint alone did not
close unsupported-default-stream adoption; the later metadata contract above
covers the described regular-file component cases. Installed ADS acceptance
remains separate.

Native filenames also have a bounded reversible projection in NTFSNames.m.
Oversized/unpaired/reserved names use parent-directory link ordinals and full file
references; raw UTF-16 directory/per-link xattrs supply the reverse mapping.
Five authored namespace images, hidden/DOS accounting, scan/response exhaustion,
allocation/read failure sweeps and exactly-once replies pass current component
checks. Aliases do not move enumeration continuations and remain deterministic
only for immutable media. Installed names, Windows/native case-policy and native
normalization are still required; alias lookup currently scans from the root.

See ACCEPTANCE.md for exact results and generated log locations. Do not repeat
the completed MFT bootstrap work as a new feature, or interpret this checkpoint
as Windows/native mount acceptance. No writable core contract is implemented.

## Deferred continuation: native read-only acceptance

The current source passed an unsigned Debug app/extension build, including the
new core source and Swift bridge. Unsigned builds use
`artifacts/fskit/DerivedData/Build/Products/Debug/Machlin NTFS.app`.
A personally signed Release build passed strict deep signature verification;
its isolated output is under `artifacts/native-signing/build2/`. That build
precedes the reparse-core continuation; rebuild current source before installation.
Build with an explicit personal team using `scripts/build_fskit.py --team TEAM`
only when preparing the dedicated test VM. The script supports an isolated
`--derived-data`, matching app/extension `--build-number` and `--clean`. Explicit
manual profiles require both `--app-profile` and `--extension-profile`.
Verify the personal identity, entitlements and the guest's provisioning UDID
against the profile before installation; keep provisioning state out of Git.
The initial native target is
macOS 26.5+, with a distinct macOS 27 protocol path requiring its own runtime test.

Use the Machlin lab only from `/Users/darekhta/Development/machlin/lab`, after
reading its current VM instructions. Do not take over an ext4 or kernel VM that
another task owns. Select/create a disposable stock macOS test VM and document
its path and ownership in ignored generated state before installation. The
continuation created `lab/vm/ntfs-fskit-stock-26`, configured for four CPUs and
8 GiB RAM. It remains stopped: both VM slots belonged to other tasks, so boot
failed before guest identity or transport verification. Do not stop those tasks'
guests. Ownership and boot evidence are in `lab/artifacts/ntfs-fskit/`.
The user redirected continuation to the core; resume native acceptance when a
dedicated VM slot becomes available and that work is requested.

Install/enable the app inside that VM, explicitly select the `machlinntfs`
filesystem and capture evidence of the loaded module/build. Verify hashes for all
fixture files, Unicode/case-preserved names, small-buffer directory continuation,
stat, sparse/compressed reads, concurrent readers, mmap, failed writes, repeated
unmount/reload, extension termination and virtual device removal. Check the image
hash before and after every read-only run. Include a control that proves the
Machlin module was selected instead of Apple's built-in NTFS reader. Do not infer
this from a successful mount or from source compilation.

## Core compatibility priorities

The approved no-VM continuation is tracked in CORE-QUALIFICATION.md. It adds a
Windows-only read-only acquisition tool, an offline manifest comparator,
reference-based lossless inspector commands and separate structure fuzz targets.
The collector's Win32 calls have not executed on Windows; its fixed-width
transport and synthetic oracle checks are locally qualified. Preserve partial
acquisition and failed feature checks instead of converting them to passes.

`ntfs/security.h` provides original descriptor/ACE decoders and bounded immutable
snapshots from `$Secure` or per-file descriptor attributes. It checks both
indexes, locator/header/hash/copy agreement, inherited bounds, bitmap/MST/USA
and storage limits. Real external images require nonresident per-file storage
despite an old format note claiming it is always resident. Preserve explicit
source selection and never fall back from a damaged nonzero security ID.
SECURITY.md defines the API, budgets and remaining contracts. Identity mapping,
full security decisions and native authorization are still needed; parser/resolver
success grants no access and does not interpret callback conditions.

`ntfs/access.h` now provides a separate allocation-free DACL plane with exact file
generic mappings, plain original-order allow/deny ACEs, ordinary owner/OWNER RIGHTS
and enabled/disabled/deny-only/restricting token contexts. Both checks share one
SID-comparison budget and every error/denial has zero grant. Storage snapshots
can be evaluated without copying or I/O after node close. ACCESS.md defines
supported contracts and explicit unsupported restricted ownership, advanced ACEs,
SACL/integrity/privileges, maximum access and remaining native identity/operation
policy. An allowed discretionary result is not complete authorization.

The preceding 27-suite sanitized checkpoint, freestanding check, expanded
FSKit component tests and unsigned app build pass. Security storage adds
74 contracts and 262 allocation/191 I/O failure positions with retry/exact release.
Four external geometries provide 24 original descriptor-byte/ID comparisons and
unchanged images. The latest image fuzz campaign completed 47,915 executions in
61 seconds with reported peak RSS 901 MiB and no finding. Earlier failed format
assumptions remain recorded in acceptance. Windows and installed authorization
remain unqualified. The DACL suite adds 196,809 decisions including 196,608
independent per-right token oracles; its separate descriptor/context fuzz campaign
passed 14,450,666 executions in 61 seconds with peak RSS 489 MiB and no finding.
The earlier wrong owner-read test expectation remains in the failed focused log;
the corrected case verifies owner control rights separately from the allow trustee.
The independent AccessCheck collector/offline comparison tools add 337 local
transport, SDK span/count, token construction, cleanup and report contracts.
They retain queried native fields and original descriptor bytes, distinguish API
errors from denials, and keep unsupported/partial/out-of-plane work visible.
The SDK-shaped fake provider cannot qualify Windows behavior. Standalone SID
packets now have an exact public decoder and security fuzz seeds; the expanded
campaign passed 8,949,047 executions in 61 seconds with peak RSS 526 MiB and no
finding. See ACCESS-ORACLE.md for acquisition/comparison commands. Windows
acquisition and native DACL comparisons remain unrun; obtain those observations
before enabling restricted-owner semantics or claiming Windows authorization.
`ntfs-workload` and `scripts/benchmark.py` add repeated
POSIX/memory profiles with original-byte and image-integrity checks. Live-node
metadata reuse removes repeated presence-validation allocations and has a measured
benefit for the attribute-list open workload; data-read measurements are mixed.
See PERFORMANCE.md for evidence and cache/concurrency limits. The previous signed
app artifact predates these changes and remains unsuitable as current-source
native acceptance.

The subsequent case-policy checkpoint passes 28 sanitized suites, both
freestanding targets, style, legacy components and the unsigned app build.
Stored directory flags select exact/folded lookup without replacing NTFS index
collation. Seventeen policy images, 47 allocation/eight I/O failures, mixed
parents, original-file identities and sensitive aliases pass. Corpus verification
now compares the collector's queried case flags with core stat and explicitly
retains missing observations. Image fuzz passed 43,409 executions in 61 seconds,
peak RSS 906 MiB, with no finding. Logs are `artifacts/plan-case-policy-*.log`;
the successful component run uses the `fskit-final` suffix and retains two
macOS-27 runtime SKIPs. CASE-POLICY.md explains the on-disk observations and
volume-wide Sensitive capability strategy. Windows flags and installed cache
behavior remain unrun. Do not treat compiled modern replies or a context double
as runtime/authorization evidence.

The metadata diagnostic checkpoint passes 31 sanitized suites and exposes
`ntfs_validate`/`ntfs-validate`: private read-only ownership, MFT/cluster bitmap
checks, extension/list membership, exact filename/index pairing, directory graph
and physical extent ownership. Fifty-seven image verdicts, seven budget dimensions
and 508 allocation/346 read faults pass with unchanged input and complete retry.
Four independent bitmap geometries pass; all images remain unchanged. The final
diagnostic fuzz run passes 47,096 executions in 61 seconds with peak RSS 609 MiB
and no finding. Freestanding/style/unsigned app checks pass; applicable legacy
component tests preserve two modern-runtime SKIPs. Logs are
`artifacts/plan-validation-final-*.log`, `artifacts/plan-validation-fskit.log`,
`artifacts/interoperability-validation-final/` and
`artifacts/fuzz-validation-reviewed/`. VALIDATION.md defines what complete means.
Keep explicit incompleteness for separate DOS header counts and listed/flagged
bad-cluster storage. View-index semantic consistency, full replicas, native
journal and Windows-authored large/fragmented metadata remain open. Retain the
three failed initial external reports: they led to narrow system-record framing
and diagnostic bad-cluster handling, not blanket orphan or overlap exclusions.

1. Build a Windows-authored corpus and retain the independently generated oracle.
   Current handcrafted images target individual contracts; mkntfs tests provide
   independent ordinary formatting, data and indexes. Neither closes Windows
   interoperability for every format feature.
2. Validate the completed MFT bootstrap and attribute-list reader against real
   Windows-created fragmented metadata. Add each observed layout as an independent
   regression. A next extension outside all already decoded MFT runs is rejected;
   do not replace this with guessed addresses. NTFS-3G's format notes require the
   attribute list's own mapping pairs to fit in its base record; extension
   placement of that mapping is not an assumed missing feature.
3. Extend sustained fuzzing with Windows-derived seeds and independent mutation
   strategies. Current bounded runs and fault sweeps are evidence, not exhaustive
   validation of hostile media. Preserve malformed-list and tree-bound tests.
4. Check compression and sparse behavior with Windows-generated files, including
   allocation-size conventions, mixed/partial units and fragmented attributes.
   Current decoder boundary vectors and large logical-offset tests are synthetic.
5. Qualify the implemented lossless filename projection and per-directory case
   policy with Windows-created images and installed mounts. The adapter reports
   Sensitive for distinct native cache keys while core lookup respects each
   directory's stored flag; qualify positive/negative caching in mixed trees.
   The complete WSL/POSIX namespace and normalization contracts remain open.
6. Qualify the core reparse reader and implemented LINK-POLICY.md projection with
   Windows-authored links and installed mounts. Extend intermediate resolution,
   hard-linked reparse identity and cross-volume ownership through explicit
   contracts. WIM-backed WOF, cloud placeholders, third-party GUID owners and WSL tags still
   require separate content/resolution contracts. Do not expose encoded data as
   ordinary file content or turn every tag into a symlink.
7. Extend security storage to whole-store consistency and Windows qualification;
   qualify the DACL plane against Windows AccessCheck and implement restricted
   ownership, advanced ACE/SACL/privilege policy, identity mapping and owning
   authorization. Preserve explicit unsupported returns until those contracts pass.
   Current mode/UID/GID are a single-user read-only presentation, not
   Windows ACL enforcement. EFS and native Windows ACL translation remain absent;
   the read-only ADS xattr projection is separately defined in NATIVE-NAMESPACE.md.

## Writable and product continuation

Start with WRITES.md. Establish native $LogFile replay and crash ordering before
allocation, create/write/truncate, directory insertion/removal or rename. Preserve
dirty/hibernation state and recovery evidence. A private log or clearing a dirty
bit does not create Windows-compatible recovery. Test writable transactions with
Windows replay and chkdsk, plus per-sector interruption and device-cache failures.

Follow PERFORMANCE.md for measured optimization; no installed throughput win has
been established. Follow COMMERCIALIZATION.md for distribution, activation,
updates, privacy, support and later open sourcing. LXNU integration stays deferred
until required and belongs in a separate native adapter with its own acceptance.

The next task is not complete at a clean build or a focused commit. Close the
agreed continuation scope and update acceptance with evidence, limitations and
separate skips/failures.
