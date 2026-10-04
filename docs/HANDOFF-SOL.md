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

## Current native development installation

Fresh personally signed build 3 is installed in the isolated stock macOS 26.5.2
guest after actual version/kernel/RPC verification. Main checks all four host
product hashes/signatures; the installed app and extension preserve all eight
bundle-file hashes, strict signatures, build numbers and minimum OS. Existing
personal extension provisioning covers the exact guest. Normal app launch and
LaunchServices/PlugInKit discovery succeed at the installed path. A new signed
public FSClient helper observes NTFS with `enabled: true` after ordinary By Category
→ File System Extensions enablement. No authentication dialog or credential entry
was needed. This is distinct from PlugInKit election. Ext4 remains enabled and idle.

The standalone `tests/mounted_read.c` checker and both complete-filename fixture
images are staged. Main compares all two image/nine oracle hashes and verifies
the checker signature. Strict compilation, usage and host non-NTFS identity refusal
pass. Separate standard and NTFS 3.0 guest runs now pass the whole checker. It admits
only statfs type machlinntfs plus native read-only flags before mutation probes.
Use only task-owned read-only attachments, actual returned device IDs and explicit
extraction options through the public mount -F client. Actual option propagation,
two directory streams, all nine contents, case lookup, read-only mmap and write/create
refusals pass. Both runs detach without force, retain unchanged image hashes and leave
no task mount. Main reviews all raw checker and cleanup commands.

The installed access-admission matrix also rejects missing extraction with EACCES,
unknown mode with ENOTSUP and duplicate selection with EINVAL; each leaves no mount.
A single valid request then passes the whole checker on that same attachment. Main
checks all twenty actual commands and cleanup; review native-read/attempt-4-access-admission/.
This closes native configuration refusal/retry on the legacy runtime, not Windows ACLs.

Both mounts still report noowners despite requested owners; diskutil global permissions
are disabled. Returned IDs do not qualify native ownership or isolation. A single
documented Disk Arbitration route with per-attachment owners-on fails at mount approval
with kDAReturnNotReady after successful probe/staging. Its checker never runs; cleanup
passes and no policy/capability is changed. Review native-read/{attempt-1,attempt-2-ntfs30,
client-options,attempt-3-diskarbitration}/ under the guest artifacts. Next diagnose
ownership-preserving admission without weakening native authorization. Windows remains
at the account-password screen by explicit user request. Do not continue account
setup or cold-boot the Windows VM.

Read NATIVE-INSTALLATION.md and review
artifacts/fskit-guest-26.5.2/{signed/review,installation,modules-helper,read-preparation,native-read}/.
Sol retains VM preparation/UI ownership; hand a verified enabled guest to Luna for
prepared CLI runs. Only one worker may operate this VM at a time.

## Current write foundations and VM preparation

The user expanded scope to complete native writes and authorized isolated VM work.
Keep WRITES.md's native recovery/durability gate; this is authorization to implement
and qualify writing, not evidence that mutations can already be enabled.

Latest acceptance is private common-header LFS 1.1 RCRD page encoding: 117 fatal-
sanitizer suites, six focused suites, style, both 2-KiB freestanding targets and
54 FSKit PASS groups/eleven runtime SKIPs/zero failures. The clean unsigned Release
contains four universal products and compiles the encoder for both architectures;
strict bundle verification still rejects unsigned packaging. Main verifies seven
unchanged source fingerprints and actual products. The installed signed build 3
predates this private page helper; no newer unsigned bundle was installed.

Read ntfs/logfile_encode.h and WRITE-FOUNDATIONS.md. The page helper admits all
geometry/capacity/used-range checks before stores, constructs canonical header/USA
padding, preserves the complete restored body and protects tails using disjoint
caller workspace/output. Each buffer needs one complete page through the 64-KiB
policy; no allocation/I/O occurs. Modern layouts and unknown flags refuse. Copy/LSN
values remain opaque and do not select history, routing, completion or WAL transfers.
Native journal planning, durability and recovery remain open.

All 44 whole-page C goldens pass; main separately reconstructs their complete bytes
and checks 132 packet files, 44 numeric rows and 132 new fuzz envelopes. Fresh fuzz
replays 2,378 seeds and completes 116,265 runs in 61 seconds with 686 MiB peak RSS.
These are synthetic canonical page outputs, not Windows output/recovery acceptance.
The initial test-compilation signature error is retained under initial/; only corrected
focused/final runs pass. Evidence: artifacts/logfile-page-encode/{initial,initial-r1,final}/,
artifacts/logfile-page-encode/review.json and artifacts/{fuzz,fskit}-logfile-page-encode/.

Preceding acceptance is private logical journal encoding: 113 fatal-sanitizer suites,
five focused suites, style, both 2-KiB freestanding targets, 54 local FSKit PASS groups/
eleven runtime SKIPs and clean unsigned universal Release. Read
ntfs/logfile_encode.h and WRITE-FOUNDATIONS.md: measurement/serialization admit all
wire widths, capacities and disjoint used ranges before publication, preserve errors/
unused capacity and perform no allocation/I/O. The LFS common header is the only
writer layout; physical geometry/identity/flags are owning-layer work. Update opcodes,
targets and LCNs remain opaque. Canonical reserved/padding bytes are zero.

All 135 synthetic C cases pass; the composed original-input run passes 210 cases
including those same 135 plus 39 LFS records/36 NTFS payloads. Do not report all 210
as native cases. Main checks 690 input/golden files and 345 numeric rows, directly
compares all original inputs and independently reconstructs native canonical goldens.
Two appended fuzz selectors preserve earlier numbering; 270 new inputs cover exact/
short capacity. Fresh fuzz replays 2,246 seeds and completes 125,030 runs in 61 seconds
with 658 MiB peak fuzzer RSS. Actual source/product hashes, fatal test rows and both
architecture slices pass main review. New module compilation is confirmed in the
core archive for each architecture. Strict verification rejects the unsigned bundle.
Evidence: artifacts/logfile-encode/{initial,final}/, artifacts/logfile-encode/review.json
and artifacts/{fuzz,fskit}-logfile-encode/. Device writing, physical WAL planning,
current history, native analysis/recovery and installed mounts remain unqualified.

The new macOS clone now has actual post-login 26.5.2/25F84/arm64/stock-Darwin/RPC
verification. Inherited ext4 build 41 stays enabled with no active fixture/endpoints.
Existing personal signing resources cover this guest's NTFS extension. Fresh signed
build 3 is installed and enabled as recorded above; it predates the new page helper.
Review artifacts/fskit-guest-26.5.2/{preparation/post-login,signing-inventory}/.
The user explicitly chose to leave Windows at its account-password screen; do not
resume that UI or read the private credential file without new steering.

Preceding acceptance is the ending circular written-prefix correction: 108 fatal-
sanitizer suites, ten focused suites, style, both 2-KiB freestanding targets,
54 local FSKit PASS groups/eleven runtime SKIPs and clean unsigned universal Release.
The completed LFS 1.1 observer now caps its final circular segment by
NextRecordOffset; earlier unfinished segments may extend beyond it. The final
completion witness and every selected tail prefix still gate publication.
Transfer count/position never define record fragments. All 37 C/CLI cases pass,
including ten-page separate-transfer records, wrap and short/unwritten endings.
Six previously successful bad packets now refuse with CORRUPT; four historical
completed two-page packets and six checkpoint/analysis packets remain byte-identical.
An unfinished historical final page retains its STALE refusal. Main checks all
74 authored packets/37 numeric rows, three unchanged original journals, actual
source/product hashes and raw fatal-sanitizer results. Fresh fuzz replays 1,976
authored seeds and completes 121,654 runs in 61 seconds with 642 MiB peak fuzzer RSS.
Review artifacts/logfile-written-prefix/{baseline,initial,final}/,
artifacts/logfile-written-prefix/review.json and artifacts/{fuzz,fskit}-logfile-written-prefix/.
The documented build harness passes; an earlier SDK-resolution failure from a direct
Meson command is retained. Minimum OS stays 26.5 and strict bundle verification
rejects the unsigned build. The isolated machlin-ntfs-fskit-26.5.2 clone reaches its
login screen and awaits manual inherited-account login. Fresh guest version/kernel/
RPC verification and signed NTFS installation remain pending; review
artifacts/fskit-guest-26.5.2/preparation/. The source and unrelated guests are unchanged.
Windows remains at the user's manual local-account credential handoff. This checkpoint
qualifies framing only; current history, recovery, native writes and installed mounts
remain open.

The complete checkpoint decoder now composes all four dumps and checks name/dirty
target membership against physical allocated OAT keys. Each present dump LSN is
distinct. Duplicate name targets reject, repeated dirty targets are valid, and
client-0 stored self-references remain opaque. Checked fixed-stride lookup plus a
caller-owned bitset bounds work to linear traversal and scratch to 8 KiB. The 136
original C/CLI graph cases check all presence masks, key boundaries/free entries,
missing OATs, duplicates, LSN collisions, exact/short/NULL scratch, immutable
aligned/unaligned packets, zero errors and armed no-callback counters. Four composed
fuzz suites and 408 three-variant seeds retain the existing selector numbering.

Independent historical observation finds all name/dirty targets allocated and name
targets unique in ten original checkpoints. Native C/CLI each pass 23 cases: ten
explicitly projected nonempty snapshots, ten STALE old checkpoints under unchanged
original owners and three unchanged original current empty snapshots. Main compares
all 816 authored and 138 native packet/workspace files plus 159 numeric goldens,
every native checkpoint/26 unique dumps to retained originals, all thirteen copied
journals and projected tails, source fingerprints and actual product hashes.
No original current nonempty history, analysis, recovery or writing is qualified.

The preceding snapshot acceptance is 106 fatal-sanitizer suites, thirteen focused suites, style,
both 2-KiB freestanding targets, 54 local component PASS groups/eleven runtime SKIPs
and clean unsigned universal Release. Fresh fuzz replays 1,932 authored inputs and
reports 138,888 runs in 61 seconds with 637 MiB peak fuzzer RSS. All nine compiled
source hashes stay fixed. Actual app/extension minimum OS remains 26.5 versus guest
26.4; installed acceptance needs a compatible isolated runtime. Strict deep bundle
verification rejects unsigned code. Review artifacts/checkpoint-snapshot/{initial,
native,final}/, artifacts/checkpoint-snapshot/review.json, LOGFILE.md and the new
artifacts/{fuzz,fskit}-checkpoint-snapshot/ products/campaign.

Next qualify current page/copy/continuation history and volume semantics, then
implement native analysis and writable ownership. Snapshot framing/membership alone
cannot authorize replay or mutations.

`ntfs/checkpoint.h` now binds each exact checkpoint dump to the selected-client
RESTART record, checking anchor geometry/order, record client/LSN/action/body and
every allocated versioned entry after complete free-topology validation. All 147
independent C/CLI cases pass with no I/O/allocation, zero errors and guarded immutable
aligned/unaligned inputs. Four composed fuzz suites and 441 new three-variant seeds
exercise source, checkpoint, dump-envelope and whole-body mutations.
Original observation acquired ten historical checkpoints and 26 exact dumps;
their original current owners reject the old checkpoints with STALE. Ten explicitly
synthetic owner projections provide 26 positive/fourteen absent bindings without
changing any bytes after the restart pages. Three unchanged original current
owners/checkpoints supply twelve absent bindings. All 62 C/CLI native-packet cases
pass. Preserve that evidence boundary: no original current nonempty history or
recovery is qualified. Review artifacts/checkpoint-binding/{initial,fuzz-focused,
native,final}/, artifacts/checkpoint-binding/review.json and LOGFILE.md. That preceding
single-dump checkpoint passed all 100
fatal-sanitizer suites, style, both 2-KiB targets, 54 component PASS groups/eleven
runtime SKIPs and clean universal Release pass. Fresh fuzz replays 1,524 inputs,
reporting 100,879 runs in 61 seconds and 589 MiB fuzzer RSS. Main compares actual
packets/oracles, immutable journal tails, source fingerprints and product hashes;
checkpoint.c compiles on both architectures. Strict deep bundle verification
refuses unsigned code. Actual app/extension minimum OS is 26.5, while the prepared
guest is 26.4; prepare a compatible runtime before installed acceptance.

Whole-snapshot membership above follows this single-dump framing. Current page/copy
history, volume semantics, analysis and writable ownership remain necessary.

The current update decoder accepts empty LCN vectors with one reserved opaque slot
and absolute data offsets. Lossless attribute-name entry/full-dump decoding checks
byte lengths, unpadded entries and exact string/list terminators. Ninety-one authored
name vectors, 33 original historical payloads, nine original dumps/23 entries and
288 original table/entry vectors pass framing checks with unchanged inputs. Physical
44-byte client-0 OAT keys differ from their opaque stored self-reference; do not
substitute that self-reference when binding names or dirty-page targets.
LOGFILE.md and WRITE-FOUNDATIONS.md retain the complete primitive boundaries.

The preceding empty-LCN/name checkpoint passed all 94 fatal-sanitizer suites,
both 2-KiB targets, style, 54 FSKit component PASS
groups/eleven runtime SKIPs and clean universal Release pass. Fresh journal fuzz
replays 1,083 inputs, reporting 96,306 executions in 61 seconds and 520 MiB fuzzer
RSS. Actual changed-core compilation and all product architecture slices are
reviewed; strict deep bundle verification still refuses unsigned code. Review
artifacts/logfile-names/review.json and {checked,final,native}/, with campaign and
products in artifacts/{fuzz,fskit}-logfile-names/. Keep the initial test-author END
code mistake separately. The older .build seed directory retains one superseded
Boolean-rule seed; it does not belong to the fresh campaign.
Composed record binding and whole-snapshot membership above follow this primitive
checkpoint; volume semantics, current history/analysis and writable ownership remain open.
These passing historical framing checks provide no recovery or mutation admission.

Completed LFS 1.1 tail-copy routing now uses both slots and exact shared record
assembly. LOGFILE.md records selection, prefix conflict, unsupported partial-tail,
error/publication and budget contracts. Twenty-five original core/CLI cases pass,
including every read position with five backend results, allocation faults, retry,
capacity/null admission, wrap and exact/one-below credits. All 88 fatal-sanitizer
suites, style, both 2-KiB targets, 54 component PASS groups/eleven runtime SKIPs and
clean Release pass. Fresh journal fuzz replays 942 inputs and reports an exact
terminal 110,815 executions in 61 seconds. Review artifacts/logfile-legacy/ and
artifacts/fuzz-logfile-legacy/.
Both actual architecture slices are present in the app, embedded/standalone
extension and archive. Strict deep bundle verification refuses unsigned code;
final/product-review/product-review.json retains separate build/signing evidence.

All six original selected checkpoint/analysis records now read through that API;
checkpoint bytes match retained originals and all three journal hashes stay intact.
This qualifies completed-copy observation, not complete current history or replay.
Modern fast-page routing and native continuation/history qualification remain open.

Private USA output and native checkpoint-table/entry decoders are implemented.
WRITE-FOUNDATIONS.md describes exact byte, topology, version and publication
contracts. No device-write callback or FSKit mutation was enabled. That preceding
qualification is 82 fatal-sanitizer suites, 54 component PASS groups/eleven runtime SKIPs, both
2-KiB freestanding targets, style and clean universal Release. Exact authors cover
109 protected-byte and 380 table/entry vectors. Fresh journal fuzz replays 903 inputs
and reports an exact terminal 92,230 executions in 61 seconds. Preserve the initial
fixture-only Boolean serialization failure and the later raw-byte API review.

Review artifacts/write-checkpoint-tables/final/, artifacts/write-record-protect/,
artifacts/fuzz-write-foundations/ and artifacts/native-logfile-observation/.
The three unchanged original NIST journals have valid selected restart areas;
circular-only checkpoint observation refuses their uncopied/stale regular storage.
Exact restart packets occur in valid legacy tail copies. Main retained protected
pages and derived original packets in tail-diagnosis.json; this manual observation
does not establish complete current history, checkpoint-table ownership or recovery.
All three packets pass the selected-client restart binder with empty table references.
Actual app, embedded/standalone extension and archive contain both architecture
slices; strict bundle verification fails despite executable linker ad hoc metadata.
The final/product-review/ report retains those separate build/signing outcomes.
Next implement complete copy/current-history selection, bind native table records
and analysis, then the writable owner/WAL/durability and mutation sequence.

The isolated machlin-ntfs-write-lab macOS clone actually booted macOS 26.4 with
guest RPC; its original source remains unchanged/stopped. Only the user-authorized
lxnu-btrfs-kext-lab guest was gracefully shut down; btrfs-fskit-stock and unrelated
UTM guests stayed intact. Preparation evidence is artifacts/write-vm-inventory/.
The separate machlin-ntfs-windows UTM guest was created through its documented
configuration API, with thin imported 64-GiB/8-GiB NVMe disks, TPM, actual secure
ARM64 firmware and disabled sharing. The user's finalized official ISO has valid
ARM64 EFI and EFI BCD contents. Actual Windows Setup booted and selected Pro;
the user approved its displayed Microsoft terms and installation reached account OOBE.
The official UTM guest-tools downloader supplied signed ARM64 NetKVM storage;
only the network driver family was selected and OOBE network became Connected.
Actual desktop driver version/trust inventory remains unverified; no full guest-tools
installer was run. The user approved local account ntfs-lab. Supported Windows Pro
Work/school > Sign-in options > Domain join instead reached password creation without
organization enrollment. A fresh private password is stored locally under
artifacts/windows-write-vm/credentials/ with directory/file modes 0700/0600.
Never read/print those credentials into tools, chat or logs.

The computer-use credential policy requires user takeover for password entry,
confirmation and submission. The pending user handoff leaves the VM at that screen;
no agent operates its UI until the user reports completion. Then Sol alone should
verify actual desktop boot/build/ARM64, disk mapping, network driver inventory and
chkdsk availability before a CLI execution handoff. The 8-GiB test disk remains
blank. See artifacts/windows-write-vm/ for media/config/firmware/account-gate evidence.
Installed desktop, chkdsk results and recovery/writing acceptance remain open.
Only one agent operates each VM.

## Preceding checked base metadata retention

Checked standard information and reparse presence now survive temporary node
closure in an independently keyed payload inside the configured record cache.
Direct-mapped lookup verifies the complete reference; raw/count eviction is separate.
Only successful full checks publish, with cold publication precharge, fresh base
header checks and ancestor admission. Failed collisions keep prior successful
metadata. Sizes/mappings remain separately validated. Capacity zero disables the
volume memo; default 64 entries add 6,656 accounted bytes, one adds 104 bytes.
There is no new allocation, public ABI or writable capability.

That qualification is 75 fatal-sanitizer suites, 54 component PASS groups/eleven
actual macOS-27 runtime SKIPs, style, both 2-KiB freestanding targets and universal
Release. New selected-object authors cover 32 fitting and 256 competing independent
resident files, with 290 exact inventories/bodies and 288 streams. Fresh fuzz
replays 443 inputs and exits zero; last periodic execution count is 48,037 at
71 seconds, not an exact terminal total. All three original NIST diagnostics and
11,380 comparison commands pass again. Eight full portable Release products
reproduce exactly across two build directories. Both native binary slice sets pass;
strict signature verification fails for unsigned bundles despite linker ad hoc
binary metadata. Nothing here qualifies installed mounts or distribution signing.

Review artifacts/metadata-memo-review.json and its linked actual-file, benchmark,
reproducibility and app-product reviews. Stage logs use
artifacts/plan-metadata-memo-{checked,final}-*; retained portable/component products
are in artifacts/metadata-memo-products/, universal products in
artifacts/fskit-metadata-memo/. Preserve the initial test-only resident-allocation
expectation failure and the corrected reviewer partition-length assertion.
Source remains unchanged throughout final qualification.

The 254 paired runs and 28 reference-only controls qualify this targeted reuse.
Large fresh-core median falls from 71 to 42 ms relative to the preceding count memo;
the 32-object fitting controls improve about 10%. Pressure sequential median for
256 objects is about 1.4% slower, with overlapping ranges and mixed other profiles.
Document the extra memory and this tradeoff; PERFORMANCE.md retains exact tables.
No installed throughput or RSS benefit is established.

Next core work is writable groundwork: acquire selected-client restart records
from qualified current physical history, then validate checkpoint tables and native
transaction/recovery analysis. WRITES.md orders this work before any write API.
The existing circular observer, wrapped assembly and snapshot/prefix binder do not
establish active written history; tail/fast-copy routing and native recovery remain
open. Windows acquisition, native directory counts/authorization and installed
runtime also remain open. No VM is required for the next portable implementation
and fault-model work; native recovery acceptance still requires Windows evidence.

## Preceding bounded filename-count reuse

The core now memoizes only complete successful counts within the configured record
cache array. Each count payload retains its own full sequence-bearing reference;
raw-record eviction does not discard it. Round-robin replacement bounds retention,
zero entries disables volume reuse and default retention adds 1 KiB without a
separate allocation or public ABI change. Fresh-node base/header checks, per-slot
work, cold publication precharge and hot ancestor admission remain mandatory.
Failures never publish; node-local reuse retains its original contract.

Qualification is 73 fatal-sanitizer suites, the expanded DOS/eviction/owner/sequence/
exact-boundary/fault/retry test, 54 native component groups/eleven genuine macOS-27
runtime SKIPs, both 2-KiB freestanding targets and clean universal Release. Image
fuzz replays 440 authored seeds and exits zero; the last periodic observation is
51,898 executions at 71 seconds with zero OOM/timeout/crash counters. All three
original NIST partitions pass full diagnostics and 11,380 external comparison
commands again, including all 1,133 user paths and three separate roots.

Evidence uses artifacts/plan-count-cache-{checked,boundaries,matrix,final}-*,
artifacts/count-cache-{checked,boundaries}-testlog.json,
artifacts/fuzz-count-cache-reviewed/, artifacts/nist-corpus-count-cache-reviewed/,
artifacts/count-cache-app-products.json and artifacts/count-cache-review.json.
Preserve the prelaunch supervisor path failure and the recorded comment-only
source-snapshot delta. Retained app products are under artifacts/fskit-count-cache/;
linker ad hoc signatures grant no distribution authority. Performance reports and
actual-file review are documented in PERFORMANCE.md.

The 144 paired measurements qualify repeated hard-link/alias counts, with all
original inventory oracles passing and unchanged native/workload/public headers.
Forty sealed-product controls follow the archive rebuild; differing timestamp bytes
were subsequently identified by the two-directory comparison.
preserve both original and sealed archive reports. Accepted portable/component
products are under artifacts/count-cache-accepted/.
Those preceding runs do not qualify unique-object throughput, pressure behavior
or installed I/O. The current metadata continuation above adds scoped independent
object/capacity controls and retains fully checked standard information/reparse
presence across temporary closure. Portable journal work can connect selected
active-client restart acquisition with the
existing physical circular observer and snapshot/prefix binder; active written
history and tail/fast-copy routing still require their own contracts. Windows
acquisition, native directory counts/authorization and installed runtime remain open.

Fresh committed-source portable Release reproducibility now matches all eight
actual full products under artifacts/reproducibility-count-cache-fixed/. Main
checks each archive timestamp is zero; shared tool_environment fixes ZERO_AR_DATE=1
without postprocessing products. Preserve the initial timestamp-only failure in
artifacts/reproducibility-count-cache/ and the diagnosis/review in
artifacts/{archive-timestamp-diagnosis,count-cache-reproducibility-review}.json.
Six CLI files remain identical to the initial run. This qualifies two build
directories in the same checkout/toolchain, not relocated/native app builds.

## Preceding native primary-count adoption

FSKit now uses ntfs_node_link_counts for item/page linkCount and all three
single-edge reparse guards. Separate DOS aliases no longer add native links or
another reparse owning context. Two genuine primary names remain unsupported
for readlink projection. No raw-count fallback exists. Item adoption checks the
complete storage before publication; names-only pages retain classification.

The trusted preparation author supplies exact filenames for 153 selected native
images, preserving I30 keys and ordinary attribute bytes. The CLI checks 1,127
inventories/3,265 exact bodies, and main verifies all original/prepared hashes.
There are 72 fatal-sanitizer suites, 54 component PASS groups/eleven actual
macOS-27 runtime SKIPs, style and a clean universal Release. Four count mutations,
ordinary DOS-bearing hard links, five source/intermediate DOS link vectors,
320 allocation/69 read fault positions and 56 core/physical boundaries pass.
Current evidence uses artifacts/plan-fskit-primary-*,
artifacts/fskit-primary-checked-testlog.json,
artifacts/fskit-primary-fixtures-review.json and
artifacts/fskit-primary-filename-storage-cases.json. Preserve the omitted-data,
omitted-base-name and first x86_64 compiler failures separately.
Main actual-file review is artifacts/fskit-primary-review.json; accepted CLI/archive
and component binaries are under artifacts/fskit-primary-accepted/. The app remains
under artifacts/fskit-primary-counts/ with linker ad hoc signing and no distribution
authority.

At that checkpoint the next optimization was to avoid repeating the complete
filename inventory for temporary nodes referencing the same immutable inode.
The two current-only large-directory
runs are correct but cost about 2.59 seconds and 5 GB of requested bytes per 2,000
names with record caching disabled. Exact observations are under
artifacts/directory-primary-counts-cold/. Require bounded owning-layer reuse,
ancestor admission, failure/retry and measured comparison, now recorded above. Native directory
link policy, Windows observations and installed acceptance remain open.

## Preceding selected native filename groundwork

Eight basic/namespace images now have complete selected filename storage authored
from the exact original structured index names. They retain their original stream
bytes and namespace failures. The large case has 2,000 long primary names in real
extension records, with 2,064 MFT slots. The separate DOS alias counts physically
but not as another primary name. Invalid NUL storage and stale index references
retain their rejection cases.

Current core qualification is 71 fatal-sanitizer suites. The new CLI checks 33
inventories, 2,077 exact filename bodies, 23 original streams and one stale lookup.
Main independently compares every source/image hash. Evidence is
artifacts/filename-storage-reviewed/, artifacts/plan-filename-storage-reviewed-*,
artifacts/filename-storage-reviewed-testlog.json and
artifacts/filename-storage-review.json. These are selected-object storage fixtures,
not whole-volume diagnostic or Windows-authored images. The trusted writer assumes
a complete initialized base MFT mapping and resident volume bitmap.

At that checkpoint, the owning-layer adapter migration and remaining native
fixture families still needed complete filename bodies. The current section above
records their selected native adoption.
Core and adapter implementation sources are unchanged by this fixture checkpoint;
the prior component/universal-build evidence retains its scope.

## Filename inventory qualification

The new additive ntfs_node_link_counts API keeps ntfs_stat.links as the physical
FILE-header value and separately returns physical_names, primary_names and
dos_aliases. Complete resident filenames may live in checked listed extensions;
the list itself may be nonresident. Private bounded sorting and one read per
selected extension validate location uniqueness, owner/sequence and complete
storage. Cached success remains subject to operation/ancestor admission. This
does not establish parent/index reachability or native directory link policy.

Evidence is 70 fatal-sanitizer suites, both 2-KiB freestanding targets, style,
46 FSKit component groups/eleven genuine runtime SKIPs and a clean universal
Release. The module compiles for both architectures; app signatures remain
linker ad hoc with no distribution authority. The new tests cover 43 authored
inventories, 23 allocation/24 partial-full read fault positions, twelve cold
budget boundaries and hot-cache refusal/retry. Main actual-file review is
artifacts/link-counts-review.json; accepted CLI/archive/component binaries are
under artifacts/link-counts-accepted/ and the app under artifacts/fskit-link-counts/.

The offline NIST comparison passes all three full diagnostics and 1,133 documented
user paths plus three separate structural roots. Counts match standalone
NTFS-3G filename namespaces; original info/descriptor exports are retained, and
every source hash stays unchanged. The report is
artifacts/nist-corpus-logical-links-reviewed/report.json. The image campaign
replays all 435 authored inputs, including 43 new inventory seeds, and exits zero
with OOM/timeout/crash counters zero. Its last periodic sample is 50,022 executions
at 70 seconds; terminal exit is zero at 71 seconds. Evidence is under
artifacts/fuzz-link-counts-reviewed/. Earlier validation fuzz, performance and
reproducibility retain their original scope.

At that checkpoint, the next owning-layer work was to migrate FSKit linkCount and all three single-edge reparse
guards from stat.links to checked primary counts. Existing native fixtures can
omit FILE_NAME storage; author complete names/parents/listed extensions before
enabling strict inventory use. Do not fall back to raw header counts or invent
names to keep component tests passing. Qualify DOS-bearing ordinary hard links,
symlink/junction contexts, quotas, faults, remount/revocation and both protocol
families. Ext4 exports its inode count directly; NTFS needs this format boundary.
Windows/native observations remain a separate gate.

Retain the first two harness failures, app environment failure and broken-output
corpus attempt described in ACCEPTANCE.md. The corrected corpus supervisor owns
its deadline/capture outside the transient REPL connection. No VM, host install,
write capability, native authorization or commercial acceptance was added.

## Preceding public-corpus diagnostic qualification

Full diagnostics now count all physical FILE_NAME/index pairs, including separate
DOS aliases, against the base FILE header. The legacy deferred counter remains
zero with unchanged public report layout. Native logical hard-link presentation
is a separate open contract. The canonical internal `$Repair` omission resolves
through checked root/$Extend/$RmMetadata ownership, exact spelling, single names,
directory parents and a hidden/system regular leaf. `$Extend` retains fixed slot
11; movable metadata has no prescribed slot. Parent-range searches allocate and
read nothing, charge bounded work and preserve present-packet/nonzero-ID checks.
No descriptor is synthesized and no access decision follows.

Current evidence: 68 fatal-sanitizer suites, 259 general diagnostic images plus
nine independent store cases, two 2-KiB freestanding targets, style, 46 component
PASS groups/eleven genuine macOS-27 runtime SKIPs and a clean universal Release
app. Four new profiles add 854 allocation/438 I/O fault positions; the maintenance
component accepts four corrected inventories before extraction activation. Both
app binaries remain linker ad hoc signed without distribution authority.
Main actual-file review is artifacts/nist-validation-review.json; accepted logs
use artifacts/plan-nist-validation-*.
The reviewed CLI/archive and component binaries are retained under
artifacts/nist-validation-accepted/; universal app products remain under
artifacts/fskit-nist-validation/.

The three public NIST partitions pass full diagnostics and independent offline
comparison of 1,133 documented user objects, 1,079 readable streams and the
symlink's expected ordinary-data refusal. A 512-entry directory, nine directory
levels, separate DOS aliases, hard links, ADS, common/extended standard information,
indexed/per-file descriptors and raw symlink bytes have actual external oracles.
Every source hash stays unchanged. The accepted report is
artifacts/nist-corpus-comparison-layout-aware/report.json. DEVELOPMENT.md defines
the offline command, pins, resource limits and SII/SDS versus SDH oracle boundary.
Retain the two earlier failed oracle attempts and the initial collector-key error;
ACCEPTANCE.md identifies the corrected test assumptions. Authoring OS/publisher
digests remain unestablished, so this does not replace Windows acquisition.

Validation fuzz replays all 266 actual authored inputs and exits zero with periodic
OOM/timeout/crash counters zero. Its last periodic observation is 45,501 executions
at 69 seconds, not an exact terminal total. See artifacts/fuzz-nist-validation-reviewed/.
Earlier image fuzz, measurements and portable reproducibility retain their exact
source scopes. Windows/native logical counts and authorization, installed mounts,
native recovery, release and the remaining optimization program stay open.

## Preceding explicit extraction access

Native load or activation must select ntfs-access=extract. An ordinary load can
remain unselected for maintenance; activation then returns EACCES with no root.
Malformed, duplicate and unsupported modes refuse, including during remount.
A selected load carries policy into separate activation; successful activation
retains it across remount. Native UID/GID presentation snapshots the extension's
effective credentials once. Neither those IDs nor existing 0400/0500 modes map
Windows principals or prove installed isolation. NATIVE-ACCESS.md defines this
explicit restricted product mode and the native acceptance matrix to execute.

Evidence at that checkpoint is 45 fatal-sanitizer component PASS groups/eleven genuine
runtime SKIPs, style and a clean arm64/x86_64 Release app. The original first
component attempt failed compilation on a missing engine getter declaration and
ran no tests; preserve that log separately. Accepted logs are
artifacts/plan-access-mode-*-declared.log and
artifacts/plan-access-mode-{app-release,products}.log. Main actual-file review is
artifacts/access-mode-review.json. Both bundle binaries have linker ad hoc
signatures, no distribution authority, and compile the new policy on both targets.
The updated native directory tool checks all twelve independent namespace entries
in six smoke runs/three profiles under artifacts/directory-access-mode-smoke/.
Its oracle and unchanged-input checks are compatibility evidence, not a timing gain.

Portable core sources have not changed from the preceding 68-suite/freestanding/
fuzz qualification. Do not rerun those for this adapter-only change or treat their
reports as native evidence. Before installed acceptance, propagate the explicit
extraction option, observe actual service credentials, and check both protocol
families, users/groups/root, owner-ignore options, mode caching, execute/mmap and
mutation flows. Full Windows identity/DACL authorization, Windows acquisition,
installed/commercial acceptance and recovery remain open.

## Preceding extent-read qualification

Nonresident reads retain one checked mapping index per stream. Current and
successor hits precede the binary fallback; indexes survive bootstrap array
growth, while every I/O/retry still passes ordinary admission. Independent
streams own independent positions and require external volume serialization.
The field costs eight bytes per stream on tested targets with no read allocation.

Current checks pass all 68 sanitized suites, both 2-KiB freestanding targets,
style, 42 component PASS groups/ten runtime SKIPs and the clean universal Release
app. Six original profiles check up to 1,024 runs through eleven attribute records,
independent contents/streams, sparse/VDL semantics, 34 partial/full read failures,
36 compound budgets and cleanup. Main actual-file review is
`artifacts/extents-review.json`; eight full portable Release/O3 products match
under `artifacts/reproducibility-extents-candidate/`. Accepted logs use
`artifacts/plan-extents-*-candidate.log` and `artifacts/plan-extents-app-release.log`.
The first app command used default Debug; the later explicit Release evidence is
separate. Both are unsigned for distribution. Main accepts the targeted extent
lookup change after 1,272 actual alternating pairs/2,544 runs: long random-4-KiB
memory reductions are 16.6–17.7%, warm POSIX reductions 3.8–7.3% and the measured
mount plus public stream costs sixteen extra core bytes. Small random memory
controls include 1.2–3.9% regressions. Retain every control/range and the original
synthetic input/callback scope in PERFORMANCE.md; no broad/native benefit follows.

Fresh image/validation fuzz fixed-replays 392/242 actual unique files and exits
zero with every periodic crash/timeout/OOM counter zero under
`artifacts/fuzz-extents-{image,validation}-reviewed/`. Main checks actual binaries
and executed entries. Last periodic executions are 53,673/47,137 at 71/69 seconds;
neither terminal totals nor RSS are observed. Data/resource/deadline/RSS policies
remain 1 MiB plus 4 KiB/five seconds/1 GiB. The separate 16-MiB workload images
are covered by the extent suite, not these bounded fuzz campaigns.
Windows, installed FSKit, identity/authorization, recovery and the full
optimization/release program remain open.

## Preceding boot consistency

Full diagnostics now resolve fixed `$Boot` slot 7's ordinary nonresident/listed
LCN-zero storage and compare one complete logical sector with its reserved copy
at the boot-declared data-span end. Larger resources cannot move the copy.
Bounds, staging, callbacks and comparison retain existing budgets; normal mount
and recovery selection remain separate. Stage BOOT appends value 10 with stable
previous enum values/report layout/API 2. VALIDATION.md defines exact supported
profile, owner/storage rejection and Windows/historical gaps.

Current source passes 67 sanitized suites, both 2-KiB freestanding targets, style,
42 component PASS groups/ten runtime SKIPs and the clean dual-architecture Release
app. There are 244 complete-volume verdicts, including 37 new boot cases. Seven
boot profiles cover 49 allocation faults, 44 partial/full read failures, 66
pre-callback refusals and seven comparison precharges with retry/cleanup. Native
full checking rejects a mountable damaged copy and retains EIO for activation;
quick checking remains partial. Four external NTFS-3G geometries compare full
primary/exported/reserved sectors and retain unchanged source hashes.

Accepted core logs are `artifacts/plan-boot-replicas-*-canonical-geometry.log`;
freestanding uses `*-resource-fixed.log`, and component/style/app/oracle use
`*-aligned-loaders.log`. Main independently reviews actual default/compact
images, owner/mapping frames, results, external source bytes, compiled core and
bundle binaries in `artifacts/boot-replicas-review.json`. The app retains linker
ad hoc signatures without distribution authority. ACCEPTANCE.md records initial
test-resource, compact-geometry, compiler-preflight and journal-span failures.
Canonical fixture dispatch shares one configured module; default boot bytes are
unchanged. Explicit test-loader padding keeps physical alignment and copy offsets.

Sequential validation/image campaigns fixed-replay 242/392 actual inputs, including
all 37 compact boot cases and 22 journal images. Exploration exits zero with all
reported OOM/timeout/crash counters zero. Reports are
`artifacts/fuzz-boot-replicas-validation-canonical-reviewed/` and
`artifacts/fuzz-boot-replicas-image-span-reviewed/`. Resource inputs now admit
1 MiB plus 4 KiB, while authored data span remains 1 MiB; five-second input and
1-GiB per-process RSS policies remain. Last periodic counts are 41,479/37,866 at
70/60 seconds, not exact terminal totals; actual RSS is not measured. Windows,
installed/runtime, authorization, recovery and commercial qualification remain
open. Fresh committed-source portable Release/O3 reproducibility matches all eight
actual full products under `artifacts/reproducibility-boot-replicas/`. Main compares
full bytes and actual selected options in the current review; native-app and
relocated-source qualification remain false. The launcher log is
`artifacts/plan-boot-replicas-reproducibility.log`. Earlier performance evidence
retains its source scope.

## Preceding within-owner intermediate links

The adapter now resolves checked intermediate symlink/junction destinations to
translate subsequent components with their actual directory's case/alias policy.
Native targets retain intermediate link components. Core snapshots remain
lossless and target content is never read. Every nested expansion retains the
same owner/root policy and shares component/raw-entry/core/physical credits.
The active full-reference stack detects recursion but permits finite reuse;
at most 63 snapshots expand, including the initial source. Active cycles or the
ceiling return the appended TOO_MANY_LINKS/ELOOP result. Existing API 2 result
values remain stable. LINK-POLICY.md defines dangling, directory, unique-edge and
native stack/allocation scope.

Current source passes 67 sanitized suites, both 2-KiB freestanding targets,
format/style, 42 FSKit groups/ten genuine modern-runtime SKIPs and the clean
arm64/x86_64 Release app. Components qualify 76 authored path/storage forms,
including 29 chain cases, 28 exact/one-below ancestor boundaries, 205 allocation
positions and 44 physical-read positions with partial/full failed transfers.
Required failures, actual quota dimensions, retry, once-only callbacks, original
bytes and cleanup pass. Main checks actual generated geometries/packets/edges,
suite results, changed compilation and bundle binaries in
`artifacts/link-chains-review.json`. Accepted logs use
`artifacts/plan-link-chains-*-contracts.log`; ACCEPTANCE.md preserves initial
fixture/pagination and scope-closure/allocation-errno test errors.
CODE_SIGNING_ALLOWED=NO retains linker ad hoc signatures, not a distribution team
or authority. Native/Windows path walking, loop/memory stress, cross-volume and
reparse hard-link contracts, identity/authorization and commercial release remain
open. Preceding fuzz and workload reports retain their exact source scopes.
Fresh committed-source portable Release/O3 reproducibility matches all eight
actual full products under `artifacts/reproducibility-link-chains/`. Main compares
complete bytes and actual selected build options in the current review. This is
one arm64 checkout/toolchain in distinct build directories, with native-app and
relocated-source qualification explicitly false.

## Preceding stored-access masks and diagnostic processes

Generic mappings belong to access requests. Applicable stored generic/mixed ACE
masks now return UNSUPPORTED, including entries after a sufficient grant,
nonmatching trustees, zero requests, ordinary ownership and restricting contexts.
The core evaluates supported stored concrete rights without rewriting snapshots;
inherit-only entries remain nonapplicable but retain framing checks. Six exact
retained local pre/post packets reproduce four corrected refusals and two unchanged
supported controls. ACCESS.md records the policy and primary format source.
This is a deliberately limited DACL contract; FSKit still does not authenticate
Windows principals or enforce this evaluator as native authorization.

That checkpoint's local evidence is 67 sanitized core suites, 197,201 access decisions
(196,608 independent per-right oracles and 392 stored-mask verdicts), 425 transport
checks, both 2-KiB freestanding targets, format/style, 36 FSKit component groups
with ten runtime SKIPs and the clean unsigned arm64/x86_64 Release app. The app
compiles the changed access core for both architectures; later test/process
changes leave product source unchanged. Common fuzz, component and diagnostic
children now explicitly select fatal ASan/UBSan options. A separate process suite
proves recovering-control versus fatal exits and actual diagnostic-wrapper
rejection using disposable injected faults. Its first missing-SDK compile failure
is retained separately from the corrected complete run.

Its 60-second access campaign replays all 52 seeds, completes 8,751,208
executions in 61 seconds and observes a 519-MiB libFuzzer process peak under the
unchanged 1-GiB ceiling. No crash, timeout, OOM or sanitizer finding is reported.
Current logs use `artifacts/plan-stored-mask-*`, matched packets use
`artifacts/stored-mask-{before,after}/`, and fatal campaign evidence is under
`artifacts/fuzz-stored-mask-fatal/`. Main review is
`artifacts/stored-mask-review.json`. Preserve preceding campaign/environment and
cache/maintenance evidence with their exact source scopes.
That checkpoint's committed-source portable Release/O3 reproducibility matches all eight
full products under `artifacts/reproducibility-stored-mask/`, independently read
by main. The two builds use one checkout/toolchain and distinct directories;
relocated-source/native app reproducibility and distribution remain unqualified.

Next acquire real Windows AccessCheck vectors before expanding restricted-owner,
maximum-access, privilege or advanced-ACE semantics. Native identity/owning
authorization, installed FSKit, Windows interoperability and commercial release
remain open. The broader work is tracked in CORE-QUALIFICATION.md.

## Preceding read-only FSKit maintenance

The private validator now runs through `FSManageableResourceMaintenanceOperations`.
Default/`-n` runs a full supported inventory; `-q` is mount eligibility with an
explicit incomplete report, and `-f` overrides quick mode. Repair and format
refuse asynchronously without I/O or ownership takeover. A forced failed-layout
load can create a geometry-free nonmountable unary identity, retired after every
check with valid zero statistics and ESTALE activation/mount replies.

The controller reserves load/unload/check state without holding its monitor
through I/O or volume methods. Checking admits only inactive owners without live
items; active reads and busy publication refuse promptly. The original mounted
core and private diagnostic share one serialized resource pool. Cancelled tasks
stop at callback boundaries and wait up to five seconds for owned work to drain;
timeout requests FSKit container escalation and never frees borrowed I/O storage.
Native drain wins over checker completion. A sealed late cancellation handler
retains no old resource or volume. Full failures block activation until a clean
full retry; quick success and cancellation cannot clear them. See LIFECYCLE.md.

The current component passes 36 groups/ten genuine modern-runtime SKIPs, with
191/25 full/quick allocation and 86/7 partial-full physical-read positions,
204 required failures/12 optional omissions, eight exact/one-below boundaries,
weak retired-owner release, five blocked checker cases, blocked load and two
prompt admission cases. Three unchanged-core validation suites, format/style and
the clean unsigned arm64/x86_64 Release app pass. Main reviews every component
group and all eight actual changed-adapter architecture compilations under
`artifacts/readonly-check-review.json`; logs use
`artifacts/plan-readonly-check-*-admission.log` plus the initial targeted-core log.
The final test grace naming change passes the format/component/style-only
`*-named.log` rerun without changing app or core source.
ACCEPTANCE.md preserves the corrected ARC compile failures and two benign
App Intents metadata warnings.

This adds no installed/native, Windows, write, signing/distribution or general
performance acceptance. When native qualification resumes, check actual unary
acquisition, quick/full/corrupt/dirty task results and client exit status, async
repair/format refusal, cancellation/escalation, retained retired identities and
the complete ordinary read/mount behavior on both supported runtime families.
The broader no-VM and measured optimization scope remains in CORE-QUALIFICATION.md.

## Preceding optional compression-unit retention

LZNT1 and WOF XPRESS/LZX streams retain at most two decoded outputs. The original
output/input/workspace allocation stays required; after the first useful fill,
one distinct miss attempts one optional output allocation. Refusal preserves
single-unit reading without poisoning enclosing credits. Hits promote the older
output; replacement invalidates only the victim before I/O/decode and publishes
only after complete success. Failed fills preserve the other unit. Close releases
the separately owned extra allocation before the original storage.

All 66 sanitized core suites, both freestanding targets, style, 25 component
groups/nine explicit modern-runtime SKIPs and the unsigned dual-architecture
Release app pass. Dedicated profiles cover six layouts, four optional refusals,
14 partial/full replacement faults, 12 read-byte/work boundaries, compound
fallback failure and exact cleanup. Required operation boundaries remain strict;
the WOF suite has 390 allocation/101 read positions and cached-prefix checks after
late codec errors. Pressure tests fill both slots, measure accessed-item release
and verify exact extra-unit recreation after NORMAL. Current logs use
`artifacts/plan-unit-cache-*-reviewed.log` and the later pressure logs.

Fresh image/validation campaigns replay 363/205 unique seeds and exit zero with
no reported OOM/timeout/crash; last periodic counts are 51,793/45,993, not exact
terminal totals or aggregate RSS observations. Current Release/O3 reproducibility
matches all eight actual full products under `artifacts/reproducibility-unit-cache/`.
Matched retained releases pass 4,560 runs/240 paired configurations with unchanged
workload/POSIX sources, original bytes and media hashes. All five warmed two-unit
inputs reduce physical calls from 4,500 to zero per 3,000 requests. The second
output costs one codec unit; private state also grows. Three-unit cyclic I/O is
unchanged, and general timings are mixed.

Longer hot profiles use 500,000 operations/15 repetitions, with overlapping
ranges and no resolved speedup. The largest short general negative case was
XPRESS16K sequential/memory/512-byte/four-reader: +10.63% wall/+25.99% CPU over
3,000 requests. Its 200,000-request confirmation is +0.39%/+1.14%, with overlapping
ranges. All short/negative results remain retained; PERFORMANCE.md records other
confirmations and memory costs. Main independently checks original/stored bytes,
every run counter/range/sample/pair and summary under
`artifacts/unit-cache-review-confirmed.json`; ACCEPTANCE.md retains the corrected
review-only pairing assertion and its failed artifact.

The bounded cache is accepted for the measured two-unit reuse benefit. Next close
Windows/provider and installed/native qualification, owning authorization,
aggregate pressure/device measurements and the remaining functional/recovery
contracts in CORE-QUALIFICATION.md. This portable comparison supplies no native
mount, Windows compatibility or broad throughput claim.

## Preceding compression workload baseline

The opt-in `strided` workload cyclically visits bounded windows, continuing each
reader's independent position through warmup. The runner records stride/position
configuration and verifies ranges, delivered bytes and prefix samples against
original file bytes; full hashes remain separate. The two focused sanitized
suites pass 47 measured profiles and 86 helper contracts, with format/build/style
passing under `artifacts/plan-compression-profile-*.log`.

At this preceding baseline no core/adapter source changed and both LZNT1/WOF
cache one decoded unit per stream. The retained current-only baseline passes 540 runs/60 summaries:
five synthetic codec/storage inputs, both callbacks, one reader, 512-byte reads,
64 record-cache entries, 0/128 warmup and 3,000 measured operations, with nine
repetitions at each of one/two/three unit-stride positions. Reports use
`artifacts/compression-profile-baseline-*/report.json`. Both ordinary Release/O3
builds match eight actual products under
`artifacts/reproducibility-compression-profile/`. Main review checks actual
products, re-authored original and stored bytes, every range/sample/resource
counter and summary median/range in `artifacts/compression-profile-review.json`.
PERFORMANCE.md defines mixed raw/packed/sparse units, warmed-cache scope and hot
clock-resolution limits. This baseline supplies no speedup, Windows or native
mount claim; relocated/native release qualification remains separate.

This remains the retained source/product baseline for the current candidate;
its one-slot timing and counters must not be treated as candidate observations.

## Preceding exact native dot lookup

The shared FSKit adapter resolves exact `.` and `..` from the same checked
numeric ancestry used by names-only enumeration. Both root components select
the root. Live canonical items require no core allocation/I/O; a released parent
reopens the full sequence-bearing reference and must still be an ordinary
directory before adoption. Admission, native publication and compound core/
rounded-physical budgets remain mandatory. Stored dot names retain aliases in
both authored case modes, and no parent FSItem is retained for the ancestry.

ASan/UBSan components and style pass: 25 PASS groups/nine explicit macOS-27
runtime SKIPs, two required allocation/two partial-full read faults and 12
core/physical exact/one-below boundaries. Identity, both released ancestors,
drained remount, wrong owner/type and cached/cold permanent revocation have
separate checks. The unsigned Release app compiles the changed owner for arm64
and x86_64 and passes. Logs are `artifacts/plan-dot-lookup-{component,style}-named-final.log`
and `artifacts/plan-dot-lookup-app.log`.
Actual log/architecture/compiler-diagnostic review passes under
`artifacts/dot-lookup-review.json`.

Preserve two failed new-test attempts in `*-component-initial.log` and
`*-component-owner-fixed.log`. The compiler AST confirms that the original shared
weak declaration accidentally made the second reference strong. Separate weak
declarations and explicit child lifetime across the inner autorelease pool
correct the helper; both parent-release assertions remain mandatory. See
`artifacts/plan-dot-lookup-arc-declarations.log` and LIFECYCLE.md for exact scope.
No core/portable-product source changed; the preceding 65-suite, external-image,
fuzz and portable Release evidence below retains its exact source scope.
Installed dot/path/case behavior, modern runtime/native counts, authorization,
full Windows qualification and the complete measured optimization plan remain
open. This checkpoint does not establish a native mount or performance gain.

## Preceding complete bad-cluster list checkpoint

Fixed `$BadClus::$Bad` now uses the original complete attribute-list reader with
an internal metadata-only description policy. First-in-extension, multiple and
base-owned continuations share sequence/base/list/VCN checks, complete
volume-sized coverage and VCN == LCN physical identity. Descriptions never read
bad storage, including zero/full VDL; public content opening is refused. An
ordinary file's ADS with the same spelling remains readable. Flagged first
extents remain unsupported and mismatched continuation flags/units are corrupt.

All 65 sanitized-build suites, both 2-KiB freestanding targets, style, 22 component
groups/eight explicit runtime SKIPs and the unsigned arm64/x86_64 Release app pass.
All four independent bitmap/mirror-prefix geometries pass with unchanged media.
There are 32 new complete-image verdicts, eight positive, and 207 combined
diagnostic cases. Nine storage/admission profiles include 25 private-open
allocation/12 partial/full read failures and 38 exact/one-below cumulative
operation boundaries with independently counted callbacks/bytes. Four diagnostic
profiles add 935 allocation/890 partial/full read failures beside the earlier
17 profiles' 3,328 allocation/1,803 read failures. Forbidden-range callbacks cover
two distant bad runs; every failure closes owned storage and fresh retry passes.

Current logs use `artifacts/plan-bad-clusters-*-reviewed.log` and the external
report is `artifacts/interoperability-bad-clusters-reviewed/`. Main review
independently re-authors all 32 actual new images and checks the complete
manifest/test results and actual changed-core compilation for both architectures.
VALIDATION.md defines exact flags, resource and content-admission contracts.
Windows-authored chains, installed behavior, flagged forms and the complete
continuation/optimization plan remain open. Earlier source comparisons and
performance reports retain their recorded scope.

Fresh sequential image/validation campaigns uniquely fixed-replay all 363/205
compact inputs, including 40 bad-cluster forms/32 new chains in both walkers.
Both exit zero with all periodic OOM/timeout/crash counters zero; their last
reported counts are 51,938/45,153 at 70/69 seconds, with no exact terminal total
or observed RSS. Reports are
`artifacts/fuzz-bad-clusters-{image,validation}-isolated/`; unchanged limits remain
1-MiB input/five-second timeout/1-GiB per-process RSS ceiling. The initial
duplicate interrupted validation wrapper remains unqualified in
`artifacts/fuzz-bad-clusters-validation-reviewed/run-m4pdapfu/`. Its report still
says running, but actual log interruption and no matching live task process were
verified before the sequential reruns; preserve its original files.

Both committed-source Release/O3 builds produce eight equal full portable products
under `artifacts/reproducibility-bad-clusters/`. Main independently re-reads every
pair, actual fuzz binary, unique replay path/counter and all 32 re-authored images
in `artifacts/bad-clusters-review.json`. Reproducibility remains local same-
checkout/toolchain/macOS arm64. Native/relocated/signing/CI and the full measured
optimization program still require their own evidence.

## Preceding per-file security checkpoint

General `ntfs_validate` now checks selected unnamed zero-ID descriptor bodies
after indexed-store/reference validation. It reuses the original bounded
snapshot/decoder, shares one core operation across each node/descriptor and
charges descriptor work before decoding to both diagnostic and core budgets.
Each temporary owner releases before the next file. Missing ordinary storage,
invalid packets and limits retain precise partial reports without new API fields.

The initial external oracle rejected zero-ID `$MFT` without a descriptor.
Original metadata inventories and 48 retained `ntfsinfo` exports establish the
fixed-internal exception; explicit synthetic omissions/present damage and
ordinary system-flag cases guard it. Every present selected packet and all
nonzero IDs remain checked. Empty/inert reserved records retain their earlier
absence contract. SECURITY.md and PROVENANCE.md define exact scope; this is not
an ACL/default identity or authorization rule. The failed oracle remains retained.

Current source passes 64 sanitized-build suites, both 2-KiB freestanding targets,
style, 22 component groups/eight explicit runtime SKIPs and the unsigned
arm64/x86_64 Release app. Both fresh four-geometry oracles pass unchanged,
including 24 original descriptor comparisons. There are 175 diagnostic verdicts,
3,328 allocation/1,803 read faults across 17 profiles, 68 partial/full per-file
SECURITY errors, 18 pre-callback refusals/three parser precharges and the compound
core maximum-descriptor boundary. Validation fuzz fixed-replays all 173 compact
seeds with no OOM/timeout/crash, with a last reported exploration count of 43,828
at 63 seconds; no exact terminal total/observed RSS is available. The two largest
per-file cases remain direct full-image tests.

Logs are `artifacts/plan-file-security-*-owner-fixed.log`; current external
reports are `artifacts/interoperability-file-security-{owner-fixed,descriptors-owner-fixed}/`;
system observations are `artifacts/file-security-system-inventory/`; fuzz is
`artifacts/fuzz-file-security-validation-owner-fixed/`. Do not promote preceding
directory timings to a new source comparison. Native Windows, installed FSKit,
identity/owning authorization, recovery and the full measured optimization
program remain required under CORE-QUALIFICATION.md.

Both isolated ordinary Release/O3 builds match all eight actual portable products
under `artifacts/reproducibility-file-security/`, with unchanged source during
the comparison. The fresh retained abstract model uses coherent per-file
descriptors: 49,855 states, 47 current native-byte endpoint/diagnostic/content
checks and four unsafe witnesses pass under
`artifacts/recovery-model-file-security/`. Main review checks full products,
independently re-authored inputs, every metadata endpoint/unowned byte and
actual tools, external packets and replay paths in
`artifacts/file-security-review.json`. These remain local reproducibility and
abstract/native-byte evidence, without a product writer or native log replay.
Earlier model reports have earlier diagnostic scope; preserve them as history.

## Preceding indexed security-store checkpoint

`ntfs_security_store_validate` now completely traverses supported SII/SDH trees,
inventories both used allocation bitmaps, checks exact cross-index membership
and nonoverlapping SDS intervals, then validates every indexed hash/descriptor/
copy. General `ntfs_validate` additionally rejects missing nonzero base-FILE
security references. SECURITY.md and VALIDATION.md define partial subjects,
operation/storage caps and the scope of `complete`; free/unindexed SDS and
zero-ID per-file payload semantics remain opaque to the general diagnostic.

The current source passes 64 sanitized-build suites, both freestanding targets
within 2 KiB, style, 22 legacy component groups/eight explicit modern-runtime
SKIPs and an unsigned arm64/x86_64 Release app. Both independent four-geometry
oracles pass unchanged, including complete leaf-view membership/store counters.
Current logs are `artifacts/plan-secure-store-*-reviewed.log`; SECURITY.md records
the 46 store/seven complete-volume verdicts and exact fault/budget evidence.
Image/validation fuzz replay all 323/125 authored seeds and pass 53,736/57,077
executions with zero OOM/timeout/crash. Five store layouts outside the compact
1-MiB envelope retain full direct-suite coverage; actual replay/binary/descriptor
evidence is reviewed in `artifacts/secure-store-review.json`.
Both isolated ordinary Release/O3 builds match all eight actual portable
products under `artifacts/reproducibility-secure-store/`. Fresh current-only
legacy directory baselines pass 54 runs/six complete inventory summaries;
PERFORMANCE.md records actual large/small page settings, O2 adapter/O3 core
configuration and the absence of paired/installed gain claims. Actual product/
source/input evidence is independently reviewed in the same review report.
The 64-KiB external geometry still compares only four mirror records and reports
60 declared tail records as unchecked. No native mount, Windows access decision,
identity mapping, recovery or commercial qualification was performed.

Preserve the bounded immutable-media and serialized-owner contracts. Next security
work includes native Windows full-view/fragmented-store observations, zero-ID
payload qualification, other metadata views, complete Windows/native identities
and owning authorization. Do not treat diagnostics or DACL evaluation as an
access grant. Historical checkpoints below retain their source-specific scope.

## Transaction reference-model checkpoint

Read RECOVERY-MODEL.md before treating any model replay as native recovery.
`tests/transaction_model.py` supplies an exclusive serialized in-memory owner,
complete immutable snapshots, reservation/private/log credits, WAL/commit/home/
checkpoint ordering, sticky uncertain I/O and cleanup without writes. The simulator
injects partial/full sector transfers, arbitrary pending-cell persistence and
interrupted recovery/retirement. It uses typed observations, not serialized journal
bytes; the public core and FSKit remain read-only.

The final model passes 49,855 crash/fault states across deferred commit, steal
commit and steal abort, 22 ownership contracts, 14 history refusals, 1,205 recovery
interruptions and four unsafe-order witnesses. Forty-seven actual reconstructed
8-MiB images pass complete read-only native diagnostics and exact content reads.
Review checks both authored endpoints, actual tool/image digests, all native JSON
reports, complete metadata bytes and unchanged unowned image spans. Evidence is
under `artifacts/recovery-model-retirement-fixed/`. All 62 sanitized-build suites,
build and style pass under `artifacts/plan-recovery-model-{build,suite,style}.log`.
ACCEPTANCE.md retains the two initial harness failures and first successful run.

Preserve the reference model's single-history scope. Extend its foundation with
qualified native journal ownership/current history, checkpoint tables/opcodes/CLRs,
interleaved transactions and broader allocation/security/concurrency failures.
Real device barriers, native Windows replay/chkdsk, installed FSKit and full
WRITES.md acceptance remain required. This checkpoint changes no product source
and qualifies no writable operation or commercial release.

## Accounting measurement checkpoint

The benchmark runner now retains binaries, validates ordinary release evidence,
requires matching toolchain/workload/POSIX sources for paired variants, alternates
execution order and checks independent read ranges/prefix samples alongside full
before/after content hashes. Fifty-eight helper contracts and six-path paired
smoke pass; canonical-path failure evidence remains in ACCEPTANCE.md.
Ten input matrices pass 2,880 runs/160 paired configurations with nine repeats
per variant. PERFORMANCE.md describes the measured guard cost and retains broad
data/native/Windows/independent-driver limits; historical adapter gains remain
scoped to their earlier source.

The governor now obtains sticky failure from the head because every required
refusal propagates to all ancestors and begin rejects exhausted parents. It
clears usage before assigning the remaining fields, with unchanged ancestor
credit preflight. All 61 suites, both freestanding targets, style, component
22 PASS/eight SKIP and unsigned Release operation source on both architectures
pass. The 32-level test exercises every denying ancestor, all propagated flags,
unwind and reuse. A matched 2,880-run matrix has overlapping wall ranges and mixed
medians; 120 longer confirmation runs qualify only the cached resident read
profiles (2.18%/1.55% wall, 15/15 faster pairs each with CPU confirmation).
Opens remain mixed and read p99 is unchanged at clock resolution. Both isolated
ordinary Release/O3 builds and all eight actual portable product byte comparisons
pass under `artifacts/reproducibility-accounting/`. Current-only legacy directory
baselines also pass 54 runs/six summaries with complete independent inventories
under `artifacts/fskit-directory-accounting-{large,small}/`. The real handler
includes compound core/physical scopes; its older matched-reference archive gate
remains intact. PERFORMANCE.md records scope, ranges and actual input/product
review. The current image campaign also replays all 282 unique authored seeds
and passes 52,898 executions/70 seconds with zero OOM, timeout or crash events
under `artifacts/fuzz-accounting-image/`. Configured RSS is a ceiling, not an
observed peak; longer campaigns and Windows seeds remain required.
Preserve the complete continuation in
CORE-QUALIFICATION.md; this checkpoint enables neither native authorization nor
writes/recovery or a commercial release.

## Ordinary directory inventory checkpoint

The diagnostic now compares the complete `$I30` bitmap with the fully traversed
cursor's bounded visited-block set. Used unreachable/out-of-span slots and partial
allocation records fail with the owning directory's subject; free storage stays
opaque and unread. This diagnostic-only check changes no ordinary FSKit directory
operation. Read VALIDATION.md for slot/VCN units, work credits and the explicit
consistency inference from original format research. View indexes and Windows
qualification remain open.

All 60 sanitized suites, both freestanding 2-KiB-frame targets, style, 22 component
groups/eight modern-runtime SKIPs and an unsigned Release app compiled for both
architectures pass. The 118-image inventory includes 22 new cases, 237 added
allocation/191 read fault positions, six partial/full bitmap failures and nine
pre-callback read/work budgets. Validation fuzz fixed-replays all 118 seeds and
passes 54,415 executions; four independent bitmap/mirror-export geometries pass
with unchanged images. ACCEPTANCE.md retains exact logs and the corrected
diagnostic subject bug. It also distinguishes independent exported metadata from
the product's used-slot check. Earlier Release reproducibility predates this
inventory source; Windows/native authorization, recovery and the complete
optimization program remain part of CORE-QUALIFICATION.md.
The subsequent current-source ordinary Release/O3 comparison passes both builds
and all eight full archive/CLI byte comparisons under
`artifacts/reproducibility-index/`. Review independently checked actual equality,
lengths and reported digests. Its separate-build-directory/same-checkout scope
qualifies no relocated source, native app/signing or remote CI execution.

## Operation-budget checkpoint

The mounted reader now has cumulative read/allocation/work ceilings plus one
aggregate core live-storage cap. Public owning calls have implicit scopes;
compound FSKit requests use explicit core scopes and separate rounded-physical
read scopes. Nested calls charge every ancestor, refusal precedes callbacks and
cleanup remains available. Terminal native teardown detaches caller scope storage
before core release. Optional validated-record retention may be omitted without
poisoning a required read. Read OPERATION-BUDGETS.md before changing boundaries,
units, retry or ownership. The public API is now version 2: rebuild all callers
and use `ntfs_default_limits` before overriding policy fields.

At the operation-budget checkpoint, local evidence passed 60 sanitized core
suites, both freestanding 2-KiB-frame targets, style, 22 component PASS groups/
eight explicit modern-runtime
SKIPs and the unsigned Release app compiled for arm64/x86_64. The operation suite
includes 12 storage/operation profiles and 144 exact/one-below boundaries, plus
mount/nesting/callback/live-storage/cache/codec retries. Image/validation campaigns
fixed-replay all 282/96 authored seeds and pass 51,427/57,672 executions. Four
independent NTFS-3G image geometries still agree on exact files/ADS/names and remain
unchanged. Exact logs and earlier failed test attempts remain in ACCEPTANCE.md.

The committed operation source also passes two isolated ordinary Release/O3
builds and all eight full archive/CLI byte comparisons under
`artifacts/reproducibility-operation/`. Review independently re-read every product
and checked equality, lengths and reported digests. Compiler/SDK, source revision
and selected options remain in its generated report. Relocated sources, native
app/signing and remote CI still need separate execution.

This is a resource-contract checkpoint. Windows acquisition, installed behavior,
full owning authorization, journal history/recovery, crash/durability simulation
and commercial distribution remain open under the full CORE-QUALIFICATION.md
scope. Native Foundation/response/window/kernel memory and synchronous-I/O
deadlines are separate from the core budget. Prior retained performance results
predate these guards; current accounting overhead remains unmeasured.

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
python3 scripts/build_fskit.py --configuration Release
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
without hiding objects or inventing ordinary-file sizes. Backend exact dot lookup
now shares checked ancestry; installed path semantics remain unqualified.
Broader checkpoint/index reuse, native scheduling and buffer lifetime also remain
open.

## Bounded native directory continuations

An enumerated item now lazily owns at most two independent actual core cursors.
The table uses the resource allocator and retains separate pending entries,
native views, visible positions, cumulative inspected-work credits and failures.
Noninitial cookies use an exact or nearest earlier same-view position; misses
replace a completed cursor, unused slot or least-recent inactive slot before
opening a new one. Initial cookies always start fresh. Completed-scan replacement
keeps repeated sequential scans to one retained core cursor and preserves cached
EOF without I/O/allocation. Native aliases/cookies/verifiers keep their meanings.

Packing pins a slot and the item admits at most two recursive enumeration calls,
including virtual entries and calls across detach/remount. A third returns EBUSY.
Unmount/invalidation close every core child, detach the table and advance an item
epoch. The old native call precisely retains the table allocation and allocator
until its C pointer is no longer used. Epoch checks return ESTALE after reentrant
remount even if admission has reopened; the immutable owner's persistent verifier
remains valid for a later retry. Elevated-pressure completion closes older
inactive slots while protecting the latest/pinned positions. Do not copy or
share core cursor frames, visited sets or scan budgets to extend this cache.

The final sanitized component passes 20 groups/seven modern-runtime SKIPs under
`artifacts/plan-directory-component-complete.log`. Thirty-two cases cover four
layouts, same/separate views, exact resumes, failed new opens, third-position
eviction and pressure. Refused physical index-prefix reads distinguish reuse from
replay. Reentry, virtual/stored remount, terminal invalidation, recursive remount,
completed-scan reuse and cached EOF have separate checks. Names-only passes all
34 allocation/13 read faults; interleaved pages pass all 151 allocation/41 read
faults with exact prefixes, one reply, fresh-scan retry, unchanged media and zero
leaks. The unsigned Release app compiles the changed owner for both architectures
under `artifacts/plan-directory-app-complete.log`; style passes under
`artifacts/plan-directory-style-complete.log`.

`scripts/benchmark_fskit_directory.py` and
`tools/fskit_directory_workload.m` measure the actual legacy handler against
independently authored complete inventories. The final large/small reports under
`artifacts/fskit-directory-{large,small}-sustained/` retain 54 paired runs each,
nine repetitions per profile/version, alternated binary order and explicit warmup
with the MFT cache disabled. Adapter/workload O2 and ordinary Release/O3 core are
unsanitized. Review verified full retained binaries and source/input/archive
digests; only the owner source changes between matched versions. Six original
namespace images remain byte-identical under `artifacts/directory-fixture-before/`.

On the 2,000-hard-link/alias workload, interleaved/separate-view wall medians fall
by 88–89% and physical reader calls from about 1.05 million to 64 thousand. The
12-link workload improves by 32–35%. Sequential changes of +1.35%/-1.68% have
overlapping ranges and establish no stable material gain or regression. Added
peak resource-pool costs are 1,152 bytes sequentially and 53,016/16,537 bytes with
two readers on the large/small inputs. The pool includes C children/charged table,
excluding Foundation/window; process RSS is separate. Earlier compile/preflight
failures and shorter paired reports remain retained. PERFORMANCE.md and
DEVELOPMENT.md give the reproduction commands, counters and evidence boundaries.

Core/include/POSIX/portable CLI sources are unchanged; the preceding 59-suite,
freestanding and eight-product Release evidence was not rerun. This is a targeted
memory-reader optimization, with no installed or macOS 27 acceptance. Continue
the full CORE-QUALIFICATION.md plan: diverse independent/Windows-authored files,
more than two interleaved positions, bounded checked-index/checkpoint reuse,
native cancellation/authorization, real pressure/device profiles and the complete
journal/transaction/crash/durability work. No VM or installation was used and no
write capability is enabled.

## Required mirror-prefix diagnostic

`ntfs_validate` now opens fixed slot 1's complete unnamed stream and verifies the
required first four logical MFT replicas independently of ordinary mount. It
checks ordinary nonresident storage, the boot starting LCN and initialized/whole
record coverage through the existing fragmented/listed stream owner. Allocated
copies pass FILE/MST restoration and compare used bytes excluding protection
state/slack; free slots require exact opaque raw replicas. All extents still
undergo ownership/bitmap checks. Windows-dependent extended tails remain
explicitly unqualified; no copy is selected for repair. See VALIDATION.md for
sources, errors, counters and budgets. Stage MIRROR is appended to preserve
existing numeric stage values; do not interpret enum order as pass order.

All 39 new direct C/CLI cases, 96 total CLI verdicts, seven budgets,
1,068 allocation/772 read failures,
80 partial/full mirror-stage read failures and 48 prefix-budget checks pass.
The original 57 image hashes remain unchanged. All 59 sanitized suites, style,
both freestanding 2-KiB-frame targets and the unsigned arm64/x86_64 Release app
pass under `artifacts/plan-mirror-*.log`. Current adapter behavior is unchanged;
the preceding component evidence and modern-runtime SKIPs still apply separately.
The initial compile/fixture failures are retained alongside passing logs.

Four external mkntfs profiles in `artifacts/interoperability-mirror-reviewed/report.json`
match independent bitmap inventories, exported FILE allocation geometry and exact
required prefix bytes.
The 64-KiB-cluster profile compares four of 64 declared records, reporting 60
unchecked; image hashes stay unchanged. The bounded validation campaign
fixed-replays all 96 compact inputs and completes 59,760 executions/68 seconds,
coverage 3,289/features 9,107 and reported crash/timeout/OOM counts of zero under
`artifacts/fuzz-mirror-validation/`. Its 1-MiB input, 1024-MiB RSS ceiling and
five-second timeout are policies, not complete coverage or observed peak RSS.

The committed diagnostic passes both isolated ordinary Release/O3 builds and
all eight archive/CLI full byte comparisons under
`artifacts/reproducibility-mirror/`, with launcher evidence in
`artifacts/plan-mirror-reproducibility.log`. Review independently re-read the
actual products and verified equality, reported lengths and digests. Source
revision and artifact hashes remain in the generated report. Relocated-source,
native app/signing and remote CI acceptance remain open.

Native Windows replica observations, extended tails, boot replicas, complete
store/index checks and the full recovery/transaction simulator remain required
under CORE-QUALIFICATION.md and WRITES.md. Ordinary mount's strict record-zero
comparison/dirty rejection and the absence of a write callback are unchanged.
No VM, installation, Windows acquisition or native recovery was performed.

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
The committed binding also passes both isolated ordinary Release/O3 builds and
all eight archive/CLI byte comparisons under
`artifacts/reproducibility-logrestart-record/`, with command evidence in
`artifacts/plan-logrestart-record-reproducibility.log`. Source revision and
artifact hashes stay in that generated report. Relocated/native app and remote
CI scope limits remain open.

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
   Windows-authored links and installed mounts, including the implemented bounded
   intermediate chains. Extend hard-linked reparse identity and cross-volume ownership through explicit
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
