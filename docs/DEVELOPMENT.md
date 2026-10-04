# Development

Run standalone commands in `/Users/darekhta/Development/machlin/ntfs` (or the
equivalent checkout). Use the ongoing development branch. Generated state lives
under `.build/`, `artifacts/` and `vendor/`, all ignored. Xcode clang/clang-format,
Meson, Ninja, Python 3 and XcodeGen are development prerequisites.

`make test` configures the sanitized C build, generates deterministic images and
runs its tests. `make check-style` checks C formatting; `make format` applies it.
`make fskit` builds the app and extension unsigned. Builds never install the
extension or touch boot policy. Installed tests belong in a dedicated stock macOS
VM; use the absolute lab working directory for its VM commands.

Routine prepared execution is delegated to Luna; implementation and diagnosis
remain with the main agent. Sol owns VM preparation and installed FSKit work.
Record reports in artifacts, source history in Git, and summaries in acceptance.
Never interpret an unsigned build as an installed mount or a commercial release.

The optional offline public-corpus comparison uses existing NIST DFR-15/16/17
partitions and ignored standalone NTFS-3G tools. Obtain archives from the NIST
links in PROVENANCE.md; their documented single type-07 partition starts at byte
65,536 and spans 300 MiB. Retain acquisition and extraction hashes separately.
Name the extracted files dfr-{15,16,17}-ntfs.partition.img and run:

```sh
python3 tests/nist_corpus.py --images artifacts/public-corpus-nist-acquired --output artifacts/nist-corpus-comparison-new
```

The output directory must be fresh. Local first-acquisition pins guard inputs;
they do not establish publisher digest authority or a Windows author. Documented
normal names, full normal/DOS inventories and identities, metadata wire exports,
all readable user streams, selected descriptor bytes and raw symlink packets
have independent oracles. Ordinary symlink data reads must refuse. The runner
supports common/extended standard information and indexed/per-file descriptors.
Each object's physical/primary/DOS counts compare with exported FILE_NAME
namespace labels. Original per-record ntfsinfo and selected security packets
are retained. Structural root observations are separate from the 1,133 documented
user paths. Its resident-leaf SII oracle does not independently inventory an
allocated SDH tree. The command cap is 12,000 per profile, covering ten calls per
object in the largest 1,031-object profile plus directory/store/root work. Pipe
output, files and total run time are bounded; actual binary
digests, original exports, diagnostic reports and unchanged image hashes remain
in the output. This test downloads nothing, mounts nothing and does not enable
an extension. Windows acquisition and installed acceptance remain separate.

Native activation requires an explicit read-only extraction choice at load or
activation: -o ntfs-access=extract. Windows ACLs are not enforced. Ordinary loads
without the choice still support maintenance, but cannot activate. Internal
component/workload callers use activateExtraction:; native messages use task
options. NATIVE-ACCESS.md defines exact parsing, metadata and installed limits.

The access component models unary load and both activation message families
without acquiring a real device. It checks invalid configuration before resource
creation, explicit load/activation selection, parser count/string boundaries,
root allocation refusal/retry, native presentation and remount/terminal lifetime.
The current component has eleven macOS-27 runtime SKIPs, including extraction
activation. Directory smoke reports qualify the migrated internal activation
entry point and policy module list, with no optimization claim.

`scripts/check_core.py` additionally compiles arm64 and x86_64 objects on macOS
without libc assumptions and with a 2 KiB frame limit. `scripts/test_fskit.py`
exercises the real adapter against a bounded fake resource in-process; it neither
mounts an image nor enables an extension. `scripts/fuzz.py --seconds 60` builds a
separate libFuzzer binary with ASan/UBSan and bounded memory/I/O. Failures retain
their corpus input under artifacts/fuzz for diagnosis.
If the selected macOS toolchain lacks libFuzzer, pass a full LLVM compiler, for
example `--compiler /opt/homebrew/opt/llvm/bin/clang`; a failed runtime preflight
is not a completed campaign. The SDK still comes from the selected Xcode.
The component includes eight semaphore-gated resource-read/lifecycle scenarios
with both a private-window request and an explicitly aligned caller buffer
(16 gated cases), and interleaved enumeration with five-second test deadlines. Modern runtime
checks explicitly SKIP without macOS 27. See LIFECYCLE.md for admission/teardown
ownership and the absence of a native synchronous-I/O timeout guarantee.
Five additional modeled eligibility/ownership/publication cases cover conditional
reclaim, weak canonical identity, final-item lifetime and lookup replies racing
reclaim/unmount/deactivation. The eligibility model does not execute the real
macOS 27 kernel/framework count mechanism.
The separate enumeration component checks names-only virtual current/parent
entries, parent release/remount and corrupt-edge rejection, separate native cookie
views, alias stability, interleaved buffers, scan budgets, packer revocation and
all 34 allocation/13 I/O fault positions in its current names-only nested-index
operation. Two retained continuations also have 32 layout/view/reuse/eviction/
pressure cases and an interleaved 151 allocation/41 I/O sweep. Callback reentry,
recursive remount, detached table lifetime, completed-scan replacement and cached
EOF have explicit ownership checks. The
content component additionally exercises six encoded-stream metadata variants and
ten explicit corruption/unsupported rejections, requested-size pages, independent
ADS, zero-byte read errors, remount and revocation without default-content I/O.
The link component authors 81 native path/storage verdicts and checks root option
binding, unique-edge identity, intermediate within-owner chains, requested
metadata/names-only pages, aliases, original-wire xattrs, remount/revocation and
all 320 allocation/69 read fault positions across listed/reserved and chain lookup
and reopened snapshots. Every read position receives partial and full failed
transfers. Four listed source/chain profiles additionally exercise 56 exact/one-below core and
rounded-physical ancestor boundaries, checking the specific exhausted dimension,
allocation versus read/work errors, successful scope closure and fresh retry.
Core reparse tests
also check copy guards, physical allocation and node-independent lifetime. See
LINK-POLICY.md for the supported subset and remaining resolution contracts.
The preceding component had ten explicit macOS-27 runtime SKIPs: lifecycle,
operation budgets, pressure, enumeration, dot lookup, content metadata, link projection and
two case-policy checks and the temporary maintenance identity. These in-process
results do not mount the filesystem.

The resource-bound maintenance component also compiles the actual filesystem
controller and checker. Public-message task/options/device doubles drive full/
quick/forced checks and asynchronous refusals without a daemon-acquired resource.
It sweeps required/optional allocations and partial/full physical reads, tightens
memory/I/O/work credits, and gates cancellation, revocation, teardown, blocked
load and active-read/publication admission. Its five-second cancellation-drain
timeout deliberately keeps borrowed buffers owned until the gated read returns;
test deadlines include drain grace. Current-source components, both app
architectures and installed task behavior remain distinct evidence. LIFECYCLE.md
defines option, progress, failure retention, temporary identity and native limits.

The separate `operation` suite checks 12 storage/operation profiles and 144
exact/one-below thresholds across cumulative read/allocation/work and aggregate
live storage. Mount/ABI admission, nested scopes, callback reentry, failed
attempts, optional-cache omission, sibling storage and decoder retry have separate
checks. The native operation component executes physical rounding/fragment,
compound/nested quota, publication/packing and terminal detach paths. Public API
version 2 requires rebuilt callers and complete default-initialized limits; see
OPERATION-BUDGETS.md for policy units, output and lifetime contracts. Existing
diagnostic/journal and native namespace/response caps remain separate.

The pressure component injects Dispatch data-source notifications without host
pressure changes. It measures disposable core bytes for LZNT1/XPRESS/LZX, delivers
an event during blocked I/O, sweeps cold LZX allocation/read faults and checks
copied ADS/reparse data, identities, interleaved pending entries and remount.
See READ-CACHE-POLICY.md for exact measurements and native delivery/stress gaps.

`tests/fskit_lookup.m` additionally checks exact native dot lookup, root clamping,
canonical reuse without callbacks, released-parent reconstruction, stored-dot
aliases, remount/revocation and every required cold-parent allocation/partial/
full read fault. Explicit enclosing core/physical scopes exercise exact and
one-below credits without replacing zero limits with invalid API inputs. Separate
weak declarations keep parent-release assertions independent of ARC declaration
binding; LIFECYCLE.md records the compiler diagnostic and acceptance scope.
Modern result checks explicitly SKIP without the macOS 27 runtime.

`tests/extent_fixtures.py` separately authors six 16-MiB immutable images and
independent 4-MiB content oracles under `.build/extent-fixtures`. The default
Meson build tracks that author and its canonical wire helper. Profiles contain
one, sixteen, 256 or 1,024 unmerged runs, up to eleven attribute records, sparse
holes and a VDL tail. The `extents` suite checks every run edge, full contents,
random/reverse/interleaved independent streams, guarded EOF/zero reads, unchanged
images and exact allocation cleanup. It forbids read-path allocations and
exercises 34 partial/full I/O failures plus 36 compound credit boundaries.
Use those `.data` files as `--expected-data` for `scripts/benchmark.py` and retain
both ordinary Release reports for alternating paired measurements. PERFORMANCE.md
records the actual input/callback scope and workload-specific tradeoffs.

The native directory workload checks every name, identity and requested size
against independently authored namespace inventories. It measures the actual
legacy protocol handler on an immutable memory reader with separate warmup. Use
the prepared native images, whose selected filename storage is complete. Record
caching defaults to zero; --record-cache-entries profiles zero through the normal
default 64. Use a new artifact directory for each execution:

```sh
python3 scripts/build.py .build-release --release
python3 scripts/benchmark_fskit_directory.py .build/native-fixtures/namespace-large.img .build/native-fixtures/namespace-large.json --build .build-release --output artifacts/directory-before --pages 8 16 --rounds 1 --warmup-rounds 1 --repetitions 5 --record-cache-entries 64
# Retain that binary before changing the adapter, then compare both versions:
python3 scripts/benchmark_fskit_directory.py .build/native-fixtures/namespace-large.img .build/native-fixtures/namespace-large.json --build .build-release --output artifacts/directory-after --reference artifacts/directory-before --pages 8 16 --rounds 1 --warmup-rounds 1 --repetitions 5 --record-cache-entries 64
```

The default reference requires identical inputs, workload, core and toolchain.
For complete core-version comparisons, add --compare-core together with
--reference: every adapter/workload/public-header hash must then remain identical,
while retained core archives may differ. Machine, input, policy, compiler/SDK,
passing-reference and actual-binary guards still apply. Both
binaries run with the new invocation's parameters; their earlier measurement
settings may differ. Reports retain both parameter sets, binaries, source/input
digests, exact inventory outcomes and per-run counters. PERFORMANCE.md records
the memory tradeoff and the limits of this synthetic component profile.

Use `--target all` for the image, whole-volume diagnostic and ten standalone parser/decision targets, or select
`mapping-pairs`, `attribute-list`, `index-root`, `index-block`, `lznt1`, `reparse`,
`security`, `access`, `wof` or `logfile`. The time budget applies per target. Each campaign retains its own
binary, log and report; persistent corpora remain under the selected `--output`.
Whole-image `image`/`validation` exploration uses one libFuzzer child at a time
with bounded corpus subsets and merges. Fixed-file batches first execute every
authored seed once and retain `seed-replay.log` plus its report outcome; child
subset selection alone is not seed-coverage evidence. OOM/timeout/crash remain
fatal, with unchanged sanitizers, five-second input deadlines and a 1-GiB
per-process RSS ceiling. Image/validation resources now admit up to 1 MiB plus
4 KiB for the reserved boot sector; the authored data span remains 1 MiB.
Standalone parser envelopes remain separate. The configured
RSS ceiling is not actual or aggregate memory usage. The observed earlier image
corpus OOM and its fixed replay remain separately recorded in ACCEPTANCE.md.
The `access` target also replays every authored input before exploration. Its
request/stored generic-mask seeds distinguish concrete grants, unsupported raw/
mixed ACEs and nonapplicable inherit-only entries, with ordinary and restricting
contexts. These checks exercise the discretionary evaluator, not native identity
mapping or Windows acquisition.

Fuzz children, FSKit component children and bounded diagnostic tools use
`sanitizer_environment()`: the normal tool allowlist plus explicit ASan/UBSan
halt/abort options. Ambient options cannot restore recovering behavior. Meson's
sanitized setup already selects fatal options. Exit zero alone is insufficient
when a runtime can report and continue; see
[Clang's UBSan runtime contract](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html).
The `sanitizer-runtime` suite compiles two disposable, separately instrumented
programs with the selected Clang and an explicit macOS SDK. Clean controls exit
zero, a recovering UBSan control reports its injected fault and exits zero,
and hardened UBSan/ASan faults terminate. The actual bounded diagnostic wrapper
must also reject each injected fault. These expected negative-test diagnostics
are kept separate from driver findings; the suite does not read filesystem images
or access devices. Only selected sanitizer options are retained in reports.

The image target additionally selects one tightened operation dimension from a
named control seed, walks public owning calls under shared credits and compares
usage with independent allocator/read attempts. This complements its original
full walk; it does not replace successful content exploration with quota refusal.
The `logfile` target uses a 2-MiB envelope for restart/client/page/logical-record/
NTFS-update/LSN primitives and complete exported logical sources. Its custom
mutator restores and reseals USA pages or either restart copy, reaching checked
restart-area spans alongside ordinary framing mutations. The `logfile`,
`logfile-cli` and `fuzz-logfile` suites check independent metadata/restored-byte
oracles, zero errors, scratch/input guards and lossless names. `ntfs-logfile`
inspects bounded exported packets/logical journals and read-only NTFS image files. The `logfile-source`,
`logfile-source-cli` and `fuzz-logfile-source` suites cover bounded copy selection,
conflicts, cached clients, staged physical pages, backend errors and read credits.
The `logfile-records`/`logfile-records-cli` suites add exact physical circular
assembly, one wrap, extended/USA-intersecting bytes, shared credits and the
1-MiB record-cap boundary. `circular-record LOGICAL_JOURNAL_FILE DECIMAL_LSN`
retains exact bytes and physical accounting with no current-history claim.
The two record fuzz suites check resealed record/continuation mutations and
explicit fault/budget controls. The logfile campaign first replays every authored
seed in fixed batches; its report lists 28 included record sources, six fault
seeds and the two complete 4-MiB sources excluded by its unchanged 2-MiB cap.
Direct C/CLI tests retain both larger sources without truncation.
The `logfile-clients`/`logfile-clients-cli` suites check 858 pair lookups and 42
exact reports across seven active/free snapshots, including sequence boundaries,
full-length unpaired names and the client-count limit. `active-client
LOGICAL_JOURNAL_FILE INDEX SEQUENCE` reports selected active snapshot metadata.
The `fuzz-logfile-clients` suite and dedicated campaign check the same cached
lookup with mismatched sequences and no extra I/O/allocation. Snapshot membership
does not qualify record liveness or current journal history.
The `logfile-checkpoint`/`logfile-checkpoint-cli` suites add 77 independently
authored NTFS client restart common-prefix verdicts and 75 exact packet reports
plus two transport rejections. `client-restart NTFS_CLIENT_RESTART_PACKET` retains
the client version, raw analysis/table anchors/counts and opaque extension span.
The separate `fuzz-logfile-checkpoint` smoke and 77 authored campaign seeds check
deterministic fields/zero errors and immutable guards; structured mutation focuses
on the common prefix even when its tail is large. This does not interpret tables,
optional extensions, current history or recovery; see LOGFILE.md.
The `logfile-restart-records`/`logfile-restart-records-cli` suites add 165 complete
source/record verdicts and 161 exact binding reports/four transport checks.
`client-restart-record LOGICAL_JOURNAL_FILE ASSEMBLED_RECORD` checks selected
type/active identity/exact NTFS name/restart LSN before prefix interpretation.
Its cached core operation reads/allocates nothing. The separate
`fuzz-logfile-restart-record` smoke and complete source/record campaign seeds
check deterministic outputs, guards, no cached callbacks and cleanup. Mutations
reseal source restart pages or focus on record context/common-prefix fields.
Physical/current-history provenance and native journal ownership remain open.
The `logfile-volume`, `logfile-volume-cli` and `fuzz-logfile-volume` suites add
counted ordinary-stream binding, fragmented/listed storage, source-node-independent
ownership, mount/binding rejection, physical partial-read faults/retries and
unchanged image/report oracles. `volume-journal` uses a portable core mount,
never a native mount. Image fuzz also authors small journal-bearing volumes with
explicit geometry skips for larger layouts; source/component suites retain them.
All 22 independent sources fit the fuzz envelope, including three 1-MiB files;
default core memory/I/O caps remain unchanged. LOGFILE.md defines commands and the
remaining complete-journal, LCN-less, Windows and recovery requirements.
The `recovery-model` suite executes the original in-memory transaction/durability
reference model with separately authored native NTFS endpoints. It neither writes
a device nor mounts media. To retain all representative regular-file images,
native diagnostic reports and a bounded exploration report in a new directory:

```sh
python3 tests/recovery_model.py .build/ntfs-inspect .build/ntfs-validate --output artifacts/recovery-model-next
```

The ordinary suite uses a temporary directory; the retained run preserves failed
attempts. Child diagnostics have output/deadline limits and the explorer has a
hard state ceiling. See RECOVERY-MODEL.md for typed history, persistence subsets,
logical reservation credits and unqualified native recovery/Windows contracts.
The `access` target independently mutates a descriptor/token envelope, including
group attributes, user/restricting SIDs, requested rights and comparison limits.
It asserts deterministic decisions, exact grants and zero error outputs. See
ACCESS.md for the discretionary contract and remaining authorization policies.
The `wof` target independently mutates provider metadata, bounded chunk tables
and exact-size XPRESS/LZX units with a 128-KiB input ceiling. It checks deterministic
verdicts/counts and scratch/output guards; no filesystem provider reads or Windows
codec execute. `tests/wof_fixtures.py` and `tests/lzx_fixtures.py` author its seeds
and separate content/error vectors. The separate `wof-files` suite authors 37 complete storage/format cases,
byte oracles and 390 allocation/101 read faults in selected stat/open/cold-content
operations. The ordinary image target reads first/middle/tail default positions
and therefore also exercises provider storage/table/content lifetimes. Twenty-three
legacy component cases cover WOF attributes/content, backing inventory, ADS/raw
metadata and remount/revocation; modern content checks retain their runtime SKIP.
The LZX suite checks 140 content/31 invalid vectors; the optional external oracle
command in WOF.md checks captured wimlib packets and reverse-direction synthetic
decoding without linking that codec into product binaries. See WOF.md for contracts
and remaining Windows/native qualification. FSKIT-EXT4-LESSONS.md records the
inspected sibling history, adopted result/error and revoked-acquisition guards,
and native/memory-pressure/distribution work still required.
Image mutation can preserve FILE/INDX fixups and alter validated inner spans.
The fuzzer authors 1-MiB physical images instead of retaining unused 8-MiB tails
for every corpus entry. All fixture payload locations and large logical sparse
sizes are preserved. The corpus directory includes the input-size bound so older
full-image corpora remain available without being loaded into the compact run.
The process RSS budget stays 1 GiB, independently of the harness's 8-MiB core
allocation budget. A corpus-growth RSS failure is still a failed fuzz run and
must be reported and diagnosed before retrying.

Reparse fixture generation supplies both full images and small standalone
`.reparse` buffers. The reparse target seeds standalone buffers; image fuzzing exercises the decoder
and opens/copies reparse metadata through the public node API. Inspect metadata
without following Windows targets using
`.build/ntfs-inspect .build/fixtures/reparse-relative.img reparse /hello.txt`.
The inspector prints UTF-16 code units so unpaired surrogates remain visible.

Some Xcode distributions omit the libFuzzer runtime. In that case, pass an
explicit full LLVM compiler, for example `--compiler /opt/homebrew/opt/llvm/bin/clang`.
The harness reports a missing runtime before linking. Core and FSKit acceptance
still use the selected Xcode toolchain; this override is only for fuzzing.

The independent suite is `tests/interoperability.py`; bootstrap pinned external
tools with `scripts/bootstrap_test_tools.py`. It uses regular image files only,
and refuses to overwrite earlier image inputs. See PERFORMANCE.md for release
build measurements. Sanitizers are not a performance configuration.

Build/test subprocesses receive an explicit environment allowlist. Meson's report
format includes environment values; do not invoke it with ambient credentials or
display entire unreviewed reports. CI uploads only selected generated reports.
The workflow is prepared for macOS/Linux core checks and independent Linux image
tests, but remote CI is unverified until the owner creates a private repository.

`corpus-contract` and `workload-contract` are regular sanitized suites. The former
checks reference-addressed inspection, independently expected stream bytes and
inventories, hard-link consistency, original UTF-16 and truthful partial reporting.
The latter verifies measured read ranges against original fixture bytes, ADS,
sparse/VDL/compression, explicit warmup, record-cache controls and serialized
readers on both POSIX and memory callbacks. Neither executes native Windows APIs.
An opt-in `strided` profile adds cyclic windows through `--stride` and
`--positions`; the benchmark runner exposes their plural matrix forms. Use
codec-unit strides to measure hot, alternating and wider compression working
sets. The focused workload/benchmark suites pass 47 measured profiles and 86
helper contracts; PERFORMANCE.md defines the schedule and measurement limits.
The FSKit component also verifies bounded stream xattrs and their raw UTF-16
reverse manifest. Filename projection adds five namespace images, hard-link and
lossless name reversal, response/scan exhaustion and complete required-allocation
and read-failure sweeps. Their formats and limits appear in NATIVE-NAMESPACE.md.
See CORE-QUALIFICATION.md for Windows-only acquisition and offline verification.

The separate `compression-cache` suite checks six LZNT1/XPRESS/LZX profiles with
independent original bytes, two-unit hits/promotion/eviction, crossing-unit and
partial/EOF reads, independent streams and counted lifetime. Required allocation
failure remains fatal; four optional-refusal modes preserve successful data and
do not repeatedly attempt storage. Fourteen partial/full replacement I/O faults,
twelve read-byte/work boundaries and compound optional-allocation/partial-read
failures check retained-output preservation, one-slot invalidation, fresh retry
and exact release. The WOF suite separately checks late codec errors. Current
FSKit pressure scenarios also fill both slots and verify their release/recreation;
see READ-CACHE-POLICY.md. Correctness evidence does not establish a speedup.

The separate `bad-clusters` suite checks complete unflagged system-stream
lists, metadata-only/public-content guards, forbidden bad-range reads, exact
callback accounting, required allocation/partial/full read faults and cumulative
operation boundaries. `validation-cli` checks all 32 additional complete-image
inventories/failure subjects; the image/validation campaigns retain compact
bad-cluster seeds for both public admission and private diagnostic paths. See
VALIDATION.md for counts, limits and native Windows gaps.

The `secure` suite checks descriptor storage as well as standalone MS-DTYP
framing. `ntfs-inspect IMAGE security-ref HEX_REFERENCE` emits the original
self-relative descriptor bytes, without opening file content.
`security-id HEX_SECURITY_ID` resolves an indexed ID directly. These are
read-only diagnostic APIs, not access decisions. See SECURITY.md.

The separate `secure-store`/`secure-store-cli` suites exercise complete indexed
storage, both allocation inventories, off-path corruption and FILE references.
`ntfs-inspect IMAGE security-store [MAX_DESCRIPTORS]` emits a bounded JSON report;
the optional cap is positive decimal. Whole-store work runs in one mounted
operation and can share an explicit caller scope. Ordinary FSKit lookup does
not implicitly scan the store. The general `validation`/`validation-cli` suites
also check selected zero-ID per-file bodies with complete authored inventories,
partial/full I/O faults, parser precharge and compound operation limits.
SECURITY.md defines free/unindexed/reserved-record scope
and the separate native authorization requirement.

The `access-oracle-contract` suite tests the independent Windows access collector,
SDK buffer framing, diagnostic transport and truthful offline reports with a
synthetic provider. The `ntfs-dacl-evaluate` executable accepts bounded original
descriptor/SID packets and emits the core's discretionary result; it does not
authenticate identity. Acquire decisions using `scripts/collect_windows_access.py`
on Windows, then compare with `tests/windows_access.py` on POSIX. Use new capture
and report directories. See ACCESS-ORACLE.md for commands and explicit native
qualification limits; no Windows acquisition has run at this checkpoint.

The `case-policy` suite covers stored directory flags and exact/folded lookup,
including collisions split across tree separators, mixed parent policies and
required allocation/read faults. `tests/case_fixtures.py` authors these images
without importing parser code. FSKit components cover sensitive aliases and
mixed directory identities; modern reply tests explicitly SKIP without macOS 27.
See CASE-POLICY.md and ACCEPTANCE.md for evidence and native acceptance limits.

The `stat` suite independently authors encrypted, unknown-compression and
unsupported-unit metadata, including resident/nonresident attribute lists. It
checks complete sizes/mappings, corruption and stale extensions, all required
allocation/read fault positions, retry, independent ADS and exact cleanup.
Private metadata-only descriptions cannot be read; both mapping-pair and
attribute-list fuzz targets exercise that separation. A synthetic metadata
verdict does not qualify EFS decryption or Windows-authored compression layouts.

`validation`, `validation-cli` and `fuzz-validation` qualify the private
read-only diagnostic. Run `.build/ntfs-validate IMAGE` for a JSON report; exit zero
requires a complete verdict. Seven positive-decimal options bound record/run/link
counts, live memory, read calls/bytes and work. The dedicated `--target validation`
campaign uses its own complete compact-image corpus and checks deterministic
reports, exact cleanup and dynamic budgets. Ordinary mount does not implicitly
run this diagnostic. See VALIDATION.md for supported passes and explicit gaps.
Boot diagnostic fixtures preserve a reserved sector after their declared data
span; they are larger than focused parser images. Maintenance, enumeration and
lookup test loaders pad that backing to their existing physical alignment
without changing the BPB or reserved-copy offset. Full checker tests include a
mountable damaged copy: quick scope succeeds, full scope fails and subsequent
activation retains EIO.
Compare both bitmap inventories, required mirror-prefix and declared boot-copy exports using existing
images and a new evidence directory:

```sh
python3 tests/validation_oracle.py --images artifacts/interoperability-stream-catalog --output artifacts/interoperability-validation-next
```

Compare against external NTFS-3G exports using an existing interoperability image
directory and a new evidence directory:

```sh
python3 tests/secure_oracle.py --images artifacts/interoperability-stream-catalog --output artifacts/interoperability-secure-next
```

The oracle applies deadlines/output budgets, verifies image hashes and retains
failed run status. It covers indexed and per-file descriptor storage; it does
not mount media or execute Win32/native authorization. The compact image fuzz
campaign includes security-storage inputs and the public snapshot API; larger
maximum-descriptor/second-pair/depth fixtures remain in the ordinary test suite
when their physical placement exceeds the compact image bound.

For repeated optimized measurements use `scripts/benchmark.py`, an independently
supplied original stream payload and a new artifact directory; see PERFORMANCE.md.
The runner checks Meson's selected release/sanitizer options and never displays
its complete option/environment reports. It records each run and integrity check,
including failures, instead of overwriting earlier output.

`scripts/benchmark_fskit_resource.py` separately compiles the real resource at
`-O2` and measures it over a deterministic immutable memory reader without a core
mount or extension installation. It retains its binary so `--reference` can
alternate matched baseline/candidate executions. Aligned and offset/address/length
profiles check bytes, caller guards, source hashes, physical transfer bounds and
callback destinations. See PERFORMANCE.md for exact commands and measured limits.
`tests/fskit_read_path.m` adds 120 geometry/fault verdicts at physical alignments
512/4096/65536, covering direct and window reads, mixed tails, EOF, short/partial/
full errors, over-reported lengths, retry and permanent revocation. Lifecycle
buffers own raw aligned memory; a mutable Foundation data wrapper may rehome it.

Compare reproducible portable Release products with:

```sh
python3 scripts/check_reproducible.py --output artifacts/reproducibility-next
```

The new output contains two ordinary Meson build directories, bounded combined
setup/compile logs and a JSON report. Compiled product sources must be committed;
ordinary Git checks them before and after the run and requires an unchanged
revision. Each build explicitly selects Release/O3, no sanitizers and the same
compiler/SDK and selected options. Eight archives/CLI products undergo full byte
comparison and SHA-256 checks. This qualifies distinct build directories in the
same checkout; relocated sources, FSKit app/signing and other toolchains remain
separate. The prepared CI matrix runs the same check, but remote execution has
not occurred. Build failures, deadlines and log-budget exhaustion fail the check
and retain bounded diagnostics; timeout cleanup targets only that build's process
group.
