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

## Writer control flow and Release checks

Check a fallible producer's result before consuming its output. When a function
owns resources, take the same cleanup path on failure and retain the exact size
used for each allocation. The directory constructor now retains its root buffer
size rather than deriving it from construction state during cleanup. Recovery
selects the final retained transaction only after proving the array is nonempty.
These conventions preserve callback order, error values and release accounting.
The image item's native rebind method likewise checks metadata, stat, link counts
and ancestry before transferring the node and publishing the item's fields.
Every failure keeps its existing single node-close path; locking, native replies
and authenticated open rights retain their original contract.

The selected Xcode Release compiler exposed conditional-initialization warnings
that the sanitized build did not report. The prepared strict check compiles every
core C source independently for arm64 and x86_64 with `-Os`,
`-Wconditional-uninitialized -Werror`, freestanding flags and the 2-KiB frame
ceiling. Keep its failed and corrected reports alongside the connected regression
and actual unsigned Release build. Explicit result guards and cleanup-size
ownership are reviewed separately from new journal/recovery semantics; see
[the refactoring plan](REFACTORING.md).

## Private ordinary-operation image CLI

The manual `ntfs-write-operation-image-tests` executable uses the experimental
complete-operation owner on a private ordinary image. It resolves ASCII acceptance
paths through checked full file references and closes every immutable core child
before preparing or executing a mutation. It does not mount media or enable FSKit
namespace/resize operations.

```sh
meson compile -C .build ntfs-write-operation-image-tests
mkdir artifacts/operation-create-prepare-next
.build/ntfs-write-operation-image-tests prepare PRIVATE_IMAGE create /fixture/new.txt FILETIME artifacts/operation-create-prepare-next
```

Replace `PRIVATE_IMAGE` with an inactive, exclusively owned disposable image and
`FILETIME` with unsigned decimal 100-nanosecond ticks since the Windows epoch.
The modes are `prepare` and `execute`; operations are `create`, `mkdir`, `remove`,
`rmdir`, `resize SIZE`, `write OFFSET PAYLOAD_FILE` and `rename DESTINATION REPLACE`.
`REPLACE` is zero or one. Write payloads are bounded ordinary files. The fresh
trace directory receives complete original/projected regions, physical publication
frames and `plan.json` before execution. The final JSON distinguishes requested
execution, actual execution, completion and permanent poisoning. Preparation
performs no writes. Retain the first failing invocation and its private image;
do not retry uncertain execution.

Ten connected private-fixture operations pass exact full-image, content, zero-gap,
time, full validation and fresh zero-rewrite recovery checks. Read-only create
preparation on the native checkpoint postimage also passes without changing media.
These CLI results are under `artifacts/overwrite/operation-image-cli-*`; native
execution of new FILE/INDX families remains a separate acceptance requirement.

For native Windows batches, use QGA for bounded manifests/reports and
`scripts/windows_image_archive.py` for full detached postimages. The receiver binds
the private VM interface, one exact peer and a bounded set of expected case/hash
pairs. Gzip transfer bounds both wire bytes and decoded image size; the host checks
the complete native post-detach SHA, persists the exact image and publishes a
read-only file before returning a receipt. Release only generated detached guest
copies after every corresponding host receipt and full file has been verified.
The release body first rechecks the complete group's paths, plain-file state,
detachment, sizes and hashes. Original disks/base images are never operands.
Transport failure preserves partials and returns no successful receipt; no native
case is repeated automatically. Five independent archive tests run as
`windows-image-archive` in the ordinary Meson suite.

## Installed image commands

The signed app exposes `--image-command status|import FILE_NAME|mount IMAGE_ID|unmount IMAGE_ID`
and `unmount-path MOUNT_PATH`. Use `scripts/fskit_image.py` with an explicit dedicated
Tart VM and a fresh ignored output directory. It always runs the installed app,
closes stdin and retains the native JSON reply, exits and raw diagnostics. It
changes no VM lifecycle state and never retries an invocation automatically.

```sh
python3 scripts/fskit_image.py --vm machlin-ntfs-fskit-27.0.1 \
  --output artifacts/image-status-next status
python3 scripts/fskit_image.py --vm machlin-ntfs-fskit-27.0.1 \
  --output artifacts/image-import-next import generated.ntfs
python3 scripts/fskit_image.py --vm machlin-ntfs-fskit-27.0.1 \
  --output artifacts/image-mount-next mount SAVED_IMAGE_ID
python3 scripts/fskit_image.py --vm machlin-ntfs-fskit-27.0.1 \
  --output artifacts/image-unmount-next unmount SAVED_IMAGE_ID
```

`status` returns the app's private Inbox path and saved images. Prepare only an
inactive, explicitly owned generated test image in that Inbox before `import`.
Import accepts a basename, creates a real app-scope bookmark and positively
restores it. For external files, the ordinary picker grant is saved instead.
Mount restores scope without UI and checks unchanged backing identity/ownership;
ordinary unmount drains the native owner. A deadline may leave a remote operation
pending: retain the failure and inspect native state before any next action.
Do not run a staged app binary: its launch may register the staged extension.
Initial OS extension enablement may require the ordinary Settings toggle;
PlugInKit election output does not prove actual FSClient enablement.

The installed checker `tests/mounted_write.c` has separate `write`, `check`,
`resident-write`, `resident-check` and `deny` modes. The write modes verify
positioned I/O/fsync and shared mappings against
independent before/after files; `check` reopens the exact result without mutation;
`deny` checks all three open modes for an authenticated foreign caller. Generated
acceptance reports bind actual loaded identities, full-image bytes, fresh mounts
and the independent Windows postimage. This is bounded existing-file overwriting;
unsupported mutation families remain explicit in WRITES.md.

Current checkpoint-transaction qualification runs `checkpoint-transactions`,
`checkpoint-transactions-cli` and the four `fuzz-checkpoint-transaction` variants,
then the full 160 fatal-ASan/UBSan suites. The original author is
tests/checkpoint_transaction_fixtures.py: 69 profiles, 50 complete/19 refused
results and 1,774 exact seed/chain views. The regular-file diagnostic is
`ntfs-logfile checkpoint-transactions LOGICAL_JOURNAL_FILE INDEX SEQUENCE`;
it acquires the owning checkpoint, checks physical transaction keys and stored
roots, and reports aggregate capture/chain credits separately from preparation.
The CLI uses defaults and compares 65 profiles/137 exact views; explicit policy
boundaries and the largest wire table remain in the C suite. See LOGFILE.md for
the full ownership, callback, budget and refusal contract. Review
artifacts/checkpoint-transactions/{focused-json-corrected-20261005,final-20261005}/
and artifacts/fskit-checkpoint-transactions/.

Selector 28 adds 87 checkpoint-chain envelopes while preserving all preceding
3,204 authored names/bytes. Fuzz traversal has explicit 512-entry/aggregate-record
and 1-MiB checkpoint workspace policies; the C suite independently qualifies
production 4096-record limits and the maximum redo-length-fitting table. All
3,291 fresh seeds replay before the 60-second exploration, under unchanged
2-MiB input/1-GiB RSS/five-second caps. Use a fresh --output directory and retain
prior corpora. Fixed replay requires absolute paths when its cwd differs from
the corpus root. Native continuation ownership, post-checkpoint analysis and
Windows recovery still precede writes.
The qualified campaign and all 7,351 prior input paths pass independent raw-log/
byte review. Append-only corpus retention adds 278 missing files to the unchanged
3,961 baseline inputs for 4,239 total; keep the complete reviewed plan/result in
checkpoint-transactions/corpus-preservation-20261005/ and failed invocations.

Preceding checkpoint-input qualification runs `checkpoint-capture`,
`checkpoint-capture-cli` and four `fuzz-checkpoint-capture` variants, followed by
all 148 fatal-ASan/UBSan suites. The original author is
tests/checkpoint_capture_fixtures.py: 144 acquisition/refusal cases, 78 complete
captures and 310 exact packet oracles. Capture uses one explicit active client,
prepared index, caller record/name workspaces and shared whole-operation I/O
ceilings. Run `ntfs-logfile checkpoint-capture LOGICAL_JOURNAL_FILE INDEX SEQUENCE`;
the diagnostic reports exact concatenated packets and separate acquisition/index
evidence. Review artifacts/checkpoint-capture/{focused,final}/ and the complete
span/failure/lifetime contract in LOGFILE.md. This is an owned analysis input;
native client history/continuation semantics, transaction recovery and Windows
durability acceptance remain separate.

Preceding selector 26 adds 160 acquisition envelopes without changing any of the
preceding 2,934 authored journal seeds. The campaign exhaustively replays all 3,094
seeds, then passes 40,649 units/61 seconds at 707 MiB under the unchanged 2-MiB input,
1-GiB RSS and five-second per-input ceilings. External reload remains disabled.
The exact frozen binary additionally replays all 3,315 prior corpus paths in 104
fixed batches. Review artifacts/fuzz-checkpoint-capture/ and
artifacts/checkpoint-capture/{fuzz-campaign-execution,prior-corpus-replay}/;
main-review.json binds raw execution and every retained byte to qualified inputs.
Keep prior corpora and fresh discoveries. The unchanged original Windows journal
also supplies three exact checkpoint packets/704 bytes, with separate acquisition
and preparation reports in checkpoint-capture/native-execution/. That source has
no dirty/transaction anchors, post-checkpoint history or modern spanning witness.
The additive corpus-preservation plan retains the 3,315 old and 3,284 fresh files,
adds 350 missing paths and leaves 3,665 in artifacts/fuzz/logfile/corpus-2097152/.
Review artifacts/checkpoint-capture/corpus-preservation/. Do not drop preceding
mutations when adding a selector or starting a separate campaign.

Preceding selected-window qualification runs `logfile-history`, `logfile-history-cli`,
`fuzz-logfile-history` and `fuzz-logfile-history-tail-fault`, then all 142 fatal-sanitizer
suites. The original fixture author is tests/logfile_history_fixtures.py: 123 windows,
65 complete results/58 refusals and 861 exact emitted packet oracles. The regular-file
CLI is `ntfs-logfile records LOGICAL_JOURNAL_FILE DECIMAL_FIRST_LSN`; it shares one
4,096-read/16-MiB budget across the entire walk and caps records at 4,096, index memory
and individual record workspace at 1 MiB. These are explicit tool policies; production
defaults are unchanged. Review artifacts/logfile-history/{final,native-execution}/ and
artifacts/fskit-logfile-history/. The frozen native comparison preserves the original
Windows Recovery journal and complete packets, without claiming native replay or writes.

The preceding journal index qualification runs `logfile-index`, `logfile-index-cli` and
five `fuzz-logfile-index` variants alongside the preceding inventory/legacy/fast
checks, then all 138 fatal-sanitizer suites. Its original author is
tests/logfile_index_fixtures.py: 71 target-selection graphs/14,922 rows and 109
exact packet results. Complete scan plus comparison credits and retained bytes
have independent admission, failure/retry and lifetime checks. The regular-file
CLI commands are `ntfs-logfile index LOGICAL_JOURNAL_FILE` and
`ntfs-logfile indexed-record LOGICAL_JOURNAL_FILE DECIMAL_LSN`; they use named
1-MiB index-memory and 4,096-read/16-MiB policies. Production defaults remain unchanged.
Current source/product evidence is under artifacts/logfile-index/ and
artifacts/fskit-logfile-index/. The frozen Windows comparison is in the Recovery
observation's native-core-index/ with original-source and whole-packet comparisons.
This is per-target selection/acquisition, not current history or recovery.

The preceding journal campaign replays 2,795 authored seeds, retaining all 2,557
preceding bytes and 238 appended index envelopes. The lone logfile process passes
`-reload=0`; no peer modifies its corpus during the run. Startup corpus loading and
every authored seed's fixed replay still execute. This avoids the observed duplicate
batch allocation during periodic corpus imports, whose saved OOM input passes
alone. See [LLVM's reload option](https://llvm.org/docs/LibFuzzer.html#options).
Keep the failed run and standalone diagnostic under artifacts/logfile-index/;
the corrected campaign and source/seed/corpus review are in reload-bound/ and
artifacts/fuzz-logfile-index/. Input/RSS/time limits and fatal sanitizers stay unchanged.

Preceding selector 25 adds 139 whole-source history envelopes to the unchanged 2,795
authored journal seeds. The fresh campaign exhaustively replays all 2,934 seeds before
coverage exploration with the same 2-MiB input, 1-GiB RSS and five-second per-input caps.
Keep the preceding learned corpus under artifacts/fuzz-logfile-index/logfile/ unchanged;
all 3,004 retained files pass 94 fixed-file replay batches with the current binary.
Their byte-preserving merge adds 209 missing units to artifacts/fuzz/logfile/, retaining
all 3,106 fresh campaign files for 3,315 total. Separate raw commands, logs and before/
after manifests are under artifacts/logfile-history/prior-corpus-replay/. Main verifies
every executed path, terminal count, source identity and retained file byte. A successful
fresh corpus run alone does not establish coverage of preceding learned mutations.

The preceding journal inventory qualification runs `logfile-inventory`,
`logfile-inventory-cli` and the three `fuzz-logfile-inventory` variants, then all
131 fatal-sanitizer suites. Its original author is tests/logfile_inventory_fixtures.py:
60 complete graphs/14,729 ordered rows, with exact backend/visitor failures,
full retry and preflight credits. Run `ntfs-logfile pages LOGICAL_JOURNAL_FILE`
for immutable regular-file metadata using explicit 4,096-read/16-MiB limits.
Ordinary source defaults are not automatically increased for a complete scan.

Artifacts/logfile-inventory/ retains focused/full raw logs, actual host products
and main source/fixture/seed review. The fresh journal campaign replays 2,557
inputs, including all 2,482 preceding inputs unchanged; its 4-MiB legacy graph
is tested outside the unchanged 2-MiB fuzz envelope. Complete native Windows
comparison is in the frozen Recovery observation's history-inventory/ and
native-core-inventory/ with separate main reviews. These offline queries leave
the source and VM unchanged. Physical coverage is distinct from authoritative
history, native recovery, writable admission and installed acceptance.

The preceding mount-refusal qualification runs `volume-flags` and `volume-flags-cli`
over 44 independently authored protected images, then the complete 126-suite fatal-
sanitizer run. DIRTY identifies the named dirty bit; all other nonzero flags stay
unsupported and version admission keeps priority. Artifacts/volume-flags/ retains
the pre-change diagnostic, final host evidence and unchanged original Recovery
image refusal. No force/admission, native recovery or writable qualification follows.

The preceding completed fast-copy qualification runs `logfile-fast`, `logfile-fast-cli`
and five `fuzz-logfile-fast` variants, then the full fatal-sanitizer suite. Its
independent author is tests/logfile_fast_fixtures.py. That checkpoint has 124 suites
and 2,482 freshly replayed journal seeds, including all 2,378 preceding inputs
unchanged. The CLI is `ntfs-logfile fast-record LOGICAL_JOURNAL_FILE DECIMAL_LSN`;
it explicitly supplies more read credits than the ordinary source defaults.
This is immutable per-target observation; LOGFILE.md and WRITES.md retain native
current-history and recovery qualification as separate requirements. Preserve the
initial fake-device lifetime-budget failure separately from passing corrected runs.

The frozen Windows Recovery observation is retained under
artifacts/windows-write-vm/recovery-partition-observation/. Main-authored runners
acquire exact selected-client records and bind their checkpoint tables without
altering the journal or projecting a different owner. Main review independently
restores native page protection and compares complete packets/membership. Use
the recorded bounded arguments and immutable input hashes for offline execution;
do not force volume admission or treat these reads as Windows recovery acceptance.
ACCEPTANCE.md records the actual nonzero-flag refusal and physical acquisition limits.

The preceding private page-encoding qualification runs `logfile-page-encode` and the
three `fuzz-logfile-page-encode` variants, then the full fatal-sanitizer suite. Its
independent author is tests/logfile_page_encode_fixtures.py; regenerate seeds into a
fresh directory for a campaign so superseded persistent build seeds are excluded.
That checkpoint passes 117 suites and 2,378 freshly replayed journal seeds. Retain whole
packet goldens, failed initial builds and final source/product evidence separately;
ACCEPTANCE.md and WRITE-FOUNDATIONS.md define their exact scope.

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

The public read-only native module query is `tools/fskit_modules.swift`; the
standalone installed reading checker is `tests/mounted_read.c`. Their prepared
arm64 binaries target macOS 26.5 and have separate personal development signatures.
They are not part of the sanitized core suite and must not be treated as installed
acceptance merely because they compile. [NATIVE-INSTALLATION.md](NATIVE-INSTALLATION.md)
records exact discovery/enablement, fixture and native mount gates. VM execution
uses the absolute lab directory and a single designated operator.

The first installed legacy reading runs now pass on both complete-filename standard
and NTFS 3.0 images using public mount -F and explicit read-only extraction options.
Their observed noowners flags remain an ownership qualification gap. The documented
Disk Arbitration owners-on candidate fails at mount approval and is retained separately;
do not silently retry it as a passing mount or change persistent ownership policy.
NATIVE-INSTALLATION.md records the successful route, cleanup and exact limits.

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

Independent-object controls are authored by tests/metadata_objects_fixtures.py
under .build/metadata-objects-fixtures. metadata-objects-{fit,pressure}.img/.json
contain 32/256 distinct resident files, with complete selected filename bodies and
exact stream oracles. They qualify selected objects, not a whole volume or Windows
authoring. Use them with the same directory runner and profile capacities 0/1/64;
inventory_unique_references records the distinction from many names of one inode.
The metadata-volume-cache and metadata-objects-cli suites exercise those inputs.
The image fuzz campaign adds their two valid and one rejected-collision images,
authored directly inside its existing bounded geometry.

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
setup/compile logs and a JSON report. Compiled product sources and the checker,
bounded-tool and environment helpers must be committed;
ordinary Git checks them before and after the run and requires an unchanged
revision. Each build explicitly selects Release/O3, no sanitizers and the same
compiler/SDK and selected options. The shared tool environment fixes ZERO_AR_DATE=1
for Apple archive member/symbol-table timestamps; the report records this selected
policy without forwarding ambient environment values. Products are not rewritten.
Eight archives/CLI products undergo full byte
comparison and SHA-256 checks. This qualifies distinct build directories in the
same checkout; relocated sources, FSKit app/signing and other toolchains remain
separate. The prepared CI matrix runs the same check, but remote execution has
not occurred. Build failures, deadlines and log-budget exhaustion fail the check
and retain bounded diagnostics; timeout cleanup targets only that build's process
group.
