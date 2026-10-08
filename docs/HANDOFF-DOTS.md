# Dots handoff: complete the cloud-executable NTFS work

Prepared on 2026-10-08 for the private `machlin-project/ntfs` repository.
Work on the existing `development` branch.

The owner subsequently confirmed intentional public visibility for hosted CI.
Preserve the proprietary license and never publish credentials or owner artifacts.
References below to private repository access describe the original handoff;
[current cloud status](CLOUD-STATUS.md) owns the continuation's actual results.

## Assignment and completion boundary

The owner requests **all project work that can be completed in a cloud environment**.
Dots receives the private GitHub repository and its authorized cloud environment.
It does not receive the owner's Mac, local workspace, retained disk images,
signing keys, or test VMs. Complete implementation, diagnosis, tests, automation,
and documentation wherever those inputs are sufficient. Fixing the first CI
failure or completing the directory batch is a checkpoint, not the whole task.

Use available GitHub-hosted Linux, macOS, and Windows jobs where useful. A Linux
interactive environment does not make macOS compilation or Windows API tests
impossible if the repository's hosted runners can perform them. Conversely,
requesting a runner is not evidence that its SDK, runtime, privileges, or disk
operations are available: establish those capabilities and record the outcome.

Finish when every applicable work item below is either implemented and verified
in the cloud, or has a concrete remaining dependency that the available cloud
environment cannot supply. A missing VM can block a native verdict while leaving
portable implementation, fault tests, and acceptance-harness work actionable.
Continue those parts. Do not turn unimplemented code into an environment blocker.

The result is a completed cloud development boundary, with an exact residual
native/release handoff. It is not automatically a production-ready driver.

## Read first and interpret historical notes correctly

Read [AGENTS.md](../AGENTS.md), [README](../README.md),
[architecture](ARCHITECTURE.md), [acceptance](ACCEPTANCE.md),
[development](DEVELOPMENT.md), [write ownership](WRITES.md), and
[provenance](PROVENANCE.md). Use the [documentation map](README.md) and
[format reference](format/README.md) for the affected components.

The latest implementation batch is directory mutation and journal preparation.
[Directory acceptance](DIRECTORY-ACCEPTANCE.md) contains its prepared execution
plan. [The Sol handoff](HANDOFF-SOL.md) contains useful historical evidence and
the owner's local operating procedure; its absolute paths and VM snapshots are
not resources available to Dots.

Earlier instructions to stop after preparing tests describe the previous work
session. The present assignment authorizes cloud implementation and verification.
It does not authorize access to the owner's machines. Historical statements such
as "no write callback," "native work pending," and earlier suite counts must be
read with their component and checkpoint context; later owning write paths and
acceptance may supersede them. Reconcile current code and the newest evidence
before treating an old paragraph as a current missing feature.

## What exists and what was actually observed

Machlin NTFS is an independent proprietary NTFS implementation and FSKit product.
The freestanding C core owns disk semantics. The FSKit adapter owns native
lifecycle, serialization, authorization delivery, and buffering. This repository
does not need `lab/`, XNU, LXNU, or sibling filesystem repositories to build its
portable core. Adding a kernel adapter is outside this assignment.

The core implements bounded metadata/content reading, directory traversal,
selected compression/reparse/security interpretation, validation, journal
analysis, and an exclusive ordinary-image mutation/recovery owner. The FSKit
image route supports a bounded ordinary-file mutation profile. Public block
resources retain read-only extraction. Unsupported operation families must not
be advertised as implemented merely because their refusal is tested.

The [first private cloud run](https://github.com/machlin-project/ntfs/actions/runs/37830205767)
was inspected while preparing this handoff:

| Stage | Observed result | Consequence |
| --- | --- | --- |
| macOS core job | 220 tests passed, zero failures | The current portable suite, including directory seed replays and the pure harness regression, ran in hosted macOS |
| macOS reproducibility | Two isolated Release builds produced eight byte-identical products | Same-checkout build-directory reproducibility passed for that runner/toolchain |
| Linux core and interoperability jobs | Compilation failed before tests/oracle execution | Linux acceptance is open; dependency installation succeeded |
| Image fuzz job | Fixture generation raised an assertion before fuzzer execution | No fuzz verdict follows; the subsequent logfile command was skipped |
| Dedicated directory stress/fuzz and current native directory batch | No new execution evidence established by that workflow | These remain work to perform, with native inputs recreated or supplied independently |

The preceding locally accepted core checkpoint recorded 213 sanitized suites,
316 strict compiler-context objects, and six portable/GPR checks. Installed
signed build 19 and its Windows postimage have earlier bounded native acceptance;
they predate the later preparation optimizations. Those local reports and images
are ignored, absent from a fresh clone, and cannot qualify new cloud changes.
Recheck current Actions and Git state when starting; this table is an observed
baseline, not a promise that the branch will remain at that state.

## First confirmed defects

These are observed failures, not speculative review findings:

1. [core/mst.c](../core/mst.c), the protected-record policy static assertion:
   GCC rejects comparison of two anonymous enum types with `-Werror=enum-compare`.
2. [core/logfile.c](../core/logfile.c), `ntfs_logfile_restart_decode`:
   GCC rejects the comparison of `info.last_data_bytes` with
   `NTFS_LOGFILE_MAX_RECORD_BYTES - info.record_header_bytes` under
   `-Werror=sign-compare`. Preserve the width and arithmetic bounds when fixing it.
3. [tests/wof_file_fixtures.py](../tests/wof_file_fixtures.py), WOF cache peer
   placement: `f.put_data(image, CACHE_PEER_LCN, packed)` reaches the bounds
   assertion in [tests/fixtures.py](../tests/fixtures.py) for the image fuzzer's
   one-MiB geometry. Make authored storage fit and remain nonoverlapping at every
   supported fixture geometry, with independently checked content and allocation.

Fix the causes and every additional failure exposed afterward. Keep warnings as
errors, fatal sanitizers, complete ordinary fixtures, and meaningful compact fuzz
coverage. Selecting only the compiler that happens to pass, deleting the bounds
assertion, silently dropping the peer case, or simply raising the fuzz memory
limit does not close these defects.

## Environment and evidence rules

| Environment/input | Work to perform | Boundary to retain |
| --- | --- | --- |
| Fresh Linux clone | GCC/Clang builds, portable tests, sanitizers, fuzzing, regular-image recovery, standalone external oracles, CLI checks | Use tracked sources and generated scratch files; preserve POSIX/Darwin durability distinctions |
| Hosted macOS with a suitable Xcode/SDK | Selected-Xcode style, strict architecture/context compilation, adapter component tests, unsigned universal app build | SDK compilation, runtime component tests, and installed FSKit mounts are separate stages |
| Hosted Windows | Native AccessCheck and corpus collectors; disposable NTFS/VHD qualification if actual runner capabilities allow it | Record Windows provenance and real results; never substitute a synthetic provider for Windows |
| Old `artifacts/`, `.build/`, `vendor/`, local signing and VM state | Treat as absent; recreate cloud inputs and tool builds through documented commands | Never invent a manifest, native verdict, hash, or successful prior run |
| Installed FSKit, signing/notarization, physical-device/power-cut acceptance | Prepare all source-side code and tests; run only when the needed authorized environment really exists | No installation on the owner's host, no extraction of owner credentials, no claim from an unsigned build |

Use repository-relative paths. The tracked
[environment helper](../scripts/environment.py) excludes ambient credentials
from build reports; keep that property when adding compiler or platform options.
Keep generated inputs, failures, binaries, and reports in ignored directories or
private CI artifacts. Retain failed attempts and minimize copies for diagnosis;
do not replace a failing input with a successful rerun.

Use ordinary Git history and focused commits on `development`. Preserve existing
authors and signatures; do not rewrite history or force-push. The owner's local
publication identity is `darekhta`, `Dmitri Arekhta <dmitri.arekhta@me.com>`, using
`git@github-personal.com:machlin-project/ntfs.git` and a personal signing key.
That SSH alias/key is local configuration, not a cloud prerequisite. In the cloud,
use the already authorized GitHub integration and available approved signing
identity; do not copy private keys or manufacture credentials. If publication
credentials are unavailable, finish and retain reviewable commits first and
report that precise publication blocker.

Keep implementation/review ownership separate from routine execution where the
orchestrator provides the workers named in AGENTS.md. If those model-specific
workers are unavailable in Dots, preserve the review and execution responsibilities
sequentially instead of blocking all cloud work on a missing model provider.

## Work programme

The order below resolves dependencies. Keep a concise current status for each
workstream, with links to code, regressions, and actual evidence. Continue through
all workstreams; the initial defect list is not an exhaustive code review.

### 1. Repair and complete the cloud build/test pipeline

Fix the confirmed failures first. Establish fresh Linux GCC and Clang builds and
retain the macOS passing boundary. Compiler selection must be explicit and
compatible with environment isolation; an ambient `CC` assignment is currently
filtered by the helper and is not proof that the requested compiler ran.

Extend [.github/workflows/core.yml](../.github/workflows/core.yml) to cover the
cloud-executable gates below, with bounded runtime, useful failure artifacts,
and explicit prerequisites. Keep quick regressions on ordinary changes and
provide a manually invocable bounded broader matrix for expensive campaigns.
Do not mask failures with `continue-on-error`, missing-file success, assertion
removal, or platform-wide skips. A missing required SDK/tool is an explicitly
unexecuted gate, not a test pass.

Retain fatal ASan/UBSan, assertions, freestanding checks, and the 2-KiB frame
budget. Add relevant compiler/architecture coverage where a real cloud toolchain
supports it. Inspect the actual Meson inventory instead of hard-coding a historical
suite count. Keep build/fixture failures distinct from tests that actually ran.

### 2. Complete directory mutation qualification

Run and fix the tracked operation fuzzer, deterministic stress generator, and
pure harness tests. Start with [fuzz_directory.c](../tests/fuzz_directory.c),
[directory_fuzz_seeds.py](../scripts/directory_fuzz_seeds.py),
[stress_directory.py](../scripts/stress_directory.py), and
[directory_harness.py](../tests/directory_harness.py).

Close split/merge/root spill/root collapse, cascading deletion, variable-length
replacement, empty-root regrowth, absent/duplicate lookups, reference reuse, and
allocation-failure coverage. Preserve the independent ordered-key model, wire-tree
walk, live-node reachability, byte bounds, and allocation balance. Extend relevant
name/collation cases without making the implementation its own oracle.

The prepared offline sequence contains 803 operations and four phase snapshots.
The local descriptor and base-VHD inputs in DIRECTORY-ACCEPTANCE.md are unavailable
in a fresh cloud checkout. Complete equivalent synthetic cloud coverage now, and
connect fresh Windows-generated inputs through workstream 5. Preserve complete
image comparisons, preselected interruption cuts, both commit sides, every affected
metadata class, fresh-owner recovery, and a second quiet reopen. Synthetic and
Windows-authored results retain distinct provenance.

### 3. Finish core correctness, recovery, and resource-bound work

Review the actual code against the contracts, repair demonstrated defects, and
add independent regressions for missing coverage in these areas:

| Area and code entry points | Required cloud work |
| --- | --- |
| `mount.c`, `attribute.c`, `stream_mapping.c`, `directory.c`, `index.c`, `validate_*.c` | Malformed/truncated metadata, checked sizes and offsets, sequence/extent ownership, cycles, collision and geometry boundaries, consistent partial/error results |
| `write_directory_tree.c`, `write_directory_store.c`, `write_mutation_bitmap.c`, `write_allocation.c`, `write_stream.c` | Dirty-node publication, original allocation exclusion, bitmap boundary/growth accounting, generation reuse, cache revision/invalidation, ENOSPC and preparation failure leaving the entire image unchanged |
| `write_program.c`, `write_payload.c`, `write_journal.c`, `write_execute.c`, `write_transaction.c` | Complete operation preparation, WAL ordering, barrier and partial-transfer failures, poisoning, exact bytes outside managed regions |
| `write_recover.c`, `write_replay.c`, `write_batch_recover.c`, `write_checkpoint*.c`, `write_history.c` | Fresh-media recovery, interrupted recovery, compensation, checkpoint advancement, retained histories, repeated reuse and circular wrap, stable old-or-committed endpoints |
| `operation.c`, `memory.c`, `unit_cache.c`, stream/WOF caches | Aggregate and ancestor budgets, exact allocation balance, overflow/alignment, optional-allocation refusal, stale view/cache rejection, portable/GPR behavior |

Use the existing complete-image, independent transaction/durability, packet,
fault-injection, and allocator models. Improve their blind spots rather than
adding tests that repeat an implementation expression. A new regression should
identify the contract it protects and, for a bug fix, reproduce the original
failure. Run the appropriate full boundary after connected implementation work.

### 4. Complete remaining portable feature implementation

Build a current capability matrix from WRITES.md, NATIVE-NAMESPACE.md, ACCESS.md,
LIFECYCLE.md, CORE-QUALIFICATION.md, the format research register, and the code.
For each remaining feature distinguish missing implementation, missing independent
format knowledge, missing native qualification, and an intentional product policy.
Do not classify every `NTFS_UNSUPPORTED` branch as a bug, or classify every missing
feature as permanently excluded just because it needs eventual native acceptance.

The documented candidate families include deferred retirement for open unlink
and opened-victim replacement; ordinary metadata setters; hard-link/symlink
creation; named-stream and sparse writes; encoded/compressed writes; and shared
security-store/ACL mutation. Complete their cloud-feasible owning contracts,
algorithms, and independent tests wherever the format and product contract can be
established. Use hosted Windows observations where possible. Keep new mutation
families behind their existing admission boundary until their own durability,
recovery, and native evidence justify enabling them.

For deferred retirement, account for held handles/mappings, namespace removal,
last-reference lifetime, storage reuse, crash recovery, and stale FILE generations
as one owning operation. For each new storage/namespace/security family, prepare
all affected metadata and redo/undo before any transfer, cover interruption and
resource failures, and prove unaffected streams/security/bytes are retained.
Tests and a coherent contract precede widening the supported profile.

If a family depends on an unresolved native fact, finish the independently
specified parts, retain explicit refusal for the remainder, and record the exact
question, attempted cloud investigation, and minimum needed observation in
[the research register](format/13-research-and-coverage.md). Do not guess a
Windows rule to make a test pass. EFS key handling, arbitrary provider semantics,
or product identity policy cannot be invented from a broad completion request.

### 5. Make independent Windows and filesystem oracles cloud-reproducible

Run the standalone NTFS-3G interoperability/validation oracles after the Linux
build is fixed. Keep those tools under ignored `vendor/`; no GPL filesystem
implementation code may enter or link with the product. Maintain tool provenance,
download verification, original expected contents, and unchanged input evidence.
Use public corpora only with documented origin and reproducible acquisition.

Add hosted-Windows execution for the existing
[AccessCheck collector](../scripts/collect_windows_access.py) and
[offline comparison](../tests/windows_access.py), following
[ACCESS-ORACLE.md](ACCESS-ORACLE.md). This collector uses disposable token copies
and authored descriptors; it does not require the owner's VM or file ACL changes.
Use actual results to repair supported decision semantics and strengthen tests.
A pure DACL comparison still does not establish FSKit's native authorization.

Determine whether an ephemeral hosted Windows runner can create and attach a new
private VHD, format its new test volume, author a known NTFS namespace, flush,
detach, and retain exact media. If available, implement the missing cloud input
bootstrap and feed fresh inputs into the tracked C/Windows directory and recovery
harnesses. Replace owner-machine paths and fixed geometry assumptions with
validated manifest inputs, retaining all disk identity and ownership guards.
Do not weaken a collector to accept an unexpected disk or a missing native event.

Every destructive test operation must target the newly created scratch VHD,
with its disk/partition identity checked and system/boot/host disks excluded.
Do not change machine-wide disk policy. Compare namespace, data, ADS, references,
timestamps, security, clean state, read-only chkdsk, and original matching events
as applicable. Bind expected torn-page warnings to the original crash bytes.
Retain detached postimages and do not rerun a completed candidate to obtain a
better verdict. VHD recovery is separate from physical power-loss acceptance.

If runner privileges or services prevent this gate, retain the observed refusal,
finish the bootstrap/packaging/manifest tests that can run, and report that exact
limitation. Absence of the owner's old VHD alone is not sufficient reason to skip
investigating a reproducible cloud input source.

### 6. Complete cloud-feasible FSKit and native-policy engineering

Use hosted macOS with a verified suitable SDK for
[test_fskit.py](../scripts/test_fskit.py), an unsigned universal Release build,
and the selected-Xcode style/strict-object checks. Repair compile and component
failures. Record runtime-dependent skips individually; do not substitute a
different SDK, old installed build, or fake framework result as native evidence.

Review `NTFSVolume.m`, `NTFSVolumeItems.m`, `NTFSVolumeRead.m`,
`NTFSImageVolume.m`, `NTFSImageTransport.m`, `NTFSResource.m`, and the associated
`tests/fskit_*.m` contracts. Complete deterministic tests for exactly-once replies,
admission/publication ordering, revoked resources, overlapping teardown,
reader/writer leases, reentrant callbacks, lazy rebinding after mutation,
directory-cookie epochs, and pressure cleanup. Fix owning-layer defects exposed
by those tests. Preserve serialization unless an independently tested concurrency
and lifetime contract justifies a change.

Finish portable security decoding/evaluation, unsupported-feature presentation,
name/ADS/link projection, and source-side lifecycle/cancellation work within
their documented contracts. Never use the mount owner or root as a substitute
for the caller, broaden native authorization, or hide errors behind successful
empty results. Full Windows identity mapping needs an explicit product policy
and native enforcement evidence.

Prepare the installed directory/mmap/remount and failure scenarios so an owner
with the required signed environment can execute them without redesign. Hosted
component checks cannot establish Finder behavior, actual FSContext delivery,
installed extension selection, or kernel cache/mmap coherence by themselves.

### 7. Complete fuzzing, performance, and reproducibility coverage

Exercise every target listed in [scripts/fuzz.py](../scripts/fuzz.py), not only
the two targets currently present in CI. Include the directory operation target,
all authored seed replays, malformed metadata, security, content codecs, and
journal/recovery boundaries. Use bounded campaigns, retain crashes/timeouts/OOMs,
minimize reproducible findings, and turn fixes into ordinary regressions. Keep
the existing resource limits meaningful; disclose actual coverage and duration.

Review [PERFORMANCE.md](PERFORMANCE.md) against current source. Make the useful
portable benchmark/toolchain paths runnable in the cloud; several preparation
benchmark helpers currently call `xcrun` unconditionally. Preserve the selected
Xcode route while adding explicit Linux tooling where applicable. Run matched
retained-baseline/current comparisons for affected hot paths, with independent
output checks, memory/I/O accounting, repetitions, and disclosed regressions.
Optimize demonstrated remaining costs without weakening validation, ownership,
durability, or budgets. Shared-runner CPU results do not establish disk throughput.

Run same-checkout Release reproducibility on supported cloud platforms. Extend
to relocated checkouts and unsigned packaging where feasible, fixing unstable
paths/timestamps through build configuration rather than rewriting products.
Keep compiler-context object checks distinct from an actual kernel adapter/load.

### 8. Finish cloud-deliverable product tooling and documentation

Complete reliable command-line help, failure diagnostics, bounded subprocesses,
artifact retention, clean-clone setup, and unsigned packaging that can be verified
without owner credentials. Preserve originals and caller-owned output on error.
Avoid adding a second build system or custom source-history ledger.

Bring the current capability/acceptance overview, development instructions,
format chapters, code/test links, provenance, and release checklist into agreement.
Keep earlier failed experiments as history, with an unambiguous current summary.
Update diagrams when format relationships change and inspect their rendered SVGs.

Prepare everything source-side for the release gates in
[COMMERCIALIZATION.md](COMMERCIALIZATION.md), including artifact contents and
dependency notices. Pricing, payment accounts, licensing policy, signing keys,
notarization credentials, and a public/open-source release require owner inputs;
do not fabricate those decisions or introduce a licensing/network dependency
inside filesystem algorithms. The repository remains private and proprietary.

## Initial commands and prerequisites

Run from the repository root of a fresh cloud checkout. Establish Python 3.13,
C build tools, GCC and Clang/libFuzzer, and `clang-format`; macOS additionally
needs the selected supported Xcode and XcodeGen. Verify installed versions in
generated reports. Use the workflow's pinned Python build-tool versions initially.
These are entry commands, not a claim that the current Linux baseline passes:

```sh
python3 -m venv .build-dots-venv
. .build-dots-venv/bin/activate
python3 -m pip install meson==1.11.1 ninja==1.13.2
python3 scripts/build.py .build
python3 scripts/test.py .build
python3 scripts/format.py --check
python3 scripts/check_core.py
```

After fixing baseline failures, run the prepared directory gate with fresh output
directories; the seed below is the documented reproducible stress seed:

```sh
python3 scripts/stress_directory.py --cases 256 --seed 20261008 --output artifacts/dots-cloud-directory-stress
python3 scripts/fuzz.py --target directory-mutation --seconds 900 --compiler clang --output artifacts/dots-cloud-directory-fuzz
python3 scripts/bootstrap_test_tools.py
python3 tests/interoperability.py
```

Run all other fuzz targets with documented per-target budgets and fresh reports.
On macOS, select a full LLVM compiler with libFuzzer where the selected Xcode
does not supply that runtime. Commit relevant build/product sources before
running the reproducibility checker, which intentionally requires committed,
unchanged inputs:

```sh
python3 scripts/check_reproducible.py --output artifacts/dots-cloud-reproducibility
```

On a suitable hosted macOS runner, after the sanitized core and fixtures exist:

```sh
python3 scripts/test_fskit.py
python3 scripts/build_fskit.py --configuration Release --derived-data artifacts/dots-cloud-fskit/DerivedData
```

Consult each existing tool's arguments for additional oracle/CPU/native gates.
Do not blindly execute the owner-local absolute paths in historical documents.
If a compiler, platform, or manifest option is missing, implement and test a small
explicit interface instead of silently changing the intended command's semantics.

## Non-negotiable implementation contracts

- Keep the core freestanding, allocator/read callbacks explicit, disk bytes
  untrusted, arithmetic checked, iterations bounded, and FILE sequences checked.
  Read-only environments acquire no write capability.
- Preserve complete-operation ownership, WAL/barrier ordering, old-or-committed
  recovery, unchanged images on preparation failure, and poisoned uncertain I/O.
  Implement semantics at the layer owning the objects and their concurrency.
- Use named ABI/wire fields and limits. In owned C/Objective-C, declarations
  precede statements with a blank line; use braces and one statement per line.
  Keep source, comments, and documentation in English.
- Keep Windows format facts, published specifications, independently observed
  media, synthetic tests, and unresolved interpretations distinct. Record sources
  for new format research; do not import GPL filesystem algorithms.
- Preserve all failures and explicit unsupported contracts. No blanket skips,
  automatic repair, dirty-bit clearing to admit media, fabricated verdicts, or
  relaxed security checks to obtain green tests.

## Required final delivery

Deliver focused implementation and test commits, usable CI, and updated current
documentation. Push through the existing authorized repository integration when
available. A clean working tree or a green subset of CI is not by itself completion.

For every workstream, report what changed, why, which tests actually ran, results,
and remaining limits. Put source revisions and binary/input identities in generated
reports; use Git for source history rather than repeating hashes in Markdown.
Link private Actions runs and selected reports without publishing credentials,
owner data, or enormous unfiltered environment-bearing logs.

The final acceptance summary must distinguish portable tests, external-tool
comparisons, actual Windows observations, macOS component tests, unsigned app
builds, installed FSKit behavior, and release readiness. New tests supplement
earlier evidence; they do not silently inherit its native scope.

For each unresolved item provide: affected contract and code; implementation and
portable checks already completed; attempted cloud route and exact missing
capability/input; the smallest owner action or native experiment needed; and the
prepared command/expected outcome. Leave no actionable cloud work behind merely
because a later gate needs an owner-controlled machine. State explicitly whether
all feasible cloud work is complete, and do not call the whole product finished
while native, security-policy, or release gates remain open.
