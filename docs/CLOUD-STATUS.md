# Cloud development status

The owner intentionally made the repository public for hosted CI. The code remains
proprietary under the existing LICENSE; public visibility does not grant an
open-source license. No owner credentials, machine state, historical disk images
or signing artifacts are inputs to this cloud continuation.

## Current evidence

The first cloud continuation reproduced the two strict GCC failures and the
one-MiB WOF fixture failure on unchanged sources. Both affected C files now compile
with GCC 14.2 and warnings as errors. Compact fixture generation passes. Seven
isolated-toolchain tests and two independent WOF geometry tests pass on Python
3.12.14. The geometry test walks authored mappings, proves disjoint bounded
storage, checks exact allocation bits and preserves the original primary payload.
Ordinary fixtures retain their full peer; compact fixtures retain a multi-chunk
peer and the primary's multi-page validation table. No assertion or sanitizer
policy was removed.

The interactive Linux environment initially lacked Meson, Ninja and Clang.
Official PyPI installation encountered a proxy timeout; a privileged distro
install was unavailable. Pinned official Meson and Ninja Git sources then
bootstrapped successfully under ignored vendor storage. A full GCC sanitized
build now passes with the unchanged 2-KiB frame ceiling. Journal traversals use
small I/O counters instead of discovery inventories; catalog, validation,
directory editing and rename reuse their owning bounded scratch.

Local LeakSanitizer cannot run under the sandbox's ptrace instrumentation.
Supplementary ASan/UBSan runs explicitly disable only leak scanning; allocation
balance assertions remain. They pass the new journal/governor, timestamp,
reparse, sparse, catalog and Unicode-directory checks. These are not a full
native sanitizer-suite verdict. The recorded original failed attempts remain.

The [first continuation Actions run](https://github.com/machlin-project/ntfs/actions/runs/37842836097)
passes image and logfile fuzzing and short directory stress. Linux Clang passes
219 of 221 tests, 79 strict objects and eight-product Release reproducibility;
macOS passes 220 of 221 tests, 158 strict objects and the same reproducibility
boundary. The failures identify an original empty-resident-read null-pointer
offset, a new restart-fixture expected-field omission, GCC stack/diagnostic
failures, a directory oracle replay timeout and an upstream archive HTTP 403.
Corrections are prepared without relaxing sanitizer, stack, timeout or checksum
limits. Wider qualification of the corrected source is still pending.

## Workstreams

| Stream | Verified cloud boundary | Remaining bounded work |
| --- | --- | --- |
| Pipeline | Four Linux compiler/architecture jobs pass on 8b63aad; macOS passes 247 tests and both eight-product Release comparisons | Apply retained Xcode style; final exact-source full matrix after connected changes |
| Directory | Fifteen fuzz targets, 900-second directory campaign and deterministic stress pass; f415c6b completes all 803 native-source operations, C recovery cuts and packaging | Diagnose the first retained Windows replay failure in group 00, then qualify fresh candidates without retrying completed ones |
| Core/recovery | Fatal hosted sanitizers, budgets, whole-image publication checks, independent recovery and quiet reopen; native checkpoint reserve pressure is handled before freezing the next predecessor | Wider new-family crash and native postimage evidence; preserve resource and physical-space bounds |
| Features | Private timestamp, reparse, sparse, lifetime, security-edit and USN boundaries; compression-unit ownership and complete hardlink C qualification have focused checks | [Each owning family](PORTABLE-FEATURES.md) retains its specific media/index/lifetime/native dependency; missing coupling remains implementation work |
| Independent oracles | Pinned external-tool comparison, native 276-vector DACL decisions, 28-case corpus, 295 codec pairs and 1024-link limit observations pass | Native directory/hardlink recovery, 175 new unit packets and corrected metadata cache/handle observations |
| FSKit | Hosted component/app-support groups and strict context objects pass; both unsigned universal builds/packages and UUID bindings pass | Full app linker-path reproducibility and usable dSYMs; SDK 27 and installed signed execution remain explicit unavailable gates |
| Fuzz/performance/reproducibility | All fifteen campaigns pass; five-platform matched codec evidence retains gains and regressions; core Release relocation passes | Decide bounded empty-encoder/XPRESS probes, verify new unit fuzz coverage, then freeze final measured/native source |
| Tooling/docs | Guarded scratch acquisition/transport, immutable original failures, bounded commands, provenance and per-family capability map | Complete fresh postimage review and final clean-clone/source-bound residual handoff |


This is an intermediate checkpoint. All feasible cloud work is **not complete**.
Portable, external-tool, Windows API/VHD, macOS component, unsigned-app, installed
FSKit and commercial-release evidence remain distinct.

## Wider hosted checkpoint and current continuation

The [first broad continuation](https://github.com/machlin-project/ntfs/actions/runs/37847726901)
passes all 233 tests on GCC and Clang for both Linux x86-64 and ARM64, strict
objects, same-source and relocated Release reproducibility, all thirteen fuzz
targets (including 900 seconds of directory exploration), 256 deterministic
directory stress cases and the serial matched performance job. Its macOS
component checks, including lazy-view teardown, pass; 324 compiler-context
objects and six portable/GPR checks also pass. Modern macOS 27-only checks
remain separately unexecuted on the observed SDK 26.5/runtime 26.6.

The run also preserves failed macOS path-spelling/style checks, missing modern
Swift API declarations, the Windows transfer test's path-spelling expectation,
the native bootstrap's .NET alternate-stream constructor and a missing upstream
Autotools macro. The fresh Windows runner did create, attach, initialize and
format its guarded scratch NTFS VHD; the failed candidate was detached and
retained unchanged. Corrections use canonical path identities, exact selected-
Xcode formatting, a guarded documented SDK bridge, Win32 alternate-stream I/O
and the missing declared build prerequisite. Their next hosted verdict is pending.

The next local source boundary additionally includes private hard-link
preparation, original LZNT1 encoding and build-bound unsigned packaging. Their
independent focused tests pass, but neither new filesystem admission nor actual
Windows codec/link-count verdicts are implied. Compression performance work now
requires retained pre-optimization source, matched measurements and explicit
corner-case/differential coverage before any gain is accepted.

## Fresh independent Windows boundary

Source `62d2986bdc97d2c5e470d1d9b2668b11fc2da23a` passes the
[native LZNT1 oracle](https://github.com/machlin-project/ntfs/actions/runs/37852693510):
Windows ntdll decoded all 295 original encoded/plain pairs. The independent
[hard-link observer](https://github.com/machlin-project/ntfs/actions/runs/37852693547)
created 1023 additional names, observed 1024 total links, and rejected one more
with error 1142 while preserving namespace, identity and original DATA/ADS.
Neither result widens filesystem mutation admission. Compression optimization
has its own retained baseline, differential tests and subsequent native rerun.

## Native input and packaging continuation

The [next broad run](https://github.com/machlin-project/ntfs/actions/runs/37854379914)
passes all fourteen fuzz campaigns, Linux matrices and fresh Windows scratch
acquisition. Its original AccessCheck capture exposes six zero-request decision
mismatches; the corpus consumer refuses the original NTFS 3.1 volume flag 0x0080.
Neither failed verdict is converted into acceptance by the successful capture.

The [controlled volume-policy probe](https://github.com/machlin-project/ntfs/actions/runs/37858557415)
then observes 0x0080 with per-volume short-name creation disabled, 0x0000 when
enabled, and the same transitions on disable/re-enable. All four native phases
pass read-only chkdsk, flush, confirmed detach and unchanged read-only capture.
The original baseline remains unchanged and the machine policy is not modified.
The narrowly observed flag can now receive its own admission/combination tests.

Hosted macOS passes 65 component groups, 11 app-support checks, 332 compiler
contexts and six focused checks. Both universal Release app builds and the first
unsigned package pass. Three of 240 core tests fail in temporary-path or
case-insensitive-filesystem fixtures. The two-build app comparison differs only
in executable payloads retaining absolute debug-map paths; normal Release debug
stripping and separately UUID-bound dSYM retention are prepared for a fresh build.
SDK 27 coverage and installed signed behavior remain distinct unavailable gates.

## Qualified native profile and Access continuation

The full native corpus validator now succeeds at source `9581ad8`: 256 records,
2,943 claimed and allocated clusters, no unclaimed clusters, and all four mirror
records agree. Its first directory writer attempt exposed a quiet-checkpoint
profile refusal before any persistence. Five retained Windows remounts show the
opaque historical word changing while geometry stays fixed. The continuation
preserves that word and constrains the narrowly observed profile without naming
its universal meaning or altering original native images.

A new preparation-only copy remains unchanged; a separate fresh copy completes
the first mkdir, passes complete validation, and has a quiet recovery reopen.
These local fatal ASan/UBSan supplements exclude only the sandbox-incompatible
LeakSanitizer. Full 803-operation and Windows recovery qualification remains open.
The new shared benchmark profile passes old-policy/current GCC admission with
identical checksums and resource counters; original frozen inputs remain intact.

Restricted-owner and ordered maximum-access decisions now match all 276 retained
Windows DACL vectors, with no failed or unsupported in-plane cases. Six mandatory
authorization-plane probes remain outside that claim. The Mac synthetic Access
report harness reuses only identical immutable packets after evaluating every
distinct request; it retains every report assertion and the 120-second deadline.

## Reproduce and request the wider gates

### Exact-source checkpoint: 8b63aad

The [full run](https://github.com/machlin-project/ntfs/actions/runs/37866655275)
passes all four Linux GCC/Clang and x86-64/ARM64 core jobs, every one of the fifteen
fuzz campaigns, deterministic directory stress, standalone interoperability,
Windows acquisition/corpus/Access comparison, and serial portable performance.
The macOS core suite passes all 247 tests; its remaining job failure is formatting.
The retained selected-Xcode patch is applied with C-token and adjacent-string
equivalence checked. Both same-path and relocated core Release builds produce
eight identical products. This does not qualify the unsigned app comparison.

Fresh Windows Access observations again match all 276 in-plane vectors; six
mandatory-plane boundaries remain distinct. The original corpus passes 28/28.
The full native-source directory sequence completes 287 operations before the
next execution preparation refuses with no writes. Its retained history crosses
the existing checkpoint-reserve allocation threshold. On a fresh copy, querying
that existing pressure signal before freezing the next predecessor, checkpointing,
and executing the original operation once passes the independent 288-object
model, whole-image publication comparison, full validator and quiet recovery.
The complete 803-operation and Windows replay verdicts remain pending.

Both unsigned universal app builds, dSYM UUID bindings and packages pass. The
strict relocated comparison still differs in linker UUIDs and the arm64 ad-hoc
signature page hashes containing them; code, data and symbols otherwise match.
Release compiler path mapping and a separate retained linker diagnostic are
prepared. Actual SDK 27 compilation remains explicitly unexecuted on the available
SDK 26.5/runtime 26.6, and installed signed behavior remains separate.

The [five-platform codec run](https://github.com/machlin-project/ntfs/actions/runs/37866655284)
passes all differential and timing jobs, and the
[fresh native decoder](https://github.com/machlin-project/ntfs/actions/runs/37866655342)
passes the 295 original pairs. Classic encoder widths remove the earlier measured
nonempty Clang regression while retaining the single-pass bound-capacity gain.
Empty calls still show a measured regression and remain under investigation;
successful CI is not a claim that every timing case improved. The new compression
unit owner and complete hard-link persistence harness have separate qualification
work and do not widen filesystem admission.

Use separate build directories for different compilers:

```sh
python3 scripts/build.py .build-gcc --compiler gcc
python3 scripts/test.py .build-gcc
python3 scripts/build.py .build-clang --compiler clang
python3 scripts/test.py .build-clang
python3 scripts/check_core.py --compiler gcc
python3 tests/test_wof_geometry.py
```

Ambient CC and credential variables are not forwarded. Existing Meson builds
must match the requested compiler; reconfiguration explicitly restores assertions
and requested sanitizer settings. Darwin retains selected-Xcode toolchain/SDK
discovery and selected-Xcode formatting.

The `Portable NTFS` workflow runs short gates on ordinary changes. Invoke its
manual workflow with `broad=true`, or use the explicit `[cloud-full]` marker in a
development push commit message, for every fuzz target, 256 directory stress
cases and macOS component/app/context gates. A marker run explores directory
mutation for 900 seconds and other targets for 60 seconds, after authored replay.
The manual input selects a bounded per-target exploration budget. Failure logs,
inputs and reports stay attached to their original runs; a later passing attempt
does not erase the failure.
