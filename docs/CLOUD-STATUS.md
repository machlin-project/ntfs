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

| Stream | Current source work | Remaining verification/work |
| --- | --- | --- |
| Pipeline | Full GCC sanitized build; isolated compiler selection; x86/ARM GCC/Clang/Xcode matrix | Exact-revision full hosted suites, strict objects and selected-Xcode style |
| Directory | Unicode/case-policy queries added; independent expected keys cached without dropping any complete flat/wire/reachability check | 256 deterministic cases, 900-second campaign, synthetic/native complete-image qualification |
| Core/recovery | Checked restart payload limits, small journal counters, scratch ownership, zero-byte resident reads; 32-ancestor/five-dimension governor regression | Full malformed, allocation, WAL and fresh-owner recovery boundaries |
| Remaining features | [Timestamp, reparse and sparse preparation; retirement model](PORTABLE-FEATURES.md) pass local focused checks | Complete coupled media operations and precise independent/native facts remain explicit; no admission widened |
| Independent oracles | [Guarded Windows bootstrap/replay](WINDOWS-CLOUD.md), AccessCheck and [pinned external tools](EXTERNAL-ORACLES.md) prepared; portable contracts pass | Actual Windows and standalone-tool results, fresh C/native recovery inputs |
| FSKit | Lazy immutable-view teardown/reply ordering fixed with four prepared deterministic cases; suitable legacy SDK work kept separate from modern SDK requirement | Hosted component/app outcomes; installed behavior still needs signed native environment |
| Fuzz/performance/reproducibility | All-target fixed seed replay, explicit Linux/Xcode matched benchmark tooling, relocated Release path; 18 helper/six reproducibility regressions pass | All campaigns, measured comparisons, relocated/packaging results |
| Tooling/docs | Bounded commands, provenance, original failure/input retention and current capability map | Final clean-clone/release preparation and per-contract residual handoff |

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
