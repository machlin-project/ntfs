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

The interactive Linux environment lacks Meson, Ninja and Clang. Official PyPI
installation encountered a proxy timeout; a privileged distro install is not
available. Its fresh ordinary build therefore stopped before compilation.
Direct GCC/Python checks are narrower evidence, not a full suite pass. Hosted CI
provides the complete toolchains and is pending at this checkpoint.

## Workstreams

| Stream | Current source work | Remaining verification/work |
| --- | --- | --- |
| Pipeline | Fixed enum/signedness compilation; explicit isolated compiler selection; GCC/Clang/Xcode matrix | Exact-revision full hosted suites, strict objects and style |
| Directory | Existing independent tree/stress/fault harness retained; short and broad CI gates wired | 256 deterministic cases, 900-second campaign, synthetic/native complete-image qualification |
| Core/recovery | Restart payload arithmetic widened before addition, with exact-limit/over-limit/UINT32_MAX vectors | Full malformed, allocation, WAL and fresh-owner recovery boundaries |
| Remaining features | Owning contracts under active review | Reconcile the complete feature matrix; new families remain gated until qualified |
| Independent oracles | Existing external-tool and Windows interfaces retained | Native AccessCheck, guarded fresh VHD bootstrap and independent directory/recovery comparisons |
| FSKit | Hosted component, selected SDK, unsigned universal app and strict-context gates prepared | Actual hosted outcomes; installed behavior still needs signed native environment |
| Fuzz/performance/reproducibility | Complete fuzz inventory discovered from source; explicit compiler reproducibility route | All campaigns, matched performance, relocated/packaging checks |
| Tooling/docs | Current status separates evidence levels; failures retained | Final clean-clone instructions, release preparation and per-contract residual handoff |

This is an intermediate checkpoint. All feasible cloud work is **not complete**.
Portable, external-tool, Windows API/VHD, macOS component, unsigned-app, installed
FSKit and commercial-release evidence remain distinct.

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
