# Acceptance

The delivered scope is a bounded read-only core and FSKit development product.
Local core, adapter component, signed app-build and independent-image checks
passed. Installed native mounts, Windows interoperability and commercial release
qualification remain open. The requested 60% is not a measured completion claim;
see [the handoff](HANDOFF-SOL.md) for the delivered scope and remaining work.

| Contract | Scope and required evidence | Status |
| --- | --- | --- |
| Geometry and MST | 512/4096-byte sectors, 1/4/64-KiB clusters in independent images; boot bounds and torn FILE/INDX tests | Local tests passed |
| MFT and attributes | NTFS 3.0/3.1 headers; incremental fragmented bootstrap with resident/nonresident lists; sequence, base reference, continuation instance, reachability, gaps and duplicates | Local tests passed within limits below |
| Streams | Fragmentation, sparse/VDL zeroing, independent ADS and directory ADS, mixed LZNT1 units, empty nonresident data, cache retry and offsets beyond 4 GiB | Synthetic tests passed; ordinary data/ADS independently compared |
| Directories | Resident/external B-tree, allocation bitmap, cycle rejection, local ordering, ancestor bounds, persistent cursor and collision-aware $UpCase lookup | Synthetic and independent image tests passed |
| Resource safety | Allocation/read failure sweeps on five layouts, exact release accounting, BUSY lifetime, 2,000 deterministic image mutations under ASan/UBSan | Local tests passed; counts below |
| Coverage-guided fuzzing | Bounded libFuzzer/ASan/UBSan using full LLVM; 171,809 executions in 121 seconds on compact physical images | Completed without reported crash or sanitizer finding; ongoing fuzzing required |
| Portable boundary | Freestanding arm64/x86_64 compilation with 2-KiB frame budget; selected Xcode formatting | Passed; kernel integration untested |
| FSKit component | Aligned resource reads, short/error I/O, permanent resource revocation including cached data, item identity, stored names, pagination/replay, EROFS, concurrent reads and teardown under ASan/UBSan | Passed in-process on macOS 26.6.2 |
| FSKit application | Host app and embedded extension, legacy/modern protocol sources, personal development signing and strict deep signature verification | Signed Release build passed; installed runtime and macOS 27 untested |
| Native installation | Signed VM mount, Finder, mmap, concurrency, removal | Not run |
| Windows corpus | Windows-authored metadata, sparse/compressed edge cases, native repair and roundtrip evidence | Not run |
| Write/recovery | Native log, allocation, namespace transactions, crash matrix | Not implemented |
| Security and special data | $Secure/ACL policy, reparse points, EFS, WOF | Not implemented |
| Distribution | Personal signing, notarization, installer, licensing and support | Not implemented |
| Remote CI | macOS/Linux core, Linux oracle and bounded libFuzzer workflow | Prepared; not executed remotely |
| Performance baseline | Unsanitized optimized build; 100 full reads and 1,000 lookups against a warm POSIX image | Measurement recorded; native performance unmeasured |

`make test` passed ten suites: primitives/lifecycle on five filesystem layouts,
stream boundaries, decoder vectors, image contracts, deterministic fuzz smoke and
build-environment isolation. The image suite checks nine file hashes across all
five layouts, ordering, case folding, ADS, four damaged images and 31 additional
format/continuation/rejection cases. Unsupported and corrupt
inputs passing their rejection tests do not establish support for those layouts.

| Fault sweep layout | Allocation failure positions | I/O failure positions |
| --- | ---: | ---: |
| Standard | 243 | 41 |
| NTFS 3.0 common FILE header | 243 | 41 |
| Fragmented MFT, resident list | 248 | 43 |
| Fragmented MFT, nonresident list | 248 | 44 |
| Nested directory index | 253 | 51 |

The fragmented MFT fixtures require an extension found through one decoded prefix
to reveal the location of the next extension. The original contiguous MFT is
erased. Index fixtures cover parent and ancestor bound violations, duplicates and
case collisions split across a separator and child. Stream tests compare mixed
compressed/raw/hole/final units, invalidate a compressed cache fill on injected
I/O failure and verify sparse/VDL zeros without device reads. Decoder vectors
cover every token length/displacement split and short/overlong output buffers.
NTFS 3.0 acceptance here covers synthetic common-header records; no Windows 2000
authored corpus has been tested.

The external suite used separately built NTFS-3G utilities to create four regular
64-MiB images and write 100 files per image. It compared file bytes with both
independent expected content and ntfscat, exercised Unicode names, case folding,
external directory indexes and ADS, and verified every image remained unchanged.
NTFS-3G is an external test oracle; no NTFS-3G library is linked into the driver.

Generated local evidence is under ignored paths:

- `artifacts/core-ready-test.log`, `core-ready-style.log` and
  `core-ready-compile.log`.
- `artifacts/core-ready-fskit-build.log` and `core-ready-fskit-component.log`.
- `artifacts/interoperability-core-ready/report.json` and `commands.log`.
- `artifacts/core-ready-fuzz.log` and `core-ready-compact-images.log`.
- `artifacts/core-ready-release.log` and `benchmark-core-ready.json`.
- `.build/meson-logs/testlog.json` contains individual sanitized test results.

The continuation also passed the adapter component tests after adding a permanent
revocation latch. Cached resident and compressed reads, metadata, lookup and
enumeration fail once the resource is revoked; reclaim and teardown remain usable
without further device I/O. The signed Release app and embedded extension passed
strict deep signature verification. This does not verify installation, enabled
module state or a provisioning profile authorizing the test guest. Evidence is in
`artifacts/native-revocation-*.log`, `artifacts/native-signing-build2.log` and
`artifacts/native-signing/`.

An independent `ntfs-fskit-stock-26` guest was cloned and left stopped. Its first
boot was blocked by the macOS concurrent-VM limit while both slots belonged to
other tasks. No existing VM was stopped or modified. The user subsequently
redirected continuation to the core; native acceptance is deferred. Generated
ownership and boot evidence remain in the lab's `artifacts/ntfs-fskit/` directory.

The initial fuzz build with Xcode could not link because that distribution lacks
the libFuzzer runtime. It executed no fuzz inputs. The successful run used the
explicit LLVM compiler override documented in DEVELOPMENT.md.

A subsequent attempt with the accumulated full-image corpus hit the 1-GiB process
RSS limit. The allocation report attributed 88% of live heap bytes to libFuzzer's
retained corpus; the core allocator remained bounded. Preserve this failed run
as `artifacts/core-handoff-fuzz.log`. The runner now authors 1-MiB physical images
covering all fixture payloads, retaining the larger logical sparse streams. It
uses a separate corpus and keeps the original seeds and failure evidence. The
ordinary 8-MiB fixture suite remains unchanged in physical geometry. The same
image contracts pass on all five compact seed layouts as well.

The final compact fuzz run completed 171,809 executions in 121 seconds without a
reported crash, timeout, OOM or sanitizer finding. Final process RSS was 552 MiB;
the retained corpus had 184 entries. This bounded run does not establish complete
coverage or production security. The final release benchmark and Python syntax
checks also passed. Performance numbers describe a warm POSIX image only; see
PERFORMANCE.md for the workload and limits.

Keep source revisions in Git and generated artifact identities in reports.
Review selected report fields; do not dump unfiltered legacy Meson reports.

During MFT bootstrap, each extension must be reachable through the decoded MFT
prefix. Attribute-list streams must be fully addressable from their base record.
NTFS compression supports the ordinary 16-cluster unit with clusters up to 4 KiB;
larger compressed units are rejected.
Unpaired UTF-16 names have no lossless FSKit UTF-8 presentation yet. These are
limits, not successful feature tests. Dirty or otherwise flagged volumes are
refused without recovery. The mirror check covers MFT bootstrap record zero;
mount is not a full filesystem consistency check. Distinct case-sensitive names
with identical $UpCase keys produce UNSUPPORTED during lookup; full WSL/POSIX
namespace semantics remain open. Stream names use exact UTF-16 matching. The
adapter uses a single-user read-only mode/UID/GID presentation and rejects reparse
items; it does not enforce Windows ACLs.
Directory enumeration requesting attributes can fail on unsupported files.
Named streams are available through the core and inspector, without a native
xattr mapping. Per-volume operations are serialized, with a 64-MiB core memory
budget and 16,384 live FSItem limit. No read/write claim may omit these limits.
