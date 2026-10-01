# Acceptance

The delivered scope is a bounded read-only core and FSKit development product.
Local core, adapter component, unsigned app-build and independent-image checks
passed. Installed native mounts, Windows interoperability and commercial release
qualification remain open. The requested 60% is not a measured completion claim;
see [the handoff](HANDOFF-SOL.md) for the delivered scope and remaining work.

| Contract | Scope and required evidence | Status |
| --- | --- | --- |
| Geometry and MST | 512/4096-byte sectors, 1/4/64-KiB clusters in independent images; boot bounds and torn FILE/INDX tests | Local tests passed |
| MFT and attributes | Sequence identities, resident/nonresident attributes and ordinary extension lists; stale/wrong-base and continuation-instance tests | Local tests passed within limits below |
| Streams | Fragmentation, sparse/VDL zeroing, ADS, bounded LZNT1 and a partial final uncompressed unit | Synthetic tests passed; ordinary data/ADS independently compared |
| Directories | Resident/external B-tree, allocation bitmap, cycle rejection, persistent cursor and $UpCase lookup | Synthetic and independent image tests passed |
| Resource safety | 235 allocation-failure positions, 36 I/O-failure positions, exact release accounting, BUSY lifetime, 2,000 deterministic image mutations under ASan/UBSan | Local tests passed |
| Coverage-guided fuzzing | Bounded libFuzzer/ASan/UBSan run using full LLVM; 28,999 executions in 61 seconds | Completed without reported crash or sanitizer finding; ongoing fuzzing required |
| Portable boundary | Freestanding arm64/x86_64 compilation with 2-KiB frame budget; selected Xcode formatting | Passed; kernel integration untested |
| FSKit component | Aligned resource reads, short/error I/O, item identity, stored names, pagination/replay, EROFS, concurrent reads and teardown under ASan/UBSan | Passed in-process on macOS 26.6.2 |
| FSKit application | Host app and embedded extension, legacy/modern protocol sources, unsigned Xcode build | Build passed; macOS 27 runtime untested |
| Native installation | Signed VM mount, Finder, mmap, concurrency, removal | Not run |
| Windows corpus | Windows-authored metadata, sparse/compressed edge cases, native repair and roundtrip evidence | Not run |
| Write/recovery | Native log, allocation, namespace transactions, crash matrix | Not implemented |
| Security and special data | $Secure/ACL policy, reparse points, EFS, WOF | Not implemented |
| Distribution | Personal signing, notarization, installer, licensing and support | Not implemented |
| Remote CI | macOS/Linux core, Linux oracle and bounded libFuzzer workflow | Prepared; not executed remotely |
| Performance baseline | Unsanitized optimized build; 100 full reads and 1,000 lookups against a warm POSIX image | Measurement recorded; native performance unmeasured |

`make test` passed all four suites: primitives/lifecycle, image contracts,
deterministic fuzz smoke and build-environment isolation. The image suite checks
nine expected file hashes, ordering, case folding, ADS, four damaged images and
twelve additional format/continuation/rejection cases. Unsupported and corrupt
inputs passing their rejection tests do not establish support for those layouts.

The external suite used separately built NTFS-3G utilities to create four regular
64-MiB images and write 100 files per image. It compared file bytes with both
independent expected content and ntfscat, exercised Unicode names, case folding,
external directory indexes and ADS, and verified every image remained unchanged.
NTFS-3G is an external test oracle; no NTFS-3G library is linked into the driver.

Generated local evidence is under ignored paths:

- `artifacts/final-core.log`, `final-style.log` and `final-core-check.log`.
- `artifacts/final-fskit-build.log` and `final-fskit-component.log`.
- `artifacts/interoperability-final/report.json` and `commands.log`.
- `artifacts/final-fuzz-llvm.log`, `final-release-build.log` and `benchmark-posix.json`.
- `.build/meson-logs/testlog.json` contains individual sanitized test results.

The initial fuzz build with Xcode could not link because that distribution lacks
the libFuzzer runtime. It executed no fuzz inputs. The successful run used the
explicit LLVM compiler override documented in DEVELOPMENT.md. Python syntax
checks also passed for all scripts and tests.

Keep source revisions in Git and generated artifact identities in reports.
Review selected report fields; do not dump unfiltered legacy Meson reports.

MFT bootstrap with an attribute list is rejected. Attribute-list streams must be
fully addressable from their base record. NTFS compression supports the ordinary
16-cluster unit with clusters up to 4 KiB; larger compressed units are rejected.
Unpaired UTF-16 names have no lossless FSKit UTF-8 presentation yet. These are
limits, not successful feature tests. Dirty or otherwise flagged volumes are
refused without recovery. The mirror check covers MFT bootstrap record zero;
mount is not a full filesystem consistency check. Case-sensitive/WSL namespace
semantics remain open. The adapter uses a single-user read-only mode/UID/GID
presentation and rejects reparse items; it does not enforce Windows ACLs.
Directory enumeration requesting attributes can fail on unsupported files.
Named streams are available through the core and inspector, without a native
xattr mapping. Per-volume operations are serialized, with a 64-MiB core memory
budget and 16,384 live FSItem limit. No read/write claim may omit these limits.
