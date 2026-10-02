# Acceptance

The delivered scope is a bounded read-only core and FSKit development product.
Local core, adapter component, current unsigned app-build and independent-image
checks passed. A preceding signed Release build passed signature verification.
Installed native mounts, Windows interoperability and commercial release
qualification remain open. The requested 60% is not a measured completion claim;
see [the handoff](HANDOFF-SOL.md) for the delivered scope and remaining work.

| Contract | Scope and required evidence | Status |
| --- | --- | --- |
| Geometry and MST | 512/4096-byte sectors, 1/4/64-KiB clusters in independent images; boot bounds and torn FILE/INDX tests | Local tests passed |
| MFT and attributes | NTFS 3.0/3.1 headers; incremental fragmented bootstrap with resident/nonresident lists; sequence, base reference, continuation instance, reachability, gaps and duplicates | Local tests passed within limits below |
| Streams | Fragmentation, sparse/VDL zeroing, independent ADS and directory ADS, mixed LZNT1 units, empty nonresident data, cache retry and offsets beyond 4 GiB | Synthetic tests passed; ordinary data/ADS independently compared |
| Stream inventory and projection | Bounded exact-UTF-16 catalog, extension ownership/duplicates, immutable lifetime, read-only FSKit xattrs and reverse manifest, response limits and revocation | 14 core and five component scenarios passed; four independent image geometries verify inventories and bytes; installed and Windows-authored projection untested |
| Native filenames and hard links | Bounded reversible aliases and per-link UTF-16 manifests; inode identity separated from link spelling; native length, Unicode, hidden/DOS ordinals, response/scan exhaustion, faults and revocation | Five authored namespace images and component sweeps passed; installed case/normalization and Windows-authored namespace untested |
| Directories | Resident/external B-tree, allocation bitmap, cycle rejection, local ordering, ancestor bounds, persistent cursor and collision-aware $UpCase lookup | Synthetic and independent image tests passed |
| Reparse metadata | Microsoft framing, relative/absolute symlinks and junction targets, lossless UTF-16, fragmented/listed attributes, snapshot lifetime, opaque WOF/cloud classification and fail-closed traversal/data access | Synthetic tests passed; Windows-authored links and native translation untested |
| Resource safety | Allocation/read failure sweeps on five layouts and reparse snapshots, exact release accounting, BUSY lifetime, 2,000 deterministic image mutations under ASan/UBSan | Local tests passed; counts below |
| Coverage-guided fuzzing | Separate bounded image and parser libFuzzer/ASan/UBSan campaigns; fixup-preserving image mutations; descriptor campaign and counts below | Completed without reported crash or sanitizer finding; sustained Windows-seeded fuzzing remains required |
| Portable boundary | Freestanding arm64/x86_64 compilation with 2-KiB frame budget; selected Xcode formatting | Passed; kernel integration untested |
| FSKit component | Aligned resource reads, short/error I/O, permanent resource revocation including cached data, item identity, stored names, pagination/replay, EROFS, concurrent reads and teardown under ASan/UBSan | Passed in-process on macOS 26.6.2 |
| FSKit application | Host app and embedded extension, legacy/modern protocol sources, personal development signing and strict deep signature verification | Current unsigned build and earlier signed Release passed; installed runtime and macOS 27 untested |
| Native installation | Signed VM mount, Finder, mmap, concurrency, removal | Not run |
| Windows corpus | Read-only Windows collector, offline manifest verifier and synthetic contract tests; native metadata/sparse/compression/repair evidence | Tools locally tested; Windows acquisition/qualification not run |
| Write/recovery | Native log, allocation, namespace transactions, crash matrix | Not implemented |
| Security descriptors and storage | MS-DTYP framing and ACL states; bounded immutable `$Secure` and per-file attribute snapshots, checked indexes/hash/copies and fault retry | 74 local contracts and four independent image geometries passed; whole-store/Windows/native authorization qualification incomplete |
| Discretionary token decisions | Ordered plain allow/deny DACLs, exact generic file masks, ordinary owner/OWNER RIGHTS and enabled/disabled/deny-only/restricting contexts, no partial grants, bounds and immutable snapshots | 196,809 local decisions including 196,608 independent per-right oracles; bounded context fuzz passed; Windows AccessCheck/full/native authorization incomplete |
| Windows access observations | Original in-memory descriptors, queried disposable tokens, native MapGenericMask/AccessCheck results, bounded offline transport and explicit mismatch/unsupported/error reports | 337 local transport/SDK/acquisition/reporting contracts passed; Windows acquisition and native DACL comparison not run |
| Full authorization and special data | Advanced ACE/SACL/integrity/privilege/maximum access, restricted ownership, identity mapping and owning native decisions; reparse target resolution, EFS and WOF/cloud content | Not implemented |
| Distribution | Personal signing, notarization, installer, licensing and support | Not implemented |
| Remote CI | macOS/Linux core, Linux oracle and bounded libFuzzer workflow | Prepared; not executed remotely |
| Performance and metadata reuse | Release POSIX/memory profiles, warmup/cache controls, reader scaling and five-run matrices; verified live-node metadata cache | Specific allocation/metadata improvement measured; native performance unmeasured |

The original core handoff passed eleven suites: primitives/lifecycle on five filesystem layouts,
stream boundaries, decoder vectors, reparse metadata, image contracts,
deterministic fuzz smoke and build-environment isolation. The image suite checks
nine file hashes across all five layouts, ordering, case folding, ADS, four damaged
images and 31 additional format/continuation/rejection cases. Unsupported and corrupt
inputs passing their rejection tests do not establish support for those layouts.

An earlier no-VM checkpoint passed 23 sanitized suites, including six standalone
parser mutation targets, corpus/workload contracts, metadata-cache fault/retry
checks, security descriptor vectors and its standalone mutation target. Evidence
is retained in `artifacts/plan-security-tests.log`. After reviewing reparse presence,
all 22 suites, freestanding targets, formatting and the direct FSKit component
passed again under `artifacts/plan-reparse-presence-*.log`. The reparse suite now
includes 26 image contracts: base attributes omitted from a list and invalid named
reparse attributes cannot become ordinary data after clearing the flag. Permanent
revocation still precedes cached operations.

Seven 30-second campaigns (image and the six original standalone parsers) passed
under `artifacts/fuzz-parser-foundation/`. The new security target completed
10,147,598 executions in 61 seconds with reported peak RSS 520 MiB and no crash or
sanitizer finding, retained under `artifacts/fuzz-security-descriptor/`. These are
bounded campaigns, not exhaustive hostile-media or Windows compatibility proof.
The foundation campaigns precede metadata reuse. Subsequent image campaigns passed
55,504 executions after reuse and 53,473 after the reviewed presence fix, each in
61 seconds, under `artifacts/fuzz-verified-metadata/` and
`artifacts/fuzz-reparse-presence/`. The latter reported peak RSS 613 MiB and no
crash or sanitizer finding. The current unsigned app and extension also built
after that fix (`artifacts/plan-guard-app-build.log`); neither was installed.

The stream catalog and native xattr projection subsequently passed all 23 suites,
freestanding targets, expanded component tests, style and the current unsigned
app build under `artifacts/plan-ads-*.log`. The catalog suite covers fourteen
inventories/rejections and 28 allocation/one I/O failure positions. Five adapter
scenarios cover native stream manifests, exact UTF-16, bounded responses, retry
and revocation. Image fuzzing completed 55,509 executions in 61 seconds with peak
RSS 682 MiB and no reported finding under `artifacts/fuzz-stream-catalog/`.
Four independent image geometries subsequently passed 100 file-byte oracles each,
ADS bytes, exact stream inventories, case folding and unchanged image hashes
under `artifacts/interoperability-stream-catalog/` and
`artifacts/plan-ads-oracle.log`. Windows acceptance remains unrun.
NATIVE-NAMESPACE.md defines the format and its remaining limits.

Native filename projection subsequently passed all 23 suites after fixture
changes (`artifacts/plan-names-budget-tests.log`), current component fault/budget
checks, style and the unsigned app (`artifacts/plan-names-verified-*.log`). Five
namespace images include twelve hard links and a 2,000-link tree. Required name
manifest allocations/I/O passed 13/five failure positions; alias lookup passed
17/six, with exactly-once failure replies, retry and zero tracked allocation
leaks. Initial cache-insertion fault-test diagnosis is retained and explained in
NATIVE-NAMESPACE.md. This is component acceptance, not installed namespace proof.

Security storage subsequently passed all 24 sanitized suites, both freestanding
targets, style, the existing FSKit component and unsigned app under
`artifacts/plan-secure-observed-*.log`. Final review improved the collision fixture
to use distinct descriptor bytes and owner SIDs with one checksum, then repeated
all 24 suites and style under `artifacts/plan-secure-collision-*.log`. The current
suite covers 74 contracts and 262 allocation/191 I/O failure positions, retry,
unchanged failure outputs and exact release. It includes resident/external view indexes, hash collisions,
ancestor bounds, cycles/depth, bitmap/MST/USA, maximum descriptors, later SDS
pairs and resident/nonresident/listed per-file attributes. No default file data
is opened to inspect its security metadata.

The independent comparison checks 24 original descriptor-byte/ID observations
in four existing image geometries, with unchanged images, under
`artifacts/interoperability-secure3/` and `artifacts/plan-secure-oracle3.log`.
Earlier failed comparisons remain under `interoperability-secure/` and
`interoperability-secure2/`: real per-file and nonresident descriptor storage
exposed incorrect assumptions in the old format notes. They are failures, not
successful runs. The initial build rename error and authored allocation-size
fixture error are also retained in the earlier `plan-secure-*` logs.
The first updated image fuzz campaign completed 43,226 executions in 61 seconds,
reported coverage 3,005 and peak RSS 918 MiB under
`artifacts/fuzz-secure-resolver/`. After improving the collision fixture, a new
campaign completed 47,915 executions in 61 seconds with coverage 2,987 and peak
RSS 901 MiB under `artifacts/fuzz-secure-collision/`. Neither reported a finding;
coverage values from separate bounded campaigns are not monotonic. Process RSS includes libFuzzer's retained
image corpus; the separate core allocation budget remains 8 MiB. This is bounded
local evidence, not Windows or installed authorization acceptance. SECURITY.md
defines source selection, supported bounds and remaining security contracts.

The discretionary evaluator subsequently passed all 26 sanitized suites,
freestanding targets, style, FSKit components and unsigned source app build under
`artifacts/plan-access-observed-*.log`. Its suite covers 196,809 decisions, including
196,608 independent per-right ordered token oracles. Final review replaced its
SACL vector with a real high-integrity SID and NO_READ_UP, then repeated the
affected build/test/style under `artifacts/plan-access-review-*.log`. That vector
proves the DACL-only boundary, not integrity enforcement. Final named-constant
and seed cleanup passed all 26 suites and style again under
`artifacts/plan-access-final-*.log`. Snapshot evaluation
survives node close and performs no allocation/I/O under forced next-call faults.
An earlier focused failure remains in `plan-access-focused.log`: the test
incorrectly assumed ownership implied FILE_READ_DATA for the genuine collision
descriptor. Corrected expectations distinguish implicit owner control rights
from the original DACL trustee; no core grant policy was changed to pass it.

The separate descriptor/token campaign completed 14,450,666 executions in
61 seconds with coverage 436 and peak RSS 489 MiB, exit zero and no reported
finding under `artifacts/fuzz-access-context/`. No Windows AccessCheck or installed
native authorization was exercised. ACCESS.md defines exact masks, feature
rejection, shared comparison budgets and the remaining restricted-owner,
advanced-ACE, SACL/integrity/privilege, identity and native operation contracts.

The independent AccessCheck pipeline subsequently passed all 27 ASan/UBSan
suites, both freestanding targets, selected-toolchain style, FSKit components and
the unsigned current-source app build under `artifacts/plan-access-oracle-observed-*.log`.
The new suite passed 337 contracts covering original SID/descriptor transport,
SDK pointer/count bounds, token-copy rights and requested transformations,
cleanup after acquisition failures, partial manifests, original-byte checks,
missing/tampered vectors, API failure versus denial, output budgets and deadlines.
The intentionally coarse fake provider produces both matching and mismatching
decisions and cannot claim Windows provenance or native qualification.

Standalone SID decoding is allocation-free, preserves the full six-byte
authority/15-subauthority range, rejects trailing storage and zeroes errors.
Native SDK-shaped buffers and SID packets are authored independently. The
expanded security fuzz corpus includes standalone SID packets and completed
8,949,047 executions in 61 seconds with coverage 172, peak RSS 526 MiB and no
reported finding under `artifacts/fuzz-access-oracle-sid/`. This bounded run is
local robustness evidence. No Windows AccessCheck acquisition, filesystem access,
installed mount or complete authorization was exercised. ACCESS-ORACLE.md defines
the capture/comparison commands, scope, bounds and unresolved probes.

A retained synthetic review is available in
`artifacts/access-oracle-synthetic-capture/manifest.json` and
`artifacts/access-oracle-synthetic-review/report.json`. Its six contexts/144 cases
produce 65 matches, 52 deliberate mismatches, 21 unsupported cases and six
out-of-plane observations. The report remains `gaps`, the input is unchanged,
and both native DACL/full-authorization qualification flags remain false. This
example demonstrates reporting behavior, not Windows access results.

Before/after release matrices each retain 400 measurements, independent full
stream-byte oracles and unchanged input hashes. Metadata reuse removes repeated
presence-validation allocations and improves the measured open/lookup profiles;
data-read changes are mixed. PERFORMANCE.md records exact scope, counts and
remaining optimization requirements. CORE-QUALIFICATION.md retains every agreed
functional and optimization deliverable without treating this checkpoint as
completion of the full continuation.

| Fault sweep layout | Allocation failure positions | I/O failure positions |
| --- | ---: | ---: |
| Standard | 249 | 41 |
| NTFS 3.0 common FILE header | 249 | 41 |
| Fragmented MFT, resident list | 254 | 43 |
| Fragmented MFT, nonresident list | 254 | 44 |
| Nested directory index | 259 | 51 |

The fragmented MFT fixtures require an extension found through one decoded prefix
to reveal the location of the next extension. The original contiguous MFT is
erased. Index fixtures cover parent and ancestor bound violations, duplicates and
case collisions split across a separator and child. Stream tests compare mixed
compressed/raw/hole/final units, invalidate a compressed cache fill on injected
I/O failure and verify sparse/VDL zeros without device reads. Decoder vectors
cover every token length/displacement split and short/overlong output buffers.
NTFS 3.0 acceptance here covers synthetic common-header records; no Windows 2000
authored corpus has been tested.

The reparse suite adds standalone decoder vectors and 26 image contracts.
It checks resident, fragmented nonresident and attribute-list storage, targets
whose print and substitute names appear in either order, unpaired surrogate
preservation, capacity checks before copying, source-node closure and BUSY unmount.
Decoder vectors cover truncation, exact framing, reserved fields, overlapping
strings without terminators, embedded NULs, offset alignment/ranges, every cloud
tag variant, future flags and GUID-envelope rejection. WOF/cloud/unknown tag tests
validate framing and classification only. They do not validate provider payloads
or establish file-content support. Opening a junction on a non-directory is corrupt.

The suite sweeps 45 snapshot-allocation and six snapshot-I/O failure positions and
verifies exact release accounting. Ordinary stream reads and directory traversal
refuse reparse nodes, including a junction with a plausible local index. A cleared
standard-information flag with an existing reparse attribute returns CORRUPT for
both base-record and listed-extension storage. The inspector's `reparse` command
reports tags, link flags and UTF-16 code units without following targets.

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
- `artifacts/core-reparse-*.log` and `core-reparse-final-*.log` record the core
  continuation, selected compiler checks, adapter component tests and fuzz runs.
- `artifacts/interoperability-reparse/report.json` and `commands.log` record the
  repeated independent four-geometry oracle after the metadata guards changed.

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

At the original core handoff, the compact fuzz run completed 171,809 executions in
121 seconds without a reported crash, timeout, OOM or sanitizer finding. Final
process RSS was 552 MiB; the retained corpus had 184 entries. This bounded run does
not establish complete coverage or production security. The final release benchmark and Python syntax
checks also passed. Performance numbers describe a warm POSIX image only; see
PERFORMANCE.md for the workload and limits.

The reparse continuation passed all eleven suites, both freestanding compilation
targets and the in-process FSKit component tests. A repeated independent oracle
again compared 100 files in each of four geometries and preserved the image hashes.
After final GUID-envelope review, the bounded fuzz run completed 90,737 executions
in 61 seconds without a reported crash, timeout, OOM or sanitizer finding. Final
RSS was 609 MiB; the retained corpus had 234 entries occupying 164 MiB. Raw reparse
buffers accompany full images so the decoder receives direct mutation coverage.
This remains bounded local evidence; Windows-authored reparse points, provider
data formats and installed native behavior have not been qualified. The inspector
also preserved an unpaired surrogate as `d800 0078`; changed Python files passed
syntax compilation.

The current unsigned Debug app and extension also built with the new C API and
source module, including the Swift bridge and both FSKit protocol implementations.
This is compilation evidence, not installation or runtime acceptance; see
`artifacts/core-reparse-fskit-build.log`.

Keep source revisions in Git and generated artifact identities in reports.
Review selected report fields; do not dump unfiltered legacy Meson reports.

During MFT bootstrap, each extension must be reachable through the decoded MFT
prefix. Attribute-list streams must be fully addressable from their base record.
NTFS compression supports the ordinary 16-cluster unit with clusters up to 4 KiB;
larger compressed units are rejected.
Unpaired, oversized and reserved filenames now have bounded native aliases and
UTF-16 reverse manifests, qualified by component tests; installed projection and
native normalization remain untested. Dirty or otherwise flagged volumes are
refused without recovery. The mirror check covers MFT bootstrap record zero;
mount is not a full filesystem consistency check. Distinct case-sensitive names
with identical $UpCase keys produce UNSUPPORTED during lookup; full WSL/POSIX
namespace semantics remain open. Stream names use exact UTF-16 matching. The
adapter uses a single-user read-only mode/UID/GID presentation and rejects reparse
items; it does not enforce Windows ACLs.
Directory enumeration requesting attributes can fail on unsupported files.
Named streams now have a bounded read-only xattr projection and reverse manifest
in both FSKit protocol paths, qualified only by component/build tests. Unsupported
default streams can still prevent item adoption, and installed projection remains
untested. Per-volume operations are serialized, with a 64-MiB core memory
budget and 16,384 live FSItem limit. No read/write claim may omit these limits.
