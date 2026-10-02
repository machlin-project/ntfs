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
  names and opaque tag classification. Preserve rejection of ordinary data reads
  and directory traversal, including attributes whose standard-information flag
  was cleared. Classifying WOF/cloud tags does not decode their data.
- Independent stream flags: an unencrypted ADS remains readable beside an
  encrypted default stream. Exact UTF-16 stream-name matching is documented.
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
make fskit
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

Continue unsupported-object attribute pages: reparse and unsupported default
streams can still stop a page or prevent item adoption. The packer's nullable
argument is not evidence that requested attributes may be omitted. Define
truthful metadata and stable continuation, then test links, ADS and rejection
without hiding objects or inventing ordinary-file sizes. Backend dot lookup and
parent resolution remain separate from virtual enumeration. Bounded checkpoints,
native scheduling and buffer lifetime also remain open.

## Core handoff checkpoint

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
NATIVE-NAMESPACE.md for format and limits. Do not promote these results to
installed ADS acceptance or close unsupported-default-stream adoption.

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
6. Qualify the reparse metadata reader with Windows-authored links. Define target
   translation and namespace ownership before enabling native symlink/junction
   behavior. WOF, cloud placeholders, third-party GUID owners and WSL tags require
   separate content/resolution contracts. The current adapter rejects reparse
   items. Do not expose encoded data as ordinary file content or turn every tag
   into a symlink.
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
