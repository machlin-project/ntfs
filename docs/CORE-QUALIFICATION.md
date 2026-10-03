# Core qualification and continuation

This file tracks the agreed no-VM continuation scope. A working local parser,
component build or microbenchmark cannot establish Windows compatibility,
installed FSKit behavior or commercial readiness. Preserve those evidence
boundaries when updating ACCEPTANCE.md and HANDOFF-SOL.md.

| Required outcome | Current implementation and evidence | Work remaining |
| --- | --- | --- |
| Independent corpus and sustained fuzzing | Windows-only read-only collector; local manifest verifier and synthetic acquisition/UTF-16/hard-link regressions; separate image, full diagnostic, mapping-pair, attribute-list, index-root/block, LZNT1, reparse, security, DACL/token, WOF/XPRESS/LZX and LFS/NTFS-log fuzz targets; FILE/INDX fixup-preserving image mutations and USA-preserving log-page mutations; bidirectional external LZX codec observations | Execute acquisition on a Windows machine; extend expected-operation observations; use Windows seeds and longer scheduled campaigns; reduce every found defect to a retained regression |
| Metadata consistency and corruption diagnosis | Private read-only validator for MFT/cluster bitmaps, extension/list references, required mirror prefix/boot-anchor mapping, exact namespace pairing/link graph, complete ordinary directory bitmap/reachability inventory and physical ownership; seven budgets, 118 image verdicts, 1,305 allocation/963 I/O faults, 80 partial/full mirror-stage failures and 48 mirror prefix budgets; six partial/full bitmap failures and nine index read-prefix budgets; four independent bitmap/mirror-export geometries and bounded diagnostic fuzz; cached metadata validates before publication | Windows/DOS and listed/flagged bad-cluster qualification; view-store relations and allocation inventories, Windows-dependent extended mirror tails, boot replicas and native journal checks; real fragmented and large-directory corpus |
| Owning-operation resource bounds | API 2 implicit/explicit scopes, cumulative read/allocation/work limits and aggregate core live storage; nested ancestor charging, pre-callback refusal, uniformly propagated sticky result, unconditional cleanup and detached scope lifetime; FSKit compound scopes plus rounded physical fragments; 12 profiles/144 exact boundaries, all 32 denying ancestors at depth 32, failed-attempt/cache/codec/reentry checks and budgeted image fuzz pass | Windows-authored large/fragmented/hostile workloads, longer scheduled campaigns, installed scheduling/buffer behavior, complete native aggregate allocation/RSS stress, matched accounting-simplification and native cost measurements; work units are not elapsed deadlines; see OPERATION-BUDGETS.md |
| Names, hard links, streams | Reference-addressed inspector preserves UTF-16 code units; bounded ADS catalog/xattrs; reversible bounded FSKit filename aliases and raw per-link manifests; per-directory exact/folded lookup retaining B-tree collation, 17 policy images and 47 allocation/eight I/O faults; mixed parents and sensitive aliases pass components; complete encoded-stream size metadata, strict content rejection and independent ADS with 18 core verdicts, 29 allocation/four I/O faults and six native component variants | Windows/native case-policy and volume-capability/cache qualification; installed filename/ADS and encoded-object flows; native normalization and Windows-authored EFS/compression metadata |
| Links and special data | Immutable lossless core reparse snapshots, original-wire copies/physical sizes; bounded single-edge FSKit symlink/junction projection with explicit current-owner roots, numeric ancestry and filename aliases; 47 component verdicts and 79 allocation/17 read faults; ordinary EFS metadata and independent plaintext ADS; WOF XPRESS4K/8K/16K and LZX32K storage/table/content with 37 verdicts, 376 allocation/101 read faults, 23 legacy provider scenarios and bounded image fuzz; 87 content/11 invalid XPRESS and 140 content/31 invalid LZX vectors; 192 external LZX streams and 139 external synthetic decodes | Windows/installed link semantics, intermediate chains, context-dependent reparse hard links and cross-volume ownership; provider-specific native fault/interleaving and hard-link qualification, Windows codec/format observations; WIM/cloud/unknown policies and EFS decryption/key ownership |
| Security | Original descriptor/SID/ACL/ACE parser and bounded immutable resolver for `$Secure` and per-file attributes; distinct absent/NULL/empty ACLs, checked index paths/hash/copies and four external image geometries; bounded ordered DACL evaluator with exact generic mappings, ordinary ownership and deny-only/restricting contexts, 196,608 independent per-right oracles | Whole-store/Windows qualification; native AccessCheck comparisons, restricted ownership, advanced ACE/SACL/privilege/maximum-access policy and Windows-to-native identities; integrate owning authorization |
| FSKit lifecycle and interoperability | Separate admission/drain; 16 gated direct/window-read/overlapping-teardown cases and 120 resource geometry/fault verdicts at three alignments; conditional reclaim, weak canonical identity and five modeled eligibility/publication cases; virtual dot/parent IDs, separate cookie views/native errors; two lazy pool-backed independent continuations, 32 layout/view/cache/pressure cases, reentrant pin/epoch/retired-table ownership, 34 allocation/13 I/O names-only faults and 151 allocation/41 I/O interleaved faults; encoded-file pages and bounded native link/raw-metadata/remount/revocation checks; late-unit WOF errors and common result-construction/revoked-acquisition guards informed by ext4 history; independent pressure observer with selective cache release, three measured allocation scenarios and blocked-read/fault/namespace components | Synchronous I/O interruption/deadlines and task cancellation; native reclaim counts/macOS 27 runtime and installed scheduling/buffer lifetime; actual modern result-construction failure injection; complete link/provider resolution, backend dot lookup/parent resolution and broader checkpoint/index reuse; installed pressure notification delivery/aggregate stress and distribution discovery; see LIFECYCLE.md, READ-CACHE-POLICY.md and FSKIT-EXT4-LESSONS.md |
| Recovery and release processes | No write callback; native recovery contract in WRITES.md; immutable LFS 1.1/2.0 primitives/nonempty-LCN update framing, 109 verdicts/110 diagnostic contracts; independent logical owner, bounded compatible restart selection/conflicts, cached clients and staged physical pages, 22 source/report verdicts; counted ordinary NTFS stream binding, 24 volume/report verdicts and 54 allocation/58 physical-read faults; physical wrapped-record observation with 30 byte/report verdicts, 14 allocation/40 partial-read faults and exact 1-MiB custom-credit boundary; cached active-client index/sequence lookup with 858 pair queries/seven snapshots and 42 exact reports; source/record USA-preserving fuzz and mounted-volume image fuzz path; private CI workflow and provenance | Native journal admission/drain ownership, written/current circular history and qualified record selection, legacy tail/modern fast-page routing and native client registration/checkpoints/tables; qualify LCN-less/native Windows packets and copy lifecycle/version transitions; transaction/crash/durability simulator and relocated-source/native release reproducibility; actual private CI execution and later native Windows recovery acceptance |

The complete ordinary directory allocation inventory passes 22 new images with
cache on/off, free-storage no-read controls, fragmented/paged required-failure
sweeps and all three bitmap-read partial/full/budget prefixes. All 60 sanitized
suites, both freestanding targets, style, 22 component groups/eight modern-runtime
SKIPs and the unsigned arm64/x86_64 Release app pass. The validation campaign
fixed-replays 118 seeds and explores 54,415 executions with no reported finding;
all four independent bitmap/mirror-export geometries pass unchanged. This closes
the ordinary `$I30` used-block inventory implementation, leaving Windows-authored
and non-directory view-store qualification in the row above. See VALIDATION.md
and ACCEPTANCE.md for inference, scope, retained diagnostic failure and logs.
Earlier Release reproducibility predates the new inventory source.
A subsequent current-source comparison passes both ordinary Release/O3 builds
and all eight full archive/CLI byte comparisons under
`artifacts/reproducibility-index/`. Review re-read each actual pair and checked
equality, lengths and reported digests. Same-checkout/toolchain scope remains;
relocated/native/remote CI qualification and current accounting overhead remain
open.

Portable Release reproducibility now has a separate ordinary-build checker:
two build directories in the same checkout produce eight byte-identical local
arm64 archives/CLI products without normalization. It retains compiler/SDK,
Git revision, selected options and bounded diagnostics in generated reports.
Prepared macOS/Linux CI, relocated sources and native app/signing still require
their own execution. See DEVELOPMENT.md and ACCEPTANCE.md.

The operation-budget continuation passes all 60 sanitized core suites, both
freestanding 2-KiB-frame targets, selected style, 22 component PASS groups/eight
explicit macOS-27 runtime SKIPs and an unsigned Release app for arm64/x86_64.
Image/validation campaigns fixed-replay all 282/96 seeds and explore 51,427/57,672
executions with unchanged input/RSS/timeout policies and no reported OOM/timeout/
crash. Four external image geometries again agree on ordinary/ADS bytes and names.
This closes implementation of the general core/native accounting model, with
the qualification gaps retained in its row above. Prior portable reproducibility
and performance reports predate the changed core ABI. A subsequent current-source
comparison now passes both ordinary Release/O3 builds and all eight full archive/
CLI byte comparisons under `artifacts/reproducibility-operation/`. Review re-read
both actual products and checked equality, lengths and reported digests. Its
same-checkout/toolchain scope remains unchanged; relocated/native app/remote CI
acceptance and accounting-overhead measurement remain separate.

The current mirror diagnostic passes both ordinary Release/O3 builds and all
eight full product byte comparisons under `artifacts/reproducibility-mirror/`.
Review independently verified the actual products against each other and the
reported lengths/digests. The same-checkout/toolchain scope remains unchanged;
relocated sources, native app/signing and remote CI remain unqualified.

The subsequent NTFS client restart decoder retains only the 64-byte common
prefix for client formats 0.0/1.0, raw analysis/table LSN/count fields and an opaque
tail. Its 77 aligned/unaligned verdicts, 75 exact reports/two transport checks,
56 sanitized suites and 249 fixed-replayed logfile seeds pass. Complete table and
extension semantics, containing-record ownership, written/current history and
native Windows qualification remain in the recovery scope above. The earlier
reproducibility report predates this decoder. A subsequent eight-product local
comparison now qualifies its committed Release/O3 products under
`artifacts/reproducibility-logcheckpoint/`; relocated/native and remote CI
acceptance remains open.
Selected-client restart-record binding now checks exact assembled framing,
selected active index/sequence, RESTART type, exact NTFS client name and stored
restart LSN before prefix interpretation, without cached callbacks/allocations.
Its 165 verdicts across 19 sources, 161 exact reports/four transports, 59 sanitized
suites and all 414 fixed-replayed logfile seeds pass. It does not qualify physical
page/current-history provenance, native registration lifecycle or complete
checkpoint tables/extensions. Those remain in the full recovery scope above;
the earlier Release comparison predates this binding source change. A subsequent
comparison now passes both Release/O3 builds and all eight full product byte
comparisons under `artifacts/reproducibility-logrestart-record/`. Relocated/native
app and remote CI acceptance remains open.

Optimization is a separate acceptance stream:

Historical metadata/resource/directory improvements below predate accounting
guards; their percentages remain scoped to those sources. The new paired core
experiment passes 2,880 runs/160 paired configurations across ten storage inputs,
with independent bytes/ranges/samples and retained release/toolchain/source
agreement. It quantifies targeted guard cost, while the later head-result/usage
initialization simplification still needs its own matched measurement. Native
cost/baselines and broader comparisons remain separate in PERFORMANCE.md.

Adaptive FSKit retention has measured component core-allocation release and warm
unit I/O preservation; READ-CACHE-POLICY.md distinguishes that evidence from
aggregate memory, installed notification delivery and throughput measurements.

| Required outcome | Current implementation and evidence | Work remaining |
| --- | --- | --- |
| Repeatable measurements | `ntfs-workload` records wall/CPU, request percentiles, allocation/I/O/cache counters and peak memory; POSIX/memory callbacks, explicit warmup, request sizes and serialized readers; runner checks independent original bytes/ranges/samples, retains binaries and validates release/toolchain/source evidence for alternating pairs; 58 helper contracts and ten input matrices pass; actual legacy directory handler has full independent inventory and retained-binary comparisons, nine paired repetitions per profile on large/small authored namespaces | Qualify the accounting simplification; broaden independent file-set, fragmentation and compression workloads; true native/device cache profiles and matched independent driver comparisons |
| Metadata reuse | One validated metadata snapshot per live immutable node; failed checks publish nothing; retry, zero repeated I/O/allocation and owner-lifetime tests | Attribute-list/stream metadata and bounded index reuse only where profiles justify their cost |
| Directory continuation | Two independent actual core cursors retained per enumerated item through a lazy bounded table; exact/nearest-earlier same-view reuse, completed-scan eviction, pinned packing, epoch teardown and pressure trimming; all 32 cache cases and 151 allocation/41 read faults pass; matched legacy memory-reader interleaving wall reductions of 88–89% on the 2,000-link fixture and 32–35% on the 12-link fixture, with disclosed pool cost | Broader bounded checkpoint/checked-index reuse, more than two active positions, diverse independent files and Windows-authored fragmentation; installed/native/device profiles and aggregate allocation/RSS stress |
| Native link and type metadata | Immutable target bytes reused per live FSItem; names-only classification validates node/reparse metadata without target resolution; alias translation has one shared scan budget | Measure cold/warm classification and alias-heavy paths, including repeated page lookahead; bounded checked-record/index/alias reuse only after profiling and unchanged fault/lifetime behavior |
| Data I/O | Whole-run coalescing, sparse/VDL zeroing and bounded compression buffer; resource-aligned caller transfers with unchanged limits and window fallback; five-run retained-binary memory-reader comparisons show targeted 64-KiB/1-MiB benefit with byte/guard/fault/lifecycle checks | Native caller alignment/transport/buffer/device qualification, matched independent driver throughput; broader fragmentation, reused buffers and extent hints only after profiling |
| Compression | Existing one-unit LZNT1 and WOF XPRESS/LZX caches; independent codec vectors, external LZX packets and integrated provider byte/fault cases | Profile misses and whole-table open cost; evaluate bounded cache sizes and hot-loop changes; measure WOF codec/unit/page caches on independent original workloads |
| Concurrency | Benchmark discloses external serialization and lock wait in latency | Object/callback/teardown contract, then independent reads with measured benefit and progress guarantees |

## Windows acquisition and comparison

Use a disposable NTFS fixture volume prepared on Windows and attached read-only
before acquisition. Its assigned drive root must report `FILE_READ_ONLY_VOLUME`;
the collector does not change device state or format media. Put the selected tree
on that volume and the output on another volume. All native API execution remains
unqualified until an actual Windows run passes.

```sh
python scripts/collect_windows_corpus.py --volume R:\ --tree corpus --output C:\ntfs-corpus-new
```

The new output contains `volume.img`, original stream payloads and `manifest.json`.
Metadata preserves file references, individual link names, original UTF-16,
FILETIMEs, stream names, reparse bytes and native security descriptors. The
collector does not follow reparse targets. Security/case observations that fail
make acquisition partial; cloud and unknown-provider content is explicitly
provider-dependent. Windows decoding of WOF data is an oracle observation, not a
claim that this core supports it.

Copy that output to a host regular-file directory, then run:

```sh
python3 tests/windows_corpus.py artifacts/windows-corpus/manifest.json --reader .build/ntfs-inspect --report artifacts/windows-corpus/report.json
```

The verifier checks exact stored names/references, directory inventory, metadata,
reparse targets and full content hashes. Repeated hard-link observations must
agree before a shared stream is read once. Partial acquisition stays partial;
unsupported driver operations fail their check. Reports list security and
case-policy gaps separately. Neither collector nor verifier mounts the image.

## Evidence boundaries

VALIDATION.md defines the implemented whole-volume diagnostic passes and their
remaining semantic gaps. A complete report means those passes succeeded within
budget; it does not close full metadata/security/recovery qualification. The
independent mkntfs images and synthetic mutation cases are separate from native
Windows-authored corpus evidence.

Synthetic corpus tests qualify the manifest/transport and inspector contracts,
not the Win32 calls or Windows-authored on-disk features. NTFS-3G utilities are
independent external image/oracle tools, not linked product code. Parser fuzzing
checks bounded hostile inputs, not exhaustive semantic compatibility. The security
parser preserves checked spans and values; it does not make access decisions or
validate application-specific callback conditions. The separate DACL evaluator
has synthetic decision and bounded context-fuzz evidence; that does not close
full Windows/native authorization. ACCESS.md retains its unsupported policies.
ACCESS-ORACLE.md defines the independent Windows collector and bounded offline
comparison path. Its 337 synthetic transport, SDK span, acquisition and reporting
contracts pass; original native token fields and descriptor bytes are retained,
with missing/unsupported/error cases visible. Windows acquisition remains unrun.

Every continuation must retain its full scope. Focused commits are checkpoints;
the rows above cannot be closed by shrinking them to already passing tests.
