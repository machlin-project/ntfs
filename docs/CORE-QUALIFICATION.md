# Core qualification and continuation

This file tracks the agreed no-VM continuation scope. A working local parser,
component build or microbenchmark cannot establish Windows compatibility,
installed FSKit behavior or commercial readiness. Preserve those evidence
boundaries when updating ACCEPTANCE.md and HANDOFF-SOL.md.

| Required outcome | Current implementation and evidence | Work remaining |
| --- | --- | --- |
| Independent corpus and sustained fuzzing | Windows-only read-only collector; local manifest verifier and synthetic acquisition/UTF-16/hard-link regressions; separate image, full diagnostic, mapping-pair, attribute-list, index-root/block, LZNT1, reparse, security, DACL/token and WOF/XPRESS fuzz targets; FILE/INDX fixup-preserving image mutations | Execute acquisition on a Windows machine; extend expected-operation observations; use Windows seeds and longer scheduled campaigns; reduce every found defect to a retained regression |
| Metadata consistency and corruption diagnosis | Private read-only validator for MFT/cluster bitmaps, extension/list references, exact namespace pairing/link graph and physical ownership; seven budgets, 57 image verdicts, 508 allocation/346 I/O faults, four independent bitmap geometries and bounded diagnostic fuzz; cached metadata validates before publication | Windows/DOS and listed/flagged bad-cluster qualification; view-store and unreferenced index-block consistency, full replicas and native journal checks; per-operation budgets outside the diagnostic; real fragmented and large-directory corpus |
| Names, hard links, streams | Reference-addressed inspector preserves UTF-16 code units; bounded ADS catalog/xattrs; reversible bounded FSKit filename aliases and raw per-link manifests; per-directory exact/folded lookup retaining B-tree collation, 17 policy images and 47 allocation/eight I/O faults; mixed parents and sensitive aliases pass components; complete encoded-stream size metadata, strict content rejection and independent ADS with 18 core verdicts, 29 allocation/four I/O faults and six native component variants | Windows/native case-policy and volume-capability/cache qualification; installed filename/ADS and encoded-object flows; native normalization and Windows-authored EFS/compression metadata |
| Links and special data | Immutable lossless core reparse snapshots, original-wire copies/physical sizes; bounded single-edge FSKit symlink/junction projection with explicit current-owner roots, numeric ancestry and filename aliases; 47 component verdicts and 79 allocation/17 read faults; ordinary EFS metadata and independent plaintext ADS; WOF XPRESS4K/8K/16K storage/table/content with 28 verdicts, 216 allocation/68 read faults, 14 legacy provider scenarios and bounded image fuzz; standalone codec has 87 content/11 invalid vectors | Windows/installed link semantics, intermediate chains, context-dependent reparse hard links and cross-volume ownership; LZX, provider-specific native fault/interleaving and hard-link qualification, Windows codec/format observations; provider-specific cloud/unknown policies and EFS decryption/key ownership |
| Security | Original descriptor/SID/ACL/ACE parser and bounded immutable resolver for `$Secure` and per-file attributes; distinct absent/NULL/empty ACLs, checked index paths/hash/copies and four external image geometries; bounded ordered DACL evaluator with exact generic mappings, ordinary ownership and deny-only/restricting contexts, 196,608 independent per-right oracles | Whole-store/Windows qualification; native AccessCheck comparisons, restricted ownership, advanced ACE/SACL/privilege/maximum-access policy and Windows-to-native identities; integrate owning authorization |
| FSKit lifecycle and interoperability | Separate admission/drain; eight gated-read/overlapping-teardown cases; conditional reclaim, weak canonical identity and five modeled eligibility/publication cases; virtual dot/parent IDs, separate cookie views/native errors, replay and 33 allocation/13 I/O enumeration faults; encoded-file pages and bounded native link/raw-metadata/remount/revocation checks | Synchronous I/O interruption/deadlines and task cancellation; native reclaim counts/macOS 27 runtime and installed scheduling/buffer lifetime; complete link/provider resolution, backend dot lookup/parent resolution and bounded enumeration checkpoints; see LIFECYCLE.md |
| Recovery and release processes | No write callback; native recovery contract in WRITES.md; private CI workflow and provenance | Read-only `$LogFile` decoder, transaction/crash/durability simulator, reproducible-build checks and diagnostics; actual private CI execution and later native Windows recovery acceptance |

Optimization is a separate acceptance stream:

| Required outcome | Current implementation and evidence | Work remaining |
| --- | --- | --- |
| Repeatable measurements | `ntfs-workload` records wall/CPU, request percentiles, allocation/I/O/cache counters and peak memory; POSIX/memory callbacks, explicit warmup, request sizes and serialized readers; benchmark runner requires independent original bytes and a release build | Broaden file-set, fragmentation and compression workloads; true native/device cache profiles and matched independent driver comparisons |
| Metadata reuse | One validated metadata snapshot per live immutable node; failed checks publish nothing; retry, zero repeated I/O/allocation and owner-lifetime tests | Attribute-list/stream metadata and bounded index reuse only where profiles justify their cost |
| Directory continuation | Existing persistent core B-tree cursor; native reversal uses a separate bounded cursor and preserves a pending enumeration entry | Bounded checkpoints and independently retained interleaved adapter cursors; measured large-directory/alias reuse |
| Native link and type metadata | Immutable target bytes reused per live FSItem; names-only classification validates node/reparse metadata without target resolution; alias translation has one shared scan budget | Measure cold/warm classification and alias-heavy paths, including repeated page lookahead; bounded checked-record/index/alias reuse only after profiling and unchanged fault/lifetime behavior |
| Data I/O | Existing whole-run coalescing, sparse/VDL zeroing and bounded compression buffer | Resource-aligned direct path, bounce-copy reduction, reused buffers and extent hints; measured gains with fault/memory checks |
| Compression | Existing one-unit LZNT1 and WOF XPRESS caches; independent codec vectors and integrated provider byte/fault cases | Profile misses and whole-table open cost; evaluate bounded cache sizes and hot-loop changes; measure WOF codec/unit/page caches on independent original workloads |
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
