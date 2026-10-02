# Core qualification and continuation

This file tracks the agreed no-VM continuation scope. A working local parser,
component build or microbenchmark cannot establish Windows compatibility,
installed FSKit behavior or commercial readiness. Preserve those evidence
boundaries when updating ACCEPTANCE.md and HANDOFF-SOL.md.

| Required outcome | Current implementation and evidence | Work remaining |
| --- | --- | --- |
| Independent corpus and sustained fuzzing | Windows-only read-only collector; local manifest verifier and synthetic acquisition/UTF-16/hard-link regressions; separate image, mapping-pair, attribute-list, index-root/block, LZNT1, reparse, security and DACL/token fuzz targets; FILE/INDX fixup-preserving image mutations | Execute acquisition on a Windows machine; extend expected-operation observations; use Windows seeds and longer scheduled campaigns; reduce every found defect to a retained regression |
| Metadata consistency and corruption diagnosis | Existing fragmented-MFT/continuation/index/stream tests and allocation/read sweeps; cached metadata validates before publication and retries failures | Read-only validator for reference, allocation and namespace consistency; per-operation I/O/work budgets; real fragmented and large-directory corpus |
| Names, hard links, streams | Reference-addressed inspector preserves UTF-16 code units; bounded ADS catalog/xattrs; reversible bounded FSKit filename aliases and raw per-link manifests; per-directory exact/folded lookup retaining B-tree collation, 17 policy images and 47 allocation/eight I/O faults; mixed parents and sensitive aliases pass components | Windows/native case-policy and volume-capability/cache qualification; installed filename/ADS and unsupported-object flows; native normalization behavior |
| Links and special data | Reparse snapshots and symlink/junction names are lossless in core; filter-owned ordinary data/traversal remain rejected | FSKit symlink operations and explicit path/volume translation; WOF file-provider framing, chunk tables and XPRESS/LZX; provider-specific cloud/unknown/EFS policies |
| Security | Original descriptor/SID/ACL/ACE parser and bounded immutable resolver for `$Secure` and per-file attributes; distinct absent/NULL/empty ACLs, checked index paths/hash/copies and four external image geometries; bounded ordered DACL evaluator with exact generic mappings, ordinary ownership and deny-only/restricting contexts, 196,608 independent per-right oracles | Whole-store/Windows qualification; native AccessCheck comparisons, restricted ownership, advanced ACE/SACL/privilege/maximum-access policy and Windows-to-native identities; integrate owning authorization |
| FSKit lifecycle and interoperability | Existing retained owner, permanent revocation, counted objects and externally serialized component tests; cache change passes cached-operation revocation tests | Cancellation/late-callback/exactly-once tests, revoke/unmount during a blocked read, interleaved enumeration and exhaustion; links/ADS/unsupported-object flows; legacy and modern runtime acceptance |
| Recovery and release processes | No write callback; native recovery contract in WRITES.md; private CI workflow and provenance | Read-only `$LogFile` decoder, transaction/crash/durability simulator, reproducible-build checks and diagnostics; actual private CI execution and later native Windows recovery acceptance |

Optimization is a separate acceptance stream:

| Required outcome | Current implementation and evidence | Work remaining |
| --- | --- | --- |
| Repeatable measurements | `ntfs-workload` records wall/CPU, request percentiles, allocation/I/O/cache counters and peak memory; POSIX/memory callbacks, explicit warmup, request sizes and serialized readers; benchmark runner requires independent original bytes and a release build | Broaden file-set, fragmentation and compression workloads; true native/device cache profiles and matched independent driver comparisons |
| Metadata reuse | One validated metadata snapshot per live immutable node; failed checks publish nothing; retry, zero repeated I/O/allocation and owner-lifetime tests | Attribute-list/stream metadata and bounded index reuse only where profiles justify their cost |
| Directory continuation | Existing persistent core B-tree cursor; native reversal uses a separate bounded cursor and preserves a pending enumeration entry | Bounded checkpoints and independently retained interleaved adapter cursors; measured large-directory/alias reuse |
| Data I/O | Existing whole-run coalescing, sparse/VDL zeroing and bounded compression buffer | Resource-aligned direct path, bounce-copy reduction, reused buffers and extent hints; measured gains with fault/memory checks |
| Compression | Existing one-unit LZNT1 cache and independent vectors | Profile misses; evaluate bounded cache sizes and hot-loop changes, then WOF decoder profiles |
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
