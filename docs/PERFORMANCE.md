# Performance contracts

Current optimizations are structural: binary-search run lookup, adjacent-run
coalescing, geometrically grown bounded vectors, a 64-entry MFT LRU, whole-run
data reads capped at 1 MiB, a persistent in-order directory cursor, direct B-tree
lookup and one decoded LZNT1 unit per stream. Sparse and uninitialized ranges
produce zeros without backing I/O. Compressed physical prefixes are read in
contiguous ranges, including prefixes fragmented across multiple runs.

The FSKit resource owns one aligned 1 MiB bounce buffer and caps aggregate core
allocations at 64 MiB. A volume caps live FSItem identities at 16,384. Enumeration
with attributes uses temporary node snapshots, not a permanent item per returned
name. One cursor is retained per held directory item; sequential continuation is
linear. Interleaved scans can replay a prefix, and that cost remains a target for
native profiling. Admission is serialized per volume. Parallel core readers and
kernel-offloaded I/O are deliberately not claimed.

To collect a local baseline:

```sh
python3 scripts/build.py .build-release --release
.build-release/ntfs-benchmark artifacts/interoperability-core-ready/ntfs-s512-c4096.img large.bin
```

The tool reports elapsed time, bytes, device calls and metadata cache hits for
100 repeated full-file reads and 1,000 root-directory lookups. It caps its source
file at 64 MiB. This is a warm POSIX image microbenchmark: the host page cache,
allocator and syscall overhead are included. It does not measure FSKit, physical
media performance, Finder behavior or an advantage over another driver. Raw
measurements belong under ignored artifacts. Do not claim SOTA or a throughput
win without a matched independent baseline.

The core handoff release-build run is recorded in
`artifacts/benchmark-core-ready.json`, with build output in
`artifacts/core-ready-release.log`. This establishes that the measurement path
works after the metadata/lookup changes; native performance qualification and
comparative repetitions remain open.

That baseline predates the reparse presence guard. Proving that a cleared reparse
flag denotes an ordinary object can decode its attribute list. Metadata costs
for listed attributes need a separate profile before introducing a presence cache
or claiming unchanged throughput. Snapshot name copying itself uses validated
resident memory and performs no device I/O.

Before optimizing the installed product, establish these profiles with hashes,
device-call counts, peak memory, CPU and latency percentiles:

| Profile | Required comparison |
| --- | --- |
| Sequential and random reads | Same immutable media, file set, cache state and request size |
| Resident small files | Cold and warm MFT; repeated opens and closes |
| Large directories | Lookup near each tree boundary, full scans, concurrent pagination |
| Fragmented and sparse streams | Extent count independently varied from file length |
| LZNT1 | Compressible, incompressible, sparse and partial final units |
| FSKit concurrency | Throughput and tail latency as readers increase; teardown progress |
| Memory pressure | Budget exhaustion returns errors without leaks or corrupting cursors |

Use repetitions and disclose hardware, OS, toolchain, workload and cache policy.
Compare our native path with Windows and an independent NTFS implementation where
environments permit. Optimization follows correctness and cannot weaken sequence,
fixup, allocation, VDL or unsupported-feature checks.
