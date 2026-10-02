# Performance contracts

Current optimizations are structural: binary-search run lookup, adjacent-run
coalescing, geometrically grown bounded vectors, a 64-entry MFT LRU, whole-run
data reads capped at 1 MiB, a persistent in-order directory cursor, direct B-tree
lookup and one decoded LZNT1 unit per stream. Sparse and uninitialized ranges
produce zeros without backing I/O. Compressed physical prefixes are read in
contiguous ranges, including prefixes fragmented across multiple runs.

WOF XPRESS/LZX streams retain one decoded unit, private input/workspace and one
4-KiB offset page. XPRESS16K uses 34,432 bytes and LZX32K uses 70,476 bytes for data/scratch;
backing extents and any underlying storage codec have their separate allocations.
Every fresh open validates the complete table within the default chunk-work cap.
That linear startup cost, duplicated provider metadata inspection, unit/page
misses and aggregate owner memory need cold/warm measurement before optimizing
reuse. Correct content/fault checks do not establish a throughput improvement.

The FSKit resource reads physically aligned offsets/lengths directly into an
equally aligned caller buffer, one bounded fragment at a time. Other fragments
use its single aligned 1 MiB bounce buffer. It still caps aggregate core
allocations at 64 MiB. A volume caps live FSItem identities at 16,384. Enumeration
with attributes uses temporary node snapshots, not a permanent item per returned
name. One cursor is retained per held directory item; sequential continuation is
linear. Interleaved scans can replay a prefix, and that cost remains a target for
native profiling. Admission is serialized per volume. Parallel core readers and
kernel-offloaded I/O are deliberately not claimed.

FSKit now suspends optional read-cache retention on observed elevated pressure,
without scanning dormant objects. Access/completion cleanup releases disposable
stream/catalog/raw-snapshot allocations and preserves directory continuation and
identity. The component measures 135,632/18,816/79,436 released core bytes in its
LZNT1/XPRESS4K/LZX32K scenarios, with record caching disabled. Warm normal reads
retain their no-additional-I/O behavior. READ-CACHE-POLICY.md defines excluded
memory and remaining aggregate/installed/performance measurements; these byte
counts do not establish a throughput or RSS improvement.

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
| WOF XPRESS/LZX | Independently encoded raw/packed units, partial final units, listed/fragmented backing and tables spanning multiple pages; separate table-open and warm-unit costs; LZX CALL conversion and external codec packets |
| FSKit concurrency | Throughput and tail latency as readers increase; teardown progress |
| Memory pressure | Budget exhaustion returns errors without leaks or corrupting cursors |

Use repetitions and disclose hardware, OS, toolchain, workload and cache policy.
Compare our native path with Windows and an independent NTFS implementation where
environments permit. Optimization follows correctness and cannot weaken sequence,
fixup, allocation, VDL or unsupported-feature checks.

## Repeated portable workload measurements

`ntfs-workload` extends the original single microbenchmark with sequential/random
reads, repeated stream open, lookup/stat, persistent directory continuation and
complete directory scans. It reports wall/process CPU, p50/p95/p99 request latency,
bytes, entries, allocations, exact core I/O/cache counters, peak core allocation
and process RSS. Request latency includes waiting for external serialization.
Each reader owns its own stream/cursor and buffer; it does not call one volume
concurrently. The join barrier precedes child and owner teardown.

The POSIX callback includes host syscall and page-cache costs. The memory callback
preloads the same immutable image before measurement to profile core/copying cost.
Both count logical core device calls. Setup runs before timing; explicit warmup
continues existing stream/cursor state. Setting record-cache entries to zero
disables that cache, not the host cache or compression-unit cache. Hashing source
media warms the host page cache, so these are never claimed as cold-device runs.
The output names the clock and its resolution; Darwin uses monotonic raw timing
to avoid rounding sub-microsecond operations to zero. Percentiles remain per-run;
the runner summarizes their medians/ranges without calling them pooled percentiles.

```sh
python3 scripts/build.py .build-release --release
python3 scripts/benchmark.py artifacts/interoperability-next/ntfs-s512-c4096.img /large.bin --expected-data artifacts/interoperability-next/large.bin --dataset-kind ntfs3g --build .build-release --output artifacts/measure-next --requests 4096 65536 --readers 1 4 --warmup-operations 0 2000 --operations 2000 --repetitions 5
```

The runner refuses an existing output directory, non-release/sanitized build,
changed input bytes or a content mismatch against the independently supplied
original stream payload. It preserves failed qualification reports. Five-run
matrices cover 64 configurations on a 64-MiB NTFS-3G image and 16 configurations
on the independently authored 8-MiB attribute-list fixture. Baseline evidence is
in `artifacts/plan-measure-oracle-2/` and `artifacts/plan-measure-metadata/`;
initial cache reports are in `artifacts/plan-cache-measure-oracle/` and
`artifacts/plan-cache-measure-metadata/`. After reparse-presence review, another
400 measurements passed under `artifacts/plan-guard-measure-oracle/` and
`artifacts/plan-guard-measure-metadata/`, with full byte oracles and unchanged
images. The images contain 2,097,408-byte and 8,192-byte tested streams
respectively; image size is not the independent content-oracle size. Earlier
failed preflights remain retained.

## Validated live-node metadata reuse

Standard information and the reparse-presence result are cached only after the
whole validation succeeds, using 112 additional bytes in each live node and no
separate allocation. Stream mappings/size/content still use their own validation.
The immutable-media contract makes the snapshot valid until node close. Repeated
checks do no I/O or allocation; allocation/read failures before publication remain
retryable. The core regression and FSKit permanent-revocation tests pass.

For 10,000 repeated opens of the attribute-list fixture, the current POSIX
five-run median is 1.40 million operations/s with the record cache disabled and
2.67 million with 64 entries, versus original medians of 1.22 and 2.13 million.
Allocations fell from about 90,000 to 60,000 per run. Initial cache publication
adds three allocations to the latter total. The earlier cache-only checkpoint
was faster; its timings cannot be attributed to the final reviewed guard.
Lookup/stat now measures 370,000 versus 348,000 operations/s with the cache
disabled; 485,000 versus 483,000 with 64 entries has overlapping run ranges and
does not establish a useful timing gain. Its allocations remain unchanged.

Each held node still adds 112 bytes. Closing the temporary attribute-list stream
before opening the requested data stream reduces overlapping lifetimes: measured
open peak is now 56 bytes below the original baseline, while parent/child lookup
peak remains 224 bytes higher. These peak measurements describe this fixture,
not all filesystem layouts.

Data-read changes were mixed across the independent five-run matrices, so no
consistent read-throughput improvement is established. Four-reader latency still
exposes contention in the serialized volume. These measurements justify this
specific metadata reuse; they do not establish FSKit performance, a broad driver
advantage or completion of the remaining optimization program.

## Native link and type metadata measurements

The link continuation caches immutable emitted target bytes per live FSItem.
Names-only enumeration now validates node/reparse metadata for accurate types,
without resolving targets. That adds metadata work compared with trusting cached
index flags. Alias translation uses independent cursors with one shared raw-entry
budget. Component fault counts establish required work and retry behavior; they
are not timing or native throughput measurements.

Add cold/warm metadata profiles for plain and reparse-heavy directories, one-entry
pages, interleaved continuation and alias-heavy nested targets. Record latency,
CPU, I/O, allocation counts and peak native memory separately from C core and
sanitizer/corpus overhead. Measure repeated page lookahead and repeated same-item
lookup before introducing bounded checked-record/index/alias reuse. Preserve
parent provenance, immutable target identity, scan limits, failure retry and
revocation/unmount ordering. No performance gain or independent-driver comparison
is established by the native-link component checkpoint.

## Standalone XPRESS measurement scope

The original XPRESS decoder now uses 1,664 bytes of caller scratch with an
eight-bit prefix table and canonical fallback. Exact-byte vectors and bounded
fuzz qualify correctness within WOF.md's single-block contract; they establish
no throughput gain. Add matched codec profiles for short/long codes, literals,
overlapping copies, extended lengths and WOF unit sizes. Record decode CPU,
latency and scratch separately from compressed-input reads and future unit-cache
hits/misses. Integrated provider/cache and native comparisons remain open.

## FSKit resource transfer measurements

`tools/fskit_read_workload.m` compiles the actual `NTFSResource` with an original
synchronous aligned memory reader. The runner builds an unsanitized `-O2` binary,
retains it with source/binary hashes and compiler/SDK information, and refuses an
existing output directory. It bounds subprocess output/deadlines and records
failures. A reference run executes the preserved baseline binary alongside the
candidate, alternating their order between repetitions. This is a resource
microbenchmark, not an installed FSKit mount or physical-device measurement.

```sh
python3 scripts/benchmark_fskit_resource.py --output artifacts/resource-before --repetitions 5
# After the product change, retaining the identical workload/compiler/SDK:
python3 scripts/benchmark_fskit_resource.py --output artifacts/resource-after --reference artifacts/resource-before --repetitions 5
```

Each process owns a deterministic 64-MiB source, one caller buffer and the
resource's fixed window. Source SHA-256 and full first/last-request bytes are
checked outside measurement; every measured request checks three byte samples.
Caller guards and source immutability must pass. Setup and 128 warmup requests
precede reset counters/timers. The phase measures 2,000 sequential ring reads,
wall/process CPU, p50/p95/p99 and process peak RSS. Reader callbacks check physical
offset/length/address alignment, bounds and the 1-MiB transfer limit. Callback
destinations distinguish caller-directed transfers from private-window transfers;
inferred bounce-copy bytes equal requested bytes minus caller-directed device
bytes. This does not instrument `memcpy`. The direct-reader control omits resource
admission, checks and synchronization as well as copying, so its entire timing
difference cannot be attributed to the copy alone.

The initial 85-run/17-configuration baseline is retained under
`artifacts/fskit-resource-baseline/`. The matched continuation under
`artifacts/fskit-resource-direct/` contains 170 runs and 34 summaries: both
versions, five repetitions, physical alignment 4 KiB, requests 4 KiB/64 KiB/1 MiB,
aligned/offset/pointer/length profiles and a 1-MiB-plus-one-sector profile. All
byte/guard/source checks pass; device call counts and bytes are identical per
matched configuration. Aligned resource transfers now go into the caller, with
zero inferred bounce-copy bytes. Unaligned profiles still use the fixed window.

| Resource profile | Baseline/candidate wall median, ms | Wall reduction | Baseline/candidate p99 median, us |
| --- | --- | --- | --- |
| Aligned 4 KiB | 0.544 / 0.505 | 7.3% | 0.334 / 0.333 |
| Aligned 64 KiB | 4.567 / 2.414 | 47.1% | 2.750 / 1.584 |
| Aligned 1 MiB | 56.077 / 28.499 | 49.2% | 35.916 / 20.250 |
| Aligned 1 MiB plus 4 KiB | 63.005 / 29.261 | 53.6% | 38.375 / 19.417 |

Process CPU medians fall about 7%, 47%, 49% and 54% in the same profiles.
The small 4-KiB phase lasts about half a millisecond and its timing is particularly
sensitive to noise. An initial offset-4-KiB wall difference of +3.9% prompted a
longer matched run: 100,000 requests, 1,024 warmups and ten repetitions, retained
under `artifacts/fskit-resource-offset-repeat/`. Its 20 runs pass with wall
medians 34.934/34.857 ms, candidate/reference ratio 1.0022; CPU ratio 0.9947.
Per-run p50/p95/p99 medians match at 333/375/458 ns. Paired timings move in both
directions, so that run does not establish a sustained fallback regression.

Direct eligibility requires an aligned disk offset, aligned caller address and
an exact aligned fragment length. Partial sectors and unaligned caller addresses
never receive rounded device spans. Failed direct reads may change requested
caller bytes; errors and late revocation still reject the operation, and native
replies report zero completed bytes. Callers discard failed data. Earlier exact
fragments can also be visible on a later failure in the window path. This is a
synchronous exact-read contract, not atomic output publication.

The optimization adds no core allocations and retains the 1-MiB resource window,
64-MiB core limit and existing serialization. It proves a targeted memory-reader
benefit; actual caller alignment frequency, native transport cost, installed
buffer lifetime, physical-device throughput, other alignments' performance and
independent-driver comparisons remain to be measured.
