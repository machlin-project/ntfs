# Performance contracts

## Huffman decoding

The next CPU batch accelerates the existing XPRESS-Huffman and WOF LZX decoders.
It retains the eight-bit prefix tables, canonical alphabets and caller-owned
1,664/4,940-byte workspaces. No larger lookup tree, allocation, public interface
or architecture-specific instruction is introduced by this batch.

XPRESS's complete 512-symbol uniform alphabet has nine-bit codes, so it missed
every entry in the old eight-bit fast table. The fallback now selects a canonical
bucket directly from the already buffered bits, starting after the prefix width,
and consumes the symbol once. Mandatory refill still occurs before any raw
match-length extension. LZX performs a zero-padded short-code lookup on the bits
already buffered, checks the actual code length, and previews at most one bounded
following word for crossing/long codes. Only consumption commits that word to the
reader. Both builders overwrite reachable tables without clearing them first;
LZX clears only its retained main/length histories at unit start.

The LZX short path is inlined separately from its refill/canonical fallback.
The buffered word has its actual 16-bit type. Disassembly of the earlier 32-bit
field showed a paired load spanning the separately updated bit count; the targeted
word-width probe removed the remaining short-code regression. Failed candidates
and their exact measurements remain retained. The final algorithm uses general
registers; compiler SIMD policy and the separately owned memory helpers follow
the context rules in the preceding [CPU batch](#cpu-primitives-and-compression).

### Matched Huffman measurements

The frozen reference is the accepted memory/match optimization checkpoint. The
same harness, independent packets, selected Xcode Clang `-O2`, unaligned buffers
and nine alternating before/after pairs are used for every profile. The expanded
set has 68 comparisons: 19 XPRESS/LZX workloads plus 15 unchanged memory/LZNT1
controls, each in ordinary userspace and GPR-only host execution. Ratios above
one mean faster complete decodes, including tree construction and CALL translation.

| Workload | Userspace median ratio | GPR-only median ratio |
| --- | ---: | ---: |
| XPRESS, 9-bit literal 4-KiB block | 2.05× | 1.93× |
| XPRESS, 15-bit literal 4-KiB block | 2.16× | 2.17× |
| XPRESS, mixed-width 4-KiB block | 1.45× | 1.42× |
| XPRESS, short codes / small tree | 1.03× / 1.10× | 1.03× / 1.09× |
| LZX, balanced literal 32-KiB unit | 4.25× | 4.15× |
| LZX, 16-bit literal 32-KiB unit | 4.20× | 4.22× |
| LZX, mixed-width 32-KiB unit | 3.53× | 3.58× |
| LZX, one-bit codes / small tree | 1.19× / 1.30× | 1.19× / 1.25× |
| LZX, repeated-match unit | 1.41× | 1.38× |

The ordinary LZX literal profile decreases from 412.7 to 97.2 microseconds per
32-KiB decode; XPRESS decreases from 31.3 to 15.2 microseconds per 4-KiB decode.
Already match-dominated XPRESS profiles improve only 1.01–1.07× in userspace;
this change targets symbol parsing rather than their previously accelerated copies.
Unchanged controls range 0.98–1.09× in userspace and 0.96–1.02× in the GPR run.
None of the final 68 median ratios is below 0.95×. Earlier controls show scheduling
variation and are retained; these samples are not a confidence interval or a
guarantee for other input distributions.

The independent author covers every legal main-code width at all 16 word offsets,
short final codes without lookahead, all secondary trees, raw transitions,
retained lengths and interleaved XPRESS extension bytes. All 662 packets and
229,388 truncation/mutation/boundary checks match the frozen reference's status,
written count and entire partial output in each of three fatal-ASan/UBSan
contexts: userspace, portable memory and GPR-only. Independent expected bytes
also validate successful output; differential agreement alone is not the oracle.
The 54 CPU packets additionally cover all 32 alignments with exact allocation ends.

Evidence is in `artifacts/huffman-optimization-20261008/comparison-accepted/`,
`artifacts/huffman-differential-accepted-20261008/` and the preceding diagnostic
comparisons in the same benchmark directory. [Development instructions](DEVELOPMENT.md#cpu-optimization-checks)
describe reproduction; `--case NAME` can isolate a workload for diagnosis without
rerunning unchanged profiles. These CPU measurements establish neither mounted
FSKit throughput nor actual kernel execution. Full regression and compiler-context
acceptance are recorded separately in [ACCEPTANCE.md](ACCEPTANCE.md).

## CPU primitives and compression

This preceding implementation batch follows the separation already used by
Machlin ext4: portable algorithms, acceleration selected for the execution
context, independent byte oracles and measurements against a frozen Git baseline.
It does not add a kernel filesystem adapter or a new encoded-content write family.

The initial audit found these actual opportunities:

| Area | Current NTFS work | Decision |
| --- | --- | --- |
| CRC/SHA | No CRC or SHA implementation/call path in this core. USA fixups compare sector markers; `$Secure` uses a rotate/add DWORD hash. | ext4's CRC32C/SHA acceleration cannot replace these different format operations. No unused checksum backend is added. |
| Encryption | EFS content is explicitly unsupported; there is no production cipher/key provider to accelerate. | Retain classification/refusal. Future EFS requires its own format, key-lifetime and native-provider contract before AES optimization. |
| LZNT1, XPRESS-Huffman, WOF LZX | Each expands backward matches byte by byte. | Share checked match expansion, widening short repeating prefixes before wide copies. |
| LZX CALL translation | Scans every decoded byte for opcode `0xE8`. | Search complete bounded blocks, retaining exact first-opcode order, operand skipping and the excluded final ten bytes. |
| Copy, zero, equality | Used throughout record/recovery validation and stream buffering. | Preserve compiler-vectorized userspace copies; use wide GPR operations for kernel copies, NEON equality/search, and checked large-range DC ZVA. |
| `$Secure` hash and Huffman parsing | Serial format-dependent operations remain at this checkpoint. | No separate speedup is included in this batch's figures. The subsequent Huffman batch is measured above. |

[memory.c](../core/memory.c) owns the primitives. Wide accesses consume only
complete spans and impose no caller alignment requirement. Copy retains forward
byte-loop overlap semantics. A backward match requires an already validated
nonzero distance and output span; small periods first grow through disjoint
prefix copies. No wide load reads not-yet-produced bytes. The three decoders keep
their framing, match bounds, error results, caller workspaces and publication rules.
Equality is ordinary metadata comparison, not constant-time authentication.

ARM64 userspace uses NEON for equality, byte search and sufficiently long matches.
Ordinary copy and small zero loops retain Clang's own vectorization, which measured
better than the initial explicit 16-byte loops. `KERNEL`, `_KERNEL`, `__KERNEL__`
and `NTFS_NO_SIMD` exclude explicit NEON. A kernel toolchain must also disable
automatic SIMD/FP generation; the checked Clang profile uses `-mkernel` and
`-mgeneral-regs-only`. Other targets use bounded word/byte operations.
`NTFS_MEMORY_PORTABLE` selects byte primitives and excludes both explicit NEON
and DC ZVA; compiler vectorization remains a toolchain decision.

ARM64 zeroing queries `DCZID_EL0` on each admitted large range and checks the
prohibition bit and reported block size. Only naturally aligned, completely
contained normal-RAM blocks use `DC ZVA`; edges use stores. The measured thresholds
are 16 KiB for userspace and 256 bytes for the GPR profile. The core never receives
device-register mappings. No mutable feature cache, new allocation, platform
callback or SIMD-context ownership is introduced.

The GPR kernel compilation also exposed a pre-existing 2,096-byte checkpoint
capture frame. Keeping packet acquisition in its own non-inlined helper preserves
its bounded scratch frame without altering checkpoint data, admission, I/O order,
accounting, errors or publication. Both kernel architectures now meet the 2-KiB
per-function ceiling; this is not a bound on a complete nested call chain.

### Matched CPU measurements

On the current Apple Silicon host with selected Xcode Clang `-O2`, each of the
52 comparisons has nine alternating before/after pairs. Both versions use the
same frozen harness and independent packet/expected-byte files. Untimed pilots
choose identical operation counts targeting approximately 20 ms for the faster
sample. Output validation is outside the timed loop; every run also checks exact
bytes and a retained checksum. Inputs and outputs deliberately have a three-byte
misalignment. Reports retain actual compiler identity, commands and raw samples.

| Complete operation/profile | Userspace median ratio | GPR-only median ratio |
| --- | ---: | ---: |
| LZNT1, four repeated-pattern 4-KiB chunks | 2.03–6.24× | 1.30–31.81× |
| XPRESS, five repeated-pattern 4-KiB chunks | 1.21–2.48× | 1.09–3.59× |
| LZX, uniform unit and three raw/CALL profiles | 3.35–7.97× | 2.73–6.21× |
| Equal 4/64-KiB metadata buffers | 16.96–20.56× | 10.58–11.71× |
| Zero 64-KiB buffer | 2.19× | 9.56× |
| Copy 4/64-KiB buffers | 1.01–1.11× | 3.65–4.02× |

Ratios above one mean faster. The literal-heavy LZNT1/XPRESS/LZX controls range
0.97–1.03× in userspace and 0.98–1.03× in the GPR profile. The 64-byte userspace
zero control regresses from 4.71 to 5.09 ns per benchmark operation (0.925×);
the extra large-range decision is retained for the measured large-buffer benefit.
These timings include loop/dispatch overhead. The original manual-copy/small-zero
regressions remain recorded and motivated the final implementation.

Individual ratios, especially very compressible LZNT1, vary substantially with
host scheduling; the table describes these medians, not guaranteed rates or a
confidence interval. These are CPU microbenchmarks of complete decodes and memory
operations, not filesystem throughput, mounted FSKit performance, physical-device
I/O or actual kernel execution. GPR-only measurements execute as host processes.
No compression encoder, EFS decryption, CRC support or new kernel adapter is implied.

Evidence: `artifacts/cpu-optimization-sdk-20261008/comparison-tuned/result.json`;
the first candidate remains in `comparison/`. The 46 independent packets at all
32 alignments, exact allocation ends, byte-loop overlap oracles and protected
page ends cover the default, portable and GPR implementations. The complete
compiler/disassembly matrix is in `artifacts/cpu-boundaries-complete-20261008/`:
308 objects across 77 core files, userspace arm64/x86_64 and kernel arm64e/x86_64.
All 154 kernel objects are checked for SIMD/FP registers, and every context's
memory object has no unresolved runtime dependency. Full integration results
are recorded separately in [ACCEPTANCE.md](ACCEPTANCE.md).

## Core acquisition and allocation

The portable core now reuses completed work within explicit immutable lifetimes.
This batch covers the journal, cluster allocation, WOF stream reopening and
little-endian fields. FSKit builds/tests, VM operations and installed acceptance
are outside this batch. The implementation does not change disk layouts, packet
selection, physical allocation order or supported operation families.

### Journal traversal

Index preparation remains a separate operation. Each history, checkpoint capture
or transaction-chain call starts with an empty reuse descriptor. After routing the
requested LSN to an exact physical page and circular target, a successful protected
reload can serve further records while the source scratch generation is unchanged.
Every attempted page load advances that generation; saturation disables reuse.
Legacy completed tails and circular spanning starts are selected before the reuse
check, so a common target cannot hide a change in physical selection. No extra page
buffer is allocated. New public calls still reload and compare protected headers
against prepared metadata. The generation check also defensively rejects scratch
changed by nested page I/O; it does not grant general callback reentrancy.

A private packet buffer grows only when a later packet exceeds its capacity. Old
storage is released before growth, keeping at most one packet allocation and the
existing 1-MiB ceiling. The buffer remains charged during callbacks and is released
on every call outcome. Only complete validated packet bytes reach caller storage.
Single-record APIs retain their separate allocation and fresh-page behavior.

`pages_read` and `copy_pages_read` describe assembled segments; `read_calls` and
`read_bytes` count actual callback attempts, including failures. A reused page
therefore contributes a segment but no physical read. Budgets apply before actual
transfers and never reset per packet. Checkpoint composition retains aggregate
credits across capture and individual transaction chains; record/link caps remain
unchanged. The dense independent 600-record/eight-page fixture now requires eight
reads and one packet allocation, replacing 600 of each. Tests cover exact packets,
copies, legacy tail/circular transitions, wrap, spanning packets, short credits,
failed reads, every staging growth and caller-buffer isolation.

### Cluster allocation

First-fit scans inspect the union of original and privately edited bitmap words,
skip occupied 64-bit words and append consecutive free spans. The final partial
word is read and written only within bitmap storage, and padding beyond the volume
is never allocated. Allocation order and run coalescing match the independent
bit-by-bit model, including partial changes on no-space/run-cap refusal. Original
allocations remain unavailable after private retirement, preventing precommit
payloads from overwriting the old state. Admission still charges the original
whole-volume work bound before allocation. Bitmap snapshots, run capacity and
physical mutation/journal composition are unchanged.

The independent model covers every 0–257-bit geometry at sixteen alignments,
empty/full/alternating/mixed original and private maps, partial words, no-space
and the 4,096-run limit. Whole-image regression additionally checks that accepted
mutations retain their exact original physical placements and bytes.

### WOF and wire fields

A live node retains a completed WOF table proof keyed by logical size, stored
size and algorithm. Every open still validates provider metadata, placeholder
policy, complete backing mappings, VDL and chunk limits, and allocates its own
bounded table window. A matching node proof skips only the full table walk;
actual reads fetch and validate their local chunk boundaries. Publication follows
successful stream allocation. Failed opens publish no proof, new nodes validate
again, and closing a node cannot invalidate an already opened stream. The private
node fields add 24 bytes on both supported 64-bit architectures, without a new
allocation or public ABI. XPRESS/LZX table-page fixtures verify cold/warm counts,
all warm-open allocation/read failures, cold retry after final-allocation refusal,
new-node isolation and independent data after node close.

Private inline little-endian helpers expose exact unaligned 2/4/8-byte operations
to each caller without LTO. Supported little-endian compilers use constant-size
builtin copies; the portable fallback assembles bytes explicitly. Independent
byte oracles check all bits, widths, thirty-two alignments and exact allocation
ends. Kernel compilation retains general-register restrictions and the 2-KiB
frame ceiling.

### Measurement scope

`scripts/benchmark_core.py` freezes the Git reference, identical C harness and
independent journal/WOF fixtures before paired comparison. It measures ordinary
userspace and GPR-only host executables with identical compiler/SDK/options,
nine alternating pairs and exact semantic checksums. Counters measure actual
allocation/read callbacks. Bitmap cases use a nearly full 1,048,576-cluster map
and request 256 contiguous or alternating free clusters; this emphasizes search
cost and does not represent complete write throughput. WOF compares repeated
stream opens on one node with a fresh-node control. Journal preparation is outside
traversal counters; its one-time setup remains in elapsed time.

CPU controls retain the separate frozen codec/memory harness. Initial regressions
and tuning candidates remain in artifacts; measurements do not establish mounted
throughput, kernel execution or Windows recovery acceptance. Full bitmap snapshot
I/O and write-plan composition, volume-wide WOF proof retention and FSKit view
replacement/parallelism remain potential later work requiring their own lifetime,
resource and durability design.

The final paired core measurements are:

| Workload | Userspace | GPR-only host | Deterministic work change |
| --- | ---: | ---: | --- |
| Nearly full bitmap, contiguous request | 33.55× | 33.97× | Same 256 clusters and one run |
| Nearly full bitmap, fragmented request | 32.85× | 32.96× | Same 256 clusters and 256 runs |
| Dense journal traversal | 3.46× | 5.36× | Per walk: 600→8 reads, 600→1 allocations |
| Same-node WOF stream reopening | 28.91× | 22.33× | 1,000 opens: 2,000→2 table reads |
| WOF fresh-node control | 1.04× | 1.06× | Full validation and callback counts retained |

These are medians of nine alternating pairs, not whole-driver speedups. The
full CPU control run retains 68 profiles. Its two noisy short samples are checked
again with 21 alternating pairs calibrated to 200 ms: 4-KiB zeroing is at parity
(1.003× userspace / 0.999× GPR), and one-bit LZX is 1.070× / 1.069×. Both executables
have identical disassembly to that full control run. All original samples remain
available; longer controls resolve measurement variation without changing code.

Earlier candidates showed layout-sensitive slowdowns in the tight GPR copy loop
and LZX long-code bucket loop. Disassembly confirmed shifted loop placement after
surrounding code growth; it does not establish the hardware cause. Explicit
function alignment stabilizes their placement and removed the measured slowdowns;
LZX retains equivalent bounded word normalization. The unsuccessful inline/shift
candidates and their measurements are retained. Exact-width endian loads remove
split-byte code generation without enabling LTO or kernel SIMD.

Evidence: `artifacts/core-optimization-20261008/core-prepared/accepted/`,
`cpu/accepted/`, `cpu/long-controls/` and `disassembly/` under the same batch root.
Correctness and native scope are recorded separately in [ACCEPTANCE.md](ACCEPTANCE.md).

## Checked base metadata across temporary nodes

The current bounded memo retains checked standard information and reparse presence
by full reference in the existing record-cache allocation. Direct-mapped lookup
and independent raw/count/metadata keys avoid an associative scan. Stream sizes,
maps and content remain outside this payload. Default 64-entry retention adds
6,656 accounted bytes beyond the preceding count memo, without another allocation.
Capacity one adds 104 bytes; zero disables volume retention and adds no storage.

Seven reports under artifacts/directory-metadata-paired-* contain 254 paired runs;
six artifacts/directory-metadata-before-* reports retain 28 reference-only runs.
Main verifies all actual binaries, archives, 26 unchanged native/workload/public
headers, input bytes and every run log in artifacts/metadata-memo-benchmark-review.json.
The reference core already contains the checked filename-count memo. Its archive
comes from the preceding passing portable reproducibility build; the benchmark
git_head field identifies the current compiler caller, not that archive's source.
The review binds each actual core archive to its own qualification report.

Both cores use the same Release/O3 policy, O2 native/workload compiler, SDK and
arguments. Paired order alternates. Each repetition has a fresh process/owner with
an immutable memory reader and external serialization; source/host caches are warm.
Zero warmup measures fresh core state, not cold media. Large has 2,000 names of one
inode, pages 8/16 and one measured scan; warm uses one warmup and seven pairs per
profile, fresh uses zero warmup and seven sequential pairs. Small has twelve names
of one inode, pages 1/2, 100 rounds and nine pairs/profile. Independent-object controls
have 32 fitting files/100 rounds or 256 competing files/30 rounds, pages 8/16,
one warmup and nine pairs/profile. Disabled/single-entry pressure uses sequential
only. These selected synthetic layouts do not qualify whole-volume consistency.

| Inventory/state | Profile | Reference/current wall median, ms | Reference/current CPU median, ms |
| --- | --- | ---: | ---: |
| Large/fresh | Sequential | 71.224 / 41.964 | 70.875 / 41.804 |
| Large/warm | Sequential | 69.717 / 40.631 | 69.362 / 40.453 |
| Large/warm | Interleaved | 135.218 / 77.771 | 134.162 / 77.283 |
| Large/warm | Views | 100.826 / 43.338 | 100.354 / 43.051 |
| Small/warm | Sequential | 6.721 / 5.720 | 6.681 / 5.692 |
| Small/warm | Interleaved | 11.812 / 9.953 | 11.779 / 9.857 |
| Small/warm | Views | 10.616 / 8.628 | 10.515 / 8.575 |
| 32 independent/fitting | Sequential | 5.146 / 4.659 | 5.065 / 4.610 |
| 32 independent/fitting | Interleaved | 9.754 / 8.790 | 9.724 / 8.742 |
| 32 independent/fitting | Views | 8.656 / 7.752 | 8.635 / 7.696 |
| 256 independent/pressure | Sequential | 15.968 / 16.198 | 15.880 / 16.036 |
| 256 independent/pressure | Interleaved | 30.638 / 30.201 | 30.391 / 30.046 |
| 256 independent/pressure | Views | 26.361 / 26.283 | 26.266 / 26.107 |
| 256 independent/cache zero | Sequential | 15.365 / 15.254 | 15.248 / 15.119 |
| 256 independent/cache one | Sequential | 15.026 / 14.807 | 14.931 / 14.797 |

Large fresh wall ranges are 69.933–72.158 / 41.043–43.439 ms. Reads fall from 7,524
to 5,276, requested bytes from 296,479,744 to 151,456,768 and allocations from
23,342 to 16,598. Baseline/peak accounted storage rises by exactly 6,656 bytes,
from 140,456/345,568 to 147,112/352,224 bytes. Warm profiles retain lower I/O and
allocation counts; all per-run percentiles, ranges and counters remain in reports.
Small sequential allocations fall from 22,000 to 15,100 with unchanged I/O;
interleaved/views fall from 38,600/29,900 to 26,600/17,600.

The fitting 32-object controls improve median wall time about 9.5–10.4%, with
overlapping ranges and unchanged I/O/allocation counts. The pressure sequential
median is 1.44% slower (about 0.23 ms): ranges 15.599–16.485 / 15.736–17.244 ms
overlap. Other pressure profiles have small reductions, and counters remain
identical; there is no blanket pressure speedup. Default retention always adds
6,656 accounted bytes in this matrix, including peak storage. Single retention
adds 104 bytes and disabled retention adds zero. No RSS benefit, installed FSKit,
macOS-27 runtime, physical-media throughput or general unique-file gain is established.

## Preceding bounded filename-count reuse

Temporary FSKit enumeration nodes previously repeated a complete FILE_NAME
inventory for every name of the same inode. A bounded volume-owned memo now
retains fully checked physical/primary/DOS counts by full reference. Its payloads
reuse the existing record-cache allocation independently of raw-record replacement;
the default 64 entries add 1 KiB. Cold checks, operation admission and zero failure
outputs remain mandatory. ARCHITECTURE.md describes replacement and ownership.

The matched reports are artifacts/directory-count-cache-paired-{cold,warm,small}/
report.json; the initial three-pair probe is directory-count-cache-paired-large/.
All 104 original runs pass independent original name/reference/type/size oracles.
Main verifies retained binaries, both core archives and all 26 unchanged native,
workload and public-header sources in artifacts/count-cache-benchmark-review.json.
Both versions use 64 raw-record cache entries, the same Release/O3 core policy,
O2 native/workload compiler, SDK, input bytes and arguments. Paired repetitions
alternate execution order. Each process owns a new immutable memory-reader volume.

Both inventories contain many names of one inode: 2,000 for large and twelve for
small. This specifically measures repeated hard-link/alias inventory work, not
2,000 independently owned files. Large uses pages 8/16 and one measured scan;
cold has zero full-scan warmups and seven repetitions, warm has one warmup and
five repetitions per profile. Small uses pages 1/2, 100 measured rounds, one
warmup and nine repetitions per profile. Source and host caches are already warm;
zero warmup is fresh core state, not cold physical media. Interleaved advances two
attribute-requested scans; views alternates names-only and attribute-requested scans.

| Inventory/state | Profile | Reference/current wall median, ms | Reference/current CPU median, ms |
| --- | --- | ---: | ---: |
| Large/fresh | Sequential | 2,770.089 / 71.028 | 2,753.213 / 70.683 |
| Large/warm | Sequential | 2,802.321 / 70.394 | 2,782.926 / 69.943 |
| Large/warm | Interleaved | 5,390.137 / 135.332 | 5,358.512 / 134.611 |
| Large/warm | Views | 2,702.689 / 101.469 | 2,686.365 / 100.891 |
| Small/warm | Sequential | 11.666 / 7.040 | 11.562 / 6.981 |
| Small/warm | Interleaved | 20.347 / 11.939 | 20.186 / 11.832 |
| Small/warm | Views | 14.368 / 10.395 | 14.282 / 10.346 |

Fresh large wall ranges are 2,745.435–2,779.825 ms before and 69.556–72.483 ms
after. Its p50/p95/p99 request medians fall from 11.006/11.528/11.710 ms to
0.275/0.329/0.385 ms. Reads fall from 4,508,019 to 7,524, requested bytes from
5,047,707,648 to 296,479,744 and allocations from 4,528,334 to 23,342. Baseline
accounted owner storage increases by 1,024 bytes; peak storage falls from 360,416
to 345,568 bytes as temporary inventory scratch disappears. Warm large profiles
reduce accounted peaks by 31,656 bytes. RSS stays around 24.6 MB; no RSS benefit
is established. Full per-run latency ranges and counters remain in the reports.

Small sequential ranges are 11.426–13.383 ms before and 6.655–7.866 ms after.
Interleaved ranges are 19.808–20.994 / 11.550–12.203 ms; views ranges are
14.214–14.836 / 10.263–10.818 ms. Reads/bytes remain identical; allocations fall
from 40,400/70,600/43,500 to 22,000/38,600/29,900 for sequential/interleaved/views.
Small peak accounted storage increases by 408 bytes, with no native RSS advantage
claimed. These results qualify this targeted reuse, not installed FSKit, macOS 27
runtime, Windows compatibility, unique-file throughput or the wider optimization
program. The subsequent metadata section above adds scoped independent-object,
capacity and pressure controls; it retains the pressure tradeoff explicitly.

The rebuild after the private-header comment clarification has a different archive
digest. A later two-directory comparison identifies archive timestamps as the
source of differing bytes, not an executable-source change. The sealed Release
therefore retains forty additional paired controls under
artifacts/directory-count-cache-sealed-{large,small}/. All pass unchanged source,
input, policy and inventory guards. Sealed large/fresh wall median is 70.878 ms
(69.826–72.928) versus 2,768 ms before; small sequential/interleaved/views medians
are 6.608/11.924/10.260 ms versus 11.468/20.276/14.121 ms. Reads, bytes, allocations
and accounted memory retain the exact reductions above. Those controls qualify
the rebuilt product separately; the earlier table retains its measured archive.

The timestamp-only failure and actual member-payload comparison are retained in
artifacts/reproducibility-count-cache/ and artifacts/archive-timestamp-diagnosis.json.
After fixing the shared archive environment, all eight full Release product pairs
match under artifacts/reproducibility-count-cache-fixed/. No measured binary is
rewritten or replaced; the earlier timing reports retain their original archives.

The runner defaults to an identical-core reference guard. Explicit --compare-core
requires --reference and permits different retained core archives only while all
adapter/workload/public-header hashes match. Input, toolchain, policy, machine,
prior passing report and actual retained-binary checks remain in force. Both
binaries are rerun with the current matrix; prior matrix length may differ.

## Preceding primary-count cost observation

The native primary-count adoption has a current-only cost observation under
artifacts/directory-primary-counts-cold/report.json. Both independently checked
2,000-entry hard-link/alias scans pass with pages 8/16, one measured sequential
round, zero warmup rounds and two fresh-process repetitions. The core is Release/O3,
the adapter/workload O2, with no sanitizer or MFT record cache. Input/host caches
are already warm; this is not cold-device or installed-mount performance.

Median wall/CPU is 2,594.169/2,577.514 ms per scan; p50/p95/p99 request medians are
10.322/10.730/10.875 ms. Each run has 251 requests, 4,508,019 reads,
5,047,707,648 requested bytes and 4,528,274 allocations. Peak accounted core
storage is 293,344 bytes and measured RSS is about 24.60 MB. This is an observed
cost, not a paired speedup. At that checkpoint each temporary entry node repeated
the complete 2,000-name inventory. The bounded reuse above is a separate measured
change; disabled record caching still retains this complete cold path.

The core operation-accounting guards now have a paired retained-Release comparison
across ordinary/fragmented/resident/sparse/LZNT1/WOF reading and metadata. It
measures complete reader versions with the same workload, compiler, SDK, inputs
and arguments. A separate matched comparison qualifies the accounting
simplification for small cached resident reads; repeated opens remain mixed.
Earlier optimization percentages below cannot be assigned to the guarded product.
Compound native pages have a current-source baseline below; installed I/O and
broader workloads remain separate.
Ordinary directory comparisons require an identical core archive; complete core
comparisons now have the explicit stricter native-source mode described above.
Earlier binaries with different native/workload/public-header sources remain
ineligible for that mode. OPERATION-BUDGETS.md distinguishes work units,
cumulative allocation attempts, live core/pool bytes and excluded native/RSS
memory. Broader and installed optimization acceptance remains separate.

The preceding indexed-store source has ordinary Release/O3 byte comparisons
and legacy directory baselines. Both isolated builds match all eight portable
products under `artifacts/reproducibility-secure-store/`. The native workloads
use that verified archive with O2 adapter/workload sources, no sanitizer and no
MFT record cache. Each profile has nine repetitions, ten measured rounds and
five separate warmup rounds. Large uses the 2,000-entry `namespace-large` image
with pages 8/16; small uses the 12-entry `namespace` image with pages 1/2.

| Inventory | Profile | Median batch wall / CPU (ms) | Peak accounted core bytes |
| --- | --- | ---: | ---: |
| Large | Sequential | 67.476 / 67.477 | 196,232 |
| Large | Interleaved | 130.349 / 130.337 | 248,096 |
| Large | Views | 120.012 / 120.005 | 248,096 |
| Small | Sequential | 0.899 / 0.902 | 151,561 |
| Small | Interleaved | 1.276 / 1.278 | 166,946 |
| Small | Views | 0.951 / 0.957 | 166,946 |

These 54 runs/six summaries are current-only observations with complete original
inventory checks. Reports retain ranges, request percentiles, resource calls/
bytes, allocations and measured process RSS under
`artifacts/fskit-directory-secure-store-{large,small}/`. Main review compares the
actual binaries/archive/source/input bytes and every run's oracle verdict in
`artifacts/secure-store-review.json`. No paired improvement or installed/macOS-27
runtime performance is inferred. The complete security diagnostic is explicit
and is not part of ordinary native enumeration. Earlier percentages retain
their original source/workload scope.

Current optimizations include checked current/successor extent reuse with a
binary-search fallback, adjacent-run
coalescing, geometrically grown bounded vectors, a 64-entry MFT LRU, whole-run
data reads capped at 1 MiB, a persistent in-order directory cursor, direct B-tree
lookup and at most two decoded LZNT1 units per stream. Sparse and uninitialized ranges
produce zeros without backing I/O. Compressed physical prefixes are read in
contiguous ranges, including prefixes fragmented across multiple runs.

WOF XPRESS/LZX streams retain at most two decoded units, private input/workspace and one
4-KiB offset page. XPRESS16K uses 34,432 bytes and LZX32K uses 70,476 bytes for data/scratch;
these required allocations exclude the optional extra 16-KiB/32-KiB output.
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
name. An enumerated directory lazily retains at most two independent core cursors
through a table charged to the same resource pool. Same-view exact or nearest
earlier positions reuse traversal; initial cookies, evicted positions and older
rewinds can still replay a prefix. Sequential continuation remains linear.
Admission is serialized per volume. Parallel core readers and
kernel-offloaded I/O are deliberately not claimed.

FSKit now suspends optional read-cache retention on observed elevated pressure,
without scanning dormant objects. Access/completion cleanup releases disposable
stream/catalog/raw-snapshot allocations and older inactive directory positions,
while preserving the latest/pinned continuations and identity. The component
measures 135,632/18,816/79,436 released core bytes in its
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

`ntfs-workload` extends the original single microbenchmark with sequential,
random and strided reads, repeated stream open, lookup/stat, persistent directory continuation and
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
original stream payload. It now retains immutable measurement binaries and checks
each read run's delivered bytes and deterministic prefix samples against the
original file, outside the measured process. Full content hashes still run before
and after; sampling alone does not establish full content integrity.
It preserves failed qualification reports. Five-run
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

## Compression working-set measurements

The opt-in `strided` profile cyclically visits `positions` windows whose starts
are separated by `stride_bytes`. Each reader owns its stream and continues its
position across warmup. A one-position workload measures repeated access to one
unit; two positions alternate units; more positions exercise a wider working set.
Set the stride to the input codec's unit size and keep requests within each unit
to separate those cases. Every
window start must fit the stream before multiplication, including wide strides;
the last request may return a partial EOF. Existing default profiles are unchanged.

The runner supplies `--strides` and `--positions`, retains both in each strided
configuration and checks delivered ranges and prefix samples against independent
original bytes. Full content hashes still run outside measurements. The focused
sanitized suites pass 47 measured profiles and 86 helper contracts, including
warmup/reader scheduling, partial EOF, offsets beyond 4 GiB, invalid windows and
wide arithmetic. Logs use `artifacts/plan-compression-profile-*.log`.

The preceding baseline retains one decoded unit per LZNT1/WOF stream. Its harness checks
establish no cache or throughput improvement. Retain ordinary Release products
before changing the cache, then compare identical hot, alternating and wider
workloads with CPU, latency, allocation and I/O metrics. Sparse/raw units and
paged WOF tables can change read counts independently of decoder-cache misses;
record the exact storage layout before interpreting them.

The current-only baseline passes 540 runs/60 summaries: five independently
authored LZNT1/XPRESS4K/8K/16K/LZX32K inputs, memory/POSIX callbacks, one reader,
512-byte requests, 64 record-cache entries, 0/128 warmup operations and 3,000
measured operations, with nine repetitions of each configuration. All use codec-
unit strides and one/two/three positions. Setup and media hashing warm metadata
and the host page cache; this is not cold-device evidence. Ordinary committed-
source Release/O3 products are retained under
`artifacts/reproducibility-compression-profile/`; both builds match all eight
actual full products on the same checkout/toolchain/macOS arm64. Native app,
relocated-source and remote CI qualification remain separate.

The memory callback's 128-warmup wall medians are below, in milliseconds per
3,000 requests. Full timing/CPU/latency/RSS ranges remain in each
`artifacts/compression-profile-baseline-*/report.json`.

| Input | One position | Two positions | Three positions | Peak charged core bytes |
| --- | --- | --- | --- | --- |
| LZNT1 mixed units | 0.151 | 120.950 | 81.512 | 270,760 |
| WOF XPRESS4K | 0.152 | 9.973 | 10.196 | 153,840 |
| WOF XPRESS8K | 0.151 | 18.668 | 15.439 | 162,032 |
| WOF XPRESS16K | 0.155 | 34.359 | 25.938 | 178,416 |
| WOF LZX32K packed/raw | 0.154 | 78.787 | 57.121 | 214,460 |

LZNT1's first three windows contain a fragmented compressed prefix, a full raw
unit and a hole. WOF's windows contain a packed first unit, a raw second unit and
a partial packed final unit. Wider profiles therefore change the data mix as
well as cache access. The hot warm runs make zero resource reads; alternating
runs make 4,500 calls because the authored backing spans fragmented physical
runs. Their observed call/byte counts exactly match independent packet lengths
and physical layouts. These are resource observations, not explicit decoder-miss
counters. Hot p99 reaches the clock resolution; a candidate needs longer hot
runs before a regression conclusion.

Main review re-authors the original payloads, checks actual packed/raw input
storage and retained binaries, verifies every measured range/sample and resource
counter, and recomputes all summary medians/ranges in
`artifacts/compression-profile-review.json`. This establishes the baseline for a
bounded second decoded-output slot; that baseline changes no cache source or claims a speedup.
Required-allocation failures, optional storage refusal, failed-fill retry and
exact release must remain qualified before comparing a candidate. Those baseline
runs do not cover sequential/random, multiple readers or installed workloads.

### Optional second decoded output

The current bounded cache keeps the original required input/output/workspace and
attempts one optional output on the first distinct-unit miss after a useful fill.
Allocation/live-credit refusal preserves single-unit reading without poisoning
owning scopes. Hits promote the older output; failed replacements preserve the
other valid unit. Correctness/fault/pressure evidence is in ACCEPTANCE.md and
READ-CACHE-POLICY.md.

Matched ordinary Release/O3 binaries retain identical workload/POSIX sources,
toolchain, arguments, independently authored bytes and immutable image hashes.
The comparison passes 4,560 runs/240 paired configurations across the five
preceding codec/storage inputs: 1,080 strided, 300 longer hot, 2,880 general and
300 longer negative-case confirmation runs. Each report summary is per variant,
so there are 480 summaries. Both current Release builds match all eight full
products under `artifacts/reproducibility-unit-cache/`. Reports use
`artifacts/compression-{profile,hot,general,confirm}-unit-cache-*/report.json`.

For memory callbacks, two positions and 128 warmup, wall medians below are
milliseconds per 3,000 512-byte reads. Every input reduces physical resource
calls from 4,500 to zero in every repetition; CPU confirms the avoided fill work.

| Input | Retained one-unit reference | Current two-unit cache | Extra charged core bytes |
| --- | ---: | ---: | ---: |
| LZNT1 mixed | 117.475 | 0.152 | 65,600 |
| XPRESS4K packed/raw | 10.837 | 0.157 | 4,224 |
| XPRESS8K packed/raw | 18.711 | 0.156 | 8,320 |
| XPRESS16K packed/raw | 34.304 | 0.154 | 16,512 |
| LZX32K packed/raw | 79.907 | 0.157 | 32,896 |

The extra output itself is 64/4/8/16/32 KiB. Private stream/cache state additionally
costs 64 bytes for this single-reader LZNT1 owner and 128 for these WOF owners,
including the mounted MFT stream. Cold two-position profiles fill both outputs
with three physical calls rather than 4,500. One-position profiles never allocate
the extra output. Three cyclic positions exceed the cache and keep the original
physical call/byte counts, while retaining the additional unit. These observations
are specific to the earlier raw/packed/hole/partial layouts, not explicit decoder
miss counters or cold-device measurements.

Longer hot checks use one position, 2,000 warmup, 500,000 measured 512-byte reads
and 15 repetitions on both callbacks. Wall medians range from -0.23% to +0.23%
and CPU from -0.25% to +0.29% relative to the reference. All ranges overlap and
paired directions are mixed; there is no resolved hot-path gain. Physical I/O
and measured allocation counts are unchanged; private-state costs remain.
Per-request p99 can still reach clock resolution despite a longer total sample.

The general matrix covers sequential/random, memory/POSIX, 512/4096-byte requests,
one/four externally serialized readers, 0/128 warmup and nine repetitions of
3,000 measured operations. Per codec, 16 of its 32 paired configurations lower
physical I/O and 16 keep it equal. Timing medians are mixed. The largest short
negative case is XPRESS16K sequential/memory/512-byte/four-reader/cold:
1.706 to 1.888 ms (+10.63%) wall and 2.155 to 2.715 ms (+25.99%) CPU, with
overlapping ranges. Neither those small intervals nor lower I/O establish a
general throughput conclusion.

Targeted confirmations retain the exact negative configurations and extend
LZNT1/XPRESS4K/XPRESS16K sequential runs to 200,000 operations, XPRESS8K to 30,000,
with 15 repetitions. Across ten pairs wall medians range -1.18% to +1.58%, CPU
-1.16% to +2.37%, all ranges overlap and paired directions remain mixed.
The preceding XPRESS16K case becomes +0.39%/+1.14%; XPRESS8K's short POSIX/4096-byte/
one-reader +6.40%/+6.79% becomes -0.55%/-0.37%. I/O is exactly unchanged in these
sequential confirmations. Extra charged core bytes range 8,320 to 262,304,
depending on output-unit size and reader count. The short negative reports remain
qualified observations, not discarded results or a universal no-regression claim.

Main review re-authors original/stored bytes, independently predicts every read
range/sample and physical call/byte/allocation count using successful one/two-
unit working sets, verifies each alternating pair and recomputes every summary
median/range/deviation. It also checks actual releases and fuzz replay/event
evidence in `artifacts/unit-cache-review-confirmed.json`. Acceptance records the
initial review-only ordering assertion and its retained failed artifact.
The cache is accepted for measured reuse benefit with explicit memory cost.
Windows, FSKit/device/independent-driver comparisons, aggregate native/RSS stress,
broader codec/metadata/concurrency work and complete optimization qualification
remain separate. Multiple benchmark readers still share externally serialized
core ownership and do not establish independent parallel reads.

## Paired reader accounting measurements

`--release-report` verifies the selected binaries against a passing ordinary
Release reproducibility report. `--reference-release` selects the first retained
build in a second report, verifies the actual products and requires identical
release options, compiler/SDK/host and unchanged workload/POSIX source through
ordinary Git. Both variants run the same new invocation and alternate execution
order between repetitions. Core sources may differ: this compares reader
versions, with no independent-driver or isolated-instruction-cost claim. Copies
of both inspector/workload binaries and their digests remain in the output;
input, original-data and retained-binary changes fail qualification. Paired
bytes, entry counts and sampled sums must agree. I/O/allocation differences remain
reported metrics, so a genuine reuse optimization can change them.

```sh
python3 scripts/benchmark.py artifacts/interoperability-operation-reviewed/ntfs-s512-c4096.img /large.bin --expected-data artifacts/interoperability-operation-reviewed/large.bin --dataset-kind ntfs3g --build artifacts/reproducibility-index/first --release-report artifacts/reproducibility-index/report.json --reference-release artifacts/reproducibility-mirror/report.json --output artifacts/measure-accounting-next --profiles sequential random --backends posix memory --requests 4096 65536 --readers 1 4 --cache-entries 64 --warmup-operations 0 2000 --operations 10000 --repetitions 9
```

The initial guard comparison passes 2,880 runs across 160 paired configurations
(320 variant summaries), nine repetitions per variant/configuration, under
`artifacts/measure-accounting-{large,metadata,resident,fragmented,sparse,lznt1,wof-4k,wof-lzx-packed,wof-pages,wof-lzx-pages}/`.
The independent large-file source is a 64-MiB NTFS-3G image with a 2,097,408-byte
original payload. Synthetic sources cover resident/attribute-list/fragmented/
sparse/LZNT1 storage, mixed XPRESS4K/LZX units and 1,100-entry provider tables.
Provider table-open oracles contain 4,502,281/36,012,809 decoded bytes; their images
are 8 MiB. Acquisition uses authored original data, never inspector exports.

Hardware is Apple M4 Pro, 14 logical CPUs and 64 GiB RAM on arm64 macOS 26.6.2,
with selected Xcode clang 21 and SDK 27. Exact build/hardware/revision/digest
evidence remains in generated reports. Only one task-owned benchmark ran at a
time. The host page cache is warm; zero warmup means new stream/unit/cursor state,
not cold physical media. Percentiles retain per-run resolution and ranges.

Selected memory-backend/cache-64/one-reader/2,000-warmup medians:

| Profile | Operations/request | Before/guarded wall, ms | Change |
| --- | --- | ---: | ---: |
| Resident sequential | 50,000 / 17 bytes | 1.799 / 2.140 | +18.92% |
| Resident repeated open | 50,000 | 5.547 / 6.556 | +18.20% |
| Attribute-list repeated open | 10,000 | 3.596 / 4.118 | +14.52% |
| Directory continuation | 10,000 | 1.686 / 1.887 | +11.92% |
| Ordinary sequential | 10,000 / 64 KiB | 8.566 / 8.683 | +1.36% |

The metadata/resident ranges support targeted accounting optimization; broad
data-read percentages have overlapping ranges and cannot establish a universal
regression. Random WOF/table-open timings are mixed with overlapping ranges,
so their lower guarded medians establish no throughput win. All selected rows
retain identical I/O/allocation counts and add 248 peak core bytes for the new
volume accounting state. Process RSS and native pool/window memory are separate.
These reports precede the head-result/usage-initialization change described below.
Native/Windows/device, larger independent directory/file sets, matched independent
drivers and the complete optimization program remain open.

### Accounting simplification

Required refusal propagates the same sticky result to all active scopes, and
begin refuses an exhausted parent. The head therefore supplies that result
without scanning older flags. Admission still preflights and charges every
ancestor. Begin clears usage before assigning every remaining scope field;
selected limits are copied first, preserving aliasing and reused storage.
The 32-level test denies every ancestor in turn, verifies all 1,024 propagated
flags and zero failed work credits, checks unwind admission and reuses scope
storage after fresh successful calls. API version, limits and object sizes stay
unchanged.

Two isolated ordinary Release/O3 builds retain eight byte-identical products in
`artifacts/reproducibility-accounting/`. Review checked the actual full bytes,
lengths and digests. This qualifies portable products in separate build
directories on the same checkout/toolchain; relocated sources, native app/signing
and remote CI still require separate evidence.

The candidate-versus-guarded reports in
`artifacts/measure-accounting-optimized-{large,metadata,resident,fragmented,sparse,lznt1,wof-4k,wof-lzx-packed,wof-pages,wof-lzx-pages}/`
pass the same 2,880-run/160-paired-configuration matrix. Every configuration has
overlapping wall ranges; mixed small medians do not establish a broad speedup.
Every actual pair preserves bytes, entries, sampled sums, allocation/I/O/cache
counts and peak core bytes. Review also verified actual images, original files
and retained binaries against their reports and release evidence.

Unresolved small gains prompted two longer targeted comparisons:
`artifacts/measure-accounting-optimized-{resident,metadata}-confirm/`.
They pass 120 runs/four paired configurations, with one million operations and
15 repetitions per variant, memory backend, one reader, cache 64 and 2,000 warmup
operations. Both execution orders occur. All pairs retain identical semantic,
allocation/I/O/cache and core-peak results; full before/after byte oracles and
actual source/binary integrity pass.

| Profile | Guarded/candidate wall median, ms | Change | Candidate faster pairs |
| --- | ---: | ---: | ---: |
| Resident sequential, 17-byte request | 42.390 / 41.466 | -2.18% | 15/15 |
| Resident random, 17-byte request | 42.266 / 41.612 | -1.55% | 15/15 |
| Resident repeated open | 124.485 / 125.215 | +0.59% | 5/15 |
| Attribute-list repeated open | 372.657 / 372.205 | -0.12% | 8/15 |

CPU medians improve by 2.14%/1.53% for the two read profiles, with matching paired
signs. Wall ranges still overlap: sequential guarded/candidate ranges are
41.808–46.813/41.095–41.851 ms, and random ranges are
41.718–43.147/41.101–41.862 ms. Acceptance uses the consistent paired read result
and CPU confirmation, with no gain claimed for opens or broader workloads.
Resident-read per-run p99 medians remain 42 ns at the host clock's resolution;
this establishes no tail-latency improvement. The same workload includes its
prefix-sampling loop in wall/CPU, so this is complete reader cost rather than an
isolated instruction measurement. Native aggregate memory, scheduling and
installed/device performance remain separate qualification.

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

## FSKit directory continuation measurements

The current API 2 accounting source has a fresh baseline in
`artifacts/fskit-directory-accounting-{large,small}/report.json`, using the
verified ordinary Release archive from `artifacts/reproducibility-accounting/`.
Both current-only reports pass 27 runs/three profiles, nine repetitions each,
with the same large/small inventories and page/round/warmup settings below.
Actual source/header/archive/binary and input hashes were independently checked;
every complete inventory and EOF check passes. The real legacy owner includes
compound core scopes and rounded physical read scopes. Adapter/workload is O2,
core is Release/O3, and no sanitizer or installed extension is involved.

| Input/profile | Current wall median, ms | Reader calls | Peak charged pool bytes |
| --- | ---: | ---: | ---: |
| Large sequential | 66.630 | 32,720 | 196,232 |
| Large interleaved | 128.400 | 64,190 | 248,096 |
| Large separate views | 117.594 | 64,200 | 248,096 |
| Small sequential | 5.547 | 2,800 | 151,561 |
| Small interleaved | 9.884 | 5,000 | 166,946 |
| Small separate views | 9.215 | 5,100 | 166,946 |

The pool includes core and charged continuation storage, excluding Foundation
objects and the resource window. Process RSS medians are approximately
24.5 MB/15.5 MB for large/small runs and include workload/input/native storage.
Small sequential wall ranges are 5.457–9.946 ms; its isolated slow run remains
retained rather than discarded. The reports retain all CPU/percentile/RSS ranges.
These are current-only memory-reader baselines, with no guard-cost comparison,
attribution of earlier adapter gains, modern-runtime or installed/device claim.
The runner's identical-core-archive requirement for paired references remains
unchanged; pre-accounting binaries cannot serve as its matched reference.

```sh
python3 scripts/benchmark_fskit_directory.py .build/fixtures/namespace-large.img .build/fixtures/namespace-large.json --build artifacts/reproducibility-accounting/first --output artifacts/directory-accounting-next --pages 8 16 --rounds 10 --warmup-rounds 5 --repetitions 9
python3 scripts/benchmark_fskit_directory.py .build/fixtures/namespace.img .build/fixtures/namespace.json --build artifacts/reproducibility-accounting/first --output artifacts/directory-accounting-small-next --pages 1 2 --rounds 100 --warmup-rounds 10 --repetitions 9
```

The earlier adapter comparison follows and remains scoped to its earlier source.

`tools/fskit_directory_workload.m` calls the actual legacy directory handler with
an immutable aligned memory reader and external serialization. Independently
authored manifests check every packed native spelling, original reference, type
and requested size, including the names-only virtual prefix. Each reader checks
complete order and explicit EOF. The large fixture contains 2,000 hard links with
oversized UTF-16 aliases; the small fixture has 12 visible links. They are
namespace workloads, not measurements of 2,000 independent file bodies.
Adding their expected sizes/large inventory changes no image bytes: review
compared all six original namespace images in full under
`artifacts/directory-fixture-before/report.json`.

```sh
python3 scripts/build.py .build-release --release
python3 scripts/benchmark_fskit_directory.py .build/fixtures/namespace-large.img .build/fixtures/namespace-large.json --output artifacts/directory-before --pages 8 16 --rounds 10 --warmup-rounds 5 --repetitions 9
# After the adapter change, compare the retained binary and unchanged workload:
python3 scripts/benchmark_fskit_directory.py .build/fixtures/namespace-large.img .build/fixtures/namespace-large.json --output artifacts/directory-after --reference artifacts/directory-before --pages 8 16 --rounds 10 --warmup-rounds 5 --repetitions 9
```

The runner requires an ordinary Release/O3 unsanitized core; adapter/workload
compilation is O2 without sanitizers. It retains both binaries, full source/input/
archive digests, compiler/SDK, run logs and failures. A paired comparison requires
identical inputs, workload, core and toolchain and alternates binary order between
repetitions. Both binaries run with the new invocation's arguments even when the
reference's older matrix was shorter. Each process has a new owner, no MFT record
cache and explicit full-scan warmup before timing/counter reset. The source and
host caches are warm. Wall/process CPU and p50/p95/p99 include native object
construction and inventory checks; reported percentiles remain per-run.

The final reports are `artifacts/fskit-directory-large-sustained/report.json` and
`artifacts/fskit-directory-small-sustained/report.json`. Each contains 54 passing
runs and six summaries: nine repetitions of three profiles for both binaries.
Large phases use ten rounds/five warmups and page sizes 8/16; small phases use
100 rounds/ten warmups and page sizes 1/2. Sequential has one attribute-requested
reader, interleaved has two in that view, and views alternates names-only with
attribute-requested enumeration. Review verified the complete retained binaries,
current source/input/archive digests and that only the native owner source differs.

| Input/profile | Reference/current wall median, ms | Wall change | Reference/current reader calls |
| --- | ---: | ---: | ---: |
| Large sequential | 68.600 / 69.529 | +1.35% | 32,720 / 32,720 |
| Large interleaved | 1,135.434 / 135.238 | -88.09% | 1,047,610 / 64,190 |
| Large separate views | 1,139.495 / 122.318 | -89.27% | 1,046,340 / 64,200 |
| Small sequential | 5.234 / 5.146 | -1.68% | 2,800 / 2,800 |
| Small interleaved | 13.975 / 9.462 | -32.30% | 9,900 / 5,000 |
| Small separate views | 13.143 / 8.565 | -34.83% | 9,700 / 5,100 |

Large interleaved process CPU falls from 1,131.123 to 134.737 ms; separate views
fall from 1,133.963 to 121.836 ms. Their p99 per-run medians fall from
1,126.792/1,159.417 to 65.917/66.000 us respectively. Large interleaved reader bytes
fall from 4,156,672,000 to 128,583,680 and allocations from 1,164,330 to 151,910.
The reports retain all metrics/ranges for both inputs and profiles.

Sequential timings do not establish a stable material benefit or regression:
large reference/current ranges are 65.629–70.078/66.930–71.374 ms and small ranges
are 4.891–6.190/4.976–5.732 ms. Both keep identical measured read and allocation
counts. Earlier shorter paired reports under `artifacts/fskit-directory-{large,small}-compared/`
showed higher sequential medians. They describe an earlier candidate and remain
retained; they prompted completed-scan victim preference and the longer final
comparison above.

| Input/profile | Reference/current peak pool bytes | Added peak |
| --- | ---: | ---: |
| Large sequential | 194,832 / 195,984 | 1,152 |
| Large two-reader profiles | 194,832 / 247,848 | 53,016 |
| Small sequential | 150,161 / 151,313 | 1,152 |
| Small two-reader profiles | 150,161 / 166,698 | 16,537 |

The reported `baseline_core_bytes`/`peak_core_bytes` now describe the resource
allocation pool: core children plus the charged continuation table. Foundation
objects and the separate I/O window are excluded. Process peak RSS is reported
separately and includes input/manifest/workload/native objects and warmup; these
runs establish no aggregate installed-memory improvement. The 64-MiB pool limit
still applies, and elevated-pressure completion discards older inactive slots.
LIFECYCLE.md records 32 reuse/eviction/pressure cases, reentrant ownership checks
and every 151 allocation/41 read fault position in interleaved pagination.

This qualifies a targeted legacy memory-reader optimization. macOS 27 execution,
installed native buffer scheduling, physical media, diverse independent files,
Windows-authored fragmentation, more than two active positions and performance
under real pressure remain open. Broader bounded checkpoints and checked index/
alias reuse need their own profiles; no independent-driver advantage is claimed.

## Checked stream extent positions

One stream-owned mapping index reuses the current or immediate successor extent.
Every hit checks its array bound and VCN span; a miss keeps the binary search.
The position survives bootstrap mapping-array growth and failed data I/O while
the ordinary exact-read/work/admission contract still owns every request. It
allocates no read storage. The private object costs eight additional bytes on
arm64/x86_64; the measured mount plus stream raises peak accounted core storage
by sixteen bytes. Independent streams retain independent positions. This change
does not introduce concurrent calls on a volume.

`tests/extent_fixtures.py` authors six original 16-MiB images with independent
4-MiB content: one, sixteen, 256 or 1,024 deliberately unmerged extents, plus
1,024-entry sparse and VDL-tail variants. Attribute lists span up to eleven FILE
records. SHAKE-derived bytes distinguish each stored extent; holes and bytes past
VDL have explicit zero oracles. Main independently reconstructs actual protected
records, extension ownership, mappings and all data. The images are focused
synthetic workloads, not Windows or complete-volume diagnostic qualification.

The initial baseline has 168 runs/24 summaries under
`artifacts/extent-baseline-{contiguous,runs-16,runs-256,runs-1024}/`. The matched
candidate has six reports with nine repetitions and 300,000 operations; four
longer confirmations have thirteen repetitions and one million operations.
Together they contain 1,272 alternating pairs/2,544 measured runs. Inputs,
workload/POSIX sources, compiler, SDK, optimized build options and independently
verified Release products match. Both retained binaries check complete original
content before/after; every measured pair has equal delivered/sample bytes,
resource calls/bytes and zero read allocations. Main verifies actual retained
binaries and every pair in `artifacts/extents-review.json`.

Profiles use one externally serialized reader, no MFT cache, 128 warmup requests,
sequential/random offsets, requests of one/64/4,096 bytes and memory/POSIX
callbacks. Setup and complete image/data checks warm host storage; these are
algorithm and warm-file observations, not cold-device or installed FSKit tests.
The runner records wall/CPU, throughput, p50/p95/p99, allocation/I/O/cache counters,
peak accounted core bytes and process RSS. RSS includes the image/oracle/workload,
so the sixteen-byte accounted change implies no measured RSS improvement.

The table uses the median of thirteen paired candidate/reference ratios, rather
than a ratio of aggregate timing medians. Positive reduction means faster.

| Random 4-KiB profile | Callback | Paired wall reduction | Paired CPU reduction | All paired wall ratios |
| --- | --- | ---: | ---: | ---: |
| 1,024 extents | Memory | 16.6% | 16.6% | 0.777–0.895 |
| Sparse, 1,024 extents | Memory | 17.7% | 17.7% | 0.804–0.895 |
| VDL tail, 1,024 extents | Memory | 16.6% | 16.6% | 0.741–0.895 |
| 1,024 extents | POSIX | 3.8% | 3.8% | 0.851–0.995 |
| Sparse, 1,024 extents | POSIX | 7.3% | 7.3% | 0.844–1.058 |
| VDL tail, 1,024 extents | POSIX | 4.4% | 4.4% | 0.902–0.989 |

Every long random-4-KiB memory pair improves on the three fragmented profiles.
Those reads usually cross an extent boundary, making the second lookup local.
Sequential 4-KiB memory paired reductions are 2.2%, 5.2% and 10.7% respectively,
with overlapping/noisy ranges; the largest sequential figure is not universal.
Contiguous and small-request controls remain mixed. Long random one-byte memory
paired medians regress 2.7% for ordinary fragmentation, 2.4% for sparse and 3.9%
for the VDL profile; 64-byte controls range from 1.3% slower to 1.7% faster.
POSIX and tail-percentile controls also retain jitter. The thirteen-pair contiguous
random-4-KiB POSIX wall range is 0.679–3.748 while its CPU median ratio is 0.998;
do not infer a broad storage improvement from that wall series.

This accepts a targeted split-read optimization with a fixed small storage cost,
unchanged resource calls and explicit small random-read tradeoffs. Reports retain
all controls under `artifacts/extent-paired-candidate-{PROFILE}/` and
`artifacts/extent-paired-confirmation-{PROFILE}/`; launcher logs use
`artifacts/plan-extents-paired-{candidate,confirmation}-{PROFILE}.log`.
The six-profile suite checks 17,420 byte results, two independent stream lifetimes,
34 partial/full failures and 36 exact/one-below compound limits without read
allocations. Current 68-suite, freestanding, component, universal Release and
fresh image/diagnostic fuzz evidence is in ACCEPTANCE.md. Windows-authored
fragmentation, broader/competing readers, native/device profiles, copy coalescing,
buffer reuse and the rest of the optimization program remain open. This is not
an independent-driver comparison.

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
