# Private bounded LZNT1 encoding

This component prepares LZNT1 byte packets only. It does not enable compressed
filesystem writes. NTFS compression-unit storage, physical allocation, sparse
padding, FILE size/accounting, original-unit before images, WAL/recovery and
native mutation admission remain separate owning work.

## Interface and ownership

`core/write_lznt1.h` exposes a private worst-case bound, exact measurement and
encoding operation. Input is at most 1 MiB, a component resource policy rather
than an LZNT1 format limit. Empty input emits no bytes. Nonempty calls receive
12,288 bytes of caller-owned scratch: 4,096 two-byte hash positions and one
4,096-byte candidate body. Scratch needs no particular alignment. No allocation,
read/write callback or global mutable state exists in the encoder.

All declared pointer ranges and capacities participate in disjointness checks.
Address wrap, missing required storage, overlapping input/workspace/output/size
results, insufficient scratch and over-policy input refuse before scratch or
results change. Exact measurement uses the caller's scratch. When output capacity
is below the checked raw bound, encoding first measures the complete stream and
then checks capacity; an insufficient output leaves output and size untouched but
may change admitted scratch. A deterministic second pass publishes only after
every fallible check. Capacity at or above the raw bound already proves that all
chunks fit and therefore uses one encoding pass after the same complete admission.
Callers must keep input immutable throughout either route. Both routes produce
identical bytes. Output beyond the returned size and workspace beyond its required
extent remain unchanged.

The worst-case bound is input bytes plus two bytes for each started 4-KiB chunk.
At the one-MiB input limit this is 1,049,088 bytes. Chunk-count and addition
arithmetic are checked. Exact measurement permits smaller caller output than
this raw bound, including the six-byte encoding of a 4-KiB repeated byte.

## Format facts and independent algorithm

Microsoft's [MS-XCA LZNT1 description](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/5655f4a3-6ba4-489b-959f-e1f407c52f15)
and [buffer grammar](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/124d9696-a69c-409a-a055-2562fbe255f9)
specify independent chunks and groups of up to eight literal or match elements.
The [chunk definition](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/cba0fa15-bd62-4eda-8838-8fc7ab406df1)
specifies the two-byte header: bit 15 selects compressed storage, bits 14..12
carry signature 3, and bits 11..0 hold body bytes minus one. The
[processing rules](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/b1ba6d34-499c-4017-ab0c-fe2daee93efc)
establish 4,096-byte source units, legal overlapping references and ignored
unused final flag bits. End markers are optional; this encoder emits none.

The repository's existing original decoder and named constants implement the
position-sensitive match format. At chunk output positions 1..16, length has
12 low bits and distance has four high bits. Each transition after 16, 32, 64,
128, 256, 512, 1024 and 2048 moves one bit from length to distance. Stored length
adds three; stored distance adds one. A match cannot start at position zero or
refer into an earlier chunk. Microsoft's
[worked example](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/94164d22-2928-4417-876e-d193766c4db6)
corroborates low-to-high flag order, these initial widths and overlap expansion.

Our original encoder keeps one most-recent position for a three-byte hash and
uses a greedy match only after comparing the original bytes. Hash collisions
can reduce compression but cannot establish byte equality. Positions consumed
by a match are indexed once; references can overlap because equality is checked
against the original complete input. There are no candidate chains or searches
through an unbounded dictionary. Each chunk resets its dictionary and emits its
raw body whenever the candidate body is not strictly shorter. Compression is
useful but is not advertised as optimal or byte-identical to Windows output.

Match comparisons are linear in consumed input: a successful match consumes its
compared prefix; a rejected short candidate compares at most three bytes.
Dictionary insertion visits each position once, token-width selection advances
at most eight boundaries per chunk, and each chunk clears a fixed 8-KiB table.
Measurement uses one pass. Encoding uses one pass with raw-bound capacity or two
with a smaller admitted capacity. The core uses constant stack space beneath
the existing 2-KiB frame budget.

The codec, hash selection, publication admission and independent tests are
repository-owned. No external codec or GPL implementation was copied or linked.
A search result exposed a third-party discussion quoting the same Microsoft
width rule; it was not used as an implementation source. Microsoft protocol
facts and existing repository-owned framing are the relevant sources. This is
not a legal clean-room or patent-clearance claim.

## Independent local evidence

`tests/write_lznt1.c` supplies literal-wire packets for raw CAT, a full repeated
byte, alternating two-byte and three-byte patterns, and equal-size raw fallback.
An independently authored wire walk uses an explicit nine-entry width table and
checks every literal and reference against original plaintext. It does not call
the encoder's token-width or matching helpers. The public original decoder
provides an additional round-trip check, never the sole expected-byte oracle.

The suite checks nine widths on both sides of every transition, chunk resets,
mixed raw/compressed streams, one-MiB input, 16 alignments, exact output capacity,
all short capacities for goldens, partial-output refusal across multiple chunks,
all shorter workspace capacities, all buffer alias classes, touching endpoints,
address wrap, over-policy sizes and deterministic scratch reuse. There are 160
additional exact-allocation-end cases for sanitizers. Long unique triples test
far references through the final 4093-byte displacement. Independent malformed
wire packets and a short decoded destination retain the existing decoder's
bounded error contracts.

`tests/fuzz_write_lznt1.c` adds an original arbitrary-plaintext encoder/decode
oracle, deterministic repeat checking, output-capacity refusal and exact input/
workspace/decoded allocation ends. Its standalone mode runs 512 deterministic
inputs; the libFuzzer entry point can run under fatal ASan/UBSan without importing
an external codec.

Current actual results belong in ACCEPTANCE and CLOUD-STATUS after integration;
a prepared test or native workflow is not a successful execution claim.

`tests/write_lznt1_differential.c` compares a frozen pre-optimization encoder
with the current encoder across all nine width intervals, input sizes through
one MiB, seven patterns, chunk resets and eight output-capacity choices. It
checks exact encoded bytes, size publication and untouched refused outputs.
`tests/lznt1_contract.c` independently checks all 256 flag combinations, literal
groups and the chunk-end error/publication order, then compares complete output
buffers, statuses and lengths with the frozen decoder for byte truncations,
mutations, every short destination, multiple chunks and overlapping declarations.
These checks retain exact allocation ends and 32 alignments. The ordinary Meson
suite runs the independent decoder contract; the explicit differential runner
also tests userspace, portable memory/wire access and GPR-only host contexts:

```sh
python3 scripts/check_lznt1.py --compiler clang --reference artifacts/codec-reference/reference --fixtures .build/cpu-fixtures --output artifacts/lznt1-check-next
```

The reference directory must be an unchanged export containing the private
encoder, its headers and the existing original decoder. The runner requires
fatal ASan/UBSan by default and retains Linux LeakSanitizer. Apple ASan does not
supply the same leak-scanning boundary. A restricted local no-LSan supplement is
separate evidence and does not satisfy the full hosted Linux sanitizer gate.

`scripts/benchmark_lznt1.py` freezes a committed reference, original fixture
bytes, harness, compiler identity and products, then alternates matched Release
calls in userspace and GPR-only host contexts. The three operations are exact
measurement, exact-capacity encoding and raw-bound-capacity encoding. They retain
separate wall/process-CPU samples, identical work counts, output checksums and
the 12-KiB workspace with zero core allocations/I/O. Original wire inspection
checks every emitted literal and match against the input before and after timing.
The 18 fixtures include empty/tiny inputs, incompressible bytes, periods, mixed
chunks, original records and the one-MiB ceiling. Complete in-memory codec timing
is separate from compression-unit storage or mounted filesystem throughput.

```sh
python3 scripts/benchmark_lznt1.py prepare --compiler clang --reference PRE_CHANGE_REVISION --output artifacts/encoder-next
python3 scripts/benchmark_lznt1.py compare --compiler clang --output artifacts/encoder-next --comparison candidate --repetitions 9 --sample-ms 50
```

## Independent hosted Windows oracle

The C suite optionally writes its original plaintext and emitted packet pairs to
an already-created empty directory. Every file uses exclusive creation. Run:

```
mkdir artifacts/lznt1-corpus-next
.build/ntfs-write-lznt1-tests artifacts/lznt1-corpus-next
```

Transfer these generated pairs as CI artifacts, then on actual Windows run:

```
python scripts/collect_windows_lznt1.py --corpus CORPUS --output NEW_REPORT_DIRECTORY
```

The collector calls `ntdll!RtlDecompressBuffer` with format LZNT1 and exact-size
output, independently comparing the result with original plaintext. Microsoft's
[API contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtldecompressbuffer)
defines the format, buffer sizes and returned decompressed length. The report
records actual platform provenance, collector/input hashes, native statuses,
lengths, exact data, native buffer guards and unchanged source files. Corpus
count, per-file size and aggregate bytes are bounded. Empty/unpaired/unexpected
members, symlinks, special files, absent Windows/export, changed inputs and the
first native mismatch fail explicitly. A report directory is never overwritten.
No device, volume or filesystem compression setting is touched.

`tests/windows_lznt1_contract.py` uses a separately labeled synthetic provider to
exercise the transport and every verdict dimension. These are harness tests,
not Windows codec evidence. The hosted job must execute the actual collector
successfully before claiming Windows compatibility for the generated packets.
Even successful native decompression does not qualify compressed NTFS storage,
Windows recovery, FSKit mutation or release readiness.
