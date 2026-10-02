# WOF format and decoder contracts

The core reads observed WOF file-provider XPRESS4K/8K/16K and LZX32K streams through the
ordinary public stream API. Standalone metadata/table/codec primitives remain in
`ntfs/wof.h`; storage and lifetime belong to `core/wof_stream.c`. FSKit projects known
file-provider metadata as ordinary files with truthful sizes, independent ADS and
original reparse bytes. WIM backing and Windows/installed qualification
remain open.

## Stored metadata

The ordinary reparse decoder validates the complete Microsoft envelope first.
The WOF decoder accepts the observed 16-byte file-provider payload: external
version 1, provider 2, file-provider version 1 and a supported algorithm. WIM,
unknown versions/algorithms and larger future shapes return UNSUPPORTED;
truncated known fields return CORRUPT. Errors zero output structures. Generic WOF
tag classification remains opaque and does not imply this provider verdict.

Microsoft's [WOF external prefix](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_wof_external_info),
[file-provider prefix](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_provider_external_info_v0)
and [algorithm identifiers](https://learn.microsoft.com/en-us/windows/win32/api/wofapi/ns-wofapi-wof_file_compression_info_v1)
describe the interface fields. API parameter structures, including Flags, are not
presumed to be the stored reparse shape. The observed shape and separate sparse
unnamed data/`WofCompressedData` streams come from
[original NTFS format research](https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20%28NTFS%29.asciidoc).
Only format facts were used; no external filesystem implementation was imported.

| Algorithm | Logical chunk size | Content primitive |
| --- | --- | --- |
| XPRESS4K | 4 KiB | Integrated XPRESS-Huffman reading |
| LZX | 32 KiB | Integrated WOF/WIM-variant LZX reading |
| XPRESS8K | 8 KiB | Integrated XPRESS-Huffman reading |
| XPRESS16K | 16 KiB | Integrated XPRESS-Huffman reading |

## Chunk geometry

`ntfs_wof_layout_init` takes independently known logical and backing-stream sizes.
Checked ceiling division gives chunk count. A nonempty file has `chunks - 1`
stored starts: the first start is implicit zero and the final end is the backing
payload size. Offsets are relative to the table's end. Exact multiples do not add
an empty chunk or a redundant final entry. This explicitly interprets the
omitted-first-start format notes; the older research floor-division formula is
ambiguous at exact multiples. Synthetic boundaries do not replace a Windows
observation.

Offsets use four bytes below 4 GiB logical size and eight bytes at or above it,
as described by the original
[NTFS-3G system-compression layout comment](https://github.com/ebiggers/ntfs-3g-system-compression/blob/master/src/system_compression.c).
Sizes stay in NTFS's signed 64-bit stream domain. Spans must be positive, remain
inside the payload and fit their logical chunk, including the shortened final
chunk. Equal stored/logical lengths select raw storage. Empty logical files require
empty backing storage. Only a complete table pass establishes global ordering.

Zero work budget selects 1,048,576 chunks; the hard ceiling is 16,777,216.
Worst-case flat tables occupy 8 MiB and 128 MiB respectively. These are policy
limits, not format restrictions. The primitives allocate nothing. Public stream
opening uses the default work cap and validates the entire table through one
4-KiB page, charged to the existing owner allocator. It never allocates a flat
table. Each subsequent random read checks its local span using that same page.

## Storage, lifetime and native projection

Known file-provider metadata requires a fully validated sparse unnamed stream
with no physical runs (or an empty resident placeholder), plus the exact UTF-16
`WofCompressedData` attribute. Backing VDL must cover its complete stored size.
Resident, fragmented and attribute-list backing storage use the ordinary bounded
attribute reader. Node stat reports placeholder logical size and backing physical
allocation independently of table contents and codec support. The placeholder's
VDL does not describe decoded content. Malformed storage fails explicitly;
encrypted backing retains inspectable sizes while default reads return
UNSUPPORTED. Independent plaintext ADS do not require opening the default content.

The public stream owns its complete provider state after source-node close and
holds one counted volume child. A single lazy allocation contains private output,
input and aligned queried codec scratch. XPRESS16K uses 34,432 bytes and LZX32K
uses 70,476 bytes, excluding the optional table page and backing metadata.
One decoded unit and one table page are cached. Failed fills
invalidate their tags before I/O, retain buffers for retry and publish no failed
unit bytes. Core reads may return an already completed prefix if a later unit
fails, following the existing stream contract. Teardown releases private backing,
page and buffers without additional reads.

FSKit uses explicit provider classification rather than treating every reparse
object as a symlink. Known provider objects have ordinary-file type/attributes,
including metadata-only encrypted cases. The raw reparse xattr and lossless
stream manifest remain available. The backing name retains its catalog ordinal
but has no public encoded-content alias; ordinary ADS retain theirs. Admission
also gates cached reads and xattrs after revocation. Unmount closes transient
provider descriptions and a remount reopens them under the retained item owner.

## XPRESS-Huffman

The original decoder implements one exact-size block, at most 64 KiB, using
[MS-XCA encoding](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/c7ec7ba9-ca8f-448f-bb85-027c1516db1c)
and [MS-XCA decoding rules](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/26db8e62-bbd8-472c-a09e-623f6de10f0b).
It checks complete canonical trees, maintains little-endian word lookahead before
raw length extensions, bounds distance/length and supports overlapping copies.
A 32-bit escaped length cannot fit this block after its required prefix and is
rejected. Multi-block continuation is outside this API.

The caller supplies queried scratch size/alignment. Canonical buckets and an
eight-bit prefix table currently use 1,664 bytes without allocation or I/O.
Errors leave `written` zero but may alter an output prefix and scratch. Regions
must not overlap. An owning cache must decode privately and publish only after
success. EOF is optional when final words are consumed; otherwise one EOF must
exhaust input. Unused prefetched bits need not be zero. No arbitrary unread suffix
is accepted. This preserves the specification's optional EOF without inventing a
zero-padding restriction.

## LZX32K

The original decoder implements independent WOF/WIM-variant units with a 32-KiB
window. It starts directly with the block type and default-size flag; an explicit
size has 16 bits. This differs from the CAB/Delta stream/header and 24-bit sizes
in Microsoft's [MS-PATCH header](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-patch/517e354e-a5c5-4239-ada5-25389cfe3170).
The observed WIM variant follows the original
[compression-format research](https://github.com/libyal/libfwnt/blob/main/documentation/Compression%20methods.asciidoc).
Compression variant and provider are separate: decoding these LZX units does not
implement the WIM-backed WOF provider.

Verbatim, aligned-offset and raw blocks share unit-local output history and
repeated offsets. Canonical main/secondary/pretree/aligned alphabets have exact
bounded spans; oversubscribed and incomplete nonempty trees are corrupt. An
unused secondary/aligned tree may be empty, but requesting a symbol from it is
corrupt. Pretree length differences persist across blocks, including bounded
short/long zero runs and repeated-length codes. Matches remain within completed
history and the current block, with lengths through 257 bytes; Delta's extended
length escape and external dictionary are outside this format.

Raw block alignment, three little-endian offsets and odd-byte padding are checked
before copying. Repeated slots swap with R0; a new offset shifts the queue. Aligned
low bits apply when the footer has at least three bits, including equality.
Unused final-word bits need not be zero; a producer's single extra zero lookahead
word is allowed, while arbitrary unread suffixes are rejected. These are explicit
single-unit bounds, not a continuing archive stream.

Every encoded unit receives the inverse x86 CALL transform with WIM's fixed
12,000,000-byte parameter, unit-local positions and untouched final ten bytes.
The original author's [format constants](https://github.com/ebiggers/wimlib/blob/master/include/wimlib/lzx_constants.h)
cross-check that parameter and the 32-KiB alphabets; its implementation was not
imported. Equal-size WOF raw chunks bypass the decoder and transform entirely.
Independent raw/encoded CALL fixtures check this distinction. The decoder uses
4,940 bytes of caller-owned scratch aligned to four bytes, no allocation/I/O and
the same zero-error-count/private-publication contract as XPRESS.

`tests/lzx_oracle.py` optionally loads an explicitly selected external wimlib
library in a separate test process. It captures packets from independently
patterned original bytes at several compression levels, checks external exact
roundtrips, and can run the core vector reader and externally decode our positive
packets. Library version/hash, raw compressor refusals and failure reports remain
generated artifacts. No product links that library; ordinary `make test` uses
the repository-owned declarative author without an external codec dependency.
For a fresh ignored report directory:

```sh
python3 tests/lzx_oracle.py --library /opt/homebrew/opt/wimlib/lib/libwim.dylib --output artifacts/lzx-oracle-next --synthetic .build/lzx-fixtures/lzx-vectors --reader .build/ntfs-lzx-tests --invalid .build/lzx-fixtures/lzx-invalid
```

## Evidence and continuation

The LZX integration passes all 37 sanitized C suites, both freestanding targets,
style, the legacy component and current unsigned app. It adds 140 exact content
and 31 invalid vectors; 192 independently compressed external packets decode
exactly, and the external decoder checks 139 nonempty authored packets. Reports
retain 168 raw compressor refusals separately. The public file suite now checks
37 verdicts and all 376 allocation/101 read failure positions in selected
operations, including LZX page changes, raw/encoded CALL distinctions and a late
corrupt unit. Twenty-three legacy provider cases check bytes, truthful metadata,
raw manifests, zero-count errors, remount/revocation and exactly-once replies.
Six modern runtime checks explicitly SKIP. Source/component/build evidence is
`artifacts/plan-lzx-*.log`; external provenance/results are under
`artifacts/lzx-oracle-checked-2/`. ACCEPTANCE.md preserves earlier failures and
the exact evidence boundaries. No Windows/installed WOF acceptance is established.

The subsequent [pressure policy](READ-CACHE-POLICY.md) checks release/reopen of
XPRESS/LZX caches with unchanged bytes, raw snapshots and native identity. It
adds a separate seventh modern runtime SKIP to the component; native notification
delivery and aggregate memory stress remain open.

The WOF/XPRESS/LZX campaign completes 1,122,244 executions in 61 seconds (coverage
691, features 2,392, peak RSS 466 MiB); the image campaign completes 45,986
(coverage 3,749, features 14,573, peak RSS 982 MiB). Both exit zero without a
reported crash/sanitizer finding, under `artifacts/fuzz-lzx-{wof,image}/`.
The near-cap image RSS includes runner corpus/sanitizer overhead; codec allocation
bounds are separate. Longer Windows-seeded campaigns and provider-specific native
fault/interleaving/hard-link qualification remain open.

The preceding XPRESS integration passed all 35 sanitized C suites, both freestanding targets with the 2-KiB frame budget,
selected Xcode style, legacy component and current unsigned app build pass. The
new file suite checks 28 storage/format verdicts, exact original-byte oracles,
complete stream lifetime, independent ADS, mixed raw/packed chunks, empty/exact/
partial files, VDL independence, fragmented/listed data and multi-page tables.
Sweeps inject all 216 required allocation and 68 read failure positions in the
selected stat/open/cold-content operations, including a table-page crossing;
retry, guards, unchanged images and exact cleanup pass. These counts do not claim
every possible read position in a large file.

Fourteen legacy FSKit provider cases check file classification/requested sizes,
byte output, raw reparse/full reverse-manifest oracles, hidden backing aliases,
independent ADS, malformed-table/codec errors, metadata-only LZX/encryption and
remount/revocation/exactly-once replies. Six modern runtime checks explicitly
SKIP without macOS 27. The modern result object has no public byte-count getter;
its test checks result/error and buffer bytes, while legacy checks its count too.
No installed mount or Windows codec ran. Evidence uses
`artifacts/plan-wof-files-core-final.log`, `plan-wof-files-freestanding-reviewed.log`,
`plan-wof-files-style-final.log`, `plan-wof-files-component-accepted.log` and
`plan-wof-files-app-accepted.log`.

The image campaign now reads first/middle/tail default-stream positions, reaching
raw/final WOF chunks and table-page changes. It completed 47,555 executions in
61 seconds, coverage 3,536, feature count 13,962 and peak RSS 958 MiB, exit zero
without a reported sanitizer/crash finding. Evidence uses
`artifacts/fuzz-wof-files-image/` and `artifacts/plan-wof-files-fuzz-image.log`.
That near-cap process RSS includes corpus/sanitizer overhead; it does not measure
native provider memory or qualify Windows-authored formats.

The preceding standalone checkpoint passed all 34 sanitized C suites, both
freestanding targets with the 2-KiB frame budget,
selected Xcode style, the legacy FSKit component and current unsigned app passed.
Six modern FSKit runtime checks explicitly SKIP without macOS 27.
The WOF suite has 87 exact-byte XPRESS vectors and 11 malformed vectors covering
short/maximal codes, word-prefetch boundaries, byte/word extensions, distance
classes, overlapping copies, optional EOF, nonzero padding, short input/scratch,
zero error counts and guards. Provider/table checks include future/truncated
shapes, raw/packed/final spans, duplicate/descending offsets, work limits and
widths below/at/above 4 GiB. The fixture author uses declarative alphabets,
original payload patterns and a separately checked short wire packet; it does not
execute a Windows codec.

Evidence uses `artifacts/plan-wof-{core,freestanding,style,component,app}-final.log`.
The dedicated `wof` fuzz target mutates provider packets, bounded layout/table
envelopes and XPRESS blocks, checking deterministic verdicts and guards. Its
60-second campaign completed 3,079,633 executions in 61 seconds, coverage 360,
feature count 1,129 and reported peak RSS 479 MiB, exit zero without a crash or
sanitizer finding. Reports use `artifacts/fuzz-wof-primitives/` and launcher log
`artifacts/plan-wof-fuzz-final.log`. This is standalone synthetic evidence.

Next, expand provider-specific native fault/interleaving and hard-link cases and
acquire Windows-generated raw, packed, fragmented and partial-final samples for
every algorithm. Installed authorization and performance remain distinct gates.
