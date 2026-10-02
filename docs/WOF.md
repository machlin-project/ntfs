# WOF format and decoder contracts

This checkpoint supplies standalone file-provider metadata, chunk-table and
XPRESS-Huffman primitives in `ntfs/wof.h`. It does not open or read WOF files.
Public stream opening still rejects reparse objects; FSKit provider adoption
remains unsupported. LZX content, WIM backing and Windows-authored qualification
remain required parts of the continuation.

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
| XPRESS4K | 4 KiB | Standalone XPRESS-Huffman |
| LZX | 32 KiB | Not implemented |
| XPRESS8K | 8 KiB | Standalone XPRESS-Huffman |
| XPRESS16K | 16 KiB | Standalone XPRESS-Huffman |

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
limits, not format restrictions. The primitives allocate nothing. Future stream
integration must charge the adapter's aggregate memory/I/O budgets; a hard-cap
flat table cannot fit its 64-MiB allocation budget. Use a bounded paged whole-table
pass before exposing random content reads.

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
must not overlap. A future cache must decode privately and publish only after
success. EOF is optional when final words are consumed; otherwise one EOF must
exhaust input. Unused prefetched bits need not be zero. No arbitrary unread suffix
is accepted. This preserves the specification's optional EOF without inventing a
zero-padding restriction.

## Evidence and continuation

All 34 sanitized C suites, both freestanding targets with the 2-KiB frame budget,
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

Next, validate sparse unnamed storage, the exact named backing attribute, full
extent ownership and the entire chunk table. Preserve counted node-independent
stream lifetime, lazy bounded buffers, allocation/read retry, truthful metadata,
ADS policy and native admission/revocation/unmount. Keep the public reparse guard
until end-to-end content and fault checks pass. Implement LZX separately and
acquire Windows-generated raw, packed, fragmented and partial-final samples for
every algorithm. Installed authorization and performance remain distinct gates.
