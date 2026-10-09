# 12 · Reparse points and compression

[Reference index](README.md) · [Previous](11-worked-examples.md) · [Next](13-research-and-coverage.md)

A physical attribute map tells us where bytes are stored. Reparse providers,
compression and encryption can change what those bytes mean as file content.
Metadata inspection and plaintext reading need separate admission.

![Content classification selects ordinary reads, a decoder, a provider or refusal](diagrams/content.svg)

[Diagram source](diagrams/content.mmd)

## Reparse envelope

The Microsoft reparse common prefix is eight bytes. Offsets are relative to the
complete reparse value:

| Offset | Width | Field |
| --- | --- | --- |
| `0x00` | 4 | Reparse tag |
| `0x04` | 2 | Payload byte length |
| `0x06` | 2 | Reserved storage |
| `0x08` | Variable | Provider payload |

The selected tag determines the payload shape. Third-party GUID framing adds a
16-byte GUID after the common prefix. Complete size and tag/provider framing
must be proved before interpreting names or content. Microsoft defines
[REPARSE_DATA_BUFFER](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_reparse_data_buffer)
and [REPARSE_GUID_DATA_BUFFER](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_reparse_guid_data_buffer).

Important admitted/classified tags include:

| Tag | Role |
| --- | --- |
| `0xA0000003` | Mount point / junction |
| `0xA000000C` | Symbolic link |
| `0x80000017` | Windows Overlay Filter |
| `0x9000001A` | Cloud-family base tag; variants need their own classification |

The Microsoft bit, name-surrogate bit and directory bit are tag properties.
They do not establish provider availability or make every reparse object a
symlink.

## Symlink and junction names

Name payloads declare substitute/print offsets and lengths in **bytes**, relative
to their PathBuffer. The symlink form additionally contains flags, including
relative-target bit 1. Substitute name supplies the target; print name is display
metadata. Validate each declared span and UTF-16 framing separately.

Reading a reparse packet is not following it. Windows roots, drive-relative
paths, cross-volume destinations and native filesystem path-walk policy require
an owning integration contract. Our adapter's qualified projection policy is in
[LINK-POLICY.md](../LINK-POLICY.md).

### Private payload authoring

[write_reparse.c](../../core/write_reparse.c) provides an allocation-free private
encoder for the documented symlink and junction envelopes. It stores substitute
then print UTF-16 names, each with a trailing zero unit; lengths exclude those
terminators and offsets remain relative to PathBuffer. The common reserved word
is zero. The substitute is nonempty, the print name may be empty, and embedded
zero units refuse. Other UTF-16 units, including unpaired surrogates, remain
exact. Only the defined relative symlink flag is accepted; junctions have none.

The complete result, including the common header, is capped at 16 KiB. Counts
are bounded before input traversal and byte conversion. Inputs may share name
storage; outputs may not alias inputs or each other. Every failure preserves
both the output buffer and its size output. Encoding writes only the returned
extent and performs no allocation, I/O, target resolution or filesystem change.

Microsoft's linked REPARSE_DATA_BUFFER definition supplies byte units, optional
terminator and flag semantics. The canonical name order and always-present
terminators are our encoding choice, not a requirement inferred for every native
packet. [write_reparse.c tests](../../tests/write_reparse.c) use independent literal
packets plus exact-capacity, one-past, UTF-16, alias and unchanged-error vectors.
They do not prove native creation, Reparse index maintenance, privilege behavior,
cross-volume ownership, WAL publication or recovery; those gates remain closed.

## Native NTFS compression

The admitted NTFS compression profile uses 16-cluster logical units and LZNT1.
Runlists may describe a full uncompressed unit, physical compressed clusters
followed by holes padding the logical unit, or an entirely sparse unit. Runs can
cross unit boundaries; a parser cannot equate one mapping-pairs entry with one
compression unit.

Within an LZNT1 chunk, literal and backward-reference tokens reconstruct at most
4096 bytes. Token length/distance partition changes with output position, and
overlapping references must be bounded. The original decoder validates chunk
framing, exact requested output and dictionary bounds before cache publication.
The run-level arrangement follows
[original compression/run research](https://flatcap.github.io/linux-ntfs/ntfs/concepts/data_runs.html).

Compressed DATA does not authorize writing raw decoded bytes into its stored
extents. A writer would need encoding, unit remapping, size/bitmap changes and
native recovery; this is outside the current ordinary write family.

### Private unit packet ownership

[The byte encoder](../../core/write_lznt1.c) and
[unit packet owner](../../core/write_lznt1_unit.c) prepare new content before any
physical allocation or media operation. The latter admits the reader's four
cluster sizes, 512 through 4096 bytes, and normalizes a full 16-cluster plaintext
unit. Logical EOF and initialized-prefix bytes are distinct inputs; bytes after
initialization, including the tail beyond EOF, are zero. The owned result is
empty, entirely sparse, raw full-unit plaintext, or a cluster-rounded encoded
prefix followed by a positive virtual-hole count. These are proposed relative
unit counts, not native tail highest-VCN or AllocatedSize decisions.

The current reader supplies all physical prefix bytes to the decoder. A packet
ending exactly at a cluster boundary needs no terminator; padding must contain a
complete two-byte zero header. An encoded length one byte short of the boundary
therefore needs an additional cluster. If that would occupy the full unit,
preparation selects raw storage, because a full physical unit has no compressed
representation signal. This conservative packet choice is locally tested reader
compatibility, not a claim about Windows' preferred encoder heuristic.

[Independent unit tests](../../tests/write_lznt1_unit.c) retain exact packet
lengths 510, 511, 512 and 7679 in an 8192-byte unit, direct raw/sparse oracles,
separate EOF/VDL cases, ownership/aliasing checks and allocation refusal. The
[owning contract](../LZNT1-UNIT-PREPARATION.md) records actual execution and native
boundaries. Before enabling mutation, native observations must resolve tail
mapping/size fields and truncate/regrow/VDL behavior; allocation provenance,
before images, WAL publication and fresh-owner recovery still need their higher
owning operation. No mapping or compressed-write admission follows from this API.

## WOF file-provider storage

**Implementation lifetime.** A complete offset-table validation may be retained
after successful stream publication, on its node and in an optional bounded
volume cache. Reuse binds the full sequence-bearing FILE reference, logical size,
stored size and algorithm to one immutable volume. Reopening still validates
provider/placeholder/backing metadata and each decoded chunk's local boundaries.
Failed opens publish no proof or replacement; a new volume starts cold. This is
an implementation reuse rule, not an additional NTFS field or a weaker table-ordering
contract. See [the lifetime and failure checks](../PERFORMANCE.md#mutation-planning-and-cross-node-wof)
and [independent cache tests](../../tests/wof_cache.c).

Our observed supported WOF payload is 16 bytes: outer version, provider,
provider version and algorithm, each a little-endian DWORD. It is not assumed
identical to every WOFAPI parameter structure. The admitted profile uses outer
version 1, file provider 2 and provider version 1.

Logical content is backed by a named DATA stream `WofCompressedData`. The
unnamed stream supplies a sparse placeholder/logical size under the qualified
profile. Microsoft's [WOF external interface](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_wof_external_info)
documents provider concepts; the exact stored shape and provenance are in
[WOF.md](../WOF.md).

| Stored algorithm | Identifier | Logical chunk |
| --- | --- | --- |
| XPRESS4K | 0 | 4096 bytes |
| LZX | 1 | 32768 bytes |
| XPRESS8K | 2 | 8192 bytes |
| XPRESS16K | 3 | 16384 bytes |

The backing table stores cumulative chunk boundaries. The first start is implicit
zero and the last end is the payload size; a nonempty stream with `n` chunks has
`n - 1` stored boundaries. Offsets use four bytes below 4-GiB logical size and
eight bytes at or above that threshold in our researched profile. Boundaries are
relative to the table's end. Complete table validation establishes ordering;
checking one chunk does not.

An equal stored/logical chunk size selects raw storage. Other chunks select the
qualified codec. The WOF/WIM LZX variant differs from a generic CAB/Delta LZX
header; using an unrelated decoder with the same algorithm name is insufficient.

The local Huffman fast paths preserve these framing boundaries: XPRESS refills
its word reservoir before reading an interleaved raw length extension; LZX may
preview a complete next word but advances the stored position only if the symbol
consumes it. A short final code does not require a padding word merely to index
the prefix table. [WOF.md](../WOF.md) records the exact variant and error contracts.

## Encryption and unknown providers

Encrypted/default-provider content can retain inspectable metadata and stream
names without a plaintext read capability. Independent plaintext ADS remain
separate objects. EFS decryption and mutation, WIM-provider resolution, cloud
hydration and arbitrary provider execution are not supplied by this core.

Unknown data must remain classified and bounded, then return an explicit
unsupported result where interpretation is required. Treating stored ciphertext
or provider bytes as ordinary user content would silently change semantics.

## Implementation and evidence

- Reparse snapshots: [reparse.c](../../core/reparse.c).
- NTFS compression: [lznt1.c](../../core/lznt1.c), [stream_read.c](../../core/stream_read.c).
- WOF geometry/provider: [wof.c](../../core/wof.c), [wof_stream.c](../../core/wof_stream.c).
- Codecs: [xpress.c](../../core/xpress.c), [lzx.c](../../core/lzx.c).
- Bounded match expansion and opcode search: [memory.c](../../core/memory.c).
- Independent provider files: [wof_file_fixtures.py](../../tests/wof_file_fixtures.py).
- Independent codec authors: [lzx_fixtures.py](../../tests/lzx_fixtures.py),
  [wof_fixtures.py](../../tests/wof_fixtures.py).
- Independent CPU packets and boundary checks: [cpu_fixtures.py](../../tests/cpu_fixtures.py),
  [cpu_codecs.c](../../tests/cpu_codecs.c), [cpu_memory.c](../../tests/cpu_memory.c).
- All Huffman widths/word offsets, truncations, mutations and frozen-reference
  comparison: [huffman_fixtures.py](../../tests/huffman_fixtures.py),
  [huffman.c](../../tests/huffman.c), [check_huffman.py](../../scripts/check_huffman.py).

Current reader/provider behavior and its native corpus limits are described in
[WOF.md](../WOF.md) and [ACCEPTANCE.md](../ACCEPTANCE.md). It does not qualify
encoded-content or reparse mutation.
