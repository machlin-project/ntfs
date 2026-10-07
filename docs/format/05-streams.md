# 05 · Streams and sizes

[Reference index](README.md) · [Previous](04-mapping-pairs.md) · [Next](06-directories.md)

A DATA attribute is a stream. A file can have unnamed default content and several
named streams, each with independent storage and sizes. The stream's logical
content is not necessarily equal to the bytes physically present in its clusters.

## Three lengths

The first nonresident extent supplies allocated length, logical size and
initialized length. Their field map is in [attributes](03-attributes.md).

| Length | Question it answers |
| --- | --- |
| Logical size / EOF | Where does the readable stream end? |
| Initialized / valid data length | Which prefix has initialized content? |
| Allocation | How much storage is described or physically charged under this storage profile? |

For ordinary uncompressed, nonsparse storage, initialized length is at most EOF,
and allocation covers EOF in whole clusters. Sparse and compressed streams need
their separate logical-coverage and physical-allocation interpretation; do not
apply the ordinary inequality to their actual physical storage count.

![Initialized content, zero-readable tail, EOF and cluster allocation](diagrams/stream-sizes.svg)

[Diagram source](diagrams/stream-sizes.mmd)

Within `[initialized, EOF)`, ordinary reads return zero even if old physical
storage contains other bytes. At EOF, reads stop. A sparse hole also returns zero
without disk I/O. These rules prevent an allocated but uninitialized region from
exposing old storage contents. Microsoft's
[SetFileValidData documentation](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfilevaliddata)
explains why initialized length is a distinct security-sensitive concept.

**Authored example:** with EOF 6000, initialized length 4500 and ordinary
allocation 8192, a read at 4400 requesting 2000 bytes returns 1600 bytes: 100 from
initialized content followed by 1500 zeroes. The request does not expose bytes
6000–6399 or allocation slack.

## Resident content

Resident DATA is stored in the FILE record. Its value length is the logical
length and all stored value bytes are initialized. The record's own allocated
container size is not DATA allocation. Growing a resident stream may require
moving its content to nonresident storage because other attributes consume the
same FILE capacity.

That conversion couples content, mapping, cluster bitmap, sizes, FILE protection
and recovery. Shrinking a nonresident stream may permit a resident representation
again, but representation changes are a writer decision, not a property inferred
from the requested size alone.

## Standard information and duplicated metadata

SI is the object's standard-information value. Its common value is 48 bytes,
with a 24-byte extension in the admitted modern form. Offsets below are relative
to the **SI value**, not the attribute record. Microsoft describes its object
role in [STANDARD_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/devnotes/standard-information);
the named byte map is `ntfs_disk_standard` plus `ntfs_disk_standard_extension`.

| Offset | Width | Field |
| --- | --- | --- |
| `0x00` | 8 | Creation time |
| `0x08` | 8 | Modification time |
| `0x10` | 8 | FILE/metadata change time |
| `0x18` | 8 | Access time |
| `0x20` | 4 | File attributes |
| `0x24` | 4 | Maximum versions |
| `0x28` | 4 | Version / qualified directory-policy overlay |
| `0x2C` | 4 | Class ID |
| `0x30` | 4 | Owner/quota ID in the modern extension |
| `0x34` | 4 | Security ID in the modern extension |
| `0x38` | 8 | Quota charge in the modern extension |
| `0x40` | 8 | USN in the modern extension |

SI times and DATA sizes are used explicitly for ordinary stat. FILE_NAME values
contain duplicate cached metadata with a separate update lifetime. Attribute
storage flags, SI file flags, FILE-header flags and native API flags also belong
to different domains; sharing a word such as "compressed" does not make their
numeric values interchangeable.

## Named streams

Attribute name and directory name are separate dimensions:

```text
directory name: report.txt
default stream: $DATA with no attribute name
named stream:  $DATA with UTF-16 name Zone.Identifier
```

Win32 presents these through syntax such as `report.txt:Zone.Identifier:$DATA`.
The on-disk name is length-delimited; it is not a colon-separated pathname.
Microsoft documents [file streams](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams).

Opening one named stream must not require decoding unrelated default content.
For example, a plaintext named stream can be independently readable while the
default stream uses an unsupported encryption or provider profile. Changing the
default DATA does not authorize dropping or rewriting other attributes.

## Grow, shrink and write beyond EOF

The ordinary mutation batch must preserve these relationships:

| Operation | Required visible result |
| --- | --- |
| Grow without writing | New readable bytes are zero; old initialized content remains intact. |
| Write beyond EOF | The gap is zero-visible; written bytes and the new EOF become visible together with complete metadata. |
| Shrink | Bytes beyond the new EOF become inaccessible; retirement of storage remains recoverable. |
| Regrow after shrink | Retired bytes do not reappear as old data. |
| Resident → nonresident | Prefix content and independent attributes survive; mapping and bitmap agree. |

User DATA rollback guarantees are distinct from metadata atomicity. The current
initialized overwrite family does not promise all-or-nothing user-data rollback.
Resident DATA participates in FILE metadata logging in its qualified family.
The exact durability protocol is in [recovery and writing](10-recovery-and-writing.md).

## Implementation and evidence

- Storage lifetime: [stream.c](../../core/stream.c).
- Mapping ownership: [stream_mapping.c](../../core/stream_mapping.c).
- Readable ranges and zero boundaries: [stream_read.c](../../core/stream_read.c).
- Independent stream catalogue: [catalog.c](../../core/catalog.c).
- Size and timestamp presentation: [node.c](../../core/node.c).
- Existing DATA-only owner: [overwrite.c](../../core/overwrite.c),
  [DATA-OVERWRITE.md](../DATA-OVERWRITE.md).
- Resident write oracles: [write_resident_fixtures.py](../../tests/write_resident_fixtures.py).
- Qualified journal behavior: [NATIVE-WRITE-JOURNAL.md](../NATIVE-WRITE-JOURNAL.md).

Grow/shrink/conversion behavior is part of the active ordinary mutation batch.
Local planned-image checks do not yet qualify native durable allocation or FSKit
resize. Named-stream, sparse, compressed and encrypted writes remain separate
contracts.
