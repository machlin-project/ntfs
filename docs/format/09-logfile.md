# 09 · `$LogFile`

[Reference index](README.md) · [Previous](08-system-files.md) · [Next](10-recovery-and-writing.md)

`$LogFile` contains two related formats: LFS frames opaque client records into a
circular journal, and the NTFS client gives those payloads metadata-update and
checkpoint meaning. Valid LFS bytes are not automatically an executable NTFS
transaction.

The layout basis is [original Linux-NTFS `$LogFile` research](https://flatcap.github.io/linux-ntfs/ntfs/files/logfile.html).
[Maxim Suhanov's original LFS research](https://dfir.ru/2019/02/16/how-the-logfile-works/)
explains version boundaries and native observations. Our decoders and original
Windows captures resolve qualified details; unresolved meanings remain in
[the research register](13-research-and-coverage.md).

## Three version domains

| Version | Stored in | Selects |
| --- | --- | --- |
| NTFS 3.0/3.1 | `$VOLUME_INFORMATION` | Filesystem metadata profile |
| LFS 1.1 or 2.0 | RSTR page | Journal framing and copy-area layout |
| NTFS client 0.0 or 1.0 | Client restart payload | NTFS restart-table entry layouts |

The current qualified write family uses LFS 1.1. Read-only format support for
LFS 2.0 does not add a 2.0 writer or generic recovery.

## Physical arrangement

![Two restart roots, copy storage and circular records](diagrams/log-layout.svg)

[Diagram source](diagrams/log-layout.mmd)

Legacy LFS 1.1 has two RSTR pages, two tail-copy pages, then circular record
pages. Restart and log page sizes are declared separately. The supported modern
4-KiB LFS 2.0 profile has 32 fast-copy slots after its restart pages. Do not locate
circular storage using the legacy two-slot formula for a modern source.

A tail page's common `copy_value` is its target **logical `$LogFile` byte offset**.
That is not a volume LCN or physical image offset. The nonresident `$LogFile`
stream still needs a checked mapping to physical storage.

## RSTR page and restart area

The common RSTR prefix is 30 bytes, not a required 32-byte C structure. Offsets
are relative to the protected/restored page as appropriate:

| Offset | Width | Field |
| --- | --- | --- |
| `0x00` | 8 | MST magic/USA fields; magic `RSTR` |
| `0x08` | 8 | Chkdsk-associated LSN |
| `0x10` | 4 | System/restart page bytes |
| `0x14` | 4 | Log page bytes |
| `0x18` | 2 | Restart-area offset |
| `0x1A` | 2 | LFS minor version |
| `0x1C` | 2 | LFS major version |

The declared restart area begins elsewhere in the page. Its common prefix is
48 bytes, with offsets relative to the **area**:

| Offset | Width | Field |
| --- | --- | --- |
| `0x00` | 8 | `current_lsn` |
| `0x08` | 2 | Client count |
| `0x0A` | 2 | Free-client-list head |
| `0x0C` | 2 | In-use-client-list head |
| `0x0E` | 2 | Flags, including clean-dismount `0x0002` |
| `0x10` | 4 | Sequence-number bits |
| `0x14` | 2 | Complete restart-area length |
| `0x16` | 2 | Client-array offset relative to the area |
| `0x18` | 8 | Logical journal file bytes |
| `0x20` | 4 | Current record's client-data bytes |
| `0x24` | 2 | LFS record-header bytes |
| `0x26` | 2 | Data offset within a log page |
| `0x28` | 4 | Open/revision-associated field; retain its qualified interpretation |
| `0x2C` | 4 | Remaining common-prefix storage |

Each 160-byte client entry has oldest LSN, client-restart LSN, list links,
sequence, name byte count and fixed name capacity. The active NTFS identity
requires the selected client index, its sequence, in-use membership and exact
UTF-16 name. A same-index entry from another lifetime is not interchangeable.

`CurrentLsn` identifies restart-time state. Later durable records can exist.
Neither that scalar, the clean hint, nor the largest raw LSN observed while
scanning proves the current completed endpoint. Root selection checks whole
declared restart areas and competing copies; conflict cannot be hidden by
choosing the first decodable page.

## LSN arithmetic

An LSN combines epoch and eight-byte-unit logical file offset. With
`offset_bits = 64 - sequence_bits`:

```text
epoch       = lsn >> offset_bits
file_offset = (lsn & ((1 << offset_bits) - 1)) << 3
page_offset = floor(file_offset / log_page_bytes) × log_page_bytes
record_offset = file_offset - page_offset
```

The declared split must represent the journal geometry. A nonzero record LSN
must identify room for a complete header in circular storage, not a restart,
copy slot or page header. Sequence exhaustion requires refusal; it cannot invent
a wrapped representable successor.

**An LSN points to a record's start.** A spanning record may finish on another
page, even after circular wrap. Reserving a subsequent operation from the start
page alone can overwrite its continuation. Placement requires the verified
completed endpoint or canonical successor position.

## RCRD page

The common page header is 40 bytes. Offsets are relative to the page:

| Offset | Width | Field | Interpretation |
| --- | --- | --- | --- |
| `0x00` | 8 | MST prefix | Magic `RCRD`, USA location/count |
| `0x08` | 8 | `copy_value` | Last-start LSN in circular pages; target offset in legacy tails |
| `0x10` | 4 | `flags` | Record-end `0x00000001`; qualified client-restart flag `0x00000002` |
| `0x14` | 2 | `page_count` | Pages in the described I/O transfer |
| `0x16` | 2 | `page_position` | One-based position in that transfer |
| `0x18` | 2 | `next_record_offset` | Declared completed/free boundary |
| `0x1A` | 6 | Reserved | Separate from the endpoint LSN |
| `0x20` | 8 | `last_end_lsn` | Latest completed record ending on this page |

The USA follows in declared bounded space. Our familiar 4-KiB profile has nine
USA words and data beginning at byte 64. Supported LFS 2.0 fast framing adds a
DWORD target after the canonical USA/padding; it is not the legacy `copy_value`
interpretation.

`page_count` and `page_position` describe physical transfers, **not the number of
pages in a logical record**. A spanning record can cross several transfers. Its
byte extent determines assembly. An unfinished segment can extend beyond the
declared completed prefix; its final completed segment must fit that prefix.

Our qualified continuation fixtures leave an unfinished segment's boundary at
the current data/header position and carry no unrelated end LSN. Historical
variants of zero boundary and native multi-page publication need separately
recorded evidence; the scalar page decoder's tolerance does not widen the
owning-history contract.

## LFS record header

The common record header is 48 bytes. The restart area may declare a longer
header, which the read assembler handles separately. Offsets below are relative
to the logical, USA-restored and assembled record:

| Offset | Width | Field |
| --- | --- | --- |
| `0x00` | 8 | This LSN |
| `0x08` | 8 | Previous LSN |
| `0x10` | 8 | Undo-next LSN |
| `0x18` | 4 | Client payload byte length |
| `0x1C` | 2 | Client sequence |
| `0x1E` | 2 | Client index |
| `0x20` | 4 | Record type: client update 1, client restart 2 |
| `0x24` | 4 | Transaction key |
| `0x28` | 2 | Flags: multi-page 1, deleting 2, adding 4 in our admitted framing |
| `0x2A` | 6 | Reserved storage |

Links must precede the record, remain in the proved retained history and bind the
correct client/transaction lifetime. A reused transaction key alone is not a
stable transaction identity. Flag framing is separate from interpreting NTFS
transaction state.

## NTFS update payload

The NTFS update common prefix is 32 bytes. The stored form reserves one 8-byte
LCN slot even when the declared LCN count is zero. Offsets are relative to the
**client payload**, excluding the LFS record header:

| Offset | Width | Field |
| --- | --- | --- |
| `0x00` | 2 | Redo operation |
| `0x02` | 2 | Undo operation |
| `0x04` | 2 | Redo offset |
| `0x06` | 2 | Redo byte length |
| `0x08` | 2 | Undo offset |
| `0x0A` | 2 | Undo byte length |
| `0x0C` | 2 | Target attribute's physical restart-table key |
| `0x0E` | 2 | LCN count |
| `0x10` | 2 | Record offset |
| `0x12` | 2 | Attribute offset |
| `0x14` | 2 | Cluster-block/sector index |
| `0x16` | 2 | Qualified target flags / otherwise opaque field |
| `0x18` | 8 | Target VCN |
| `0x20` | `8 × count` | Declared LCN vector; reserve at least one stored slot |

Redo/undo offsets are eight-byte aligned and independently bounded. They can
share stored bytes in original packets. Unused LCN capacity and live pointer
fields are not addresses to trust. Physical execution additionally needs OAT
identity, current mapping, volume bounds and permitted operation semantics.

An observed native compensation form can retain an undo length with its offset
at the payload's endpoint while storing only redo bytes. Our decoder preserves
that inactive declaration separately and exposes an empty safe undo span. It
does not generally excuse out-of-bounds update spans.

## Native operation vocabulary

These numbers describe the researched wire vocabulary. Only a qualified subset
is executable by our writer/recovery owner.

| Code | Operation | Code | Operation |
| --- | --- | --- | --- |
| `0x00` | Noop | `0x12` | Set index-entry VCN in allocation |
| `0x01` | Compensation | `0x13` | Update filename in root |
| `0x02` | Initialize FILE record | `0x14` | Update filename in allocation |
| `0x03` | Deallocate FILE record | `0x15` | Set bitmap bits |
| `0x04` | Write end of FILE record | `0x16` | Clear bitmap bits |
| `0x05` | Create attribute | `0x17` | Hot fix |
| `0x06` | Delete attribute | `0x18` | End top-level action |
| `0x07` | Update resident value | `0x19` | Prepare transaction |
| `0x08` | Update nonresident value | `0x1A` | Commit transaction |
| `0x09` | Update mapping pairs | `0x1B` | Forget transaction |
| `0x0A` | Delete dirty clusters | `0x1C` | Open nonresident attribute |
| `0x0B` | Set new attribute sizes | `0x1D` | Open-attribute table dump |
| `0x0C` | Add index entry to root | `0x1E` | Attribute-name dump |
| `0x0D` | Delete index entry from root | `0x1F` | Dirty-page table dump |
| `0x0E` | Add index entry to allocation | `0x20` | Transaction table dump |
| `0x0F` | Delete index entry from allocation | `0x21` | Update record data in root |
| `0x10` | Write end of index buffer | `0x22` | Update record data in allocation |
| `0x11` | Set index-entry VCN in root | — | — |

Our Windows-created historical capture contains original witnesses for allocation,
FILE initialization/deallocation, attribute changes, size/mapping updates,
directory changes and bitmap operations. Those observations help design a native
program; they do not establish replay semantics for every opcode or arbitrary
full-snapshot substitution.

## Client checkpoint and restart tables

The NTFS client restart common prefix is 64 bytes: client version, analysis LSN,
four table LSNs, and four table byte lengths. The remaining extension is retained
under its qualified profile. Native lengths and opaque extension storage must
not be normalized merely to match a convenient struct size.

The four tables describe open attributes, names, dirty pages and transactions.
A restart-table header is 24 bytes. Target and transaction keys are physical
byte positions in the qualified table layout, not host array pointers. Client
version selects entry size and meaning; our modern OAT entry is 40 bytes, while
the admitted older entry is 44 bytes. Dirty-page and transaction entries likewise
need their own version and complete membership checks.

The checkpoint roots, exact dump packets, names, target keys and transaction
links have to agree as a complete owned snapshot. Resolving one table or one
record cannot decide winner/loser state or permit history truncation.

## Implementation and evidence

- Named fields: [disk.h](../../core/disk.h), [logfile_tables_disk.h](../../core/logfile_tables_disk.h).
- Scalar framing: [logfile.c](../../core/logfile.c).
- Copies, exact assembly and proved history: [logfile_source.c](../../core/logfile_source.c).
- Pure private encoding: [logfile_encode.c](../../core/logfile_encode.c).
- Table/checkpoint binding: [logfile_tables.c](../../core/logfile_tables.c),
  [checkpoint.c](../../core/checkpoint.c).
- Independent continuation/wrap authors: [logfile_history_fixtures.py](../../tests/logfile_history_fixtures.py).
- Current detailed contracts: [LOGFILE.md](../LOGFILE.md),
  [RECOVERY-INPUTS.md](../RECOVERY-INPUTS.md).

These components supply different degrees of format and ownership evidence.
The narrower native write/recovery family is described in the next chapter.
