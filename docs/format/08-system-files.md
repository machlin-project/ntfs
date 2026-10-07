# 08 · System files and allocation

[Reference index](README.md) · [Previous](07-security.md) · [Next](09-logfile.md)

NTFS stores most metadata as files. Their fixed bootstrap identities and attribute
roles matter more than a displayed name. Microsoft's
[MFT description](https://learn.microsoft.com/en-us/windows/win32/devnotes/master-file-table)
documents the reserved first sixteen slots and principal allocation files.

## Metadata map

| MFT slot | File | Principal role |
| --- | --- | --- |
| 0 | `$MFT` | Unnamed DATA contains FILE records; unnamed BITMAP allocates slots |
| 1 | `$MFTMirr` | Redundant critical MFT prefix |
| 2 | `$LogFile` | LFS and NTFS client recovery journal |
| 3 | `$Volume` | Version, volume state and label |
| 4 | `$AttrDef` | Attribute definitions and constraints; full interpretation remains open |
| 5 | Root directory | Bootstrap root identity and namespace |
| 6 | `$Bitmap` | Unnamed DATA contains volume-cluster allocation bits |
| 7 | `$Boot` | Boot data and geometry anchor |
| 8 | `$BadClus` | Named `$Bad` storage describes bad-cluster ownership |
| 9 | `$Secure` | Shared security descriptors and their indexes |
| 10 | `$UpCase` | Volume-owned UTF-16 uppercase mapping |
| 11 | `$Extend` | Parent of additional metadata such as quota and change-journal files |

Slots below 16 remain reserved even when an individual slot is unused. Files
under `$Extend` require checked namespace ownership, not a guessed fixed record
number. The table follows [original MFT research](https://flatcap.github.io/linux-ntfs/ntfs/files/mft.html)
and the named identities in [disk.h](../../core/disk.h).

This bootstrap reservation does not establish Windows's ordinary allocation
policy for every later slot. The older MFT research describes slots 16–23 as
unused reserved space, while Microsoft's version-3 description reserves the
first sixteen. Our local planner excludes slots below 16; native qualification
of reuse in the 16–23 range remains a separate question in
[the research register](13-research-and-coverage.md).

## Three allocation maps

![Cluster, MFT-slot and index-block allocation are separate domains](diagrams/allocation.svg)

[Diagram source](diagrams/allocation.mmd)

| Map | Location | One bit allocates |
| --- | --- | --- |
| Volume bitmap | `$Bitmap::$DATA` | One volume cluster / LCN |
| MFT bitmap | `$MFT::$BITMAP` | One MFT FILE slot |
| Index bitmap | Owning file's `$BITMAP` with the index name | One index-allocation block slot |

Within a byte, bit `n % 8` describes position `n`; the byte index is `n / 8`.
The containing map's object determines what `n` means. An index block can span
several clusters, so its bitmap cannot be indexed by physical LCN.

Allocation maps prove occupancy. Stream mappings and the complete validator
establish which object owns occupied storage. A set volume bit does not identify
a file; an unset MFT bit does not prove the old slot's bytes are valid for reuse.

## MFT growth and reuse

Allocating a FILE slot can require growing `$MFT::$DATA`, its mapping and its
bitmap, then initializing new protected FILE containers. That growth itself
consumes clusters recorded in the volume bitmap. Changing the MFT mapping is
especially sensitive because subsequent FILE addresses depend on it.

Generation reuse must invalidate old full references. A retired, correctly
framed FILE can supply its next sequence; torn or contradictory retirement
requires refusal or an owning recovery solution. The first sixteen slots are
outside ordinary file allocation.

An MFT zone or allocation locality preference is not an additional allocation
bitmap. Do not infer cluster ownership from a zone or from apparent physical
contiguity. Full and fragmented-space cases need the same correctness rules.

## Retiring storage safely

In one prepared operation, newly allocated storage must not be selected from
clusters still referenced by the pre-operation state merely because another
planned change frees them. Until the transaction's commit/recovery decision,
the old object can still be authoritative.

The planner therefore distinguishes original occupancy from planned occupancy.
After a complete durable retirement and checkpoint decision, later operations
can reuse the storage. This distinction is necessary for loser recovery and
also for open-object lifetime; an open unlinked object cannot release live
storage solely because its last pathname disappeared.

## Other critical metadata

`$UpCase` contains 65,536 UTF-16 mapping entries, 131,072 bytes. Filename collation
uses these volume-owned entries rather than the host's locale tables.

`$BadClus:$Bad` has a special ownership interpretation. Its implicit holes are
not a license for ordinary DATA to ignore sparse framing. Our validator includes
bad-cluster reservations in physical ownership accounting.

`$UsnJrnl` is the change journal, distinct from `$LogFile`. The current bounded
writer refuses an active unsupported change-journal profile rather than silently
pretending to maintain it. Hibernation and unsupported volume features also
prevent writable admission. Detailed extended-metadata coverage is recorded in
[chapter 13](13-research-and-coverage.md).

## Implementation and evidence

- MFT bootstrap and stream: [mount.c](../../core/mount.c), [stream.c](../../core/stream.c).
- Metadata-only bad-cluster mappings: [stream_mapping.c](../../core/stream_mapping.c).
- Whole-volume ownership and bitmaps: [validate.c](../../core/validate.c),
  [VALIDATION.md](../VALIDATION.md).
- Independent ownership fixtures: [validation_fixtures.py](../../tests/validation_fixtures.py).
- Bad-cluster cases: [bad_clusters_fixtures.py](../../tests/bad_clusters_fixtures.py).
- Writer admission: [write_recover.c](../../core/write_recover.c), [WRITES.md](../WRITES.md).

The ordinary mutation batch locally exercises MFT growth, index growth,
fragmentation, ENOSPC and generation reuse. Complete native WAL/recovery and
open-unlink lifetime are still required before these become product write support.
