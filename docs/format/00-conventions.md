# 00 · Conventions and evidence

[Reference index](README.md) · [Next: volume geometry](01-volume.md)

## Five address spaces

NTFS discussions become ambiguous when every location is called an offset. Use
the containing object and units explicitly.

| Address | Unit and origin | Example |
| --- | --- | --- |
| Image offset | Bytes from the beginning of the backing image | A GPT partition starts partway through a raw disk image. |
| Volume offset | Bytes from the NTFS partition's beginning | `LCN × cluster_bytes` identifies a physical cluster. |
| Stream offset | Bytes from the beginning of one attribute value | MFT record `n` starts at `n × record_bytes` in `$MFT::$DATA`. |
| Record/attribute offset | Bytes from a specified record or attribute header | `value_offset` starts at the attribute, not at the FILE record. |
| VCN / LCN | Clusters in a stream / in the volume | VCN 3 may map to LCN 200, or to a sparse hole. |

An index's child VCN uses the unit selected by its geometry. An LSN is an encoded
log position with an epoch. Neither is a general physical byte address. Their
specific conversions are in [directories](06-directories.md) and
[`$LogFile`](09-logfile.md).

An offline partition export has image offset zero equal to volume offset zero.
That equivalence must not be carried over to a raw GPT disk or a virtual-disk
container. Container headers and partition bounds belong to acquisition and
transport, not to NTFS mapping pairs.

## Byte notation

All table offsets are hexadecimal bytes, relative to the object named above the
table. Widths are decimal bytes. Integers are little-endian unless stated
otherwise. `u16`, `u32` and `u64` mean unsigned integers of those widths. Signed
values and byte arrays are identified explicitly.

UTF-16 lengths count **16-bit code units** unless a field explicitly counts bytes.
A supplementary character occupies two units. Length-delimited disk names do not
require a trailing NUL. The original units are preserved independently of how a
native filesystem adapter presents a name.

Ranges use half-open notation: `[start, end)` contains `end - start` bytes. VCN
tables may show inclusive cluster ranges for convenience; a nonresident
attribute's `highest_vcn` is inclusive. Convert between the two deliberately.

## Checked arithmetic

For a region inside a containing size, validate:

```text
start <= containing_bytes
length <= containing_bytes - start
```

Do this before pointer arithmetic, reading or copying. Checking only
`start + length <= containing_bytes` permits integer wrap. Multiplications such
as `LCN × cluster_bytes` also need an overflow and volume-bound check.

Wire structures in [core/disk.h](../../core/disk.h) store fields as byte arrays.
This avoids host-endian and alignment assumptions. Production offsets derive
from `offsetof` and `sizeof`; documentation offsets are a readable rendering of
the named layout, not constants to paste into implementation code.

## Format rules and implementation policies

A byte width or a format relationship is different from a resource limit chosen
by this implementation. For example:

| Format relationship | Machlin policy or contract |
| --- | --- |
| A run header declares the integer widths following it. | Decode under bounded run, memory and operation-work budgets. |
| A FILE reference contains a record number and generation. | Reject stale references before publishing an owning node. |
| A log page can contain part of a record. | Accept only a completely proved history for recovery. |
| A record has update-sequence protection. | Guard new output against its actual old physical sector tails. |

Do not document a policy ceiling as the maximum NTFS can represent. The current
resource policies live in [ntfs.h](../../include/ntfs/ntfs.h),
[internal.h](../../core/internal.h) and
[OPERATION-BUDGETS.md](../OPERATION-BUDGETS.md).

## Timestamps and identities

NTFS timestamps use 100-nanosecond ticks from 1601-01-01 UTC. Our conversion uses:

```text
unix_ticks = ntfs_ticks - 116444736000000000
unix_seconds = unix_ticks / 10000000
```

Signed time conversion, range and subsecond handling still need their own checks.
The timestamp field is a disk value; native access-time and cache policies are a
separate contract. The tick convention is documented by
[Microsoft's FILETIME definition](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime).

Do not merge these identifiers:

| Identifier | Meaning |
| --- | --- |
| FILE reference | MFT slot plus the FILE generation |
| Attribute instance | One attribute record inside a FILE record |
| Security ID | Entry identifier in `$Secure` |
| USA marker | A protected transfer's sector-tail marker |
| LSN | Log position plus epoch |
| USN | Change-journal sequence; a different journal and contract |

## Reading evidence

Every example in this reference is either explicitly authored or linked to an
observation. Round-tripping our own encoder demonstrates internal consistency;
an independent byte oracle is stronger format evidence; Windows consumption and
recovery are additional behavior evidence. None alone is an observed hardware
power-cut result.

The source catalogue is [PROVENANCE.md](../PROVENANCE.md). Actual feature
qualification and its limits are in [ACCEPTANCE.md](../ACCEPTANCE.md). The
[research register](13-research-and-coverage.md) keeps ambiguous facts visible
without promoting them into supported behavior.
