# 01 · Volume geometry

[Reference index](README.md) · [Previous](00-conventions.md) · [Next](02-records-and-fixups.md)

The boot record gives enough geometry to locate the first MFT record. That record
then supplies the actual stream mapping; the boot MFT LCN does not imply that the
entire MFT is contiguous.

![Bootstrap from partition bounds through the MFT's own mapping](diagrams/bootstrap.svg)

[Diagram source](diagrams/bootstrap.mmd)

## Boot record

Offsets below are relative to the NTFS volume's beginning. This table describes
the fields used by our bootstrap, rather than every legacy BPB or bootstrap-code
byte. The named layout is `ntfs_disk_boot` in [disk.h](../../core/disk.h).
The geometry follows [original Linux-NTFS boot research](https://flatcap.github.io/linux-ntfs/ntfs/files/boot.html).

| Offset | Width | Field | Interpretation |
| --- | --- | --- | --- |
| `0x00` | 3 | `jump` | Bootstrap instruction bytes |
| `0x03` | 8 | `oem` | The eight bytes `NTFS    ` |
| `0x0B` | 2 | `sector_size` | Bytes per sector |
| `0x0D` | 1 | `sectors_per_cluster` | Sector count per cluster |
| `0x28` | 8 | `sectors` | Volume sector count |
| `0x30` | 8 | `mft_lcn` | Location of `$MFT`'s first cluster |
| `0x38` | 8 | `mirror_lcn` | Location of `$MFTMirr`'s first cluster |
| `0x40` | 1 | `record_code` | Signed FILE-record size code; three following bytes are separate storage |
| `0x44` | 1 | `index_code` | Signed index-record size code; three following bytes are separate storage |
| `0x48` | 8 | `serial` | Volume serial number |
| `0x1FE` | 2 | `signature` | Little-endian `0xAA55`, stored as `55 AA` |

Older tables sometimes display the size code and its following three bytes as a
single four-byte row. The decoder interprets the first byte as the signed size
code; it does not use a native 32-bit signed multiplication.

## Derive the sizes

For the ordinary supported sector/cluster encoding:

```text
cluster_bytes = sector_bytes × sectors_per_cluster
volume_bytes  = sector_count × sector_bytes
cluster_count = floor(sector_count / sectors_per_cluster)
```

For a FILE or index size code interpreted as signed `c`:

```text
c > 0: record_bytes = c × cluster_bytes
c < 0: record_bytes = 2^(-c)
c = 0: invalid
```

**Authored example:** sector size 512, eight sectors per cluster, FILE code
`F6` and index code `01` give a 4096-byte cluster, 1024-byte FILE record and
4096-byte index record. Sector, cluster, FILE and log-page sizes remain distinct.

Machlin checks representable sizes, powers of two, containing image bounds and
its named resource ceilings. An otherwise meaningful NTFS geometry outside a
qualified policy returns an explicit refusal. The general reader's geometry
does not widen the current writer's 512/4096/1024 profile.

## Bootstrap and the mirror

The bootstrap reads the FILE record at `mft_lcn × cluster_bytes`, verifies its
multi-sector protection, and resolves the unnamed DATA attribute that represents
the MFT. Subsequent record `n` is addressed at stream offset
`n × record_bytes`, translated through that stream's checked mapping pairs.

`$MFTMirr` provides a redundant critical prefix, not a duplicate of every file's
MFT record. Our validator checks the required four-record prefix and its boot
anchor. See [system files](08-system-files.md) for the relationship between the
MFT stream, its bitmap and the mirror. Mirror geometry beyond the qualified
writer profile must not be inferred from this four-record check.

## Volume information

NTFS version and volume state come from `$Volume::$VOLUME_INFORMATION`, not from
the OEM string. Its value has this common prefix:

| Offset | Width | Field |
| --- | --- | --- |
| `0x00` | 8 | Reserved bytes |
| `0x08` | 1 | Major NTFS version |
| `0x09` | 1 | Minor NTFS version |
| `0x0A` | 2 | Volume flags |

The dirty bit is `0x0001`. Our ordinary immutable mount refuses dirty state and
also refuses other unsupported nonzero flags. An unknown bit is not evidence
that Windows requires repair; conversely, a zero volume flag is not proof of a
quiet, recoverable `$LogFile`. These are independent admission checks.

## Implementation and evidence

- Bootstrap and admission: [mount.c](../../core/mount.c).
- Wire definitions: [disk.h](../../core/disk.h).
- Independent boot geometry: [boot_fixtures.py](../../tests/boot_fixtures.py).
- Mirror invariants: [mirror_fixtures.py](../../tests/mirror_fixtures.py).
- Volume-state refusals: [volume_flags.c](../../tests/volume_flags.c).

Published geometry and synthetic boundary tests establish the named layout and
our admission behavior. Installed writable geometry and native recovery remain
the narrower profiles listed in [ACCEPTANCE.md](../ACCEPTANCE.md).
