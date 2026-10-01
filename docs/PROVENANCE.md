# Code provenance

The NTFS core is an original implementation in this repository. Its design uses
published Microsoft descriptions, NTFS-3G's reverse-engineered format information,
independently authored fixtures and Apple SDK interfaces. NTFS-3G layout comments
are consulted for format facts; this is not a source-isolated clean-room process.
The sibling ext4 repository informed component boundaries and
development workflow. It is not an NTFS implementation dependency.

Primary references:

- [Microsoft MFT overview](https://learn.microsoft.com/en-us/windows/win32/devnotes/master-file-table)
- [Attribute header and mapping pairs](https://learn.microsoft.com/en-us/windows/win32/devnotes/attribute-record-header)
- [Attribute lists](https://learn.microsoft.com/en-us/windows/win32/devnotes/attribute-list-entry)
- [Multisector headers](https://learn.microsoft.com/en-us/windows/win32/devnotes/multi-sector-header)
- [Apple FSKit](https://developer.apple.com/documentation/fskit)
- [NTFS-3G release and source](https://github.com/tuxera/ntfs-3g/tree/2022.10.3)

Cross-checked format details include the 512-byte fixup stride, compression-unit
byte width, physical versus logical allocation, partial final compression units,
and the special attribute-list instance rule for continuation extents. Regression
fixtures must cover these independently, including cases not explained by the
Microsoft developer notes. Conflicting references require observed image evidence.

No Linux ntfs3, ntfs-3g or proprietary driver source is copied into or linked with
this implementation. Separately built ntfs-3g utilities may generate and inspect
test images under ignored vendor/artifacts paths; their GPL license applies to
those external tools. They are not shipped with the driver. This engineering
record is not a legal clean-room certification or a patent clearance opinion.

Any later third-party code requires a recorded origin, version, license and
retained notices before it enters product source. Keep product licensing,
entitlements, payment integration and diagnostics outside filesystem algorithms.
Before a future open-source release, the owner selects the license and reviews
all contributor and third-party rights; proprietary status changes only through
that explicit release decision.
