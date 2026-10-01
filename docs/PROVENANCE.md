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
- [Independent file streams](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams)
- [Stream names](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/5953f072-b28c-4fbf-ae50-09b0173317b9)
- [Directory and file stream model](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c54dec26-1551-4d3a-a0ea-4fa40f848eb3)
- [Multisector headers](https://learn.microsoft.com/en-us/windows/win32/devnotes/multi-sector-header)
- [Reparse tags](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c8e77b37-3909-4fe6-a4ea-2b9d423b1ee4)
- [Symbolic-link buffers](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/b41f1cbf-10df-4a47-98d4-1c52a833d913)
- [Mount-point buffers](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/ca069dad-ed16-42aa-b057-b6b207f447cc)
- [Reparse size restrictions](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points)
- [Third-party GUID buffers](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_reparse_guid_data_buffer)
- [Apple FSKit](https://developer.apple.com/documentation/fskit)
- [NTFS-3G release and source](https://github.com/tuxera/ntfs-3g/tree/2022.10.3)

Cross-checked format details include the 512-byte fixup stride, compression-unit
byte width, physical versus logical allocation, partial final compression units,
the special attribute-list instance rule for continuation extents, the requirement
that the list's own mapping fit its base record, and filename collation's raw
UTF-16 tie-break after $UpCase. NTFS-3G's `MFT_RECORD_OLD` layout identifies the
common FILE header separately from the optional NTFS 3.1 fields; fixtures cover
both layouts. Microsoft stream documentation establishes
independent compression/encryption state and named data on directories. Regression
fixtures must cover these independently, including cases not explained by the
Microsoft developer notes. Conflicting references require observed image evidence.
The explicit bootstrap, B-tree bounds, stream lifetime and decoder algorithms
are repository-owned implementations. Synthetic vectors use independently
authored named fields and expected bytes; Windows corpus qualification remains
separate from both those vectors and the external NTFS-3G utility comparisons.

The reparse decoder uses MS-FSCC's tag definitions, relative name offsets and
symlink flags. Microsoft documents the complete 16-KiB buffer limit and separate
third-party GUID envelope. NTFS-3G's `REPARSE_POINT` layout note confirms that the
attribute may be resident or nonresident. No NTFS-3G reparse implementation was
used or copied. The ownership, validation and copying code is original; synthetic
buffers and storage layouts do not establish Windows-authored reparse acceptance.

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
