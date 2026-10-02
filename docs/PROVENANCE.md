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
- [Self-relative security descriptors](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d)
- [SID packet representation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861)
- [ACL packet representation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/20233ed8-a6c6-4097-aafa-dd545ed24428)
- [ACE packet framing and trailing bytes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586)
- [Object ACE fields](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_allowed_object_ace)
- [Ordered discretionary access checks](https://learn.microsoft.com/en-us/windows/win32/secauthz/how-dacls-control-access-to-an-object)
- [AccessCheck inputs and exact granted mask](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-accesscheck)
- [File access rights and generic mappings](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights)
- [Token group attributes](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_groups)
- [Restricted token creation and two-check semantics](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken)
- [Impersonation token copies and explicit handle rights](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex)
- [Native token information and returned buffer lengths](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation)
- [Restricting-list detection](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-istokenrestricted)
- [OWNER RIGHTS and well-known identities](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers)
- [Volume read-only flag](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationa)
- [NTFS native volume geometry](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-ntfs_volume_data_buffer)
- [Native file information and hard-link identity](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-by_handle_file_information)
- [Native stream enumeration](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-win32_find_stream_data)
- [Apple FSKit](https://developer.apple.com/documentation/fskit)
- [Microsoft per-directory case semantics](https://learn.microsoft.com/en-us/windows/wsl/case-sensitivity)
- [Original Keramics NTFS format research](https://keramics.github.io/ntfs.html)
- [Original MFT Browser standard-information field template](https://github.com/kacos2000/MFT_Browser/blob/master/NTFS%20-%20MFT%20FILE%20Record.tpl)
- [NTFS-3G release and source](https://github.com/tuxera/ntfs-3g/tree/2022.10.3)
- [NTFS-3G layout facts](https://github.com/tuxera/ntfs-3g/blob/2022.10.3/include/ntfs-3g/layout.h)
- [Original Linux-NTFS Secure format notes](https://flatcap.github.io/linux-ntfs/ntfs/files/secure.html)
- [Original Linux-NTFS descriptor format notes](https://flatcap.github.io/linux-ntfs/ntfs/attributes/security_descriptor.html)
- [Original Linux-NTFS MFT and reserved-record notes](https://flatcap.github.io/linux-ntfs/ntfs/files/mft.html)
- [Original Linux-NTFS filename lifetime notes](https://flatcap.github.io/linux-ntfs/ntfs/attributes/file_name.html)
- [Original Linux-NTFS root anchor notes](https://flatcap.github.io/linux-ntfs/ntfs/files/dot.html)
- [Original Linux-NTFS bad-cluster format notes](https://flatcap.github.io/linux-ntfs/ntfs/files/badclus.html)

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

The security decoder uses MS-DTYP's self-relative offsets, little-endian fields,
six-byte SID authority and bounded subauthority vector. It preserves ACE order,
optional object GUID spans and opaque callback/unknown payloads. Extra non-callback
ACE bytes are ignored as required by MS-DTYP, rather than rejected as an invented
format restriction. The implementation and independent vector authors are
original. It does not use a GPL security parser or establish Windows/native access
decisions. The collector uses documented Win32 volume, identity and stream APIs;
fixed-width ctypes layouts and serialization pass local tests, while actual
Windows calls remain a separate required observation.

The resolver uses reverse-engineered view-index/SDS format facts, not imported
filesystem algorithms. Raw external exports confirm ID ordering, hash/ID
ordering, locator fields, duplicates and the mathematical rotate-three/add-DWORD
checksum. The old Secure page mislabels SII sorting and its descriptor-body
offset; an old descriptor note incorrectly says per-file storage is always
resident. Observed NTFS-3G images establish both indexed storage and nonresident
per-file descriptors. Original search, ownership, bounds and fixtures remain
repository-owned; the failed oracle runs are retained rather than converted to
passes. Actual Windows storage and authorization qualification remain required.

The discretionary evaluator uses Microsoft's ordered DACL, exact file mapping,
SID/group attribute and restricted-token descriptions. It is original code;
its independent per-right test oracle is not a port of a filesystem/security
implementation. Owner control grants and OWNER RIGHTS are a separate policy from
data-read grants. Restricted-owner combinations remain explicitly unsupported
pending native observations; ambiguous pseudocode is not used to invent grants.
SACL/integrity/privilege/advanced ACE policy and native enforcement remain open.
No native AccessCheck comparisons have executed at this checkpoint.
The observation collector, SDK layouts, diagnostic transport and report tests are
also original. Their interface facts come from Microsoft's token and AccessCheck
documentation. A synthetic provider tests acquisition/failure/report contracts;
it is not treated as an independent Windows decision oracle. See ACCESS-ORACLE.md.

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

Directory case policy uses published standard-information field observations:
disabled version numbering, a low-byte case indicator and separate upper storage
bytes. CASE-POLICY.md separates those facts from the original core/adapter
implementation and the remaining Windows/native validation. Microsoft's WSL
extended-attribute interface is not presumed to be literal NTFS EA storage.
Synthetic policy images and component tests qualify local interpretation only.

The consistency diagnostic uses Microsoft's two allocation planes and complete
attribute-list membership rule, original Linux-NTFS filename/root/reserved-slot
facts, and independently exported metadata. NTFS-3G's layout comments identify
the observed but uninterpreted record flag `0x0004`; no behavior is inferred from
it. Independent mkntfs templates narrow reserved-record handling to inert zero-link
storage, and `$BadClus::$Bad` exports confirm implicit holes and volume-sized
virtual allocation. The original bounded mapping parser is reused for diagnostic
bad-cluster intervals. It never reads bad sectors and imports no external
filesystem algorithm. VALIDATION.md separates observed facts, original graph/sort/ownership
algorithms and unsupported DOS/listed-bad-cluster/store/recovery work. The oracle
compares standalone raw bitmap exports, never links NTFS-3G into the product.
