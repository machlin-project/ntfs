# Code provenance

The NTFS core is an original implementation in this repository. Its design uses
published Microsoft descriptions, NTFS-3G's reverse-engineered format information,
independently authored fixtures and Apple SDK interfaces. NTFS-3G layout comments
are consulted for format facts; this is not a source-isolated clean-room process.
The sibling ext4 repository informed component boundaries and development
workflow. Its native FSKit fix history also informs the result/error and
revoked-acquisition guards and adaptive read-cache retention. The independent
NTFS observer/completion cleanup follows selected Dispatch SDK guidance;
FSKIT-EXT4-LESSONS.md maps inspected subjects and
remaining NTFS evidence. It is not an NTFS implementation dependency.

The checked extent-position algorithm is original code over this core's existing
validated mapping arrays. The six extent workloads use the original wire author,
SHAKE-derived per-extent bytes and explicit sparse/VDL oracles. Their manifests
describe synthetic storage and grant no Windows qualification. No foreign
filesystem/cache algorithm or product dependency was imported for this change.

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
- [Windows symbolic-link target paths](https://learn.microsoft.com/en-us/windows/win32/fileio/creating-symbolic-links)
- [Windows namespaces and path spelling](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file)
- [Windows volume root and GUID naming](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-volume)
- [Third-party GUID buffers](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_reparse_guid_data_buffer)
- [Self-relative security descriptors](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d)
- [SID packet representation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861)
- [ACL packet representation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/20233ed8-a6c6-4097-aafa-dd545ed24428)
- [ACE packet framing and trailing bytes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586)
- [Object ACE fields](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_allowed_object_ace)
- [Ordered discretionary access checks](https://learn.microsoft.com/en-us/windows/win32/secauthz/how-dacls-control-access-to-an-object)
- [AccessCheck inputs and exact granted mask](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-accesscheck)
- [Request mapping versus stored ACE masks](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b)
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
- [WOF external information](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_wof_external_info)
- [WOF algorithm identifiers](https://learn.microsoft.com/en-us/windows/win32/api/wofapi/ns-wofapi-wof_file_compression_info_v1)
- [MS-XCA Huffman encoding](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/c7ec7ba9-ca8f-448f-bb85-027c1516db1c)
- [MS-XCA Huffman decoding](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/26db8e62-bbd8-472c-a09e-623f6de10f0b)
- [Apple FSKit](https://developer.apple.com/documentation/fskit)
- [Microsoft per-directory case semantics](https://learn.microsoft.com/en-us/windows/wsl/case-sensitivity)
- [Original Keramics NTFS format research](https://keramics.github.io/ntfs.html)
- [Original MFT Browser standard-information field template](https://github.com/kacos2000/MFT_Browser/blob/master/NTFS%20-%20MFT%20FILE%20Record.tpl)
- [NTFS-3G release and source](https://github.com/tuxera/ntfs-3g/tree/2022.10.3)
- [NTFS-3G layout facts](https://github.com/tuxera/ntfs-3g/blob/2022.10.3/include/ntfs-3g/layout.h)
- [NTFS-3G log layout facts](https://github.com/tuxera/ntfs-3g/blob/2022.10.3/include/ntfs-3g/logfile.h)
- [Original Linux-NTFS log structures](https://flatcap.github.io/linux-ntfs/ntfs/files/logfile.html)
- [Original LFS research and version boundaries](https://dfir.ru/2019/02/16/how-the-logfile-works/)
- [Declarative NTFS client restart prefix in Linux v6.12](https://github.com/torvalds/linux/blob/v6.12/fs/ntfs3/fslog.c)
- [Original NTFS client restart payload fields](https://github.com/msuhanov/dfir_ntfs/blob/master/dfir_ntfs/LogFile.py)
- [LLVM libFuzzer process and corpus contracts](https://llvm.org/docs/LibFuzzer.html)
- [Original Linux-NTFS Secure format notes](https://flatcap.github.io/linux-ntfs/ntfs/files/secure.html)
- [Original Linux-NTFS descriptor format notes](https://flatcap.github.io/linux-ntfs/ntfs/attributes/security_descriptor.html)
- [Original Linux-NTFS MFT and reserved-record notes](https://flatcap.github.io/linux-ntfs/ntfs/files/mft.html)
- [Original Linux-NTFS filename lifetime notes](https://flatcap.github.io/linux-ntfs/ntfs/attributes/file_name.html)
- [Original Linux-NTFS root anchor notes](https://flatcap.github.io/linux-ntfs/ntfs/files/dot.html)
- [Original Linux-NTFS bad-cluster format notes](https://flatcap.github.io/linux-ntfs/ntfs/files/badclus.html)
- [Original Linux-NTFS index bitmap format notes](https://flatcap.github.io/linux-ntfs/ntfs/attributes/bitmap.html)
- [Original Linux-NTFS index allocation format notes](https://flatcap.github.io/linux-ntfs/ntfs/attributes/index_allocation.html)
- [Original Linux-NTFS index root and VCN unit notes](https://flatcap.github.io/linux-ntfs/ntfs/attributes/index_root.html)

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

The transaction/durability reference model is original repository work over
typed in-memory cells. Its WAL/commit/home/checkpoint protocol, ownership and
crash exploration import no external filesystem/recovery implementation. The
independent NTFS endpoint author uses existing named-wire fixture helpers and
does not import the model. It authors complete FILE/INDX records with new fixup
sequences; abstract fragment identities and credit sizes are not an NTFS log
layout. Native log interpretation and Windows recovery remain unqualified; see
RECOVERY-MODEL.md and WRITES.md.

The ordinary directory inventory diagnostic uses only the original Linux-NTFS
format facts that an index bitmap bit identifies one allocation record, allocation
stores the tree's subnodes and subcluster index VCNs use sectors. Its reachability
policy is an explicit consistency inference, implemented through the repository's
existing bounded visited set, paged bitmap scan and independent fixture author.
No external inventory implementation was examined or imported. Free records stay
opaque; Windows-authored layouts and other non-directory view indexes require
separate qualification. The indexed `$Secure` diagnostic now applies these same
repository mechanisms to supported SII/SDH views. Its cross-index bijection,
SDS interval ordering/nonoverlap and FILE-ID consistency are explicit repository
inferences from the existing named layouts and external byte observations. It
does not assume SDS physical order follows IDs; older research text is not an
ordering oracle. The cursors, bounded locator heapsort and fixture authors are
original work, with no foreign traversal/recovery implementation imported.

The mirror diagnostic's mandatory four-record prefix uses the
[MS-FSCC glossary](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/8ac44452-328c-4d7b-a784-d72afd19bd9f).
[Original Linux-NTFS mirror research](https://flatcap.github.io/linux-ntfs/ntfs/files/mftmirr.html)
describes a larger first-cluster extent. Only the explanatory Windows observation
in pinned NTFS-3G 2022.10.3
[ntfsfix.c](https://github.com/tuxera/ntfs-3g/blob/2022.10.3/ntfsprogs/ntfsfix.c)
was used for its report of changed big-cluster coverage since Windows 10 in 2017;
no repair/comparison implementation was adopted. The independent diagnostic
compares the required prefix and reports extended tails as unqualified.
[Original fixup facts](https://flatcap.github.io/linux-ntfs/ntfs/concepts/fixup.html)
explain saved sector tails and the update-sequence counter. Private buffer
ownership, normalized used-span comparison, budgets, reports and synthetic
geometry/fault oracles are original repository work. Native Windows replica
coverage and repair remain separate acceptance requirements.

The boot diagnostic uses
[Microsoft's BPB/boot-frame description](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc781134(v=ws.10))
and [original Linux-NTFS boot research](https://flatcap.github.io/linux-ntfs/ntfs/files/boot.html)
for fixed slot 7, nonresident LCN-zero storage and older backup variants. Only
the reservation/copy-placement facts in pinned NTFS-3G 2022.10.3
[mkntfs.c](https://github.com/tuxera/ntfs-3g/blob/2022.10.3/ntfsprogs/mkntfs.c)
were inspected to establish the supported declared-end reserved-sector profile.
No formatter or repair implementation was adopted. The original private owner,
bounded staging/comparison, reports, fault/quota fixtures and independent BPB/
standalone-export oracle retain this profile's scope. Windows-authored boot
copies, historical middle-copy placement and recovery selection remain open.

Regular-file size inspection separates Microsoft's nonresident FileSize,
AllocatedLength and ValidDataLength fields from content-decoder availability.
The compression-format mask and sparse/encrypted flags determine known attribute
framing; original Linux-NTFS/NTFS-3G layout notes cross-check the physical-size
tail and extent fields. The repository's metadata-only description validates
complete mappings and list ownership, rejects all data reads and imports no
external filesystem implementation. Synthetic EFS/unknown-compression/unit
fixtures establish local structural behavior; actual Windows-authored metadata
and decryption remain separate qualification.

The reparse decoder uses MS-FSCC's tag definitions, relative name offsets and
symlink flags. Microsoft documents the complete 16-KiB buffer limit and separate
third-party GUID envelope. NTFS-3G's `REPARSE_POINT` layout note confirms that the
attribute may be resident or nonresident. No NTFS-3G reparse implementation was
used or copied. The ownership, validation and copying code is original; synthetic
buffers and storage layouts do not establish Windows-authored reparse acceptance.

The FSKit intermediate-link resolver is original adapter code. Microsoft reparse
restrictions provide format and path-walk context; the cumulative 63-snapshot
ceiling, full-reference active stack, shared budgets and relative native emission
are this repository's policy. Independent fixtures specify original packets,
stored directory names and expected native bytes without invoking the resolver.
Local components do not establish Windows or installed native equivalence, and
the portable core still does not follow reparse targets.

WOF.md records the provider storage/table/lifetime and XPRESS contract. The observed
stored payload and stream arrangement use original libfsntfs format research;
the original NTFS-3G system-compression layout comment supplies independent chunk
and offset-width facts. The woftool author's README was also consulted for format
context, without adopting its implementation. API parameter flags are not presumed
to exist in stored bytes. The exact-multiple table interpretation remains subject
to Windows qualification rather than an uncritical floor-division formula.
XPRESS uses the Microsoft specification with an original compact canonical tree,
bit reader and caller-scratch contract; no external codec source was imported.
Declarative test alphabets, independently patterned expected bytes and one short
hand-authored packet qualify local encoding/decoding only. Independently authored
file images now combine those packets with sparse placeholders, fragmented/listed
backing and original-byte/manifest expectations. The owning stream and native
projection are original implementation code. These checks do not qualify Windows
WOF writers/codecs; Windows and installed provider acceptance remain open.

LZX uses the WOF/WIM variant documented by original libfwnt format research,
Microsoft MS-PATCH's shared Huffman/run/repeated-offset rules and the original
wimlib author's format constants. MS-PATCH's Delta header and extended lengths
are deliberately not substituted for WIM's 32-KiB variant. The constants header
supplies format facts, including the fixed CALL transform parameter; no foreign
codec implementation was imported. The compact canonical trees, bounded word
reader, block state and caller-scratch API are repository-owned original code.
See [MS-PATCH block format](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-patch/517e354e-a5c5-4239-ada5-25389cfe3170),
[original compression research](https://github.com/libyal/libfwnt/blob/main/documentation/Compression%20methods.asciidoc)
and [original wimlib format constants](https://github.com/ebiggers/wimlib/blob/master/include/wimlib/lzx_constants.h).

An already installed, explicitly selected wimlib library is an optional external
test oracle, loaded only by tests/lzx_oracle.py through its documented compression
API. The test process records library provenance and captured original/encoded
bytes in ignored artifacts; no library/header/implementation is vendored into
product sources or app bundles. Bidirectional codec comparisons are separate
from the independent image author and from still-required native Windows WOF
observations. Ordinary core tests need no external codec library.

Native target translation uses Microsoft's substitute-name/relative-flag and
namespace/root descriptions. Explicit current-owner bindings, numeric ancestry,
filename alias recovery and inode-context limits are repository-owned policy;
LINK-POLICY.md records the distinction from full Windows path resolution. ext4
was consulted for native FSKit type/callback conventions, without copying an
external NTFS implementation. Forty-seven synthetic projection verdicts and
fault sweeps remain separate from Windows/installed acceptance.

The security decoder uses MS-DTYP's self-relative offsets, little-endian fields,
six-byte SID authority and bounded subauthority vector. It preserves ACE order,
optional object GUID spans and opaque callback/unknown payloads. Extra non-callback
ACE bytes are ignored as required by MS-DTYP, rather than rejected as an invented
format restriction. The implementation and independent vector authors are
original. It does not use a GPL security parser or establish Windows/native access
decisions. The collector uses documented Win32 volume, identity and stream APIs;
fixed-width ctypes layouts and serialization pass local tests, while actual
Windows calls remain a separate required observation.

The DACL evaluator maps the desired request only. MS-DTYP distinguishes that
mapping from the mask already stored in an ACE. Applicable stored generic bits
therefore remain outside the evaluator's concrete-rights policy and return
UNSUPPORTED; original metadata stays lossless. This corrects an independently
retained local overgrant and adds request/stored/inherit-only fuzz inputs. These
policy regressions are separate from native Windows AccessCheck observations.

The resolver uses reverse-engineered view-index/SDS format facts, not imported
filesystem algorithms. Raw external exports confirm ID ordering, hash/ID
ordering, locator fields, duplicates and the mathematical rotate-three/add-DWORD
checksum. The old Secure page mislabels SII sorting and its descriptor-body
offset; an old descriptor note incorrectly says per-file storage is always
resident. Observed NTFS-3G images establish both indexed storage and nonresident
per-file descriptors. Original search, ownership, bounds and fixtures remain
repository-owned; the failed oracle runs are retained rather than converted to
passes. Actual Windows storage and authorization qualification remain required.

The whole-volume per-file pass reuses the original bounded snapshot/descriptor
decoder. [Original MFT inventories](https://flatcap.github.io/linux-ntfs/ntfs/files/mft.html)
and the corresponding MFTMirr/LogFile/Bitmap/BadClus/UpCase attribute tables omit
per-file descriptors. Independent `ntfsinfo` exports of slots 0 through 11 in
all four geometries observe zero-ID `$MFT` without one, with unchanged images.
The initial diagnostic wrongly required storage there and failed; its report
remains retained. The diagnostic now permits absence only for those six fixed
internal records and recognized inert reserved records, while checking every
present selected packet and all nonzero indexed references. Ordinary files,
root, Volume/Boot and arbitrary system-marked objects retain required storage.
This is a read-only consistency policy informed by original research and local
NTFS-3G observations, not a native Windows authorization/default-ACL rule.

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

LOGFILE.md separates the original immutable-byte decoders and independent field/
restored-byte fixtures from complete native journal/recovery work. NTFS-3G's
declarative header and original Linux-NTFS/libfsntfs/Suhanov research supply format
facts. Short NTFS-3G recovery offset helpers were also inspected for the conflicting
LCN-less address-base fact; the product refuses that variant pending independent
original-byte qualification. No foreign journal/replay/transaction algorithm was
imported, and no NTFS-3G utility or library is linked to the product.
The logical-source owner, compatible-copy comparison, partial diagnostic reports
and private page-publication contracts are also original repository code. Its
sources and expected metadata/restored-page bytes are authored from named wire
fields, separately from implementation offsets. No foreign copy-routing or
recovery implementation was imported for this continuation; tail/fast routing,
current circular history and native Windows qualification remain open.
The counted volume binder reuses the repository's existing stream/extent
implementation and the documented reserved `$LogFile` slot. Its fixtures place
independently authored journal bytes in named NTFS mappings; no foreign stream
or recovery algorithm was imported. Process-isolated fuzzing follows LLVM's
public corpus/process interface as test infrastructure; it is not product code
or a change in the allocator/disk format.
The physical circular-record assembly loop is original repository code. Published
LFS research supplies the first-segment-only header, continuation data-offset and
circular-wrap facts; declarative layout headers supply field meanings. Independent
fixtures pattern original client bytes and author protected fragments, extended
headers and unpadded exact-byte oracles. No foreign assembly/recovery algorithm
was imported. Physical byte framing does not qualify native page/current-history
selection or recovery.
The active-client resolver is also original repository code: named stored index/
sequence fields and the already validated in-use chain define its bounded
snapshot lookup. Independent chain orders, full UTF-16 names, field-boundary
sequences and free-entry LSNs author its expected results. No native replay or
client-registration implementation was imported; sequence lifecycle and record
liveness still require original Windows qualification.
The NTFS client restart common-prefix decoder and fixture author are original
repository code. The pinned Linux `NTFS_RESTART` declaration and Suhanov's named
payload fields were consulted only for the common layout/version facts, alongside
the original LFS research. No foreign parser, table, replay or recovery algorithm
was imported. Only client 0.0/1.0 common fields are interpreted; raw table anchors
and opaque extensions do not qualify complete checkpoints or native history.
The selected-client record binder is original repository code, composing existing
exact framing, active snapshot identity and common-prefix contracts. Its independent
fixtures author whole selected sources and assembled records, gate precedence,
sequence/name/LSN boundaries and complete-record limits. No foreign binding,
registration or recovery implementation was imported; matching snapshot identity
still requires native page/current-history qualification.

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
algorithms and unqualified DOS/flagged-bad-cluster/other-store/recovery work. The oracle
compares standalone raw bitmap exports, never links NTFS-3G into the product.

The complete listed bad-cluster description combines those original interval
facts with Microsoft's ordinary attribute-list/extension ownership contract.
An internal description policy reuses our original list/mapping algorithms,
requires complete volume coverage and VCN == LCN, and forbids content reading.
Original independent fixtures author first-in-extension, multiple and base-owned
continuations, nonresident list storage and malformed/failing counterparts.
No GPL implementation or default allocation policy was copied. Independent
mkntfs empty-stream inventories remain separate from unacquired Windows-authored
bad-cluster chains and flagged forms.
