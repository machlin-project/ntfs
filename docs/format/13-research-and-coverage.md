# 13 · Research and coverage

[Reference index](README.md) · [Previous](12-reparse-and-compression.md)

This register makes missing knowledge explicit. It is a format/research map;
feature acceptance remains in [ACCEPTANCE.md](../ACCEPTANCE.md). Closing a row
requires evidence at the layer described, not just another parser or successful
final-image comparison.

## Current coverage

| Area | Reference coverage | Remaining work |
| --- | --- | --- |
| Geometry, FILE, USA, attribute framing | Field maps, conversions, examples and code/test links | Additional native geometry/version qualification |
| Mapping pairs, sizes, named streams | Fragmentation, signed deltas, holes, EOF/VDL and ADS | Durable mapping/size changes beyond the existing overwrite family |
| Directories and case policy | Root/INDX/bitmap, VCN units, collation, link representations | Native DOS association, mixed-policy cases and namespace recovery |
| Security descriptors and `$Secure` | Shared/per-file selection, SID/ACL/ACE framing and store correspondence | Full inheritance/token semantics and durable shared-store mutation |
| LFS and NTFS log framing | Restart/page/packet/update tables, copies, LSNs, vocabulary | Native multi-page publication, generic update execution and floor advancement |
| Existing overwrite recovery | Qualified owning family and ordering | Allocation/namespace recovery, sustained ring reuse, hardware power cuts |
| Reparse, LZNT1, WOF | Selected envelopes and storage/codec profiles | General providers, encoded writes and broader native captures |

## Research register

| Question | Present evidence or boundary | Evidence needed to close it |
| --- | --- | --- |
| Native multi-page LFS publication | Original framing research plus independent continuation/wrap fixtures; scalar decode is broader than proved history. | Windows-authored spanning packets, complete page/transfer/copy relationships, then C publication and interrupted native recovery. |
| Completed tail cursor | LSN identifies start; an assembled record can end after wrap. | Carry the proved ending/successor position into reservation; test old continuation preservation and sequence exhaustion. |
| Zero next-record boundary variants | Scalar page decoder accepts zero; owning assembly currently has a narrower unfinished-boundary rule. | Retained native examples and explicit interpretation for each supported variant. |
| Restart open/revision storage | Named original field research and observed values; do not reinterpret opaque changes casually. | Version-specific original evidence and interrupted publication behavior. |
| Generic FILE/INDX snapshots | Existing FILE reconstruction family is qualified; original INDEX update witnesses exist. | Operation-specific semantics for new/free records and index images, target binding, loser/winner recovery and native fault acceptance. |
| Allocation bitmap updates | Original native set/clear witnesses and locally consistent planned images. | Complete bitmap/mapping ordering and replay across every affected metadata object. |
| Checkpoint floor advancement | A byte-level hypothesis exists; earlier empty-checkpoint publication caused repair demand. | Actual owning C protocol, every publication prefix, live-obligation retention and Windows recovery without repair. |
| Ring wrap and sustained reuse | Read framing handles qualified wrap fixtures; current product writer retains bounded original roots. | Hundreds of actual connected mutations, checkpoint reuse, complete interruption/recovery sweep and one native batch. |
| MFT attribute-list growth | Read resolver checks extent/list provenance; ordinary planner has bounded inline map capacity. | Extension-record allocation, list rewriting, generation ownership, native logging and recovery. |
| MFT slots 16–23 | Microsoft reserves the first sixteen slots; older MFT research describes a larger unused reservation. The local planner starts at slot 16. | Windows-authored allocation/reuse under record pressure, the affected record roles and native recovery qualification for the selected allocation policy. |
| Long name / DOS pair association | Physical inventory and read projection exist; mutation refuses unqualified pairs. | Windows-created rename/remove/hard-link examples proving association and all affected counts/keys. |
| Per-directory case bytes | Published behavior plus original field research and synthetic tests. | Native case-flag queries paired with exact source records, collision/index and cache tests. |
| Create owner/group and inherited ACEs | Local planner uses an explicit parent-derived, plain-ACE profile. | Caller-token/native authority contract; broader inherited ACE forms and native creation comparison. |
| Shared security-store insertion | Store is read/validated; existing writes preserve it. | ID allocation, hash/deduplication, both indexes, duplicate SDS blocks, native WAL and recovery. |
| Open unlink / replace | Stable native identities exist for the bounded overwrite owner. | Owning open-reference lifetime, deferred retirement, storage reuse and crash recovery. |
| `$UsnJrnl` maintenance | Current write admission refuses the unsupported active journal profile. | Detailed `$Max`/`$J` versioned records, reason/coalescing semantics and coupled native mutation. |
| `$AttrDef`, `$ObjId`, `$Quota`, `$Reparse` indexes | Roles are identified; ordinary read validation does not imply mutation. | Dedicated field maps, independent fixtures, original native captures and owning update contracts. |
| EAs and EFS | Attribute/provider classification is bounded; broad interpretation and writing are absent. | Dedicated researched layouts, security semantics and native behavior evidence. |
| 4Kn and wider writer geometry | Reader and writer geometry policies are separate. | Original native source profiles, physical alignment/MST proof and full recovery acceptance. |

The register records concrete next evidence, not inferred percentage completion.
A newly resolved item moves into the relevant chapter with its source and test,
while its qualification change is recorded separately.

## Resolved documentation traps

| Trap | Rule used in this reference |
| --- | --- |
| Treating a FILE header as always 48 bytes | Separate the 42-byte common header from its optional six-byte modern extension; honor declared USA/attribute positions. |
| Treating a RSTR prefix as always 32 bytes | The common prefix ends at 30; the following USA word is not a fixed field. |
| Following the inconsistent SDS descriptor offset | The locator occupies 20 bytes; the descriptor starts at `0x14`, as checked by the named layout and independent store fixtures. |
| Assuming VDL is always cluster-rounded | It is an initialized byte prefix. [SetFileValidData](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfilevaliddata) explicitly describes byte precision; an older attribute devnote has misleading rounding wording. |
| Treating transfer page count as record length | Assemble from the logical record's byte extent; transfer counts describe I/O framing. |
| Treating a dirty/clean scalar as writable authority | Volume flags, selected roots, complete history and physical ownership are separate checks. |
| Replacing volume `$UpCase` with host casing | Retain on-disk collation and original UTF-16 units; native presentation is separate. |
| Equating FILE_NAME copies with live SI/DATA | Treat duplicate values as cached metadata under the selected stat policy. |
| Using raw source observations as recovery acceptance | A wire witness supplies format evidence; only a complete owning behavior experiment can qualify execution. |

Conflicting published prose is kept visible when it affects an implementation
choice. The sources can contain useful field facts and still have outdated or
inconsistent explanatory notes.

## How to add a native observation

1. State the operation, supported geometry and the object/stream being observed.
2. Capture only an authorized, quiescent or explicitly modeled interrupted source.
3. Record exact acquisition, source identity and hashes in generated reports.
4. Decode with named fields, preserving original bytes and unknown storage.
5. Compare independent expected bytes or native semantic observations.
6. Explain the relationship learned, its scope and the remaining alternatives.
7. Add the compact finding to its chapter, with a link to the stable acceptance
   contract or fixture author. Keep run-specific identifiers out of Markdown.

Our development loop remains one connected implementation/test batch followed
by one prepared native acceptance batch. Documentation should capture findings
as we work, without turning every new field into another VM cycle.

## Further source entry points

Sources are cited near the fields and claims they support. For subjects awaiting
their own detailed chapters, useful primary starting points are:

- [Microsoft's USN_RECORD_V2 layout](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2).
- [Microsoft's FILE_NAME structure](https://learn.microsoft.com/en-us/windows/win32/devnotes/file-name).
- [Microsoft's per-directory case behavior](https://learn.microsoft.com/en-us/windows/wsl/case-sensitivity).
- [Original Linux-NTFS metadata catalogue](https://flatcap.github.io/linux-ntfs/ntfs/files/index.html).

The complete attribution record is [PROVENANCE.md](../PROVENANCE.md). Foreign
filesystem implementation code is not imported into this reference or the core.
Consulted layout comments and format research remain explicitly attributed.
