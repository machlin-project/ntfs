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
| Existing overwrite recovery | Qualified owning family and ordering; experimental fresh recovery retains a settled qualified prefix and ordinary groups | Native snapshot/history qualification, sustained checkpoint/ring reuse and hardware power cuts |
| Reparse, LZNT1, WOF | Selected envelopes and storage/codec profiles | General providers, encoded writes and broader native captures |

## Research register

| Question | Present evidence or boundary | Evidence needed to close it |
| --- | --- | --- |
| Native multi-page LFS publication | Original framing research plus independent continuation/wrap fixtures; scalar decode is broader than proved history. Bounded physical assembly of the Windows creation control includes four spanning packets, with completed headers for three. Three retained Windows journals supply 84 completed spanning packets, at most 1392 bytes each; none supplies a pure continuation page. Complete current owning history remains unselected. | Retain a completed native packet large enough to require a pure continuation page and prove its page/transfer/copy relationships; bind transaction ownership, then qualify C publication and interrupted native recovery. |
| Spanning-page LSN read admission | Exact signed Windows driver and matched public PDB establish that every copied circular page must cover the requested record LSN. Two zero-LSN continuations in the actual preceding C create violate that predicate and lead to a corrupt-disk exception if read. A regression reproduces the C defect; the writer now carries the record LSN on every segment. The corrected complete-create candidate still gets a matching native health error; its exact detached postimage is reviewed. | Diagnose the remaining native rejection and qualify fresh complete-operation and interruption/recovery inputs; live attribution of the original warning and other operation-specific contracts remain separate. |
| FILE snapshot flag admission | Exact `NtfsCheckLogRecord` and its operation-class bytes refuse `ADDING` with Initialize FILE undo, diagnostic reason 53. Fifteen preceding snapshots among 86 actual C packets violate it. A regression fails on that output; compiler/recovery and independent checkpoint fixtures now distinguish a real FILE inverse from Initialize/Noop. Local coverage closes all 198 suites with zero-write malformed-flag refusal for loser and winner. All 86 packets from ten fresh C operations pass the inspected admission predicates. | Fresh native operation/interruption acceptance; do not infer complete replay semantics or live branch attribution from this packet predicate. |
| Completed tail cursor | The pure batch planner passes independent continuation/wrap/floor tests. The experimental physical executor now derives its exact successor from the preceding settled owning history's completed extent and independently reopens its prepared records. | Qualify that composition through general journal-derived recovery and interrupted native execution. |
| Zero next-record boundary variants | Scalar page decoder accepts zero; owning assembly currently has a narrower unfinished-boundary rule. | Retained native examples and explicit interpretation for each supported variant. |
| Restart open/revision storage | Named original field research and observed values; do not reinterpret opaque changes casually. | Version-specific original evidence and interrupted publication behavior. |
| Generic FILE/INDX snapshots | Existing FILE reconstruction family is qualified; experimental compilation/execution and fresh recovery bind a settled qualified prefix, several ordinary groups, complete object views and interrupted compensation. Fresh native-source operations pass complete local oracles. Actual C create still fails native health admission after both the POSIX-name and bitmap corrections, with NTFS 98/level-2/state-3 and changed volume flags; exact postimages retain unchanged new FILE bytes. Full `0x02 / 0x02` and whole-INDX substitution remain unqualified. | Diagnose the native rejection independently of the closed metadata defects; establish operation-specific Windows replay semantics for new/free records and index images, sustained native checkpoint reuse and native fault acceptance. |
| FILE retirement | Five original Deallocate packets bind exact current home LSNs and clear MFT bits; generation advances and links remain stored. The experimental backward history proof binds complete earlier retirement to later FILE reuse through initialization, allocation and the matching sequence; free bytes remain explicitly unknown. | Native directory retirement, generation wrap, publication and interrupted recovery. The matched capture has no independent preceding-body snapshot. |
| New-record Noop / Deallocate inverse | The complete-local inventory retains eight-byte inverse prefixes, both FILE multi-sector geometry and zeros. The experimental compiler retains the selected inverse before initialization; private prefix tests caught and closed the opposite-order gap. | Distinguish existing free slots from newly exposed MFT storage; original allocation/undo witnesses, OAT identity and complete cross-object recovery before admitting this separate form. |
| Ownership of previously unused storage | Planner/compiler provenance and physical before guards continue into fresh ordinary recovery and private backward historical views. An old FILE snapshot needs complete original initialization and a set MFT bit; matching free FILE bytes cannot authorize it. The compiler retains unchanged free slots as exact raw bytes. Private mappings, original index/volume bitmap ownership and mirror guards prove the targets. | Native Windows qualification of free-storage effects and allocation rollback; historical index-buffer/cluster reuse and sustained checkpoint reuse. |
| Complete physical operation execution | Eighteen local operation/storage/alignment profiles, exact reopened journal/metadata receipts and required fault/poison states pass. Actual regular-image operations continue after completed compensation and open-only recovered groups. Settled-history acquisition publishes scalar values after proving the complete actual retained history. | Connected checkpoint reuse, native snapshot recovery and Windows/FSKit acceptance. |
| Fresh ordinary journal recovery | A separate owner receives only reopened media, bootstraps through a complete FILE-zero replica and continues exact compensation. Private backward views bind earlier ordinary groups and a settled qualified prefix without shortening the physical endpoint or fabricating old free bytes. Local sequences retain original packets, unrelated bytes and zero-rewrite second opens. | Qualified operations after ordinary groups, historical index/cluster reuse, sustained checkpoint reuse and native Windows recovery of the experimental snapshot forms. |
| Attribute opens without a transaction update | Local continuation retains explicit open-only groups. Each actual open LSN and sequence-bearing owner is checked; no transaction Forget is fabricated. A group with updates cannot be skipped before its real completion. | Native OAT-key reuse/open lifetime behavior after interrupted opens and later operations. |
| Uncompleted legacy transfer copies | A private writer index can retain a protected unfinished copy as a physical candidate when its circular home is torn. It supplies no completed-prefix or endpoint authority; an available unfinished circular first segment must bind the exact selected successor. Public reader policy is unchanged. | Native multi-page transfer/copy witnesses and interrupted recovery proving each supported publication variant; do not infer completed payload from absent continuation bytes. |
| Allocation bitmap updates | Original native shared-span set/clear witnesses; pure native payload programs have exact independent goldens and forward/inverse agreement with every ordinary planned bitmap cluster. | Bind actual OAT lifetimes and nonzero-VCN addressing, then complete bitmap/mapping ordering, compensation and native replay across every affected metadata object. |
| Content-only bitmap storage | Three independent overallocated MFT/volume/both profiles reproduce and close unintended stream resizing/re-encoding. The planner now preserves unchanged nonresident attributes, mappings and allocated tails; ten fresh local operations also preserve FILE zero and its mirror. The fresh Windows create rejection remains. | Native cross-object operation and recovery acceptance; real size growth must still change allocation and mapping through its owning transaction. |
| NTFS-3G comparison authority | The driver does not log its own writes. Its standalone utility decodes concrete opens/updates; clean selected calls return early, historical scans warn on accepted controls, and selected simulation fails before any action on two Windows-accepted checkpoint states. | Use documented operation meaning and exact decoded fields with qualified native witnesses; a utility exit code cannot close our WAL/recovery gate. |
| Checkpoint floor advancement | Native empty checkpoints and five byte-level publication observations retain a settled Forget anchor; the earlier new-bootstrap publication remains disqualified. The [experimental C protocol](../CHECKPOINT-REUSE.md) passes independent full-byte, origin/refusal, allocation/read-fault and writer/interrupted-recovery states. Exact old-history proof binds mixed roots before floor advancement. All 196 actual-C Windows states pass native files/ADS/time/identity/ACL, clean state, read-only chkdsk and original-event review with exactly predicted injected USA warnings. | Sustained native operation/recovery, additional supported geometries and installed operation admission. |
| Ring wrap and sustained reuse | Experimental execution passes 640 connected operations and 5,632 packets on each modeled ring. Real POSIX transfers, F_FULLFSYNC and close/reopen also pass 640 operations, 256 checkpoints and 119 wraps with exact whole-image and zero-rewrite recovery checks. The separate 196-state Windows gate qualifies one settled checkpoint transition and interrupted recovery; the installed overwrite owner retains its existing origin admission. | Sustained native mixed operation/recovery beyond ring capacity, native ordinary-mutation interruptions and writable FSKit integration. |
| MFT attribute-list growth | Read resolver checks extent/list provenance; ordinary planner has bounded inline map capacity. | Extension-record allocation, list rewriting, generation ownership, native logging and recovery. |
| MFT slots 16–23 | Microsoft reserves the first sixteen slots; older MFT research describes a larger unused reservation. The local planner starts at slot 16. Metadata-only diagnostics at slots 16 and 63 both mount healthy and pass file checks, but have the same filename-linkage chkdsk failure. Relocation alone does not resolve that observation. | Windows-authored allocation/reuse under record pressure, the affected record roles and native recovery qualification for the selected allocation policy. |
| Long name / DOS pair association | Physical inventory and read projection exist; mutation refuses unqualified pairs. Four controlled unpaired Win32 create images have the same native filename-linkage failure. An unpaired POSIX diagnostic, a Win32/DOS pair and an actual Windows-created file all pass native/chkdsk review. The native control uses the observed enabled short-name policy and retains the same long/DOS names and physical count as the paired diagnostic. C create/rename now emit POSIX names with a failing-before/passing-after regression; a fresh actual C native create still fails health admission while preserving that corrected name. | Actual C WAL/create/rename/recovery acceptance using the selected unpaired representation; native pair mutation, rename/remove/hard-link examples proving association and all affected counts/keys. |
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
| Assuming retirement zeroes link count | The five exact native header transitions retain links. Liveness comes from checked flags, allocation and reference generation; the 24-byte inverse and the body have separate extents. |
| Treating a RSTR prefix as always 32 bytes | The common prefix ends at 30; the following USA word is not a fixed field. |
| Following the inconsistent SDS descriptor offset | The locator occupies 20 bytes; the descriptor starts at `0x14`, as checked by the named layout and independent store fixtures. |
| Assuming VDL is always cluster-rounded | It is an initialized byte prefix. [SetFileValidData](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfilevaliddata) explicitly describes byte precision; an older attribute devnote has misleading rounding wording. |
| Treating transfer page count as record length | Assemble from the logical record's byte extent; transfer counts describe I/O framing. |
| Treating every FILE initialization as ADDING | A selected full Initialize/Initialize snapshot has a real undo and clears ADDING; Initialize/Noop carries it. Native operation-specific flag admission is separate from commit state. |
| Treating external recovery exit status as native WAL acceptance | Check whether any actions were inspected/executed and compare accepted controls; preserve the Windows gate separately. |
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
