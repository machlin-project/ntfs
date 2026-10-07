# Machlin NTFS

An independent, proprietary NTFS implementation for a commercial macOS FSKit
product. The C core owns disk semantics; the FSKit extension owns platform
lifecycle and I/O. There is no kernel adapter or LXNU integration in this scope.
The owner intends a later open-source release; no open-source license is granted
today. See LICENSE and docs/PROVENANCE.md.

The implementation provides bounded read-only extraction and experimental editing
of existing ordinary-file ranges in offline images. Installed initialized-range
and resident-range acceptance are complete. It is not a production NTFS driver.
Build, component tests and installed native
acceptance are tracked separately in [the acceptance matrix](docs/ACCEPTANCE.md).
Write support requires the separate recovery contract in [WRITES.md](docs/WRITES.md).

The [NTFS format reference](docs/format/README.md) explains disk structures and
their relationships in chapters with diagrams, field tables and original worked
examples. It is updated alongside implementation and native research. See the
[documentation map](docs/README.md) for component and acceptance contracts.

The installed macOS 27 FSKit image route now passes initialized ordinary-file
`pwrite`/`fsync`, shared-mapping mutation after the writer descriptor closes,
coherence through another descriptor and a prefaulted mapping, and two fresh mounts
through saved permissions. Ordinary unmount releases the backing image. The exact
postimage then passes independent Windows file/ADS/time/File ID/ACL checks,
read-only chkdsk, clean state and a matching healthy NTFS event. This qualifies
bounded overwriting, not general NTFS writing or production use.

The [native ordinary-file journal](docs/NATIVE-WRITE-JOURNAL.md) preserves the
original client roots and supports native redo/compensation for this family.
All 110 actual writer interruption states and 264 interrupted-recovery states
pass offline whole-image comparisons and native Windows VHD recovery. Independent
review binds the 264 healthy events and 154 exactly predicted torn-page warnings;
no unrelated warning or repair is admitted. Hardware power cuts remain untested.

The separate image owner retains the original security-scoped URL and native
backing owner, requires exclusive offline ownership and `F_FULLFSYNC`, closes all
immutable reader leases before mutation and lazily rebuilds item/core caches.
Authenticated owner writes pass; root and nobody are refused for all three tested
open modes. Ordinary vnode attributes permit kernel mount construction without
granting namespace or data authority. Metadata confidentiality across native
attribute caches is not claimed. Block-resource mounts retain read-only extraction.

The app saves genuine app-scope bookmarks and exposes `status`, `import`, `mount`
and ordinary `unmount` commands. [The CLI harness](scripts/fskit_image.py) runs the
installed signed app in a dedicated VM without console, picker or credential
input. Automation imports generated images only from the app's own Inbox;
external files require an ordinary picker grant. Initial OS extension enablement
is separate from repeated mount/test automation. See [DEVELOPMENT.md](docs/DEVELOPMENT.md).

The current resident implementation passes 176 fatal ASan/UBSan suites, selected-Xcode
style and both freestanding architectures. FSKit components pass 63 host groups
with thirteen explicit runtime SKIPs and all 80 native groups with zero SKIPs,
preserving 871 preceding inputs and twelve new resident files. All 91 actual
resident writer interruption states and all 264 interrupted-recovery states
pass offline and native Windows recovery, with independent original-event review.
The personally signed universal app is installed in the disposable test VM.
Actual resident `pwrite`/`fsync`, observer and shared-mapping coherence, ordinary
unmount and a fresh saved-URL mount pass. The exact postimage passes Windows
file/ADS/FILETIME/identity/ACL, clean state, read-only chkdsk and original healthy
event review. Allocation/free, resize,
create/delete/rename, sparse/compressed/ADS writes, Windows ACL
mutation and block-device writes remain unsupported. Distribution signing,
notarization and commercial release acceptance remain open.

A new [recovery-input owner](docs/RECOVERY-INPUTS.md) internally acquires the owning
checkpoint and exact retained client history through the completed endpoint,
separates reused transaction lifetimes and binds checkpoint roots. Owned packets
survive source close while keeping volume memory and lifetime accounting. This
prepares native recovery execution; it adds no write capability.

The connected ordinary-mutation batch now prepares complete create/resize/rename/
remove images, native metadata programs, LFS pages and bound inverse prefixes.
Its experimental physical executor also passes complete test-backend operations
and three actual ordinary-image write/persistence/reopen cases. A separate private
owner now derives recovery from reopened media, including torn MFT bootstrap,
complete old/committed metadata and interrupted compensation. It retains a settled
qualified prefix and several ordinary lifetimes after the exact quiet origin,
with private backward ownership and FILE generation-reuse proofs. Whole FILE/INDX
composition remains experimental. Settled checkpoint advancement and circular
journal reuse now pass a complete 196-suite local regression and a real POSIX
sequence of 640 mutations, 256 checkpoints and 119 wraps with F_FULLFSYNC and
fresh zero-rewrite recovery. Native snapshot qualification, sustained native
reuse and FSKit mutation admission still require the connected native acceptance gate.
The separate actual C checkpoint transition and interrupted-recovery gate now passes
all 196 Windows states, read-only chkdsk and original-event review; this does not
qualify new FILE/INDX mutation or sustained native ring reuse. The connected
ordinary-operation native batch rejects its first complete create image: Windows
reports a matching NTFS error and changes the volume flags. The exact detached
failure image is retained; the remaining 27 inputs have not run. Separate native
diagnostics establish a filename representation error: unpaired Win32 output fails
chkdsk, while an unpaired POSIX name and a Win32/DOS pair pass. C create/rename now
emit the selected POSIX representation, with a regression and all 198 sanitized
suites passing. A fresh current-C batch also passes ten offline operations and seven
fault profiles, but Windows again rejects its first complete create image before
file/chkdsk checks. Its corrected filename is preserved in the exact detached
failure image; the other 27 inputs remain unexecuted. A separate bitmap regression
now preserves unchanged nonresident attribute/mapping bytes and allocated tails
during content-only changes. All 198 sanitized suites, ten fresh operations and
seven fault profiles pass; FILE zero and its mirror stay unchanged in those ten
operations. Windows still rejects the fresh bitmap-corrected create candidate
before file/chkdsk checks. Its exact detached image and original error are reviewed.
Standalone `ntfsrecover` comparisons supply decoded fields, but its selected mode
also rejects two previously Windows-accepted checkpoint states; its return code
cannot qualify our WAL. Actual C journal/recovery and FSKit mutation admission
remain open. Exact Windows driver disassembly now identifies a violated spanning-
page LSN condition in the preceding C create. The corrected writer carries the
packet LSN on every circular segment; all 198 sanitized suites, ten fresh
operations and seven fault profiles pass. Windows still reports `Warning` on
the first fresh complete-create candidate, with a matching error event and
unchanged new FILE bytes; the other 27 inputs have not run. The exact detached
failure image is retained and reviewed.

The exact driver's packet validator also rejects full FILE undo snapshots
carrying `ADDING`; the compiler and recovery owner now enforce the valid
representation. Current local coverage is 198 passing suites, with selected-Xcode
style and twelve strict compilations. A fresh native operation/recovery gate is
pending. See
[the current batch evidence](docs/ACCEPTANCE.md#private-ordinary-operation-image-harness)
and [its format and recovery scope](docs/format/10-recovery-and-writing.md).

Two original, locked Windows test-disk captures now supply complete native clean
checkpoint/history inputs. Legacy client-restart page flags and an exactly compared
restart copy retained in a former modern fast slot are qualified without clearing
volume flags or modifying captured bytes. The newly captured unencrypted NTFS volume
also passes full allocation/metadata validation and exact Windows-authored file/ADS
comparison. These preceding immutable observations alone did not establish recovery;
the later bounded native recovery results are described above.

Three public NIST partitions now pass complete diagnostics and an independent
offline NTFS-3G comparison of 1,133 documented user objects and their readable
streams. The validator checks physical DOS-alias counts and the observed internal
repair descriptor omission through bounded namespace ownership. Current evidence
is 163 sanitized suites, 54 FSKit component groups/eleven runtime SKIPs and a clean
universal Release app. This corpus has unestablished authoring OS; Windows/native
acceptance remains separate. See [development](docs/DEVELOPMENT.md) for the corpus command
and [the current handoff](docs/HANDOFF-SOL.md) for exact evidence and limitations.

Write foundations now include private USA-protected metadata output and native
checkpoint-table/entry framing with complete bounded free-chain validation.
Private logical LFS/NTFS update encoders now measure and serialize exact packets,
with wire-width admission, checked overlap and unchanged errors. Independent goldens
cover 135 authored cases and 75 retained original packet inputs; physical journal
placement and native transaction semantics remain separate.
Private common-header LFS 1.1 page encoding now constructs complete RCRD pages and
USA protection in disjoint caller buffers. A separate 4-KiB LFS 2.0 serializer
preserves its opaque DWORD target and complete data region. 112 independent
whole-page goldens cover sizes, sequence wrap, transfer fields and restart flags.
LSN/copy fields remain opaque;
this is not native WAL planning or durable publication.
Independent byte/topology vectors and journal fuzzing pass; these primitives add
no device writes. [Their contracts](docs/WRITE-FOUNDATIONS.md) separate framing
from current history, native transaction recovery and writable admission.

Selected-client checkpoint acquisition now reads the stored restart and every
referenced dump through one prepared owner, under aggregate I/O limits. It validates
all anchors before table reads and publishes one complete caller-owned input snapshot
only after packet binding and cross-table checks. Exact bytes and value-only views
survive source close. All 144 acquisition/refusal profiles pass, with 310 independent
packet oracles, fault sweeps and bounded workspace checks. This prepares transaction
analysis inputs; current native history, recovery and durable writing remain open.

Selected transaction traversal now verifies exact packet identity, retained
previous-LSN chains and every undo-next reference under one operation budget.
Private bounded link scratch detects unrelated branches and reused transaction IDs;
raw Prepare/Commit/Forget markers do not decide recovery state. All 79 original
profiles and 8,455 exact packet oracles pass, with fault and resource checks.
This supplies another native analysis primitive; no device write API or writable
FSKit behavior is implemented.

Checkpoint transaction verification now acquires the selected checkpoint and
binds every allocated physical transaction key to its stored first/undo roots
and complete previous-LSN chain. The entire capture and all chains share I/O and
aggregate record ceilings. All 69 original profiles pass, including complete
preflight, 4096-record shared limits and failure/retry checks; the diagnostic
passes 65 default-policy profiles. This prepares checked checkpoint state for
later analysis. Native post-checkpoint state and Windows recovery remain open.

The immutable journal owner now also routes completed LFS 1.1 tail copies while
assembling records. It examines both slots, rejects conflicting written prefixes,
preserves backend errors and shares read credits across copies and continuations.
The final circular segment must fit its declared written prefix; earlier unfinished
segments can extend beyond NextRecordOffset. Separate I/O transfers and circular
wrap have independent exact-byte and rejection checks.
Original NIST checkpoint and analysis bytes now read through this API. A separate
immutable LFS 2.0 observer now examines all 32 fast slots and selects completed
copies per circular target, rejecting equal-epoch conflicts and preserving shared
I/O credits/backend errors. Seventy-two independent graphs and exact record oracles
pass; this does not establish complete current history or continuation provenance.
Three complete packets from an unmodified Windows Recovery journal also pass
fast-copy byte comparison and selected-client checkpoint membership with their
original owner. Complete modern history and replay still need qualification; see
[journal contracts](docs/LOGFILE.md).

The same owner now inventories every complete physical record-storage page,
including all copy slots and the circular area. It reserves the whole operation's
read credits before I/O, reuses private buffers without allocation and preserves
missing, torn, unsupported-routing and backend-failure evidence. Sixty independent
graphs cover 14,729 ordered page observations. On the frozen Windows journal, all
1,170 observations match independent source-byte review: 54 protected common
headers, 1,116 missing signatures and one invalid copy target. A separate native
page window supplies four exact records, including the preceding restart packet.
Physical coverage and observed LSN maxima do not select current history or enable
recovery.

An optional retained journal index now resolves complete competing prefixes per
circular target under explicit memory and whole-operation read bounds. Failed
preparation publishes nothing. Indexed record reads recheck selected protected
pages without repeating copy-slot scans. Seventy-one original graphs supply
14,922 target rows and 109 exact record results. On the frozen Windows journal,
all 1,138 target decisions and four complete packets agree independently; one
unrouted copy remains visible. Current endpoint, active-window continuity and
native analysis/recovery still need qualification before writing can be enabled.

The prepared index also supports a bounded ordered record visitor from an explicit
exact caller LSN. Complete packet framing must agree through the selected completed
endpoint; an unfinished successor header is verified separately. Shared operation
credits, exact packet bytes, prefix boundaries, ring sequence/wrap and refusals have
123 original window cases, including the exact 1-MiB record limit. The CLI is
`ntfs-logfile records LOGICAL_JOURNAL_FILE DECIMAL_FIRST_LSN`. Its completed framing
interval does not select native client analysis bounds or qualify recovery/durability.
Windows continuation provenance and transaction replay remain required under WRITES.md.

Volume admission now reports DIRTY only for the actual dirty bit. Other nonzero
flags remain unsupported; all 44 bit/version profiles and the unchanged Windows
Recovery refusal pass. This corrects diagnostics without admitting flagged media.

Empty-LCN journal payloads now retain the reserved first slot as opaque storage,
with absolute checked data offsets. Lossless attribute-name entry/full-dump decoding
validates byte lengths, unpadded storage and exact terminators without allocation.
Original historical payloads, names and complete table entries pass independent
framing comparisons. Exact dump records now bind to the selected-client checkpoint
snapshot, checking anchors, client identity, actions and every allocated entry.
The complete snapshot also checks distinct table LSNs and name/dirty target membership
using allocated physical OAT keys, with bounded caller scratch and no I/O/allocation.
Volume semantics, complete current physical history and native recovery remain open.

The core now inventories complete FILE_NAME storage separately as physical
names, primary names and DOS aliases. Listed extensions have checked sequences
and ownership; successful immutable counts are cached under operation budgets.
All 1,133 documented NIST user paths and three separate roots match NTFS-3G's
exported filename namespaces. FSKit now uses checked primary counts for item/page
attributes and all three single-edge reparse guards; see
[native namespace policy](docs/NATIVE-NAMESPACE.md).

A fresh personally signed development build is now installed and discovered in the
isolated stock macOS 26.5.2 guest. Ordinary File System Extensions enablement succeeds;
public FSClient reports the exact installed NTFS module enabled. Both complete-filename
standard and NTFS 3.0 fixtures pass installed reading, directory, mmap and write-refusal
checks through the public client. The preserved VM's disposable clone now boots
stock macOS 27.0.1, and the same installed build passes both complete native
read/mmap/refusal regressions there with unchanged images. Both mounts ignore ownership despite requesting
`owners`; native isolation remains unqualified. [Native installation](docs/NATIVE-INSTALLATION.md)
keeps development signing, discovery, enabled admission and mounted behavior distinct.

Fully checked counts now also survive temporary node closure in a bounded volume
memo keyed by the complete reference. Default retention adds 1 KiB, and failed or
quota-refused inventories publish nothing. Paired legacy component workloads show
targeted hard-link/alias gains while preserving complete cold checks, DOS separation
and work admission. [Performance evidence](docs/PERFORMANCE.md) records scope and
memory tradeoffs; installed throughput remains unqualified.

Checked base metadata now also survives temporary node closure, independently of
raw-record and filename-count replacement. It retains standard information and
checked reparse presence; stream sizes and mappings keep their separate validation.
The default metadata payload adds 6,656 accounted bytes. Matched controls cover
many names of one inode, 32 independent files fitting retention and 256 competing
files, including disabled/single-entry policies. Large fresh-core enumeration falls
from 71 to 42 ms; pressure sequential median increases about 1.4%. These are scoped
component observations. [The writable sequence](docs/WRITES.md) starts with native
journal history/recovery qualification before bounded existing-file writes.

Eight selected synthetic namespace images now retain complete filename bodies,
including 2,000 long names stored in real MFT extensions. Exact body/stream
oracles and stale-reference rejection pass. This prepares fixture coverage for
FSKit adoption. A separate preparation author now completes 153 actual native
inputs while preserving their original index keys and ordinary attributes. DOS
aliases, genuine reparse hard-link refusal, filename corruption, faults and quotas
pass the component checks; whole-volume and installed acceptance remain separate.

FSKit activation now requires an explicit read-only extraction choice through
the task option ntfs-access=extract, at load or activation. Windows permissions
are not enforced in that mode. Each owner keeps immutable native presentation
IDs and owner-read/search mode bits; installed identity and enforcement remain
unqualified. See [native access policy](docs/NATIVE-ACCESS.md) before mounting.

Mounted operations now have explicit read/allocation/work budgets and an aggregate
core live-memory cap. Compound FSKit requests share credits across nested core
calls and separately bound rounded physical resource reads. This changes the
public API to version 2; see [operation contracts](docs/OPERATION-BUDGETS.md) for
caller migration, retry, teardown and the limits of memory/time accounting.

Layout follows the ext4 sibling: `core/`, `include/`, `adapters/posix/`,
`adapters/fskit/`, `tests/`, `tools/`, `scripts/` and `docs/`. The core is original
C11 with explicit allocation and exact device reads. No third-party NTFS
implementation is linked into the product.

Implemented reading includes MFT/attribute lists, resident and fragmented data,
sparse and uninitialized ranges, alternate data streams, LZNT1, indexed directory
enumeration, $UpCase lookup and bounded reparse metadata decoding. Symlink and
junction targets are available as lossless UTF-16. FSKit now projects a bounded
within-owner subset with explicit Windows root bindings, checked intermediate
symlink/junction chains and reversible target aliases; see
[native link policy](docs/LINK-POLICY.md). Cross-volume targets, context-dependent
reparse hard links and cloud content remain open. WOF file-provider streams
read XPRESS4K/8K/16K and LZX32K with bounded storage/table validation. The FSKit app and extension
build unsigned from current source; a prior personally signed Release passed strict
signature verification. Direct adapter tests and independent NTFS-3G image
comparisons pass. Broader installed behavior and Windows-authored corpus acceptance
are still required. Core and FSKit tests
run with `make test` and `python3 scripts/test_fskit.py`; build the app with
`make fskit`. See development prerequisites and exact evidence below.

Validated nonresident stream reads now retain one checked extent index, reusing
the current or immediately following run before the binary-search fallback.
Six original workloads include up to 1,024 runs through eleven attribute records,
sparse storage and uninitialized tails. Exact bytes, independent streams,
partial/full I/O failures and compound quota checks pass. Current source passes
72 sanitized suites and builds the universal Release app. Matched portable
measurements and their tradeoffs are tracked in PERFORMANCE.md; Windows/native
and the complete optimization program remain open.

The resource now reads fully aligned fragments into caller storage and keeps a
bounded window for unaligned requests. Separate retained-binary memory-reader
measurements show a targeted improvement; [PERFORMANCE.md](docs/PERFORMANCE.md)
records timings, fault/lifecycle checks and the remaining native qualification.
Directory items now retain at most two independent enumeration continuations,
allocated lazily within the resource pool. Repeated legacy component measurements
reduce interleaved scan time on the authored large/small namespace workloads;
installed performance and broader directory profiles remain unqualified.

Read [architecture](docs/ARCHITECTURE.md), [development](docs/DEVELOPMENT.md),
[acceptance](docs/ACCEPTANCE.md) and [handoff](docs/HANDOFF-SOL.md).

The no-VM continuation adds reference-based lossless inspection, Windows corpus
acquisition/verification tools, standalone parser fuzz targets, an MS-DTYP security
descriptor decoder/resolver and repeated portable workload measurements. Verified metadata
reuse has a measured benefit for attribute-list opens. `$Secure` and per-file
descriptors have bounded read-only snapshots; full authorization, Windows/provider qualification, complete
reparse resolution, Windows/native qualification and recovery remain open;
see [the complete continuation scope](docs/CORE-QUALIFICATION.md).
[WOF reading](docs/WOF.md) validates sparse unnamed storage, named backing extents,
the complete paged chunk table and exact-size XPRESS-Huffman/LZX units. Counted streams
survive source nodes, retain at most two private decoded units and retry failed
fills. The second output is optional and falls back to one unit under allocation
or live-credit refusal; native pressure releases both with their owning stream.
Core and legacy FSKit content checks pass locally; Windows/native provider
qualification remain open.
Stored stream names now have a bounded immutable catalog and read-only FSKit
xattr projection with a lossless UTF-16 reverse manifest. Bounded native filename
aliases preserve unpaired/oversized/reserved names and individual hard links;
both projections pass component tests, with installed behavior still unqualified. See
[native namespace contracts](docs/NATIVE-NAMESPACE.md) for tested scope and limits.
See [security metadata](docs/SECURITY.md) for source selection, validation and the
remaining Windows/native authorization contracts.
The allocation-free [DACL evaluator](docs/ACCESS.md) now implements ordered plain
ACEs, exact file-right mappings, ordinary ownership and restricted/deny-only token
contexts. It remains a separate discretionary plane; native identity, integrity,
privilege and owning-operation authorization are still incomplete.
Generic requests map to concrete rights; applicable generic bits already stored
in ACEs refuse explicitly instead of inventing an access grant.
An independent [Windows AccessCheck observation pipeline](docs/ACCESS-ORACLE.md)
now captures queried tokens and original descriptors for bounded offline comparison.
Its transport/acquisition/reporting contracts pass locally; native Windows
decisions have not yet been acquired.
Stored per-directory case policy now selects exact UTF-16 or folded lookup while
preserving NTFS B-tree ordering. Mixed-directory/alias and fault checks pass
locally; installed cache behavior and Windows-authored flags remain unqualified.
See [directory case policy](docs/CASE-POLICY.md).
The separate [consistency diagnostic](docs/VALIDATION.md) now checks bounded
MFT/cluster allocation, extension/list ownership, filename/index pairing,
required mirror-prefix/boot-anchor consistency, declared reserved boot-sector
agreement, directory reachability and physical
extents through a private read-only mount. Complete ordinary directory bitmaps
also reject used unreachable index blocks while leaving free storage unread;
this check adds no whole-bitmap scan to normal FSKit enumeration.
Complete unflagged `$BadClus::$Bad` mappings now support attribute-list
continuations through the shared checked reader. The private description is
metadata-only and public content opening is refused; diagnostics never read bad
clusters. Flagged storage and Windows-authored chains retain explicit gaps.
Declared extended mirror tails retain
explicit unchecked counts; prefix agreement selects no repair source.
Synthetic fault/budget checks and four independent bitmap geometries pass;
complete reports retain a defined scope, with native Windows, view-store and
recovery qualification still open.
The boot pass checks ordinary nonresident/listed LCN-zero `$Boot` storage and one
full logical sector at the declared data-span end, even for a larger resource.
Thirty-seven authored cases, bounded fault/quota profiles and four independent
NTFS-3G exports pass; Windows backup variants and recovery authority remain open.
Normal mount remains separate from that full diagnostic. Compact fuzz authors now
share canonical CLI geometry and preserve the reserved copy within a 1-MiB data
span plus a 4-KiB resource allowance. See VALIDATION.md and ACCEPTANCE.md.
The FSKit [lifecycle contract](docs/LIFECYCLE.md) now closes admission before
draining reads, clears transient caches at unmount and retains item ownership for
reclamation. Eight blocked-read/overlapping-teardown scenarios and interleaved
enumerations pass locally; synchronous I/O interruption and installed lifecycle
remain separate acceptance requirements.
The resource-bound read-only maintenance entry point now runs that private
diagnostic as an FSKit task. Quick checks retain an explicit partial scope;
repair/formatting refuse asynchronously. Forced failed-layout loads can retain
a temporary nonmountable identity, and cancellation drains owned storage before
retirement. Ordinary synchronous item reads retain their separate interruption
limits; installed checker dispatch and client behavior still require acceptance.
Conditional native reclaim now serializes against item-result publication;
older runtimes retain item ownership until the last FSItem reference. Five
modeled eligibility/ownership/publication cases and the current component/app
checks pass. Names-only enumeration now includes virtual current/parent entries
with stable stored-name aliases, checked parent identity and native cookie errors.
Local replay/fault/budget checks pass; native reclaim counts and installed
enumeration still require acceptance. See the lifecycle document.
Exact native dot lookup now shares that checked ancestry, including root clamping
and reopening a released parent by full sequence-bearing reference. Cached
identities require no core I/O/allocation; admission and compound budgets remain
mandatory. Component fault/quota checks pass, with installed path walking and
macOS 27 runtime still unqualified.
Ordinary-file sizes now validate the complete unnamed-stream mapping separately
from content decoding. EFS-flagged and unsupported-compression files can retain
truthful FSKit attributes and independent readable ADS while default reads return
ENOTSUP. Six synthetic storage variants, corruption/rejection pages and remount/
revocation checks pass locally. Known WOF file-provider metadata also retains truthful
attributes and independent ADS beside unsupported encrypted backing. These checks do not
qualify Windows-authored EFS or installed behavior. Native links retain separate
path, identity, configuration and installed-acceptance limits.
The [ext4 FSKit history review](docs/FSKIT-EXT4-LESSONS.md) maps observed native
lessons to NTFS contracts and remaining runtime/distribution checks.
Automatic [read-cache retention](docs/READ-CACHE-POLICY.md) now reacts to observed
memory pressure without scanning dormant items. Accessed streams/catalogs/raw
snapshots and older inactive directory continuations become disposable while
the latest/pinned positions and item identity remain protected. Exact bytes,
measured core allocation release, blocked-read delivery and
fault/lifetime scenarios pass locally; installed delivery and memory stress remain
separate requirements.
The independent [read-only log primitives](docs/LOGFILE.md) now decode LFS restart
areas/client lists, LSNs, protected pages and logical record/update framing.
Complete journal assembly, transaction analysis, recovery and Windows log
qualification remain open; structural decoding cannot enable writes or dirty mounts.
An independent logical-source owner now selects compatible restart copies with
bounded conflict/partial-I/O reports, retains lossless clients and stages physical
page reads. Counted ordinary `$LogFile` stream binding holds the core volume
through owner close and validates fragmented/listed storage. The `journal`
diagnostic reads exported regular files; `volume-journal` reads NTFS image files
through an ordinary portable core mount. Physical circular records now assemble
by LSN across adjacent protected pages and one wrap, with shared I/O credits,
bounded private staging and exact byte oracles. The `circular-record` diagnostic
retains exact bytes without alignment padding. Current circular history, copy
routing, native client/transaction interpretation and journal lifecycle remain open.
Cached active-client index/sequence lookup now distinguishes raw/free metadata
from selected active membership without I/O or allocation. Independent chain,
sequence-boundary and full UTF-16-name checks pass locally; record liveness and
native checkpoint interpretation remain separate work.
An executable [transaction/durability reference model](docs/RECOVERY-MODEL.md)
now exercises bounded serialized ownership, WAL/commit/home/checkpoint ordering,
partial writes and interrupted replay against independently authored native NTFS
metadata/content endpoints. It operates only on in-memory typed cells and adds
no device writer or native journal recovery. The full native recovery/Windows
acceptance contract remains in WRITES.md and CORE-QUALIFICATION.md.
The separate NTFS client restart decoder now retains the 64-byte common prefix
for client formats 0.0/1.0, raw analysis/table LSNs and byte counts, and an opaque
extension span. Its `client-restart` packet diagnostic makes no table-presence,
current-history or recovery decision; these client versions are distinct from LFS
restart-page versions.
Already assembled client restart records can now be checked against the selected
snapshot's type, active index/sequence, exact NTFS name and stored restart LSN
before prefix decoding. Cached binding uses no I/O/allocation and preserves zero
error outputs. Page provenance and current written history remain separate from
this snapshot match; see the `client-restart-record` diagnostic and LOGFILE.md.
The separate indexed `$Secure` diagnostic now walks both complete supported view
trees and used allocation inventories, checks exact SII/SDH membership and
nonoverlapping SDS intervals, and validates every indexed descriptor/hash/copy.
The general consistency diagnostic also rejects missing nonzero FILE security
IDs. It also validates selected unnamed per-file descriptors for zero-ID base
files, including resident, fragmented and listed storage. Unindexed SDS gaps,
Windows/native identity and authorization remain separate contracts;
SECURITY.md defines the exact scope and fixed-internal/reserved-record exceptions.
