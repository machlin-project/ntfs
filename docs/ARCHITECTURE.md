# Architecture

FSKit's explicit extraction mode owns activation policy independently of NTFS
security parsing and DACL evaluation. Load/activation must select the mode;
missing or unsupported selection publishes no root. Native presentation IDs
snapshot the extension process once and survive remount. This neither maps
Windows principals nor proves installed native enforcement; see NATIVE-ACCESS.md.

The portable C11 core owns NTFS 3.0/3.1 boot geometry, FILE/INDX fixups, MFT
references, attributes, mapping pairs, streams, directory indexes, reparse metadata
and Unicode collation. Byte-array wire structures have compile-time size checks.
No native errno, allocator, filesystem runtime or page-cache object crosses this
boundary.
The FILE record uses the common header; the additional NTFS 3.1 fields are an
optional wire extension, so older update-sequence arrays do not overlap a falsely
required header tail. Both header layouts have complete synthetic image tests.
The environment supplies allocation, deallocation and bounded exact reads.
It has no write method. Media must remain immutable for an entire mounted owner.

Read-only streams have three private implementation components. `stream.c` owns
ordinary attribute-derived construction and final release. `stream_mapping.c`
owns mapping-pair assembly, run lookup and the distinct metadata-only `$Bad`
profile. `stream_read.c` owns physical/sparse reads, initialized-data clipping and
LZNT1 unit filling. All retain the existing shared stream object, volume allocator,
operation governor and decoded-unit cache; no additional owner or callback is
introduced. Public call admission remains in `api.c`, and WOF retains its separate
provider lifetime and content route.

Immutable security storage has three private components.
[secure.c](../core/secure.c) owns descriptor acquisition and snapshot lifetime;
[secure_index.c](../core/secure_index.c) owns complete SII/SDH seeks and ordered
cursors; [secure_store.c](../core/secure_store.c) owns whole-store validation.
The [private storage contract](../core/secure_internal.h) preserves the original
cursor/snapshot fields, volume allocator and caller charges. Wire decoding and
DACL evaluation retain their separate `security.c` and `access.c` contracts.
Splitting storage does not reorder ACEs or change native authorization.

Whole-volume validation retains one
[private context](../core/validate_internal.h), its bounded environment, borrowed
report, private mounted volume and accounted vectors. [validate.c](../core/validate.c)
owns credits, allocation/release and pass orchestration.
[Record/attribute passes](../core/validate_records.c),
[namespace/graph passes](../core/validate_namespace.c),
[allocation/boot/mirror passes](../core/validate_media.c) and
[security passes](../core/validate_security.c) share that same context. Pass order
remains records, attributes, mirror, boot, namespace, allocation, security.
Partial diagnostics, failure precedence, bad-cluster I/O refusal and final cleanup
retain their existing contracts; no pass receives a separate resource governor.

Immutable journal acquisition retains one
[source and workspace contract](../core/logfile_source_internal.h).
[logfile_source.c](../core/logfile_source.c) owns source lifetime, environment,
restart/client acquisition and volume binding.
[logfile_pages.c](../core/logfile_pages.c) owns protected pages and copy routing;
[logfile_index.c](../core/logfile_index.c) owns retained physical indexing;
[logfile_records.c](../core/logfile_records.c) owns complete record assembly,
checkpoint/transaction capture and ordered history visits. Borrowed page bytes
still belong to the source's original raw/scratch windows and survive only their
original observation boundary. Physical inventory, selected framing and owning
recovery evidence remain distinct; extraction grants no extra replay authority.

FSKit retains one volume owner across four private implementation components.
[NTFSVolume.m](../adapters/fskit/NTFSVolume.m) owns native lifecycle, request
admission, operation/publication serialization and replies.
[NTFSVolumeItems.m](../adapters/fskit/NTFSVolumeItems.m) owns canonical item and
ancestry binding, reader caches and directory-continuation storage.
[NTFSVolumeRead.m](../adapters/fskit/NTFSVolumeRead.m) owns complete immutable
lookup, attributes, data, xattr and enumeration bodies.
[NTFSImageVolume.m](../adapters/fskit/NTFSImageVolume.m) owns recovered image
construction, view replacement, authenticated open rights and prepared mutations.
The [private storage contract](../adapters/fskit/NTFSVolumeInternal.h) retains the
same volume/item fields and their ordering; categories introduce no additional
owner, monitor, callback or native item identity. Whole method bodies retain their
original lock, authorization, cleanup and reply order. Extraction qualification
and the separate installed gate are recorded in [REFACTORING.md](REFACTORING.md).

The private [NTFSWireBytes.h](../adapters/fskit/NTFSWireBytes.h) supplies the
identical little-endian byte encoder used by the native filename and stream
manifests. Their callers retain field widths, admission, allocations and
publication. This pure byte helper owns no native resource or lifetime.

The private `NTFSImageTransport` platform component holds the original authorized
`FSPathURLResource` and balances successful security-scope access for its lifetime.
[FSKit transports that scope intact](https://developer.apple.com/documentation/fskit/fspathurlresource).
The transport opens only an existing writable, singly linked ordinary image;
it neither creates/truncates backing files nor derives device paths. POSIX flock
coordinates cooperating owners, and its caller must exclude uncooperative users
and mappings. This is an offline-image contract, not arbitrary file exclusivity
or block-device admission.

Each published immutable image reader retains a counted lease and claim generation.
Writes refuse before I/O while any lease survives, so native callers must close all
core children and drop read resources before mutation. Unclaim, revocation, changed
file identity/size/ownership and uncertain transfer/persistence prevent successful
stale reads. Availability checks validate the backing identity before cached
metadata and authorization as well as before data transfers. A subsequent immutable reader sees a fresh core epoch. Image readers and the
writer share one 64-MiB core allocation cap; private reservation may precede claim,
while all media I/O requires it. The existing read environment remains unchanged.
Native transfers reuse the POSIX image backend, with mandatory `F_FULLFSYNC` and
no cache-only fallback. A complete exclusive operation also excludes reader
publication between transfers. Reentrant unclaim poisons the transport and defers
lock release until the native transfer returns. Public macOS 27 image resource
loading selects this transport only after complete explicit editing policy;
installed scope passes for the tested authorized image; arbitrary uncooperative
access is still outside the ownership contract.

The private image-volume factory acquires and recovers its C owner before publishing
an immutable view. Its existing-file range operation closes all item caches, nodes
and read leases under publication/operation serialization before calling the
writer. Stable FSItems retain full sequence-bearing references and numeric ancestry;
no consumer follows an old core pointer. Successful completion allocates nothing.
The next read mounts a fresh view and lazily rebinds each item, including metadata,
stream catalog and directory ancestry. Allocation refusal is retryable and never
serves stale bytes or converts a durable write into an unreported failure.
Unmount closes admission before draining mutation; a reentrant request defers its
reply to a different execution context. Invalidation similarly defers C-owner
release until the active write returns. Uncertain I/O remains permanently poisoned.
Separate installed tests establish observer/prefaulted-mapping coherence and
shared-mapping writes after descriptor close for this bounded file profile;
component tests alone do not establish those native outcomes. Public block-resource owners retain read-only extraction. A separate
image-editing factory prepares native write replies before
mutation and retains open rights belonging to the backing file's native owner.
Its selected image policy cannot switch to extraction; unknown, conflicting or
forced-checker options refuse before image I/O. Authenticated owner/root/nobody FSContext delivery and actual open enforcement
pass in the installed test profile; broader security coverage remains open.

Path-resource probing retains the original URL, requires positive security scope
before opening the backing file, and acquires only a temporary immutable reader.
It publishes no write owner and performs no recovery or writes. Scope and claim
are released on every outcome. After the complete bounded native interrupted
recovery gate, public macOS 27 path loading now admits the complete image owner;
it never turns a read-only block owner into a writer. Separate installed authorization, cache/mmap, persistence, two fresh saved-URL
mounts and independent Windows postimage acceptance now pass for initialized
ordinary-file ranges; ACCEPTANCE.md records the exact limits.
Controller unload closes admission and replies only after mutation drains and
the image owner is released.

Format values live in `core/disk.h`; implementation budgets live in
`core/internal.h` and the public default limits. Field positions come from
`sizeof`/`offsetof`. Tests author their own named wire fields and geometry so
expected values do not simply mirror parser expressions.

Public owning boundaries in `core/api.c` create an implicit execution scope or
share the caller's explicit scope. Core reads, allocation attempts and defined
work charges check every ancestor before admission; all volume-owned storage
shares one live cap. Optional record-cache storage may be omitted without
poisoning a successful required read. FSKit wraps compound requests and separately
charges rounded physical fragments. Caller scope storage survives native teardown
through explicit detach/end. [OPERATION-BUDGETS.md](OPERATION-BUDGETS.md) defines
API version 2, accounting/error/lifetime contracts and excluded native memory.
These policies do not supply a synchronous-I/O deadline or full RSS bound.

Complete filename counts have a volume-owned bounded memo in the existing record
cache array. Each payload has its own full sequence-bearing reference, independent
of the raw record stored in that slot. Raw-record replacement cannot discard the
checked count. A round-robin cursor replaces count payloads only after a complete
successful inventory; failures publish nothing. A fresh node still validates its
base record and physical header before reuse. The immutable media and serialized
owner contract bounds validity to this mounted volume. Node-local reuse remains
available when record caching is disabled.
The payload adds sixteen bytes per configured slot on both supported architectures,
or 1 KiB at the default 64 entries, without a separate allocation or public ABI
change. Zero record-cache entries disables volume reuse. Lookup charges every
inspected payload and cold publication is precharged before inventory I/O;
operation and ancestor admission remain mandatory on hits. NATIVE-NAMESPACE.md
and PERFORMANCE.md record the semantics and measured scope.

Each nonresident stream retains one mapping-array index for read locality.
Raw storage and cold LZNT1 unit fills recheck the current run and its immediate
successor before the binary-search fallback. Bounds and VCN membership are
checked on every hit; an index remains valid across bootstrap run-array growth.
The position describes verified geometry, so an I/O failure can retain it while
a later read still requires full callback admission and successful data transfer.
Independent streams own independent positions. Diagnostic pure lookups retain
their binary-search contract. The private field adds eight bytes per stream on
the tested architectures and allocates no separate storage.

All calls on one volume and its children require external serialization. Objects
hold a counted volume lifetime; unmount returns BUSY while nodes, public streams,
reparse snapshots or iterators remain open. Streams own decoded metadata
independently of source nodes. The FSKit adapter supplies serialized admission
and closes every child before unloading its retained resource. Removal and failed
reads return I/O errors.
The resource owner permanently latches FSKit revocation. Admission checks precede
cached stream and metadata operations, and a completed read is checked again;
cleanup remains permitted on a failed owner without further device reads.
The resource uses caller storage directly only when the physical disk offset,
caller address and complete bounded fragment length are aligned. Other fragments
use one aligned private window; rounded device spans never reach a partial caller
span. Exact-read errors may alter requested destination bytes, which callers
discard. Full transfer and post-read availability are required before success;
native read replies also require final admission and report zero bytes on error.
The resource keeps the same 1-MiB fragment/window bound and core allocation cap.
PERFORMANCE.md separates measured memory-reader benefit from native performance.
Native admission has a separate short-held lock, so unmount/deactivation close it
before waiting for an outstanding serialized read. Unmount drains operations and
closes transient item caches while preserving nodes for reclamation; invalidation
releases every child before the core/resource. Delayed reads cannot report success
after observing closed admission. Replies run outside the operation monitor.
Activation/lookup result publication has a separate lock shared with reclaim and
teardown. On macOS 27, the adapter uses conditional native reclaim while preventing
concurrent item returns. Older runtimes defer cleanup until the last FSItem
reference. Weak canonical indexing and each item's retained owner avoid a cycle;
final-reference cleanup releases children without device I/O. Native count and
installed scheduling qualification remain separate from the tested eligibility
model.
[LIFECYCLE.md](LIFECYCLE.md) defines remount, overlapping teardown and the remaining
synchronous cancellation/deadline and installed-runtime limits.
The filesystem controller has separate load/unload/check reservations; its monitor
never spans core I/O, volume ownership methods or replies. Maintenance admits an
inactive volume without live items, runs a private validator through the same
serialized resource pool, then seals and detaches its admission/resource owner.
Forced failed-layout loads can publish a geometry-free, nonmountable unary identity
with valid zero statistics. Quick/full scope, asynchronous repair/format refusal,
cooperative cancellation/drain and terminal retirement retain separate contracts
from ordinary item-read interruption; see the lifecycle document.
An independent Dispatch pressure observer changes read-cache retention without
waiting for the operation monitor or traversing dormant items. Access/completion
boundaries release default streams, catalogs and raw reparse snapshots while
preserving checked nodes, native targets and the latest or pinned directory
continuations. Older inactive positions can be reconstructed after eviction. See
READ-CACHE-POLICY.md for source lifetime, measured component bytes and the remaining
installed delivery/aggregate-stress limits.
Opening a named stream reads file metadata independently of the default stream:
an encrypted default stream does not prevent opening a separate unencrypted ADS.
Stream names match exact UTF-16 units; filename lookup has a different contract.

Regular-file stat uses a private metadata-only stream description. It validates
the complete unnamed attribute and its extent/list ownership, VCN continuity,
sizes and physical allocation without reading or copying its content. Known
attribute framing remains inspectable when encryption, compression format or
compression-unit geometry prevents content decoding. Unknown flag families and
malformed mappings still fail explicitly. Every read entry point rejects a
metadata-only description, including EOF and zero-length reads; public stream
opening keeps its strict decoder checks. FSKit can therefore adopt such ordinary
files, supply requested sizes and enumerate their independent ADS without
presenting encoded bytes as file data. Reparse objects retain their separate
provider/link projection contract.

The stream-name catalog is an independent immutable snapshot, sorted by exact
UTF-16 units. It validates first-extent references without requiring content
support; complete mappings are checked by stream open. Both FSKit protocols expose
bounded read-only stream xattrs and a lossless reverse manifest, with owner
admission before cached access. See NATIVE-NAMESPACE.md for format, limits and
the remaining authorization and unsupported-object contracts.
The native name policy has its own adapter module. Original UTF-8 within NAME_MAX
passes through; reserved, oversized and unpaired names use a sequence-bearing
reference and visible-link ordinal in their owning directory. Bounded independent
cursors resolve aliases and expose original UTF-16 manifests without moving a
native enumeration continuation. Exhaustion is an error, never successful
truncation. Native case/normalization and installed behavior remain unqualified.
Names-only directory enumeration has a virtual current/parent prefix and a
separate cookie view tag; disk-visible ordinals still identify projected names.
Directories keep the checked owning edge's numeric parent reference without
retaining a parent FSItem. Exact native `.` and `..` lookup uses the same checked
ancestry; both root components select the root. A live canonical parent needs no
core allocation or I/O. If its FSItem was released, the adapter reopens the full
sequence-bearing reference and checks ordinary-directory metadata before
adoption. Admission, compound budgets and item publication still own this path;
stored dot names remain separately addressable through aliases.
Wrong-view/stale/out-of-range cookies use the native
directory-cookie error. See LIFECYCLE.md for local parent/replay/fault evidence
and the remaining unsupported-object and installed contracts.
Each enumerated directory lazily allocates a two-position continuation table
through the resource's bounded allocator. Every slot owns its actual core cursor,
pending entry, native view, visible position, inspected-entry credit and budget
failure; no core traversal state is copied or shared. Noninitial cookies select
the same view's exact position or closest earlier retained position. Otherwise
the adapter replaces a completed scan, unused slot or least-recent inactive
position before constructing a fresh cursor. Initial cookies always start fresh.
Native packing pins a slot, and the item bounds recursive enumerations to two
calls even across reentrant remount. A precisely retained table owner keeps C
storage and its allocator alive while teardown closes every core child and
detaches the table. An item epoch makes the old call stale after that transition,
even when a packer has already remounted the same immutable owner. Persistent
cookie verification still describes that immutable owner. Pressure cleanup
drops older inactive slots; neither pinned cursors nor native cookies change.

Reparse metadata uses the ordinary attribute reader, including resident values,
fragmented nonresident mappings and sequence-checked attribute-list extensions.
`ntfs_reparse_open` owns a snapshot bounded by Windows' 16-KiB complete-buffer
limit; resident storage transfers from the temporary stream without another data
copy. The snapshot survives node close and never reads the device again.
`ntfs_reparse_decode` also validates standalone buffers without allocating.
The Microsoft envelope requires an exact declared size. Symlink and mount-point
name offsets are relative to their path buffer, aligned to UTF-16 units and checked
against its span; embedded NULs and empty substitute names are refused. Strings
may appear in either order, share storage and omit terminators. Reserved fields
are ignored as specified; unknown symlink flags return UNSUPPORTED.

The snapshot reports original tags, link flags and both stored names. Name copying
returns host-endian UTF-16 losslessly, including unpaired surrogates, without adding
a terminator. It checks capacity before any copying. This is structural decoding,
not Windows path resolution or a complete pathname-policy validator. WOF, all cloud
tag variants and unknown Microsoft tags are classified with opaque payloads;
classification alone does not decode their content. GUID framing remains
UNSUPPORTED. Microsoft-tagged
buffers whose size fits only the GUID envelope also report UNSUPPORTED; this is
not validation of the GUID or its provider payload.
The independent `ntfs/wof.h` primitives validate the observed file-provider
payload, bounded cumulative chunk tables and one exact-size XPRESS-Huffman block
or independent WOF/WIM-variant LZX32K unit.
The decoder uses caller-owned aligned scratch and no allocation/I/O. Failed
decoding leaves its byte count zero but may replace an output prefix. The WOF
stream owns sparse unnamed and exact named backing descriptions, validates all
extents and the complete chunk table through one 4-KiB page before publication,
then lazily retains a required private input/output unit and codec workspace.
A second output-only unit is optional and shares the bounded cache policy below.
Victim tags are invalidated before replacement and published only after successful I/O/decode.
The public stream owns the counted volume lifetime independently of its source node;
private backing descriptions do not double-count it. Known provider metadata can
report logical/backing-physical sizes without requiring a supported codec or
reading the table. Placeholder VDL does not zero provider content. Independent ADS
stay readable while the backing encoding itself remains catalogued but inaccessible
through public streams/xattrs. WOF.md defines codec variants and Windows/native gaps.
Default data reads reject other reparse nodes; directory traversal rejects all
reparse nodes. An attribute existing without its standard-information flag is
corrupt. Presence checks scan
both the base record and the complete attribute-list envelope, regardless of name;
an omitted base attribute or invalid named reparse attribute cannot evade the guard.
Checking absence can read an attribute list even for an ordinary file. FSKit
projects supported symlink/junction objects under LINK-POLICY.md's
explicit current-volume binding and filename policy. Numeric ancestry carries
directory provenance without retaining parent FSItems. Cached immutable native
targets are separate from counted wire snapshots, which unmount closes and raw
xattr access reopens. Names-only pages classify checked metadata without resolving
targets; requested attributes require truthful projected sizes. The adapter's
intermediate-directory resolver retains emitted native link components while
checking their within-owner destinations to translate subsequent names. A full-
reference active stack detects cycles; cumulative snapshot, component and alias
credits span every nested expansion. Context-dependent hard links, cross-volume
ownership, installed path walking and full native authorization remain open.

An MFT record cache contains only validated immutable records and has an explicit
entry budget. Metadata copies prevent eviction from invalidating a node. Run
vectors coalesce adjacent runs, grow geometrically within a cap and use binary
search. Data I/O coalesces within physical runs and clips at initialized data and
EOF. Sparse regions and uninitialized tails are zeroed without device reads.
LZNT1 and WOF streams retain at most two decoded units, with separate bounded
input storage. The required decode allocation owns one output, input and any
codec workspace. After a useful first fill, one distinct-unit miss attempts a
single optional output allocation. Failure or allocation/live-credit refusal
keeps the one-unit path and does not poison the operation. The optional attempt
is not repeated during that stream's lifetime. Both allocations remain charged
to the volume and owning scopes; stream close releases them exactly.
The current unit keeps its direct hit path. Reusing the older unit promotes it;
a miss invalidates only the older victim before any I/O, table lookup or decoding.
A failed fill preserves the other valid output. Without extra storage, replacement
invalidates the single output as before. Complete decode/raw copy and padding
precede publication. There is no global file-data cache or speculative read-ahead.
Direct LZNT1 decoding distinguishes
insufficient output capacity from corrupt input. A decoded unit exceeding its
on-disk unit size is corrupt at the stream boundary.

A live node caches standard-information metadata and the checked reparse-presence
result only after that complete operation succeeds. The cache has no separate
allocation or owner, inherits the record snapshot's immutable-media lifetime and
is never populated by failed I/O, allocation or corruption checks. Sizes and runs
of individual streams still undergo complete attribute validation; stat does not
cache a readable stream or bypass content checks. FSKit admission
checks continue to gate cached operations after permanent revocation.

Checked base metadata also survives temporary node closure in the existing
volume record-cache allocation. A direct-mapped slot uses record number modulo
configured capacity for constant-cost lookup, while metadata.reference carries
the complete sequence-bearing key. Raw bytes, filename counts and metadata have
independent keys and replacement. A hit compares the newly checked base header's
physical links and directory flag before node-local publication. Only complete
successful standard-information/presence validation replaces a payload; even a
failed colliding object retains the previous checked value. Zero reference marks
an unused slot because checked nodes require a nonzero sequence.
No stream size/mapping, decoded reparse packet or readable content is retained in
this memo. Record-cache capacity zero disables it while preserving node-local
reuse. Each configured slot adds sizeof(struct ntfs_stat) to mounted storage,
without a separate allocation. The original cold/node-local charges remain,
plus one payload lookup and cold publication precharge. The owner remains
immutable and externally serialized; this is not a concurrency change.

The standalone security decoder in `ntfs/security.h` owns MS-DTYP byte framing.
It returns original control bits, lossless SID values, checked component spans,
and distinct absent/NULL/empty ACL states. It validates known ACE layouts, optional
object GUIDs and callback/application spans without sorting or interpreting
conditions. Unknown ACE bodies remain explicitly opaque. No input pointer becomes
a native identity or access grant. The resolver now owns bounded immutable
snapshots from `$Secure` or per-file descriptor attributes, independently of file
content. It checks both indexes and SDS copies, reuses one block buffer and
retains original bytes. The separate whole-store diagnostic traverses both
supported view trees and used allocation inventories, checks exact membership
and nonoverlapping SDS intervals, and validates every indexed descriptor/copy.
The private whole-volume diagnostic additionally checks nonzero FILE-ID
references and selected zero-ID per-file descriptor framing. Source selection,
budgets and evidence are defined in
SECURITY.md. A separate allocation-free discretionary evaluator uses immutable
caller-owned user/group/restricting contexts, preserves plain ACE order and exact
file-right mappings, and returns no partial grant on denial/error. It checks all
applicable DACL features before deciding and shares a bounded SID-comparison
budget across ownership and both token contexts. ACCESS.md defines supported
ownership and explicit unsupported cases. Full token/security policy, identity
mapping and owning native authorization remain incomplete contracts.

Directory enumeration owns an explicit stack of at most 32 index frames, a
bounded hash set of visited child VCNs and a persistent in-order cursor. Lookup
descends the filename B-tree. Every child checks its allocation bitmap, VCN,
fixups, entry spans, parent references, local ordering and inherited ancestor key
bounds. Unicode collation uses the volume's validated $UpCase, with original
UTF-16 units breaking case ties. The stored standard-information directory flag
selects exact or folded lookup without changing that ordering. Sensitive lookup
seeks the full key; insensitive lookup seeks the folded lower bound and checks
its successor for ambiguous collisions, including across a tree boundary. Each
directory owns its policy independently of its parent. UTF conversion rejects
invalid sequences. CASE-POLICY.md records format sources, unsupported flags and
the volume-wide FSKit capability strategy requiring native qualification.

Mount verifies primary and mirrored MFT bootstrap records, volume version and
flags, $UpCase, and the root index. It does not claim a full filesystem check.
Volume-information version admission precedes flag classification. A set named
dirty bit returns DIRTY; other nonzero flags remain UNSUPPORTED. Only zero flags
can advance mounting. An unsupported flag is not interpreted as dirty state or
as proof that Windows repair is required; no flag is cleared to admit a volume.
The separate synchronous `ntfs_validate` API uses its own private mount and
budgeted callback owner. It scans record allocation, complete supported attribute
mappings, the required four-record mirror prefix/boot-anchor mapping, exact
filename/index edges, directory reachability, physical cluster ownership and
selected security storage. Missing ordinary zero-ID descriptors fail; specific
fixed internal metadata and empty/inert reserved records can lack them, while
every present selected descriptor still undergoes framing checks. Descriptor
staging is private to each file and
released before the next; decoding shares diagnostic and mounted work credits.
Mirror replicas use two bounded private record buffers; allocated copies compare
used logical bytes after MST restoration, while free slots remain opaque. Larger
declared mirror tails have explicit unchecked counts and no native coverage claim.
The boot pass resolves fixed slot 7's ordinary nonresident LCN-zero data owner
and compares one full logical sector with its declared reserved backup. Private
sector buffers and exact backing bounds retain diagnostic credits without
widening mounted stream bounds. Larger supplied resources cannot relocate the
copy. Agreement is scoped to the observed backup profile; boot-loader tails,
Windows variants and recovery authority remain separate. See VALIDATION.md.
Bounded heapsort and an iterative graph walk keep temporary storage
and traversal explicit. It never mutates an existing mounted owner or reads bad
sectors. Its complete flag applies only to those defined passes; unsupported
features, faults and budget exhaustion retain partial reports. VALIDATION.md
defines system-file interpretation, evidence and remaining store/recovery gaps.
The fixed bad-cluster stream now uses an internal metadata-only description
through the shared complete attribute-list/extension reader. Its volume-sized
implicit holes and VCN-equal physical runs retain their special size contract;
ordinary sparse/content decoding is unchanged. Public access to that system
stream is explicitly unsupported, and no diagnostic path can read bad storage.
Flagged storage and native Windows chains retain separate qualification under
VALIDATION.md.
Dirty/recovery-flagged volumes are refused without replay. MFT bootstrap supports
resident/nonresident attribute lists. The first data extent belongs to record
zero; each extension must be reachable through the already decoded MFT prefix.
An extension may reveal the runs needed to read a later extension. No guessed
physical placement is used, and the record cache is enabled after bootstrap.
Ordinary attribute lists use the same instance, sequence, base-reference and
contiguous-VCN checks. The attribute list's own mapping must fit its base record.
EFS data, complete reparse resolution and NTFS security enforcement remain explicit gaps;
see acceptance.

Independent `ntfs/logfile.h` primitives decode immutable LFS 1.1/2.0 common
restart/client/page/LSN/record framing with bounded caller scratch and no I/O or
allocation. Client chains have complete membership/backlink and active-LSN
checks. The NTFS update decoder validates empty/nonempty LCN vectors and redo/undo
spans; count-zero storage retains one opaque reserved slot before absolute data
offsets. Independent original historical packets qualify that observed layout.
Allocation-free name-entry/full-dump decoders preserve lossless UTF-16LE spans with
byte-counted lengths, unpadded entries and exact string/list terminators. Membership
and owning cross-table semantics remain separate. The separate NTFS client restart
decoder retains the 64-byte common prefix for client formats 0.0/1.0, raw LSN/count
pairs and an opaque extension span. Named-field publication into a zeroed output
retains deterministic padding without copying a temporary structure. Table
contents, optional extensions and complete checkpoint semantics remain opaque. LOGFILE.md
defines the primitive/complete-journal boundary. An independent logical-source
owner now probes bounded restart-copy candidates, selects compatible newer/equal
areas and reports conflicts or partial read evidence. An exported source's
read-only callback context outlives the serialized owner. The separate volume
binder resolves fixed MFT record 2's ordinary fully initialized unnamed stream
through complete extent/list/sequence checks, closes the temporary node and
holds a counted backing stream. Unmount is BUSY until every journal owner closes;
owner buffers/object release before the stream callback context. Logical-source
credits start after construction, separately from metadata/run and physical I/O
limits. Unsupported encoded/sparse/partial-VDL or reparse/directory/view forms
refuse automatic binding explicitly.
Three bounded private buffers retain selected metadata and stage physical page
reads, publishing caller bytes only after complete integrity checks. Native
journal admission/drain integration remains separate. The serialized physical
inventory now preflights exact whole-storage read credits and scans every copy
slot/circular page using those buffers without allocation. Its transient visitor
receives common metadata plus independent target/structural results; backend
failure aborts before exposing failed bytes. Coverage, routing-valid observed LSN
maxima and partial progress have explicit counters. Complete coverage does not
select competing copies, a current endpoint or continuation provenance. RSTR
CurrentLsn remains a restart-time observation, not a bound on later log records.
An explicit optional retained index now owns complete per-target prefix comparison,
unresolved-copy evidence and direct selected-page acquisition in this journal owner.
One caller-bounded allocation contains target metadata and comparison scratch;
whole-scan plus worst-case copy-read credits are admitted before work. Only a
complete preparation publishes it; cached queries have no callbacks, and clear/close
release it. Indexed record reads recheck selected protected headers/targets and
reuse exact assembly. Legacy circular zero-start continuations retain observation
without provenance. RSTR CurrentLsn does not limit candidate epochs. Ordered
active-window/endpoint/continuation qualification remains separate; native analysis,
recovery and persistence still require their owning contracts. See LOGFILE.md.
The same prepared owner supplies a bounded selected-record visitor from an exact
caller anchor. Per-target routing metadata remains private; a continuation's header
LSN page is never substituted for its declared copy target. An O(targets + copy slots)
pass gathers a candidate completed end and preserves regressions/unresolved evidence.
Ordered exact assembly, written boundaries and physical sequence/wrap checks must
agree through that end. A tagged unfinished successor has separate header-only
verification. One operation shares all read credits and one private record staging
allocation at a time; successful callbacks borrow unpadded bytes. Reports retain
partial evidence and cannot authorize native recovery or resume a failed analysis.
Native client analysis owns its lower bound, transaction state and durability gate;
selected framing alone does not qualify continuation freshness or native history.
Physical circular-record
assembly locates the first header by LSN and joins adjacent protected payload
pages through at most one wrap. One shared operation budget, a no-page-revisit
bound and at most one 1-MiB ephemeral allocation limit traversal and memory;
caller bytes publish only after all framing/link-geometry checks succeed. The
observation does not establish written/current history or route tail/fast copies.
Those contracts, native client/transaction interpretation and recovery remain
separate work. The mount policy still refuses dirty media.
Completed LFS 1.1 observation additionally examines both tail slots, selects only
compatible completed copies and shares credits across copy scans and record pages.
Selected tail segments and the final circular segment must fit their declared
written prefixes. Earlier unfinished circular segments may extend beyond
NextRecordOffset. The final record-end/last-end-LSN witness remains mandatory.
I/O transfer positions never identify record fragments; complete current history
and continuation provenance remain separate from this immutable observation.
Cached active-client lookup additionally matches a selected restart entry's
index/sequence and bounded in-use membership with no allocation or callback.
Inactive entries remain inspectable through the separate raw snapshot getter;
their old LSNs do not authorize active lookup. Matching a pair is separate from
record liveness, current history and native payload interpretation.
`ntfs_logfile_decode_client_restart_record` now combines exact assembled-record
framing with selected active identity, the exact NTFS client name and equality
with its nonzero stored restart LSN before common-prefix decoding. It uses the
selected header length and no additional callbacks or allocations. Foreign types/
names and stale identity/LSNs fail before payload interpretation, with zero output.
This snapshot binding does not establish page/continuation provenance or current
written history; native journal admission/drain remains separate.
The independent `ntfs/checkpoint.h` composition then binds an exact dump record
to that checkpoint's named anchor, selected geometry and client pair. It checks
the action envelope, advertised body length, complete free topology and every
allocated versioned entry before publishing borrowed spans. Absent anchors ignore
dump input; every failure leaves zero metadata. No I/O or allocation occurs.
The complete snapshot then checks distinct dump LSNs and name/dirty targets against
allocated physical OAT keys. Checked fixed-stride lookup is constant work; duplicate
name targets use a caller-owned bitset, at most 8 KiB. The full walk is linear in
supplied bytes. Client-0 opaque stored self-references are never lookup keys. Errors
zero the whole snapshot, and source/record bytes remain immutable without callbacks.
Volume reference/type/LCN semantics and complete current page/copy history remain
owning-layer work before native analysis, redo/undo or writable admission.

The checkpoint transaction composition acquires those owned inputs internally,
admits every allocated seed, then binds each complete chain to its physical
transaction-table key and stored first/undo roots. Capture and all chains share
source-bounded I/O and aggregate record credits. Disjoint caller buffers hold the
private checkpoint, one reusable record and bounded link pairs; no additional
retained owner allocation is introduced. Callbacks see fully bound individual
chains but must retain the whole analysis privately until outer success. Raw
states and markers cannot choose recovery actions. Post-checkpoint native state,
current continuation ownership and durability remain separate under WRITES.md.

Private logical journal encoders accept immutable typed descriptions and borrowed
byte spans without callbacks or allocation. Wire widths and checked disjoint used
output ranges gate every store; all errors and unused capacity stay unchanged.
The LFS encoder writes only its known common header, leaving physical geometry,
identity, flag planning and current history to the journal owner. The update encoder
derives vector count and exact aligned data layout before serialization, allowing
caller reservation through the same measurement admission. Reserved storage and
inter-span padding are zero, and borrowed spans are copied once. Opaque target/opcode
values authorize no physical action. WRITE-FOUNDATIONS.md defines the private
packet/publication boundary; native transaction planning and device durability remain
required under WRITES.md.

The private page encoder constructs only common-header LFS 1.1 RCRD pages. A complete
restored data region and typed scalar fields are admitted before touching either used
buffer. Caller workspace and output each hold one page, bounded by the 64-KiB policy,
and remain disjoint from each other, the description and borrowed bytes. Canonical
header/USA padding is cleared; the body is copied once into workspace, then the
existing protection primitive copies and seals the output. This uses constant stack
space and no allocation or I/O. Transfer count/position and next-record boundaries
have scalar checks; copy_value and last_end_lsn stay opaque. Modern layouts, unknown
flags, physical placement, completion/history decisions and persistence remain the
owning journal planner's work. WRITE-FOUNDATIONS.md records the complete contract.

Future LXNU integration can reuse freestanding algorithms through a new owning
adapter. It must preserve native object lifetime and authorization, and must not
turn FSKit into a userspace syscall translator. No speculative kernel hooks are
part of this delivery.
