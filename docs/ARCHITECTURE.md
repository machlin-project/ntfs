# Architecture

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
then lazily retains one private input/output unit and codec workspace. Cache tags
are invalidated before replacement and published only after successful I/O/decode.
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
projects supported single-edge symlink/junction objects under LINK-POLICY.md's
explicit current-volume binding and filename policy. Numeric ancestry carries
directory provenance without retaining parent FSItems. Cached immutable native
targets are separate from counted wire snapshots, which unmount closes and raw
xattr access reopens. Names-only pages classify checked metadata without resolving
targets; requested attributes require truthful projected sizes. Intermediate
reparse chains, context-dependent hard links, cross-volume ownership and full
native authorization remain open.

An MFT record cache contains only validated immutable records and has an explicit
entry budget. Metadata copies prevent eviction from invalidating a node. Run
vectors coalesce adjacent runs, grow geometrically within a cap and use binary
search. Data I/O coalesces within physical runs and clips at initialized data and
EOF. Sparse regions and uninitialized tails are zeroed without device reads.
Compressed streams retain one decoded compression unit, with separate bounded
input storage. There is no global file-data cache or speculative read-ahead.
Changing compression units invalidates the cache before I/O; a failed fill cannot
leave a valid tag on partially replaced data. Direct LZNT1 decoding distinguishes
insufficient output capacity from corrupt input. A decoded unit exceeding its
on-disk unit size is corrupt at the stream boundary.

A live node caches standard-information metadata and the checked reparse-presence
result only after that complete operation succeeds. The cache has no separate
allocation or owner, inherits the record snapshot's immutable-media lifetime and
is never populated by failed I/O, allocation or corruption checks. Sizes and runs
of individual streams still undergo complete attribute validation; stat does not
cache a readable stream or bypass content checks. FSKit admission
checks continue to gate cached operations after permanent revocation.

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
checks. The NTFS update decoder validates nonempty LCN vectors and redo/undo spans;
LCN-less updates remain explicitly unsupported. The separate NTFS client restart
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
journal admission/drain integration remains separate. Physical circular-record
assembly locates the first header by LSN and joins adjacent protected payload
pages through at most one wrap. One shared operation budget, a no-page-revisit
bound and at most one 1-MiB ephemeral allocation limit traversal and memory;
caller bytes publish only after all framing/link-geometry checks succeed. The
observation does not establish written/current history or route tail/fast copies.
Those contracts, native client/transaction interpretation and recovery remain
separate work. The mount policy still refuses dirty media.
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

Future LXNU integration can reuse freestanding algorithms through a new owning
adapter. It must preserve native object lifetime and authorization, and must not
turn FSKit into a userspace syscall translator. No speculative kernel hooks are
part of this delivery.
