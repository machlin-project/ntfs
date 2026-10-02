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

All calls on one volume and its children require external serialization. Objects
hold a counted volume lifetime; unmount returns BUSY while nodes, public streams,
reparse snapshots or iterators remain open. Streams own decoded metadata
independently of source nodes. The FSKit adapter supplies serialized admission
and closes every child before unloading its retained resource. Removal and failed
reads return I/O errors.
The resource owner permanently latches FSKit revocation. Admission checks precede
cached stream and metadata operations, and a completed read is checked again;
cleanup remains permitted on a failed owner without further device reads.
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
Opening a named stream reads file metadata independently of the default stream:
an encrypted default stream does not prevent opening a separate unencrypted ADS.
Stream names match exact UTF-16 units; filename lookup has a different contract.

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
retaining a parent FSItem. Wrong-view/stale/out-of-range cookies use the native
directory-cookie error. See LIFECYCLE.md for local parent/replay/fault evidence
and the remaining unsupported-object and installed contracts.

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
their content is not decoded. GUID framing remains UNSUPPORTED. Microsoft-tagged
buffers whose size fits only the GUID envelope also report UNSUPPORTED; this is
not validation of the GUID or its provider payload.
Ordinary data reads and directory traversal reject reparse nodes. An attribute
existing without its standard-information flag is corrupt. Presence checks scan
both the base record and the complete attribute-list envelope, regardless of name;
an omitted base attribute or invalid named reparse attribute cannot evade the guard.
Checking absence can read an attribute list even for an ordinary file. FSKit
continues to reject reparse items until its
own target-translation, namespace and authorization contracts are defined.

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
of individual streams still undergo ordinary attribute validation. FSKit admission
checks continue to gate cached operations after permanent revocation.

The standalone security decoder in `ntfs/security.h` owns MS-DTYP byte framing.
It returns original control bits, lossless SID values, checked component spans,
and distinct absent/NULL/empty ACL states. It validates known ACE layouts, optional
object GUIDs and callback/application spans without sorting or interpreting
conditions. Unknown ACE bodies remain explicitly opaque. No input pointer becomes
a native identity or access grant. The resolver now owns bounded immutable
snapshots from `$Secure` or per-file descriptor attributes, independently of file
content. It checks both indexes and SDS copies, reuses one block buffer and
retains original bytes. Source selection, budgets and evidence are defined in
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
mappings, exact filename/index edges, directory reachability and physical cluster
ownership. Bounded heapsort and an iterative graph walk keep temporary storage
and traversal explicit. It never mutates an existing mounted owner or reads bad
sectors. Its complete flag applies only to those defined passes; unsupported
features, faults and budget exhaustion retain partial reports. VALIDATION.md
defines system-file interpretation, evidence and remaining store/recovery gaps.
Dirty/recovery-flagged volumes are refused without replay. MFT bootstrap supports
resident/nonresident attribute lists. The first data extent belongs to record
zero; each extension must be reachable through the already decoded MFT prefix.
An extension may reveal the runs needed to read a later extension. No guessed
physical placement is used, and the record cache is enabled after bootstrap.
Ordinary attribute lists use the same instance, sequence, base-reference and
contiguous-VCN checks. The attribute list's own mapping must fit its base record.
EFS data, reparse translation and NTFS security enforcement remain explicit gaps;
see acceptance.

Future LXNU integration can reuse freestanding algorithms through a new owning
adapter. It must preserve native object lifetime and authorization, and must not
turn FSKit into a userspace syscall translator. No speculative kernel hooks are
part of this delivery.
