# Architecture

The portable C11 core owns NTFS 3.0/3.1 boot geometry, FILE/INDX fixups, MFT
references, attributes, mapping pairs, streams, directory indexes and Unicode
collation. Byte-array wire structures have compile-time size checks. No native
errno, allocator, filesystem runtime or page-cache object crosses this boundary.
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
hold a counted volume lifetime; unmount returns BUSY while nodes, public streams
or iterators remain open. Streams own decoded metadata independently of source
nodes. The FSKit adapter supplies serialized admission and closes every child
before unloading its retained resource. Removal and failed reads return I/O errors.
The resource owner permanently latches FSKit revocation. Admission checks precede
cached stream and metadata operations, and a completed read is checked again;
cleanup remains permitted on a failed owner without further device reads.
Opening a named stream reads file metadata independently of the default stream:
an encrypted default stream does not prevent opening a separate unencrypted ADS.
Stream names match exact UTF-16 units; filename lookup has a different contract.

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

Directory enumeration owns an explicit stack of at most 32 index frames, a
bounded hash set of visited child VCNs and a persistent in-order cursor. Lookup
descends the filename B-tree. Every child checks its allocation bitmap, VCN,
fixups, entry spans, parent references, local ordering and inherited ancestor key
bounds. Unicode collation uses the volume's validated $UpCase, with original
UTF-16 units breaking case ties. Lookup seeks the folded lower bound and checks
its successor; distinct names with the same folded key return UNSUPPORTED even
when separated by a tree boundary. UTF conversion rejects invalid sequences.

Mount verifies primary and mirrored MFT bootstrap records, volume version and
flags, $UpCase, and the root index. It does not claim a full filesystem check.
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
