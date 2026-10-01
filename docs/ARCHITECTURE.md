# Architecture

The portable C11 core owns NTFS 3.0/3.1 boot geometry, FILE/INDX fixups, MFT
references, attributes, mapping pairs, streams, directory indexes and Unicode
collation. Byte-array wire structures have compile-time size checks. No native
errno, allocator, filesystem runtime or page-cache object crosses this boundary.
The environment supplies allocation, deallocation and bounded exact reads.
It has no write method. Media must remain immutable for an entire mounted owner.

All calls on one volume and its children require external serialization. Objects
hold a counted volume lifetime; unmount returns BUSY while nodes, public streams
or iterators remain open. Streams own decoded metadata independently of source
nodes. The FSKit adapter supplies serialized admission and closes every child
before unloading its retained resource. Removal and failed reads return I/O errors.

An MFT record cache contains only validated immutable records and has an explicit
entry budget. Metadata copies prevent eviction from invalidating a node. Run
vectors coalesce adjacent runs, grow geometrically within a cap and use binary
search. Data I/O coalesces within physical runs and clips at initialized data and
EOF. Sparse regions and uninitialized tails are zeroed without device reads.
Compressed streams retain one decoded compression unit, with separate bounded
input storage. There is no global file-data cache or speculative read-ahead.

Directory enumeration owns an explicit stack of at most 32 index frames, a
bounded hash set of visited child VCNs and a persistent in-order cursor. Lookup
descends the filename B-tree. Every child checks its allocation bitmap, VCN,
fixups, entry spans and parent references. Unicode collation uses the volume's
validated $UpCase, not the host locale. UTF conversion rejects invalid sequences.

Mount verifies primary and mirrored MFT bootstrap records, volume version and
flags, $UpCase, and the root index. It does not claim a full filesystem check.
Dirty/recovery-flagged volumes are refused without replay. MFT attribute-list
bootstrap, EFS, reparse translation and NTFS security enforcement remain explicit
gaps; see acceptance. Ordinary file attribute lists may span extension records,
with instance, sequence, base-reference and contiguous-VCN checks.

Future LXNU integration can reuse freestanding algorithms through a new owning
adapter. It must preserve native object lifetime and authorization, and must not
turn FSKit into a userspace syscall translator. No speculative kernel hooks are
part of this delivery.
