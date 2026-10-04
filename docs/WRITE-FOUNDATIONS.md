# Private metadata and journal encoding

Device writes remain disabled. These original C primitives prepare native write
and recovery implementation without giving the immutable read environment a
write callback or changing FSKit mutation admission. The complete ownership and
durability gate remains [WRITES.md](WRITES.md).

The immutable LFS 1.1 owner also checks declared written-prefix admission for every
selected completed tail segment and the final circular segment. Earlier unfinished
circular segments are not capped by NextRecordOffset. Independent separate-transfer,
wrap and historical-byte checks qualify this framing rule only; current history and
continuation provenance remain required. See LOGFILE.md and ACCEPTANCE.md.
The modern LFS 2.0 observer now selects completed fast copies per circular target
with bounded 32-slot examination and equal-epoch written-prefix checks. This is
immutable reading; it does not expand the private page encoder's LFS 1.1 profile
or establish complete current history, native recovery or writable admission.
Native Windows Recovery snapshot packets now confirm that observation profile
and selected-client table membership. No generated packet or page has gained
Windows-consumption or durable-publication evidence from those reads.

## Logical journal output

`ntfs/logfile_encode.h` owns allocation-free logical LFS record and NTFS update
serialization. It grants no device capability. Typed descriptions have normal C
alignment; borrowed payload/vector buffers and encoded output require only byte
alignment. Inputs remain immutable through the call. Used output must be disjoint
from the description and every nonempty input; input buffers may alias each other.
Checked address-range overflow and overlap return INVALID before publication.
Every error preserves the whole output, including the measurement result; bytes
after the exact encoded packet remain unchanged even when capacity shares storage
with an input beyond that used packet.

The LFS encoder accepts the known 48-byte common header and exact described payload
length. Larger aligned header extensions, unknown record types and unknown flags
return UNSUPPORTED. Invalid scalar framing/description returns INVALID; wire/policy/
capacity refusals are RANGE. The nonzero LSN, scalar previous/undo order and client
index checks match the packet decoder. Physical LSN geometry, active client identity,
record liveness and MULTI_PAGE planning remain the future journal owner's contract.
Known flags are preserved without guessing placement. Header padding is zero and
no trailing alignment bytes are emitted.

The update description borrows an exact little-endian LCN byte vector plus redo and
undo bytes. Vector length must be divisible by sizeof(uint64_t); its derived count,
redo/undo lengths and every nonempty data start must fit the native uint16_t fields.
The measurement publishes an exact uint32_t byte count after the same admission as
encoding, for later reservation/planning. Empty data spans use offset zero. Redo
follows the stored vector prefix; undo follows aligned redo. An empty vector still
reserves one zero LCN slot. Raw operation codes, flags, targets and LCN values confer
no address/recovery interpretation. Scalar fields and borrowed content are preserved;
reserved storage and inter-span padding are zero. Only padding/header storage is
cleared, and each borrowed span is copied once. No whole-packet zeroing, allocation,
callback or I/O is needed.

Independent whole-packet goldens cover every known LFS flag combination, both types,
unaligned payload lengths, empty/shared data, maximum vector/length/start fields and
the record cap. Direct rejection tests cover NULL/overlap/address/width/offset/capacity
boundaries and unchanged inputs/errors. Retained native input packets preserve their
original bytes; canonical output placement is explicitly authored. No generated
packet has yet been consumed by Windows recovery. ACCEPTANCE.md records current
counts, fuzz and original-input comparisons. Physical WAL pages, ordering, native
transaction semantics and durable publication still require WRITES.md acceptance.

## Private protected journal pages

`ntfs_logfile_page_encode` constructs one common-header LFS 1.1 RCRD page from a typed
description and the complete restored data region, including caller-owned unused
bytes. It has no allocation, callback or device I/O. Modern/unknown versions and
unknown flags return UNSUPPORTED. Page size must be a power of two from the fixed
512-byte protection stride through the named 64-KiB policy. The canonical USA follows
the complete named common page header; the aligned data offset must leave that whole
array and room for a common logical record header. The borrowed length must exactly
fill the remaining page. Transfer position/count must be consistently zero or in
range; a nonzero next-record boundary must be aligned inside the data region.

These are scalar framing checks. `copy_value` and `last_end_lsn` remain opaque, even
at their maximum wire values. The helper neither validates physical LSN geometry nor
selects routing, completion, record fragments, current history or I/O transfers.
Those decisions belong to the native journal owner before device publication.

Workspace and output each require one complete page and byte alignment suffices.
Their used ranges must be disjoint from each other, the description and borrowed
data; unused capacity may alias inputs. Admission checks address overflow, capacities
and all geometry before stores. Every error preserves output; workspace is disposable.
Canonical reserved header/USA padding is zero, and the complete restored body is
copied once to workspace. `ntfs_record_protect` then saves every restored sector tail
and advances the supplied prior sequence while skipping reserved values. Inputs and
unused capacities stay unchanged. Constant stack use preserves the freestanding
2-KiB frame budget; the caller owns both page-sized buffers.

Forty-four independent whole-page goldens cover 512-byte, 4-KiB, 16-KiB and 64-KiB
pages, sequence boundaries and 24 transfer/flag/next-record combinations. Tests check
aligned/unaligned bytes, exact/extra/one-below capacities, restoration of every tail,
repeatability, descriptor/data/buffer aliasing, address/width/version refusals and
unchanged errors. Main independently reconstructs all complete golden pages from
named fields and restored bodies, checks all 132 packet files and compares 132 new
fuzz envelopes. These are synthetic canonical output cases, not Windows-generated or
Windows-consumed pages. ACCEPTANCE.md records final evidence and the retained initial
test-compilation failure. WAL planning and recovery remain required under WRITES.md.

## Protected metadata output

`ntfs/record.h` exposes `ntfs_record_protect` for a complete private, already
restored FILE, INDX, RSTR or RCRD snapshot. It accepts byte alignment and disjoint
used input/output ranges, and allocates nothing. The named 64-KiB policy bounds
the complete record. Capacity, overlap, magic, stride and the entire USA geometry
are admitted before any output byte changes.

The encoder advances the stored sequence and saves original restored tail words
before substituting the new sequence. It skips zero and the reader's reserved
maximum sequence; a new zero/reserved initial value starts at one. USA protection
uses the fixed 512-byte stride independently of device sector size. Input and
unused output capacity remain unchanged; every failure leaves all output bytes
unchanged. Endian stores operate on byte arrays without host alignment assumptions.

This API proves protection geometry only. It does not validate higher FILE/index/
journal contents, acquire a writable device, reserve storage, construct a native
transaction or establish persistence. A transaction owner must validate and own
the complete snapshot, generate its log intent and order durable publication
before using encoded home bytes.

The independent fixture author specifies named wire fields and exact protected
bytes for all four magics, four record sizes through the cap, sequence boundaries,
unaligned buffers and exact/extra capacity. The C test compares the whole golden
packet, rejects corruption of each protected sector tail before restoration,
checks unchanged errors/input, and checks exact independent little-endian stores.

## Native restart tables

`ntfs/logfile_tables.h` decodes one exact restart table and allocated open-attribute,
dirty-page and transaction entries. All inputs remain immutable; errors zero
outputs. Byte alignment is sufficient. The record-byte policy and wire count widths
bound work without a table-sized allocation.

The table decoder checks every entry's allocation/link word, exact declared storage
and allocation count, then complete free-chain coverage, termination and stored
tail. Links are entry-aligned byte offsets from the table start. Bounding a
deterministic free chain by its exact free count detects cycles and disconnected
elements with constant scratch storage and linear work. Reserved fields and the
free-goal allocation hint remain opaque.

Open-attribute entries use the separate NTFS 3.0/3.1 client-0 and client-1 wire
layouts. Live name pointers never become disk addresses. The client-0 historical
self-reference is observed without inventing a resolution for its documented
entry-size discrepancy. Client-1 retains its raw dirty-page byte; interpretation
belongs to native analysis. Free entries return NOT_FOUND and ignore stale payloads.

Dirty-page entries preserve the declared LCN span and remaining whole-vector
capacity separately. The vector must fit before publication. Raw target attribute,
transfer, VCN, LSN and LCN values still require qualified table ownership and volume
geometry. Transaction entries preserve the four known stored states and raw LSN/
undo fields; unknown allocated states refuse with UNSUPPORTED.

Attribute-name entry and complete-dump framing now has a separate allocation-free
linear decoder. Stored lengths count UTF-16LE bytes; each entry has a zero UTF-16
terminator and no alignment padding. A complete dump ends with an exact four-byte
zero header. Lossless name spans retain unpaired surrogates and embedded zero units.
Duplicate/target membership and owning name semantics remain separate from framing.
LOGFILE.md records the independently observed original packets and authored limits.

The update decoder now admits empty LCN vectors while retaining the reserved first
slot as opaque storage. Absolute redo/undo offsets must follow that complete stored
prefix. Original historical packets independently establish the observed 40-byte
prefix, including nonzero stale slot bytes. Compact forms lacking it are corrupt;
successful framing still authorizes no physical LCN or recovery action.

`ntfs/checkpoint.h` now composes selected-client RESTART binding, exact dump
LSN/client/action/body checks and complete versioned allocated/free framing.
It publishes borrowed spans only after the whole packet passes, without I/O or
allocation. An absent anchor ignores dump input and returns NOT_FOUND; foreign
identities/LSNs are STALE. LOGFILE.md records the admission/error contract and
explicit synthetic owner projections used with exact historical packets.

The complete snapshot also validates distinct dump LSNs and allocated physical OAT
targets for names and dirty pages. Duplicate name targets reject; several dirty
entries may share one target. One caller-owned bit per OAT entry bounds duplicate
checking to 8 KiB; errors zero the complete snapshot and no callbacks occur.
LOGFILE.md defines workspace, absent-table and borrowed-span contracts.

These are checkpoint framing/membership contracts. Volume references/types/LCNs,
current page/copy history,
transaction analysis and redo/undo remain separate work. A valid table or stored
committed state cannot authorize replay or a writable mount.

The independent author constructs every free subset and order through four entries,
mixed entry sizes and full 16-bit entry counts, then malformed heads/tails/links,
cycles, lost elements, count mismatches, client versions, truncated vectors and
stale free payloads. Structured fuzz selectors preserve table framing or allocated
entry markers for deeper mutations, alongside generic damaged inputs. The same
journal target also checks deterministic encoding/restoration and output guards.

Format facts come from [original USA notes](https://flatcap.github.io/linux-ntfs/ntfs/concepts/fixup.html),
[original checkpoint field tables](https://flatcap.github.io/linux-ntfs/ntfs/files/logfile.html)
and [original LFS research](https://dfir.ru/2019/02/16/how-the-logfile-works/).
Implementation, topology proof, admission/publication and fixtures are repository-owned.
These sources and synthetic vectors do not establish native Windows recovery.
