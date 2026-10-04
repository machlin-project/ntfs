# Private metadata encoding and checkpoint framing

Device writes remain disabled. These original C primitives prepare native write
and recovery implementation without giving the immutable read environment a
write callback or changing FSKit mutation admission. The complete ownership and
durability gate remains [WRITES.md](WRITES.md).

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

These are checkpoint framing contracts. Table-dump record
binding, cross-table references, current page/copy history,
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
