# Read-only log diagnostics

`ntfs/logfile.h` provides independent byte decoders for the common LFS 1.1/2.0
restart prefix/area, complete client lists, LSN geometry, protected record pages,
exact logical LFS records, an NTFS update payload with a nonempty LCN vector and
the NTFS client's 64-byte common restart prefix for client formats 0.0/1.0.
These byte primitives do not allocate, access a device, mutate input or provide
a write capability.
The ordinary mount and FSKit mutation contracts are unchanged. A successfully
decoded restart page or its clean hint does not authorize mounting dirty media.

The separate logical-source owner now reads bounded restart candidates and selects
compatible redundant copies with conflict reports. These are foundations for
journal inspection. A physical circular-record observer now assembles exact
bytes across adjacent protected pages and one wrap. It does not route legacy
tail/modern fast-page copies, validate the active circular history or interpret NTFS
checkpoint tables. Active restart-snapshot identity now has a bounded pair
lookup and the client restart prefix has a separate decoder; record liveness,
complete native client payload interpretation, transaction analysis,
redo/undo execution and Windows recovery acceptance remain separate work.
LFS version numbers do not establish the NTFS client's payload version.
An already assembled client restart record can now be bound to selected active
snapshot identity before common-prefix decoding. This does not establish its
physical/current-history provenance.

Separate [native checkpoint framing](WRITE-FOUNDATIONS.md) now checks complete
restart-table free topology and client-versioned open-attribute/dirty-page plus
transaction entries. It does not yet bind table-dump records, attribute-name
packets or cross-table references to qualified current history. Those independent
decoders do not advance native replay or writable admission.

## Logical source ownership and copy reports

`ntfs_logfile_open` takes an immutable logical `$LogFile` byte environment, not a
volume/block-device environment. Its exact read/allocate/release callbacks and
context stay alive until `ntfs_logfile_close`; the caller serializes operations.
An exported regular file can supply this source without mounting an NTFS volume.
`ntfs_logfile_open_volume` instead binds the fixed MFT record 2's unnamed DATA
stream in an already mounted immutable core volume. It uses the usual complete
mapping/list/extension sequence and base-ownership checks. The temporary node
closes before logical-source discovery; a counted public backing stream keeps
the volume BUSY until the journal owner closes. Each independently opened owner
has its own stream. Close releases the journal buffers/object before releasing
that callback context's stream. Native admission/drain integration remains
separate work. No dirty-mount or write policy changes.

Automatic binding supports ordinary fully initialized, unencoded storage. It
explicitly refuses directory, reparse, view/uninterpreted record, encoded/sparse
standard-information or stream flags, and partial initialized-length forms.
This is a bounded system-file policy, not a claim to decode those forms. Invalid
owner arguments/limits fail before metadata reads. Binding errors release the
temporary node and stream and leave the source NULL; pre-discovery failures have
an empty report. Logical read credits/reporting begin after stream construction.
Metadata/run limits and actual physical resource reads retain their own counters:
one logical restart-page read may span multiple physical extents.

Discovery probes offset zero and each possible second-copy position for supported
512-byte through 64-KiB system pages. It therefore finds a valid second copy even
when the first prefix or USA is damaged. A nonzero candidate must claim its own
offset as its system-page size. Full pages have the same checked byte/USA/client
contract as the independent restart primitive. All candidate positions are
examined before publication; resource exhaustion cannot silently make an early
candidate authoritative. Unknown-version/CHKD candidates refuse automatic
selection. Every backend error aborts discovery with its original result, even
when that result is also used for a structural decoder error.

Compatible copies must agree on LFS version, system/log page sizes, declared and
usable file geometry, LSN bit width and record header/data offsets. Increasing
numeric current LSNs select the newer compatible copy. Equal-LSN copies require
identical declared restored restart-area bytes; differing USA protection words
are outside that comparison. Incompatible geometry or divergent equal-LSN bytes
produce CONFLICT and UNSUPPORTED. This conservative refusal does not label every
such native transition corrupt: original Windows lifecycle/resize/version-change
observations are still needed. One good supported copy can be selected beside
missing or structurally bad storage, with SINGLE_COPY visible in the report.

The owner allocates one object and three `max_page_bytes` buffers, with no
journal-sized allocation. Defaults are 64-KiB pages and 32 read calls/256 KiB per
operation; discovery has nine candidates and at most 18 exact reads. Both system
and log-page sizes must fit the buffer policy. Read credit is reserved before a
callback, including a failed or partial callback. On failure the owner output is
NULL and all allocations are released. The optional report retains bounded
partial candidate/status/read evidence, clears its selected index and never
publishes a selected snapshot. `scan_complete` means candidate probing finished,
not that a journal history or recovery operation is qualified.

Selected restart/client queries copy immutable snapshots with no allocation/I/O
and preserve original UTF-16 units. Physical page reading checks aligned file
bounds after both restart pages and labels legacy tail, fast storage or circular
storage. It stages the exact read and USA/geometry checks privately, then copies
the restored page to the caller only on success. Every error leaves caller bytes
unchanged and its view zero; failed fills are retryable. This operation does not
route copy-union targets, establish a page's active history or assemble records.

`ntfs_logfile_get_client` retains every stored client entry, including free
entries with old opaque LSNs. `ntfs_logfile_get_active_client` additionally
requires both the requested sequence and membership in the selected active
chain. Absent, free or mismatched entries return STALE with zero output. Sequence
zero and the full 16-bit maximum are compared as stored values. The validated
immutable owner bounds traversal by client count (at most 407 with current page
limits); no additional allocation, callback or read credit is consumed. Raw and
active snapshots preserve complete UTF-16 names. The pair identifies an entry
in that selected restart snapshot; it does not establish a record's lifetime,
written/current page history or the NTFS client's payload version. Future native
admission must still gate cached use after resource revocation.

## Physical circular-record observation

`ntfs_logfile_read_circular_record` locates a complete first header through the
selected restart geometry and the caller's LSN. A different stored header LSN
returns STALE. The declared header/client length controls assembly: subsequent
physical pages contribute bytes beginning at `page_data_offset`, without another
record header. USA restoration precedes every copy, including a header or payload
intersecting a protected sector tail. Extended header bytes remain exact and
opaque. Final alignment padding is excluded from the returned record bytes.

Assembly can move from the last usable page to the first circular page once;
it never revisits a physical page. The unique payload capacity, caller capacity
and named 1-MiB record cap are checked before allocation. A single ephemeral
allocation stages the exact record while one shared read budget covers every
page; it is released on every path. Defaults remain 32 calls/256 KiB per
operation. Some complete records need explicitly larger byte credits: the
direct core test accepts an exact 1-MiB record with adequate custom credits,
while default credits refuse that same source. Errors leave caller bytes
unchanged and the record view zero, including partial reads and a failed later
page. Successful views retain first/last physical offsets, wrap state, page and
logical read counts, and decoded common record metadata. Nonzero previous/undo
LSNs must also fit the selected circular geometry.

This API observes physical framing. It does not use `copy_value`,
`next_record_offset` or `last_end_lsn` to establish written/current history,
select tail/fast copies or prove that continuation pages belong to a post-crash
record. Transfer counts/positions are separate from record segmentation, and
the known record flags remain metadata. Active client identity, checkpoint
tables and transaction interpretation remain separate. Do not use this
observation as an authoritative recovery input.

## Completed legacy tail-copy record observation

`ntfs_logfile_read_legacy_record` adds immutable LFS 1.1 copy routing to the same
exact staged-record assembly. Both tail slots are read before selecting a matching
circular target by increasing `last_end_lsn`. Targets must be aligned complete
pages in the selected circular geometry. A torn or malformed copy is unavailable;
an actual backend error aborts with its original result, including errors that share
a decoder's structural status. There is no preference for the first or second slot.

Equal-epoch copies must have the same flags, next-record boundary and restored
declared written prefix. USA words, transfer counts/positions and unused capacity
are outside that comparison. A newer valid circular page wins; divergent equal
circular/tail prefixes refuse. The selected tail is reread with snapshot header
checks, and every consumed tail byte must fit its declared written prefix.
Unknown page flags, a matching tail without a completed written prefix and modern
LFS 2.0 routing return UNSUPPORTED. A finished record additionally requires a
record-end page whose last-end LSN covers the requested record.

Returned first/last offsets remain logical circular addresses; `copy_pages_read`
counts segments read from tail storage. The shared read credits include the
two-slot scan, every circular observation and every selected-tail reread. One
temporary actual-log-page allocation holds a comparison prefix in addition to the
exact staged record; both release on every path. Cached selected restart/client
bytes remain intact. Errors preserve every caller byte and zero the view.

This is completed-copy observation, not a proof of the entire current history or
continuation provenance. It does not bind checkpoint tables or authorize recovery.
Full fast-page routing and native current-history/analysis remain prerequisites in
[WRITES.md](WRITES.md). The original format notes describe legacy tail copies as
backups that can retain bytes not yet moved to the regular area; see the
[original LFS research](https://dfir.ru/2019/02/16/how-the-logfile-works/).

## NTFS client restart common prefix

`ntfs_logfile_client_restart_decode` observes the 64-byte common prefix of an
already acquired complete NTFS client restart payload. This is distinct from
the LFS restart-page area and has its own major/minor fields. Client 0.0/1.0 are
accepted; other versions return UNSUPPORTED with zero output. The decoder accepts
byte-aligned immutable input, performs no allocation or I/O, refuses payloads
larger than the named 1-MiB record cap and reports shorter common prefixes as
CORRUPT. Input and output must be disjoint. Named fields are published into a
zeroed output only after all prefix gates; padding and every error output stay
zero.

It retains the raw analysis LSN and four LSN/byte-count pairs: open attributes,
attribute names, dirty pages and transactions. Zero or maximum fields are
observations, not a presence or range decision; the decoder deliberately preserves
even apparently inconsistent pairs. They do not authorize reads, allocation,
table traversal or recovery. The caller must separately qualify the containing
LFS record, selected active client, written/current history, table geometry and
ownership. Optional data after the common prefix is an opaque relative span,
including a one-byte tail or a bounded maximum-size tail. A successful prefix
decode makes no claim that an optional extension is complete or valid. No USN,
table contents or extension version semantics are inferred.

`ntfs_logfile_decode_client_restart_record` takes the immutable selected owner
and an exact already assembled LFS record. It uses the selected record-header
length, including opaque extended header bytes, then requires RESTART type,
selected active index/sequence, the exact four UTF-16 units `NTFS` and equality
with that client's nonzero stored restart LSN. These gates precede payload
interpretation. Absent/free/mismatched identity or LSN returns STALE; a different
known record type or client name returns UNSUPPORTED. Common-record framing and
prefix errors retain their decoder result, including a corrupt sentinel client
index. All errors zero output; neither source/record bytes nor cached state change.

Binding is bounded by the cached client count and allocates/reads nothing. Its
1-MiB cap covers the entire LFS record, so the allowed client payload is smaller
than the standalone payload cap by the selected header length. The returned
extension span remains relative to client payload bytes. The supplied bytes must
still have independently qualified page integrity and continuation/current-history
provenance before recovery use. A snapshot match does not prove registration
lifetime or a complete checkpoint. Native admission remains necessary for cached
queries after revocation; no FSKit journal owner is introduced here.

## Byte and resource contract

The immutable input, output structure and caller-owned scratch must be disjoint.
Page decoding needs scratch equal to the page size, with byte alignment. Only
successful scratch is publishable: restoration may change it before a later
structural error. All output structures are zero on failure. Restored scratch
retains the original USA/header bytes with sector tails replaced; it cannot be
passed back as an original protected page.

Named byte-array wire structures define every field in `core/disk.h`. The common
restart prefix is 30 bytes; the next word belongs to the USA rather than a falsely
required 32-byte header. The existing atomic USA verifier uses its fixed 512-byte
stride independently of a device's logical sector size. Every tail is checked
before restoration, and the array must fit before the declared area/data offset.
Unknown versions are rejected before assuming their integrity mechanism.

The parser caps each page at 64 KiB and each logical record at 1 MiB. The observed
file-size ceiling is 4 GiB; decoding does not allocate a journal-sized buffer.
Page powers of two, declared/available/usable lengths, restart/client spans,
header alignment and minimum usable geometry are checked. LSN offset/sequence
widths cannot produce an undefined shift or overflowing byte conversion. Offset
widths may reserve more than the minimum file-address bits, as documented by the
original format research. Nonzero LSNs must address a complete record header in
the circular area, outside restart/tail/fast-page storage and page headers.

Both free and active client chains must cover their bounded array exactly once,
with consistent backward links. A 52-byte visited bitmap prevents cycles and
duplicate membership without allocation; the 64-KiB fixture holds 407 clients.
Active client LSNs undergo geometry/current-LSN checks. Free records may retain
stale LSNs from a former client lifetime. Names preserve up to 64 UTF-16 units,
including unpaired surrogates. Traversal is linear in the bounded client count.
Raw flags and page copy-union values remain visible without inventing a recovery
decision from them. Page transfer positions are distinct from record segmentation.

Logical LFS decoding requires the exact assembled header/client length, excluding
trailing alignment padding. It retains transaction/client identifiers, previous
and undo-next LSNs, known record flags and opaque client bytes. A qualified
history reader must first establish which pages belong to that record. The NTFS update decoder
checks the complete LCN vector and aligned, bounded redo/undo spans; the spans may
share bytes. Target identifiers, operation codes and LCN values are metadata,
never physical write addresses.

Published NTFS update notes describe a reserved first LCN slot, while the
NTFS-3G recovery utility uses a different offset base when no LCN follows. The
current update decoder explicitly returns UNSUPPORTED for that variant as soon
as its shared prefix through the LCN count is available. It does not presume a
full target-VCN layout for shorter packets. The LFS record decoder still preserves
the original client payload. Do not resolve this
disagreement by silently choosing an offset formula; obtain original Windows
packets and independent observations. Checkpoint table bodies and optional client
restart extensions remain opaque, and unknown LFS record types/flags, CHKD and other page versions are
unsupported. Erased/missing restart storage is not treated as a valid clean page.

## Diagnostic and qualification workflow

The packet modes of `ntfs-logfile` read bounded regular files opened read-only. They decode an
exported restart page, record page with an independent restart configuration,
already assembled LFS record, NTFS update payload or client restart common prefix.
They do not mount an image
or report the journal/volume as consistent. Successful JSON reports retain
`recovery_qualified: false`; a decoder error exits one with zero metadata, while
transport/argument/configuration failures exit two. The `journal` mode uses exact
bounded reads from a regular-file logical source rather than loading the entire
export. JSON retains every candidate result, read accounting, selection and the
selected lossless restart/client metadata, or NULL selected metadata on failure.
`volume-journal` reads an NTFS regular-file image through the portable core's
ordinary read-only mount and counted stream binding. It closes the journal,
then the core volume, then the image; it does not perform a native mount. A
mount/binding failure still produces a bounded report with no selected metadata.
Ordinary dirty-media rejection remains in force, and every mode retains
`recovery_qualified: false`.
`circular-record` takes an exported logical source and a decimal LSN. Its JSON
retains exact assembled bytes as `bytes_hex`, common record metadata and physical
assembly/read accounting; record, assembly and bytes are NULL on error. It uses
default credits and reports only the physical observation described above.
`active-client` takes an exported logical source and decimal index/sequence
values. It reports the selected active entry or NULL with its lookup error;
it does not read record content or change any recovery qualification.
`client-restart-record` takes an exported logical journal and an already assembled
record packet. Discovery selects the cached snapshot; binding makes no further
source reads or allocations. Its JSON has the same prefix fields and zero-error
contract as `client-restart`, with its own scope and `recovery_qualified: false`.
Both inputs are opened read-only and remain unchanged. Packet and source transport
errors exit two; discovery/binding/decoder reports exit zero or one as usual.

```sh
.build/ntfs-logfile restart EXPORTED_RESTART_PAGE LOGICAL_LOGFILE_BYTES
.build/ntfs-logfile page EXPORTED_RECORD_PAGE EXPORTED_RESTART_PAGE LOGICAL_LOGFILE_BYTES
.build/ntfs-logfile record ASSEMBLED_RECORD RECORD_HEADER_BYTES
.build/ntfs-logfile update NTFS_CLIENT_PACKET
.build/ntfs-logfile client-restart NTFS_CLIENT_RESTART_PACKET
.build/ntfs-logfile client-restart-record EXPORTED_LOGICAL_LOGFILE ASSEMBLED_RESTART_RECORD
.build/ntfs-logfile journal EXPORTED_LOGICAL_LOGFILE
.build/ntfs-logfile volume-journal NTFS_IMAGE_FILE
.build/ntfs-logfile circular-record EXPORTED_LOGICAL_LOGFILE DECIMAL_LSN
.build/ntfs-logfile active-client EXPORTED_LOGICAL_LOGFILE INDEX SEQUENCE
python3 scripts/fuzz.py --target logfile --seconds 60 --compiler /opt/homebrew/opt/llvm/bin/clang --output artifacts/fuzz-logfile-next
```

`tests/logfile_fixtures.py` authors named fields, independent expected metadata
and restored-byte oracles without importing the parser. Direct sanitized checks
cover error-output and buffer guards, exact restored bytes, all baseline restart
truncations, caller geometry and scratch equality/exhaustion. The CLI checks
every original expected field, transport errors and unchanged packet hashes.
The dedicated fuzz target exercises restart/client/page/record/update/LSN
contracts. Its custom mutator restores and reseals valid USA pages while changing
inner bytes; ordinary mutation also reaches damaged framing and envelopes. Fuzz
process RSS includes sanitizer/corpus overhead, independently of decoder storage.
Actual run counts and retained logs belong in ACCEPTANCE.md and generated reports.

Whole-source fixtures also cover copy selection/conflicts, small/mixed/maximum
pages, unknown versions, cached lossless clients, physical page bytes and torn
record-page rejection. Allocator/exact/partial-backend errors, distinct backend
result codes and page/read-credit boundaries retain separate checks. Source fuzz
repeats reports/snapshots/physical reads, checks allocation/read caps and exact
release accounting, and can restore/reseal either restart copy while directing
mutations into the checked declared restart area. The 2-MiB test envelope now
includes every source fixture, including ordinary 4-KiB system/log pages and
1-MiB files with maximum restart/mixed record-page sizes. Fuzz input/RSS is
independent of the owner's bounded three-page allocation and I/O credits.

`tests/logfile_record_fixtures.py` independently authors protected physical
fragments, exact unpadded record bytes and report metadata. Its 30 source
verdicts cover empty clients, extended headers/page prefixes, header-at-end,
two/three/four-page and wrapped records, mixed/ordinary/64-KiB pages, stale
headers, linked-LSN geometry, unknown framing, missing/torn continuations,
tail-only storage, ring revisit and record/credit boundaries. The direct suite
checks 14 allocation/40 partial-read failure positions, unchanged caller/source
bytes, retry, shared credits and exact-cap custom-policy success. Bound-volume
tests also compare independent record bytes and fail/retry the backing-stream
read and staging allocation. CLI reports compare both exact metadata and bytes.

Circular-record fuzz mode retains its requested LSN in the independent envelope
and separate read/allocation/budget controls. Resealed mutations target a record
header and nearby continuations as well as either restart copy; generic mutations
also reach damaged protection and arbitrary storage. All authored logfile seeds
execute in bounded fixed-file batches before exploration. Twenty-eight record
sources and six fault/control seeds fit the unchanged 2-MiB envelope. Two complete
4-MiB sources (maximum pages and exact-cap record) are explicitly excluded in
`logfile-record-selection.json` and the campaign report; both remain in direct
C/CLI tests. No seed is silently truncated.

`tests/logfile_client_fixtures.py` independently authors seven selected snapshots
and 858 raw/active pair expectations. Chains include empty/all-free, mixed
non-numeric active/free order, LFS 2.0 and the 407-client page bound; free entries
retain old out-of-geometry LSNs. Every client retains a full-length unpaired
UTF-16 name. Direct checks arm backend/allocation failures, compare all metadata
and prove zero cached I/O/allocation with exact source cleanup. The CLI samples
42 exact reports and argument/discovery/transport errors. Source fuzz checks
deterministic active lookup, mismatched sequences and zero errors, adding all
seven complete sources inside the existing envelope. Bound-volume cached tests
also compare active metadata and mismatched-sequence results without I/O.

`tests/logfile_checkpoint_fixtures.py` independently authors 77 common-prefix
verdicts from named wire fields: both client versions, distinct and maximum raw
LSN/count pairs, opaque/extended/exact-cap tails, unknown versions, every shorter
prefix and an over-cap payload. The direct suite checks both aligned and
unaligned input, exact zero padding/error outputs, input/output guards and
immutable bytes. The CLI compares 75 exact JSON reports and two packet-transport
rejections, arguments and unchanged hashes. All 77 complete payloads have fuzz
seeds inside the unchanged 2-MiB envelope. Structured mutations focus on declared
prefix fields, usually preserving the client version gate, while generic
mutations also reach version, truncation and framing errors.

`tests/logfile_restart_record_fixtures.py` independently authors 165 source/record
verdicts and exact prefix oracles. They cover both client versions, zero/maximum
sequence, non-numeric/maximum active chains, newer second selection, LFS 2.0,
extended headers, absent/free/foreign/stale clients, gate precedence, raw boundary
pairs, all shorter headers/prefixes, opaque tails and the complete-record cap.
The direct suite checks both input alignments, guards, zero outputs/padding and
immutable source/record bytes. Armed next-read/next-allocation failures plus exact
counters prove that cached binding performs neither callback, including failure
paths; owner close releases every allocation. The CLI compares 161 exact reports
and four transport checks plus arguments and original source/packet hashes.
All 165 complete source/record pairs fit the unchanged 2-MiB fuzz envelope.
Their separate mode checks deterministic binding/error outputs and guards,
reseals selected restart-copy mutations, and directs record/payload mutations
into context fields or the common prefix while usually preserving identity.

Independent volume layouts place the original logical journal bytes in
contiguous/fragmented runs and resident/nonresident attribute lists. They cover
mixed/maximum restart pages, ordinary 4-KiB log pages, fast storage, torn copies,
conflicts, stale sequence/base ownership, continuation gaps and unsupported
system-file forms. Exact page/report oracles are retained independently of the
core; failed physical reads may fill a prefix before returning an error. Fault
sweeps check every binding allocation/read position in selected layouts, retries,
exact release accounting and BUSY ownership, including two simultaneous owners.
These focused metadata images are not a Windows-authored complete system-file
namespace or whole-volume consistency oracle.

The image fuzz target now opens counted journal owners on mounted volumes and
checks cached clients, staged circular/tail pages, error guards and teardown.
Its seed author uses genuine 1-MiB physical geometry for bounded corpus storage;
larger journal layouts that cannot fit have explicit manifest skips and remain
in the full component/source suites. It does not truncate an 8-MiB volume or
treat a geometry skip as a passed layout. Separate logical-source fuzz retains
all of its original 1-MiB journals under the 2-MiB envelope.

Next work must integrate native journal admission/drain ownership, route tail/fast-page
copies and validate written/current circular history and continuation provenance,
then qualify client sequence lifetimes and interpret complete NTFS checkpoint
tables/extensions beyond the common prefix. Compare original
Windows 1.1/2.0 packets, including LCN-less records and interrupted writes. Add
transaction/crash/durability simulation under WRITES.md before any writable
environment, and retain native recovery/Windows roundtrips as separate acceptance.

## Format provenance

The implementation and fixture authors are repository-owned. Field/geometry
facts were consulted in [NTFS-3G's original log layout header](https://github.com/tuxera/ntfs-3g/blob/2022.10.3/include/ntfs-3g/logfile.h),
[original Linux-NTFS log notes](https://flatcap.github.io/linux-ntfs/ntfs/files/logfile.html),
[original libfsntfs research](https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20%28NTFS%29.asciidoc)
and [Maxim Suhanov's original LFS research](https://dfir.ru/2019/02/16/how-the-logfile-works/).
The common NTFS client restart prefix was cross-checked against the declarative
`NTFS_RESTART` field layout in [Linux v6.12's NTFS log source](https://github.com/torvalds/linux/blob/v6.12/fs/ntfs3/fslog.c)
and the named payload fields in [Suhanov's original parser](https://github.com/msuhanov/dfir_ntfs/blob/master/dfir_ntfs/LogFile.py).
Only layout facts were used for this original prefix decoder and independent
fixture author; no foreign parser, table/replay or recovery algorithm was imported.
The selected-client record binder reuses the repository's original record,
active-snapshot and prefix contracts. Its gate ordering, complete source/record
fixtures and cached fault/counter checks are original; no foreign registration,
binding or recovery algorithm was imported.
The short offset-base helpers in the separately retained NTFS-3G recovery utility
were inspected only to establish the conflicting LCN-less format fact; no replay,
parser or filesystem algorithm was imported. This is not source-isolated
clean-room work. PROVENANCE.md retains the proprietary/dependency boundary.
