# Read-only log diagnostics

`ntfs/logfile.h` provides independent byte decoders for the common LFS 1.1/2.0
restart prefix/area, complete client lists, LSN geometry, protected record pages,
exact logical LFS records and an NTFS update payload with a nonempty LCN vector.
These byte primitives do not allocate, access a device, mutate input or provide
a write capability.
The ordinary mount and FSKit mutation contracts are unchanged. A successfully
decoded restart page or its clean hint does not authorize mounting dirty media.

The separate logical-source owner now reads bounded restart candidates and selects
compatible redundant copies with conflict reports. These are foundations for
journal inspection. They do not yet route legacy tail/modern fast-page copies,
assemble a wrapped multi-page record, validate the active circular history or interpret NTFS
checkpoint tables. Client identity/sequence resolution, transaction analysis,
redo/undo execution and Windows recovery acceptance remain separate work.
LFS version numbers do not establish the NTFS client's payload version.

## Logical source ownership and copy reports

`ntfs_logfile_open` takes an immutable logical `$LogFile` byte environment, not a
volume/block-device environment. Its exact read/allocate/release callbacks and
context stay alive until `ntfs_logfile_close`; the caller serializes operations.
An exported regular file can supply this source without mounting an NTFS volume.
Integrating the source with a counted NTFS stream and native lifecycle remains
separate work. No native dirty-mount or write policy changes.

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
and undo-next LSNs, known record flags and opaque client bytes. Caller assembly
must first establish which pages belong to that record. The NTFS update decoder
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
packets and independent observations. Client restart/table bodies also remain
opaque, and unknown LFS record types/flags, CHKD and other page versions are
unsupported. Erased/missing restart storage is not treated as a valid clean page.

## Diagnostic and qualification workflow

`ntfs-logfile` reads bounded regular-file packets opened read-only. It decodes an
exported restart page, record page with an independent restart configuration,
already assembled LFS record or NTFS update payload. It does not mount an image
or report the journal/volume as consistent. Successful JSON reports retain
`recovery_qualified: false`; a decoder error exits one with zero metadata, while
transport/argument/configuration failures exit two. The `journal` mode uses exact
bounded reads from a regular-file logical source rather than loading the entire
export. JSON retains every candidate result, read accounting, selection and the
selected lossless restart/client metadata, or NULL selected metadata on failure.

```sh
.build/ntfs-logfile restart EXPORTED_RESTART_PAGE LOGICAL_LOGFILE_BYTES
.build/ntfs-logfile page EXPORTED_RECORD_PAGE EXPORTED_RESTART_PAGE LOGICAL_LOGFILE_BYTES
.build/ntfs-logfile record ASSEMBLED_RECORD RECORD_HEADER_BYTES
.build/ntfs-logfile update NTFS_CLIENT_PACKET
.build/ntfs-logfile journal EXPORTED_LOGICAL_LOGFILE
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

Next work must integrate counted volume/stream ownership, route tail/fast-page
copies, validate circular currentness and assemble wrapped records, then resolve
client sequences and interpret NTFS checkpoint/tables. Compare original
Windows 1.1/2.0 packets, including LCN-less records and interrupted writes. Add
transaction/crash/durability simulation under WRITES.md before any writable
environment, and retain native recovery/Windows roundtrips as separate acceptance.

## Format provenance

The implementation and fixture authors are repository-owned. Field/geometry
facts were consulted in [NTFS-3G's original log layout header](https://github.com/tuxera/ntfs-3g/blob/2022.10.3/include/ntfs-3g/logfile.h),
[original Linux-NTFS log notes](https://flatcap.github.io/linux-ntfs/ntfs/files/logfile.html),
[original libfsntfs research](https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20%28NTFS%29.asciidoc)
and [Maxim Suhanov's original LFS research](https://dfir.ru/2019/02/16/how-the-logfile-works/).
The short offset-base helpers in the separately retained NTFS-3G recovery utility
were inspected only to establish the conflicting LCN-less format fact; no replay,
parser or filesystem algorithm was imported. This is not source-isolated
clean-room work. PROVENANCE.md retains the proprietary/dependency boundary.
