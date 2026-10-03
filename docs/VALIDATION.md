# Read-only consistency diagnostic

`ntfs_validate` in `ntfs/validate.h` opens and destroys a private synchronous
mount. It uses the caller's exact read/allocation/release callbacks through a
budgeted owner; no callback can write. An already mounted owner, its children
and cached metadata remain independent. The source must stay immutable for the
whole call. This API is a diagnostic; ordinary mount does not run it implicitly.

`complete` means every implemented check below finished successfully within the
configured limits. It does not mean Windows compatibility, a complete `chkdsk`,
security enforcement, journal recovery or commercial acceptance. Corruption,
unsupported layouts, callback failures and exhausted budgets return partial
counters with `complete == false`. No repair or dirty-bit changes occur.

## Checks and storage

The record pass reads `$MFT::$BITMAP`, visits every logical MFT slot, validates
allocated FILE records and compares their in-use flags with the bitmap. Every
extension's sequence-bearing base reference must resolve to an allocated base
record. MFT size must be a whole number of records. Free tombstones are not
interpreted as active objects. MFT records and volume clusters are the distinct
allocation planes described by [Microsoft](https://learn.microsoft.com/en-us/windows/win32/devnotes/master-file-table).

The attribute pass verifies descriptor references, instances, ownership and
physical attribute membership. A present attribute list must include every
base attribute except the list itself, as required by
[Microsoft's list description](https://learn.microsoft.com/en-us/windows/win32/devnotes/master-file-table).
Resident streams are opened structurally to detect duplicate type/name keys.
Nonresident first extents use the ordinary complete stream decoder, including
listed continuations, VCN coverage, declared sizes and physical allocation.
Only first extents contribute physical runs, so continuations are not counted
twice. Resident bytes live inside their containing MFT allocation.

The mirror pass opens fixed MFT slot 1's unnamed `$DATA` through complete
attribute-list/extent validation. It requires ordinary nonresident storage,
the boot-declared starting LCN, a whole number of records and an initialized
prefix covering the first four records. Declared data may extend to the larger
of that prefix and one cluster. Short/misaligned/underinitialized prefixes are
corrupt; larger declared streams and encoded forms are explicitly unsupported.
Fragmented storage and resident/nonresident attribute lists use the existing
stream owner. All mirror extents still undergo physical ownership/bitmap checks.

The required four-record coverage follows
[Microsoft's MFT mirror definition](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/8ac44452-328c-4d7b-a784-d72afd19bd9f).
[Original Linux-NTFS research](https://flatcap.github.io/linux-ntfs/ntfs/files/mftmirr.html)
describes larger cluster-sized mirrors; the pinned NTFS-3G 2022.10.3
[Windows observation](https://github.com/tuxera/ntfs-3g/blob/2022.10.3/ntfsprogs/ntfsfix.c)
reports different big-cluster mirroring behavior since Windows 10 in 2017.
The diagnostic therefore compares the mandatory prefix and explicitly reports
larger declared tails as unqualified. It does not infer an operating-system
version or demand agreement across those tails.

Allocated replicas must independently pass FILE/MST validation. Their used
logical bytes must agree after sector-tail restoration, excluding the USA's
protection state/saved slack tails and bytes beyond `BytesInUse`. USA geometry,
sequence-bearing identity, LSN, flags and attribute bytes remain compared.
[The original fixup description](https://flatcap.github.io/linux-ntfs/ntfs/concepts/fixup.html)
identifies protection state separately from restored logical data. Free slots
remain opaque and require exact raw replicas. Ordinary mount retains its earlier
strict complete-record-zero bootstrap comparison; this diagnostic changes no
mount admission or recovery policy. A mismatch identifies inconsistent copies,
not an authoritative repair source.

`mirror_record_slots` retains the declared slot count once the stream opens;
`mirror_records_compared` advances only after each complete comparison.
`mirror_unchecked_records` reports admitted slots beyond the required prefix.
Errors retain the current primary slot/reference, related mirror-owner reference
and physical mirror cluster. Stage `MIRROR` is appended to the stage enum to
preserve existing numeric report values; enum values are not execution order.
Two record-sized private buffers and every callback/comparison share the existing
memory/read/work budgets. No tail-content read or repair is implied by success.

Each filename contributes its original UTF-16 name, namespace, parent and file
reference. Every directory is fully enumerated through the existing checked
B-tree cursor, including DOS and system entries. Exact keys must have one
filename attribute and one index entry in both directions; duplicate, dangling,
missing and stale links fail. Cached filename timestamps and sizes are not
compared with current stream metadata: [original filename research](https://flatcap.github.io/linux-ntfs/ntfs/attributes/file_name.html)
describes their independent update lifetime. The root has one `.` self-name
anchor, excluded from ordinary namespace-edge counters; its presence and link
count are checked. [Root format notes](https://flatcap.github.io/linux-ntfs/ntfs/files/dot.html)
identify this name. Other directories must have one primary parent and reach
the root. An iterative colored graph walk detects disconnected cycles without
recursive stack growth. Ordinary non-DOS link counts must match stored names.

After each ordinary `$I30` traversal finishes, the diagnostic scans its complete
bitmap and compares every used slot with the cursor's retained visited-block set.
[Original bitmap research](https://flatcap.github.io/linux-ntfs/ntfs/attributes/bitmap.html)
assigns one bit to each index record;
[allocation research](https://flatcap.github.io/linux-ntfs/ntfs/attributes/index_allocation.html)
describes the nonresident sequence of index records. Requiring all used records
to be reachable is the diagnostic's consistency inference from those format
facts, still subject to Windows-authored qualification. A used unreachable slot,
a used bit outside the logical allocation or a partial final allocation record
fails. Zero padding and free allocation slots remain opaque, even if their bytes
look like valid records or garbage. A small resident root may retain an all-zero
bitmap without allocation storage.

Bitmap slots count index records; tree VCNs use clusters, or sectors when the
index record is smaller than a cluster, as described by
[root format research](https://flatcap.github.io/linux-ntfs/ntfs/attributes/index_root.html).
The check maps between these units and reports the owning directory reference,
bitmap attribute and first physical cluster of an unreachable slot. An
out-of-span bit has no physical cluster and reports zero. `INDEX_ALLOCATION` is
appended to the stage enum without changing earlier stage values, report sizes
or API version 2. Each 256-byte stack chunk and membership probe consumes both
diagnostic work and core operation credits before further work. Reads also retain
their independent read budgets. No free index block is read and ordinary mount,
lookup and FSKit enumeration do not run this whole-bitmap diagnostic.

Physical extents are sorted, checked for overlaps and compared bit-for-bit with
`$Bitmap::$DATA`. A claimed free cluster fails immediately. An allocated cluster
without a physical owner is reported as unclaimed and fails the verdict. Sparse
holes claim no clusters. The name/run sorts use bounded heapsort, exact UTF-16
comparisons and no probabilistic identity hashes. Owned tables/vectors/arenas
are released after every exit, including budget failure.

## Observed system layouts and explicit gaps

Original [MFT research](https://flatcap.github.io/linux-ntfs/ntfs/files/mft.html)
identifies reserved in-use records 12–15. Independent mkntfs images contain
preinitialized templates rather than attribute-free records. The diagnostic
exempts only zero-link base records in that range with the ordinary in-use flag
and either no attributes, or an unnamed resident standard-information attribute,
an empty resident data attribute and at most one resident descriptor. Their
present attributes still undergo structural validation. Names, data payloads,
nonresident mappings, duplicates and other attributes do not receive this
exemption. It is not a general waiver for orphaned files.

NTFS-3G's published [layout facts](https://github.com/tuxera/ntfs-3g/blob/2022.10.3/include/ntfs-3g/layout.h)
and independent `$Quota` exports show record flag `0x0004`. The core accepts this
named uninterpreted bit without inferring its semantics. Other unknown bits
remain rejected. Accepting its header framing does not validate quota indexes.

`$BadClus::$Bad` describes bad cluster positions rather than ordinary readable
content. Its implicit holes need no ordinary sparse flag; declared allocation
and size span the volume, while each physical run must map VCN to the same LCN.
The internal diagnostic description shares the checked mapping-pair parser and
complete attribute-list reader. Resident/nonresident lists can locate the first
extent in an extension, later extents in the base or multiple sequence-checked
extensions. Complete physical membership, base ownership, duplicates, VCN order
and coverage are required before publication. Each physical run must retain
VCN == LCN across the complete volume-sized mapping; continuations contribute
one logical stream and no duplicate physical ownership.

The description is metadata-only, including when its initialized size is zero
or volume-sized. Its raw/exact/public read paths cannot read bad sectors or
present synthetic zero content. Public stream opening also refuses the fixed
record's exact `$Bad` name; an ordinary file's ADS with that spelling remains
readable. Ordinary unflagged-hole streams remain rejected. These facts
come from [original bad-cluster research](https://flatcap.github.io/linux-ntfs/ntfs/files/badclus.html)
and independent raw metadata; the complete listed-storage implementation remains
synthetically qualified pending Windows-authored chains. Flagged first extents
remain UNSUPPORTED; inconsistent flags/units in continuations are CORRUPT.
All owned descriptions/list buffers close on failure. A complete bad-cluster
open shares one mounted operation, including nested list reads and extension
allocations, in addition to the diagnostic's existing budgets.

Separate DOS aliases have exact filename/index pairing checks, but their header
link-count convention is deferred pending native observations. They increment
`deferred_dos_link_counts`; even when the other passes succeed the final result
is UNSUPPORTED, naming the first affected record. A combined Win32/DOS namespace
entry is one primary name. Reparse directories, encrypted mappings and other
unsupported ordinary stream formats also retain incomplete verdicts.

After physical ownership succeeds, a separate SECURITY pass fully walks the
supported `$Secure` SII/SDH indexes, inventories both allocation bitmaps, checks
their exact locator membership and nonoverlapping logical SDS intervals, and
validates every indexed checksum/descriptor/duplicate. Every allocated base
FILE's nonzero standard-information security ID must exist in that inventory.
Missing references/store are CORRUPT; FILE references identify their own
standard-information subject. SECURITY is appended to the public stage enum,
preserving earlier numeric values and report layout. See SECURITY.md for the
bounded vector/cursor contract, partial counts and Windows-dependent inferences.

The same SECURITY stage then validates selected unnamed per-file descriptor
bodies for allocated zero-ID base files, through bounded private snapshots.
The earlier attribute pass supplies complete extent/list and physical checks.
Specific fixed internal metadata and recognized empty/inert reserved slots may
lack a descriptor; present selected packets are checked, and missing ordinary,
root, `$Volume` or `$Boot` storage remains CORRUPT. Neither the system attribute
bit nor an arbitrary low MFT slot grants this exception; SECURITY.md defines it.
Each file shares one mounted operation across node open and descriptor reading;
temporary storage releases before the next file. Descriptor-byte work is charged
to both accounting planes before decoding. Reports identify the FILE and
`$SECURITY_DESCRIPTOR` attribute; no new report fields or API version are needed.

The diagnostic does not parse arbitrary other resident payload semantics,
unindexed SDS gaps, quota/object-ID/reparse view-index
relations or their complete allocation inventories, qualify Windows-dependent extended mirror tails, verify boot replicas,
read all file content, decompress every compression unit or replay `$LogFile`.
Those checks remain separate qualification work. Mount's existing mirror check
still covers only bootstrap record zero; the diagnostic compares the required
four-record prefix separately. Windows-authored fragmented metadata,
large directories and native DOS observations remain required.

## Budgets and reports

Defaults and configurable vector caps are deliberately conservative:

| Resource | Default | Contract |
| --- | ---: | --- |
| MFT slots | 1,048,576 | Includes allocated and free slots; configuration cannot exceed this cap |
| Physical runs | 1,048,576 | Configuration cannot exceed this cap |
| Namespace entries | 1,048,576 | Counts filename and index sides together; configuration cannot exceed this cap |
| Live allocated memory | 64 MiB | Includes private core owners, cache, tables and transient vector growth |
| Device read calls | 1,048,576 | Counts attempted forwarded reads, including callback errors |
| Device read bytes | 4 GiB | Counts requested forwarded bytes |
| Work units | 4 GiB | Accounts reads/scanned records, attribute/list spans, name comparisons, graph steps and allocation/sort steps |

All budgets must be positive. Exhaustion is RANGE with a named `exhausted`
dimension; cleanup remains allowed after the first failure. Core limits apply
as well, so a core limit can return RANGE with no diagnostic exhausted dimension.
Work units are deterministic accounting units, not CPU instructions or a timeout
for a blocked caller callback. Individual core parsers retain their own bounds;
an embedding service also needs its own I/O cancellation/deadline contract.

The report preserves the failing stage, raw `record_number` when a FILE header
has not yet validated, full references when available, attribute type and physical
cluster. These fields describe the current diagnostic subject; they are not a
stack trace or proof of a unique root cause. `streams` counts nonresident logical
streams, while `physical_runs` counts their non-hole intervals. Counts on failed
passes describe the completed prefix, never a successfully truncated inventory.
Successful reports clear subject fields and set FINISHED. API misuse clears the
report, returns INVALID and performs no callback work.

## Commands and local evidence

```sh
.build/ntfs-validate .build/fixtures/validation-standard.img
.build/ntfs-validate IMAGE --max-records 65536 --max-memory-bytes 16777216 --max-read-calls 100000 --max-work-units 67108864
python3 tests/validation_oracle.py --images artifacts/interoperability-stream-catalog --output artifacts/interoperability-validation-next
python3 scripts/fuzz.py --target validation --seconds 60 --compiler /opt/homebrew/opt/llvm/bin/clang --output artifacts/fuzz-validation-next
```

The CLI accepts only positive decimal budgets. It emits one JSON report and
returns 0 for complete success, 1 for partial/error verdicts and 2 for usage or
image-open errors. Counters use decimal strings and references use hexadecimal
strings to avoid JSON integer precision loss. Stage and exhausted fields use
the public enums. Special files are rejected after nonblocking open; a FIFO
without a writer cannot block before the regular-file check.

Original complete metadata fixtures cover supported resident/fragmented/listed
storage, extension filenames, hard links, ADS, sparse streams, nested/case-sensitive
directories, inert system records and physical bad clusters. Negative images
cover bitmap mismatch, stale/missing/duplicate links and lists, disconnected
directory cycles, invalid sizes, overlapping/unclaimed/free clusters, missing or
duplicate root anchors, duplicate empty bad-cluster streams and explicit
unsupported cases. Fault sweeps verify exact release sizes, unchanged source
bytes, complete retry and private ownership beside an existing live mount.
The physical bad-cluster test refuses any callback read of its bad sector range.
The separate `bad-clusters` suite checks nine complete storage/admission profiles,
25 private-open allocation failures, 12 partial/full open-read failures and
38 exact/one-below cumulative operation boundaries with independently counted
callbacks/bytes. Four complete diagnostic sweeps add 935 allocation failures and
890 partial/full read failures, exact release, unchanged media and fresh retry.
The 32 new complete-volume cases include eight positive inventories and exact
negative subjects for gaps/overlaps, missing/duplicate/reordered lists, stale
references/owners, malformed mappings/size/units, unsupported first flags and
free bad clusters. Forbidden-range callbacks also cover two distant bad runs.
Twenty-two additional index images cover used unreachable slots, out-of-span
padding, fragmented and multi-block trees, resident/nonresident paged bitmaps,
small roots and index sizes below/equal/above cluster size. Forbidden-range
callbacks prove free index storage stays unread. The three reads of a 513-byte
nonresident bitmap have six partial/full backend failures and nine read-call,
read-byte or work refusals before their callbacks, with retry and exact cleanup.
Required-allocation sweeps disable optional record caching; separate successful
runs exercise cache-enabled owners. A best-effort cache miss is not a required
allocation failure.

The independent suite exports both bitmaps and MFT/mirror data through standalone
NTFS-3G utilities. It compares active-record/cluster counts, exact required replica
prefix bytes and declared coverage in four geometries. It hashes every
image before and after, preserves failed reports and refuses evidence-directory
overwrites. This is independent mkntfs acceptance, not a Windows-native oracle.
See ACCEPTANCE.md for current executions and retained initial failures. The
dedicated validation fuzzer uses complete compact images, fixup-preserving and
generic mutations, and checks deterministic reports, cleanup and all four dynamic
budgets. It has its own corpus; ordinary image API fuzz seeds remain separate.
