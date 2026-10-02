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
The internal diagnostic decoder shares the checked mapping-pair parser and never
reads bad sectors. Ordinary unflagged-hole streams remain rejected. These facts
come from [original bad-cluster research](https://flatcap.github.io/linux-ntfs/ntfs/files/badclus.html)
and independent raw metadata. Listed or flagged bad-cluster storage currently
returns UNSUPPORTED, preserving an incomplete verdict.

Separate DOS aliases have exact filename/index pairing checks, but their header
link-count convention is deferred pending native observations. They increment
`deferred_dos_link_counts`; even when the other passes succeed the final result
is UNSUPPORTED, naming the first affected record. A combined Win32/DOS namespace
entry is one primary name. Reparse directories, encrypted mappings and other
unsupported ordinary stream formats also retain incomplete verdicts.

The diagnostic does not parse arbitrary resident payload semantics, validate
all `$Secure`/quota/object-ID/reparse view-index relations, enumerate unreferenced
index-allocation blocks, compare every MFT mirror record, verify boot replicas,
read all file content, decompress every compression unit or replay `$LogFile`.
Those checks remain separate qualification work. Mount's existing mirror check
still covers only bootstrap record zero. Windows-authored fragmented metadata,
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
Required-allocation sweeps disable optional record caching; separate successful
runs exercise cache-enabled owners. A best-effort cache miss is not a required
allocation failure.

The independent suite exports both bitmaps through standalone NTFS-3G utilities
and compares core active-record/cluster counts in four geometries. It hashes every
image before and after, preserves failed reports and refuses evidence-directory
overwrites. This is independent mkntfs acceptance, not a Windows-native oracle.
See ACCEPTANCE.md for current executions and retained initial failures. The
dedicated validation fuzzer uses complete compact images, fixup-preserving and
generic mutations, and checks deterministic reports, cleanup and all four dynamic
budgets. It has its own corpus; ordinary image API fuzz seeds remain separate.
