# Selected POSIX hard-link storage preparation

This is a private portable mutation contract, not execution or FSKit support.
The execution owner refuses this family before allocation or media I/O.

## Request and preserved policy

`NTFS_WRITE_CREATE_HARD_LINK` names one exact sequence-bearing ordinary base FILE,
one existing source directory/name, and one destination directory/name. Both
parents are sequence-checked. Source lookup must resolve to the requested FILE;
a stale generation or a different object fails. The selected stored source edge
must be a primary POSIX, Win32, or combined Win32/DOS filename. A DOS-only source
selection refuses; other existing DOS attributes and index entries remain intact.
No association, generation or deletion of Windows short-name pairs is inferred.

The new FILE_NAME and destination I30 key have the same original selected
FILE_NAME cache bytes, with only the parent, name length, name units and namespace
changed. The namespace is the independently qualified unpaired POSIX representation.
Existing FILE_NAME caches may legitimately differ from the source directory cache
or SI/DATA fields. The request deliberately selects the FILE_NAME cache, preserves
that difference, and does not infer a Windows cache-refresh rule.

The original FILE reference/generation, SI values and flags, all previous names,
all unnamed/named DATA attributes and data bytes, and security storage remain
unchanged. Neither target nor parent timestamps change implicitly. The new edge
increments physical FILE link count by one, therefore checked primary count by one;
DOS count does not change. This is an exact storage transform, not a native
`CreateHardLinkW` timestamp contract or a new inode-identity policy.

## Atomic private preparation

The existing complete filename inventory checks resident values, parent references,
physical/header counts and duplicate filename locations. Ordinary admission rejects
directories, special/system/read-only/encoded/reparse targets, attribute lists and
unsupported record layouts. Directory case policy controls destination collisions;
any occupied destination refuses, even when it already refers to the same object.

One indexed resident FILE_NAME is appended after the existing unnamed filename
attributes. The declared next instance must be unused and below the reserved
sentinel; no instance wrap, extension record or implicit renumbering is invented.
Insufficient inline FILE capacity returns NO_SPACE. All old attributes and their
padding are copied without rewriting. The next-instance and physical-link fields
are advanced only in the private record. The existing directory tree/store code
owns local insertion, split/root changes, cluster allocation and I30 bitmap updates.
It runs with namespace-time updates disabled.

The complete sealed FILE/INDX/bitmap regions enter the existing generic native
redo/undo compiler, which owns its bytes after plan close. No source writes or
persistence callbacks exist in this planner. Every preparation/allocation/read
failure discards the private plan; source bytes stay unchanged. Generic program
compilation and prefix compensation are preparation evidence, not new durable
family qualification. The ordinary execution owner explicitly refuses this enum
before allocation or image I/O, and no FSKit entrypoint is added.

## Independent tests

[write_hardlink_fixtures.py](../tests/write_hardlink_fixtures.py) authors original restored target-FILE goldens and
new filename values from named wire fields. The source deliberately has different
SI, FILE_NAME and directory cache values and a named-stream witness. Cases include
same/cross-parent edges, long names, existing long/DOS names, fragmented data,
case-folded collisions, stale source/target/destination generations, another source
object, directories, exhausted attribute instance, corrupt physical count, inline
FILE capacity, a real directory split and volume allocation exhaustion.

[write_hardlink.c](../tests/write_hardlink.c) compares the complete restored target record, exact old/new I30
key bodies, complete projected-volume consistency, original regions and image
preservation, owner refusal, borrowed-output aliases, every observed preparation
allocation and full/partial read failure, program allocation failure and every
complete redo-prefix inverse. It closes the plan before checking owned program
bytes. Newly allocated index storage has no predecessor object on inverse; restored
allocation metadata, rather than an invented old index image, owns that boundary.

## Minimum remaining observations

Native execution remains unadmitted until one prepared hard-link family completes
its own old-or-committed C persistence/recovery and native Windows recovery gate,
including index growth, metadata/data/security/ADS identity, clean state and
read-only chkdsk. Existing ordinary create/rename acceptance is not this evidence.

A native semantic API additionally needs an original Windows before/after witness
for source SI, every existing/new FILE_NAME and every corresponding I30 key after
hard-link creation, both before and after closing handles. Include distinct cached
values, same/cross-parent cases, a pre-existing long/DOS pair, queried short-name
policy, full FILE references and physical/primary/DOS counts. That is the minimum
observation for implicit timestamp/cache policy and native pair behavior. The
portable explicit-cache storage transform does not wait on this observation.

Base-record FILE capacity and attribute-list/extension ownership remain a separate
portable family. No GPL filesystem algorithm was imported or linked.

## Published logical-link limit and stored aliases

Microsoft's [CreateHardLinkW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createhardlinkw)
documents 1023 links created through that API for one existing file.
[MS-FSA FileLinkInformation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/891bb8eb-89f8-46ca-80b7-9f5d4e8b5583)
places its TOO_MANY_LINKS check at an existing LinkList size of 1024.
[MS-FSA Per File](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/20ff431e-7c4d-4098-a51c-e6d5614a1c93)
models the short spelling on an existing Link member. These are logical/API
limits, separate from the uint16 physical FILE-name field. The natural
reconciliation is 1023 additionally created links plus the original link;
this interpretation is not a native maximum-link-count measurement.

The private count-admission helper independently checks complete physical,
primary and DOS inventory consistency, refuses 1024 existing primary names, and
checks physical-field overflow separately. At 1023 existing primaries a single
new primary stays within the selected 1024-resulting-primary cap. DOS storage
does not consume another primary slot. This cap does not authorize any DOS
association or high-count storage: the current base-only FILE preparation reaches
inline capacity much earlier and explicitly refuses attribute-list growth.

The protocol also specifies abstract parent-time, target-change-time/archive and
duplicated-information updates. Our exact copied-cache transform deliberately
preserves those fields and is therefore not an implementation of that Windows
API semantic operation. Native observation remains needed to bind these abstract
updates to complete SI/FN/I30 disk snapshots and handle-delayed publication before
choosing and admitting the native operation.

## Portable evidence

The isolated staged build passes 13 count boundaries and 25 complete-image
profiles, 150 preparation-allocation failures, 76 full/partial read failures,
77 program-allocation failures and 45 complete redo-prefix inverses. The core
objects compile with freestanding/no-builtin and the 2-KiB frame ceiling; ASan
and UBSan remain fatal. Local LeakSanitizer cannot run under the cloud ptrace
configuration; that runtime failure is retained separately, and the passing run
uses exact owned-allocation balance assertions. There is no new native execution,
Windows recovery or installed FSKit result.

The first attempts preserve two test-harness corrections: overlay header include
ordering and the independent INDX reader's header offset. Neither required a
production-algorithm correction. Core integration and the connected full suite
remain a separate gate from this isolated staged result.

## Independent hosted Windows count observation

Run [collect_windows_hardlink_limit.py](../scripts/collect_windows_hardlink_limit.py)
with `--output artifacts/windows-hardlink-limit` in a fresh hosted Windows job.
The output must not exist. The observer creates its own unique empty directory
under the existing runner TEMP location and requires Windows to identify that
volume as NTFS before file creation. It neither opens pre-existing file targets
nor changes machine settings, privileges, disks or mount state.

The original file contains independently specified unnamed data and a `witness`
ADS. The observer uses CreateHardLinkW, checks seven preselected count milestones
through GetFileInformationByHandle, then records the next API result and exact
last-error value. The comparison retains volume/file identity, names, logical
count, size, attributes, payload and ADS hashes. Raw returned information bytes
are retained too; access timestamps are observed but excluded from preservation
assertions because the observer itself reads the streams. The expected limit
error is Microsoft's [ERROR_TOO_MANY_LINKS (1142)](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--1000-1299-).

Actual source bytes and metadata reports stay in the artifact directory, and the
uniquely owned native TEMP witness remains for same-run diagnosis. A partial,
early-failed or surprising native result remains a failed observation with its
original evidence. Eight synthetic ABI/report/refusal tests separately exercise
the harness and cannot mark a result as native. This command does not measure
raw physical filename/DOS counts, inspect ACLs or WAL, or qualify the C writer.
