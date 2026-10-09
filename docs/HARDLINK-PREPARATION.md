# Selected POSIX hard-link storage preparation

This is a private selected-cache storage contract with dedicated portable
persistence/recovery qualification. The general execution owner still refuses
this family before allocation or media I/O; no FSKit operation is enabled.

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
compilation and prefix compensation alone are preparation evidence. The dedicated
family execution harness below keeps its evidence separate. The ordinary
execution owner explicitly refuses this enum
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

The private C storage family now passes the old-or-committed persistence/recovery
boundary below. General/native execution remains unadmitted until its separate
Windows recovery gate passes, including index growth, metadata/data/security/ADS
identity, clean state and read-only chkdsk. Existing ordinary create/rename
acceptance is not this evidence.

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
the hosted observation below now verifies this API boundary on one recorded
Windows/NTFS environment. It does not measure physical FILE-name packing.

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
uses exact owned-allocation balance assertions. This preparation checkpoint alone
established no native execution, Windows recovery or installed FSKit result. The
later private C execution evidence below does not change those native boundaries.

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

## Hosted native observation

The [Windows Server 2025 observation](https://github.com/machlin-project/ntfs/actions/runs/37852693547)
on source `62d2986bdc97d2c5e470d1d9b2668b11fc2da23a` created 1023
additional links, observed 1024 total links, and received Win32 error 1142 on
the next creation. Exact original identity, namespace, payload and ADS remained
unchanged at the refusal. The retained report marks native collection and all
checks complete; its runner was Windows build 26100. This independently verifies
the logical API cap only. It does not qualify the C writer, physical DOS-pair
counts, extension-record packing, cache/time side effects or recovery.

## Private C execution and fresh recovery

[hardlink_execution.c](../tests/hardlink_execution.c) now qualifies the selected
storage transform through the existing sealed plan, owned program, batch executor
and journal-derived recovery interfaces. It adds no general-owner exception.
Five independently authored profiles cover same/cross-parent insertion, an
existing Win32/DOS pair, fragmented unnamed data and an actual index split.

The complete published-image oracle applies captured sealed publications to the
original complete image. This is complemented by the independently authored
complete target-FILE golden, full-volume validation and exact old-or-committed
bytes outside the journal. Only changed FILE/INDX USA storage and journal-derived
LSNs are normalized; unchanged sibling FILE records, parent times, security,
old names, ADS, data and trailing image bytes remain exact. Every planner/program
owner closes before execution, and every writer owner closes before recovery.

All 2,499 preselected whole/512-byte prefix/suffix writer and interrupted-recovery
states pass, including both commit sides and every metadata publication. Every
recovered image validates and a fresh second recovery owner publishes zero writes.
Execution performs no reads or allocations. Ten separate ordinary-image recovery
files additionally pass actual POSIX transfers/persistence and fresh close/reopen
with complete captured-publication comparison. This is regular-file persistence,
not a physical power-cut or Windows result.

The focused fatal ASan/UBSan run passes `write-hardlink` and `hardlink-execution`
in 1.24 and 131.37 seconds respectively. Local LeakSanitizer retains its documented
ptrace restriction, with exact owned-allocation accounting still required. Evidence
is retained in `artifacts/dots-hardlink-execution-check-20261009/retry2/`. The first
failed attempt incorrectly required complete image length to be cluster-aligned;
the unchanged fixture includes a 512-byte final sector. The harness now compares
that exact tail rather than truncating or padding the input. No core correction
was needed at this boundary; the first failure remains retained.

## Prepared native storage-family candidates

The private `hardlink-storage` request in
[write_operation_image.c](../tests/write_operation_image.c) requires an explicit
zero timestamp and source/destination paths. It calls the sealed private
interfaces directly and leaves the general execution owner and FSKit refused.
[native_hardlink_batch.py](../tests/native_hardlink_batch.py) prepares explicitly
named `hardlink-*` candidates from validated Windows scratch inputs, with
cross-parent, same-parent and a bounded search for an actual hard-link index split.
Cut selection precedes recovery verdicts and covers both commit sides, all critical
journal stages and every metadata home. It retains exact original crash images,
full-byte publication/recovery comparisons, full validation and quiet reopen.

[native_hardlink_observer.py](../tests/native_hardlink_observer.py) independently
walks raw MFT mappings and complete FILE/I30 keys. It constructs the entire new
resident FILE_NAME header, cache, name and padding from named wire fields, checks
the complete target record, preserves every old key and unselected parent
attribute, and compares the original data/ADS bytes. The core inspector's
security/identity observations complement this separate wire oracle. Its four
synthetic contract tests pass, including altered ADS, missing indexed flag, torn
FILE and changed untouched-sibling LSN refusals. Those tests establish no native
verdict.

The native source-side route is:

```sh
python3 tests/native_hardlink_batch.py \
  --cloud-manifest artifacts/windows-cloud-inputs/cloud-manifest.json \
  --build .build --output artifacts/windows-hardlink-storage
python3 tests/native_directory_package.py \
  --local artifacts/windows-hardlink-storage \
  --cloud-manifest artifacts/windows-cloud-inputs/cloud-manifest.json \
  --qemu /usr/bin/qemu-img --tag HardlinkUniqueRun \
  --output artifacts/windows-hardlink-packages
```

The unchanged packager and Windows collector accept only their already bounded
directory/name profile, with explicit hard-link case identities and source-family
reports. Original source identity, data, ADS, ACL and FILETIME checks, complete
namespace/identity checks, clean state, read-only chkdsk, original-event guards,
detached postimages and no-retry rules remain required. Candidate preparation
does not itself qualify Windows recovery or the implicit `CreateHardLinkW`
cache/time semantics described above.

### Current C on original Windows-authored media

The local current-C supplement now passes all three profiles on an unchanged
original Windows scratch source. It retains 53 individually named products:
three completed images and 50 preselected interruption inputs (14 cross-parent,
14 same-parent, 22 index-split). The split predecessor contains three live index
blocks; the selected operation adds index storage and has 44 publications.
The two other operations each have 18 publications. Original/new physical name
counts are checked, with the resulting counts two, three and two respectively.

All completed and recovered states pass the independent complete FILE/new-attribute
and I30 relationships, original data/ADS bytes and security, complete byte oracles,
full-volume validation and fresh zero-write reopen. The original source hash stays
unchanged. Evidence is retained under `artifacts/dots-hardlink-native-local-first/`,
with execution logs under `artifacts/dots-hardlink-native-local-execution-20261009/`.
The local supplement retains its explicit LeakSanitizer accommodation. No VM or
Windows recovery ran in this supplement; native media provenance does not turn a
C result into a native operating-system verdict.

[The focused hosted workflow](../.github/workflows/hardlink-storage.yml) separates
fresh source acquisition, C preparation, one-attempt Windows recovery and offline
review. [review_windows_hardlink.py](../scripts/review_windows_hardlink.py) binds the
complete expected case set to each first native report, reparses the retained
original event XML, checks sequence/ADS and health verdicts, and verifies every
confirmed-detached postimage against the original post-detach hash. Its five
synthetic contract tests pass. It does not mount, repair or retry a candidate.
Workflow preparation is not an executed Windows acceptance result.
