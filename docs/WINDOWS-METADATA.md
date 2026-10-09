# Native metadata observation

The focused [metadata workflow](../.github/workflows/metadata-observations.yml)
runs on a new hosted Windows scratch VHD when the commit includes
`[metadata-probe]`, or through workflow dispatch. Acquisition success alone does
not qualify a setter, cache update rule, writable mount or recovery behavior.

[The wrapper](../scripts/probe_windows_metadata.ps1) creates the existing guarded
native baseline, preserves it unchanged, and operates only on a separate VHD
copy. Exact disk, partition, drive and volume identities are checked through the
existing scratch guards. No machine policy or privilege setting is changed.

[The observer](../scripts/observe_windows_metadata.py) authors one small ordinary
file with two long-name hard links in separate parents. It retains four phases:
initial closed state, explicit `SetFileTime` values, ordinary read-only/hidden/
system/archive attributes, and `FILE_ATTRIBUTE_NORMAL`. Each mutation records
`FileBasicInfo` through both links and original `FSCTL_GET_NTFS_FILE_RECORD`
responses for the target and both parents before the API, while its additional
attributes handle remains open, and after that handle closes. For `SetFileTime`
that is the actual mutation handle. `SetFileAttributesW` is a path API and owns
its internal handle; the separately held handle is labeled accordingly.

Schema 2 acquires the exact-ID raw records before opening any new per-path
observation handle. It adds a raw-only snapshot after the observer handles close
while the mutation handle remains open, then another raw-first snapshot after
that handle closes. Mutation identity guards still run immediately before every
mutation. The first [schema-1 capture](https://github.com/machlin-project/ntfs/actions/runs/37869853136)
is retained as an observer-affected sequence: its additional path handles closed
before raw acquisition, so its cache timing cannot be attributed solely to the
mutation handle. Its original bytes and identities remain useful structure facts.

The observer rechecks the original volume GUID, native serial/geometry, target
IDs and reparse exclusions before mutation. A file-record response must return
the requested ordinal, and its FILE header number and sequence must bind the
exact Win32 file ID. Any sequence supplied in the output identifier must agree.
Original response bytes are saved before these checks, including unexpected
responses. The [portable contracts](../tests/windows_metadata_observer.py) verify
downward-substitution, generation, framing and in-use/base-record refusals; they
do not supply a native provider or expected cache decisions.

Every phase then closes all observer handles, runs read-only chkdsk, locks and
flushes the exact volume, confirms detach, and retains both a hashed detached VHD
and the existing read-only raw corpus. Read-only acquisition must leave its image
unchanged; the original baseline and object identity manifest remain hash-bound.
A failed working VHD is copied into evidence only after confirmed detach. Failure
stops the sequence without retry.

The API requests and primary sources are recorded separately from measured
SI/FILE_NAME/I30 effects. Decoding must establish which parent indexes are resident
before treating live FILE-record responses as complete live index-cache coverage;
the detached raw corpus also retains allocated index storage. Microsoft documents
the handle-close timestamp boundary in [File Times](https://learn.microsoft.com/en-us/windows/win32/sysinfo/file-times),
the setters in [SetFileTime](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfiletime)
and [SetFileAttributesW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileattributesw),
and the downward record enumeration behavior in
[FSCTL_GET_NTFS_FILE_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_get_ntfs_file_record).
Actual cache effects remain observations to acquire, decode and compare.
