# Fresh Windows cloud oracles and inputs

These source-side routes replace dependencies on an owner's VM, VHD and disk
identity. They do not inherit the earlier native acceptance. Record each actual
hosted run, its first failure, source revision and retained reports separately.
No native execution is established merely by adding these commands.

The [first completed scratch capture](https://github.com/machlin-project/ntfs/actions/runs/37854379914)
now passes native creation, read-only chkdsk, ordinary detach and unchanged
read-only acquisition. Offline corpus and complete-validation consumers reject
the original NTFS 3.1 `$Volume::$VOLUME_INFORMATION` flags value `0x0080` before
namespace checks. `scripts/probe_windows_volume_flags.ps1` runs a fresh guarded per-volume
short-name-policy experiment, preserving a baseline and separate detached
original/enabled/disabled/reenabled VHD/raw-corpus snapshots. It uses only the
documented per-volume `fsutil 8dot3name` form and never changes the machine policy.
The [completed probe](https://github.com/machlin-project/ntfs/actions/runs/37858557415)
observes `0x0080` with short-name creation disabled and `0x0000` with it enabled,
including a second enable transition. All five original/baseline/phase corpus
inventories retain equal identities, namespace, payload hashes, timestamps and
geometry. The core now admits only this additional flag on NTFS 3.1, retains its
raw value, preserves dirty-bit priority and refuses every other unknown bit.
The current-source corpus comparison passes all 28 checks on the unchanged first
scratch image and independently on all five baseline/phase images; the 78
synthetic version/flag profiles also pass. Full-volume validation and writable
admission remain separate from these native format and namespace/content facts;
scratch acquisition and policy observation do not establish recovery.

## Independent AccessCheck

On Windows CPython:

```powershell
python scripts/collect_windows_access.py --output artifacts/windows-access
```

Retain `manifest.json` unchanged. On the Linux/macOS build containing the diagnostic:

```sh
python3 tests/windows_access.py artifacts/windows-access/manifest.json \
  --evaluator .build/ntfs-dacl-evaluate --output artifacts/windows-access-review \
  --require-native-dacl
```

The optional CI gate requires complete native acquisition, every supported DACL
vector matching, no API errors, no comparison failures, no missing cases and no
changed input. Only explicitly declared probes may be unsupported; only boundary
cases may remain outside the discretionary plane. `status: gaps` and the full
authorization refusal remain in the report. This flag does not remove cases or
turn unsupported decisions into successful authorization. Synthetic acquisitions
cannot pass it. The default CLI behavior still fails any overall gap.

## Native scratch creation

Use Windows PowerShell on an administrative disposable runner, with Python on
PATH and a fresh output below the runner's `TEMP` or `RUNNER_TEMP`:

```powershell
& tests/windows_scratch_guard.ps1
& scripts/bootstrap_windows_ntfs.ps1 `
  -Output "$env:RUNNER_TEMP\MachlinNTFSCloud-$env:GITHUB_RUN_ID-$env:GITHUB_RUN_ATTEMPT"
```

The bootstrap uses the Windows DiskPart `create vdisk` command rather than
requiring the optional Hyper-V module. Its sole DiskPart instruction creates a
new expandable file. It never selects an existing disk or changes global SAN or
mount policy. The default logical disk is 256 MiB; explicit sizes are bounded to
128–4096 MiB. Drive R must be unused; R–Z may be selected explicitly for acquisition.

Before initialization, partitioning, formatting and every namespace mutation,
`Get-DiskImage` must resolve that exact new path to one file-backed virtual disk.
Every disk present before creation is excluded, as are boot/system/offline disks.
The blank disk must be RAW with no partitions. After initialization its GUID and
unique ID are retained; the single basic-data partition's GUID, number, offset and
length are rechecked. Actual 512-byte sectors, 4096-byte clusters and 1024-byte
FILE records remain this harness's admitted geometry, not assumptions about all
NTFS volumes. New directory/file operations have an independent original-byte
oracle, including the baseline ADS. The code never formats an existing volume.

Each file stream is flushed, read-only chkdsk must succeed, native volume locking
and `FlushFileBuffers` must succeed, and ordinary VHD detachment must complete.
The same VHD is then mounted read-only and the existing
native corpus collector captures metadata, names, stream bytes and the raw volume.
A second ordinary detach must leave the entire VHD hash unchanged. A failed step
retains `bootstrap.json`, original diagnostics and any completed inputs, returns
nonzero, and never retries creation or candidate recovery. Detachment is attempted
by the created path on failure; a failure to detach remains an explicit error.
Archive media only after checking its actual detached state.

`bootstrap.json` records OS/PowerShell identity, source-script hashes, host disk
exclusions, native GPT/partition identities, exact file hashes, command exit codes,
and stage/error details. It expressly leaves native recovery unqualified. The
corpus contains disposable runner account SIDs and authored files, no owner data
or credentials. Keep these generated artifacts outside Git. Runner capability
failures are failures with an observed stage, not test passes or inferred support.

## Consumer-local native inputs

Transfer the unchanged detached `base.vhd`, `bootstrap.json` and complete `corpus/`
directory. On the consumer with qemu-img and the built core:

```sh
python3 scripts/windows_cloud_inputs.py --bootstrap artifacts/windows-scratch/bootstrap.json \
  --qemu /usr/bin/qemu-img --output artifacts/windows-cloud-inputs
python3 tests/windows_corpus.py artifacts/windows-scratch/corpus/manifest.json \
  --reader .build/ntfs-inspect --report artifacts/windows-corpus-review/report.json
.build/ntfs-validate artifacts/windows-cloud-inputs/source.ntfs
```

The preparer rejects partial/synthetic acquisitions, duplicate JSON fields,
unsafe paths, links, changed bytes, inconsistent geometry, reparse points and
unexpected namespaces. It verifies every original payload hash, authored file
contents, complete raw partition bytes, both GPT copies and the native disk and
partition GUIDs. Any trailing partition sector not included by the native volume
API comes from the exact raw VHD, never fabricated padding. It creates a readonly
whole-disk container and partition source, baseline/source descriptors and a
consumer-local `cloud-manifest.json`. This evidence is acquisition and packaging;
it is neither core admission nor a Windows recovery verdict.

## Directory and recovery continuation

```sh
python3 tests/native_directory_batch.py \
  --cloud-manifest artifacts/windows-cloud-inputs/cloud-manifest.json \
  --build .build --qemu /usr/bin/qemu-img --output artifacts/windows-directory
python3 tests/native_directory_package.py --local artifacts/windows-directory \
  --cloud-manifest artifacts/windows-cloud-inputs/cloud-manifest.json \
  --qemu /usr/bin/qemu-img --tag CloudUniqueRun --output artifacts/windows-directory-packages
```

The full 803-operation batch retains its independent namespace model, four
structural transitions, four phase snapshots, preselected commit/metadata cuts,
fresh-owner recovery and quiet reopen. Linux copies preserve holes and discard
nontransition predecessors; macOS keeps its APFS clone route. Every new image
remains a separate regular file. Actual disk/partition geometry and a fresh root
come from validated native inputs, rather than the historical owner's disk.
Native logfile/admission failures must be diagnosed from those exact bytes;
acquisition success cannot override an unsupported recovery origin.

The packager verifies complete virtual disks and gives each candidate unique outer
GPT identities. Groups still contain at most eight VHDs. Stage each generated
`transfer.json` under its exact `batch.json` directory in a disposable Windows
runner, then run the existing `windows_directory_guard.ps1` and
`windows_image_recovery.ps1` with the generated report name. The explicit cloud
profile keeps the baseline VHD detached and hash-bound before and after every
batch, instead of requiring an owner-specific T: disk. It requires the exact
fresh root, prepared candidates, manifest geometry, and exclusion of all disks
that existed before attachment. Historical owner-VM profiles retain their original
separate admission path. Neither path changes native namespace, data, ADS, IDs,
times, ACL, plaintext/health, read-only chkdsk or original-event requirements.

The hosted replay wrapper performs the staging without trusting producer-local
absolute paths. Keep the package directory topology and pass the separately
retained baseline VHD:

```powershell
& tests/windows_cloud_transport.ps1
& scripts/replay_windows_cloud.ps1 -Packages .\downloaded-packages `
  -BaseVhd .\downloaded-inputs\base.vhd `
  -Output "$env:RUNNER_TEMP\MachlinNTFSReplay-$env:GITHUB_RUN_ID-$env:GITHUB_RUN_ATTEMPT"
```

It prechecks every group's contained file mapping and hash, refuses existing
stage/report directories, and runs the hash-bound guard/collector once per group.
Original JSON reports contain the original event XML. Only confirmed detached
postimages are copied into the wrapper output; completed postimage hashes must
agree with the first collector report. Failure preserves output and stops the
remaining groups. Uploading the wrapper output cannot include a live VHD.

Do not rerun a completed native candidate to replace its verdict. Preserve every
original event and exact detached postimage, including failures. Missing healthy
or predicted torn-page events remain failures. VHD recovery does not qualify
physical power cuts, installed FSKit behavior or release signing.

## Sources and contracts

The PowerShell bootstrap/guards and consumer adapter are original repository code.
Windows commands follow Microsoft's [create vdisk documentation](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/create-vdisk),
[Mount-DiskImage](https://learn.microsoft.com/en-us/powershell/module/storage/mount-diskimage)
and [Get-DiskImage](https://learn.microsoft.com/en-us/powershell/module/storage/get-diskimage).
File-backed storage admission uses the raw documented
[MSFT_Disk.BusType](https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/msft-disk)
value, independent of PowerShell's enum display spelling.
GPT validation reuses the repository's original UEFI-based wire checks. No foreign
filesystem implementation is imported or linked. qemu-img remains an external
container conversion/checking utility, not a filesystem oracle.

Portable `windows-cloud-inputs`, `directory-harness` and `access-contract` tests
cover local contracts. `tests/windows_scratch_guard.ps1` parses the Windows
scripts and checks refusals without discovering or modifying a disk. Only an
actual Windows acquisition/run can establish the native execution boundary.
