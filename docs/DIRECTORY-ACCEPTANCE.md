# Directory mutation acceptance batch

The preparation boundary below records the original local handoff. Subsequent
[private CI](ACCEPTANCE.md#initial-cloud-ci-and-dots-handoff) passes the 220-suite
portable gate on hosted macOS; dedicated stress/fuzz and the native phases remain
unverified. [Dots](HANDOFF-DOTS.md) now owns the complete cloud-feasible
continuation. The owner-local paths and VM procedure below are reference inputs,
not available cloud resources; the cloud handoff defines their replacement work.

## Preparation boundary

This batch is **prepared, not executed or accepted**. The user requested source,
tests and harness preparation followed by a stop **before testing**, with the
execution handoff to Sol. No build, fixture generation, fuzz campaign, test,
native mount or VM operation was performed while preparing these files.

The preceding accepted core remains the 213-suite checkpoint described in
[acceptance](ACCEPTANCE.md#incremental-directory-and-journal-preparation).
Installed build 19 predates these optimizations. It cannot qualify this batch.
This preparation changes test/harness code, not the driver's disk algorithms.

Sol owns VM preparation and installed-app identity. Luna runs bounded prepared
CLI commands after Sol hands over the selected VM. Main diagnoses failures and
reviews acceptance evidence. One worker owns a VM at a time. The Windows VM may
run alongside the user's Debian VM; do not terminate UTM or change Debian.

All host commands below run from
`/Users/darekhta/Development/machlin/ntfs`. VM transport commands use
`/Users/darekhta/Development/machlin/lab` explicitly. Use a new artifact directory
when diagnosing a failure; preserve the failed case, original report and input.
Do not rerun completed native candidates to replace their first observation.

## Prepared coverage

| Layer | Prepared test and oracle | Remaining acceptance |
| --- | --- | --- |
| Private `$I30` tree | [Operation fuzzer](../tests/fuzz_directory.c): independent name/reference/metadata model, flat-key and wire-tree checks, reachability, duplicates, absent lookups, variable-length replacement, empty-root regrowth, allocation failures | Compile, deterministic replay, stress and coverage-guided campaign |
| Complete native image | [Current-C batch](../tests/native_directory_batch.py): 803 operations, four phase snapshots, observed root spill/split/merge/root collapse, captured publications and preselected interruption cuts | Fresh C recovery, metadata/namespace/content/security checks, quiet reopen |
| Windows | [VHD packaging](../tests/native_directory_package.py), [read-only admission](../tests/windows_directory_guard.ps1), existing strict [collector](../tests/windows_image_recovery.ps1) | Native recovery, read-only chkdsk, event attribution, exact detached postimage retention |
| Installed FSKit | [Syscall workload](../tests/mounted_directory.c) and [Tart runner](../scripts/test_mounted_directory.py): 320 long names, cross-parent rename, 240 deletions, 80 short-name replacements, complete contraction, cached negative lookups and reused enumeration handles | Current signed extension, ordinary unmount/remount after each phase, byte/identity/time equality |
| FSKit → Windows | [Frozen-image observer](../tests/mounted_directory_collect.py): independent payload oracle plus warm/cold syscall metadata versus core inventory | Package all four exported phases and run the same Windows gate |

The operation-sequence fuzzer complements the existing raw index-root/index-block
parser fuzzers. It does not model arbitrary corruption, concurrent access, full
disk persistence or every Unicode collation. Allocation failure abandons the
private plan and checks allocation balance; it does not continue a failed plan.
The fixed cascading-deletion overflow regression remains in `directory-tree`.

The native namespace model is in [directory_scenarios.py](../tests/directory_scenarios.py).
Files are empty in the offline sequence. FSKit files contain 129 independently
specified bytes per identity. All names stay inside the existing strict Windows
`sequenceObjects` profile. The Windows collector and its refusal rules are unchanged.
The three native observer/checkpoint C tools now build from tracked sources with
the current core, instead of reusing older generated binaries.

## 1. One local build and regression gate

After the user hands execution to Sol, assign these commands to Luna. Capture
stdout/stderr and exit codes in a fresh `artifacts/directory-acceptance-20261008/`.
Do not invoke Meson directly with ambient credentials.

```sh
python3 scripts/format.py --check
python3 scripts/build.py .build
python3 scripts/test.py .build
python3 scripts/stress_directory.py --cases 256 --seed 20261008 --output artifacts/directory-acceptance-20261008/stress
python3 scripts/fuzz.py --target directory-mutation --seconds 900 --compiler /opt/homebrew/opt/llvm/bin/clang --output artifacts/directory-acceptance-20261008/fuzz
python3 scripts/test_fskit.py
```

The expected ordinary test count is the preceding 213 plus six new directory
seed replays and one pure harness regression. Treat the discovered Meson inventory
as authoritative if unrelated work changes that count. All assertions and fatal
ASan/UBSan remain enabled; no finding is ignored. If the indicated full LLVM
compiler is unavailable, choose an installed Clang with libFuzzer as documented
by `scripts/fuzz.py`; Apple Clang without that runtime is a preparation refusal.
The campaign first replays all 100 authored seeds, including allocation failures.
The stress runner retains those seeds plus 256 reproducible random inputs.

Stop on a compile error, sanitizer report, unexpected core refusal or model
mismatch. This preparation has deliberately not established that it compiles.
Adapter host SKIPs remain separate from the later guest component acceptance.
There is no new kernel code in this batch; the preceding strict CPU/object results
remain prior evidence. Rerun `scripts/check_cpu.py` if diagnosis changes core code.

## 2. Current-C images and native recovery inputs

The source descriptor below binds retained native media; its old binary hashes
are **not** used. All current tools come from the just-built `.build` directory.
The original image is opened read-only and remains hash-bound. Writes go only to
new private regular-file clones. This stage runs no VM commands.

```sh
python3 tests/native_directory_batch.py \
  --source-descriptor artifacts/overwrite/native-pressure-tools-20261007/result.json \
  --baseline-manifest artifacts/overwrite/resident-writer-interruptions-20261006/complete/manifest.json \
  --output artifacts/directory-acceptance-20261008/local

python3 tests/native_directory_package.py \
  --local artifacts/directory-acceptance-20261008/local \
  --collector-profile artifacts/overwrite/windows-native-growth-matrix-20261008/batch-00/batch.json \
  --raw-container artifacts/windows-write-vm/native-write-alias-20261006/native-write-alias-20261006.raw \
  --base-vhd artifacts/overwrite/native-vhd-format-preparation-20261006/base.vhd \
  --tag DirectoryCurrent20261008 \
  --output artifacts/directory-acceptance-20261008/windows-inputs
```

The batch discovers actual structural transitions by before/after live index
counts and requires all four. It saves the first occurrence of each before
recovery, then selects both commit sides, every critical journal stage and each
metadata target class. The number of cuts follows those captured plans; do not
force an old fixed case count or choose cases from successful verdicts.
The predecessor, trace, selection, winner/loser object expectations and actual
fresh-owner recovery logs are retained. Reclaimed unowned pages are excluded
from predecessor metadata comparison, while the volume and namespace still must
validate. Recovery must become quiet on a second fresh owner.

Four completed phase images are retained: `full` (320 files), `contracted`
(80 files across two parents), `reused` (160 files), and `empty`. Each snapshot
undergoes complete virtual-disk comparison to the captured-publication oracle.
Each VHD includes a new outer GPT identity; every partition byte is bound to the
selected input and every virtual disk is compared after conversion. No claimed
native result is derived from C recovery success.

## 3. Windows, bounded groups without GUI input

Sol prepares the already authorized Windows VM through its working QGA harness.
The prior transport example is `.build/native_growth_windows_batch.py`, with
transfer/archive helpers in [windows_image_archive.py](../scripts/windows_image_archive.py).
Use that transport only; do not import its old fixed candidate count, manifests,
output paths or native verdicts into the new gate. No new Windows installation
or license approval is needed.

For each generated `group-NN`, `batch.json` specifies a **fresh guest directory**
and `transfer.json` supplies exact source files, lengths, hashes and destination
names. Transfer those files, the batch JSON, the current collector and the guard
through QGA/file transfer. Admission is read-only and precedes candidate mounting:

```powershell
& .\windows_directory_guard.ps1 -Collector .\windows_image_recovery.ps1 `
    -CollectorHash $retainedCollectorSha256 -BatchManifest .\batch.json
& .\windows_image_recovery.ps1 -BatchManifest .\batch.json -ReportName $generatedReportName
```

Paths and report name come from the generated group entry, not from this example's
current directory. Hash the collector when freezing the transfer inputs. Preserve
the complete returned report, original XML and every detached output VHD on the
host. Confirm archive lengths/hashes before releasing only that group's private
guest files. Eight-case groups bound guest storage; they do not authorize deleting
old retained experiments. A transport timeout calls for status/report collection,
not a second native execution. Unexpected original T: identity is a stop condition;
do not weaken the collector to accept a different disk.

Require every product to pass content, names, references, times, security,
read-only chkdsk, clean volume state and event checks. Only sector mixtures
predicted from the original unrecovered bytes may explain torn-page warnings.
This gate is VHD mount recovery, not a hardware power-cut test.

## 4. Current installed FSKit and four remount boundaries

Sol builds/signs a **new** app version using [build_fskit.py](../scripts/build_fskit.py)
and the existing personal signing/install procedure. Current component tests must
run in the dedicated `machlin-ntfs-fskit-27.0.1` Tart VM. Retain installed/loaded
extension identity and hashes; a successful app build alone does not qualify it.
Use the existing CLI import workflow in [fskit_image.py](../scripts/fskit_image.py).

Prepare a new private copy of the same native source, in the app owner's inbox,
and import it through the signed app as user 501. Both `native-growth` and
`native-move` must initially be absent. Copy the current `ntfs-mounted-directory`
executable and any required sanitizer runtime into the guest through the existing
shared directory/CLI procedure. Do not substitute build 19 or install on the host.

The runner takes concrete identities produced during that preparation:

```sh
python3 scripts/test_mounted_directory.py \
  --vm machlin-ntfs-fskit-27.0.1 \
  --lab /Users/darekhta/Development/machlin/lab \
  --image-id "$prepared_image_id" --guest-image "$prepared_backing_path" \
  --guest-binary "$prepared_test_path" --build-number "$new_build_number" \
  --image-sha256 "$frozen_source_sha256" --binary-sha256 "$current_test_sha256" \
  --extension-sha256 "$installed_extension_sha256" \
  --output artifacts/directory-acceptance-20261008/mounted
```

These variables are generated VM preparation results, not user secrets. The runner
does not prepare or modify signing, VM lifecycle or credentials. It verifies the
owner/bookmark/backing and actual loaded extension inode, calls native syscalls,
ordinarily unmounts, freshly remounts and compares all file identities/times/bytes
after **each** phase. It then exports the inactive image through gzip binary stdout.
Failures retain the current state for diagnosis without cleanup or automatic retry.

Run the observer after all four phases, then reuse the VHD packager for these four
images with a different tag and output directory:

```sh
python3 tests/mounted_directory_collect.py \
  --mounted artifacts/directory-acceptance-20261008/mounted \
  --baseline-manifest artifacts/overwrite/resident-writer-interruptions-20261006/complete/manifest.json \
  --output artifacts/directory-acceptance-20261008/mounted-observed

python3 tests/native_directory_package.py \
  --local artifacts/directory-acceptance-20261008/mounted-observed \
  --collector-profile artifacts/overwrite/windows-native-growth-matrix-20261008/batch-00/batch.json \
  --raw-container artifacts/windows-write-vm/native-write-alias-20261006/native-write-alias-20261006.raw \
  --base-vhd artifacts/overwrite/native-vhd-format-preparation-20261006/base.vhd \
  --tag DirectoryMounted20261008 \
  --output artifacts/directory-acceptance-20261008/mounted-windows-inputs
```

Apply the same Windows group workflow to these outputs. Main reviews all reports,
first failures, skips, loaded-app evidence and retained postimages before updating
acceptance. Until then, the status of this batch remains **unverified preparation**.
