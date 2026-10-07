# Handoff to Sol

Work in `/Users/darekhta/Development/machlin/ntfs`, branch `development`.
Read AGENTS.md, README.md, ARCHITECTURE.md, ACCEPTANCE.md, PROVENANCE.md and WRITES.md.
This is an independent proprietary FSKit product; no kernel/LXNU adapter or public
license is included. The user's active scope is general NTFS writing. The bounded
checkpoint below is a tested step, not completion of that scope.

## VM ownership and operations

Never kill, terminate or relaunch UTM, change app-wide settings, or operate Debian
or unrelated VMs. The user allows the dedicated Windows VM alongside Debian.
Use the absolute lab working directory for every VM command. Only one worker may
operate a VM; obtain an explicit handoff before commands. Sol prepares native/GUI
state, Luna runs prepared CLI commands, and main owns implementation and acceptance.
Prefer the existing CLI transport; do not depend on console or credential input.
Never put credentials in source, shell arguments, environment or retained reports.
Inspect only task-owned processes and filtered relevant arguments.

The dedicated macOS 27 clone is running, its test image is ordinarily unmounted,
and the signed installed module is enabled. The preserved macOS 26.5 reading
baseline is unchanged. Windows is running and its original test volume is verified.
The latest nonboot/nonsystem postimage VHD detached normally; no boot or UTM app
lifecycle change occurred. Obtain current ownership before relying on this snapshot.
Exact VM IDs, paths, saved image IDs, loaded UUIDs and hashes live in ignored reports.
Do not read an active UTM disk image on the host or force/repair test attachments.

## Accepted existing-file writing

The core owns bounded native initialized-data and resident-data journal families
with retained original client roots, complete FILE snapshots and native redo or
compensation. Quiet origin, at most 64 complete families, no ring wrap/growth and
unsupported change-journal/volume/file features are explicit admission limits.
The immutable read environment has no write method. Arbitrary dirty-media
recovery and generic native history are not qualified.

Actual source-clone persistence and whole-image/idempotent-reopen checks pass.
All 110 initialized writer states and 264 interrupted-recovery states pass native
Windows recovery. The resident family separately passes 91 writer states and
264 interrupted-recovery states. Main's independent raw XML review binds each
case to its healthy event and exactly predicted USA warnings, with no unrelated
warning or repair.
Read NATIVE-WRITE-JOURNAL.md; retain original failed/interrupted invocations.
Do not remount a case solely to obtain delayed events.

Installed FSKit owner `pwrite`/`fsync` passes the complete file oracle; another
observer and a prefaulted read mapping see exact new data. Shared-mapping mutation
passes after the writer descriptor closes. Modified/changed times advance while
identity, size and native ownership/mode remain exact. Authenticated root and
nobody are each denied read-only, write-only and read/write opens. Ordinary
unmount removes the mount and releases backing descriptors.

Two fresh CLI mounts of one saved URL preserve the original backing inode and
entire postimage, return exact final data/metadata and ordinarily unmount. The
image moved into the app's private Inbox only after the preceding owner released
it; the old source URL is not represented as still valid. Both new mounts use
the same new saved URL. Their checks perform no new writes or GUI input.

The exported actual FSKit postimage is independently bound to a unique GPT VHD.
Windows confirms exact files/ADS/FILETIME/File ID/ACL, clean state, read-only chkdsk
and one matching healthy raw NTFS event. Candidate detach and original-volume
before/after guards pass. General writing and hardware power cuts are not implied.
Main review is `artifacts/overwrite/windows-mounted-postimage-20261006/main-review.json`.

The installed resident family also passes positioned and shared-mapping writes,
observer/prefaulted-mapping coherence, fresh same-saved-URL remount and ordinary
unmount. Its exact postimage passes independent whole-FILE/image checks, full
validation and zero-write idempotent recovery. Windows accepts all four files,
ADS, both FILETIMEs, both observed File IDs/ACLs, clean state, read-only chkdsk and
ordinary detach. Main binds the original healthy raw event and empty repair
providers. The accepted initialized image remains unchanged. See
`artifacts/overwrite/windows-resident-mounted-postimage-20261006/main-review.json`.

## Installed app and CLI harness

The current personally signed universal host embeds the exact signed extension
that performed the mounted write. Strict signatures, exact installed files,
matching executable/dSYM identities and actual enabled installed FSClient path
pass review. Development signing is not notarization or distribution readiness.

Use `scripts/fskit_image.py` with explicit VM and fresh ignored output directory.
The installed app provides `status`, `import FILE_NAME`, `mount IMAGE_ID`,
`unmount IMAGE_ID` and ordinary `unmount-path MOUNT_PATH`. It creates real app-scope
bookmarks, requires positive restored scope, and revalidates backing identity and
ownership before mounting through public FSClient. Automation imports only a
basename in the app's own Inbox; external files require a saved picker grant.
No synthetic scope, arbitrary external path authority or bookmark bytes in output.
The command wrapper closes stdin, retains JSON/raw output and never retries.
After a timeout inspect native state before another operation: the remote request
may still be pending. DEVELOPMENT.md gives prepared examples.

Run only the installed app binary. Launching staged copies can register their
nested plugins. Earlier staging registrations were removed only for this task;
the installed module then required one ordinary Settings enablement after user
unlock. Actual FSClient path and enabled state, not a PlugInKit election marker,
prove admission. Repeated mount/test operations now require no interface input.
Do not re-register staging copies or touch unrelated modules.

## Current evidence and limits

Core: 176 fatal ASan/UBSan suites, selected-Xcode style and both freestanding
architectures passed. FSKit: 63 host groups with thirteen explicit runtime SKIPs;
80 native groups, zero SKIPs, 871 preceding inputs and twelve resident inputs.
Failed startup, registration,
root-attribute authorization and initial harness-diagnostic attempts remain retained.
Ordinary vnode attributes permit kernel mount construction without granting data
or namespace rights. Native attribute-cache confidentiality is not claimed.

Acceptance reports are under `artifacts/overwrite/`:

- `mac-public-image-build9-mounted-write-20261006/`: actual positioned and mapped write.
- `mac-image-commands-fresh-remount-complete-20261006/`: two same-saved-URL fresh cycles.
- `mac-mounted-postimage-export-20261006/`: exact inactive backing export.
- `mounted-postimage-windows-preparation-20261006/`: independent whole-image/VHD oracle.
- `windows-mounted-postimage-20261006/`: native postimage and independent XML review.
- `windows-recovery-prefix-complete-delayed-main-review-20261006/`: complete bounded interruptions.
- `mac-resident-installed-acceptance12-20261006/`: installed resident write and fresh remount.
- `windows-resident-mounted-postimage-20261006/`: resident native postimage and independent XML review.

Allocation/free, resize, create/delete/rename, sparse/compressed/ADS writes,
Windows ACL mutation, generic journal history/ring wrap/growth, block-device writes,
hardware power cuts and broad native stress remain open. The next connected
implementation batch covers ordinary allocation/free, resize and namespace
mutations with their complete native WAL/recovery contract. Main writes the
batch tests first, implements the connected operations, then reviews one complete
local regression before preparing the VM batch. Do not introduce per-feature
VM loops during implementation. The five native Forget-anchored checkpoint
observations remain byte-level experiments, distinct from the later actual C
checkpoint and interrupted-recovery gate described below.
The experimental local C checkpoint/recovery implementation now passes independent
full-byte and interruption/fault inputs plus two sustained modeled sequences.
The closing local regression passes all 196 suites, both strict compiler targets,
23 private headers and the actual unsigned universal app/extension build.
The actual POSIX sequence passes 640 mutations, 256 checkpoints and 119 wraps
with F_FULLFSYNC and fresh recovery between operations. All 196 actual C
checkpoint/recovery Windows states now pass native file/ADS/time/ID/ACL, clean
state, read-only chkdsk and main's original-XML review. All full detached VHDs
are retained read-only; completed native cases are not repeated after transport
or log-sharing failures. [CHECKPOINT-REUSE.md](CHECKPOINT-REUSE.md) records the
settled-origin transition separately from still-open sustained native reuse.

The private ordinary-image harness now supports bounded transfer/persistence
faults and fresh recovery. Its complete regression passes 198 suites; seven
actual-C native-source create profiles pass full byte/content/validation and
quiet-reopen checks. Ten connected native-source operations and independent
standalone read comparisons also pass. The connected native batch has 28 reviewed
inputs, but Windows rejects its first complete create image before file/chkdsk
checks. Original XML binds a matching NTFS 98/level-2/state-3 error; the volume flags
change from zero to `0x0101`. The exact detached failure image and guest copy are
retained, with no repair/remount/retry and unchanged original test volume/base.
The remaining 27 cases are unexecuted. Main owns diagnosis of this unresolved
failure; do not rerun the failed batch. See `windows-ordinary-mutation-*` reports
under `artifacts/overwrite/`. New/free FILE and whole-INDX qualification, MFT
reservation pressure and general installed FSKit mutation remain open; they do
not inherit acceptance from the narrower checkpoint gate.
The separate four-case metadata diagnostic is complete and reviewed: both tested
FILE slots and both standard-information lengths mount healthy/pass native file
checks, but all fail read-only chkdsk on the same new-file/parent-index name linkage.
All exact detached images are retained. The next three-input filename packet now
passes native/chkdsk and main original-event/postimage review for unpaired POSIX,
Win32/DOS-pair and actual Windows creation. The control starts from a clean qualified
pre-create image; its enabled short-name policy yields the observed long/DOS pair.
The C create/rename representation is corrected to unpaired POSIX; the regression
first fails on the old code, then all 198 fatal-ASan/UBSan suites, style and six strict
changed-file compilations pass. The fresh current-C packet is separate from these
diagnostics. Its ten offline operations, seven create/fault profiles and all 28
input/container reviews pass. Windows again rejects the first complete-create
candidate before file/chkdsk checks; its corrected POSIX filename and new FILE
bytes remain unchanged. Main reviews the original NTFS error and full detached
postimage. The other 27 inputs are unexecuted; the original volume/base remain
unchanged, and the failed guest copy and immutable archive are retained.
See `windows-ordinary-posix-*` reports under `artifacts/overwrite/`.
The actual C journal gate remains open. Follow the main agent's VM handoff and
prepared commands; do not repair/remount an earlier failed or diagnostic candidate
or resume the remaining inputs without a reviewed diagnosis and new packet.
Passing filename diagnostics do not qualify the ordinary writer.
Unsupported rejection,
building or private serialization is not feature acceptance. Continue through the
user's broad write scope; do not mark the goal complete at this checkpoint.
