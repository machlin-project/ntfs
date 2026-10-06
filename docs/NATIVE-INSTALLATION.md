# Native development installation

The disposable macOS 27 test clone has the personally development-signed universal
app installed and enabled. It embeds the exact signed extension that passes
initialized ordinary-file writing. Strict signatures, exact installed files,
matching executable/dSYM identities and actual enabled FSClient path pass
independent review. The preserved macOS 26.5 reading baseline and unrelated ext4
installation are unchanged. This is not distribution signing or notarization.

The installed owner performs `pwrite`/`fsync` and shared-mapping mutation after
closing the writer descriptor. Another descriptor and a prefaulted read mapping
observe exact final data; modified/changed times advance, while identity, size,
native ownership and mode stay unchanged. Authenticated root and nobody opens
are denied in all three tested modes. Ordinary unmount releases the backing
image. Two fresh CLI mounts of one saved image URL preserve the same full
postimage and exact data/metadata, and normally unmount with no backing descriptor.
The exact postimage then passes independent native Windows data/ADS/time/File ID/
ACL, clean-state, read-only chkdsk and healthy-event checks. See ACCEPTANCE.md for
reports and remaining unsupported mutations.

The app uses the original authorized URL as a writable `FSPathURLResource` and
[FSClient.mountSingleVolume](https://developer.apple.com/documentation/fskit/fsclient/mountsinglevolume(resource:bundleid:options:completionhandler:))
with explicit image-editing policy. The host needs FSKit Mounter and user-selected
read/write entitlements. Ordinary vnode attributes remain available for kernel
mount construction without granting namespace or data authority; metadata
confidentiality across native attribute caches is not claimed.

Use the installed app's `--image-command status`, `import`, `mount`, `unmount` and
`unmount-path` through `scripts/fskit_image.py`. Picker-selected external images
are saved as app-scope bookmarks. Automation imports only a file name from the
app's private Inbox, creates a real bookmark and requires positive scope restore.
This passes in the signed sandbox even with the console locked. Saved identifiers
survive process exit; bookmark bytes are never printed. Mount revalidates identity
and ownership. Ordinary unmount uses backing-owner authority; the kernel's
mount-owner ID does not identify who may read or write the image.

The actual written image moved into the app's Inbox after the preceding mount
released its owner. Device, inode, bytes, native UID/GID, mode and single-link
identity remained exact. Both new cycles use that same new saved URL. The earlier
source URL is not represented as still valid. Generated reports retain exact
paths, IDs, artifact hashes, loaded identities and command results.

Initial OS extension enablement remains an ordinary Settings action. During app
installation, launching staged command binaries also registered their nested
extensions. Removing only those task staging registrations and registering the
installed host/module recovered the installed path but left it disabled. A
PlugInKit election marker did not prove FSClient enablement. After the user
unlocked the VM, one ordinary Machlin NTFS Settings toggle restored the exact
enabled installed path. Subsequent mount/check/unmount cycles use no UI input.
Always run commands from the installed bundle; do not launch a staging copy.

The system `mount` command prefers block resources when a module advertises block
and path support; its image attempts failed before extension launch. Changing a
path to a file URL did not select the path operation. Use the app's public FSClient
route. The direct-build fallback must use the actual `_NSExtensionMain` entry point
and SDK 27 metadata, as the normal Xcode build does. Preceding startup and
root-attribute authorization failures and their exact diagnostics remain retained.

Installed acceptance belongs to a dedicated stock macOS VM. Never install this
preview on the development host. Source builds, development signing, native
discovery/enablement, mounted behavior and distribution are separate stages.

## Public module query

`tools/fskit_modules.swift` uses only
[FSClient.fetchInstalledExtensions](https://developer.apple.com/documentation/fskit/fsclient/fetchinstalledextensions(completionhandler:))
and reports NTFS bundle identity, enabled state and path as JSON. It filters
`org.machlin.ntfs.filesystem`, keeps the main run loop available for completion and
fails after a bounded deadline if no callback arrives. Invalid arguments fail before
contacting FSKit. Successful empty output means no matching module was returned;
it does not mean the module is enabled. This tool cannot register or enable anything.

The prepared arm64 helper targets macOS 26.5 and is personally development-signed.
Its exact guest copy and strict signature were verified before the actual guest query.
A PlugInKit election marker or an ext4-only inventory cannot replace this result.

For a new installation, enable only Machlin NTFS in System Settings → General → Login
Items & Extensions → By Category → File System Extensions. Query FSClient again
and require the reviewed installed path with `enabled: true`. Preserve ext4 and
unrelated guests. Unknown authentication prompts require manual credential entry.

## Installed mounted reading checks

`tests/mounted_read.c` is a standalone POSIX checker for the complete-filename
standard and NTFS 3.0 fixture images. It first requires `machlinntfs` from `statfs`
and the native read-only mount flag. A built-in Apple NTFS mount fails that gate
before any mutation probe. The expected directory holds the nine independent
content oracles authored by `tests/fixtures.py`.

The checker verifies two interleaved directory streams, exact names without
duplicates, native metadata, guarded irregular reads, unchanged EOF, read-only mmap,
case-insensitive inode reuse and refusal of writable opens/shared mappings and file
creation. Contents include resident data, fragmented/listed extents, sparse holes,
LZNT1 and an uninitialized tail. Actual refusal errno values are reported; EACCES
can precede the volume's read-only error through native permission checks. A read-only
mount refusal does not prove that a mutation reached the adapter handler.

The prepared images and all nine expected files match their independent manifests.
The checker compiles with selected Xcode clang, strict warnings and minimum macOS
26.5, is personally development-signed and passes strict signature verification.
Its usage check and host non-NTFS identity rejection pass. Sol stages the exact
thirteen reviewed files; main independently compares share bytes and the guest manifest.
Both standard and NTFS 3.0 images then pass the complete checker in separate guest
runs through the public client. Every returned task device detaches without force,
each image hash is unchanged and the final task mount is absent. FSClient remains
enabled. Raw commands, checker rows and main reviews are in native-read/attempt-1/
and native-read/attempt-2-ntfs30/.

The separate native access-admission matrix refuses missing extraction mode with
EACCES, an unknown mode with ENOTSUP and duplicate selection with EINVAL. No mount
is published after each refusal. A single valid request on the same attachment then
mounts and passes the whole checker; cleanup leaves unchanged image bytes and no
mount. All twenty command records and main review are in
native-read/attempt-4-access-admission/. This qualifies configuration refusal/retry
on the legacy runtime, not Windows authorization or native ownership enforcement.

Use only fresh task-owned image copies and mount points. Attach each image read-only
without mounting, obtain its device from the actual hdiutil plist, and select the
public `/sbin/mount -F -t machlinntfs` client with explicit
`-o rdonly,owners,ntfs-access=extract`. Actual mount admission and extraction-option
propagation pass for these two fixtures. There is no assumed
`/sbin/mount_fskit` path. Never accept a successful default NTFS automount as this
driver's result. Detach only the device returned for that task-owned attachment and
verify unchanged image bytes afterwards. Formatting, repair and device writes are
outside these reading checks.

## Ownership route still unresolved

Both successful direct mounts report `noowners` even with `owners` requested;
diskutil reports global permissions disabled. Matching returned IDs therefore cannot
establish preserved extension credentials or same-user isolation. Do not call these
reading runs ownership acceptance or broader native authorization qualification.

The documented diskutil route accepts readOnly, mountOptions and mountPoint, passing
options through Disk Arbitration. It lacks an explicit filesystem selector, so the
actual attached entity must already identify machlinntfs. A single diagnostic attaches
the standard image with read-only/nomount/owners-on flags and requests an explicit
read-only extraction mount. Probe and module staging succeed, but mount approval
returns `kDAReturnNotReady`; diskutil exits without mounting. No reading checker or
fallback runs. The exact task attachment is detached, its hash is unchanged and no
mount remains. The cause is still undiagnosed. Evidence is in native-read/client-options/
and native-read/attempt-3-diskarbitration/.

These are per-attachment requests. No persistent `enableOwnership` database setting,
root impersonation or permission-capability change was used. The ext4 history also
records separate nomount/diskutil and direct-owner limitations, with a successful
owners-on automount path; that result does not qualify NTFS's explicit extraction
configuration or admission. Modern runtime, multiuser/root behavior, broader lifecycle,
namespace/xattr/link contracts, native throughput and commercial qualification remain open.
