# Native development installation

Installed acceptance belongs to a dedicated stock macOS VM. Do not install this
preview on the development host. Source builds, development signing, native
discovery, enabled admission, mounted behavior and distribution are separate stages.

The current isolated `machlin-ntfs-fskit-26.5.2` guest reports macOS 26.5.2/arm64
and its actual stock kernel after manual login. Its retained ext4 installation
remains enabled and idle. The fresh NTFS development build is installed in
`/Applications/Machlin NTFS.app`; all eight regular bundle files match the reviewed
signed source. Both installed signatures pass strict verification. App and extension
report build 3 and minimum macOS 26.5. The embedded development profile includes
this guest and the FSKit entitlement. This is not distribution signing or notarization.

Normal app launch and LaunchServices/PlugInKit registration discover the installed
extension. The public FSClient query currently reports its exact installed path and
`enabled: false`. The console has subsequently locked, so the ordinary File System
Extensions switch awaits manual unlock. No disk image is attached or mounted, and
the Windows VM stays at its account-password screen at the user's request.

Evidence is under `artifacts/fskit-guest-26.5.2/`: `signed/review/`, `installation/`,
`modules-helper/` and `read-preparation/`. Reports retain source/artifact identities,
commands, exits and actual guest observations; source history remains in Git.

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

After manual unlock, enable only Machlin NTFS in System Settings → General → Login
Items & Extensions → By Category → File System Extensions. Query FSClient again
and require the reviewed installed path with `enabled: true`. Preserve ext4 and
unrelated guests. Unknown authentication prompts require manual credential entry.

## Prepared mounted reading checks

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
Its usage check and host non-NTFS identity rejection pass. Actual guest reading,
permission presentation, mapping and refusal checks remain pending.

Use only fresh task-owned image copies and mount points. Attach each image read-only
without mounting, obtain its device from the actual hdiutil plist, and select the
public `/sbin/mount -F -t machlinntfs` client with explicit
`-o rdonly,ntfs-access=extract`. The guest's actual mount usage supports `-F`; mount
admission and option propagation have not yet been qualified. There is no assumed
`/sbin/mount_fskit` path. Never accept a successful default NTFS automount as this
driver's result. Detach only the device returned for that task-owned attachment and
verify unchanged image bytes afterwards. Formatting, repair and device writes are
outside these reading checks.
