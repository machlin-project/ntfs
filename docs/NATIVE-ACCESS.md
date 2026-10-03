# Native extraction access

The implemented FSKit product mode is **read-only data extraction**. It reads
supported contents without applying Windows discretionary permissions. Original
security metadata stays unchanged; the descriptor parser and DACL evaluator keep
their separate contracts in SECURITY.md and ACCESS.md. This mode does not create
a Windows token, translate SIDs or qualify native multiuser isolation.

## Explicit selection and lifetime

Select the mode with the task option:

    -o ntfs-access=extract

It can share an option list with read-only and current-volume link bindings:

    -o ro,ntfs-access=extract,windows-root=C:

Either load or activation must explicitly select extraction. A selected load
policy survives the separate activation message; activation may then omit the
option. An ordinary load without selection remains usable for inspection and
maintenance, but activation returns EACCES without opening or publishing a root.
There is no implicit Windows-permission mode or generic permissive fallback.

The parser accepts at most 128 argument strings of at most PATH_MAX UTF-16 units
each. These are trusted configuration bounds, independent of disk geometry and
the core operation budgets. A missing value or repeated selection returns
EINVAL; an unknown access mode returns ENOTSUP; excessive argument count returns
EOVERFLOW. An invalid array/string returns EINVAL. Errors clear the parsed mode,
including an error following a valid selection. Other task options retain their
own handling. Configuration parsing uses bounded Foundation storage; it is not
part of accounted core live memory.

Load rejects invalid access configuration before creating the resource owner or
performing disk I/O. Activation preserves the existing lifecycle, maintenance,
revocation and budget admission precedence. Selecting extraction during an
activation that cannot construct its root does not select the owner's mode.
A successful activation retains the selection across unmount/remount; malformed
or unsupported later options fail without replacing it. Teardown/revocation
still close ordinary item admission, regardless of the retained selection.

The internal engine entry point is named activateExtraction:. Component tests
and workloads use that explicit entry point. Native protocol messages use task
options and have no implicit activation helper. A trusted constructor may carry
the already parsed load policy; this is configuration, not authentication.

## Native metadata presentation

Each ordinary owner snapshots the extension process's effective UID and GID
once, at construction. Every projected item uses those immutable presentation
IDs, including later lookups, directory attributes and remount. They do not
identify the mount initiator and do not represent any Windows identity. UID zero
has no special Windows grant; it is only a possible native process credential.

Ordinary files and projected links have owner-read-only mode 0400. Ordinary
directories have owner-read/search mode 0500. Group/other, write, regular-file
execute and set-ID bits are absent. Ownership and permission changes remain
unsupported, mutations return read-only errors, and the volume requests FSKit's
ReadOnly mount option. The SDK does not expose a NoExec mount request in this
option family; absence of file execute bits is not an installed noexec result.

Apple describes
[doesNotSupportSettingFilePermissions](https://developer.apple.com/documentation/fskit/fsvolume/supportedcapabilities/doesnotsupportsettingfilepermissions)
as a capability about setting permissions, not a documented native authorization
override. Its true value therefore does not establish the enforcement or
non-enforcement of these presented modes.
[FSContext](https://developer.apple.com/documentation/fskit/fscontext) carries
native caller UID/GID values in handlers that provide it; those values alone do
not supply Windows group membership, restricting SIDs or privilege state.
Neither protocol family currently enforces the Windows DACL evaluator.

## Qualification still required

Component tests cover guarded parser output and exact argument bounds; missing,
malformed, duplicate and unsupported selections; zero-I/O/load-owner refusal;
once-only legacy activation replies; root-allocation failure and fresh retry;
stable root/file presentation, remount, revocation and terminal cleanup. Modern
activation is compiled and remains an explicit runtime skip without macOS 27.
The full supported suite and universal app are tracked in ACCEPTANCE.md.

Installed acceptance must observe the actual extension credentials and native
caller path for both protocol families. Check mount-option propagation, mode
caching, distinct users/groups, root behavior, ownership-ignore options,
executable/mmap access, lookup/listing/readlink/xattrs and all read-only mutation
paths. Do not claim same-user isolation merely from matching component IDs.
The generic option parser and an uninstalled app cannot prove native enforcement.

An eventual Windows-permission mode requires authenticated identity mapping,
complete supported token/descriptor policy and authorization at the owning
native operation boundary. Requests for an unsupported mode must continue to
fail explicitly. Windows acquisition, installed isolation, distribution and
commercial acceptance remain open; extraction does not close those contracts.
