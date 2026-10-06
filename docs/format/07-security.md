# 07 · Security

[Reference index](README.md) · [Previous](06-directories.md) · [Next](08-system-files.md)

NTFS security metadata is a Windows security descriptor. Its owner and group are
SIDs; its access and audit lists are ACE sequences. Parsing those bytes, resolving
their storage and enforcing native permissions are three different operations.

## Where a file's descriptor lives

The modern SI extension has a security ID. A nonzero ID selects the shared store
in fixed MFT record 9, `$Secure`. In our qualified zero-ID profile, the file's
unnamed `$SECURITY_DESCRIPTOR` attribute supplies the descriptor instead. Specific
metadata exceptions require positively proved system-file ownership.

![Two descriptor storage paths, shared indexes and duplicate SDS storage](diagrams/security.svg)

[Diagram source](diagrams/security.mmd)

The shared-store arrangement follows
[original `$Secure` research](https://flatcap.github.io/linux-ntfs/ntfs/files/secure.html).
Selection and exceptions are implemented in [SECURITY.md](../SECURITY.md); a
filename that resembles a system file does not grant an exception.

## Self-relative descriptor

The stored descriptor uses offsets from its own beginning. It does not contain
usable host pointers. Microsoft specifies this distinction in
[MS-DTYP SECURITY_DESCRIPTOR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d).
The common 20-byte prefix is represented by `ntfs_disk_security_descriptor`.

| Offset | Width | Field |
| --- | --- | --- |
| `0x00` | 1 | Revision |
| `0x01` | 1 | Resource-manager/control-associated byte |
| `0x02` | 2 | Control flags, including self-relative `0x8000` |
| `0x04` | 4 | Owner SID offset |
| `0x08` | 4 | Group SID offset |
| `0x0C` | 4 | SACL offset |
| `0x10` | 4 | DACL offset |

Offsets determine component locations; their order is not fixed. Complete
component ranges need validation before publication. A SID has an eight-byte
prefix: revision (1), subauthority count (1), and a six-byte **big-endian**
identifier authority. The following subauthorities are little-endian 32-bit
integers. This mixed endian layout is deliberate.

An ACL begins with an eight-byte header containing revision, total byte size and
ACE count. Each ACE begins with type (1), flags (1), and byte size (2), followed
by its type-specific body. Recognizing an ACE boundary does not imply support
for evaluating its conditional, object, callback or claim semantics.

## Absent, NULL and empty DACLs

These are different states:

| State | Stored relationship | Consequence in Windows DACL evaluation |
| --- | --- | --- |
| No DACL | DACL-present flag clear | No DACL restriction supplied |
| NULL DACL | DACL-present flag set, offset zero | No DACL restriction supplied |
| Empty DACL | Valid ACL with zero ACEs | No allow ACE grants access through that DACL |

Other token/privilege rules can still matter. Treating an empty ACL as NULL
changes access materially. Microsoft explains the distinction in
[NULL DACLs and empty DACLs](https://learn.microsoft.com/en-us/windows/win32/secauthz/null-dacls-and-empty-dacls).

Owner SID, SI's owner/quota ID and a macOS UID are different identifiers.
Displaying a native owner or mode cannot substitute for a Windows access check.
Our evaluator and platform boundary are described in [ACCESS.md](../ACCESS.md)
and [NATIVE-ACCESS.md](../NATIVE-ACCESS.md).

## Shared security store

`$Secure` uses a named DATA stream `$SDS` plus `$SII` and `$SDH` indexes.
An SDS entry has a 20-byte locator prefix:

| Offset | Width | Field |
| --- | --- | --- |
| `0x00` | 4 | Descriptor hash |
| `0x04` | 4 | Security ID |
| `0x08` | 8 | Canonical entry offset in `$SDS` |
| `0x10` | 4 | Complete entry byte length, including locator |
| `0x14` | Variable | Self-relative descriptor |

The original `$Secure` page has an inconsistent descriptor offset in its SDS
table. The four locator fields occupy 20 bytes, so the descriptor starts at
`0x14`; our named layout and independent store fixtures check that boundary.

Entries are aligned to 16 bytes. Our qualified store profile uses pairs of
256-KiB blocks: canonical storage in the first block and duplicate bytes at the
same within-block offset in the second. An entry cannot cross its block boundary.
Both locators and complete descriptor bytes are compared before adoption.

`$SII` is keyed by security ID. `$SDH` is keyed by descriptor hash and security ID.
Their view-index entries carry locator data rather than directory FILE_NAME keys.
Validation checks the complete correspondence, duplicate storage and overlap
bounds; a successful single ID lookup is not proof that the whole store is valid.
The descriptor hash rotates a 32-bit accumulator left by three and adds each
complete little-endian DWORD, under the exact framing in our store validator.

## Creation and inheritance

Inheritable ACE flags distinguish propagation to files and directories,
inherit-only entries and no-propagate behavior. Generic rights and creator-owner
substitution require type-specific decisions; copying the parent's descriptor
verbatim is not an inheritance algorithm.

The current ordinary planner deliberately selects owner/group from the parent
and handles its admitted plain inheritance forms. This is an explicit test
profile, not complete Windows caller-token creation semantics. Unknown inheritable
forms must refuse. Native ACL mutation, `$Secure` insertion/deduplication and
broader token semantics remain open. Microsoft's
[ACE inheritance rules](https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-inheritance-rules)
provide the semantic baseline.

## Implementation and evidence

- Descriptor/SID/ACL framing: [security.c](../../core/security.c),
  [security.h](../../include/ntfs/security.h).
- Shared storage: [secure.c](../../core/secure.c).
- DACL evaluator: [access.c](../../core/access.c).
- Independent descriptor bytes: [secure_fixtures.py](../../tests/secure_fixtures.py).
- Store relationships: [secure_store_fixtures.py](../../tests/secure_store_fixtures.py).
- Native comparison pipeline: [ACCESS-ORACLE.md](../ACCESS-ORACLE.md).

Existing bounded overwrites preserve security bytes and identity in native
acceptance. That evidence does not qualify general security rewriting or the
new creation inheritance profile.
