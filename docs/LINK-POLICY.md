# Native link projection

The FSKit adapter presents supported NTFS symlink and junction metadata as native
symlinks. The portable core preserves the original reparse packet and never follows
its target. This policy belongs to the adapter; it does not implement a complete
Windows reparse resolver or qualify installed macOS path walking.

## Ownership and configuration

Relative targets start at the link's checked containing directory. A single
leading Windows separator starts at the mounted NTFS root. Explicit absolute
targets require trusted configuration binding their Windows root to this owner:
`windows-root=C:` or `windows-root=Volume{12345678-1234-5678-9abc-123456789abc}`.
Bindings are accepted in task-option tokens and comma-separated `-o` lists at
resource loading or first activation. Drive letters and canonical GUID aliases
are compared without case sensitivity. Duplicate or malformed bindings fail.
No drive letter or Windows volume GUID is inferred from the NTFS serial.

The policy records this core's serial, and checked ancestry also records the core
owner pointer and full sequence-bearing directory references. Bindings cannot
change after activation, or replace a different binding supplied while loading.
Empty later options preserve the existing configuration. Recreate the owner to
change its aliases. The trusted caller is responsible for identifying the correct
Windows roots; this code does not discover Windows Mount Manager state.

Absolute targets can use ordinary drive roots, the NT `\??\` prefix or the Win32
`\\?\` prefix. Their native output is relative: it climbs the checked containing
directory's ancestry to this volume's root, then emits the translated suffix.
This avoids depending on the host mount path. UNC, device realms, unbound/foreign
roots, drive-relative paths, colon/ADS components and paths escaping this root
return UNSUPPORTED. Cross-volume mappings are not implemented.

## Names, targets and identity

Translation uses the substitute name, not the display name. Both slash forms
separate components; repeated separators collapse, explicit dot components remain
and a trailing separator retains its native directory requirement. Each existing
ordinary component uses checked NTFS lookup and its containing directory's own
exact/folded policy. Returned spelling is the stored spelling. Reserved,
oversized and unpaired names use the same filename aliases as enumeration and
lookup; independent cursors recover their visible ordinals. A stored DOS name
selects a visible link to the same full file reference in that directory.

Dangling targets retain plain representable components. A missing target cannot
invent a sequence/ordinal alias for a reserved or unrepresentable name. Existing
nonterminal components must be ordinary directories; intermediate reparse
resolution remains UNSUPPORTED. Ordinary-directory cycles are corrupt. Native
loop handling, multi-hop reparse chains, junction ownership across volumes and
Windows-authored semantics remain separate work.

Native readlink bytes are inode-scoped. This implementation requires exactly one
stored hard-link edge for a projected reparse object. Multiply linked reparse
objects are explicitly UNSUPPORTED, because alias/case/root-relative translation
may depend on the containing edge. Ordinary hard-link identity and per-link name
projection are unchanged. Supporting context-dependent reparse hard links requires
an explicit native identity contract rather than caching whichever edge opened
first.

## Attributes and raw metadata

Supported items report FSItemTypeSymlink in lookup and attribute-requested pages.
Their size is the emitted native target's UTF-8 byte count; allocSize is the
physical allocation of the checked reparse attribute, excluding resident MFT
storage. Junctions use native symlink behavior, not traversal of a plausible local
NTFS index. Ordinary data reads on projected links return ENOTSUP with zero bytes.

Names-only enumeration classifies checked base/reparse metadata without resolving
the target. Known links remain symlinks even when their path policy prevents
adoption; opaque providers remain Unknown. Malformed metadata, resource failures
and native scan exhaustion remain explicit errors. Requested attributes require
successful translation; an unsupported entry stays pending for retry and cannot
be replaced with nil attributes or fabricated sizes.

The read-only xattr `org.machlin.ntfs.reparse` returns the complete original wire
packet, including tag, flags, reserved bytes and both UTF-16 names. Projected links
do not expose ordinary stream xattrs. `ntfs_reparse_bytes` is a bounded immutable
snapshot copy API: a size query reports RANGE and required bytes, short buffers
remain unchanged, and copying does not require the source node or device I/O.
Snapshots retain counted core lifetime and report their checked physical size.

## Bounds and lifetime

Output is limited to PATH_MAX minus its terminator (currently 1,023 bytes).
Component count and ancestry depth are capped at PATH_MAX/2 (currently 512).
Configuration permits at most 64 root bindings and 128 option tokens, each at
most PATH_MAX units. Required alias scans share one raw-entry budget across all
components, including hidden metadata and DOS entries; equality succeeds and
exhaustion returns RANGE. Indexed lookup and structural parsing retain the core's
own bounds. These are distinct from an aggregate native deadline/I/O budget.

Ancestry tokens retain numeric parent provenance, not parent FSItems or core nodes.
The volume weakly indexes them under the existing bounded ownership model. Cached
native targets remain immutable across unmount/remount, while unmount closes
counted reparse snapshots. Raw-metadata access reopens them after admission.
Permanent revocation precedes cached target/attribute/xattr access; cleanup closes
all children without further resource reads. Both FSKit protocol families reply
once. Modern result construction remains compiled but requires macOS 27 runtime
and installed acceptance.

## Local evidence and remaining qualification

Independent fixtures author original packets, directory keys and expected native
bytes. They exercise relative/rooted/drive/GUID targets, canonical and sensitive
names, aliases/DOS names, nested paths, dangling targets, dot/trailing components,
path/component/shared-scan bounds, junctions, fragmented and attribute-list
storage, root escapes, foreign/UNC/device paths, intermediate reparse objects,
cycles, hard-link limits and malformed/opaque packets.

The component checks real legacy callbacks, requested-size and names-only pages,
wire-byte equality, cached reads, raw-data rejection, remount/revocation, failure
retry and exact core-allocation cleanup. Core tests additionally exercise copy
misuse, short-buffer guards, physical sizes and source-node-independent snapshots;
image fuzzing checks bounded copies. ACCEPTANCE.md records completed run counts.
Synthetic component passes do not establish Windows compatibility, installed
path walking, native loop limits, normalization/cache behavior or authorization.

Primary format/policy references are Microsoft's [reparse buffer fields](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_reparse_data_buffer),
[symbolic-link paths](https://learn.microsoft.com/en-us/windows/win32/fileio/creating-symbolic-links),
[path namespaces](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file)
and [volume naming](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-volume).
The relative native projection and explicit binding policy are this repository's
design. ext4 was consulted for FSKit type/callback conventions; no third-party
NTFS implementation was imported.
