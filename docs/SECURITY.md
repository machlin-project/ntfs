# Read-only security metadata

The core returns original self-relative security descriptors through
`ntfs/security.h`. Those APIs validate storage and byte framing; they do not map
identities or grant access. The separate `ntfs/access.h` discretionary evaluator
is defined in [ACCESS.md](ACCESS.md); it is not complete native authorization.
FSKit still uses its documented single-user read-only development presentation.
Do not expose that presentation as Windows ACL enforcement.

## Source selection and ownership

`ntfs_security_open` reads standard information without opening default file data.
A nonzero security ID selects `$Secure`. ID zero selects the file's unnamed
`$SECURITY_DESCRIPTOR` attribute, including resident, nonresident and listed
storage. A referenced missing ID or missing per-file descriptor is CORRUPT.
There is no fallback from a failed nonzero ID to per-file metadata. This also
allows metadata inspection of an encrypted or reparse-owned file without
claiming its content or target is supported.

`ntfs_security_resolve` directly looks up a nonzero ID. An absent indexed ID is
NOT_FOUND; requesting zero is INVALID. Both opening functions publish NULL on
failure. A successful snapshot owns its bytes independently of the source node,
counts as a live volume child and prevents unmount until closed. Original bytes
exclude the SDS entry header and padding. Size, ID, decoded-info and whole-byte
copy accessors perform no allocation or I/O. A short copy returns RANGE with the
required size and leaves the destination unchanged. Snapshot ID zero identifies
per-file storage; it is not an access identity.

The volume, nodes and snapshots retain the existing immutable-media and external
serialization contract. No native object, identity or callback is embedded in
the freestanding core.

## Storage validation and budgets

Indexed resolution checks `$SII` and `$SDH` locators against each other, then the
stored primary header, descriptor checksum and duplicate header/body. A damaged
copy or failed read returns an error; this read-only resolver performs no repair
and does not choose a surviving copy. The checksum detects format inconsistencies
and is not authentication.

Each searched view-index frame is checked completely before a result is used:
header/entry/key/data/trailer spans, terminal framing, child flags, strict local
ordering and inherited ancestor bounds. Descent additionally checks initialized
unencoded allocation/bitmap streams, bitmap membership, arithmetic, VCN, MST and
update-sequence-array placement. Cycles and budget exhaustion are explicit errors.
This checks the searched paths, not every unvisited branch, stored descriptor or
cluster owner. Whole-volume consistency validation remains separate work.

| Bound | Contract |
| --- | --- |
| Index depth | At most 32 frames including the resident root; the configured directory-node cap additionally limits child blocks per seek |
| Index memory | One reused block buffer per seek, at most 64 KiB, plus a resident root and copied ancestor bounds/visited VCNs; parents do not accumulate |
| Indexed descriptor | Each complete SDS record fits its 256-KiB block; its 20-byte header leaves at most 262,124 descriptor bytes |
| Per-file descriptor | At most `NTFS_SECURITY_MAX_BYTES` (1 MiB); nonresident storage must be fully initialized and unencoded |
| Copy comparison | A 4-KiB temporary buffer checks the duplicate body, including trailing bytes not consumed by the DWORD checksum |
| Attribute work | Existing run/list/record budgets and extension instance, sequence, base-reference and contiguous-VCN validation still apply |

The block size comes from each index root and must be a supported power of two,
at least a sector. Index descent bounds do not constitute a bound on all MFT or
attribute-list I/O: those operations retain their own configured limits. A future
aggregate operation budget and whole-volume validator must account for that work.
No additional security cache or performance gain is claimed at this checkpoint.

## Evidence and next contracts

Independent authored vectors cover both storage families, SID/ACL states, hash
collisions, maximum IDs/descriptor size, multiple SDS pairs, fragmented/listed
attributes, index ordering/bounds, allocation bitmap, MST/USA, depth/cycles,
capacity, lifetime, and required-allocation/read failure with retry and exact
release. The regular core suite and portable compilation remain separate from
adapter component tests and an unsigned app build.

`tests/secure_oracle.py` compares original descriptor bytes and independently
reported security IDs against external NTFS-3G exports in existing regular
images. It applies output/deadline limits, refuses an existing output directory,
retains truthful failure reports and checks input hashes after each profile.
The observed root descriptor is a 4,140-byte nonresident per-file attribute;
ordinary files have 80-byte per-file descriptors, while indexed records 256/257
hold 104-byte descriptors. Four geometries provide 24 comparisons. These are
NTFS-3G-authored images, not Windows qualification.

Native Windows acquisition is still required. The collector requests owner,
group and DACL information; a Win32-returned descriptor can omit components or
have a different self-relative placement from the stored original. Compare the
requested semantic fields rather than treating that API response as an exact
on-disk-byte oracle. The separate discretionary evaluator preserves ACE order and
ACL states, handles enabled/disabled/deny-only identities and ordinary restricted
checks, maps exact generic file rights and rejects unsupported applicable ACEs
explicitly. Restricted ownership, maximum access, conditional/object policies,
SACL/privilege evaluation, identity mapping, native owning authorization and
installed FSKit tests remain incomplete. Decoder or resolver success grants no
access; a DACL result is only one input to a future complete authorization decision.
