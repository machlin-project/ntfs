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
cluster owner. The separate indexed-store diagnostic below supplies complete
supported view traversal; physical ownership belongs to `ntfs_validate`.

| Bound | Contract |
| --- | --- |
| Index depth | At most 32 frames including the resident root; the configured directory-node cap additionally limits child blocks per seek |
| Index memory | One reused block buffer per seek, at most 64 KiB, plus a resident root and copied ancestor bounds/visited VCNs; parents do not accumulate |
| Indexed descriptor | Each complete SDS record fits its 256-KiB block; its 20-byte header leaves at most 262,124 descriptor bytes |
| Per-file descriptor | At most `NTFS_SECURITY_MAX_BYTES` (1 MiB); nonresident storage must be fully initialized and unencoded |
| Copy comparison | A 4-KiB temporary buffer checks the duplicate body, including trailing bytes not consumed by the DWORD checksum |
| Attribute work | Existing run/list/record budgets and extension instance, sequence, base-reference and contiguous-VCN validation still apply |

The block size comes from each index root and must be a supported power of two,
at least a sector. All owning security calls now share mounted operation credits
with their MFT/list work and the volume's aggregate live-storage ledger. The
limits and accounting units are defined in OPERATION-BUDGETS.md. No additional
security cache or performance gain is claimed.

## Complete indexed-store diagnostic

`ntfs_security_store_validate` opens fixed `$Secure` slot 9 on an existing
serialized immutable volume. It walks both supported view trees in order,
validating every frame and inherited key bound. One global visited-VCN set per
index rejects cycles and cross-branch aliases. The complete allocation bitmap
must identify exactly the visited slots; used orphan/out-of-range bits and
partial allocation records fail, while free block content stays unread. This
reuses the repository's ordinary-index inventory mechanisms without adding a
whole-bitmap scan to normal lookup or FSKit enumeration.

The complete SII inventory is unique and ordered by security ID. Every SDH
hash/ID entry must match its exact SII locator, with equal membership counts.
The private locator vector then sorts by logical SDS offset and rejects all
overlapping indexed intervals before reading descriptor bodies. Physical SDS
order need not follow ID order. Finally every indexed primary descriptor,
checksum and complete duplicate must agree, including bytes outside the DWORD
checksum's complete-word prefix. No surviving copy is selected for repair.

The descriptor cap defaults to 65,536 and can be selected up to 1,048,576; it
is a diagnostic policy. The vector grows geometrically within that cap. Each
cursor retains at most 32 heap-backed frames, each bounded by its root's block
size and the 64-KiB supported maximum. The SII cursor closes before SDH opens;
descriptor buffers are private and freed between entries. Mounted read,
allocation, work, directory-node and live-storage limits can refuse earlier.
Every copy, frame, transition, vector growth/sort, membership probe and bitmap
scan is charged before the associated work. Limits and report storage must not
overlap; invalid arguments do no callback work.

The report's stage and counts retain a partial observation on failure. Entry and
descriptor counts advance only after their corresponding step succeeds;
descriptor bytes exclude headers and padding. Block counts identify admitted
unique child VCNs, including one whose later read fails. Subject fields identify
the current/last examined locator rather than a unique root cause. `cluster`
can identify an in-span used orphan; it does not promise a physical address for
every malformed child or out-of-range bit. Successful reports clear locator/
cluster subjects and finish with `complete == true`.

`complete` applies to indexed supported storage. Unindexed SDS gaps/free content,
all FILE references, other metadata stores and authorization are outside this
standalone API. The general `ntfs_validate` diagnostic additionally checks every
allocated base FILE's nonzero security ID against the SII inventory, after its
namespace and physical-ownership passes. Missing indexed references/store are
CORRUPT. Zero-ID per-file payload semantics remain outside that general pass;
the independent resolver still validates those when requested. No descriptor
or diagnostic result maps an identity or grants native access.

The all-used-slots reachability, exact cross-index membership and nonoverlap
rules are repository consistency inferences from the published layout and
existing byte observations. Native Windows qualification remains required.
This diagnostic adds no writer, journal replay or automatic mount-time scan.

```sh
.build/ntfs-inspect IMAGE security-store
.build/ntfs-inspect IMAGE security-store 65536
```

The CLI emits a bounded JSON report with decimal-string 64-bit counters and
explicit `authorization: false`/opaque unused-SDS scope. Its optional descriptor
cap is positive decimal; a refusal returns status 1 and a partial report.

## Evidence and next contracts

Independent authored vectors cover both storage families, SID/ACL states, hash
collisions, maximum IDs/descriptor size, multiple SDS pairs, fragmented/listed
attributes, index ordering/bounds, allocation bitmap, MST/USA, depth/cycles,
capacity, lifetime, and required-allocation/read failure with retry and exact
release. The regular core suite and portable compilation remain separate from
adapter component tests and an unsigned app build.

The indexed-store suite adds 46 independent verdicts with exact bounded reports,
physical SDS order permutations, leaf/subcluster/large/deep trees, 129-entry
catalog growth, both used-block inventories, global aliases, off-path descriptor/
copy damage and unchanged inputs. Six retained-owner profiles pass all 496
required-allocation failure positions and both partial/full transfer modes at
730 read positions (1,460 injected read errors), with fresh retry and exact
release accounting. All five operation dimensions pass exact/one-below credits;
the maximum descriptor additionally passes exact/one-below aggregate storage.
Forbidden-read spans prove unused SDS gaps and free index blocks remain unread.
Seven complete-volume cases check valid storage, missing IDs/store and unrelated
descriptor damage. Its valid image additionally passes 149 allocation/111 read
failures and four exact/one-below diagnostic boundaries. Existing focused
inventories now explicitly use zero IDs because they omit `$Secure`; the separate
nonzero missing-store case rejects that invalid reference rather than bypassing
the new check. Zero-ID payload interpretation remains an explicit scope limit.

`tests/secure_oracle.py` compares original descriptor bytes and independently
reported security IDs against external NTFS-3G exports in existing regular
images. It applies output/deadline limits, refuses an existing output directory,
retains truthful failure reports and checks input hashes after each profile.
The observed root descriptor is a 4,140-byte nonresident per-file attribute;
ordinary files have 80-byte per-file descriptors, while indexed records 256/257
hold 104-byte descriptors. Four geometries provide 24 comparisons. The current
oracle also exports both complete leaf roots, independently checks locator
membership/checksums/duplicate bytes and compares the whole-store report's two
entries/descriptors, 208 payload bytes and zero visited allocation blocks.
The actual product performs its bitmap inventory; these external leaf exports
do not independently observe an external view-tree allocation traversal.
Evidence is under `artifacts/interoperability-secure-store-reviewed/`; the
whole-volume oracle is `artifacts/interoperability-secure-store-validation-reviewed/`.
These are NTFS-3G-authored images, not Windows qualification.

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
