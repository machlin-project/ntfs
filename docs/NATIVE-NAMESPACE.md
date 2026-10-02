# Native stream and name presentation

The core preserves original UTF-16 code units and distinguishes names of directory
links from the referenced inode. Native projection belongs to the adapter.
Ordinary filenames retain their original UTF-8 bytes without normalization. The
adapter supplies bounded reversible aliases for names that cannot be passed
through. Stored per-directory policy now selects exact UTF-16 or $UpCase-folded
lookup; ambiguous collisions in an insensitive directory remain rejected. See
CASE-POLICY.md for format evidence and required Windows/native qualification.

Supported single-edge symlink and junction targets now use this same stored-name
and alias policy. Explicit Windows roots bind only to the current mounted owner;
unbound/cross-volume paths and intermediate reparse resolution remain rejected.
LINK-POLICY.md defines native size/type, inode-context limits, bounded target
translation and the original-wire `org.machlin.ntfs.reparse` xattr. Ordinary inode
hard links and reparse hard-link qualification are separate contracts.

## Filename projection

A component that converts to valid UTF-8 within the native 255-byte NAME_MAX cap
passes through, except leading-tilde names and native dot components. Oversized,
unpaired and reserved names use `~ntfs-<16 reference hex>-<8 ordinal hex>`.
The reference includes its MFT sequence; the ordinal counts visible directory
links, excluding DOS aliases and hidden system records. The owning directory
provides the remaining identity. Every leading-tilde literal is projected too,
so a stored filename resembling an alias cannot shadow another projected link.
Alias syntax parsing accepts ASCII case variants. The owning volume requires
canonical lowercase spelling in sensitive directories and returns canonical
spelling in insensitive directories. Malformed aliases never fall back to a
stored literal name.

Resolution opens an independent bounded directory cursor, selects that link,
checks the full reference and confirms that its name requires projection before
opening the sequence-checked node. Ordinary indexed lookup retains the stored
name; an alias cannot be forged for a link that passes through. Lookup and
enumeration return the same spelling. Hard links reuse one FSItem identity while
retaining each link's own projected name. Aliases are deterministic for immutable
media, not persistent paths across namespace changes or future writes.

The directory xattr `org.machlin.ntfs.names` returns the original visible link
inventory. Its binary little-endian format is independent of NSString:

| Record | Fields in wire order |
| --- | --- |
| Header | Eight bytes `NTFSNAM` including NUL; uint32 version (1); uint32 entry count; uint64 sequence-bearing parent reference |
| Each link | uint32 visible ordinal; uint64 sequence-bearing target reference; uint16 UTF-16 unit count; uint8 original namespace; uint8 zero reserved; exactly that many uint16 original units |

There is no implicit padding or name terminator. This is checked directory
metadata, not full namespace consistency acceptance: a later lookup also checks
the referenced FILE record's sequence. The complete manifest is bounded by the
native xattr response cap and fails with E2BIG rather than returning a successful
partial inventory. The addressable directory xattr
`org.machlin.ntfs.name.XXXXXXXX` returns the same format for one visible ordinal,
with entry count one. Those per-link keys are omitted from listxattr so listing
itself remains bounded. A client can recover an aliased link's original units
even when the complete manifest exceeds the response budget.

The default scan budget is 1,048,576 stored entries, including hidden/DOS entries;
the native owner can select a smaller positive cap. A boundary entry can detect
that the cap has been crossed. Enumeration reports EOVERFLOW and latches the
failed continuation. While that state remains retained, retrying its cookie
performs no further I/O; reconstruction still observes the same scan cap and
cannot turn exhaustion into a successful truncated listing. Initial-cookie rewind starts
a new bounded cursor. Each retained continuation has its own cumulative credit;
reuse does not reset it. The adapter retains at most two actual cursors and may
reconstruct evicted positions, under the resource pool and LIFECYCLE.md's native
call bounds. Reverse-manifest exhaustion reports E2BIG. Independent reversal
does not move a pending native enumeration entry. Resource admission and post-I/O checks
apply to all these operations, and cleanup remains valid after revocation.

Alias resolution currently scans from the directory root; index/checkpoint reuse
is a separate measured optimization. NUL/slash wire names are rejected rather
than projected. Reparse/provider projection, unknown/malformed metadata, native
case/normalization behavior and Windows ACL authorization remain separate
required contracts.

## Read-only alternate streams

The core stream catalog snapshots stored `$DATA` names, including the unnamed
stream. It sorts exact UTF-16 units, without case folding or normalization, checks
first-extent MFT sequences and base references, rejects duplicate primary names
and detects primary base attributes missing from the list. Complete mappings and
data support are checked when opening the selected stream. Provider-owned and
encrypted names can be inventoried without reading their content.

Caller-selected catalog caps range from one to 4,096 entries; the adapter permits
1,024 per held item and uses the existing aggregate core-allocation budget. Sorting
uses bounded in-place heapsort. A catalog holds the volume, survives source-node
close and releases its counted lifetime explicitly. Adapter reclaim and teardown
close catalogs before releasing the resource. Cached operations still require
admission on an available owner.

Both FSKit protocol paths expose named streams as
`org.machlin.ntfs.stream.XXXXXXXX`, where the eight lowercase hex digits select
the exact catalog ordinal. The unnamed stream keeps its ordinary file read path
and is not exposed under a stream xattr. Sorting is deterministic for the same
immutable medium. The ordinal is not an identity guaranteed across media changes;
there is no write capability or live namespace mutation in this contract.

These short names fit the native xattr name cap even when the original name has
255 UTF-16 units or unpaired surrogates. A separate read-only xattr,
`org.machlin.ntfs.streams`, supplies the reverse mapping. No stream implicitly
becomes `com.apple.ResourceFork`, FinderInfo or another Apple semantic attribute.

The manifest is a bounded binary value with little-endian integer fields:

| Record | Fields in wire order |
| --- | --- |
| Header | Eight bytes `NTFSADS` including its NUL; uint32 version (1); uint32 named-entry count; uint64 sequence-bearing file reference |
| Each named entry | uint32 catalog ordinal; uint16 UTF-16 unit count; uint16 zero reserved; exactly that many uint16 original units, without a terminator |

The manifest contains only named entries, while ordinals include the default
stream if one exists. There is no implicit padding between records. Matching
an alias resolves the catalog entry directly; it does not parse the manifest or
convert the original name through NSString. The inspector's `streams-ref` command
returns the same inventory as JSON code-unit arrays for offline comparisons.

Known WOF file-provider items retain that complete manifest, including the
`WofCompressedData` entry and its stable catalog ordinal. The backing encoding is
omitted from listxattr aliases and explicit gets of its alias return ENOATTR.
Independent named ADS keep their original ordinals and read contracts. WOF items
also expose original bytes through `org.machlin.ntfs.reparse`. Twenty-three legacy
provider cases compare complete byte/manifest oracles and remount/revocation
behavior; installed projection and provider hard-link qualification remain open.

An xattr response is capped at 1,048,575 bytes. Larger streams remain visible but
get returns E2BIG; unknown, malformed and default-stream aliases return ENOATTR.
The adapter opens and validates the selected stream before reading exact bytes,
checks revocation again before returning data, and does not cache file content.
Setting or deleting any xattr returns EROFS. This projection does not provide
Windows ACL authorization or EFS decryption. Default WOF XPRESS/LZX content has
the separate owning stream contract in WOF.md. Ordinary
EFS-flagged and unsupported-compression files now have complete checked size
metadata independent of decoding; they can be adopted by FSKit and expose a
separate readable ADS. Default reads remain ENOTSUP. Reparse items and
unknown/malformed metadata remain explicitly rejected at native adoption.

## Local evidence

Five independently authored namespace images qualify twelve hard links with
ordinary and boundary-size UTF-8, oversized BMP/surrogate-pair names, unpaired
surrogates, composed/decomposed Unicode and reserved literals; hidden/DOS entries
preserve visible ordinals. A 2,000-link B-tree exceeds the full-manifest budget
while a single last-link response and lookup remain available. Corrupt NUL names
and stale references fail their native operation. Smaller scan budgets verify
sticky exhaustion and restart rather than successful truncation.

Required-allocation sweeps disable the optional record cache: name manifests
passed 13 allocation and five I/O failure positions; alias lookup passed 17
allocation and six I/O positions. Every failure replies once, retries successfully
and releases all tracked core allocations. Ordinary namespace/ADS cases retain
the default cache. An initial fault-test expectation incorrectly required ENOMEM
for best-effort cache insertion; diagnosis and the failed run remain under
`artifacts/plan-names-diagnosis.log`, `artifacts/plan-names-cache-diagnosis.log`
and `artifacts/plan-names-budget-fskit.log`.

All 23 suites passed after the namespace fixture changes
(`artifacts/plan-names-budget-tests.log`); current component, style and unsigned
app checks passed under `artifacts/plan-names-verified-*.log`. Both protocol paths
and the Swift bridge compile; installed alias/normalization behavior and native
Windows-authored namespace acceptance remain unqualified.

The core catalog suite passes fourteen inventories/rejections, exact surrogate
and case-distinct names, source-node-independent lifetime, 28 allocation failures
and one I/O failure position. The FSKit component passes five stream projections:
resident ADS, a 255-unit unpaired name, directory ADS, an oversized sparse stream
and fragmented data. It checks manifest bytes, exactly one protocol reply,
allocation retry, failed-read retry, revocation during reading and cached access,
and cleanup after permanent revocation. Both protocol implementations and the
Swift bridge compile in the current unsigned app.

All 23 sanitized suites, freestanding targets and style checks passed under
`artifacts/plan-ads-*.log`. Image fuzzing exercised named opens and catalogs for
55,509 executions in 61 seconds without a reported finding, retained under
`artifacts/fuzz-stream-catalog/`. Independent NTFS-3G images passed four geometries
with 100 file-byte comparisons each, original ADS bytes and exact stream
inventories, without changing any image; evidence is retained under
`artifacts/interoperability-stream-catalog/` and `artifacts/plan-ads-oracle.log`.
Installed xattr behavior and Windows-authored stream inventories remain
unqualified.

The subsequent metadata/content component covers six ordinary encoded-stream
variants, including empty encrypted data and both attribute-list storage forms.
Lookup and requested-attribute pages preserve logical and physical sizes;
independent plaintext ADS remain readable. Default reads fail with zero reported
bytes and unchanged sentinel buffers, including after remount. Ten explicit
metadata/reparse failures retain the pending attribute entry; names-only pages
still contain the objects. Admission rejects cached metadata/ADS after permanent
revocation without further core allocation or device I/O. The legacy checks pass
under `artifacts/plan-stat-component-reviewed.log`; modern checks compile but
explicitly SKIP without macOS 27. These synthetic results do not qualify
Windows-authored EFS/compression or installed projection.
