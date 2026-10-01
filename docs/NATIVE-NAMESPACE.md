# Native stream and name presentation

The core preserves original UTF-16 code units and distinguishes names of directory
links from the referenced inode. Native projection belongs to the adapter.
Ordinary filenames still use strict UTF-8 conversion; bounded aliases for
unpaired/oversized filenames and per-directory case policy remain required.

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

An xattr response is capped at 1,048,575 bytes. Larger streams remain visible but
get returns E2BIG; unknown, malformed and default-stream aliases return ENOATTR.
The adapter opens and validates the selected stream before reading exact bytes,
checks revocation again before returning data, and does not cache file content.
Setting or deleting any xattr returns EROFS. This projection does not provide
Windows ACL authorization, EFS decryption or provider content support. Files whose
default stream cannot currently be adopted by FSKit still need the separate
unsupported-object metadata contract.

## Local evidence

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
