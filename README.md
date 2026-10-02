# Machlin NTFS

An independent, proprietary NTFS implementation for a commercial macOS FSKit
product. The C core owns disk semantics; the FSKit extension owns platform
lifecycle and I/O. There is no kernel adapter or LXNU integration in this scope.
The owner intends a later open-source release; no open-source license is granted
today. See LICENSE and docs/PROVENANCE.md.

The initial delivery is a bounded read-only implementation and an engineering
handoff, not a production NTFS driver. Build, component tests and installed native
acceptance are tracked separately in [the acceptance matrix](docs/ACCEPTANCE.md).
Write support requires the separate recovery contract in [WRITES.md](docs/WRITES.md).

Layout follows the ext4 sibling: `core/`, `include/`, `adapters/posix/`,
`adapters/fskit/`, `tests/`, `tools/`, `scripts/` and `docs/`. The core is original
C11 with explicit allocation and exact device reads. No third-party NTFS
implementation is linked into the product.

Implemented reading includes MFT/attribute lists, resident and fragmented data,
sparse and uninitialized ranges, alternate data streams, LZNT1, indexed directory
enumeration, $UpCase lookup and bounded reparse metadata decoding. Symlink and
junction targets are available as lossless UTF-16. FSKit now projects a bounded
single-edge subset with explicit Windows root bindings and reversible target
aliases; see [native link policy](docs/LINK-POLICY.md). Intermediate reparse chains,
cross-volume targets and cloud content remain open. WOF file-provider streams
read XPRESS4K/8K/16K and LZX32K with bounded storage/table validation. The FSKit app and extension
build unsigned from current source; a prior personally signed Release passed strict
signature verification. Direct adapter tests and independent NTFS-3G image
comparisons pass. Native installation and Windows-authored corpus acceptance
are still required. Core and FSKit tests
run with `make test` and `python3 scripts/test_fskit.py`; build the app with
`make fskit`. See development prerequisites and exact evidence below.

The resource now reads fully aligned fragments into caller storage and keeps a
bounded window for unaligned requests. Separate retained-binary memory-reader
measurements show a targeted improvement; [PERFORMANCE.md](docs/PERFORMANCE.md)
records timings, fault/lifecycle checks and the remaining native qualification.

Read [architecture](docs/ARCHITECTURE.md), [development](docs/DEVELOPMENT.md),
[acceptance](docs/ACCEPTANCE.md) and [handoff](docs/HANDOFF-SOL.md).

The no-VM continuation adds reference-based lossless inspection, Windows corpus
acquisition/verification tools, standalone parser fuzz targets, an MS-DTYP security
descriptor decoder/resolver and repeated portable workload measurements. Verified metadata
reuse has a measured benefit for attribute-list opens. `$Secure` and per-file
descriptors have bounded read-only snapshots; full authorization, Windows/provider qualification, complete
reparse resolution, Windows/native qualification and recovery remain open;
see [the complete continuation scope](docs/CORE-QUALIFICATION.md).
[WOF reading](docs/WOF.md) validates sparse unnamed storage, named backing extents,
the complete paged chunk table and exact-size XPRESS-Huffman/LZX units. Counted streams
survive source nodes, retain one private decoded unit and retry failed fills.
Core and legacy FSKit content checks pass locally; Windows/native provider
qualification remain open.
Stored stream names now have a bounded immutable catalog and read-only FSKit
xattr projection with a lossless UTF-16 reverse manifest. Bounded native filename
aliases preserve unpaired/oversized/reserved names and individual hard links;
both projections pass component tests, with installed behavior still unqualified. See
[native namespace contracts](docs/NATIVE-NAMESPACE.md) for tested scope and limits.
See [security metadata](docs/SECURITY.md) for source selection, validation and the
remaining Windows/native authorization contracts.
The allocation-free [DACL evaluator](docs/ACCESS.md) now implements ordered plain
ACEs, exact file-right mappings, ordinary ownership and restricted/deny-only token
contexts. It remains a separate discretionary plane; native identity, integrity,
privilege and owning-operation authorization are still incomplete.
An independent [Windows AccessCheck observation pipeline](docs/ACCESS-ORACLE.md)
now captures queried tokens and original descriptors for bounded offline comparison.
Its transport/acquisition/reporting contracts pass locally; native Windows
decisions have not yet been acquired.
Stored per-directory case policy now selects exact UTF-16 or folded lookup while
preserving NTFS B-tree ordering. Mixed-directory/alias and fault checks pass
locally; installed cache behavior and Windows-authored flags remain unqualified.
See [directory case policy](docs/CASE-POLICY.md).
The separate [consistency diagnostic](docs/VALIDATION.md) now checks bounded
MFT/cluster allocation, extension/list ownership, filename/index pairing,
required mirror-prefix/boot-anchor consistency, directory reachability and physical
extents through a private read-only mount. Declared extended mirror tails retain
explicit unchecked counts; prefix agreement selects no repair source.
Synthetic fault/budget checks and four independent bitmap geometries pass;
complete reports retain a defined scope, with native Windows, view-store and
recovery qualification still open.
The FSKit [lifecycle contract](docs/LIFECYCLE.md) now closes admission before
draining reads, clears transient caches at unmount and retains item ownership for
reclamation. Eight blocked-read/overlapping-teardown scenarios and interleaved
enumerations pass locally; synchronous I/O interruption and installed lifecycle
remain separate acceptance requirements.
Conditional native reclaim now serializes against item-result publication;
older runtimes retain item ownership until the last FSItem reference. Five
modeled eligibility/ownership/publication cases and the current component/app
checks pass. Names-only enumeration now includes virtual current/parent entries
with stable stored-name aliases, checked parent identity and native cookie errors.
Local replay/fault/budget checks pass; native reclaim counts and installed
enumeration still require acceptance. See the lifecycle document.
Ordinary-file sizes now validate the complete unnamed-stream mapping separately
from content decoding. EFS-flagged and unsupported-compression files can retain
truthful FSKit attributes and independent readable ADS while default reads return
ENOTSUP. Six synthetic storage variants, corruption/rejection pages and remount/
revocation checks pass locally. Known WOF file-provider metadata also retains truthful
attributes and independent ADS beside unsupported encrypted backing. These checks do not
qualify Windows-authored EFS or installed behavior. Native links retain separate
path, identity, configuration and installed-acceptance limits.
The [ext4 FSKit history review](docs/FSKIT-EXT4-LESSONS.md) maps observed native
lessons to NTFS contracts and remaining runtime/distribution checks.
Automatic [read-cache retention](docs/READ-CACHE-POLICY.md) now reacts to observed
memory pressure without scanning dormant items. Accessed streams/catalogs/raw
snapshots become disposable while directory continuation and item identity stay
owned. Exact bytes, measured core allocation release, blocked-read delivery and
fault/lifetime scenarios pass locally; installed delivery and memory stress remain
separate requirements.
The independent [read-only log primitives](docs/LOGFILE.md) now decode LFS restart
areas/client lists, LSNs, protected pages and logical record/update framing.
Complete journal assembly, transaction analysis, recovery and Windows log
qualification remain open; structural decoding cannot enable writes or dirty mounts.
An independent logical-source owner now selects compatible restart copies with
bounded conflict/partial-I/O reports, retains lossless clients and stages physical
page reads. Counted ordinary `$LogFile` stream binding holds the core volume
through owner close and validates fragmented/listed storage. The `journal`
diagnostic reads exported regular files; `volume-journal` reads NTFS image files
through an ordinary portable core mount. Physical circular records now assemble
by LSN across adjacent protected pages and one wrap, with shared I/O credits,
bounded private staging and exact byte oracles. The `circular-record` diagnostic
retains exact bytes without alignment padding. Current circular history, copy
routing, native client/transaction interpretation and journal lifecycle remain open.
Cached active-client index/sequence lookup now distinguishes raw/free metadata
from selected active membership without I/O or allocation. Independent chain,
sequence-boundary and full UTF-16-name checks pass locally; record liveness and
native checkpoint interpretation remain separate work.
The separate NTFS client restart decoder now retains the 64-byte common prefix
for client formats 0.0/1.0, raw analysis/table LSNs and byte counts, and an opaque
extension span. Its `client-restart` packet diagnostic makes no table-presence,
current-history or recovery decision; these client versions are distinct from LFS
restart-page versions.
Already assembled client restart records can now be checked against the selected
snapshot's type, active index/sequence, exact NTFS name and stored restart LSN
before prefix decoding. Cached binding uses no I/O/allocation and preserves zero
error outputs. Page provenance and current written history remain separate from
this snapshot match; see the `client-restart-record` diagnostic and LOGFILE.md.
