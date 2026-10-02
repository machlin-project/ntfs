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
junction targets are available as lossless UTF-16; following links and decoding
WOF/cloud data remain outside the implemented scope. The FSKit app and extension
build unsigned from current source; a prior personally signed Release passed strict
signature verification. Direct adapter tests and independent NTFS-3G image
comparisons pass. Native installation and Windows-authored corpus acceptance
are still required. Core and FSKit tests
run with `make test` and `python3 scripts/test_fskit.py`; build the app with
`make fskit`. See development prerequisites and exact evidence below.

Read [architecture](docs/ARCHITECTURE.md), [development](docs/DEVELOPMENT.md),
[acceptance](docs/ACCEPTANCE.md) and [handoff](docs/HANDOFF-SOL.md).

The no-VM continuation adds reference-based lossless inspection, Windows corpus
acquisition/verification tools, standalone parser fuzz targets, an MS-DTYP security
descriptor decoder/resolver and repeated portable workload measurements. Verified metadata
reuse has a measured benefit for attribute-list opens. `$Secure` and per-file
descriptors have bounded read-only snapshots; full authorization, WOF, native symlink
projection, Windows/native case-policy qualification and recovery remain open;
see [the complete continuation scope](docs/CORE-QUALIFICATION.md).
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
