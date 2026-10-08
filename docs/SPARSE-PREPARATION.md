# Private sparse zero/punch preparation

`core/write_sparse.h` owns an uncompressed mapping transformation, not sparse
filesystem mutation. The ordinary writer and FSKit still reject sparse writes.
No bitmap, FILE, stream, volume or journal is changed by this interface.

## Input and ownership

The caller supplies a complete VCN-zero-based, cluster-rounded logical mapping,
its logical/physical cluster bounds, an existing-reader-supported power-of-two
cluster size and one bounded byte interval. Runs must be nonempty and contiguous
in VCN order. Physical extents must fit the volume and must not overlap one
another; holes carry the existing `NTFS_HOLE` sentinel. The complete volume and
logical byte extents must fit the selected signed address ceiling.

The private resource policy permits at most 512 original runs. It caps input
validation at 130,816 physical-ownership interval comparisons and bounds output
storage before allocation. This is not a native format/run-count restriction.
One allocation owns the original runs, at most original-count plus two projected
runs, at most original-count retired candidates and two partial byte spans.
There are no source reads or device writes. The allocator context survives close;
input descriptions and their run arrays may be released or changed after return.

Pointer/span admission precedes output publication. Aliases and over-policy
borrowed spans leave input/output untouched; post-admission failures publish a
NULL plan. Allocation failure cannot publish a partial map or alter source data.
All returned descriptors remain immutable until plan close.

## Transformation

Every fully covered logical cluster becomes a hole. A non-hole predecessor is
also recorded as an original physical retirement candidate, bound to its VCN.
Existing holes have no retirement candidate. Partial first/last clusters remain
mapped, with exact physical byte spans that would need zeroing. A request wholly
inside one cluster produces one span; a partial hole produces none.

The original run array remains byte-for-byte intact. The projected map merges
only adjacent holes or physically contiguous extents with contiguous VCNs. A
zero-length request preserves both arrays exactly and has no retirement or zero
span. Logical mapping and data outside the selected interval remain unchanged.
The transform deliberately does not free a partially covered terminal cluster
based on an inferred EOF: its input mapping is cluster-rounded, and real EOF/VDL
semantics remain with the future stream owner.

Retirement candidates are not bitmap authority. They prove only non-overlap
inside this supplied map, not ownership against other streams or volume metadata.
Before execution, the caller must bind the exact FILE generation and stream,
validate whole-volume allocation, preserve partial-data before images, establish
EOF/VDL and sparse flag/size semantics, prepare every changed mapping/bitmap/SI/FN
and redo/undo byte, and reserve complete durability/recovery resources. Clearing
allocation before those obligations are met would invalidate this contract.

## Independent checks and remaining gate

[The C test](../tests/write_sparse.c) expands inputs/results into an independent
per-cluster mapping and byte-content oracle. It varies 243 hole/fragmented physical
patterns and every ordered pair of selected start/end/one-byte-before/after
cluster boundaries, plus a contiguous multi-cluster extent. It separately checks
the exact original-minus-projected physical retirement set, partial-zero spans,
input lifetime, allocator failure, aliases, cross-owned/out-of-volume runs,
arithmetic overflow, the maximum run policy and all supported cluster sizes at
high physical addresses. An empty mapping and zero-length requests are explicit.

These tests qualify mathematical preparation and resource ownership only.
Partial data rollback, sparse attribute encoding/size accounting, VDL transitions,
complete WAL/bitmap composition, fresh-media interruption recovery and native
Windows/FSKit behavior remain unimplemented or unqualified. See
[the capability map](PORTABLE-FEATURES.md) for the next owning steps.
