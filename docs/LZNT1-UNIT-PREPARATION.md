# Private LZNT1 unit packet preparation

`core/write_lznt1_unit.c` owns proposed new-content bytes for one logical
16-cluster LZNT1 unit. It performs no device read, physical cluster allocation,
runlist edit, bitmap/FILE update, WAL operation or media publication. Ordinary
compressed filesystem writes remain refused. This component is separate from
the [byte encoder](LZNT1-ENCODING.md) and from native tail/update qualification.

## Content and ownership

The admitted cluster sizes are 512, 1024, 2048 and 4096 bytes, matching the
current compressed reader. Unit size is therefore 8–64 KiB. The caller declares
source storage, the logical bytes remaining in this unit and the initialized
prefix. Every count is bounded by the unit; initialization must fit both source
storage and logical EOF. Only initialized bytes are read. The remaining complete
unit is zero, including bytes after VDL and EOF. Unused declared source storage
still participates in alias/address-wrap checks.

The result owns its metadata and any stored bytes after the caller changes or
discards source data, the input descriptor or the environment descriptor. The
allocator context must remain valid until close. One allocation owns each result:
empty/all-zero content needs only the private owner, while nonzero content needs
the owner, one normalized unit, the encoder's raw bound and its 12-KiB scratch.
The maximum buffer portion is 143,392 bytes, plus owner metadata. The core does
not allocate again or call the environment's read callback.

All pre-allocation admission failures preserve the caller's result pointer.
Allocation or encoder failure publishes NULL and releases any acquired storage.
The result pointer cannot overlap the input/environment descriptor or any
declared source byte, even an unused tail. Touching disjoint endpoints is legal.
Source storage must stay immutable during preparation; the allocator is the
ordinary trusted explicit allocator contract.

## Four packet states

| State | Owned payload | Proposed relative unit shape |
| --- | --- | --- |
| Empty logical content | None | Zero logical/physical/hole clusters |
| All-zero normalized content | None | Sixteen virtual-hole clusters |
| Raw | Complete normalized plaintext unit | Sixteen physical clusters, no hole suffix |
| Packed | LZNT1 packets plus bounded zero padding | A nonempty physical prefix shorter than sixteen clusters, followed by virtual holes |

Nonempty counts describe a complete proposed logical unit. `logical_bytes` and
`initialized_bytes` are separate content-clipping facts. These counts do not
select a final FILE tail's highest VCN, AllocatedSize, physical-size field or
native mapping span. No LCNs, retired extents or allocation permissions appear
in this API. A higher owner still owes complete before images, stream/FILE
provenance and the coupled allocation/metadata/recovery contract.

## Exact physical rounding

The existing `stream_read.c` collects all physical clusters in a unit before
calling `ntfs_lznt1_decode`. That decoder accepts an exact packet end or a
complete two-byte zero header; it rejects one dangling byte. The packet owner
therefore applies these rules before publishing any result:

1. Encode the full normalized unit with admitted raw-bound capacity.
2. Round packet bytes to whole clusters.
3. An exact boundary needs no marker. A nonempty gap contains a complete zero
   header, followed only by zero bytes.
4. If the first rounded boundary leaves exactly one byte, add one cluster.
5. Use packed storage only when that complete prefix remains shorter than the
   logical unit. Otherwise select raw plaintext storage.

The last rule is also a representation requirement: the reader interprets a
unit with no hole suffix as raw. Encoding into all sixteen physical clusters
would therefore mislabel packet bytes as plaintext. Padding is never written
past the admitted encoder buffer; candidates at or beyond the full-unit size
fall back before padding writes.

This is a conservative private storage choice consistent with the current
reader, not a claim that Windows uses an identical compression heuristic or
that the result is the optimal packet or physical allocation.

## Independent tests and remaining native questions

`tests/write_lznt1_unit.c` authors plaintext independently and walks every packet
using an explicit nine-entry width table. Every literal and reference is checked
against normalized plaintext; the product decoder is an additional oracle.
Raw and sparse results have direct byte/zero oracles. Allocation guards, exact
allocation ends, source alignments, source/descriptor lifetime, EOF/VDL clipping,
declared-span aliasing, unsupported geometry and allocation refusal have separate
checks. Padding fixtures must include exact-boundary/no-marker, two-byte padding,
one-byte-gap expansion and one-byte-gap raw fallback; missing fixture coverage
fails rather than skipping a case.

The fixed suite passes 244 owned-unit cases in each of userspace, forced portable
memory/wire and general-register-only kernel compilation contexts under local
fatal ASan/UBSan. Local LSan is explicitly unavailable under the ptraced executor;
full hosted sanitizer qualification remains a distinct gate. All four admitted
cluster sizes, 128 deterministic randomized content/EOF/VDL cases, poisoned unused
source tails and allocation/output refusal behavior are included. Optional corpus
export produces 175 independently checked original/padded packet pairs for native
Windows qualification. The exported packet contains every physical padding byte.

The first local fixture search stopped because a single entropy-prefix sweep did
not reach encoded length 512. A bounded second perturbation found it; failed and
successful discovery evidence is preserved. The final suite uses four fixed
authored inputs with lengths 510, 511, 512 and 7679 bytes in an 8192-byte unit.
They respectively establish two-byte padding, one-byte-gap expansion to two
clusters, exact-boundary/no-marker and one-byte-gap expansion forcing raw fallback.
Both one-byte-gap packets separately demonstrate the decoder's dangling-byte
refusal. The initial failure was missing fixture coverage, not a sanitizer finding.

The existing encoder fuzz target also exercises the unit owner through cluster,
EOF, VDL and allocation-refusal selectors, preserving separate independent packet
and plaintext checks. Authored seeds retain all four padding boundaries, their
allocation failures and every cluster geometry. Current execution evidence is
retained under `artifacts/dots-lznt1-unit/`: 514 deterministic fuzz-smoke inputs
pass in each of the three GCC sanitizer contexts, and the 22 authored unit seeds
pass their bounded generation contract. The campaign permits 65,542 bytes so its
six-byte selector does not exclude a full initialized 64-KiB unit; the encoder
API's separate 1-MiB admission limit is unchanged. Full-unit noise and period-3
seeds and smoke cases retain both raw and packed paths. This executor has no Clang/libFuzzer;
native padded-packet and hosted mutation-campaign results must be recorded
separately before claiming those boundaries pass.

Before any mapping or mutation admission, obtain independent Windows before/
after observations for compressible, noisy and all-zero files at cluster−1,
cluster, cluster+1, unit−1, unit and unit+1 sizes, with truncate/regrow and VDL
transitions. Retain actual DATA header sizes/highest VCN, physical-prefix/hole
runs and stored bytes including padding. Native update/WAL order, physical
ownership, allocation accounting, failure publication and fresh-owner recovery
remain separate work. WOF provider transforms are outside this component.
