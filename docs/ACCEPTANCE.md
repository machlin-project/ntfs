# Acceptance

The delivered scope is a bounded read-only core and FSKit development product.
Local core, adapter component, current unsigned app-build and independent-image
checks passed. A preceding signed Release build passed signature verification.
Installed native mounts, Windows interoperability and commercial release
qualification remain open. The requested 60% is not a measured completion claim;
see [the handoff](HANDOFF-SOL.md) for the delivered scope and remaining work.

The current compression-cache continuation implements at most two private decoded
outputs for LZNT1 and WOF XPRESS/LZX streams. A second distinct-unit miss attempts
one optional output allocation; allocator or allocation/live-credit refusal
keeps successful one-slot reading without poisoning enclosing operations. A
failed replacement preserves the other valid unit. Tags publish only after a
complete fill, and stream close frees both outputs exactly.

All 66 ASan/UBSan core suites, both 2-KiB freestanding targets, style, 25 FSKit
component groups/nine explicit modern-runtime SKIPs and the unsigned arm64/x86_64
Release app pass. Six dedicated cache profiles cover four optional-refusal modes,
required failure, 14 partial/full replacement faults, 12 read-byte/work boundaries,
compound fallback/partial-I/O failure, promotion/eviction and independent owners.
The original 12 operation profiles/144 required exact-one-below boundaries remain;
optional output storage has separately checked omission contracts. The WOF suite
passes 37 verdicts and 390 allocation/101 read faults, including cached-prefix
preservation after late codec failure.

Main review reads all actual suite results, selected sanitizer options, both
architectures' changed-core compilation and pressure PASS/SKIP groups. Logs use
`artifacts/plan-unit-cache-*-reviewed.log` and the later
`artifacts/plan-unit-cache-pressure-{format,component,style}.log`. Pressure checks
fill both outputs, release them on accessed-item cleanup and recreate exactly
one extra unit after restoration. READ-CACHE-POLICY.md records current core bytes.
Fresh sequential image/validation campaigns fixed-replay 363/205 unique seeds,
exit zero and report no OOM/timeout/crash. Their last periodic exploration counts
are 51,793/45,993 at 69/68 seconds; terminal exits occur at 70/69 seconds, with no
exact final execution totals or aggregate observed RSS. Input/time/per-process
RSS policies remain 1 MiB/five seconds/1 GiB. Reports use
`artifacts/fuzz-unit-cache-{image,validation}-reviewed/`.
Committed-source ordinary Release/O3 reproducibility matches all eight full
actual products under `artifacts/reproducibility-unit-cache/`.

Matched retained-release comparisons pass 4,560 runs/240 paired configurations:
hot/alternating/wider strides, longer one-unit hot reads, sequential/random with
one/four externally serialized readers, and longer confirmation of short negative
cases. Five warmed two-unit inputs reduce physical callbacks from 4,500 to zero
per 3,000 requests. The optional output costs one unit, plus current private-state
fields; no three-unit cyclic I/O saving or general throughput improvement is
established. PERFORMANCE.md records the exact medians, memory cost, negative
results and longer confirmation. Reports use
`artifacts/compression-{profile,hot,general,confirm}-unit-cache-*/report.json`.

Main review independently re-authors original/stored bytes, verifies all run
ranges/samples, physical call/byte and allocation counts, matched pairs and every
summary median/range. It also reads actual release products, fuzz binaries/unique
replays and periodic events in `artifacts/unit-cache-review-confirmed.json`.
An initial review-only assertion reversed the runner's alternating variant order;
the failed `artifacts/unit-cache-review.json` remains, and the corrected original
matrix review remains in `artifacts/unit-cache-review-order-fixed.json`. Product
tests, measurements and pairing order were unchanged.
The bounded cache is accepted for the measured reuse benefit with explicit memory
cost. Windows, installed/modern FSKit, owning authorization, native aggregate
pressure, device/independent-driver comparisons, relocated/native release and the
complete continuation remain open.

The preceding optimization continuation adds an opt-in strided workload for hot,
alternating and wider compression working sets, with independent delivered-byte
and range/sample oracles. The two focused sanitized suites pass: 47 measured
profiles and 86 benchmark helper contracts. Format/build/style pass; logs use
`artifacts/plan-compression-profile-*.log`. No core or adapter source changed;
the preceding full-suite/native-component evidence retains its source scope.
At that baseline LZNT1/WOF cache one decoded unit per stream. Its current-only Release
baseline passes 540 runs/60 summaries across five synthetic codec/storage
inputs. Both ordinary Release/O3 builds match eight actual full products under
`artifacts/reproducibility-compression-profile/`. Main review checks actual
products, independently re-authored payload/storage bytes, measured ranges and
resource counters, and every summary median/range in
`artifacts/compression-profile-review.json`. Reports use
`artifacts/compression-profile-baseline-*/report.json`; PERFORMANCE.md records
the exact configuration and mixed-unit/clock/cache limits. At that baseline a
qualified cache improvement, Windows/installed behavior and relocated/native
release evidence were still open; those current-only results establish no speedup.

The current shared FSKit lookup recognizes exact native `.` and `..` through
checked numeric ancestry. Root lookup clamps both to the root; a live canonical
parent needs no core I/O/allocation, while a released parent reopens its full
sequence-bearing reference and must still describe an ordinary directory.
Admission, native publication and compound core/physical budgets remain active.
Stored dot names remain accessible by their aliases in both authored case modes.

The ASan/UBSan component passes 25 groups/nine explicit macOS-27 runtime SKIPs;
style and the unsigned arm64/x86_64 Release app pass. The cold parent path covers
two required allocation faults, two partial/full read faults and 12 exact/
one-below core/physical boundaries, with exact replies, retry and zero leaked
core storage. Both released ancestors, remount, file/foreign/impostor rejection,
cached permanent revocation and cold-read revocation have separate checks.
Current logs are `artifacts/plan-dot-lookup-{component,style}-named-final.log` and
`artifacts/plan-dot-lookup-app.log`; actual changed owner compilation is present
for both architectures. At that dot-lookup checkpoint the core/portable products
were unchanged and retained the preceding bad-cluster suite/oracle/fuzz/
reproducibility evidence below.
No installed mount, modern runtime, native authorization or performance gain is
established by this continuation.
Main review re-reads actual PASS/SKIP groups, both protocol architectures and
the compiler diagnostic in `artifacts/dot-lookup-review.json`.

Two initial test attempts failed the parent-release assertion in
`artifacts/plan-dot-lookup-component-{initial,owner-fixed}.log`. The selected
compiler AST diagnostic confirms that the second variable in the original shared
`__weak` declaration was strong (`artifacts/plan-dot-lookup-arc-declarations.log`).
The final helper declares each weak reference separately and retains the child
across its inner autorelease pool; both parent-release assertions remain required.
No product checks or budgets were relaxed to make those attempts pass.

The preceding bad-cluster continuation passes all 65 sanitized-build suites, both
2-KiB freestanding targets, style, 22 legacy component groups/eight explicit
modern-runtime SKIPs and the unsigned arm64/x86_64 Release app. The private
metadata-only system description now follows complete unflagged attribute lists,
including first-in-extension, multiple and base-owned continuations. Public
opening of fixed `$BadClus::$Bad` content is refused; ordinary ADS with that
spelling still reads. Forbidden-range callbacks cover both distant bad runs.
There are 32 new complete-volume cases (eight positive), bringing the combined
diagnostic total to 207. Nine storage/admission profiles include 25 private-open
allocation failures, 12 partial/full open-read failures and 38 exact/one-below
core operation boundaries. Four added diagnostic profiles cover 935 allocation
failures and 890 partial/full read failures with exact cleanup/retry/accounting.
The earlier 17 diagnostic profiles still cover 3,328 allocation/1,803 read faults.

Current logs are `artifacts/plan-bad-clusters-*-reviewed.log`; all four independent
bitmap/mirror-prefix geometries pass unchanged under
`artifacts/interoperability-bad-clusters-reviewed/`. Main review independently
re-authors all 32 actual new images, checks exact current manifest/test results
and actual changed core compilation for both architectures. VALIDATION.md defines
supported flags/size/list policies. Windows-authored chains, flagged storage,
installed behavior and the complete continuation/optimization plan remain open.
Earlier reproducibility/performance reports retain their earlier source scope.

Fresh sequential image/validation campaigns replay every 363/205 compact input
once, including all 40 bad-cluster images and 32 new chains in both walkers.
Both exit zero with all periodic OOM/timeout/crash counters zero. The last reported
exploration counts are 51,938/45,153 at 70/69 seconds, not exact terminal totals;
fork mode provides no final execution total. Input/time/RSS policies remain
1 MiB/five seconds/1 GiB per process, and RSS is configured, not observed.
The two maximum/over-limit per-file descriptor images retain direct tests outside
the compact envelope. Current reports are
`artifacts/fuzz-bad-clusters-{image,validation}-isolated/`, with launcher logs
`artifacts/plan-bad-clusters-fuzz-{image,validation}-isolated.log`.

An initial worker launched a duplicate validation wrapper against shared corpus
storage and stopped it. Its original `running` report and interrupted log remain
under `artifacts/fuzz-bad-clusters-validation-reviewed/run-m4pdapfu/`; it is not
qualified evidence. Main verified no remaining matching task process before
the fresh sequential campaigns. The other initial reports remain history.
Committed-source Release/O3 reproducibility now matches all eight actual full
portable products under `artifacts/reproducibility-bad-clusters/`, with unchanged
source during both builds. Main independently re-reads every pair, actual fuzz
binary, unique fixed replay path and periodic event counter in
`artifacts/bad-clusters-review.json`. Reproducibility remains same-checkout/
toolchain/macOS arm64; native/relocated/signing/remote CI remain separate, and
no current performance improvement is inferred from earlier measurements.

The preceding per-file security continuation passes all 64 sanitized-build suites,
both 2-KiB freestanding targets, style, 22 legacy component groups/eight explicit
modern-runtime SKIPs and the unsigned arm64/x86_64 Release app. The complete
diagnostic now checks selected unnamed zero-ID descriptors with bounded
per-file staging and parser precharge; 48 new cases and two additional indexed/
per-file combinations bring the total to 175 complete-volume verdicts. Its
17 fault profiles cover 3,328 allocation/1,803 read failures, plus 68 partial/full
SECURITY-stage errors, 18 pre-callback refusals, three parser-work refusals and
the maximum descriptor's compound core read-credit boundary.

Both fresh four-geometry external oracles pass with unchanged images; descriptor
exports retain 24 byte comparisons and the complete leaf-store counters. The
initial validation oracle incorrectly required a per-file descriptor on zero-ID
`$MFT` and failed at SECURITY. Its original log/report remain under
`artifacts/plan-file-security-validation-oracle-reviewed.log` and
`artifacts/interoperability-file-security-reviewed/`. The corrected fixed-slot
policy uses original metadata inventories and 48 independent `ntfsinfo` exports,
retained in `artifacts/file-security-system-inventory/`. It checks present packets
and all nonzero IDs; missing ordinary/system-flagged file, root, Volume and Boot
cases still fail. SECURITY.md and PROVENANCE.md define its precise scope.

Current logs use `artifacts/plan-file-security-*-owner-fixed.log`; successful
oracles are `artifacts/interoperability-file-security-{owner-fixed,descriptors-owner-fixed}/`.
The validation campaign fixed-replays all 173 compact seeds, exits zero and
reports no OOM/timeout/crash events under
`artifacts/fuzz-file-security-validation-owner-fixed/`. Its last reported
exploration count is 43,828 at 63 seconds, not an exact final total; fork mode
emits no terminal execution count. The 1-MiB envelope omits the maximum and
over-limit per-file layouts, which retain direct full-image tests. Configured
1-GiB RSS is a ceiling, not observed usage. Native Windows, installed/runtime,
identity/authorization and distribution acceptance remain open.

The committed source also passes two isolated ordinary Release/O3 builds and
all eight full product byte comparisons under
`artifacts/reproducibility-file-security/`. A fresh retained reference-model run
uses coherent authored per-file descriptors: 49,855 modeled states and all 47
native-byte endpoint images pass the expanded diagnostic/content checks under
`artifacts/recovery-model-file-security/`. Main review re-authors both inputs,
compares every metadata endpoint/unowned byte and actual diagnostic/tool digest;
it also re-reads all release products, original external packets, unique fuzz
replays/event counters and component/build evidence. The reviewed report is
`artifacts/file-security-review.json`; launch logs are
`artifacts/plan-file-security-{reproducibility,recovery-endpoints}.log`.
Reproducibility covers one checkout/toolchain/macOS arm64, not relocated/native
signing or remote CI. The abstract model still supplies no native replay or
device writer. Earlier native-byte reports and directory measurements retain
their earlier source/diagnostic scope rather than qualifying this expanded pass.

The indexed security-store checkpoint passes 64 sanitized-build suites, both
2-KiB freestanding targets, style, 22 FSKit component groups/eight explicit
modern-runtime SKIPs and the unsigned arm64/x86_64 Release app. Both independent
four-geometry oracles pass unchanged. SECURITY.md and VALIDATION.md define exact
full-index/nonzero-reference scope; native Windows/installed/distribution
acceptance remains open. Logs are `artifacts/plan-secure-store-*-reviewed.log`.
The initial CLI fixture-stage, author wire-name and small-layout live-cap test
failures remain in the corresponding `*-initial.log`, `*-next.log` and
`*-wire-fixed.log` files. They required test/author corrections; no product
checks were relaxed. Existing metadata-only authors now use explicit zero IDs
instead of dangling placeholder indexed references; a separate missing-store
case proves nonzero references still fail.

The indexed-store image campaign fixed-replays all 323 authored seeds and completes
53,736 exploration executions in 70 seconds; validation fixed-replays 125 seeds
and completes 57,077 executions in 68 seconds. Both pass with zero OOM/timeout/
crash events under `artifacts/fuzz-secure-store-{image,validation}/`. The 1-MiB
envelope retains 41 of the 46 store cases; maximum-descriptor, second-pair,
129-entry catalog and the two deepest trees remain in the full direct suite.
The 1-GiB process ceiling is not an observed peak RSS. Independent review checks
actual fuzz binary/report identities, each unique replayed path, every periodic
event counter, unchanged external images and retained descriptor bytes in
`artifacts/secure-store-review.json`. Ordinary Git reads/re-authorship also
confirm all 65 preceding security images retain identical bytes.

Both isolated ordinary Release/O3 builds also match all eight actual portable
products under `artifacts/reproducibility-secure-store/`, with unchanged Git
source during the comparison. Current-only large/small legacy directory
baselines pass 54 runs/six complete-inventory summaries under
`artifacts/fskit-directory-secure-store-{large,small}/`. PERFORMANCE.md records
their distinct page settings and O2 adapter/O3 core configuration. Main review
checks actual products, source/input bytes and every oracle result in
`artifacts/secure-store-review.json`. No matched gain, installed performance,
relocated/native signing reproducibility or broader release qualification is
claimed.

| Contract | Scope and required evidence | Status |
| --- | --- | --- |
| Geometry and MST | 512/4096-byte sectors, 1/4/64-KiB clusters in independent images; boot bounds and torn FILE/INDX tests | Local tests passed |
| MFT and attributes | NTFS 3.0/3.1 headers; incremental fragmented bootstrap with resident/nonresident lists; sequence, base reference, continuation instance, reachability, gaps and duplicates | Local tests passed within limits below |
| Read-only consistency diagnostic | Private bounded mount; MFT/cluster bitmaps, extension/list ownership, complete unflagged bad-cluster lists with metadata-only/content guards, required four-record mirror prefix and boot-anchor mapping, exact filename/index pairing, complete ordinary directory bitmap/reachability inventory, namespace reachability/link counts, physical ownership, complete indexed security/nonzero FILE-ID references and selected zero-ID per-file bodies; partial budget/fault/unsupported reports | 207 synthetic verdicts, seven budgets plus four security exact/one-below boundaries, 3,328 allocation/1,803 read faults plus 935 allocation/890 partial/full bad-chain failures, 25 private-open allocation/12 partial/full read failures and 38 operation boundaries; 80 partial/full mirror-stage read failures, 48 mirror prefix budgets, six partial/full index-bitmap failures, nine index read-prefix budgets, 68 partial/full per-file SECURITY failures, 18 per-file pre-callback refusals/three parser precharges and compound core boundary passed; four independent bitmap/mirror-export geometries passed; extended mirror tails, boot replicas, DOS counts, flagged/native-Windows bad-cluster storage, other view-index semantics and Windows qualification remain open |
| Streams | Fragmentation, sparse/VDL zeroing, independent ADS and directory ADS, mixed LZNT1 units, empty nonresident data, cache retry and offsets beyond 4 GiB | Synthetic tests passed; ordinary data/ADS independently compared |
| Metadata without content decoding | Complete unnamed-stream mappings and list/extent ownership; truthful logical/physical sizes for ordinary encoded files, strict content rejection and independent readable ADS | 18 core verdicts, 29 allocation/four read faults and six FSKit storage variants passed; Windows-authored EFS/compression metadata and installed behavior unqualified |
| Stream inventory and projection | Bounded exact-UTF-16 catalog, extension ownership/duplicates, immutable lifetime, read-only FSKit xattrs and reverse manifest, response limits and revocation | 14 core and five component scenarios passed; four independent image geometries verify inventories and bytes; installed and Windows-authored projection untested |
| Native filenames and hard links | Bounded reversible aliases and per-link UTF-16 manifests; inode identity separated from link spelling; native length, Unicode, hidden/DOS ordinals, response/scan exhaustion, faults and revocation | Five authored namespace images and component sweeps passed; installed case/normalization and Windows-authored namespace untested |
| Directories | Resident/external B-tree, allocation bitmap, cycle rejection, local ordering, ancestor bounds, persistent cursor and collision-aware $UpCase lookup | Synthetic and independent image tests passed |
| Per-directory case policy | Stored standard-information policy, exact UTF-16 lookup retaining folded/raw index order, mixed parent flags and alias spelling; legacy/unknown policy handling and fault retry | 17 synthetic images with 47 allocation/eight I/O faults and legacy adapter components passed; Windows flags, installed cache/capability interpretation and macOS 27 runtime unqualified |
| Reparse metadata and native link projection | Microsoft framing, immutable original-wire copies/physical sizes and lossless names; bounded single-edge symlink/junction projection, checked ancestry, explicit Windows root bindings and target aliases; opaque provider classification and raw-data rejection | Core checks and 47 legacy path/storage verdicts passed; 79 allocation/17 read fault positions across native lookup/reopened metadata passed; intermediate/multiply linked/cross-volume resolution, Windows links and installed path walking remain open |
| Resource safety | Allocation/read failure sweeps on five layouts and reparse snapshots, exact release accounting, BUSY lifetime, 2,000 deterministic image mutations under ASan/UBSan | Local tests passed; counts below |
| Operation budgets | API 2 cumulative exact-read/allocation/work credits, aggregate volume-owned live storage, nested scopes and pre-callback refusal; cleanup/detach/retry and optional cache omission; compound FSKit scopes with separate rounded physical transfers | 12 profiles/144 exact/one-below boundaries plus mount/ABI/nesting/callback/live-storage/cache/codec/native reply checks pass; Windows stress, native aggregate/RSS, installed scheduling and measured overhead remain open; work units do not provide deadlines |
| WOF standalone primitives | Observed file-provider metadata, bounded cumulative chunk tables/4-GiB widths and caller-scratch XPRESS-Huffman/LZX decoding; exact output and hostile-input guards | 87 content/11 invalid XPRESS and 140 content/31 invalid LZX vectors passed; bidirectional wimlib comparison passed for 192 external packets and 139 nonempty synthetic packets; bounded provider/table/codec fuzz passed; Windows codec observations remain open |
| WOF file-provider reading | Sparse unnamed/exact backing storage, complete extents and paged table, raw/XPRESS4K/8K/16K/LZX32K content, counted independent lifetime, lazy private unit, truthful encrypted metadata and native ADS/projection | 37 core verdicts, 376 allocation/101 read faults and 23 legacy provider scenarios passed; bounded image fuzz passed; provider-specific native fault/interleaving/hard-link expansion, Windows and installed qualification remain open |
| Coverage-guided fuzzing | Separate bounded image and parser libFuzzer/ASan/UBSan campaigns; fixup-preserving image mutations; descriptor campaign and counts below | Completed without reported crash or sanitizer finding; sustained Windows-seeded fuzzing remains required |
| Portable boundary | Freestanding arm64/x86_64 compilation with 2-KiB frame budget; selected Xcode formatting | Passed; kernel integration untested |
| FSKit component | Aligned reads, permanent revocation, initial revoked-resource rejection, common result/error boundary, item identity/names, pagination/replay, EROFS, concurrent reads; separate admission/drain and publication/reclaim ownership; virtual dot/parent entries and exact dot lookup/released-parent reconstruction, cookie views/native errors and faults/budgets; compound operation/physical credits and safe terminal scope end; encoded-stream attributes/ADS and explicit rejection pages; bounded native link projection/raw metadata/remount | 25 in-process PASS groups; nine modern lifecycle/operation/pressure/enumeration/lookup/content/link/case checks explicitly skipped without macOS 27; actual modern result-constructor failure injection, native reclaim counts, synchronous I/O interruption, complete link/provider resolution and installed lifetime remain open |
| FSKit directory continuations | At most two lazy pool-backed independent cursors with exact/nearest-earlier same-view reuse, individual scan credits, completed-scan replacement, pinned packing, bounded recursion and epoch/retired-table teardown; pressure trims older inactive positions | 32 layout/view/cache/pressure cases, reentry/remount/invalidation/EOF checks, 34 allocation/13 read names-only faults and 151 allocation/41 read interleaved faults passed again with operation scopes; earlier paired large/small legacy memory-reader benefit had increased bounded pool peak; current guard overhead and installed/native/device qualification remain open |
| FSKit pressure retention | Independent Dispatch observer, coalesced level precedence, weak/canceled-source ownership and selective access/completion release; preserved cursor/pending entry/identity and returned bytes | Three measured core-byte scenarios, blocked-read notification, 11 allocation/two read reopen faults, catalog failure/retry, ADS/links/interleaving/remount and permanent revocation passed; installed native delivery and aggregate allocation/RSS stress remain open |
| FSKit application | Host app and embedded extension, legacy/modern protocol sources, personal development signing and strict deep signature verification | Current unsigned build and earlier signed Release passed; installed runtime and macOS 27 untested |
| Native installation | Signed VM mount, Finder, mmap, concurrency, removal | Not run |
| Windows corpus | Read-only Windows collector, offline manifest verifier and synthetic contract tests; native metadata/sparse/compression/repair evidence | Tools locally tested; Windows acquisition/qualification not run |
| Read-only log primitives | LFS 1.1/2.0 common restart/client/page framing, LSN geometry and exact logical records; nonempty-LCN NTFS update spans; bounded immutable inputs/caller scratch and diagnostic transport | 109 independent verdicts and 110 diagnostic contracts passed; structured USA-preserving fuzz passed; complete journal ownership/copy routing/current-history/checkpoint tables, LCN-less and Windows log qualification remain open |
| Logical log source and restart copies | Immutable exact logical reads, all bounded restart positions, compatible newer/equal selection and explicit conflicts/partial reports; cached lossless clients and staged physical pages with per-operation credits | 22 independent source verdicts, 22 exact reports/two transport checks, allocation/partial-read/backend-code/budget checks and all-source fuzz passed; native journal ownership, tail/fast routing and circular currentness remain open |
| NTFS journal stream binding | Fixed MFT slot/unnamed ordinary stream, complete fragmented/list/sequence/base ownership, node-independent counted lifetime, logical versus physical read accounting, staged partial-read isolation and refusal of unsupported system-file forms | 24 image verdicts/exact reports, 54 allocation/58 physical-read faults with retry, two simultaneous owners, BUSY unmount and unchanged images passed; ordinary dirty-media policy is unchanged; native journal admission/drain remains open |
| Physical circular-record observation | LSN-addressed adjacent protected fragments and one wrap, no-page-revisit bound, exact unpadded bytes/extended headers, shared read credits and bounded ephemeral staging | 30 C verdicts/exact CLI reports, 14 allocation/40 partial-read faults and exact 1-MiB custom-credit boundary passed; eight bound-volume storage forms also check exact records and resource/staging faults; written/current history, copy routing, active clients and recovery remain unqualified |
| Selected active LFS client | Cached index/sequence match plus selected in-use membership, zero stale output and bounded no-I/O/no-allocation lookup, distinct raw/free metadata | 858 pair queries across seven snapshots and 42 exact CLI reports passed, including sequence/name/client-count boundaries; all-source fuzz and counted volume checks passed; record liveness, client registration lifecycle and native checkpoint interpretation remain unqualified |
| NTFS client restart common prefix | Client 0.0/1.0 64-byte version/analysis/table-anchor fields, raw LSN/count pairs and opaque tail, immutable bounded input with no I/O/allocation and zero errors/padding | 77 aligned/unaligned verdicts, 75 exact CLI reports/two transport checks and all 77 fixed fuzz seeds passed; complete extensions/tables, containing-record ownership, selected current history and native Windows qualification remain open |
| Selected NTFS client restart record | Exact assembled framing using selected header length, RESTART type, active index/sequence, exact NTFS name and stored nonzero restart LSN before common-prefix decoding | 165 aligned/unaligned verdicts across 19 sources, 161 exact CLI reports/four transports and cached callback/fault/zero-output checks passed; all complete pairs fixed-replayed; physical/current-history provenance, native registration and complete checkpoint semantics remain open |
| Transaction/durability reference model | Exclusive serialized owner, complete private/log credits, data/WAL/commit/home/checkpoint ordering, arbitrary pending-sector eviction, partial/full I/O failures and interrupted abstract replay against independently authored NTFS endpoints | 49,855 modeled states, 22 ownership contracts, 14 history refusals, 1,205 interrupted-recovery states, 47 complete native-byte diagnostics/content checks and four unsafe-order witnesses passed; typed in-memory evidence, no native journal or product write API; see RECOVERY-MODEL.md |
| Write/recovery | Native replay, allocation, namespace transactions, crash/durability matrix | Product implementation remains open; read-only primitives and abstract reference-model replay do not provide native recovery or permit writes/dirty mounts |
| Security descriptors and storage | MS-DTYP framing and ACL states; bounded immutable `$Secure` and per-file attribute snapshots, checked indexes/hash/copies and fault retry; whole-volume selected per-file framing with explicit fixed-internal/inert source exceptions | 74 resolver contracts plus 46 whole-store/nine complete-volume store verdicts and 48 per-file diagnostic images, 496 allocation/730 partial-and-full store read positions, six operation profiles and whole-volume fault/budget checks; six per-file fault layouts and staged parser/I/O boundaries; four independent complete leaf-view/descriptor geometries passed; Windows/native authorization qualification incomplete |
| Discretionary token decisions | Ordered plain allow/deny DACLs, exact generic file masks, ordinary owner/OWNER RIGHTS and enabled/disabled/deny-only/restricting contexts, no partial grants, bounds and immutable snapshots | 196,809 local decisions including 196,608 independent per-right oracles; bounded context fuzz passed; Windows AccessCheck/full/native authorization incomplete |
| Windows access observations | Original in-memory descriptors, queried disposable tokens, native MapGenericMask/AccessCheck results, bounded offline transport and explicit mismatch/unsupported/error reports | 337 local transport/SDK/acquisition/reporting contracts passed; Windows acquisition and native DACL comparison not run |
| Full authorization and special data | Advanced ACE/SACL/integrity/privilege/maximum access, restricted ownership, identity mapping and owning native decisions; complete reparse target resolution, EFS decryption and WIM/cloud content | Not implemented; bounded single-edge native links and WOF file-provider content are tracked separately |
| Distribution | Personal signing, notarization, installer, licensing and support | Not implemented |
| Portable Release reproducibility | Two isolated ordinary Meson build directories, clean compiled-source Git state/unchanged revision, identical selected release options, bounded failure logs and full archive/CLI byte comparisons | Eight products match on local arm64 macOS; relocated checkout, other toolchains, Linux remote and native app/signing qualification remain open |
| Remote CI | macOS/Linux core, Linux oracle and bounded libFuzzer workflow | Prepared; not executed remotely |
| FSKit resource transfers | Physically aligned caller-directed fragments with bounded window fallback; exact completion/revocation/error checks and unchanged allocation/I/O limits | 120 geometry/fault verdicts at three alignments and 16 gated direct/window lifecycle cases passed; targeted memory-reader measurements below; installed buffer/device qualification open |
| Performance and metadata reuse | Release POSIX/memory profiles, warmup/cache controls, reader scaling and five-run matrices; verified live-node metadata cache; retained-binary FSKit resource and nine-repetition directory comparisons with independent exact inventories | Specific allocation/metadata, aligned resource and interleaved-directory memory-reader improvement measured; installed/device and independent-driver performance unmeasured |

The executable transaction reference model passes all three deferred/steal/abort
profiles, every operation's five sector-prefix fault variants, bounded home/control
persistence powersets and interrupted replay/retirement. The retained report and
independent review are `artifacts/recovery-model-retirement-fixed/{report,review}.json`;
its bounded launch log is `artifacts/plan-recovery-model-retirement-fixed.log`.
All 47 actual images select exact authored metadata endpoints, preserve unowned
bytes and pass complete native consistency/content checks. Actual reader/validator
digests and every image/diagnostic report pass review. The native torn-WAL witness
fails with corrupt metadata. No Windows replay or native log qualification follows.

Build, all 62 sanitized-build suites and selected style pass in
`artifacts/plan-recovery-model-{build,suite,style}.log`. This changes test/model
sources and Meson registration only; core, public API and adapters are unchanged.
Earlier app/component/freestanding and ordinary Release evidence remains scoped
to its unchanged compiled product sources, not newly executed native acceptance.
The initial author failure unpacked two of three fixture return values; the next
native predicate incorrectly expected `ok` instead of the diagnostic's `success`.
Both failed attempts remain under `artifacts/recovery-model-{initial,author-fixed}/`
and their corresponding `plan-recovery-model-*.log` files. The first successful
contract run remains separate under `artifacts/recovery-model-contract-fixed/`;
the final run adds torn/full retirement failures and sequential owner reuse without
weakening endpoint or corruption oracles. RECOVERY-MODEL.md records exact scope.

The paired portable reader measurement adds 58 independent benchmark contracts:
canonical retained-build paths, actual release product/digest agreement, failed/
changed/duplicate evidence rejection, matched toolchain/source and semantic
results, and independently modeled read ranges/samples. The initial contract
failure in `artifacts/plan-accounting-benchmark-contract-initial.log` exposed
macOS `/var` versus `/private/var` path aliases; canonicalizing selected paths
fixed the loader. The retry/focused logs use `plan-accounting-*-canonical.log`.
`artifacts/measure-accounting-smoke/report.json` qualifies all six workload paths
with 24 paired runs; its short timings establish no performance conclusion.

The real guard comparison passes 2,880 runs/160 paired configurations, nine
repetitions per variant, across ten ordinary/synthetic storage and compression
inputs. Reports are `artifacts/measure-accounting-*/report.json`, excluding the
separately scoped smoke. Full byte oracles, read schedule/sample checks, paired
semantic results and input/binary integrity pass. PERFORMANCE.md preserves
hardware/cache/matrix scope and selected overhead; this is no installed or
independent-driver performance claim.

The governor simplification uses the uniformly propagated head result
and clears only usage before explicitly assigning scope fields. Its 32-level
test denies each ancestor in turn, checks all 1,024 scope flags/zero work credits,
rejects new children during unwind and reuses storage after a fresh success.
The existing 12 profiles/144 boundaries remain unchanged. All 61 sanitized
suites, style, both freestanding 2-KiB-frame targets, 22 component groups/eight
modern-runtime SKIPs and the actual unsigned Release operation source compiled
for both architectures pass under `artifacts/plan-accounting-*-candidate.log`.
Its matched comparison passes 2,880 runs/160 paired configurations under
`artifacts/measure-accounting-optimized-*/`. Broad wall ranges overlap and mixed
medians establish no general improvement. Two longer confirmation reports add
120 runs/four paired configurations, one million operations and 15 repetitions
per variant: cached resident sequential/random wall medians improve 2.18%/1.55%,
with matching CPU direction in all 15 pairs of each profile. Open profiles are
mixed and read p99 remains clock-quantized at 42 ns. PERFORMANCE.md scopes
acceptance to those resident reads. Actual paired results, I/O/allocation/cache
counts, peak core bytes, inputs/originals and retained binaries pass independent
review. Core/native resource limits and full qualification gaps remain unchanged.

The committed accounting source passes two isolated ordinary Release/O3 builds
and all eight portable archive/CLI byte comparisons under
`artifacts/reproducibility-accounting/`, with its bounded launcher log at
`artifacts/plan-accounting-reproducibility-candidate.log`. Review re-read actual
full products and checked lengths/digests/equality. This same-checkout/toolchain,
separate-build-directory evidence does not qualify relocated sources, native
app/signing or remote CI.

Fresh current-source legacy directory baselines pass 54 runs/six summaries in
`artifacts/fskit-directory-accounting-{large,small}/report.json`, with bounded
launch logs at `artifacts/plan-accounting-native-{large,small}-baseline.log`.
The actual owner uses core/physical compound scopes, the verified Release
archive and current native/header sources. Complete independent inventories,
order, sizes, EOF and request checks pass. Review checked actual inputs,
source/archive/binary digests and retained summary medians. PERFORMANCE.md
records current-only wall/CPU/percentile/memory scope; no paired guard-cost,
earlier-adapter gain, modern-runtime or installed/device conclusion follows.

The current image campaign passes all 282 unique authored image/journal-volume
fixed-file replays and 52,898 executions in 70 seconds, with OOM/timeout/crash
counters 0/0/0 and exit zero. Evidence remains in
`artifacts/fuzz-accounting-image/report.json`, its retained campaign/replay logs
and `artifacts/plan-accounting-image-fuzz-candidate.log`. Review checked every
unique Executed line, final counters and the actual retained fuzzer digest.
One-MiB input, five-second per-input timeout and 1,024-MiB RSS are configured
ceilings; RSS is not a measured campaign peak. This bounded local campaign
does not replace Windows seeds or longer scheduled fuzzing.

The ordinary directory allocation diagnostic now scans the complete `$I30`
bitmap after checked traversal and rejects used unreachable slots, out-of-span
bits and partial final allocation records. Free storage stays opaque and unread;
normal mounted directory operations do not run this complete inventory. Twenty-two
new images cover free garbage, orphan records, fragmentation, long resident/
nonresident bitmaps, small roots and three index/cluster size relations. Both
cache modes pass. Added fragmented/paged required-failure sweeps contribute 237
allocation/191 read positions to the totals above; three bitmap reads add six
partial/full failures and nine read-call/read-byte/work refusals before callbacks.
Every retry releases its owners and preserves media.

`artifacts/plan-index-focused-owner-fixed.log` passes all five focused suites;
`artifacts/plan-index-freestanding-owner-fixed.log` passes both 2-KiB-frame targets.
The complete sanitized run passes 60/60 in
`artifacts/plan-index-suite-equivalent-complete.log`, style in
`artifacts/plan-index-style-complete.log`, and 22 component groups/eight explicit
modern-runtime SKIPs in `artifacts/plan-index-component-complete.log`.
`artifacts/plan-index-app-release-complete.log` is an actual unsigned Release
app build with both changed core sources compiled for arm64/x86_64. No installed
runtime follows from that build.

The initial focused failure in `artifacts/plan-index-focused-initial.log`
identified a diagnostic subject bug: namespace pairing left the last child in
the report before the owning directory's inventory failed. Restoring the owning
directory before that check fixed product reporting without weakening its oracle.
`artifacts/plan-index-existing-fixtures-compare.json` verifies all 96 preceding
fixtures remain byte-identical and adds exactly 22. The unsupported prepared
launcher spelling is retained in `artifacts/plan-index-suite-complete.log`;
the documented build/test launchers pass under the successful log above.

`artifacts/fuzz-index-validation/report.json` passes fixed replay of all 118 seeds
and 54,415 exploration executions over 68 seconds, with zero reported OOM,
timeout or crash events. Review counted every replay line and checked the actual
binary against its reported digest. The unchanged 1024-MiB RSS ceiling is a policy,
not an observed campaign peak. `artifacts/interoperability-index-reviewed/report.json`
passes complete diagnostics and independent MFT/cluster bitmap and required mirror
prefix exports in all four preceding external image geometries. Review rehashed
each actual image against both reports. The independent utility does not compare
external `$I30` visited slots; that new product check executes inside the diagnostic.
Windows, view-store, native installation, authorization and recovery remain open.
The preceding Release reproducibility report predates this changed core source.
A subsequent current-source check passes both ordinary Release/O3 builds and
all eight full archive/CLI byte comparisons in
`artifacts/reproducibility-index/report.json`, with bounded launcher output in
`artifacts/plan-index-reproducibility-complete.log`. Review independently re-read
all actual product pairs and verified equality, lengths and reported digests.
The source revision stays unchanged during the check; compiler/SDK, revision and
selected options remain in its generated report. This qualifies separate build
directories in one checkout/toolchain. Relocated sources, native app/signing and
remote CI still require their own execution. The inventory adds diagnostic cost;
current mounted accounting overhead and broader performance remain unmeasured.

The operation-budget continuation passes all 60 sanitized core suites in
`artifacts/plan-operation-suite-complete.log`, both freestanding 2-KiB-frame
targets in `artifacts/plan-operation-freestanding-complete.log` and selected
formatting in `artifacts/plan-operation-style-complete.log`. The focused core
log `artifacts/plan-operation-core-focused-scans.log` records 12 profiles/144
exact/one-below boundaries with independent callback/byte/live-peak accounting
and original byte oracles, plus mount/ABI, nesting/LIFO/depth/detach, callback
reentry, failed attempts, optional cache omission, sibling storage and cold/cache
LZNT1/XPRESS/LZX retry. Refused requests do not reach the backend; required
cleanup remains possible and media is unchanged.

The complete component passes 22 groups/eight explicit modern-runtime SKIPs in
`artifacts/plan-operation-component-focused-scans.log`. New checks include physical
rounding/fragments, failed attempts, nested credits, callback scope refusal,
logical-versus-physical read accounting, cached work, publication/packing errors,
provider classification, packer reentry and terminal detach. The unsigned Release
app passes in `artifacts/plan-operation-app-release-reviewed.log`: actual CompileC
evidence covers core API/accounting and Resource/Volume/FileSystem on both arm64
and x86_64. The preceding `artifacts/plan-operation-app-complete.log` is a successful
Debug build, not Release. Neither build installs or signs the extension.

The first core test attempt in
`artifacts/plan-operation-core-focused-initial.log` passed four groups before an
incorrect expected journal-page assertion. The fixture manifest independently
identified its `system-4096` source; correcting only the oracle made the test pass.
The initial component compile in
`artifacts/plan-operation-component-focused-reviewed.log` missed the modern
lookup selector's context argument. The test was corrected to the selected SDK;
no product fix was inferred from either failed test attempt. Retained intermediate
build/focused logs do not replace the complete qualification above.

`artifacts/fuzz-operation-image/report.json` and
`artifacts/fuzz-operation-validation/report.json` retain passing complete fixed
replays of 282/96 authored seeds and separate exploration of 51,427 executions/
70 seconds and 57,672/68 seconds. The final logs report OOM/timeout/crash counts
of zero, with unchanged 1-MiB input, 1024-MiB per-process RSS ceiling and five-second
input timeout. Campaign peak RSS is not recorded; the ceiling is not an observed
peak. Review independently counted replay execution lines and verified both
retained binaries against their reported digests. The image walk additionally
checks tightened shared credits against actual callback attempts.

`artifacts/interoperability-operation-reviewed/report.json` again passes all four
external mkntfs geometries, 100 files each, exact ordinary/large/Unicode/ADS bytes,
stored names/stream inventory and case-folded lookup. Review rehashed every image
against its retained report. This run does not compare bitmap or mirror exports;
their preceding independent evidence remains separate below. No Windows corpus,
VM, installed mount, native authorization or recovery ran. Current guard overhead
and native aggregate allocation/RSS stress remain open; OPERATION-BUDGETS.md
defines the accounting and ABI migration contract.

The committed operation source passes both isolated ordinary Release/O3 builds
and all eight full archive/CLI byte comparisons in
`artifacts/reproducibility-operation/report.json`, with bounded logs beside it
and launcher evidence in `artifacts/plan-operation-reproducibility.log`. Review
independently re-read both copies of every product and checked full byte equality,
reported lengths and digests. Apple clang/SDK, unchanged source revision and
selected options remain in the generated report. This is same-checkout local
arm64 portable evidence; relocated sources, native app/signing and remote CI
remain unqualified.

The preceding directory continuation component passes 20 groups with seven explicit
macOS-27 runtime SKIPs in `artifacts/plan-directory-component-complete.log`.
Names-only and interleaved fault sweeps cover all 34/13 and 151/41 allocation/read
positions, exact prefixes, one native reply, fresh-scan retry, unchanged media and
complete cleanup. Thirty-two independent cache cases include hidden/large layouts
and same/separate views. Packer reentry, remount, retired-table lifetime, bounded
recursive remount, completed-scan replacement and cached EOF have explicit tests.
Style passes in `artifacts/plan-directory-style-complete.log`; the unsigned Release
app passes in `artifacts/plan-directory-app-complete.log`, compiling the actual
changed `NTFSVolume.m` for arm64 and x86_64. Core/include/POSIX/portable CLI sources
are unchanged; their preceding 59-suite/frame/Release evidence was not rerun.

`artifacts/fskit-directory-{large,small}-sustained/report.json` each retain 54 exact
inventory-qualified paired runs, nine repetitions/profile/binary, immutable warm
memory inputs and no MFT record cache. The 2,000-link interleaved profiles reduce
wall medians by 88–89%; the 12-link profiles by 32–35%. Sequential ranges overlap
with median changes of +1.35%/-1.68%, establishing no stable material change.
Sequential peak pool cost is 1,152 bytes; two-reader added peaks are 53,016/16,537
bytes respectively. The resource pool includes the charged adapter table and core
children, excluding Foundation/window; process RSS retains its separate scope.
Review verified actual binary/source/archive/input digests. Six original namespace
images remain byte-identical in `artifacts/directory-fixture-before/report.json`;
only independent expected-size/large-inventory manifests were added.

The earlier helper-name/assert compilation failure remains in
`artifacts/plan-directory-large.log`, and tuple/list reference-preflight failure
in `artifacts/fskit-directory-large-optimized/report.json`. Neither ran a passing
measurement matrix. Earlier shorter paired reports retain higher sequential
medians and prompted EOF victim preference and the longer final comparison. See
PERFORMANCE.md for complete scope/counters; no mount, Windows acquisition or
modern runtime ran.

The mirror-prefix continuation passes all 59 sanitized core suites and style in
`artifacts/plan-mirror-{core,style}-final.log`. Initial focused/build/frame logs
under `artifacts/plan-mirror-*-geometry-fixed.log` qualify the three affected
suites and both freestanding 2-KiB-frame targets. The unsigned Release app passes
under `artifacts/plan-mirror-app-final.log`; both architectures compile the actual
changed `core/validate.c`. Unchanged adapter components were not rerun; their
preceding evidence and seven modern-runtime SKIPs remain separate below.

The committed mirror diagnostic also passes both isolated ordinary Release/O3
builds and all eight archive/CLI full byte comparisons in
`artifacts/reproducibility-mirror/report.json`, with launcher evidence in
`artifacts/plan-mirror-reproducibility.log`. Review independently re-read both
copies of every product and verified full byte equality, reported lengths and
digests. Compiler/SDK, source revision, selected options and hashes remain in
the generated report. This qualifies the current local portable products;
relocated checkout, native app/signing and remote CI remain open.

Thirty-nine new images cover first-copy admission, stale identity/LSN/body data,
torn/invalid records, independent protection/slack, opaque free slots, complete
fragmented/listed mappings, 1/64-KiB clusters and unqualified extended tails.
All 57 existing diagnostic images remain byte-identical in
`artifacts/plan-mirror-fixture-compare-geometry-fixed.log`. Across eight successful
storage configurations, the C suite sweeps 1,068 allocation and 772 read failures
with retry and exact cleanup. Four mirror-stage partial/full sweeps cover another
80 read failures and 48 read-call/byte/work prefix budgets. The CLI checks all 96
verdicts/coverage counters, seven budgets, unchanged images and transport errors.
The initial constant-name and fixture-bitmap sizing failures remain in
`artifacts/plan-mirror-build-{initial,initial-fixed}.log`; neither failed run
qualified the tests that had not executed.

`artifacts/interoperability-mirror-reviewed/report.json` compares both allocation planes
and independently exported exact required replica prefixes on four mkntfs
geometries. Prefix lengths derive from the independently exported FILE allocation
fields, cross-checked with the core geometry. Prefix sizes are 4 KiB for three profiles and 16 KiB with 4096-byte
records. The 64-KiB-cluster profile explicitly compares four of 64 declared
records and reports 60 unqualified slots. Every image hash remains unchanged.
This external-tool evidence does not establish Windows-dependent tail coverage.

The validation campaign fixed-replays all 96 complete compact authored images;
the retained replay log has 96 execution lines. Exploration completes 59,760
executions/68 seconds, coverage 3,289/features 9,107, exit zero and reported
OOM/timeout/crash counts of zero in
`artifacts/fuzz-mirror-validation/report.json`. The unchanged input/RSS/timeout
policies remain 1 MiB/1024 MiB/five seconds; RSS is a policy ceiling, not an
observed peak. Required-prefix agreement selects no authoritative repair copy,
admits no dirty volume and enables no write. Windows and installed acceptance,
extended mirror tails, boot replicas and native recovery remain open.

The selected-client restart-record continuation passes all 59 sanitized core
suites, style, 18 component PASS groups/seven explicit macOS-27 runtime SKIPs
and the unsigned Release app under `artifacts/plan-logrestart-record-*-final.log`.
Both arm64/x86_64 compile the changed `core/logfile_source.c`. The identical
product passes both freestanding 2-KiB-frame targets in the retained initial
build/eight-focused-suite/frame logs under
`artifacts/plan-logrestart-record-*-initial.log`.
Its 165 independent verdicts span 19 selected sources, including the 407-entry
active chain, new second copy, zero/max sequence, exact/foreign names, stale/free
identities, gate precedence, extended headers and complete-record cap. Armed
next-read/allocation failures and exact counters prove no cached callbacks.
The CLI compares 161 exact reports and four transports plus arguments/hashes.
The fixture review replaces a numeric oracle-list position with a named payload
key; all 265 authored files remain byte-identical and three focused suites pass
in `artifacts/plan-logrestart-record-fixture-reviewed.log`.

Its logfile campaign fixed-replays all 414 seeds, including all 165 complete new
source/record pairs. The replay log contains 414 execution lines. Exploration
passes 101,694 executions/61 seconds, coverage 1,065/features 2,687, peak RSS
529 MiB and exit zero in `artifacts/fuzz-logrestart-record-final/report.json`.
Input/RSS/timeout policies and the two explicit complete 4-MiB record-source
exclusions are unchanged. Selected-snapshot matching does not establish native
page/current-history provenance, complete checkpoint semantics or recovery.
No VM, installed mount or Windows journal ran.

The committed binding source also passes both isolated Release/O3 builds and
all eight archive/CLI full byte comparisons in
`artifacts/reproducibility-logrestart-record/report.json`, with bounded build
logs beside it and launcher evidence in
`artifacts/plan-logrestart-record-reproducibility.log`. Compiler/SDK, source
revision, selected options and hashes remain in the generated report. This
qualifies that binding's local portable products; relocated checkout, native app/
signing and remote CI still require separate evidence.

The preceding client restart-prefix continuation passes all 56 sanitized core suites,
style, both freestanding 2-KiB-frame targets, 18 component PASS groups/seven
explicit macOS-27 runtime SKIPs and the unsigned Release app. Both arm64/x86_64
compile the actual changed `core/logfile.c`. Logs are retained under
`artifacts/plan-logcheckpoint-*-final.log`; the earlier build/eight focused
suites/frame logs remain under `artifacts/plan-logcheckpoint-*-initial.log`.
The independent 77-prefix corpus preserves raw boundary pairs and opaque tails,
checks every shorter prefix, unknown versions and the exact/over-cap boundary,
and proves zero padding/errors, unchanged input and caller guards. The CLI
compares 75 exact reports and two transport rejections plus argument errors.

The dedicated logfile campaign fixed-replays all 249 authored seeds, including
all 77 new payloads; its replay log contains 249 execution lines. Exploration
passes 103,509 executions in 61 seconds, coverage 1,033/features 2,677, peak RSS
520 MiB and exit zero in `artifacts/fuzz-logcheckpoint-final/report.json`.
The unchanged 2-MiB input cap still explicitly excludes the same two complete
4-MiB record sources; both remain in direct C/CLI suites. Prefix success does
not qualify extension/table contents, current history, native recovery or writes.
No VM, installed mount or Windows journal ran.

The preceding resource transfer continuation passes 18 component PASS groups/seven explicit
macOS-27 runtime SKIPs, style, four affected tool contracts and an unsigned Release
app under `artifacts/plan-resource-*-final-fixed.log`. Both arm64/x86_64 compile
the actual changed resource. Core code was unchanged at that checkpoint; its
then-current full 53-suite/freestanding evidence was the active-client run below.
Independent resource cases cover aligned/offset/address/length/mixed-tail/EOF
transfers, zero-I/O bounds errors, short/partial/full errors, over-reported counts,
retry, unchanged guards/source and permanent revocation. Native lifecycle tests
observe the blocked transfer's destination and retain aligned raw storage until
completion. Failed direct fills still produce error replies with zero bytes;
teardown/reclaim cannot free active storage early. The failed mutable-data buffer
assumption and diagnostic runs remain in
`artifacts/plan-resource-component-{final,diagnosis}.log`; owning raw aligned
storage fixes the test without changing product code.

The release resource benchmark passes 85 initial baseline runs, 170 matched
old/new runs and a 20-run longer fallback repeat. Caller-directed aligned profiles
eliminate inferred bounce-copy bytes without changing device calls/bytes or core
allocation policy. Matched wall medians improve about 47%/49% for 64-KiB/1-MiB
requests and 54% for 1-MiB-plus-sector requests over the memory reader.
PERFORMANCE.md records scope, per-run percentiles, timing variance and exact
reports under `artifacts/fskit-resource-{baseline,direct,offset-repeat}/`.
Installed buffer lifetime and native throughput remain unqualified.

`scripts/check_reproducible.py` passes two Release/O3 builds and full byte equality
for `libntfs.a`, `libntfs-posix.a` and six CLI products. Selected compiler/SDK,
source revision and artifact hashes stay in
`artifacts/reproducibility-accepted/report.json`; setup/compile logs are retained
beside it, with launcher/style evidence in `artifacts/plan-reproducibility*.log`.
The earlier ordinary build probe also matches all eight products under
`artifacts/reproducibility-probe/`. No source remapping, timestamp rewriting or
binary normalization was needed. CI is prepared to repeat the comparison on
macOS/Linux and upload bounded reports/logs; it has not run remotely.
That report predates the client restart-prefix change; a new comparison is
required for products compiled from the later source.
The subsequent current-source comparison now passes both Release/O3 builds and
all eight full byte comparisons under `artifacts/reproducibility-logcheckpoint/`,
with launcher evidence in `artifacts/plan-logcheckpoint-reproducibility.log`.
It covers the new prefix decoder; relocated/native app and remote CI limits
remain unchanged.

The active-client continuation passes all 53 sanitized core suites, style,
17 component PASS/seven runtime SKIPs and the unsigned arm64/x86_64 app under
`artifacts/plan-logclients-*-final.log`. Initial build/nine focused suites and
both freestanding 2-KiB-frame targets pass under
`artifacts/plan-logclients-*-initial.log`. Both app architectures compile the
changed source owner. Seven independent snapshots retain 858 raw/active pair
expectations, covering non-numeric mixed chains, empty/all-free lists, LFS 2.0,
407 active clients, full-length unpaired names, zero/max sequences and free old
out-of-geometry LSNs. Armed allocation/read failures prove no cached callbacks;
CLI samples 42 exact reports plus argument/discovery/transport errors.

The logfile campaign fixed-replays all 172 authored seeds, with 172 execution
lines and a passing replay report. All seven new client sources fit its unchanged
input cap. Exploration passes 91,838 executions/61 seconds, coverage
989/features 2,602, peak RSS 515 MiB and exit zero in
`artifacts/fuzz-logclients-final/report.json`. Synthetic selected membership
does not qualify native client registration, current record history or recovery.
No installed mount or Windows journal ran.

The preceding physical-record continuation passes all 50 sanitized core suites, both
freestanding 2-KiB-frame targets, style, 17 component PASS/seven runtime SKIPs
and the unsigned arm64/x86_64 app under `artifacts/plan-logrecords-*-final.log`.
Both app architectures compile the changed source owner; no installed mount or
Windows journal qualification ran. Thirty independent source verdicts and exact
CLI byte/report oracles cover fragments/wrap, empty data, extended framing,
USA-intersecting bytes, stale/unsupported/corrupt storage, linked-LSN geometry,
ring bounds and credit/cap failures. Fourteen allocation/40 partial-read failure
positions preserve caller bytes and exact cleanup with retry. An independently
authored exact 1-MiB record is refused by default byte credits and accepted with
sufficient explicit credits. Eight ordinary bound-volume variants separately
compare exact record bytes and check partial physical-read/staging-allocation
failure and retry through the counted backing context.

The logfile campaign fixed-replays all 165 authored seeds before exploration,
with 165 execution lines and a passing replay report. Its 28 included record
sources and six fault/control seeds fit the unchanged 2-MiB envelope; two full
4-MiB sources are explicitly excluded and remain in direct C/CLI checks.
Exploration passes 103,760 executions/61 seconds, coverage 951/features 2,417,
peak RSS 537 MiB and exit zero in
`artifacts/fuzz-logrecords-final/report.json`. This bounded synthetic campaign
does not qualify sustained Windows-seeded fuzzing or authoritative recovery.

The preceding volume-binding continuation passes all 46 sanitized C suites, both
freestanding 2-KiB-frame targets, style, the component's 17 PASS/seven runtime SKIPs
and the unsigned arm64/x86_64 app under `artifacts/plan-logvolume-*-final.log`.
Both app-core architectures compile the new owner; no installed mount ran.
The 24 independently authored 8-MiB images include contiguous/fragmented storage,
resident/nonresident attribute lists, ordinary 4-KiB and maximum 64-KiB restart
pages, fast storage and a torn first copy. Conflicts, stale sequence/base
ownership, continuation gaps, directory/reparse/view/uninterpreted records,
encoded/sparse SI and attribute flags, partial initialized length and missing
streams retain exact error reports. Five complete binding sweeps exercise 54
allocation and 58 physical-read failures, including a late physical extent in a
64-KiB logical read, with retry, exact release accounting and unchanged media.
Two independently opened owners preserve BUSY until the last close. Cached
restart/client snapshots survive the temporary node without reads/allocations;
tail/circular bytes match original sidecars, including partial backend fills.
The CLI additionally checks a core mount rejection and two transport errors.
Initial fixture expectations used CORRUPT for a foreign extension owner; the
existing shared resolver's documented STALE result was retained and the author
corrected. Failed and corrected logs remain under
`artifacts/plan-logvolume-{build-initial,focused-initial,focused-corrected}.log`.

The image fuzz path now exercises counted journal owners. Its author includes 22
unique journal-bearing 1-MiB volume seeds, explicitly excluding the two larger
physical layouts, which remain in the full image/source suites. These are
authored geometries, not truncated larger images. A fixed-file replay executes
all 282 image seeds (260 existing and 22 journal volumes), exit zero, peak RSS
348 MiB under `artifacts/plan-logvolume-image-corpus-replay.log`.
The first in-process campaign reached the 1024-MiB process limit while libFuzzer
retained roughly 557 MiB of corpus arrays plus ASan quarantine; its OOM, report
and input remain in `artifacts/fuzz-logvolume-image-final/`. The retained input
passes 2,000 fixed repeats without a sanitizer/assertion/OOM finding, peak RSS
337 MiB, under `artifacts/plan-logvolume-image-oom-replay.log`.

Whole-image exploration now uses one libFuzzer child at a time with bounded
subsets/merges; OOM, timeout and crash remain fatal. The accepted campaign records
55,049 executions over a 70-second supervisor interval, coverage 4,368/features
15,132, no reported OOM/timeout/crash and exit zero in
`artifacts/fuzz-logvolume-image-process-final/report.json`. Its configured
1024-MiB limit is per process; actual peak or aggregate RSS is not reported by
that supervisor. This is harness corpus retention, not driver optimization.
The separate in-process logical-source campaign passes 116,814 executions in
61 seconds, coverage 834/features 1,948, peak RSS 474 MiB and exit zero in
`artifacts/fuzz-logvolume-source-final/report.json`. No Windows journal or native
recovery/currentness/transaction acceptance is established by these runs.
The permanent pre-exploration replay is also verified in bounded 32-file batches:
282 image and 57 diagnostic seeds match every fixed execution, peak batch RSS
128/126 MiB, with passing report status in
`artifacts/fuzz-logvolume-{image,validation}-workflow/report.json`. Those requested
one-second probes lasted three/two seconds and qualify the replay/process
workflow only; they are not additional full-duration campaigns.

The preceding logical-source continuation passes all 43 sanitized C suites and style under
`artifacts/plan-logsource-{build,core,style}-final.log`. Product C passes both
freestanding targets with the 2-KiB frame limit, the component's 17 PASS/seven
explicit macOS-27 SKIP groups and the unsigned app build under
`artifacts/plan-logsource-{freestanding,component,app}-reviewed.log`. The new owner
compiles into arm64 and x86_64 app-core objects; no native installation ran.

The independent logical-source fixtures cover 22 verdicts and exact CLI reports,
plus two transport errors. Supported/unknown/CHKD candidates, compatible newer
and equivalent copies, different USA words, divergent equal-LSN areas and
incompatible versions/geometry retain distinct outcomes. A valid second copy
survives a damaged/missing first prefix or USA. Lossless cached clients, small,
ordinary 4-KiB and maximum 64-KiB restart geometries, mixed record-page sizes and
exact physical tail/fast/circular page bytes pass. Torn record pages and partial
backend reads publish no caller bytes. Allocation/read fault sweeps, six original
backend result codes and exact/exhausted page/read-credit boundaries pass with
release accounting and unchanged source bytes. A selected restart does not
establish an active post-crash history; LOGFILE.md defines the conservative
equal-LSN refusal and the missing native lifecycle/version-transition evidence.

All 22 original sources now have fuzz envelopes, including the three 1-MiB files;
there are 131 unique combined packet/source seeds. The 2-MiB test ceiling leaves
core page/allocation/read limits unchanged. The final campaign completes 108,449
executions in 61 seconds, coverage 819/features 1,856, peak RSS 526 MiB and exit
zero without a reported crash/sanitizer finding. It repeats source reports,
cached metadata and staged physical reads, checks input/output guards and memory/
read accounting, and restores/reseals either restart copy while mutating its
checked declared area. `artifacts/fuzz-logsource-final/report.json` retains the
binary and outcome; `artifacts/plan-logsource-fuzz-final.log` retains the runner.
The earlier 128-KiB campaign remains in `artifacts/fuzz-logsource-reviewed/`; it
excluded two large sources and did not exercise ordinary 4-KiB source geometry.
The initial compile error used the wrong repository allocation-error enum;
`artifacts/plan-logsource-build-initial.log` remains alongside corrected evidence.
Native journal ownership, routed/current circular records, checkpoints,
transaction/crash/durability simulation, Windows and remote CI remain open.

The preceding read-only log primitive continuation passes all 40 sanitized C suites, both
freestanding targets with the 2-KiB frame limit, selected-toolchain style, the
FSKit component and the current unsigned app/extension build. The component has
17 PASS groups and seven explicit macOS-27 runtime SKIPs. The new module also
compiled into both app-core architectures; no extension was installed.

Its independently authored fixtures cover 109 structural verdicts across
restart/client/page/record/update buffers: complete free/active client membership,
cycles/backlinks, 407 clients/64-KiB pages, lossless names, geometry up to the
observed 4-GiB log ceiling, wider LSN offsets, unknown integrity/version rejection,
torn USA tails, opaque page-copy/operation values, logical header extensions,
assembled multi-page inputs and shared/invalid redo/undo spans. Exact restored
bytes, scratch/output/input guards, all baseline restart truncations, argument
and policy boundaries pass. Short LCN-less variants reject from their shared
prefix without requiring the unresolved target-VCN layout. Fixture generation
and CLI checks enforce unique packet paths; odd and out-of-stride restart-area
offsets have distinct packets. The CLI adds 110 exact metadata/transport contracts
with unchanged file hashes. No native journal assembly, client checkpoint/table
interpretation, transaction recovery or LCN-less addressing is accepted.

The dedicated structured log campaign completes 126,853 executions in 61 seconds,
coverage 343, feature count 1,079 and peak RSS 488 MiB, exit zero with no reported
crash/sanitizer finding. The mutator restores/reseals USA while changing inner
bytes; ordinary mutation also reaches framing/envelope errors. Its 128-KiB input
cap and process RSS are distinct from the allocation-free decoder and 64-KiB
caller page scratch. The report is `artifacts/fuzz-logfile-accepted/report.json`.
Evidence uses `artifacts/plan-logfile-{build,core,freestanding,style,component,app,fuzz}-accepted.log`.
Earlier successful focused/build logs remain separate; Windows log qualification,
full transaction/crash/durability simulation and actual remote CI remain open.
[LOGFILE.md](LOGFILE.md) defines the primitive/complete-journal and format-source
boundaries without changing WRITES.md's acceptance gates.

The preceding FSKit pressure continuation passes 17 sanitized component PASS
groups, the current unsigned app/extension and selected-toolchain style. Seven
modern runtime checks explicitly SKIP. The independent observer changes retention
while resource I/O is blocked, without releasing outstanding buffers or visiting
dormant objects. Access/completion cleanup releases streams/catalogs/raw snapshots
while preserving identities, immutable native targets and pending enumeration
state. Tracked core-byte release is 135,632/18,816/79,436 in the LZNT1/XPRESS4K/LZX32K
scenarios. The cold LZX reopen covers every 11 allocation/two read failure position
plus catalog allocation failure/retry with exact bytes, no leaks and zero native
error counts. ADS, raw wire bytes, link identity, interleaved/full/empty packers,
permanent revocation and elevated remount state pass. READ-CACHE-POLICY.md defines
the measured scope and excluded memory. These are injected Dispatch component
observations, not installed native delivery or aggregate/RSS stress evidence.
Logs are `artifacts/plan-pressure-component-final.log`, `plan-pressure-style-final.log`
and `plan-pressure-app-reviewed.log`; the first
failed link fixture remains in `plan-pressure-component-initial.log`. That input
escaped the explicit owning root; the corrected scenario uses independently
authored supported native-link expectations. The existing escape-rejection cases
still pass. Portable C sources remain unchanged from the preceding checkpoint.

The preceding LZX continuation passes all 37 sanitized C suites, both freestanding targets
with the 2-KiB frame budget, selected Xcode style, the legacy component and the
current unsigned app/extension build. The original WOF/WIM-variant decoder has
140 exact-byte content vectors and 31 malformed vectors for all three block
types, complete/empty alphabets, maximum code lengths, pretree runs/deltas,
repeated/new offsets, aligned footer boundaries, overlapping copies, multiple
blocks, CALL conversion and raw alignment/padding. Input immutability, queried
scratch/output guards, argument limits and retry after failure pass. Scratch is
4,940 bytes at four-byte alignment; an owning LZX stream's private data/scratch
allocation is 70,476 bytes plus its separate table page/backing metadata.

The independently authored file suite now has 37 verdicts with 376 allocation and
101 read failure positions across selected stat/open/cold-read operations.
Additional LZX cases include mixed raw/packed units, resident/empty/exact/listed
storage, multi-page tables and CALL conversion that must bypass equal-size raw
chunks. A later corrupt unit retains only the correct earlier core prefix and
never publishes a failed private cache. Twenty-three legacy provider cases verify
byte/metadata/manifest oracles, native zero-count errors, remount/revocation and
exactly-once replies. Six modern checks explicitly SKIP; no installed mount ran.

The optional external codec comparison uses wimlib 1.14.5 in a separate test
process: 192 captured packets at three compression levels decode exactly through
the core, and the external decoder verifies all 139 nonempty synthetic packets.
The 168 compressor refusals remain explicit raw fallbacks, not codec passes.
The empty synthetic unit qualifies the core API only. The report is
`artifacts/lzx-oracle-checked-2/report.json`; library identities remain there.
These comparisons qualify that external WIM-variant codec, not Windows WOF writers.

Inspected ext4 history exposed modern result-construction and revoked-acquisition
guards. The shared boundary component now checks preserved operation errors,
EIO for a missing successful result, and rejecting an unavailable resource before
geometry access. Both protocol sources compile; real modern result failures,
installed reclamation/buffer lifetime and pressure delivery/stress remain open.
FSKIT-EXT4-LESSONS.md maps adopted contracts and remaining native requirements.

Evidence uses `artifacts/plan-lzx-{core,freestanding,app,style}-final.log`,
`plan-lzx-component-reviewed.log` and `plan-lzx-oracle-checked-2.log`. Earlier logs
retain the tiny-input compressor refusal, an independently corrected repeat-queue
byte oracle and the Xcode conditional-initialization diagnostic. External decoding
confirmed the repeat-queue result before the expected bytes changed; header reads
now have separate explicit status checks. None of those failures is counted as a
pass.

Final fixture constant naming preserved all previously tested bytes: 484 codec
files, 148 full-image files and 148 compact-image files compare exactly against
the retained inputs. All 360 external oracle level/payload pairs retain their
inventory, sizes and captured-byte hashes. The review report is
`artifacts/lzx-fixture-review/report.json`, with launcher log
`artifacts/plan-lzx-fixture-review.log`.

The expanded WOF/XPRESS/LZX campaign completed 1,122,244 executions in 61 seconds,
coverage 691, feature count 2,392 and peak RSS 466 MiB. The image campaign completed
45,986 executions in 61 seconds, coverage 3,749, feature count 14,573 and peak RSS
982 MiB. Both exit zero without a reported crash/sanitizer finding, under
`artifacts/fuzz-lzx-{wof,image}/` and `artifacts/plan-lzx-fuzz-{wof,image}.log`.
Image RSS approaches the separate 1-GiB runner cap and includes corpus/sanitizer
overhead; it does not describe driver allocations. Sustained Windows-seeded
campaigns, native provider faults/interleavings/hard links, authorization and
measured performance remain requirements.

The preceding WOF file-provider continuation passed all 35 sanitized C suites, both
freestanding targets with the 2-KiB frame limit, selected Xcode style, the legacy
component and current unsigned app/extension build. Twenty-eight independently
authored storage/format verdicts check exact bytes, raw/XPRESS4K/8K/16K chunks,
partial/exact/empty files, fragmented/resident/listed backing, placeholder VDL,
multi-page tables, unsupported codecs, malformed metadata and stale ownership.
All 216 required allocation and 68 read failures in the selected stat/open/cold
content operations pass with retry, guards, unchanged images and exact cleanup.
Source-node-independent streams keep unmount BUSY until released. Failure in a
later unit may retain a correctly completed core prefix; failed private unit
contents and cache tags are never published.

Fourteen legacy FSKit provider cases check ordinary-file classification,
requested sizes and content, metadata-only LZX/encryption, independent ADS,
original-wire reparse/full reverse-manifest oracles, hidden backing aliases,
table/codec errors, remount, permanent revocation and exactly-once replies.
Six macOS-27 checks explicitly SKIP. Core and app/component compilation do not
establish installed provider operations, native authorization or Windows codec
compatibility. Evidence uses `artifacts/plan-wof-files-core-final.log`,
`plan-wof-files-freestanding-reviewed.log`, `plan-wof-files-style-final.log`,
`plan-wof-files-component-accepted.log` and `plan-wof-files-app-accepted.log`.
Initial logs retain the independent page-allocation expectation error and older
opaque reparse rejection assertions; the component's first new test also assumed
a byte-count getter absent from the SDK. Original corruption/retry checks remain
enforced after those test corrections.

The image campaign now reads first/middle/tail default-stream positions. It
completed 47,555 executions in 61 seconds, coverage 3,536, feature count 13,962
and peak RSS 958 MiB, exit zero without a reported sanitizer/crash finding.
Evidence uses `artifacts/fuzz-wof-files-image/` and
`artifacts/plan-wof-files-fuzz-image.log`. That near-cap process RSS includes
corpus/sanitizer overhead and is distinct from bounded core allocations. This is
synthetic core coverage, not Foundation/installed/Windows provider qualification.
[WOF.md](WOF.md) preserves LZX, native fault/interleaving expansion, Windows samples,
authorization and measured provider-performance requirements.

The subsequent naming/comment review preserved all 112 WOF image/data/reparse/
manifest files in each 8-MiB and 1-MiB geometry; the 28 compact images also match
the campaign corpus. Evidence uses `artifacts/plan-wof-files-fixture-final.log`
and `artifacts/wof-files-fixture-review/report.json`. The initial comparison log
is retained separately: that checker first looked for sidecars in the image-only
corpus before comparing them with the complete per-run seed directory.

The preceding WOF primitive continuation passed all 34 sanitized C suites,
both freestanding targets with the 2-KiB frame limit, selected Xcode style, legacy FSKit component
and current unsigned app/extension build. Its standalone decoder has 87 exact-byte
vectors and 11 explicit invalid vectors covering short/maximal codes, lookahead
boundaries, raw length extensions, distance-bit classes, overlapping copies,
optional EOF/nonzero padding, truncations and scratch/output guards. Provider/table
checks cover observed framing, unknown/future shapes, raw/packed/final spans,
duplicate/descending offsets, work caps and widths below/at/above 4 GiB.
Six modern runtime checks explicitly SKIP; no installed mount or Windows codec ran.
Evidence uses `artifacts/plan-wof-{core,freestanding,style,component,app}-final.log`.

The dedicated WOF/XPRESS campaign completed 3,079,633 executions in 61 seconds,
coverage 360, feature count 1,129 and reported peak RSS 479 MiB. It exited zero
without a reported crash or sanitizer finding, under `artifacts/fuzz-wof-primitives/`
with launcher log `artifacts/plan-wof-fuzz-final.log`. Provider/table envelopes and
independent codec blocks are exercised without media I/O. This bounded synthetic
campaign did not establish Windows format/codec compatibility or integrated
provider reads. The public reparse read guard was still closed at that checkpoint.

The preceding native-link continuation passes all 32 sanitized core suites, both
freestanding targets, selected Xcode style, the expanded FSKit component and the
current unsigned app/extension. Forty-seven independently authored path/storage
verdicts cover explicit drive/GUID ownership, relative/rooted/dangling targets,
case policy, aliases/DOS names, nested paths, junctions, path/component/shared-scan
equality/exhaustion and explicit unsupported/corrupt cases. Real legacy callbacks
check requested attributes and names-only inventory, original-wire xattrs,
raw-data rejection, cached targets, remount/revocation and exactly-once replies.

Four native sweeps cover listed lookup 32 allocation/eight read positions, listed
metadata reopening eight/three, reserved-name lookup 36/six and resident metadata
reopening three/zero: 79 allocation and 17 read positions in total, with retry,
unchanged input and zero leaked core allocations. Names-only enumeration now
classifies checked node/reparse metadata rather than stale index attributes; its
existing nested operation covers 33 allocation/13 read positions. Six modern
checks explicitly SKIP: lifecycle, enumeration, content metadata, link projection
and two case-policy checks. Logs are
`artifacts/plan-links-{core-reviewed,component-reviewed,freestanding,style,app-build}.log`.
Earlier successful baseline/expanded logs are retained separately.
After replacing fixture instance/VCN literals with named constants, final core,
component, style and app checks passed under
`artifacts/plan-links-{core,component,style,app}-final.log`. All 47 regenerated
images and their expectation manifest remained byte-identical; Python syntax
and hash evidence is in `artifacts/plan-links-fixture-final.log`.

The bounded image campaign completed 49,163 executions in 61 seconds, coverage
3,059, feature count 12,423 and peak RSS 940 MiB. The reparse campaign completed
15,253,435 executions in 61 seconds, coverage 111, feature count 150 and peak RSS
508 MiB. Both exited zero without a reported crash or sanitizer finding; reports
are under `artifacts/fuzz-native-links-{image,reparse}/` and launcher logs under
`artifacts/plan-links-{image,reparse}-fuzz.log`. Image process RSS approached the
separate 1-GiB runner cap; this includes corpus/sanitizer overhead and is not a
native driver-memory measurement. The image campaign exercises core snapshot
copies, not the Foundation target translator.

[LINK-POLICY.md](LINK-POLICY.md) defines the implemented subset. Intermediate
reparse chains, multiply linked reparse objects and cross-volume mappings remain
explicitly unsupported. Native path walking/loops/normalization, Windows-authored
targets, macOS 27 runtime and authorization remain unqualified. No installation,
mount or Windows acquisition ran.

The preceding metadata/content continuation passes all 32 sanitized core suites,
both freestanding compilation targets, the expanded FSKit component, selected
Xcode style and the current unsigned app/extension build. Regular-file stat now
validates the complete unnamed-stream mapping independently of content decoding,
without reading data or copying resident payloads. Its 18 metadata verdicts cover
encrypted data, unknown compression format, unsupported unit geometry, empty
encrypted data, resident/nonresident attribute lists and malformed/stale mappings.
All 29 allocation/four read failure positions return explicit errors and permit
complete retry; independent ADS, unchanged input and exact cleanup also pass.

The legacy FSKit component checks six encoded-stream storage variants and ten
explicit metadata/reparse rejections. Requested-attribute pages retain truthful
sizes, names-only pages retain the objects, and a failed attribute entry remains
pending on retry. Default reads return ENOTSUP with zero bytes and unchanged
sentinel data; independent plaintext ADS remain readable. Remount, permanent
revocation, exactly-once replies and absence of default-content I/O also pass.
The existing alias fault sweep now needs 16 allocations/six reads; name manifests
retain 13/five. Five modern checks explicitly SKIP: lifecycle, enumeration,
content metadata and two case-policy checks. Both protocol sources and the Swift
bridge compile, but no installed mount or Windows-authored EFS/compression check
ran. Reparse/provider projection and full authorization remain open.

Evidence is `artifacts/plan-stat-{core-accepted,component-reviewed,style-reviewed,app-build}.log`
and `artifacts/plan-stat-freestanding.log`. Earlier component failures remain in
`plan-stat-{component-initial,component-diagnostic,component-cookie-diagnostic}.log`:
the new fixture reused a neighboring file's continuation record and correctly
triggered ESTALE. The fixture now reserves an unused MFT slot, while the complete
directory/continuation assertions remain enforced.

The updated mapping-pair target completed 3,469,071 executions in 61 seconds,
coverage 675, feature count 1,784 and peak RSS 502 MiB. The attribute-list target
completed 170,108 executions in 61 seconds, coverage 473, feature count 848 and
peak RSS 405 MiB. Both exited zero without a crash or sanitizer finding, under
`artifacts/fuzz-stat-mapping/` and `artifacts/fuzz-stat-list/`, with launcher logs
`artifacts/plan-stat-fuzz-{mapping,list}.log`. Metadata-only read guards and size
resolution are exercised separately from strict stream opening. These bounded
synthetic campaigns do not establish Windows compatibility or complete coverage.

The lifecycle adapter continuation passes eight semaphore-gated read scenarios,
interleaved enumeration with empty packer rewinds, existing namespace allocation/
I/O sweeps, selected-toolchain style and the current unsigned Debug app/extension
build. Unmount now closes admission before waiting for the serialized read, clears
transient caches and preserves nodes for reclaim. Deactivation is terminal;
revocation rejects a late successful device return. Replies are checked exactly
once, including overlapping unmount/deactivation and inspection from another
thread. Three explicit macOS-27 runtime SKIPs remain: one lifecycle suite and two
case-policy checks. Evidence uses `artifacts/plan-lifecycle-{component-reviewed,style,app-build}.log`.
The portable core did not change and its preceding qualification was not rerun.
Synchronous read interruption/deadlines, task cancellation, native conditional
reclaim qualification and installed scheduling/buffer lifetime remain open; see
[LIFECYCLE.md](LIFECYCLE.md).

The subsequent item-ownership continuation passes the sanitized component,
selected-toolchain style and current unsigned Debug app/extension build under
`artifacts/plan-reclaim-{component-reviewed,style,app-build}.log`. The weak canonical
index and retained item owner preserve identity on deferred reclaim and release
the volume without a cycle when its last item disappears. Five modeled cases
check conditional cleanup and lookup replies racing reclaim, unmount and
deactivation while another thread can inspect core state. Both protocol classes
compile; the same three macOS-27 runtime checks explicitly SKIP. The model does
not execute native kernel/framework counts, and no installed mount ran. Core
source is unchanged and its preceding 31-suite evidence was not rerun.

The subsequent directory-view checkpoint passes all 31 sanitized core suites,
the expanded FSKit component, selected-toolchain style and the current unsigned
app/extension build. Names-only enumeration includes virtual current/parent
entries with correct root/nested IDs while attribute-requested pages omit them.
Separate cookie views preserve disk-visible alias ordinals and reject wrong-view,
bad-verifier, out-of-range and past-EOF continuations with the native cookie error.
The component checks parent FSItem release and child remount, two corrupt parent
edges, empty/interleaved buffers, scan exhaustion and post-packer revocation.
The nested-index sweep covers all 12 allocation/four read positions with exactly
one reply, rewind retry, unchanged input and zero leaked core allocations.
Four macOS-27 runtime checks explicitly SKIP: lifecycle, enumeration and two
case-policy checks. Evidence is
`artifacts/plan-enumeration-{core-tests,component-accepted,style,app-build}.log`.
Earlier failed component attempts remain in
`plan-enumeration-{component-reviewed,component-final,component-lifetime-reviewed}.log`:
the extracted test module lacked an import and its combined weak-observer
declaration retained the parent. Both test defects were fixed with the ownership
assertion preserved. No installed mount, native reclaim-count or Windows check
ran, and unsupported-object attribute pages remain open. LIFECYCLE.md records
the implemented contract and its limits.

The preceding consistency diagnostic checkpoint passes all 31 sanitized suites, both
freestanding targets, selected-toolchain style and the current unsigned Debug
app build. Legacy FSKit components passed with two explicit macOS-27 runtime
SKIPs; the new diagnostic has no FSKit runtime entry point. Its 57 complete
metadata fixtures cover positive storage variants, damaged links/lists/bitmaps,
cycles, physical overlaps and explicit unsupported cases. Four fault sweeps cover
112/84, 137/88, 138/89 and 121/85 allocation/read positions, with retry, unchanged
input, exact release sizes and zero leaked allocations. Tests also check all
seven budget dimensions, API misuse, boundary equality, an independent existing
live mount and refusal to read physical bad sectors.

The independent diagnostic compares both standalone NTFS-3G bitmap exports
against full core inventories in four geometries. Each image has 119 active MFT
records; allocated cluster counts are 4,706, 1,179, 1,308 and 82 in sector/cluster
profiles 512/1024, 512/4096, 4096/4096 and 512/65536 respectively. Every diagnostic
was complete and every image hash unchanged. Final evidence is
`artifacts/interoperability-validation-final/report.json` and
`artifacts/plan-validation-final-oracle.log`. Initial failed oracle reports remain
under `interoperability-validation-{initial,reviewed,system}`: they exposed the
uninterpreted record flag, special bad-cluster mapping and preinitialized reserved
record templates. None was silently skipped or counted as a pass.

After final root-anchor/duplicate-stream review, the dedicated validation fuzz
campaign completed 47,096 executions in 61 seconds, coverage 3,065, feature count
8,505 and peak RSS 609 MiB, exit zero with no crash or sanitizer finding. Evidence
is under `artifacts/fuzz-validation-reviewed/` and
`artifacts/plan-validation-final-fuzz.log`; the earlier successful campaign is
preserved separately under `artifacts/fuzz-validation/`. Final build/tests/style/
freestanding/app logs use `artifacts/plan-validation-final-*.log`; applicable
component evidence is `artifacts/plan-validation-fskit.log`. Python syntax checks
passed for 30 files under `artifacts/plan-validation-python.log`. These bounded
local campaigns and independent mkntfs layouts do not qualify Windows/native
behavior. [VALIDATION.md](VALIDATION.md) defines complete-verdict scope and gaps.

The original core handoff passed eleven suites: primitives/lifecycle on five filesystem layouts,
stream boundaries, decoder vectors, reparse metadata, image contracts,
deterministic fuzz smoke and build-environment isolation. The image suite checks
nine file hashes across all five layouts, ordering, case folding, ADS, four damaged
images and 31 additional format/continuation/rejection cases. Unsupported and corrupt
inputs passing their rejection tests do not establish support for those layouts.

An earlier no-VM checkpoint passed 23 sanitized suites, including six standalone
parser mutation targets, corpus/workload contracts, metadata-cache fault/retry
checks, security descriptor vectors and its standalone mutation target. Evidence
is retained in `artifacts/plan-security-tests.log`. After reviewing reparse presence,
all 22 suites, freestanding targets, formatting and the direct FSKit component
passed again under `artifacts/plan-reparse-presence-*.log`. The reparse suite now
includes 26 image contracts: base attributes omitted from a list and invalid named
reparse attributes cannot become ordinary data after clearing the flag. Permanent
revocation still precedes cached operations.

Seven 30-second campaigns (image and the six original standalone parsers) passed
under `artifacts/fuzz-parser-foundation/`. The new security target completed
10,147,598 executions in 61 seconds with reported peak RSS 520 MiB and no crash or
sanitizer finding, retained under `artifacts/fuzz-security-descriptor/`. These are
bounded campaigns, not exhaustive hostile-media or Windows compatibility proof.
The foundation campaigns precede metadata reuse. Subsequent image campaigns passed
55,504 executions after reuse and 53,473 after the reviewed presence fix, each in
61 seconds, under `artifacts/fuzz-verified-metadata/` and
`artifacts/fuzz-reparse-presence/`. The latter reported peak RSS 613 MiB and no
crash or sanitizer finding. The current unsigned app and extension also built
after that fix (`artifacts/plan-guard-app-build.log`); neither was installed.

The stream catalog and native xattr projection subsequently passed all 23 suites,
freestanding targets, expanded component tests, style and the current unsigned
app build under `artifacts/plan-ads-*.log`. The catalog suite covers fourteen
inventories/rejections and 28 allocation/one I/O failure positions. Five adapter
scenarios cover native stream manifests, exact UTF-16, bounded responses, retry
and revocation. Image fuzzing completed 55,509 executions in 61 seconds with peak
RSS 682 MiB and no reported finding under `artifacts/fuzz-stream-catalog/`.
Four independent image geometries subsequently passed 100 file-byte oracles each,
ADS bytes, exact stream inventories, case folding and unchanged image hashes
under `artifacts/interoperability-stream-catalog/` and
`artifacts/plan-ads-oracle.log`. Windows acceptance remains unrun.
NATIVE-NAMESPACE.md defines the format and its remaining limits.

Native filename projection subsequently passed all 23 suites after fixture
changes (`artifacts/plan-names-budget-tests.log`), current component fault/budget
checks, style and the unsigned app (`artifacts/plan-names-verified-*.log`). Five
namespace images include twelve hard links and a 2,000-link tree. Required name
manifest allocations/I/O passed 13/five failure positions; alias lookup passed
17/six, with exactly-once failure replies, retry and zero tracked allocation
leaks. Initial cache-insertion fault-test diagnosis is retained and explained in
NATIVE-NAMESPACE.md. This is component acceptance, not installed namespace proof.

Security storage subsequently passed all 24 sanitized suites, both freestanding
targets, style, the existing FSKit component and unsigned app under
`artifacts/plan-secure-observed-*.log`. Final review improved the collision fixture
to use distinct descriptor bytes and owner SIDs with one checksum, then repeated
all 24 suites and style under `artifacts/plan-secure-collision-*.log`. The current
suite covers 74 contracts and 262 allocation/191 I/O failure positions, retry,
unchanged failure outputs and exact release. It includes resident/external view indexes, hash collisions,
ancestor bounds, cycles/depth, bitmap/MST/USA, maximum descriptors, later SDS
pairs and resident/nonresident/listed per-file attributes. No default file data
is opened to inspect its security metadata.

The independent comparison checks 24 original descriptor-byte/ID observations
in four existing image geometries, with unchanged images, under
`artifacts/interoperability-secure3/` and `artifacts/plan-secure-oracle3.log`.
Earlier failed comparisons remain under `interoperability-secure/` and
`interoperability-secure2/`: real per-file and nonresident descriptor storage
exposed incorrect assumptions in the old format notes. They are failures, not
successful runs. The initial build rename error and authored allocation-size
fixture error are also retained in the earlier `plan-secure-*` logs.
The first updated image fuzz campaign completed 43,226 executions in 61 seconds,
reported coverage 3,005 and peak RSS 918 MiB under
`artifacts/fuzz-secure-resolver/`. After improving the collision fixture, a new
campaign completed 47,915 executions in 61 seconds with coverage 2,987 and peak
RSS 901 MiB under `artifacts/fuzz-secure-collision/`. Neither reported a finding;
coverage values from separate bounded campaigns are not monotonic. Process RSS includes libFuzzer's retained
image corpus; the separate core allocation budget remains 8 MiB. This is bounded
local evidence, not Windows or installed authorization acceptance. SECURITY.md
defines source selection, supported bounds and remaining security contracts.

The discretionary evaluator subsequently passed all 26 sanitized suites,
freestanding targets, style, FSKit components and unsigned source app build under
`artifacts/plan-access-observed-*.log`. Its suite covers 196,809 decisions, including
196,608 independent per-right ordered token oracles. Final review replaced its
SACL vector with a real high-integrity SID and NO_READ_UP, then repeated the
affected build/test/style under `artifacts/plan-access-review-*.log`. That vector
proves the DACL-only boundary, not integrity enforcement. Final named-constant
and seed cleanup passed all 26 suites and style again under
`artifacts/plan-access-final-*.log`. Snapshot evaluation
survives node close and performs no allocation/I/O under forced next-call faults.
An earlier focused failure remains in `plan-access-focused.log`: the test
incorrectly assumed ownership implied FILE_READ_DATA for the genuine collision
descriptor. Corrected expectations distinguish implicit owner control rights
from the original DACL trustee; no core grant policy was changed to pass it.

The separate descriptor/token campaign completed 14,450,666 executions in
61 seconds with coverage 436 and peak RSS 489 MiB, exit zero and no reported
finding under `artifacts/fuzz-access-context/`. No Windows AccessCheck or installed
native authorization was exercised. ACCESS.md defines exact masks, feature
rejection, shared comparison budgets and the remaining restricted-owner,
advanced-ACE, SACL/integrity/privilege, identity and native operation contracts.

The independent AccessCheck pipeline subsequently passed all 27 ASan/UBSan
suites, both freestanding targets, selected-toolchain style, FSKit components and
the unsigned current-source app build under `artifacts/plan-access-oracle-observed-*.log`.
The new suite passed 337 contracts covering original SID/descriptor transport,
SDK pointer/count bounds, token-copy rights and requested transformations,
cleanup after acquisition failures, partial manifests, original-byte checks,
missing/tampered vectors, API failure versus denial, output budgets and deadlines.
The intentionally coarse fake provider produces both matching and mismatching
decisions and cannot claim Windows provenance or native qualification.

Standalone SID decoding is allocation-free, preserves the full six-byte
authority/15-subauthority range, rejects trailing storage and zeroes errors.
Native SDK-shaped buffers and SID packets are authored independently. The
expanded security fuzz corpus includes standalone SID packets and completed
8,949,047 executions in 61 seconds with coverage 172, peak RSS 526 MiB and no
reported finding under `artifacts/fuzz-access-oracle-sid/`. This bounded run is
local robustness evidence. No Windows AccessCheck acquisition, filesystem access,
installed mount or complete authorization was exercised. ACCESS-ORACLE.md defines
the capture/comparison commands, scope, bounds and unresolved probes.

A retained synthetic review is available in
`artifacts/access-oracle-synthetic-capture/manifest.json` and
`artifacts/access-oracle-synthetic-review/report.json`. Its six contexts/144 cases
produce 65 matches, 52 deliberate mismatches, 21 unsupported cases and six
out-of-plane observations. The report remains `gaps`, the input is unchanged,
and both native DACL/full-authorization qualification flags remain false. This
example demonstrates reporting behavior, not Windows access results.

Before/after release matrices each retain 400 measurements, independent full
stream-byte oracles and unchanged input hashes. Metadata reuse removes repeated
presence-validation allocations and improves the measured open/lookup profiles;
data-read changes are mixed. PERFORMANCE.md records exact scope, counts and
remaining optimization requirements. CORE-QUALIFICATION.md retains every agreed
functional and optimization deliverable without treating this checkpoint as
completion of the full continuation.

The subsequent directory-case checkpoint passed all 28 ASan/UBSan suites,
both 2-KiB-frame freestanding targets, selected Xcode formatting, legacy FSKit
components and the unsigned app/extension build. Seventeen authored images cover
exact ASCII/Unicode case collisions across tree boundaries, resident/external/
nested/listed indexes, cache controls, mixed parents, standard-information sizes,
legacy/storage/unknown policy fields and corrupt/stale records. Forty-seven
required-allocation and eight I/O failure positions verify release accounting
and retry. The sensitive namespace component preserves hard-link manifests and
rejects noncanonical aliases; mixed parents preserve distinct file identities,
folded canonical names, directory enumeration and cached-operation revocation.
Corpus contracts compare native policy observations with core stat and preserve
unknown/missing observations as failures/gaps. Their observations remain synthetic.

The modern case-reply test compiles but emits two explicit SKIPs on this macOS
26 runtime; no macOS 27 callback behavior was executed. Its guarded opaque context
double tests reply framing only, never native authorization. The initial component
compile failure is retained in `artifacts/plan-case-policy-fskit.log`; the corrected
successful run is `artifacts/plan-case-policy-fskit-final.log`. Other evidence is
`artifacts/plan-case-policy-{build,tests,freestanding,style,app-build,fuzz}.log`.
Final test review named expected-name indices and checked mixed-directory
references; the focused suite and style passed again under
`artifacts/plan-case-policy-test-review{,-build}.log` and
`artifacts/plan-case-policy-style-final.log`, without changing core/adapter code.
Image fuzz completed 43,409 executions in 61 seconds with peak RSS 906 MiB and no
reported finding under `artifacts/fuzz-case-policy/`. This bounded campaign does
not establish exhaustive hostile-input coverage. CASE-POLICY.md retains the
format provenance, volume-wide Sensitive capability strategy and required
Windows/installed cache acceptance. Neither native acquisition nor a mount ran.

| Fault sweep layout | Allocation failure positions | I/O failure positions |
| --- | ---: | ---: |
| Standard | 249 | 41 |
| NTFS 3.0 common FILE header | 249 | 41 |
| Fragmented MFT, resident list | 254 | 43 |
| Fragmented MFT, nonresident list | 254 | 44 |
| Nested directory index | 259 | 51 |

The fragmented MFT fixtures require an extension found through one decoded prefix
to reveal the location of the next extension. The original contiguous MFT is
erased. Index fixtures cover parent and ancestor bound violations, duplicates and
case collisions split across a separator and child. Stream tests compare mixed
compressed/raw/hole/final units, invalidate a compressed cache fill on injected
I/O failure and verify sparse/VDL zeros without device reads. Decoder vectors
cover every token length/displacement split and short/overlong output buffers.
NTFS 3.0 acceptance here covers synthetic common-header records; no Windows 2000
authored corpus has been tested.

The reparse suite adds standalone decoder vectors and 26 image contracts.
It checks resident, fragmented nonresident and attribute-list storage, targets
whose print and substitute names appear in either order, unpaired surrogate
preservation, capacity checks before copying, source-node closure and BUSY unmount.
Decoder vectors cover truncation, exact framing, reserved fields, overlapping
strings without terminators, embedded NULs, offset alignment/ranges, every cloud
tag variant, future flags and GUID-envelope rejection. WOF/cloud/unknown tag tests
validate framing and classification only. They do not validate provider payloads
or establish file-content support. Opening a junction on a non-directory is corrupt.

The suite sweeps 45 snapshot-allocation and six snapshot-I/O failure positions and
verifies exact release accounting. Ordinary stream reads and directory traversal
refuse reparse nodes, including a junction with a plausible local index. A cleared
standard-information flag with an existing reparse attribute returns CORRUPT for
both base-record and listed-extension storage. The inspector's `reparse` command
reports tags, link flags and UTF-16 code units without following targets.

The external suite used separately built NTFS-3G utilities to create four regular
64-MiB images and write 100 files per image. It compared file bytes with both
independent expected content and ntfscat, exercised Unicode names, case folding,
external directory indexes and ADS, and verified every image remained unchanged.
NTFS-3G is an external test oracle; no NTFS-3G library is linked into the driver.

Generated local evidence is under ignored paths:

- `artifacts/core-ready-test.log`, `core-ready-style.log` and
  `core-ready-compile.log`.
- `artifacts/core-ready-fskit-build.log` and `core-ready-fskit-component.log`.
- `artifacts/interoperability-core-ready/report.json` and `commands.log`.
- `artifacts/core-ready-fuzz.log` and `core-ready-compact-images.log`.
- `artifacts/core-ready-release.log` and `benchmark-core-ready.json`.
- `.build/meson-logs/testlog.json` contains individual sanitized test results.
- `artifacts/core-reparse-*.log` and `core-reparse-final-*.log` record the core
  continuation, selected compiler checks, adapter component tests and fuzz runs.
- `artifacts/interoperability-reparse/report.json` and `commands.log` record the
  repeated independent four-geometry oracle after the metadata guards changed.

The continuation also passed the adapter component tests after adding a permanent
revocation latch. Cached resident and compressed reads, metadata, lookup and
enumeration fail once the resource is revoked; reclaim and teardown remain usable
without further device I/O. The signed Release app and embedded extension passed
strict deep signature verification. This does not verify installation, enabled
module state or a provisioning profile authorizing the test guest. Evidence is in
`artifacts/native-revocation-*.log`, `artifacts/native-signing-build2.log` and
`artifacts/native-signing/`.

An independent `ntfs-fskit-stock-26` guest was cloned and left stopped. Its first
boot was blocked by the macOS concurrent-VM limit while both slots belonged to
other tasks. No existing VM was stopped or modified. The user subsequently
redirected continuation to the core; native acceptance is deferred. Generated
ownership and boot evidence remain in the lab's `artifacts/ntfs-fskit/` directory.

The initial fuzz build with Xcode could not link because that distribution lacks
the libFuzzer runtime. It executed no fuzz inputs. The successful run used the
explicit LLVM compiler override documented in DEVELOPMENT.md.

A subsequent attempt with the accumulated full-image corpus hit the 1-GiB process
RSS limit. The allocation report attributed 88% of live heap bytes to libFuzzer's
retained corpus; the core allocator remained bounded. Preserve this failed run
as `artifacts/core-handoff-fuzz.log`. The runner now authors 1-MiB physical images
covering all fixture payloads, retaining the larger logical sparse streams. It
uses a separate corpus and keeps the original seeds and failure evidence. The
ordinary 8-MiB fixture suite remains unchanged in physical geometry. The same
image contracts pass on all five compact seed layouts as well.

At the original core handoff, the compact fuzz run completed 171,809 executions in
121 seconds without a reported crash, timeout, OOM or sanitizer finding. Final
process RSS was 552 MiB; the retained corpus had 184 entries. This bounded run does
not establish complete coverage or production security. The final release benchmark and Python syntax
checks also passed. Performance numbers describe a warm POSIX image only; see
PERFORMANCE.md for the workload and limits.

The reparse continuation passed all eleven suites, both freestanding compilation
targets and the in-process FSKit component tests. A repeated independent oracle
again compared 100 files in each of four geometries and preserved the image hashes.
After final GUID-envelope review, the bounded fuzz run completed 90,737 executions
in 61 seconds without a reported crash, timeout, OOM or sanitizer finding. Final
RSS was 609 MiB; the retained corpus had 234 entries occupying 164 MiB. Raw reparse
buffers accompany full images so the decoder receives direct mutation coverage.
This remains bounded local evidence; Windows-authored reparse points, provider
data formats and installed native behavior have not been qualified. The inspector
also preserved an unpaired surrogate as `d800 0078`; changed Python files passed
syntax compilation.

The current unsigned Debug app and extension also built with the new C API and
source module, including the Swift bridge and both FSKit protocol implementations.
This is compilation evidence, not installation or runtime acceptance; see
`artifacts/core-reparse-fskit-build.log`.

Keep source revisions in Git and generated artifact identities in reports.
Review selected report fields; do not dump unfiltered legacy Meson reports.

During MFT bootstrap, each extension must be reachable through the decoded MFT
prefix. Attribute-list streams must be fully addressable from their base record.
NTFS compression supports the ordinary 16-cluster unit with clusters up to 4 KiB;
larger compressed units are rejected.
Unpaired, oversized and reserved filenames now have bounded native aliases and
UTF-16 reverse manifests, qualified by component tests; installed projection and
native normalization remain untested. Dirty or otherwise flagged volumes are
refused without recovery. The mirror check covers MFT bootstrap record zero;
mount is not a full filesystem consistency check. Case-sensitive directories use
exact UTF-16 lookup; collisions in an insensitive directory remain UNSUPPORTED.
Windows/native case-policy and full WSL/POSIX namespace qualification remain open.
Stream names use exact UTF-16 matching. The
adapter uses a single-user read-only mode/UID/GID presentation; it projects the
supported link and WOF subsets but does not enforce Windows ACLs.
Regular encoded files with supported metadata framing now retain requested
attributes and independent ADS; their default content remains unsupported.
Directory enumeration requesting attributes still fails explicitly on unsupported
provider/link objects, unknown flag families and malformed metadata, without consuming the failed
entry or reporting invented sizes.
Names-only virtual dot/parent entries and native invalid-cookie errors now pass
component checks, with view-specific cookies and stable stored alias ordinals.
Exact native dot lookup now uses checked ancestry and can reconstruct released
parents by full reference. Installed interpretation remains separate acceptance
work; LIFECYCLE.md records the SDK contracts and remaining gaps.
Named streams now have a bounded read-only xattr projection and reverse manifest
in both FSKit protocol paths, qualified only by component/build tests. Reparse and
unknown/malformed metadata can still prevent item adoption; installed projection
remains untested. Per-volume operations are serialized, with a 64-MiB core memory
budget and 16,384 live FSItem limit. No read/write claim may omit these limits.
