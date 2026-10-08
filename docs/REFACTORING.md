# Driver refactoring

The agreed driver refactoring is complete. Reading, mutation construction,
journal/recovery, security, diagnostics and native FSKit responsibilities have
explicit components and consistent private helper and owner names. The final
batch audits every production C and Objective-C translation unit and retains the
existing Swift application, command and extension boundaries. Public interfaces,
wire layouts and supported operations retain their original contracts.

This closes the structural/style work. Remaining product and recovery gates are
tracked in [ACCEPTANCE.md](ACCEPTANCE.md) and [WRITES.md](WRITES.md). Source history
belongs to ordinary Git; exact build and artifact identities belong to generated
reports.

## Completion batch

The last connected batch follows the accepted ordinary-image implementation and
native-source growth recovery. Its finite plan is complete:

1. Review all 76 C core files and their 818 functions, including mount/bootstrap,
   metadata, streams/codecs, security and diagnostic admission.
2. Regularize the remaining private names in both reading and writing: 212
   helpers, 168 parameter/local declarations and 27 private structure tags.
   Declaration-bound edits preserve their exact uses and leave member fields intact.
3. Apply matching ownership conventions to all 14 FSKit implementation files and
   both POSIX transports. Preserve selectors, locks, authenticated context, reader
   leases, replies and error order. Review the three unchanged Swift sources and
   existing public/private headers at their current boundaries.
4. Consolidate the two identical native manifest byte encoders into the private
   [NTFSWireBytes.h](../adapters/fskit/NTFSWireBytes.h). The helper preserves the
   complete original body, byte order and caller-specific admission.
5. Review complete ordered source tokens, compile both architectures, then run the
   complete connected local regression and current-code native components once.

Short loop indices and bit-decoder arithmetic names remain local and clear.
Complete owning operations retain their boundaries; function size alone does not
justify moving validation, lifetime or error handling elsewhere.

## Applied cleanup

The component map incorporates the preceding accepted extractions and the final
driver-wide naming audit. Files within a row cooperate under the same existing
owner; a private component does not introduce a second allocator or governor.

| Responsibility | Owning components and preserved boundary |
| --- | --- |
| Byte primitives and format decoding | [memory.c](../core/memory.c) (added by the subsequent CPU optimization batch) owns bounded copies, zeroing, comparisons and LZ expansion; [support.c](../core/support.c) retains wire integers, allocator/I/O helpers and diagnostics. Execution-context selection stays outside filesystem admission. |
| Admission and immutable metadata | [api.c](../core/api.c), [mount.c](../core/mount.c), [record.c](../core/record.c), [attribute.c](../core/attribute.c), [node.c](../core/node.c), [catalog.c](../core/catalog.c): public admission, complete reachable-prefix bootstrap, sequence/instance checks and borrowed attribute lifetime. |
| Stream content | [stream.c](../core/stream.c), [stream_mapping.c](../core/stream_mapping.c), [stream_read.c](../core/stream_read.c), [wof_stream.c](../core/wof_stream.c): construction/release, mapping pairs, run lookup, sparse/VDL reads and provider-owned decoding/cache lifetime. |
| Names, indexes and links | [directory.c](../core/directory.c), [index.c](../core/index.c), [links.c](../core/links.c), [reparse.c](../core/reparse.c), [unicode.c](../core/unicode.c): persistent filename cursors, physical allocation inventory, original link provenance and Unicode collation. |
| Security | [security.c](../core/security.c), [access.c](../core/access.c), [secure.c](../core/secure.c), [secure_index.c](../core/secure_index.c), [secure_store.c](../core/secure_store.c): wire decoding, ordered DACL evaluation, descriptor/snapshot ownership, SII/SDH traversal and whole-store validation. |
| Whole-volume diagnostics | [validate.c](../core/validate.c), [validate_records.c](../core/validate_records.c), [validate_namespace.c](../core/validate_namespace.c), [validate_media.c](../core/validate_media.c), [validate_security.c](../core/validate_security.c): one context/accounting owner, complete ordered passes and bounded partial reports. |
| Immutable journal acquisition | [logfile_source.c](../core/logfile_source.c), [logfile_pages.c](../core/logfile_pages.c), [logfile_index.c](../core/logfile_index.c), [logfile_records.c](../core/logfile_records.c): source lifetime, protected-page routing, retained indexing and complete record/history/capture. |
| Mutation storage | [write_record.c](../core/write_record.c), [write_attribute.c](../core/write_attribute.c), [write_stream.c](../core/write_stream.c), [write_directory.c](../core/write_directory.c), [write_directory_store.c](../core/write_directory_store.c): FILE ownership, attributes/streams, directory keys and complete index construction under one mutation plan. |
| Mutation planning | [write_namespace.c](../core/write_namespace.c), [write_allocation.c](../core/write_allocation.c), [write_growth.c](../core/write_growth.c), [write_mutation.c](../core/write_mutation.c), [write_mutation_owner.c](../core/write_mutation_owner.c): namespace, allocation/growth and complete owner preview/execution. |
| Program, journal and execution | [write_program.c](../core/write_program.c), [write_program_packets.c](../core/write_program_packets.c), [write_metadata.c](../core/write_metadata.c), [write_journal.c](../core/write_journal.c), [write_replay.c](../core/write_replay.c), [write_transaction.c](../core/write_transaction.c), [write_execute.c](../core/write_execute.c): retained payloads, compensation/original bindings, complete preparation and ordered physical execution. |
| Retained recovery and reuse | [write_history.c](../core/write_history.c), [write_batch_capture.c](../core/write_batch_capture.c), [write_batch_pages.c](../core/write_batch_pages.c), [write_batch_execute.c](../core/write_batch_execute.c), [write_batch_recover.c](../core/write_batch_recover.c), [write_checkpoint.c](../core/write_checkpoint.c), [write_retirement.c](../core/write_retirement.c): original history, bounded batch storage, checkpoint/recovery and safe retirement. |
| Native volume | [NTFSVolume.m](../adapters/fskit/NTFSVolume.m), [NTFSVolumeItems.m](../adapters/fskit/NTFSVolumeItems.m), [NTFSVolumeRead.m](../adapters/fskit/NTFSVolumeRead.m), [NTFSImageVolume.m](../adapters/fskit/NTFSImageVolume.m): lifecycle/admission, canonical items/caches, complete immutable requests and complete image operations under one volume owner. |
| Native bridges and transports | [NTFSFileSystem.m](../adapters/fskit/NTFSFileSystem.m), [NTFSCheckTask.m](../adapters/fskit/NTFSCheckTask.m), [NTFSResource.m](../adapters/fskit/NTFSResource.m), [NTFSImageTransport.m](../adapters/fskit/NTFSImageTransport.m), [NTFSNames.m](../adapters/fskit/NTFSNames.m), [NTFSLinks.m](../adapters/fskit/NTFSLinks.m): probing/check tasks, native resources, authorized image ownership and name/link conversion. |
| POSIX and application | [image.c](../adapters/posix/image.c), [overwrite_image.c](../adapters/posix/overwrite_image.c), [App.swift](../adapters/fskit/App.swift), [ImageCommands.swift](../adapters/fskit/ImageCommands.swift), [NTFSExtension.swift](../adapters/fskit/NTFSExtension.swift): immutable input, exclusively claimed persistent image, UI/CLI coordination and extension entry point. |

Equivalent pointer arithmetic remains in
[pointer_range.h](../core/pointer_range.h); equivalent restored-record comparison
remains in the private metadata component. Required-pointer, empty-range,
alias/output and differing FILE comparison policies remain at their owning
boundaries. Read-only code still has no write callback.

## Concrete findings

| Finding | Completed resolution |
| --- | --- |
| Generic helpers and abbreviated object owners across old/new code | Private names describe their component, object and action; volume, attribute, restart, environment, input/output and comparison operands have explicit roles. Fields and external names retain their original contracts. |
| Combined program/mutation/read/security/diagnostic implementations | Complete operations have private component interfaces and one retained ownership/accounting boundary, as mapped above. Bootstrap and complete index storage construction retain their indivisible proofs. |
| Repeated byte helpers | Only contract-equivalent pointer arithmetic, restored-byte comparison, wire rounding and native manifest encoding are shared. Different admission and allocation rules remain explicit. |
| Native volume responsibilities | Lifecycle, items/caches, immutable reads and complete image operations are extracted with unchanged serialization, context, read leases and exactly-once replies. |
| Historical refactoring prose obscured current work | This record presents the current map, conventions and final evidence. Earlier implementation and acceptance checkpoints remain available through Git and the acceptance history. |

## Implementation order

The completed sequence was equivalent byte helpers, private writer contracts and
program composition, mutation storage, stream reading, security/diagnostic/journal
components, native volume extraction, and the final audit of the remaining core,
FSKit and POSIX names. Functional changes and their conformance tests have separate
checkpoints. This batch introduces no new NTFS semantics or write admission.

## Conventions to apply

These conventions remain the development rules after completion:

| Concern | Convention |
| --- | --- |
| Names | Private helpers identify their component and action; private core types use `ntfs_`. Use descriptive object owners and units; keep short local indices where unambiguous. |
| Inputs and owners | Distinguish immutable source capability, allocator, borrowed request and retained workspace. Preserve borrowed-buffer lifetime and exact allocation/release charges. |
| Coordinates | Keep physical/logical bytes, FILE numbers, VCNs, LCNs, UTF-16 units and bit ranges distinct; use named wire fields and constants. |
| Errors and publication | Check producer results before use, release acquired owners with their exact size and retain original failure precedence. Preserve completed/poisoned execution reports. |
| Interfaces | C owns NTFS semantics; FSKit owns native lifecycle, buffering and authorization. Keep decoding, complete planning and physical execution distinct. |
| Style | Selected-Xcode `.clang-format`, declarations at block starts, braces and one statement per line. Public naming remains stable. |
| Tests | Preserve independent byte, object, fault and lifetime oracles. Mechanical changes use source equivalence and the existing regression rather than tests that duplicate their implementation. |

## Verification and completion

The final batch passes all **202 registered C suites** with assertions and fatal
ASan/UBSan, selected-Xcode formatting, and **152 strict freestanding object builds**
across arm64/x86_64 under the 2-KiB frame ceiling. All **45 retained whole images**
are byte-identical to the accepted pre-edit baseline: 41 actual postimages and four
modeled recovery seeds. Draft frontend checks cover both architectures, all native
and POSIX sources and both changed private headers.

Host FSKit passes **64 groups**, with **13 explicit runtime SKIPs** and zero failures.
The current-source standalone component binary then passes **all 81 groups with
zero SKIPs** in the dedicated macOS 27 VM. Frozen fixture manifests and the current
binary are verified before and after. The actual unsigned Release app, both
extension copies and all 76 core archive members build for arm64/x86_64. This
build is not installed; signed build 19 and its accepted mounted/Windows scenario
retain their preceding functional baseline.

Main independently compares complete source tokens under the explicit identifier
substitutions and verifies the shared encoder against both original bodies.
All operators, literal values, public interfaces, structure members, selectors,
locking, callback/error order and policies are preserved. The initial draft
collision/token-review refusals and standalone-header fixture failure are retained;
successful frontend checks are reused, and the connected regression runs once.
A launcher argument refusal occurs before any VM command; the native stage
subsequently completes once with the corrected argument list.
Documentation links/anchors and all 28 unchanged rendered diagrams pass checks.

Evidence is under `artifacts/overwrite/refactor-completion-*20261008/`, including
the frozen baseline, declaration/source review, dual-architecture frontend,
connected local regression, current native component run and final main review.
VM commands use the CLI harness with serialized delegated ownership. No VM
lifecycle, UTM, Debian, host installation or installed native mutation is part of
this batch. New device writing, unsupported operation families and distribution
qualification retain their separate product gates.
