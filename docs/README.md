# Documentation

Start with the [NTFS format reference](format/README.md): a chaptered guide to
volume bytes, metadata relationships, journal framing and recovery, with original
diagrams, field maps, examples and a research register.

## Product and development

- [Unsigned engineering packaging](UNSIGNED-PACKAGING.md): exact build-bound
  app inventory, deterministic transport and separate release/native gates.
- [Private LZNT1 encoding](LZNT1-ENCODING.md): original bounded codec and
  independent byte/native-oracle contract, without compressed media admission.
- [Compression-unit preparation](LZNT1-UNIT-PREPARATION.md): owned normalized
  plaintext, sparse/raw/packed selection and exact cluster-padding boundaries.
- [Native XPRESS oracle](XPRESS-ORACLE.md): independent Windows raw-buffer
  observations with required packets and explicitly separate compatibility cases.

- [Dots cloud handoff](HANDOFF-DOTS.md): complete all work feasible from the
  proprietary repository and cloud runners, with observed CI failures, implementation
  priorities, verification gates, and the residual native/release boundary.
- [Architecture](ARCHITECTURE.md): component and ownership boundaries.
- [Development](DEVELOPMENT.md): prepared build/test and VM workflows.
- [Acceptance](ACCEPTANCE.md): actual evidence and remaining feature gates.
- [Write contract](WRITES.md): durability, allocation, namespace and recovery scope.
- [Portable feature map](PORTABLE-FEATURES.md): implemented capabilities, remaining
  cloud algorithms, independent native evidence and intentional policy boundaries.
- [Deferred retirement](DEFERRED-RETIREMENT.md): explicit lifetime/durability model
  for open unlink/replacement, with native orphan authority left unresolved.
- [Hard-link preparation](HARDLINK-PREPARATION.md): complete selected-cache POSIX
  link storage, private persistence/recovery qualification and general admission gates.
- [Native metadata observations](WINDOWS-METADATA.md): fresh guarded Windows
  captures separating open-handle API observations from exact stored cache bytes.
- [Sparse preparation](SPARSE-PREPARATION.md): private owned zero/punch mapping and
  partial-byte spans, preserving the unsupported media-execution boundary.
- [Completed driver refactoring](REFACTORING.md): component map, consistent
  ownership conventions and complete local/native regression evidence.
- [Current VM handoff](HANDOFF-SOL.md): execution paths and operating constraints.
- [Directory acceptance batch](DIRECTORY-ACCEPTANCE.md): prepared fuzz/stress,
  native recovery and installed FSKit phases, with execution still pending.
- [Provenance](PROVENANCE.md): sources, consulted layouts and dependency attribution.
- [CPU optimizations](PERFORMANCE.md#cpu-primitives-and-compression): compression,
  memory operations, userspace/kernel selection and measured tradeoffs.
- [Huffman decoding](PERFORMANCE.md#huffman-decoding): bounded prefix/word paths,
  differential contracts and matched XPRESS/LZX measurements.
- [Core acquisition and allocation](PERFORMANCE.md#core-acquisition-and-allocation):
  journal page/staging reuse, word-based first-fit, WOF node proofs and inline
  wire fields, with C-only acceptance separate from native testing.
- [Mutation planning and WOF reuse](PERFORMANCE.md#mutation-planning-and-cross-node-wof):
  bounded region/MFT indexes, bitmap retirement, cross-node WOF proofs and
  complete growing-write preparation measurements.

## Detailed contracts

| Area | Documents |
| --- | --- |
| Metadata and ownership | [Validation](VALIDATION.md), [operation budgets](OPERATION-BUDGETS.md), [core qualification](CORE-QUALIFICATION.md) |
| Names and native objects | [Namespace](NATIVE-NAMESPACE.md), [case policy](CASE-POLICY.md), [links](LINK-POLICY.md), [lifecycle](LIFECYCLE.md) |
| Security | [Storage](SECURITY.md), [private descriptor editing](SECURITY-EDITING.md), [DACL evaluation](ACCESS.md), [native access](NATIVE-ACCESS.md), [Windows oracle](ACCESS-ORACLE.md) |
| Journal and recovery | [Log framing](LOGFILE.md), [USN record framing](USN-RECORDS.md), [recovery inputs](RECOVERY-INPUTS.md), [model](RECOVERY-MODEL.md), [write foundations](WRITE-FOUNDATIONS.md) |
| Writable images | [Native journal](NATIVE-WRITE-JOURNAL.md), [DATA-only overwrite](DATA-OVERWRITE.md), [installation](NATIVE-INSTALLATION.md) |
| Journal reuse | [Settled checkpoint implementation/test contract](CHECKPOINT-REUSE.md) |
| Content and performance | [WOF](WOF.md), [read caches](READ-CACHE-POLICY.md), [performance](PERFORMANCE.md) |
| Product preparation | [Commercialization](COMMERCIALIZATION.md), [ext4 integration lessons](FSKIT-EXT4-LESSONS.md) |

The format reference explains what bytes and relationships mean. These detailed
contracts describe what this implementation owns and what its tests establish.
