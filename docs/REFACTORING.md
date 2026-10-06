# Driver refactoring plan

This review follows the verified ordinary-mutation preparation checkpoint in
[ACCEPTANCE.md](ACCEPTANCE.md#ordinary-mutation-planning-and-complete-lfs-placement).
The checkpoint passes complete local regression; expanded device writing and
native recovery retain their separate unfinished gates. Refactoring proceeds in
focused behavior-preserving commits on `development`.

The purpose is consistent, readable ownership and module boundaries across the C
core and FSKit. Formatting already passes the selected-Xcode profile. The larger
problems are repeated helpers, inconsistent internal names and files that combine
several responsibilities.

## Concrete findings

| Area | Current finding | Proposed change |
| --- | --- | --- |
| Pointer/range checks | Writer modules repeat `separate`, `valid_range` and `range`. They differ in zero-length and NULL admission, so they are not interchangeable merely because their names match. | Introduce a small checked-range helper for proven equivalent cases. Preserve explicit caller-specific NULL/output rules and audit each conversion. |
| Complete program | `write_program.c` combines retained storage, FILE/INDX compilation, private application, OAT/transaction serialization, source-packet binding and compensation placement. | Separate metadata compilation/application from packet binding and page composition behind one private owner. Keep public opaque getters and lifetime unchanged. |
| Writer contracts | `write_internal.h` collects overwrite metadata, journal layout, history, replay, execution, recovery and owner entry points. Most modules receive more declarations than they use. | Split private contracts by owning component and include only the required interfaces. Preserve wire structures and public declarations. |
| Internal names | Newly added code mixes generic `target`, `append`, `emit`, `prepare`, `allocate` and `release` with explicit mutation/recovery names. Variables alternate between `source`, `reader`, `environment` and `input` for different roles. | Use names that identify the object or action; distinguish immutable source, allocator, owned workspace and borrowed input consistently. |
| Mutation storage | Record construction, attribute replacement and stream serialization live together in `write_record.c`; directory verification and tree reconstruction live together in `write_directory.c`. | Separate byte construction from namespace/storage algorithms where this removes a real dependency. Keep complete mutation ownership and collation in their existing semantic layer. |
| Memory and cleanup | Program, mutation, bitmap, replay and volume owners have distinct accounting, reservation and lifetime rules, with repeated cleanup patterns. | Make local ownership/cleanup conventions uniform. Share byte helpers, not an allocator framework that would erase different governors or change callback order. |
| FSKit volume | `NTFSVolume.m` owns lifecycle, operation budgets, item/cache publication, rebinding, image access rights, writable-image dispatch and read operations. | Extract private components at existing complete-operation boundaries, keeping serialization, context authorization and teardown with their native owner. |
| Evidence prose | Acceptance has accumulated long historical sections, while format facts, private hypotheses and product gates now have separate documents. | Keep current contracts easy to find, use links for historical evidence, and preserve useful limitations and reproduction paths. Source and artifact identities remain in Git and generated reports. |

## Implementation order

1. **Make internal conventions explicit.** Audit range/alias helpers and their
   call sites, establish descriptive names and retain the existing declaration,
   brace and formatting rules. Convert only equivalent helpers in the first
   code commit. Keep checked arithmetic and zero-length/NULL behavior explicit.
2. **Separate C contracts and program responsibilities.** Split the large private
   writer header and complete-program implementation. Keep one opaque owner,
   copied payload lifetime, exact allocation/release accounting and unchanged
   exported API. Update code links in the format reference when files move.
3. **Regularize mutation construction and cleanup.** Review FILE attributes,
   mapping/bitmap construction and directory byte building. Remove duplicates
   only when their semantic and ownership contracts agree. Use named local
   cleanup paths and predictable result publication without combining policies.
4. **Review and extract FSKit responsibilities.** Start with private item/cache
   and complete image-operation boundaries. Prepare the exact extraction and
   locking/lifetime review before moving methods. Preserve native reply timing,
   authenticated caller rights, read leases and draining unmount/invalidation.
5. **Close the refactoring boundary.** Run the complete local regression once
   after the connected cleanup. Run installed acceptance where changed native
   lifecycle, authorization, buffering or persistence requires it. Then resume
   functional write/recovery integration under its original acceptance contract.

Each step produces a reviewable commit with a stated scope. Do not mix new NTFS
semantics, allocation policy, native opcode admission or checkpoint advancement
into cleanup. A discovered behavior defect gets its own failing conformance test
and functional fix before the cleanup proceeds.

## Conventions to apply

| Concern | Convention |
| --- | --- |
| Internal function names | Describe the owning object and operation; avoid a generic name when several modules perform materially different versions of it. |
| Inputs and owners | `source` denotes immutable media capability; `allocator` denotes allocation capability; `input` denotes a borrowed typed request; owned scratch/workspaces remain visibly separate. |
| Coordinates and lengths | Distinguish physical bytes, logical stream bytes, FILE numbers, VCNs, LCNs, UTF-16 units and bit ranges in names. Retain named wire fields and constants. |
| Result publication | State alias behavior, ordinary failure output and completed/poisoned execution reporting at each owning boundary. Preserve those contracts independently. |
| Memory | Every allocation has one owning object, an exact accounted size and a matching release. Keep optional retention separate from required work reservation. |
| Errors and cleanup | Declare resources at block starts, initialize owners predictably, release only acquired resources and preserve the original failing result. Never hide durable completion with a later allocation failure. |
| Interfaces | Keep wire decoders, pure byte construction, complete mutation planning and physical execution distinct. FSKit supplies native lifecycle/authorization; C owns NTFS semantics. |
| Tests | Retain independent byte, object, fault and lifetime oracles. Add tests for missing contracts, not for a mechanical rename or a moved function. |

Public API renaming and new abstractions are not required for this cleanup. In
particular, the existing overwrite owner must not be presented as a generally
writable NTFS owner through a cosmetic rename.

## Verification and completion

Use focused checks for each affected contract during implementation. The connected
C cleanup closes with fatal ASan/UBSan regression, selected-Xcode formatting and
freestanding arm64/x86_64 compilation under the 2-KiB stack ceiling. Preserve exact
packet/page outputs, full projected metadata, inverse prefixes, fault positions,
input lifetime and accounting. Host FSKit PASS and runtime SKIP counts remain
separate from installed behavior.

For native changes, use the dedicated macOS VM and the prepared CLI harness,
followed by the necessary Windows postimage/recovery checks. VM operations remain
delegated and serialized; UTM and unrelated VMs remain under the user's control.
The [development workflow](DEVELOPMENT.md) and [write contract](WRITES.md) retain
their authority. Refactoring is complete when the agreed boundaries/conventions
are applied and their required evidence passes, not when source formatting alone
is uniform.
