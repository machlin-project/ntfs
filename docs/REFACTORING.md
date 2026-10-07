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

## Applied cleanup

Ten writer/encoder modules now share the private
[pointer-range helpers](../core/pointer_range.h). Their equivalent arithmetic
checks preserve NULL/zero-length admission, overflow refusal and alias behavior.
Required-pointer rules and failed-output publication remain at each operation's
owning boundary. Helpers with stricter empty-range/NULL rules, including the
bounded journal/history/recovery interfaces, retain their existing local policy.
No allocator, operation governor or native transport policy is combined.

All fourteen affected writer/encoder suites pass with fatal ASan/UBSan; their
existing byte, fault, lifetime and alias oracles are retained. Evidence is in
`artifacts/overwrite/refactor-pointer-ranges-focused-20261007/`.

The complete program is now separated into
[metadata compilation/application](../core/write_program.c) and
[packet, original-binding and compensation composition](../core/write_program_packets.c).
The [private storage contract](../core/write_program_internal.h) preserves one
retained owner, copied payload lifetime and exact accounting. Internal compiler
and packet helpers now identify their owning object and action.

The former combined writer header is replaced by component contracts for
metadata, journal serialization, replay, retained history, overlay validation,
physical execution, transaction preparation and recovery. The native adapter
includes only the [image-owner entry points](../core/write_owner.h) and
[durable reports](../core/write_status.h); it receives no private FILE/journal
workspace layouts through that boundary. The qualified family's packet-size
ceiling belongs to replay and is reused by retained history; the original values,
structure fields and stage ordering are preserved. These are implementation
boundaries, not expanded operation or recovery admission.

The connected cleanup passes all 181 fatal-ASan/UBSan suites, selected-Xcode
formatting, 106 freestanding objects (53 core sources per architecture) under
the 2-KiB frame ceiling, and eleven independent private-header syntax checks.
FSKit host components remain 63 PASS / 13 explicit runtime-SDK SKIP / 0 FAIL.
The three actual regular-image postimages are byte-identical to the preceding
physical-execution checkpoint. Main checks unchanged program function bodies,
structure fields, prototypes, stage order and policy expressions independently.
The updated diagram is rendered and visually reviewed. Initial missing budget
and native wire includes, plus a failed header-check wrapper invocation, remain
retained separately from their corrected evidence. Reports and the consolidated
review are in `artifacts/overwrite/refactor-write-components-*` directories.

Mutation-construction review, broader naming/cleanup work and FSKit extraction
remain in the plan; this does not complete driver refactoring. Native lifecycle,
locking, authorization, transfers and reply code are unchanged, so this cleanup
adds no installed VM acceptance. Functional recovery/write admission retains
its original native gate.

The next focused cleanup makes successful producer outputs explicit before use
in nine existing writer modules and the native image-item rebind method. The
directory constructor retains its exact root allocation size for cleanup; recovery
selects the last retained transaction only after proving the array is nonempty.
Fourteen C functions preserve ordered calls and errors. Native item rebinding
preserves metadata/stat/link/ancestry order, its failure node close and successful
field publication. Locking, authenticated rights and native replies retain their
existing code. This is consistent control flow, not the planned FSKit extraction.

The connected recovery working set passes all 184 fatal-ASan/UBSan suites with
assertions enabled, both freestanding architectures and fifteen standalone headers.
All nine regular-image writer/recovery postimages are byte-identical before/after
the C guard changes. Strict Release compilation passes 116 core checks and eleven
native x86_64 frontend checks; actual unsigned app/extension/archive builds supply
both architectures. Host FSKit after native guard cleanup remains 63 PASS /
13 runtime-SDK SKIP / 0 FAIL. Initial compiler refusals remain retained separately.
The main equivalence and final evidence review is under
`artifacts/overwrite/batch-recovery-main-review-20261007/`; current acceptance is
recorded in the existing recovery section of ACCEPTANCE.md.

## Concrete findings

| Area | Current finding | Proposed change |
| --- | --- | --- |
| Pointer/range checks | Ten modules now use one checked-arithmetic helper; remaining local policies differ in zero-length and NULL admission. | Preserve explicit caller-specific NULL/output rules and audit each further conversion. |
| Complete program | Metadata compilation/application and packet/compensation composition now have separate modules behind one private retained owner. | Keep public opaque getters, copied byte lifetime and exact accounting at this boundary when adding new families. |
| Writer contracts | Component contracts replace the combined header; the native image-owner contract exposes entry points and durable reports. | Include the owning interfaces explicitly and preserve structure fields, policy values and public declarations. |
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
