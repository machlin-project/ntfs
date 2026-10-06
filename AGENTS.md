# Machlin NTFS development

This independent, proprietary repository owns the NTFS implementation and its
FSKit product. Read README.md, docs/ARCHITECTURE.md, docs/ACCEPTANCE.md and
docs/DEVELOPMENT.md before changes. Workspace identity and VM policies apply.
Standalone builds and tests run here; Machlin VM commands run from the absolute
lab directory. Develop on development. Do not publish this repository or grant
an open-source license without the owner's explicit instruction.

The main agent owns architecture, implementation, tests, diagnosis and acceptance.
Delegate prepared CLI builds/tests and artifact collection to gpt-6-luna and VM
operations to gpt-6.1-sol, with exact absolute paths and bounded commands. Only
one worker operates a VM. Never install this driver on the development host.

Core C is freestanding: explicit allocator and exact read callbacks, no FSKit,
Foundation, libc allocation, native errno or LXNU dependencies. NTFS disk bytes
are untrusted. Use named wire fields, checked arithmetic, bounded iteration,
sequence-checked file references and fail-closed unsupported-feature handling.
Give format values, policy limits and buffer sizes meaningful names. Derive field
offsets from wire structures and sizeof/offsetof. Fixture authors must use named
fields and geometry constants too; unexplained numeric offsets are not acceptable.
Use .clang-format from the selected Xcode toolchain; declarations start each
block, braces surround control flow, one statement per line, English source.

Read-only code has no write capability. Do not add writes before the ownership,
durability and native NTFS recovery contract in docs/WRITES.md has acceptance.
FSKit owns native lifecycle, locking, error conversion and buffering. Future LXNU
integration is separate and currently out of scope. Do not import GPL filesystem
implementation code; standalone third-party test utilities stay under ignored
vendor/. Track dependency provenance and retained notices. Keep device images,
reports, signing credentials and generated projects out of Git.

Core tests, adapter component tests, app builds, installed mounts and commercial
release readiness are distinct evidence. Unsupported rejection is not feature
support. Update acceptance and handoff with actual results and limitations.

Maintain docs/format/ as the living NTFS disk-format reference. When a work batch
changes format interpretation, metadata relationships or recovery semantics, or
establishes a new native observation, update the relevant chapter with named
fields, units, sources and code/test links. Keep published facts, native
observations, locally verified behavior and unresolved interpretations distinct.
Add concrete open questions to its research register; keep feature acceptance in
the existing acceptance documents. Update diagram sources and inspect their
rendered SVGs when the relationships change. Keep artifact hashes and UUIDs in
generated reports, not the reference.
