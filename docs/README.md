# Documentation

Start with the [NTFS format reference](format/README.md): a chaptered guide to
volume bytes, metadata relationships, journal framing and recovery, with original
diagrams, field maps, examples and a research register.

## Product and development

- [Architecture](ARCHITECTURE.md): component and ownership boundaries.
- [Development](DEVELOPMENT.md): prepared build/test and VM workflows.
- [Acceptance](ACCEPTANCE.md): actual evidence and remaining feature gates.
- [Write contract](WRITES.md): durability, allocation, namespace and recovery scope.
- [Current VM handoff](HANDOFF-SOL.md): execution paths and operating constraints.
- [Provenance](PROVENANCE.md): sources, consulted layouts and dependency attribution.

## Detailed contracts

| Area | Documents |
| --- | --- |
| Metadata and ownership | [Validation](VALIDATION.md), [operation budgets](OPERATION-BUDGETS.md), [core qualification](CORE-QUALIFICATION.md) |
| Names and native objects | [Namespace](NATIVE-NAMESPACE.md), [case policy](CASE-POLICY.md), [links](LINK-POLICY.md), [lifecycle](LIFECYCLE.md) |
| Security | [Storage](SECURITY.md), [DACL evaluation](ACCESS.md), [native access](NATIVE-ACCESS.md), [Windows oracle](ACCESS-ORACLE.md) |
| Journal and recovery | [Log framing](LOGFILE.md), [recovery inputs](RECOVERY-INPUTS.md), [model](RECOVERY-MODEL.md), [write foundations](WRITE-FOUNDATIONS.md) |
| Writable images | [Native journal](NATIVE-WRITE-JOURNAL.md), [DATA-only overwrite](DATA-OVERWRITE.md), [installation](NATIVE-INSTALLATION.md) |
| Content and performance | [WOF](WOF.md), [read caches](READ-CACHE-POLICY.md), [performance](PERFORMANCE.md) |
| Product preparation | [Commercialization](COMMERCIALIZATION.md), [ext4 integration lessons](FSKIT-EXT4-LESSONS.md) |

The format reference explains what bytes and relationships mean. These detailed
contracts describe what this implementation owns and what its tests establish.
