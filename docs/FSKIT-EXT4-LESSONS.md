# FSKit lessons from ext4

The sibling ext4 repository's installed results and fix history inform this
adapter. They do not qualify NTFS mounts. Inspect both `../ext4/docs/FSKIT.md`
and the relevant implementation history with ordinary Git; source revisions
remain in Git and native artifact identities remain in generated reports.

Current NTFS legacy installation independently confirms public enabled discovery and
exact synthetic reading through direct mount -F on two fixtures. It also reproduces
the noowners limitation and a failed separate nomount/diskutil route: successful probe
and module staging precede kDAReturnNotReady at mount approval. These are scoped NTFS
observations, not adoption of ext4's owners-on automount acceptance. Explicit NTFS
extraction selection and ownership-preserving admission remain separate work; see
NATIVE-INSTALLATION.md. Permission capabilities were not changed to bypass the failure.

| Ext4 finding and history subject | NTFS application | Evidence still required |
| --- | --- | --- |
| `Fix FSKit discovery and native ownership acceptance`: `usableButLimited` prevented Disk Arbitration recognition, and an underscore in the short name was truncated by its `_fskit` handling | Probe uses `usable`, short/type name `machlinntfs`, subtype zero; read-only policy is separate | Actual Disk Arbitration image discovery, mount point, ownership flags and registration; direct mounting alone is insufficient |
| `Require macOS 26.5 for FSKit and reject writable opens`: cached writes and shared writable mappings must be refused before admission | Read-only open/close and mutation replies stay explicit; no kernel block-map protocol is advertised | Ordinary POSIX writes, writable mmap, Finder operations and read-only mount flags on both supported runtime families |
| `Separate FSKit protocol generations and publish mutation metadata`: legacy counts and modern result objects are incompatible ABIs; a modern result is ignored on error | Separate complete sibling volume classes share the core engine. A late WOF decode error retains a correct core prefix but native handlers return an error with zero legacy count or no modern result | Installed buffer strategy and modern runtime execution; local late-block tests do not establish kernel behavior |
| The modern bridge checks fallible result construction | All successful NTFS modern result-producing handlers now convert an absent result to EIO and preserve an existing operation error | The common result/error boundary runs locally; actual modern result-constructor failure injection still needs the appropriate runtime |
| `Stop revoked FSKit owners and cover forced resource removal`: cached state must reject a revoked owner, and old ownership cannot recover when a resource reappears | Admission and post-read checks permanently latch revocation; initial revoked acquisition rejects before inspecting geometry. Cleanup frees state without another device read | Installed held descriptors, mappings, SIGBUS/EIO and complete remount bytes; forced image detach does not prove physical unplug/power-loss behavior |
| Conditional reclaim must serialize with lookup publication; old runtimes retain ownership through the final item reference | Weak canonical identity, retained item owner, separate publication/admission/drain synchronization and modeled reclaim eligibility | Real framework counts, lookup/reclaim races, stale items after unload and native scheduling on each OS |
| `Adapt FSKit read metadata retention to memory pressure`: read metadata is disposable, retained identities are not; coalesced elevated notifications outrank normal | A separate NTFS observer now changes optional retention without scanning items or waiting for I/O. Access/completion cleanup releases streams/catalogs/raw snapshots while preserving identities, pending directory entries and callback buffers. READ-CACHE-POLICY.md records exact-byte, allocation, fault and blocked-read evidence | Measured aggregate allocation/RSS and installed native notification delivery/stress on each supported OS |
| Ext4's installed cache experiments expose limitations that component callbacks cannot predict | Requested attributes, case/normalization keys, metadata cache changes and response masks remain separate NTFS acceptance requirements | Windows-authored case/security metadata and native observations. `FSContext` UID/GID alone is not a complete Windows token or authenticated identity mapping |
| Ext4 packages a filesystem catalog and validates Developer ID installation independently of an unsigned build | NTFS currently has an app/extension development build; distribution remains open | Catalog/installer/signing/notarization, controlled VM installation and discovery beside Apple's existing NTFS support |
| `Admit unary maintenance volumes without filesystem geometry`: macOS 27.0.1 rejects a unary `(nil, nil)` load before maintenance dispatch; a temporary unmountable identity reaches the task | Explicit forced NTFS checker loads can create a nonmountable, geometry-free unary identity with zero counts and a valid accounting unit. Private checks share the bound resource, close admission and retire temporary identities after every verdict; ordinary loads still require a valid core | Installed unary dispatch and native client behavior on both supported OS families; component constructor/retirement checks do not qualify daemon acquisition |
| `Complete rejected maintenance tasks asynchronously`: the native 27 formatter trapped in its initial synchronous-error reply; asynchronous public task completion retained EINVAL and unchanged media | NTFS check/format refusals complete asynchronously once, with noncancellable progress and no I/O/resource takeover. The accepted read-only checker has separate cooperative cancellation/drain ownership; no formatting or repair is enabled | Installed task/cancellation/client exit-status acceptance remains open. The checker cannot interrupt a synchronous read; the ordinary item-read contract is separate |

The NTFS result/error and revoked-acquisition changes above are original adapter
code informed by the inspected history. Ext4's writing, journal, maintenance,
encryption and persistence-service implementations are not copied into the
read-only NTFS core. Keep installed acceptance, core correctness and measured
optimization as separate streams in CORE-QUALIFICATION.md.
