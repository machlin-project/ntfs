# Product and release process

The repository is proprietary under LICENSE. The owner made its GitHub remote
public specifically for cloud CI; that does not grant an open-source license or
authorize product distribution. Historical release-policy notes below retain
their original context. It has no authorized commercial release,
open-source grant, payment integration, trial enforcement or distribution package.
A future product distribution or open-source license is an ownership decision,
not an automatic date-based conversion. Maintain contributor rights and dependency
provenance so that decision remains possible.

Keep the filesystem core usable without licensing or network access. A future
commercial control plane may decide whether a new mount is admitted; it must
never interrupt an admitted read, prevent recovery/flush/unmount, or change disk
semantics on expiry or a network failure. Payment, activation, support and update
services belong to the app. No service credentials belong in the extension,
repository, diagnostic archive or build logs.

The shipped binaries contain original core code and Apple platform adapters.
NTFS-3G utilities are external development tools, covered by their own license;
the product must not link them or bundle them incidentally. Source inspection for
format knowledge is documented in PROVENANCE.md. Obtain the appropriate review
of distribution rights and third-party notices before a paid release.

Release gates, all currently open:

1. Freeze a supported format/OS/hardware matrix and close every advertised row.
2. Establish a Windows corpus with documented provenance, independent contents,
   compressed/sparse/ADS/reparse/security variations and repair results.
3. Pass signed native VM mounts, Finder, mmap, cancellation, resource loss,
   sandbox/lifetime checks and mixed-client stress on each supported OS.
4. Settle NTFS authorization mapping and unsupported-file presentation before
   claiming Windows permissions or general-purpose filesystem compatibility.
5. Use the personal developer identity and explicit application identifiers;
   notarize, validate hardened runtime/entitlements and verify upgrade/uninstall.
6. Define pricing, trial terms, offline behavior, activation recovery, privacy,
   update signing, support and incident response. Implement and test those
   controls independently of filesystem metadata code.
7. Publish only a reviewed private repository or signed release artifact, with
   explicit owner authorization. No current test creates a GitHub repository,
   uploads source or installs a filesystem extension on the development host.

Unsigned Xcode builds can register their DerivedData application with Launch
Services as part of Xcode's standard build processing. That is not installation,
extension enablement or a verified mount. Installed qualification must identify
the selected Machlin module so a successful Apple NTFS mount cannot be mistaken
for a test of this implementation.

For eventual open sourcing, review history and contributor permissions, choose
the license, remove non-source generated/private material, retain third-party
notices, publish reproducible tests and define maintenance responsibilities. Do
not rebuild history from another project's .git directory or carry unrelated refs.
