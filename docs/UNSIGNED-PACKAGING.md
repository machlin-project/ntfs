# Unsigned FSKit artifact retention

`python3 scripts/package_unsigned.py --app 'artifacts/cloud-macos/DerivedData/Build/Products/Release/Machlin NTFS.app' --build-report artifacts/cloud-macos/DerivedData/build-report.json --output artifacts/cloud-macos/package`

Run after the unsigned Release build in the same clean, committed checkout. The
output's parent must already exist; the output itself must not exist. Python 3.13
and the ordinary tracked scripts are sufficient to package an existing app.
Building the app still requires the selected suitable macOS SDK and XcodeGen.
Nothing here installs, launches, signs, notarizes, enables or mounts the app.

## What is retained

- `unsigned-fskit.tar`: the complete admitted `.app`, unchanged `LICENSE`, the
  repository's `PROVENANCE.md`, a scope/dependency notice, the unchanged build
  report and `manifest.json`.
- `manifest.json`: every directory, ordinary file, mode, byte count, SHA-256 and
  symlink target; bound build-report digest; both bundle identities/versions and per-architecture dynamic
  dependencies/signature classification; notice hashes and packaging Git tree.
- `report.json`: success/failure, completed archive size and SHA-256, exact scope,
  repeat-packaging result and explicit false native/distribution qualifications.

Use the tar as the CI transport. Uploading the raw `.app` through an artifact
service can lose POSIX executable modes or symbolic-link identity. The tar is
uncompressed and deterministic, with sorted members, numeric owner/group zero,
empty owner/group names, and the packaging commit's committer time. File data,
file modes and relative symlink targets are not rewritten. Repacking equal inputs
at different filesystem locations and mtimes yields equal transport bytes.

Only Xcode's `com.apple.xcode.CreatedByBuildSystem` extended attribute may be
omitted. Any other extended attribute fails instead of silently dropping resource
forks, Finder metadata, quarantine or other potentially meaningful information.
There is no extended-attribute or ACL preservation claim. An unexpected attribute
requires an explicit reviewed transport policy before admission.

The original app is read-only to this tool. It refuses every preexisting output,
including a directory, file, or dangling symlink. A newly claimed output retains
its failure report and any `.partial` file produced before a failure. A failed
partial transport must never be treated as an installable/completed artifact.

## Admission boundary

The current reviewed product layout contains the existing `Machlin NTFS.app`
and exactly its `Contents/Extensions/NTFSExtension.appex`. Both require real
Info.plists, matching versions, the repository's existing identifiers, and real
executable-mode files. The extension must identify the FSKit extension point.
No application identity or license policy is selected by this tooling.

Both executable files must contain exactly the arm64 and x86_64 64-bit executable
Mach-O slices. Their container/load-command ranges are bounded, architectures
cannot duplicate or overlap, and all dynamic dependencies must be Apple system
paths. Legacy foreign-library and dyld-environment commands are refused. The
parser is a packaging admission check, not Apple's complete executable loader or
code-signature cryptographic verifier.

An absent embedded signature is recorded as absent. A bounded ad-hoc envelope
containing only ad-hoc CodeDirectories is admitted and recorded as having no
distribution identity. This accommodates linker ad-hoc signatures without calling
them Developer ID or distribution signing. Certificate-backed/CMS, ambiguous
signature envelopes, embedded profiles, `_CodeSignature`, unexpected frameworks,
extra executables, executable-looking resources, or extra code bundles fail.
Actual hosted output must establish the precise emitted shape; fixture success
alone does not prove that a particular SDK's app is admitted.

Resources may contain safe relative symbolic links confined to their own
Resources directory. Escapes, dangling/cyclic links, hard links, devices/FIFOs,
case-folding collisions, noncanonical/control-character paths, set-ID/special
modes, group/world-writable data, oversized files/trees and changed input are
refused. Inventory limits are 4,096 entries, 256 MiB per file and 512 MiB total.

The explicit layout, executable count and dependency review prevent incidental
packaging of standalone test tools. A filename/magic/dependency check cannot prove
arbitrary resource data or statically linked code's authorship. Original build
sources, dependency rights and `PROVENANCE.md` still require review; the packager
is not a legal clearance or a general software-composition audit. GPL test tools,
images, credentials, `vendor/`, DerivedData intermediates and diagnostic logs are
outside this product payload.

## Reproducibility and provenance scope

Every archive is verified against the pre-read inventory, then independently
serialized and verified a second time. Both hashes must match, and the original
app's complete inventory must remain unchanged before publication. The packaging
checkout must be committed/clean and retain the same Git revision/tree through
publication. Git is the source-history authority; no custom history ledger exists.

The CLI requires the retained successful unsigned Release `build-report.json`
from `scripts/build_fskit.py`. Its source revision, tree and epoch must match the
packaging checkout; its complete app inventory must exactly match the current
app; and its source archive hash and actual Xcode/SDK/compiler identity must be
present. The original report is included unchanged and bound by SHA-256. A changed
resource, mode, link, executable, report source or build verdict cannot inherit
the earlier build result. This is evidence binding, not a cryptographic builder
attestation or proof against fabricated external build reports.

The extended existing build helper retains all earlier command-line options and
still runs XcodeGen/Xcode. It requires a clean committed source tree and a new
DerivedData output. It exports that exact Git commit into its owned output,
generates the project there, selects the same Xcode route, explicitly requests
both Release architectures and records bounded commands/logs. A fresh source
export protects caller-generated projects and isolates original sources. Reusing
an old DerivedData output now refuses, including with `--clean`; use a new output
path. `--clean` still asks Xcode to clean its newly owned snapshot. The build
report records the exact produced app inventory and checks the original checkout
again before declaring success. Failures retain the owned output and report.
The Xcode build deadline defaults to 1,200 seconds and cannot exceed 1,800 seconds;
each build output stream is limited to 32 MiB. Tool identity queries and project
generation also have explicit budgets. Environment isolation is preserved.

Repeat packaging is not independent app-build reproducibility. For that gate,
build twice into new outputs and pass `--compare-app SECOND_APP` and
`--compare-build-report SECOND_REPORT` to the packager. Both reports must identify
distinct original outputs, the same source and toolchain, and their exact actual
inventories. Equal complete inventories yield a separately labeled app-build
comparison. Differences fail, retaining the exact paths in the report; no archive
is published. Both original build reports are retained in a passing package.
Differing Mach-O UUID/path/toolchain bytes must be diagnosed at build
configuration, never patched in completed binaries. Synthetic comparison tests
are not an actual two-Xcode-build verdict; hosted execution remains separate.


No packaging result establishes actual SDK compilation, installed/native FSKit,
Windows image acceptance, authorization mapping, notarization, upgrade/uninstall,
physical power-loss behavior, or commercial release readiness. Signing and the
remaining product/release gates remain separately owned in COMMERCIALIZATION.md.

## Independent regression coverage

`python3 tests/test_unsigned_package.py`

`python3 tests/test_fskit_build_tool.py`

The tests author synthetic universal Mach-O headers, load commands, simple
ad-hoc and non-ad-hoc envelopes, independent bundle metadata and original resource
bytes. These are not real app builds and are never executed. They cover complete
inventory/transport roundtrip, resource modes and symlinks, relocation/mtime
independence, preexisting output preservation, missing/malformed metadata and
executables, bundle/version/extension identity, architecture/range/signature and
dependency refusal, content/path/link/mode/size budgets, archive failure, source
changes and input changes before publication. Build-tool tests preserve argument
contracts, new-output/failure retention and selected-profile isolation. Additional
synthetic evidence tests cover successful build binding, invalid verdict/source/
toolchain, changed app data, two-distinct-build comparison and exact difference
reporting. These tests never execute signing or Xcode.

## Format sources

The original packaging parser uses Apple's published
[Mach-O declarations](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
and [code-signing blob declarations](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
for wire field meanings and constants. No Apple signing implementation or foreign
filesystem implementation is copied into product code. This is offline development
tooling; it never supplies a distribution identity or entitlement authority.
