# Handoff to Sol

Work in `/Users/darekhta/Development/machlin/ntfs`, branch `development`.
Read AGENTS.md, README.md, ARCHITECTURE.md, ACCEPTANCE.md, PROVENANCE.md and WRITES.md.
This is an independent proprietary FSKit product. No kernel adapter or LXNU
changes are included. Publishing source, choosing a public license and enabling
writes are separate decisions.

## Meaning of the requested 60%

The request was to establish roughly 60% of a driver and hand off the remainder.
There was no existing NTFS backlog or effort estimate from which a measured
percentage could be calculated. This delivery establishes six engineering
baselines: repository/process, validated disk decoding, MFT/attributes, stream
reading, indexed namespace and the FSKit app/adapter. This is a concrete partial
driver; it is not evidence that 60% of the total effort or commercial readiness
has been achieved. Writes, native recovery and qualification may dominate the
remaining effort. Use the acceptance matrix rather than a line-count percentage.

## What to preserve

- Freestanding core with explicit allocation/read callbacks and a separate
  proprietary licensing boundary. There is no disk write capability.
- Immutable resource lifetime, counted children, bounded runs/attribute lists/
  directory depth, atomic fixup verification and sequence-checked references.
- $UpCase-based lookup, stored-name return, sparse/VDL zeroing, ADS and LZNT1
  handling, including fragmented and partial final compression units.
- Complete separate legacy/modern FSKit protocol classes. Their read completion
  signatures differ; do not advertise both protocol families on one class.
- A retained resource owner through C callbacks, synchronized operation admission,
  canonical FSItem identities, replayable directory cookies, explicit EROFS for
  every implemented mutation and invalidation of all children before release.
- Separate component/build/mount evidence. NTFS-3G reverse-engineered format facts
  are valid engineering references; copying GPL implementation into this closed
  product is not part of the implementation plan.
- Safe build environments. Meson records environment variables in reports. Run
  `make test` through the allowlisted launcher; never dump ambient environments
  or unfiltered legacy Meson logs. Inspect selected test result fields.

## Reproduce local evidence

```sh
make test
make check-style
python3 scripts/check_core.py
make fskit
python3 scripts/test_fskit.py
python3 scripts/bootstrap_test_tools.py
python3 tests/interoperability.py --output artifacts/interoperability-next
python3 scripts/fuzz.py --seconds 60
python3 scripts/build.py .build-release --release
.build-release/ntfs-benchmark artifacts/interoperability-next/ntfs-s512-c4096.img large.bin
```

The interoperability runner refuses to overwrite its image files; choose a new
ignored output directory for a new execution. If Xcode omits libFuzzer, add
`--compiler /opt/homebrew/opt/llvm/bin/clang` to the fuzz command; see DEVELOPMENT.md.
Routine prepared runs belong to
Luna (`gpt-6-luna`); diagnosis, implementation and acceptance belong to the current
main task owner. FSKit VM preparation belongs to Sol (`gpt-6.1-sol`); one agent
owns a VM at a time. Give workers absolute directories and bounded tasks.

## First continuation: native read-only acceptance

The unsigned app is produced under
`artifacts/fskit/DerivedData/Build/Products/Debug/Machlin NTFS.app`.
Build with an explicit personal team using `scripts/build_fskit.py --team TEAM`
only when preparing the dedicated test VM. Verify the personal identity and
entitlements; keep provisioning state out of Git. The initial native target is
macOS 26.5+, with a distinct macOS 27 protocol path requiring its own runtime test.

Use the Machlin lab only from `/Users/darekhta/Development/machlin/lab`, after
reading its current VM instructions. Do not take over an ext4 or kernel VM that
another task owns. Select/create a disposable stock macOS test VM and document
its path and ownership in ignored generated state before installation. No NTFS
test VM is allocated by this handoff.

Install/enable the app inside that VM, explicitly select the `machlinntfs`
filesystem and capture evidence of the loaded module/build. Verify hashes for all
fixture files, Unicode/case-preserved names, small-buffer directory continuation,
stat, sparse/compressed reads, concurrent readers, mmap, failed writes, repeated
unmount/reload, extension termination and virtual device removal. Check the image
hash before and after every read-only run. Include a control that proves the
Machlin module was selected instead of Apple's built-in NTFS reader. Do not infer
this from a successful mount or from source compilation.

## Core compatibility priorities

1. Build a Windows-authored corpus and retain the independently generated oracle.
   Current handcrafted images target individual contracts; mkntfs tests provide
   independent ordinary formatting, data and indexes. Neither closes Windows
   interoperability for every format feature.
2. Add fragmented $MFT bootstrap through $ATTRIBUTE_LIST, including extensions
   located outside the initially reachable MFT runs. Current mount rejects this
   layout explicitly. Do not recursively trust records before their runs resolve.
3. Support extension placement of large attribute lists and exercise cycles,
   duplicate segments, VCN gaps and every allocation/read failure boundary.
4. Expand compressed/sparse edge coverage with Windows-generated files, malformed
   chunk boundaries, large logical offsets and unusually fragmented attributes.
5. Define lossless presentation for unpaired UTF-16 names and case-sensitive NTFS
   directories. Current product advertises case-insensitive lookup and has no
   complete WSL/POSIX namespace contract.
6. Handle reparse tags explicitly: symlinks, junctions, WOF and cloud placeholders
   have different semantics. Current adapter rejects reparse items. Do not expose
   encoded data as ordinary file content or turn every tag into a symlink.
7. Implement $Secure/security-descriptor resolution and an owning authorization
   policy. Current mode/UID/GID are a single-user read-only presentation, not
   Windows ACL enforcement. EFS and native ACL/xattr translation remain absent.

## Writable and product continuation

Start with WRITES.md. Establish native $LogFile replay and crash ordering before
allocation, create/write/truncate, directory insertion/removal or rename. Preserve
dirty/hibernation state and recovery evidence. A private log or clearing a dirty
bit does not create Windows-compatible recovery. Test writable transactions with
Windows replay and chkdsk, plus per-sector interruption and device-cache failures.

Follow PERFORMANCE.md for measured optimization; no installed throughput win has
been established. Follow COMMERCIALIZATION.md for distribution, activation,
updates, privacy, support and later open sourcing. LXNU integration stays deferred
until required and belongs in a separate native adapter with its own acceptance.

The next task is not complete at a clean build or a focused commit. Close the
agreed continuation scope and update acceptance with evidence, limitations and
separate skips/failures.
