# Bounded standalone external NTFS oracles

External NTFS utilities remain development-only programs beneath ignored
`vendor/`. No upstream filesystem source is copied into, linked with, installed
as, or shipped with the product. The driver's read-only image comparisons and
whole-file byte oracles remain original repository work.

## Verified acquisition and private build

The default route preserves the existing NTFS-3G 2022.10.3 release archive and
its pinned SHA-256. Downloads stream into a new retained `.download` file; only a
matching complete archive can be copied into the cache and extracted. The cache
is never replaced on mismatch. HTTPS must remain at the official Tuxera origin;
byte, socket and elapsed-time limits apply. Extraction rejects escaping names,
links, special files, duplicate normalized paths and excessive file/byte counts.

```sh
python3 scripts/bootstrap_test_tools.py --compiler clang \
  --output artifacts/test-tools-archive --prefix vendor/ntfs-tools-archive
```

A separately selected official Git route is available when the release archive
route cannot be acquired. It is not an automatic fallback or a claim of archive
byte equality. The [upstream release tag](https://github.com/tuxera/ntfs-3g/releases/tag/2022.10.3)
is independently pinned to its full commit in the script. The clone uses no
checkout until that identity matches. Autoconf, Automake and Libtool are additional
prerequisites; missing tools fail with retained diagnostics.

```sh
python3 scripts/bootstrap_test_tools.py --source git-pinned --compiler clang \
  --output artifacts/test-tools-git --prefix vendor/ntfs-tools-git
```

Each build owns a new vendor work directory, evidence directory and final prefix.
Configure/build/install commands have deadlines and bounded separate original
stdout/stderr logs. Failure stops the batch, kills its process group when needed,
and writes terminal failure status; completed or failed logs are never replaced.
An explicit compiler is selected through the isolated tool environment. Ambient
credentials, CC and flags cannot enter build reports or silently change selection.

Upstream's [build configuration](https://github.com/tuxera/ntfs-3g/blob/2022.10.3/configure.ac)
uses root executable directories unless an explicit exec-prefix is supplied.
The bootstrap supplies both prefix and exec-prefix, disables the FUSE driver,
mount helper and ldconfig, and installs first into a private DESTDIR. Unexpected
staged top-level destinations refuse publication. Only the resulting private
utility tree is copied beneath vendor; no system prefix is installed. Original
COPYING/COPYING.LIB notices and source/compiler/binary identities are retained.

## Immutable image comparison

```sh
python3 tests/interoperability.py --tools vendor/ntfs-tools-archive \
  --reader .build/ntfs-inspect --output artifacts/interoperability-archive
```

The consumer binds selected binaries to their completed `source-provenance.json`
(or an explicit `--tool-provenance` bootstrap report). It authors four regular
64-MiB geometry profiles with the original 100-file byte oracle, long directory,
Unicode name, ADS and case-folding checks. The core and external ntfscat must
match the independently authored contents. Exact image hashes before and after
read-only comparison remain equal, including diagnostic checks on failure.

Every command uses the same credential-isolating environment with fatal sanitizer
settings, a per-command deadline, bounded binary output and a whole-run deadline.
The original image, payloads and commands remain in a fresh output directory.
`report.json` records current/failed profiles, tool provenance and explicit
absence of Windows acceptance. A missing executable or failed subprocess leaves
a failure report instead of a misleading running state.

Portable `external-tool-contracts` covers download preservation/hash admission,
archive path/type checks, exact Git pin refusal before source execution,
vendor-only installation targets and terminal oracle errors. Bounded subprocess
and binary-output contracts are shared with the benchmark toolchain tests.
Passing those synthetic contracts is distinct from building the external utilities
and passing actual interoperability or Windows qualification.
