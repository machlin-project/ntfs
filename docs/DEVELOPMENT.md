# Development

Run standalone commands in `/Users/darekhta/Development/machlin/ntfs` (or the
equivalent checkout). Use the ongoing development branch. Generated state lives
under `.build/`, `artifacts/` and `vendor/`, all ignored. Xcode clang/clang-format,
Meson, Ninja, Python 3 and XcodeGen are development prerequisites.

`make test` configures the sanitized C build, generates deterministic images and
runs its tests. `make check-style` checks C formatting; `make format` applies it.
`make fskit` builds the app and extension unsigned. Builds never install the
extension or touch boot policy. Installed tests belong in a dedicated stock macOS
VM; use the absolute lab working directory for its VM commands.

Routine prepared execution is delegated to Luna; implementation and diagnosis
remain with the main agent. Sol owns VM preparation and installed FSKit work.
Record reports in artifacts, source history in Git, and summaries in acceptance.
Never interpret an unsigned build as an installed mount or a commercial release.

`scripts/check_core.py` additionally compiles arm64 and x86_64 objects on macOS
without libc assumptions and with a 2 KiB frame limit. `scripts/test_fskit.py`
exercises the real adapter against a bounded fake resource in-process; it neither
mounts an image nor enables an extension. `scripts/fuzz.py --seconds 60` builds a
separate libFuzzer binary with ASan/UBSan and bounded memory/I/O. Failures retain
their corpus input under artifacts/fuzz for diagnosis.
The component includes eight semaphore-gated resource-read/lifecycle scenarios
and interleaved enumeration with five-second test deadlines. Modern runtime
checks explicitly SKIP without macOS 27. See LIFECYCLE.md for admission/teardown
ownership and the absence of a native synchronous-I/O timeout guarantee.
Five additional modeled eligibility/ownership/publication cases cover conditional
reclaim, weak canonical identity, final-item lifetime and lookup replies racing
reclaim/unmount/deactivation. The eligibility model does not execute the real
macOS 27 kernel/framework count mechanism.
The separate enumeration component checks names-only virtual current/parent
entries, parent release/remount and corrupt-edge rejection, separate native cookie
views, alias stability, interleaved buffers, scan budgets, packer revocation and
all 33 allocation/13 I/O fault positions in its current nested-index operation. The
content component additionally exercises six encoded-stream metadata variants and
ten explicit corruption/unsupported rejections, requested-size pages, independent
ADS, zero-byte read errors, remount and revocation without default-content I/O.
The link component authors 47 native path/storage verdicts and checks root option
binding, single-edge identity, requested metadata/names-only pages, aliases,
original-wire xattrs, remount/revocation and all 79 allocation/17 read fault
positions across listed/reserved lookup and reopened snapshots. Core reparse tests
also check copy guards, physical allocation and node-independent lifetime. See
LINK-POLICY.md for the supported subset and remaining resolution contracts.
The current component has seven explicit macOS-27 runtime SKIPs: lifecycle,
pressure, enumeration, content metadata, link projection and two case-policy checks. These in-process
results do not mount the filesystem.
The pressure component injects Dispatch data-source notifications without host
pressure changes. It measures disposable core bytes for LZNT1/XPRESS/LZX, delivers
an event during blocked I/O, sweeps cold LZX allocation/read faults and checks
copied ADS/reparse data, identities, interleaved pending entries and remount.
See READ-CACHE-POLICY.md for exact measurements and native delivery/stress gaps.
Use `--target all` for the image, whole-volume diagnostic and ten standalone parser/decision targets, or select
`mapping-pairs`, `attribute-list`, `index-root`, `index-block`, `lznt1`, `reparse`,
`security`, `access`, `wof` or `logfile`. The time budget applies per target. Each campaign retains its own
binary, log and report; persistent corpora remain under the selected `--output`.
Whole-image `image`/`validation` exploration uses one libFuzzer child at a time
with bounded corpus subsets and merges. Fixed-file batches first execute every
authored seed once and retain `seed-replay.log` plus its report outcome; child
subset selection alone is not seed-coverage evidence. OOM/timeout/crash remain
fatal, with unchanged sanitizers and per-process RSS/input limits. The configured
RSS ceiling is not actual or aggregate memory usage. The observed earlier image
corpus OOM and its fixed replay remain separately recorded in ACCEPTANCE.md.
The `logfile` target uses a 2-MiB envelope for restart/client/page/logical-record/
NTFS-update/LSN primitives and complete exported logical sources. Its custom
mutator restores and reseals USA pages or either restart copy, reaching checked
restart-area spans alongside ordinary framing mutations. The `logfile`,
`logfile-cli` and `fuzz-logfile` suites check independent metadata/restored-byte
oracles, zero errors, scratch/input guards and lossless names. `ntfs-logfile`
inspects bounded exported packets/logical journals and read-only NTFS image files. The `logfile-source`,
`logfile-source-cli` and `fuzz-logfile-source` suites cover bounded copy selection,
conflicts, cached clients, staged physical pages, backend errors and read credits.
The `logfile-records`/`logfile-records-cli` suites add exact physical circular
assembly, one wrap, extended/USA-intersecting bytes, shared credits and the
1-MiB record-cap boundary. `circular-record LOGICAL_JOURNAL_FILE DECIMAL_LSN`
retains exact bytes and physical accounting with no current-history claim.
The two record fuzz suites check resealed record/continuation mutations and
explicit fault/budget controls. The logfile campaign first replays every authored
seed in fixed batches; its report lists 28 included record sources, six fault
seeds and the two complete 4-MiB sources excluded by its unchanged 2-MiB cap.
Direct C/CLI tests retain both larger sources without truncation.
The `logfile-clients`/`logfile-clients-cli` suites check 858 pair lookups and 42
exact reports across seven active/free snapshots, including sequence boundaries,
full-length unpaired names and the client-count limit. `active-client
LOGICAL_JOURNAL_FILE INDEX SEQUENCE` reports selected active snapshot metadata.
The `fuzz-logfile-clients` suite and dedicated campaign check the same cached
lookup with mismatched sequences and no extra I/O/allocation. Snapshot membership
does not qualify record liveness or current journal history.
The `logfile-volume`, `logfile-volume-cli` and `fuzz-logfile-volume` suites add
counted ordinary-stream binding, fragmented/listed storage, source-node-independent
ownership, mount/binding rejection, physical partial-read faults/retries and
unchanged image/report oracles. `volume-journal` uses a portable core mount,
never a native mount. Image fuzz also authors small journal-bearing volumes with
explicit geometry skips for larger layouts; source/component suites retain them.
All 22 independent sources fit the fuzz envelope, including three 1-MiB files;
default core memory/I/O caps remain unchanged. LOGFILE.md defines commands and the
remaining complete-journal, LCN-less, Windows and recovery requirements.
The `access` target independently mutates a descriptor/token envelope, including
group attributes, user/restricting SIDs, requested rights and comparison limits.
It asserts deterministic decisions, exact grants and zero error outputs. See
ACCESS.md for the discretionary contract and remaining authorization policies.
The `wof` target independently mutates provider metadata, bounded chunk tables
and exact-size XPRESS/LZX units with a 128-KiB input ceiling. It checks deterministic
verdicts/counts and scratch/output guards; no filesystem provider reads or Windows
codec execute. `tests/wof_fixtures.py` and `tests/lzx_fixtures.py` author its seeds
and separate content/error vectors. The separate `wof-files` suite authors 37 complete storage/format cases,
byte oracles and 376 allocation/101 read faults in selected stat/open/cold-content
operations. The ordinary image target reads first/middle/tail default positions
and therefore also exercises provider storage/table/content lifetimes. Twenty-three
legacy component cases cover WOF attributes/content, backing inventory, ADS/raw
metadata and remount/revocation; modern content checks retain their runtime SKIP.
The LZX suite checks 140 content/31 invalid vectors; the optional external oracle
command in WOF.md checks captured wimlib packets and reverse-direction synthetic
decoding without linking that codec into product binaries. See WOF.md for contracts
and remaining Windows/native qualification. FSKIT-EXT4-LESSONS.md records the
inspected sibling history, adopted result/error and revoked-acquisition guards,
and native/memory-pressure/distribution work still required.
Image mutation can preserve FILE/INDX fixups and alter validated inner spans.
The fuzzer authors 1-MiB physical images instead of retaining unused 8-MiB tails
for every corpus entry. All fixture payload locations and large logical sparse
sizes are preserved. The corpus directory includes the input-size bound so older
full-image corpora remain available without being loaded into the compact run.
The process RSS budget stays 1 GiB, independently of the harness's 8-MiB core
allocation budget. A corpus-growth RSS failure is still a failed fuzz run and
must be reported and diagnosed before retrying.

Reparse fixture generation supplies both full images and small standalone
`.reparse` buffers. The reparse target seeds standalone buffers; image fuzzing exercises the decoder
and opens/copies reparse metadata through the public node API. Inspect metadata
without following Windows targets using
`.build/ntfs-inspect .build/fixtures/reparse-relative.img reparse /hello.txt`.
The inspector prints UTF-16 code units so unpaired surrogates remain visible.

Some Xcode distributions omit the libFuzzer runtime. In that case, pass an
explicit full LLVM compiler, for example `--compiler /opt/homebrew/opt/llvm/bin/clang`.
The harness reports a missing runtime before linking. Core and FSKit acceptance
still use the selected Xcode toolchain; this override is only for fuzzing.

The independent suite is `tests/interoperability.py`; bootstrap pinned external
tools with `scripts/bootstrap_test_tools.py`. It uses regular image files only,
and refuses to overwrite earlier image inputs. See PERFORMANCE.md for release
build measurements. Sanitizers are not a performance configuration.

Build/test subprocesses receive an explicit environment allowlist. Meson's report
format includes environment values; do not invoke it with ambient credentials or
display entire unreviewed reports. CI uploads only selected generated reports.
The workflow is prepared for macOS/Linux core checks and independent Linux image
tests, but remote CI is unverified until the owner creates a private repository.

`corpus-contract` and `workload-contract` are regular sanitized suites. The former
checks reference-addressed inspection, independently expected stream bytes and
inventories, hard-link consistency, original UTF-16 and truthful partial reporting.
The latter verifies measured read ranges against original fixture bytes, ADS,
sparse/VDL/compression, explicit warmup, record-cache controls and serialized
readers on both POSIX and memory callbacks. Neither executes native Windows APIs.
The FSKit component also verifies bounded stream xattrs and their raw UTF-16
reverse manifest. Filename projection adds five namespace images, hard-link and
lossless name reversal, response/scan exhaustion and complete required-allocation
and read-failure sweeps. Their formats and limits appear in NATIVE-NAMESPACE.md.
See CORE-QUALIFICATION.md for Windows-only acquisition and offline verification.

The `secure` suite checks descriptor storage as well as standalone MS-DTYP
framing. `ntfs-inspect IMAGE security-ref HEX_REFERENCE` emits the original
self-relative descriptor bytes, without opening file content.
`security-id HEX_SECURITY_ID` resolves an indexed ID directly. These are
read-only diagnostic APIs, not access decisions. See SECURITY.md.

The `access-oracle-contract` suite tests the independent Windows access collector,
SDK buffer framing, diagnostic transport and truthful offline reports with a
synthetic provider. The `ntfs-dacl-evaluate` executable accepts bounded original
descriptor/SID packets and emits the core's discretionary result; it does not
authenticate identity. Acquire decisions using `scripts/collect_windows_access.py`
on Windows, then compare with `tests/windows_access.py` on POSIX. Use new capture
and report directories. See ACCESS-ORACLE.md for commands and explicit native
qualification limits; no Windows acquisition has run at this checkpoint.

The `case-policy` suite covers stored directory flags and exact/folded lookup,
including collisions split across tree separators, mixed parent policies and
required allocation/read faults. `tests/case_fixtures.py` authors these images
without importing parser code. FSKit components cover sensitive aliases and
mixed directory identities; modern reply tests explicitly SKIP without macOS 27.
See CASE-POLICY.md and ACCEPTANCE.md for evidence and native acceptance limits.

The `stat` suite independently authors encrypted, unknown-compression and
unsupported-unit metadata, including resident/nonresident attribute lists. It
checks complete sizes/mappings, corruption and stale extensions, all required
allocation/read fault positions, retry, independent ADS and exact cleanup.
Private metadata-only descriptions cannot be read; both mapping-pair and
attribute-list fuzz targets exercise that separation. A synthetic metadata
verdict does not qualify EFS decryption or Windows-authored compression layouts.

`validation`, `validation-cli` and `fuzz-validation` qualify the private
read-only diagnostic. Run `.build/ntfs-validate IMAGE` for a JSON report; exit zero
requires a complete verdict. Seven positive-decimal options bound record/run/link
counts, live memory, read calls/bytes and work. The dedicated `--target validation`
campaign uses its own complete compact-image corpus and checks deterministic
reports, exact cleanup and dynamic budgets. Ordinary mount does not implicitly
run this diagnostic. See VALIDATION.md for supported passes and explicit gaps.
Compare both bitmap inventories with independent external exports using existing
images and a new evidence directory:

```sh
python3 tests/validation_oracle.py --images artifacts/interoperability-stream-catalog --output artifacts/interoperability-validation-next
```

Compare against external NTFS-3G exports using an existing interoperability image
directory and a new evidence directory:

```sh
python3 tests/secure_oracle.py --images artifacts/interoperability-stream-catalog --output artifacts/interoperability-secure-next
```

The oracle applies deadlines/output budgets, verifies image hashes and retains
failed run status. It covers indexed and per-file descriptor storage; it does
not mount media or execute Win32/native authorization. The compact image fuzz
campaign includes security-storage inputs and the public snapshot API; larger
maximum-descriptor/second-pair/depth fixtures remain in the ordinary test suite
when their physical placement exceeds the compact image bound.

For repeated optimized measurements use `scripts/benchmark.py`, an independently
supplied original stream payload and a new artifact directory; see PERFORMANCE.md.
The runner checks Meson's selected release/sanitizer options and never displays
its complete option/environment reports. It records each run and integrity check,
including failures, instead of overwriting earlier output.
