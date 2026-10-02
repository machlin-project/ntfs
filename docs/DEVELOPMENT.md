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
Use `--target all` for the image and eight standalone parser/decision targets, or select
`mapping-pairs`, `attribute-list`, `index-root`, `index-block`, `lznt1`, `reparse`,
`security` or `access`. The time budget applies per target. Each campaign retains its own
binary, log and report; persistent corpora remain under the selected `--output`.
The `access` target independently mutates a descriptor/token envelope, including
group attributes, user/restricting SIDs, requested rights and comparison limits.
It asserts deterministic decisions, exact grants and zero error outputs. See
ACCESS.md for the discretionary contract and remaining authorization policies.
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
