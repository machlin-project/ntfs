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
The fuzzer authors 1-MiB physical images instead of retaining unused 8-MiB tails
for every corpus entry. All fixture payload locations and large logical sparse
sizes are preserved. The corpus directory includes the input-size bound so older
full-image corpora remain available without being loaded into the compact run.
The process RSS budget stays 1 GiB, independently of the harness's 8-MiB core
allocation budget. A corpus-growth RSS failure is still a failed fuzz run and
must be reported and diagnosed before retrying.

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
