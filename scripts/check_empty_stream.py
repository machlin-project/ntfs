#!/usr/bin/env python3
"""Prove the empty-stream regression fails in the retained component and passes now.

Only write_stream.c is historical. Both binaries use current headers, the other
current core components, and the same current independent regression test.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

from benchmark_toolchain import command, identity
from bounded_tool import run_tool
from environment import sanitizer_environment, selected_toolchain

ROOT = Path(__file__).resolve().parents[1]
BASELINE = '35136fa055d83928b27f5e7238fa289fb5a9cc0c'
SOURCE_BYTES_MAX = 1024 * 1024
COMPILE_TIMEOUT_SECONDS = 120
RUN_TIMEOUT_SECONDS = 60
EXPECTED_DIAGNOSTIC = 'runtime error: applying zero offset to null pointer'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', default='clang')
    parser.add_argument('--reference', default=BASELINE)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('This differential gate requires the Linux Clang UBSan diagnostic')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report_path = output / 'report.json'
    report = dict(status='running', historical_component='core/write_stream.c',
                  scope=__doc__, assertions_enabled=True, frame_limit_bytes=2048,
                  baseline_expected_failure=False, current_passed=False)

    def save():
        report_path.write_text(json.dumps(report, indent=2) + '\n')

    save()
    try:
        environment = selected_toolchain(args.compiler)
        report['toolchain'] = identity(environment)
        if 'clang' not in report['toolchain']['compiler_version'].lower():
            raise ValueError('The negative diagnostic gate requires actual Clang')
        revision = run_tool(['git', 'rev-parse', '--verify', '--end-of-options',
                             args.reference + '^{commit}']).decode().strip()
        if not re.fullmatch('[0-9a-f]{40}', revision):
            raise ValueError('Expected an exact retained Git commit')
        report['baseline_revision'] = revision
        baseline = output / 'baseline-write_stream.c'
        baseline.write_bytes(run_tool(['git', 'show', revision + ':core/write_stream.c'],
                                      output_limit=SOURCE_BYTES_MAX))
        report['baseline_component_sha256'] = digest(baseline)
        report['current_component_sha256'] = digest(ROOT / 'core/write_stream.c')
        harness = ROOT / 'tests/mutation_stream_cache.c'
        report['regression_sha256'] = digest(harness)
        flags = [environment['CC'], '-std=c11', '-O1', '-g', '-UNDEBUG',
                 '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                 '-fno-omit-frame-pointer', '-Wall', '-Wextra', '-Werror',
                 '-Wdeclaration-after-statement', '-I', str(ROOT / 'include'),
                 '-I', str(ROOT / 'core'), '-I', str(ROOT / 'tests')]
        strict = ['-ffreestanding', '-fno-builtin', '-Wframe-larger-than=2048']
        objects = []
        sources = [path for path in sorted((ROOT / 'core').glob('*.c'))
                   if path.name != 'write_stream.c']
        sources += [harness, ROOT / 'tests/fuzz_device.c']
        for source in sources:
            label = source.parent.name + '-' + source.stem
            target = output / (label + '.o')
            command([*flags, *(strict if source.parent.name == 'core' else []),
                     '-c', source, '-o', target], output, label, environment,
                    timeout=COMPILE_TIMEOUT_SECONDS)
            objects.append(target)
        runtime = sanitizer_environment()
        report['sanitizer_options'] = {key: runtime[key] for key in ('ASAN_OPTIONS', 'UBSAN_OPTIONS')}
        for name, source in (('baseline', baseline), ('current', ROOT / 'core/write_stream.c')):
            target = output / (name + '-write_stream.o')
            binary = output / (name + '-regression')
            command([*flags, *strict, '-c', source, '-o', target], output,
                    name + '-compile', environment, timeout=COMPILE_TIMEOUT_SECONDS)
            command([*flags, *objects, target, '-o', binary], output,
                    name + '-link', environment, timeout=COMPILE_TIMEOUT_SECONDS)
            report[name + '_binary_sha256'] = digest(binary)
            if name == 'baseline':
                try:
                    command([binary], output, 'baseline-run', runtime, timeout=RUN_TIMEOUT_SECONDS)
                except RuntimeError:
                    execution = json.loads((output / 'baseline-run.command.json').read_text())
                    errors = (output / 'baseline-run.stderr').read_text()
                    if (not execution.get('exitCode') or EXPECTED_DIAGNOSTIC not in errors or
                            'baseline-write_stream.c:' not in errors or
                            'SUMMARY: UndefinedBehaviorSanitizer:' not in errors):
                        raise ValueError('Historical component failed for an unexpected reason')
                    report['baseline_expected_failure'] = True
                else:
                    raise ValueError('Historical component unexpectedly passed the new regression')
            else:
                command([binary], output, 'current-run', runtime, timeout=RUN_TIMEOUT_SECONDS)
                report['current_passed'] = True
            save()
        report['status'] = 'pass'
    except BaseException as error:
        report['status'] = 'failed'
        report['error'] = f'{type(error).__name__}: {error}'
        raise
    finally:
        save()
    print('PASS: retained component reproduces exact fatal null-offset UBSan finding; current regression passes')


if __name__ == '__main__':
    main()
