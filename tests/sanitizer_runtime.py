#!/usr/bin/env python3
"""Observe actual sanitizer exits after the common clean environment boundary."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from environment import sanitizer_environment, tool_environment
from bounded_tool import run_tool

COMPILE_TIMEOUT_SECONDS = 60
RUNTIME_TIMEOUT_SECONDS = 10
OUTPUT_BYTES_MAX = 1024 * 1024
SENTINEL_NAME = 'NTFS_TEST_CREDENTIAL_SENTINEL'
SENTINEL_VALUE = 'synthetic-ambient-sentinel'


def run(arguments, environment, directory, name, timeout):
    value = subprocess.run(arguments, cwd=directory, env=environment, stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if len(value.stdout) > OUTPUT_BYTES_MAX or len(value.stderr) > OUTPUT_BYTES_MAX:
        raise ValueError('Sanitizer contract output exceeds its retained bound')
    (directory / (name + '.stdout')).write_bytes(value.stdout)
    (directory / (name + '.stderr')).write_bytes(value.stderr)
    return value


def main():
    artifacts = ROOT / 'artifacts'
    artifacts.mkdir(exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix='sanitizer-runtime-', dir=artifacts))
    # These synthetic inputs must neither enter children nor disable termination.
    os.environ[SENTINEL_NAME] = SENTINEL_VALUE
    os.environ['ASAN_OPTIONS'] = 'halt_on_error=0:abort_on_error=0'
    os.environ['UBSAN_OPTIONS'] = 'halt_on_error=0:abort_on_error=0'
    environment = sanitizer_environment()
    assert SENTINEL_NAME not in environment
    assert all('halt_on_error=1' in environment[name] and 'abort_on_error=1' in environment[name]
               for name in ('ASAN_OPTIONS', 'UBSAN_OPTIONS'))
    assert 'ASAN_OPTIONS' not in tool_environment() and 'UBSAN_OPTIONS' not in tool_environment()
    if sys.platform == 'darwin':
        compiler = subprocess.check_output(['xcrun', '--find', 'clang'], env=tool_environment(),
                                           stdin=subprocess.DEVNULL, text=True, timeout=RUNTIME_TIMEOUT_SECONDS).strip()
        sdk = ['-isysroot', subprocess.check_output(['xcrun', '--show-sdk-path'], env=tool_environment(),
                                                   stdin=subprocess.DEVNULL, text=True,
                                                   timeout=RUNTIME_TIMEOUT_SECONDS).strip()]
    else:
        compiler = shutil.which('clang')
        if compiler is None:
            raise RuntimeError('Sanitizer contract requires the development Clang toolchain')
        sdk = []
    executables = {}
    for kind in ('address', 'undefined'):
        executable = output / ('sanitizer-' + kind)
        compile_result = run([compiler, *sdk, '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                              '-Wdeclaration-after-statement', '-fsanitize=' + kind,
                              str(ROOT / 'tests/sanitizer_runtime.c'), '-o', str(executable)],
                             tool_environment(), output, 'compile-' + kind, COMPILE_TIMEOUT_SECONDS)
        assert compile_result.returncode == 0, compile_result.stderr.decode(errors='replace')
        executables[kind] = executable
    cases = []
    for name, selected, kind, fault, expected, marker in (
            ('clean-undefined', environment, 'undefined', 'clean', True, b''),
            ('clean-address', environment, 'address', 'clean', True, b''),
            ('recovering-undefined-control', tool_environment(), 'undefined', 'undefined', True, b'runtime error:'),
            ('fatal-undefined', environment, 'undefined', 'undefined', False, b'runtime error:'),
            ('fatal-address', environment, 'address', 'address', False, b'ERROR: AddressSanitizer')):
        value = run([str(executables[kind]), fault], selected, output, name, RUNTIME_TIMEOUT_SECONDS)
        assert (value.returncode == 0) == expected, (name, value.returncode)
        if marker:
            assert marker in value.stderr, (name, value.stderr.decode(errors='replace'))
        else:
            assert not value.stdout and not value.stderr
        assert SENTINEL_VALUE.encode() not in value.stdout + value.stderr
        cases.append({'name': name, 'returncode': value.returncode,
                      'expected_injected_finding': bool(marker),
                      'stderr': str((output / (name + '.stderr')).relative_to(ROOT))})
    for kind, marker in (('undefined', 'runtime error:'), ('address', 'ERROR: AddressSanitizer')):
        assert run_tool([str(executables[kind]), 'clean']) == b''
        try:
            run_tool([str(executables[kind]), kind], output_limit=OUTPUT_BYTES_MAX)
        except RuntimeError as error:
            message = str(error)
            assert 'Diagnostic exited' in message and marker in message
            assert SENTINEL_VALUE not in message
            path = output / ('diagnostic-' + kind + '.stderr')
            path.write_text(message + '\n')
            cases.append({'name': 'diagnostic-' + kind, 'wrapper_rejected': True,
                          'expected_injected_finding': True,
                          'stderr': str(path.relative_to(ROOT))})
        else:
            raise AssertionError('Diagnostic wrapper accepted an injected sanitizer finding')
    report = {'scope': 'Disposable injected sanitizer faults; no driver or filesystem I/O',
              'compiler': compiler,
              'sanitizer_options': {name: environment[name] for name in ('ASAN_OPTIONS', 'UBSAN_OPTIONS')},
              'cases': cases}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: clean execution, recovering UBSan control, fatal UBSan/ASan exits, diagnostic rejection and ambient '
          'option/sentinel isolation; report=' + str((output / 'report.json').relative_to(ROOT)))


if __name__ == '__main__':
    main()
