#!/usr/bin/env python3
"""Compare portable Release products from two ordinary isolated Meson builds."""
from pathlib import Path
import argparse
import filecmp
import hashlib
import json
import os
import platform
import selectors
import shutil
import signal
import subprocess
import sys
import time

from bounded_tool import run_tool
from environment import selected_toolchain

ROOT = Path(__file__).resolve().parents[1]
PRODUCTS = ('libntfs.a', 'libntfs-posix.a', 'ntfs-inspect', 'ntfs-validate',
            'ntfs-dacl-evaluate', 'ntfs-logfile', 'ntfs-workload', 'ntfs-benchmark')
TARGETS = PRODUCTS[2:]
SOURCE_PATHS = ('meson.build', 'core', 'include', 'adapters/posix', 'tools',
                'scripts/check_reproducible.py', 'scripts/environment.py',
                'scripts/bounded_tool.py')
HASH_IO_BYTES = 1024 * 1024
MAX_BUILD_LOG_BYTES = 4 * HASH_IO_BYTES
LOG_IO_BYTES = 65536
DEFAULT_JOBS = 4
MAX_JOBS = 8
DEFAULT_TIMEOUT_SECONDS = 300
MAX_TIMEOUT_SECONDS = 900


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(HASH_IO_BYTES), b''):
            value.update(chunk)
    return value.hexdigest()


def clean_product_sources():
    # Ordinary Git owns source history; this check has no custom source inventory.
    value = run_tool(['git', 'status', '--porcelain', '--untracked-files=normal',
                      '--', *SOURCE_PATHS])
    if value:
        raise ValueError('Commit build-source changes before comparing release builds')


def run_logged(command, log, environment, timeout):
    """Retain bounded combined output, including diagnostics from a failed build."""
    deadline = time.monotonic() + timeout
    retained = 0
    process = subprocess.Popen(command, cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               start_new_session=True)
    try:
        with log.open('wb') as output, selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f'Build exceeded its deadline; see {log}')
                ready = selector.select(remaining)
                if not ready:
                    raise TimeoutError(f'Build exceeded its deadline; see {log}')
                chunk = os.read(process.stdout.fileno(), LOG_IO_BYTES)
                if not chunk:
                    selector.unregister(process.stdout)
                    continue
                available = MAX_BUILD_LOG_BYTES - retained
                output.write(chunk[:available])
                retained += min(len(chunk), available)
                if len(chunk) > available:
                    raise ValueError(f'Build exceeded its retained-log budget; see {log}')
        process.wait(timeout=max(0, deadline - time.monotonic()))
        if process.returncode != 0:
            raise RuntimeError(f'Build exited {process.returncode}; see {log}')
    except BaseException:
        # The session belongs only to this compiler/build invocation. Kill its
        # children as well as the launcher on timeout or output-budget failure.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise
    finally:
        process.stdout.close()


def selected_options(build):
    raw = run_tool(['meson', 'introspect', '--buildoptions', str(build)],
                   timeout=30, output_limit=65536)
    selected = {item['name']: item['value'] for item in json.loads(raw)
                if item['name'] in ('buildtype', 'optimization', 'debug', 'b_sanitize',
                                    'b_lto', 'b_ndebug', 'c_std', 'werror')}
    if (selected.get('buildtype') != 'release' or selected.get('b_sanitize') not in
            ('none', [], ['none']) or str(selected.get('optimization')) != '3' or
            selected.get('debug') or selected.get('b_ndebug') not in ('false', False)):
        raise ValueError('Expected the requested unsanitized optimized release configuration')
    return selected


def write_report(path, report):
    path.write_text(json.dumps(report, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='New ignored artifact directory')
    parser.add_argument('--jobs', type=int, default=DEFAULT_JOBS)
    parser.add_argument('--compiler', help='One explicit compiler executable; ambient CC is ignored')
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT_SECONDS,
                        help='Deadline in seconds for each setup/compile invocation')
    args = parser.parse_args()
    if sys.platform not in ('darwin', 'linux'):
        parser.error('This POSIX build check supports macOS and Linux')
    if not 1 <= args.jobs <= MAX_JOBS or not 1 <= args.timeout <= MAX_TIMEOUT_SECONDS:
        parser.error('jobs or timeout exceeds its positive execution budget')
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    report_path = args.output / 'report.json'
    report = {'schema': 1, 'status': 'running', 'platform': platform.platform(),
              'machine': platform.machine(), 'scope': 'portable release archives and CLI products; '
              'same checkout/toolchain, distinct build directories',
              'native_app_qualified': False, 'relocated_checkout_qualified': False,
              'builds': [], 'products': []}
    write_report(report_path, report)
    try:
        clean_product_sources()
        report['git_head_before'] = run_tool(['git', 'rev-parse', 'HEAD']).decode().strip()
        environment = selected_toolchain(args.compiler)
        compiler = environment['CC']
        report['archive_environment'] = {'ZERO_AR_DATE': environment['ZERO_AR_DATE']}
        if sys.platform == 'darwin':
            sdk = environment['SDKROOT']
            report['sdk_path'] = sdk
            report['sdk_version'] = run_tool(['xcrun', '--show-sdk-version']).decode().strip()
        report['compiler_path'] = compiler
        report['compiler_version'] = run_tool([compiler, '--version']).decode().splitlines()[0]
        for name in ('first', 'second'):
            directory = args.output / name
            setup = ['meson', 'setup', str(directory), '-Dbuildtype=release',
                     '-Db_sanitize=none', '-Db_lundef=false', '-Db_ndebug=false']
            compile_command = ['meson', 'compile', '-C', str(directory), '-j', str(args.jobs), *TARGETS]
            entry = {'directory': str(directory), 'setup_command': setup,
                     'compile_command': compile_command, 'status': 'running'}
            report['builds'].append(entry)
            write_report(report_path, report)
            started = time.monotonic()
            run_logged(setup, args.output / f'{name}-setup.log', environment, args.timeout)
            entry['options'] = selected_options(directory)
            run_logged(compile_command, args.output / f'{name}-compile.log', environment, args.timeout)
            entry['seconds'] = time.monotonic() - started
            entry['status'] = 'pass'
            write_report(report_path, report)
        if report['builds'][0]['options'] != report['builds'][1]['options']:
            raise ValueError('Isolated builds did not use identical selected options')
        for product in PRODUCTS:
            first, second = (args.output / name / product for name in ('first', 'second'))
            result = {'name': product, 'first_bytes': first.stat().st_size,
                      'second_bytes': second.stat().st_size, 'first_sha256': digest(first),
                      'second_sha256': digest(second),
                      'byte_equal': filecmp.cmp(first, second, shallow=False)}
            report['products'].append(result)
        clean_product_sources()
        report['git_head_after'] = run_tool(['git', 'rev-parse', 'HEAD']).decode().strip()
        if report['git_head_before'] != report['git_head_after']:
            raise ValueError('Source revision changed during the build comparison')
        if not all(item['byte_equal'] for item in report['products']):
            raise ValueError('Release artifacts differ between build directories')
        report['status'] = 'pass'
    except Exception as error:
        report['status'] = 'failed'
        report['error'] = f'{type(error).__name__}: {error}'
        raise
    finally:
        write_report(report_path, report)
    print(f'PASS: two isolated release builds, {len(report["products"])} byte-identical '
          f'products; {report_path}')


if __name__ == '__main__':
    main()
