"""Shared portable flags and retained evidence for the existing benchmark tools.

These helpers do not build products: Meson remains the ordinary build system.
The isolated compiler commands are the existing matched benchmark experiments.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import signal
import subprocess
import sys
import time

from environment import selected_toolchain

ROOT = Path(__file__).resolve().parents[1]
QUERY_TIMEOUT_SECONDS = 15
COMMAND_TIMEOUT_SECONDS = 300
CLEANUP_TIMEOUT_SECONDS = 5
MAX_LOG_BYTES = 8 * 1024 * 1024
LOG_CHUNK_BYTES = 65536
MAX_REPETITIONS = 100
PROFILES = {'userspace': [], 'general-registers': ['-DKERNEL', '-mgeneral-regs-only']}


def select(compiler=None):
    if sys.platform not in ('darwin', 'linux'):
        raise ValueError('Host benchmark tools support macOS and Linux')
    environment = selected_toolchain(compiler)
    if platform.machine().lower() not in ('arm64', 'aarch64', 'x86_64', 'amd64'):
        raise ValueError('General-register experiments require ARM64 or x86_64')
    return environment


def sdk_flags(environment):
    return ['-isysroot', environment['SDKROOT']] if sys.platform == 'darwin' else []


def host_flags():
    # Expose clock_gettime and MAP_ANON under strict C11 on glibc as on Darwin.
    return ['-D_POSIX_C_SOURCE=200809L', '-D_DEFAULT_SOURCE'] if sys.platform == 'linux' else []


def section_flags():
    return ['-ffunction-sections', '-fdata-sections'] if sys.platform == 'linux' else []


def linker_flags():
    return ['-Wl,-dead_strip'] if sys.platform == 'darwin' else ['-Wl,--gc-sections']


def identity(environment):
    def query(*arguments):
        return subprocess.check_output(arguments, cwd=ROOT, env=environment,
                                       stdin=subprocess.DEVNULL, text=True,
                                       timeout=QUERY_TIMEOUT_SECONDS).strip()
    return {'compiler_path': environment['CC'],
            'compiler_version': query(environment['CC'], '--version'),
            'compiler_target': query(environment['CC'], '-dumpmachine'),
            'sdk_path': environment.get('SDKROOT'),
            'sdk_version': query('xcrun', '--show-sdk-version') if sys.platform == 'darwin' else None,
            'platform': platform.platform(), 'machine': platform.machine(),
            'host': platform.node(), 'processor': platform.processor(),
            'profiles': PROFILES}


def matching(prepared, toolchain):
    if prepared.get('toolchain') != toolchain:
        raise ValueError('Comparison requires the same compiler, SDK, host and contexts as preparation')


def validate_comparison(name, repetitions):
    if (not name or Path(name).name != name or name in ('.', '..') or
            not 5 <= repetitions <= MAX_REPETITIONS):
        raise ValueError('Comparison needs one new directory name and 5 to 100 repetitions')


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def retained_hashes(output, paths):
    return {str(path.relative_to(output)): digest(path) for path in paths}


def verify_hashes(output, hashes):
    if not hashes:
        raise ValueError('Preparation does not identify retained inputs and binaries')
    for name, expected in hashes.items():
        path = (output / name).resolve(strict=True)
        if not path.is_relative_to(output.resolve()) or digest(path) != expected:
            raise ValueError(f'Retained benchmark input or binary changed: {name}')


def command(argv, output, name, env, timeout=COMMAND_TIMEOUT_SECONDS, output_limit=MAX_LOG_BYTES,
            *, cwd=None, text=True):
    """Bound wall time and both logs, preserving diagnostics even on failure."""
    if timeout <= 0 or output_limit <= 0:
        raise ValueError('Command budgets must be positive')
    argv = list(map(str, argv))
    cwd = ROOT if cwd is None else Path(cwd)
    retained = [output / f'{name}{suffix}' for suffix in ('.command.json', '.stdout', '.stderr')]
    if any(path.exists() or path.is_symlink() for path in retained):
        raise FileExistsError(f'Refusing to replace retained command artifacts: {name}')
    entry = {'argv': argv, 'cwd': str(cwd), 'timeout_seconds': timeout, 'output_limit_bytes': output_limit,
             'status': 'running'}
    report = output / f'{name}.command.json'
    with report.open('x') as retained_report:
        retained_report.write(json.dumps(entry, indent=2) + '\n')
    process = None
    deadline = time.monotonic() + timeout
    counts = [0, 0]
    try:
        with (output / f'{name}.stdout').open('xb') as stdout, \
                (output / f'{name}.stderr').open('xb') as stderr:
            process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       start_new_session=True)
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, (stdout, 0))
                selector.register(process.stderr, selectors.EVENT_READ, (stderr, 1))
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not (ready := selector.select(remaining)):
                        raise TimeoutError(f'{name} exceeded its command deadline')
                    for key, _ in ready:
                        chunk = os.read(key.fileobj.fileno(), LOG_CHUNK_BYTES)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        stream, index = key.data
                        available = output_limit - counts[index]
                        stream.write(chunk[:available])
                        counts[index] += min(len(chunk), available)
                        if len(chunk) > available:
                            raise ValueError(f'{name} exceeded its retained-log budget')
            process.wait(timeout=max(0, deadline - time.monotonic()))
            entry['exitCode'] = process.returncode
            if process.returncode:
                raise RuntimeError(f'{name} exited {process.returncode}; see retained stderr')
        entry['status'] = 'pass'
        stdout = output / f'{name}.stdout'
        return stdout.read_text() if text else stdout.read_bytes()
    except BaseException as error:
        entry['status'] = 'failed'
        entry['error'] = f'{type(error).__name__}: {error}'
        if process is not None and process.returncode is None:
            # A child not yet reaped still owns its PID. Kill its session group
            # before poll/wait can release that identity. Darwin can refuse a
            # group signal after the last live member exits; preserve the
            # original failure and record cleanup diagnostics separately.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError as cleanup_error:
                entry.setdefault('cleanup_errors', []).append(
                    f'group termination: {type(cleanup_error).__name__}: {cleanup_error}')
                if process.poll() is None:
                    try:
                        process.kill()
                    except OSError as child_error:
                        entry['cleanup_errors'].append(
                            f'child termination: {type(child_error).__name__}: {child_error}')
            try:
                process.wait(timeout=CLEANUP_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                entry.setdefault('cleanup_errors', []).append('Owned child did not exit before cleanup deadline')
            entry['exitCode'] = process.returncode
        raise
    finally:
        if process is not None:
            process.stdout.close()
            process.stderr.close()
        report.write_text(json.dumps(entry, indent=2) + '\n')
