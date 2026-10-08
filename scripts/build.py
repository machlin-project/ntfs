#!/usr/bin/env python3
"""Configure a sanitized or Release build with an explicit isolated toolchain."""
import argparse
import json
from pathlib import Path
import subprocess

from environment import selected_toolchain

ROOT = Path(__file__).resolve().parents[1]
MAX_JOBS = 8
BUILD_TIMEOUT_SECONDS = 1800


def verify_compiler(build, compiler):
    """Meson caches CC: never claim an override changed an existing build."""
    inventory = build / 'meson-info/intro-compilers.json'
    recorded = json.loads(inventory.read_text())['host']['c']['exelist']
    if len(recorded) != 1 or Path(recorded[0]).resolve() != Path(compiler).resolve():
        raise ValueError('Build directory uses another compiler; select a fresh build directory')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', nargs='?', default='.build')
    parser.add_argument('--release', action='store_true', help='Unsanitized optimized build for measurements')
    parser.add_argument('--compiler', help='One compiler executable, for example gcc or clang; ambient CC is ignored')
    parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args()
    if not 1 <= args.jobs <= MAX_JOBS:
        parser.error(f'--jobs must be between 1 and {MAX_JOBS}')
    build = (ROOT / args.directory).resolve()
    env = selected_toolchain(args.compiler)
    configured = (build / 'build.ninja').exists()
    if configured:
        verify_compiler(build, env['CC'])
    options = (['-Dbuildtype=release', '-Db_sanitize=none'] if args.release else
               ['-Dbuildtype=debugoptimized', '-Db_sanitize=address,undefined'])
    setup = ['meson', 'setup', *(['--reconfigure'] if configured else []), str(build),
             *options, '-Db_lundef=false', '-Db_ndebug=false']
    subprocess.run(setup, cwd=ROOT, env=env, check=True, timeout=BUILD_TIMEOUT_SECONDS)
    verify_compiler(build, env['CC'])
    subprocess.run(['meson', 'compile', '-C', str(build), '-j', str(args.jobs)],
                   cwd=ROOT, env=env, check=True, timeout=BUILD_TIMEOUT_SECONDS)


if __name__ == '__main__':
    main()
