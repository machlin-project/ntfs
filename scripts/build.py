#!/usr/bin/env python3
"""Configure a local sanitized build with the selected system toolchain."""
from environment import tool_environment
from pathlib import Path
import subprocess
import sys
import argparse

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('directory', nargs='?', default='.build')
parser.add_argument('--release', action='store_true', help='Unsanitized optimized build for measurements')
args = parser.parse_args()
build = root / args.directory
env = tool_environment()
if sys.platform == 'darwin':
    for key in ('CFLAGS', 'CPPFLAGS', 'CXXFLAGS', 'LDFLAGS', 'CC', 'CXX', 'SDKROOT'):
        env.pop(key, None)
    env['CC'] = subprocess.check_output(['xcrun', '--find', 'clang'], text=True).strip()
    env['SDKROOT'] = subprocess.check_output(['xcrun', '--show-sdk-path'], text=True).strip()
if not (build / 'build.ninja').exists():
    options = ['-Dbuildtype=release', '-Db_sanitize=none'] if args.release else ['-Dbuildtype=debugoptimized', '-Db_sanitize=address,undefined']
    subprocess.run(['meson', 'setup', str(build), *options, '-Db_lundef=false'], cwd=root, env=env, check=True)
subprocess.run(['meson', 'compile', '-C', str(build), '-j', '4'], cwd=root, env=env, check=True)
