#!/usr/bin/env python3
"""Format only owned C/Objective-C source using the selected Xcode toolchain."""
from pathlib import Path
import argparse
import shutil
import subprocess
import sys
from environment import tool_environment

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--check', action='store_true')
parser.add_argument('--formatter', help='Explicit clang-format executable on non-Darwin hosts')
args = parser.parse_args()
env = tool_environment()
if sys.platform == 'darwin' and args.formatter:
    parser.error('Darwin formatting must use the selected Xcode toolchain')
formatter = subprocess.check_output(['xcrun', '--find', 'clang-format'], env=env, text=True, timeout=15).strip() if sys.platform == 'darwin' else shutil.which(args.formatter or 'clang-format', path=env.get('PATH'))
if not formatter:
    raise SystemExit('clang-format is required')
paths = sorted(p for d in ('core', 'include', 'adapters', 'tests', 'tools') for p in (root / d).rglob('*') if p.suffix in ('.c', '.h', '.m') and '.xcodeproj' not in str(p))
subprocess.run([formatter, *(('--dry-run', '--Werror') if args.check else ('-i',)), *map(str, paths)], cwd=root, env=env, check=True, timeout=120)
