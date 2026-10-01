#!/usr/bin/env python3
"""Format only owned C/Objective-C source using the selected Xcode toolchain."""
from pathlib import Path
import argparse
import shutil
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
formatter = subprocess.check_output(['xcrun', '--find', 'clang-format'], text=True).strip() if sys.platform == 'darwin' else shutil.which('clang-format')
if not formatter:
    raise SystemExit('clang-format is required')
paths = sorted(p for d in ('core', 'include', 'adapters', 'tests', 'tools') for p in (root / d).rglob('*') if p.suffix in ('.c', '.h', '.m') and '.xcodeproj' not in str(p))
subprocess.run([formatter, *(('--dry-run', '--Werror') if args.check else ('-i',)), *map(str, paths)], cwd=root, check=True)
