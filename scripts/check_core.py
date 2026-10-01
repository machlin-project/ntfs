#!/usr/bin/env python3
"""Compile the core without libc assumptions and with a small stack budget."""
from pathlib import Path
import subprocess
import sys
from environment import tool_environment

root = Path(__file__).resolve().parents[1]
output = root / 'artifacts/freestanding'
output.mkdir(parents=True, exist_ok=True)
env = tool_environment()
if sys.platform == 'darwin':
    cc = subprocess.check_output(['xcrun', '--find', 'clang'], text=True).strip()
    sdk = ['-isysroot', subprocess.check_output(['xcrun', '--show-sdk-path'], text=True).strip()]
    targets = [['-arch', 'arm64'], ['-arch', 'x86_64']]
else:
    cc, sdk, targets = 'clang', [], [[]]
for target in targets:
    arch = target[-1] if target else 'native'
    for source in sorted((root / 'core').glob('*.c')):
        subprocess.run([cc, *sdk, *target, '-std=c11', '-O2', '-ffreestanding', '-fno-builtin', '-Wall', '-Wextra', '-Werror', '-Wdeclaration-after-statement', '-Wframe-larger-than=2048', '-I', str(root / 'include'), '-c', str(source), '-o', str(output / f'{source.stem}-{arch}.o')], cwd=root, env=env, check=True)
print(f'PASS: freestanding core with 2 KiB frame budget on {len(targets)} compilation targets; this is not kernel acceptance')
