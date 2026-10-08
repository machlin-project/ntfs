#!/usr/bin/env python3
"""Compile the core without libc assumptions and with a small stack budget."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

from environment import selected_toolchain

ROOT = Path(__file__).resolve().parents[1]
COMPILE_TIMEOUT_SECONDS = 60
FRAME_BYTES = 2048


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', help='One explicit compiler executable; defaults to the platform compiler')
    parser.add_argument('--output', type=Path, default=ROOT / 'artifacts/freestanding')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    env = selected_toolchain(args.compiler)
    sdk = ['-isysroot', env['SDKROOT']] if sys.platform == 'darwin' else []
    targets = [['-arch', 'arm64'], ['-arch', 'x86_64']] if sys.platform == 'darwin' else [[]]
    report = {'status': 'running', 'compiler': env['CC'], 'frame_limit_bytes': FRAME_BYTES,
              'kernel_qualified': False, 'objects': []}
    try:
        report['compiler_version'] = subprocess.check_output(
            [env['CC'], '--version'], env=env, text=True, timeout=15).splitlines()[0]
        for target in targets:
            arch = target[-1] if target else 'native'
            for source in sorted((ROOT / 'core').glob('*.c')):
                command = [env['CC'], *sdk, *target, '-std=c11', '-O2', '-ffreestanding',
                           '-fno-builtin', '-Wall', '-Wextra', '-Werror',
                           '-Wdeclaration-after-statement', f'-Wframe-larger-than={FRAME_BYTES}',
                           '-I', str(ROOT / 'include'), '-c', str(source),
                           '-o', str(output / f'{source.stem}-{arch}.o')]
                subprocess.run(command, cwd=ROOT, env=env, check=True, timeout=COMPILE_TIMEOUT_SECONDS)
                report['objects'].append({'source': str(source.relative_to(ROOT)), 'architecture': arch})
        report['status'] = 'pass'
    except Exception as error:
        report['status'] = 'failed'
        report['error'] = f'{type(error).__name__}: {error}'
        raise
    finally:
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f'PASS: {len(report["objects"])} freestanding objects with 2 KiB frames; not kernel acceptance')


if __name__ == '__main__':
    main()
