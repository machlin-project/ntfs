#!/usr/bin/env python3
"""Replay retained deterministic directory stress inputs with fatal sanitizers."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import time

from directory_fuzz_seeds import generate
from environment import sanitizer_environment

ROOT = Path(__file__).resolve().parents[1]
BATCH_FILES = 16


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / '.build/ntfs-fuzz-directory-mutation')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cases', type=int, default=256)
    parser.add_argument('--seed', type=int, default=20261008)
    args = parser.parse_args()
    if not 1 <= args.cases <= 10000:
        parser.error('--cases must be between 1 and 10000')
    binary, output = args.binary.resolve(strict=True), args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    paths = generate(output / 'seeds', stress=args.cases, seed=args.seed)
    env = sanitizer_environment()
    report = dict(status='running', seed=args.seed, inputs=len(paths), commands=[],
                  binary=str(binary), binarySha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  sanitizerOptions={key: env[key] for key in ('ASAN_OPTIONS', 'UBSAN_OPTIONS')})
    try:
        for first in range(0, len(paths), BATCH_FILES):
            command = [str(binary), *map(str, paths[first:first + BATCH_FILES])]
            started = time.monotonic()
            with (output / f'batch-{first:05d}.log').open('xb') as log:
                result = subprocess.run(command, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                        stdout=log, stderr=log, timeout=300)
            report['commands'].append(dict(argv=command, exitCode=result.returncode,
                                           seconds=time.monotonic() - started))
            (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
            result.check_returncode()
        report['status'] = 'pass'
    except BaseException:
        report['status'] = 'fail'
        raise
    finally:
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
