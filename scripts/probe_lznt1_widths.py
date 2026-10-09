#!/usr/bin/env python3
"""Isolate LZNT1 width-state cost without editing the product checkout.

Two immutable source exports use the same raw-bound single-pass wrapper. The
control restores only the original per-position chunk encoder. Both variants
run strict differential checks and matched measurements against one frozen
pre-optimization source, harness and original fixture set.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

import benchmark_lznt1
import check_lznt1
from benchmark_toolchain import select, validate_comparison
from cpu_fixtures import author

ROOT = Path(__file__).resolve().parents[1]
CASES = (
    'measure-zeros-4096', 'measure-period-31-4096',
    'measure-noise-4096', 'measure-noise-65536',
    'exact-empty', 'exact-zeros-4096', 'exact-period-3-4096',
    'exact-zeros-65536', 'exact-noise-65536',
    'bound-empty', 'bound-zeros-65536', 'bound-noise-4096',
    'bound-noise-65536', 'bound-mixed-65536',
)
CHUNK_START = 'static size_t\nlznt1_write_chunk('
CHUNK_END = 'static size_t\nlznt1_write_walk('


def chunk(text):
    if text.count(CHUNK_START) != 1 or text.count(CHUNK_END) != 1:
        raise ValueError('Source must contain exactly one named chunk encoder and walk')
    first, last = text.index(CHUNK_START), text.index(CHUNK_END)
    if first >= last:
        raise ValueError('Unexpected chunk/walk source order')
    return first, last, text[first:last]


def invoke(module, arguments):
    previous = sys.argv
    try:
        sys.argv = [module.__file__, *map(str, arguments)]
        module.main()
    finally:
        sys.argv = previous


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', required=True)
    parser.add_argument('--candidate', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--compiler')
    parser.add_argument('--repetitions', type=int, default=9)
    parser.add_argument('--sample-ms', type=int, default=200)
    args = parser.parse_args()
    validate_comparison('probe', args.repetitions)
    if not 10 <= args.sample_ms <= 1000:
        parser.error('--sample-ms must be from 10 to 1000')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    env = select(args.compiler)
    compiler = ['--compiler', args.compiler] if args.compiler else []
    candidate = subprocess.check_output(
        ['git', 'rev-parse', '--verify', args.candidate + '^{commit}'],
        cwd=ROOT, env=env, text=True, timeout=15).strip()
    benchmark = output / 'benchmark'
    invoke(benchmark_lznt1, ['prepare', *compiler, '--reference', args.reference,
                            '--output', benchmark])
    source = output / 'persistent-width-source'
    source.mkdir()
    archive = subprocess.check_output(['git', 'archive', candidate, 'core', 'include', 'tests'],
                                      cwd=ROOT, env=env, timeout=30)
    with tarfile.open(fileobj=io.BytesIO(archive)) as package:
        package.extractall(source, filter='data')
    control = output / 'classic-width-source'
    shutil.copytree(source, control)
    original = (benchmark / 'reference/core/write_lznt1.c').read_text()
    current = (source / 'core/write_lznt1.c').read_text()
    first, last, current_chunk = chunk(current)
    original_chunk = chunk(original)[2]
    if current_chunk == original_chunk:
        raise ValueError('The selected candidate already has the reference chunk encoder')
    controlled = current[:first] + original_chunk + current[last:]
    (control / 'core/write_lznt1.c').write_text(controlled)
    fixtures = output / 'codec-fixtures'
    author(fixtures)
    scope = {
        'candidate': candidate,
        'reference': json.loads((benchmark / 'prepared.json').read_text())['reference'],
        'control': 'Only lznt1_write_chunk restored; candidate publication wrapper retained',
        'currentEncoderSha256': hashlib.sha256(current.encode()).hexdigest(),
        'controlEncoderSha256': hashlib.sha256(controlled.encode()).hexdigest(),
        'cases': CASES,
        'productCheckoutModified': False,
        'complete': False,
    }
    (output / 'scope.json').write_text(json.dumps(scope, indent=2) + '\n')
    previous_check_root, previous_benchmark_root = check_lznt1.ROOT, benchmark_lznt1.ROOT
    try:
        for name, tree in (('persistent-width', source), ('classic-width', control)):
            check_lznt1.ROOT = tree
            invoke(check_lznt1, [*compiler, '--reference', benchmark / 'reference',
                                 '--fixtures', fixtures, '--output', output / (name + '-check')])
        # Keep every correctness check outside both serial timing phases.
        for name, tree in (('persistent-width', source), ('classic-width', control)):
            benchmark_lznt1.ROOT = tree
            selections = [argument for case in CASES for argument in ('--case', case)]
            invoke(benchmark_lznt1, ['compare', *compiler, '--output', benchmark,
                                     '--comparison', name, '--repetitions', args.repetitions,
                                     '--sample-ms', args.sample_ms, *selections])
    finally:
        check_lznt1.ROOT, benchmark_lznt1.ROOT = previous_check_root, previous_benchmark_root
    scope['complete'] = True
    (output / 'scope.json').write_text(json.dumps(scope, indent=2) + '\n')
    print(json.dumps({'complete': True, 'comparisons': len(CASES) * 2 * 2,
                      'output': str(output)}))


if __name__ == '__main__':
    main()
