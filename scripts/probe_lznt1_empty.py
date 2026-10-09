#!/usr/bin/env python3
"""Isolate a post-admission empty-encode return without editing product source."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile

import benchmark_lznt1
import check_lznt1
from benchmark_toolchain import select, validate_comparison
from cpu_fixtures import author
from probe_lznt1_widths import invoke

ROOT = Path(__file__).resolve().parents[1]
CASES = ('measure-empty', 'exact-empty', 'bound-empty',
         'measure-zeros-4096', 'exact-period-3-4096', 'exact-noise-65536',
         'bound-zeros-65536', 'bound-noise-65536', 'bound-mixed-65536')
ADMITTED_BOUND = '\tresult = ntfs_write_lznt1_bound(bytes, &required);'


def empty_return(text):
    if text.count(ADMITTED_BOUND) != 1:
        raise ValueError('Expected exactly one post-admission encode bound')
    return text.replace(ADMITTED_BOUND,
                        '\tif (bytes == 0) {\n\t\t*written = 0;\n'
                        '\t\treturn NTFS_OK;\n\t}\n' + ADMITTED_BOUND)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--compiler')
    parser.add_argument('--repetitions', type=int, default=13)
    parser.add_argument('--sample-ms', type=int, default=250)
    args = parser.parse_args()
    validate_comparison('probe', args.repetitions)
    if not 10 <= args.sample_ms <= 1000:
        parser.error('--sample-ms must be from 10 to 1000')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    env = select(args.compiler)
    compiler = ['--compiler', args.compiler] if args.compiler else []
    reference = subprocess.check_output(
        ['git', 'rev-parse', '--verify', args.reference + '^{commit}'],
        cwd=ROOT, env=env, text=True, timeout=15).strip()
    benchmark = output / 'benchmark'
    invoke(benchmark_lznt1, ['prepare', *compiler, '--reference', reference,
                            '--output', benchmark])
    source = output / 'current-source'
    source.mkdir()
    archive = subprocess.check_output(['git', 'archive', reference, 'core', 'include', 'tests'],
                                      cwd=ROOT, env=env, timeout=30)
    with tarfile.open(fileobj=io.BytesIO(archive)) as package:
        package.extractall(source, filter='data')
    candidate = output / 'empty-return-source'
    shutil.copytree(source, candidate)
    # Freeze identical current admission tests in both historical core exports.
    admission = (ROOT / 'tests/write_lznt1.c').read_bytes()
    for tree in (source, candidate):
        (tree / 'tests/write_lznt1.c').write_bytes(admission)
    current = (source / 'core/write_lznt1.c').read_text()
    changed = empty_return(current)
    (candidate / 'core/write_lznt1.c').write_text(changed)
    fixtures = output / 'codec-fixtures'
    author(fixtures)
    scope = dict(reference=reference, productCheckoutModified=False, cases=CASES,
                 currentSha256=hashlib.sha256(current.encode()).hexdigest(),
                 candidateSha256=hashlib.sha256(changed.encode()).hexdigest(),
                 admissionHarnessSha256=hashlib.sha256(admission).hexdigest(),
                 change='Only zero-byte success after all existing argument and alias admission',
                 complete=False)
    (output / 'scope.json').write_text(json.dumps(scope, indent=2) + '\n')
    old_check, old_benchmark = check_lznt1.ROOT, benchmark_lznt1.ROOT
    try:
        for name, tree in (('current', source), ('empty-return', candidate)):
            check_lznt1.ROOT = tree
            invoke(check_lznt1, [*compiler, '--reference', benchmark / 'reference',
                                 '--fixtures', fixtures, '--output', output / (name + '-check')])
        for name, tree in (('current', source), ('empty-return', candidate)):
            benchmark_lznt1.ROOT = tree
            selections = [argument for case in CASES for argument in ('--case', case)]
            invoke(benchmark_lznt1, ['compare', *compiler, '--output', benchmark,
                                     '--comparison', name, '--repetitions', args.repetitions,
                                     '--sample-ms', args.sample_ms, *selections])
    finally:
        check_lznt1.ROOT, benchmark_lznt1.ROOT = old_check, old_benchmark
    scope['complete'] = True
    (output / 'scope.json').write_text(json.dumps(scope, indent=2) + '\n')
    print(json.dumps(dict(complete=True, comparisons=len(CASES) * 2 * 2, output=str(output))))


if __name__ == '__main__':
    main()
