#!/usr/bin/env python3
"""Compare an isolated constant nine-bit XPRESS return with an immutable source.

The candidate only separates the already validated nine-bit symbol return from
the longer canonical-width search. Both variants retain the same refill helper.
The product checkout is not changed; strict differential checks precede timing.
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

import benchmark_cpu
import check_huffman
from benchmark_toolchain import select, validate_comparison

ROOT = Path(__file__).resolve().parents[1]
CASES = ('copy-64', 'zero-4096', 'lznt1-literals', 'lzx-long-codes',
         'xpress-literals', 'xpress-short-codes', 'xpress-long-codes',
         'xpress-mixed-codes', 'xpress-small-tree', 'xpress-period-3')
MISS = '\tif (offset >= tree->count[bits]) {'
RETURN = '\t*out = tree->symbols[tree->base[bits] + offset];'


def constant_nine(text):
    start = text.index('\tbits = XPRESS_PREFIX_BITS + 1;')
    first = text.index(MISS, start)
    last = text.index(RETURN, first)
    lines = text[first:last].splitlines()
    if lines[0] != MISS or lines[-1] != '\t}' or lines.count(MISS) != 1:
        raise ValueError('Unexpected canonical fallback shape')
    if any(line and not line.startswith('\t\t') for line in lines[1:-1]):
        raise ValueError('Unexpected nested canonical fallback indentation')
    body = '\n'.join(line[1:] if line else line for line in lines[1:-1]) + '\n'
    early = ('\tif (offset < tree->count[bits]) {\n'
             '\t\t*out = tree->symbols[tree->base[XPRESS_PREFIX_BITS + 1] + offset];\n'
             '\t\treturn xpress_take_bits(reader, XPRESS_PREFIX_BITS + 1, &ignored);\n'
             '\t}\n')
    return text[:first] + early + body + text[last:]


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
    invoke(benchmark_cpu, ['prepare', *compiler, '--reference', reference,
                           '--output', benchmark])
    source = output / 'current-source'
    source.mkdir()
    archive = subprocess.check_output(['git', 'archive', reference, 'core', 'include', 'tests'],
                                      cwd=ROOT, env=env, timeout=30)
    with tarfile.open(fileobj=io.BytesIO(archive)) as package:
        package.extractall(source, filter='data')
    candidate = output / 'constant-nine-source'
    shutil.copytree(source, candidate)
    current = (source / 'core/xpress.c').read_text()
    changed = constant_nine(current)
    (candidate / 'core/xpress.c').write_text(changed)
    scope = dict(reference=reference, productCheckoutModified=False, cases=CASES,
                 currentSha256=hashlib.sha256(current.encode()).hexdigest(),
                 candidateSha256=hashlib.sha256(changed.encode()).hexdigest(),
                 change='Only XPRESS validated nine-bit return separated; longer bucket search retained',
                 complete=False)
    (output / 'scope.json').write_text(json.dumps(scope, indent=2) + '\n')
    old_check, old_benchmark = check_huffman.ROOT, benchmark_cpu.ROOT
    try:
        for name, tree in (('current', source), ('constant-nine', candidate)):
            check_huffman.ROOT = tree
            invoke(check_huffman, [*compiler, '--reference', benchmark / 'reference',
                                   '--fixtures', benchmark / 'huffman-fixtures',
                                   '--output', output / (name + '-check')])
        for name, tree in (('current', source), ('constant-nine', candidate)):
            benchmark_cpu.ROOT = tree
            selections = [argument for case in CASES for argument in ('--case', case)]
            invoke(benchmark_cpu, ['compare', *compiler, '--output', benchmark,
                                   '--comparison', name, '--repetitions', args.repetitions,
                                   '--sample-ms', args.sample_ms, *selections])
    finally:
        check_huffman.ROOT, benchmark_cpu.ROOT = old_check, old_benchmark
    scope['complete'] = True
    (output / 'scope.json').write_text(json.dumps(scope, indent=2) + '\n')
    print(json.dumps(dict(complete=True, comparisons=len(CASES) * 2 * 2, output=str(output))))


if __name__ == '__main__':
    main()
