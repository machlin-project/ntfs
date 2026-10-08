#!/usr/bin/env python3
"""Compare CPU primitives and complete decodes against a frozen Git revision.

Prepare before editing core sources. Compare later with the identical harness,
inputs and toolchain. Measurements use Release code, independent expected bytes,
alternating pair order and medians; they do not measure mounted filesystem I/O.
"""
import argparse
import io
import json
from pathlib import Path
import statistics
import subprocess
import sys
import tarfile

from environment import sanitizer_environment
from benchmark_toolchain import (command, PROFILES, select, sdk_flags, host_flags,
                                 section_flags, linker_flags, identity, matching,
                                 validate_comparison, retained_hashes, verify_hashes, digest)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
from cpu_fixtures import author
from huffman_fixtures import author as author_huffman


def build(source, output, harness, flags, label, clang, env):
    sources = [source / 'core' / name for name in ('support.c', 'lznt1.c', 'xpress.c', 'lzx.c')]
    if (source / 'core/memory.c').exists():
        sources.append(source / 'core/memory.c')
    target = output / label
    argv = [clang, *sdk_flags(env), *host_flags(), *section_flags(), '-std=c11', '-O2', '-g', '-UNDEBUG', '-ffreestanding', '-fno-builtin',
            '-Wall', '-Wextra', '-Werror', '-Wdeclaration-after-statement',
            '-I', source / 'include', '-I', source / 'core', *flags, *sources,
            harness, *linker_flags(), '-o', target]
    command(argv, output, f'{label}-build', env)
    return target, list(map(str, argv))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('prepare', 'compare'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--reference', default='HEAD')
    parser.add_argument('--compiler', help='Explicit compiler executable; defaults to selected Xcode or cc')
    parser.add_argument('--repetitions', type=int, default=9)
    parser.add_argument('--sample-ms', type=int, default=20,
                        help='Minimum pilot-calibrated sample duration; increase for noisy controls')
    parser.add_argument('--comparison', default='comparison')
    parser.add_argument('--case', action='append', default=[],
                        help='Measure only this named workload (repeatable); default: all')
    args = parser.parse_args()
    if not 10 <= args.sample_ms <= 1000:
        parser.error('--sample-ms must be from 10 to 1000')
    validate_comparison(args.comparison, args.repetitions)
    output = args.output.resolve()
    env = select(args.compiler)
    clang = env['CC']
    toolchain = identity(env)
    compiler = toolchain['compiler_version']
    if args.stage == 'prepare':
        output.mkdir(parents=True, exist_ok=False)
        revision = subprocess.check_output(['git', 'rev-parse', args.reference], cwd=ROOT,
                                           env=env, text=True, timeout=15).strip()
        archive = subprocess.check_output(['git', 'archive', revision, 'core', 'include'],
                                         cwd=ROOT, env=env, timeout=30)
        source = output / 'reference'
        source.mkdir()
        with tarfile.open(fileobj=io.BytesIO(archive)) as package:
            package.extractall(source, filter='data')
        harness = output / 'benchmark_cpu.c'
        harness.write_bytes((ROOT / 'tools/benchmark_cpu.c').read_bytes())
        fixtures = output / 'fixtures'
        profiles = author(fixtures)
        commands = {}
        for profile, flags in PROFILES.items():
            _, commands[profile] = build(source, output, harness, flags,
                                         f'before-{profile}', clang, env)
        # Verify independent codec packets on the baseline before measuring changes.
        binary, _ = build(source, output, ROOT / 'tests/cpu_codecs.c',
                          ['-fsanitize=address,undefined'], 'before-codecs', clang, env)
        command([binary, fixtures], output, 'before-codecs-check', sanitizer_environment())
        boundary_fixtures = output / 'huffman-fixtures'
        author_huffman(boundary_fixtures)
        binary, _ = build(source, output, ROOT / 'tests/huffman.c',
                          ['-fsanitize=address,undefined'], 'before-huffman', clang, env)
        command([binary, boundary_fixtures], output, 'before-huffman-check', sanitizer_environment())
        hashes = retained_hashes(output, [harness, *fixtures.iterdir(),
                                          *boundary_fixtures.iterdir(),
                                          *(path for path in source.rglob('*') if path.is_file()),
                                          *(output / f'before-{name}' for name in PROFILES)])
        report = dict(reference=revision, compiler=compiler, toolchain=toolchain, hashes=hashes,
                      profiles=profiles, buildCommands=commands, prepared=True)
        (output / 'prepared.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(dict(prepared=True, codecProfiles=len(profiles), output=str(output))))
        return
    prepared = json.loads((output / 'prepared.json').read_text())
    if not prepared.get('prepared'):
        raise ValueError('Reference preparation is incomplete')
    matching(prepared, toolchain)
    verify_hashes(output, prepared['hashes'])
    current = output / args.comparison
    current.mkdir(exist_ok=False)
    commands, binaries = {}, {}
    for profile, flags in PROFILES.items():
        binary, commands[profile] = build(ROOT, current, output / 'benchmark_cpu.c', flags,
                                          f'after-{profile}', clang, env)
        binaries[profile] = (output / f'before-{profile}', binary)
    jobs = []
    for operation in ('copy', 'zero', 'equal'):
        for size in (64, 4096, 65536):
            jobs.append((f'{operation}-{size}', [operation, str(size), '-'],
                         max(64, (2 * 1024 * 1024) // size)))
    for profile in prepared['profiles']:
        if profile['measure']:
            name = profile['name']
            jobs.append((name, [profile['codec'], output / 'fixtures' / f'{name}.packed',
                               output / 'fixtures' / f'{name}.data'],
                         max(64, (2 * 1024 * 1024) // profile['bytes'])))
    results = []
    if args.case:
        assert set(args.case) <= {job[0] for job in jobs}, 'Unknown workload name'
        jobs = [job for job in jobs if job[0] in args.case]
    for context, pair in binaries.items():
        for name, argv, iterations in jobs:
            rows = [[], []]
            pilot = [json.loads(command([pair[version], *argv, iterations], current,
                                        f'{context}-{name}-pilot-{version}', env))
                     for version in (0, 1)]
            # Give even the faster version the requested sample duration. Pilot results
            # choose identical work counts; they are excluded from statistics.
            iterations = max(64, min(10000000, int(iterations * args.sample_ms * 1000000 /
                                                   min(row['ns'] for row in pilot))))
            for repetition in range(args.repetitions):
                for version in (0, 1) if repetition % 2 == 0 else (1, 0):
                    raw = command([pair[version], *argv, iterations], current,
                                  f'{context}-{name}-{repetition}-{version}', env)
                    rows[version].append(json.loads(raw))
            assert len({row['checksum'] for group in rows for row in group}) == 1
            assert len({row['bytes'] for group in rows for row in group}) == 1
            medians = [statistics.median(row['ns'] for row in group) for group in rows]
            # Historical frozen harnesses only supplied monotonic wall time.
            # Do not silently label their elapsed samples as process CPU time.
            cpu = ([statistics.median(row['cpuNs'] for row in group) for group in rows]
                   if all('cpuNs' in row for group in rows for row in group) else None)
            results.append(dict(context=context, name=name, bytes=rows[0][0]['bytes'],
                                iterations=iterations, medianNs=medians, medianCpuNs=cpu,
                                speedup=medians[0] / medians[1],
                                cpuSpeedup=cpu[0] / cpu[1] if cpu else None, samples=rows))
    verify_hashes(output, prepared['hashes'])
    products = retained_hashes(current, [pair[1] for pair in binaries.values()])
    sources = {name: digest(ROOT / 'core' / name)
               for name in ('lznt1.c', 'xpress.c', 'lzx.c', 'memory.c', 'support.c')}
    report = dict(complete=True, reference=prepared['reference'], compiler=compiler, toolchain=toolchain,
                  candidateProducts=products, candidateSources=sources,
                  repetitions=args.repetitions, sampleMilliseconds=args.sample_ms, selectedCases=args.case,
                  buildCommands=commands, results=results)
    (current / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(complete=True, comparisons=len(results), output=str(current))))


if __name__ == '__main__':
    main()
