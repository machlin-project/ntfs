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
import platform
import statistics
import subprocess
import sys
import tarfile

from environment import sanitizer_environment, tool_environment

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
from cpu_fixtures import author

PROFILES = {'userspace': [], 'general-registers': ['-DKERNEL', '-mgeneral-regs-only']}


def command(argv, output, name, env):
    result = subprocess.run(list(map(str, argv)), cwd=ROOT, env=env, capture_output=True)
    (output / f'{name}.stdout').write_bytes(result.stdout)
    (output / f'{name}.stderr').write_bytes(result.stderr)
    if result.returncode:
        raise RuntimeError(f'{name} exited {result.returncode}; see retained stderr')
    return result.stdout.decode()


def build(source, output, harness, flags, label, clang, env):
    sources = [source / 'core' / name for name in ('support.c', 'lznt1.c', 'xpress.c', 'lzx.c')]
    if (source / 'core/memory.c').exists():
        sources.append(source / 'core/memory.c')
    target = output / label
    sdk = subprocess.check_output(['xcrun', '--show-sdk-path'], env=env, text=True).strip()
    argv = [clang, '-isysroot', sdk, '-std=c11', '-O2', '-g', '-UNDEBUG', '-ffreestanding', '-fno-builtin',
            '-Wall', '-Wextra', '-Werror', '-Wdeclaration-after-statement',
            '-I', source / 'include', '-I', source / 'core', *flags, *sources,
            harness, '-Wl,-dead_strip', '-o', target]
    command(argv, output, f'{label}-build', env)
    return target, list(map(str, argv))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('prepare', 'compare'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--reference', default='HEAD')
    parser.add_argument('--repetitions', type=int, default=9)
    parser.add_argument('--comparison', default='comparison')
    args = parser.parse_args()
    output = args.output.resolve()
    env = tool_environment()
    clang = subprocess.check_output(['xcrun', '--find', 'clang'], env=env, text=True).strip()
    compiler = subprocess.check_output([clang, '--version'], env=env, text=True)
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        parser.error('This paired instruction experiment targets macOS arm64')
    if args.stage == 'prepare':
        output.mkdir(parents=True, exist_ok=False)
        revision = subprocess.check_output(['git', 'rev-parse', args.reference], cwd=ROOT,
                                           env=env, text=True).strip()
        archive = subprocess.check_output(['git', 'archive', revision, 'core', 'include'],
                                         cwd=ROOT, env=env)
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
        report = dict(reference=revision, compiler=compiler, machine=platform.machine(),
                      profiles=profiles, buildCommands=commands, prepared=True)
        (output / 'prepared.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(dict(prepared=True, codecProfiles=len(profiles), output=str(output))))
        return
    prepared = json.loads((output / 'prepared.json').read_text())
    assert prepared['prepared'] and compiler == prepared['compiler']
    assert args.repetitions >= 5
    assert Path(args.comparison).name == args.comparison and args.comparison not in ('.', '..')
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
    for context, pair in binaries.items():
        for name, argv, iterations in jobs:
            rows = [[], []]
            pilot = [json.loads(command([pair[version], *argv, iterations], current,
                                        f'{context}-{name}-pilot-{version}', env))
                     for version in (0, 1)]
            # Give even the faster version about 20 ms per sample. Pilot results
            # choose identical work counts; they are excluded from statistics.
            iterations = max(64, min(10000000, int(iterations * 20000000 /
                                                   min(row['ns'] for row in pilot))))
            for repetition in range(args.repetitions):
                for version in (0, 1) if repetition % 2 == 0 else (1, 0):
                    raw = command([pair[version], *argv, iterations], current,
                                  f'{context}-{name}-{repetition}-{version}', env)
                    rows[version].append(json.loads(raw))
            assert len({row['checksum'] for group in rows for row in group}) == 1
            assert len({row['bytes'] for group in rows for row in group}) == 1
            medians = [statistics.median(row['ns'] for row in group) for group in rows]
            results.append(dict(context=context, name=name, bytes=rows[0][0]['bytes'],
                                iterations=iterations, medianNs=medians,
                                speedup=medians[0] / medians[1], samples=rows))
    report = dict(complete=True, reference=prepared['reference'], compiler=compiler,
                  repetitions=args.repetitions, buildCommands=commands, results=results)
    (current / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(complete=True, comparisons=len(results), output=str(current))))


if __name__ == '__main__':
    main()
