#!/usr/bin/env python3
"""Retained matched LZNT1 encoder/measurement experiments, separate from I/O.

The three operations deliberately distinguish exact capacity (which may need a
measurement pass), raw worst-case capacity and measurement alone. Every timed
binary independently inspects output tokens against the authored source bytes.
"""
import argparse
import io
import json
from pathlib import Path
import statistics
import subprocess
import tarfile

from benchmark_toolchain import (command, PROFILES, select, sdk_flags, host_flags,
                                 section_flags, linker_flags, identity, matching,
                                 validate_comparison, retained_hashes, verify_hashes, digest)

ROOT = Path(__file__).resolve().parents[1]


def author(output):
    output.mkdir()
    profiles = []

    def add(name, data):
        (output / f'{name}.data').write_bytes(data)
        profiles.append(dict(name=name, bytes=len(data)))

    state = 0x4c5a4e54
    noise = bytearray()
    for _ in range(65536):
        state ^= (state << 13) & 0xffffffff
        state ^= state >> 17
        state ^= (state << 5) & 0xffffffff
        noise.append(state & 255)
    add('empty', b'')
    add('tiny-raw', b'CAT')
    add('tiny-repeat', b'A' * 17)
    for size in (4096, 65536):
        add(f'noise-{size}', bytes(noise[:size]))
        add(f'zeros-{size}', b'\0' * size)
        for period in (3, 16, 31, 63):
            pattern = bytes(range(period))
            add(f'period-{period}-{size}', (pattern * ((size + period - 1) // period))[:size])
    add('zeros-1048576', b'\0' * 1048576)
    add('mixed-65536', b''.join(bytes(noise[index:index + 4096]) if index % 8192 else b'Q' * 4096
                              for index in range(0, 65536, 4096)))
    line = b'2026-10-08T00:00:00Z original authored compression fixture record=00000000\n'
    text = b''.join(line.replace(b'00000000', f'{index:08d}'.encode()) for index in range(1100))
    add('records-65536', text[:65536])
    (output / 'profiles.json').write_text(json.dumps(profiles, indent=2) + '\n')
    return profiles


def build(source, output, harness, flags, label, env):
    target = output / label
    sources = [source / 'core' / name for name in ('support.c', 'memory.c', 'write_lznt1.c')]
    argv = [env['CC'], *sdk_flags(env), *host_flags(), *section_flags(), '-std=c11', '-O2', '-g',
            '-UNDEBUG', '-ffreestanding', '-fno-builtin', '-Wall', '-Wextra', '-Werror',
            '-Wdeclaration-after-statement', '-I', source / 'include', '-I', source / 'core',
            *flags, *sources, harness, *linker_flags(), '-o', target]
    command(argv, output, f'{label}-build', env)
    return target, list(map(str, argv))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('prepare', 'compare'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--reference', default='HEAD')
    parser.add_argument('--compiler')
    parser.add_argument('--repetitions', type=int, default=9)
    parser.add_argument('--sample-ms', type=int, default=50)
    parser.add_argument('--comparison', default='comparison')
    parser.add_argument('--case', action='append', default=[])
    args = parser.parse_args()
    if not 10 <= args.sample_ms <= 1000:
        parser.error('--sample-ms must be from 10 to 1000')
    validate_comparison(args.comparison, args.repetitions)
    output = args.output.resolve()
    env = select(args.compiler)
    toolchain = identity(env)
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
        harness = output / 'benchmark_lznt1.c'
        harness.write_bytes((ROOT / 'tools/benchmark_lznt1.c').read_bytes())
        fixtures = output / 'fixtures'
        profiles = author(fixtures)
        commands = {}
        for context, flags in PROFILES.items():
            _, commands[context] = build(source, output, harness, flags, f'before-{context}', env)
        hashes = retained_hashes(output, [harness, *fixtures.iterdir(),
                                          *(path for path in source.rglob('*') if path.is_file()),
                                          *(output / f'before-{name}' for name in PROFILES)])
        prepared = dict(prepared=True, reference=revision, toolchain=toolchain, hashes=hashes,
                        profiles=profiles, buildCommands=commands,
                        scope='Release CPU microbenchmark; separate sanitizer acceptance required')
        (output / 'prepared.json').write_text(json.dumps(prepared, indent=2) + '\n')
        print(json.dumps(dict(prepared=True, profiles=len(profiles), output=str(output))))
        return
    prepared = json.loads((output / 'prepared.json').read_text())
    if not prepared.get('prepared'):
        raise ValueError('Reference preparation is incomplete')
    matching(prepared, toolchain)
    verify_hashes(output, prepared['hashes'])
    current = output / args.comparison
    current.mkdir(exist_ok=False)
    commands, binaries = {}, {}
    for context, flags in PROFILES.items():
        binary, commands[context] = build(ROOT, current, output / 'benchmark_lznt1.c',
                                          flags, f'after-{context}', env)
        binaries[context] = (output / f'before-{context}', binary)
    jobs = [(f"{mode}-{profile['name']}", [mode, output / 'fixtures' / f"{profile['name']}.data"],
             max(16, 1048576 // max(1, profile['bytes'])))
            for mode in ('measure', 'exact', 'bound') for profile in prepared['profiles']]
    if args.case:
        if not set(args.case) <= {job[0] for job in jobs}:
            raise ValueError('Unknown workload name')
        jobs = [job for job in jobs if job[0] in args.case]
    results = []
    for context, pair in binaries.items():
        for name, argv, iterations in jobs:
            pilots = [json.loads(command([binary, *argv, iterations], current,
                                        f'{context}-{name}-pilot-{version}', env))
                      for version, binary in enumerate(pair)]
            iterations = max(16, min(10000000, int(iterations * args.sample_ms * 1000000 /
                                                   min(row['ns'] for row in pilots))))
            rows = [[], []]
            for repetition in range(args.repetitions):
                for version in (0, 1) if repetition % 2 == 0 else (1, 0):
                    raw = command([pair[version], *argv, iterations], current,
                                  f'{context}-{name}-{repetition}-{version}', env)
                    rows[version].append(json.loads(raw))
            for field in ('bytes', 'encodedBytes', 'capacity', 'workspaceBytes',
                          'coreAllocations', 'coreIoCalls', 'checksum'):
                if len({row[field] for group in rows for row in group}) != 1:
                    raise ValueError(f'Changed output/resource contract: {context}/{name}/{field}')
            wall = [statistics.median(row['ns'] for row in group) for group in rows]
            cpu = [statistics.median(row['cpuNs'] for row in group) for group in rows]
            results.append(dict(context=context, name=name, iterations=iterations,
                                medianNs=wall, medianCpuNs=cpu, speedup=wall[0] / wall[1],
                                cpuSpeedup=cpu[0] / cpu[1], samples=rows))
    verify_hashes(output, prepared['hashes'])
    products = retained_hashes(current, [pair[1] for pair in binaries.values()])
    report = dict(complete=True, reference=prepared['reference'], toolchain=toolchain,
                  candidateProducts=products, candidateEncoderSha256=digest(ROOT / 'core/write_lznt1.c'),
                  repetitions=args.repetitions, sampleMilliseconds=args.sample_ms,
                  selectedCases=args.case, buildCommands=commands, results=results,
                  scope='Complete in-memory codec calls; no filesystem or native mount claim')
    (current / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(complete=True, comparisons=len(results), output=str(current))))


if __name__ == '__main__':
    main()
