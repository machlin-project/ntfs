#!/usr/bin/env python3
"""Freeze and compare portable core allocation, journal and WOF workloads."""
import argparse
import io
import json
from pathlib import Path
import shutil
import statistics
import subprocess
import tarfile

from benchmark_cpu import command, PROFILES
from benchmark_toolchain import (select, sdk_flags, host_flags, identity, matching,
                                 validate_comparison, retained_hashes, verify_hashes)

ROOT = Path(__file__).resolve().parents[1]


def build(source, output, harness, flags, label, compiler, sdk, env):
    binary = output / label
    argv = [compiler, *sdk_flags(env), *host_flags(), '-std=c11', '-O2', '-UNDEBUG', '-ffreestanding',
            '-fno-builtin', '-Wall', '-Wextra', '-Werror', '-Wdeclaration-after-statement',
            '-I', source / 'core', '-I', source / 'include', *flags,
            *sorted((source / 'core').glob('*.c')), harness, '-o', binary]
    command(argv, output, label + '-build', env)
    return binary, list(map(str, argv))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('prepare', 'compare'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--reference', default='HEAD')
    parser.add_argument('--compiler', help='Explicit compiler executable; defaults to selected Xcode or cc')
    parser.add_argument('--comparison', default='comparison')
    parser.add_argument('--repetitions', type=int, default=9)
    args = parser.parse_args()
    validate_comparison(args.comparison, args.repetitions)
    env = select(args.compiler)
    output = args.output.resolve()
    compiler = env['CC']
    sdk = env.get('SDKROOT')
    toolchain = identity(env)
    version = toolchain['compiler_version']
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
        harness = output / 'benchmark_core.c'
        shutil.copyfile(ROOT / 'tools/benchmark_core.c', harness)
        fixtures = output / 'fixtures'
        fixtures.mkdir()
        journal = ROOT / '.build/logfile-history-fixtures/fast-shared-operation-credits.journal'
        wof = ROOT / '.build/fixtures/wof-file-pages.img'
        for path in (journal, wof):
            shutil.copyfile(path, fixtures / path.name)
        first = (journal.parent / (journal.name + '.packets.rows')).read_text().split()[0]
        jobs = {'bitmap': ['bitmap', '64'], 'fragmented': ['fragmented', '64'],
                'journal': ['journal', '100', str(fixtures / journal.name), first],
                'wof': ['wof', '1000', str(fixtures / wof.name)],
                'wof-cold': ['wof-cold', '1000', str(fixtures / wof.name)]}
        builds, baseline = {}, {}
        for profile, flags in PROFILES.items():
            binary, builds[profile] = build(source, output, harness, flags,
                                             'before-' + profile, compiler, sdk, env)
            for name, argv in jobs.items():
                baseline[profile + '/' + name] = json.loads(command(
                    [binary, *argv], output, 'before-' + profile + '-' + name, env))
        hashes = retained_hashes(output, (harness, *fixtures.iterdir(), *(output / ('before-' + name) for name in PROFILES)))
        report = dict(reference=revision, compiler=version, sdk=sdk, toolchain=toolchain, jobs=jobs,
                      builds=builds, baseline=baseline, hashes=hashes, complete=True)
        (output / 'prepared.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(dict(complete=True, profiles=len(baseline))))
        return
    prepared = json.loads((output / 'prepared.json').read_text())
    if not prepared.get('complete'):
        raise ValueError('Reference preparation is incomplete')
    matching(prepared, toolchain)
    verify_hashes(output, prepared['hashes'])
    current = output / args.comparison
    current.mkdir(exist_ok=False)
    builds, rows = {}, []
    for profile, flags in PROFILES.items():
        binary, builds[profile] = build(ROOT, current, output / 'benchmark_core.c', flags,
                                        'after-' + profile, compiler, sdk, env)
        pair = (output / ('before-' + profile), binary)
        for name, argv in prepared['jobs'].items():
            samples = [[], []]
            for repetition in range(args.repetitions):
                for side in ((0, 1) if repetition % 2 == 0 else (1, 0)):
                    value = json.loads(command([pair[side], *argv], current,
                        f'{profile}-{name}-{repetition}-{side}', env))
                    assert value['checksum'] == prepared['baseline'][profile + '/' + name]['checksum']
                    samples[side].append(value)
            medians = [statistics.median(item['ns'] for item in sample) for sample in samples]
            rows.append(dict(profile=profile, case=name, speedup=medians[0] / medians[1],
                             median_ns=medians, samples=samples))
    verify_hashes(output, prepared['hashes'])
    (current / 'result.json').write_text(json.dumps(dict(complete=True, builds=builds, toolchain=toolchain,
        comparisons=rows), indent=2) + '\n')
    print(json.dumps([dict(profile=row['profile'], case=row['case'], speedup=row['speedup'])
                      for row in rows]))


if __name__ == '__main__':
    main()
