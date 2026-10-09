#!/usr/bin/env python3
"""Compare directory planning, journal preparation and stream descriptions.

Each implementation reads the same frozen volume. Physical directory layouts may
change; outside timing, complete validation and a sorted namespace digest must
agree. This measures CPU and callback costs, not mounted or durable-device I/O.
"""
import argparse
import io
import json
from pathlib import Path
import shutil
import statistics
import subprocess
import tarfile
from benchmark_core import build
from benchmark_cpu import command, PROFILES
from benchmark_toolchain import (select, sdk_flags, host_flags, identity, matching,
                                 validate_comparison, retained_hashes, verify_hashes)

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('prepare', 'compare'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--reference', default='HEAD')
    parser.add_argument('--compiler', help='Explicit compiler executable; defaults to selected Xcode or cc')
    parser.add_argument('--comparison', default='comparison')
    parser.add_argument('--repetitions', type=int, default=9)
    parser.add_argument('--fixture', type=Path,
                        help='Freeze this independently authored synthetic writer image during prepare')
    args = parser.parse_args()
    if args.stage != 'prepare' and args.fixture is not None:
        parser.error('--fixture is only valid for a new prepare stage')
    output = args.output.resolve()
    validate_comparison(args.comparison, args.repetitions)
    env = select(args.compiler)
    compiler = env['CC']
    sdk = env.get('SDKROOT')
    toolchain = identity(env)
    version = toolchain['compiler_version']
    if args.stage == 'prepare':
        output.mkdir(parents=True, exist_ok=False)
        revision = subprocess.check_output(['git', 'rev-parse', args.reference], cwd=ROOT, env=env, text=True, timeout=15).strip()
        source = output / 'reference'
        source.mkdir()
        archive = subprocess.check_output(['git', 'archive', revision, 'core', 'include'], cwd=ROOT, env=env, timeout=30)
        with tarfile.open(fileobj=io.BytesIO(archive)) as package:
            package.extractall(source, filter='data')
        for name in ('benchmark_write.c', 'benchmark_mutation.c'):
            shutil.copyfile(ROOT / 'tools' / name, output / name)
        fixture = args.fixture or ROOT / '.build/write-mutation-cases/history-source.img'
        shutil.copyfile(fixture, output / 'small.img')
        builds, baseline, jobs = {}, {}, {}
        for profile, flags in PROFILES.items():
            binary, builds[profile] = build(source, output, output / 'benchmark_write.c', flags,
                                            'before-' + profile, compiler, sdk, env)
            if not jobs:
                command([binary, 'seed', '256', output / 'small.img', output / 'large.img'], output, 'seed', env)
                jobs = {size + '/' + phase: [phase, str(count), str(output / (size + '.img'))]
                        for size in ('small', 'large')
                        for phase, count in (('plan', 256), ('program', 512), ('execution', 32), ('stream', 16384))}
            for name, argv in jobs.items():
                baseline[profile + '/' + name] = json.loads(command([binary, *argv], output,
                    'before-' + profile + '-' + name.replace('/', '-'), env))
        hashes = retained_hashes(output, [*(path for path in output.iterdir() if path.suffix in ('.c', '.img')), *(output / ('before-' + name) for name in PROFILES)])
        report = dict(complete=True, reference=revision, compiler=version, sdk=sdk, toolchain=toolchain,
                      builds=builds, baseline=baseline, jobs=jobs, hashes=hashes,
                      fixture_source=str(fixture.resolve()))
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
        binary, builds[profile] = build(ROOT, current, output / 'benchmark_write.c', flags,
                                       'after-' + profile, compiler, sdk, env)
        pair = (output / ('before-' + profile), binary)
        for name, argv in prepared['jobs'].items():
            samples = [[], []]
            for repetition in range(args.repetitions):
                for side in ((0, 1) if repetition % 2 == 0 else (1, 0)):
                    value = json.loads(command([pair[side], *argv], current,
                        f'{profile}-{name.replace("/", "-")}-{repetition}-{side}', env))
                    assert value['checksum'] == prepared['baseline'][profile + '/' + name]['checksum']
                    samples[side].append(value)
            for sample in samples:
                for field in ('reads', 'read_bytes', 'allocations', 'allocation_bytes', 'peak_live_bytes', 'regions', 'updates', 'publications'):
                    assert len({value[field] for value in sample}) == 1, (name, field)
            medians = [statistics.median(value['ns'] for value in sample) for sample in samples]
            rows.append(dict(profile=profile, case=name, speedup=medians[0] / medians[1], median_ns=medians, samples=samples))
    verify_hashes(output, prepared['hashes'])
    (current / 'result.json').write_text(json.dumps(dict(complete=True, builds=builds, toolchain=toolchain,
        scope=__doc__, comparisons=rows), indent=2) + '\n')
    print(json.dumps([dict(profile=row['profile'], case=row['case'], speedup=row['speedup']) for row in rows]))


if __name__ == '__main__':
    main()
