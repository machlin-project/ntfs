#!/usr/bin/env python3
"""Compare indexed mutation planning and bitmap operations against frozen core C."""
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
                        help='Freeze this image or virtual-volume prefix for complete mutations')
    parser.add_argument('--case', action='append', choices=(
        'patch', 'overlay', 'record', 'free', 'mft', 'patch-small',
        'create', 'grow', 'shrink', 'unlink', 'grow-write'))
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
        harness = output / 'benchmark_mutation.c'
        shutil.copyfile(ROOT / 'tools/benchmark_mutation.c', harness)
        fixture = output / 'source.img'
        shutil.copyfile(args.fixture or ROOT / '.build/write-mutation-cases/source.img', fixture)
        jobs = {name: [name, '64'] for name in ('patch', 'overlay', 'record', 'free', 'mft')}
        jobs['patch-small'] = ['patch-small', '65536']
        jobs.update({name: [name, '40', str(fixture)] for name in ('create', 'grow', 'shrink', 'unlink', 'grow-write')})
        if args.case:
            jobs = {name: argv for name, argv in jobs.items() if name in args.case}
        builds, baseline = {}, {}
        for profile, flags in PROFILES.items():
            binary, builds[profile] = build(source, output, harness, flags,
                                             'before-' + profile, compiler, sdk, env)
            for name, argv in jobs.items():
                baseline[profile + '/' + name] = json.loads(command(
                    [binary, *argv], output, 'before-' + profile + '-' + name, env))
        hashes = retained_hashes(output, (harness, fixture, *(output / ('before-' + name) for name in PROFILES)))
        report = dict(reference=revision, compiler=version, sdk=sdk, toolchain=toolchain, jobs=jobs,
                      builds=builds, baseline=baseline, hashes=hashes, complete=True,
                      scope='Host CPU mutation planning; no durable execution or mounted I/O')
        (output / 'prepared.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(dict(complete=True, profiles=len(baseline))))
        return
    prepared = json.loads((output / 'prepared.json').read_text())
    if not prepared.get('complete'):
        raise ValueError('Reference preparation is incomplete')
    matching(prepared, toolchain)
    if args.case and not set(args.case) <= prepared['jobs'].keys():
        parser.error('--case must name a workload included in the frozen preparation')
    verify_hashes(output, prepared['hashes'])
    current = output / args.comparison
    current.mkdir(exist_ok=False)
    builds, rows = {}, []
    for profile, flags in PROFILES.items():
        binary, builds[profile] = build(ROOT, current, output / 'benchmark_mutation.c', flags,
                                        'after-' + profile, compiler, sdk, env)
        pair = (output / ('before-' + profile), binary)
        for name, argv in prepared['jobs'].items():
            if args.case and name not in args.case:
                continue
            samples = [[], []]
            for repetition in range(args.repetitions):
                for side in ((0, 1) if repetition % 2 == 0 else (1, 0)):
                    value = json.loads(command([pair[side], *argv], current,
                        f'{profile}-{name}-{repetition}-{side}', env))
                    assert value['checksum'] == prepared['baseline'][profile + '/' + name]['checksum']
                    samples[side].append(value)
            for sample in samples:
                for field in ('reads', 'read_bytes', 'allocations', 'allocation_bytes', 'peak_live_bytes'):
                    assert len({row[field] for row in sample}) == 1, (profile, name, field)
            medians = [statistics.median(item['ns'] for item in sample) for sample in samples]
            rows.append(dict(profile=profile, case=name, speedup=medians[0] / medians[1],
                             median_ns=medians, samples=samples))
    verify_hashes(output, prepared['hashes'])
    (current / 'result.json').write_text(json.dumps(dict(complete=True, builds=builds, toolchain=toolchain,
        scope=prepared['scope'], comparisons=rows), indent=2) + '\n')
    print(json.dumps([dict(profile=row['profile'], case=row['case'], speedup=row['speedup'])
                      for row in rows]))


if __name__ == '__main__':
    main()
