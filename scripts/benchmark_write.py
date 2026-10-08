#!/usr/bin/env python3
"""Compare directory planning, journal preparation and stream descriptions.

Each implementation reads the same frozen volume. Physical directory layouts may
change; outside timing, complete validation and a sorted namespace digest must
agree. This measures CPU and callback costs, not mounted or durable-device I/O.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import shutil
import statistics
import subprocess
import tarfile
from benchmark_core import build
from benchmark_cpu import command, PROFILES
from environment import tool_environment

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('prepare', 'compare'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--reference', default='HEAD')
    parser.add_argument('--comparison', default='comparison')
    parser.add_argument('--repetitions', type=int, default=9)
    args = parser.parse_args()
    output = args.output.resolve()
    env = tool_environment()
    compiler = subprocess.check_output(['xcrun', '--find', 'clang'], env=env, text=True).strip()
    sdk = subprocess.check_output(['xcrun', '--show-sdk-path'], env=env, text=True).strip()
    version = subprocess.check_output([compiler, '--version'], env=env, text=True)
    if args.stage == 'prepare':
        output.mkdir(parents=True, exist_ok=False)
        revision = subprocess.check_output(['git', 'rev-parse', args.reference], cwd=ROOT, env=env, text=True).strip()
        source = output / 'reference'
        source.mkdir()
        archive = subprocess.check_output(['git', 'archive', revision, 'core', 'include'], cwd=ROOT, env=env)
        with tarfile.open(fileobj=io.BytesIO(archive)) as package:
            package.extractall(source, filter='data')
        for name in ('benchmark_write.c', 'benchmark_mutation.c'):
            shutil.copyfile(ROOT / 'tools' / name, output / name)
        shutil.copyfile(ROOT / '.build/write-mutation-cases/history-source.img', output / 'small.img')
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
        hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in output.iterdir() if path.suffix in ('.c', '.img')}
        report = dict(complete=True, reference=revision, compiler=version, sdk=sdk,
                      builds=builds, baseline=baseline, jobs=jobs, hashes=hashes)
        (output / 'prepared.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(dict(complete=True, profiles=len(baseline))))
        return
    prepared = json.loads((output / 'prepared.json').read_text())
    assert prepared['complete'] and version == prepared['compiler'] and sdk == prepared['sdk']
    assert args.repetitions >= 5 and Path(args.comparison).name == args.comparison
    for name, digest in prepared['hashes'].items():
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == digest
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
    (current / 'result.json').write_text(json.dumps(dict(complete=True, builds=builds,
        scope=__doc__, comparisons=rows), indent=2) + '\n')
    print(json.dumps([dict(profile=row['profile'], case=row['case'], speedup=row['speedup']) for row in rows]))


if __name__ == '__main__':
    main()
