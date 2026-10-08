#!/usr/bin/env python3
"""Freeze and compare portable core allocation, journal and WOF workloads."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import shutil
import statistics
import subprocess
import tarfile

from benchmark_cpu import command, PROFILES
from environment import tool_environment

ROOT = Path(__file__).resolve().parents[1]


def build(source, output, harness, flags, label, compiler, sdk, env):
    binary = output / label
    argv = [compiler, '-isysroot', sdk, '-std=c11', '-O2', '-UNDEBUG', '-ffreestanding',
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
    parser.add_argument('--comparison', default='comparison')
    parser.add_argument('--repetitions', type=int, default=9)
    args = parser.parse_args()
    env = tool_environment()
    output = args.output.resolve()
    compiler = subprocess.check_output(['xcrun', '--find', 'clang'], env=env, text=True).strip()
    sdk = subprocess.check_output(['xcrun', '--show-sdk-path'], env=env, text=True).strip()
    version = subprocess.check_output([compiler, '--version'], env=env, text=True)
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
        hashes = {str(path.relative_to(output)): hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in (harness, *fixtures.iterdir())}
        report = dict(reference=revision, compiler=version, sdk=sdk, jobs=jobs,
                      builds=builds, baseline=baseline, hashes=hashes, complete=True)
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
    (current / 'result.json').write_text(json.dumps(dict(complete=True, builds=builds,
        comparisons=rows), indent=2) + '\n')
    print(json.dumps([dict(profile=row['profile'], case=row['case'], speedup=row['speedup'])
                      for row in rows]))


if __name__ == '__main__':
    main()
