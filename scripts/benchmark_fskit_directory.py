#!/usr/bin/env python3
"""Measure native directory continuation against an independently authored inventory."""
from pathlib import Path
import argparse
import hashlib
import json
import platform
import statistics
import sys

from bounded_tool import bounded_read, run_tool
from check_reproducible import selected_options

ROOT = Path(__file__).resolve().parents[1]
MIB = 1024 * 1024
MAX_IMAGE_BYTES = 64 * MIB
MAX_MANIFEST_BYTES = 16 * MIB
MAX_REPORT_BYTES = 16 * MIB
MAX_PAGE_ENTRIES = 1024
MAX_ROUNDS = 100
MAX_REPETITIONS = 100
MAX_ENTRIES = 16384
MAX_SAMPLES = 1000000
# Profile disabled through normal default retention, rather than arbitrary tuning.
MAX_RECORD_CACHE_ENTRIES = 64
PROFILES = ('sequential', 'interleaved', 'views')
METRICS = ('wall_ns', 'cpu_ns', 'p50_ns', 'p95_ns', 'p99_ns', 'read_calls',
           'read_bytes', 'allocations', 'baseline_core_bytes', 'peak_core_bytes',
           'peak_rss_bytes', 'entries_per_second')
WORKLOAD = 'tools/fskit_directory_workload.m'
ADAPTERS = ('NTFSResource.m', 'NTFSNames.m', 'NTFSLinks.m', 'NTFSAccessPolicy.m', 'NTFSReadCachePolicy.m',
            'NTFSVolume.m', 'NTFSLegacyVolume.m', 'NTFSModernVolume.m')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, report):
    path.write_text(json.dumps(report, indent=2) + '\n')


def summarize(runs):
    return {field: {'median': statistics.median(run[field] for run in runs),
                    'min': min(run[field] for run in runs),
                    'max': max(run[field] for run in runs),
                    'sample_stdev': statistics.stdev(run[field] for run in runs)}
            for field in METRICS}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--build', type=Path, default=ROOT / '.build-release')
    parser.add_argument('--output', type=Path, required=True, help='New artifact directory')
    parser.add_argument('--reference', type=Path, help='Prior passing output with retained binary')
    parser.add_argument('--compare-core', action='store_true',
                        help='Compare complete core versions with identical native sources and public headers')
    parser.add_argument('--profiles', nargs='+', choices=PROFILES, default=PROFILES)
    parser.add_argument('--pages', nargs=2, type=int, default=(8, 16), metavar=('A', 'B'))
    parser.add_argument('--rounds', type=int, default=2)
    parser.add_argument('--warmup-rounds', type=int, default=1)
    parser.add_argument('--repetitions', type=int, default=5)
    parser.add_argument('--record-cache-entries', type=int, default=0)
    args = parser.parse_args()
    if args.compare_core and args.reference is None:
        parser.error('--compare-core requires --reference')
    if sys.platform != 'darwin':
        parser.error('Native directory components require macOS and its SDK')
    if (any(not 1 <= page <= MAX_PAGE_ENTRIES for page in args.pages) or
            not 1 <= args.rounds <= MAX_ROUNDS or
            not 0 <= args.warmup_rounds <= MAX_ROUNDS or
            not 2 <= args.repetitions <= MAX_REPETITIONS or
            not 0 <= args.record_cache_entries <= MAX_RECORD_CACHE_ENTRIES):
        parser.error('Page, round or repetition count exceeds its execution budget')
    args.image, args.manifest = args.image.resolve(), args.manifest.resolve()
    image = bounded_read(args.image, MAX_IMAGE_BYTES)
    inventory = bounded_read(args.manifest, MAX_MANIFEST_BYTES)
    expected = json.loads(inventory)
    if (not isinstance(expected, list) or not 1 <= len(expected) <= MAX_ENTRIES or
            any(not isinstance(entry, dict) or not isinstance(entry.get('native'), str) or
                type(entry.get('reference')) is not int or not 0 < entry['reference'] < 2**64 or
                type(entry.get('size')) is not int or not 0 <= entry['size'] < 2**64
                for entry in expected)):
        parser.error('Inventory requires bounded original names, references and sizes')
    if args.rounds * 2 * (len(expected) + 3) > MAX_SAMPLES:
        parser.error('Requested inventory/round matrix exceeds the sample budget')
    inputs = {'image_sha256': hashlib.sha256(image).hexdigest(),
              'manifest_sha256': hashlib.sha256(inventory).hexdigest(), 'entries': len(expected)}
    del image, inventory
    args.build = args.build.resolve()
    options = selected_options(args.build)
    archive = args.build / 'libntfs.a'
    archive_hash = digest(archive)
    paths = [ROOT / WORKLOAD, *sorted((ROOT / 'adapters/fskit').glob('*.[mh]')),
             *sorted((ROOT / 'include/ntfs').glob('*.h'))]
    sources = {str(path.relative_to(ROOT)): digest(path) for path in paths}
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    binary = args.output / 'ntfs-fskit-directory-workload'
    report_path = args.output / 'report.json'
    parameters = {'pages': list(args.pages), 'rounds': args.rounds,
                  'warmup_rounds': args.warmup_rounds,
                  'profiles': list(args.profiles), 'record_cache_entries': args.record_cache_entries}
    report = {'schema': 1, 'status': 'running', 'scope': 'real legacy FSKit directory component; '
              'immutable memory reader, external serialization, synthetic namespace inventory',
              'inventory_unique_references': len({entry['reference'] for entry in expected}),
              'machine': platform.machine(), 'platform': platform.platform(),
              'installed_mount_qualified': False, 'modern_runtime_qualified': False,
              'inputs': inputs, 'parameters': parameters,
              'cache_policy': 'new process/owner per repetition; configured bounded MFT record cache; '
              'explicit full-scan warmup before measured rounds; source/host cache already warm',
              'memory_scope': 'resource allocation pool: core and charged adapter continuation '
              'buffers; excludes Foundation objects and resource window; process peak RSS '
              'includes immutable input, manifest, workload, native objects and warmup',
              'percentile_scope': 'per-run percentiles, not pooled request samples',
              'comparison_scope': ('complete core versions; identical adapter/workload/public headers'
                                   if args.compare_core else 'identical core archive'),
              'variants': {}, 'runs': [], 'summaries': []}
    save(report_path, report)
    try:
        compiler = run_tool(['xcrun', '--find', 'clang']).decode().strip()
        sdk = run_tool(['xcrun', '--show-sdk-path']).decode().strip()
        compiler_version = run_tool([compiler, '--version']).decode().splitlines()[0]
        sdk_version = run_tool(['xcrun', '--show-sdk-version']).decode().strip()
        command = [compiler, '-isysroot', sdk, '-mmacosx-version-min=26.5', '-fobjc-arc',
                   '-fblocks', '-O2', '-Wall', '-Wextra', '-Werror',
                   '-Wdeclaration-after-statement', '-Wno-deprecated-declarations',
                   '-I', str(ROOT / 'include'), '-I', str(ROOT / 'adapters/fskit'),
                   '-framework', 'Foundation', '-framework', 'FSKit', str(ROOT / WORKLOAD),
                   *(str(ROOT / 'adapters/fskit' / name) for name in ADAPTERS),
                   str(archive), '-o', str(binary)]
        report['compile_command'] = command
        try:
            (args.output / 'compile.log').write_bytes(run_tool(command, timeout=120,
                                                              output_limit=MIB))
        except Exception as error:
            (args.output / 'compile.log').write_text(str(error) + '\n')
            raise
        current = {'binary': str(binary), 'binary_sha256': digest(binary),
                   'source_sha256': sources, 'core_archive_sha256': archive_hash,
                   'core_options': options, 'compiler': compiler_version, 'sdk_version': sdk_version,
                   'git_head': run_tool(['git', 'rev-parse', 'HEAD']).decode().strip(),
                   'optimization': 'O2 adapter/workload, Release/O3 core, no sanitizer'}
        report['variants']['current'] = current
        if args.reference is not None:
            reference = json.loads(bounded_read(args.reference.resolve() / 'report.json',
                                                MAX_REPORT_BYTES))
            previous = reference['variants']['current']
            if (reference['status'] != 'pass' or reference['machine'] != report['machine'] or
                    reference['inputs'] != inputs or
                    previous['compiler'] != compiler_version or previous['sdk_version'] != sdk_version or
                    previous['core_options'] != options or
                    (not args.compare_core and previous['core_archive_sha256'] != archive_hash) or
                    (args.compare_core and previous['source_sha256'] != sources) or
                    previous['source_sha256'][WORKLOAD] != sources[WORKLOAD] or
                    digest(Path(previous['binary'])) != previous['binary_sha256']):
                raise ValueError('Reference inputs, native sources, core policy or toolchain do not match')
            # Both retained binaries are executed with the current arguments.
            # A longer paired matrix may differ from the reference's old run.
            report['reference_prior_parameters'] = reference['parameters']
            report['variants']['reference'] = previous
        for profile in args.profiles:
            repeated = {name: [] for name in report['variants']}
            for repetition in range(args.repetitions):
                variants = list(report['variants'])
                if repetition % 2:
                    variants.reverse()
                for variant in variants:
                    command = [report['variants'][variant]['binary'], str(args.image),
                               str(args.manifest), profile, *(str(page) for page in args.pages),
                               str(args.rounds), str(args.warmup_rounds), str(args.record_cache_entries)]
                    log = args.output / f'run-{len(report["runs"]):05}.log'
                    try:
                        raw = run_tool(command, timeout=120, output_limit=16384)
                        log.write_bytes(raw)
                    except Exception as error:
                        log.write_text(str(error) + '\n')
                        raise
                    value = json.loads(raw)
                    readers = 1 if profile == 'sequential' else 2
                    entries = args.rounds * (readers * len(expected) + (2 if profile == 'views' else 0))
                    if (value['oracle'] != 'pass' or value['profile'] != profile or
                            value['page_a'] != args.pages[0] or value['page_b'] != args.pages[1] or
                            value['rounds'] != args.rounds or value['warmup_rounds'] != args.warmup_rounds or
                            value['record_cache_entries'] != args.record_cache_entries or
                            value['entries'] != entries or
                            value['wall_ns'] <= 0 or value['requests'] <= 0):
                        raise ValueError('Inventory, request completion or timing qualification failed')
                    value.update({'variant': variant, 'repetition': repetition, 'log': str(log),
                                  'entries_per_second': entries * 1_000_000_000 / value['wall_ns']})
                    report['runs'].append(value)
                    repeated[variant].append(value)
                    save(report_path, report)
            for variant, runs in repeated.items():
                report['summaries'].append({'profile': profile, 'variant': variant,
                                            'repetitions': args.repetitions, 'metrics': summarize(runs)})
        if (digest(archive) != archive_hash or
                any(digest(ROOT / path) != value for path, value in sources.items()) or
                digest(args.image) != inputs['image_sha256'] or
                digest(args.manifest) != inputs['manifest_sha256'] or
                any(digest(Path(variant['binary'])) != variant['binary_sha256']
                    for variant in report['variants'].values())):
            raise ValueError('Measured source, input, archive or binary changed during execution')
        report['status'] = 'pass'
    except Exception as error:
        report['status'] = 'failed'
        report['error'] = f'{type(error).__name__}: {error}'
        raise
    finally:
        save(report_path, report)
    print(f'PASS: {len(report["runs"])} native directory runs with independent inventory; {report_path}')


if __name__ == '__main__':
    main()
