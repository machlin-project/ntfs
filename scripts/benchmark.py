#!/usr/bin/env python3
"""Repeat bounded core workloads on immutable media with an independent data oracle."""
from environment import tool_environment
from pathlib import Path
import argparse
import hashlib
import itertools
import json
import platform
import re
import shutil
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
from windows_corpus import tool

HASH_IO_BYTES = 1024 * 1024
NANOSECONDS_PER_SECOND = 1_000_000_000
MEBIBYTE_BYTES = 1024 * 1024
MAX_OPERATIONS = 1_000_000
MAX_REQUEST_BYTES = 1024 * 1024
MAX_READERS = 64
MAX_REPETITIONS = 100
SAMPLE_BYTES = 64
UINT32_MASK = (1 << 32) - 1
UINT64_MASK = (1 << 64) - 1
RANDOM_MULTIPLIER = 1664525
RANDOM_INCREMENT = 1013904223
RANDOM_SEED = 0x85A7F12D
RELEASE_TOOLCHAIN_FIELDS = ('compiler_path', 'compiler_version', 'sdk_path', 'sdk_version',
                           'platform', 'machine')
WORKLOAD_SOURCES = ('tools/workload.c', 'tools/path.c', 'tools/path.h', 'adapters/posix')
RESULT_FIELDS = ('bytes', 'entries', 'sampled_sum')
PROFILE_NAMES = ('sequential', 'random', 'open', 'lookup', 'directory-next', 'directory-scan')
METRICS = ('wall_ns', 'cpu_ns', 'p50_ns', 'p95_ns', 'p99_ns', 'peak_core_bytes',
           'peak_rss_bytes', 'allocations', 'read_calls', 'read_bytes',
           'record_cache_hits', 'record_cache_misses', 'operations_per_second',
           'data_mib_per_second')


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(HASH_IO_BYTES), b''):
            value.update(chunk)
    return value.hexdigest()


def write_report(path, report):
    # Reports contain selected metrics, not compiler/Meson environment dumps.
    path.write_text(json.dumps(report, indent=2) + '\n')


def optimized_build(directory):
    raw = subprocess.check_output(['meson', 'introspect', '--buildoptions', str(directory)],
                                  cwd=ROOT, env=tool_environment(), stdin=subprocess.DEVNULL,
                                  timeout=30)
    selected = {item['name']: item['value'] for item in json.loads(raw)
                if item['name'] in ('buildtype', 'b_sanitize', 'optimization', 'b_lto')}
    # Meson versions serialize the disabled sanitizer option as a string or list.
    if selected.get('buildtype') != 'release' or selected.get('b_sanitize') not in ('none', [], ['none']):
        raise ValueError('Measurements require an unsanitized release Meson build')
    if str(selected.get('optimization')) not in ('2', '3', 's'):
        raise ValueError('Measurements require an optimized Meson build')
    return selected


def release_evidence(path, directory=None):
    """Verify retained build products against an ordinary Release check report."""
    report = json.loads(path.read_text())
    revision = report.get('git_head_after', '')
    if (report.get('status') != 'pass' or report.get('git_head_before') != revision or
            re.fullmatch(r'[0-9a-f]{40,64}', revision) is None):
        raise ValueError('Release evidence must pass with an unchanged Git revision')
    builds = report['builds']
    if len(builds) != 2 or any(item.get('status') != 'pass' for item in builds):
        raise ValueError('Release evidence must retain two successful builds')
    if directory is None:
        directory = Path(builds[0]['directory'])
    directory = directory.resolve(strict=True)
    matches = [(index, item) for index, item in enumerate(builds)
               if Path(item['directory']).resolve(strict=True) == directory]
    if len(matches) != 1:
        raise ValueError('Selected build must appear exactly once in the release evidence')
    index, build = matches[0]
    if index not in (0, 1) or build.get('status') != 'pass':
        raise ValueError('Release evidence must identify a successful first or second build')
    side = 'first' if index == 0 else 'second'
    for name in ('ntfs-workload', 'ntfs-inspect'):
        products = [item for item in report['products'] if item['name'] == name]
        if len(products) != 1:
            raise ValueError('Release evidence must identify each measured product once')
        product, actual = products[0], directory / name
        if (not product.get('byte_equal') or
                product['first_bytes'] != product['second_bytes'] or
                product['first_sha256'] != product['second_sha256'] or
                not actual.is_file() or
                actual.stat().st_size != product[side + '_bytes'] or
                digest(actual) != product[side + '_sha256']):
            raise ValueError('Actual measurement binary differs from its release evidence')
    return directory, {'report': str(path), 'revision': revision,
                       'options': build['options'],
                       **{name: report[name] for name in RELEASE_TOOLCHAIN_FIELDS}}


def matching_releases(reference, current):
    if any(reference[name] != current[name]
           for name in (*RELEASE_TOOLCHAIN_FIELDS, 'options')):
        raise ValueError('Paired runs require identical release options, compiler, SDK and host')
    result = subprocess.run(['git', 'diff', '--exit-code', reference['revision'],
                             current['revision'], '--', *WORKLOAD_SOURCES],
                            cwd=ROOT, env=tool_environment(), stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
    if result.returncode != 0:
        raise ValueError('Paired runs require unchanged workload and POSIX adapter sources')


def expected_reads(path, profile, request, operations, warmup, readers):
    """Check deterministic delivered ranges/samples against independent file bytes."""
    size = path.stat().st_size
    if size == 0:
        return 0, 0
    total = sampled = 0
    with path.open('rb') as data:
        for reader in range(readers):
            measured = operations // readers + (reader < operations % readers)
            skipped = warmup // readers + (reader < warmup % readers)
            offset, random = 0, (RANDOM_SEED + reader) & UINT32_MASK
            for operation in range(skipped + measured):
                if profile == 'random':
                    random = (random * RANDOM_MULTIPLIER + RANDOM_INCREMENT) & UINT32_MASK
                    high = random << 32
                    random = (random * RANDOM_MULTIPLIER + RANDOM_INCREMENT) & UINT32_MASK
                    offset = (high | random) % (max(0, size - request) + 1)
                count = min(request, size - offset)
                if operation >= skipped:
                    data.seek(offset)
                    sample = data.read(min(SAMPLE_BYTES, count))
                    if len(sample) != min(SAMPLE_BYTES, count):
                        raise ValueError('Independent data oracle changed during range checking')
                    total += count
                    sampled += sum(sample)
                offset += count
                if offset >= size:
                    offset = 0
    return total, sampled & UINT64_MASK


def validate_run(value, key, operations, expected):
    if (value['wall_ns'] <= 0 or value['cpu_ns'] <= 0 or value['operations'] != operations or
            not 0 <= value['p50_ns'] <= value['p95_ns'] <= value['p99_ns']):
        raise ValueError('Workload returned invalid timing or operation counts')
    for name, selected in key.items():
        if value[name] != selected:
            raise ValueError(f'Unexpected measured {name}')
    if expected is not None and (value['bytes'], int(value['sampled_sum'], 16)) != expected:
        raise ValueError('Measured read ranges/samples differ from the independent oracle')


def validate_pair(pair):
    if len(pair) == 2 and any(pair[0][field] != pair[1][field] for field in RESULT_FIELDS):
        raise ValueError('Paired variants returned different semantic workload results')


def summarize(runs):
    result = {}
    for field in METRICS:
        values = [run[field] for run in runs]
        result[field] = {'median': statistics.median(values), 'min': min(values),
                         'max': max(values),
                         'sample_stdev': statistics.stdev(values) if len(values) > 1 else 0}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('file', help='UTF-8 path inside the image, without link traversal')
    parser.add_argument('--expected-data', type=Path, required=True,
                        help='Independent original bytes for the selected stream')
    parser.add_argument('--stream', default='')
    parser.add_argument('--directory', default='/')
    parser.add_argument('--build', type=Path, default=ROOT / '.build-release')
    parser.add_argument('--release-report', type=Path,
                        help='Ordinary reproducibility report identifying the measured build')
    parser.add_argument('--reference-release', type=Path,
                        help='Compare the first build in a retained release report, with alternating order')
    parser.add_argument('--output', type=Path, required=True, help='New ignored artifact directory')
    parser.add_argument('--dataset-kind', choices=('synthetic', 'ntfs3g', 'windows', 'unknown'),
                        default='unknown', help='Declared input provenance; not native acceptance')
    parser.add_argument('--profiles', nargs='+', choices=PROFILE_NAMES, default=PROFILE_NAMES)
    parser.add_argument('--backends', nargs='+', choices=('posix', 'memory'), default=('posix', 'memory'))
    parser.add_argument('--requests', nargs='+', type=int, default=(65536,))
    parser.add_argument('--readers', nargs='+', type=int, default=(1,))
    parser.add_argument('--cache-entries', nargs='+', type=int, default=(64,))
    parser.add_argument('--warmup-operations', nargs='+', type=int, default=(0,))
    parser.add_argument('--operations', type=int, default=1000)
    parser.add_argument('--repetitions', type=int, default=5)
    args = parser.parse_args()
    if args.reference_release is not None and args.release_report is None:
        parser.error('Paired comparison requires --release-report for the current build')
    for name, values, minimum, maximum in (
            ('operations', (args.operations,), 1, MAX_OPERATIONS),
            ('repetitions', (args.repetitions,), 2, MAX_REPETITIONS),
            ('requests', args.requests, 1, MAX_REQUEST_BYTES),
            ('readers', args.readers, 1, min(MAX_READERS, args.operations)),
            ('cache entries', args.cache_entries, 0, 4096),
            ('warmup operations', args.warmup_operations, 0, MAX_OPERATIONS)):
        if any(value < minimum or value > maximum for value in values):
            parser.error(f'{name} must be in [{minimum}, {maximum}]')
    args.image = args.image.resolve(strict=True)
    args.expected_data = args.expected_data.resolve(strict=True)
    args.build = args.build.resolve(strict=True)
    args.output = args.output.resolve()
    if not args.image.is_file() or not args.expected_data.is_file():
        parser.error('image and data oracle must be regular files')
    args.output.mkdir(parents=True, exist_ok=False)
    report_path = args.output / 'report.json'
    report = {'status': 'running', 'platform': platform.platform(), 'machine': platform.machine(),
              'processor': platform.processor(), 'declared_dataset_kind': args.dataset_kind,
              'image': str(args.image), 'source_bytes': args.image.stat().st_size,
              'file': args.file, 'stream': args.stream, 'directory': args.directory,
              'scope': 'portable core, shared volume with external serialization',
              'cache_policy': 'new mount per run; setup warms metadata; explicit warmup continues '
                              'stream/cursor state; image integrity pass warms host page cache',
              'comparisons': 'POSIX callback versus preloaded memory callback; no FSKit/native baseline',
              'percentile_summary': 'summary of per-run percentiles, not pooled request percentiles',
              'runs': [], 'summaries': [], 'variants': {}}
    write_report(report_path, report)
    image_hash = None
    try:
        report['build_options'] = optimized_build(args.build)
        workload, inspector = args.build / 'ntfs-workload', args.build / 'ntfs-inspect'
        report['workload_sha256'] = digest(workload)
        report['inspector_sha256'] = digest(inspector)
        variants = {'current': args.build}
        evidence = {}
        if args.release_report is not None:
            _, evidence['current'] = release_evidence(args.release_report.resolve(strict=True),
                                                      args.build)
        if args.reference_release is not None:
            variants['reference'], evidence['reference'] = release_evidence(
                args.reference_release.resolve(strict=True))
            if optimized_build(variants['reference']) != report['build_options']:
                raise ValueError('Paired runs require the same actual optimized build options')
            matching_releases(evidence['reference'], evidence['current'])
            report['comparisons'] = ('alternating paired retained Release binaries; identical '
                                     'workload/adapter sources, toolchain, inputs and arguments; '
                                     'portable core, not FSKit/native or an independent driver')
        for variant, build in variants.items():
            retained = args.output / 'binaries' / variant
            retained.mkdir(parents=True)
            value = {'release': evidence.get(variant), 'directory': str(retained)}
            for name in ('ntfs-workload', 'ntfs-inspect'):
                before = digest(build / name)
                shutil.copyfile(build / name, retained / name)
                shutil.copymode(build / name, retained / name)
                if digest(retained / name) != before:
                    raise ValueError('Binary changed while retaining the measurement artifact')
                value[name + '_sha256'] = before
            variants[variant] = retained
            report['variants'][variant] = value
        image_hash = digest(args.image)
        report['image_sha256_before'] = image_hash
        report['oracle_bytes'] = args.expected_data.stat().st_size
        report['oracle_sha256'] = digest(args.expected_data)
        arguments = (args.file, args.stream) if args.stream else (args.file,)
        for build in variants.values():
            if tool(build / 'ntfs-inspect', args.image, 'cat', *arguments,
                    content_bytes=report['oracle_bytes']) != report['oracle_sha256']:
                raise ValueError('Driver content differs from the independent byte oracle')
        report['data_oracle'] = 'pass before measurements'
        for profile, backend, request, readers, cache, warmup in itertools.product(
                args.profiles, args.backends, args.requests, args.readers,
                args.cache_entries, args.warmup_operations):
            # Request size affects data reads only; avoid duplicated metadata workloads.
            if profile not in ('sequential', 'random') and request != args.requests[0]:
                continue
            path = args.directory if profile.startswith('directory-') else args.file
            key = {'profile': profile, 'backend': backend, 'request_bytes': request,
                   'readers': readers, 'record_cache_entries': cache, 'warmup_operations': warmup}
            expected = (expected_reads(args.expected_data, profile, request, args.operations,
                                       warmup, readers)
                        if profile in ('sequential', 'random') else None)
            repeated = {variant: [] for variant in variants}
            for repetition in range(args.repetitions):
                order = sorted(variants, reverse=repetition % 2 == 0)
                pair = []
                for position, variant in enumerate(order):
                    run_id = len(report['runs'])
                    command = [str(variants[variant] / 'ntfs-workload'), str(args.image), path,
                               '--profile', profile, '--backend', backend,
                               '--operations', str(args.operations), '--request', str(request),
                               '--readers', str(readers), '--cache-entries', str(cache),
                               '--warmup-operations', str(warmup), '--stream', args.stream]
                    log = args.output / f'run-{run_id:05}.log'
                    started = time.monotonic()
                    with log.open('wb') as errors:
                        result = subprocess.run(command, cwd=ROOT, env=tool_environment(),
                                                stdin=subprocess.DEVNULL,
                                                stdout=subprocess.PIPE, stderr=errors, timeout=120)
                    if result.returncode != 0:
                        raise RuntimeError(f'Workload exit {result.returncode}: {log}')
                    value = json.loads(result.stdout)
                    validate_run(value, key, args.operations, expected)
                    seconds = value['wall_ns'] / NANOSECONDS_PER_SECOND
                    value['operations_per_second'] = value['operations'] / seconds
                    value['data_mib_per_second'] = value['bytes'] / MEBIBYTE_BYTES / seconds
                    value['repetition'] = repetition
                    value['variant'] = variant
                    value['pair_position'] = position
                    value['process_seconds'] = time.monotonic() - started
                    value['log'] = str(log)
                    if digest(args.image) != image_hash:
                        raise ValueError('Source image changed during a read-only workload')
                    repeated[variant].append(value)
                    pair.append(value)
                    report['runs'].append(value)
                    write_report(report_path, report)
                validate_pair(pair)
            for variant, runs in repeated.items():
                report['summaries'].append({'configuration': {**key, 'variant': variant},
                                            'repetitions': args.repetitions,
                                            'metrics': summarize(runs)})
        for variant, build in variants.items():
            if tool(build / 'ntfs-inspect', args.image, 'cat', *arguments,
                    content_bytes=report['oracle_bytes']) != report['oracle_sha256']:
                raise ValueError('Driver content changed after measured workloads')
            for name in ('ntfs-workload', 'ntfs-inspect'):
                if digest(build / name) != report['variants'][variant][name + '_sha256']:
                    raise ValueError('Retained measurement binary changed during the run')
        if digest(args.expected_data) != report['oracle_sha256']:
            raise ValueError('Independent original data changed during the run')
        report['data_oracle'] = 'pass before and after measurements'
        report['status'] = 'pass'
    except Exception as error:
        report['status'] = 'failed'
        report['error'] = f'{type(error).__name__}: {error}'
        raise
    finally:
        if image_hash is not None:
            report['image_sha256_after'] = digest(args.image)
            if report['image_sha256_after'] != image_hash:
                report['status'] = 'failed'
                report['integrity_error'] = 'source image changed'
        write_report(report_path, report)
    if report['status'] != 'pass':
        raise SystemExit('Benchmark qualification failed; see retained report')
    print(f'PASS: {len(report["runs"])} repetitions, {len(report["summaries"])} configurations; '
          f'independent bytes and unchanged source: {report_path}')


if __name__ == '__main__':
    main()
