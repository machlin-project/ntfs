#!/usr/bin/env python3
"""Repeat bounded core workloads on immutable media with an independent data oracle."""
from environment import tool_environment
from pathlib import Path
import argparse
import hashlib
import itertools
import json
import platform
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
                                  cwd=ROOT, env=tool_environment(), timeout=30)
    selected = {item['name']: item['value'] for item in json.loads(raw)
                if item['name'] in ('buildtype', 'b_sanitize', 'optimization', 'b_lto')}
    # Meson versions serialize the disabled sanitizer option as a string or list.
    if selected.get('buildtype') != 'release' or selected.get('b_sanitize') not in ('none', [], ['none']):
        raise ValueError('Measurements require an unsanitized release Meson build')
    if str(selected.get('optimization')) not in ('2', '3', 's'):
        raise ValueError('Measurements require an optimized Meson build')
    return selected


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
    workload, inspector = args.build / 'ntfs-workload', args.build / 'ntfs-inspect'
    report = {'status': 'running', 'platform': platform.platform(), 'machine': platform.machine(),
              'processor': platform.processor(), 'declared_dataset_kind': args.dataset_kind,
              'image': str(args.image), 'source_bytes': args.image.stat().st_size,
              'file': args.file, 'stream': args.stream, 'directory': args.directory,
              'scope': 'portable core, shared volume with external serialization',
              'cache_policy': 'new mount per run; setup warms metadata; explicit warmup continues '
                              'stream/cursor state; image integrity pass warms host page cache',
              'comparisons': 'POSIX callback versus preloaded memory callback; no FSKit/native baseline',
              'percentile_summary': 'summary of per-run percentiles, not pooled request percentiles',
              'runs': [], 'summaries': []}
    write_report(report_path, report)
    image_hash = None
    try:
        report['build_options'] = optimized_build(args.build)
        report['workload_sha256'] = digest(workload)
        report['inspector_sha256'] = digest(inspector)
        image_hash = digest(args.image)
        report['image_sha256_before'] = image_hash
        report['oracle_bytes'] = args.expected_data.stat().st_size
        report['oracle_sha256'] = digest(args.expected_data)
        arguments = (args.file, args.stream) if args.stream else (args.file,)
        actual = tool(inspector, args.image, 'cat', *arguments,
                      content_bytes=report['oracle_bytes'])
        if actual != report['oracle_sha256']:
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
            repeated = []
            for repetition in range(args.repetitions):
                run_id = len(report['runs'])
                command = [str(workload), str(args.image), path, '--profile', profile,
                           '--backend', backend, '--operations', str(args.operations),
                           '--request', str(request), '--readers', str(readers),
                           '--cache-entries', str(cache), '--warmup-operations', str(warmup),
                           '--stream', args.stream]
                log = args.output / f'run-{run_id:05}.log'
                started = time.monotonic()
                with log.open('wb') as errors:
                    result = subprocess.run(command, cwd=ROOT, env=tool_environment(),
                                            stdout=subprocess.PIPE, stderr=errors, timeout=120)
                if result.returncode != 0:
                    raise RuntimeError(f'Workload exit {result.returncode}: {log}')
                value = json.loads(result.stdout)
                if value['wall_ns'] <= 0:
                    raise ValueError('Workload timer returned a zero duration')
                for name, expected in key.items():
                    if value[name] != expected:
                        raise ValueError(f'Unexpected measured {name}')
                seconds = value['wall_ns'] / NANOSECONDS_PER_SECOND
                value['operations_per_second'] = value['operations'] / seconds
                value['data_mib_per_second'] = value['bytes'] / MEBIBYTE_BYTES / seconds
                value['repetition'] = repetition
                value['process_seconds'] = time.monotonic() - started
                value['log'] = str(log)
                if digest(args.image) != image_hash:
                    raise ValueError('Source image changed during a read-only workload')
                repeated.append(value)
                report['runs'].append(value)
                write_report(report_path, report)
            report['summaries'].append({'configuration': key, 'repetitions': args.repetitions,
                                        'metrics': summarize(repeated)})
        if tool(inspector, args.image, 'cat', *arguments, content_bytes=report['oracle_bytes']) != actual:
            raise ValueError('Driver content changed after measured workloads')
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
