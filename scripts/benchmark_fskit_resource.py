#!/usr/bin/env python3
"""Measure real FSKit resource reads over an immutable aligned memory reader."""
from pathlib import Path
import argparse
import hashlib
import itertools
import json
import platform
import statistics
import sys
import time

from bounded_tool import bounded_read, run_tool

ROOT = Path(__file__).resolve().parents[1]
WINDOW_BYTES = 1024 * 1024
MIN_ALIGNMENT = 512
MAX_ALIGNMENT = 65536
MAX_OPERATIONS = 1_000_000
MAX_REPETITIONS = 100
REPORT_LIMIT_BYTES = 16 * WINDOW_BYTES
PROFILES = ('aligned', 'offset', 'pointer', 'length', 'multi-window')
METRICS = ('wall_ns', 'cpu_ns', 'p50_ns', 'p95_ns', 'p99_ns', 'read_calls',
           'read_bytes', 'direct_read_calls', 'direct_read_bytes', 'window_read_calls',
           'window_read_bytes', 'inferred_bounce_copy_bytes', 'peak_rss_bytes',
           'operations_per_second', 'data_mib_per_second')
SOURCES = ('tools/fskit_read_workload.m', 'adapters/fskit/NTFSResource.m',
           'adapters/fskit/NTFSResource.h', 'core/support.c', 'core/internal.h',
           'core/disk.h', 'include/ntfs/ntfs.h')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_report(path, report):
    path.write_text(json.dumps(report, indent=2) + '\n')


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
    parser.add_argument('--output', type=Path, required=True,
                        help='New ignored artifact directory retaining its measurement binary')
    parser.add_argument('--reference', type=Path,
                        help='Prior passing output; rerun its retained binary alongside the candidate')
    parser.add_argument('--requests', nargs='+', type=int, default=(4096, 65536, WINDOW_BYTES))
    parser.add_argument('--alignments', nargs='+', type=int, default=(4096,))
    parser.add_argument('--profiles', nargs='+', choices=PROFILES, default=PROFILES)
    parser.add_argument('--operations', type=int, default=2000)
    parser.add_argument('--warmup-operations', type=int, default=128)
    parser.add_argument('--repetitions', type=int, default=5)
    args = parser.parse_args()
    if sys.platform != 'darwin':
        parser.error('FSKit resource measurements require macOS and its SDK')
    for name, values, minimum, maximum in (
            ('requests', args.requests, MIN_ALIGNMENT, WINDOW_BYTES),
            ('alignments', args.alignments, MIN_ALIGNMENT, MAX_ALIGNMENT),
            ('operations', (args.operations,), 1, MAX_OPERATIONS),
            ('warmup operations', (args.warmup_operations,), 0, MAX_OPERATIONS),
            ('repetitions', (args.repetitions,), 2, MAX_REPETITIONS)):
        if any(value < minimum or value > maximum for value in values):
            parser.error(f'{name} must be in [{minimum}, {maximum}]')
    if any(alignment & (alignment - 1) for alignment in args.alignments):
        parser.error('alignments must be powers of two')
    if any(request < alignment or request % alignment
           for request, alignment in itertools.product(args.requests, args.alignments)):
        parser.error('every request must be a positive multiple of every alignment')
    if 'multi-window' in args.profiles and WINDOW_BYTES not in args.requests:
        parser.error('multi-window requires the 1-MiB request in the matrix')
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    report_path = args.output / 'report.json'
    binary = args.output / 'ntfs-fskit-read-workload'
    source_hashes = {name: digest(ROOT / name) for name in SOURCES}
    report = {'schema': 1, 'status': 'running', 'scope': 'real FSKit resource, memory reader only',
              'platform': platform.platform(), 'machine': platform.machine(),
              'native_device_qualified': False,
              'cache_policy': 'new process/owner per run; 64-MiB deterministic resident source; '
                              'full initial oracle then explicit warmup before counters/timers',
              'reader_control': 'same callbacks and 1-MiB cap without resource admission, '
                                'geometry checks, synchronization or bounce copy',
              'copy_metric': 'requested bytes minus observed caller-directed device bytes; '
                             'inferred from destinations, no memcpy instrumentation',
              'percentile_summary': 'per-run percentile summaries, not pooled request percentiles',
              'variants': {}, 'runs': [], 'summaries': []}
    write_report(report_path, report)
    try:
        compiler = run_tool(['xcrun', '--find', 'clang']).decode().strip()
        sdk = run_tool(['xcrun', '--show-sdk-path']).decode().strip()
        report['compiler'] = run_tool([compiler, '--version']).decode().splitlines()[0]
        report['sdk_version'] = run_tool(['xcrun', '--show-sdk-version']).decode().strip()
        report['git_head'] = run_tool(['git', 'rev-parse', 'HEAD']).decode().strip()
        command = [compiler, '-isysroot', sdk, '-mmacosx-version-min=26.5', '-fobjc-arc',
                   '-fblocks', '-O2', '-Wall', '-Wextra', '-Werror',
                   '-Wdeclaration-after-statement', '-Wno-deprecated-declarations',
                   '-I', str(ROOT / 'include'), '-I', str(ROOT / 'adapters/fskit'),
                   '-framework', 'Foundation', '-framework', 'FSKit',
                   str(ROOT / 'tools/fskit_read_workload.m'),
                   str(ROOT / 'adapters/fskit/NTFSResource.m'), str(ROOT / 'core/support.c'),
                   '-o', str(binary)]
        report['compile_command'] = command
        compile_log = args.output / 'compile.log'
        try:
            compile_log.write_bytes(run_tool(command, timeout=120, output_limit=65536))
        except Exception as error:
            compile_log.write_text(str(error) + '\n')
            raise
        current = {'binary': str(binary), 'binary_sha256': digest(binary),
                   'source_sha256': source_hashes, 'optimization': 'O2, no sanitizer',
                   'compiler': report['compiler'], 'sdk_version': report['sdk_version']}
        report['variants']['current'] = current
        if args.reference is not None:
            reference = json.loads(bounded_read(args.reference.resolve() / 'report.json',
                                                REPORT_LIMIT_BYTES))
            previous = reference['variants']['current']
            if reference['status'] != 'pass' or reference['machine'] != report['machine']:
                raise ValueError('Reference must be a passing report on this architecture')
            if (previous['compiler'] != current['compiler'] or
                    previous['sdk_version'] != current['sdk_version'] or
                    previous['source_sha256']['tools/fskit_read_workload.m'] !=
                    source_hashes['tools/fskit_read_workload.m']):
                raise ValueError('Reference requires the same workload, compiler and SDK')
            if digest(Path(previous['binary'])) != previous['binary_sha256']:
                raise ValueError('Retained reference binary changed')
            report['variants']['reference'] = previous
        for profile, request, alignment in itertools.product(
                args.profiles, args.requests, args.alignments):
            if profile == 'multi-window' and request != WINDOW_BYTES:
                continue
            backends = ('resource', 'reader') if profile in ('aligned', 'multi-window') else ('resource',)
            for backend in backends:
                key = {'profile': profile, 'backend': backend, 'request_bytes': request,
                       'alignment': alignment, 'operations': args.operations,
                       'warmup_operations': args.warmup_operations}
                repeated = {name: [] for name in report['variants']}
                for repetition in range(args.repetitions):
                    # Alternate old/new order to avoid consistently favoring one variant.
                    variants = list(report['variants'])
                    if repetition % 2:
                        variants.reverse()
                    for variant in variants:
                        command = [report['variants'][variant]['binary'], profile, backend,
                                   str(request), str(alignment), str(args.operations),
                                   str(args.warmup_operations)]
                        log = args.output / f'run-{len(report["runs"]):05}.log'
                        started = time.monotonic()
                        try:
                            raw = run_tool(command, timeout=120, output_limit=16384)
                            log.write_bytes(raw)
                        except Exception as error:
                            log.write_text(str(error) + '\n')
                            raise
                        value = json.loads(raw)
                        for field, expected in key.items():
                            if value[field] != expected:
                                raise ValueError(f'Unexpected measured {field}')
                        if (value['wall_ns'] <= 0 or value['guards'] != 'pass' or
                                not value['source_immutable'] or value['source_sha256_before'] !=
                                value['source_sha256_after']):
                            raise ValueError('Timer, byte/guard or immutable-source oracle failed')
                        seconds = value['wall_ns'] / 1_000_000_000
                        value.update({'operations_per_second': value['operations'] / seconds,
                                      'data_mib_per_second': value['bytes'] / WINDOW_BYTES / seconds,
                                      'variant': variant, 'repetition': repetition,
                                      'process_seconds': time.monotonic() - started, 'log': str(log)})
                        repeated[variant].append(value)
                        report['runs'].append(value)
                        write_report(report_path, report)
                for variant, values in repeated.items():
                    report['summaries'].append({'configuration': key, 'variant': variant,
                                                'repetitions': args.repetitions,
                                                'metrics': summarize(values)})
        if any(digest(ROOT / name) != value for name, value in source_hashes.items()):
            raise ValueError('Measured product/workload source changed during execution')
        for variant in report['variants'].values():
            if digest(Path(variant['binary'])) != variant['binary_sha256']:
                raise ValueError('Measured binary changed during execution')
        report['status'] = 'pass'
    except Exception as error:
        report['status'] = 'failed'
        report['error'] = f'{type(error).__name__}: {error}'
        raise
    finally:
        write_report(report_path, report)
    print(f'PASS: {len(report["runs"])} runs, {len(report["summaries"])} summaries; '
          f'byte/guard/immutable-source oracles: {report_path}')


if __name__ == '__main__':
    main()
