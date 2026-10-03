"""Reject stale comparison evidence and check independent measured read schedules."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import hashlib
import json
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import benchmark as b
from workload_contract import expected_read

OPERATIONS = 29
WARMUP = 13
READERS = 3
REFERENCE_REVISION = 'a' * 40
CURRENT_REVISION = 'b' * 40


def main():
    checks = 0

    def refused(call):
        nonlocal checks
        try:
            call()
        except ValueError:
            checks += 1
        else:
            raise AssertionError('Invalid measurement evidence was accepted')

    with tempfile.TemporaryDirectory(prefix='ntfs-benchmark-contract-') as temporary:
        root = Path(temporary)
        data_path = root / 'original.bin'
        # The array oracle independently models documented reader division,
        # random offsets, EOF clipping and prefix sampling, without file seeks.
        for data in (b'', b'abcdefg', bytes(range(256)) * 19):
            data_path.write_bytes(data)
            for profile in ('sequential', 'random'):
                for request in (1, 17, 64, 4096):
                    expected = expected_read(data, profile, request, OPERATIONS, WARMUP, READERS)
                    assert b.expected_reads(data_path, profile, request, OPERATIONS,
                                            WARMUP, READERS) == expected
                    checks += 1

        directories = [root / 'first', root / 'second']
        products = []
        for directory in directories:
            directory.mkdir()
        for name in ('ntfs-workload', 'ntfs-inspect'):
            contents = ('independent retained product ' + name).encode()
            for directory in directories:
                (directory / name).write_bytes(contents)
            products.append({'name': name, 'byte_equal': True,
                             'first_bytes': len(contents), 'second_bytes': len(contents),
                             'first_sha256': hashlib.sha256(contents).hexdigest(),
                             'second_sha256': hashlib.sha256(contents).hexdigest()})
        report = {'status': 'pass', 'git_head_before': REFERENCE_REVISION,
                  'git_head_after': REFERENCE_REVISION,
                  'builds': [{'directory': str(directory), 'status': 'pass',
                              'options': {'optimization': '3'}} for directory in directories],
                  'products': products,
                  **{name: 'fixed-' + name for name in b.RELEASE_TOOLCHAIN_FIELDS}}
        report_path = root / 'release.json'

        def load(value, directory=None):
            report_path.write_text(json.dumps(value))
            return b.release_evidence(report_path, directory)

        for directory in directories:
            selected, evidence = load(report, directory)
            assert selected == directory.resolve() and evidence['revision'] == REFERENCE_REVISION
            checks += 1
        mutations = []
        for key, value in (('status', 'failed'), ('git_head_before', CURRENT_REVISION),
                           ('git_head_after', '--help')):
            candidate = deepcopy(report)
            candidate[key] = value
            mutations.append(candidate)
        candidate = deepcopy(report)
        candidate['builds'][1]['status'] = 'failed'
        mutations.append(candidate)
        candidate = deepcopy(report)
        candidate['builds'].append(candidate['builds'][0])
        mutations.append(candidate)
        for key, value in (('byte_equal', False), ('first_bytes', 1),
                           ('first_sha256', '0' * 64)):
            candidate = deepcopy(report)
            candidate['products'][0][key] = value
            mutations.append(candidate)
        candidate = deepcopy(report)
        candidate['products'].append(candidate['products'][0])
        mutations.append(candidate)
        for candidate in mutations:
            refused(lambda candidate=candidate: load(candidate))
        refused(lambda: load(report, root))
        (directories[0] / 'ntfs-workload').write_bytes(b'changed artifact')
        refused(lambda: load(report))

        reference = {**evidence, 'revision': REFERENCE_REVISION}
        current = {**evidence, 'revision': CURRENT_REVISION}
        with patch.object(b.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as git:
            b.matching_releases(reference, current)
            assert git.call_args.args[0][:5] == ['git', 'diff', '--exit-code',
                                                REFERENCE_REVISION, CURRENT_REVISION]
            checks += 1
        for name in (*b.RELEASE_TOOLCHAIN_FIELDS, 'options'):
            changed = {**current, name: 'different'}
            refused(lambda changed=changed: b.matching_releases(reference, changed))
        with patch.object(b.subprocess, 'run', return_value=SimpleNamespace(returncode=1)):
            refused(lambda: b.matching_releases(reference, current))

        key = {'profile': 'sequential', 'backend': 'memory', 'request_bytes': 3,
               'readers': 1, 'record_cache_entries': 0, 'warmup_operations': 0}
        row = {**key, 'wall_ns': 10, 'cpu_ns': 9, 'operations': 2,
               'p50_ns': 1, 'p95_ns': 2, 'p99_ns': 3, 'bytes': 6, 'entries': 0,
               'sampled_sum': f'{sum(b"abcdef"):016x}'}
        expected = (6, sum(b'abcdef'))
        b.validate_run(row, key, 2, expected)
        b.validate_pair([row, dict(row)])
        checks += 2
        for name, value in (('wall_ns', 0), ('cpu_ns', 0), ('operations', 1),
                             ('p50_ns', 4), ('readers', 2), ('bytes', 5),
                             ('sampled_sum', '0000000000000000')):
            refused(lambda name=name, value=value:
                    b.validate_run({**row, name: value}, key, 2, expected))
        for name, value in (('bytes', 5), ('entries', 1), ('sampled_sum', '0')):
            refused(lambda name=name, value=value:
                    b.validate_pair([row, {**row, name: value}]))

    print(f'PASS: {checks} independent range, release, toolchain/source and result contracts')


if __name__ == '__main__':
    main()
