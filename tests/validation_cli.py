#!/usr/bin/env python3
"""Check diagnostic verdicts, partial counters and CLI resource boundaries."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from environment import tool_environment

TOOL_SECONDS = 10
REPORT_BYTES = 16 * 1024
HASH_BYTES = 64 * 1024
STAGE_SETUP, STAGE_FINISHED = 0, 6
LIMIT_NONE = 0
OPTION_LIMITS = (('memory-bytes', 1), ('read-calls', 2), ('read-bytes', 3),
                 ('work-units', 4), ('records', 5), ('runs', 6), ('links', 7))


def image_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(HASH_BYTES), b''):
            digest.update(chunk)
    return digest.hexdigest()


def invoke(tool, arguments, status):
    # This executable emits one fixed-size report, or a fixed usage/error line.
    result = subprocess.run([str(tool), *map(str, arguments)], cwd=ROOT,
                            env=tool_environment(), stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=TOOL_SECONDS)
    assert len(result.stdout) <= REPORT_BYTES and len(result.stderr) <= REPORT_BYTES
    if status is None:
        assert result.returncode in (0, 1), (arguments, result.returncode, result.stderr)
    else:
        assert result.returncode == status, (arguments, result.returncode, result.stderr)
    if status == 2:
        assert not result.stdout and result.stderr
        return None
    assert not result.stderr, result.stderr
    report = json.loads(result.stdout)
    assert report['complete'] == (result.returncode == 0)
    assert (report['stage'] == STAGE_FINISHED) == report['complete']
    assert all(isinstance(report[name], str) and report[name].isdigit()
               for name in ('read_calls', 'read_bytes', 'work_units', 'peak_memory_bytes'))
    return report


def main():
    tool, fixtures = Path(sys.argv[1]), Path(sys.argv[2])
    cases = json.loads((fixtures / 'validation-cases.json').read_text())
    for case in cases:
        image = fixtures / case['image']
        original = image_hash(image)
        report = invoke(tool, [image], 0 if case['complete'] else 1)
        assert report['result'] == case['result'], (case['image'], report)
        assert report['complete'] == case['complete'] and report['exhausted'] == LIMIT_NONE
        assert image_hash(image) == original
        for name, expected in case.get('mirror', {}).items():
            assert report[name] == expected, (case['image'], name, expected, report)
        for name, expected in case.get('inventory', {}).items():
            assert report[name] == expected, (case['image'], name, expected, report)
        for name, expected in case.get('boot', {}).items():
            assert report[name] == expected, (case['image'], name, expected, report)
        assert report['deferred_dos_link_counts'] == '0'
        if case['image'] == 'validation-allocated-unclaimed-cluster.img':
            assert report['unclaimed_clusters'] == '1'
        if case['complete']:
            assert report['mirror_records_compared'] == '4'
            assert report['claimed_clusters'] == report['allocated_clusters']
            assert report['unclaimed_clusters'] == '0'
    image = fixtures / 'validation-standard.img'
    for option, exhausted in OPTION_LIMITS:
        report = invoke(tool, [image, '--max-' + option, 1], 1)
        assert report['result'] == 'resource limit' and report['exhausted'] == exhausted
    for arguments in ([], [image, '--max-work-units'], [image, '--unknown', 1],
                      *([image, '--max-read-calls', text]
                        for text in ('0', '-1', '+1', '1x', '18446744073709551616')),
                      [image, '--max-records', 1 << 32]):
        invoke(tool, arguments, 2)
    report = invoke(tool, [image, '--max-records', (1 << 20) + 1], 1)
    assert report['result'] == 'invalid argument' and report['stage'] == STAGE_SETUP
    assert report['read_calls'] == '0' and report['allocation_calls'] == '0'
    with tempfile.TemporaryDirectory(prefix='ntfs-validation-cli-') as directory:
        path = Path(directory)
        invoke(tool, [path], 2)
        invoke(tool, [path / 'missing'], 2)
        if hasattr(os, 'mkfifo'):
            fifo = path / 'fifo'
            os.mkfifo(fifo)
            invoke(tool, [fifo], 2)
    print(f'PASS: {len(cases)} diagnostic images, all seven budgets, CLI errors and special-file rejection')


if __name__ == '__main__':
    main()
