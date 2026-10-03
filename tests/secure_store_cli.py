#!/usr/bin/env python3
"""Independent whole-store reports, off-path evidence and immutable image checks."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from environment import tool_environment

TOOL_SECONDS = 10
REPORT_BYTES = 16 * 1024
HASH_BYTES = 64 * 1024
STAGE_SII, STAGE_FINISHED = 1, 6
MAX_DESCRIPTORS = 1024 * 1024
COUNTERS = ('sii_entries', 'sdh_entries', 'sii_blocks', 'sdh_blocks',
            'descriptors', 'descriptor_bytes', 'offset', 'cluster')


def image_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(HASH_BYTES), b''):
            digest.update(chunk)
    return digest.hexdigest()


def invoke(tool, image, *arguments, raw=False):
    result = subprocess.run([str(tool), str(image), *map(str, arguments)], cwd=ROOT,
                            env=tool_environment(), stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=TOOL_SECONDS)
    assert len(result.stdout) <= REPORT_BYTES and len(result.stderr) <= REPORT_BYTES
    if raw:
        return result
    assert result.returncode in (0, 1) and not result.stderr, (image, result.stderr)
    report = json.loads(result.stdout)
    assert report['complete'] == (result.returncode == 0)
    assert (report['stage'] == STAGE_FINISHED) == report['complete']
    assert not report['authorization'] and report['unused_sds_gaps'] == 'opaque'
    assert all(isinstance(report[field], str) and report[field].isdigit() for field in COUNTERS)
    if report['complete']:
        assert report['security_id'] == 0 and report['hash'] == 0
        assert report['offset'] == '0' and report['cluster'] == '0'
    return report


def main():
    tool, fixtures = Path(sys.argv[1]), Path(sys.argv[2])
    cases = json.loads((fixtures / 'secure-store-cases.json').read_text())
    for case in cases:
        image = fixtures / case['image']
        before = image_hash(image)
        report = invoke(tool, image, 'security-store')
        assert all(report[field] == case[field] for field in ('result', 'stage', 'complete')), (case, report)
        assert not report['descriptor_limit'], (case, report)
        for field, expected in case.get('counts', {}).items():
            assert report[field] == str(expected), (case['image'], field, expected, report)
        assert image_hash(image) == before
    leaf = fixtures / 'secure-store-leaf.img'
    assert invoke(tool, leaf, 'security-store', 4)['complete']
    limited = invoke(tool, leaf, 'security-store', 3)
    assert limited['result'] == 'resource limit' and limited['descriptor_limit']
    assert limited['stage'] == STAGE_SII and limited['sii_entries'] == '3'
    assert limited['descriptors'] == '0'
    for value in ('', '0', '-1', '+1', '1x', str(MAX_DESCRIPTORS + 1), '9' * 40):
        result = invoke(tool, leaf, 'security-store', value, raw=True)
        assert result.returncode == 1 and not result.stdout and result.stderr
    extra = invoke(tool, leaf, 'security-store', 4, 4, raw=True)
    assert extra.returncode == 1 and not extra.stdout and extra.stderr
    # The old per-ID resolver correctly examines only its searched paths and
    # descriptor. Whole-store diagnostics must find the unrelated damaged ID.
    for label in ('off-path-primary', 'off-path-copy-header', 'off-path-copy-body', 'off-path-descriptor'):
        image = fixtures / ('secure-store-' + label + '.img')
        before = image_hash(image)
        result = invoke(tool, image, 'security-id', '100', raw=True)
        assert result.returncode == 0 and not result.stderr
        assert result.stdout == (fixtures / 'secure-expected/256.bin').read_bytes()
        assert not invoke(tool, image, 'security-store')['complete']
        assert image_hash(image) == before
    validation_cases = json.loads((fixtures / 'secure-store-validation-cases.json').read_text())
    validator = Path(sys.argv[3])
    for case in validation_cases:
        image = fixtures / case['image']
        before = image_hash(image)
        result = invoke(validator, image, raw=True)
        assert result.returncode == (0 if case['complete'] else 1) and not result.stderr
        report = json.loads(result.stdout)
        assert all(report[field] == case[field] for field in ('result', 'stage', 'complete')), (case, report)
        assert report['record_number'] == str(case['record_number']), (case, report)
        assert report['exhausted'] == 0 and image_hash(image) == before
    print(f'PASS: {len(cases)} whole-store verdicts, exact reports, caps, off-path corruption and unchanged images')
    print(f'PASS: {len(validation_cases)} complete-volume security/reference verdicts')


if __name__ == '__main__':
    main()
