#!/usr/bin/env python3
"""Check all target metadata and exact indexed records against independent goldens."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from environment import tool_environment

DEADLINE_SECONDS = 10
MAX_OUTPUT_BYTES = 3 * 1024 * 1024
INDEX_MEMORY_BYTES = 1024 * 1024
ARGUMENT_ERROR = 2
LSN_MAXIMUM = (1 << 64) - 1


def invoke(binary, command, *arguments):
    run = subprocess.run([str(binary), command, *map(str, arguments)], cwd=ROOT,
        env=tool_environment(), stdin=subprocess.DEVNULL, capture_output=True,
        timeout=DEADLINE_SECONDS, check=False)
    assert len(run.stdout) <= MAX_OUTPUT_BYTES and len(run.stderr) <= MAX_OUTPUT_BYTES
    return run


def storage(report):
    required, retained = report['required_bytes'], report['retained_bytes']
    if report['published']:
        assert 0 < required == retained <= INDEX_MEMORY_BYTES
    else:
        assert retained == 0
    return {key: value for key, value in report.items() if key not in
            ('required_bytes', 'retained_bytes')}


def main(binary, directory):
    manifest = json.loads((directory / 'manifest.json').read_text())
    hashes = {path: hashlib.sha256(path.read_bytes()).hexdigest()
              for path in directory.rglob('*') if path.is_file()}
    observations = 0
    for case in manifest['cases']:
        assert hashes[directory / case['path']] == case['source_sha256']
        run = invoke(binary, 'index', directory / case['path'])
        assert run.returncode == (0 if case['code'] == 0 else 1) and not run.stderr, case['path']
        result = json.loads(run.stdout)
        assert result['schema_version'] == 1 and result['scope'] == 'index'
        assert result['history_qualified'] is False and result['recovery_qualified'] is False
        assert result['code'] == case['code'] and isinstance(result['result'], str)
        assert result['targets'] == case['targets'], case['path']
        assert storage(result['index']) == case['index'], (case['path'], result['index'], case['index'])
        observations += len(result['targets'])
    for case in manifest['records']:
        assert hashes[directory / case['path']] == case['source_sha256']
        run = invoke(binary, 'indexed-record', directory / case['path'], case['lsn'])
        assert run.returncode == (0 if case['code'] == 0 else 1) and not run.stderr, case['path']
        result = json.loads(run.stdout)
        assert result['schema_version'] == 1 and result['scope'] == 'indexed-record'
        assert result['history_qualified'] is False and result['recovery_qualified'] is False
        storage(result['preparation'])
        expected = dict(code=case['code'], requested_lsn=case['lsn'], record=None,
                        assembly=None, bytes_hex=None)
        if case['code'] == 0:
            expected['record'] = case['record_fields']
            expected['assembly'] = dict(first_page_offset=case['first_page'],
                last_page_offset=case['last_page'], bytes=case['bytes'], pages_read=case['pages'],
                copy_pages_read=case['copies'], read_calls=case['pages'],
                read_bytes=case['pages'] * case['page_bytes'], wrapped=case['wrapped'])
            expected['bytes_hex'] = (directory / (case['path'] + '.record')).read_bytes().hex()
        actual = {key: value for key, value in result.items() if key not in
                  ('schema_version', 'scope', 'history_qualified', 'recovery_qualified',
                   'result', 'preparation')}
        assert actual == expected, (case['path'], actual, expected)
    first = directory / manifest['cases'][0]['path']
    for command, arguments in (
        ('index', ()), ('index', (directory,)), ('index', (directory / 'absent.journal',)),
        ('index', (first, 'extra')), ('indexed-record', (first,)),
        *(('indexed-record', (first, value)) for value in
          ('-1', '+1', '1x', '', str(LSN_MAXIMUM + 1)))):
        run = invoke(binary, command, *arguments)
        assert run.returncode == ARGUMENT_ERROR and not run.stdout
    assert all(hashlib.sha256(path.read_bytes()).hexdigest() == digest
               for path, digest in hashes.items())
    print(f'PASS: {len(manifest["cases"])} target-index graphs/{observations} target rows, '
          f'{len(manifest["records"])} exact record results and unchanged inputs; '
          'no current-history or recovery acceptance')


if __name__ == '__main__':
    main(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
