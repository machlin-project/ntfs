#!/usr/bin/env python3
"""Compare circular-record JSON and exact restored bytes with authored oracles."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from environment import tool_environment

DEADLINE_SECONDS = 10
MAX_RECORD_BYTES = 1024 * 1024
MAX_JSON_METADATA_BYTES = 4096
MAX_OUTPUT_BYTES = MAX_RECORD_BYTES * 2 + MAX_JSON_METADATA_BYTES
ARGUMENT_ERROR = 2
CORRUPT = 2
LSN_MAXIMUM = (1 << 64) - 1


def invoke(binary, *arguments):
    run = subprocess.run([str(binary), 'circular-record', *map(str, arguments)],
        cwd=ROOT, env=tool_environment(), stdin=subprocess.DEVNULL, capture_output=True,
        timeout=DEADLINE_SECONDS, check=False)
    assert len(run.stdout) <= MAX_OUTPUT_BYTES and len(run.stderr) <= MAX_OUTPUT_BYTES
    return run


def main(binary, directory):
    cases = json.loads((directory / 'manifest.json').read_text())['cases']
    assert len({case['path'] for case in cases}) == len(cases)
    hashes = {path: hashlib.sha256(path.read_bytes()).hexdigest()
              for path in directory.iterdir() if path.is_file()}
    for case in cases:
        run = invoke(binary, directory / case['path'], case['lsn'])
        assert run.returncode == (0 if case['code'] == 0 else 1), (case['path'], run.stderr)
        result = json.loads(run.stdout)
        assert result['schema_version'] == 1 and result['scope'] == 'circular-record'
        assert result['recovery_qualified'] is False and isinstance(result['result'], str)
        expected = dict(code=case['code'], requested_lsn=case['lsn'], record=None,
                        assembly=None, bytes_hex=None)
        if case['code'] == 0:
            expected['record'] = case['record_fields']
            expected['assembly'] = dict(first_page_offset=case['first_page'],
                last_page_offset=case['last_page'], bytes=case['bytes'],
                pages_read=case['pages'], read_calls=case['pages'],
                read_bytes=case['pages'] * case['page_bytes'], wrapped=case['wrapped'])
            expected['bytes_hex'] = (directory / (case['path'] + '.record')).read_bytes().hex()
        metadata = {key: value for key, value in result.items() if key not in
                    ('schema_version', 'scope', 'recovery_qualified', 'result')}
        assert metadata == expected, (case['path'], metadata, expected)
    # Opening a regular file with no restart fails before record assembly.
    run = invoke(binary, directory / 'manifest.json', 0)
    assert run.returncode == 1
    result = json.loads(run.stdout)
    assert result['code'] == CORRUPT and result['record'] is None
    assert result['assembly'] is None and result['bytes_hex'] is None
    for arguments in ((directory, 0), (directory / 'absent.journal', 0),
                      (directory / cases[0]['path'],),
                      *((directory / cases[0]['path'], value)
                        for value in ('-1', '+1', '1x', '', str(LSN_MAXIMUM + 1)))):
        run = invoke(binary, *arguments)
        assert run.returncode == ARGUMENT_ERROR and not run.stdout
    assert all(hashlib.sha256(path.read_bytes()).hexdigest() == expected
               for path, expected in hashes.items())
    print(f'PASS: {len(cases)} exact circular-record reports/byte oracles, discovery/argument/transport '
          'errors and unchanged sources; no current-history/recovery acceptance')


if __name__ == '__main__':
    main(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
