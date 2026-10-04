#!/usr/bin/env python3
"""Compare routed fast-copy reports and complete byte packets with authored oracles."""
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
LSN_MAXIMUM = (1 << 64) - 1


def invoke(binary, *arguments):
    run = subprocess.run([str(binary), 'fast-record', *map(str, arguments)],
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
        assert result['schema_version'] == 1 and result['scope'] == 'fast-record'
        assert result['recovery_qualified'] is False and isinstance(result['result'], str)
        expected = dict(code=case['code'], requested_lsn=case['lsn'], record=None,
                        assembly=None, bytes_hex=None)
        if case['code'] == 0:
            expected['record'] = case['record_fields']
            expected['assembly'] = dict(first_page_offset=case['first_page'],
                last_page_offset=case['last_page'], bytes=case['bytes'],
                pages_read=case['pages'], copy_pages_read=case['copies'], read_calls=case['reads'],
                read_bytes=case['reads'] * case['page_bytes'], wrapped=case['wrapped'])
            expected['bytes_hex'] = (directory / (case['path'] + '.record')).read_bytes().hex()
        actual = {key: value for key, value in result.items() if key not in
                  ('schema_version', 'scope', 'recovery_qualified', 'result')}
        assert actual == expected, (case['path'], actual, expected)
    for arguments in ((directory, 0), (directory / 'absent.journal', 0),
                      (directory / cases[0]['path'],),
                      *((directory / cases[0]['path'], value)
                        for value in ('-1', '+1', '1x', '', str(LSN_MAXIMUM + 1)))):
        run = invoke(binary, *arguments)
        assert run.returncode == ARGUMENT_ERROR and not run.stdout
    assert all(hashlib.sha256(path.read_bytes()).hexdigest() == expected
               for path, expected in hashes.items())
    print(f'PASS: {len(cases)} exact fast-copy reports/byte oracles and unchanged sources; '
          'no current-history/recovery acceptance')


if __name__ == '__main__':
    main(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
