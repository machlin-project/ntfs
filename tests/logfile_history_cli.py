#!/usr/bin/env python3
"""Compare selected window diagnostics with original exact packet declarations."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from environment import tool_environment

DEADLINE_SECONDS = 10
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
LSN_MAXIMUM = (1 << 64) - 1


def invoke(binary, *arguments):
    run = subprocess.run([str(binary), 'records', *map(str, arguments)], cwd=ROOT,
        env=tool_environment(), stdin=subprocess.DEVNULL, capture_output=True,
        timeout=DEADLINE_SECONDS, check=False)
    assert len(run.stdout) <= MAX_OUTPUT_BYTES and len(run.stderr) <= MAX_OUTPUT_BYTES
    return run


def main(binary, directory):
    cases = json.loads((directory / 'manifest.json').read_text())['cases']
    hashes = {path: hashlib.sha256(path.read_bytes()).hexdigest()
              for path in directory.rglob('*') if path.is_file()}
    packets = 0
    for case in cases:
        assert hashes[directory / case['path']] == case['source_sha256']
        run = invoke(binary, directory / case['path'], case['first_lsn'])
        assert not run.stderr and run.returncode == (0 if case['code'] == 0 else 1), (case['path'], run.stderr)
        result = json.loads(run.stdout)
        assert result['schema_version'] == 1 and result['scope'] == 'records'
        assert result['requested_lsn'] == case['first_lsn'] and result['code'] == case['code'], (case['path'], result)
        assert result['history_qualified'] is False and result['recovery_qualified'] is False
        expected = []
        for record in case['records']:
            packet = (directory / record['packet_path']).read_bytes()
            assert hashlib.sha256(packet).hexdigest() == record['packet_sha256']
            expected.append(dict(record=record['record'], assembly=record['assembly'], bytes_hex=packet.hex()))
        assert result['records'] == expected, (case['path'], result['records'], expected)
        history = result['history']
        # Rejected windows retain useful partial evidence, without making the
        # unverified candidate/header tags into an accepted history boundary.
        fields = case['history'] if case['code'] == 0 else {key: case['history'][key] for key in (
            'record_bytes', 'read_calls', 'read_bytes', 'examined_records', 'visited_records',
            'copy_pages_read', 'endpoint_verified', 'tail_verified', 'complete', 'wrapped')}
        assert {key: history[key] for key in fields} == fields, (case['path'], history, fields)
        assert result['preparation']['published'] is True
        assert result['preparation']['required_bytes'] == result['preparation']['retained_bytes']
        packets += len(expected)
    first = directory / cases[0]['path']
    for arguments in ((), (first,), (first, '1', 'extra'), (directory, '1'),
        (directory / 'missing.journal', '1'),
        *((first, value) for value in ('-1', '+1', '', '1x', str(LSN_MAXIMUM + 1)))):
        run = invoke(binary, *arguments)
        assert run.returncode == 2 and not run.stdout
    assert all(hashlib.sha256(path.read_bytes()).hexdigest() == digest for path, digest in hashes.items())
    print(f'PASS: {len(cases)} selected-window results/{packets} exact packets, immutable inputs; '
          'native history/recovery acceptance remains separate')


if __name__ == '__main__':
    main(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
