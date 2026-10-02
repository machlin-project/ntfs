#!/usr/bin/env python3
"""Verify diagnostic fields against independent original packet expectations."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from environment import tool_environment

VERDICTS = {'success': 0, 'corrupt': 2, 'unsupported': 3, 'range': 11}
DEADLINE_SECONDS = 10
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
ARGUMENT_ERROR = 2


def main(binary, directory):
    cases = json.loads((directory / 'manifest.json').read_text())['cases']
    assert len({case['path'] for case in cases}) == len(cases), 'Packet identities must be unique'
    hashes = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in directory.iterdir() if path.is_file()}
    count = 0
    for case in cases:
        if case['kind'] == 'client':
            continue  # The public client API has direct C coverage.
        command = [str(binary), case['kind'], str(directory / case['path'])]
        if case['kind'] == 'page':
            command.append(str(directory / case['config']))
        if case['kind'] in ('restart', 'page', 'record'):
            command.append(str(case['parameter']))
        run = subprocess.run(command, cwd=ROOT, env=tool_environment(), stdin=subprocess.DEVNULL,
                             capture_output=True, timeout=DEADLINE_SECONDS, check=False)
        assert len(run.stdout) <= MAX_OUTPUT_BYTES and len(run.stderr) <= MAX_OUTPUT_BYTES
        expected = VERDICTS[case['expected']]
        assert run.returncode == (0 if expected == 0 else 1), (case['path'], run.returncode, run.stderr)
        result = json.loads(run.stdout)
        assert result['schema_version'] == 1 and result['scope'] == case['kind']
        assert result['code'] == expected and result['recovery_qualified'] is False, case['path']
        metadata = {key: value for key, value in result.items() if key not in
                    ('schema_version', 'scope', 'code', 'result', 'recovery_qualified')}
        if expected == 0:
            assert metadata == case['fields'], (case['path'], metadata, case['fields'])
        else:
            def zero(value):
                if isinstance(value, dict):
                    return all(zero(item) for item in value.values())
                if isinstance(value, list):
                    return not value
                return value == 0
            assert zero(metadata), (case['path'], metadata)
        count += 1
    packet = str(directory / 'base.restart')
    for command in ([str(binary)], [str(binary), 'restart', packet, '-1'],
                    [str(binary), 'restart', packet, '0x100000'],
                    [str(binary), 'restart', packet, str((1 << 32) + 1)],
                    [str(binary), 'restart', str(directory), '1048576'],
                    [str(binary), 'page', str(directory / 'base.page'),
                     str(directory / 'cycle.restart'), '1048576']):
        run = subprocess.run(command, cwd=ROOT, env=tool_environment(), stdin=subprocess.DEVNULL,
                             capture_output=True, timeout=DEADLINE_SECONDS, check=False)
        assert run.returncode == ARGUMENT_ERROR and not run.stdout
        count += 1
    assert all(hashlib.sha256(path.read_bytes()).hexdigest() == expected for path, expected in hashes.items())
    print(f'PASS: {count} read-only log diagnostic field/argument contracts, original bytes unchanged; no recovery acceptance')


if __name__ == '__main__':
    main(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
