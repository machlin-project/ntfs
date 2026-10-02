#!/usr/bin/env python3
"""Verify independent whole-source diagnostic reports without mounting media."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from environment import tool_environment

DEADLINE_SECONDS = 10
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
ARGUMENT_ERROR = 2


def main(binary, directory):
    cases = json.loads((directory / 'manifest.json').read_text())['cases']
    assert len({case['path'] for case in cases}) == len(cases)
    hashes = {path: hashlib.sha256(path.read_bytes()).hexdigest()
              for path in directory.iterdir() if path.is_file()}
    for case in cases:
        run = subprocess.run([str(binary), 'journal', str(directory / case['path'])],
            cwd=ROOT, env=tool_environment(), stdin=subprocess.DEVNULL, capture_output=True,
            timeout=DEADLINE_SECONDS, check=False)
        assert len(run.stdout) <= MAX_OUTPUT_BYTES and len(run.stderr) <= MAX_OUTPUT_BYTES
        assert run.returncode == (0 if case['code'] == 0 else 1), (case['path'], run.stderr)
        result = json.loads(run.stdout)
        assert result['schema_version'] == 1 and result['scope'] == 'journal'
        assert result['recovery_qualified'] is False and isinstance(result['result'], str)
        metadata = {key: value for key, value in result.items() if key not in
                    ('schema_version', 'scope', 'recovery_qualified', 'result')}
        expected = {key: case[key] for key in ('code', 'scan_complete', 'selection',
                    'selected_probe', 'read_calls', 'read_bytes', 'probes')}
        expected['selected_restart'] = case['fields']
        assert metadata == expected, (case['path'], metadata, expected)
    for path in (directory, directory / 'absent.journal'):
        run = subprocess.run([str(binary), 'journal', str(path)], cwd=ROOT,
            env=tool_environment(), stdin=subprocess.DEVNULL, capture_output=True,
            timeout=DEADLINE_SECONDS, check=False)
        assert run.returncode == ARGUMENT_ERROR and not run.stdout
    assert all(hashlib.sha256(path.read_bytes()).hexdigest() == expected
               for path, expected in hashes.items())
    print(f'PASS: {len(cases)} exact whole-source log reports and two transport errors; original bytes unchanged')


if __name__ == '__main__':
    main(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
