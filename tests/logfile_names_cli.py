#!/usr/bin/env python3
"""Check name-entry/dump metadata against original packet goldens."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from environment import tool_environment

DEADLINE_SECONDS = 10
MAX_OUTPUT_BYTES = 4096
ARGUMENT_ERROR = 2
ENTRY = 1


def main(binary, directory):
    cases = json.loads((directory / 'manifest.json').read_text())['cases']
    for case in cases:
        path = directory / (case['name'] + '.input')
        command = 'attribute-name' if case['kind'] == ENTRY else 'attribute-names'
        run = subprocess.run([str(binary), command, str(path)], cwd=ROOT,
            env=tool_environment(), stdin=subprocess.DEVNULL, capture_output=True,
            timeout=DEADLINE_SECONDS, check=False)
        assert len(run.stdout) <= MAX_OUTPUT_BYTES and len(run.stderr) <= MAX_OUTPUT_BYTES
        assert run.returncode == (0 if case['code'] == 0 else 1), (case['name'], run.stderr)
        result = json.loads(run.stdout)
        assert result['schema_version'] == 1 and result['scope'] == command
        assert result['recovery_qualified'] is False and result['code'] == case['code'], (
            case['name'], result, case['code'])
        v = case['values']
        if case['kind'] == ENTRY:
            expected = dict(target_attribute=v[0], name_units=v[1], bytes=v[2],
                name=dict(offset=v[3], length=v[4]))
        else:
            expected = dict(entry_count=v[0], entries=dict(offset=v[1], length=v[2]))
        observed = {key: value for key, value in result.items() if key not in
            ('schema_version', 'scope', 'code', 'result', 'recovery_qualified')}
        assert observed == expected, (case['name'], observed, expected)
        assert hashlib.sha256(path.read_bytes()).hexdigest() == case['sha256']
    for command in ('attribute-name', 'attribute-names'):
        for path in (directory, directory / 'absent.input'):
            run = subprocess.run([str(binary), command, str(path)], cwd=ROOT,
                env=tool_environment(), stdin=subprocess.DEVNULL, capture_output=True,
                timeout=DEADLINE_SECONDS, check=False)
            assert run.returncode == ARGUMENT_ERROR and not run.stdout
    print(f'PASS: {len(cases)} exact attribute-name framing reports and unchanged packets')


if __name__ == '__main__':
    main(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
