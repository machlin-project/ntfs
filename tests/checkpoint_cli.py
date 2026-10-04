#!/usr/bin/env python3
"""Compare composed snapshot binding reports with independent numeric oracles."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from environment import tool_environment

KINDS = ('open-attributes', 'attribute-names', 'dirty-pages', 'transactions')
NAME_KIND = 1
MAX_OUTPUT_BYTES = 4096
DEADLINE_SECONDS = 10
ARGUMENT_ERROR = 2


def main(binary, directory):
    manifest = json.loads((directory / 'manifest.json').read_text())
    for case in manifest['cases']:
        checkpoint = directory / (case['name'] + '.checkpoint')
        table = directory / (case['name'] + '.table')
        table_argument = '-' if case['table_bytes'] == 0 else str(table)
        kind = KINDS[case['kind']] if case['kind'] < len(KINDS) else 'invalid-kind'
        result = subprocess.run([str(binary), 'checkpoint-table',
            str(directory / case['source']), str(checkpoint), kind, table_argument],
            cwd=ROOT, env=tool_environment(), stdin=subprocess.DEVNULL,
            capture_output=True, timeout=DEADLINE_SECONDS)
        assert len(result.stdout) <= MAX_OUTPUT_BYTES and len(result.stderr) <= MAX_OUTPUT_BYTES
        if case['transport']:
            assert result.returncode == ARGUMENT_ERROR and not result.stdout, case['name']
        else:
            assert result.returncode == (0 if case['code'] == 0 else 1), (case['name'], result.stderr)
            decoded = json.loads(result.stdout)
            assert decoded['schema_version'] == 1 and decoded['scope'] == 'checkpoint-table'
            assert decoded['code'] == case['code'] and decoded['recovery_qualified'] is False
            assert decoded['requested_kind'] == kind
            entries = decoded['names']['entries'] if decoded['kind'] == NAME_KIND else decoded['table']['entries']
            table_fields = decoded['table']
            values = [decoded['kind'], decoded['client_major'], decoded['client_minor'],
                decoded['checkpoint_lsn'], decoded['table_lsn'], decoded['body']['offset'],
                decoded['body']['length'], table_fields['entry_bytes'], table_fields['entry_count'],
                table_fields['allocated_count'], table_fields['free_goal'], table_fields['first_free'],
                table_fields['last_free'], entries['offset'], entries['length'], decoded['names']['entry_count']]
            assert values == case['expected'], (case['name'], values, case['expected'])
        assert hashlib.sha256(checkpoint.read_bytes()).hexdigest() == case['checkpoint_sha256']
        assert hashlib.sha256(table.read_bytes()).hexdigest() == case['table_sha256']
    base = manifest['cases'][0]
    for wrong in ('invalid-kind', '', 'open_attributes'):
        result = subprocess.run([str(binary), 'checkpoint-table', str(directory / base['source']),
            str(directory / (base['name'] + '.checkpoint')), wrong,
            str(directory / (base['name'] + '.table'))], cwd=ROOT, env=tool_environment(),
            stdin=subprocess.DEVNULL, capture_output=True, timeout=DEADLINE_SECONDS)
        assert result.returncode == ARGUMENT_ERROR and not result.stdout
    print(f"PASS: {len(manifest['cases'])} exact composed checkpoint reports and immutable packets")


if __name__ == '__main__':
    main(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
