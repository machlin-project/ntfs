#!/usr/bin/env python3
"""Compare active-client diagnostics against authored chain/sequence queries."""
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
CORRUPT = 2
WORD_MAXIMUM = (1 << 16) - 1


def invoke(binary, *arguments):
    run = subprocess.run([str(binary), 'active-client', *map(str, arguments)], cwd=ROOT,
        env=tool_environment(), stdin=subprocess.DEVNULL, capture_output=True,
        timeout=DEADLINE_SECONDS, check=False)
    assert len(run.stdout) <= MAX_OUTPUT_BYTES and len(run.stderr) <= MAX_OUTPUT_BYTES
    return run


def main(binary, directory):
    cases = json.loads((directory / 'manifest.json').read_text())['cases']
    hashes = {path: hashlib.sha256(path.read_bytes()).hexdigest()
              for path in directory.iterdir() if path.is_file()}
    count = 0
    for case in cases:
        for query in case['cli_queries']:
            run = invoke(binary, directory / case['path'], query['index'], query['sequence'])
            assert run.returncode == (0 if query['code'] == 0 else 1), (case['path'], run.stderr)
            result = json.loads(run.stdout)
            assert result['schema_version'] == 1 and result['scope'] == 'active-client'
            assert result['recovery_qualified'] is False and isinstance(result['result'], str)
            metadata = {key: value for key, value in result.items() if key not in
                        ('schema_version', 'scope', 'recovery_qualified', 'result')}
            expected = dict(code=query['code'], index=query['index'], sequence=query['sequence'],
                            client=query['fields'] if query['code'] == 0 else None)
            assert metadata == expected, (case['path'], query, metadata, expected)
            count += 1
    run = invoke(binary, directory / 'manifest.json', 0, 0)
    assert run.returncode == 1
    result = json.loads(run.stdout)
    assert result['code'] == CORRUPT and result['client'] is None
    valid = directory / cases[0]['path']
    for arguments in ((directory, 0, 0), (directory / 'absent.journal', 0, 0),
                      (valid, 0), (valid, '-1', 0), (valid, 0, '-1'),
                      (valid, WORD_MAXIMUM + 1, 0), (valid, 0, WORD_MAXIMUM + 1),
                      (valid, '1x', 0), (valid, 0, '')):
        run = invoke(binary, *arguments)
        assert run.returncode == ARGUMENT_ERROR and not run.stdout
    assert all(hashlib.sha256(path.read_bytes()).hexdigest() == expected
               for path, expected in hashes.items())
    print(f'PASS: {count} exact active-client reports across {len(cases)} snapshots, '
          'discovery/argument/transport errors and unchanged sources; no current-history/recovery acceptance')


if __name__ == '__main__':
    main(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
