#!/usr/bin/env python3
"""Compare every ordered page observation with independently authored metadata."""
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
ARGUMENT_ERROR = 2


def invoke(binary, *arguments):
    run = subprocess.run([str(binary), 'pages', *map(str, arguments)], cwd=ROOT,
        env=tool_environment(), stdin=subprocess.DEVNULL, capture_output=True,
        timeout=DEADLINE_SECONDS, check=False)
    assert len(run.stdout) <= MAX_OUTPUT_BYTES and len(run.stderr) <= MAX_OUTPUT_BYTES
    return run


def main(binary, directory):
    cases = json.loads((directory / 'manifest.json').read_text())['cases']
    hashes = {path: hashlib.sha256(path.read_bytes()).hexdigest()
              for path in directory.iterdir() if path.is_file()}
    observations = 0
    for case in cases:
        assert hashes[directory / case['path']] == case['source_sha256']
        run = invoke(binary, directory / case['path'])
        assert run.returncode == 0 and not run.stderr, (case['path'], run.stderr)
        result = json.loads(run.stdout)
        assert result['schema_version'] == 1 and result['scope'] == 'pages'
        assert result['history_qualified'] is False and result['recovery_qualified'] is False
        assert isinstance(result['result'], str)
        actual = {key: value for key, value in result.items() if key not in
                  ('schema_version', 'scope', 'history_qualified', 'recovery_qualified', 'result')}
        expected = dict(code=0, restart_current_lsn=case['restart_current_lsn'],
                        pages=case['rows'], inventory=case['inventory'])
        assert actual == expected, (case['path'], actual, expected)
        observations += len(result['pages'])
    for arguments in ((), (directory,), (directory / 'absent.journal',),
                      (directory / cases[0]['path'], 'extra')):
        run = invoke(binary, *arguments)
        assert run.returncode == ARGUMENT_ERROR and not run.stdout
    assert all(hashlib.sha256(path.read_bytes()).hexdigest() == expected
               for path, expected in hashes.items())
    print(f'PASS: {len(cases)} complete inventories/{observations} ordered pages, '
          'CLI transport refusals and unchanged inputs')


if __name__ == '__main__':
    main(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
