#!/usr/bin/env python3
"""Compare exact client-restart reports to independently authored field oracles."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from environment import tool_environment

TOOL_TIMEOUT_SECONDS = 10
MAX_REPORT_BYTES = 4096
ARGUMENT_STATUS = 2


def call(arguments):
    value = subprocess.run(arguments, cwd=ROOT, env=tool_environment(), stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=TOOL_TIMEOUT_SECONDS)
    assert len(value.stdout) <= MAX_REPORT_BYTES and len(value.stderr) <= MAX_REPORT_BYTES
    return value


def main():
    tool, fixtures = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    cases = json.loads((fixtures / 'cases.json').read_text())
    reports, transports = 0, 0
    for case in cases:
        path = fixtures / case['path']
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        value = call([str(tool), 'client-restart', str(path)])
        if case['transport']:
            assert value.returncode == ARGUMENT_STATUS and not value.stdout and value.stderr
            transports += 1
        else:
            assert value.returncode == (0 if case['code'] == 0 else 1) and not value.stderr
            assert json.loads(value.stdout) == case['expected'], case['path']
            reports += 1
        assert hashlib.sha256(path.read_bytes()).hexdigest() == before
    for arguments in ([], ['client-restart'], ['client-restart', str(fixtures / 'base-empty.payload'), '1'],
                      ['client-restart', str(fixtures / 'missing.payload')], ['unknown', str(fixtures)]):
        value = call([str(tool), *arguments])
        assert value.returncode == ARGUMENT_STATUS and not value.stdout and value.stderr
    print(f'PASS: {reports} exact client-restart reports, {transports} packet transport '
          'checks, argument errors and unchanged source hashes')


if __name__ == '__main__':
    main()
