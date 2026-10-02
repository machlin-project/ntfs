#!/usr/bin/env python3
"""Compare selected-client record diagnostics to original snapshot/packet oracles."""
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
        source, record = fixtures / case['source'], fixtures / case['path']
        before = [hashlib.sha256(path.read_bytes()).hexdigest() for path in (source, record)]
        value = call([str(tool), 'client-restart-record', str(source), str(record)])
        if case['transport']:
            assert value.returncode == ARGUMENT_STATUS and not value.stdout and value.stderr
            transports += 1
        else:
            assert value.returncode == (0 if case['code'] == 0 else 1) and not value.stderr
            assert json.loads(value.stdout) == case['expected'], case['path']
            reports += 1
        assert [hashlib.sha256(path.read_bytes()).hexdigest() for path in (source, record)] == before
    source, record = fixtures / 'base.journal', fixtures / 'payload-base-fields.record'
    for arguments in (['client-restart-record'], ['client-restart-record', str(source)],
                      ['client-restart-record', str(source), str(record), 'extra'],
                      ['client-restart-record', str(source), str(fixtures / 'missing.record')],
                      ['client-restart-record', str(fixtures / 'missing.journal'), str(record)]):
        value = call([str(tool), *arguments])
        assert value.returncode == ARGUMENT_STATUS and not value.stdout and value.stderr
    print(f'PASS: {reports} exact selected-client restart-record reports, {transports} transport '
          'checks, argument errors and unchanged source/packet hashes')


if __name__ == '__main__':
    main()
