#!/usr/bin/env python3
"""Check exact public flag-refusal diagnostics and successful clean controls."""
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
SUCCESS, UNSUPPORTED, DIRTY = 0, 3, 13
DIAGNOSTICS = {UNSUPPORTED: b'unsupported format',
               DIRTY: b'volume requires Windows recovery'}


def invoke(binary, image):
    result = subprocess.run([str(binary), str(image), 'info-json'], cwd=ROOT,
        env=tool_environment(), stdin=subprocess.DEVNULL, capture_output=True,
        timeout=DEADLINE_SECONDS, check=False)
    assert len(result.stdout) <= MAX_OUTPUT_BYTES and len(result.stderr) <= MAX_OUTPUT_BYTES
    return result


def main(binary, directory):
    manifest = json.loads((directory / 'manifest.json').read_text())
    cases = manifest['cases']
    assert len({case['path'] for case in cases}) == len(cases)
    for case in cases:
        image = directory / case['path']
        assert hashlib.sha256(image.read_bytes()).hexdigest() == case['sha256']
        result = invoke(binary, image)
        if case['code'] == SUCCESS:
            assert result.returncode == 0 and not result.stderr, case['path']
            info = json.loads(result.stdout)
            assert (info['major_version'], info['minor_version'], info['volume_flags']) == (
                case['major'], case['minor'], case['flags'])
        else:
            assert result.returncode == 1 and not result.stdout, case['path']
            assert result.stderr == DIAGNOSTICS[case['code']] + b'\n', (case['path'], result.stderr)
        assert hashlib.sha256(image.read_bytes()).hexdigest() == case['sha256']
    # The observation has no process-global state that survives a failed CLI invocation.
    assert invoke(binary, directory / 'clean-version-1.img').returncode == 0
    print(f'PASS: {len(cases)} exact public volume diagnostics/clean controls and unchanged images')


if __name__ == '__main__':
    main(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
