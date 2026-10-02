#!/usr/bin/env python3
"""Independently expected NTFS-backed journal reports; unchanged image files."""
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
SUCCESS = 0
NOT_NTFS = 1
REPORT_KEYS = ('scan_complete', 'selection', 'selected_probe', 'read_calls', 'read_bytes', 'probes')


def main(binary, directory):
    manifest = json.loads((directory / 'manifest.json').read_text())
    cases = manifest['cases']
    assert not manifest['skipped']
    assert len({case['path'] for case in cases}) == len(cases)
    hashes = {path: hashlib.sha256(path.read_bytes()).hexdigest()
              for path in directory.iterdir() if path.is_file()}
    for case in cases:
        run = subprocess.run([str(binary), 'volume-journal', str(directory / case['path'])],
            cwd=ROOT, env=tool_environment(), stdin=subprocess.DEVNULL, capture_output=True,
            timeout=DEADLINE_SECONDS, check=False)
        assert len(run.stdout) <= MAX_OUTPUT_BYTES and len(run.stderr) <= MAX_OUTPUT_BYTES
        assert run.returncode == (0 if case['code'] == SUCCESS else 1), (case['path'], run.stderr)
        result = json.loads(run.stdout)
        assert result['schema_version'] == 1 and result['scope'] == 'volume-journal'
        assert result['recovery_qualified'] is False and isinstance(result['result'], str)
        metadata = {key: value for key, value in result.items() if key not in
                    ('schema_version', 'scope', 'recovery_qualified', 'result')}
        source = case['source_expected']
        if source is None:
            expected = dict(code=case['code'], scan_complete=False, selection=0,
                            selected_probe=None, read_calls=0, read_bytes=0, probes=[],
                            selected_restart=None)
        else:
            expected = {key: source[key] for key in REPORT_KEYS}
            expected.update(code=case['code'], selected_restart=source['fields'])
        assert metadata == expected, (case['path'], metadata, expected)
    for path in (directory, directory / 'absent.img'):
        run = subprocess.run([str(binary), 'volume-journal', str(path)], cwd=ROOT,
            env=tool_environment(), stdin=subprocess.DEVNULL, capture_output=True,
            timeout=DEADLINE_SECONDS, check=False)
        assert run.returncode == ARGUMENT_ERROR and not run.stdout
    # A regular file can pass transport admission but fail the core mount.
    run = subprocess.run([str(binary), 'volume-journal', str(directory / 'manifest.json')],
        cwd=ROOT, env=tool_environment(), stdin=subprocess.DEVNULL, capture_output=True,
        timeout=DEADLINE_SECONDS, check=False)
    assert run.returncode == 1 and len(run.stdout) <= MAX_OUTPUT_BYTES
    rejected = json.loads(run.stdout)
    assert rejected['code'] == NOT_NTFS and rejected['scan_complete'] is False
    assert rejected['selected_probe'] is None and rejected['selected_restart'] is None
    assert rejected['read_calls'] == rejected['read_bytes'] == 0 and not rejected['probes']
    assert all(hashlib.sha256(path.read_bytes()).hexdigest() == expected
               for path, expected in hashes.items())
    print(f'PASS: {len(cases)} exact NTFS-backed log reports, mount rejection and two transport errors; original images unchanged')


if __name__ == '__main__':
    main(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
