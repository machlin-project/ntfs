#!/usr/bin/env python3
"""Compare complete checkpoint reports to original membership graph oracles."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from environment import sanitizer_environment

KINDS = 4
MAX_OUTPUT_BYTES = 4096
DEADLINE_SECONDS = 10
ARGUMENT_ERROR = 2
MAX_WORKSPACE_BYTES = 8 * 1024


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(binary, directory):
    manifest = json.loads((directory / 'manifest.json').read_text())
    for case in manifest['cases']:
        source = directory / case['source']
        checkpoint = directory / (case['name'] + '.checkpoint')
        dumps = [directory / f"{case['name']}.dump-{kind}" for kind in range(KINDS)]
        source_before = digest(source)
        paths = ['-' if dump.stat().st_size == 0 else str(dump) for dump in dumps]
        capacity = '-' if case['null_workspace'] else str(case['capacity'])
        command = [str(binary), 'checkpoint-snapshot', str(source), str(checkpoint), *paths, capacity]
        result = subprocess.run(command, cwd=ROOT, env=sanitizer_environment(),
            stdin=subprocess.DEVNULL, capture_output=True, timeout=DEADLINE_SECONDS)
        assert len(result.stdout) <= MAX_OUTPUT_BYTES and len(result.stderr) <= MAX_OUTPUT_BYTES
        assert result.returncode == (0 if case['code'] == 0 else 1), (case['name'], result.stderr)
        value = json.loads(result.stdout)
        assert value['schema_version'] == 1 and value['scope'] == 'checkpoint-snapshot'
        assert value['code'] == case['code'] and value['recovery_qualified'] is False, (case['name'], value)
        assert len(value['tables']) == KINDS
        values = [value['present_mask'], value['client_major'], value['client_minor'],
            value['checkpoint_lsn'], value['named_attributes'], value['dirty_pages']]
        for table in value['tables']:
            values.extend((table['kind'], table['table_lsn'], table['body']['offset'],
                table['body']['length'], table['table']['allocated_count'], table['names']['entry_count']))
        assert values == case['expected'], (case['name'], values, case['expected'])
        assert digest(source) == source_before and digest(checkpoint) == case['checkpoint_sha256']
        assert [digest(dump) for dump in dumps] == case['dump_sha256']
    malformed_commands = [command[:-1] + [bad]
        for bad in ('invalid', str(MAX_WORKSPACE_BYTES + 1), '-1', '')]
    malformed_commands.extend((command[:-1], command + ['extra-argument']))
    for malformed in malformed_commands:
        invalid = subprocess.run(malformed, cwd=ROOT, env=sanitizer_environment(),
            stdin=subprocess.DEVNULL, capture_output=True, timeout=DEADLINE_SECONDS)
        assert invalid.returncode == ARGUMENT_ERROR and not invalid.stdout
    print(f"PASS: {len(manifest['cases'])} exact complete checkpoint reports, transport bounds and immutable sources/packets")


if __name__ == '__main__':
    main(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
