#!/usr/bin/env python3
"""Check complete independently owned names and resident stream bytes."""
import hashlib
import json
from pathlib import Path
import sys

from filename_storage_cli import require_stored_bodies

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from bounded_tool import run_tool

TOOL_SECONDS = 10
OUTPUT_BYTES = 1024 * 1024


def main():
    inspector, directory = Path(sys.argv[1]), Path(sys.argv[2])
    cases = json.loads((directory / 'metadata-objects-cases.json').read_text())
    names, streams, bodies = 0, 0, 0
    for case in cases:
        image = directory / case['image']
        raw = image.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == case['sha256']
        bodies += require_stored_bodies(raw, case['objects'])
        for obj in case['objects']:
            result = run_tool([inspector, image, 'links-ref', obj['reference']],
                              timeout=TOOL_SECONDS, output_limit=OUTPUT_BYTES)
            assert json.loads(result) == obj['counts'], (case['image'], obj)
            names += 1
        for stream in case['streams']:
            result = run_tool([inspector, image, 'cat-ref', stream['reference']],
                              timeout=TOOL_SECONDS, output_limit=OUTPUT_BYTES)
            assert result == bytes.fromhex(stream['hex']), (case['image'], stream['reference'])
            streams += 1
        assert hashlib.sha256(image.read_bytes()).hexdigest() == case['sha256']
    print(f'PASS: {len(cases)} independent-object images, {names} checked inventories, '
          f'{bodies} exact filename bodies and {streams} exact resident streams')


if __name__ == '__main__':
    main()
