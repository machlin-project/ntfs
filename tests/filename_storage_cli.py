#!/usr/bin/env python3
"""Require complete selected names and unchanged independently authored streams."""
import hashlib
import json
from pathlib import Path
import sys

import fixtures as f
from filename_storage import FilenameStorage
from secure_store_fixtures import kind, resident_value

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from bounded_tool import run_tool

TOOL_SECONDS = 10
OUTPUT_BYTES = 1024 * 1024
LARGE_LONG_NAMES = 2000
HEX_NIBBLE_BITS = 4
HEX_UNIT_DIGITS = f.U16_BYTES * f.BYTE_BITS // HEX_NIBBLE_BITS


def require_stored_bodies(raw, objects):
    """Check authored body bytes separately from the C count observations."""
    snapshot = FilenameStorage(raw)
    actual = {int(obj['reference'], 16): [] for obj in objects}
    for number, (header, values) in snapshot.parts.items():
        owner = header['base'] or f.file_reference(number, header['sequence'])
        if owner in actual:
            actual[owner].extend(hashlib.sha256(resident_value(value)).hexdigest()
                                 for value in values if kind(value) == f.FILENAME)
    bodies = 0
    for obj in objects:
        found = sorted(actual[int(obj['reference'], 16)])
        assert found == obj['filename_body_hashes'], obj['reference']
        bodies += len(found)
    return bodies


def main():
    inspector, fixtures = Path(sys.argv[1]), Path(sys.argv[2])
    cases = json.loads((fixtures / 'filename-storage-cases.json').read_text())
    observations, streams, bodies, lookups = 0, 0, 0, 0
    for case in cases:
        image = fixtures / case['image']
        raw = image.read_bytes()
        before = hashlib.sha256(raw).hexdigest()
        assert before == case['sha256'], case['image']
        bodies += require_stored_bodies(raw, case['objects'])
        for obj in case['objects']:
            try:
                result = run_tool([inspector, image, 'links-ref', obj['reference']],
                                  timeout=TOOL_SECONDS, output_limit=OUTPUT_BYTES)
            except RuntimeError as error:
                assert obj['result'] != 'success', (case['image'], obj, str(error))
                assert str(error).strip() == 'Diagnostic exited 1: ' + obj['result']
            else:
                assert obj['result'] == 'success', (case['image'], obj)
                assert json.loads(result) == obj['counts'], (case['image'], obj, result)
            observations += 1
        for stream in case['streams']:
            result = run_tool([inspector, image, 'cat-ref', stream['reference']],
                              timeout=TOOL_SECONDS, output_limit=OUTPUT_BYTES)
            assert result == bytes.fromhex(stream['hex']), case['image']
            streams += 1
        for lookup in case['lookup_cases']:
            name = ''.join(f'{unit:0{HEX_UNIT_DIGITS}x}' for unit in lookup['name_units'])
            try:
                result = run_tool([inspector, image, 'lookup-ref', lookup['parent'], name],
                                  timeout=TOOL_SECONDS, output_limit=OUTPUT_BYTES)
            except RuntimeError as error:
                assert str(error).strip() == 'Diagnostic exited 1: ' + lookup['result'], case['image']
            else:
                raise AssertionError((case['image'], lookup, result))
            lookups += 1
        assert hashlib.sha256(image.read_bytes()).hexdigest() == before, case['image']
    large = next(case for case in cases if case['image'] == 'namespace-large.img')
    assert large['new_extension_records'] == LARGE_LONG_NAMES
    assert large['mft_record_slots'] > LARGE_LONG_NAMES
    print(f'PASS: {len(cases)} complete selected namespace images, {observations} filename inventories, '
          f'{bodies} exact filename bodies, {streams} original stream-byte oracles, '
          f'{lookups} retained lookup rejection; 2,000 long filenames use real MFT extensions')


if __name__ == '__main__':
    main()
