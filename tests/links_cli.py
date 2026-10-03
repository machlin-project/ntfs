#!/usr/bin/env python3
"""Check every independent filename inventory through the bounded inspector."""
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from bounded_tool import run_tool

TOOL_SECONDS = 10
OUTPUT_BYTES = 4096


def main():
    reader, directory = Path(sys.argv[1]), Path(sys.argv[2])
    cases = json.loads((directory / 'link-count-cases.json').read_text())
    for case in cases:
        image = directory / case['image']
        original = hashlib.sha256(image.read_bytes()).digest()
        try:
            raw = run_tool([reader, image, 'links-ref', case['reference']],
                           timeout=TOOL_SECONDS, output_limit=OUTPUT_BYTES)
        except RuntimeError as error:
            assert case['result'] != 'success', (case, str(error))
            assert str(error).strip() == 'Diagnostic exited 1: ' + case['result'], (case, str(error))
        else:
            assert case['result'] == 'success', (case, raw)
            report = json.loads(raw)
            assert report == {key: case[key] for key in ('physical_names', 'primary_names', 'dos_aliases')}, (case, report)
        assert hashlib.sha256(image.read_bytes()).digest() == original, case
    print(f'PASS: {len(cases)} independently authored filename inventory verdicts and unchanged sources')


if __name__ == '__main__':
    main()
