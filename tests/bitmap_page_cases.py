#!/usr/bin/env python3
"""Exercise complete plans with large virtual bitmaps and a live-memory ceiling."""
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from environment import sanitizer_environment

MIB = 1024 * 1024


def main():
    binary, fixtures = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    rows = []
    for profile in ('early', 'late', 'boundary', 'mft-paged', 'mft-grow'):
        for operation in ('create', 'grow', 'shrink', 'unlink', 'grow-write'):
            ceiling = (8 if operation == 'grow-write' else 2) * MIB
            run = subprocess.run([str(binary), operation, '1', str(fixtures / (profile + '.img')),
                                  str(ceiling)], check=True, capture_output=True, text=True,
                                 env=sanitizer_environment())
            row = json.loads(run.stdout)
            assert row['peak_live_bytes'] <= ceiling
            rows.append(dict(profile=profile, **row))
    print(json.dumps(rows, indent=2))


if __name__ == '__main__':
    main()
