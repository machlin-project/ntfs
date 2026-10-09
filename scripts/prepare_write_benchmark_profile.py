#!/usr/bin/env python3
"""Author a fresh common synthetic quiet profile for old/new writer comparison.

No native input is accepted implicitly and no frozen artifact is replaced. The
historical literal admitted by the earlier implementation is placed below an
independently authored compatible anchor/epoch in this new synthetic image.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
import logfile_fixtures as wire
from write_mutation_cases import expanded_journal_image, HISTORY_JOURNAL_BYTES

COMMON_HISTORICAL_STATE = 0x01000000
SOURCE_BYTES_MAX = 256 * 1024 * 1024


def prepare(source, output):
    source = source.resolve(strict=True)
    if not source.is_file() or source.stat().st_size > SOURCE_BYTES_MAX:
        raise ValueError('Use a bounded regular synthetic writer fixture')
    original = source.read_bytes()
    before = hashlib.sha256(original).hexdigest()
    output.mkdir(parents=True, exist_ok=False)
    offset_bits = HISTORY_JOURNAL_BYTES.bit_length() - wire.OFFSET_SHIFT
    minimum_sequence = (COMMON_HISTORICAL_STATE >> offset_bits) + 1
    authored = expanded_journal_image(original, HISTORY_JOURNAL_BYTES,
        minimum_sequence=minimum_sequence, historical_state=COMMON_HISTORICAL_STATE)
    image = output / 'common-quiet.img'
    image.write_bytes(authored)
    image.chmod(0o444)
    if hashlib.sha256(source.read_bytes()).hexdigest() != before:
        raise ValueError('Original synthetic source changed during preparation')
    report = dict(schema_version=1, profile='common-synthetic-quiet-v1',
        provenance='Independently authored synthetic benchmark profile; no native qualification',
        source=str(source), source_sha256=before, image=image.name,
        image_sha256=hashlib.sha256(authored).hexdigest(),
        journal_bytes=HISTORY_JOURNAL_BYTES, historical_state=COMMON_HISTORICAL_STATE,
        minimum_sequence=minimum_sequence,
        source_unchanged=True, old_and_new_admission_pending=True)
    (output / 'profile.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True,
                        help='Original synthetic write-mutation history-source.img')
    parser.add_argument('--output', type=Path, required=True, help='New profile directory')
    args = parser.parse_args()
    print(json.dumps(prepare(args.source, args.output)))


if __name__ == '__main__':
    main()
