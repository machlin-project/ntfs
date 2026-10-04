#!/usr/bin/env python3
"""Author restored metadata packets and exact protected-byte oracles."""
from pathlib import Path
import hashlib
import json
import struct
import sys

from logfile_fixtures import Layout

USA_STRIDE = 512
USA_WORD = struct.Struct('<H')
MAX_RECORD_BYTES = 64 * 1024
FIRST_SEQUENCE = 1
RESERVED_SEQUENCE = (1 << (USA_WORD.size * 8)) - 1
MST_FIELDS = (('magic', '4s'), ('usa_offset', 'H'), ('usa_count', 'H'))
MST = Layout(MST_FIELDS)
FILE = Layout((*MST_FIELDS, ('lsn', 'Q'), ('sequence', 'H'), ('links', 'H'),
    ('attrs_offset', 'H'), ('flags', 'H'), ('used', 'I'), ('allocated', 'I'),
    ('base_reference', 'Q'), ('next_instance', 'H'), ('reserved', 'H'),
    ('record_number', 'I')))
INDX = Layout((*MST_FIELDS, ('lsn', 'Q'), ('vcn', 'Q'), ('entries_offset', 'I'),
    ('used', 'I'), ('allocated', 'I'), ('flags', 'B'), ('reserved', '3s')))
RSTR = Layout((*MST_FIELDS, ('chkdsk_lsn', 'Q'), ('system_page_bytes', 'I'),
    ('log_page_bytes', 'I'), ('area_offset', 'H'), ('minor', 'H'), ('major', 'H')))
RCRD = Layout((*MST_FIELDS, ('copy_value', 'Q'), ('flags', 'I'), ('page_count', 'H'),
    ('page_position', 'H'), ('next_record_offset', 'H'), ('reserved', '6s'),
    ('last_end_lsn', 'Q')))
HEADERS = {'FILE': FILE, 'INDX': INDX, 'RSTR': RSTR, 'RCRD': RCRD}
SIZES = (USA_STRIDE, 2 * USA_STRIDE, 8 * USA_STRIDE, MAX_RECORD_BYTES)
SEQUENCES = (0, FIRST_SEQUENCE, RESERVED_SEQUENCE - 2,
             RESERVED_SEQUENCE - 1, RESERVED_SEQUENCE)
PATTERN_MULTIPLIER = 37
PATTERN_BIAS = 19
UNUSED_CAPACITY_BYTES = 17
BYTE_MASK = (1 << 8) - 1
SUCCESS = 0
CORRUPT = 2
UNSUPPORTED = 3
RANGE = 11


def restored(magic, size, sequence, offset=None):
    header = HEADERS[magic]
    offset = ((header.size + USA_WORD.size - 1) // USA_WORD.size * USA_WORD.size
              if offset is None else offset)
    data = bytearray((position * PATTERN_MULTIPLIER + PATTERN_BIAS) & BYTE_MASK
                     for position in range(size))
    count = size // USA_STRIDE + 1
    data[:header.size] = header.pack(dict(magic=magic.encode('ascii'),
        usa_offset=offset, usa_count=count))
    USA_WORD.pack_into(data, offset, sequence)
    return data, offset, count


def protected(data, offset, count, sequence):
    result = bytearray(data)
    following = (sequence + 1) & RESERVED_SEQUENCE
    if following in (0, RESERVED_SEQUENCE):
        following = FIRST_SEQUENCE
    USA_WORD.pack_into(result, offset, following)
    for ordinal in range(1, count):
        tail = ordinal * USA_STRIDE - USA_WORD.size
        result[offset + ordinal * USA_WORD.size:offset + (ordinal + 1) * USA_WORD.size] = (
            data[tail:tail + USA_WORD.size])
        USA_WORD.pack_into(result, tail, following)
    return result


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    cases = []

    def add(name, data, code, capacity=None, expected=None):
        capacity = len(data) if capacity is None else capacity
        original = bytes(data)
        (output / (name + '.input')).write_bytes(original)
        row = dict(name=name, bytes=len(original), capacity=capacity, code=code,
                   input_sha256=hashlib.sha256(original).hexdigest())
        if expected is not None:
            (output / (name + '.expected')).write_bytes(expected)
            row['expected_sha256'] = hashlib.sha256(expected).hexdigest()
        cases.append(row)

    for magic in HEADERS:
        for size in SIZES:
            for sequence in SEQUENCES:
                data, offset, count = restored(magic, size, sequence)
                add(f'{magic.lower()}-{size}-{sequence}', data, SUCCESS,
                    expected=protected(data, offset, count, sequence))
    data, offset, count = restored('FILE', USA_STRIDE, FIRST_SEQUENCE)
    add('capacity-extra', data, SUCCESS, capacity=len(data) + UNUSED_CAPACITY_BYTES,
        expected=protected(data, offset, count, FIRST_SEQUENCE))
    last_offset = USA_STRIDE - USA_WORD.size - count * USA_WORD.size
    last, _, _ = restored('FILE', USA_STRIDE, FIRST_SEQUENCE, last_offset)
    add('last-fitting-usa', last, SUCCESS,
        expected=protected(last, last_offset, count, FIRST_SEQUENCE))
    for length in range(MST.size + 1):
        add(f'short-prefix-{length}', data[:length], CORRUPT)
    add('short-stride', data[:-1], CORRUPT)
    add('incomplete-extra-stride', data + bytes([PATTERN_BIAS]), CORRUPT)
    add('capacity-zero', data, RANGE, capacity=0)
    add('capacity-one-below', data, RANGE, capacity=len(data) - 1)
    oversized, _, _ = restored('FILE', MAX_RECORD_BYTES + USA_STRIDE, FIRST_SEQUENCE)
    add('oversized-policy', oversized, RANGE)
    for name, field, value in (
            ('usa-in-header', 'usa_offset', MST.size - USA_WORD.size),
            ('usa-odd', 'usa_offset', offset + 1),
            ('usa-crosses-tail', 'usa_offset', last_offset + USA_WORD.size),
            ('usa-at-tail', 'usa_offset', USA_STRIDE - USA_WORD.size),
            ('usa-outside', 'usa_offset', RESERVED_SEQUENCE - 1),
            ('usa-count-zero', 'usa_count', 0),
            ('usa-count-one', 'usa_count', 1),
            ('usa-count-too-small', 'usa_count', count - 1),
            ('usa-count-too-large', 'usa_count', count + 1),
            ('usa-count-maximum', 'usa_count', RESERVED_SEQUENCE)):
        changed = bytearray(data)
        MST.put(changed, field, value)
        add(name, changed, CORRUPT)
    for magic in (b'CHKD', b'BAAD', b'????'):
        changed = bytearray(data)
        MST.put(changed, 'magic', magic)
        add('unsupported-' + magic.hex(), changed, UNSUPPORTED)
    (output / 'cases.tsv').write_text(''.join(
        f'{row["name"]} {row["code"]} {row["capacity"]}\n' for row in cases))
    (output / 'manifest.json').write_text(json.dumps(dict(
        scope='original protected-record byte vectors; no higher record or volume acceptance',
        cases=cases), indent=2) + '\n')
    return len(cases)


if __name__ == '__main__':
    output = Path(sys.argv[1])
    count = author(output)
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text('record protection fixtures\n')
    print(f'Authored {count} restored/protected record vectors')
