#!/usr/bin/env python3
"""Author independent allocation-bitmap states and exact native update payloads."""
from pathlib import Path
from itertools import groupby
import json
import struct
import sys

import logfile_fixtures as w

CLUSTER_BYTES = 4096
BITS_PER_BYTE = 8
BITMAP_BITS = CLUSTER_BYTES * BITS_PER_BYTE
MAX_RANGES = 4096
SET_BITS, CLEAR_BITS = 0x15, 0x16
DATA, BITMAP = 0x80, 0xb0
VOLUME_BITMAP_REFERENCE = (1 << 48) | 6
MFT_REFERENCE = 1 << 48
DIRECTORY_REFERENCE = (3 << 48) | 79
VOLUME_BITMAP_KEY, MFT_BITMAP_KEY, DIRECTORY_BITMAP_KEY = 24, 104, 144
PHYSICAL_CLUSTER = 786431
LARGE_VCN = (1 << 35) + 19
BIT_RANGE = struct.Struct('<II')
SUCCESS, RANGE = 'success', 'range'


def bitmap(value=0, changes=()):
    output = bytearray([value] * CLUSTER_BYTES)
    for first, count, set_bits in changes:
        assert 0 <= first < BITMAP_BITS and 0 < count <= BITMAP_BITS - first
        for bit in range(first, first + count):
            mask = 1 << (bit % BITS_PER_BYTE)
            if set_bits:
                output[bit // BITS_PER_BYTE] |= mask
            else:
                output[bit // BITS_PER_BYTE] &= ~mask
    return bytes(output)


def payload(first, count, set_bits, key, vcn, lcn):
    region = BIT_RANGE.pack(first, count)
    prefix = w.UPDATE.size + w.LSN_BYTES
    fields = dict(redo_operation=SET_BITS if set_bits else CLEAR_BITS,
                  undo_operation=CLEAR_BITS if set_bits else SET_BITS,
                  redo_offset=prefix, redo_bytes=len(region),
                  undo_offset=prefix + len(region), undo_bytes=len(region),
                  target_attribute=key, lcns=1, target_vcn=vcn)
    return bytes(w.UPDATE.pack(fields)) + struct.pack('<Q', lcn) + region + region


def ranges(before, after):
    changes = []
    for bit in range(BITMAP_BITS):
        mask = 1 << (bit % BITS_PER_BYTE)
        old = bool(before[bit // BITS_PER_BYTE] & mask)
        new = bool(after[bit // BITS_PER_BYTE] & mask)
        changes.append(None if old == new else new)
    position = 0
    for state, members in groupby(changes):
        count = len(list(members))
        if state is not None:
            yield position, count, state
        position += count


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    cases = []

    def add(name, before, after, *, key=VOLUME_BITMAP_KEY, reference=VOLUME_BITMAP_REFERENCE,
            attribute=DATA, vcn=0, name_units=()):
        directory = output / name
        directory.mkdir(exist_ok=True)
        intervals = list(ranges(before, after))
        result = SUCCESS if len(intervals) <= MAX_RANGES else RANGE
        goldens = b''.join(payload(first, count, state, key, vcn, PHYSICAL_CLUSTER)
                           for first, count, state in intervals) if result == SUCCESS else b''
        (directory / 'before.bin').write_bytes(before)
        (directory / 'after.bin').write_bytes(after)
        (directory / 'payloads.bin').write_bytes(goldens)
        names = list(name_units) + [0] * (4 - len(name_units))
        (directory / 'expected.txt').write_text(' '.join(map(str, (
            result, len(intervals) if result == SUCCESS else 0, key, reference,
            PHYSICAL_CLUSTER * CLUSTER_BYTES, vcn * CLUSTER_BYTES, attribute,
            len(name_units), *names))) + '\n')
        cases.append(dict(name=name, result=result, ranges=len(intervals),
                          logicalVCN=vcn, attributeType=attribute))

    zero, one = bitmap(), bitmap(0xff)
    add('unchanged-zero', zero, zero)
    add('unchanged-one', one, one)
    add('set-first', zero, bitmap(changes=[(0, 1, True)]))
    add('clear-first', one, bitmap(0xff, [(0, 1, False)]))
    add('set-last', zero, bitmap(changes=[(BITMAP_BITS - 1, 1, True)]))
    add('clear-last', one, bitmap(0xff, [(BITMAP_BITS - 1, 1, False)]))
    add('set-complete-cluster', zero, one)
    add('clear-complete-cluster', one, zero)
    add('byte-crossing', zero, bitmap(changes=[(6, 19, True)]))
    add('sector-crossing', one, bitmap(0xff, [(512 * BITS_PER_BYTE - 7, 21, False)]))
    add('separated-ranges', zero, bitmap(changes=[(44, 1, True), (61, 1, True), (4099, 71, True)]))
    mixed = bitmap(changes=[(1, 9, True), (41, 73, True), (BITMAP_BITS - 51, 51, True)])
    after = bitmap(changes=[(0, 4, True), (51, 87, True), (BITMAP_BITS - 81, 29, True)])
    add('mixed-allocation-retirement', mixed, after)
    add('MFT-record-bitmap', zero, bitmap(changes=[(44, 1, True)]), key=MFT_BITMAP_KEY,
        reference=MFT_REFERENCE, attribute=BITMAP)
    add('directory-index-bitmap', one, bitmap(0xff, [(19, 11, False)]),
        key=DIRECTORY_BITMAP_KEY, reference=DIRECTORY_REFERENCE, attribute=BITMAP,
        name_units=tuple(map(ord, '$I30')))
    add('nonzero-VCN', mixed, after, vcn=19)
    add('wide-VCN', one, bitmap(0xff, [(61, 1, False)]), vcn=LARGE_VCN)
    add('maximum-ranges', zero, bytes([0x0f] * CLUSTER_BYTES))
    add('too-many-ranges', zero, bytes([0x55] * CLUSTER_BYTES))
    for pattern in (0x33, 0x55, 0xa5, 0x96):
        add(f'unchanged-pattern-{pattern:02x}', bitmap(pattern), bitmap(pattern))
    (output / 'cases.rows').write_text('\n'.join(case['name'] for case in cases) + '\n')
    (output / 'manifest.json').write_text(json.dumps(dict(
        cases=cases, originalWireAuthor=True, nativeExecutionQualified=False), indent=2) + '\n')


if __name__ == '__main__':
    author(Path(sys.argv[1]))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text('independent native bitmap range goldens\n')
