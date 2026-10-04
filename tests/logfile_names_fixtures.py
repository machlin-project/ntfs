#!/usr/bin/env python3
"""Original byte-counted UTF-16 name packets; no parser offsets are imported."""
from pathlib import Path
import hashlib
import json
import struct
import sys
from logfile_fixtures import Layout, WORD_BYTES

SUCCESS, CORRUPT, END = 0, 2, 14
WHOLE, ENTRY = 0, 1
MAX_PACKET_BYTES = 1024 * 1024
MAX_NAME_BYTES = (1 << (WORD_BYTES * 8)) - WORD_BYTES
FIRST_TARGET = 24
SECOND_TARGET = 68
THIRD_TARGET = 112
INVALID_TERMINATOR = 0x1234
OPAQUE_FOLLOWING = b'following capacity'
HEADER = Layout((('target_attribute', 'H'), ('name_bytes', 'H')))
TERMINATOR = bytes(HEADER.size)


def entry(target, units):
    encoded = struct.pack(f'<{len(units)}H', *units)
    raw = bytes(HEADER.pack(dict(target_attribute=target, name_bytes=len(encoded))))
    raw += encoded + bytes(WORD_BYTES)
    expected = [target, len(units), len(raw), HEADER.size, len(encoded)]
    return raw, expected


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    cases = []
    names = set()

    def add(name, kind, data, code=SUCCESS, values=None):
        assert name not in names
        names.add(name)
        values = values or [0] * 5
        (output / (name + '.input')).write_bytes(data)
        (output / (name + '.expected')).write_text(' '.join(map(str, values)) + '\n')
        cases.append(dict(name=name, kind=kind, code=code, size=len(data), values=values,
            sha256=hashlib.sha256(data).hexdigest()))

    examples = [('empty-name', ()), ('ascii', tuple(map(ord, '$I30'))),
        ('unpaired', (0xd800, ord('x'), 0xdc00)), ('embedded-zero', (ord('x'), 0, ord('y'))),
        ('maximum', (0xffff,) * (MAX_NAME_BYTES // WORD_BYTES))]
    for name, units in examples:
        raw, fields = entry(FIRST_TARGET, units)
        add(name + '-entry', ENTRY, raw, values=fields)
        add(name + '-following', ENTRY, raw + OPAQUE_FOLLOWING, values=fields)
        add(name + '-dump', WHOLE, raw + TERMINATOR, values=[1, 0, len(raw), 0, 0])
    first, _ = entry(FIRST_TARGET, tuple(map(ord, '$I30')))
    second, _ = entry(SECOND_TARGET, tuple(map(ord, '$SDS')))
    third, _ = entry(THIRD_TARGET, tuple(map(ord, '$SDH')))
    packet = first + second + third + TERMINATOR
    add('three-unpadded-names', WHOLE, packet, values=[3, 0, len(packet) - len(TERMINATOR), 0, 0])
    add('empty-dump', WHOLE, TERMINATOR)
    add('entry-list-terminator', ENTRY, TERMINATOR, code=END)
    add('entry-terminator-following', ENTRY, TERMINATOR + OPAQUE_FOLLOWING, code=END)
    add('dump-trailing-bytes', WHOLE, packet + OPAQUE_FOLLOWING, code=CORRUPT)
    add('missing-list-terminator', WHOLE, first + second, code=CORRUPT)
    add('duplicate-target-framing', WHOLE, first + first + TERMINATOR,
        values=[2, 0, len(first) * 2, 0, 0])
    maximum_target, fields = entry((1 << (WORD_BYTES * 8)) - 1, (ord('x'),))
    add('maximum-target-entry', ENTRY, maximum_target, values=fields)
    empty, _ = entry(FIRST_TARGET, ())
    repeats = (MAX_PACKET_BYTES - len(TERMINATOR)) // len(empty)
    assert repeats * len(empty) + len(TERMINATOR) == MAX_PACKET_BYTES
    add('maximum-entry-count', WHOLE, empty * repeats + TERMINATOR,
        values=[repeats, 0, repeats * len(empty), 0, 0])
    for length in range(1, len(first)):
        add(f'truncated-entry-{length}', ENTRY, first[:length], code=CORRUPT)
    for length in range(1, len(packet)):
        add(f'truncated-dump-{length}', WHOLE, packet[:length], code=CORRUPT)
    for name, field, value in [('odd-byte-length', 'name_bytes', 1),
                               ('declared-too-long', 'name_bytes', MAX_NAME_BYTES),
                               ('zero-target-name', 'target_attribute', 0)]:
        malformed = bytearray(first)
        HEADER.put(malformed, field, value)
        add(name + '-entry', ENTRY, malformed, code=CORRUPT)
        add(name + '-dump', WHOLE, malformed + TERMINATOR, code=CORRUPT)
    malformed = bytearray(first)
    struct.pack_into('<H', malformed, len(first) - WORD_BYTES, INVALID_TERMINATOR)
    add('nonzero-string-terminator-entry', ENTRY, malformed, code=CORRUPT)
    add('nonzero-string-terminator-dump', WHOLE, malformed + TERMINATOR, code=CORRUPT)
    add('partial-list-terminator', WHOLE, first + TERMINATOR[:-1], code=CORRUPT)
    (output / 'manifest.json').write_text(json.dumps(dict(cases=cases), indent=2) + '\n')
    (output / 'cases.tsv').write_text('\n'.join(
        f"{c['name']} {c['kind']} {c['code']}" for c in cases) + '\n')
    return cases


if __name__ == '__main__':
    author(Path(sys.argv[1]))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text('original-byte-counted-attribute-names\n')
