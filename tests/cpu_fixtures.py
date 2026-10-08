#!/usr/bin/env python3
"""Author CPU-workload packets from explicit tokens and independent byte patterns."""
from pathlib import Path
import json
import struct
import sys

import lzx_fixtures as lzx
import wof_fixtures as xpress

LZNT_UNIT = 4096
LZNT_SIGNATURE = 0x3000
LZNT_PACKED = 0x8000
LZNT_MIN_MATCH = 3
LZNT_LENGTH_BITS = 12
LZNT_SHIFT_THRESHOLD = 16
FLAG_BITS = 8
WORD = struct.Struct('<H')


def lznt_period(period, size):
    original = (period * ((size + len(period) - 1) // len(period)))[:size]
    tokens = [(False, bytes([value])) for value in original[:len(period)]]
    position = len(period)
    while position < size:
        shift = LZNT_LENGTH_BITS
        previous = position - 1
        while previous >= LZNT_SHIFT_THRESHOLD:
            shift -= 1
            previous >>= 1
        length = min(size - position, (1 << shift) - 1 + LZNT_MIN_MATCH)
        if length < LZNT_MIN_MATCH:
            tokens.append((False, original[position:position + 1]))
            position += 1
        else:
            token = ((len(period) - 1) << shift) | (length - LZNT_MIN_MATCH)
            tokens.append((True, WORD.pack(token)))
            position += length
    payload = bytearray()
    for index in range(0, len(tokens), FLAG_BITS):
        group = tokens[index:index + FLAG_BITS]
        payload.append(sum(int(match) << bit for bit, (match, _) in enumerate(group)))
        payload.extend(b''.join(value for _, value in group))
    assert 0 < len(payload) <= LZNT_UNIT
    return WORD.pack(LZNT_SIGNATURE | LZNT_PACKED | (len(payload) - 1)) + payload, original


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    profiles = []

    def add(codec, name, packed, original, measure=False):
        stem = f'{codec}-{name}'
        (output / f'{stem}.packed').write_bytes(packed)
        (output / f'{stem}.data').write_bytes(original)
        profiles.append(dict(codec=codec, name=stem, bytes=len(original), measure=measure))

    for distance in (1, 2, 3, 7, 8, 15, 16, 17, 31, 32, 63):
        period = bytes(65 + index % 26 for index in range(distance))
        for size in (distance + 3, 127, LZNT_UNIT):
            packed, original = lznt_period(period, size)
            add('lznt1', f'period-{distance}-{size}', packed, original,
                size == LZNT_UNIT and distance in (1, 3, 16, 31))
    original = bytes(range(256)) * (LZNT_UNIT // 256)
    add('lznt1', 'raw', WORD.pack(LZNT_SIGNATURE | (len(original) - 1)) + original,
        original, True)
    original = b'abcdefgh' * 384
    payload = b''.join(b'\0' + original[index:index + FLAG_BITS]
                       for index in range(0, len(original), FLAG_BITS))
    add('lznt1', 'literals', WORD.pack(LZNT_SIGNATURE | LZNT_PACKED | (len(payload) - 1))
        + payload, original, True)

    uniform = {symbol: (symbol, xpress.UNIFORM_CODE_BITS) for symbol in range(xpress.SYMBOLS)}
    for distance in (1, 3, 7, 16, 31):
        period = bytes(65 + index % 26 for index in range(distance))
        size = xpress.UNIT_4K
        original = (period * ((size + distance - 1) // distance))[:size]
        packed = xpress.encode(uniform, [*map(xpress.literal, period),
                                        xpress.match(distance, size - distance)])
        add('xpress', f'period-{distance}', packed, original, True)
    original = b'AB' * (xpress.UNIT_4K // 2)
    add('xpress', 'literals', xpress.encode(uniform, map(xpress.literal, original)), original, True)

    original = b'A' * lzx.UNIT_BYTES
    add('lzx', 'period-1', lzx.encode_uniform(original), original, True)
    for gap in (0, 37, 256):
        encoded = bytearray(b'\x90' * lzx.UNIT_BYTES)
        original = bytearray(encoded)
        if gap:
            for position in range(0, len(encoded) - lzx.E8_TAIL_BYTES, gap):
                encoded[position] = lzx.E8_OPCODE
                encoded[position + 1:position + lzx.CALL_BYTES] = lzx.CALL.pack(position)
                original[position] = lzx.E8_OPCODE
                original[position + 1:position + lzx.CALL_BYTES] = lzx.CALL.pack(0)
        packet = lzx.Packet()
        packet.raw(encoded, default=True)
        add('lzx', f'raw-calls-{gap}', packet.finish(), bytes(original), True)
    original = b'ABCD' * (lzx.UNIT_BYTES // 4)
    packet = lzx.Packet()
    packet.compressed(len(original), map(lzx.literal, original), default=True)
    add('lzx', 'literals', packet.finish(), original, True)

    (output / 'profiles.json').write_text(json.dumps(profiles, indent=2) + '\n')
    (output / 'cases.txt').write_text(''.join(f"{p['codec']} {p['name']}\n" for p in profiles))
    return profiles


if __name__ == '__main__':
    author(Path(sys.argv[1]))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text('Independent CPU codec packets authored\n')
