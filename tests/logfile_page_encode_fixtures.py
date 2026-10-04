#!/usr/bin/env python3
"""Independently author canonical private LFS 1.1 protected record pages."""
from pathlib import Path
import argparse
import hashlib
import json
import struct

import logfile_fixtures as w

WORD_MAX = (1 << (w.WORD_BYTES * w.BITS_PER_BYTE)) - 1
BYTE_MAX = (1 << w.BITS_PER_BYTE) - 1
INPUT_PADDING = 0x6d
PATTERN_MULTIPLIER = 13
PATTERN_ADDEND = 7
TRANSFER_PAGES = 4


def canonical(fields, data_offset, body, previous_sequence):
    # Append the named header, empty USA/padding and complete restored data.
    # Save tails from this constructed page, not from the input's old USA words.
    fields = dict(fields, reserved=bytes(struct.calcsize('<' + dict(w.PAGE.fields)['reserved'])))
    output = bytearray(w.PAGE.pack(fields))
    output.extend(bytes(data_offset - len(output)))
    output.extend(body)
    sequence = (previous_sequence + 1) & WORD_MAX
    if sequence in (0, WORD_MAX):
        sequence = 1
    struct.pack_into('<H', output, w.PAGE.size, sequence)
    for sector in range(1, fields['usa_count']):
        tail = sector * w.USA_STRIDE - w.WORD_BYTES
        saved = w.PAGE.size + sector * w.WORD_BYTES
        output[saved:saved + w.WORD_BYTES] = output[tail:tail + w.WORD_BYTES]
        struct.pack_into('<H', output, tail, sequence)
    return bytes(output)


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    cases = []

    def add(name, size, previous_sequence, *, count=1, position=1,
            flags=w.RECORD_END, next_kind='data'):
        usa_count = size // w.USA_STRIDE + 1
        data_offset = w.aligned(w.PAGE.size + usa_count * w.WORD_BYTES)
        next_offset = {'zero': 0, 'data': data_offset, 'end': size}[next_kind]
        assert next_offset <= WORD_MAX
        record_lsn = w.lsn_at((w.RESTART_PAGES + w.LEGACY_TAIL_PAGES) * size + data_offset,
                              file_bytes=w.LARGE_FILE_BYTES)
        fields = dict(magic=b'RCRD', usa_offset=w.PAGE.size, usa_count=usa_count,
                      copy_value=record_lsn, last_end_lsn=record_lsn, flags=flags,
                      page_count=count, page_position=position, next_record_offset=next_offset,
                      reserved=bytes([INPUT_PADDING]) *
                      struct.calcsize('<' + dict(w.PAGE.fields)['reserved']))
        body = bytes((index * PATTERN_MULTIPLIER + PATTERN_ADDEND) & BYTE_MAX
                     for index in range(size - data_offset))
        original = bytearray(w.PAGE.pack(fields))
        original.extend(bytes([INPUT_PADDING]) * (data_offset - len(original)))
        struct.pack_into('<H', original, w.PAGE.size, previous_sequence)
        original.extend(body)
        expected = canonical(fields, data_offset, body, previous_sequence)
        restart_offset = w.aligned(w.RESTART_HEADER.size + usa_count * w.WORD_BYTES)
        restart, _ = w.restart(system=size, log=size, file_bytes=w.LARGE_FILE_BYTES,
                               area_offset=restart_offset, page_data_offset=data_offset)
        restart, _ = w.protect(restart, w.RESTART_HEADER)
        packets = {'input': bytes(original), 'expected': expected, 'restart': bytes(restart)}
        for suffix, packet in packets.items():
            (output / (name + '.' + suffix)).write_bytes(packet)
        cases.append(dict(name=name, bytes=size, data_offset=data_offset,
                          prior_update_sequence=previous_sequence, fields=fields | {'reserved': None},
                          hashes={suffix: hashlib.sha256(packet).hexdigest()
                                  for suffix, packet in packets.items()}))

    for size in (w.USA_STRIDE, w.PAGE_BYTES, 4 * w.PAGE_BYTES, w.MAX_PAGE_BYTES):
        for previous_sequence in (0, 1, WORD_MAX - 2, WORD_MAX - 1, WORD_MAX):
            add(f'size-{size}-sequence-{previous_sequence}', size, previous_sequence)
    for count, position in ((0, 0), (1, 1), (TRANSFER_PAGES, 1),
                            (TRANSFER_PAGES, TRANSFER_PAGES)):
        for flags in (0, w.RECORD_END):
            for next_kind in ('zero', 'data', 'end'):
                add(f'transfer-{count}-{position}-flags-{flags}-next-{next_kind}',
                    w.PAGE_BYTES, w.USA_SEQUENCE, count=count, position=position,
                    flags=flags, next_kind=next_kind)
    # JSON metadata has no byte blobs; packet files retain all independent goldens.
    for case in cases:
        case['fields'].pop('magic')
    (output / 'manifest.json').write_text(json.dumps(cases, indent=2) + '\n')
    (output / 'cases.tsv').write_text(''.join(f"{case['name']} {case['data_offset']}\n"
                                            for case in cases))
    return cases


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('stamp', nargs='?', type=Path)
    args = parser.parse_args()
    cases = author(args.output)
    if args.stamp:
        args.stamp.write_text(f'authored {len(cases)} complete private LFS pages\n')
