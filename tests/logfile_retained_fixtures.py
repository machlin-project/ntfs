#!/usr/bin/env python3
"""Author completed legacy restart pages and exact retained modern duplicates."""
from pathlib import Path
import hashlib
import json
import sys
import logfile_fixtures as w
import logfile_inventory_fixtures as physical
from logfile_source_fixtures import restart

OK, CORRUPT, UNSUPPORTED, NOT_FOUND = 0, 2, 3, 6
SOURCE_BYTES = 256 * 1024
PAGE_BYTES = 4096
DATA_OFFSET = physical.FAST.size
LEGACY_CIRCULAR = (w.RESTART_PAGES + w.LEGACY_TAIL_PAGES) * PAGE_BYTES
HOME = (w.RESTART_PAGES + w.FAST_PAGES) * PAGE_BYTES
RESTART_PAGE = 2
NATIVE_ALIAS = 18 * PAGE_BYTES
UNUSED_BYTE, DIFFERENT_UNUSED_BYTE = 0x39, 0x71
BODY_LENGTHS = (13, 27)
PAIR_READS = 2


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    cases = []
    packets = []
    cursor = DATA_OFFSET
    for length in BODY_LENGTHS:
        lsn = w.lsn_at(HOME + cursor, SOURCE_BYTES)
        body = bytes(index * 17 % 251 for index in range(length))
        packet = bytes(w.RECORD.pack(dict(lsn=lsn, previous_lsn=0, undo_next_lsn=0,
            data_bytes=length, client_sequence=w.CLIENT_SEQUENCE, client_index=0,
            type=w.UPDATE_TYPE, transaction=w.TRANSACTION))) + body
        packets.append((cursor, lsn, packet))
        cursor = w.aligned(cursor + len(packet))
    first, end = packets[0][1], packets[-1][1]
    restart_raw, _ = restart(system=PAGE_BYTES, log=PAGE_BYTES,
        file_bytes=SOURCE_BYTES, current=end, page_data_offset=DATA_OFFSET)
    fields = dict(magic=b'RCRD', usa_offset=w.PAGE.size, copy_value=end,
        last_end_lsn=end, flags=w.RECORD_END | RESTART_PAGE,
        page_count=1, page_position=1, next_record_offset=cursor)
    common = bytearray([UNUSED_BYTE]) * PAGE_BYTES
    common[:w.PAGE.size] = w.PAGE.pack(fields)
    for offset, _, packet in packets:
        common[offset:offset + len(packet)] = packet
    physical.FAST.put(common, 'file_offset', 0)

    def add(name, address=NATIVE_ALIAS, *, code=OK, qualified=True,
            mutate=None, tails=False, home=True, faults=False):
        source = bytearray(SOURCE_BYTES)
        for ordinal in range(w.RESTART_PAGES):
            source[ordinal * PAGE_BYTES:(ordinal + 1) * PAGE_BYTES] = restart_raw
        pages = {HOME: bytearray(common)} if home else {}
        retained = bytearray(common)
        physical.FAST.put(retained, 'file_offset', HOME)
        if mutate:
            mutate(retained)
        pages[address] = retained
        if tails:
            for slot in range(w.LEGACY_TAIL_PAGES):
                tail = bytearray(common)
                w.PAGE.put(tail, 'copy_value', HOME)
                pages[(w.RESTART_PAGES + slot) * PAGE_BYTES] = tail
        for offset, restored in pages.items():
            raw, _ = w.protect(restored, w.PAGE)
            source[offset:offset + PAGE_BYTES] = raw
        path = name + '.journal'
        (output / path).write_bytes(source)
        emitted = []
        if code == OK:
            for ordinal, (_, lsn, packet) in enumerate(packets):
                packet_path = path + f'.packet-{ordinal}'
                (output / packet_path).write_bytes(packet)
                emitted.append(dict(lsn=lsn, path=packet_path,
                    sha256=hashlib.sha256(packet).hexdigest()))
        cases.append(dict(path=path, code=code, qualified=qualified, first_lsn=first,
            alias=address, home=HOME, packets=emitted, faults=faults,
            maximum_reads=(SOURCE_BYTES // PAGE_BYTES - w.RESTART_PAGES +
                PAIR_READS * w.LEGACY_TAIL_PAGES + (PAIR_READS if qualified else 0)),
            sha256=hashlib.sha256(source).hexdigest()))

    add('native-shape-with-tails', tails=True, faults=True)
    for ordinal in range(w.FAST_PAGES - w.LEGACY_TAIL_PAGES):
        add(f'former-fast-slot-{ordinal}', LEGACY_CIRCULAR + ordinal * PAGE_BYTES)
    add('different-unused-tail', mutate=lambda page:
        page.__setitem__(slice(cursor, PAGE_BYTES), bytes([DIFFERENT_UNUSED_BYTE]) *
                         (PAGE_BYTES - cursor)))
    add('written-prefix-conflict', code=UNSUPPORTED, qualified=False,
        mutate=lambda page: page.__setitem__(DATA_OFFSET + w.RECORD.size, 0xee))
    add('missing-home', home=False, code=NOT_FOUND, qualified=False)
    for name, field, value in (
        ('zero-target', 'file_offset', 0), ('unaligned-target', 'file_offset', HOME + 1),
        ('other-target', 'file_offset', HOME + PAGE_BYTES),
        ('legacy-target', 'file_offset', LEGACY_CIRCULAR),
        ('outside-target', 'file_offset', SOURCE_BYTES)):
        add(name, code=CORRUPT, qualified=False,
            mutate=lambda page, field=field, value=value: physical.FAST.put(page, field, value))
    for name, field, value in (
        ('spanning-transfer', 'page_count', 2), ('no-restart-flag', 'flags', w.RECORD_END)):
        add(name, code=CORRUPT, qualified=False,
            mutate=lambda page, field=field, value=value: w.PAGE.put(page, field, value))
    (output / 'manifest.json').write_text(json.dumps(dict(cases=cases), indent=2) + '\n')
    (output / 'cases.rows').write_text(''.join(' '.join(map(str, (
        case['path'], case['code'], int(case['qualified']), case['first_lsn'],
        case['alias'], case['home'], case['maximum_reads'], int(case['faults'])))) + '\n'
        for case in cases))
    return cases


if __name__ == '__main__':
    author(Path(sys.argv[1]))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text('authored retained restart-page copies\n')
