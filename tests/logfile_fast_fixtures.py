#!/usr/bin/env python3
"""Original protected LFS 2.0 fast-slot graphs and exact record byte oracles."""
from pathlib import Path
import hashlib
import json
import struct
import sys
import logfile_fixtures as w
from logfile_source_fixtures import restart

SUCCESS, CORRUPT, UNSUPPORTED, NOT_FOUND, STALE = 0, 2, 3, 6, 10
FAST_PAGE_BYTES = w.PAGE_BYTES
FAST_FILE_BYTES = w.FILE_BYTES
FAST_USA_WORDS = FAST_PAGE_BYTES // w.USA_STRIDE + 1
CLIENT_RESTART_PAGE = 0x00000002
UNUSED_BYTE, OTHER_UNUSED_BYTE, CONFLICT_BYTE = 0x71, 0x39, 0xe3
MISSING_PAGE_BYTE = 0xff
OLD_PAYLOAD = b'older'
NEW_PAYLOAD = bytes(range(64))
NEWER_PAYLOAD = b'later completed record'
PAYLOAD_MODULUS = 251
TRANSFER_COUNT, TRANSFER_POSITION = 7, 3
FAST = w.Layout(w.PAGE.fields + (
    ('usa_capacity', f'{FAST_USA_WORDS * w.WORD_BYTES}s'),
    ('usa_padding', 'H'), ('file_offset', 'I')))
MAX_U32 = (1 << (struct.calcsize('<I') * w.BITS_PER_BYTE)) - 1


def packet(lsn, payload, flags=0, kind=w.UPDATE_TYPE, header_bytes=w.RECORD.size):
    return bytes(w.RECORD.pack(dict(lsn=lsn, data_bytes=len(payload),
        client_sequence=w.CLIENT_SEQUENCE, type=kind,
        transaction=w.TRANSACTION, flags=flags))).ljust(header_bytes, b'\0') + payload


def page(body, *, last_start, last_end, next_record, target=0,
         flags=w.RECORD_END, sequence=w.USA_SEQUENCE, count=1, position=1,
         usa_offset=w.PAGE.size):
    logical = bytearray(body)
    logical[:w.PAGE.size] = w.PAGE.pack(dict(magic=b'RCRD', usa_offset=usa_offset,
        copy_value=last_start, last_end_lsn=last_end, flags=flags,
        page_count=count, page_position=position, next_record_offset=next_record))
    FAST.put(logical, 'file_offset', target)
    raw, _ = w.protect(logical, w.PAGE)
    raw = bytearray(raw)
    struct.pack_into('<H', raw, usa_offset, sequence)
    for sector in range(1, len(raw) // w.USA_STRIDE + 1):
        struct.pack_into('<H', raw, sector * w.USA_STRIDE - w.WORD_BYTES, sequence)
    return raw


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    cases = []
    names = set()
    circular = (w.RESTART_PAGES + w.FAST_PAGES) * FAST_PAGE_BYTES
    fast_base = w.RESTART_PAGES * FAST_PAGE_BYTES
    old_lsn = w.lsn_at(circular + FAST.size, FAST_FILE_BYTES)
    old_packet = packet(old_lsn, OLD_PAYLOAD)
    record_offset = w.aligned(FAST.size + len(old_packet))
    requested = w.lsn_at(circular + record_offset, FAST_FILE_BYTES)
    expected = packet(requested, NEW_PAYLOAD)
    next_record = w.aligned(record_offset + len(expected))
    old_body = bytearray([UNUSED_BYTE]) * FAST_PAGE_BYTES
    old_body[FAST.size:FAST.size + len(old_packet)] = old_packet
    new_body = bytearray(old_body)
    new_body[record_offset:record_offset + len(expected)] = expected
    old_page = page(old_body, last_start=old_lsn, last_end=old_lsn, next_record=record_offset)
    new_page = page(new_body, last_start=requested, last_end=requested, next_record=next_record)
    new_fast = page(new_body, last_start=requested, last_end=requested,
                    next_record=next_record, target=circular)

    def put(source, offset, data):
        source[offset:offset + len(data)] = data

    def base(*, current=requested, major=w.FAST_MAJOR, minor=w.FAST_MINOR,
             system=FAST_PAGE_BYTES, log=FAST_PAGE_BYTES, data_offset=FAST.size,
             header_bytes=w.RECORD.size):
        source = bytearray(FAST_FILE_BYTES)
        raw, _ = restart(current=current, major=major, minor=minor, file_bytes=FAST_FILE_BYTES,
            system=system, log=log, page_data_offset=data_offset,
            record_header_bytes=header_bytes)
        for index in range(w.RESTART_PAGES):
            put(source, index * system, raw)
        return source

    def standard(slots=((0, new_fast),), regular=old_page):
        source = base()
        put(source, circular, regular)
        for index, raw in slots:
            put(source, fast_base + index * FAST_PAGE_BYTES, raw)
        return source

    def add(name, source, *, code=SUCCESS, query=requested, record=expected,
            pages=1, copies=1, reads=w.FAST_PAGES + 2,
            first=circular, last=circular, wrapped=False, faults=False,
            header_bytes=w.RECORD.size):
        assert name not in names
        names.add(name)
        filename = name + '.journal'
        (output / filename).write_bytes(source)
        (output / (filename + '.record')).write_bytes(record)
        fields = {key: struct.unpack_from('<' + form, record, w.RECORD.offsets[key])[0]
                  for key, form in w.RECORD.fields if key != 'reserved'}
        fields['data'] = dict(offset=header_bytes, length=fields.pop('data_bytes'))
        cases.append(dict(path=filename, code=code, lsn=query, bytes=len(record),
            pages=pages, copies=copies, reads=reads, page_bytes=FAST_PAGE_BYTES,
            first_page=first, last_page=last, wrapped=wrapped, faults=faults,
            record_fields=fields, source_sha256=hashlib.sha256(source).hexdigest(),
            record_sha256=hashlib.sha256(record).hexdigest()))

    for slot in range(w.FAST_PAGES):
        add(f'latest-in-slot-{slot:02}', standard(((slot, new_fast),)), faults=slot == 0)
    old_fast = page(old_body, last_start=old_lsn, last_end=old_lsn,
                    next_record=record_offset, target=circular)
    add('newest-before-older-slot', standard(((0, new_fast), (w.FAST_PAGES - 1, old_fast))))
    add('newest-after-older-slot', standard(((0, old_fast), (w.FAST_PAGES - 1, new_fast))))
    add('missing-circular', standard(regular=bytes([MISSING_PAGE_BYTE]) * FAST_PAGE_BYTES))
    torn = bytearray(new_fast)
    struct.pack_into('<H', torn, FAST_PAGE_BYTES - w.WORD_BYTES, w.USA_SEQUENCE + 1)
    add('torn-later-copy', standard(((0, new_fast), (w.FAST_PAGES - 1, torn))))
    add('torn-only-copy-circular-remains', standard(((0, torn),), new_page),
        copies=0, reads=w.FAST_PAGES + 1)
    add('no-valid-copy-circular-remains', standard((), new_page),
        copies=0, reads=w.FAST_PAGES + 1)
    add('no-valid-storage', standard((), bytes(FAST_PAGE_BYTES)),
        code=CORRUPT, copies=0, reads=w.FAST_PAGES + 1)

    equivalent_body = bytearray(new_body)
    equivalent_body[next_record:] = bytes([OTHER_UNUSED_BYTE]) * (FAST_PAGE_BYTES - next_record)
    equivalent_fast = page(equivalent_body, last_start=requested, last_end=requested,
        next_record=next_record, target=circular, sequence=w.USA_SEQUENCE + 1,
        count=TRANSFER_COUNT, position=TRANSFER_POSITION)
    add('equal-copy-usa-transfer-capacity-differ', standard(((0, new_fast), (w.FAST_PAGES - 1, equivalent_fast))),
        reads=w.FAST_PAGES + 3, faults=True)
    boundary_usa = page(new_body, last_start=requested, last_end=requested,
        next_record=next_record, target=circular, usa_offset=w.PAGE.size + w.WORD_BYTES)
    add('usa-ends-at-fast-target', standard(((0, boundary_usa),)))
    add('all-slots-equal', standard(tuple((slot, new_fast if slot % 2 else equivalent_fast)
        for slot in range(w.FAST_PAGES))), reads=2 * w.FAST_PAGES + 1, faults=True)
    add('equal-circular-prefix', standard(regular=new_page))
    conflicting_body = bytearray(new_body)
    conflicting_body[record_offset + w.RECORD.size] = CONFLICT_BYTE
    conflicting_fast = page(conflicting_body, last_start=requested, last_end=requested,
        next_record=next_record, target=circular)
    add('equal-fast-written-conflict', standard(((0, new_fast), (w.FAST_PAGES - 1, conflicting_fast))),
        code=UNSUPPORTED, reads=w.FAST_PAGES + 3)
    conflicting_page = page(conflicting_body, last_start=requested, last_end=requested,
                            next_record=next_record)
    add('equal-circular-written-conflict', standard(regular=conflicting_page), code=UNSUPPORTED)
    older_end_fast = page(new_body, last_start=requested, last_end=old_lsn,
                         next_record=next_record, target=circular)
    add('equal-start-different-end', standard(((0, new_fast), (w.FAST_PAGES - 1, older_end_fast))),
        code=UNSUPPORTED, reads=w.FAST_PAGES + 3)

    newer_lsn = w.lsn_at(circular + next_record, FAST_FILE_BYTES)
    later_packet = packet(newer_lsn, NEWER_PAYLOAD)
    later_body = bytearray(new_body)
    later_body[next_record:next_record + len(later_packet)] = later_packet
    later_page = page(later_body, last_start=newer_lsn, last_end=newer_lsn,
                      next_record=w.aligned(next_record + len(later_packet)))
    add('newer-circular-wins', standard(regular=later_page), copies=0, reads=w.FAST_PAGES + 1)
    restart_page = page(new_body, last_start=requested, last_end=requested,
        next_record=next_record, target=circular, flags=w.RECORD_END | CLIENT_RESTART_PAGE)
    add('client-restart-page-bit', standard(((0, restart_page),)))
    add('equal-start-different-page-flags', standard(((0, new_fast), (w.FAST_PAGES - 1, restart_page))),
        code=UNSUPPORTED, reads=w.FAST_PAGES + 3)
    for name, target in [('restart-target', 0), ('fast-storage-target', fast_base),
                         ('unaligned-target', circular + w.ALIGNMENT),
                         ('outside-file-target', FAST_FILE_BYTES), ('maximum-target', MAX_U32)]:
        bad = page(new_body, last_start=requested, last_end=requested,
                   next_record=next_record, target=target)
        add(name, standard(((0, bad),), new_page), copies=0, reads=w.FAST_PAGES + 1)
    bad_lsn = page(new_body, last_start=0, last_end=requested,
                   next_record=next_record, target=circular)
    add('invalid-fast-last-start', standard(((0, bad_lsn),), new_page),
        copies=0, reads=w.FAST_PAGES + 1)
    reversed_end = page(new_body, last_start=old_lsn, last_end=requested,
                       next_record=next_record, target=circular)
    add('fast-end-after-last-start', standard(((0, reversed_end),), new_page),
        copies=0, reads=w.FAST_PAGES + 1)
    unknown = page(new_body, last_start=requested, last_end=requested,
                   next_record=next_record, target=circular, flags=w.UNKNOWN_PAGE_FLAG)
    add('unknown-fast-page-flags', standard(((0, unknown),)), code=UNSUPPORTED, reads=1)
    unknown_circular = page(new_body, last_start=requested, last_end=requested,
                            next_record=next_record, flags=w.UNKNOWN_PAGE_FLAG)
    add('unknown-circular-page-flags', standard(regular=unknown_circular),
        code=UNSUPPORTED, reads=w.FAST_PAGES + 1)
    overlapping_usa = page(new_body, last_start=requested, last_end=requested,
        next_record=next_record, target=circular, usa_offset=w.PAGE.size + 2 * w.WORD_BYTES)
    add('usa-overlaps-fast-target', standard(((0, overlapping_usa),)), code=UNSUPPORTED, reads=1)
    unfinished = page(new_body, last_start=requested, last_end=0,
        next_record=record_offset, target=circular, flags=0)
    add('unresolved-latest-copy', standard(((0, unfinished),), bytes(FAST_PAGE_BYTES)),
        code=UNSUPPORTED, reads=w.FAST_PAGES + 1)
    short_prefix = page(new_body, last_start=requested, last_end=requested,
        next_record=record_offset + w.RECORD.size, target=circular)
    add('record-outside-fast-written-prefix', standard(((0, short_prefix),)), code=CORRUPT)
    add('wrong-requested-header', standard(), query=requested + w.ALIGNMENT, code=STALE)
    add('zero-request', standard(), query=0, code=NOT_FOUND, reads=0)

    complete_payload = bytes(i % PAYLOAD_MODULUS
        for i in range(FAST_PAGE_BYTES - record_offset - w.RECORD.size))
    complete_packet = packet(requested, complete_payload)
    complete_body = bytearray(old_body)
    complete_body[record_offset:] = complete_packet
    complete_fast = page(complete_body, last_start=requested, last_end=requested,
                          next_record=FAST_PAGE_BYTES, target=circular)
    add('complete-at-page-end', standard(((0, complete_fast),)), record=complete_packet)

    extended_data = FAST.size + 2 * w.ALIGNMENT
    extended_header = w.EXTENDED_RECORD_HEADER_BYTES
    extended_old_lsn = w.lsn_at(circular + extended_data, FAST_FILE_BYTES)
    extended_old = packet(extended_old_lsn, OLD_PAYLOAD, header_bytes=extended_header)
    extended_offset = w.aligned(extended_data + len(extended_old))
    extended_lsn = w.lsn_at(circular + extended_offset, FAST_FILE_BYTES)
    extended_record = packet(extended_lsn, NEW_PAYLOAD, header_bytes=extended_header)
    extended_next = w.aligned(extended_offset + len(extended_record))
    extended_body = bytearray([UNUSED_BYTE]) * FAST_PAGE_BYTES
    extended_body[extended_data:extended_data + len(extended_old)] = extended_old
    extended_old_page = page(extended_body, last_start=extended_old_lsn,
        last_end=extended_old_lsn, next_record=extended_offset)
    extended_body[extended_offset:extended_offset + len(extended_record)] = extended_record
    extended_fast = page(extended_body, last_start=extended_lsn, last_end=extended_lsn,
        next_record=extended_next, target=circular)
    extended_source = base(current=extended_lsn, data_offset=extended_data,
                           header_bytes=extended_header)
    put(extended_source, circular, extended_old_page)
    put(extended_source, fast_base, extended_fast)
    add('extended-data-and-record-headers', extended_source, query=extended_lsn,
        record=extended_record, header_bytes=extended_header)

    stability_fast = page(new_body, last_start=requested, last_end=requested,
        next_record=next_record, target=circular, count=TRANSFER_COUNT,
        position=TRANSFER_POSITION)
    add('reload-header-stability', standard(((0, stability_fast),)))
    changed = []
    for field, value in [('file_offset', circular + FAST_PAGE_BYTES),
                         ('copy_value', newer_lsn), ('last_end_lsn', old_lsn),
                         ('flags', w.RECORD_END | CLIENT_RESTART_PAGE),
                         ('page_count', TRANSFER_COUNT + 1),
                         ('page_position', TRANSFER_POSITION - 1),
                         ('next_record_offset', next_record + w.ALIGNMENT)]:
        changed_page = bytearray(new_body)
        changed_page[:w.PAGE.size] = w.PAGE.pack(dict(magic=b'RCRD',
            usa_offset=w.PAGE.size, copy_value=requested, last_end_lsn=requested,
            flags=w.RECORD_END, page_count=TRANSFER_COUNT, page_position=TRANSFER_POSITION,
            next_record_offset=next_record))
        FAST.put(changed_page, 'file_offset', circular)
        FAST.put(changed_page, field, value)
        raw, _ = w.protect(changed_page, w.PAGE)
        filename = f'changed-{field}.page'
        (output / filename).write_bytes(raw)
        changed.append(filename)
    (output / 'changed.tsv').write_text('\n'.join(changed) + '\n')

    for wrapped in (False, True):
        first = FAST_FILE_BYTES - FAST_PAGE_BYTES if wrapped else circular
        last = circular if wrapped else first + FAST_PAGE_BYTES
        start_lsn = w.lsn_at(first + record_offset, FAST_FILE_BYTES)
        prior_lsn = w.lsn_at(first + FAST.size, FAST_FILE_BYTES)
        spanning_packet = packet(start_lsn, bytes(i % PAYLOAD_MODULUS
            for i in range(FAST_PAGE_BYTES + w.ALIGNMENT)), flags=w.MULTI_PAGE)
        first_amount = FAST_PAGE_BYTES - record_offset
        head_body = bytearray([UNUSED_BYTE]) * FAST_PAGE_BYTES
        head_body[record_offset:] = spanning_packet[:first_amount]
        head = page(head_body, last_start=start_lsn, last_end=prior_lsn,
                    next_record=record_offset, count=0, position=0)
        ending_body = bytearray([UNUSED_BYTE]) * FAST_PAGE_BYTES
        remainder = spanning_packet[first_amount:]
        ending_body[FAST.size:FAST.size + len(remainder)] = remainder
        ending = page(ending_body, last_start=start_lsn, last_end=start_lsn,
            next_record=w.aligned(FAST.size + len(remainder)), target=last,
            count=TRANSFER_COUNT, position=TRANSFER_POSITION)
        source = base(current=start_lsn)
        put(source, first, head)
        put(source, fast_base + (w.FAST_PAGES - 1) * FAST_PAGE_BYTES, ending)
        add('wrapped-fast-ending' if wrapped else 'separate-transfer-fast-ending', source,
            query=start_lsn, record=spanning_packet, pages=2, reads=w.FAST_PAGES + 3,
            first=first, last=last, wrapped=wrapped, faults=True)

    legacy_lsn = w.lsn_at((w.RESTART_PAGES + w.LEGACY_TAIL_PAGES) * FAST_PAGE_BYTES + FAST.size,
                         FAST_FILE_BYTES)
    add('legacy-layout-refused', base(major=w.LEGACY_MAJOR, minor=w.LEGACY_MINOR, current=legacy_lsn),
        code=UNSUPPORTED, query=legacy_lsn, reads=0)
    for log in (w.USA_STRIDE, 2 * FAST_PAGE_BYTES):
        start = w.RESTART_PAGES * FAST_PAGE_BYTES + w.FAST_PAGES * log
        data_offset = max(FAST.size, w.aligned(w.PAGE.size + (log // w.USA_STRIDE + 1) * w.WORD_BYTES))
        lsn = w.lsn_at(start + data_offset, FAST_FILE_BYTES)
        add(f'unsupported-log-page-{log}', base(log=log, current=lsn, data_offset=data_offset),
            code=UNSUPPORTED, query=lsn, reads=0)
    other_system = 2 * FAST_PAGE_BYTES
    other_circular = w.RESTART_PAGES * other_system + w.FAST_PAGES * FAST_PAGE_BYTES
    other_lsn = w.lsn_at(other_circular + FAST.size, FAST_FILE_BYTES)
    add('unsupported-system-page', base(system=other_system, current=other_lsn),
        code=UNSUPPORTED, query=other_lsn, reads=0)

    lines = [' '.join(map(str, (case['path'], case['code'], case['lsn'], case['bytes'],
        case['pages'], case['copies'], case['reads'], case['page_bytes'], case['first_page'],
        case['last_page'], int(case['wrapped']), int(case['faults'])))) for case in cases]
    (output / 'cases.tsv').write_text('\n'.join(lines) + '\n')
    (output / 'manifest.json').write_text(json.dumps(dict(schema_version=1,
        origin='Original synthetic LFS 2.0 fast-slot graphs; no Windows/current-history acceptance',
        fast_target_offset=FAST.offsets['file_offset'], cases=cases), indent=2) + '\n')
    return cases


if __name__ == '__main__':
    cases = author(Path(sys.argv[1]))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text(f'{len(cases)} independent fast-copy graphs\n')
