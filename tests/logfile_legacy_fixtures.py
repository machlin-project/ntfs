#!/usr/bin/env python3
"""Original completed-tail layouts with exact routed record byte oracles."""
from pathlib import Path
import hashlib
import json
import struct
import sys
import logfile_fixtures as w
from logfile_source_fixtures import restart, SMALL_FILE_BYTES, SMALL_PAGE_BYTES

SUCCESS, CORRUPT, UNSUPPORTED, NOT_FOUND, STALE = 0, 2, 3, 6, 10
OLD_PAYLOAD = b'older'
NEW_PAYLOAD = bytes(range(64))
NEWER_PAYLOAD = b'later completed record'
UNUSED_BYTE = 0x71
DIFFERENT_UNUSED_BYTE = 0x39
MISSING_BYTE = 0xff
LARGE_PAYLOAD_BYTES = 4000
MODERN_FILE_BYTES = 2 * SMALL_FILE_BYTES
PAYLOAD_MODULUS = 251
SECOND_USA_SEQUENCE = w.USA_SEQUENCE + 1
WRITTEN_CONFLICT_BYTE = 0xe3
ALTERNATE_TRANSFER_PAGES = 7
ALTERNATE_TRANSFER_POSITION = 3
UNALIGNED_FINAL_BYTES = w.WORD_BYTES


def packet(lsn, payload, flags=0):
    return bytes(w.RECORD.pack(dict(lsn=lsn, data_bytes=len(payload),
        client_sequence=w.CLIENT_SEQUENCE, type=w.UPDATE_TYPE,
        transaction=w.TRANSACTION, flags=flags))) + payload


def protected_page(data, *, target, last_end, next_record, tail=False,
                   flags=w.RECORD_END, sequence=w.USA_SEQUENCE, count=1, position=1,
                   last_start=None):
    logical = bytearray(data)
    logical[:w.PAGE.size] = w.PAGE.pack(dict(magic=b'RCRD', usa_offset=w.PAGE.size,
        copy_value=target if tail else (last_end if last_start is None else last_start),
        last_end_lsn=last_end,
        flags=flags, page_count=count, page_position=position,
        next_record_offset=next_record))
    raw, _ = w.protect(logical, w.PAGE)
    raw = bytearray(raw)
    usa_offset = w.PAGE.size
    struct.pack_into('<H', raw, usa_offset, sequence)
    for sector in range(1, len(raw) // w.USA_STRIDE + 1):
        struct.pack_into('<H', raw, sector * w.USA_STRIDE - w.WORD_BYTES, sequence)
    return raw


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    cases = []
    names = set()
    page_bytes = SMALL_PAGE_BYTES
    circular = (w.RESTART_PAGES + w.LEGACY_TAIL_PAGES) * page_bytes
    tail_base = w.RESTART_PAGES * page_bytes
    old_lsn = w.lsn_at(circular + w.PAGE_DATA_OFFSET, SMALL_FILE_BYTES)
    old_packet = packet(old_lsn, OLD_PAYLOAD)
    record_offset = w.aligned(w.PAGE_DATA_OFFSET + len(old_packet))
    requested = w.lsn_at(circular + record_offset, SMALL_FILE_BYTES)
    expected = packet(requested, NEW_PAYLOAD)
    next_record = w.aligned(record_offset + len(expected))

    def add(name, source, *, code=SUCCESS, query=requested, record=expected,
            pages=1, copies=1, reads=4, first=circular, last=circular, wrapped=False):
        assert name not in names
        names.add(name)
        filename = name + '.journal'
        (output / filename).write_bytes(source)
        (output / (filename + '.record')).write_bytes(record)
        fields = {key: struct.unpack_from('<' + form, record, w.RECORD.offsets[key])[0]
            for key, form in w.RECORD.fields if key != 'reserved'}
        fields['data'] = dict(offset=w.RECORD.size, length=fields.pop('data_bytes'))
        cases.append(dict(path=filename, code=code, lsn=query, bytes=len(record),
            pages=pages, copies=copies, reads=reads, page_bytes=page_bytes,
            first_page=first, last_page=last, wrapped=wrapped, record_fields=fields,
            source_sha256=hashlib.sha256(source).hexdigest(),
            record_sha256=hashlib.sha256(record).hexdigest()))

    def base(current=requested, major=w.LEGACY_MAJOR, minor=w.LEGACY_MINOR,
             file_bytes=SMALL_FILE_BYTES):
        source = bytearray(file_bytes)
        raw, _ = restart(current=current, major=major, minor=minor, file_bytes=file_bytes)
        for index in range(w.RESTART_PAGES):
            source[index * page_bytes:(index + 1) * page_bytes] = raw
        return source

    def put(source, offset, data):
        source[offset:offset + len(data)] = data

    old_data = bytearray([UNUSED_BYTE]) * page_bytes
    old_data[w.PAGE_DATA_OFFSET:w.PAGE_DATA_OFFSET + len(old_packet)] = old_packet
    new_data = bytearray(old_data)
    new_data[record_offset:record_offset + len(expected)] = expected
    old_tail = protected_page(old_data, target=circular, last_end=old_lsn,
        next_record=record_offset, tail=True)
    new_tail = protected_page(new_data, target=circular, last_end=requested,
        next_record=next_record, tail=True)
    old_circular = protected_page(old_data, target=circular, last_end=old_lsn,
        next_record=record_offset)
    new_circular = protected_page(new_data, target=circular, last_end=requested,
        next_record=next_record)

    def standard(first=old_tail, second=new_tail, regular=old_circular):
        source = base()
        put(source, tail_base, first)
        put(source, tail_base + page_bytes, second)
        put(source, circular, regular)
        return source

    add('newer-second-slot', standard())
    add('newer-first-slot', standard(new_tail, old_tail))
    add('missing-circular', standard(regular=bytes([MISSING_BYTE]) * page_bytes))
    torn_tail = bytearray(old_tail)
    struct.pack_into('<H', torn_tail, page_bytes - w.WORD_BYTES, SECOND_USA_SEQUENCE)
    add('torn-first-tail', standard(torn_tail))
    add('torn-second-tail', standard(new_tail, torn_tail))
    add('no-valid-tail', standard(bytes(page_bytes), bytes(page_bytes), new_circular),
        copies=0, reads=3)
    add('no-valid-page', standard(bytes(page_bytes), bytes(page_bytes), bytes(page_bytes)),
        code=CORRUPT, copies=0, reads=3)

    for label, end in (('circular-unwritten-payload', record_offset + w.RECORD.size),
                       ('circular-empty-written-prefix', 0)):
        page = protected_page(new_data, target=circular, last_end=requested,
            next_record=end)
        add(label, standard(bytes(page_bytes), bytes(page_bytes), page),
            code=CORRUPT, copies=0, reads=w.LEGACY_TAIL_PAGES + 1)
    for label, gap in (('circular-complete-at-page-end', 0),
                       ('circular-complete-before-aligned-page-end', UNALIGNED_FINAL_BYTES)):
        payload_bytes = page_bytes - record_offset - w.RECORD.size - gap
        complete = packet(requested, bytes(i % PAYLOAD_MODULUS for i in range(payload_bytes)))
        data = bytearray(old_data)
        data[record_offset:record_offset + len(complete)] = complete
        page = protected_page(data, target=circular, last_end=requested,
            next_record=page_bytes)
        add(label, standard(bytes(page_bytes), bytes(page_bytes), page),
            record=complete, copies=0, reads=w.LEGACY_TAIL_PAGES + 1)

    changed_capacity = bytearray(new_data)
    changed_capacity[next_record:] = bytes([DIFFERENT_UNUSED_BYTE]) * (page_bytes - next_record)
    equal_tail = protected_page(changed_capacity, target=circular, last_end=requested,
        next_record=next_record, tail=True, sequence=SECOND_USA_SEQUENCE,
        count=ALTERNATE_TRANSFER_PAGES, position=ALTERNATE_TRANSFER_POSITION)
    add('equal-tail-prefix-different-usa-and-capacity', standard(new_tail, equal_tail))
    add('equal-circular-and-tail-prefix', standard(regular=new_circular))
    equal_conflict = bytearray(new_data)
    equal_conflict[w.PAGE_DATA_OFFSET + w.RECORD.size] = WRITTEN_CONFLICT_BYTE
    conflict_tail = protected_page(equal_conflict, target=circular, last_end=requested,
        next_record=next_record, tail=True)
    add('equal-tail-written-conflict', standard(new_tail, conflict_tail),
        code=UNSUPPORTED, reads=2)
    conflict_circular = protected_page(equal_conflict, target=circular, last_end=requested,
        next_record=next_record)
    add('equal-circular-written-conflict', standard(regular=conflict_circular), code=UNSUPPORTED)

    newer_data = bytearray(new_data)
    newer_lsn = w.lsn_at(circular + next_record, SMALL_FILE_BYTES)
    newer_packet = packet(newer_lsn, NEWER_PAYLOAD)
    newer_data[next_record:next_record + len(newer_packet)] = newer_packet
    newer_circular = protected_page(newer_data, target=circular, last_end=newer_lsn,
        next_record=w.aligned(next_record + len(newer_packet)))
    add('newer-circular-wins', standard(regular=newer_circular), copies=0, reads=3)

    for label, target in [('target-in-restart', 0),
                          ('unaligned-target', circular + w.ALIGNMENT),
                          ('target-outside-file', SMALL_FILE_BYTES)]:
        malformed = bytearray(old_tail)
        w.PAGE.put(malformed, 'copy_value', target)
        add(label, standard(malformed))
    unrelated_target = circular + page_bytes
    unrelated_lsn = w.lsn_at(unrelated_target + w.PAGE_DATA_OFFSET, SMALL_FILE_BYTES)
    unrelated = protected_page(old_data, target=unrelated_target, last_end=unrelated_lsn,
        next_record=record_offset, tail=True)
    add('different-targets', standard(unrelated, new_tail))
    unknown = protected_page(old_data, target=circular, last_end=old_lsn,
        next_record=record_offset, tail=True, flags=w.UNKNOWN_PAGE_FLAG)
    add('unknown-tail-flags', standard(unknown), code=UNSUPPORTED, reads=1)
    unknown_circular = protected_page(new_data, target=circular, last_end=requested,
        next_record=next_record, flags=w.UNKNOWN_PAGE_FLAG)
    add('unknown-circular-flags', standard(regular=unknown_circular), code=UNSUPPORTED, reads=3)
    unfinished = protected_page(new_data, target=circular, last_end=0,
        next_record=record_offset, tail=True, flags=0)
    add('unresolved-matching-tail', standard(unfinished, bytes(page_bytes), bytes(page_bytes)),
        code=UNSUPPORTED, reads=3)
    short_prefix = protected_page(new_data, target=circular, last_end=requested,
        next_record=record_offset + w.RECORD.size, tail=True)
    add('record-crosses-written-tail-prefix', standard(old_tail, short_prefix), code=CORRUPT)
    add('requested-header-stale', standard(), query=requested + w.ALIGNMENT, code=STALE)
    add('zero-request', standard(), query=0, code=NOT_FOUND, reads=0)
    modern_circular = (w.RESTART_PAGES + w.FAST_PAGES) * page_bytes
    modern_lsn = w.lsn_at(modern_circular + record_offset, MODERN_FILE_BYTES)
    add('fast-version-refusal', base(current=modern_lsn, major=w.FAST_MAJOR,
        minor=w.FAST_MINOR, file_bytes=MODERN_FILE_BYTES),
        query=modern_lsn, record=packet(modern_lsn, NEW_PAYLOAD), code=UNSUPPORTED, reads=0,
        first=modern_circular, last=modern_circular)

    for wrapped in (False, True):
        first = SMALL_FILE_BYTES - page_bytes if wrapped else circular
        start = page_bytes - w.RECORD.size
        lsn = w.lsn_at(first + start, SMALL_FILE_BYTES)
        record = packet(lsn, bytes(i % PAYLOAD_MODULUS for i in range(LARGE_PAYLOAD_BYTES)), w.MULTI_PAGE)
        source = base(current=lsn)
        offset, cursor, copied, pages = first, start, 0, 0
        while copied < len(record):
            amount = min(page_bytes - cursor, len(record) - copied)
            final = copied + amount == len(record)
            data = bytearray([UNUSED_BYTE]) * page_bytes
            data[cursor:cursor + amount] = record[copied:copied + amount]
            next_free = w.aligned(cursor + amount) if final else 0
            raw = protected_page(data, target=offset, last_end=lsn if final else 0,
                next_record=next_free, tail=final, flags=w.RECORD_END if final else 0)
            put(source, tail_base + page_bytes if final else offset, raw)
            pages += 1
            copied += amount
            if copied != len(record):
                offset += page_bytes
                if offset == SMALL_FILE_BYTES:
                    offset = circular
            cursor = w.PAGE_DATA_OFFSET
        add('wrapped-tail-continuation' if wrapped else 'tail-continuation', source,
            query=lsn, record=record, pages=pages, copies=1, reads=w.LEGACY_TAIL_PAGES + pages + 1,
            first=first, last=offset, wrapped=wrapped)

    # NextRecordOffset remains at the start of an unfinished record. Each page
    # uses its own single-page transfer; transfer counts never identify a record.
    for wrapped in (False, True):
        first = SMALL_FILE_BYTES - page_bytes if wrapped else circular
        earlier_lsn = w.lsn_at(first + w.PAGE_DATA_OFFSET, SMALL_FILE_BYTES)
        earlier = packet(earlier_lsn, OLD_PAYLOAD)
        start = w.aligned(w.PAGE_DATA_OFFSET + len(earlier))
        lsn = w.lsn_at(first + start, SMALL_FILE_BYTES)
        complete = packet(lsn, bytes(i % PAYLOAD_MODULUS for i in range(LARGE_PAYLOAD_BYTES)),
            w.MULTI_PAGE)
        for verdict, suffix in ((SUCCESS, 'complete'), (CORRUPT, 'unwritten-final'),
                                (CORRUPT, 'short-final'), (STALE, 'unfinished-final')):
            source = base(current=lsn)
            offset, cursor, copied, pages = first, start, 0, 0
            while copied < len(complete):
                amount = min(page_bytes - cursor, len(complete) - copied)
                final = copied + amount == len(complete)
                data = bytearray([UNUSED_BYTE]) * page_bytes
                if copied == 0:
                    data[w.PAGE_DATA_OFFSET:w.PAGE_DATA_OFFSET + len(earlier)] = earlier
                data[cursor:cursor + amount] = complete[copied:copied + amount]
                next_free = w.aligned(cursor + amount) if final else cursor
                if final and suffix == 'unwritten-final':
                    next_free = cursor
                elif final and suffix == 'short-final':
                    next_free -= w.ALIGNMENT
                flags = w.RECORD_END if final or copied == 0 else 0
                last_end = lsn if final else (earlier_lsn if copied == 0 else 0)
                if final and suffix == 'unfinished-final':
                    flags, last_end = 0, 0
                raw = protected_page(data, target=offset, last_end=last_end,
                    next_record=next_free, flags=flags, last_start=lsn if copied == 0 else 0)
                put(source, offset, raw)
                pages += 1
                copied += amount
                if copied != len(complete):
                    offset += page_bytes
                    if offset == SMALL_FILE_BYTES:
                        offset = circular
                cursor = w.PAGE_DATA_OFFSET
            prefix = 'circular-wrapped-split-' if wrapped else 'circular-split-'
            add(prefix + suffix, source, code=verdict, query=lsn, record=complete,
                pages=pages, copies=0, reads=w.LEGACY_TAIL_PAGES + pages,
                first=first, last=offset, wrapped=wrapped)

    (output / 'manifest.json').write_text(json.dumps(dict(cases=cases), indent=2) + '\n')
    (output / 'cases.tsv').write_text('\n'.join(
        f"{c['path']}\t{c['code']}\t{c['lsn']}\t{c['bytes']}\t{c['pages']}\t{c['copies']}\t"
        f"{c['reads']}\t{c['page_bytes']}\t{c['first_page']}\t{c['last_page']}\t{int(c['wrapped'])}"
        for c in cases) + '\n')
    return cases


if __name__ == '__main__':
    author(Path(sys.argv[1]))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text('original-completed-tail-records\n')
