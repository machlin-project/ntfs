#!/usr/bin/env python3
"""Independently author physical circular fragments and exact record byte oracles."""
from pathlib import Path
import json
import struct
import sys
import logfile_fixtures as w
from logfile_source_fixtures import restart, SMALL_FILE_BYTES, SMALL_PAGE_BYTES

SUCCESS, CORRUPT, UNSUPPORTED, NOT_FOUND, STALE, RANGE = 0, 2, 3, 6, 10, 11
MAX_RECORD_BYTES = 1024 * 1024
MAX_SOURCE_BYTES = 4 * 1024 * 1024
TRANSFER_PAGES = 5
TRANSFER_POSITION = 3
FIRST_RECORD_GAP = 24
EXTENSION_BYTE = 0x7e
PADDING_BYTE = 0xcc
PAYLOAD_FACTOR = 29
PAYLOAD_MODULUS = 251


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    cases = []
    names = set()

    def add(name, payload_bytes=37, *, system=SMALL_PAGE_BYTES, log=SMALL_PAGE_BYTES,
            file_bytes=SMALL_FILE_BYTES, header_bytes=w.RECORD.size, data_offset=w.PAGE_DATA_OFFSET,
            last_page=False, at_end=False, flags=None, record_type=w.UPDATE_TYPE,
            client_index=0, previous=0, undo=0, stale=False, requested=None,
            declared=None, bad_page=None, missing_page=None, malformed_next=False,
            tail_only=False, verdict=SUCCESS):
        assert name not in names
        names.add(name)
        circular = w.RESTART_PAGES * system + w.LEGACY_TAIL_PAGES * log
        first_page = file_bytes - log if last_page else circular
        record_offset = log - header_bytes if at_end else data_offset + FIRST_RECORD_GAP
        record_lsn = w.lsn_at(first_page + record_offset, file_bytes)
        query = record_lsn if requested is None else requested
        payload = bytes((index * PAYLOAD_FACTOR) % PAYLOAD_MODULUS for index in range(payload_bytes))
        total = header_bytes + len(payload)
        fragmented = total > log - record_offset
        record_flags = w.MULTI_PAGE if fragmented else 0
        if flags is not None:
            record_flags = flags
        record = w.RECORD.pack(dict(lsn=record_lsn + w.ALIGNMENT if stale else record_lsn,
            previous_lsn=previous, undo_next_lsn=undo,
            data_bytes=len(payload) if declared is None else declared,
            client_sequence=w.CLIENT_SEQUENCE, client_index=client_index, type=record_type,
            transaction=w.TRANSACTION, flags=record_flags))
        record += bytes([EXTENSION_BYTE]) * (header_bytes - w.RECORD.size) + payload
        source = bytearray(file_bytes)
        raw, _ = restart(system=system, log=log, file_bytes=file_bytes,
            record_header_bytes=header_bytes, page_data_offset=data_offset, current=record_lsn)
        for position in range(w.RESTART_PAGES):
            source[position * system:(position + 1) * system] = raw
        offset, cursor, copied, pages = first_page, record_offset, 0, []
        while copied < len(record):
            amount = min(log - cursor, len(record) - copied)
            final = copied + amount == len(record)
            next_record = w.aligned(cursor + amount) if final else 0
            if next_record >= log:
                next_record = 0
            if malformed_next:
                next_record = data_offset - w.ALIGNMENT
            page = bytearray([PADDING_BYTE]) * log
            page[:w.PAGE.size] = w.PAGE.pack(dict(magic=b'RCRD', usa_offset=w.PAGE.size,
                copy_value=record_lsn, flags=w.RECORD_END if final else 0,
                page_count=TRANSFER_PAGES, page_position=TRANSFER_POSITION,
                next_record_offset=next_record, last_end_lsn=record_lsn if final else 0))
            page[cursor:cursor + amount] = record[copied:copied + amount]
            raw_page, _ = w.protect(page, w.PAGE)
            if len(pages) == bad_page:
                raw_page = bytearray(raw_page)
                struct.pack_into('<H', raw_page, log - w.WORD_BYTES, w.USA_SEQUENCE + 1)
            if len(pages) == missing_page:
                raw_page = bytes(log)
            physical_offset = w.RESTART_PAGES * system if tail_only else offset
            source[physical_offset:physical_offset + log] = raw_page
            pages.append(offset)
            copied += amount
            offset += log
            if offset == file_bytes:
                offset = circular
            cursor = data_offset
            assert offset != first_page or copied == len(record)
        filename = name + '.journal'
        (output / filename).write_bytes(source)
        (output / (filename + '.record')).write_bytes(record)
        fields = dict(lsn=record_lsn, previous_lsn=previous, undo_next_lsn=undo,
            type=record_type, transaction=w.TRANSACTION, client_sequence=w.CLIENT_SEQUENCE,
            client_index=client_index, flags=record_flags, data=dict(offset=header_bytes, length=len(payload)))
        case = dict(path=filename, code=verdict, lsn=query, record_fields=fields,
            bytes=len(record), header_bytes=header_bytes, pages=len(pages), page_bytes=log,
            first_page=first_page, last_page=pages[-1], wrapped=any(
                later < earlier for earlier, later in zip(pages, pages[1:])))
        cases.append(case)

    add('single')
    add('empty-client', payload_bytes=0)
    add('flagged-small', flags=w.MULTI_PAGE)
    add('extended-header', header_bytes=w.EXTENDED_RECORD_HEADER_BYTES)
    add('header-at-end', at_end=True)
    add('two-pages', payload_bytes=500)
    add('three-pages', payload_bytes=1101)
    add('credits', payload_bytes=6000)
    add('wrap-two-pages', payload_bytes=500, last_page=True)
    add('wrap-four-pages', payload_bytes=1400, last_page=True)
    add('extended-page-prefix', payload_bytes=600, data_offset=w.PAGE_DATA_OFFSET + 2 * w.ALIGNMENT)
    add('mixed-pages', payload_bytes=500, system=w.PAGE_BYTES, last_page=True)
    add('ordinary-pages', payload_bytes=2 * w.PAGE_BYTES, system=w.PAGE_BYTES,
        log=w.PAGE_BYTES, file_bytes=w.FILE_BYTES)
    maximum_data_offset = w.aligned(w.PAGE.size + (w.MAX_PAGE_BYTES // w.USA_STRIDE + 1) * w.WORD_BYTES)
    add('maximum-pages', payload_bytes=4 * w.PAGE_BYTES, system=w.MAX_PAGE_BYTES,
        log=w.MAX_PAGE_BYTES, file_bytes=MAX_SOURCE_BYTES, data_offset=maximum_data_offset, at_end=True)
    # Default byte credits reject this complete record. The direct core suite
    # separately observes exact-cap success with explicitly sufficient credits.
    add('at-record-cap', payload_bytes=MAX_RECORD_BYTES - w.RECORD.size,
        system=w.MAX_PAGE_BYTES, log=w.MAX_PAGE_BYTES, file_bytes=MAX_SOURCE_BYTES,
        data_offset=maximum_data_offset, verdict=RANGE)
    add('stale-header', stale=True, verdict=STALE)
    add('zero-lsn', requested=0, verdict=NOT_FOUND)
    add('restart-lsn', requested=w.lsn_at(0, SMALL_FILE_BYTES), verdict=CORRUPT)
    add('record-cap', declared=MAX_RECORD_BYTES, verdict=RANGE)
    add('ring-revisit', declared=SMALL_FILE_BYTES, verdict=RANGE)
    add('unknown-flags', payload_bytes=500, flags=w.UNKNOWN_RECORD_FLAG, verdict=UNSUPPORTED)
    add('unknown-type', record_type=(1 << (struct.calcsize('<I') * w.BITS_PER_BYTE)) - 1,
        verdict=UNSUPPORTED)
    add('no-client', client_index=w.NO_CLIENT, verdict=CORRUPT)
    add('previous-in-restart', previous=1, verdict=CORRUPT)
    add('undo-in-restart', undo=1, verdict=CORRUPT)
    add('torn-first', bad_page=0, verdict=CORRUPT)
    add('torn-continuation', payload_bytes=1101, bad_page=1, verdict=CORRUPT)
    add('missing-continuation', payload_bytes=1101, missing_page=1, verdict=CORRUPT)
    add('invalid-next-offset', malformed_next=True, verdict=CORRUPT)
    add('tail-only', tail_only=True, verdict=CORRUPT)
    (output / 'manifest.json').write_text(json.dumps(dict(cases=cases), indent=2) + '\n')
    (output / 'cases.tsv').write_text('\n'.join(
        f"{case['path']}\t{case['code']}\t{case['lsn']}\t{case['bytes']}\t{case['header_bytes']}\t{case['pages']}\t"
        f"{case['page_bytes']}\t{case['first_page']}\t{case['last_page']}\t{int(case['wrapped'])}"
        for case in cases) + '\n')
    return cases


if __name__ == '__main__':
    author(Path(sys.argv[1]))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text('original-physical-record-fragments\n')
