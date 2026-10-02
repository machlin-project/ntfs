#!/usr/bin/env python3
"""Original logical journal sources with independent copy and byte expectations."""
from pathlib import Path
import json
import struct
import sys
import logfile_fixtures as wire

SMALL_PAGE_BYTES = wire.USA_STRIDE
SMALL_FILE_BYTES = 32 * 1024
PROBE_OFFSETS = (0, *(wire.USA_STRIDE << shift for shift in range(8)))
SUCCESS = 0
CORRUPT = 2
UNSUPPORTED = 3
NOT_FOUND = 6
SINGLE = 1
EQUAL = 2
NEWER = 3
CONFLICT = 4
PAYLOAD = b'Original journal page payload'


def restart(**options):
    system = options.get('system', SMALL_PAGE_BYTES)
    options.setdefault('system', system)
    options.setdefault('log', SMALL_PAGE_BYTES)
    options.setdefault('file_bytes', SMALL_FILE_BYTES)
    options.setdefault('area_offset', max(wire.RESTART_OFFSET,
        wire.aligned(wire.RESTART_HEADER.size + (system // wire.USA_STRIDE + 1) * wire.WORD_BYTES)))
    logical, fields = wire.restart(**options)
    raw, _ = wire.protect(logical, wire.RESTART_HEADER)
    return raw, fields


def record_page(fields, tail=False):
    data = bytearray(fields['log_page_bytes'])
    record = wire.RECORD.pack(dict(lsn=fields['current_lsn'], data_bytes=len(PAYLOAD),
        client_sequence=wire.CLIENT_SEQUENCE, type=wire.UPDATE_TYPE, transaction=wire.TRANSACTION)) + PAYLOAD
    copy_value = fields['circular_offset'] if tail else fields['current_lsn']
    header = wire.PAGE.pack(dict(magic=b'RCRD', usa_offset=wire.PAGE.size,
        copy_value=copy_value, flags=wire.RECORD_END, page_count=1, page_position=1,
        next_record_offset=wire.aligned(fields['page_data_offset'] + len(record)),
        last_end_lsn=fields['current_lsn']))
    data[:len(header)] = header
    offset_bits = wire.LSN_BITS - fields['sequence_bits']
    start = ((fields['current_lsn'] & ((1 << offset_bits) - 1)) << wire.OFFSET_SHIFT) % fields['log_page_bytes']
    data[start:start + len(record)] = record
    raw, restored = wire.protect(data, wire.PAGE)
    return raw, restored, record


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    cases = []
    names = set()
    base, base_fields = restart()
    newer, newer_fields = restart(current=wire.lsn_at(
        base_fields['circular_offset'] + wire.PAGE_DATA_OFFSET + wire.ALIGNMENT,
        SMALL_FILE_BYTES))

    def add(name, packets, verdict, selection, selected=None, size=SMALL_FILE_BYTES, corrupt_page=False):
        assert name not in names
        names.add(name)
        source = bytearray(size)
        probes = {offset: dict(offset=offset, page_bytes=0, code=NOT_FOUND, current_lsn=0)
                  for offset in PROBE_OFFSETS}
        full_reads = []
        for offset, raw, fields, code, full in packets:
            assert offset + len(raw) <= len(source)
            source[offset:offset + len(raw)] = raw
            probes[offset] = dict(offset=offset, page_bytes=fields['system_page_bytes'],
                                 code=code, current_lsn=fields['current_lsn'] if code == SUCCESS else 0)
            if full:
                full_reads.append(len(raw))
        selected_fields = None
        filename = name + '.journal'
        if selected is not None:
            selected_fields = next(fields for offset, _, fields, _, _ in packets if offset == selected)
            for tail in (False, True):
                raw, restored, record = record_page(selected_fields, tail)
                if corrupt_page and not tail:
                    raw = bytearray(raw)
                    struct.pack_into('<H', raw, len(raw) - wire.WORD_BYTES, wire.USA_SEQUENCE + 1)
                position = wire.RESTART_PAGES * selected_fields['system_page_bytes'] if tail else selected_fields['circular_offset']
                source[position:position + len(raw)] = raw
                (output / (filename + ('.tail' if tail else '.page'))).write_bytes(restored)
                if not tail:
                    (output / (filename + '.record')).write_bytes(record)
        (output / filename).write_bytes(source)
        prefix_reads = sum(offset + wire.RESTART_HEADER.size <= size for offset in PROBE_OFFSETS)
        case = dict(path=filename, code=verdict, selection=selection, selected_offset=selected,
            selected_probe=PROBE_OFFSETS.index(selected) if selected is not None else None,
            scan_complete=True, read_calls=prefix_reads + len(full_reads),
            read_bytes=prefix_reads * wire.RESTART_HEADER.size + sum(full_reads),
            probes=list(probes.values()), fields=selected_fields, page_code=CORRUPT if corrupt_page else SUCCESS)
        cases.append(case)

    packet = lambda offset, raw=base, fields=base_fields, code=SUCCESS, full=True: (offset, raw, fields, code, full)
    add('equal', [packet(0), packet(SMALL_PAGE_BYTES)], SUCCESS, EQUAL, 0)
    add('torn-record-page', [packet(0), packet(SMALL_PAGE_BYTES)], SUCCESS, EQUAL, 0, corrupt_page=True)
    other_usa = bytearray(base)
    usa = wire.RESTART_HEADER.size
    struct.pack_into('<H', other_usa, usa, wire.USA_SEQUENCE + 1)
    for tail in range(wire.USA_STRIDE - wire.WORD_BYTES, len(other_usa), wire.USA_STRIDE):
        struct.pack_into('<H', other_usa, tail, wire.USA_SEQUENCE + 1)
    add('different-usa', [packet(0), packet(SMALL_PAGE_BYTES, other_usa)], SUCCESS, EQUAL, 0)
    add('newer-second', [packet(0), packet(SMALL_PAGE_BYTES, newer, newer_fields)], SUCCESS, NEWER, SMALL_PAGE_BYTES)
    add('newer-first', [packet(0, newer, newer_fields), packet(SMALL_PAGE_BYTES)], SUCCESS, NEWER, 0)
    add('missing-first', [packet(SMALL_PAGE_BYTES)], SUCCESS, SINGLE, SMALL_PAGE_BYTES)
    add('missing-second', [packet(0)], SUCCESS, SINGLE, 0)
    torn = bytearray(base)
    struct.pack_into('<H', torn, len(torn) - wire.WORD_BYTES, wire.USA_SEQUENCE + 1)
    add('torn-first', [packet(0, torn, code=CORRUPT), packet(SMALL_PAGE_BYTES)], SUCCESS, SINGLE, SMALL_PAGE_BYTES)
    add('torn-second', [packet(0), packet(SMALL_PAGE_BYTES, torn, code=CORRUPT)], SUCCESS, SINGLE, 0)
    add('both-torn', [packet(0, torn, code=CORRUPT), packet(SMALL_PAGE_BYTES, torn, code=CORRUPT)], CORRUPT, 0)
    add('no-restart', [], CORRUPT, 0)
    divergent, divergent_fields = restart(flags=0)
    add('equal-lsn-conflict', [packet(0), packet(SMALL_PAGE_BYTES, divergent, divergent_fields)], UNSUPPORTED, CONFLICT)
    incompatible, incompatible_fields = restart(sequence_bits=base_fields['sequence_bits'] - 1)
    add('geometry-conflict', [packet(0), packet(SMALL_PAGE_BYTES, incompatible, incompatible_fields)], UNSUPPORTED, CONFLICT)
    fast, fast_fields = restart(major=wire.FAST_MAJOR, minor=wire.FAST_MINOR)
    add('fast', [packet(0, fast, fast_fields), packet(SMALL_PAGE_BYTES, fast, fast_fields)], SUCCESS, EQUAL, 0)
    add('version-conflict', [packet(0), packet(SMALL_PAGE_BYTES, fast, fast_fields)], UNSUPPORTED, CONFLICT)
    unknown = bytearray(base)
    wire.RESTART_HEADER.put(unknown, 'major', wire.UNSUPPORTED_MAJOR)
    add('unknown-second', [packet(0), packet(SMALL_PAGE_BYTES, unknown, code=UNSUPPORTED, full=False)], UNSUPPORTED, 0)
    chkd = bytearray(base)
    wire.RESTART_HEADER.put(chkd, 'magic', b'CHKD')
    add('chkd-first', [packet(0, chkd, code=UNSUPPORTED, full=False), packet(SMALL_PAGE_BYTES)], UNSUPPORTED, 0)
    for name, options in (
        ('system-4096', dict(system=wire.PAGE_BYTES)),
        ('ordinary-4096', dict(system=wire.PAGE_BYTES, log=wire.PAGE_BYTES, file_bytes=wire.FILE_BYTES)),
        ('maximum-page', dict(system=wire.MAX_PAGE_BYTES, log=wire.PAGE_BYTES, file_bytes=wire.FILE_BYTES)),
        ('larger-record-page', dict(system=wire.PAGE_BYTES // 2, log=wire.PAGE_BYTES, file_bytes=wire.FILE_BYTES)),
        ('unpaired-client', dict(clients=[wire.client(
            oldest=base_fields['current_lsn'], restart=base_fields['current_lsn'], name=(ord('N'), 0xd800))])),
    ):
        raw, fields = restart(**options)
        add(name, [packet(0, raw, fields), packet(fields['system_page_bytes'], raw, fields)],
            SUCCESS, EQUAL, 0, size=fields['file_bytes'])
    (output / 'manifest.json').write_text(json.dumps(dict(cases=cases), indent=2) + '\n')
    lines = []
    for case in cases:
        fields = case['fields'] or {}
        lines.append('\t'.join(map(str, (case['path'], case['code'], case['selection'],
            case['selected_offset'] or 0, fields.get('current_lsn', 0), fields.get('system_page_bytes', 0),
            fields.get('log_page_bytes', 0), case['read_calls'], case['read_bytes'], case['page_code']))))
    (output / 'cases.tsv').write_text('\n'.join(lines) + '\n')
    return cases


if __name__ == '__main__':
    author(Path(sys.argv[1]))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text('original-logfile-sources\n')
