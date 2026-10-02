#!/usr/bin/env python3
"""Author original selected-client snapshots, exact records and independent verdicts."""
from pathlib import Path
import json
import sys

import logfile_fixtures as w
import logfile_checkpoint_fixtures as prefix
from logfile_source_fixtures import restart, SMALL_FILE_BYTES, SMALL_PAGE_BYTES

SUCCESS, CORRUPT, UNSUPPORTED, STALE, RANGE = 0, 2, 3, 10, 11
RESULTS = dict(prefix.RESULTS)
RESULTS[STALE] = 'stale file reference'
RESTART_TYPE = 2
UNKNOWN_TYPE = 3
UNKNOWN_FLAGS = 0x8000
MAX_SEQUENCE = (1 << (w.WORD_BYTES * w.BITS_PER_BYTE)) - 1
STALE_FREE_LSN = (1 << w.LSN_BITS) - 1
OPAQUE_HEADER_BYTE = 0x6b
UNPAIRED_NAME_UNIT = 0xd800
DEFAULT_PAYLOAD_NAME = 'base-fields.payload'
MIXED_ACTIVE_ORDER = (2, 0)
MIXED_CLIENT_COUNT = 3


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    payload_cases = prefix.author(output / 'payloads')
    payload_by_path = {case['path']: case for case in payload_cases}
    default_expected = payload_by_path[DEFAULT_PAYLOAD_NAME]['expected']
    cases = []

    def source(name, *, sequence=w.CLIENT_SEQUENCE, name_units=None, restart_lsn=None,
               free=False, empty=False, system=SMALL_PAGE_BYTES, log=SMALL_PAGE_BYTES,
               file_bytes=SMALL_FILE_BYTES, major=w.LEGACY_MAJOR, minor=w.LEGACY_MINOR,
               header_bytes=w.RECORD.size, active_order=None, count=1, newer_second=False):
        circular = w.RESTART_PAGES * system + (
            w.FAST_PAGES if major == w.FAST_MAJOR else w.LEGACY_TAIL_PAGES) * log
        lsn = w.lsn_at(circular + w.PAGE_DATA_OFFSET, file_bytes)
        current = lsn + w.ALIGNMENT if newer_second else lsn
        active = list(active_order) if active_order is not None else ([] if free or empty else [0])
        free_order = [index for index in range(count) if index not in active] if not empty else []
        entries = []
        for index in range(0 if empty else count):
            chain = active if index in active else free_order
            position = chain.index(index)
            chosen = current if restart_lsn is None else restart_lsn
            if index not in active and restart_lsn is None:
                chosen = STALE_FREE_LSN
            options = dict(oldest=current if index in active else STALE_FREE_LSN,
                restart=chosen, previous=chain[position - 1] if position else w.NO_CLIENT,
                following=chain[position + 1] if position + 1 < len(chain) else w.NO_CLIENT,
                sequence=(sequence + index) & MAX_SEQUENCE)
            if name_units is not None:
                options['name'] = name_units
            entries.append(w.client(**options))
        raw, fields = restart(system=system, log=log, file_bytes=file_bytes, major=major,
            minor=minor, clients=entries, current=0 if empty else current,
            in_use_head=active[0] if active else w.NO_CLIENT,
            free_head=free_order[0] if free_order else w.NO_CLIENT,
            record_header_bytes=header_bytes)
        data = bytearray(file_bytes)
        for position in range(w.RESTART_PAGES):
            data[position * system:(position + 1) * system] = raw
        if newer_second:
            old, _ = restart(system=system, log=log, file_bytes=file_bytes, major=major,
                minor=minor, current=lsn, record_header_bytes=header_bytes)
            data[:system] = old
        path = name + '.journal'
        (output / path).write_bytes(data)
        return dict(path=path, fields=fields, header_bytes=header_bytes,
                    lsn=current, sequence=sequence)

    def packet(owner, payload, **changes):
        values = dict(lsn=owner['lsn'], client_sequence=owner['sequence'], client_index=0,
                      type=RESTART_TYPE, data_bytes=len(payload))
        values.update(changes)
        extension = bytes([OPAQUE_HEADER_BYTE]) * (owner['header_bytes'] - w.RECORD.size)
        return w.RECORD.pack(values) + extension + payload

    def add(name, owner, payload, code=SUCCESS, *, expected=None, record=None, **changes):
        raw = packet(owner, payload, **changes) if record is None else record
        if len(raw) > prefix.MAX_PACKET_BYTES:
            code = RANGE
        value = dict(default_expected if expected is None else expected)
        if code != SUCCESS:
            value = prefix.report({}, 0, CORRUPT)
        value.update(scope='client-restart-record', code=code, result=RESULTS[code])
        path = name + '.record'
        (output / path).write_bytes(raw)
        cases.append(dict(path=path, source=owner['path'], code=code, expected=value,
                          transport=len(raw) == 0 or len(raw) > prefix.MAX_PACKET_BYTES))

    base = source('base')
    for case in payload_cases:
        payload = (output / 'payloads' / case['path']).read_bytes()
        add('payload-' + Path(case['path']).stem, base, payload, case['code'], expected=case['expected'])
    payload = (output / 'payloads' / DEFAULT_PAYLOAD_NAME).read_bytes()
    for name, options in (
        ('zero-sequence', dict(sequence=0)),
        ('maximum-sequence', dict(sequence=MAX_SEQUENCE)),
        ('extended-header', dict(header_bytes=w.EXTENDED_RECORD_HEADER_BYTES)),
        ('fast-pages', dict(major=w.FAST_MAJOR, minor=w.FAST_MINOR)),
        ('newer-second', dict(newer_second=True)),
        ('mixed-active-order', dict(active_order=MIXED_ACTIVE_ORDER,
            count=MIXED_CLIENT_COUNT, system=w.PAGE_BYTES)),
    ):
        owner = source(name, **options)
        add(name, owner, payload)
    maximum_area = max(w.RESTART_OFFSET, w.aligned(w.RESTART_HEADER.size +
        (w.MAX_PAGE_BYTES // w.USA_STRIDE + 1) * w.WORD_BYTES))
    maximum_count = (w.MAX_PAGE_BYTES - maximum_area - w.CLIENTS_OFFSET) // w.CLIENT.size
    owner = source('maximum-active-chain', count=maximum_count,
        active_order=reversed(range(maximum_count)), system=w.MAX_PAGE_BYTES,
        log=w.PAGE_BYTES, file_bytes=w.FILE_BYTES)
    add('maximum-active-chain', owner, payload)
    add('wrong-sequence', base, payload, STALE, client_sequence=w.CLIENT_SEQUENCE + 1)
    add('absent-index', base, payload, STALE, client_index=1)
    add('sentinel-index', base, payload, CORRUPT, client_index=w.NO_CLIENT)
    owner = source('free-client', free=True)
    add('free-client', owner, payload, STALE, lsn=STALE_FREE_LSN)
    owner = source('empty-clients', empty=True)
    add('empty-clients', owner, payload, STALE, lsn=base['lsn'])
    owner = source('missing-restart-lsn', restart_lsn=0)
    add('missing-restart-lsn', owner, payload, STALE)
    add('older-lsn', base, payload, STALE, lsn=base['lsn'] - w.ALIGNMENT)
    add('newer-lsn', base, payload, STALE, lsn=base['lsn'] + w.ALIGNMENT)
    names = (
        ('lowercase-client', tuple(map(ord, 'ntfs'))),
        ('other-client', tuple(map(ord, 'OTHER'))),
        ('short-client-name', tuple(map(ord, 'NTF'))),
        ('long-client-name', tuple(map(ord, 'NTFSX'))),
        ('nul-client-name', (*map(ord, 'NTFS'), 0)),
        ('unpaired-client-name', (*map(ord, 'NTFS'), UNPAIRED_NAME_UNIT)),
        ('maximum-client-name', (*map(ord, 'NTFS'), *(UNPAIRED_NAME_UNIT for _ in range(
            w.CLIENT_NAME_BYTES // w.WORD_BYTES - len('NTFS'))))),
    )
    for name, units in names:
        add(name, source(name, name_units=units), payload, UNSUPPORTED)
    for name, code, changes in (
        ('update-record', UNSUPPORTED, dict(type=w.UPDATE_TYPE)),
        ('unknown-record-type', UNSUPPORTED, dict(type=UNKNOWN_TYPE)),
        ('unknown-record-flags', UNSUPPORTED, dict(flags=UNKNOWN_FLAGS)),
        ('zero-record-lsn', CORRUPT, dict(lsn=0)),
        ('previous-not-older', CORRUPT, dict(previous_lsn=base['lsn'])),
        ('undo-not-older', CORRUPT, dict(undo_next_lsn=base['lsn'])),
        ('short-declared-payload', CORRUPT, dict(data_bytes=len(payload) - 1)),
        ('long-declared-payload', CORRUPT, dict(data_bytes=len(payload) + 1)),
    ):
        add(name, base, payload, code, **changes)
    bad_payload = (output / 'payloads/unknown-major.payload').read_bytes()
    add('stale-before-payload', base, bad_payload, STALE, client_sequence=w.CLIENT_SEQUENCE + 1)
    add('type-before-payload', base, bad_payload, UNSUPPORTED, type=w.UPDATE_TYPE)
    owner = source('name-before-payload', name_units=tuple(map(ord, 'OTHER')))
    add('name-before-payload', owner, bad_payload, UNSUPPORTED)
    raw = packet(base, payload)
    add('truncated-payload-framing', base, payload, CORRUPT, record=raw[:-1])
    add('trailing-alignment-framing', base, payload, CORRUPT, record=raw + bytes(w.ALIGNMENT))
    for size in range(w.RECORD.size):
        add(f'truncated-record-{size:02}', base, payload, CORRUPT, record=raw[:size])
    for name, flag in (('multi-page-flag', w.MULTI_PAGE), ('deleting-flag', w.RECORD_DELETING),
                       ('adding-flag', w.RECORD_ADDING)):
        add(name, base, payload, flags=flag)
    cap_payload = payload + bytes([prefix.OPAQUE_BYTE]) * (
        prefix.MAX_PACKET_BYTES - w.RECORD.size - len(payload))
    cap_expected = dict(default_expected, extension=dict(
        offset=prefix.CLIENT_RESTART.size,
        length=len(cap_payload) - prefix.CLIENT_RESTART.size))
    add('exact-record-cap', base, cap_payload, expected=cap_expected)
    add('over-record-cap', base, cap_payload, record=packet(base, cap_payload) + b'\0', code=RANGE)
    (output / 'cases.json').write_text(json.dumps(cases, indent=2) + '\n')
    lines = []
    for case in cases:
        value = case['expected']
        row = [case['source'], case['path'], str(case['code']), str(value['major']),
               str(value['minor']), str(value['analysis_lsn'])]
        for table in prefix.TABLES:
            row.extend((str(value[table]['lsn']), str(value[table]['bytes'])))
        row.extend((str(value['extension']['offset']), str(value['extension']['length'])))
        lines.append('\t'.join(row))
    (output / 'cases.tsv').write_text('\n'.join(lines) + '\n')
    return cases


if __name__ == '__main__':
    author(Path(sys.argv[1]))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text('original selected-client restart record fixtures\n')
