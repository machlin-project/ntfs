#!/usr/bin/env python3
"""Original physical journal graphs with complete ordered metadata oracles."""
from pathlib import Path
import hashlib
import json
import struct
import sys
import logfile_fixtures as w
from logfile_source_fixtures import restart

SUCCESS, INVALID, CORRUPT, UNSUPPORTED, NOT_FOUND = 0, 9, 2, 3, 6
CIRCULAR, LEGACY_TAIL, FAST_STORAGE = 0, 1, 2
FAST_PAGE_BYTES = 4096
BASE_FILE_BYTES = 1024 * 1024
LARGE_FILE_BYTES = 4 * BASE_FILE_BYTES
SMALL_FILE_BYTES = 32 * 1024
CLIENT_RESTART_PAGE = 0x00000002
UNKNOWN_PAGE_FLAG = 0x00000004
FILL_BYTE = 0x79
TORN_SEQUENCE = 0x3344
FAST_USA_WORDS = FAST_PAGE_BYTES // w.USA_STRIDE + 1
FAST = w.Layout(w.PAGE.fields + (
    ('usa_capacity', f'{FAST_USA_WORDS * w.WORD_BYTES}s'),
    ('usa_padding', 'H'), ('file_offset', 'I')))
MAX_DWORD = (1 << (struct.calcsize('<I') * w.BITS_PER_BYTE)) - 1
ROW_FIELDS = ('offset', 'storage', 'code', 'target_code', 'target_offset',
              'copy_value', 'last_end_lsn', 'flags', 'page_count',
              'page_position', 'next_record_offset')


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    cases = []

    def graph(name, *, major=w.FAST_MAJOR, minor=w.FAST_MINOR,
              system=FAST_PAGE_BYTES, log=FAST_PAGE_BYTES, data_offset=FAST.size,
              file_bytes=BASE_FILE_BYTES, extra_bytes=0, faults=False):
        copies = w.FAST_PAGES if major == w.FAST_MAJOR else w.LEGACY_TAIL_PAGES
        start = w.RESTART_PAGES * system
        circular = start + copies * log
        current = w.lsn_at(circular + data_offset, file_bytes)
        raw, _ = restart(major=major, minor=minor, system=system, log=log,
            file_bytes=file_bytes, current=current, page_data_offset=data_offset)
        source = bytearray(file_bytes + extra_bytes)
        for index in range(w.RESTART_PAGES):
            source[index * system:index * system + len(raw)] = raw
        rows = {offset: dict(offset=offset, storage=CIRCULAR if offset >= circular else
                FAST_STORAGE if major == w.FAST_MAJOR else LEGACY_TAIL,
                code=NOT_FOUND, target_code=INVALID, target_offset=0, page=None)
                for offset in range(start, file_bytes - file_bytes % log, log)}
        return dict(name=name, source=source, rows=rows, major=major, log=log,
                    system=system, file_bytes=file_bytes, data_offset=data_offset,
                    circular=circular, current=current, faults=faults)

    def put(g, offset, *, target=None, epoch=None, ending=None, flags=w.RECORD_END,
            count=1, position=1, next_record=None, usa_offset=w.PAGE.size,
            code=SUCCESS, target_code=SUCCESS, torn=False, magic=b'RCRD'):
        logical_target = offset if offset >= g['circular'] else (
            g['circular'] if target is None else target)
        if epoch is None:
            epoch = w.lsn_at(g['circular'] + g['data_offset'], g['file_bytes'])
            if logical_target >= g['circular'] and logical_target < g['file_bytes']:
                epoch = w.lsn_at(logical_target + g['data_offset'], g['file_bytes'])
        if ending is None:
            ending = epoch
        if next_record is None:
            next_record = w.aligned(g['data_offset'] + w.RECORD.size)
        storage = g['rows'][offset]['storage']
        copy_value = logical_target if storage == LEGACY_TAIL else epoch
        fields = dict(copy_value=copy_value, last_end_lsn=ending, flags=flags,
                      page_count=count, page_position=position, next_record_offset=next_record)
        logical = bytearray([FILL_BYTE]) * g['log']
        logical[:w.PAGE.size] = w.PAGE.pack(dict(magic=magic, usa_offset=usa_offset, **fields))
        if storage == FAST_STORAGE and g['log'] >= FAST.size:
            FAST.put(logical, 'file_offset', logical_target)
        raw, _ = w.protect(logical, w.PAGE)
        if torn:
            raw = bytearray(raw)
            struct.pack_into('<H', raw, g['log'] - w.WORD_BYTES, TORN_SEQUENCE)
        g['source'][offset:offset + g['log']] = raw
        g['rows'][offset] = dict(offset=offset, storage=storage, code=code,
            target_code=target_code if code == SUCCESS else INVALID,
            target_offset=logical_target if code == SUCCESS and target_code != UNSUPPORTED else 0,
            page=fields if code == SUCCESS else None)

    def finish(g):
        filename = g['name'] + '.journal'
        (output / filename).write_bytes(g['source'])
        rows = list(g['rows'].values())
        routed = [row for row in rows if row['code'] == SUCCESS and row['target_code'] == SUCCESS]
        epochs = [row['page']['last_end_lsn'] if row['storage'] == LEGACY_TAIL else
                  row['page']['copy_value'] for row in routed]
        endings = [row['page']['last_end_lsn'] for row in routed
                   if row['page']['flags'] & w.RECORD_END]
        summary = dict(complete=True, total_pages=len(rows), examined_pages=len(rows),
            visited_pages=len(rows), decoded_pages=sum(row['code'] == SUCCESS for row in rows),
            missing_pages=sum(row['code'] == NOT_FOUND for row in rows),
            corrupt_pages=sum(row['code'] == CORRUPT for row in rows),
            invalid_targets=sum(row['code'] == SUCCESS and row['target_code'] not in
                                (SUCCESS, UNSUPPORTED) for row in rows),
            unsupported_targets=sum(row['code'] == SUCCESS and row['target_code'] == UNSUPPORTED
                                    for row in rows),
            read_calls=len(rows), read_bytes=len(rows) * g['log'],
            next_offset=g['file_bytes'] - g['file_bytes'] % g['log'],
            max_observed_epoch_lsn=max(epochs, default=0), max_observed_end_lsn=max(endings, default=0))
        row_lines = []
        for row in rows:
            flattened = dict(row)
            flattened.update(row['page'] or dict.fromkeys(ROW_FIELDS[5:], 0))
            row_lines.append(' '.join(str(flattened[key]) for key in ROW_FIELDS))
        (output / (filename + '.rows')).write_text('\n'.join(row_lines) + '\n')
        cases.append(dict(path=filename, log_page_bytes=g['log'],
            system_page_bytes=g['system'], restart_current_lsn=g['current'], rows=rows,
            inventory=summary, faults=g['faults'],
            source_sha256=hashlib.sha256(g['source']).hexdigest()))

    for slot in range(w.FAST_PAGES):
        g = graph(f'later-fast-slot-{slot:02}', faults=slot == 0)
        newer = w.lsn_at(g['circular'] + g['data_offset'] + w.ALIGNMENT, g['file_bytes'])
        put(g, g['circular'])
        put(g, w.RESTART_PAGES * g['system'] + slot * g['log'], epoch=newer)
        finish(g)

    for log in (w.USA_STRIDE, FAST_PAGE_BYTES, w.MAX_PAGE_BYTES):
        data_offset = w.aligned(w.PAGE.size + (log // w.USA_STRIDE + 1) * w.WORD_BYTES)
        g = graph(f'legacy-{log}', major=w.LEGACY_MAJOR, minor=w.LEGACY_MINOR,
                  system=log, log=log, data_offset=data_offset,
                  file_bytes=LARGE_FILE_BYTES if log == w.MAX_PAGE_BYTES else
                  SMALL_FILE_BYTES if log == w.USA_STRIDE else BASE_FILE_BYTES,
                  faults=log == w.USA_STRIDE)
        put(g, w.RESTART_PAGES * log)
        put(g, g['circular'])
        put(g, g['file_bytes'] - log)
        finish(g)

    g = graph('fast-usa-touching-target')
    put(g, w.RESTART_PAGES * g['system'], usa_offset=w.PAGE.size + w.WORD_BYTES)
    finish(g)
    g = graph('fast-usa-overlapping-target', data_offset=FAST.size + w.ALIGNMENT)
    put(g, w.RESTART_PAGES * g['system'], usa_offset=w.PAGE.size + 2 * w.WORD_BYTES,
        target_code=UNSUPPORTED)
    finish(g)
    g = graph('fast-extended-data-offset', data_offset=2 * FAST.size)
    put(g, w.RESTART_PAGES * g['system'])
    put(g, g['circular'])
    finish(g)
    g = graph('fast-other-page-layout', log=2 * FAST_PAGE_BYTES,
              data_offset=2 * FAST.size)
    put(g, w.RESTART_PAGES * g['system'], target_code=UNSUPPORTED)
    put(g, g['circular'])
    finish(g)
    g = graph('declared-trailing-capacity', extra_bytes=w.ALIGNMENT)
    put(g, g['file_bytes'] - g['log'])
    finish(g)
    g = graph('partial-declared-last-page', file_bytes=BASE_FILE_BYTES + w.ALIGNMENT)
    put(g, g['circular'])
    finish(g)

    for name, options in (
        ('torn', dict(torn=True, code=CORRUPT)),
        ('missing-signature', dict(magic=b'XXXX', code=NOT_FOUND)),
        ('bad-transfer', dict(count=1, position=2, code=CORRUPT)),
        ('bad-zero-transfer', dict(count=0, position=1, code=CORRUPT)),
        ('bad-next', dict(next_record=FAST.size - w.ALIGNMENT, code=CORRUPT)),
        ('bad-end-address', dict(ending=1, code=CORRUPT)),
        ('zero-start', dict(epoch=0, ending=0, target_code=NOT_FOUND)),
        ('bad-start-address', dict(epoch=1, ending=0, target_code=CORRUPT)),
        ('unknown-flags', dict(flags=UNKNOWN_PAGE_FLAG, target_code=UNSUPPORTED)),
        ('incomplete-prefix', dict(flags=0, ending=0, next_record=0)),
    ):
        g = graph('page-' + name)
        put(g, g['circular'], **options)
        finish(g)

    for name, target in (('restart', 0), ('fast', w.RESTART_PAGES * FAST_PAGE_BYTES),
                         ('unaligned', (w.RESTART_PAGES + w.FAST_PAGES) * FAST_PAGE_BYTES + w.ALIGNMENT),
                         ('outside', BASE_FILE_BYTES), ('maximum', MAX_DWORD)):
        g = graph('fast-target-' + name)
        put(g, w.RESTART_PAGES * g['system'], target=target, target_code=CORRUPT)
        finish(g)
    g = graph('fast-reversed-epoch')
    later = w.lsn_at(g['circular'] + g['data_offset'] + w.ALIGNMENT, g['file_bytes'])
    put(g, w.RESTART_PAGES * g['system'], epoch=g['current'], ending=later, target_code=CORRUPT)
    finish(g)
    g = graph('both-epoch-conflicts-visible')
    put(g, w.RESTART_PAGES * g['system'])
    put(g, (w.RESTART_PAGES + w.FAST_PAGES - 1) * g['system'],
        flags=w.RECORD_END | CLIENT_RESTART_PAGE)
    finish(g)
    g = graph('all-missing')
    finish(g)
    g = graph('all-circular-pages')
    for offset in range(g['circular'], g['file_bytes'], g['log']):
        put(g, offset)
    finish(g)

    (output / 'manifest.json').write_text(json.dumps(dict(cases=cases), indent=2) + '\n')
    lines = []
    for case in cases:
        summary = case['inventory']
        lines.append(' '.join(map(str, (case['path'], case['log_page_bytes'],
            summary['total_pages'], summary['decoded_pages'], summary['missing_pages'],
            summary['corrupt_pages'], summary['invalid_targets'], summary['unsupported_targets'],
            summary['max_observed_epoch_lsn'], summary['max_observed_end_lsn'], int(case['faults'])))))
    (output / 'cases.txt').write_text('\n'.join(lines) + '\n')
    virtual = bytearray(2 * w.MAX_PAGE_BYTES)
    raw, _ = restart(major=w.LEGACY_MAJOR, minor=w.LEGACY_MINOR,
        system=w.USA_STRIDE, log=w.USA_STRIDE, file_bytes=w.MAX_FILE_BYTES,
        current=w.lsn_at((w.RESTART_PAGES + w.LEGACY_TAIL_PAGES) * w.USA_STRIDE +
                        w.PAGE_DATA_OFFSET, w.MAX_FILE_BYTES))
    for index in range(w.RESTART_PAGES):
        virtual[index * w.USA_STRIDE:index * w.USA_STRIDE + len(raw)] = raw
    (output / 'maximum-file-prefix.bin').write_bytes(virtual)
    return cases


if __name__ == '__main__':
    result = author(Path(sys.argv[1]))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text(f'{len(result)} original complete physical inventories\n')
