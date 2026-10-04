#!/usr/bin/env python3
"""Original selected-checkpoint/dump records and independent whole-body verdicts."""
from pathlib import Path
import hashlib
import json
import struct
import sys
import logfile_fixtures as w
import logfile_tables_fixtures as t
from logfile_source_fixtures import restart, SMALL_FILE_BYTES, SMALL_PAGE_BYTES
from logfile_checkpoint_fixtures import CLIENT_RESTART, TABLES
from logfile_names_fixtures import entry as name_entry, TERMINATOR

OPEN, NAMES, DIRTY, TRANSACTIONS = range(4)
DUMP_OPERATIONS = (29, 30, 31, 32)
NOOP, COMPENSATION = 0, 1
SUCCESS, CORRUPT, UNSUPPORTED, NOT_FOUND, INVALID, STALE, RANGE = 0, 2, 3, 6, 9, 10, 11
SUMMARY_VALUES = 16
STORED_UPDATE_BYTES = w.UPDATE.size + w.LSN_BYTES
OPAQUE_HEADER_BYTE = 0x6b
OPAQUE_EXTENSION_BYTE = 0x7d
UNKNOWN_STATE = 4
UNKNOWN_RECORD_TYPE = 3
MAX_INPUT_BYTES = 1024 * 1024
OPEN_COUNT = 3
DIRTY_COUNT = 4
TRANSACTION_COUNT = 4
FREE_OPEN_ORDER = (1,)
FREE_DIRTY_ORDER = (1, 3)
FREE_TRANSACTION_ORDER = (1,)
UNPAIRED_UNITS = (0xd800, ord('x'), 0xdc00)
FIRST_NAME_TARGET = t.TABLE.size
SECOND_NAME_TARGET = FIRST_NAME_TARGET + t.OPEN_BASE.size


def summary(*values):
    assert len(values) <= SUMMARY_VALUES
    return list(values) + [0] * (SUMMARY_VALUES - len(values))


def make_body(kind, major, count=None):
    if kind == NAMES:
        first, _ = name_entry(FIRST_NAME_TARGET, tuple(map(ord, '$I30')))
        second, _ = name_entry(SECOND_NAME_TARGET, UNPAIRED_UNITS)
        return first + second + TERMINATOR, [0] * 6 + [0, len(first) + len(second), 2]
    layout = t.OPEN_BASE if major == 0 else t.OPEN
    free = FREE_OPEN_ORDER
    values = dict(allocated=t.ALLOCATED, reference=t.REFERENCE, open_lsn=t.OPEN_LSN,
        attribute_type=t.ATTRIBUTE_TYPE, index_buffer_bytes=t.INDEX_BYTES,
        attribute_offset=t.LEGACY_ATTRIBUTE_OFFSET, name_pointer=t.OPAQUE_POINTER,
        dirty_pages=t.STALE_BYTE)
    size = layout.size
    count = {OPEN: OPEN_COUNT, DIRTY: DIRTY_COUNT, TRANSACTIONS: TRANSACTION_COUNT}[kind] if count is None else count
    suffix = b''
    if kind == DIRTY:
        layout = t.DIRTY_BASE if major == 0 else t.DIRTY
        suffix = b''.join(t.LCN.pack(lcn) for lcn in t.LCNS)
        size = layout.size + len(suffix) + t.LCN.size
        free = FREE_DIRTY_ORDER
        values = dict(allocated=t.ALLOCATED, target_attribute=FIRST_NAME_TARGET,
            transfer_bytes=t.TRANSFER_BYTES, lcns=len(t.LCNS), vcn=t.TARGET_VCN,
            oldest_lsn=t.FIRST_LSN)
    elif kind == TRANSACTIONS:
        layout = t.TRANSACTION
        size = layout.size
        free = FREE_TRANSACTION_ORDER
        values = dict(allocated=t.ALLOCATED, state=1, first_lsn=t.FIRST_LSN,
            previous_lsn=t.PREVIOUS_LSN, undo_next_lsn=t.UNDO_LSN,
            undo_records=t.UNDO_RECORDS, undo_bytes=t.UNDO_BYTES)
    body, _ = t.table(size, count, tuple(i for i in free if i < count))
    for index in range(count):
        offset = t.TABLE.size + index * size
        if index not in free:
            current = dict(values)
            if kind == TRANSACTIONS:
                current['state'] = index
            body[offset:offset + layout.size] = layout.pack(current)
            if suffix:
                body[offset + layout.size:offset + layout.size + len(suffix)] = suffix
    header = {name: struct.unpack_from('<' + form, body, t.TABLE.offsets[name])[0]
        for name, form in t.TABLE.fields if not form.endswith('s')}
    fields = [header['entry_bytes'], header['entries'], header['allocated'], header['free_goal'],
        header['first_free'], header['last_free'], t.TABLE.size, count * size, 0]
    return bytes(body), fields


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    cases, owners = [], {}

    def owner(name, *, major=0, header_bytes=w.RECORD.size, fast=False,
              sequence=w.CLIENT_SEQUENCE, extension=0, file_bytes=SMALL_FILE_BYTES):
        log = SMALL_PAGE_BYTES
        circular = w.RESTART_PAGES * log + (w.FAST_PAGES if fast else w.LEGACY_TAIL_PAGES) * log
        anchor = w.lsn_at(circular + w.PAGE_DATA_OFFSET, file_bytes)
        checkpoint_lsn = w.lsn_at(circular + log + w.PAGE_DATA_OFFSET, file_bytes)
        client, _ = w.client(oldest=anchor, restart=checkpoint_lsn, sequence=sequence)
        page, _ = restart(clients=[(client, {})], current=checkpoint_lsn,
            file_bytes=file_bytes, major=w.FAST_MAJOR if fast else w.LEGACY_MAJOR,
            minor=w.FAST_MINOR if fast else w.LEGACY_MINOR,
            record_header_bytes=header_bytes)
        page = bytearray(page)
        area_offset = struct.unpack_from('<H', page, w.RESTART_HEADER.offsets['area_offset'])[0]
        w.RESTART_AREA.put(page, 'last_data_bytes', CLIENT_RESTART.size + extension, area_offset)
        source = bytearray(file_bytes)
        for index in range(w.RESTART_PAGES):
            source[index * log:(index + 1) * log] = page
        path = name + '.journal'
        (output / path).write_bytes(source)
        value = dict(source=path, major=major, header_bytes=header_bytes, anchor=anchor,
            checkpoint_lsn=checkpoint_lsn, sequence=sequence, extension=extension,
            file_bytes=file_bytes)
        owners[name] = value
        return value

    def records(selected, kind, body):
        fields = dict(major=selected['major'], minor=0, analysis_lsn=selected['anchor'])
        fields[TABLES[kind] + '_lsn'] = selected['anchor']
        fields[TABLES[kind] + '_bytes'] = len(body)
        prefix = CLIENT_RESTART.pack(fields) + bytes([OPAQUE_EXTENSION_BYTE]) * selected['extension']
        extension = bytes([OPAQUE_HEADER_BYTE]) * (selected['header_bytes'] - w.RECORD.size)
        common = dict(client_sequence=selected['sequence'], client_index=0)
        checkpoint = w.RECORD.pack(dict(common, lsn=selected['checkpoint_lsn'],
            data_bytes=len(prefix), type=w.RESTART_TYPE)) + extension + prefix
        update = w.UPDATE.pack(dict(redo_operation=DUMP_OPERATIONS[kind],
            undo_operation=NOOP, redo_offset=STORED_UPDATE_BYTES, redo_bytes=len(body)))
        update += struct.pack('<Q', w.UNUSED_LCN_SLOT) + body
        table = w.RECORD.pack(dict(common, lsn=selected['anchor'],
            data_bytes=len(update), type=w.UPDATE_TYPE, transaction=w.TRANSACTION)) + extension + update
        return bytes(checkpoint), bytes(table)

    def add(name, selected, kind, body, code=SUCCESS, *, checkpoint=None, table=None, values=None):
        first, second = records(selected, kind if kind in range(len(TABLES)) else OPEN, body)
        checkpoint = first if checkpoint is None else bytes(checkpoint)
        table = second if table is None else bytes(table)
        assert len({c['name'] for c in cases}) == len(cases)
        (output / (name + '.checkpoint')).write_bytes(checkpoint)
        (output / (name + '.table')).write_bytes(table)
        if code == SUCCESS:
            expected = summary(kind, selected['major'], 0, selected['checkpoint_lsn'],
                selected['anchor'], selected['header_bytes'] + STORED_UPDATE_BYTES, len(body),
                *values)
        else:
            expected = summary()
        (output / (name + '.expected')).write_text(' '.join(map(str, expected)) + '\n')
        cases.append(dict(name=name, source=selected['source'], kind=kind, code=code,
            expected=expected, checkpoint_bytes=len(checkpoint), table_bytes=len(table),
            checkpoint_sha256=hashlib.sha256(checkpoint).hexdigest(),
            table_sha256=hashlib.sha256(table).hexdigest(),
            transport=len(checkpoint) == 0 or len(checkpoint) > MAX_INPUT_BYTES or
                len(table) > MAX_INPUT_BYTES or kind not in range(len(TABLES))))

    base = owner('base')
    for major in (0, 1):
        for extended in (False, True):
            selected = owner(f'client-{major}-extended-{int(extended)}', major=major,
                header_bytes=w.EXTENDED_RECORD_HEADER_BYTES if extended else w.RECORD.size,
                extension=48 if extended else 0, fast=extended)
            for kind in range(len(TABLES)):
                body, values = make_body(kind, major)
                add(f'client-{major}-extended-{int(extended)}-kind-{kind}', selected,
                    kind, body, values=values)
    body, values = make_body(OPEN, 0)
    first, second = records(base, OPEN, body)
    prefix_base = base['header_bytes']
    update_base = base['header_bytes']
    for kind in range(len(TABLES)):
        empty = bytearray(first)
        CLIENT_RESTART.put(empty, TABLES[OPEN] + '_lsn', 0, prefix_base)
        CLIENT_RESTART.put(empty, TABLES[OPEN] + '_bytes', 0, prefix_base)
        add(f'absent-kind-{kind}', base, kind, body, NOT_FOUND, checkpoint=empty, table=b'')
    for name, field, value, code in (
        ('missing-anchor', 'open_attributes_lsn', 0, CORRUPT),
        ('missing-length', 'open_attributes_bytes', 0, CORRUPT),
        ('future-anchor', 'open_attributes_lsn', base['checkpoint_lsn'] + w.ALIGNMENT, CORRUPT),
        ('self-anchor', 'open_attributes_lsn', base['checkpoint_lsn'], CORRUPT),
        ('anchor-in-restart-page', 'open_attributes_lsn', w.lsn_at(w.PAGE_DATA_OFFSET, SMALL_FILE_BYTES), CORRUPT),
        ('over-cap-anchor', 'open_attributes_bytes', MAX_INPUT_BYTES + 1, RANGE),
        ('wrong-length', 'open_attributes_bytes', len(body) + 1, CORRUPT),
        ('unknown-client-version', 'major', 2, UNSUPPORTED),
    ):
        changed = bytearray(first)
        CLIENT_RESTART.put(changed, field, value, prefix_base)
        add(name, base, OPEN, body, code, checkpoint=changed)
    for name, field, value, code in (
        ('stale-checkpoint-lsn', 'lsn', base['checkpoint_lsn'] + w.ALIGNMENT, STALE),
        ('stale-checkpoint-sequence', 'client_sequence', w.CLIENT_SEQUENCE + 1, STALE),
        ('absent-checkpoint-client', 'client_index', 1, STALE),
        ('checkpoint-update-type', 'type', w.UPDATE_TYPE, UNSUPPORTED),
    ):
        changed = bytearray(first)
        w.RECORD.put(changed, field, value)
        add(name, base, OPEN, body, code, checkpoint=changed)
    for name, field, value, code in (
        ('stale-table-lsn', 'lsn', base['anchor'] + w.ALIGNMENT, STALE),
        ('foreign-table-client', 'client_index', 1, STALE),
        ('foreign-table-sequence', 'client_sequence', w.CLIENT_SEQUENCE + 1, STALE),
        ('table-restart-type', 'type', w.RESTART_TYPE, UNSUPPORTED),
        ('table-unknown-type', 'type', UNKNOWN_RECORD_TYPE, UNSUPPORTED),
        ('table-unknown-flags', 'flags', w.UNKNOWN_RECORD_FLAG, UNSUPPORTED),
        ('bad-previous-geometry', 'previous_lsn', w.lsn_at(w.PAGE_DATA_OFFSET, SMALL_FILE_BYTES, sequence=1), CORRUPT),
        ('bad-undo-geometry', 'undo_next_lsn', w.lsn_at(w.PAGE_DATA_OFFSET, SMALL_FILE_BYTES, sequence=1), CORRUPT),
    ):
        changed = bytearray(second)
        w.RECORD.put(changed, field, value)
        add(name, base, OPEN, body, code, table=changed)
    for name, field, value, code in (
        ('wrong-dump-opcode', 'redo_operation', DUMP_OPERATIONS[DIRTY], UNSUPPORTED),
        ('undo-action', 'undo_operation', COMPENSATION, UNSUPPORTED),
        ('lcn-vector', 'lcns', 1, UNSUPPORTED),
        ('body-before-stored-prefix', 'redo_offset', w.UPDATE.size, CORRUPT),
        ('short-body-span', 'redo_bytes', len(body) - 1, CORRUPT),
        ('nonempty-undo', 'undo_offset', STORED_UPDATE_BYTES, UNSUPPORTED),
    ):
        changed = bytearray(second)
        w.UPDATE.put(changed, field, value, update_base)
        if name == 'nonempty-undo':
            w.UPDATE.put(changed, 'undo_bytes', w.LSN_BYTES, update_base)
        add(name, base, OPEN, body, code, table=changed)
    for length in range(1, w.RECORD.size + STORED_UPDATE_BYTES):
        changed = bytearray(second[:length])
        if length >= w.RECORD.size:
            w.RECORD.put(changed, 'data_bytes', length - w.RECORD.size)
        add(f'truncated-table-prefix-{length}', base, OPEN, body, CORRUPT, table=changed)
    add('empty-checkpoint', base, OPEN, body, CORRUPT, checkpoint=b'')
    add('over-cap-table-record', base, OPEN, body, RANGE, table=bytes(MAX_INPUT_BYTES + 1))
    add('invalid-kind', base, len(TABLES), body, INVALID)
    broken = bytearray(body)
    t.TABLE.put(broken, 'allocated', OPEN_COUNT)
    add('bad-free-topology', base, OPEN, broken, CORRUPT)
    for kind in (OPEN, DIRTY, TRANSACTIONS):
        unsupported, _ = t.table(t.LINK.size, OPEN_COUNT, FREE_OPEN_ORDER)
        add(f'unsupported-entry-size-kind-{kind}', base, kind, unsupported, UNSUPPORTED)
    for kind in (DIRTY, TRANSACTIONS):
        raw, fields = make_body(kind, 0)
        broken = bytearray(raw)
        if kind == DIRTY:
            t.DIRTY_BASE.put(broken, 'lcns', len(t.LCNS) + 2, t.TABLE.size)
            code = CORRUPT
        else:
            t.TRANSACTION.put(broken, 'state', UNKNOWN_STATE, t.TABLE.size)
            code = UNSUPPORTED
        add(f'bad-allocated-entry-kind-{kind}', base, kind, broken, code)
    raw, fields = make_body(TRANSACTIONS, 0)
    stale_free = bytearray(raw)
    t.TRANSACTION.put(stale_free, 'state', UNKNOWN_STATE,
        t.TABLE.size + t.TRANSACTION.size * FREE_TRANSACTION_ORDER[0])
    add('stale-free-transaction', base, TRANSACTIONS, stale_free, values=fields)
    names, fields = make_body(NAMES, 0)
    add('truncated-name-dump', base, NAMES, names[:-1], CORRUPT)
    add('trailing-name-dump', base, NAMES, names + bytes(w.WORD_BYTES), CORRUPT)
    empty, _ = t.table(t.OPEN_BASE.size, 0, ())
    add('empty-open-table', base, OPEN, empty, values=[t.OPEN_BASE.size, 0, 0, t.ALLOCATED,
        0, 0, t.TABLE.size, 0, 0])
    maximum = ((1 << (w.WORD_BYTES * w.BITS_PER_BYTE)) - 1 - t.TABLE.size) // t.OPEN_BASE.size
    large = owner('large', file_bytes=w.FILE_BYTES)
    raw, fields = make_body(OPEN, 0, maximum)
    add('large-complete-open-table', large, OPEN, raw, values=fields)
    (output / 'manifest.json').write_text(json.dumps(dict(cases=cases, owners=owners), indent=2) + '\n')
    (output / 'cases.tsv').write_text('\n'.join(
        f"{c['name']} {c['source']} {c['name']}.checkpoint {c['name']}.table {c['kind']} {c['code']}"
        for c in cases) + '\n')
    return cases


if __name__ == '__main__':
    author(Path(sys.argv[1]))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text('original-selected-checkpoint-table-bindings\n')
