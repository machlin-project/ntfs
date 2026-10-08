#!/usr/bin/env python3
"""Independently author LFS/NTFS log packets from named format fields."""
from pathlib import Path
import copy
import json
import struct
import sys

BITS_PER_BYTE = 8
WORD_BYTES = struct.calcsize('<H')
LSN_BYTES = struct.calcsize('<Q')
LSN_BITS = LSN_BYTES * BITS_PER_BYTE
OFFSET_SHIFT = 3
ALIGNMENT = 8
USA_STRIDE = 512
PAGE_BYTES = 4096
FILE_BYTES = 1024 * 1024
LARGE_FILE_BYTES = 8 * FILE_BYTES
MAX_FILE_BYTES = 1 << 32
MAX_PAGE_BYTES = 65536
NO_CLIENT = (1 << 16) - 1
USA_SEQUENCE = 0x1234
RESTART_OFFSET = 64
CLIENTS_OFFSET = 64
PAGE_DATA_OFFSET = 64
RESTART_PAGES = 2
LEGACY_TAIL_PAGES = 2
FAST_PAGES = 32
MIN_RECORD_PAGES = 48
CLIENT_NAME_BYTES = 128
CLEAN = 0x0002
SINGLE_PAGE_IO = 0x0001
LEGACY_MAJOR = 1
LEGACY_MINOR = 1
FAST_MAJOR = 2
FAST_MINOR = 0
UNSUPPORTED_MAJOR = 3
UNSUPPORTED_MINOR = 2
UNKNOWN_RESTART_FLAG = 0x4000
UNKNOWN_RECORD_FLAG = 0x8000
UNKNOWN_PAGE_FLAG = 0x80000000
UPDATE_TYPE = 1
RESTART_TYPE = 2
MULTI_PAGE = 0x0001
RECORD_DELETING = 0x0002
RECORD_ADDING = 0x0004
UPDATE_RESIDENT = 0x0007
COMPENSATION = 0x0001
RECORD_END = 0x00000001
OPEN_COUNT = 19
CLIENT_SEQUENCE = 7
TRANSACTION = 24
TARGET_VCN = 11
TARGET_RECORD_OFFSET = 152
TARGET_ATTRIBUTE_OFFSET = 24
ATTRIBUTE_ACTS_ON_MFT = 0x0002
LSN_SEQUENCE = 2
PHYSICAL_LCN = 87134
UNUSED_LCN_SLOT = 0x8877665544332211
REDO = b'new data'
UNDO = b'old data'
SUCCESS = 'success'
CORRUPT = 'corrupt'
UNSUPPORTED = 'unsupported'
RANGE = 'range'


class Layout:
    """Declarative test wire fields; no parser offsets/constants are imported."""

    def __init__(self, fields):
        self.fields = fields
        self.offsets = {}
        position = 0
        for name, form in fields:
            self.offsets[name] = position
            position += struct.calcsize('<' + form)
        self.size = position

    def pack(self, values):
        output = bytearray(self.size)
        for name, form in self.fields:
            default = bytes(struct.calcsize('<' + form)) if form.endswith('s') else 0
            struct.pack_into('<' + form, output, self.offsets[name], values.get(name, default))
        return output

    def put(self, data, field, value, base=0):
        form = dict(self.fields)[field]
        struct.pack_into('<' + form, data, base + self.offsets[field], value)


RESTART_HEADER = Layout((('magic', '4s'), ('usa_offset', 'H'), ('usa_count', 'H'),
    ('chkdsk_lsn', 'Q'), ('system_page_bytes', 'I'), ('log_page_bytes', 'I'),
    ('area_offset', 'H'), ('minor', 'H'), ('major', 'H')))
RESTART_AREA = Layout((('current_lsn', 'Q'), ('clients', 'H'), ('free_head', 'H'),
    ('in_use_head', 'H'), ('flags', 'H'), ('sequence_bits', 'I'), ('length', 'H'),
    ('clients_offset', 'H'), ('file_bytes', 'Q'), ('last_data_bytes', 'I'),
    ('record_header_bytes', 'H'), ('page_data_offset', 'H'), ('open_count', 'I'),
    ('reserved', 'I')))
CLIENT = Layout((('oldest_lsn', 'Q'), ('restart_lsn', 'Q'), ('previous', 'H'),
    ('next', 'H'), ('sequence', 'H'), ('reserved', '6s'), ('name_bytes', 'I'),
    ('name', f'{CLIENT_NAME_BYTES}s')))
PAGE = Layout((('magic', '4s'), ('usa_offset', 'H'), ('usa_count', 'H'),
    ('copy_value', 'Q'), ('flags', 'I'), ('page_count', 'H'), ('page_position', 'H'),
    ('next_record_offset', 'H'), ('reserved', '6s'), ('last_end_lsn', 'Q')))
RECORD = Layout((('lsn', 'Q'), ('previous_lsn', 'Q'), ('undo_next_lsn', 'Q'),
    ('data_bytes', 'I'), ('client_sequence', 'H'), ('client_index', 'H'), ('type', 'I'),
    ('transaction', 'I'), ('flags', 'H'), ('reserved', '6s')))
EXTENDED_RECORD_HEADER_BYTES = RECORD.size + 2 * ALIGNMENT
BASE_SEQUENCE_BITS = LSN_BITS + OFFSET_SHIFT - FILE_BYTES.bit_length()
UPDATE = Layout((('redo_operation', 'H'), ('undo_operation', 'H'), ('redo_offset', 'H'),
    ('redo_bytes', 'H'), ('undo_offset', 'H'), ('undo_bytes', 'H'), ('target_attribute', 'H'),
    ('lcns', 'H'), ('record_offset', 'H'), ('attribute_offset', 'H'), ('cluster_index', 'H'),
    ('attribute_flags', 'H'), ('target_vcn', 'Q')))


def aligned(value):
    return (value + ALIGNMENT - 1) // ALIGNMENT * ALIGNMENT


def lsn_at(offset, file_bytes=FILE_BYTES, sequence=LSN_SEQUENCE, sequence_bits=None):
    chosen = sequence_bits if sequence_bits is not None else LSN_BITS + OFFSET_SHIFT - file_bytes.bit_length()
    return (sequence << (LSN_BITS - chosen)) | (offset >> OFFSET_SHIFT)


BASE_LSN = lsn_at((RESTART_PAGES + LEGACY_TAIL_PAGES) * PAGE_BYTES + PAGE_DATA_OFFSET)


def protect(logical, header):
    """Return raw and independently expected restored pages, including USA bytes."""
    raw = bytearray(logical)
    usa_offset = struct.unpack_from('<H', raw, header.offsets['usa_offset'])[0]
    count = len(raw) // USA_STRIDE + 1
    header.put(raw, 'usa_count', count)
    struct.pack_into('<H', raw, usa_offset, USA_SEQUENCE)
    for sector in range(1, count):
        tail = sector * USA_STRIDE - WORD_BYTES
        raw[usa_offset + sector * WORD_BYTES:usa_offset + (sector + 1) * WORD_BYTES] = raw[tail:tail + WORD_BYTES]
    restored = bytearray(raw)
    for sector in range(1, count):
        struct.pack_into('<H', raw, sector * USA_STRIDE - WORD_BYTES, USA_SEQUENCE)
    return bytes(raw), bytes(restored)


def client(oldest=BASE_LSN, restart=BASE_LSN, previous=NO_CLIENT, following=NO_CLIENT,
           name=(ord('N'), ord('T'), ord('F'), ord('S')), sequence=CLIENT_SEQUENCE):
    encoded = struct.pack(f'<{len(name)}H', *name)
    values = dict(oldest_lsn=oldest, restart_lsn=restart, previous=previous, next=following,
                  sequence=sequence, name_bytes=len(encoded), name=encoded.ljust(CLIENT_NAME_BYTES, b'\0'))
    expected = dict(oldest_lsn=oldest, restart_lsn=restart, previous=previous, next=following,
                    sequence=sequence, name_utf16=list(name))
    return CLIENT.pack(values), expected


def restart(major=LEGACY_MAJOR, minor=LEGACY_MINOR, system=PAGE_BYTES, log=PAGE_BYTES, file_bytes=FILE_BYTES,
            flags=CLEAN, clients=None, free_head=NO_CLIENT, in_use_head=0,
            area_offset=RESTART_OFFSET, clients_offset=CLIENTS_OFFSET, sequence_bits=None,
            record_header_bytes=RECORD.size, page_data_offset=PAGE_DATA_OFFSET, current=None):
    bits = sequence_bits if sequence_bits is not None else LSN_BITS + OFFSET_SHIFT - file_bytes.bit_length()
    circular = RESTART_PAGES * system + (FAST_PAGES if major == FAST_MAJOR else LEGACY_TAIL_PAGES) * log
    current = lsn_at(circular + page_data_offset, file_bytes, sequence_bits=bits) if current is None else current
    if clients is None:
        clients = [client(current, current)]
    data = bytearray(system)
    header = RESTART_HEADER.pack(dict(magic=b'RSTR', usa_offset=RESTART_HEADER.size,
        system_page_bytes=system, log_page_bytes=log, area_offset=area_offset, minor=minor, major=major))
    data[:len(header)] = header
    length = clients_offset + len(clients) * CLIENT.size
    area = RESTART_AREA.pack(dict(current_lsn=current, clients=len(clients), free_head=free_head,
        in_use_head=in_use_head, flags=flags, sequence_bits=bits, length=length,
        clients_offset=clients_offset, file_bytes=file_bytes, record_header_bytes=record_header_bytes,
        page_data_offset=page_data_offset, open_count=OPEN_COUNT))
    data[area_offset:area_offset + len(area)] = area
    for index, (packet, _) in enumerate(clients):
        offset = area_offset + clients_offset + index * CLIENT.size
        data[offset:offset + CLIENT.size] = packet
    expected = dict(major=major, minor=minor, flags=flags, clean_hint=bool(flags & CLEAN) or in_use_head == NO_CLIENT,
        system_page_bytes=system, log_page_bytes=log, file_bytes=file_bytes,
        usable_bytes=file_bytes // log * log, circular_offset=circular, current_lsn=current,
        sequence_bits=bits, last_data_bytes=0, open_count=OPEN_COUNT,
        record_header_bytes=record_header_bytes, page_data_offset=page_data_offset,
        free_head=free_head, in_use_head=in_use_head, client_count=len(clients),
        area=dict(offset=area_offset, length=length),
        clients=dict(offset=area_offset + clients_offset, length=len(clients) * CLIENT.size),
        client_records=[entry for _, entry in clients])
    return data, expected


def update(lcns=(PHYSICAL_LCN,), redo=REDO, undo=UNDO, shared=False,
           include_unused_slot=True, unused_slot=UNUSED_LCN_SLOT):
    storage = lcns if lcns or not include_unused_slot else (unused_slot,)
    prefix = UPDATE.size + len(storage) * LSN_BYTES
    undo_offset = prefix if shared else aligned(prefix + len(redo))
    size = max(prefix + len(redo), undo_offset + len(undo))
    data = bytearray(size)
    values = dict(redo_operation=UPDATE_RESIDENT, undo_operation=UPDATE_RESIDENT,
        redo_offset=prefix, redo_bytes=len(redo), undo_offset=undo_offset, undo_bytes=len(undo),
        lcns=len(lcns), record_offset=TARGET_RECORD_OFFSET, attribute_offset=TARGET_ATTRIBUTE_OFFSET, cluster_index=0,
        attribute_flags=ATTRIBUTE_ACTS_ON_MFT, target_vcn=TARGET_VCN)
    data[:UPDATE.size] = UPDATE.pack(values)
    data[UPDATE.size:prefix] = struct.pack(f'<{len(storage)}Q', *storage)
    data[prefix:prefix + len(redo)] = redo
    data[undo_offset:undo_offset + len(undo)] = undo
    expected = {key: values[key] for key in ('redo_operation', 'undo_operation', 'target_attribute') if key in values}
    expected.update(target_attribute=0, lcn_count=len(lcns), compensation_undo_bytes=0,
        record_offset=TARGET_RECORD_OFFSET, attribute_offset=TARGET_ATTRIBUTE_OFFSET,
        cluster_index=0, attribute_flags=ATTRIBUTE_ACTS_ON_MFT, target_vcn=TARGET_VCN,
        redo=dict(offset=prefix, length=len(redo)), undo=dict(offset=undo_offset, length=len(undo)),
        lcns=dict(offset=UPDATE.size, length=len(lcns) * LSN_BYTES))
    return data, expected


def record(payload=None, header_bytes=RECORD.size, flags=0, kind=UPDATE_TYPE):
    if payload is None:
        payload = update()[0]
    values = dict(lsn=BASE_LSN, previous_lsn=0, undo_next_lsn=0, data_bytes=len(payload),
        client_sequence=CLIENT_SEQUENCE, client_index=0, type=kind, transaction=TRANSACTION, flags=flags)
    data = RECORD.pack(values) + bytes(header_bytes - RECORD.size) + payload
    expected = {key: value for key, value in values.items() if key != 'data_bytes'}
    expected['data'] = dict(offset=header_bytes, length=len(payload))
    return data, expected


def page(packet=None):
    packet = record()[0] if packet is None else packet
    next_offset = aligned(PAGE_DATA_OFFSET + len(packet))
    data = bytearray(PAGE_BYTES)
    values = dict(magic=b'RCRD', usa_offset=PAGE.size, copy_value=BASE_LSN, last_end_lsn=BASE_LSN,
                  flags=RECORD_END, page_count=1, page_position=1, next_record_offset=next_offset)
    data[:PAGE.size] = PAGE.pack(values)
    data[PAGE_DATA_OFFSET:PAGE_DATA_OFFSET + len(packet)] = packet
    expected = {key: value for key, value in values.items() if key not in ('magic', 'usa_offset')}
    return data, expected


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    cases = []
    authored_paths = set()

    def add(name, kind, data, expected=SUCCESS, fields=None, parameter=FILE_BYTES,
            config='base.restart', header=None):
        restored = None
        if header is not None:
            data, restored = protect(data, header)
        path = f'{name}.{kind}'
        assert path not in authored_paths, f'Duplicate independently authored packet: {path}'
        authored_paths.add(path)
        (output / path).write_bytes(data)
        if restored is not None:
            (output / (path + '.restored')).write_bytes(restored)
        cases.append(dict(path=path, kind=kind, expected=expected, fields=fields or {},
                          parameter=parameter, config=config))

    base, base_fields = restart()
    add('base', 'restart', base, fields=base_fields, header=RESTART_HEADER)
    for name, options in (
        ('fast', dict(major=FAST_MAJOR, minor=FAST_MINOR)), ('dirty-hint', dict(flags=0)),
        ('single-page-flag', dict(flags=CLEAN | SINGLE_PAGE_IO)), ('unknown-hint', dict(flags=CLEAN | UNKNOWN_RESTART_FLAG)),
        ('extended-record-header', dict(record_header_bytes=EXTENDED_RECORD_HEADER_BYTES)),
        ('wide-offset', dict(sequence_bits=BASE_SEQUENCE_BITS - 1)),
        ('system-8192', dict(system=2 * PAGE_BYTES)),
        ('small-pages', dict(system=USA_STRIDE, log=USA_STRIDE,
                             area_offset=aligned(RESTART_HEADER.size + 2 * WORD_BYTES),
                             clients_offset=RESTART_AREA.size, page_data_offset=aligned(PAGE.size + 2 * WORD_BYTES))),
        ('empty-clients', dict(clients=[], in_use_head=NO_CLIENT, current=0)),
        ('closed-stale-free', dict(clients=[client(oldest=MAX_FILE_BYTES, restart=MAX_FILE_BYTES)],
                                  free_head=0, in_use_head=NO_CLIENT, current=0, flags=0)),
        ('file-4g', dict(file_bytes=MAX_FILE_BYTES)),
        ('nonaligned-size', dict(file_bytes=FILE_BYTES + 1)),
    ):
        data, fields = restart(**options)
        add(name, 'restart', data, fields=fields, parameter=max(FILE_BYTES, options.get('file_bytes', 0)), header=RESTART_HEADER)
    clients = [client(previous=NO_CLIENT, following=1), client(previous=0, following=NO_CLIENT,
        name=(0xd800, 0x0078)), client(oldest=MAX_FILE_BYTES, previous=NO_CLIENT, following=NO_CLIENT)]
    data, fields = restart(clients=clients, free_head=2)
    add('mixed-lists', 'restart', data, fields=fields, header=RESTART_HEADER)
    maximum_clients = (MAX_PAGE_BYTES - aligned(RESTART_HEADER.size +
        (MAX_PAGE_BYTES // USA_STRIDE + 1) * WORD_BYTES) - RESTART_AREA.size) // CLIENT.size
    many = [client(oldest=0, restart=0, previous=index - 1 if index else NO_CLIENT,
        following=index + 1 if index + 1 < maximum_clients else NO_CLIENT,
        name=tuple(range(CLIENT_NAME_BYTES // WORD_BYTES))) for index in range(maximum_clients)]
    data, fields = restart(system=MAX_PAGE_BYTES, log=MAX_PAGE_BYTES, file_bytes=LARGE_FILE_BYTES,
        clients=many, current=0, area_offset=aligned(RESTART_HEADER.size +
            (MAX_PAGE_BYTES // USA_STRIDE + 1) * WORD_BYTES), clients_offset=RESTART_AREA.size,
        page_data_offset=aligned(PAGE.size + (MAX_PAGE_BYTES // USA_STRIDE + 1) * WORD_BYTES))
    add('maximum-clients', 'restart', data, fields=fields, parameter=LARGE_FILE_BYTES, header=RESTART_HEADER)
    for field, value in (
        ('clients', NO_CLIENT), ('free_head', 1), ('in_use_head', 1), ('length', RESTART_AREA.size),
        ('clients_offset', CLIENTS_OFFSET - 1), ('sequence_bits', 0), ('sequence_bits', BASE_SEQUENCE_BITS + 1),
        ('file_bytes', (RESTART_PAGES + MIN_RECORD_PAGES - 1) * PAGE_BYTES), ('file_bytes', MAX_FILE_BYTES + 1),
        ('file_bytes', 0), ('file_bytes', (1 << LSN_BITS) - 1), ('record_header_bytes', RECORD.size - ALIGNMENT),
        ('record_header_bytes', RECORD.size + 1), ('page_data_offset', PAGE.size),
        ('page_data_offset', PAGE_DATA_OFFSET + 1), ('page_data_offset', PAGE_BYTES),
        ('current_lsn', lsn_at(PAGE_DATA_OFFSET)),
        ('current_lsn', lsn_at((RESTART_PAGES + LEGACY_TAIL_PAGES) * PAGE_BYTES)),
    ):
        data = bytearray(base)
        RESTART_AREA.put(data, field, value, RESTART_OFFSET)
        add(f'area-{field}-{value}', 'restart', data, CORRUPT, header=RESTART_HEADER)
    for field, value in (('major', UNSUPPORTED_MAJOR), ('minor', UNSUPPORTED_MINOR), ('magic', b'CHKD')):
        data = bytearray(base)
        RESTART_HEADER.put(data, field, value)
        add(f'unsupported-{field}', 'restart', data, UNSUPPORTED, header=RESTART_HEADER)
    for field, value in (('magic', b'NOPE'), ('chkdsk_lsn', BASE_LSN),
                         ('system_page_bytes', PAGE_BYTES - 1), ('log_page_bytes', PAGE_BYTES - 1),
                         ('area_offset', RESTART_OFFSET + 1), ('area_offset', USA_STRIDE)):
        data = bytearray(base)
        RESTART_HEADER.put(data, field, value)
        label = value.hex() if isinstance(value, bytes) else str(value)
        add(f'header-{field}-{label}', 'restart', data, CORRUPT, header=RESTART_HEADER)
    for name, field, value in (('cycle', 'next', 0), ('bad-backlink', 'previous', 0),
                              ('bad-next', 'next', 1), ('odd-name', 'name_bytes', 3),
                              ('long-name', 'name_bytes', CLIENT_NAME_BYTES + WORD_BYTES),
                              ('future-client', 'restart_lsn', BASE_LSN + ALIGNMENT),
                              ('header-client-lsn', 'oldest_lsn', lsn_at(PAGE_DATA_OFFSET))):
        data = bytearray(base)
        CLIENT.put(data, field, value, RESTART_OFFSET + CLIENTS_OFFSET)
        add(name, 'restart', data, CORRUPT, header=RESTART_HEADER)
    data, _ = restart(clients=[client(), client()], free_head=0)
    add('duplicate-list', 'restart', data, CORRUPT, header=RESTART_HEADER)
    data, _ = restart(clients=[client(), client()])
    add('orphan-client', 'restart', data, CORRUPT, header=RESTART_HEADER)
    add('short-file', 'restart', base, CORRUPT, parameter=FILE_BYTES - 1, header=RESTART_HEADER)
    data = bytearray(base)
    RESTART_AREA.put(data, 'last_data_bytes', FILE_BYTES, RESTART_OFFSET)
    add('record-policy', 'restart', data, RANGE, header=RESTART_HEADER)
    for label, payload, result in (
        ('record-policy-exact', FILE_BYTES - RECORD.size, SUCCESS),
        ('record-policy-over', FILE_BYTES - RECORD.size + 1, RANGE),
        ('record-policy-u32', (1 << 32) - 1, RANGE),
    ):
        data = bytearray(base)
        RESTART_AREA.put(data, 'last_data_bytes', payload, RESTART_OFFSET)
        add(label, 'restart', data, result, header=RESTART_HEADER)
    raw, _ = protect(base, RESTART_HEADER)
    for name, change in (
        ('torn-first', lambda packet: struct.pack_into('<H', packet, USA_STRIDE - WORD_BYTES, USA_SEQUENCE + 1)),
        ('torn-last', lambda packet: struct.pack_into('<H', packet, PAGE_BYTES - WORD_BYTES, USA_SEQUENCE + 1)),
        ('bad-usa-count', lambda packet: RESTART_HEADER.put(packet, 'usa_count', 1)),
        ('overlap-usa', lambda packet: RESTART_HEADER.put(packet, 'usa_offset', RESTART_OFFSET)),
    ):
        packet = bytearray(raw)
        change(packet)
        add(name, 'restart', packet, CORRUPT)
    add('erased', 'restart', bytes([0xff]) * PAGE_BYTES, CORRUPT)
    add('zero', 'restart', bytes(PAGE_BYTES), CORRUPT)
    data = bytearray(raw)
    RESTART_HEADER.put(data, 'major', UNSUPPORTED_MAJOR)
    RESTART_HEADER.put(data, 'minor', 0)
    RESTART_HEADER.put(data, 'usa_count', 0)
    add('unknown-integrity', 'restart', data, UNSUPPORTED)
    data = bytearray(raw)
    RESTART_HEADER.put(data, 'system_page_bytes', 2 * MAX_PAGE_BYTES)
    add('page-policy', 'restart', data, UNSUPPORTED)

    packet, fields = page()
    add('base', 'page', packet, fields=fields, header=PAGE)
    for name, changes in (
        ('tail-union', dict(copy_value=(RESTART_PAGES + LEGACY_TAIL_PAGES) * PAGE_BYTES)),
        ('no-complete-record', dict(next_record_offset=0, last_end_lsn=0)),
        ('transfer-position', dict(page_count=3, page_position=2)),
        ('unknown-page-flags', dict(flags=UNKNOWN_PAGE_FLAG | RECORD_END)),
    ):
        data = bytearray(packet)
        expected = copy.deepcopy(fields)
        for field, value in changes.items():
            PAGE.put(data, field, value)
            expected[field] = value
        add(name, 'page', data, fields=expected, header=PAGE)
    for field, value in (('next_record_offset', PAGE_DATA_OFFSET - ALIGNMENT),
                         ('next_record_offset', PAGE_DATA_OFFSET + 1), ('next_record_offset', PAGE_BYTES + ALIGNMENT),
                         ('page_position', 2), ('page_count', 0),
                         ('last_end_lsn', lsn_at(PAGE_DATA_OFFSET))):
        data = bytearray(packet)
        PAGE.put(data, field, value)
        add(f'bad-{field}-{value}', 'page', data, CORRUPT, header=PAGE)
    raw, _ = protect(packet, PAGE)
    data = bytearray(raw)
    struct.pack_into('<H', data, PAGE_BYTES - WORD_BYTES, USA_SEQUENCE + 1)
    add('torn', 'page', data, CORRUPT)
    data = bytearray(raw)
    PAGE.put(data, 'usa_offset', PAGE_DATA_OFFSET)
    add('overlap-usa', 'page', data, CORRUPT)

    for name, options in (
        ('base', {}), ('empty-client', dict(payload=b'')),
        ('restart-client', dict(payload=b'opaque restart data', kind=RESTART_TYPE)),
        ('extended-header', dict(header_bytes=EXTENDED_RECORD_HEADER_BYTES)),
        ('multi-page', dict(payload=b'original' * PAGE_BYTES, flags=MULTI_PAGE)),
        ('new-flags', dict(flags=RECORD_ADDING | RECORD_DELETING)),
    ):
        data, fields = record(**options)
        add(name, 'record', data, fields=fields, parameter=options.get('header_bytes', RECORD.size))
    data, _ = record()
    for field, value, verdict in (
        ('lsn', 0, CORRUPT), ('previous_lsn', BASE_LSN, CORRUPT),
        ('undo_next_lsn', BASE_LSN + 1, CORRUPT), ('data_bytes', 0, CORRUPT),
        ('client_index', NO_CLIENT, CORRUPT), ('type', 0, UNSUPPORTED), ('flags', UNKNOWN_RECORD_FLAG, UNSUPPORTED),
    ):
        packet = bytearray(data)
        RECORD.put(packet, field, value)
        add(f'bad-{field}', 'record', packet, verdict, parameter=RECORD.size)
    add('extra-byte', 'record', data + b'x', CORRUPT, parameter=RECORD.size)
    add('short-prefix', 'record', data[:RECORD.size - 1], CORRUPT, parameter=RECORD.size)

    for name, options in (('base', {}), ('shared', dict(shared=True, undo=REDO)),
                          ('empty', dict(redo=b'', undo=b'')),
                          ('two-lcns', dict(lcns=(PHYSICAL_LCN, PHYSICAL_LCN + 1))),
                          ('lcnless', dict(lcns=())),
                          ('lcnless-shared', dict(lcns=(), shared=True, undo=REDO)),
                          ('lcnless-empty', dict(lcns=(), redo=b'', undo=b'')),
                          ('lcnless-zero-unused-slot', dict(lcns=(), unused_slot=0)),
                          ('lcnless-maximum-unused-slot', dict(lcns=(), unused_slot=(1 << LSN_BITS) - 1))):
        data, fields = update(**options)
        add(name, 'update', data, fields=fields)
    data, _ = update()
    for field, value in (('redo_offset', 0), ('redo_offset', UPDATE.size),
                         ('redo_offset', UPDATE.size + LSN_BYTES + 1), ('redo_bytes', NO_CLIENT),
                         ('undo_offset', len(data) + ALIGNMENT), ('lcns', NO_CLIENT)):
        packet = bytearray(data)
        UPDATE.put(packet, field, value)
        add(f'bad-{field}-{value}', 'update', packet, CORRUPT)
    packet = bytearray(data)
    UPDATE.put(packet, 'redo_operation', NO_CLIENT)
    fields = update()[1]
    fields['redo_operation'] = NO_CLIENT
    add('opaque-operation', 'update', packet, fields=fields)
    compensation, expected = update(undo=b'')
    UPDATE.put(compensation, 'undo_operation', COMPENSATION)
    UPDATE.put(compensation, 'undo_bytes', len(REDO))
    expected['undo_operation'] = COMPENSATION
    expected['compensation_undo_bytes'] = len(REDO)
    add('compensation-omitted-undo', 'update', compensation, fields=expected)
    for name, changes in (
        ('wrong-operation', dict(undo_operation=UPDATE_RESIDENT)),
        ('wrong-length', dict(undo_bytes=len(REDO) + 1)),
        ('wrong-endpoint', dict(undo_offset=len(compensation) + ALIGNMENT)),
        ('missing-redo', dict(redo_bytes=0)),
    ):
        malformed = bytearray(compensation)
        for field, value in changes.items():
            UPDATE.put(malformed, field, value)
        add('compensation-' + name, 'update', malformed, CORRUPT)
    lcnless = update(lcns=())[0]
    add('lcnless-compact', 'update', update(lcns=(), include_unused_slot=False)[0], CORRUPT)
    add('lcnless-common-prefix', 'update', lcnless[:UPDATE.offsets['lcns'] + WORD_BYTES], CORRUPT)
    add('lcnless-short-target', 'update', lcnless[:UPDATE.offsets['target_vcn']], CORRUPT)
    for size in range(1, UPDATE.size + LSN_BYTES):
        add(f'lcnless-truncated-{size}', 'update', lcnless[:size], CORRUPT)
    for field, value in (('redo_offset', UPDATE.size), ('undo_offset', UPDATE.size),
                         ('redo_offset', UPDATE.size + LSN_BYTES + 1),
                         ('redo_bytes', NO_CLIENT), ('undo_offset', len(lcnless) + ALIGNMENT)):
        packet = bytearray(lcnless)
        UPDATE.put(packet, field, value)
        add(f'lcnless-bad-{field}-{value}', 'update', packet, CORRUPT)
    packet, fields = update(lcns=(), redo=b'', undo=b'')
    UPDATE.put(packet, 'redo_offset', 0)
    UPDATE.put(packet, 'undo_offset', 0)
    fields['redo']['offset'] = fields['undo']['offset'] = 0
    add('lcnless-empty-zero-offsets', 'update', packet, fields=fields)
    add('short-prefix', 'update', data[:UPDATE.size - 1], CORRUPT)
    for name, options in (('base', {}), ('unpaired', dict(name=(0xd800, 0x0078))),
                          ('maximum-name', dict(name=tuple(range(CLIENT_NAME_BYTES // WORD_BYTES))))):
        packet, fields = client(**options)
        add(name, 'client', packet, fields=fields)
    packet = client()[0]
    bad = bytearray(packet)
    CLIENT.put(bad, 'name_bytes', 3)
    add('odd-name', 'client', bad, CORRUPT)
    add('short', 'client', packet[:-1], CORRUPT)
    (output / 'manifest.json').write_text(json.dumps(dict(cases=cases), indent=2) + '\n')
    (output / 'cases.tsv').write_text(''.join(f"{case['path']} {case['kind']} {case['expected']} {case['parameter']} {case['config']}\n" for case in cases))
    return cases


if __name__ == '__main__':
    author(Path(sys.argv[1]))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).touch()
