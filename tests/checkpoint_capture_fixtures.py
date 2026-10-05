#!/usr/bin/env python3
"""Original protected journals with complete checkpoint packet ownership oracles."""
from pathlib import Path
import copy
import hashlib
import json
import struct
import sys

import logfile_fixtures as w
import logfile_tables_fixtures as t
from logfile_history_fixtures import Window
from logfile_source_fixtures import restart, SMALL_FILE_BYTES
from logfile_checkpoint_fixtures import CLIENT_RESTART, TABLES, EXTENDED_RESTART_BYTES
from logfile_names_fixtures import entry as name_entry, TERMINATOR
from checkpoint_fixtures import make_body, DUMP_OPERATIONS, STORED_UPDATE_BYTES

OPEN, NAMES, DIRTY, TRANSACTIONS = range(len(TABLES))
KINDS = len(TABLES)
OK, CORRUPT, UNSUPPORTED, NOT_FOUND, STALE, RANGE = 0, 2, 3, 6, 10, 11
ALL_TABLES = (1 << KINDS) - 1
DUMP_PAGE_STRIDE = 8
LARGE_DUMP_PAGE_STRIDE = 24
OPAQUE_EXTENSION = bytes([0x7d]) * (EXTENDED_RESTART_BYTES - CLIENT_RESTART.size)
OPAQUE_HEADER_BYTE = 0x6b
SECOND_ALLOCATED_OPEN = 2
LARGE_SOURCE_BYTES = 4 * 1024 * 1024
MAX_RECORD_BYTES = 1024 * 1024
MAX_BODY_BYTES = (1 << (w.WORD_BYTES * t.BITS_PER_BYTE)) - 1
REPORT_COLUMNS = 8


def digest(data):
    return hashlib.sha256(data).hexdigest()


def bodies(major):
    values = [make_body(kind, major)[0] for kind in range(KINDS)]
    stride = t.OPEN_BASE.size if major == 0 else t.OPEN.size
    first, _ = name_entry(t.TABLE.size, tuple(map(ord, '$I30')))
    second, _ = name_entry(t.TABLE.size + SECOND_ALLOCATED_OPEN * stride,
        (0xd800, ord('x'), 0xdc00))
    values[NAMES] = first + second + TERMINATOR
    return values


class Journal:
    def __init__(self, major=0, modern=False, extended=False, *, log=None, size=None,
                 stride=DUMP_PAGE_STRIDE, checkpoint_page=None, extension=b''):
        header = w.EXTENDED_RECORD_HEADER_BYTES if extended else w.RECORD.size
        self.window = Window(modern, header, log=log, size=size)
        self.major, self.stride, self.extension = major, stride, extension
        self.checkpoint_page = KINDS * stride if checkpoint_page is None else checkpoint_page
        self.anchors = [self.window.lsn(kind * stride, self.window.data) for kind in range(KINDS)]
        self.checkpoint_lsn = self.window.lsn(self.checkpoint_page, self.window.data)
        self.owner_index, self.owner_sequence = 0, w.CLIENT_SEQUENCE
        self.request_index, self.request_sequence = self.owner_index, self.owner_sequence
        self.client_name = tuple(map(ord, 'NTFS'))
        self.owner_restart = self.checkpoint_lsn
        self.owner_active = True

    def packet(self, lsn, payload, kind=w.UPDATE_TYPE, *, client_index=None,
               client_sequence=None, flags=0):
        common = w.RECORD.pack(dict(lsn=lsn, data_bytes=len(payload), type=kind,
            client_index=self.owner_index if client_index is None else client_index,
            client_sequence=self.owner_sequence if client_sequence is None else client_sequence,
            transaction=w.TRANSACTION, flags=flags))
        return bytes(common + bytes([OPAQUE_HEADER_BYTE]) *
            (self.window.header - w.RECORD.size) + payload)

    def place(self, ordinal, packet, *, slot=None):
        window = self.window
        lsn = struct.unpack_from('<Q', packet, w.RECORD.offsets['lsn'])[0]
        position, offset, pages = 0, window.data, 0
        while position < len(packet):
            amount = min(window.log - offset, len(packet) - position)
            final = position + amount == len(packet)
            window.page(ordinal, start=lsn if pages == 0 else 0,
                end=lsn if final else 0,
                next_offset=w.aligned(offset + amount) if final else offset,
                chunks=[(offset, packet[position:position + amount])],
                slot=slot if pages == 0 else None)
            position += amount
            ordinal += 1
            if window.circular + ordinal * window.log == window.size:
                ordinal = 0
            offset = window.data
            pages += 1
        return dict(lsn=lsn, pages=pages, copies=int(slot is not None), packet=packet)

    def author(self, mask=ALL_TABLES, *, raw_bodies=None, prefix_changes=None,
               checkpoint_changes=None, dump_changes=None, slots=None):
        window = self.window
        raw_bodies = bodies(self.major) if raw_bodies is None else raw_bodies
        fields = dict(major=self.major, minor=0, analysis_lsn=self.anchors[OPEN])
        packets = []
        for kind, body in enumerate(raw_bodies):
            if not mask & (1 << kind):
                continue
            fields[TABLES[kind] + '_lsn'] = self.anchors[kind]
            fields[TABLES[kind] + '_bytes'] = len(body)
            update = w.UPDATE.pack(dict(redo_operation=DUMP_OPERATIONS[kind],
                redo_offset=STORED_UPDATE_BYTES, redo_bytes=len(body)))
            update += struct.pack('<Q', w.UNUSED_LCN_SLOT) + body
            changes = (dump_changes or {}).get(kind, {})
            packet = self.packet(self.anchors[kind], update, **changes)
            packets.append(self.place(kind * self.stride, packet,
                slot=(slots or {}).get(kind)))
        fields.update(prefix_changes or {})
        prefix = CLIENT_RESTART.pack(fields) + self.extension
        checkpoint_flags = w.MULTI_PAGE if len(prefix) + window.header > window.log - window.data else 0
        changes = dict(dict(flags=checkpoint_flags), **(checkpoint_changes or {}))
        checkpoint = self.packet(self.checkpoint_lsn, prefix,
            changes.pop('kind', w.RESTART_TYPE), **changes)
        checkpoint = self.place(self.checkpoint_page, checkpoint,
            slot=(slots or {}).get(KINDS))
        packets.insert(0, checkpoint)
        # Table packets may span several pages; their LFS flag is authored from
        # their own byte extent rather than transfer count or decoder behavior.
        for kind in range(KINDS):
            if mask & (1 << kind):
                ordinal = 1 + sum(bool(mask & (1 << previous)) for previous in range(kind))
                if packets[ordinal]['pages'] > 1:
                    packet = bytearray(packets[ordinal]['packet'])
                    w.RECORD.put(packet, 'flags', w.MULTI_PAGE)
                    packets[ordinal] = self.place(kind * self.stride, bytes(packet),
                        slot=(slots or {}).get(kind))
        journal = bytearray(window.raw(self.checkpoint_lsn))
        client, _ = w.client(oldest=min(self.anchors) if mask else self.checkpoint_lsn,
            restart=self.owner_restart, sequence=self.owner_sequence, name=self.client_name)
        raw, _ = restart(major=w.FAST_MAJOR if window.modern else w.LEGACY_MAJOR,
            minor=w.FAST_MINOR if window.modern else w.LEGACY_MINOR, system=window.log,
            log=window.log, file_bytes=window.size, record_header_bytes=window.header,
            page_data_offset=window.data, current=self.checkpoint_lsn,
            clients=[(client, {})], in_use_head=0 if self.owner_active else w.NO_CLIENT,
            free_head=w.NO_CLIENT if self.owner_active else 0)
        for page in range(w.RESTART_PAGES):
            journal[page * window.log:(page + 1) * window.log] = raw
        return journal, packets


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    cases = []

    def add(name, selected, *, mask=ALL_TABLES, code=OK, acquired=None, reads=None,
            requested=None, copied=None, **options):
        journal, packets = selected.author(mask, **options)
        acquired = len(packets) if acquired is None else acquired
        acquired_packets = packets[:acquired]
        reads = sum(packet['pages'] for packet in acquired_packets) if reads is None else reads
        copied = sum(packet['copies'] for packet in acquired_packets) if copied is None else copied
        checkpoint_lsn = selected.owner_restart if code != STALE or acquired else 0
        if selected.client_name != tuple(map(ord, 'NTFS')):
            checkpoint_lsn = 0
        requested = (acquired_packets[-1]['lsn'] if acquired_packets else 0) if requested is None else requested
        report = dict(checkpoint_lsn=checkpoint_lsn, requested_lsn=requested,
            read_bytes=reads * selected.window.log, read_calls=reads,
            acquired_records=acquired,
            record_bytes=sum(len(packet['packet']) for packet in acquired_packets),
            copy_pages_read=copied, complete=code == OK)
        path = name + '.journal'
        (output / path).write_bytes(journal)
        expected_packets = []
        for ordinal, packet in enumerate(packets):
            packet_path = path + f'.packet-{ordinal}'
            (output / packet_path).write_bytes(packet['packet'])
            expected_packets.append(dict(path=packet_path, lsn=packet['lsn'],
                bytes=len(packet['packet']), sha256=digest(packet['packet']),
                pages=packet['pages'], copies=packet['copies']))
        (output / (path + '.packets.tsv')).write_text('\n'.join(' '.join(map(str,
            (packet['lsn'], packet['bytes'], packet['pages'], packet['copies'])))
            for packet in expected_packets) + '\n')
        names = 2 if mask & (1 << NAMES) else 0
        dirty = 2 if mask & (1 << DIRTY) else 0
        cases.append(dict(path=path, source_sha256=digest(journal), code=code,
            client_index=selected.request_index, client_sequence=selected.request_sequence,
            client_major=selected.major, present_mask=mask, named_attributes=names,
            dirty_pages=dirty, header_bytes=selected.window.header,
            page_bytes=selected.window.log, report=report, packets=expected_packets))

    for major in (0, 1):
        for modern in (False, True):
            for mask in range(ALL_TABLES + 1):
                valid = bool(mask & (1 << OPEN)) or not mask & ((1 << NAMES) | (1 << DIRTY))
                add(f'client-{major}-fast-{int(modern)}-mask-{mask}',
                    Journal(major, modern, extended=modern, extension=OPAQUE_EXTENSION),
                    mask=mask, code=OK if valid else CORRUPT)
    for modern, slots in ((False, range(w.LEGACY_TAIL_PAGES)), (True, range(w.FAST_PAGES))):
        for slot in slots:
            add(f'copy-fast-{int(modern)}-slot-{slot:02}', Journal(1, modern), slots={OPEN: slot})
    add('checkpoint-fast-copy', Journal(1, True), slots={KINDS: w.FAST_PAGES - 1})
    for label, changes, code in (
        ('missing-lsn', {'open_attributes_lsn': 0}, CORRUPT),
        ('missing-bytes', {'open_attributes_bytes': 0}, CORRUPT),
        ('oversized-anchor', {'open_attributes_bytes': MAX_RECORD_BYTES + 1}, RANGE),
        ('unknown-client-version', {'major': 2}, UNSUPPORTED),
    ):
        add(label, Journal(), prefix_changes=changes, code=code, acquired=1)
    for kind in range(KINDS):
        journal = Journal()
        for label, anchor in (('restart-anchor', journal.checkpoint_lsn),
                              ('outside-anchor', w.lsn_at(journal.window.size, journal.window.size)),
                              ('page-header-anchor', journal.window.lsn(kind * journal.stride, 0))):
            add(f'{label}-{kind}', copy.deepcopy(journal),
                prefix_changes={TABLES[kind] + '_lsn': anchor}, code=CORRUPT, acquired=1)
        if kind != OPEN:
            add(f'duplicate-anchor-{kind}', copy.deepcopy(journal),
                prefix_changes={TABLES[kind] + '_lsn': journal.anchors[OPEN]},
                code=CORRUPT, acquired=1)
        add(f'foreign-table-sequence-{kind}', copy.deepcopy(journal),
            dump_changes={kind: dict(client_sequence=w.CLIENT_SEQUENCE + 1)}, code=STALE)
        add(f'foreign-table-index-{kind}', copy.deepcopy(journal),
            dump_changes={kind: dict(client_index=1)}, code=STALE)
        add(f'table-restart-type-{kind}', copy.deepcopy(journal),
            dump_changes={kind: dict(kind=w.RESTART_TYPE)}, code=UNSUPPORTED)
    for label, change in (('stale-request-sequence', ('request_sequence', w.CLIENT_SEQUENCE + 1)),
                          ('stale-request-index', ('request_index', 1)),
                          ('free-client', ('owner_active', False)),
                          ('foreign-client-name', ('client_name', tuple(map(ord, 'OTHER')))),
                          ('absent-restart', ('owner_restart', 0))):
        selected = Journal()
        setattr(selected, *change)
        code = UNSUPPORTED if label == 'foreign-client-name' else NOT_FOUND if label == 'absent-restart' else STALE
        add(label, selected, code=code, acquired=0)
    for label, changes, code in (
        ('foreign-checkpoint-sequence', dict(client_sequence=w.CLIENT_SEQUENCE + 1), STALE),
        ('foreign-checkpoint-index', dict(client_index=1), STALE),
        ('checkpoint-update-type', dict(kind=w.UPDATE_TYPE), UNSUPPORTED),
    ):
        add(label, Journal(), checkpoint_changes=changes, code=code, acquired=1)
    values = bodies(1)
    name, _ = name_entry(t.TABLE.size + t.OPEN.size, tuple(map(ord, 'free')))
    values[NAMES] = name + TERMINATOR
    add('name-refers-to-free-open-entry', Journal(1), raw_bodies=values, code=CORRUPT)
    values = bodies(1)
    values[NAMES] = values[NAMES][:-len(TERMINATOR)] + values[NAMES]
    add('duplicate-name-target', Journal(1), raw_bodies=values, code=CORRUPT)
    values = bodies(0)
    dirty = bytearray(values[DIRTY])
    t.DIRTY_BASE.put(dirty, 'target_attribute', t.TABLE.size + t.OPEN_BASE.size, t.TABLE.size)
    values[DIRTY] = bytes(dirty)
    add('dirty-refers-to-free-open-entry', Journal(), raw_bodies=values, code=CORRUPT)
    large = Journal(1, log=w.PAGE_BYTES, size=LARGE_SOURCE_BYTES,
        stride=LARGE_DUMP_PAGE_STRIDE)
    values = bodies(1)
    count = (MAX_BODY_BYTES - t.TABLE.size) // t.OPEN.size
    values[OPEN], _ = make_body(OPEN, 1, count)
    add('large-open-table', large, raw_bodies=values)
    extension = bytes([OPAQUE_HEADER_BYTE]) * (MAX_RECORD_BYTES - w.RECORD.size - CLIENT_RESTART.size)
    add('maximum-checkpoint-record', Journal(log=w.PAGE_BYTES, size=LARGE_SOURCE_BYTES,
        stride=LARGE_DUMP_PAGE_STRIDE, extension=extension))
    wrap = Journal(checkpoint_page=(SMALL_FILE_BYTES // w.USA_STRIDE) -
        w.RESTART_PAGES - w.LEGACY_TAIL_PAGES - 1, extension=bytes(w.USA_STRIDE))
    add('wrapped-checkpoint', wrap, mask=0)
    (output / 'manifest.json').write_text(json.dumps(dict(cases=cases), indent=2) + '\n')
    rows = []
    for case in cases:
        report = case['report']
        rows.append(' '.join(map(str, (case['path'], case['client_index'], case['client_sequence'],
            case['code'], case['present_mask'], case['client_major'], case['named_attributes'],
            case['dirty_pages'], case['header_bytes'], case['page_bytes'],
            *(int(value) for value in report.values())))))
    (output / 'cases.tsv').write_text('\n'.join(rows) + '\n')
    return cases


if __name__ == '__main__':
    author(Path(sys.argv[1]))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text('original-checkpoint-acquisitions\n')
