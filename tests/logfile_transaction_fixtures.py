#!/usr/bin/env python3
"""Original transaction graphs, protected pages and exact reverse packet oracles."""
from pathlib import Path
import hashlib
import json
import struct
import sys
import logfile_fixtures as w
from logfile_source_fixtures import restart
from logfile_history_fixtures import Window
from checkpoint_capture_fixtures import Journal

OK, INVALID, CORRUPT, UNSUPPORTED, NOT_FOUND, STALE, RANGE = 0, 9, 2, 3, 6, 10, 11
NOOP, PREPARE, COMMIT, FORGET = 0x00, 0x19, 0x1a, 0x1b
CONTROL_OPERATIONS = (PREPARE, COMMIT, FORGET)
STORED_UPDATE_BYTES = w.UPDATE.size + struct.calcsize('<Q')
OPAQUE_BYTE, ENTRY_STRIDE = 0x6d, 4
MAX_RECORD_BYTES, MAX_RECORDS = 1024 * 1024, 4096
DENSE_SOURCE_BYTES = 1024 * 1024
FIELD_COLUMNS = 21
BITS_PER_BYTE = 8


class Transactions:
    def __init__(self, modern=False, extended=False, *, log=None, size=None):
        self.journal = Journal(modern=modern, extended=extended, log=log, size=size)
        self.window = self.journal.window
        self.packets = []
        self.owner_oldest = None
        self.request_index, self.request_sequence = 0, w.CLIENT_SEQUENCE
        self.transaction = w.TRANSACTION

    def add(self, operation=NOOP, *, ordinal=None, previous=None, undo=None,
            opaque_bytes=0, changes=None, slot=None):
        ordinal = len(self.packets) * ENTRY_STRIDE if ordinal is None else ordinal
        lsn = self.window.lsn(ordinal, self.window.data)
        predecessor = self.packets[-1]['lsn'] if self.packets else 0
        payload = w.UPDATE.pack(dict(redo_operation=operation))
        payload += struct.pack('<Q', w.UNUSED_LCN_SLOT) + bytes([OPAQUE_BYTE]) * opaque_bytes
        packet = bytearray(self.journal.packet(lsn, payload))
        fields = dict(previous_lsn=predecessor if previous is None else previous,
                      undo_next_lsn=predecessor if undo is None else undo)
        if len(packet) > self.window.log - self.window.data:
            fields['flags'] = w.MULTI_PAGE
        fields.update(changes or {})
        for field, value in fields.items():
            w.RECORD.put(packet, field, value)
        value = self.journal.place(ordinal, bytes(packet), slot=slot)
        value['operation'] = operation
        self.packets.append(value)
        return value

    def raw(self, root):
        window = self.window
        current = max(packet['lsn'] for packet in self.packets)
        source = bytearray(window.raw(current))
        oldest = min(packet['lsn'] for packet in self.packets) if self.owner_oldest is None else self.owner_oldest
        client, _ = w.client(oldest=oldest, restart=root, sequence=self.journal.owner_sequence,
                             name=self.journal.client_name)
        raw, _ = restart(major=w.FAST_MAJOR if window.modern else w.LEGACY_MAJOR,
            minor=w.FAST_MINOR if window.modern else w.LEGACY_MINOR,
            system=window.log, log=window.log, file_bytes=window.size,
            record_header_bytes=window.header, page_data_offset=window.data, current=current,
            clients=[(client, {})], in_use_head=0 if self.journal.owner_active else w.NO_CLIENT,
            free_head=w.NO_CLIENT if self.journal.owner_active else 0)
        for ordinal in range(w.RESTART_PAGES):
            source[ordinal * window.log:(ordinal + 1) * window.log] = raw
        return bytes(source)


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    cases = []

    def finish(name, source, *, code=OK, delivered=None, examined=None, reads=None,
               root=None, next_lsn=None, undo_references=None, admitted=True,
               max_records=MAX_RECORDS):
        root = source.packets[-1]['lsn'] if root is None else root
        delivered = list(reversed(source.packets)) if delivered is None else delivered
        examined = len(delivered) if examined is None else examined
        reads = sum(packet['pages'] for packet in delivered) if reads is None else reads
        blob, records = bytearray(), []
        cumulative_reads = 0
        for packet in delivered:
            raw = packet['packet']
            fields = {name: struct.unpack_from('<' + kind, raw, w.RECORD.offsets[name])[0]
                      for name, kind in w.RECORD.fields if not kind.endswith('s')}
            # Public metadata is declared independently of the C decoder.
            fields.pop('data_bytes')
            fields['data'] = dict(offset=source.window.header,
                length=len(raw) - source.window.header)
            cumulative_reads += packet['pages']
            records.append(dict(record=fields, packet_offset=len(blob), bytes=len(raw),
                pages=packet['pages'], copies=packet['copies'], operation=packet['operation'],
                read_calls=cumulative_reads, read_bytes=cumulative_reads * source.window.log,
                sha256=hashlib.sha256(raw).hexdigest()))
            blob += raw
        controls = [packet for packet in delivered if packet['operation'] in CONTROL_OPERATIONS]
        control = controls[0] if controls else None
        if next_lsn is None:
            next_lsn = 0 if code == OK else root
        if undo_references is None:
            undo_references = sum(record['record']['undo_next_lsn'] != 0 for record in records) if code == OK else 0
        report = dict(root_lsn=root if admitted else 0,
            last_lsn=records[-1]['record']['lsn'] if records else 0,
            next_lsn=next_lsn if admitted else 0, control_lsn=control['lsn'] if control else 0,
            control_operation=control['operation'] if control else 0,
            transaction=source.transaction if admitted else 0, record_bytes=len(blob),
            read_bytes=reads * source.window.log, read_calls=reads, examined_records=examined,
            visited_records=len(delivered), copy_pages_read=sum(packet['copies'] for packet in delivered),
            undo_references=undo_references, complete=code == OK)
        path = name + '.journal'
        raw = source.raw(root or source.packets[-1]['lsn'])
        (output / path).write_bytes(raw)
        (output / (path + '.packets')).write_bytes(blob)
        (output / (path + '.records.tsv')).write_text(''.join(
            f"{record['record']['lsn']} {record['bytes']} {record['pages']} {record['copies']}\n"
            for record in records))
        cases.append(dict(path=path, code=code, index=source.request_index,
            sequence=source.request_sequence, transaction=source.transaction, root=root,
            page_bytes=source.window.log, max_records=max_records, records=records,
            report=report, source_sha256=hashlib.sha256(raw).hexdigest()))

    def baseline(modern=False, extended=False, *, slot=None):
        source = Transactions(modern, extended)
        for operation in (NOOP, PREPARE, NOOP, COMMIT, NOOP, FORGET):
            source.add(operation, slot=slot if operation == FORGET else None)
        return source

    for modern in (False, True):
        label = 'fast' if modern else 'legacy'
        for extended in (False, True):
            finish(f'{label}-markers-extended-{int(extended)}', baseline(modern, extended))
        for slot in range(w.FAST_PAGES if modern else w.LEGACY_TAIL_PAGES):
            finish(f'{label}-copy-{slot}', baseline(modern, slot=slot))
        for operation in (NOOP, PREPARE, COMMIT, FORGET):
            source = Transactions(modern)
            source.add(operation)
            finish(f'{label}-single-operation-{operation}', source)
        source = Transactions(modern)
        first = source.add()
        source.add()
        source.add(undo=first['lsn'])
        source.add(undo=first['lsn'])
        finish(f'{label}-undo-skips', source)
        source = Transactions(modern)
        source.add(changes=dict(transaction=w.TRANSACTION + 1))
        current = source.add(previous=0, undo=0)
        source.add(previous=current['lsn'], undo=current['lsn'])
        finish(f'{label}-unrelated-records', source, delivered=list(reversed(source.packets[1:])))
        source = baseline(modern)
        finish(f'{label}-root-suffix', source, root=source.packets[2]['lsn'],
               delivered=list(reversed(source.packets[:3])))

    # Original rejected graphs distinguish malformed framing, wrong identity,
    # retained-range failure and a valid-looking undo edge outside this generation.
    for field, value, code in [('client_index', 1, STALE),
                              ('client_sequence', w.CLIENT_SEQUENCE + 1, STALE),
                              ('transaction', w.TRANSACTION + 1, STALE),
                              ('type', w.RESTART_TYPE, UNSUPPORTED),
                              ('flags', w.RECORD_ADDING, UNSUPPORTED),
                              ('flags', w.RECORD_DELETING, UNSUPPORTED)]:
        source = Transactions()
        source.add(changes={field: value})
        finish(f'foreign-{field}-{value}', source, code=code, delivered=[], examined=1, reads=1)
    for label, mutate in [('inactive', lambda s: setattr(s.journal, 'owner_active', False)),
                          ('wrong-index', lambda s: setattr(s, 'request_index', 1)),
                          ('wrong-sequence', lambda s: setattr(s, 'request_sequence', w.CLIENT_SEQUENCE + 1)),
                          ('before-retained', lambda s: setattr(s, 'owner_oldest', s.packets[1]['lsn'])),
                          ('absent-retained', lambda s: setattr(s, 'owner_oldest', 0)),
                          ('foreign-name', lambda s: setattr(s.journal, 'client_name', tuple(map(ord, 'OTHER')))),
                          ('zero-transaction', lambda s: setattr(s, 'transaction', 0))]:
        source = baseline()
        mutate(source)
        code = UNSUPPORTED if label in ('absent-retained', 'foreign-name') else INVALID if label == 'zero-transaction' else STALE
        finish(label, source, code=code, delivered=[], examined=0, reads=0, admitted=False,
               root=source.packets[0]['lsn'] if label == 'before-retained' else None)
    source = baseline()
    finish('zero-root', source, root=0, code=INVALID, delivered=[], examined=0, reads=0, admitted=False)
    for field in ('previous_lsn', 'undo_next_lsn'):
        for label, value in [('self', lambda s: s.window.lsn(0, s.window.data)),
                             ('restart', lambda s: 1)]:
            source = Transactions()
            source.add(changes={field: value(source)})
            finish(f'{field}-{label}', source, code=CORRUPT, delivered=[], examined=0, reads=1)
    source = Transactions()
    old = source.add(FORGET)
    source.add(previous=0, undo=old['lsn'])
    finish('reused-key-undo-outside-chain', source, code=CORRUPT,
           delivered=[source.packets[-1]], next_lsn=0)
    source = Transactions()
    leaf = source.add()
    source.add(previous=0, undo=0)
    source.add(previous=leaf['lsn'], undo=source.packets[-1]['lsn'])
    finish('same-key-undo-on-sibling', source, code=CORRUPT,
           delivered=[source.packets[-1], leaf], next_lsn=0)
    source = Transactions()
    first = source.add()
    source.add()
    source.owner_oldest = source.packets[-1]['lsn']
    finish('previous-below-retained', source, code=STALE, delivered=[], examined=1, reads=1)
    source = Transactions()
    source.add(opaque_bytes=1)
    raw = bytearray(source.packets[-1]['packet'])
    w.UPDATE.put(raw, 'redo_offset', STORED_UPDATE_BYTES - w.ALIGNMENT, source.window.header)
    w.UPDATE.put(raw, 'redo_bytes', 1, source.window.header)
    source.packets[-1] = source.journal.place(0, bytes(raw)) | dict(operation=NOOP)
    finish('malformed-update-span', source, code=CORRUPT, delivered=[], examined=1, reads=1)

    source = Transactions()
    source.add()
    source.add(opaque_bytes=3 * source.window.log)
    finish('legacy-spanning-root', source)
    source = Transactions()
    source.add(ordinal=ENTRY_STRIDE)
    last_page = (source.window.size - source.window.circular) // source.window.log - 1
    source.add(ordinal=last_page, opaque_bytes=3 * source.window.log)
    finish('legacy-wrapped-root', source)
    source = Transactions(log=w.MAX_PAGE_BYTES, size=4 * DENSE_SOURCE_BYTES)
    source.add()
    source.add(ordinal=ENTRY_STRIDE, opaque_bytes=MAX_RECORD_BYTES - source.window.header - STORED_UPDATE_BYTES)
    finish('legacy-exact-record-cap', source)

    # A dense full-length chain shares completed pages with unrelated records.
    # Its explicit 4,096-record ceiling is tested both exactly and one beyond.
    for count in (MAX_RECORDS, MAX_RECORDS + 1):
        source = Transactions(size=DENSE_SOURCE_BYTES)
        window, records = source.window, []
        page, offset, chunks = 0, window.data, []
        for ordinal in range(count):
            if offset + window.header + STORED_UPDATE_BYTES > window.log:
                window.page(page, start=records[-1]['lsn'], end=records[-1]['lsn'],
                            next_offset=offset, chunks=chunks)
                page, offset, chunks = page + 1, window.data, []
            lsn = window.lsn(page, offset)
            previous = records[-1]['lsn'] if records else 0
            payload = w.UPDATE.pack(dict(redo_operation=NOOP)) + struct.pack('<Q', w.UNUSED_LCN_SLOT)
            packet = bytearray(source.journal.packet(lsn, payload))
            w.RECORD.put(packet, 'previous_lsn', previous)
            w.RECORD.put(packet, 'undo_next_lsn', previous)
            records.append(dict(lsn=lsn, pages=1, copies=0, packet=bytes(packet), operation=NOOP))
            chunks.append((offset, bytes(packet)))
            offset = w.aligned(offset + len(packet))
        window.page(page, start=records[-1]['lsn'], end=records[-1]['lsn'],
                    next_offset=offset, chunks=chunks)
        source.packets = records
        delivered = list(reversed(records))[:MAX_RECORDS]
        finish(f'dense-records-{count}', source, code=OK if count == MAX_RECORDS else RANGE,
               delivered=delivered, next_lsn=0 if count == MAX_RECORDS else records[0]['lsn'])

    (output / 'manifest.json').write_text(json.dumps(dict(cases=cases), indent=2) + '\n')
    columns = ['root_lsn', 'last_lsn', 'next_lsn', 'control_lsn', 'record_bytes', 'read_bytes',
               'transaction', 'read_calls', 'examined_records', 'visited_records',
               'copy_pages_read', 'undo_references', 'control_operation', 'complete']
    (output / 'cases.tsv').write_text(''.join('\t'.join(map(str,
        [case['path'], case['index'], case['sequence'], case['code'], case['max_records'],
         case['root'], case['transaction']] +
        [int(case['report'][name]) for name in columns])) + '\n' for case in cases))
    return cases


if __name__ == '__main__':
    author(Path(sys.argv[1]))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text('original-transaction-chain-graphs\n')
