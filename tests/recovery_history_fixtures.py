#!/usr/bin/env python3
"""Original retained client histories and independently declared lifetime outcomes."""
from pathlib import Path
import copy
import hashlib
import json
import struct
import sys

import logfile_fixtures as w
import logfile_tables_fixtures as t
import fixtures as f
from logfile_history_fixtures import Window
from logfile_source_fixtures import restart
from logfile_checkpoint_fixtures import CLIENT_RESTART
from checkpoint_fixtures import STORED_UPDATE_BYTES
from logfile_volume_fixtures import LOGFILE_RECORD, LOGFILE_LCN, FILE_ATTRIBUTES, DATA_INSTANCE, mark_clusters

OK, CORRUPT, UNSUPPORTED, STALE, RANGE = 0, 2, 3, 10, 11
NOOP, COMPENSATION, UPDATE_RESIDENT, PREPARE, COMMIT, FORGET, TABLE_DUMP = 0, 1, 7, 0x19, 0x1a, 0x1b, 0x20
ACTIVE, PREPARED, COMMITTED, FORGOTTEN = range(4)
NO_EPOCH = (1 << (t.LINK.size * t.BITS_PER_BYTE)) - 1
KEY = t.TABLE.size
SECOND_KEY = KEY + t.TRANSACTION.size
RESTART_CLIENT_MINOR = 0
SNAPSHOT_ACTIVE = 1
SOURCE_BYTES = 256 * 1024
EXTRA_RESTART_BYTES = b'opaque native client extension'
CHECKPOINT_DUMP_FLAG = 0x0004
REDO_VALUE, UNDO_VALUE = b'new', b'old'


def digest(data):
    return hashlib.sha256(data).hexdigest()


class History:
    def __init__(self, major=1, modern=False, extended=False):
        self.major = major
        self.window = Window(modern, w.EXTENDED_RECORD_HEADER_BYTES if extended else w.RECORD.size,
            size=SOURCE_BYTES)
        self.packets, self.seed = [], None
        self.current = {}
        self.epochs = []
        self.analysis = None
        self.checkpoint = None

    def append(self, payload, *, transaction=0, previous=0, undo=0, kind=w.UPDATE_TYPE,
               flags=0, sequence=None, slot=None):
        window = self.window
        page = len(self.packets)
        lsn = window.lsn(page, window.data)
        header = w.RECORD.pack(dict(lsn=lsn, data_bytes=len(payload), type=kind,
            client_index=0, client_sequence=w.CLIENT_SEQUENCE if sequence is None else sequence,
            transaction=transaction, previous_lsn=previous, undo_next_lsn=undo, flags=flags))
        packet = bytes(header) + bytes([0x67]) * (window.header - w.RECORD.size) + payload
        assert len(packet) <= window.log - window.data
        window.page(page, start=lsn, end=lsn, next_offset=w.aligned(window.data + len(packet)),
            chunks=[(window.data, packet)], slot=slot)
        value = dict(lsn=lsn, packet=packet, transaction=transaction, previous=previous, undo=undo)
        self.packets.append(value)
        return value

    def update(self, operation=UPDATE_RESIDENT, *, key=KEY, previous=None, undo=None,
               changes=None, slot=None):
        previous = self.current.get(key, 0) if previous is None else previous
        fields = dict(redo_operation=operation)
        body = struct.pack('<Q', w.UNUSED_LCN_SLOT)
        if operation == UPDATE_RESIDENT:
            fields.update(redo_offset=STORED_UPDATE_BYTES, redo_bytes=len(REDO_VALUE),
                undo_offset=w.aligned(STORED_UPDATE_BYTES + len(REDO_VALUE)), undo_bytes=len(UNDO_VALUE))
            body += REDO_VALUE
            body += bytes(fields['undo_offset'] - STORED_UPDATE_BYTES - len(REDO_VALUE))
            body += UNDO_VALUE
        fields.update(changes or {})
        if operation != UPDATE_RESIDENT and fields.get('redo_bytes', 0):
            body += bytes([0x73]) * fields['redo_bytes']
        value = self.append(bytes(w.UPDATE.pack(fields)) + body, transaction=key,
            previous=previous, undo=previous if undo is None else undo, slot=slot)
        value['operation'] = operation
        self.current[key] = value['lsn']
        return value

    def save_seed(self, *, key=KEY, state=SNAPSHOT_ACTIVE, undo=None):
        members = [packet for packet in self.packets if packet['transaction'] == key]
        self.seed = dict(allocated=t.ALLOCATED, state=state, first_lsn=members[0]['lsn'],
            previous_lsn=members[-1]['lsn'],
            undo_next_lsn=members[-1]['lsn'] if undo is None else undo,
            undo_records=t.UNDO_RECORDS, undo_bytes=t.UNDO_BYTES)

    def checkpoint_record(self, *, seed=None, empty=False, analysis=None, slot=None, dump_flags=0):
        fields = dict(major=self.major, minor=RESTART_CLIENT_MINOR)
        if seed is not None or empty:
            body = t.TABLE.pack(dict(entry_bytes=t.TRANSACTION.size,
                entries=1 if seed is not None else 0, allocated=1 if seed is not None else 0))
            if seed is not None:
                body += t.TRANSACTION.pack(seed)
            payload = w.UPDATE.pack(dict(redo_operation=TABLE_DUMP,
                redo_offset=STORED_UPDATE_BYTES, redo_bytes=len(body)))
            table = self.append(bytes(payload) + struct.pack('<Q', w.UNUSED_LCN_SLOT) + body,
                flags=dump_flags)
            fields.update(transactions_lsn=table['lsn'], transactions_bytes=len(body))
        if not self.packets:
            self.append(bytes(w.UPDATE.pack({})) + struct.pack('<Q', w.UNUSED_LCN_SLOT))
        fields['analysis_lsn'] = self.packets[0]['lsn'] if analysis is None else analysis
        self.analysis = fields['analysis_lsn']
        self.checkpoint = self.append(bytes(CLIENT_RESTART.pack(fields)) + EXTRA_RESTART_BYTES,
            kind=w.RESTART_TYPE, slot=slot)
        return self.checkpoint

    def raw(self):
        window = self.window
        raw = bytearray(window.raw(self.checkpoint['lsn']))
        client, _ = w.client(oldest=self.packets[0]['lsn'], restart=self.checkpoint['lsn'],
            sequence=w.CLIENT_SEQUENCE)
        page, _ = restart(major=w.FAST_MAJOR if window.modern else w.LEGACY_MAJOR,
            minor=w.FAST_MINOR if window.modern else w.LEGACY_MINOR,
            system=window.log, log=window.log, file_bytes=window.size,
            record_header_bytes=window.header, page_data_offset=window.data,
            current=self.checkpoint['lsn'], clients=[(client, {})], in_use_head=0, free_head=w.NO_CLIENT)
        for ordinal in range(w.RESTART_PAGES):
            raw[ordinal * window.log:(ordinal + 1) * window.log] = page
        return bytes(raw)


def lifetime(packets, state, *, complete=True):
    controls = [p for p in packets if p['operation'] in (PREPARE, COMMIT, FORGET)]
    return dict(key=packets[0]['transaction'], records=len(packets),
        first_lsn=packets[0]['lsn'] if complete else 0,
        last_lsn=packets[-1]['lsn'], predecessor_lsn=packets[0]['previous'],
        undo_next_lsn=packets[-1]['undo'], state=state, complete_chain=complete,
        control_lsn=controls[-1]['lsn'] if controls else 0,
        control_operation=controls[-1]['operation'] if controls else NOOP)


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    cases = []

    def finish(name, history, states=(), *, code=OK, verified=0, partial=0):
        source = history.raw()
        path = name + '.journal'
        (output / path).write_bytes(source)
        packets = b''.join(packet['packet'] for packet in history.packets)
        (output / (path + '.packets')).write_bytes(packets)
        cases.append(dict(path=path, code=code, states=list(states), verified_seeds=verified,
            partial_prefixes=partial, records=len(history.packets), history_bytes=len(packets),
            packet_lengths=[len(packet['packet']) for packet in history.packets],
            source_sha256=digest(source), packets_sha256=digest(packets),
            first_lsn=history.packets[0]['lsn'], checkpoint_lsn=history.checkpoint['lsn'],
            end_lsn=history.packets[-1]['lsn'], page_bytes=history.window.log))

    for major in (0, 1):
        for modern in (False, True):
            for extended in (False, True):
                h = History(major, modern, extended)
                first = h.update()
                h.save_seed()
                h.checkpoint_record(seed=h.seed)
                second = h.update()
                last = h.update(FORGET)
                finish(f'checkpoint-active-then-forget-{major}-{int(modern)}-{int(extended)}', h,
                    [lifetime([first, second, last], FORGOTTEN)], verified=1)
    for terminal, operations in ((ACTIVE, ()), (PREPARED, (PREPARE,)),
                                (COMMITTED, (PREPARE, COMMIT)), (FORGOTTEN, (FORGET,))):
        h = History()
        h.checkpoint_record(empty=True)
        values = [h.update()]
        values += [h.update(operation) for operation in operations]
        finish(f'post-checkpoint-state-{terminal}', h, [lifetime(values, terminal)])
    h = History()
    h.checkpoint_record(empty=True)
    first, second = h.update(), h.update(key=SECOND_KEY)
    commit, forget = h.update(COMMIT), h.update(FORGET, key=SECOND_KEY)
    finish('interleaved-independent-keys', h,
        [lifetime([first, commit], COMMITTED), lifetime([second, forget], FORGOTTEN)])
    h = History()
    h.checkpoint_record(empty=True)
    first, forget = h.update(), h.update(FORGET)
    second, last = h.update(previous=0), h.update()
    finish('forgotten-key-reused', h,
        [lifetime([first, forget], FORGOTTEN), lifetime([second, last], ACTIVE)])
    h = History()
    h.update()
    h.checkpoint_record()
    finish('absent-transaction-dump', h, [lifetime([h.packets[0]], ACTIVE)])
    h = History()
    h.checkpoint_record(empty=True)
    finish('empty-present-transaction-dump', h)
    h = History()
    first = h.update()
    h.checkpoint_record()
    last = h.update(FORGET, changes=dict(undo_operation=COMPENSATION))
    finish('forget-compensation-observation', h, [lifetime([first, last], FORGOTTEN)])
    for modern in (False, True):
        h = History(modern=modern)
        first = h.update()
        h.save_seed()
        h.checkpoint_record(seed=h.seed, dump_flags=CHECKPOINT_DUMP_FLAG)
        last = h.update(FORGET)
        finish(f'bound-checkpoint-dump-flag-{int(modern)}', h,
            [lifetime([first, last], FORGOTTEN)], verified=1)
    for modern in (False, True):
        h = History(modern=modern)
        first = h.update()
        h.checkpoint_record(slot=0)
        last = h.update(FORGET, slot=1)
        finish(f'checkpoint-and-current-copy-{int(modern)}', h,
            [lifetime([first, last], FORGOTTEN)])
    for terminal in (ACTIVE, FORGOTTEN):
        h = History()
        predecessor = h.window.lsn(0, h.window.data, sequence=w.LSN_SEQUENCE - 1)
        first = h.update(previous=predecessor, undo=predecessor)
        h.checkpoint_record()
        values = [first]
        if terminal == FORGOTTEN:
            values.append(h.update(FORGET))
        finish(f'truncated-prefix-state-{terminal}', h,
            [lifetime(values, terminal, complete=False)] if terminal == FORGOTTEN else [],
            code=OK if terminal == FORGOTTEN else STALE, partial=1)
    for bad in ('previous-gap', 'key-reuse-active', 'undo-foreign-key', 'undo-reused-key',
                'malformed-key', 'too-small-key', 'control-body', 'after-forget', 'foreign-sequence',
                'ordinary-update-checkpoint-flag', 'control-unknown-undo', 'control-target'):
        h = History()
        first = h.update()
        h.checkpoint_record()
        if bad == 'previous-gap':
            h.update(previous=h.checkpoint['lsn'])
        elif bad == 'key-reuse-active':
            h.update(previous=0)
        elif bad == 'undo-foreign-key':
            other = h.update(key=SECOND_KEY)
            h.update(undo=other['lsn'])
        elif bad == 'undo-reused-key':
            h.update(FORGET)
            h.update(previous=0, undo=first['lsn'])
        elif bad == 'malformed-key':
            h.update(key=KEY + 1)
        elif bad == 'too-small-key':
            h.update(key=KEY - 1)
        elif bad == 'control-body':
            h.update(FORGET, changes=dict(redo_offset=STORED_UPDATE_BYTES,
                redo_bytes=w.LSN_BYTES))
        elif bad == 'control-unknown-undo':
            h.update(FORGET, changes=dict(undo_operation=TABLE_DUMP))
        elif bad == 'control-target':
            h.update(FORGET, changes=dict(record_offset=w.ALIGNMENT))
        elif bad == 'after-forget':
            h.update(FORGET)
            h.update()
        elif bad == 'foreign-sequence':
            value = h.update()
            h.window.pages[h.window.circular + (len(h.packets) - 1) * h.window.log]['chunks'][0] = (
                h.window.data, bytes(w.RECORD.pack(dict(lsn=value['lsn'],
                    data_bytes=len(value['packet']) - h.window.header, type=w.UPDATE_TYPE,
                    client_sequence=w.CLIENT_SEQUENCE + 1, transaction=KEY))) + value['packet'][h.window.header:])
        else:
            value = h.update()
            wire = bytearray(value['packet'])
            w.RECORD.put(wire, 'flags', CHECKPOINT_DUMP_FLAG)
            h.window.pages[h.window.circular + (len(h.packets) - 1) * h.window.log]['chunks'][0] = (
                h.window.data, bytes(wire))
        finish(bad, h, code=STALE if bad == 'foreign-sequence' else
            UNSUPPORTED if bad in ('control-body', 'ordinary-update-checkpoint-flag',
                'control-unknown-undo', 'control-target') else CORRUPT)
    for bad in ('seed-first-wrong', 'seed-undo-wrong', 'seed-root-future', 'empty-seed-live-state',
                'analysis-not-packet'):
        h = History()
        first, last = h.update(), h.update()
        h.save_seed()
        seed = copy.deepcopy(h.seed)
        if bad == 'seed-first-wrong':
            seed['first_lsn'] = last['lsn']
        elif bad == 'seed-undo-wrong':
            seed['undo_next_lsn'] = first['lsn'] + w.ALIGNMENT
        elif bad == 'seed-root-future':
            seed['previous_lsn'] = h.window.lsn(len(h.packets) + 1, h.window.data)
        elif bad == 'empty-seed-live-state':
            seed.update(first_lsn=0, previous_lsn=0, undo_next_lsn=0)
        h.checkpoint_record(seed=seed,
            analysis=first['lsn'] + w.ALIGNMENT if bad == 'analysis-not-packet' else None)
        finish(bad, h, code=STALE if bad in ('seed-root-future', 'analysis-not-packet') else
            UNSUPPORTED if bad == 'empty-seed-live-state' else CORRUPT)
    (output / 'manifest.json').write_text(json.dumps(cases, indent=2) + '\n')
    image, _, _ = f.make_image()
    journal = (output / cases[0]['path']).read_bytes()
    runs = [(len(journal) // f.CLUSTER, LOGFILE_LCN)]
    f.put_data(image, LOGFILE_LCN, journal)
    f.put_record(image, LOGFILE_RECORD, f.file_record(LOGFILE_RECORD,
        [f.standard(FILE_ATTRIBUTES), f.nonresident(f.DATA, runs, len(journal), DATA_INSTANCE)]))
    mark_clusters(image, runs)
    (output / 'volume-history.img').write_bytes(image)
    with (output / 'cases.txt').open('w') as listing:
        for case in cases:
            listing.write(f"{case['path']} {case['code']} {case['records']} {case['history_bytes']} "
                f"{len(case['states'])} {case['verified_seeds']} {case['partial_prefixes']}\n")
            with (output / (case['path'] + '.states')).open('w') as states:
                for state in case['states']:
                    states.write(' '.join(str(int(state[field])) for field in
                        ('key', 'records', 'first_lsn', 'last_lsn', 'predecessor_lsn', 'undo_next_lsn',
                         'control_lsn', 'control_operation', 'state', 'complete_chain')) + '\n')
    return cases


if __name__ == '__main__':
    destination = Path(sys.argv[1])
    values = author(destination)
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text(f'{len(values)} recovery-input profiles\n')
