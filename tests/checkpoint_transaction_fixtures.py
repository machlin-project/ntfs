#!/usr/bin/env python3
"""Original checkpoint seeds with independently declared complete chain oracles."""
from pathlib import Path
import hashlib
import json
import struct
import sys

import logfile_fixtures as w
import logfile_tables_fixtures as t
from checkpoint_capture_fixtures import Journal, TRANSACTIONS
from checkpoint_fixtures import DUMP_OPERATIONS, STORED_UPDATE_BYTES
from logfile_checkpoint_fixtures import CLIENT_RESTART
from logfile_source_fixtures import restart

OK, CORRUPT, UNSUPPORTED, NOT_FOUND, INVALID, STALE, RANGE = 0, 2, 3, 6, 9, 10, 11
NOOP, PREPARE, COMMIT, FORGET = 0, 0x19, 0x1a, 0x1b
UNINITIALIZED, ACTIVE, PREPARED, COMMITTED = range(4)
CHAIN_STRIDE, TABLE_PAGE, CHECKPOINT_PAGE = 4, 48, 56
TABLE_ENTRIES = 4
FREE_ENTRIES = (1,)
MAX_RECORDS = 4096
LARGE_SOURCE_BYTES = 1024 * 1024
MAX_TABLE_ENTRIES = ((1 << (w.WORD_BYTES * t.BITS_PER_BYTE)) - 1 - t.TABLE.size) // t.TRANSACTION.size
REPORT_FIELDS = ('table_lsn', 'allocated_transactions', 'verified_transactions',
    'visited_transactions', 'requested_transaction', 'read_calls', 'read_bytes',
    'record_bytes', 'examined_records', 'checked_records', 'copy_pages_read', 'complete')
CAPTURE_FIELDS = ('checkpoint_lsn', 'requested_lsn', 'read_calls', 'read_bytes',
    'acquired_records', 'record_bytes', 'copy_pages_read', 'complete')
SEED_FIELDS = ('state', 'first_lsn', 'previous_lsn', 'undo_next_lsn', 'undo_records', 'undo_bytes')
CHAIN_FIELDS = ('root_lsn', 'last_lsn', 'next_lsn', 'control_lsn', 'record_bytes',
    'read_bytes', 'transaction', 'read_calls', 'examined_records', 'visited_records',
    'copy_pages_read', 'undo_references', 'control_operation', 'complete')


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Seeds:
    def __init__(self, major=1, modern=False, extended=False, *, entries=TABLE_ENTRIES,
                 free=FREE_ENTRIES, dense=False, size=None):
        self.journal = Journal(major, modern, extended,
            size=LARGE_SOURCE_BYTES if dense else size)
        self.window = self.journal.window
        self.major, self.entries, self.free, self.dense = major, entries, free, dense
        self.seeds, self.chains = {}, {}
        self.ordinal = 0
        self.table_page, self.checkpoint_page = TABLE_PAGE, CHECKPOINT_PAGE
        self.dense_page, self.dense_offset, self.dense_chunks = 0, self.window.data, []
        self.owner_oldest = None
        self.request_index, self.request_sequence = 0, w.CLIENT_SEQUENCE

    def add(self, entry, operation=NOOP, *, undo=None, changes=None, slot=None,
            extra_bytes=0):
        key = t.TABLE.size + entry * t.TRANSACTION.size
        chain = self.chains.setdefault(entry, [])
        previous = chain[-1]['lsn'] if chain else 0
        if self.dense:
            if self.dense_offset + self.window.header + STORED_UPDATE_BYTES > self.window.log:
                self.dense_page += 1
                self.dense_offset, self.dense_chunks = self.window.data, []
            ordinal, offset = self.dense_page, self.dense_offset
        else:
            ordinal, offset = self.ordinal, self.window.data
            self.ordinal += CHAIN_STRIDE
        lsn = self.window.lsn(ordinal, offset)
        fields = dict(transaction=key, previous_lsn=previous,
            undo_next_lsn=previous if undo is None else undo)
        if self.window.header + STORED_UPDATE_BYTES + extra_bytes > self.window.log - offset:
            fields['flags'] = w.MULTI_PAGE
        fields.update(changes or {})
        payload = w.UPDATE.pack(dict(redo_operation=operation))
        payload += struct.pack('<Q', w.UNUSED_LCN_SLOT) + bytes([0x6d]) * extra_bytes
        packet = bytearray(self.journal.packet(lsn, payload))
        for field, value in fields.items():
            w.RECORD.put(packet, field, value)
        if self.dense:
            self.dense_chunks.append((offset, bytes(packet)))
            self.dense_offset = w.aligned(offset + len(packet))
            self.window.page(ordinal, start=lsn, end=lsn, next_offset=self.dense_offset,
                chunks=self.dense_chunks)
            value = dict(lsn=lsn, pages=1, copies=0, packet=bytes(packet))
        else:
            value = self.journal.place(ordinal, bytes(packet), slot=slot)
        value.update(operation=operation, undo=fields['undo_next_lsn'])
        chain.append(value)
        self.seeds[entry] = dict(allocated=t.ALLOCATED, state=ACTIVE,
            first_lsn=chain[0]['lsn'], previous_lsn=lsn, undo_next_lsn=lsn,
            undo_records=t.UNDO_RECORDS, undo_bytes=t.UNDO_BYTES)
        return value

    def empty(self, entry):
        self.seeds[entry] = dict(allocated=t.ALLOCATED, state=UNINITIALIZED,
            first_lsn=0, previous_lsn=0, undo_next_lsn=0, undo_records=0, undo_bytes=0)
        self.chains[entry] = []

    def raw(self, *, absent=False, slots=None):
        if self.dense:
            self.table_page, self.checkpoint_page = self.dense_page + 4, self.dense_page + 8
        table_lsn = self.window.lsn(self.table_page, self.window.data)
        checkpoint_lsn = self.window.lsn(self.checkpoint_page, self.window.data)
        body, _ = t.table(t.TRANSACTION.size, self.entries, self.free)
        for entry, seed in self.seeds.items():
            offset = t.TABLE.size + entry * t.TRANSACTION.size
            body[offset:offset + t.TRANSACTION.size] = t.TRANSACTION.pack(seed)
        fields = dict(major=self.major, minor=0, analysis_lsn=table_lsn)
        captures = []
        if not absent:
            fields.update(transactions_lsn=table_lsn, transactions_bytes=len(body))
            update = w.UPDATE.pack(dict(redo_operation=DUMP_OPERATIONS[TRANSACTIONS],
                redo_offset=STORED_UPDATE_BYTES, redo_bytes=len(body)))
            update += struct.pack('<Q', w.UNUSED_LCN_SLOT) + body
            packet = self.journal.packet(table_lsn, update,
                flags=w.MULTI_PAGE if len(update) + self.window.header > self.window.log - self.window.data else 0)
            captures.append(self.journal.place(self.table_page, packet,
                slot=(slots or {}).get('table')))
        packet = self.journal.packet(checkpoint_lsn, CLIENT_RESTART.pack(fields), w.RESTART_TYPE)
        captures.insert(0, self.journal.place(self.checkpoint_page, packet,
            slot=(slots or {}).get('checkpoint')))
        oldest = min((packet['lsn'] for chain in self.chains.values() for packet in chain),
            default=table_lsn)
        oldest = oldest if self.owner_oldest is None else self.owner_oldest
        raw = bytearray(self.window.raw(checkpoint_lsn))
        client, _ = w.client(oldest=oldest, restart=checkpoint_lsn, sequence=w.CLIENT_SEQUENCE)
        page, _ = restart(major=w.FAST_MAJOR if self.window.modern else w.LEGACY_MAJOR,
            minor=w.FAST_MINOR if self.window.modern else w.LEGACY_MINOR,
            system=self.window.log, log=self.window.log, file_bytes=self.window.size,
            record_header_bytes=self.window.header, page_data_offset=self.window.data,
            current=checkpoint_lsn, clients=[(client, {})], in_use_head=0, free_head=w.NO_CLIENT)
        for ordinal in range(w.RESTART_PAGES):
            raw[ordinal * self.window.log:(ordinal + 1) * self.window.log] = page
        return bytes(raw), captures, table_lsn


def baseline(major=1, modern=False, extended=False, slot=None):
    source = Seeds(major, modern, extended)
    for entry, state in ((0, ACTIVE), (2, COMMITTED)):
        source.add(entry)
        source.add(entry, PREPARE)
        source.add(entry, FORGET, slot=slot if entry == 2 else None)
        source.seeds[entry]['state'] = state
    source.empty(3)
    return source


def chain_view(source, entry):
    packets = list(reversed(source.chains[entry]))
    seed = source.seeds[entry]
    key = t.TABLE.size + entry * t.TRANSACTION.size
    controls = [p for p in packets if p['operation'] in (PREPARE, COMMIT, FORGET)]
    control = controls[0] if controls else None
    reads = sum(p['pages'] for p in packets)
    chain = dict(root_lsn=seed['previous_lsn'], last_lsn=packets[-1]['lsn'] if packets else 0,
        next_lsn=0, control_lsn=control['lsn'] if control else 0,
        record_bytes=sum(len(p['packet']) for p in packets), read_bytes=reads * source.window.log,
        transaction=key, read_calls=reads, examined_records=len(packets), visited_records=len(packets),
        copy_pages_read=sum(p['copies'] for p in packets),
        undo_references=sum(p['undo'] != 0 for p in packets),
        control_operation=control['operation'] if control else 0, complete=True)
    return dict(key=key, snapshot={field: seed[field] for field in SEED_FIELDS}, chain=chain)


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    cases = []

    def finish(name, source, *, code=OK, delivered=None, checked=None, examined=None,
               extra_reads=0, requested=None, preflight=False, absent=False,
               max_records=MAX_RECORDS, max_transactions=MAX_RECORDS, slots=None):
        raw, captures, table_lsn = source.raw(absent=absent, slots=slots)
        entries = sorted(source.seeds)
        delivered = entries if delivered is None else delivered
        checked = entries if checked is None else checked
        views = [chain_view(source, entry) for entry in delivered]
        chains = [chain_view(source, entry)['chain'] for entry in checked]
        reads = sum(p['pages'] for p in captures)
        captured_bytes = sum(len(p['packet']) for p in captures)
        copied = sum(p['copies'] for p in captures)
        checkpoint = dict(checkpoint_lsn=captures[0]['lsn'], requested_lsn=captures[-1]['lsn'],
            read_calls=reads, read_bytes=reads * source.window.log, acquired_records=len(captures),
            record_bytes=captured_bytes, copy_pages_read=copied, complete=True)
        total_reads = reads + sum(c['read_calls'] for c in chains) + extra_reads
        report = dict(table_lsn=0 if absent else table_lsn,
            allocated_transactions=0 if absent else len(entries),
            verified_transactions=len(views), visited_transactions=len(views),
            requested_transaction=requested if requested is not None else
                (views[-1]['key'] if views else 0), read_calls=total_reads,
            read_bytes=total_reads * source.window.log,
            record_bytes=captured_bytes + sum(c['record_bytes'] for c in chains),
            examined_records=sum(c['examined_records'] for c in chains) if examined is None else examined,
            checked_records=sum(c['visited_records'] for c in chains),
            copy_pages_read=copied + sum(c['copy_pages_read'] for c in chains), complete=code == OK)
        path = name + '.journal'
        (output / path).write_bytes(raw)
        capture_bytes = b''.join(p['packet'] for p in captures)
        (output / (path + '.capture')).write_bytes(capture_bytes)
        (output / (path + '.expected')).write_text(' '.join(map(str,
            [int(checkpoint[field]) for field in CAPTURE_FIELDS] +
            [int(report[field]) for field in REPORT_FIELDS])) + '\n')
        (output / (path + '.views')).write_text(''.join(' '.join(map(str,
            [view['key']] + [int(view['snapshot'][field]) for field in SEED_FIELDS] +
            [int(view['chain'][field]) for field in CHAIN_FIELDS])) + '\n' for view in views))
        cases.append(dict(path=path, code=code, report=report, checkpoint=checkpoint,
            views=views, max_records=max_records, max_transactions=max_transactions,
            index=source.request_index, sequence=source.request_sequence,
            page_bytes=source.window.log, source_sha256=digest(raw),
            capture_sha256=digest(capture_bytes), preflight=preflight))

    for major in (0, 1):
        for modern in (False, True):
            for extended in (False, True):
                finish(f'client-{major}-fast-{int(modern)}-extended-{int(extended)}',
                    baseline(major, modern, extended))
    for modern in (False, True):
        for slot in range(w.FAST_PAGES if modern else w.LEGACY_TAIL_PAGES):
            finish(f'copy-fast-{int(modern)}-{slot}', baseline(modern=modern, slot=slot),
                slots={'checkpoint': (slot + 1) % (w.FAST_PAGES if modern else w.LEGACY_TAIL_PAGES)})
    empty = Seeds(entries=0, free=())
    finish('empty-present-table', empty)
    free = Seeds(entries=4, free=(3, 1, 0, 2))
    finish('all-free-stale-payloads', free)
    finish('absent-table', empty, absent=True, code=NOT_FOUND, delivered=[], checked=[])
    for state in (UNINITIALIZED, ACTIVE, PREPARED, COMMITTED):
        source = Seeds(entries=1, free=())
        source.add(0)
        source.seeds[0]['state'] = state
        finish(f'raw-state-{state}', source)
    source = baseline()
    source.seeds[2]['first_lsn'] = source.chains[2][1]['lsn']
    finish('first-lsn-not-chain-end', source, code=CORRUPT, delivered=[0], checked=[0, 2],
        requested=t.TABLE.size + 2 * t.TRANSACTION.size)
    source = baseline()
    source.seeds[2]['undo_next_lsn'] = source.chains[2][0]['lsn'] + w.ALIGNMENT
    finish('seed-undo-not-chain-member', source, code=CORRUPT, delivered=[0], checked=[0, 2],
        requested=t.TABLE.size + 2 * t.TRANSACTION.size)
    for ordinal, (field, value, code) in enumerate((
        ('first_lsn', 0, UNSUPPORTED), ('previous_lsn', 0, UNSUPPORTED),
        ('first_lsn', 1, CORRUPT), ('undo_next_lsn', 1, CORRUPT),
        ('previous_lsn', lambda s: s.window.lsn(s.table_page, s.window.data), CORRUPT),
        ('first_lsn', lambda s: s.seeds[2]['previous_lsn'] + w.ALIGNMENT, CORRUPT),
        ('undo_next_lsn', lambda s: s.seeds[2]['previous_lsn'] + w.ALIGNMENT, CORRUPT))):
        source = baseline()
        source.seeds[2][field] = value(source) if callable(value) else value
        finish('preflight-' + field + '-' + str(ordinal), source,
            code=code, delivered=[], checked=[], preflight=True,
            requested=t.TABLE.size + 2 * t.TRANSACTION.size)
    source = baseline()
    source.owner_oldest = source.chains[0][1]['lsn']
    finish('first-before-retained', source, code=STALE, delivered=[], checked=[],
        preflight=True, requested=t.TABLE.size)
    source = baseline()
    source.owner_oldest = 0
    finish('no-retained-chain-bound', source, code=UNSUPPORTED, delivered=[], checked=[],
        preflight=True, requested=t.TABLE.size)
    source = baseline()
    source.seeds[3]['undo_records'] = 1
    finish('empty-seed-with-undo-credit', source, code=UNSUPPORTED, delivered=[], checked=[],
        preflight=True, requested=t.TABLE.size + 3 * t.TRANSACTION.size)
    for field, value, code in (('transaction', t.TABLE.size, STALE),
                              ('client_sequence', w.CLIENT_SEQUENCE + 1, STALE)):
        source = Seeds(entries=3, free=(1,))
        source.add(0)
        source.add(2, changes={field: value})
        finish('foreign-root-' + field, source, code=code, delivered=[0], checked=[0],
            extra_reads=1, examined=2, requested=t.TABLE.size + 2 * t.TRANSACTION.size)
    finish('short-transaction-admission', baseline(), code=RANGE, delivered=[], checked=[],
        preflight=True, max_transactions=2)
    finish('short-minimum-record-admission', baseline(), code=RANGE, delivered=[], checked=[],
        preflight=True, max_records=1)
    for count in (MAX_RECORDS, MAX_RECORDS + 1):
        source = Seeds(entries=2, free=(), dense=True)
        for ordinal in range(count):
            source.add(ordinal % 2)
        if count == MAX_RECORDS:
            finish('aggregate-exact-record-cap', source)
        else:
            # Entry zero owns the extra packet. Its complete chain is accepted,
            # then entry one hits the remaining aggregate cap after 2047 packets.
            name = 'aggregate-record-cap-plus-one'
            finish(name, source, code=RANGE, delivered=[0], checked=[0],
                requested=t.TABLE.size + t.TRANSACTION.size)
            case = cases[-1]
            partial = list(reversed(source.chains[1]))[:MAX_RECORDS - len(source.chains[0])]
            case['report']['read_calls'] += len(partial)
            case['report']['read_bytes'] += len(partial) * source.window.log
            case['report']['record_bytes'] += sum(len(p['packet']) for p in partial)
            case['report']['examined_records'] = case['report']['checked_records'] = MAX_RECORDS
            report = case['report']
            (output / (case['path'] + '.expected')).write_text(' '.join(map(str,
                [int(case['checkpoint'][field]) for field in CAPTURE_FIELDS] +
                [int(report[field]) for field in REPORT_FIELDS])) + '\n')
    for count in (MAX_TABLE_ENTRIES,):
        source = Seeds(entries=count, free=(), size=LARGE_SOURCE_BYTES)
        for ordinal in range(count):
            source.empty(ordinal)
        # A maximum table spans pages and must not overlap its restart packet.
        packet_bytes = source.window.header + STORED_UPDATE_BYTES + t.TABLE.size + count * t.TRANSACTION.size
        page_payload = source.window.log - source.window.data
        source.checkpoint_page = source.table_page + (packet_bytes + page_payload - 1) // page_payload + 4
        finish('maximum-wire-table', source, delivered=list(range(count)), checked=[],
            preflight=True, max_transactions=count)
        finish('short-maximum-wire-table', source, code=RANGE, delivered=[], checked=[],
            preflight=True, max_transactions=count - 1)
    assert len({case['path'] for case in cases}) == len(cases)
    (output / 'cases.tsv').write_text(''.join(f"{case['path']} {case['code']} {case['max_records']} {case['max_transactions']}\n" for case in cases))
    manifest = dict(cases=cases, case_count=len(cases))
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


if __name__ == '__main__':
    manifest = author(Path(sys.argv[1]))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text(str(manifest['case_count']) + '\n')
