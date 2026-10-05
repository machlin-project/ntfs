#!/usr/bin/env python3
"""Original selected record windows, declared page fragments and packet oracles."""
from pathlib import Path
import copy
import hashlib
import json
import sys
import logfile_fixtures as w
import logfile_inventory_fixtures as physical
from logfile_source_fixtures import restart, SMALL_FILE_BYTES, SMALL_PAGE_BYTES

OK, CORRUPT, UNSUPPORTED, NOT_FOUND, STALE, RANGE = 0, 2, 3, 6, 10, 11
PAGE_FILL = 0xcd
EXTENSION_FILL = 0x7e
PAYLOAD_FACTOR, PAYLOAD_MODULUS = 29, 251
TRANSFER_COUNT, TRANSFER_POSITION = 5, 2
MAX_RECORD_BYTES = 1024 * 1024
HEADER_GAP = 3 * w.ALIGNMENT
MANY_RECORDS, RECORDS_PER_PAGE = 600, 80
MAX_SOURCE_BYTES = 4 * 1024 * 1024


class Window:
    def __init__(self, modern=False, header=w.RECORD.size, *, log=None, size=None):
        self.modern, self.header = modern, header
        self.log = log or (physical.FAST_PAGE_BYTES if modern else SMALL_PAGE_BYTES)
        self.size = size or (physical.BASE_FILE_BYTES if modern else SMALL_FILE_BYTES)
        self.copies = w.FAST_PAGES if modern else w.LEGACY_TAIL_PAGES
        self.circular = (w.RESTART_PAGES + self.copies) * self.log
        self.data = physical.FAST.size if modern else max(w.PAGE_DATA_OFFSET,
            w.aligned(w.PAGE.size + (self.log // w.USA_STRIDE + 1) * w.WORD_BYTES))
        self.pages = {}

    def lsn(self, page, offset, sequence=w.LSN_SEQUENCE):
        return w.lsn_at(self.circular + page * self.log + offset, self.size, sequence)

    def record(self, page, offset, length=37, *, sequence=w.LSN_SEQUENCE,
               flags=0, previous=0, undo=0, kind=w.UPDATE_TYPE):
        body = bytes(index * PAYLOAD_FACTOR % PAYLOAD_MODULUS for index in range(length))
        fields = dict(lsn=self.lsn(page, offset, sequence), previous_lsn=previous,
            undo_next_lsn=undo, client_sequence=w.CLIENT_SEQUENCE, client_index=0,
            type=kind, transaction=w.TRANSACTION, flags=flags)
        packet = w.RECORD.pack(dict(fields, data_bytes=length))
        packet += bytes([EXTENSION_FILL]) * (self.header - w.RECORD.size) + body
        fields['data'] = dict(offset=self.header, length=length)
        return dict(record=fields, packet=bytes(packet), page=page, offset=offset,
                    sequence=sequence, end_page=page, end_offset=offset + len(packet),
                    pages=1, copies=0, wrapped=False)

    def page(self, ordinal, *, start, end=0, next_offset=None, chunks=(), slot=None,
             flags=None, count=TRANSFER_COUNT, position=TRANSFER_POSITION, target=None):
        address = self.circular + ordinal * self.log
        physical_address = address if slot is None else (w.RESTART_PAGES + slot) * self.log
        values = dict(magic=b'RCRD', usa_offset=w.PAGE.size,
            copy_value=address if slot is not None and not self.modern else start,
            last_end_lsn=end, flags=(w.RECORD_END if end else 0) if flags is None else flags,
            page_count=count, page_position=position,
            next_record_offset=self.data if next_offset is None else next_offset)
        self.pages[physical_address] = dict(fields=values, chunks=list(chunks),
            target=address if target is None else target, slot=slot)
        return physical_address

    def raw(self, first):
        source = bytearray(self.size)
        raw, _ = restart(major=w.FAST_MAJOR if self.modern else w.LEGACY_MAJOR,
            minor=w.FAST_MINOR if self.modern else w.LEGACY_MINOR,
            system=self.log, log=self.log, file_bytes=self.size,
            record_header_bytes=self.header, page_data_offset=self.data, current=first)
        for ordinal in range(w.RESTART_PAGES):
            source[ordinal * self.log:(ordinal + 1) * self.log] = raw
        for address, page in self.pages.items():
            logical = bytearray([PAGE_FILL]) * self.log
            logical[:w.PAGE.size] = w.PAGE.pack(page['fields'])
            if self.modern:
                physical.FAST.put(logical, 'file_offset', page['target'])
            for offset, packet in page['chunks']:
                assert offset >= self.data and offset + len(packet) <= self.log
                logical[offset:offset + len(packet)] = packet
            protected, _ = w.protect(logical, w.PAGE)
            source[address:address + self.log] = protected
        return bytes(source)


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    cases = []

    def finish(name, window, records, *, code=OK, first=None, candidate=None,
               observed=None, reads=None, tail=None, tail_verified=False,
               endpoint=None, next_lsn=None):
        path = name + '.journal'
        assert not any(case['path'] == path for case in cases)
        first = records[0]['record']['lsn'] if first is None else first
        candidate = records[-1]['record']['lsn'] if candidate is None else candidate
        observed = candidate if observed is None else observed
        endpoint = code == OK if endpoint is None else endpoint
        expected = []
        for ordinal, record in enumerate(records):
            packet_path = path + f'.packet-{ordinal}'
            (output / packet_path).write_bytes(record['packet'])
            expected.append(dict(record=record['record'], packet_path=packet_path,
                packet_sha256=hashlib.sha256(record['packet']).hexdigest(),
                assembly=dict(first_page_offset=window.circular + record['page'] * window.log,
                    last_page_offset=window.circular + record['end_page'] * window.log,
                    bytes=len(record['packet']), pages_read=record['pages'],
                    copy_pages_read=record['copies'], read_calls=record['pages'],
                    read_bytes=record['pages'] * window.log, wrapped=record['wrapped'])))
        reads = sum(record['pages'] for record in records) + int(tail is not None) if reads is None else reads
        raw = window.raw(first or window.lsn(0, window.data))
        (output / path).write_bytes(raw)
        report = dict(first_lsn=first, candidate_end_lsn=candidate,
            observed_start_lsn=observed, record_bytes=sum(len(record['packet']) for record in records),
            read_calls=reads, read_bytes=reads * window.log, examined_records=len(records),
            visited_records=len(records), copy_pages_read=sum(record['copies'] for record in records),
            endpoint_verified=endpoint, tail_verified=tail_verified, complete=code == OK,
            wrapped=any(record['wrapped'] for record in records))
        if code == OK:
            final = records[-1]
            next_offset = w.aligned(final['end_offset'])
            next_page, sequence = final['end_page'], final['sequence'] + int(final['wrapped'])
            if next_offset + window.header > window.log:
                next_offset = window.data
                next_page += 1
                if window.circular + next_page * window.log == window.size:
                    next_page, sequence = 0, sequence + 1
            report.update(completed_end_lsn=candidate, last_lsn=candidate,
                          next_lsn=window.lsn(next_page, next_offset, sequence), tail_lsn=0)
            if tail is not None:
                report.update(tail_lsn=tail, next_lsn=tail)
            if next_lsn is not None:
                report['next_lsn'] = next_lsn
        case = dict(path=path, code=code, first_lsn=first, page_bytes=window.log,
                    records=expected, history=report, source_sha256=hashlib.sha256(raw).hexdigest())
        cases.append(case)
        (output / (path + '.packets.rows')).write_text('\n'.join(
            ' '.join(map(str, (entry['record']['lsn'], entry['assembly']['bytes'],
                entry['assembly']['first_page_offset'], entry['assembly']['last_page_offset'],
                entry['assembly']['pages_read'], entry['assembly']['copy_pages_read'],
                int(entry['assembly']['wrapped'])))) for entry in expected) + '\n')

    def single(modern=False, header=w.RECORD.size, page=0, offset=None, sequence=w.LSN_SEQUENCE):
        window = Window(modern, header)
        offset = window.data if offset is None else offset
        records = []
        for length in (0, 37, 19):
            record = window.record(page, offset, length, sequence=sequence,
                previous=records[-1]['record']['lsn'] if records else 0)
            records.append(record)
            offset = w.aligned(record['end_offset'])
        address = window.page(page, start=records[-1]['record']['lsn'],
            end=records[-1]['record']['lsn'], next_offset=offset,
            chunks=[(record['offset'], record['packet']) for record in records])
        return window, records, address

    for modern in (False, True):
        label = 'fast' if modern else 'legacy'
        for header in (w.RECORD.size, w.EXTENDED_RECORD_HEADER_BYTES):
            window, records, address = single(modern, header)
            finish(f'{label}-adjacent-header-{header}', window, records)
        window, records, address = single(modern)
        base_window, base_records, base_address = window, records, address
        gap_window, gap_records, _ = single(modern, offset=window.data + HEADER_GAP)
        finish(label + '-exact-anchor-after-gap', gap_window, gap_records)
        # Exact caller anchors can start within a written page. They are not
        # inferred from RSTR or from a page's last-start tag.
        finish(label + '-suffix', window, records[1:])
        finish(label + '-endpoint-only', window, records[-1:])
        for slot in range(window.copies):
            copy_window, copy_records = copy.deepcopy(window), copy.deepcopy(records)
            page = copy_window.pages.pop(address)
            copy_address = (w.RESTART_PAGES + slot) * window.log
            if not modern:
                page['fields']['copy_value'] = address
            page['slot'] = slot
            copy_window.pages[copy_address] = page
            for record in copy_records:
                record['copies'] = 1
            finish(f'{label}-copy-slot-{slot}', copy_window, copy_records,
                   observed=None if modern else 0)

        # A closed written prefix can leave unused page space before the next
        # physical page; padding is never interpreted as a record.
        window = Window(modern)
        first = window.record(0, window.data, 13)
        second = window.record(1, window.data, 27, previous=first['record']['lsn'])
        for ordinal, record in enumerate((first, second)):
            window.page(ordinal, start=record['record']['lsn'], end=record['record']['lsn'],
                next_offset=w.aligned(record['end_offset']), chunks=[(record['offset'], record['packet'])],
                count=1, position=1)
        finish(label + '-closed-prefix-gap', window, [first, second])

        # Completed records span independently declared chunks. Transfer metadata
        # is intentionally different on each page and does not delimit records.
        window = Window(modern)
        first = window.record(0, window.data, 1)
        span_offset = w.aligned(first['end_offset'])
        span = window.record(0, span_offset, 2 * window.log, flags=w.MULTI_PAGE,
                             previous=first['record']['lsn'])
        first_bytes = window.log - span_offset
        middle_bytes = window.log - window.data
        final_chunk = span['packet'][first_bytes + middle_bytes:]
        span.update(end_page=2, end_offset=window.data + len(final_chunk), pages=3)
        window.page(0, start=span['record']['lsn'], end=first['record']['lsn'],
            next_offset=span_offset, chunks=[(first['offset'], first['packet']),
                (span_offset, span['packet'][:first_bytes])], count=1, position=1)
        window.page(1, start=span['record']['lsn'] if modern else 0,
            chunks=[(window.data, span['packet'][first_bytes:first_bytes + middle_bytes])],
            count=TRANSFER_COUNT, position=TRANSFER_COUNT)
        window.page(2, start=span['record']['lsn'] if modern else 0,
            end=span['record']['lsn'], next_offset=w.aligned(span['end_offset']),
            chunks=[(window.data, final_chunk)], count=2, position=1)
        finish(label + '-three-page-record', window, [first, span])
        if not modern:
            tail_window, tail_records = copy.deepcopy(window), copy.deepcopy([first, span])
            tail_window.page(0, start=span['record']['lsn'], end=first['record']['lsn'],
                next_offset=span_offset, chunks=[(first['offset'], first['packet'])], slot=0,
                count=1, position=1)
            tail_records[0]['copies'] = 1
            finish('legacy-tail-prefix-circular-span', tail_window, tail_records)
        else:
            # Last-start names the header on page zero; the copy's routing DWORD
            # names page two. They must not be substituted for each other.
            copied, copied_records = copy.deepcopy(window), copy.deepcopy([first, span])
            final_address = copied.circular + 2 * copied.log
            page = copied.pages.pop(final_address)
            page['slot'] = 0
            copied.pages[w.RESTART_PAGES * copied.log] = page
            copied_records[1]['copies'] = 1
            finish('fast-continuation-copy-target', copied, copied_records)
            zero = copy.deepcopy(window)
            zero.pages[zero.circular + zero.log]['fields']['copy_value'] = 0
            finish('fast-zero-start-unqualified', zero, [first], code=NOT_FOUND,
                candidate=span['record']['lsn'], observed=span['record']['lsn'], reads=2)
        for field, value, code in (('copy_value', first['record']['lsn'], STALE),
                                  ('next_record_offset', window.data + w.ALIGNMENT, CORRUPT),
                                  ('last_end_lsn', first['record']['lsn'], CORRUPT),
                                  ('flags', w.RECORD_END, CORRUPT)):
            changed = copy.deepcopy(window)
            changed.pages[changed.circular + changed.log]['fields'][field] = value
            finish(f'{label}-middle-{field}', changed, [first], code=code,
                candidate=span['record']['lsn'], observed=span['record']['lsn'], reads=3)
        changed = copy.deepcopy(window)
        broken = bytearray(span['packet'])
        w.RECORD.put(broken, 'flags', 0)
        changed.pages[changed.circular]['chunks'][-1] = (span_offset, bytes(broken[:first_bytes]))
        finish(label + '-missing-multipage-flag', changed, [first], code=CORRUPT,
            candidate=span['record']['lsn'], observed=span['record']['lsn'], reads=4)

        # An unfinished successor has only a complete header and its first body
        # fragment. It is reported separately, never emitted as complete data.
        for following_page in (False, True):
            window, records, address = single(modern)
            ordinal = 1 if following_page else 0
            offset = window.data if following_page else w.aligned(records[-1]['end_offset'])
            tail = window.record(ordinal, offset, window.log, flags=w.MULTI_PAGE,
                previous=records[-1]['record']['lsn'])
            fields = dict(start=tail['record']['lsn'], next_offset=offset,
                chunks=[(offset, tail['packet'][:window.log - offset])])
            if following_page:
                window.page(ordinal, **fields)
            else:
                window.pages[address]['fields']['copy_value'] = tail['record']['lsn']
                window.pages[address]['chunks'].append(fields['chunks'][0])
            suffix = 'next-page' if following_page else 'same-page'
            finish(f'{label}-unfinished-{suffix}', window, records,
                observed=tail['record']['lsn'], tail=tail['record']['lsn'], tail_verified=True)
            if modern and following_page:
                copied = copy.deepcopy(window)
                page = copied.pages.pop(copied.circular + copied.log)
                page['slot'] = 0
                copied.pages[w.RESTART_PAGES * copied.log] = page
                finish('fast-unfinished-copy', copied, records, observed=tail['record']['lsn'],
                    tail=tail['record']['lsn'], tail_verified=True)
                duplicate = copy.deepcopy(copied)
                duplicate.pages[(w.RESTART_PAGES + 1) * copied.log] = copy.deepcopy(page)
                duplicate.pages[(w.RESTART_PAGES + 1) * copied.log]['slot'] = 1
                finish('fast-unfinished-equivalent-copies-unqualified', duplicate, [],
                    code=UNSUPPORTED, first=records[0]['record']['lsn'], candidate=0,
                    observed=0, reads=0)
            for field, value, code in (('lsn', tail['record']['lsn'] + 1, STALE),
                ('flags', 0, CORRUPT), ('data_bytes', 0, CORRUPT),
                ('data_bytes', MAX_RECORD_BYTES, RANGE), ('previous_lsn', 1, CORRUPT),
                ('flags', w.UNKNOWN_RECORD_FLAG, UNSUPPORTED)):
                broken = copy.deepcopy(window)
                tail_address = broken.circular + ordinal * broken.log
                packet = bytearray(broken.pages[tail_address]['chunks'][-1][1])
                w.RECORD.put(packet, field, value)
                broken.pages[tail_address]['chunks'][-1] = (offset, bytes(packet))
                finish(f'{label}-unfinished-{suffix}-{field}-{value}', broken, records,
                    code=code, observed=tail['record']['lsn'], tail=tail['record']['lsn'],
                    endpoint=True)

        # Ring sequence increments are tied to physical wrap, including a
        # record's continuation, rather than to an I/O transfer number.
        window = Window(modern)
        last_page = (window.size - window.circular) // window.log - 1
        first = window.record(last_page, window.data, 23)
        second = window.record(0, window.data, 39, sequence=w.LSN_SEQUENCE + 1)
        for ordinal, record in ((last_page, first), (0, second)):
            window.page(ordinal, start=record['record']['lsn'], end=record['record']['lsn'],
                next_offset=w.aligned(record['end_offset']), chunks=[(record['offset'], record['packet'])])
        finish(label + '-record-window-wrap', window, [first, second])
        cases[-1]['history']['wrapped'] = True
        span = window.record(last_page, window.log - window.header, window.log - window.data,
            flags=w.MULTI_PAGE)
        span.update(end_page=0, end_offset=window.log,
                    pages=2, wrapped=True)
        window.pages.clear()
        window.page(last_page, start=span['record']['lsn'], next_offset=span['offset'],
            chunks=[(span['offset'], span['packet'][:window.header])])
        window.page(0, start=span['record']['lsn'], end=span['record']['lsn'],
            next_offset=w.aligned(span['end_offset']), chunks=[(window.data, span['packet'][window.header:])])
        finish(label + '-spanning-wrap', window, [span])

        window, records, address = copy.deepcopy(base_window), copy.deepcopy(base_records), base_address
        for field, value, code in (('next_record_offset', w.aligned(records[-1]['end_offset']) + w.ALIGNMENT, CORRUPT),
            ('next_record_offset', window.data, CORRUPT), ('flags', w.UNKNOWN_PAGE_FLAG, UNSUPPORTED),
            ('last_end_lsn', records[-1]['record']['lsn'] + 1, STALE)):
            changed = copy.deepcopy(window)
            changed.pages[address]['fields'][field] = value
            count = len(records) - 1 if field == 'next_record_offset' and value > window.data else 0
            if field == 'last_end_lsn':
                count, code = 0, CORRUPT
            candidate = value if field == 'last_end_lsn' else records[-1]['record']['lsn']
            finish(f'{label}-footer-{field}-{value}', changed, records[:count], code=code,
                first=records[0]['record']['lsn'], candidate=candidate,
                observed=records[-1]['record']['lsn'], reads=0
                if field == 'last_end_lsn' else count + 1 if code != UNSUPPORTED else 0)

        # Old duplicate completion tags do not hide a unique newer end. Their
        # page bytes are outside the caller's exact requested interval.
        window, records, address = single(modern, page=2)
        old = window.lsn(0, window.data, w.LSN_SEQUENCE - 1)
        for ordinal in (0, 1):
            window.page(ordinal, start=old, end=old, next_offset=window.data)
        finish(label + '-old-duplicate-ends', window, records)
        duplicate = copy.deepcopy(window)
        duplicate.page(3, start=records[-1]['record']['lsn'], end=records[-1]['record']['lsn'])
        finish(label + '-duplicate-candidate-end', duplicate, [], code=CORRUPT,
            first=records[0]['record']['lsn'], candidate=records[-1]['record']['lsn'],
            observed=records[-1]['record']['lsn'], reads=0)

        window, records, address = single(modern)
        for recent in (False, True):
            unroute = copy.deepcopy(window)
            epoch = records[-1]['record']['lsn'] if recent else window.lsn(0, window.data, w.LSN_SEQUENCE - 1)
            unroute.page(0, start=epoch, end=epoch, next_offset=window.data, slot=0, target=0)
            if not modern:
                unroute.pages[w.RESTART_PAGES * window.log]['fields']['copy_value'] = 0
            finish(f'{label}-unrouted-{"recent" if recent else "old"}', unroute,
                [] if recent else records, code=UNSUPPORTED if recent else OK,
                first=records[0]['record']['lsn'], candidate=0 if recent else None,
                observed=0 if recent else None, reads=0 if recent else None)
        undated = copy.deepcopy(window)
        undated.page(0, start=0, end=0, next_offset=window.data + w.ALIGNMENT, slot=0, target=0)
        if not modern:
            undated.pages[w.RESTART_PAGES * window.log]['fields']['copy_value'] = 0
        finish(label + '-unrouted-undated', undated, [], code=UNSUPPORTED,
            first=records[0]['record']['lsn'], candidate=0, observed=0, reads=0)
        finish(label + '-zero-anchor', window, [], code=NOT_FOUND, first=0,
               candidate=0, observed=0, reads=0)
        finish(label + '-anchor-after-end', window, [], code=NOT_FOUND,
            first=records[-1]['record']['lsn'] + 1, candidate=records[-1]['record']['lsn'],
            observed=records[-1]['record']['lsn'], reads=0)

        # A valid final record at the greatest representable sequence cannot
        # produce a representable successor after a ring wrap.
        window = Window(modern)
        bits = w.LSN_BITS + w.OFFSET_SHIFT - window.size.bit_length()
        sequence = (1 << bits) - 1
        page = (window.size - window.circular) // window.log - 1
        record = window.record(page, window.data, window.log - window.data - window.header,
                               sequence=sequence)
        window.page(page, start=record['record']['lsn'], end=record['record']['lsn'],
            next_offset=window.log, chunks=[(record['offset'], record['packet'])])
        finish(label + '-sequence-ceiling', window, [record], code=RANGE, endpoint=True)

    # A stale complete copy can route a continuation to a page different from
    # its header's LSN page. A newer incomplete copy must not erase that end.
    window = Window(True)
    record = window.record(0, window.data, 2 * window.log, flags=w.MULTI_PAGE)
    later = window.lsn(3, window.data)
    window.page(2, start=record['record']['lsn'], end=record['record']['lsn'], slot=0)
    window.page(2, start=later, slot=1)
    finish('fast-copy-completion-regression', window, [], code=STALE,
        first=record['record']['lsn'], candidate=0, observed=later, reads=0)

    # The exact record limit and the highest supported page size share the
    # ordinary bounded walker. Body length is an independent packet oracle.
    for excess in (0, 1):
        window = Window(log=w.MAX_PAGE_BYTES, size=MAX_SOURCE_BYTES)
        record = window.record(0, window.data, MAX_RECORD_BYTES - window.header + excess,
                               flags=w.MULTI_PAGE)
        pieces = [record['packet'][offset:offset + window.log - window.data]
                  for offset in range(0, len(record['packet']), window.log - window.data)]
        record.update(pages=len(pieces), end_page=len(pieces) - 1,
                      end_offset=window.data + len(pieces[-1]))
        for page, piece in enumerate(pieces):
            final = page == len(pieces) - 1
            window.page(page, start=record['record']['lsn'] if page == 0 else 0,
                end=record['record']['lsn'] if final else 0,
                next_offset=w.aligned(record['end_offset']) if final else window.data,
                chunks=[(window.data, piece)])
        finish('legacy-record-cap-' + ('excess' if excess else 'exact'), window,
            [] if excess else [record], code=RANGE if excess else OK,
            first=record['record']['lsn'], candidate=record['record']['lsn'],
            observed=record['record']['lsn'], reads=1 if excess else len(pieces))

    # Many complete records share each page. A physical-page-sized operation
    # budget can prepare the index but cannot silently reset for every record.
    window, records = Window(True), []
    for page in range((MANY_RECORDS + RECORDS_PER_PAGE - 1) // RECORDS_PER_PAGE):
        members = [window.record(page, window.data + index * window.header, 0)
            for index in range(min(RECORDS_PER_PAGE, MANY_RECORDS - len(records)))]
        records.extend(members)
        window.page(page, start=members[-1]['record']['lsn'], end=members[-1]['record']['lsn'],
            next_offset=members[-1]['end_offset'],
            chunks=[(record['offset'], record['packet']) for record in members])
    finish('fast-shared-operation-credits', window, records)

    (output / 'manifest.json').write_text(json.dumps(dict(cases=cases), indent=2) + '\n')
    (output / 'cases.tsv').write_text('\n'.join(' '.join(map(str, (
        case['path'], case['code'], case['first_lsn'], len(case['records']), case['page_bytes'],
        case['history']['read_calls'], int(case['history']['endpoint_verified']),
        int(case['history']['tail_verified']), int(case['history']['wrapped'])))) for case in cases) + '\n')
    return cases


if __name__ == '__main__':
    author(Path(sys.argv[1]))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text('original-selected-record-windows\n')
