#!/usr/bin/env python3
"""Independent target-selection goldens and original exact record packets."""
from pathlib import Path
import copy
import hashlib
import json
import struct
import sys
import logfile_fixtures as w
import logfile_inventory_fixtures as physical
import logfile_fast_fixtures as fast
import logfile_legacy_fixtures as legacy

OK, CORRUPT, UNSUPPORTED, NOT_FOUND, INVALID = 0, 2, 3, 6, 9
CIRCULAR, TAIL, FAST = 0, 1, 2
TRANSFER_COUNT, TRANSFER_POSITION = 3, 2
OTHER_FILL, CONFLICT_FILL = 0x39, 0xe3
PAIR_READS = 2
INDEX_FIELDS = ('target_offset', 'epoch_lsn', 'code', 'prefix_conflict',
                'selected_offset', 'storage', 'copy_value', 'last_end_lsn',
                'flags', 'page_count', 'page_position', 'next_record_offset')
REPORT_FIELDS = ('indexed_targets', 'selected_pages', 'missing_targets',
                 'corrupt_targets', 'unsupported_targets', 'prefix_conflicts',
                 'compared_prefixes', 'unrouted_copies', 'unsupported_copies',
                 'read_calls')


def restored_page(raw):
    """Apply the independently authored USA words, preserving all other bytes."""
    words = dict(w.PAGE.fields)
    usa_offset = struct.unpack_from('<' + words['usa_offset'], raw,
                                    w.PAGE.offsets['usa_offset'])[0]
    usa_count = struct.unpack_from('<' + words['usa_count'], raw,
                                   w.PAGE.offsets['usa_count'])[0]
    result = bytearray(raw)
    for sector in range(1, usa_count):
        start = usa_offset + sector * w.WORD_BYTES
        tail = sector * w.USA_STRIDE - w.WORD_BYTES
        result[tail:tail + w.WORD_BYTES] = raw[start:start + w.WORD_BYTES]
    return result


def target_oracle(case, raw, *, legacy_version):
    """Project declared observations by mathematical epoch groups and byte equality.

    The inputs are the fixture author's full metadata declarations, not decoder
    output. Record bytes have a separate original packet oracle.
    """
    rows, log = case['rows'], case['log_page_bytes']
    copies = [row for row in rows if row['storage'] != CIRCULAR]
    circular = [row for row in rows if row['storage'] == CIRCULAR]
    targets, comparisons, extra_reads = [], 0, 0
    for base in circular:
        candidates = [row for row in rows if row['code'] == OK and
                      row['target_code'] == OK and row['target_offset'] == base['offset']]
        blocked = base['code'] == UNSUPPORTED or (
            base['code'] == OK and base['target_code'] == UNSUPPORTED)
        target = dict(target_offset=base['offset'], epoch_lsn=0,
                      code=base['target_code'] if base['code'] == OK else base['code'],
                      prefix_conflict=False, selected_offset=0, storage=CIRCULAR, page=None)
        if candidates:
            epoch = lambda row: row['page']['last_end_lsn' if legacy_version else 'copy_value']
            newest = max(map(epoch, candidates))
            peers = sorted((row for row in candidates if epoch(row) == newest),
                           key=lambda row: row['offset'])
            selected = peers[0]
            page = selected['page']
            target.update(epoch_lsn=newest, code=OK, selected_offset=selected['offset'],
                          storage=selected['storage'], page=page)
            incomplete = selected['storage'] != CIRCULAR and (
                not page['flags'] & w.RECORD_END or not page['last_end_lsn'] or
                page['next_record_offset'] < case['data_offset'])
            if blocked or incomplete:
                target['code'] = UNSUPPORTED
            elif len(peers) > 1:
                # Each peer is re-read once; the canonical prefix is private.
                extra_reads += len(peers)
                comparisons += len(peers) - 1
                spans = []
                for peer in peers:
                    fields = peer['page']
                    restored = restored_page(raw[peer['offset']:peer['offset'] + log])
                    spans.append((fields['flags'], fields['last_end_lsn'],
                        fields['next_record_offset'],
                        bytes(restored[case['data_offset']:fields['next_record_offset']])))
                if any(span != spans[0] for span in spans[1:]):
                    target.update(code=UNSUPPORTED, prefix_conflict=True)
        elif blocked:
            target['code'] = UNSUPPORTED
        targets.append(target)
    unresolved = [row for row in copies if row['code'] != OK or row['target_code'] != OK]
    report = dict(published=True, indexed_targets=len(targets),
        selected_pages=sum(row['code'] == OK for row in targets),
        missing_targets=sum(row['code'] == NOT_FOUND for row in targets),
        corrupt_targets=sum(row['code'] == CORRUPT for row in targets),
        unsupported_targets=sum(row['code'] == UNSUPPORTED for row in targets),
        prefix_conflicts=sum(row['prefix_conflict'] for row in targets),
        compared_prefixes=comparisons,
        unrouted_copies=sum(row['code'] != NOT_FOUND for row in unresolved),
        unsupported_copies=sum((row['target_code'] if row['code'] == OK else row['code']) ==
                               UNSUPPORTED for row in unresolved),
        read_calls=len(rows) + extra_reads, read_bytes=(len(rows) + extra_reads) * log,
        physical_complete=True, physical_pages=len(rows), physical_examined=len(rows),
        physical_visited=len(rows))
    return targets, report


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    original = physical.author(output / 'physical')
    cases = []

    def finish(case, path, *, legacy_version, faults=False):
        raw = (output / path).read_bytes()
        circular = next(row['offset'] for row in case['rows'] if row['storage'] == CIRCULAR)
        case = dict(case, data_offset=case.get('data_offset',
            w.aligned(w.PAGE.size + (case['log_page_bytes'] // w.USA_STRIDE + 1) * w.WORD_BYTES)
            if legacy_version else physical.FAST.size))
        supported = legacy_version or (case['system_page_bytes'] == physical.FAST_PAGE_BYTES and
            case['log_page_bytes'] == physical.FAST_PAGE_BYTES)
        targets, report = target_oracle(case, raw, legacy_version=legacy_version) if supported else (
            [], dict.fromkeys(REPORT_FIELDS, 0))
        if not supported:
            report.update(published=False, read_bytes=0, physical_complete=False,
                          physical_pages=0, physical_examined=0, physical_visited=0)
        copies = w.LEGACY_TAIL_PAGES if legacy_version else w.FAST_PAGES
        cases.append(dict(path=path, code=OK if supported else UNSUPPORTED,
            page_bytes=case['log_page_bytes'], circular_offset=circular, copy_pages=copies,
            maximum_reads=len(case['rows']) + PAIR_READS * copies, faults=faults,
            targets=targets, index=report, source_sha256=hashlib.sha256(raw).hexdigest()))
        lines = []
        for target in targets:
            flat = dict(target, prefix_conflict=int(target['prefix_conflict']))
            flat.update(target['page'] or dict.fromkeys(INDEX_FIELDS[6:], 0))
            lines.append(' '.join(str(flat[key]) for key in INDEX_FIELDS))
        (output / (path + '.index.rows')).write_text('\n'.join(lines) + '\n')

    for case in original:
        legacy_version = case['path'].startswith('legacy-')
        finish(case, 'physical/' + case['path'], legacy_version=legacy_version)

    # These graphs make the entire equivalence group and cross-target read
    # bounds visible; older disagreements cannot override a unique newer epoch.
    def graph(name, *, legacy_version=False):
        template = next(case for case in original if case['path'] ==
                        ('legacy-512.journal' if legacy_version else 'later-fast-slot-00.journal'))
        case = copy.deepcopy(template)
        case['path'] = name + '.journal'
        case['data_offset'] = w.aligned(w.PAGE.size +
            (case['log_page_bytes'] // w.USA_STRIDE + 1) * w.WORD_BYTES) if legacy_version else physical.FAST.size
        source = bytearray((output / 'physical' / template['path']).read_bytes())
        first = w.RESTART_PAGES * case['system_page_bytes']
        source[first:] = bytes(len(source) - first)
        for row in case['rows']:
            row.update(code=NOT_FOUND, target_code=INVALID, target_offset=0, page=None)
        return case, source

    def store(case, source, offset, *, target=None, epoch=None, ending=None,
              flags=w.RECORD_END, next_record=None, fill=physical.FILL_BYTE,
              sequence=w.USA_SEQUENCE, count=TRANSFER_COUNT, position=TRANSFER_POSITION,
              conflict=False, unused=False, unsupported=False):
        row = next(row for row in case['rows'] if row['offset'] == offset)
        circular = next(row['offset'] for row in case['rows'] if row['storage'] == CIRCULAR)
        target = circular if target is None else target
        epoch = w.lsn_at(target + case['data_offset'], len(source)) if epoch is None else epoch
        ending = epoch if ending is None else ending
        next_record = case['data_offset'] + w.RECORD.size if next_record is None else next_record
        fields = dict(copy_value=target if row['storage'] == TAIL else epoch,
            last_end_lsn=ending, flags=flags, page_count=count, page_position=position,
            next_record_offset=next_record)
        logical = bytearray([fill]) * case['log_page_bytes']
        logical[:w.PAGE.size] = w.PAGE.pack(dict(magic=b'RCRD', usa_offset=w.PAGE.size, **fields))
        if row['storage'] == FAST:
            physical.FAST.put(logical, 'file_offset', target)
        if conflict:
            logical[case['data_offset'] + w.WORD_BYTES] = CONFLICT_FILL
        if unused:
            logical[next_record:] = bytes([OTHER_FILL]) * (len(logical) - next_record)
        raw, _ = w.protect(logical, w.PAGE)
        raw = bytearray(raw)
        w.PAGE.put(raw, 'usa_count', len(raw) // w.USA_STRIDE + 1)
        struct.pack_into('<H', raw, w.PAGE.size, sequence)
        for sector in range(1, len(raw) // w.USA_STRIDE + 1):
            struct.pack_into('<H', raw, sector * w.USA_STRIDE - w.WORD_BYTES, sequence)
        source[offset:offset + len(raw)] = raw
        row.update(code=OK, target_code=UNSUPPORTED if unsupported else OK,
                   target_offset=0 if unsupported else target, page=fields)

    for name in ('all-fast-and-circular-equal', 'late-prefix-conflict',
                 'early-prefix-conflict', 'newest-over-older-conflicts',
                 'two-independent-target-groups', 'all-target-groups-paired',
                 'unknown-circular-blocks-copy', 'incomplete-copy-no-fallback',
                 'future-epoch-after-restart'):
        case, source = graph(name)
        log, rows = case['log_page_bytes'], case['rows']
        circular = next(row['offset'] for row in rows if row['storage'] == CIRCULAR)
        first = w.RESTART_PAGES * case['system_page_bytes']
        for slot in range(w.FAST_PAGES):
            target = circular
            if name == 'two-independent-target-groups':
                target += (slot % PAIR_READS) * log
            elif name == 'all-target-groups-paired':
                target += slot * log
            epoch = w.lsn_at(target + case['data_offset'], len(source))
            newer = name == 'newest-over-older-conflicts' and slot == w.FAST_PAGES - 1
            if newer or name == 'future-epoch-after-restart':
                epoch += w.ALIGNMENT
            store(case, source, first + slot * log, target=target, epoch=epoch,
                conflict=(name == 'late-prefix-conflict' and slot == w.FAST_PAGES - 1) or
                         (name in ('early-prefix-conflict', 'newest-over-older-conflicts') and slot == 1),
                unused=slot % PAIR_READS == 0, sequence=w.USA_SEQUENCE + slot,
                flags=0 if name == 'incomplete-copy-no-fallback' else w.RECORD_END,
                ending=0 if name == 'incomplete-copy-no-fallback' else epoch)
        circular_targets = w.FAST_PAGES if name == 'all-target-groups-paired' else (
            PAIR_READS if name == 'two-independent-target-groups' else 1)
        for target_slot in range(circular_targets):
            target = circular + target_slot * log
            store(case, source, target, target=target,
                flags=physical.UNKNOWN_PAGE_FLAG if name == 'unknown-circular-blocks-copy' else w.RECORD_END,
                unsupported=name == 'unknown-circular-blocks-copy')
        (output / case['path']).write_bytes(source)
        finish(case, case['path'], legacy_version=False,
               faults=name in ('all-fast-and-circular-equal', 'all-target-groups-paired',
                               'early-prefix-conflict'))

    for name in ('legacy-both-tails-and-circle-equal', 'legacy-last-end-orders-circle'):
        case, source = graph(name, legacy_version=True)
        first = w.RESTART_PAGES * case['system_page_bytes']
        circular = next(row['offset'] for row in case['rows'] if row['storage'] == CIRCULAR)
        epoch = w.lsn_at(circular + case['data_offset'], len(source))
        for slot in range(w.LEGACY_TAIL_PAGES):
            store(case, source, first + slot * case['log_page_bytes'], epoch=epoch)
        store(case, source, circular, epoch=epoch + w.ALIGNMENT,
              ending=epoch if name.endswith('-equal') else epoch + w.ALIGNMENT)
        (output / case['path']).write_bytes(source)
        finish(case, case['path'], legacy_version=True,
               faults=name == 'legacy-both-tails-and-circle-equal')

    changes = []
    equal = next(case for case in cases if case['path'] == 'all-fast-and-circular-equal.journal')
    source = (output / equal['path']).read_bytes()
    first = w.RESTART_PAGES * physical.FAST_PAGE_BYTES
    circle = equal['circular_offset']
    for role, offset, read in (('canonical', first, equal['index']['physical_pages'] + 1),
                              ('duplicate', first + physical.FAST_PAGE_BYTES,
                               equal['index']['physical_pages'] + PAIR_READS),
                              ('circular', circle, equal['index']['read_calls'])):
        original = restored_page(source[offset:offset + physical.FAST_PAGE_BYTES])
        current = w.lsn_at(circle + physical.FAST.size, len(source))
        for field, value in (
            ('copy_value', current + w.ALIGNMENT), ('last_end_lsn', 0),
            ('flags', w.RECORD_END | physical.CLIENT_RESTART_PAGE),
            ('page_count', TRANSFER_COUNT + 1), ('page_position', TRANSFER_POSITION - 1),
            ('next_record_offset', physical.FAST.size + w.RECORD.size + w.ALIGNMENT),
            *((('file_offset', circle + physical.FAST_PAGE_BYTES),) if role != 'circular' else ())):
            changed = bytearray(original)
            physical.FAST.put(changed, field, value)
            raw, _ = w.protect(changed, w.PAGE)
            filename = f'index-changed-{role}-{field}.page'
            (output / filename).write_bytes(raw)
            changes.append(dict(path=filename, offset=offset, read=read,
                                source_sha256=hashlib.sha256(raw).hexdigest()))
    (output / 'changes.tsv').write_text('\n'.join(
        f'{change["path"]} {change["offset"]} {change["read"]}' for change in changes) + '\n')

    records = []
    for category, authored in (('fast', fast.author(output / 'fast')),
                               ('legacy', legacy.author(output / 'legacy'))):
        for case in authored:
            case = dict(case, path=category + '/' + case['path'])
            # Signature absence is preserved as NOT_FOUND by complete inventory.
            if case['path'] in ('fast/no-valid-storage.journal', 'legacy/no-valid-page.journal',
                                'fast/legacy-layout-refused.journal'):
                case['code'] = NOT_FOUND
            case['reads'] = case['pages'] if case['code'] == OK else 0
            records.append(case)
    (output / 'manifest.json').write_text(json.dumps(dict(schema_version=1,
        origin='Original physical declarations, complete equivalence groups and exact packets; '
               'no current-history or recovery acceptance', cases=cases, records=records,
        changes=changes), indent=2) + '\n')
    (output / 'cases.tsv').write_text('\n'.join(' '.join(map(str, (
        case['path'], case['code'], case['page_bytes'], case['copy_pages'],
        *(case['index'][key] for key in REPORT_FIELDS), int(case['faults']))))
        for case in cases) + '\n')
    (output / 'records.tsv').write_text('\n'.join(' '.join(map(str, (
        case['path'], case['code'], case['lsn'], case['bytes'], case['pages'],
        case['copies'], case['page_bytes'], case['first_page'], case['last_page'],
        int(case['wrapped'])))) for case in records) + '\n')
    return cases, records


if __name__ == '__main__':
    cases, records = author(Path(sys.argv[1]))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text(f'{len(cases)} target-index graphs/{len(records)} exact packets\n')
