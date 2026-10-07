#!/usr/bin/env python3
"""Independent whole-page settled checkpoint and publication oracles."""
from pathlib import Path
import json
import struct
import sys

import fixtures as f
import filename_storage as storage
import validation_fixtures as v
import logfile_fixtures as w
import logfile_tables_fixtures as tables
from logfile_checkpoint_fixtures import CLIENT_RESTART
from write_metadata_fixtures import FILE, STANDARD, NEW_TIME, ARCHIVE
from write_journal_fixtures import fields, restore_page, protect_page, guarded_publication

CLIENT_RESTART_PAGE = 0x00000002
OPEN_OPERATION = 28
FORGET_OPERATION = 27
INITIALIZE_FILE_OPERATION = 2
COMPENSATION_OPERATION = 1
ADDING_FLAG = 4
DELETING_FLAG = 2
MFT_TARGET_FLAG = 2
CHECKPOINT_PUBLICATIONS = 8
CHECKPOINT_BODY_BYTES = CLIENT_RESTART.size + 48
NOOP_OPERATION = 0


def log_geometry(image):
    first = f.MFT_LCN * f.CLUSTER + v.LOGFILE_RECORD * f.RECORD
    _, attributes = storage.record_parts(image[first:first + f.RECORD])
    stream, runs = storage.mapping(next(attribute for attribute in attributes
        if storage.attr_header(attribute)['type'] == f.DATA and not storage.attr_name(attribute)))
    assert len(runs) == 1 and runs[0][1] is not None
    return runs[0][1] * f.CLUSTER, stream['size']


def records(page):
    header = fields(w.PAGE, page)
    cursor = w.PAGE_DATA_OFFSET
    found = []
    while cursor < header['next_record_offset']:
        record = fields(w.RECORD, page, cursor)
        length = w.RECORD.size + record['data_bytes']
        assert cursor + length <= header['next_record_offset']
        found.append((cursor, record, length))
        cursor = w.aligned(cursor + length)
    assert cursor == header['next_record_offset']
    return found


def ordinary_settled_at_end(source, compensated):
    """Author a complete ordinary FILE lifetime ending at the last circular page."""
    candidate = bytearray(source)
    log_first, log_bytes = log_geometry(source)
    root, header, _ = restore_page(source[log_first:log_first + w.PAGE_BYTES], w.RESTART_HEADER)
    area = fields(w.RESTART_AREA, root, header['area_offset'])
    client_first = header['area_offset'] + area['clients_offset']
    client = fields(w.CLIENT, root, client_first)
    offset_bits = w.LSN_BITS - area['sequence_bits']
    epoch = area['current_lsn'] >> offset_bits
    mask = (1 << offset_bits) - 1
    quiet_page = ((client['oldest_lsn'] & mask) << w.OFFSET_SHIFT) // w.PAGE_BYTES * w.PAGE_BYTES
    packets = 6 if compensated else 4
    origin_page = log_bytes - (packets + 1) * w.PAGE_BYTES
    quiet, _, _ = restore_page(source[log_first + quiet_page:
                                      log_first + quiet_page + w.PAGE_BYTES], w.PAGE)
    mapping = {record['lsn']: w.lsn_at(origin_page + within, log_bytes, epoch, area['sequence_bits'])
               for within, record, _ in records(quiet)}
    circular = (w.RESTART_PAGES + w.LEGACY_TAIL_PAGES) * w.PAGE_BYTES
    candidate[log_first + w.RESTART_PAGES * w.PAGE_BYTES:log_first + log_bytes] = bytes(
        log_bytes - w.RESTART_PAGES * w.PAGE_BYTES)
    page_header = fields(w.PAGE, quiet)
    for key in ('copy_value', 'last_end_lsn'):
        w.PAGE.put(quiet, key, mapping[page_header[key]])
    for within, record, _ in records(quiet):
        w.RECORD.put(quiet, 'lsn', mapping[record['lsn']], within)
        if record['type'] == w.RESTART_TYPE:
            body = within + w.RECORD.size
            CLIENT_RESTART.put(quiet, 'analysis_lsn', mapping[client['oldest_lsn']], body)
            struct.pack_into('<Q', quiet, body + record['data_bytes'] - w.LSN_BYTES,
                             mapping[client['oldest_lsn']])
    physical = log_first + origin_page
    candidate[physical:physical + w.PAGE_BYTES] = protect_page(quiet, w.PAGE, 0)
    for slot in range(w.RESTART_PAGES):
        physical = log_first + slot * w.PAGE_BYTES
        root, header, sequence = restore_page(source[physical:physical + w.PAGE_BYTES], w.RESTART_HEADER)
        w.RESTART_AREA.put(root, 'current_lsn', mapping[area['current_lsn']], header['area_offset'])
        w.CLIENT.put(root, 'oldest_lsn', mapping[client['oldest_lsn']], client_first)
        w.CLIENT.put(root, 'restart_lsn', mapping[client['restart_lsn']], client_first)
        candidate[physical:physical + w.PAGE_BYTES] = protect_page(root, w.RESTART_HEADER, sequence)
    user_first = f.MFT_LCN * f.CLUSTER + v.FRAGMENTED_RECORD * f.RECORD
    before, home_header, sequence = restore_page(source[user_first:user_first + f.RECORD], FILE)
    after = bytearray(before)
    _, attributes = storage.record_parts(source[user_first:user_first + f.RECORD])
    si_first = home_header['attrs_offset']
    for attribute in attributes:
        if storage.attr_header(attribute)['type'] == f.SI:
            break
        si_first += len(attribute)
    resident = dict(zip(storage.RESIDENT_FIELDS,
                        f.RESIDENT_HEADER.unpack_from(attribute, f.ATTR_HEADER.size)))
    value_first = si_first + resident['offset']
    STANDARD.put(after, 'modified', NEW_TIME, value_first)
    STANDARD.put(after, 'changed', NEW_TIME, value_first)
    STANDARD.put(after, 'attributes', fields(STANDARD, before, value_first)['attributes'] | ARCHIVE,
                 value_first)
    snapshot_bytes = f.RECORD
    first = origin_page + w.PAGE_BYTES

    def lsn(ordinal):
        return w.lsn_at(first + ordinal * w.PAGE_BYTES + w.PAGE_DATA_OFFSET,
                        log_bytes, epoch, area['sequence_bits'])

    def payload(operation, redo=b'', undo=b'', *, inverse=0, target=False):
        prefix = w.UPDATE.size + w.LSN_BYTES
        undo_first = w.aligned(prefix + len(redo))
        description = dict(redo_operation=operation, undo_operation=inverse,
            redo_offset=prefix, redo_bytes=len(redo), undo_offset=undo_first,
            undo_bytes=len(undo), target_attribute=tables.TABLE.size,
            attribute_flags=MFT_TARGET_FLAG)
        if target:
            description.update(lcns=1, target_vcn=v.FRAGMENTED_RECORD * f.RECORD // f.CLUSTER,
                cluster_index=v.FRAGMENTED_RECORD * f.RECORD % f.CLUSTER // f.SECTOR)
        elif operation == FORGET_OPERATION:
            description.update(target_attribute=0, attribute_flags=0)
        lcn = f.MFT_LCN + description['target_vcn'] if target else (1 << w.LSN_BITS) - 1
        body = w.UPDATE.pack(description) + struct.pack('<Q', lcn) + redo
        return body + bytes(undo_first - len(body)) + undo

    opened = payload(OPEN_OPERATION, tables.OPEN.pack(dict(allocated=tables.ALLOCATED,
        attribute_type=f.DATA, reference=f.file_reference(f.MFT_RECORD),
        open_lsn=mapping[client['restart_lsn']])))
    snapshot = payload(INITIALIZE_FILE_OPERATION, bytes(before[:snapshot_bytes]),
        bytes(before[:snapshot_bytes]), inverse=INITIALIZE_FILE_OPERATION, target=True)
    changed = payload(INITIALIZE_FILE_OPERATION, bytes(after[:snapshot_bytes]), target=True)
    # A complete FILE inverse must remain visible to native undo validation.
    updates = [(opened, tables.TABLE.size, ADDING_FLAG, 0, 0),
               (snapshot, tables.TABLE.size + tables.TRANSACTION.size, 0, 0, 0),
               (changed, tables.TABLE.size + tables.TRANSACTION.size, ADDING_FLAG, lsn(1), lsn(1))]
    if compensated:
        empty_inverse = payload(0, inverse=COMPENSATION_OPERATION, target=True)
        updates.append((empty_inverse, tables.TABLE.size + tables.TRANSACTION.size,
                        DELETING_FLAG, lsn(2), lsn(1)))
        inverse = bytearray(payload(INITIALIZE_FILE_OPERATION, bytes(before[:snapshot_bytes]),
            inverse=COMPENSATION_OPERATION, target=True))
        w.UPDATE.put(inverse, 'undo_bytes', snapshot_bytes)
        updates.append((inverse, tables.TABLE.size + tables.TRANSACTION.size, 0, lsn(3), 0))
    terminal = payload(FORGET_OPERATION, inverse=COMPENSATION_OPERATION)
    updates.append((terminal, tables.TABLE.size + tables.TRANSACTION.size, DELETING_FLAG,
                    lsn(len(updates) - 1), 0))
    assert len(updates) == packets
    for ordinal, (body, transaction, flags, previous, undo) in enumerate(updates):
        packet = w.RECORD.pack(dict(lsn=lsn(ordinal), previous_lsn=previous, undo_next_lsn=undo,
            data_bytes=len(body), type=w.UPDATE_TYPE, client_sequence=client['sequence'],
            transaction=transaction, flags=flags)) + body
        page = bytearray(w.PAGE_BYTES)
        page[:w.PAGE.size] = w.PAGE.pack(dict(magic=b'RCRD', usa_offset=w.PAGE.size,
            copy_value=lsn(ordinal), last_end_lsn=lsn(ordinal), flags=w.RECORD_END,
            page_count=1, page_position=1,
            next_record_offset=w.aligned(w.PAGE_DATA_OFFSET + len(packet))))
        page[w.PAGE_DATA_OFFSET:w.PAGE_DATA_OFFSET + len(packet)] = packet
        physical = log_first + first + ordinal * w.PAGE_BYTES
        candidate[physical:physical + w.PAGE_BYTES] = protect_page(page, w.PAGE, 0)
    if not compensated:
        FILE.put(after, 'lsn', lsn(2))
        desired = protect_page(after, FILE, sequence)
        candidate[user_first:user_first + f.RECORD] = guarded_publication(
            source[user_first:user_first + f.RECORD], desired, FILE)
    assert origin_page >= circular
    return bytes(candidate)


def author_case(output, name, source, description, wrapped):
    directory = output / name
    directory.mkdir(exist_ok=True)
    directory.joinpath('source.img').write_bytes(source)
    log_first, log_bytes = log_geometry(source)
    root, header, _ = restore_page(source[log_first:log_first + w.PAGE_BYTES], w.RESTART_HEADER)
    area = fields(w.RESTART_AREA, root, header['area_offset'])
    client_first = header['area_offset'] + area['clients_offset']
    client = fields(w.CLIENT, root, client_first)
    offset_bits = w.LSN_BITS - area['sequence_bits']
    mask = (1 << offset_bits) - 1
    checkpoint_page = ((client['restart_lsn'] & mask) << w.OFFSET_SHIFT) // w.PAGE_BYTES * w.PAGE_BYTES
    prior, _, _ = restore_page(source[log_first + checkpoint_page:
                                      log_first + checkpoint_page + w.PAGE_BYTES], w.PAGE)
    checkpoint_within = ((client['restart_lsn'] & mask) << w.OFFSET_SHIFT) - checkpoint_page
    body = bytearray(prior[checkpoint_within + w.RECORD.size:
                            checkpoint_within + w.RECORD.size + CHECKPOINT_BODY_BYTES])
    last_page = log_bytes - w.PAGE_BYTES if wrapped else description['commit_offset']
    last, _, _ = restore_page(source[log_first + last_page:
                                     log_first + last_page + w.PAGE_BYTES], w.PAGE)
    _, terminal, _ = records(last)[-1]
    terminal_within = records(last)[-1][0]
    action = fields(w.UPDATE, last, terminal_within + w.RECORD.size)
    assert action['redo_operation'] == FORGET_OPERATION and terminal['undo_next_lsn'] == 0
    new_page = last_page + w.PAGE_BYTES
    generation = terminal['lsn'] >> offset_bits
    if new_page == log_bytes:
        new_page = (w.RESTART_PAGES + w.LEGACY_TAIL_PAGES) * w.PAGE_BYTES
        generation += 1
    new_lsn = w.lsn_at(new_page + w.PAGE_DATA_OFFSET, log_bytes, generation, area['sequence_bits'])
    CLIENT_RESTART.put(body, 'analysis_lsn', terminal['lsn'])
    struct.pack_into('<Q', body, len(body) - w.LSN_BYTES, terminal['lsn'])
    packet = w.RECORD.pack(dict(lsn=new_lsn, data_bytes=len(body), type=w.RESTART_TYPE,
        client_sequence=client['sequence'])) + body
    page = bytearray(w.PAGE_BYTES)
    page[:w.PAGE.size] = w.PAGE.pack(dict(magic=b'RCRD', usa_offset=w.PAGE.size,
        copy_value=new_lsn, last_end_lsn=new_lsn, flags=w.RECORD_END | CLIENT_RESTART_PAGE,
        page_count=1, page_position=1,
        next_record_offset=w.aligned(w.PAGE_DATA_OFFSET + len(packet))))
    page[w.PAGE_DATA_OFFSET:w.PAGE_DATA_OFFSET + len(packet)] = packet
    home_physical = log_first + new_page
    desired = protect_page(page, w.PAGE, 0)
    home = guarded_publication(source[home_physical:home_physical + w.PAGE_BYTES], desired, w.PAGE)
    copied, _, marker = restore_page(home, w.PAGE)
    w.PAGE.put(copied, 'copy_value', new_page)
    copy_physical = log_first + w.RESTART_PAGES * w.PAGE_BYTES
    desired_copy = protect_page(copied, w.PAGE, marker)
    copy = guarded_publication(source[copy_physical:copy_physical + w.PAGE_BYTES], desired_copy, w.PAGE)
    roots = [[], [], []]
    for slot in range(w.RESTART_PAGES):
        physical = log_first + slot * w.PAGE_BYTES
        previous = source[physical:physical + w.PAGE_BYTES]
        for index in range(len(roots)):
            logical, root_header, sequence = restore_page(previous, w.RESTART_HEADER)
            region = root_header['area_offset']
            entries = region + fields(w.RESTART_AREA, logical, region)['clients_offset']
            w.RESTART_AREA.put(logical, 'flags', w.CLEAN if index == len(roots) - 1 else 0, region)
            if index:
                w.RESTART_AREA.put(logical, 'current_lsn', new_lsn, region)
                w.RESTART_AREA.put(logical, 'last_data_bytes', len(body), region)
                w.CLIENT.put(logical, 'oldest_lsn', terminal['lsn'], entries)
                w.CLIENT.put(logical, 'restart_lsn', new_lsn, entries)
            desired = protect_page(logical, w.RESTART_HEADER, sequence)
            previous = guarded_publication(previous, desired, w.RESTART_HEADER)
            roots[index].append((physical, previous))
    publications = [*roots[0], (copy_physical, copy), (home_physical, home), *roots[1], *roots[2]]
    assert len(publications) == CHECKPOINT_PUBLICATIONS
    candidate = bytearray(source)
    for index, (physical, image) in enumerate(publications):
        directory.joinpath('publication-' + str(index) + '.expected').write_bytes(image)
        candidate[physical:physical + len(image)] = image
    directory.joinpath('postimage.expected').write_bytes(candidate)
    directory.joinpath('case.rows').write_text(
        f'{log_first} {log_bytes} {client["oldest_lsn"]} {client["restart_lsn"]} '
        f'{terminal["lsn"]} {new_lsn} {int(wrapped)}\n' +
        ''.join(f'{physical}\n' for physical, _ in publications))
    return dict(name=name, wrapped=wrapped, analysis_lsn=terminal['lsn'], checkpoint_lsn=new_lsn,
                publications=len(publications), bytes=len(source))


def author_refusals(output, cases, quiet):
    """Preserve complete framing while independently violating ownership proofs."""
    directory = output / 'refusals'
    directory.mkdir(exist_ok=True)
    rows = []

    def publish(name, image, operation):
        directory.joinpath(name + '.img').write_bytes(image)
        rows.append((name, operation))

    publish('quiet-without-new-terminal', quiet, 'checkpoint')
    for case in cases:
        name = case['name']
        source_dir = output / name
        source = source_dir.joinpath('source.img').read_bytes()
        postimage = source_dir.joinpath('postimage.expected').read_bytes()
        metadata = list(map(int, source_dir.joinpath('case.rows').read_text().split()))
        log_first, log_bytes, _, old_checkpoint_lsn, marker_lsn, _ = metadata[:6]
        publications = metadata[7:]
        source_root, root_header, _ = restore_page(source[log_first:log_first + w.PAGE_BYTES],
                                                  w.RESTART_HEADER)
        area = fields(w.RESTART_AREA, source_root, root_header['area_offset'])
        client_first = root_header['area_offset'] + area['clients_offset']
        offset_bits = w.LSN_BITS - area['sequence_bits']
        marker_offset = (marker_lsn & ((1 << offset_bits) - 1)) << w.OFFSET_SHIFT
        marker_first = log_first + marker_offset // w.PAGE_BYTES * w.PAGE_BYTES
        marker_within = marker_offset % w.PAGE_BYTES
        checkpoint_first = publications[3]
        user_first = f.MFT_LCN * f.CLUSTER + v.FRAGMENTED_RECORD * f.RECORD

        def state(count):
            candidate = bytearray(source)
            for ordinal, physical in enumerate(publications[:count]):
                page = source_dir.joinpath('publication-' + str(ordinal) + '.expected').read_bytes()
                candidate[physical:physical + len(page)] = page
            return candidate

        def edit_page(candidate, physical, layout, edit):
            previous = candidate[physical:physical + w.PAGE_BYTES]
            logical, _, sequence = restore_page(previous, layout)
            edit(logical)
            candidate[physical:physical + w.PAGE_BYTES] = guarded_publication(
                previous, protect_page(logical, layout, sequence), layout)

        publish(name + '-dirty-writer', state(2), 'checkpoint')
        candidate = state(3)
        file = bytearray(candidate[user_first:user_first + f.RECORD])
        logical, header, sequence = restore_page(file, FILE)
        FILE.put(logical, 'lsn', fields(FILE, logical)['lsn'] + 1)
        candidate[user_first:user_first + f.RECORD] = protect_page(logical, FILE, sequence)
        publish(name + '-unsettled-home', candidate, 'recovery')

        for label, edit in (
            ('different-client', lambda root: w.CLIENT.put(root, 'sequence',
                fields(w.CLIENT, root, client_first)['sequence'] + 1, client_first)),
            ('different-open-count', lambda root: w.RESTART_AREA.put(root, 'open_count',
                area['open_count'] + 1, root_header['area_offset'])),
            ('different-new-floor', lambda root: w.CLIENT.put(root, 'oldest_lsn',
                old_checkpoint_lsn, client_first)),
            ('different-current', lambda root: w.RESTART_AREA.put(root, 'current_lsn',
                case['checkpoint_lsn'] + 1, root_header['area_offset'])),
            ('different-last-length', lambda root: w.RESTART_AREA.put(root, 'last_data_bytes',
                CHECKPOINT_BODY_BYTES + 1, root_header['area_offset'])),
        ):
            candidate = state(5)
            edit_page(candidate, log_first, w.RESTART_HEADER, edit)
            publish(name + '-' + label, candidate, 'recovery')

        candidate = state(5)
        candidate[log_first + w.PAGE_BYTES:log_first + 2 * w.PAGE_BYTES] = source[
            log_first + w.PAGE_BYTES:log_first + 2 * w.PAGE_BYTES]
        publish(name + '-old-root-still-clean', candidate, 'recovery')

        for label, edit in (
            ('wrong-analysis', lambda page: CLIENT_RESTART.put(page, 'analysis_lsn',
                marker_lsn - 1, w.PAGE_DATA_OFFSET + w.RECORD.size)),
            ('live-table', lambda page: CLIENT_RESTART.put(page, 'transactions_lsn',
                marker_lsn, w.PAGE_DATA_OFFSET + w.RECORD.size)),
        ):
            candidate = state(4)
            for physical in (publications[2], checkpoint_first):
                edit_page(candidate, physical, w.PAGE, edit)
            publish(name + '-' + label, candidate, 'recovery')

        candidate = state(4)
        edit_page(candidate, marker_first, w.PAGE, lambda page: w.RECORD.put(page,
            'undo_next_lsn', marker_lsn, marker_within))
        publish(name + '-live-terminal-undo', candidate, 'recovery')

        # The next operation must not rely on a sole copy which it will reuse.
        for label, physical in (('torn-checkpoint-home', checkpoint_first),
                                ('torn-marker-home', marker_first)):
            candidate = bytearray(postimage)
            if physical == marker_first:
                marker, _, sequence = restore_page(candidate[physical:physical + w.PAGE_BYTES], w.PAGE)
                w.PAGE.put(marker, 'copy_value', physical - log_first)
                copy_physical = log_first + (w.RESTART_PAGES + 1) * w.PAGE_BYTES
                candidate[copy_physical:copy_physical + w.PAGE_BYTES] = protect_page(marker, w.PAGE, sequence)
            candidate[physical + f.SECTOR - w.WORD_BYTES] ^= 1
            publish(name + '-' + label, candidate, 'recovery')

        # Removing the terminal packet leaves live undo, despite clean roots.
        candidate = bytearray(source)
        edit_page(candidate, marker_first, w.PAGE, lambda page: (
            w.PAGE.put(page, 'next_record_offset', marker_within),
            w.PAGE.put(page, 'last_end_lsn', 0),
            w.PAGE.put(page, 'flags', 0)))
        publish(name + '-missing-terminal-writer', candidate, 'checkpoint')

    directory.joinpath('cases.rows').write_text(''.join(' '.join(row) + '\n' for row in rows))
    return len(rows)


def author(output, history, journal):
    output.mkdir(parents=True, exist_ok=True)
    description = json.loads(journal.joinpath('manifest.json').read_text())
    cases = []
    for family, image in (('committed', 'committed-clean-original-root.img'),
                          ('compensated', 'compensated-clean-original-root.img')):
        source = history.joinpath(image).read_bytes()
        for wrapped in (False, True):
            name = family + ('-wrap' if wrapped else '-linear')
            candidate = ordinary_settled_at_end(history.joinpath('quiet-clean.img').read_bytes(),
                family == 'compensated') if wrapped else source
            case = author_case(output, name, candidate, description, wrapped)
            case['family'] = 'ordinary-complete-FILE' if wrapped else 'qualified-overwrite'
            cases.append(case)
    output.joinpath('cases.rows').write_text(''.join(case['name'] + '\n' for case in cases))
    refusals = author_refusals(output, cases, history.joinpath('quiet-clean.img').read_bytes())
    output.joinpath('manifest.json').write_text(json.dumps(dict(cases=cases,
        refusal_profiles=refusals,
        independently_authored=True, native_publication_qualified=False), indent=2) + '\n')


if __name__ == '__main__':
    author(Path(sys.argv[1]), Path(sys.argv[3]), Path(sys.argv[4]))
    Path(sys.argv[2]).write_text('independent checkpoint publication oracles\n')
