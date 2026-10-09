#!/usr/bin/env python3
"""Independent whole-page goldens for the qualified native ordinary-file WAL."""
from pathlib import Path
import json
import struct
import sys

import fixtures as f
import filename_storage as storage
import logfile_fixtures as w
import logfile_tables_fixtures as tables
import validation_fixtures as v
from logfile_checkpoint_fixtures import CLIENT_RESTART
from record_protect_fixtures import protected
from write_metadata_fixtures import STANDARD, FILE, restored, ARCHIVE, NEW_TIME

OPEN, SNAPSHOT, UPDATE, FORGET, COMPENSATION = 28, 2, 7, 27, 1
ADDING, DELETING, MFT_TARGET = 4, 2, 2
MFT_KEY = tables.TABLE.size
TRANSACTION = tables.TABLE.size + tables.TRANSACTION.size
FILETIME = NEW_TIME
FOLLOWUP_FILETIME = FILETIME + 230000000
EXECUTE_OFFSET, EXECUTE_BYTES = 123, 5000
EXECUTE_PATTERN_MULTIPLIER, EXECUTE_PATTERN_BIAS = 29, 7
REFERENCE = f.file_reference(v.FRAGMENTED_RECORD)
# Independent wire layout for the narrowly observed 112-byte quiet profile:
# opaque prefix, opaque historical word, profile scalar, opaque suffix, anchor.
QUIET_EXTENSION = struct.Struct('<QQIIQQQ')
QUIET_PROFILE_SCALAR = 0x1000


def fields(layout, data, base=0):
    return {name: struct.unpack_from('<' + form, data, base + layout.offsets[name])[0]
            for name, form in layout.fields}


def restore_page(raw, layout):
    page = bytearray(raw)
    header = fields(layout, page)
    first, count = header['usa_offset'], header['usa_count']
    sequence = struct.unpack_from('<H', page, first)[0]
    assert count == len(page) // w.USA_STRIDE + 1
    for ordinal in range(1, count):
        tail = ordinal * w.USA_STRIDE - w.WORD_BYTES
        assert struct.unpack_from('<H', page, tail)[0] == sequence
        page[tail:tail + w.WORD_BYTES] = page[first + ordinal * w.WORD_BYTES:first + (ordinal + 1) * w.WORD_BYTES]
    return page, header, sequence


def protect_page(page, layout, sequence):
    first = fields(layout, page)['usa_offset']
    count = len(page) // w.USA_STRIDE + 1
    layout.put(page, 'usa_count', count)
    return bytes(protected(page, first, count, sequence))


def guarded_publication(before, desired, layout):
    page, header, start = restore_page(desired, layout)
    occupied = {struct.unpack_from('<H', before, end - w.WORD_BYTES)[0]
                for end in range(w.USA_STRIDE, len(before) + 1, w.USA_STRIDE)}
    old = fields(layout, before)
    mst_header_bytes = layout.offsets['usa_count'] + w.WORD_BYTES
    if (old['usa_offset'] >= mst_header_bytes and old['usa_offset'] % w.WORD_BYTES == 0
            and old['usa_offset'] + w.WORD_BYTES <= len(before)):
        occupied.add(struct.unpack_from('<H', before, old['usa_offset'])[0])
    maximum = (1 << (w.WORD_BYTES * f.BYTE_BITS)) - 1
    candidates = list(range(max(1, start), maximum)) + list(range(1, max(1, start)))
    marker = next(value for value in candidates if value not in occupied)
    return protect_page(page, layout, marker - 1)


def author(output, source):
    output.mkdir(parents=True, exist_ok=True)
    assert QUIET_EXTENSION.size == 48
    image = bytearray(source.read_bytes())
    log, runs = storage.mapping(next(attr for attr in storage.record_parts(
        image[f.MFT_LCN * f.CLUSTER + v.LOGFILE_RECORD * f.RECORD:
              f.MFT_LCN * f.CLUSTER + (v.LOGFILE_RECORD + 1) * f.RECORD])[1]
        if storage.attr_header(attr)['type'] == f.DATA))
    assert len(runs) == 1
    log_first = runs[0][1] * f.CLUSTER
    journal = bytearray(image[log_first:log_first + log['size']])
    restart, rh, prior = restore_page(journal[:w.PAGE_BYTES], w.RESTART_HEADER)
    area = fields(w.RESTART_AREA, restart, rh['area_offset'])
    client = fields(w.CLIENT, restart, rh['area_offset'] + area['clients_offset'])
    offset_bits = w.LSN_BITS - area['sequence_bits']
    epoch = area['current_lsn'] >> offset_bits

    def source_offset(lsn):
        return (lsn & ((1 << offset_bits) - 1)) << w.OFFSET_SHIFT

    home = source_offset(client['restart_lsn']) // w.PAGE_BYTES * w.PAGE_BYTES
    quiet, _, quiet_sequence = restore_page(journal[home:home + w.PAGE_BYTES], w.PAGE)
    bootstrap_offset = source_offset(client['oldest_lsn']) - home
    restart_offset = source_offset(client['restart_lsn']) - home
    first_header = fields(w.RECORD, quiet, bootstrap_offset)
    last_header = fields(w.RECORD, quiet, restart_offset)
    bootstrap = bytearray(quiet[bootstrap_offset:bootstrap_offset + w.RECORD.size + first_header['data_bytes']])
    struct.pack_into('<Q', bootstrap, w.RECORD.size + w.UPDATE.size, 0)
    checkpoint = bytearray(quiet[restart_offset:restart_offset + w.RECORD.size + last_header['data_bytes']])
    assert len(checkpoint) == w.RECORD.size + CLIENT_RESTART.size + 48
    # The previous arbitrary signature literal was unrelated to this compact
    # fixture's epoch geometry. Author a bounded-profile state value instead;
    # original native images and captured expectations are never rewritten.
    historical_state = max(1, epoch - 1) << offset_bits
    assert 0 < historical_state < client['oldest_lsn']
    checkpoint[w.RECORD.size + CLIENT_RESTART.size:] = QUIET_EXTENSION.pack(
        0, historical_state, QUIET_PROFILE_SCALAR, 0, 0, 0, client['oldest_lsn'])
    quiet[restart_offset:restart_offset + len(checkpoint)] = checkpoint
    quiet[bootstrap_offset:bootstrap_offset + len(bootstrap)] = bootstrap
    journal[home:home + w.PAGE_BYTES] = protect_page(quiet, w.PAGE, quiet_sequence)
    for slot in range(w.RESTART_PAGES):
        first = slot * w.PAGE_BYTES
        page, page_header, sequence = restore_page(journal[first:first + w.PAGE_BYTES], w.RESTART_HEADER)
        w.RESTART_AREA.put(page, 'last_data_bytes', last_header['data_bytes'], page_header['area_offset'])
        journal[first:first + w.PAGE_BYTES] = protect_page(page, w.RESTART_HEADER, sequence)
    image[log_first:log_first + len(journal)] = journal
    (output / 'source.img').write_bytes(image)

    user_first = f.MFT_LCN * f.CLUSTER + v.FRAGMENTED_RECORD * f.RECORD
    before, header = restored(image[user_first:user_first + f.RECORD])
    first = (source_offset(area['current_lsn']) // w.PAGE_BYTES + 1) * w.PAGE_BYTES

    def lsn(offset, page=0):
        return w.lsn_at(first + page * w.PAGE_BYTES + offset, log['size'],
                        sequence=epoch, sequence_bits=area['sequence_bits'])

    def packet(offset, body, *, page=0, previous=0, undo=0, flags=0, transaction=TRANSACTION, kind=w.UPDATE_TYPE):
        return w.RECORD.pack(dict(lsn=lsn(offset, page), previous_lsn=previous,
            undo_next_lsn=undo, data_bytes=len(body), client_sequence=client['sequence'],
            type=kind, transaction=transaction, flags=flags)) + body

    target_vcn = v.FRAGMENTED_RECORD * f.RECORD // f.CLUSTER
    target_lcn = f.MFT_LCN + target_vcn
    cluster_index = v.FRAGMENTED_RECORD * f.RECORD % f.CLUSTER // f.SECTOR
    si_offset = header['attrs_offset']
    _, attrs = storage.record_parts(image[user_first:user_first + f.RECORD])
    for attr in attrs:
        if storage.attr_header(attr)['type'] == f.SI:
            break
        si_offset += len(attr)
    resident = dict(zip(storage.RESIDENT_FIELDS, f.RESIDENT_HEADER.unpack_from(attr, f.ATTR_HEADER.size)))
    attribute_offset = resident['offset'] + STANDARD.offsets['modified']
    change_first = si_offset + attribute_offset
    change_bytes = STANDARD.size - STANDARD.offsets['modified']

    def payload(operation, redo=b'', undo=b'', *, inverse=0, target=False, value=False):
        prefix = w.UPDATE.size + w.LSN_BYTES
        undo_offset = w.aligned(prefix + len(redo))
        description = dict(redo_operation=operation, undo_operation=inverse,
            redo_offset=prefix, redo_bytes=len(redo), undo_offset=undo_offset, undo_bytes=len(undo),
            target_attribute=MFT_KEY, attribute_flags=MFT_TARGET)
        if target:
            description.update(lcns=1, target_vcn=target_vcn, cluster_index=cluster_index)
        if value:
            description.update(record_offset=si_offset, attribute_offset=attribute_offset)
        output = w.UPDATE.pack(description) + struct.pack('<Q', target_lcn if target else (1 << w.LSN_BITS) - 1) + redo
        return output + bytes(undo_offset - len(output)) + undo

    open_offset = w.PAGE_DATA_OFFSET
    opened = packet(open_offset, payload(OPEN, tables.OPEN.pack(dict(
        allocated=tables.ALLOCATED, attribute_type=f.DATA, reference=f.file_reference(f.MFT_RECORD),
        open_lsn=area['current_lsn']))), transaction=MFT_KEY, flags=ADDING)
    snapshot_offset = w.aligned(open_offset + len(opened))
    snapshot = packet(snapshot_offset, payload(SNAPSHOT, bytes(before[:header['used']]), target=True), flags=ADDING)
    update_offset = w.aligned(snapshot_offset + len(snapshot))
    after = bytearray(before)
    FILE.put(after, 'lsn', lsn(update_offset))
    si_first = si_offset + resident['offset']
    STANDARD.put(after, 'modified', FILETIME, si_first)
    STANDARD.put(after, 'changed', FILETIME, si_first)
    STANDARD.put(after, 'attributes', struct.unpack_from('<I', after,
        si_first + STANDARD.offsets['attributes'])[0] | ARCHIVE, si_first)
    changed = packet(update_offset, payload(UPDATE, bytes(after[change_first:change_first + change_bytes]),
        bytes(before[change_first:change_first + change_bytes]), inverse=UPDATE, target=True, value=True),
        previous=lsn(snapshot_offset), undo=lsn(snapshot_offset))
    committed = packet(w.PAGE_DATA_OFFSET, payload(FORGET, inverse=COMPENSATION),
        page=1, previous=lsn(update_offset), flags=DELETING)
    new_bootstrap = packet(w.PAGE_DATA_OFFSET, bootstrap[w.RECORD.size:], page=2, transaction=MFT_KEY)
    checkpoint_offset = w.aligned(w.PAGE_DATA_OFFSET + len(new_bootstrap))
    checkpoint_body = bytearray(checkpoint[w.RECORD.size:])
    CLIENT_RESTART.put(checkpoint_body, 'analysis_lsn', lsn(w.PAGE_DATA_OFFSET, 2))
    struct.pack_into('<Q', checkpoint_body, len(checkpoint_body) - w.LSN_BYTES, lsn(w.PAGE_DATA_OFFSET, 2))
    new_checkpoint = packet(checkpoint_offset, checkpoint_body, page=2, transaction=0, kind=w.RESTART_TYPE)

    def page(records, endpoint, checkpoint=False):
        page = bytearray(w.PAGE_BYTES)
        end = max(offset + len(data) for offset, data in records)
        page[:w.PAGE.size] = w.PAGE.pack(dict(magic=b'RCRD', usa_offset=w.PAGE.size,
            copy_value=endpoint, last_end_lsn=endpoint, flags=w.RECORD_END | (2 if checkpoint else 0),
            page_count=1, page_position=1, next_record_offset=w.aligned(end)))
        for offset, data in records:
            page[offset:offset + len(data)] = data
        return protect_page(page, w.PAGE, 0)

    compensation_body = bytearray(payload(UPDATE,
        bytes(before[change_first:change_first + change_bytes]), inverse=COMPENSATION,
        target=True, value=True))
    w.UPDATE.put(compensation_body, 'undo_bytes', change_bytes)
    compensated = packet(w.PAGE_DATA_OFFSET, compensation_body, page=1,
        previous=lsn(update_offset), undo=lsn(snapshot_offset))
    abort_offset = w.PAGE_DATA_OFFSET + len(compensated)
    aborted = packet(abort_offset, payload(FORGET, inverse=COMPENSATION), page=1,
        previous=lsn(w.PAGE_DATA_OFFSET, 1), flags=DELETING)
    undo_after = bytearray(before)
    FILE.put(undo_after, 'lsn', lsn(w.PAGE_DATA_OFFSET, 1))

    outputs = dict(prepare=page(((open_offset, opened), (snapshot_offset, snapshot), (update_offset, changed)), lsn(update_offset)),
        commit=page(((w.PAGE_DATA_OFFSET, committed),), lsn(w.PAGE_DATA_OFFSET, 1)),
        checkpoint=page(((w.PAGE_DATA_OFFSET, new_bootstrap), (checkpoint_offset, new_checkpoint)), lsn(checkpoint_offset, 2), True),
        abort=page(((w.PAGE_DATA_OFFSET, compensated), (abort_offset, aborted)), lsn(abort_offset, 1)),
        **{'abort-after': bytes(undo_after), 'abort-protected': bytes(protected(undo_after,
            header['usa_offset'], header['usa_count'], struct.unpack_from('<H', before, header['usa_offset'])[0]))},
        before=bytes(before), after=bytes(after),
        protected=bytes(protected(after, header['usa_offset'], header['usa_count'],
            struct.unpack_from('<H', before, header['usa_offset'])[0])))
    for name, target in (('prepare', first), ('commit', first + w.PAGE_BYTES),
                         ('abort', first + w.PAGE_BYTES)):
        copy, _, sequence = restore_page(outputs[name], w.PAGE)
        w.PAGE.put(copy, 'copy_value', target)
        outputs[name + '-copy'] = protect_page(copy, w.PAGE, sequence)
    restored_prepare, _, sequence = restore_page(outputs['prepare'], w.PAGE)
    outputs['guarded-prepare'] = protect_page(restored_prepare, w.PAGE, sequence)
    many_tails = bytearray(outputs['prepare'])
    for ordinal in range(1, w.PAGE_BYTES // w.USA_STRIDE + 1):
        struct.pack_into('<H', many_tails, ordinal * w.USA_STRIDE - w.WORD_BYTES, ordinal)
    (output / 'guard-many-tail-before.input').write_bytes(many_tails)
    outputs['guard-many-tail'] = protect_page(restored_prepare, w.PAGE,
                                              w.PAGE_BYTES // w.USA_STRIDE)
    wrapped = protect_page(restored_prepare, w.PAGE, (1 << (w.WORD_BYTES * f.BYTE_BITS)) - 3)
    (output / 'guard-wrap-before.input').write_bytes(wrapped)
    (output / 'guard-wrap-after.input').write_bytes(wrapped)
    for slot in range(w.RESTART_PAGES):
        raw = journal[slot * w.PAGE_BYTES:(slot + 1) * w.PAGE_BYTES]
        dirty, _, sequence = restore_page(raw, w.RESTART_HEADER)
        w.RESTART_AREA.put(dirty, 'flags', 0, rh['area_offset'])
        outputs[f'dirty-{slot}'] = protect_page(dirty, w.RESTART_HEADER, sequence)
        clean, _, sequence = restore_page(outputs[f'dirty-{slot}'], w.RESTART_HEADER)
        w.RESTART_AREA.put(clean, 'flags', w.CLEAN, rh['area_offset'])
        outputs[f'retained-{slot}'] = protect_page(clean, w.RESTART_HEADER, sequence)
        w.RESTART_AREA.put(clean, 'current_lsn', lsn(checkpoint_offset, 2), rh['area_offset'])
        w.RESTART_AREA.put(clean, 'last_data_bytes', len(checkpoint_body), rh['area_offset'])
        client_at = rh['area_offset'] + area['clients_offset']
        w.CLIENT.put(clean, 'oldest_lsn', lsn(w.PAGE_DATA_OFFSET, 2), client_at)
        w.CLIENT.put(clean, 'restart_lsn', lsn(checkpoint_offset, 2), client_at)
        outputs[f'clean-{slot}'] = protect_page(clean, w.RESTART_HEADER, sequence)
    for name, data in outputs.items():
        (output / (name + '.expected')).write_bytes(data)
    for name, data in (('open', opened), ('snapshot', snapshot), ('update', changed),
                       ('commit', committed), ('compensation', compensated), ('abort', aborted)):
        (output / (name + '.packet')).write_bytes(data)
    (output / 'undo-protected.expected').write_bytes(protected(before,
        header['usa_offset'], header['usa_count'],
        struct.unpack_from('<H', before, header['usa_offset'])[0]))
    (output / 'replay.rows').write_text(' '.join(str(value) for value in (
        REFERENCE, f.file_reference(f.MFT_RECORD), target_vcn, target_lcn,
        target_lcn * f.CLUSTER, cluster_index, si_offset, attribute_offset,
        change_bytes, header['used'], lsn(open_offset), lsn(snapshot_offset),
        lsn(update_offset), lsn(w.PAGE_DATA_OFFSET, 1))) + '\n')
    (output / 'bootstrap.input').write_bytes(bootstrap)
    (output / 'checkpoint.input').write_bytes(checkpoint)
    report = dict(reference=REFERENCE, filetime=FILETIME, prepare_offset=first,
        commit_offset=first + w.PAGE_BYTES, checkpoint_offset=first + 2 * w.PAGE_BYTES,
        open_lsn=lsn(open_offset), snapshot_lsn=lsn(snapshot_offset), update_lsn=lsn(update_offset),
        commit_lsn=lsn(w.PAGE_DATA_OFFSET, 1), bootstrap_lsn=lsn(w.PAGE_DATA_OFFSET, 2),
        checkpoint_lsn=lsn(checkpoint_offset, 2), snapshot_offset=snapshot_offset,
        update_offset=update_offset, checkpoint_record_offset=checkpoint_offset)
    (output / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    (output / 'reservation.rows').write_text(' '.join(str(report[name]) for name in (
        'prepare_offset', 'commit_offset', 'checkpoint_offset', 'open_lsn', 'snapshot_lsn',
        'update_lsn', 'commit_lsn', 'bootstrap_lsn', 'checkpoint_lsn', 'snapshot_offset',
        'update_offset', 'checkpoint_record_offset')) + '\n')

    # Independent complete-volume oracle for actual prepared write callbacks.
    # Journal roots are retained; the failed new-checkpoint protocol is unused.
    executed = bytearray(image)
    for slot in range(w.RESTART_PAGES):
        location = log_first + slot * w.PAGE_BYTES
        old = bytes(executed[location:location + w.PAGE_BYTES])
        dirty = guarded_publication(old, outputs[f'dirty-{slot}'], w.RESTART_HEADER)
        retained = guarded_publication(dirty, outputs[f'retained-{slot}'], w.RESTART_HEADER)
        executed[location:location + w.PAGE_BYTES] = retained
    for name, location in (
        ('prepare-copy', log_first + w.RESTART_PAGES * w.PAGE_BYTES),
        ('prepare', log_first + report['prepare_offset']),
        ('commit-copy', log_first + (w.RESTART_PAGES + 1) * w.PAGE_BYTES),
        ('commit', log_first + report['commit_offset'])):
        old = bytes(executed[location:location + w.PAGE_BYTES])
        executed[location:location + w.PAGE_BYTES] = guarded_publication(old, outputs[name], w.PAGE)
    old_file = bytes(executed[user_first:user_first + f.RECORD])
    executed[user_first:user_first + f.RECORD] = guarded_publication(old_file, outputs['protected'], FILE)
    _, user_attrs = storage.record_parts(old_file)
    data_header, data_runs = storage.mapping(next(attr for attr in user_attrs
        if storage.attr_header(attr)['type'] == f.DATA and not storage.attr_name(attr)))
    assert data_header['initialized'] >= EXECUTE_OFFSET + EXECUTE_BYTES
    logical_first = EXECUTE_OFFSET // f.SECTOR * f.SECTOR
    logical_end = (EXECUTE_OFFSET + EXECUTE_BYTES + f.SECTOR - 1) // f.SECTOR * f.SECTOR
    payload_bytes = bytes((index * EXECUTE_PATTERN_MULTIPLIER + EXECUTE_PATTERN_BIAS) & 0xff
                          for index in range(EXECUTE_BYTES))
    (output / 'execute-payload.input').write_bytes(payload_bytes)
    (output / 'execute-range.rows').write_text(f'{EXECUTE_OFFSET} {EXECUTE_BYTES}\n')
    data_rows = []
    cursor = logical_first
    for run_index, (length, lcn) in enumerate(data_runs):
        run_first = sum(previous[0] for previous in data_runs[:run_index]) * f.CLUSTER
        run_end = run_first + length * f.CLUSTER
        if cursor >= run_end:
            continue
        assert lcn is not None and cursor >= run_first
        amount = min(logical_end, run_end) - cursor
        location = lcn * f.CLUSTER + cursor - run_first
        fragment = bytearray(image[location:location + amount])
        data_change_first, data_change_end = max(cursor, EXECUTE_OFFSET), min(cursor + amount, EXECUTE_OFFSET + EXECUTE_BYTES)
        fragment[data_change_first - cursor:data_change_end - cursor] = payload_bytes[data_change_first - EXECUTE_OFFSET:data_change_end - EXECUTE_OFFSET]
        (output / f'execute-data-{len(data_rows)}.expected').write_bytes(fragment)
        executed[location:location + amount] = fragment
        data_rows.append((location, amount))
        cursor += amount
        if cursor == logical_end:
            break
    assert cursor == logical_end and len(data_rows) == 2
    (output / 'execute-data.rows').write_text(''.join(f'{location} {amount}\n' for location, amount in data_rows))
    (output / 'execute-final.img').write_bytes(executed)

    # The next operation appends after the independently completed commit page.
    # Original client roots stay exact; the FILE snapshot comes from the complete
    # protected home of the first operation, with its advanced USA restored.
    first += 2 * w.PAGE_BYTES
    before, header = restored(outputs['protected'])
    after = bytearray(before)
    FILE.put(after, 'lsn', lsn(update_offset))
    STANDARD.put(after, 'modified', FOLLOWUP_FILETIME, si_first)
    STANDARD.put(after, 'changed', FOLLOWUP_FILETIME, si_first)
    opened = packet(open_offset, payload(OPEN, tables.OPEN.pack(dict(
        allocated=tables.ALLOCATED, attribute_type=f.DATA, reference=f.file_reference(f.MFT_RECORD),
        open_lsn=area['current_lsn']))), transaction=MFT_KEY, flags=ADDING)
    snapshot = packet(snapshot_offset, payload(SNAPSHOT, bytes(before[:header['used']]), target=True), flags=ADDING)
    changed = packet(update_offset, payload(UPDATE, bytes(after[change_first:change_first + change_bytes]),
        bytes(before[change_first:change_first + change_bytes]), inverse=UPDATE, target=True, value=True),
        previous=lsn(snapshot_offset), undo=lsn(snapshot_offset))
    committed = packet(w.PAGE_DATA_OFFSET, payload(FORGET, inverse=COMPENSATION),
        page=1, previous=lsn(update_offset), flags=DELETING)
    followup = dict(before=bytes(before), after=bytes(after),
        undo_protected=bytes(protected(before, header['usa_offset'], header['usa_count'],
            struct.unpack_from('<H', before, header['usa_offset'])[0])),
        protected=bytes(protected(after, header['usa_offset'], header['usa_count'],
            struct.unpack_from('<H', before, header['usa_offset'])[0])),
        prepare=page(((open_offset, opened), (snapshot_offset, snapshot), (update_offset, changed)), lsn(update_offset)),
        commit=page(((w.PAGE_DATA_OFFSET, committed),), lsn(w.PAGE_DATA_OFFSET, 1)))
    for slot in range(w.RESTART_PAGES):
        dirty, page_header, sequence = restore_page(outputs[f'retained-{slot}'], w.RESTART_HEADER)
        w.RESTART_AREA.put(dirty, 'flags', 0, page_header['area_offset'])
        followup[f'dirty-{slot}'] = protect_page(dirty, w.RESTART_HEADER, sequence)
        retained, page_header, sequence = restore_page(followup[f'dirty-{slot}'], w.RESTART_HEADER)
        w.RESTART_AREA.put(retained, 'flags', w.CLEAN, page_header['area_offset'])
        followup[f'retained-{slot}'] = protect_page(retained, w.RESTART_HEADER, sequence)
    for name, data in followup.items():
        (output / ('followup-' + name.replace('_', '-') + '.expected')).write_bytes(data)
    for name, data in (('open', opened), ('snapshot', snapshot), ('update', changed), ('commit', committed)):
        (output / ('followup-' + name + '.packet')).write_bytes(data)

    executed_twice = bytearray(executed)
    for slot in range(w.RESTART_PAGES):
        location = log_first + slot * w.PAGE_BYTES
        old = bytes(executed_twice[location:location + w.PAGE_BYTES])
        dirty = guarded_publication(old, followup[f'dirty-{slot}'], w.RESTART_HEADER)
        retained = guarded_publication(dirty, followup[f'retained-{slot}'], w.RESTART_HEADER)
        executed_twice[location:location + w.PAGE_BYTES] = retained
    for name, target, copy_slot in (('prepare', first, w.RESTART_PAGES),
                                   ('commit', first + w.PAGE_BYTES, w.RESTART_PAGES + 1)):
        copy_page, _, sequence = restore_page(followup[name], w.PAGE)
        w.PAGE.put(copy_page, 'copy_value', target)
        copy_raw = protect_page(copy_page, w.PAGE, sequence)
        for location, desired in ((log_first + target, followup[name]),
                                  (log_first + copy_slot * w.PAGE_BYTES, copy_raw)):
            old = bytes(executed_twice[location:location + w.PAGE_BYTES])
            executed_twice[location:location + w.PAGE_BYTES] = guarded_publication(old, desired, w.PAGE)
    old_file = bytes(executed_twice[user_first:user_first + f.RECORD])
    executed_twice[user_first:user_first + f.RECORD] = guarded_publication(old_file, followup['protected'], FILE)
    (output / 'execute-followup-final.img').write_bytes(executed_twice)


if __name__ == '__main__':
    author(Path(sys.argv[1]), Path(sys.argv[3]))
    Path(sys.argv[2]).write_text('independent native ordinary-file WAL page goldens\n')
