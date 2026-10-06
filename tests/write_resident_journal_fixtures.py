#!/usr/bin/env python3
"""Independent whole-page and FILE goldens for resident DATA/SI transactions."""
from pathlib import Path
import json
import struct
import sys

import fixtures as f
import filename_storage as storage
import logfile_fixtures as w
import logfile_tables_fixtures as tables
import validation_fixtures as v
import write_journal_fixtures as journal
from write_metadata_fixtures import STANDARD, FILE, restored, ARCHIVE, NEW_TIME
from record_protect_fixtures import protected

OPEN, SNAPSHOT, UPDATE, FORGET, COMPENSATION = 28, 2, 7, 27, 1
ADDING, DELETING, MFT_TARGET = 4, 2, 2
MFT_KEY = tables.TABLE.size
TRANSACTION = tables.TABLE.size + tables.TRANSACTION.size
TARGET_NUMBER = v.HELLO_RECORD
REFERENCE = f.file_reference(TARGET_NUMBER)
PAYLOAD = b'MACHLIN_RESIDENT'


def author(output, source, control):
    output.mkdir(parents=True, exist_ok=True)
    normalized = (control / 'source.img').read_bytes()
    log_first_record = f.MFT_LCN * f.CLUSTER + v.LOGFILE_RECORD * f.RECORD
    _, log_attrs = storage.record_parts(normalized[log_first_record:log_first_record + f.RECORD])
    log, runs = storage.mapping(next(a for a in log_attrs if
        storage.attr_header(a)['type'] == f.DATA and not storage.attr_name(a)))
    assert len(runs) == 1 and runs[0][1] is not None
    log_first = runs[0][1] * f.CLUSTER
    raw_restart = normalized[log_first:log_first + w.PAGE_BYTES]
    restart, rh, _ = journal.restore_page(raw_restart, w.RESTART_HEADER)
    area = journal.fields(w.RESTART_AREA, restart, rh['area_offset'])
    client = journal.fields(w.CLIENT, restart, rh['area_offset'] + area['clients_offset'])
    offset_bits = w.LSN_BITS - area['sequence_bits']
    first = (((area['current_lsn'] & ((1 << offset_bits) - 1)) << w.OFFSET_SHIFT) // w.PAGE_BYTES + 1) * w.PAGE_BYTES
    epoch = area['current_lsn'] >> offset_bits
    user_first = f.MFT_LCN * f.CLUSTER + TARGET_NUMBER * f.RECORD
    profiles = json.loads((source / 'cases.json').read_text())
    rows = []

    def case(profile):
        name = profile['name']
        directory = output / name
        directory.mkdir(exist_ok=True)
        image = bytearray(normalized)
        original = (source / (name + '.img')).read_bytes()
        image[user_first:user_first + f.RECORD] = original[user_first:user_first + f.RECORD]
        before, header = restored(image[user_first:user_first + f.RECORD])
        data_bytes = (source / (name + '.payload')).read_bytes()
        offset = profile['offset']
        _, attrs = storage.record_parts(image[user_first:user_first + f.RECORD])
        position = header['attrs_offset']
        standard_first = data_first = None
        for attribute in attrs:
            attr = storage.attr_header(attribute)
            resident = dict(zip(storage.RESIDENT_FIELDS,
                f.RESIDENT_HEADER.unpack_from(attribute, f.ATTR_HEADER.size)))
            if attr['type'] == f.SI:
                standard_first = position
                standard_value = resident['offset']
            if attr['type'] == f.DATA and not storage.attr_name(attribute):
                assert attr['nonresident'] == 0
                data_first = position
                data_value = resident['offset']
                data_length = resident['length']
            position += len(attribute)
        assert standard_first is not None and data_first is not None
        assert offset + len(data_bytes) <= data_length
        si_attribute = standard_value + STANDARD.offsets['modified']
        si_change = standard_first + si_attribute
        si_bytes = STANDARD.size - STANDARD.offsets['modified']
        data_attribute = data_value + offset
        data_change = data_first + data_attribute
        vcn = TARGET_NUMBER * f.RECORD // f.CLUSTER
        lcn = f.MFT_LCN + vcn
        cluster_index = TARGET_NUMBER * f.RECORD % f.CLUSTER // f.SECTOR

        def lsn(position, page=0):
            return w.lsn_at(first + page * w.PAGE_BYTES + position, log['size'],
                           sequence=epoch, sequence_bits=area['sequence_bits'])

        def payload(operation, redo=b'', undo=b'', *, inverse=0,
                    target=False, record_offset=0, attribute_offset=0,
                    compensation_bytes=0):
            prefix = w.UPDATE.size + w.LSN_BYTES
            undo_offset = w.aligned(prefix + len(redo)) if undo else prefix + len(redo)
            description = dict(redo_operation=operation, undo_operation=inverse,
                redo_offset=prefix, redo_bytes=len(redo), undo_offset=undo_offset,
                undo_bytes=compensation_bytes or len(undo), target_attribute=MFT_KEY,
                attribute_flags=MFT_TARGET, record_offset=record_offset,
                attribute_offset=attribute_offset)
            if target:
                description.update(lcns=1, target_vcn=vcn, cluster_index=cluster_index)
            body = w.UPDATE.pack(description) + struct.pack('<Q', lcn if target else (1 << w.LSN_BITS) - 1) + redo
            return body + bytes(undo_offset - len(body)) + undo

        def packet(position, body, *, page=0, previous=0, undo=0,
                   flags=0, transaction=TRANSACTION):
            return bytes(w.RECORD.pack(dict(lsn=lsn(position, page), previous_lsn=previous,
                undo_next_lsn=undo, data_bytes=len(body), client_sequence=client['sequence'],
                type=w.UPDATE_TYPE, transaction=transaction, flags=flags))) + body

        def page(records, endpoint):
            body = bytearray(w.PAGE_BYTES)
            body[:w.PAGE.size] = w.PAGE.pack(dict(magic=b'RCRD', usa_offset=w.PAGE.size,
                copy_value=endpoint, last_end_lsn=endpoint, flags=w.RECORD_END,
                page_count=1, page_position=1,
                next_record_offset=w.aligned(max(position + len(value) for position, value in records))))
            for position, value in records:
                body[position:position + len(value)] = value
            return journal.protect_page(body, w.PAGE, 0)

        open_offset = w.PAGE_DATA_OFFSET
        opened = packet(open_offset, payload(OPEN, tables.OPEN.pack(dict(
            allocated=tables.ALLOCATED, attribute_type=f.DATA,
            reference=f.file_reference(f.MFT_RECORD), open_lsn=area['current_lsn']))),
            flags=ADDING, transaction=MFT_KEY)
        snapshot_offset = w.aligned(open_offset + len(opened))
        snapshot = packet(snapshot_offset, payload(SNAPSHOT, bytes(before[:header['used']]),
            target=True), flags=ADDING)
        update_offset = w.aligned(snapshot_offset + len(snapshot))
        after = bytearray(before)
        si_value = standard_first + standard_value
        STANDARD.put(after, 'modified', NEW_TIME, si_value)
        STANDARD.put(after, 'changed', NEW_TIME, si_value)
        flags = struct.unpack_from('<I', after, si_value + STANDARD.offsets['attributes'])[0]
        STANDARD.put(after, 'attributes', flags | ARCHIVE, si_value)
        changed = packet(update_offset, payload(UPDATE,
            bytes(after[si_change:si_change + si_bytes]), bytes(before[si_change:si_change + si_bytes]),
            inverse=UPDATE, target=True, record_offset=standard_first, attribute_offset=si_attribute),
            previous=lsn(snapshot_offset), undo=lsn(snapshot_offset))
        resident_offset = w.aligned(update_offset + len(changed))
        after[data_change:data_change + len(data_bytes)] = data_bytes
        FILE.put(after, 'lsn', lsn(resident_offset))
        resident = packet(resident_offset, payload(UPDATE, data_bytes,
            bytes(before[data_change:data_change + len(data_bytes)]), inverse=UPDATE,
            target=True, record_offset=data_first, attribute_offset=data_attribute),
            previous=lsn(update_offset), undo=lsn(update_offset))
        commit = packet(w.PAGE_DATA_OFFSET, payload(FORGET, inverse=COMPENSATION), page=1,
            previous=lsn(resident_offset), flags=DELETING)
        resident_compensation = packet(w.PAGE_DATA_OFFSET, payload(UPDATE,
            bytes(before[data_change:data_change + len(data_bytes)]), inverse=COMPENSATION,
            compensation_bytes=len(data_bytes), target=True,
            record_offset=data_first, attribute_offset=data_attribute), page=1,
            previous=lsn(resident_offset), undo=lsn(update_offset))
        compensation_offset = w.aligned(w.PAGE_DATA_OFFSET + len(resident_compensation))
        compensation = packet(compensation_offset, payload(UPDATE,
            bytes(before[si_change:si_change + si_bytes]), inverse=COMPENSATION,
            compensation_bytes=si_bytes, target=True, record_offset=standard_first,
            attribute_offset=si_attribute), page=1,
            previous=lsn(w.PAGE_DATA_OFFSET, 1), undo=lsn(snapshot_offset))
        abort_offset = w.aligned(compensation_offset + len(compensation))
        abort = packet(abort_offset, payload(FORGET, inverse=COMPENSATION), page=1,
            previous=lsn(compensation_offset, 1), flags=DELETING)
        undo_after = bytearray(before)
        FILE.put(undo_after, 'lsn', lsn(compensation_offset, 1))
        sequence = struct.unpack_from('<H', before, header['usa_offset'])[0]
        outputs = {'prepare':page([(open_offset, opened), (snapshot_offset, snapshot),
            (update_offset, changed), (resident_offset, resident)], lsn(resident_offset)),
            'commit':page([(w.PAGE_DATA_OFFSET, commit)], lsn(w.PAGE_DATA_OFFSET, 1)),
            'abort':page([(w.PAGE_DATA_OFFSET, resident_compensation),
                (compensation_offset, compensation), (abort_offset, abort)], lsn(abort_offset, 1)),
            'before':bytes(before), 'after':bytes(after), 'abort-after':bytes(undo_after),
            'protected':bytes(protected(after, header['usa_offset'], header['usa_count'], sequence)),
            'abort-protected':bytes(protected(undo_after, header['usa_offset'], header['usa_count'], sequence)),
            'undo-protected':bytes(protected(before, header['usa_offset'], header['usa_count'], sequence))}
        for name, target in [('prepare',first), ('commit',first+w.PAGE_BYTES), ('abort',first+w.PAGE_BYTES)]:
            copy, _, prior = journal.restore_page(outputs[name], w.PAGE)
            w.PAGE.put(copy, 'copy_value', target)
            outputs[name+'-copy'] = journal.protect_page(copy, w.PAGE, prior)
        for name, value in outputs.items():
            (directory/(name+'.expected')).write_bytes(value)
        for name, value in [('open',opened), ('snapshot',snapshot), ('update',changed),
            ('resident',resident), ('commit',commit), ('resident-compensation',resident_compensation),
            ('compensation',compensation), ('abort',abort)]:
            (directory/(name+'.packet')).write_bytes(value)
        (directory/'payload.input').write_bytes(data_bytes)
        (directory/'source.img').write_bytes(image)
        for slot in range(w.RESTART_PAGES):
            (directory/f'dirty-{slot}.expected').write_bytes((control/f'dirty-{slot}.expected').read_bytes())
            (directory/f'retained-{slot}.expected').write_bytes((control/f'retained-{slot}.expected').read_bytes())
        executed = bytearray(image)
        for slot in range(w.RESTART_PAGES):
            location = log_first + slot*w.PAGE_BYTES
            old = bytes(executed[location:location+w.PAGE_BYTES])
            dirty = journal.guarded_publication(old, (directory/f'dirty-{slot}.expected').read_bytes(), w.RESTART_HEADER)
            executed[location:location+w.PAGE_BYTES] = journal.guarded_publication(dirty,
                (directory/f'retained-{slot}.expected').read_bytes(), w.RESTART_HEADER)
        for name, location in [('prepare-copy',log_first+w.RESTART_PAGES*w.PAGE_BYTES),
            ('prepare',log_first+first), ('commit-copy',log_first+(w.RESTART_PAGES+1)*w.PAGE_BYTES),
            ('commit',log_first+first+w.PAGE_BYTES)]:
            old = bytes(executed[location:location+w.PAGE_BYTES])
            executed[location:location+w.PAGE_BYTES] = journal.guarded_publication(old,outputs[name],w.PAGE)
        executed[user_first:user_first+f.RECORD] = journal.guarded_publication(
            image[user_first:user_first+f.RECORD],outputs['protected'],FILE)
        (directory/'execute-final.img').write_bytes(executed)
        rows.append({'name':profile['name'], 'reference':REFERENCE,
            'filetime':NEW_TIME, 'offset':offset, 'bytes':len(data_bytes),
            'resident_lsn':lsn(resident_offset), 'resident_offset':resident_offset,
            'resident_compensation_lsn':lsn(w.PAGE_DATA_OFFSET,1),
            'compensation_lsn':lsn(compensation_offset,1), 'abort_lsn':lsn(abort_offset,1),
            'log_physical':log_first, 'file_physical':user_first})

    for profile in profiles:
        if profile['code'] == 0:
            case(profile)
    (output/'cases.json').write_text(json.dumps(rows,indent=2)+'\n')
    keys = ('name','reference','filetime','offset','bytes','resident_lsn','resident_offset',
            'resident_compensation_lsn','compensation_lsn','abort_lsn','log_physical','file_physical')
    (output/'cases.rows').write_text(''.join(' '.join(str(row[key]) for key in keys)+'\n' for row in rows))
    return rows


if __name__ == '__main__':
    rows = author(Path(sys.argv[1]),Path(sys.argv[3]),Path(sys.argv[4]))
    Path(sys.argv[2]).write_text(f'{len(rows)} independent resident DATA/SI journal families\n')
