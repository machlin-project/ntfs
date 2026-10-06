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
REFERENCE = f.file_reference(v.FRAGMENTED_RECORD)
NATIVE_EMPTY_EXTENSION = bytes.fromhex(
    '00000000000000000000000100000000001000000000000000000000000000000000000000000000')


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


def author(output, source):
    output.mkdir(parents=True, exist_ok=True)
    assert len(NATIVE_EMPTY_EXTENSION) == 48 - w.LSN_BYTES
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
    checkpoint[w.RECORD.size + CLIENT_RESTART.size:] = NATIVE_EMPTY_EXTENSION + struct.pack('<Q', client['oldest_lsn'])
    quiet[restart_offset:restart_offset + len(checkpoint)] = checkpoint
    quiet[bootstrap_offset:bootstrap_offset + len(bootstrap)] = bootstrap
    journal[home:home + w.PAGE_BYTES] = protect_page(quiet, w.PAGE, quiet_sequence)
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

    outputs = dict(prepare=page(((open_offset, opened), (snapshot_offset, snapshot), (update_offset, changed)), lsn(update_offset)),
        commit=page(((w.PAGE_DATA_OFFSET, committed),), lsn(w.PAGE_DATA_OFFSET, 1)),
        checkpoint=page(((w.PAGE_DATA_OFFSET, new_bootstrap), (checkpoint_offset, new_checkpoint)), lsn(checkpoint_offset, 2), True),
        before=bytes(before), after=bytes(after),
        protected=bytes(protected(after, header['usa_offset'], header['usa_count'],
            struct.unpack_from('<H', before, header['usa_offset'])[0])))
    for slot in range(w.RESTART_PAGES):
        raw = journal[slot * w.PAGE_BYTES:(slot + 1) * w.PAGE_BYTES]
        dirty, _, sequence = restore_page(raw, w.RESTART_HEADER)
        w.RESTART_AREA.put(dirty, 'flags', 0, rh['area_offset'])
        outputs[f'dirty-{slot}'] = protect_page(dirty, w.RESTART_HEADER, sequence)
        clean, _, sequence = restore_page(outputs[f'dirty-{slot}'], w.RESTART_HEADER)
        w.RESTART_AREA.put(clean, 'flags', w.CLEAN, rh['area_offset'])
        w.RESTART_AREA.put(clean, 'current_lsn', lsn(checkpoint_offset, 2), rh['area_offset'])
        w.RESTART_AREA.put(clean, 'last_data_bytes', len(checkpoint_body), rh['area_offset'])
        client_at = rh['area_offset'] + area['clients_offset']
        w.CLIENT.put(clean, 'oldest_lsn', lsn(w.PAGE_DATA_OFFSET, 2), client_at)
        w.CLIENT.put(clean, 'restart_lsn', lsn(checkpoint_offset, 2), client_at)
        outputs[f'clean-{slot}'] = protect_page(clean, w.RESTART_HEADER, sequence)
    for name, data in outputs.items():
        (output / (name + '.expected')).write_bytes(data)
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


if __name__ == '__main__':
    author(Path(sys.argv[1]), Path(sys.argv[3]))
    Path(sys.argv[2]).write_text('independent native ordinary-file WAL page goldens\n')
