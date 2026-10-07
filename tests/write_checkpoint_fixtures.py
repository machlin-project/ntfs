#!/usr/bin/env python3
"""Independent empty-checkpoint origins and refusal profiles for journal reuse."""
from pathlib import Path
import json
import struct
import sys

import fixtures as f
import filename_storage as storage
import logfile_fixtures as w
import validation_fixtures as v
import logfile_tables_fixtures as tables
from logfile_checkpoint_fixtures import CLIENT_RESTART
from write_journal_fixtures import (fields, restore_page, protect_page,
                                    guarded_publication, FORGET, COMPENSATION,
                                    OPEN, ADDING, DELETING, TRANSACTION, MFT_KEY, MFT_TARGET)

CLIENT_RESTART_PAGE = 0x00000002
EMPTY_EXTENSION_BYTES = 48
CONTROL_PAYLOAD_BYTES = w.UPDATE.size + w.LSN_BYTES
CONTROL_PACKET_BYTES = w.RECORD.size + CONTROL_PAYLOAD_BYTES
NOOP_OPERATION = 0
REFUSED = -1
SUCCESS = 0
BUSY = 15
RESTART_CLEAN_PUBLICATIONS = 2 * w.RESTART_PAGES
SPACE_FREE_PAGES = tuple(range(5, 27))


def author(output, history, journal):
    output.mkdir(parents=True, exist_ok=True)
    source = (history / 'committed-clean-original-root.img').read_bytes()
    description = json.loads((journal / 'manifest.json').read_text())
    first = f.MFT_LCN * f.CLUSTER + v.LOGFILE_RECORD * f.RECORD
    _, attributes = storage.record_parts(source[first:first + f.RECORD])
    log, runs = storage.mapping(next(attribute for attribute in attributes
        if storage.attr_header(attribute)['type'] == f.DATA and not storage.attr_name(attribute)))
    assert len(runs) == 1 and runs[0][1] is not None
    log_first = runs[0][1] * f.CLUSTER
    root, root_header, _ = restore_page(source[log_first:log_first + w.PAGE_BYTES], w.RESTART_HEADER)
    area_first = root_header['area_offset']
    area = fields(w.RESTART_AREA, root, area_first)
    client_first = area_first + area['clients_offset']
    client = fields(w.CLIENT, root, client_first)
    commit_first = log_first + description['commit_offset']
    commit, _, _ = restore_page(source[commit_first:commit_first + w.PAGE_BYTES], w.PAGE)
    forgotten = fields(w.RECORD, commit, w.PAGE_DATA_OFFSET)
    action = fields(w.UPDATE, commit, w.PAGE_DATA_OFFSET + w.RECORD.size)
    assert forgotten['data_bytes'] == CONTROL_PAYLOAD_BYTES
    assert action['redo_operation'] == FORGET and action['undo_operation'] == COMPENSATION
    assert forgotten['flags'] == DELETING and forgotten['transaction'] == TRANSACTION
    anchor = bytearray(commit[w.PAGE_DATA_OFFSET:w.PAGE_DATA_OFFSET + CONTROL_PACKET_BYTES])
    original_checkpoint = (journal / 'checkpoint.input').read_bytes()
    checkpoint_body = original_checkpoint[w.RECORD.size:]
    assert len(checkpoint_body) == CLIENT_RESTART.size + EMPTY_EXTENSION_BYTES
    offset_bits = w.LSN_BITS - area['sequence_bits']
    epoch = forgotten['lsn'] >> offset_bits
    circular = (w.RESTART_PAGES + w.LEGACY_TAIL_PAGES) * w.PAGE_BYTES
    rows = []
    manifests = []

    def sequence_lsn(page, generation, within=w.PAGE_DATA_OFFSET):
        return w.lsn_at(page + within, log['size'], generation, area['sequence_bits'])

    def frame(packet, page_offset, *, restart=False, copy=False):
        record = fields(w.RECORD, packet)
        logical = bytearray(w.PAGE_BYTES)
        logical[:w.PAGE.size] = w.PAGE.pack(dict(magic=b'RCRD', usa_offset=w.PAGE.size,
            copy_value=page_offset if copy else record['lsn'], last_end_lsn=record['lsn'],
            flags=w.RECORD_END | (CLIENT_RESTART_PAGE if restart else 0),
            page_count=1, page_position=1,
            next_record_offset=w.aligned(w.PAGE_DATA_OFFSET + len(packet))))
        logical[w.PAGE_DATA_OFFSET:w.PAGE_DATA_OFFSET + len(packet)] = packet
        return protect_page(logical, w.PAGE, 0)

    def build(name, *, wrapped=False, dirty=False, anchor_edit=None,
              checkpoint_edit=None, root_edit=None, result=SUCCESS):
        candidate = bytearray(source)
        marker = bytearray(anchor)
        marker_page = description['commit_offset']
        checkpoint_page = marker_page + w.PAGE_BYTES
        marker_lsn = forgotten['lsn']
        checkpoint_epoch = epoch
        if wrapped:
            marker_page = log['size'] - w.PAGE_BYTES
            checkpoint_page = circular
            marker_lsn = sequence_lsn(marker_page, epoch)
            checkpoint_epoch += 1
            w.RECORD.put(marker, 'lsn', marker_lsn)
        checkpoint_lsn = sequence_lsn(checkpoint_page, checkpoint_epoch)
        assert marker_lsn < checkpoint_lsn
        if anchor_edit:
            anchor_edit(marker, marker_lsn, checkpoint_lsn)
        body = bytearray(checkpoint_body)
        CLIENT_RESTART.put(body, 'analysis_lsn', marker_lsn)
        body[-w.LSN_BYTES:] = struct.pack('<Q', marker_lsn)
        packet = bytearray(w.RECORD.pack(dict(lsn=checkpoint_lsn,
            data_bytes=len(body), client_sequence=client['sequence'],
            type=w.RESTART_TYPE, transaction=0)) + body)
        if checkpoint_edit:
            checkpoint_edit(packet, marker_lsn, checkpoint_lsn)
        # A packed qualified marker remains at its actual original offset. The
        # wrapped profile independently authors a fresh single-marker page.
        if wrapped:
            desired = frame(marker, marker_page)
        else:
            logical = bytearray(commit)
            logical[w.PAGE_DATA_OFFSET:w.PAGE_DATA_OFFSET + len(marker)] = marker
            desired = protect_page(logical, w.PAGE, 0)
        physical = log_first + marker_page
        candidate[physical:physical + w.PAGE_BYTES] = guarded_publication(
            source[physical:physical + w.PAGE_BYTES], desired, w.PAGE)
        desired = frame(packet, checkpoint_page, restart=True)
        physical = log_first + checkpoint_page
        candidate[physical:physical + w.PAGE_BYTES] = guarded_publication(
            source[physical:physical + w.PAGE_BYTES], desired, w.PAGE)
        physical = log_first + w.RESTART_PAGES * w.PAGE_BYTES
        desired = frame(packet, checkpoint_page, restart=True, copy=True)
        candidate[physical:physical + w.PAGE_BYTES] = guarded_publication(
            source[physical:physical + w.PAGE_BYTES], desired, w.PAGE)
        for slot in range(w.RESTART_PAGES):
            physical = log_first + slot * w.PAGE_BYTES
            logical, header, _ = restore_page(source[physical:physical + w.PAGE_BYTES], w.RESTART_HEADER)
            region = header['area_offset']
            w.RESTART_AREA.put(logical, 'current_lsn', checkpoint_lsn, region)
            w.RESTART_AREA.put(logical, 'last_data_bytes', len(body), region)
            w.RESTART_AREA.put(logical, 'flags', 0 if dirty else w.CLEAN, region)
            w.CLIENT.put(logical, 'oldest_lsn', marker_lsn, client_first)
            w.CLIENT.put(logical, 'restart_lsn', checkpoint_lsn, client_first)
            if root_edit:
                root_edit(logical, region, client_first, slot)
            desired = protect_page(logical, w.RESTART_HEADER, 0)
            candidate[physical:physical + w.PAGE_BYTES] = guarded_publication(
                source[physical:physical + w.PAGE_BYTES], desired, w.RESTART_HEADER)
        (output / (name + '.img')).write_bytes(candidate)
        expected_publications = RESTART_CLEAN_PUBLICATIONS if dirty else 0
        rows.append((name, result, expected_publications, marker_lsn, checkpoint_lsn,
                     BUSY if dirty else SUCCESS))
        manifests.append(dict(name=name, result=result, publications=expected_publications,
            analysis_lsn=marker_lsn, checkpoint_lsn=checkpoint_lsn, wrapped=wrapped,
            dirty=dirty, image_bytes=len(candidate)))

    build('settled-forget-clean')
    build('settled-forget-dirty', dirty=True)
    build('settled-forget-wrapped', wrapped=True)
    build('settled-forget-wrapped-dirty', wrapped=True, dirty=True)

    def ordinary_marker(packet, oldest, checkpoint):
        w.UPDATE.put(packet, 'target_attribute', 0, w.RECORD.size)
        w.UPDATE.put(packet, 'attribute_flags', 0, w.RECORD.size)

    build('ordinary-forget-clean', anchor_edit=ordinary_marker)
    build('ordinary-forget-dirty', anchor_edit=ordinary_marker, dirty=True)
    build('ordinary-forget-wrapped', anchor_edit=ordinary_marker, wrapped=True)
    build('ordinary-forget-wrapped-dirty', anchor_edit=ordinary_marker, wrapped=True, dirty=True)
    for label, field, value in (
        ('wrong-transaction', 'transaction', TRANSACTION + 1),
        ('missing-deletion', 'flags', 0),
        ('adding-deletion', 'flags', DELETING | ADDING),
        ('live-undo-root', 'undo_next_lsn', forgotten['previous_lsn']),
        ('foreign-marker-client', 'client_sequence', client['sequence'] + 1),
    ):
        build(label, anchor_edit=lambda packet, oldest, checkpoint, field=field, value=value:
            w.RECORD.put(packet, field, value), result=REFUSED)
    build('self-previous-marker', anchor_edit=lambda packet, oldest, checkpoint:
        w.RECORD.put(packet, 'previous_lsn', oldest), result=REFUSED)
    build('missing-previous-marker', anchor_edit=lambda packet, oldest, checkpoint:
        w.RECORD.put(packet, 'previous_lsn', 0), result=REFUSED)
    for label, field, value in (
        ('nonterminal-marker', 'redo_operation', NOOP_OPERATION),
        ('wrong-marker-inverse', 'undo_operation', NOOP_OPERATION),
        ('marker-target', 'target_attribute', MFT_KEY + 1),
        ('marker-vcn', 'target_vcn', 1),
        ('marker-cluster', 'cluster_index', 1),
        ('marker-attribute-flags', 'attribute_flags', MFT_TARGET << 1),
    ):
        build(label, anchor_edit=lambda packet, oldest, checkpoint, field=field, value=value:
            w.UPDATE.put(packet, field, value, w.RECORD.size), result=REFUSED)
    build('mft-marker-without-flags', anchor_edit=lambda packet, oldest, checkpoint:
        w.UPDATE.put(packet, 'attribute_flags', 0, w.RECORD.size), result=REFUSED)
    build('zero-target-with-mft-flags', anchor_edit=lambda packet, oldest, checkpoint:
        w.UPDATE.put(packet, 'target_attribute', 0, w.RECORD.size), result=REFUSED)
    build('different-analysis', checkpoint_edit=lambda packet, oldest, checkpoint:
        CLIENT_RESTART.put(packet, 'analysis_lsn', oldest - 1, w.RECORD.size), result=REFUSED)
    build('different-extension-anchor', checkpoint_edit=lambda packet, oldest, checkpoint:
        packet.__setitem__(slice(len(packet) - w.LSN_BYTES, len(packet)), struct.pack('<Q', oldest - 1)),
        result=REFUSED)
    build('nonempty-checkpoint', checkpoint_edit=lambda packet, oldest, checkpoint:
        CLIENT_RESTART.put(packet, 'transactions_lsn', oldest, w.RECORD.size), result=REFUSED)
    build('foreign-checkpoint-client', checkpoint_edit=lambda packet, oldest, checkpoint:
        w.RECORD.put(packet, 'client_sequence', client['sequence'] + 1), result=REFUSED)
    build('checkpoint-transaction', checkpoint_edit=lambda packet, oldest, checkpoint:
        w.RECORD.put(packet, 'transaction', TRANSACTION), result=REFUSED)
    build('different-root-client', root_edit=lambda packet, area, client_first, slot:
        w.CLIENT.put(packet, 'sequence', client['sequence'] + slot, client_first), result=REFUSED)
    (output / 'cases.rows').write_text(''.join(' '.join(map(str, row)) + '\n' for row in rows))
    (output / 'manifest.json').write_text(json.dumps(dict(profiles=manifests,
        native_publication_qualified=False, independently_authored=True), indent=2) + '\n')

    floor_lsn = client['oldest_lsn']
    floor_page = ((floor_lsn & ((1 << offset_bits) - 1)) << w.OFFSET_SHIFT) // w.PAGE_BYTES * w.PAGE_BYTES
    cursor = description['commit_offset'] + w.PAGE_BYTES
    cursor_epoch = epoch
    if cursor == log['size']:
        cursor = circular
        cursor_epoch += 1
    ring_pages = (log['size'] - circular) // w.PAGE_BYTES
    available = ((floor_page - cursor) // w.PAGE_BYTES) % ring_pages
    space_rows = []
    for free_pages in SPACE_FREE_PAGES:
        assert free_pages < available
        candidate = bytearray(source)
        previous = forgotten['lsn']
        page, generation = cursor, cursor_epoch
        opens = available - free_pages
        for ordinal in range(opens):
            record_lsn = sequence_lsn(page, generation)
            entry = tables.OPEN.pack(dict(allocated=tables.ALLOCATED, attribute_type=f.DATA,
                reference=f.file_reference(f.MFT_RECORD), open_lsn=previous))
            prefix = w.UPDATE.size + w.LSN_BYTES
            payload = w.UPDATE.pack(dict(redo_operation=OPEN, undo_operation=NOOP_OPERATION,
                redo_offset=prefix, redo_bytes=len(entry), undo_offset=prefix + len(entry),
                target_attribute=MFT_KEY, attribute_flags=MFT_TARGET))
            payload += struct.pack('<Q', (1 << w.LSN_BITS) - 1) + entry
            packet = w.RECORD.pack(dict(lsn=record_lsn, data_bytes=len(payload),
                client_sequence=client['sequence'], type=w.UPDATE_TYPE,
                transaction=MFT_KEY, flags=ADDING)) + payload
            physical = log_first + page
            desired = frame(packet, page)
            candidate[physical:physical + w.PAGE_BYTES] = guarded_publication(
                source[physical:physical + w.PAGE_BYTES], desired, w.PAGE)
            previous = record_lsn
            page += w.PAGE_BYTES
            if page == log['size']:
                page = circular
                generation += 1
        assert ((floor_page - page) // w.PAGE_BYTES) % ring_pages == free_pages
        name = 'space-free-' + str(free_pages)
        (output / (name + '.img')).write_bytes(candidate)
        space_rows.append((name, free_pages, opens))
    (output / 'space.rows').write_text(''.join(' '.join(map(str, row)) + '\n' for row in space_rows))


if __name__ == '__main__':
    author(Path(sys.argv[1]), Path(sys.argv[3]), Path(sys.argv[4]))
    Path(sys.argv[2]).write_text('independent settled-Forget checkpoint origins\n')
