#!/usr/bin/env python3
"""Whole-volume original fixtures for exact owning write-history acquisition."""
from pathlib import Path
import json
import struct
import sys

import fixtures as f
import filename_storage as storage
import validation_fixtures as v
import logfile_fixtures as w
from write_journal_fixtures import fields, restore_page, protect_page
from write_metadata_fixtures import STANDARD, FILE

SUCCESS, CORRUPT, UNSUPPORTED, STALE = 0, 2, 3, 10
ORIGIN_PACKETS, PREPARED_PACKETS, COMMITTED_PACKETS, CHECKPOINT_PACKETS = 2, 5, 6, 8
OPEN_ATTRIBUTE_TABLE_DUMP = 29


def author(output, source):
    output.mkdir(parents=True, exist_ok=True)
    image = source.joinpath('source.img').read_bytes()
    manifest = json.loads(source.joinpath('manifest.json').read_text())
    _, attrs = storage.record_parts(image[f.MFT_LCN * f.CLUSTER + v.LOGFILE_RECORD * f.RECORD:
        f.MFT_LCN * f.CLUSTER + (v.LOGFILE_RECORD + 1) * f.RECORD])
    log, runs = storage.mapping(next(attr for attr in attrs
        if storage.attr_header(attr)['type'] == f.DATA and not storage.attr_name(attr)))
    assert len(runs) == 1 and runs[0][1] is not None
    log_first = runs[0][1] * f.CLUSTER
    user_first = f.MFT_LCN * f.CLUSTER + v.FRAGMENTED_RECORD * f.RECORD
    home = source.joinpath('protected.expected').read_bytes()
    pages = [source.joinpath(name + '.expected').read_bytes()
             for name in ('prepare', 'commit', 'checkpoint')]
    rows = []

    def build(name, stage, *, dirty=True, home_state='none', publication=False,
              edit=None, result=SUCCESS, count=None):
        candidate = bytearray(image)
        for index in range(stage):
            first = log_first + manifest['prepare_offset'] + index * w.PAGE_BYTES
            candidate[first:first + w.PAGE_BYTES] = pages[index]
        for slot in range(w.RESTART_PAGES):
            if publication or dirty:
                first = log_first + slot * w.PAGE_BYTES
                raw = source.joinpath(('clean-' if publication else 'dirty-') + str(slot) + '.expected').read_bytes()
                candidate[first:first + w.PAGE_BYTES] = raw
        if home_state != 'none':
            length = f.SECTOR if home_state == 'first-sector' else f.RECORD
            candidate[user_first:user_first + length] = home[:length]
        if edit:
            first = log_first + manifest['prepare_offset']
            restored, _, sequence = restore_page(candidate[first:first + w.PAGE_BYTES], w.PAGE)
            edit(restored)
            candidate[first:first + w.PAGE_BYTES] = protect_page(restored, w.PAGE, sequence)
        output.joinpath(name + '.img').write_bytes(candidate)
        expected_count = count if count is not None else (
            ORIGIN_PACKETS if publication or stage == 0 else
            PREPARED_PACKETS if stage == 1 else COMMITTED_PACKETS if stage == 2 else CHECKPOINT_PACKETS)
        pending = stage != 0 and not publication
        rows.append((name, result, expected_count, int(pending), int(stage >= 2 and pending),
                     int(stage == 3 and pending), log_first, user_first))

    build('quiet-clean', 0, dirty=False)
    build('quiet-dirty', 0)
    build('prepared-no-home', 1)
    build('prepared-torn-home', 1, home_state='first-sector')
    build('committed-no-home', 2)
    build('committed-torn-home', 2, home_state='first-sector')
    # This is framing/replay preparation only. Its native intermediate boot-health
    # failure remains a write admission gate, even though exact capture succeeds.
    build('checkpoint-before-publication', 3, home_state='complete')
    build('clean-published', 3, home_state='complete', publication=True)

    def unknown_operation(page):
        w.UPDATE.put(page, 'redo_operation', OPEN_ATTRIBUTE_TABLE_DUMP,
                     manifest['update_offset'] + w.RECORD.size)
    build('unknown-operation', 1, edit=unknown_operation, result=UNSUPPORTED)

    def foreign_client(page):
        w.RECORD.put(page, 'client_sequence', w.CLIENT_SEQUENCE + 1, manifest['snapshot_offset'])
    build('foreign-client', 1, edit=foreign_client, result=STALE)

    def wrong_lcn(page):
        first = manifest['snapshot_offset'] + w.RECORD.size + w.UPDATE.size
        struct.pack_into('<Q', page, first, f.MFT_LCN + 1)
    build('wrong-MFT-map', 1, edit=wrong_lcn, result=CORRUPT)

    def incomplete_family(page):
        end = manifest['update_offset']
        w.PAGE.put(page, 'copy_value', manifest['snapshot_lsn'])
        w.PAGE.put(page, 'last_end_lsn', manifest['snapshot_lsn'])
        w.PAGE.put(page, 'next_record_offset', end)
        page[end:] = bytes(len(page) - end)
    build('incomplete-family', 1, edit=incomplete_family, result=UNSUPPORTED, count=4)

    def followup(name, committed, *, home_state='none', clean=False, edit=None, result=SUCCESS):
        candidate = bytearray(image)
        for index in range(2):
            first = log_first + manifest['prepare_offset'] + index * w.PAGE_BYTES
            candidate[first:first + w.PAGE_BYTES] = pages[index]
        second_first = manifest['commit_offset'] + w.PAGE_BYTES
        for index, page_name in enumerate(('prepare', 'commit')):
            if index and not committed:
                break
            first = log_first + second_first + index * w.PAGE_BYTES
            candidate[first:first + w.PAGE_BYTES] = source.joinpath('followup-' + page_name + '.expected').read_bytes()
        for slot in range(w.RESTART_PAGES):
            first = log_first + slot * w.PAGE_BYTES
            candidate[first:first + w.PAGE_BYTES] = source.joinpath(
                ('followup-retained-' if clean else 'followup-dirty-') + str(slot) + '.expected').read_bytes()
        candidate[user_first:user_first + f.RECORD] = home
        if home_state != 'none':
            updated = source.joinpath('followup-protected.expected').read_bytes()
            length = f.SECTOR if home_state == 'first-sector' else f.RECORD
            candidate[user_first:user_first + length] = updated[:length]
        if edit:
            first = log_first + second_first
            restored, _, sequence = restore_page(candidate[first:first + w.PAGE_BYTES], w.PAGE)
            edit(restored)
            candidate[first:first + w.PAGE_BYTES] = protect_page(restored, w.PAGE, sequence)
        output.joinpath(name + '.img').write_bytes(candidate)
        rows.append((name, result, COMMITTED_PACKETS + (4 if committed else 3),
                     1, int(committed), 0, log_first, user_first))

    followup('followup-prepared-no-home', False)
    followup('followup-prepared-torn-home', False, home_state='first-sector')
    followup('followup-committed-no-home', True)
    followup('followup-committed-torn-home', True, home_state='first-sector')
    followup('followup-clean-original-root', True, home_state='complete', clean=True)

    def wrong_previous_file(page):
        snapshot_first = manifest['snapshot_offset'] + w.RECORD.size
        update = fields(w.UPDATE, page, snapshot_first)
        record_first = snapshot_first + update['redo_offset']
        header = fields(FILE, page, record_first)
        standard_first = record_first + header['attrs_offset']
        resident = dict(zip(storage.RESIDENT_FIELDS,
                            f.RESIDENT_HEADER.unpack_from(page, standard_first + f.ATTR_HEADER.size)))
        value_first = standard_first + resident['offset']
        created = fields(STANDARD, page, value_first)['created']
        STANDARD.put(page, 'created', created ^ 1, value_first)

    followup('followup-wrong-previous-file', True, edit=wrong_previous_file, result=CORRUPT)

    def mixed(name, original, *, result=SUCCESS, corrupt_root=False):
        candidate = bytearray(output.joinpath(original + '.img').read_bytes())
        first = log_first
        candidate[first:first + w.PAGE_BYTES] = source.joinpath('retained-0.expected').read_bytes()
        if corrupt_root:
            restored, page_header, sequence = restore_page(candidate[first:first + w.PAGE_BYTES], w.RESTART_HEADER)
            area_first = page_header['area_offset']
            area = fields(w.RESTART_AREA, restored, area_first)
            w.RESTART_AREA.put(restored, 'open_count', area['open_count'] + 1, area_first)
            candidate[first:first + w.PAGE_BYTES] = protect_page(restored, w.RESTART_HEADER, sequence)
        output.joinpath(name + '.img').write_bytes(candidate)
        prior = next(row for row in rows if row[0] == original)
        rows.append((name, result, *prior[2:]))

    mixed('mixed-clean-first-quiet', 'quiet-dirty')
    mixed('mixed-clean-first-committed-torn', 'committed-torn-home')
    mixed('mixed-clean-first-followup-torn', 'followup-committed-torn-home')
    mixed('mixed-different-root', 'committed-no-home', result=UNSUPPORTED, corrupt_root=True)
    candidate = bytearray(output.joinpath('committed-torn-home.img').read_bytes())
    first = f.MFT_LCN * f.CLUSTER + f.BITMAP_RECORD * f.RECORD
    header, attributes = storage.record_parts(candidate[first:first + f.RECORD])
    index = next(index for index, attr in enumerate(attributes)
                 if storage.attr_header(attr)['type'] == f.DATA and not storage.attr_name(attr))
    value = bytearray(storage.resident_value(attributes[index]))
    cluster = v.FIRST_DATA_LCN
    assert value[cluster // f.BYTE_BITS] & (1 << (cluster % f.BYTE_BITS))
    value[cluster // f.BYTE_BITS] &= ~(1 << (cluster % f.BYTE_BITS))
    attributes[index] = f.resident(f.DATA, value, storage.attr_header(attributes[index])['instance'])
    f.put_record(candidate, f.BITMAP_RECORD, storage.encoded_record(f.BITMAP_RECORD, attributes, header))
    output.joinpath('overlay-free-data-allocation.img').write_bytes(candidate)
    output.joinpath('cases.rows').write_text(''.join(' '.join(map(str, row)) + '\n' for row in rows))


if __name__ == '__main__':
    author(Path(sys.argv[1]), Path(sys.argv[3]))
    Path(sys.argv[2]).write_text('independent complete write-history volume profiles\n')
