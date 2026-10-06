"""Independent FILE-retirement states and native payload byte oracles."""
from pathlib import Path
import json
import struct
import sys

import fixtures as f
import logfile_fixtures as log
from record_protect_fixtures import FILE, protected
from write_journal_fixtures import fields
from write_metadata_fixtures import restored

OP_NOOP, OP_INITIALIZE, OP_DEALLOCATE = 0x00, 0x02, 0x03
ADDING, DELETING, MFT_FLAGS = 0x04, 0x02, 0x02
MFT_REFERENCE, MFT_KEY = 1 << 48, 24
PHYSICAL_LCN, DEFAULT_VCN = 790001, 15
BEFORE_LSN, AFTER_LSN = 10101, 10417
REDO_LSN, UNDO_LSN = 11003, 12007
HEADER_PREFIX_BYTES = FILE.offsets['used']
CLUSTER_BLOCK_BYTES = f.SECTOR
WORD_MAX = (1 << (f.U16_BYTES * f.BYTE_BITS)) - 1
SUCCESS, UNSUPPORTED, CORRUPT = 'success', 'unsupported', 'corrupt'


def update(redo_operation, undo_operation, redo, undo, *, slot, vcn, key=MFT_KEY):
    prefix = log.UPDATE.size + log.LSN_BYTES
    undo_first = prefix + f.align(len(redo))
    wire = log.UPDATE.pack(dict(redo_operation=redo_operation, undo_operation=undo_operation,
        redo_offset=prefix, redo_bytes=len(redo), undo_offset=undo_first,
        undo_bytes=len(undo), target_attribute=key, lcns=1,
        record_offset=0, attribute_offset=0,
        cluster_index=slot * f.RECORD // CLUSTER_BLOCK_BYTES,
        attribute_flags=MFT_FLAGS, target_vcn=vcn))
    return bytes(wire) + struct.pack('<Q', PHYSICAL_LCN) + redo + bytes(f.align(len(redo)) - len(redo)) + undo


def record(number, *, sequence=2, links=1, directory=False, large=False):
    attributes = [f.standard()]
    for ordinal in range(links):
        attributes.append(f.resident(f.FILENAME,
            f.key(f'original-{number}-{ordinal}.txt'), ordinal + 1))
    payload = bytes((index * 37 + number) & 0xff for index in range(650 if large else 71))
    attributes.append(f.resident(f.DATA, payload, len(attributes)))
    if not large:
        attributes.append(f.resident(f.DATA, bytes(range(19)), len(attributes), 'notes'))
    raw = f.file_record(number, attributes, sequence=sequence, links=links, directory=directory)
    value, header = restored(raw)
    FILE.put(value, 'lsn', BEFORE_LSN)
    # Retain nonzero unused bytes and logical sector tails independently of USA.
    for offset in range(header['used'], f.RECORD):
        value[offset] = (offset * 13 + number) & 0xff
    return bytes(protected(value, header['usa_offset'], header['usa_count'], 29))


def retired(raw, *, links=None, sequence=None, flags=0):
    value, header = restored(raw)
    FILE.put(value, 'lsn', AFTER_LSN)
    FILE.put(value, 'sequence', sequence if sequence is not None else (header['sequence'] + 1) & WORD_MAX or 1)
    FILE.put(value, 'flags', flags)
    if links is not None:
        FILE.put(value, 'links', links)
    return bytes(protected(value, header['usa_offset'], header['usa_count'], 31))


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    rows = []

    def add(name, slots=(), *, vcn=DEFAULT_VCN, sequence=2, links=1,
            directory=False, large=False, change=None, result=SUCCESS):
        target = output / name
        target.mkdir(exist_ok=True)
        before = bytearray(f.CLUSTER)
        after = bytearray(f.CLUSTER)
        payloads, flags, retired_slots = [], [], []
        for slot in slots:
            number = (vcn * f.CLUSTER + slot * f.RECORD) // f.RECORD
            old = record(number, sequence=sequence, links=links, directory=directory, large=large)
            new = retired(old)
            first = slot * f.RECORD
            before[first:first + f.RECORD], after[first:first + f.RECORD] = old, new
            logical_before, h = restored(old)
            redo = bytearray(logical_before)
            undo = bytearray(logical_before)
            # Pure replay leaves protection storage to the publication owner.
            FILE.put(redo, 'sequence', (h['sequence'] + 1) & WORD_MAX or 1)
            FILE.put(redo, 'flags', 0)
            FILE.put(redo, 'lsn', REDO_LSN)
            FILE.put(undo, 'lsn', UNDO_LSN)
            (target / f'slot-{slot}.before').write_bytes(logical_before)
            (target / f'slot-{slot}.redo').write_bytes(redo)
            (target / f'slot-{slot}.undo').write_bytes(undo)
            payloads += [update(OP_INITIALIZE, OP_NOOP,
                bytes(logical_before[:h['used']]), b'', slot=slot, vcn=vcn),
                update(OP_DEALLOCATE, OP_INITIALIZE, b'',
                bytes(logical_before[:HEADER_PREFIX_BYTES]), slot=slot, vcn=vcn)]
            flags += [ADDING, DELETING]
            retired_slots.append(slot)
        if change is not None:
            change(before, after)
        if result != SUCCESS:
            payloads, flags, retired_slots = [], [], []
        (target / 'before.bin').write_bytes(before)
        (target / 'after.bin').write_bytes(after)
        for ordinal, value in enumerate(payloads):
            (target / f'step-{ordinal}.payload').write_bytes(value)
        description = f'{result} {len(payloads)} {MFT_KEY} {MFT_REFERENCE} {PHYSICAL_LCN * f.CLUSTER} {vcn * f.CLUSTER}\n'
        description += ''.join(f'{len(value)} {flag}\n' for value, flag in zip(payloads, flags))
        (target / 'expected.txt').write_text(description)
        rows.append(dict(name=name, result=result, steps=len(payloads), slots=retired_slots))

    add('unchanged-uninitialized')
    for slot in range(f.CLUSTER // f.RECORD):
        add(f'slot-{slot}', (slot,))
    add('all-four-records', tuple(range(f.CLUSTER // f.RECORD)))
    add('separated-slots', (0, 3))
    add('directory', (2,), directory=True)
    add('two-retained-links', (1,), links=2)
    add('large-used-prefix', (3,), large=True)
    add('first-generation', (0,), sequence=1)
    add('penultimate-generation', (2,), sequence=WORD_MAX - 1)
    add('sequence-wrap-skips-zero', (1,), sequence=WORD_MAX)
    add('wide-MFT-VCN', (3,), vcn=((1 << 32) - 1) // (f.CLUSTER // f.RECORD))

    def change_header(field, value):
        def apply(before, after):
            logical, h = restored(after[:f.RECORD])
            FILE.put(logical, field, value)
            after[:f.RECORD] = protected(logical, h['usa_offset'], h['usa_count'], 31)
        return apply

    add('cleared-links-refused', (0,), change=change_header('links', 0), result=UNSUPPORTED)
    add('unchanged-generation-refused', (0,), change=change_header('sequence', 2), result=UNSUPPORTED)
    add('active-successor-refused', (0,), change=change_header('flags', f.FILE_IN_USE), result=UNSUPPORTED)
    add('wrong-record-number', (0,), change=change_header('record_number', 17), result=CORRUPT)
    add('different-next-instance', (0,), change=change_header('next_instance', 49), result=UNSUPPORTED)

    def changed_body(before, after):
        logical, h = restored(after[:f.RECORD])
        logical[h['attrs_offset'] + f.ATTR_HEADER.size + f.RESIDENT_HEADER.size] ^= 1
        after[:f.RECORD] = protected(logical, h['usa_offset'], h['usa_count'], 31)

    def torn_after(before, after):
        after[f.SECTOR - f.U16_BYTES] ^= 1

    def changed_slack(before, after):
        logical, h = restored(after[:f.RECORD])
        logical[h['used'] + f.WIRE_ALIGNMENT] ^= 1
        after[:f.RECORD] = protected(logical, h['usa_offset'], h['usa_count'], 31)

    add('changed-body-refused', (0,), change=changed_body, result=UNSUPPORTED)
    add('changed-unused-byte-refused', (0,), change=changed_slack, result=UNSUPPORTED)
    add('torn-successor', (0,), change=torn_after, result=CORRUPT)
    (output / 'cases.list').write_text(''.join(row['name'] + '\n' for row in rows))
    (output / 'manifest.json').write_text(json.dumps(dict(cases=rows,
        redoLsn=REDO_LSN, undoLsn=UNDO_LSN, nativeAcceptance=False), indent=2) + '\n')
    return len(rows)


if __name__ == '__main__':
    count = author(Path(sys.argv[1]))
    Path(sys.argv[2]).write_text(str(count) + '\n')
