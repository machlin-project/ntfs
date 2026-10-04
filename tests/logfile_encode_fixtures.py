#!/usr/bin/env python3
"""Author complete private log packets independently of the C encoders."""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import logfile_fixtures as w

RECORD_KIND = 0
UPDATE_KIND = 1
SUCCESS = 0
UNSUPPORTED = 3
BYTE_MAX = (1 << w.BITS_PER_BYTE) - 1
WORD_MAX = (1 << (w.WORD_BYTES * w.BITS_PER_BYTE)) - 1
QWORD_MAX = (1 << w.LSN_BITS) - 1
RECORD_CAP = 1024 * 1024
SOURCE_PADDING = 0x6d
SOURCE_GAP_WORDS = 2
VECTOR_PATTERN_KINDS = 3
UNKNOWN_OPERATION = WORD_MAX
TARGET_ATTRIBUTE = 112
CLUSTER_INDEX = 3


def values(layout, packet):
    return {name: struct.unpack_from('<' + form, packet, layout.offsets[name])[0]
            for name, form in layout.fields}


def pattern(length, salt=0):
    return bytes((index + salt) & BYTE_MAX for index in range(length))


def canonical_update(fields, vector, redo, undo):
    # Construct by appending complete owned components; offsets follow the output
    # cursor. This author neither imports C code nor reads its constants.
    packet = bytearray(w.UPDATE.size)
    packet.extend(vector if vector else bytes(w.LSN_BYTES))
    fields = dict(fields, lcns=len(vector) // w.LSN_BYTES,
                  redo_offset=0, redo_bytes=len(redo), undo_offset=0, undo_bytes=len(undo))
    if redo:
        fields['redo_offset'] = len(packet)
        packet.extend(redo)
    if undo:
        packet.extend(bytes((-len(packet)) % w.ALIGNMENT))
        fields['undo_offset'] = len(packet)
        packet.extend(undo)
    packet[:w.UPDATE.size] = w.UPDATE.pack(fields)
    return bytes(packet)


def canonical_record(packet, header_bytes):
    fields = values(w.RECORD, packet)
    fields['reserved'] = bytes(len(fields['reserved']))
    return bytes(w.RECORD.pack(fields)) + packet[header_bytes:]


def source_update(count, redo, undo, *, shared=False, compact=False):
    vector = b''.join(struct.pack('<Q',
                      0 if index % VECTOR_PATTERN_KINDS == 0 else
                      QWORD_MAX if index % VECTOR_PATTERN_KINDS == 1 else index)
                      for index in range(count))
    fields = dict(redo_operation=w.UPDATE_RESIDENT, undo_operation=UNKNOWN_OPERATION,
                  target_attribute=TARGET_ATTRIBUTE, record_offset=w.TARGET_RECORD_OFFSET,
                  attribute_offset=w.TARGET_ATTRIBUTE_OFFSET, cluster_index=CLUSTER_INDEX,
                  attribute_flags=w.ATTRIBUTE_ACTS_ON_MFT, target_vcn=QWORD_MAX,
                  lcns=count, redo_bytes=len(redo), undo_bytes=len(undo))
    packet = bytearray(w.UPDATE.pack(fields))
    packet.extend(vector if vector else struct.pack('<Q', w.UNUSED_LCN_SLOT))
    gap = 0 if compact else SOURCE_GAP_WORDS * w.ALIGNMENT
    if redo:
        packet.extend(bytes([SOURCE_PADDING]) * gap)
        fields['redo_offset'] = len(packet)
        packet.extend(redo)
    if undo:
        if shared:
            assert redo[:len(undo)] == undo
            fields['undo_offset'] = fields['redo_offset']
        else:
            packet.extend(bytes([SOURCE_PADDING]) * ((-len(packet)) % w.ALIGNMENT + gap))
            fields['undo_offset'] = len(packet)
            packet.extend(undo)
    packet[:w.UPDATE.size] = w.UPDATE.pack(fields)
    return bytes(packet), canonical_update(fields, vector, redo, undo)


def author(output, native_records=None, native_legacy=None):
    output.mkdir(parents=True, exist_ok=True)
    cases = []

    def add(name, kind, packet, expected, *, header_bytes=w.RECORD.size, code=SUCCESS,
            provenance='independent synthetic packet'):
        (output / (name + '.input')).write_bytes(packet)
        (output / (name + '.expected')).write_bytes(expected)
        cases.append(dict(name=name, kind=kind, header_bytes=header_bytes, code=code,
                          bytes=len(expected), input_bytes=len(packet), provenance=provenance,
                          input_sha256=hashlib.sha256(packet).hexdigest(),
                          expected_sha256=hashlib.sha256(expected).hexdigest()))

    for kind in (w.UPDATE_TYPE, w.RESTART_TYPE):
        for flags in range((w.MULTI_PAGE | w.RECORD_DELETING | w.RECORD_ADDING) + 1):
            for length in (0, 1, 7, 8, 9):
                fields = dict(lsn=w.BASE_LSN, previous_lsn=w.BASE_LSN - 1,
                              undo_next_lsn=w.BASE_LSN - 2, data_bytes=length,
                              client_sequence=WORD_MAX, client_index=WORD_MAX - 1,
                              type=kind, transaction=(1 << 32) - 1, flags=flags,
                              reserved=bytes([SOURCE_PADDING]) *
                              struct.calcsize('<' + dict(w.RECORD.fields)['reserved']))
                packet = bytes(w.RECORD.pack(fields)) + pattern(length)
                add(f'record-type-{kind}-flags-{flags}-bytes-{length}', RECORD_KIND,
                    packet, canonical_record(packet, w.RECORD.size))
    for label, length in (('empty', 0), ('policy-cap', RECORD_CAP - w.RECORD.size)):
        packet = bytes(w.RECORD.pack(dict(lsn=QWORD_MAX, data_bytes=length,
            client_sequence=0, client_index=0, type=w.UPDATE_TYPE))) + pattern(length)
        add('record-' + label, RECORD_KIND, packet, canonical_record(packet, w.RECORD.size))
    extended = bytes(w.RECORD.pack(dict(lsn=w.BASE_LSN, data_bytes=len(w.REDO),
        type=w.UPDATE_TYPE))) + bytes([SOURCE_PADDING]) * w.ALIGNMENT + w.REDO
    add('record-extended-header', RECORD_KIND, extended, b'',
        header_bytes=w.RECORD.size + w.ALIGNMENT, code=UNSUPPORTED)

    for count in (0, 1, 2):
        for redo_bytes in (0, 1, 7, 8, 9):
            for undo_bytes in (0, 1, 9):
                packet, expected = source_update(count, pattern(redo_bytes), pattern(undo_bytes, 1))
                add(f'update-lcns-{count}-redo-{redo_bytes}-undo-{undo_bytes}', UPDATE_KIND,
                    packet, expected)
    packet, expected = source_update(1, w.REDO, w.REDO, shared=True)
    add('update-shared-input', UPDATE_KIND, packet, expected)
    for label, count, redo_bytes, undo_bytes in (
        ('maximum-vector-empty-data', WORD_MAX, 0, 0),
        ('maximum-redo-empty-undo', 0, WORD_MAX, 0),
        ('maximum-undo-empty-redo', 0, 0, WORD_MAX),
        ('highest-redo-start', (WORD_MAX - w.UPDATE.size) // w.LSN_BYTES, 1, 0),
        ('highest-undo-start', (WORD_MAX - w.UPDATE.size) // w.LSN_BYTES, 0, WORD_MAX),
        ('aligned-undo-boundary', (WORD_MAX - w.UPDATE.size) // w.LSN_BYTES - 1, 7, 7)):
        packet, expected = source_update(count, pattern(redo_bytes), pattern(undo_bytes, 1), compact=True)
        add('update-' + label, UPDATE_KIND, packet, expected)

    def native(name, packet):
        add('native-record-' + name, RECORD_KIND, packet,
            canonical_record(packet, w.RECORD.size), provenance='retained original journal packet')
        record = values(w.RECORD, packet)
        if record['type'] == w.UPDATE_TYPE:
            payload = packet[w.RECORD.size:]
            update = values(w.UPDATE, payload)
            vector = payload[w.UPDATE.size:w.UPDATE.size + update['lcns'] * w.LSN_BYTES]
            redo = payload[update['redo_offset']:update['redo_offset'] + update['redo_bytes']]
            undo = payload[update['undo_offset']:update['undo_offset'] + update['undo_bytes']]
            add('native-update-' + name, UPDATE_KIND, payload,
                canonical_update(update, vector, redo, undo),
                provenance='retained original journal payload; canonical placement is authored')

    if native_records is not None:
        for path in sorted(native_records.glob('*.record')):
            native(path.stem, path.read_bytes())
    if native_legacy is not None:
        for path in sorted(native_legacy.glob('*-legacy-record.stdout.log')):
            report = json.loads(path.read_text())
            assert report['code'] == SUCCESS and not report['recovery_qualified']
            native(path.name.removesuffix('.stdout.log'), bytes.fromhex(report['bytes_hex']))

    (output / 'manifest.json').write_text(json.dumps(dict(cases=cases), indent=2) + '\n')
    (output / 'cases.tsv').write_text('\n'.join(
        f"{case['name']}\t{case['kind']}\t{case['header_bytes']}\t{case['code']}\t{case['bytes']}"
        for case in cases) + '\n')
    return cases


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('stamp', type=Path, nargs='?')
    parser.add_argument('--native-records', type=Path)
    parser.add_argument('--native-legacy', type=Path)
    args = parser.parse_args()
    author(args.output, args.native_records, args.native_legacy)
    if args.stamp:
        args.stamp.touch()
