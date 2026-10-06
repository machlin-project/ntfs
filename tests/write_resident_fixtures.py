#!/usr/bin/env python3
"""Independent complete FILE goldens for unchanged-size resident DATA writes."""
from pathlib import Path
import json
import struct
import sys

import fixtures as f
import filename_storage as storage
import validation_fixtures as v
from overwrite_fixtures import get_record, set_record, replace_attribute
from record_protect_fixtures import FILE, protected
from write_metadata_fixtures import STANDARD, restored, NEW_TIME, ARCHIVE

REFERENCE = f.file_reference(v.HELLO_RECORD)
LSN_BEFORE, LSN_AFTER = 100, 500
PAYLOAD = b'MACHLIN_RESIDENT'
RESIDENT_BYTES = 512
SUCCESS, CORRUPT, UNSUPPORTED, RANGE, INVALID, STALE = 0, 2, 3, 11, 9, 10
READ_ONLY = 1


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    original, _, _ = f.make_image()
    saved = v.HELLO_DATA
    v.HELLO_DATA = f.pattern(RESIDENT_BYTES)
    try:
        base = v.build(original, 'logfile-empty', links_override={
            v.HELLO_RECORD: [v.Link('hello.txt', size=RESIDENT_BYTES)]})
    finally:
        v.HELLO_DATA = saved
    header, attrs = get_record(base, v.HELLO_RECORD)
    header['lsn'] = LSN_BEFORE
    set_record(base, v.HELLO_RECORD, header, attrs)
    rows = []

    def add(name, image=base, code=SUCCESS, offset=5, payload=PAYLOAD,
            time=NEW_TIME, lsn=LSN_AFTER, reference=REFERENCE):
        (output / (name + '.img')).write_bytes(image)
        (output / (name + '.payload')).write_bytes(payload)
        row = dict(name=name, code=code, reference=reference, time=time,
                   lsn=lsn, offset=offset, bytes=len(payload), record=0, attribute=0)
        if code == SUCCESS:
            first = f.MFT_LCN * f.CLUSTER + v.HELLO_RECORD * f.RECORD
            before, h = restored(image[first:first + f.RECORD])
            _, values = get_record(image, v.HELLO_RECORD)
            position = h['attrs_offset']
            after = bytearray(before)
            FILE.put(after, 'lsn', lsn)
            found = set()
            for value in values:
                attr = storage.attr_header(value)
                resident = dict(zip(storage.RESIDENT_FIELDS,
                                    f.RESIDENT_HEADER.unpack_from(value, f.ATTR_HEADER.size)))
                start = position + resident['offset']
                if attr['type'] == f.SI:
                    assert resident['length'] == STANDARD.size
                    STANDARD.put(after, 'modified', time, start)
                    STANDARD.put(after, 'changed', time, start)
                    flags = struct.unpack_from('<I', before, start + STANDARD.offsets['attributes'])[0]
                    STANDARD.put(after, 'attributes', flags | ARCHIVE, start)
                    found.add(f.SI)
                elif attr['type'] == f.DATA and not storage.attr_name(value):
                    assert attr['nonresident'] == 0 and offset + len(payload) <= resident['length']
                    after[start + offset:start + offset + len(payload)] = payload
                    row.update(record=position, attribute=resident['offset'] + offset)
                    found.add(f.DATA)
                position += len(value)
            assert found == {f.SI, f.DATA}
            sequence = struct.unpack_from('<H', before, h['usa_offset'])[0]
            encoded = protected(after, h['usa_offset'], h['usa_count'], sequence)
            for suffix, value in [('before', before), ('after', after), ('protected', encoded)]:
                (output / (name + '.' + suffix)).write_bytes(value)
        rows.append(row)

    add('ordinary')
    add('odd-length', payload=PAYLOAD + b'!')
    add('first-byte', offset=0, payload=b'F')
    add('last-byte', offset=RESIDENT_BYTES - 1, payload=b'L')
    add('whole-value', offset=0, payload=bytes(reversed(f.pattern(RESIDENT_BYTES))))
    raw = base[f.MFT_LCN * f.CLUSTER + v.HELLO_RECORD * f.RECORD:][:f.RECORD]
    h, values = storage.record_parts(raw)
    position = h['attrs_offset']
    for value in values:
        if storage.attr_header(value)['type'] == f.DATA and not storage.attr_name(value):
            resident = dict(zip(storage.RESIDENT_FIELDS, f.RESIDENT_HEADER.unpack_from(value, f.ATTR_HEADER.size)))
            data_first = position + resident['offset']
            break
        position += len(value)
    add('sector-tail', offset=f.SECTOR - f.U16_BYTES - data_first - len(PAYLOAD) // 2)
    add('end-offset', code=RANGE, offset=RESIDENT_BYTES)
    add('crosses-end', code=RANGE, offset=RESIDENT_BYTES - len(PAYLOAD) + 1)
    add('maximum-offset', code=RANGE, offset=(1 << 64) - 1)
    add('invalid-time', code=INVALID, time=1 << 63)
    add('zero-lsn', code=INVALID, lsn=0)
    add('stale-lsn', code=STALE, lsn=LSN_BEFORE)
    add('nonresident', code=UNSUPPORTED, reference=f.file_reference(v.FRAGMENTED_RECORD))
    add('directory', code=UNSUPPORTED, reference=f.ROOT_REF)
    image = bytearray(base)
    header, attrs = get_record(image, v.HELLO_RECORD)
    attrs.append(f.resident(f.DATA, b'unchanged named-stream oracle', v.ADS_INSTANCE, name='original-stream'))
    set_record(image, v.HELLO_RECORD, header, attrs)
    add('named-stream-preserved', image)
    image = bytearray(base)
    standard = bytearray(storage.resident_value(next(a for a in attrs if storage.attr_header(a)['type'] == f.SI)))
    STANDARD.put(standard, 'attributes', READ_ONLY)
    replace_attribute(image, v.HELLO_RECORD, f.SI, f.resident(f.SI, standard, v.SI_INSTANCE))
    add('read-only', image, UNSUPPORTED)
    (output / 'cases.json').write_text(json.dumps(rows, indent=2) + '\n')
    (output / 'cases.rows').write_text(''.join(
        f"{r['name']} {r['code']} {r['reference']} {r['time']} {r['lsn']} {r['offset']} {r['bytes']} {r['record']} {r['attribute']}\n"
        for r in rows))
    return rows


if __name__ == '__main__':
    rows = author(Path(sys.argv[1]))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text(f'{len(rows)} resident FILE profiles\n')
